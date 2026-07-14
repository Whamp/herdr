use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

use super::broker::{BrokerServer, ForwardingClient};
use super::worker::ControlAuthority;

use super::{
    FORWARDING_LAUNCH_STATUS_ENV, FORWARDING_STATUS_AVAILABLE,
    FORWARDING_STATUS_MANAGED_SSH_REQUIRED, FORWARDING_STATUS_UNAVAILABLE, INHERITED_BROKER_FD_ENV,
};

pub(crate) struct PendingBroker {
    parent: UnixStream,
    child: UnixStream,
    authority: ControlAuthority,
}

impl PendingBroker {
    pub(crate) fn new(authority: ControlAuthority) -> io::Result<Self> {
        let (parent, child) = UnixStream::pair()?;
        crate::platform::prepare_inherited_credential_receiver(&parent)?;
        Ok(Self {
            parent,
            child,
            authority,
        })
    }

    pub(crate) fn configure_child_command(&self, command: &mut Command) {
        let descriptor = self.child.as_raw_fd();
        command.env(INHERITED_BROKER_FD_ENV, descriptor.to_string());
        unsafe {
            command.pre_exec(move || {
                crate::platform::set_inherited_descriptor_cloexec(descriptor, false)
            });
        }
    }

    pub(crate) fn start(self, child_pid: u32) -> io::Result<BrokerServer> {
        let Self {
            parent,
            child,
            authority,
        } = self;
        drop(child);
        BrokerServer::start(
            parent,
            crate::platform::InheritedPeerIdentity::child(child_pid),
            authority,
        )
    }

    #[cfg(test)]
    fn parent_descriptor_for_test(&self) -> RawFd {
        self.parent.as_raw_fd()
    }

    #[cfg(test)]
    fn child_descriptor_for_test(&self) -> RawFd {
        self.child.as_raw_fd()
    }
}

pub(crate) fn adopt_external_open_forwarding(
    initial_policy: bool,
) -> io::Result<crate::external_open::ExternalOpenForwarding> {
    let status = std::env::var(FORWARDING_LAUNCH_STATUS_ENV).ok();
    std::env::remove_var(FORWARDING_LAUNCH_STATUS_ENV);
    let client = adopt_inherited_capability(initial_policy)?;
    match (client, status.as_deref()) {
        (Some(client), Some(FORWARDING_STATUS_AVAILABLE) | None) => {
            Ok(crate::external_open::ExternalOpenForwarding::available(
                std::sync::Arc::new(super::NumericForwardingController::new(client)),
            ))
        }
        (Some(_), _) => Ok(crate::external_open::ExternalOpenForwarding::Unavailable),
        (None, Some(FORWARDING_STATUS_UNAVAILABLE)) => {
            Ok(crate::external_open::ExternalOpenForwarding::Unavailable)
        }
        (None, Some(FORWARDING_STATUS_MANAGED_SSH_REQUIRED) | None) => {
            Ok(crate::external_open::ExternalOpenForwarding::ManagedSshRequired)
        }
        (None, Some(FORWARDING_STATUS_AVAILABLE) | Some(_)) => {
            Ok(crate::external_open::ExternalOpenForwarding::Unavailable)
        }
    }
}

fn adopt_inherited_capability(initial_policy: bool) -> io::Result<Option<ForwardingClient>> {
    let Some(raw_descriptor) = std::env::var_os(INHERITED_BROKER_FD_ENV) else {
        return Ok(None);
    };
    std::env::remove_var(INHERITED_BROKER_FD_ENV);
    let descriptor = raw_descriptor
        .to_str()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid inherited broker descriptor",
            )
        })?
        .parse::<RawFd>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid inherited broker descriptor",
            )
        })?;
    if descriptor < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid inherited broker descriptor",
        ));
    }
    crate::platform::set_inherited_descriptor_cloexec(descriptor, true)?;
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    ForwardingClient::from_stream(
        stream,
        initial_policy,
        crate::platform::InheritedPeerIdentity::parent(),
    )
    .map(Some)
}

#[cfg(test)]
fn descriptor_is_cloexec(descriptor: RawFd) -> io::Result<bool> {
    crate::platform::inherited_descriptor_is_cloexec(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    const CHILD_MARKER: &str = "HERDR_TEST_INHERITED_FORWARDING_CHILD";

    #[test]
    fn inherited_descriptor_child_restores_close_on_exec() {
        if std::env::var_os(CHILD_MARKER).is_none() {
            return;
        }

        let client = adopt_inherited_capability(false)
            .expect("adopt inherited capability")
            .expect("capability present");
        assert!(!client.is_active());
        assert!(std::env::var_os(INHERITED_BROKER_FD_ENV).is_none());
        assert!(descriptor_is_cloexec(client.raw_descriptor_for_test()).expect("descriptor flags"));
    }

    #[test]
    fn socket_pair_crosses_initial_exec_only_for_the_intended_child() {
        let pending = PendingBroker::new(ControlAuthority::new(
            "secret-target".to_string(),
            "/secret/control".into(),
        ))
        .expect("pending broker");
        assert!(descriptor_is_cloexec(pending.parent_descriptor_for_test()).expect("parent flags"));
        assert!(descriptor_is_cloexec(pending.child_descriptor_for_test()).expect("child flags"));

        let current_test = std::env::current_exe().expect("current test executable");
        let mut command = Command::new(current_test);
        command
            .arg("--exact")
            .arg("remote::forwarding::inheritance::tests::inherited_descriptor_child_restores_close_on_exec")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        pending.configure_child_command(&mut command);
        let mut child = command.spawn().expect("spawn intended child");
        let _broker = pending.start(child.id()).expect("start parent broker");

        assert!(child.wait().expect("wait child").success());
    }
}
