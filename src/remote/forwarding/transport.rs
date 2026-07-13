use std::io;
use std::os::unix::net::UnixStream;

use serde::de::DeserializeOwned;

use super::protocol;

pub(super) struct AuthenticatedFrameReader {
    stream: UnixStream,
    expected: crate::platform::InheritedPeerIdentity,
}

impl AuthenticatedFrameReader {
    pub(super) fn new(
        stream: UnixStream,
        expected: crate::platform::InheritedPeerIdentity,
    ) -> io::Result<Self> {
        crate::platform::prepare_inherited_credential_receiver(&stream)?;
        Ok(Self { stream, expected })
    }

    pub(super) fn read_message<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        let mut header = [0_u8; 4];
        crate::platform::read_authenticated_inherited_bytes(
            &self.stream,
            self.expected,
            &mut header,
        )?;
        let mut payload = vec![0_u8; protocol::payload_length(header)?];
        crate::platform::read_authenticated_inherited_bytes(
            &self.stream,
            self.expected,
            &mut payload,
        )?;
        protocol::decode_message(&payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::forwarding::protocol::{
        ClientMessage, CorrelationId, BROKER_PROTOCOL_VERSION,
    };

    #[cfg(target_os = "linux")]
    const UNAUTHORIZED_PAYLOAD_CHILD: &str = "HERDR_TEST_UNAUTHORIZED_BROKER_PAYLOAD_CHILD";
    #[cfg(target_os = "linux")]
    const UNAUTHORIZED_PAYLOAD_FD: &str = "HERDR_TEST_UNAUTHORIZED_BROKER_PAYLOAD_FD";

    #[test]
    fn inherited_frames_require_the_expected_platform_credentials() {
        let (expected_reader, mut expected_writer) = UnixStream::pair().expect("expected pair");
        let mut reader = AuthenticatedFrameReader::new(
            expected_reader,
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("credential reader");
        protocol::write_message(
            &mut expected_writer,
            &ClientMessage::Hello {
                id: CorrelationId::new(1).expect("id"),
                version: BROKER_PROTOCOL_VERSION,
            },
        )
        .expect("write authenticated frame");
        assert!(matches!(
            reader
                .read_message::<ClientMessage>()
                .expect("authenticated frame"),
            ClientMessage::Hello { .. }
        ));

        let (rejected_reader, mut rejected_writer) = UnixStream::pair().expect("rejected pair");
        let mut wrong_identity = crate::platform::InheritedPeerIdentity::current_process();
        #[cfg(target_os = "linux")]
        {
            wrong_identity.pid = wrong_identity.pid.saturating_add(1);
        }
        #[cfg(target_os = "macos")]
        {
            wrong_identity.uid = wrong_identity.uid.saturating_add(1);
        }
        let mut reader = AuthenticatedFrameReader::new(rejected_reader, wrong_identity)
            .expect("credential reader");
        protocol::write_message(
            &mut rejected_writer,
            &ClientMessage::Hello {
                id: CorrelationId::new(1).expect("id"),
                version: BROKER_PROTOCOL_VERSION,
            },
        )
        .expect("write rejected frame");
        assert_eq!(
            reader
                .read_message::<ClientMessage>()
                .expect_err("wrong credentials")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inherited_frame_rejects_payload_from_a_different_process() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, RawFd};
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        if std::env::var_os(UNAUTHORIZED_PAYLOAD_CHILD).is_some() {
            let descriptor = std::env::var(UNAUTHORIZED_PAYLOAD_FD)
                .expect("payload descriptor")
                .parse::<RawFd>()
                .expect("numeric payload descriptor");
            let mut writer = unsafe { UnixStream::from_raw_fd(descriptor) };
            let payload = protocol::encode_message(&ClientMessage::Hello {
                id: CorrelationId::new(1).expect("id"),
                version: BROKER_PROTOCOL_VERSION,
            })
            .expect("encode payload");
            writer.write_all(&payload).expect("write payload");
            return;
        }

        let (reader_stream, mut writer) = UnixStream::pair().expect("broker pair");
        let mut reader = AuthenticatedFrameReader::new(
            reader_stream,
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("credential reader");
        let payload = protocol::encode_message(&ClientMessage::Hello {
            id: CorrelationId::new(1).expect("id"),
            version: BROKER_PROTOCOL_VERSION,
        })
        .expect("encode payload");
        writer
            .write_all(&(payload.len() as u32).to_be_bytes())
            .expect("write authenticated header");

        let descriptor = writer.as_raw_fd();
        let current_test = std::env::current_exe().expect("current test executable");
        let mut command = Command::new(current_test);
        command
            .arg("--exact")
            .arg("remote::forwarding::transport::tests::inherited_frame_rejects_payload_from_a_different_process")
            .arg("--nocapture")
            .env(UNAUTHORIZED_PAYLOAD_CHILD, "1")
            .env(UNAUTHORIZED_PAYLOAD_FD, descriptor.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                crate::platform::set_inherited_descriptor_cloexec(descriptor, false)
            });
        }
        let mut child = command.spawn().expect("spawn payload writer");

        assert_eq!(
            reader
                .read_message::<ClientMessage>()
                .expect_err("payload credentials must be checked")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(child.wait().expect("wait payload writer").success());
    }
}
