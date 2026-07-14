use std::num::NonZeroU16;
use std::sync::Arc;

use crate::external_open::{
    ForwardingController, ForwardingPolicyChange, ForwardingPolicySettlement,
    ForwardingPreparation, ForwardingPreparationError, LoopbackTarget,
};

use super::broker::{ForwardingClient, MappingCall, PolicyCall};
use super::protocol::{ForwardFailure, ForwardSpec, LoopbackAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappingCommand {
    Scalar(ForwardSpec),
    Localhost(u16),
}

trait MappingCommandCall: Send {
    fn poll(&mut self) -> Option<Result<u16, ForwardFailure>>;
    fn cancel(&mut self);
}

trait PolicyCommandCall: Send {
    fn poll(&mut self) -> Option<(bool, Result<(), ForwardFailure>)>;
    fn cancel(&mut self);
}

trait ForwardCommand: Send + Sync {
    fn begin_mapping(
        &self,
        command: MappingCommand,
    ) -> Result<Box<dyn MappingCommandCall>, ForwardFailure>;

    fn begin_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<Box<dyn PolicyCommandCall>, ForwardFailure>;
}

impl MappingCommandCall for MappingCall {
    fn poll(&mut self) -> Option<Result<u16, ForwardFailure>> {
        self.try_wait()
    }

    fn cancel(&mut self) {
        MappingCall::cancel(self);
    }
}

impl PolicyCommandCall for PolicyCall {
    fn poll(&mut self) -> Option<(bool, Result<(), ForwardFailure>)> {
        self.try_wait()
    }

    fn cancel(&mut self) {
        PolicyCall::cancel(self);
    }
}

impl ForwardCommand for ForwardingClient {
    fn begin_mapping(
        &self,
        command: MappingCommand,
    ) -> Result<Box<dyn MappingCommandCall>, ForwardFailure> {
        let call = match command {
            MappingCommand::Scalar(spec) => ForwardingClient::begin_forward(self, spec),
            MappingCommand::Localhost(remote_port) => {
                ForwardingClient::begin_localhost(self, remote_port)
            }
        }?;
        Ok(Box::new(call))
    }

    fn begin_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<Box<dyn PolicyCommandCall>, ForwardFailure> {
        self.begin_assert_policy(enabled)
            .map(|call| Box::new(call) as Box<dyn PolicyCommandCall>)
            .map_err(|_| ForwardFailure::CapabilityClosed)
    }
}

pub(crate) struct NumericForwardingController {
    command: Arc<dyn ForwardCommand>,
    ipv6_available: bool,
}

impl NumericForwardingController {
    pub(crate) fn new(client: ForwardingClient) -> Self {
        Self {
            command: Arc::new(client),
            ipv6_available: crate::platform::external_open_ipv6_available(),
        }
    }

    #[cfg(test)]
    fn with_capability(command: Arc<dyn ForwardCommand>, ipv6_available: bool) -> Self {
        Self {
            command,
            ipv6_available,
        }
    }
}

impl ForwardingController for NumericForwardingController {
    fn begin_prepare_numeric(
        &self,
        target: LoopbackTarget,
        remote_port: NonZeroU16,
    ) -> Result<Box<dyn ForwardingPreparation>, ForwardingPreparationError> {
        if !self.ipv6_available
            && matches!(target, LoopbackTarget::Ipv6 | LoopbackTarget::Localhost)
        {
            return Err(ForwardingPreparationError::Unavailable);
        }
        if target == LoopbackTarget::Localhost {
            let call = self
                .command
                .begin_mapping(MappingCommand::Localhost(remote_port.get()))
                .map_err(forwarding_failure)?;
            return Ok(Box::new(MappingForwardOperation::new(call)));
        }
        let address = match target {
            LoopbackTarget::Ipv4(address) => LoopbackAddress::Ipv4(address.octets()),
            LoopbackTarget::Ipv6 => LoopbackAddress::Ipv6,
            LoopbackTarget::Localhost => return Err(ForwardingPreparationError::Unavailable),
        };
        let spec = forward_spec(address, remote_port);
        let call = self
            .command
            .begin_mapping(MappingCommand::Scalar(spec))
            .map_err(forwarding_failure)?;
        Ok(Box::new(MappingForwardOperation::new(call)))
    }

    fn begin_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<Box<dyn ForwardingPolicyChange>, ForwardingPreparationError> {
        let call = self
            .command
            .begin_set_enabled(enabled)
            .map_err(forwarding_failure)?;
        Ok(Box::new(NumericPolicyOperation {
            requested: enabled,
            call: Some(call),
            settled: false,
        }))
    }
}

fn forward_spec(address: LoopbackAddress, remote_port: NonZeroU16) -> ForwardSpec {
    ForwardSpec {
        local_address: address,
        local_port: remote_port.get(),
        remote_address: address,
        remote_port: remote_port.get(),
    }
}

struct MappingForwardOperation {
    call: Option<Box<dyn MappingCommandCall>>,
    settled: bool,
}

impl MappingForwardOperation {
    fn new(call: Box<dyn MappingCommandCall>) -> Self {
        Self {
            call: Some(call),
            settled: false,
        }
    }
}

impl ForwardingPreparation for MappingForwardOperation {
    fn poll(&mut self) -> Option<Result<NonZeroU16, ForwardingPreparationError>> {
        if self.settled {
            return None;
        }
        let result = self.call.as_mut()?.poll()?;
        self.call = None;
        self.settled = true;
        Some(match result {
            Ok(port) => NonZeroU16::new(port).ok_or(ForwardingPreparationError::CommandRejected),
            Err(error) => Err(forwarding_failure(error)),
        })
    }

    fn cancel(&mut self) {
        if self.settled {
            return;
        }
        if let Some(call) = self.call.as_mut() {
            call.cancel();
        }
        self.call = None;
        self.settled = true;
    }
}

impl Drop for MappingForwardOperation {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct NumericPolicyOperation {
    requested: bool,
    call: Option<Box<dyn PolicyCommandCall>>,
    settled: bool,
}

impl ForwardingPolicyChange for NumericPolicyOperation {
    fn poll(&mut self) -> Option<ForwardingPolicySettlement> {
        if self.settled {
            return None;
        }
        let (effective, result) = self.call.as_mut()?.poll()?;
        self.call = None;
        self.settled = true;
        Some(ForwardingPolicySettlement {
            requested: self.requested,
            effective,
            result: result.map_err(forwarding_failure),
        })
    }

    fn cancel(&mut self) {
        if self.settled {
            return;
        }
        if let Some(call) = self.call.as_mut() {
            call.cancel();
        }
        self.call = None;
        self.settled = true;
    }
}

impl Drop for NumericPolicyOperation {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn forwarding_failure(error: ForwardFailure) -> ForwardingPreparationError {
    match error {
        ForwardFailure::TooManyRequests => ForwardingPreparationError::TooManyRequests,
        ForwardFailure::BindFailed => ForwardingPreparationError::BindExhausted,
        ForwardFailure::AlreadyOwned | ForwardFailure::CommandRejected => {
            ForwardingPreparationError::CommandRejected
        }
        ForwardFailure::CommandTimedOut => ForwardingPreparationError::CommandTimedOut,
        ForwardFailure::AtomicCreationFailed => ForwardingPreparationError::AtomicCreationFailed,
        ForwardFailure::Disabled | ForwardFailure::Cancelled | ForwardFailure::CapabilityClosed => {
            ForwardingPreparationError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct ImmediateMappingCall {
        result: Option<Result<u16, ForwardFailure>>,
        cancelled: Arc<Mutex<usize>>,
    }

    impl MappingCommandCall for ImmediateMappingCall {
        fn poll(&mut self) -> Option<Result<u16, ForwardFailure>> {
            self.result.take()
        }

        fn cancel(&mut self) {
            *self.cancelled.lock().expect("cancel count") += 1;
            self.result = None;
        }
    }

    struct ImmediatePolicyCall {
        effective: bool,
        result: Option<Result<(), ForwardFailure>>,
    }

    impl PolicyCommandCall for ImmediatePolicyCall {
        fn poll(&mut self) -> Option<(bool, Result<(), ForwardFailure>)> {
            self.result.take().map(|result| (self.effective, result))
        }

        fn cancel(&mut self) {
            self.result = None;
        }
    }

    struct FakeForwardCommand {
        results: Mutex<VecDeque<Result<u16, ForwardFailure>>>,
        specs: Mutex<Vec<ForwardSpec>>,
        localhost_ports: Mutex<Vec<u16>>,
        cancelled: Arc<Mutex<usize>>,
    }

    impl FakeForwardCommand {
        fn new(results: impl IntoIterator<Item = Result<u16, ForwardFailure>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                specs: Mutex::new(Vec::new()),
                localhost_ports: Mutex::new(Vec::new()),
                cancelled: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl ForwardCommand for FakeForwardCommand {
        fn begin_mapping(
            &self,
            command: MappingCommand,
        ) -> Result<Box<dyn MappingCommandCall>, ForwardFailure> {
            match command {
                MappingCommand::Scalar(spec) => self.specs.lock().expect("specs").push(spec),
                MappingCommand::Localhost(remote_port) => self
                    .localhost_ports
                    .lock()
                    .expect("localhost ports")
                    .push(remote_port),
            }
            let result = self
                .results
                .lock()
                .expect("results")
                .pop_front()
                .expect("queued result");
            Ok(Box::new(ImmediateMappingCall {
                result: Some(result),
                cancelled: Arc::clone(&self.cancelled),
            }))
        }

        fn begin_set_enabled(
            &self,
            enabled: bool,
        ) -> Result<Box<dyn PolicyCommandCall>, ForwardFailure> {
            Ok(Box::new(ImmediatePolicyCall {
                effective: enabled,
                result: Some(Ok(())),
            }))
        }
    }

    #[test]
    fn scalar_preparation_sends_exact_identity_and_returns_broker_selected_port() {
        let command = Arc::new(FakeForwardCommand::new([Ok(43_123)]));
        let controller = NumericForwardingController::with_capability(command.clone(), true);
        let mut operation = controller
            .begin_prepare_numeric(
                LoopbackTarget::Ipv4(Ipv4Addr::new(127, 0, 0, 42)),
                NonZeroU16::new(8080).expect("port"),
            )
            .expect("preparation");

        assert_eq!(
            operation.poll(),
            Some(Ok(NonZeroU16::new(43_123).expect("port")))
        );
        assert_eq!(
            *command.specs.lock().expect("specs"),
            vec![forward_spec(
                LoopbackAddress::Ipv4([127, 0, 0, 42]),
                NonZeroU16::new(8080).expect("port")
            )]
        );
    }

    #[test]
    fn localhost_uses_atomic_command_and_ipv4_only_capability_fails_closed() {
        let command = Arc::new(FakeForwardCommand::new([Ok(8080), Ok(8080)]));
        let available = NumericForwardingController::with_capability(command.clone(), true);
        let mut localhost = available
            .begin_prepare_numeric(
                LoopbackTarget::Localhost,
                NonZeroU16::new(8080).expect("port"),
            )
            .expect("localhost");
        assert_eq!(
            localhost.poll(),
            Some(Ok(NonZeroU16::new(8080).expect("port")))
        );

        let ipv4_only = NumericForwardingController::with_capability(command.clone(), false);
        for target in [LoopbackTarget::Localhost, LoopbackTarget::Ipv6] {
            assert!(matches!(
                ipv4_only.begin_prepare_numeric(target, NonZeroU16::new(8080).expect("port")),
                Err(ForwardingPreparationError::Unavailable)
            ));
        }
        assert_eq!(
            *command.localhost_ports.lock().expect("localhost ports"),
            vec![8080]
        );
    }

    #[test]
    fn scalar_and_localhost_cancellation_share_one_idempotent_dispatch_path() {
        let command = Arc::new(FakeForwardCommand::new([Ok(8080), Ok(8081)]));
        let cancellations = Arc::clone(&command.cancelled);
        let controller = NumericForwardingController::with_capability(command, true);

        for (target, port) in [
            (LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST), 8080),
            (LoopbackTarget::Localhost, 8081),
        ] {
            let mut operation = controller
                .begin_prepare_numeric(target, NonZeroU16::new(port).expect("port"))
                .expect("preparation");
            operation.cancel();
            operation.cancel();
            assert_eq!(operation.poll(), None);
        }

        assert_eq!(*cancellations.lock().expect("cancellations"), 2);
    }
}
