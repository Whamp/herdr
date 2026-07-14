use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::num::NonZeroU16;
use std::sync::Arc;

use crate::external_open::{
    ForwardingController, ForwardingPolicyChange, ForwardingPolicySettlement,
    ForwardingPreparation, ForwardingPreparationError, LoopbackTarget,
};

use super::broker::{ForwardCall, ForwardingClient, PolicyCall};
use super::protocol::{ForwardFailure, ForwardSpec, LoopbackAddress};

trait ForwardCommandCall: Send {
    fn poll(&mut self) -> Option<Result<(), ForwardFailure>>;
    fn cancel(&mut self);
}

trait PolicyCommandCall: Send {
    fn poll(&mut self) -> Option<(bool, Result<(), ForwardFailure>)>;
    fn cancel(&mut self);
}

trait ForwardCommand: Send + Sync {
    fn begin_forward(
        &self,
        spec: ForwardSpec,
    ) -> Result<Box<dyn ForwardCommandCall>, ForwardFailure>;

    fn begin_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<Box<dyn PolicyCommandCall>, ForwardFailure>;
}

impl ForwardCommandCall for ForwardCall {
    fn poll(&mut self) -> Option<Result<(), ForwardFailure>> {
        self.try_wait()
    }

    fn cancel(&mut self) {
        ForwardCall::cancel(self);
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
    fn begin_forward(
        &self,
        spec: ForwardSpec,
    ) -> Result<Box<dyn ForwardCommandCall>, ForwardFailure> {
        ForwardingClient::begin_forward(self, spec)
            .map(|call| Box::new(call) as Box<dyn ForwardCommandCall>)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateFailure {
    Collision,
    Unavailable,
}

struct PortReservation {
    port: NonZeroU16,
    _listener: Option<TcpListener>,
}

impl PortReservation {
    #[cfg(test)]
    fn for_test(port: NonZeroU16) -> Self {
        Self {
            port,
            _listener: None,
        }
    }
}

trait PortCandidates: Send + Sync {
    fn reserve_fresh(&self, target: LoopbackAddress) -> Result<PortReservation, CandidateFailure>;
}

struct SystemPortCandidates;

impl PortCandidates for SystemPortCandidates {
    fn reserve_fresh(&self, target: LoopbackAddress) -> Result<PortReservation, CandidateFailure> {
        let address = match target {
            LoopbackAddress::Ipv4(octets) => IpAddr::V4(Ipv4Addr::from(octets)),
            LoopbackAddress::Ipv6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        let listener = TcpListener::bind(SocketAddr::new(address, 0)).map_err(candidate_failure)?;
        let port = listener
            .local_addr()
            .ok()
            .and_then(|address| NonZeroU16::new(address.port()))
            .ok_or(CandidateFailure::Unavailable)?;
        Ok(PortReservation {
            port,
            _listener: Some(listener),
        })
    }
}

fn candidate_failure(error: io::Error) -> CandidateFailure {
    if error.kind() == io::ErrorKind::AddrInUse {
        CandidateFailure::Collision
    } else {
        CandidateFailure::Unavailable
    }
}

pub(crate) struct NumericForwardingController {
    command: Arc<dyn ForwardCommand>,
    candidates: Arc<dyn PortCandidates>,
}

impl NumericForwardingController {
    pub(crate) fn new(client: ForwardingClient) -> Self {
        Self {
            command: Arc::new(client),
            candidates: Arc::new(SystemPortCandidates),
        }
    }

    #[cfg(test)]
    fn with_parts(command: Arc<dyn ForwardCommand>, candidates: Arc<dyn PortCandidates>) -> Self {
        Self {
            command,
            candidates,
        }
    }
}

impl ForwardingController for NumericForwardingController {
    fn begin_prepare_numeric(
        &self,
        target: LoopbackTarget,
        remote_port: NonZeroU16,
    ) -> Result<Box<dyn ForwardingPreparation>, ForwardingPreparationError> {
        let address = match target {
            LoopbackTarget::Ipv4(address) => LoopbackAddress::Ipv4(address.octets()),
            LoopbackTarget::Ipv6 => LoopbackAddress::Ipv6,
            LoopbackTarget::Localhost => return Err(ForwardingPreparationError::Unavailable),
        };
        let spec = forward_spec(address, remote_port, remote_port);
        let call = self
            .command
            .begin_forward(spec)
            .map_err(forwarding_failure)?;
        Ok(Box::new(NumericForwardOperation {
            command: Arc::clone(&self.command),
            candidates: Arc::clone(&self.candidates),
            address,
            remote_port,
            local_port: remote_port,
            fresh_attempts: 0,
            call: Some(call),
            settled: false,
        }))
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

fn forward_spec(
    address: LoopbackAddress,
    local_port: NonZeroU16,
    remote_port: NonZeroU16,
) -> ForwardSpec {
    ForwardSpec {
        local_address: address,
        local_port: local_port.get(),
        remote_address: address,
        remote_port: remote_port.get(),
    }
}

struct NumericForwardOperation {
    command: Arc<dyn ForwardCommand>,
    candidates: Arc<dyn PortCandidates>,
    address: LoopbackAddress,
    remote_port: NonZeroU16,
    local_port: NonZeroU16,
    fresh_attempts: usize,
    call: Option<Box<dyn ForwardCommandCall>>,
    settled: bool,
}

impl NumericForwardOperation {
    fn begin_fresh_candidate(&mut self) -> Result<(), ForwardingPreparationError> {
        while self.fresh_attempts < 5 {
            self.fresh_attempts += 1;
            let reservation = match self.candidates.reserve_fresh(self.address) {
                Ok(reservation) => reservation,
                Err(CandidateFailure::Collision) => continue,
                Err(CandidateFailure::Unavailable) => {
                    return Err(ForwardingPreparationError::CommandRejected);
                }
            };
            self.local_port = reservation.port;
            drop(reservation);
            self.call = Some(
                self.command
                    .begin_forward(forward_spec(
                        self.address,
                        self.local_port,
                        self.remote_port,
                    ))
                    .map_err(forwarding_failure)?,
            );
            return Ok(());
        }
        Err(ForwardingPreparationError::BindExhausted)
    }
}

impl ForwardingPreparation for NumericForwardOperation {
    fn poll(&mut self) -> Option<Result<NonZeroU16, ForwardingPreparationError>> {
        if self.settled {
            return None;
        }
        loop {
            let result = self.call.as_mut()?.poll()?;
            self.call = None;
            match result {
                Ok(()) => {
                    self.settled = true;
                    return Some(Ok(self.local_port));
                }
                Err(ForwardFailure::BindFailed) => {
                    if let Err(error) = self.begin_fresh_candidate() {
                        self.settled = true;
                        return Some(Err(error));
                    }
                }
                Err(error) => {
                    self.settled = true;
                    return Some(Err(forwarding_failure(error)));
                }
            }
        }
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

impl Drop for NumericForwardOperation {
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
        ForwardFailure::Disabled | ForwardFailure::Cancelled | ForwardFailure::CapabilityClosed => {
            ForwardingPreparationError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct ImmediateForwardCall {
        result: Option<Result<(), ForwardFailure>>,
        cancelled: Arc<Mutex<usize>>,
    }

    impl ForwardCommandCall for ImmediateForwardCall {
        fn poll(&mut self) -> Option<Result<(), ForwardFailure>> {
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
        results: Mutex<VecDeque<Result<(), ForwardFailure>>>,
        specs: Mutex<Vec<ForwardSpec>>,
        cancelled: Arc<Mutex<usize>>,
    }

    impl FakeForwardCommand {
        fn new(results: impl IntoIterator<Item = Result<(), ForwardFailure>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                specs: Mutex::new(Vec::new()),
                cancelled: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl ForwardCommand for FakeForwardCommand {
        fn begin_forward(
            &self,
            spec: ForwardSpec,
        ) -> Result<Box<dyn ForwardCommandCall>, ForwardFailure> {
            self.specs.lock().expect("fake specs").push(spec);
            let result = self
                .results
                .lock()
                .expect("fake results")
                .pop_front()
                .expect("queued forward result");
            Ok(Box::new(ImmediateForwardCall {
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

    struct QueuedPortCandidates {
        results: Mutex<VecDeque<Result<NonZeroU16, CandidateFailure>>>,
        requests: Mutex<usize>,
    }

    impl QueuedPortCandidates {
        fn new(results: impl IntoIterator<Item = Result<u16, CandidateFailure>>) -> Self {
            Self {
                results: Mutex::new(
                    results
                        .into_iter()
                        .map(|result| {
                            result.map(|port| NonZeroU16::new(port).expect("nonzero test port"))
                        })
                        .collect(),
                ),
                requests: Mutex::new(0),
            }
        }
    }

    impl PortCandidates for QueuedPortCandidates {
        fn reserve_fresh(
            &self,
            _target: LoopbackAddress,
        ) -> Result<PortReservation, CandidateFailure> {
            *self.requests.lock().expect("candidate requests") += 1;
            self.results
                .lock()
                .expect("candidate results")
                .pop_front()
                .expect("queued candidate result")
                .map(PortReservation::for_test)
        }
    }

    fn prepare(
        command: Arc<FakeForwardCommand>,
        candidates: Arc<dyn PortCandidates>,
        target: LoopbackTarget,
        remote_port: u16,
    ) -> Box<dyn ForwardingPreparation> {
        NumericForwardingController::with_parts(command, candidates)
            .begin_prepare_numeric(
                target,
                NonZeroU16::new(remote_port).expect("nonzero remote port"),
            )
            .expect("begin numeric preparation")
    }

    #[test]
    fn preferred_port_reaches_ssh_before_fallback_candidate_selection() {
        let command = Arc::new(FakeForwardCommand::new([Ok(())]));
        let candidates = Arc::new(QueuedPortCandidates::new([]));
        let mut operation = prepare(
            command.clone(),
            candidates.clone(),
            LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST),
            8080,
        );

        assert_eq!(
            operation.poll(),
            Some(Ok(NonZeroU16::new(8080).expect("port")))
        );
        assert_eq!(*candidates.requests.lock().expect("requests"), 0);
        assert_eq!(command.specs.lock().expect("specs")[0].local_port, 8080);
    }

    #[test]
    fn clean_preferred_bind_failure_remaps_exact_ipv6_forward() {
        let command = Arc::new(FakeForwardCommand::new([
            Err(ForwardFailure::BindFailed),
            Ok(()),
        ]));
        let candidates = Arc::new(QueuedPortCandidates::new([Ok(43_123)]));
        let mut operation = prepare(command.clone(), candidates, LoopbackTarget::Ipv6, 3000);

        assert_eq!(
            operation.poll(),
            Some(Ok(NonZeroU16::new(43_123).expect("port")))
        );
        assert_eq!(
            *command.specs.lock().expect("specs"),
            vec![
                forward_spec(
                    LoopbackAddress::Ipv6,
                    NonZeroU16::new(3000).expect("port"),
                    NonZeroU16::new(3000).expect("port"),
                ),
                forward_spec(
                    LoopbackAddress::Ipv6,
                    NonZeroU16::new(43_123).expect("port"),
                    NonZeroU16::new(3000).expect("port"),
                ),
            ]
        );
    }

    #[test]
    fn fifth_fresh_ssh_candidate_can_succeed_after_four_race_collisions() {
        let command = Arc::new(FakeForwardCommand::new([
            Err(ForwardFailure::BindFailed),
            Err(ForwardFailure::BindFailed),
            Err(ForwardFailure::BindFailed),
            Err(ForwardFailure::BindFailed),
            Err(ForwardFailure::BindFailed),
            Ok(()),
        ]));
        let candidates = Arc::new(QueuedPortCandidates::new([
            Ok(40_001),
            Ok(40_002),
            Ok(40_003),
            Ok(40_004),
            Ok(40_005),
        ]));
        let mut operation = prepare(
            command.clone(),
            candidates,
            LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST),
            8080,
        );

        assert_eq!(
            operation.poll(),
            Some(Ok(NonZeroU16::new(40_005).expect("port")))
        );
        assert_eq!(command.specs.lock().expect("specs").len(), 6);
    }

    #[test]
    fn five_os_candidate_collisions_exhaust_without_an_unbounded_selection_loop() {
        let command = Arc::new(FakeForwardCommand::new([Err(ForwardFailure::BindFailed)]));
        let candidates = Arc::new(QueuedPortCandidates::new(std::iter::repeat_n(
            Err(CandidateFailure::Collision),
            5,
        )));
        let mut operation = prepare(
            command.clone(),
            candidates.clone(),
            LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST),
            8080,
        );

        assert_eq!(
            operation.poll(),
            Some(Err(ForwardingPreparationError::BindExhausted))
        );
        assert_eq!(*candidates.requests.lock().expect("requests"), 5);
        assert_eq!(command.specs.lock().expect("specs").len(), 1);
    }

    #[test]
    fn five_fresh_ssh_bind_failures_exhaust_without_a_sixth_candidate() {
        let command = Arc::new(FakeForwardCommand::new(std::iter::repeat_n(
            Err(ForwardFailure::BindFailed),
            6,
        )));
        let candidates = Arc::new(QueuedPortCandidates::new([
            Ok(40_001),
            Ok(40_002),
            Ok(40_003),
            Ok(40_004),
            Ok(40_005),
        ]));
        let mut operation = prepare(
            command.clone(),
            candidates,
            LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST),
            8080,
        );

        assert_eq!(
            operation.poll(),
            Some(Err(ForwardingPreparationError::BindExhausted))
        );
        assert_eq!(command.specs.lock().expect("specs").len(), 6);
    }

    #[test]
    fn owned_rejection_and_timeout_do_not_select_a_fallback() {
        for (failure, expected) in [
            (
                ForwardFailure::AlreadyOwned,
                ForwardingPreparationError::CommandRejected,
            ),
            (
                ForwardFailure::CommandRejected,
                ForwardingPreparationError::CommandRejected,
            ),
            (
                ForwardFailure::CommandTimedOut,
                ForwardingPreparationError::CommandTimedOut,
            ),
        ] {
            let command = Arc::new(FakeForwardCommand::new([Err(failure)]));
            let candidates = Arc::new(QueuedPortCandidates::new([]));
            let mut operation = prepare(
                command,
                candidates.clone(),
                LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST),
                9000,
            );

            assert_eq!(operation.poll(), Some(Err(expected)));
            assert_eq!(*candidates.requests.lock().expect("requests"), 0);
        }
    }

    #[test]
    fn cancelling_an_unsettled_operation_cancels_the_active_command() {
        struct BlockedCall {
            cancelled: Arc<Mutex<usize>>,
        }
        impl ForwardCommandCall for BlockedCall {
            fn poll(&mut self) -> Option<Result<(), ForwardFailure>> {
                None
            }
            fn cancel(&mut self) {
                *self.cancelled.lock().expect("cancel count") += 1;
            }
        }
        struct BlockedCommand {
            cancelled: Arc<Mutex<usize>>,
        }
        impl ForwardCommand for BlockedCommand {
            fn begin_forward(
                &self,
                _spec: ForwardSpec,
            ) -> Result<Box<dyn ForwardCommandCall>, ForwardFailure> {
                Ok(Box::new(BlockedCall {
                    cancelled: Arc::clone(&self.cancelled),
                }))
            }
            fn begin_set_enabled(
                &self,
                _enabled: bool,
            ) -> Result<Box<dyn PolicyCommandCall>, ForwardFailure> {
                unreachable!()
            }
        }

        let cancelled = Arc::new(Mutex::new(0));
        let controller = NumericForwardingController::with_parts(
            Arc::new(BlockedCommand {
                cancelled: Arc::clone(&cancelled),
            }),
            Arc::new(QueuedPortCandidates::new([])),
        );
        let mut operation = controller
            .begin_prepare_numeric(
                LoopbackTarget::Ipv4(Ipv4Addr::LOCALHOST),
                NonZeroU16::new(8080).expect("port"),
            )
            .expect("begin");

        assert_eq!(operation.poll(), None);
        operation.cancel();
        assert_eq!(*cancelled.lock().expect("cancel count"), 1);
        assert_eq!(operation.poll(), None);
    }
}
