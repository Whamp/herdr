use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

use super::protocol::{CorrelationId, ForwardFailure, ForwardSpec, LoopbackAddress};
use super::worker::{ControlOperation, LocalhostPairSpec};

const FALLBACK_CANDIDATES: usize = 5;
const QUARANTINE_DURATION: Duration = Duration::from_secs(5 * 60);
const QUARANTINE_LIMIT: usize = 64;

trait MonotonicClock: Send + Sync {
    fn now(&self) -> Duration;
}

struct SystemMonotonicClock {
    origin: Instant,
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum MappingTarget {
    Scalar(LoopbackAddress),
    Localhost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateFailure {
    Collision,
    Unavailable,
}

struct PortReservation {
    port: u16,
    _listener: Option<TcpListener>,
}

trait PortCandidates: Send + Sync {
    fn reserve_fresh(&self, target: MappingTarget) -> Result<PortReservation, CandidateFailure>;
}

struct SystemPortCandidates;

impl PortCandidates for SystemPortCandidates {
    fn reserve_fresh(&self, target: MappingTarget) -> Result<PortReservation, CandidateFailure> {
        let address = match target {
            MappingTarget::Scalar(LoopbackAddress::Ipv4(octets)) => {
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            MappingTarget::Scalar(LoopbackAddress::Ipv6) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            MappingTarget::Localhost => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let listener = TcpListener::bind(SocketAddr::new(address, 0)).map_err(candidate_failure)?;
        let port = listener
            .local_addr()
            .ok()
            .map(|address| address.port())
            .filter(|port| *port != 0)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MappingIdentity {
    target: MappingTarget,
    remote_port: u16,
}

impl MappingIdentity {
    pub(super) fn scalar(target: LoopbackAddress, remote_port: u16) -> Option<Self> {
        (target.is_valid() && remote_port != 0).then_some(Self {
            target: MappingTarget::Scalar(target),
            remote_port,
        })
    }

    pub(super) fn localhost(remote_port: u16) -> Option<Self> {
        (remote_port != 0).then_some(Self {
            target: MappingTarget::Localhost,
            remote_port,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListenerSpec {
    Scalar(ForwardSpec),
    Localhost(LocalhostPairSpec),
}

impl ListenerSpec {
    pub(super) const fn local_port(self) -> u16 {
        match self {
            Self::Scalar(spec) => spec.local_port,
            Self::Localhost(pair) => pair.local_port(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MappingAttempt {
    controller_id: CorrelationId,
    identity: MappingIdentity,
    generation: u64,
    spec: ListenerSpec,
}

impl MappingAttempt {
    pub(super) const fn controller_id(self) -> CorrelationId {
        self.controller_id
    }

    pub(super) const fn operation(self) -> ControlOperation {
        match self.spec {
            ListenerSpec::Scalar(spec) => ControlOperation::Forward(spec),
            ListenerSpec::Localhost(pair) => ControlOperation::ForwardPair(pair),
        }
    }

    pub(super) const fn cancellation(self) -> ControlOperation {
        match self.spec {
            ListenerSpec::Scalar(spec) => ControlOperation::Cancel(spec),
            ListenerSpec::Localhost(pair) => ControlOperation::CancelPair(pair),
        }
    }

    #[cfg(test)]
    pub(super) const fn local_port(self) -> u16 {
        self.spec.local_port()
    }

    pub(super) const fn is_localhost(self) -> bool {
        matches!(self.spec, ListenerSpec::Localhost(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MappingSettlement {
    pub(super) id: CorrelationId,
    pub(super) result: Result<u16, ForwardFailure>,
}

impl MappingSettlement {
    pub(super) const fn ready(id: CorrelationId, local_port: u16) -> Self {
        Self {
            id,
            result: Ok(local_port),
        }
    }

    pub(super) const fn failed(id: CorrelationId, failure: ForwardFailure) -> Self {
        Self {
            id,
            result: Err(failure),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MappingRequest {
    Ready(MappingSettlement),
    Pending { attempt: Option<MappingAttempt> },
    Failed(MappingSettlement),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MappingControlResult {
    Succeeded,
    BindFailed,
    Rejected,
    TimedOut,
    PairSucceeded,
    PairFirstBindFailed,
    PairFirstFailed,
    PairFirstTimedOut,
    PairSecondFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RevokedWaiter {
    pub(super) localhost: bool,
    pub(super) settlement: MappingSettlement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaiterCancellation {
    NotFound,
    Removed,
    AbandonedBeforeStart(MappingAttempt),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct MappingCompletion {
    pub(super) attempt: Option<MappingAttempt>,
    pub(super) cancellation: Option<MappingAttempt>,
    pub(super) settlements: Vec<MappingSettlement>,
}

#[derive(Debug)]
enum MappingState {
    Creating {
        attempt: MappingAttempt,
        waiters: BTreeSet<CorrelationId>,
        fallback_attempts: usize,
        started: bool,
        revoked: bool,
    },
    Ready {
        spec: ListenerSpec,
        generation: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct QuarantinedPort {
    port: u16,
    expires_at: Duration,
}

pub(super) struct MappingRegistry {
    mappings: BTreeMap<MappingIdentity, MappingState>,
    quarantine: VecDeque<QuarantinedPort>,
    candidates: Arc<dyn PortCandidates>,
    clock: Arc<dyn MonotonicClock>,
    generation: u64,
    master_live: bool,
}

impl Default for MappingRegistry {
    fn default() -> Self {
        Self {
            mappings: BTreeMap::new(),
            quarantine: VecDeque::new(),
            candidates: Arc::new(SystemPortCandidates),
            clock: Arc::new(SystemMonotonicClock::default()),
            generation: 1,
            master_live: true,
        }
    }
}

impl MappingRegistry {
    pub(super) fn request_scalar(
        &mut self,
        id: CorrelationId,
        address: LoopbackAddress,
        remote_port: u16,
    ) -> MappingRequest {
        let Some(identity) = MappingIdentity::scalar(address, remote_port) else {
            return MappingRequest::Failed(MappingSettlement::failed(
                id,
                ForwardFailure::CommandRejected,
            ));
        };
        let spec = ListenerSpec::Scalar(ForwardSpec {
            local_address: address,
            local_port: remote_port,
            remote_address: address,
            remote_port,
        });
        self.request(id, identity, spec, 0)
    }

    pub(super) fn request_localhost(
        &mut self,
        id: CorrelationId,
        remote_port: u16,
    ) -> MappingRequest {
        let Some(identity) = MappingIdentity::localhost(remote_port) else {
            return MappingRequest::Failed(MappingSettlement::failed(
                id,
                ForwardFailure::CommandRejected,
            ));
        };
        if let Some(request) = self.request_existing(id, identity) {
            return request;
        }
        let (spec, fallback_attempts) = if self.is_quarantined(remote_port) {
            let mut fallback_attempts = 0;
            match self.fresh_attempt(id, identity, &mut fallback_attempts) {
                Ok(attempt) => (attempt.spec, fallback_attempts),
                Err(failure) => {
                    return MappingRequest::Failed(MappingSettlement::failed(id, failure));
                }
            }
        } else {
            let Some(pair) = LocalhostPairSpec::new(remote_port, remote_port) else {
                return MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CommandRejected,
                ));
            };
            (ListenerSpec::Localhost(pair), 0)
        };
        self.request(id, identity, spec, fallback_attempts)
    }

    fn request_existing(
        &mut self,
        id: CorrelationId,
        identity: MappingIdentity,
    ) -> Option<MappingRequest> {
        if !self.master_live {
            return Some(MappingRequest::Failed(MappingSettlement::failed(
                id,
                ForwardFailure::CapabilityClosed,
            )));
        }
        self.mappings
            .get_mut(&identity)
            .map(|mapping| match mapping {
                MappingState::Creating { waiters, .. } => {
                    waiters.insert(id);
                    MappingRequest::Pending { attempt: None }
                }
                MappingState::Ready { spec, generation } if *generation == self.generation => {
                    MappingRequest::Ready(MappingSettlement::ready(id, spec.local_port()))
                }
                MappingState::Ready { .. } => MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CapabilityClosed,
                )),
            })
    }

    fn request(
        &mut self,
        id: CorrelationId,
        identity: MappingIdentity,
        initial_spec: ListenerSpec,
        fallback_attempts: usize,
    ) -> MappingRequest {
        if let Some(request) = self.request_existing(id, identity) {
            return request;
        }
        let attempt = MappingAttempt {
            controller_id: id,
            identity,
            generation: self.generation,
            spec: initial_spec,
        };
        self.mappings.insert(
            identity,
            MappingState::Creating {
                attempt,
                waiters: BTreeSet::from([id]),
                fallback_attempts,
                started: false,
                revoked: false,
            },
        );
        MappingRequest::Pending {
            attempt: Some(attempt),
        }
    }

    pub(super) fn start(&mut self, attempt: MappingAttempt) -> bool {
        let Some(MappingState::Creating {
            attempt: current,
            started,
            ..
        }) = self.mappings.get_mut(&attempt.identity)
        else {
            return false;
        };
        if *current != attempt || attempt.generation != self.generation || !self.master_live {
            return false;
        }
        *started = true;
        true
    }

    pub(super) fn waiter_count(&self) -> usize {
        self.mappings
            .values()
            .map(|mapping| match mapping {
                MappingState::Creating { waiters, .. } => waiters.len(),
                MappingState::Ready { .. } => 0,
            })
            .sum()
    }

    pub(super) fn revoke_creating(&mut self) -> Vec<RevokedWaiter> {
        let mut settlements = Vec::new();
        for mapping in self.mappings.values_mut() {
            if let MappingState::Creating {
                attempt,
                waiters,
                revoked,
                ..
            } = mapping
            {
                settlements.extend(waiters.iter().copied().map(|id| RevokedWaiter {
                    localhost: attempt.is_localhost(),
                    settlement: MappingSettlement::failed(id, ForwardFailure::Cancelled),
                }));
                waiters.clear();
                *revoked = true;
            }
        }
        settlements
    }

    pub(super) fn master_died(&mut self) -> Vec<MappingSettlement> {
        self.master_live = false;
        self.quarantine.clear();
        let mappings = std::mem::take(&mut self.mappings);
        mappings
            .into_values()
            .flat_map(|mapping| match mapping {
                MappingState::Creating { waiters, .. } => waiters
                    .into_iter()
                    .map(|id| MappingSettlement::failed(id, ForwardFailure::CapabilityClosed))
                    .collect::<Vec<_>>(),
                MappingState::Ready { .. } => Vec::new(),
            })
            .collect()
    }

    #[cfg(test)]
    pub(super) fn replace_master(&mut self) -> bool {
        let Some(generation) = self.generation.checked_add(1) else {
            return false;
        };
        self.mappings.clear();
        self.quarantine.clear();
        self.generation = generation;
        self.master_live = true;
        true
    }

    pub(super) fn cancel_waiter(&mut self, id: CorrelationId) -> WaiterCancellation {
        let identity = self.mappings.iter().find_map(|(identity, mapping)| {
            let MappingState::Creating { waiters, .. } = mapping else {
                return None;
            };
            waiters.contains(&id).then_some(*identity)
        });
        let Some(identity) = identity else {
            return WaiterCancellation::NotFound;
        };
        let Some(MappingState::Creating {
            attempt,
            waiters,
            started,
            ..
        }) = self.mappings.get_mut(&identity)
        else {
            return WaiterCancellation::NotFound;
        };
        waiters.remove(&id);
        if waiters.is_empty() && !*started {
            let abandoned = *attempt;
            self.mappings.remove(&identity);
            WaiterCancellation::AbandonedBeforeStart(abandoned)
        } else {
            WaiterCancellation::Removed
        }
    }

    pub(super) fn complete(
        &mut self,
        attempt: MappingAttempt,
        result: MappingControlResult,
    ) -> MappingCompletion {
        if attempt.generation != self.generation || !self.master_live {
            return MappingCompletion::default();
        }
        let Some(mapping) = self.mappings.remove(&attempt.identity) else {
            return MappingCompletion::default();
        };
        let MappingState::Creating {
            attempt: current,
            waiters,
            mut fallback_attempts,
            started,
            revoked,
        } = mapping
        else {
            self.mappings.insert(attempt.identity, mapping);
            return MappingCompletion::default();
        };
        if current != attempt {
            self.mappings.insert(
                attempt.identity,
                MappingState::Creating {
                    attempt: current,
                    waiters,
                    fallback_attempts,
                    started,
                    revoked,
                },
            );
            return MappingCompletion::default();
        }
        let failure = match (attempt.spec, result) {
            (ListenerSpec::Scalar(_), MappingControlResult::Succeeded)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairSucceeded)
                if revoked =>
            {
                return MappingCompletion {
                    attempt: None,
                    cancellation: Some(attempt),
                    settlements: Vec::new(),
                };
            }
            (ListenerSpec::Scalar(_), MappingControlResult::Succeeded)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairSucceeded) => {
                let settlements = waiters
                    .iter()
                    .copied()
                    .map(|id| MappingSettlement::ready(id, attempt.spec.local_port()))
                    .collect();
                self.mappings.insert(
                    attempt.identity,
                    MappingState::Ready {
                        spec: attempt.spec,
                        generation: attempt.generation,
                    },
                );
                return MappingCompletion {
                    attempt: None,
                    cancellation: None,
                    settlements,
                };
            }
            (ListenerSpec::Scalar(_), MappingControlResult::BindFailed)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairFirstBindFailed)
                if !waiters.is_empty() =>
            {
                match self.fresh_attempt(
                    attempt.controller_id,
                    attempt.identity,
                    &mut fallback_attempts,
                ) {
                    Ok(next) => {
                        self.mappings.insert(
                            attempt.identity,
                            MappingState::Creating {
                                attempt: next,
                                waiters,
                                fallback_attempts,
                                started: false,
                                revoked,
                            },
                        );
                        return MappingCompletion {
                            attempt: Some(next),
                            cancellation: None,
                            settlements: Vec::new(),
                        };
                    }
                    Err(failure) => failure,
                }
            }
            (ListenerSpec::Scalar(_), MappingControlResult::BindFailed)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairFirstBindFailed) => {
                ForwardFailure::BindFailed
            }
            (ListenerSpec::Scalar(_), MappingControlResult::Rejected)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairFirstFailed) => {
                ForwardFailure::CommandRejected
            }
            (ListenerSpec::Scalar(_), MappingControlResult::TimedOut)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairFirstTimedOut) => {
                ForwardFailure::CommandTimedOut
            }
            (ListenerSpec::Localhost(_), MappingControlResult::PairSecondFailed) => {
                self.quarantine(attempt.spec.local_port());
                ForwardFailure::AtomicCreationFailed
            }
            _ => ForwardFailure::CommandRejected,
        };
        MappingCompletion {
            attempt: None,
            cancellation: None,
            settlements: waiters
                .into_iter()
                .map(|id| MappingSettlement::failed(id, failure))
                .collect(),
        }
    }

    fn fresh_attempt(
        &mut self,
        controller_id: CorrelationId,
        identity: MappingIdentity,
        fallback_attempts: &mut usize,
    ) -> Result<MappingAttempt, ForwardFailure> {
        while *fallback_attempts < FALLBACK_CANDIDATES {
            *fallback_attempts += 1;
            let reservation = match self.candidates.reserve_fresh(identity.target) {
                Ok(reservation) => reservation,
                Err(CandidateFailure::Collision) => continue,
                Err(CandidateFailure::Unavailable) => {
                    return Err(ForwardFailure::CommandRejected);
                }
            };
            let local_port = reservation.port;
            if identity.target == MappingTarget::Localhost && self.is_quarantined(local_port) {
                drop(reservation);
                continue;
            }
            drop(reservation);
            let spec = match identity.target {
                MappingTarget::Scalar(address) => ListenerSpec::Scalar(ForwardSpec {
                    local_address: address,
                    local_port,
                    remote_address: address,
                    remote_port: identity.remote_port,
                }),
                MappingTarget::Localhost => ListenerSpec::Localhost(
                    LocalhostPairSpec::new(local_port, identity.remote_port)
                        .ok_or(ForwardFailure::CommandRejected)?,
                ),
            };
            return Ok(MappingAttempt {
                controller_id,
                identity,
                generation: self.generation,
                spec,
            });
        }
        Err(ForwardFailure::BindFailed)
    }

    fn quarantine(&mut self, port: u16) {
        self.expire_quarantine();
        self.quarantine.retain(|entry| entry.port != port);
        let expires_at = self
            .clock
            .now()
            .checked_add(QUARANTINE_DURATION)
            .unwrap_or(Duration::MAX);
        self.quarantine
            .push_back(QuarantinedPort { port, expires_at });
        while self.quarantine.len() > QUARANTINE_LIMIT {
            self.quarantine.pop_front();
        }
    }

    fn is_quarantined(&mut self, port: u16) -> bool {
        self.expire_quarantine();
        self.quarantine.iter().any(|entry| entry.port == port)
    }

    fn expire_quarantine(&mut self) {
        let now = self.clock.now();
        self.quarantine.retain(|entry| now < entry.expires_at);
    }

    #[cfg(test)]
    fn for_test(fallback_ports: impl IntoIterator<Item = Result<u16, CandidateFailure>>) -> Self {
        Self::for_test_with_clock(fallback_ports, Arc::new(FakeMonotonicClock::default()))
    }

    #[cfg(test)]
    fn for_test_with_clock(
        fallback_ports: impl IntoIterator<Item = Result<u16, CandidateFailure>>,
        clock: Arc<FakeMonotonicClock>,
    ) -> Self {
        Self {
            candidates: Arc::new(QueuedPortCandidates {
                results: Mutex::new(fallback_ports.into_iter().collect()),
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            clock,
            ..Self::default()
        }
    }

    #[cfg(test)]
    fn for_test_with_candidate_calls(
        fallback_ports: impl IntoIterator<Item = Result<u16, CandidateFailure>>,
    ) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                candidates: Arc::new(QueuedPortCandidates {
                    results: Mutex::new(fallback_ports.into_iter().collect()),
                    calls: Arc::clone(&calls),
                }),
                ..Self::default()
            },
            calls,
        )
    }

    #[cfg(test)]
    pub(super) fn for_broker_test(
        fallback_ports: impl IntoIterator<Item = u16>,
    ) -> (Self, Arc<AtomicUsize>) {
        Self::for_test_with_candidate_calls(fallback_ports.into_iter().map(Ok))
    }

    #[cfg(test)]
    fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

#[cfg(test)]
#[derive(Default)]
struct FakeMonotonicClock {
    now_seconds: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl FakeMonotonicClock {
    fn set(&self, now: Duration) {
        self.now_seconds
            .store(now.as_secs(), std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
impl MonotonicClock for FakeMonotonicClock {
    fn now(&self) -> Duration {
        Duration::from_secs(self.now_seconds.load(std::sync::atomic::Ordering::Acquire))
    }
}

#[cfg(test)]
struct QueuedPortCandidates {
    results: Mutex<VecDeque<Result<u16, CandidateFailure>>>,
    calls: Arc<AtomicUsize>,
}

#[cfg(test)]
impl PortCandidates for QueuedPortCandidates {
    fn reserve_fresh(&self, _target: MappingTarget) -> Result<PortReservation, CandidateFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.results
            .lock()
            .expect("candidate results")
            .pop_front()
            .ok_or(CandidateFailure::Unavailable)?
            .map(|port| PortReservation {
                port,
                _listener: None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::forwarding::protocol::LoopbackAddress;

    #[test]
    fn mapping_identity_uses_only_preserved_target_and_effective_remote_port() {
        let ipv4 = MappingIdentity::scalar(LoopbackAddress::Ipv4([127, 0, 0, 42]), 8080)
            .expect("valid identity");

        assert_eq!(
            ipv4,
            MappingIdentity::scalar(LoopbackAddress::Ipv4([127, 0, 0, 42]), 8080)
                .expect("same identity")
        );
        assert_ne!(
            ipv4,
            MappingIdentity::scalar(LoopbackAddress::Ipv4([127, 0, 0, 43]), 8080)
                .expect("different numeric identity")
        );
        assert_ne!(
            ipv4,
            MappingIdentity::scalar(LoopbackAddress::Ipv4([127, 0, 0, 42]), 8081)
                .expect("different port identity")
        );
        assert_ne!(
            ipv4,
            MappingIdentity::localhost(8080).expect("localhost pair identity")
        );
    }

    #[test]
    fn scalar_requests_coalesce_and_reuse_one_ready_mapping() {
        let mut registry = MappingRegistry::for_test([]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let third = CorrelationId::new(3).expect("id");
        let address = LoopbackAddress::Ipv4([127, 0, 0, 42]);

        let MappingRequest::Pending {
            attempt: Some(attempt),
        } = registry.request_scalar(first, address, 8080)
        else {
            panic!("first waiter starts one attempt");
        };
        assert_eq!(
            registry.request_scalar(second, address, 8080),
            MappingRequest::Pending { attempt: None }
        );
        assert!(registry.start(attempt));

        let completed = registry.complete(attempt, MappingControlResult::Succeeded);
        assert_eq!(
            completed.settlements,
            vec![
                MappingSettlement::ready(first, 8080),
                MappingSettlement::ready(second, 8080),
            ]
        );
        assert_eq!(
            registry.request_scalar(third, address, 8080),
            MappingRequest::Ready(MappingSettlement::ready(third, 8080))
        );
        assert_eq!(registry.mapping_count(), 1);
    }

    #[test]
    fn scalar_failure_is_common_to_waiters_and_a_later_request_retries_fresh() {
        let mut registry = MappingRegistry::for_test([Ok(43_123)]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let address = LoopbackAddress::Ipv6;
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_scalar(first, address, 8080)
        else {
            panic!("preferred attempt");
        };
        assert!(matches!(
            registry.request_scalar(second, address, 8080),
            MappingRequest::Pending { attempt: None }
        ));
        assert!(registry.start(preferred));

        let fallback = registry.complete(preferred, MappingControlResult::BindFailed);
        let remapped = fallback.attempt.expect("one shared fallback");
        assert_eq!(remapped.local_port(), 43_123);
        assert!(fallback.settlements.is_empty());
        assert!(registry.start(remapped));
        let failed = registry.complete(remapped, MappingControlResult::Rejected);
        assert_eq!(
            failed.settlements,
            vec![
                MappingSettlement::failed(first, ForwardFailure::CommandRejected),
                MappingSettlement::failed(second, ForwardFailure::CommandRejected),
            ]
        );
        assert_eq!(registry.mapping_count(), 0);

        let third = CorrelationId::new(3).expect("id");
        let MappingRequest::Pending {
            attempt: Some(retry),
        } = registry.request_scalar(third, address, 8080)
        else {
            panic!("fresh retry");
        };
        assert_eq!(retry.local_port(), 8080);
    }

    #[test]
    fn localhost_requests_share_one_atomic_attempt_and_ready_pair() {
        let mut registry = MappingRegistry::for_test([]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let third = CorrelationId::new(3).expect("id");
        let MappingRequest::Pending {
            attempt: Some(pair),
        } = registry.request_localhost(first, 8080)
        else {
            panic!("pair attempt");
        };
        assert!(pair.is_localhost());
        assert_eq!(
            registry.request_localhost(second, 8080),
            MappingRequest::Pending { attempt: None }
        );
        assert!(registry.start(pair));

        let completed = registry.complete(pair, MappingControlResult::PairSucceeded);
        assert_eq!(
            completed.settlements,
            vec![
                MappingSettlement::ready(first, 8080),
                MappingSettlement::ready(second, 8080),
            ]
        );
        assert_eq!(
            registry.request_localhost(third, 8080),
            MappingRequest::Ready(MappingSettlement::ready(third, 8080))
        );
        assert_eq!(registry.mapping_count(), 1);
    }

    #[test]
    fn cancellation_removes_only_its_waiter_and_respects_indivisible_start() {
        let mut registry = MappingRegistry::for_test([]);
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(shared),
        } = registry.request_scalar(first, address, 8001)
        else {
            panic!("shared attempt");
        };
        let _ = registry.request_scalar(second, address, 8001);
        assert!(registry.start(shared));
        assert_eq!(registry.cancel_waiter(first), WaiterCancellation::Removed);
        assert_eq!(
            registry
                .complete(shared, MappingControlResult::Succeeded)
                .settlements,
            vec![MappingSettlement::ready(second, 8001)]
        );

        let before = CorrelationId::new(3).expect("id");
        let MappingRequest::Pending {
            attempt: Some(queued),
        } = registry.request_scalar(before, address, 8002)
        else {
            panic!("queued attempt");
        };
        assert_eq!(
            registry.cancel_waiter(before),
            WaiterCancellation::AbandonedBeforeStart(queued)
        );
        assert!(!registry.start(queued));

        let after = CorrelationId::new(4).expect("id");
        let MappingRequest::Pending {
            attempt: Some(running_pair),
        } = registry.request_localhost(after, 8003)
        else {
            panic!("running pair");
        };
        assert!(registry.start(running_pair));
        assert_eq!(registry.cancel_waiter(after), WaiterCancellation::Removed);
        assert!(registry
            .complete(running_pair, MappingControlResult::PairSucceeded)
            .settlements
            .is_empty());
        assert!(matches!(
            registry.request_localhost(CorrelationId::new(5).expect("id"), 8003),
            MappingRequest::Ready(_)
        ));
    }

    #[test]
    fn localhost_first_member_fallback_preserves_timeout_and_stops_without_waiters() {
        let mut registry = MappingRegistry::for_test([Ok(43_123)]);
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(id, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));
        let fallback = registry.complete(preferred, MappingControlResult::PairFirstBindFailed);
        let remapped = fallback.attempt.expect("fallback pair");
        assert_eq!(remapped.local_port(), 43_123);
        assert!(registry.start(remapped));
        assert_eq!(
            registry
                .complete(remapped, MappingControlResult::PairFirstTimedOut)
                .settlements,
            vec![MappingSettlement::failed(
                id,
                ForwardFailure::CommandTimedOut
            )]
        );

        let mut no_waiters = MappingRegistry::for_test([Ok(44_000)]);
        let cancelled = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(running),
        } = no_waiters.request_localhost(cancelled, 8081)
        else {
            panic!("running pair");
        };
        assert!(no_waiters.start(running));
        assert_eq!(
            no_waiters.cancel_waiter(cancelled),
            WaiterCancellation::Removed
        );
        assert_eq!(
            no_waiters.complete(running, MappingControlResult::PairFirstBindFailed),
            MappingCompletion::default()
        );
        assert_eq!(no_waiters.mapping_count(), 0);
    }

    #[test]
    fn partial_localhost_failure_quarantines_the_candidate_for_the_next_click() {
        let mut registry = MappingRegistry::for_test([Ok(43_123)]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(pair),
        } = registry.request_localhost(first, 8080)
        else {
            panic!("pair");
        };
        let _ = registry.request_localhost(second, 8080);
        assert!(registry.start(pair));

        assert_eq!(
            registry
                .complete(pair, MappingControlResult::PairSecondFailed)
                .settlements,
            vec![
                MappingSettlement::failed(first, ForwardFailure::AtomicCreationFailed),
                MappingSettlement::failed(second, ForwardFailure::AtomicCreationFailed),
            ]
        );
        let MappingRequest::Pending {
            attempt: Some(retry),
        } = registry.request_localhost(CorrelationId::new(3).expect("id"), 8080)
        else {
            panic!("retry");
        };
        assert_eq!(retry.local_port(), 43_123);
    }

    #[test]
    fn quarantined_preferred_port_does_not_hide_a_remapped_creating_mapping() {
        let (mut registry, candidate_calls) =
            MappingRegistry::for_test_with_candidate_calls([Ok(43_123)]);
        let failed = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(failed, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));
        let _ = registry.complete(preferred, MappingControlResult::PairSecondFailed);

        let owner = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(remapped),
        } = registry.request_localhost(owner, 8080)
        else {
            panic!("remapped pair");
        };
        assert_eq!(remapped.local_port(), 43_123);
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 1);

        let joined = CorrelationId::new(3).expect("id");
        assert_eq!(
            registry.request_localhost(joined, 8080),
            MappingRequest::Pending { attempt: None }
        );
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn quarantined_preferred_port_does_not_hide_a_remapped_ready_mapping() {
        let (mut registry, candidate_calls) =
            MappingRegistry::for_test_with_candidate_calls([Ok(43_123)]);
        let failed = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(failed, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));
        let _ = registry.complete(preferred, MappingControlResult::PairSecondFailed);

        let owner = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(remapped),
        } = registry.request_localhost(owner, 8080)
        else {
            panic!("remapped pair");
        };
        assert_eq!(remapped.local_port(), 43_123);
        assert!(registry.start(remapped));
        assert_eq!(
            registry
                .complete(remapped, MappingControlResult::PairSucceeded)
                .settlements,
            vec![MappingSettlement::ready(owner, 43_123)]
        );
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 1);

        let reused = CorrelationId::new(3).expect("id");
        assert_eq!(
            registry.request_localhost(reused, 8080),
            MappingRequest::Ready(MappingSettlement::ready(reused, 43_123))
        );
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 1);

        let _ = registry.master_died();
        let after_master_death = CorrelationId::new(4).expect("id");
        assert_eq!(
            registry.request_localhost(after_master_death, 8080),
            MappingRequest::Failed(MappingSettlement::failed(
                after_master_death,
                ForwardFailure::CapabilityClosed,
            ))
        );
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn quarantine_lookup_remains_isolated_by_mapping_identity() {
        let (mut registry, candidate_calls) = MappingRegistry::for_test_with_candidate_calls([
            Ok(43_123),
            Err(CandidateFailure::Unavailable),
        ]);
        registry.quarantine(8080);
        let first = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(remapped),
        } = registry.request_localhost(first, 8080)
        else {
            panic!("remapped pair");
        };
        assert!(registry.start(remapped));
        let _ = registry.complete(remapped, MappingControlResult::PairSucceeded);
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 1);

        registry.quarantine(9090);
        let isolated = CorrelationId::new(2).expect("id");
        assert_eq!(
            registry.request_localhost(isolated, 9090),
            MappingRequest::Failed(MappingSettlement::failed(
                isolated,
                ForwardFailure::CommandRejected,
            ))
        );
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 2);

        let reused = CorrelationId::new(3).expect("id");
        assert_eq!(
            registry.request_localhost(reused, 8080),
            MappingRequest::Ready(MappingSettlement::ready(reused, 43_123))
        );
        assert_eq!(candidate_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn master_death_fails_waiters_and_rejects_generation_stale_completion() {
        let mut registry = MappingRegistry::for_test([]);
        let address = LoopbackAddress::Ipv4([127, 0, 0, 42]);
        let quarantined_id = CorrelationId::new(9).expect("id");
        let MappingRequest::Pending {
            attempt: Some(quarantined),
        } = registry.request_localhost(quarantined_id, 9000)
        else {
            panic!("quarantine candidate");
        };
        assert!(registry.start(quarantined));
        let _ = registry.complete(quarantined, MappingControlResult::PairSecondFailed);

        let ready_id = CorrelationId::new(10).expect("id");
        let MappingRequest::Pending {
            attempt: Some(ready),
        } = registry.request_scalar(ready_id, address, 9090)
        else {
            panic!("ready candidate");
        };
        assert!(registry.start(ready));
        let _ = registry.complete(ready, MappingControlResult::Succeeded);

        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(stale),
        } = registry.request_scalar(first, address, 8080)
        else {
            panic!("attempt");
        };
        let _ = registry.request_scalar(second, address, 8080);
        assert!(registry.start(stale));

        assert_eq!(
            registry.master_died(),
            vec![
                MappingSettlement::failed(first, ForwardFailure::CapabilityClosed),
                MappingSettlement::failed(second, ForwardFailure::CapabilityClosed),
            ]
        );
        assert_eq!(registry.mapping_count(), 0);
        assert!(registry
            .complete(stale, MappingControlResult::Succeeded)
            .settlements
            .is_empty());
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(3).expect("id"), address, 8080),
            MappingRequest::Failed(MappingSettlement {
                result: Err(ForwardFailure::CapabilityClosed),
                ..
            })
        ));

        assert!(registry.replace_master());
        let MappingRequest::Pending {
            attempt: Some(fresh),
        } = registry.request_scalar(CorrelationId::new(4).expect("id"), address, 8080)
        else {
            panic!("fresh generation");
        };
        assert_ne!(fresh.generation, stale.generation);
        assert!(registry.start(fresh));
        let MappingRequest::Pending {
            attempt: Some(fresh_pair),
        } = registry.request_localhost(CorrelationId::new(5).expect("id"), 9000)
        else {
            panic!("quarantine cleared with master state");
        };
        assert_eq!(fresh_pair.local_port(), 9000);
        assert!(registry
            .complete(stale, MappingControlResult::Succeeded)
            .settlements
            .is_empty());
        assert_eq!(registry.mapping_count(), 2);
    }

    #[test]
    fn five_fresh_candidate_collisions_fail_once_without_a_sixth_attempt() {
        let mut registry = MappingRegistry::for_test(std::iter::repeat_n(
            Err(CandidateFailure::Collision),
            FALLBACK_CANDIDATES,
        ));
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_scalar(id, LoopbackAddress::Ipv6, 8080)
        else {
            panic!("preferred");
        };
        assert!(registry.start(preferred));

        assert_eq!(
            registry.complete(preferred, MappingControlResult::BindFailed),
            MappingCompletion {
                attempt: None,
                cancellation: None,
                settlements: vec![MappingSettlement::failed(id, ForwardFailure::BindFailed)],
            }
        );
        assert_eq!(registry.mapping_count(), 0);
    }

    #[test]
    fn quarantined_fresh_fallback_is_not_emitted_as_an_ssh_attempt() {
        let mut registry = MappingRegistry::for_test([Ok(43_123), Ok(44_123)]);
        registry.quarantine(43_123);
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(id, 8080)
        else {
            panic!("preferred pair");
        };
        let mut ssh_command_ports = Vec::new();
        assert!(registry.start(preferred));
        ssh_command_ports.push(preferred.local_port());

        let fallback = registry.complete(preferred, MappingControlResult::PairFirstBindFailed);
        let next = fallback.attempt.expect("eligible fallback");
        assert!(registry.start(next));
        ssh_command_ports.push(next.local_port());

        assert_eq!(ssh_command_ports, vec![8080, 44_123]);
    }

    #[test]
    fn multiple_quarantined_fallbacks_are_skipped_before_the_next_eligible_candidate() {
        let mut registry = MappingRegistry::for_test([Ok(43_123), Ok(44_123), Ok(45_123)]);
        registry.quarantine(43_123);
        registry.quarantine(44_123);
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(id, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));

        let fallback = registry.complete(preferred, MappingControlResult::PairFirstBindFailed);

        assert_eq!(
            fallback.attempt.map(MappingAttempt::local_port),
            Some(45_123)
        );
    }

    #[test]
    fn all_bounded_fallback_candidates_quarantined_settles_without_a_busy_loop() {
        let quarantined = [43_123, 44_123, 45_123, 46_123, 47_123];
        let mut registry =
            MappingRegistry::for_test(quarantined.into_iter().map(Ok).chain([Ok(48_123)]));
        for port in quarantined {
            registry.quarantine(port);
        }
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(id, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));

        assert_eq!(
            registry.complete(preferred, MappingControlResult::PairFirstBindFailed),
            MappingCompletion {
                attempt: None,
                cancellation: None,
                settlements: vec![MappingSettlement::failed(id, ForwardFailure::BindFailed)],
            }
        );
    }

    #[test]
    fn quarantined_fallback_followed_by_candidate_source_exhaustion_settles_once() {
        let mut registry = MappingRegistry::for_test([Ok(43_123)]);
        registry.quarantine(43_123);
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(id, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));

        assert_eq!(
            registry.complete(preferred, MappingControlResult::PairFirstBindFailed),
            MappingCompletion {
                attempt: None,
                cancellation: None,
                settlements: vec![MappingSettlement::failed(
                    id,
                    ForwardFailure::CommandRejected,
                )],
            }
        );
    }

    #[test]
    fn fresh_fallback_is_eligible_at_exact_lazy_quarantine_expiry() {
        let clock = Arc::new(FakeMonotonicClock::default());
        let mut registry = MappingRegistry::for_test_with_clock([Ok(43_123)], clock.clone());
        registry.quarantine(43_123);
        clock.set(QUARANTINE_DURATION);
        let id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(preferred),
        } = registry.request_localhost(id, 8080)
        else {
            panic!("preferred pair");
        };
        assert!(registry.start(preferred));

        let fallback = registry.complete(preferred, MappingControlResult::PairFirstBindFailed);

        assert_eq!(
            fallback.attempt.map(MappingAttempt::local_port),
            Some(43_123)
        );
    }

    #[test]
    fn localhost_quarantine_expires_at_five_minutes_and_retains_64_recent_ports() {
        let clock = Arc::new(FakeMonotonicClock::default());
        let mut registry = MappingRegistry::for_test_with_clock([Ok(43_123)], clock.clone());
        let first = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(pair),
        } = registry.request_localhost(first, 8080)
        else {
            panic!("pair");
        };
        assert!(registry.start(pair));
        let _ = registry.complete(pair, MappingControlResult::PairSecondFailed);

        clock.set(Duration::from_secs(299));
        let MappingRequest::Pending {
            attempt: Some(before_expiry),
        } = registry.request_localhost(CorrelationId::new(2).expect("id"), 8080)
        else {
            panic!("quarantined retry");
        };
        assert_eq!(before_expiry.local_port(), 43_123);
        assert!(matches!(
            registry.cancel_waiter(CorrelationId::new(2).expect("id")),
            WaiterCancellation::AbandonedBeforeStart(_)
        ));

        clock.set(Duration::from_secs(300));
        let MappingRequest::Pending {
            attempt: Some(at_expiry),
        } = registry.request_localhost(CorrelationId::new(3).expect("id"), 8080)
        else {
            panic!("expired retry");
        };
        assert_eq!(at_expiry.local_port(), 8080);

        let mut bounded = MappingRegistry::for_test([Ok(50_000)]);
        for port in 1..=65_u16 {
            let id = CorrelationId::new(u64::from(port)).expect("id");
            let MappingRequest::Pending {
                attempt: Some(pair),
            } = bounded.request_localhost(id, port)
            else {
                panic!("pair");
            };
            assert!(bounded.start(pair));
            let _ = bounded.complete(pair, MappingControlResult::PairSecondFailed);
        }
        let MappingRequest::Pending {
            attempt: Some(evicted),
        } = bounded.request_localhost(CorrelationId::new(100).expect("id"), 1)
        else {
            panic!("oldest quarantine evicted");
        };
        assert_eq!(evicted.local_port(), 1);
        let _ = bounded.cancel_waiter(CorrelationId::new(100).expect("id"));
        let MappingRequest::Pending {
            attempt: Some(retained),
        } = bounded.request_localhost(CorrelationId::new(101).expect("id"), 2)
        else {
            panic!("recent quarantine retained");
        };
        assert_eq!(retained.local_port(), 50_000);
    }

    #[test]
    fn generated_identity_matrix_settles_each_waiter_exactly_once() {
        let mut registry = MappingRegistry::for_test([]);
        let mut terminal = BTreeSet::new();

        for mapping in 0..32_u64 {
            let base = mapping * 4 + 1;
            let ids = [base, base + 1, base + 2, base + 3]
                .map(|value| CorrelationId::new(value).expect("id"));
            let port = 8_000 + u16::try_from(mapping).expect("bounded mapping");
            let first = if mapping % 2 == 0 {
                registry.request_scalar(
                    ids[0],
                    LoopbackAddress::Ipv4([127, 0, 0, u8::try_from(mapping + 1).expect("octet")]),
                    port,
                )
            } else {
                registry.request_localhost(ids[0], port)
            };
            let MappingRequest::Pending {
                attempt: Some(attempt),
            } = first
            else {
                panic!("first request starts an attempt");
            };
            let joined = if mapping % 2 == 0 {
                let address =
                    LoopbackAddress::Ipv4([127, 0, 0, u8::try_from(mapping + 1).expect("octet")]);
                [ids[1], ids[2]].map(|id| registry.request_scalar(id, address, port))
            } else {
                [ids[1], ids[2]].map(|id| registry.request_localhost(id, port))
            };
            assert!(joined
                .into_iter()
                .all(|request| request == MappingRequest::Pending { attempt: None }));
            assert!(registry.start(attempt));
            assert_eq!(registry.cancel_waiter(ids[1]), WaiterCancellation::Removed);
            assert!(terminal.insert(ids[1]));

            let result = if attempt.is_localhost() {
                MappingControlResult::PairSucceeded
            } else {
                MappingControlResult::Succeeded
            };
            for settlement in registry.complete(attempt, result).settlements {
                assert!(terminal.insert(settlement.id));
            }
            let ready = if mapping % 2 == 0 {
                registry.request_scalar(
                    ids[3],
                    LoopbackAddress::Ipv4([127, 0, 0, u8::try_from(mapping + 1).expect("octet")]),
                    port,
                )
            } else {
                registry.request_localhost(ids[3], port)
            };
            let MappingRequest::Ready(settlement) = ready else {
                panic!("ready reuse");
            };
            assert!(terminal.insert(settlement.id));
        }

        assert_eq!(terminal.len(), 32 * 4);
        assert_eq!(registry.mapping_count(), 32);
    }
}
