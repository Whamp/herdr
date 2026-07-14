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
const MAX_FORWARD_REQUESTS: usize = 32;
const MAX_MAPPING_WAITERS: usize = 8;
const LIFETIME_LISTENER_LIMIT: u16 = 128;

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

    const fn listener_slots(self) -> ListenerSlots {
        match self {
            Self::Scalar(_) => ListenerSlots::SCALAR,
            Self::Localhost(_) => ListenerSlots::ATOMIC_PAIR,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MappingAttempt {
    controller_id: CorrelationId,
    identity: MappingIdentity,
    generation: u64,
    spec: ListenerSpec,
    listener_reservation: Option<ListenerReservation>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SavedLimitChange {
    pub(super) controller_id: CorrelationId,
    pub(super) requested_limit: crate::config::SavedPortForwardLimit,
    pub(super) cancellations: Vec<MappingCancellation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSavedLimit {
    controller_id: CorrelationId,
    requested_limit: crate::config::SavedPortForwardLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MappingCancellation {
    controller_id: CorrelationId,
    spec: ListenerSpec,
}

impl MappingCancellation {
    pub(super) const fn operation(self) -> ControlOperation {
        match self.spec {
            ListenerSpec::Scalar(spec) => ControlOperation::Cancel(spec),
            ListenerSpec::Localhost(pair) => ControlOperation::CancelPair(pair),
        }
    }

    pub(super) const fn controller_id(self) -> CorrelationId {
        self.controller_id
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
    Pending {
        attempt: Option<MappingAttempt>,
    },
    Replacing {
        attempt: MappingAttempt,
        cancellation: MappingCancellation,
    },
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
    pub(super) cancellation_policy: Option<CorrelationId>,
    pub(super) settlements: Vec<MappingSettlement>,
    pub(super) invariant_error: Option<ListenerLedgerInvariant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RequestOrder(u128);

#[derive(Debug)]
struct RequestOrderSequence {
    next: RequestOrder,
}

impl Default for RequestOrderSequence {
    fn default() -> Self {
        Self {
            next: RequestOrder(1),
        }
    }
}

impl RequestOrderSequence {
    fn issue(&mut self) -> RequestOrder {
        let issued = self.next;
        self.next = match issued.0.checked_add(1) {
            Some(next) => RequestOrder(next),
            None => panic!("mapping request order space exhausted"),
        };
        issued
    }
}

#[derive(Debug)]
enum MappingState {
    Creating {
        attempt: MappingAttempt,
        waiters: BTreeSet<CorrelationId>,
        fallback_attempts: usize,
        started: bool,
        revoked: bool,
        last_requested: RequestOrder,
    },
    Ready {
        spec: ListenerSpec,
        generation: u64,
        last_requested: RequestOrder,
    },
}

#[derive(Debug, Clone, Copy)]
struct QuarantinedPort {
    port: u16,
    expires_at: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerSlots(u8);

impl ListenerSlots {
    const SCALAR: Self = Self(1);
    const ATOMIC_PAIR: Self = Self(2);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ListenerReservationId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerReservation {
    id: ListenerReservationId,
    slots: ListenerSlots,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListenerLedgerInvariant {
    ReservationIdsExhausted,
    UnknownReservation,
    SuccessfulListenersExceedReservation,
    AccountingOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerReservationError {
    CapacityExhausted,
    Invariant(ListenerLedgerInvariant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerSettlement {
    consumed_success: u8,
    released_unused: u8,
}

#[derive(Debug)]
struct LifetimeLedger {
    available: u16,
    consumed_success: u16,
    next_reservation_id: u64,
    reserved: BTreeMap<ListenerReservationId, ListenerSlots>,
}

impl Default for LifetimeLedger {
    fn default() -> Self {
        Self {
            available: LIFETIME_LISTENER_LIMIT,
            consumed_success: 0,
            next_reservation_id: 1,
            reserved: BTreeMap::new(),
        }
    }
}

impl LifetimeLedger {
    fn reserve(
        &mut self,
        slots: ListenerSlots,
    ) -> Result<ListenerReservation, ListenerReservationError> {
        let requested = u16::from(slots.0);
        if self.available < requested {
            return Err(ListenerReservationError::CapacityExhausted);
        }
        let id = ListenerReservationId(self.next_reservation_id);
        self.next_reservation_id =
            self.next_reservation_id
                .checked_add(1)
                .ok_or(ListenerReservationError::Invariant(
                    ListenerLedgerInvariant::ReservationIdsExhausted,
                ))?;
        self.available -= requested;
        if self.reserved.insert(id, slots).is_some() {
            return Err(ListenerReservationError::Invariant(
                ListenerLedgerInvariant::AccountingOverflow,
            ));
        }
        Ok(ListenerReservation { id, slots })
    }

    fn settle(
        &mut self,
        reservation: ListenerReservation,
        successful: u8,
    ) -> Result<ListenerSettlement, ListenerLedgerInvariant> {
        let Some(reserved) = self.reserved.get(&reservation.id).copied() else {
            return Err(ListenerLedgerInvariant::UnknownReservation);
        };
        if reserved != reservation.slots || successful > reserved.0 {
            return Err(ListenerLedgerInvariant::SuccessfulListenersExceedReservation);
        }
        let released_unused = reserved.0 - successful;
        let consumed_success = self
            .consumed_success
            .checked_add(u16::from(successful))
            .ok_or(ListenerLedgerInvariant::AccountingOverflow)?;
        let available = self
            .available
            .checked_add(u16::from(released_unused))
            .ok_or(ListenerLedgerInvariant::AccountingOverflow)?;
        if consumed_success > LIFETIME_LISTENER_LIMIT || available > LIFETIME_LISTENER_LIMIT {
            return Err(ListenerLedgerInvariant::AccountingOverflow);
        }
        self.reserved.remove(&reservation.id);
        self.consumed_success = consumed_success;
        self.available = available;
        Ok(ListenerSettlement {
            consumed_success: successful,
            released_unused,
        })
    }

    #[cfg(test)]
    fn with_consumed(consumed_success: u16) -> Self {
        Self {
            available: LIFETIME_LISTENER_LIMIT - consumed_success,
            consumed_success,
            ..Self::default()
        }
    }

    #[cfg(test)]
    fn counts(&self) -> (u16, u16, u16) {
        let reserved = self.reserved.values().map(|slots| u16::from(slots.0)).sum();
        (self.available, reserved, self.consumed_success)
    }
}

pub(super) struct MappingRegistry {
    mappings: BTreeMap<MappingIdentity, MappingState>,
    active_requests: BTreeSet<CorrelationId>,
    saved_limit: crate::config::SavedPortForwardLimit,
    pending_saved_limit: Option<PendingSavedLimit>,
    request_order: RequestOrderSequence,
    lifetime_ledger: LifetimeLedger,
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
            active_requests: BTreeSet::new(),
            saved_limit: crate::config::SavedPortForwardLimit::DEFAULT,
            pending_saved_limit: None,
            request_order: RequestOrderSequence::default(),
            lifetime_ledger: LifetimeLedger::default(),
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
        self.request(id, identity, spec, 0, None)
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
        if let Err(failure) = self.distinct_admission(id) {
            return MappingRequest::Failed(MappingSettlement::failed(id, failure));
        }
        let reservation = match self.lifetime_ledger.reserve(ListenerSlots::ATOMIC_PAIR) {
            Ok(reservation) => reservation,
            Err(ListenerReservationError::CapacityExhausted) => {
                return MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CapacityExhausted,
                ));
            }
            Err(ListenerReservationError::Invariant(_)) => {
                return MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CapabilityClosed,
                ));
            }
        };
        let (spec, fallback_attempts) = if self.is_quarantined(remote_port) {
            let mut fallback_attempts = 0;
            match self.fresh_attempt(id, identity, &mut fallback_attempts, Some(reservation)) {
                Ok(attempt) => (attempt.spec, fallback_attempts),
                Err(failure) => {
                    if self.lifetime_ledger.settle(reservation, 0).is_err() {
                        return MappingRequest::Failed(MappingSettlement::failed(
                            id,
                            ForwardFailure::CapabilityClosed,
                        ));
                    }
                    return MappingRequest::Failed(MappingSettlement::failed(id, failure));
                }
            }
        } else {
            let Some(pair) = LocalhostPairSpec::new(remote_port, remote_port) else {
                let _ = self.lifetime_ledger.settle(reservation, 0);
                return MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CommandRejected,
                ));
            };
            (ListenerSpec::Localhost(pair), 0)
        };
        self.request(id, identity, spec, fallback_attempts, Some(reservation))
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
        if !self.mappings.contains_key(&identity) {
            return None;
        }
        let request_order = self.request_order.issue();
        if let Some(MappingState::Ready {
            spec, generation, ..
        }) = self.mappings.get(&identity)
        {
            if *generation != self.generation {
                return Some(MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CapabilityClosed,
                )));
            }
            let local_port = spec.local_port();
            if let Some(MappingState::Ready { last_requested, .. }) =
                self.mappings.get_mut(&identity)
            {
                *last_requested = request_order;
            }
            return Some(MappingRequest::Ready(MappingSettlement::ready(
                id, local_port,
            )));
        }
        let MappingState::Creating {
            waiters,
            last_requested,
            ..
        } = self.mappings.get_mut(&identity)?
        else {
            return None;
        };
        *last_requested = request_order;
        if waiters.contains(&id) {
            return Some(MappingRequest::Pending { attempt: None });
        }
        if waiters.len() >= MAX_MAPPING_WAITERS {
            return Some(MappingRequest::Failed(MappingSettlement::failed(
                id,
                ForwardFailure::TooManyWaiters,
            )));
        }
        if self.active_requests.len() >= MAX_FORWARD_REQUESTS || !self.active_requests.insert(id) {
            return Some(MappingRequest::Failed(MappingSettlement::failed(
                id,
                ForwardFailure::TooManyRequests,
            )));
        }
        waiters.insert(id);
        Some(MappingRequest::Pending { attempt: None })
    }

    fn request(
        &mut self,
        id: CorrelationId,
        identity: MappingIdentity,
        initial_spec: ListenerSpec,
        fallback_attempts: usize,
        pre_reserved_listeners: Option<ListenerReservation>,
    ) -> MappingRequest {
        if let Some(request) = self.request_existing(id, identity) {
            if let Some(reservation) = pre_reserved_listeners {
                let _ = self.lifetime_ledger.settle(reservation, 0);
            }
            return request;
        }
        let replacement_identity = match self.distinct_admission(id) {
            Ok(replacement) => replacement,
            Err(failure) => {
                if let Some(reservation) = pre_reserved_listeners {
                    let _ = self.lifetime_ledger.settle(reservation, 0);
                }
                return MappingRequest::Failed(MappingSettlement::failed(id, failure));
            }
        };
        if !self.active_requests.insert(id) {
            if let Some(reservation) = pre_reserved_listeners {
                let _ = self.lifetime_ledger.settle(reservation, 0);
            }
            return MappingRequest::Failed(MappingSettlement::failed(
                id,
                ForwardFailure::TooManyRequests,
            ));
        }
        let required_listeners = initial_spec.listener_slots();
        let listener_reservation = match pre_reserved_listeners {
            Some(reservation) if reservation.slots == required_listeners => reservation,
            Some(reservation) => {
                let _ = self.lifetime_ledger.settle(reservation, 0);
                self.active_requests.remove(&id);
                return MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CommandRejected,
                ));
            }
            None => match self.lifetime_ledger.reserve(required_listeners) {
                Ok(reservation) => reservation,
                Err(ListenerReservationError::CapacityExhausted) => {
                    self.active_requests.remove(&id);
                    return MappingRequest::Failed(MappingSettlement::failed(
                        id,
                        ForwardFailure::CapacityExhausted,
                    ));
                }
                Err(ListenerReservationError::Invariant(_)) => {
                    self.active_requests.remove(&id);
                    return MappingRequest::Failed(MappingSettlement::failed(
                        id,
                        ForwardFailure::CapabilityClosed,
                    ));
                }
            },
        };
        let attempt = MappingAttempt {
            controller_id: id,
            identity,
            generation: self.generation,
            spec: initial_spec,
            listener_reservation: Some(listener_reservation),
        };
        let replacement = replacement_identity.and_then(|identity| {
            let MappingState::Ready { spec, .. } = self.mappings.remove(&identity)? else {
                return None;
            };
            Some(MappingCancellation {
                controller_id: id,
                spec,
            })
        });
        let last_requested = self.request_order.issue();
        self.mappings.insert(
            identity,
            MappingState::Creating {
                attempt,
                waiters: BTreeSet::from([id]),
                fallback_attempts,
                started: false,
                revoked: false,
                last_requested,
            },
        );
        if let Some(cancellation) = replacement {
            MappingRequest::Replacing {
                attempt,
                cancellation,
            }
        } else {
            MappingRequest::Pending {
                attempt: Some(attempt),
            }
        }
    }

    fn distinct_admission(
        &self,
        id: CorrelationId,
    ) -> Result<Option<MappingIdentity>, ForwardFailure> {
        if self.active_requests.len() >= MAX_FORWARD_REQUESTS || self.active_requests.contains(&id)
        {
            return Err(ForwardFailure::TooManyRequests);
        }
        if self.pending_saved_limit.is_some() {
            return Err(ForwardFailure::TooManyRequests);
        }
        if self.saved_limit.admits_count(self.mappings.len()) {
            return Ok(None);
        }
        if self.saved_limit.is_reached_by(self.mappings.len()) {
            return self
                .least_recent_ready()
                .map(Some)
                .ok_or(ForwardFailure::TooManyRequests);
        }
        Err(ForwardFailure::TooManyRequests)
    }

    fn least_recent_ready(&self) -> Option<MappingIdentity> {
        self.mappings
            .iter()
            .filter_map(|(identity, mapping)| match mapping {
                MappingState::Ready { last_requested, .. } => {
                    Some(((*last_requested, *identity), *identity))
                }
                MappingState::Creating { .. } => None,
            })
            .min_by_key(|(order, _)| *order)
            .map(|(_, identity)| identity)
    }

    pub(super) fn begin_saved_limit_change(
        &mut self,
        saved_limit: crate::config::SavedPortForwardLimit,
        controller_id: CorrelationId,
    ) -> SavedLimitChange {
        let mut cancellations = Vec::new();
        while saved_limit.is_exceeded_by(self.mappings.len()) {
            let Some(identity) = self.least_recent_ready() else {
                break;
            };
            let Some(MappingState::Ready { spec, .. }) = self.mappings.remove(&identity) else {
                continue;
            };
            cancellations.push(MappingCancellation {
                controller_id,
                spec,
            });
        }
        self.pending_saved_limit = Some(PendingSavedLimit {
            controller_id,
            requested_limit: saved_limit,
        });
        SavedLimitChange {
            controller_id,
            requested_limit: saved_limit,
            cancellations,
        }
    }

    pub(super) fn saved_limit_change_converged(&self, change: &SavedLimitChange) -> bool {
        self.pending_saved_limit
            == Some(PendingSavedLimit {
                controller_id: change.controller_id,
                requested_limit: change.requested_limit,
            })
            && !change.requested_limit.is_exceeded_by(self.mappings.len())
    }

    pub(super) fn commit_saved_limit(&mut self, change: &SavedLimitChange) -> bool {
        if !self.clear_pending_saved_limit(change) {
            return false;
        }
        self.saved_limit = change.requested_limit;
        true
    }

    pub(super) fn abort_saved_limit_change(&mut self, change: &SavedLimitChange) -> bool {
        self.clear_pending_saved_limit(change)
    }

    fn clear_pending_saved_limit(&mut self, change: &SavedLimitChange) -> bool {
        let expected = PendingSavedLimit {
            controller_id: change.controller_id,
            requested_limit: change.requested_limit,
        };
        if self.pending_saved_limit != Some(expected) {
            return false;
        }
        self.pending_saved_limit = None;
        true
    }

    #[cfg(test)]
    pub(super) fn set_saved_limit(
        &mut self,
        saved_limit: crate::config::SavedPortForwardLimit,
        controller_id: CorrelationId,
    ) -> Vec<MappingCancellation> {
        let change = self.begin_saved_limit_change(saved_limit, controller_id);
        let _ = self.commit_saved_limit(&change);
        change.cancellations
    }

    pub(super) const fn saved_limit(&self) -> crate::config::SavedPortForwardLimit {
        self.saved_limit
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

    #[cfg(test)]
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
                for id in waiters.iter() {
                    self.active_requests.remove(id);
                }
                waiters.clear();
                *revoked = true;
            }
        }
        settlements
    }

    pub(super) fn master_died(&mut self) -> Vec<MappingSettlement> {
        self.master_live = false;
        self.quarantine.clear();
        self.active_requests.clear();
        self.lifetime_ledger = LifetimeLedger::default();
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
        self.active_requests.clear();
        self.lifetime_ledger = LifetimeLedger::default();
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
        self.active_requests.remove(&id);
        if waiters.is_empty() && !*started {
            let abandoned = *attempt;
            let Some(reservation) = abandoned.listener_reservation else {
                return WaiterCancellation::NotFound;
            };
            if self.lifetime_ledger.settle(reservation, 0).is_err() {
                return WaiterCancellation::NotFound;
            }
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
            last_requested,
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
                    last_requested,
                },
            );
            return MappingCompletion::default();
        }
        let successful_listeners = match result {
            MappingControlResult::Succeeded => 1,
            MappingControlResult::PairSucceeded => 2,
            MappingControlResult::PairSecondFailed => 1,
            MappingControlResult::BindFailed
            | MappingControlResult::Rejected
            | MappingControlResult::TimedOut
            | MappingControlResult::PairFirstBindFailed
            | MappingControlResult::PairFirstFailed
            | MappingControlResult::PairFirstTimedOut => 0,
        };
        let failure = match (attempt.spec, result) {
            (ListenerSpec::Scalar(_), MappingControlResult::Succeeded)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairSucceeded)
                if revoked =>
            {
                if let Err(error) = self.settle_listener_reservation(attempt, successful_listeners)
                {
                    return MappingCompletion {
                        invariant_error: Some(error),
                        ..MappingCompletion::default()
                    };
                }
                return MappingCompletion {
                    attempt: None,
                    cancellation: Some(attempt),
                    cancellation_policy: None,
                    settlements: Vec::new(),
                    invariant_error: None,
                };
            }
            (ListenerSpec::Scalar(_), MappingControlResult::Succeeded)
            | (ListenerSpec::Localhost(_), MappingControlResult::PairSucceeded) => {
                if let Err(error) = self.settle_listener_reservation(attempt, successful_listeners)
                {
                    return MappingCompletion {
                        invariant_error: Some(error),
                        ..MappingCompletion::default()
                    };
                }
                self.mappings.insert(
                    attempt.identity,
                    MappingState::Ready {
                        spec: attempt.spec,
                        generation: attempt.generation,
                        last_requested,
                    },
                );
                let (effective_limit, cancellation_policy) = self
                    .pending_saved_limit
                    .map(|pending| (pending.requested_limit, Some(pending.controller_id)))
                    .unwrap_or((self.saved_limit, None));
                let cancellation = if effective_limit.is_exceeded_by(self.mappings.len()) {
                    self.least_recent_ready().and_then(|identity| {
                        let MappingState::Ready {
                            spec, generation, ..
                        } = self.mappings.remove(&identity)?
                        else {
                            return None;
                        };
                        Some(MappingAttempt {
                            controller_id: attempt.controller_id,
                            identity,
                            generation,
                            spec,
                            listener_reservation: None,
                        })
                    })
                } else {
                    None
                };
                let completed_was_evicted =
                    cancellation.is_some_and(|cancelled| cancelled.identity == attempt.identity);
                for id in waiters.iter() {
                    self.active_requests.remove(id);
                }
                let settlements = waiters
                    .into_iter()
                    .map(|id| {
                        if completed_was_evicted {
                            MappingSettlement::failed(id, ForwardFailure::CapacityExhausted)
                        } else {
                            MappingSettlement::ready(id, attempt.spec.local_port())
                        }
                    })
                    .collect();
                return MappingCompletion {
                    attempt: None,
                    cancellation,
                    cancellation_policy: cancellation.and(cancellation_policy),
                    settlements,
                    invariant_error: None,
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
                    attempt.listener_reservation,
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
                                last_requested,
                            },
                        );
                        return MappingCompletion {
                            attempt: Some(next),
                            cancellation: None,
                            cancellation_policy: None,
                            settlements: Vec::new(),
                            invariant_error: None,
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
        if let Err(error) = self.settle_listener_reservation(attempt, successful_listeners) {
            return MappingCompletion {
                invariant_error: Some(error),
                ..MappingCompletion::default()
            };
        }
        for id in waiters.iter() {
            self.active_requests.remove(id);
        }
        MappingCompletion {
            attempt: None,
            cancellation: None,
            cancellation_policy: None,
            settlements: waiters
                .into_iter()
                .map(|id| MappingSettlement::failed(id, failure))
                .collect(),
            invariant_error: None,
        }
    }

    fn settle_listener_reservation(
        &mut self,
        attempt: MappingAttempt,
        successful_listeners: u8,
    ) -> Result<ListenerSettlement, ListenerLedgerInvariant> {
        let reservation = attempt
            .listener_reservation
            .ok_or(ListenerLedgerInvariant::UnknownReservation)?;
        self.lifetime_ledger
            .settle(reservation, successful_listeners)
    }

    fn fresh_attempt(
        &mut self,
        controller_id: CorrelationId,
        identity: MappingIdentity,
        fallback_attempts: &mut usize,
        listener_reservation: Option<ListenerReservation>,
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
                listener_reservation,
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
    fn for_test_with_saved_limit(
        fallback_ports: impl IntoIterator<Item = Result<u16, CandidateFailure>>,
        saved_limit: crate::config::SavedPortForwardLimit,
    ) -> Self {
        Self {
            saved_limit,
            ..Self::for_test(fallback_ports)
        }
    }

    #[cfg(test)]
    fn for_test_with_capacity(
        fallback_ports: impl IntoIterator<Item = Result<u16, CandidateFailure>>,
        consumed: u16,
    ) -> Self {
        let mut registry = Self::for_test_with_saved_limit(
            fallback_ports,
            crate::config::SavedPortForwardLimit::new(64).expect("valid limit"),
        );
        registry.lifetime_ledger = LifetimeLedger::with_consumed(consumed);
        registry
    }

    #[cfg(test)]
    fn for_test_with_capacity_and_candidate_calls(
        fallback_ports: impl IntoIterator<Item = u16>,
        consumed: u16,
    ) -> (Self, Arc<AtomicUsize>) {
        let (mut registry, calls) =
            Self::for_test_with_candidate_calls(fallback_ports.into_iter().map(Ok));
        registry.saved_limit = crate::config::SavedPortForwardLimit::new(64).expect("valid limit");
        registry.lifetime_ledger = LifetimeLedger::with_consumed(consumed);
        (registry, calls)
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

    #[cfg(test)]
    fn listener_counts(&self) -> (u16, u16) {
        let (_, reserved, consumed_success) = self.lifetime_ledger.counts();
        (consumed_success, reserved)
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
    fn saved_limit(value: u8) -> crate::config::SavedPortForwardLimit {
        crate::config::SavedPortForwardLimit::new(value).expect("valid saved mapping limit")
    }

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
    fn creating_mapping_and_attachment_request_limits_are_independent_and_exact() {
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(64));
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let owner = CorrelationId::new(1).expect("id");
        let _ = registry.request_scalar(owner, address, 8_000);
        assert_eq!(
            registry.request_scalar(owner, address, 8_000),
            MappingRequest::Pending { attempt: None },
            "duplicate waiter identity must not consume another slot"
        );
        for value in 2..=8 {
            let id = CorrelationId::new(value).expect("id");
            assert_eq!(
                registry.request_scalar(id, address, 8_000),
                MappingRequest::Pending { attempt: None }
            );
        }
        let ninth = CorrelationId::new(9).expect("id");
        assert_eq!(
            registry.request_scalar(ninth, address, 8_000),
            MappingRequest::Failed(MappingSettlement::failed(
                ninth,
                ForwardFailure::TooManyWaiters,
            ))
        );

        for value in 10..=33 {
            let id = CorrelationId::new(value).expect("id");
            let port = 8_000 + u16::try_from(value).expect("bounded port");
            assert!(matches!(
                registry.request_scalar(id, address, port),
                MappingRequest::Pending { attempt: Some(_) }
            ));
        }
        let thirty_third = CorrelationId::new(34).expect("id");
        assert_eq!(
            registry.request_scalar(thirty_third, address, 9_000),
            MappingRequest::Failed(MappingSettlement::failed(
                thirty_third,
                ForwardFailure::TooManyRequests,
            ))
        );
        assert_eq!(registry.waiter_count(), 32);
        let released = CorrelationId::new(2).expect("id");
        assert_eq!(
            registry.cancel_waiter(released),
            WaiterCancellation::Removed
        );
        assert_eq!(
            registry.cancel_waiter(released),
            WaiterCancellation::NotFound
        );
        assert!(matches!(
            registry.request_scalar(thirty_third, address, 9_000),
            MappingRequest::Pending { attempt: Some(_) }
        ));
        assert_eq!(registry.waiter_count(), 32);
    }

    #[test]
    fn exact_saved_limit_replaces_the_least_recently_requested_ready_mapping() {
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(2));
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        for (id, port) in [(1, 8_001), (2, 8_002)] {
            let id = CorrelationId::new(id).expect("id");
            let MappingRequest::Pending {
                attempt: Some(attempt),
            } = registry.request_scalar(id, address, port)
            else {
                panic!("new mapping");
            };
            assert!(registry.start(attempt));
            let _ = registry.complete(attempt, MappingControlResult::Succeeded);
        }
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(3).expect("id"), address, 8_001),
            MappingRequest::Ready(_)
        ));

        let replacement_id = CorrelationId::new(4).expect("id");
        let MappingRequest::Replacing {
            attempt,
            cancellation,
        } = registry.request_scalar(replacement_id, address, 8_003)
        else {
            panic!("replacement dispatch");
        };

        assert_eq!(attempt.local_port(), 8_003);
        assert_eq!(
            cancellation.operation(),
            ControlOperation::Cancel(ForwardSpec {
                local_address: address,
                local_port: 8_002,
                remote_address: address,
                remote_port: 8_002,
            })
        );
        assert_eq!(registry.mapping_count(), 2);
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(5).expect("id"), address, 8_002),
            MappingRequest::Replacing { .. }
        ));
    }

    #[test]
    fn creating_settlement_preserves_request_time_lru_order() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(2));

        let old_id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(old_attempt),
        } = registry.request_scalar(old_id, address, 8_001)
        else {
            panic!("old creating mapping");
        };
        assert!(registry.start(old_attempt));

        let newer_id = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(newer_attempt),
        } = registry.request_scalar(newer_id, address, 8_002)
        else {
            panic!("newer mapping");
        };
        assert!(registry.start(newer_attempt));
        let _ = registry.complete(newer_attempt, MappingControlResult::Succeeded);
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(3).expect("id"), address, 8_002),
            MappingRequest::Ready(_)
        ));
        let _ = registry.complete(old_attempt, MappingControlResult::Succeeded);

        let MappingRequest::Replacing { cancellation, .. } =
            registry.request_scalar(CorrelationId::new(4).expect("id"), address, 8_003)
        else {
            panic!("replacement");
        };
        assert_eq!(
            cancellation.operation(),
            ControlOperation::Cancel(ForwardSpec {
                local_address: address,
                local_port: 8_001,
                remote_address: address,
                remote_port: 8_001,
            })
        );
    }

    #[test]
    fn coalesced_creating_waiter_refreshes_request_time_lru_order() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(2));
        let first_id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(first_attempt),
        } = registry.request_scalar(first_id, address, 8_001)
        else {
            panic!("creating mapping");
        };
        assert!(registry.start(first_attempt));

        let ready_id = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(ready_attempt),
        } = registry.request_scalar(ready_id, address, 8_002)
        else {
            panic!("ready mapping");
        };
        assert!(registry.start(ready_attempt));
        let _ = registry.complete(ready_attempt, MappingControlResult::Succeeded);
        assert_eq!(
            registry.request_scalar(CorrelationId::new(3).expect("id"), address, 8_001),
            MappingRequest::Pending { attempt: None }
        );
        let _ = registry.complete(first_attempt, MappingControlResult::Succeeded);

        let MappingRequest::Replacing { cancellation, .. } =
            registry.request_scalar(CorrelationId::new(4).expect("id"), address, 8_003)
        else {
            panic!("replacement");
        };
        assert_eq!(
            cancellation.operation(),
            ControlOperation::Cancel(ForwardSpec {
                local_address: address,
                local_port: 8_002,
                remote_address: address,
                remote_port: 8_002,
            })
        );
    }

    #[test]
    fn live_limit_decrease_evicts_ready_lru_but_preserves_creating_work() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut ready = MappingRegistry::for_test_with_saved_limit([], saved_limit(4));
        for (id, port) in [(1, 8_001), (2, 8_002), (3, 8_003)] {
            let id = CorrelationId::new(id).expect("id");
            let MappingRequest::Pending {
                attempt: Some(attempt),
            } = ready.request_scalar(id, address, port)
            else {
                panic!("new mapping");
            };
            assert!(ready.start(attempt));
            let _ = ready.complete(attempt, MappingControlResult::Succeeded);
        }
        let _ = ready.request_scalar(CorrelationId::new(4).expect("id"), address, 8_001);
        let cancellations =
            ready.set_saved_limit(saved_limit(1), CorrelationId::new(5).expect("id"));
        assert_eq!(
            cancellations
                .into_iter()
                .map(MappingCancellation::operation)
                .collect::<Vec<_>>(),
            vec![
                ControlOperation::Cancel(ForwardSpec {
                    local_address: address,
                    local_port: 8_002,
                    remote_address: address,
                    remote_port: 8_002,
                }),
                ControlOperation::Cancel(ForwardSpec {
                    local_address: address,
                    local_port: 8_003,
                    remote_address: address,
                    remote_port: 8_003,
                }),
            ]
        );
        assert_eq!(ready.mapping_count(), 1);

        let mut creating = MappingRegistry::for_test_with_saved_limit([], saved_limit(3));
        let mut attempts = Vec::new();
        for (id, port) in [(10, 9_001), (11, 9_002), (12, 9_003)] {
            let MappingRequest::Pending {
                attempt: Some(attempt),
            } = creating.request_scalar(CorrelationId::new(id).expect("id"), address, port)
            else {
                panic!("creating mapping");
            };
            attempts.push(attempt);
        }
        assert!(creating
            .set_saved_limit(saved_limit(1), CorrelationId::new(13).expect("id"))
            .is_empty());
        let rejected = CorrelationId::new(14).expect("id");
        assert_eq!(
            creating.request_scalar(rejected, address, 9_004),
            MappingRequest::Failed(MappingSettlement::failed(
                rejected,
                ForwardFailure::TooManyRequests,
            ))
        );
        assert_eq!(
            creating.request_scalar(CorrelationId::new(15).expect("id"), address, 9_001),
            MappingRequest::Pending { attempt: None }
        );
        for (index, attempt) in attempts.into_iter().enumerate() {
            assert!(creating.start(attempt));
            let completion = creating.complete(attempt, MappingControlResult::Succeeded);
            assert_eq!(completion.cancellation.is_some(), index < 2);
        }
        assert_eq!(creating.mapping_count(), 1);
    }

    #[test]
    fn over_limit_completion_evicts_an_older_ready_before_publishing() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(2));
        let old_id = CorrelationId::new(1).expect("id");
        let MappingRequest::Pending {
            attempt: Some(old_attempt),
        } = registry.request_scalar(old_id, address, 8_001)
        else {
            panic!("old mapping");
        };
        assert!(registry.start(old_attempt));
        let _ = registry.complete(old_attempt, MappingControlResult::Succeeded);

        let completed_id = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(completed_attempt),
        } = registry.request_scalar(completed_id, address, 8_002)
        else {
            panic!("creating mapping");
        };
        assert!(registry.start(completed_attempt));
        registry.saved_limit = saved_limit(1);

        let completion = registry.complete(completed_attempt, MappingControlResult::Succeeded);
        assert_eq!(
            completion.cancellation.map(MappingAttempt::cancellation),
            Some(ControlOperation::Cancel(ForwardSpec {
                local_address: address,
                local_port: 8_001,
                remote_address: address,
                remote_port: 8_001,
            }))
        );
        assert_eq!(
            completion.settlements,
            vec![MappingSettlement::ready(completed_id, 8_002)]
        );
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(3).expect("id"), address, 8_002),
            MappingRequest::Ready(_)
        ));
    }

    #[test]
    fn over_limit_completion_selected_as_victim_never_publishes_ready() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(3));
        let mut attempts = Vec::new();
        for (id, port) in [(1, 8_001), (2, 8_002), (3, 8_003)] {
            let MappingRequest::Pending {
                attempt: Some(attempt),
            } = registry.request_scalar(CorrelationId::new(id).expect("id"), address, port)
            else {
                panic!("creating mapping");
            };
            attempts.push(attempt);
        }
        assert!(registry
            .set_saved_limit(saved_limit(2), CorrelationId::new(4).expect("id"))
            .is_empty());

        let victim = attempts[1];
        let coalesced = CorrelationId::new(5).expect("id");
        assert_eq!(
            registry.request_scalar(coalesced, address, 8_002),
            MappingRequest::Pending { attempt: None }
        );
        assert!(registry.start(victim));
        let completion = registry.complete(victim, MappingControlResult::Succeeded);
        assert_eq!(
            completion.cancellation.map(MappingAttempt::cancellation),
            Some(victim.cancellation())
        );
        assert_eq!(
            completion.settlements,
            vec![
                MappingSettlement::failed(
                    victim.controller_id(),
                    ForwardFailure::CapacityExhausted,
                ),
                MappingSettlement::failed(coalesced, ForwardFailure::CapacityExhausted),
            ]
        );
        assert_eq!(registry.mapping_count(), 2);
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(6).expect("id"), address, 8_002,),
            MappingRequest::Failed(MappingSettlement {
                result: Err(ForwardFailure::TooManyRequests),
                ..
            })
        ));
    }

    #[test]
    fn lifetime_listener_capacity_reserves_atomically_and_counts_partial_pairs_forever() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut concurrent = MappingRegistry::for_test_with_capacity([], 126);
        let first = CorrelationId::new(1).expect("id");
        assert!(matches!(
            concurrent.request_scalar(first, address, 8_001),
            MappingRequest::Pending { .. }
        ));
        let pair = CorrelationId::new(2).expect("id");
        assert_eq!(
            concurrent.request_localhost(pair, 8_002),
            MappingRequest::Failed(MappingSettlement::failed(
                pair,
                ForwardFailure::CapacityExhausted,
            )),
            "the scalar reservation leaves only one indivisible slot"
        );
        assert!(matches!(
            concurrent.request_scalar(CorrelationId::new(3).expect("id"), address, 8_003),
            MappingRequest::Pending { .. }
        ));
        let exhausted = CorrelationId::new(4).expect("id");
        assert_eq!(
            concurrent.request_scalar(exhausted, address, 8_004),
            MappingRequest::Failed(MappingSettlement::failed(
                exhausted,
                ForwardFailure::CapacityExhausted,
            ))
        );

        let mut partial = MappingRegistry::for_test_with_capacity([], 126);
        let partial_id = CorrelationId::new(10).expect("id");
        let MappingRequest::Pending {
            attempt: Some(pair_attempt),
        } = partial.request_localhost(partial_id, 9_000)
        else {
            panic!("pair reservation");
        };
        assert!(partial.start(pair_attempt));
        let _ = partial.complete(pair_attempt, MappingControlResult::PairSecondFailed);
        assert_eq!(partial.listener_counts(), (127, 0));
        assert!(matches!(
            partial.request_scalar(CorrelationId::new(11).expect("id"), address, 9_001),
            MappingRequest::Pending { .. }
        ));
        assert_eq!(partial.listener_counts(), (127, 1));
    }

    #[test]
    fn reservations_at_127_and_128_release_only_never_successful_remainder() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut at_127 = MappingRegistry::for_test_with_capacity([], 127);
        let pair = CorrelationId::new(1).expect("id");
        assert_eq!(
            at_127.request_localhost(pair, 8_000),
            MappingRequest::Failed(MappingSettlement::failed(
                pair,
                ForwardFailure::CapacityExhausted,
            ))
        );
        let scalar = CorrelationId::new(2).expect("id");
        let MappingRequest::Pending {
            attempt: Some(reserved),
        } = at_127.request_scalar(scalar, address, 8_001)
        else {
            panic!("last scalar reservation");
        };
        assert_eq!(at_127.listener_counts(), (127, 1));
        assert_eq!(
            at_127.cancel_waiter(scalar),
            WaiterCancellation::AbandonedBeforeStart(reserved)
        );
        assert_eq!(at_127.listener_counts(), (127, 0));

        let mut at_128 = MappingRegistry::for_test_with_capacity([], 128);
        for (id, request) in [
            (
                CorrelationId::new(3).expect("id"),
                at_128.request_scalar(CorrelationId::new(3).expect("id"), address, 8_002),
            ),
            (
                CorrelationId::new(4).expect("id"),
                at_128.request_localhost(CorrelationId::new(4).expect("id"), 8_003),
            ),
        ] {
            assert_eq!(
                request,
                MappingRequest::Failed(MappingSettlement::failed(
                    id,
                    ForwardFailure::CapacityExhausted,
                ))
            );
        }
        assert_eq!(at_128.listener_counts(), (128, 0));
    }

    #[test]
    fn listener_lifetime_ledger_model_sequences_preserve_capacity_and_single_settlement() {
        for seed in 1_u64..=128 {
            let mut entropy = seed;
            let mut ledger = LifetimeLedger::default();
            let mut reservations = Vec::<(ListenerReservation, u8)>::new();
            let mut model_available = LIFETIME_LISTENER_LIMIT;
            let mut model_consumed = 0_u16;

            for _ in 0..256 {
                entropy = entropy
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                if entropy % 3 != 0 || reservations.is_empty() {
                    let slots = if entropy & 1 == 0 {
                        ListenerSlots::SCALAR
                    } else {
                        ListenerSlots::ATOMIC_PAIR
                    };
                    match ledger.reserve(slots) {
                        Ok(reservation) => {
                            assert!(model_available >= u16::from(slots.0));
                            model_available -= u16::from(slots.0);
                            reservations.push((reservation, slots.0));
                        }
                        Err(ListenerReservationError::CapacityExhausted) => {
                            assert!(model_available < u16::from(slots.0));
                        }
                        Err(ListenerReservationError::Invariant(error)) => {
                            panic!("unexpected ledger invariant: {error:?}");
                        }
                    }
                } else {
                    let index =
                        usize::try_from(entropy).expect("test entropy") % reservations.len();
                    let (reservation, reserved) = reservations.swap_remove(index);
                    let successful = u8::try_from(entropy % u64::from(reserved + 1))
                        .expect("successful listener count");
                    let settlement = ledger
                        .settle(reservation, successful)
                        .expect("model reservation settles once");
                    assert_eq!(settlement.consumed_success, successful);
                    assert_eq!(settlement.released_unused, reserved - successful);
                    model_consumed += u16::from(successful);
                    model_available += u16::from(reserved - successful);
                    assert_eq!(
                        ledger.settle(reservation, 0),
                        Err(ListenerLedgerInvariant::UnknownReservation)
                    );
                }

                let (available, reserved, consumed) = ledger.counts();
                assert_eq!(available, model_available);
                assert_eq!(consumed, model_consumed);
                assert_eq!(available + reserved + consumed, LIFETIME_LISTENER_LIMIT);
            }
        }
    }

    #[test]
    fn listener_lifetime_ledger_rejects_overconsume_without_losing_reservation() {
        let mut ledger = LifetimeLedger::default();
        let reservation = ledger
            .reserve(ListenerSlots::SCALAR)
            .expect("scalar reservation");
        assert_eq!(
            ledger.settle(reservation, 2),
            Err(ListenerLedgerInvariant::SuccessfulListenersExceedReservation)
        );
        assert_eq!(ledger.counts(), (127, 1, 0));
        assert_eq!(
            ledger.settle(reservation, 1),
            Ok(ListenerSettlement {
                consumed_success: 1,
                released_unused: 0,
            })
        );
        assert_eq!(ledger.counts(), (127, 0, 1));
    }

    #[test]
    fn exhaustion_preserves_ready_reuse_has_no_candidate_side_effects_and_resets_by_generation() {
        let address = LoopbackAddress::Ipv4([127, 0, 0, 1]);
        let mut registry = MappingRegistry::for_test_with_capacity([], 126);
        for (id, port) in [(1, 8_001), (2, 8_002)] {
            let id = CorrelationId::new(id).expect("id");
            let MappingRequest::Pending {
                attempt: Some(attempt),
            } = registry.request_scalar(id, address, port)
            else {
                panic!("reserved scalar");
            };
            assert!(registry.start(attempt));
            let _ = registry.complete(attempt, MappingControlResult::Succeeded);
        }
        assert_eq!(registry.listener_counts(), (128, 0));
        let _ = registry.set_saved_limit(saved_limit(1), CorrelationId::new(3).expect("id"));
        assert_eq!(registry.listener_counts(), (128, 0));
        assert!(matches!(
            registry.request_scalar(CorrelationId::new(4).expect("id"), address, 8_002),
            MappingRequest::Ready(_)
        ));
        let distinct = CorrelationId::new(5).expect("id");
        assert_eq!(
            registry.request_scalar(distinct, address, 8_003),
            MappingRequest::Failed(MappingSettlement::failed(
                distinct,
                ForwardFailure::CapacityExhausted,
            ))
        );

        let (mut candidate_guard, calls) =
            MappingRegistry::for_test_with_capacity_and_candidate_calls([43_123], 128);
        candidate_guard.quarantine(9_000);
        let guarded = CorrelationId::new(6).expect("id");
        assert_eq!(
            candidate_guard.request_localhost(guarded, 9_000),
            MappingRequest::Failed(MappingSettlement::failed(
                guarded,
                ForwardFailure::CapacityExhausted,
            ))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        let _ = registry.master_died();
        assert!(registry.replace_master());
        assert!(matches!(
            registry.request_localhost(CorrelationId::new(7).expect("id"), 9_001),
            MappingRequest::Pending { .. }
        ));
        assert_eq!(registry.listener_counts(), (0, 2));
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
                cancellation_policy: None,
                settlements: vec![MappingSettlement::failed(id, ForwardFailure::BindFailed)],
                invariant_error: None,
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
                cancellation_policy: None,
                settlements: vec![MappingSettlement::failed(id, ForwardFailure::BindFailed)],
                invariant_error: None,
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
                cancellation_policy: None,
                settlements: vec![MappingSettlement::failed(
                    id,
                    ForwardFailure::CommandRejected,
                )],
                invariant_error: None,
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
        let mut registry = MappingRegistry::for_test_with_saved_limit([], saved_limit(64));
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
