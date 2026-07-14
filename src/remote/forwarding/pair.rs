use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::protocol::{CorrelationId, ForwardFailure};
use super::worker::{LocalhostPairSpec, PairControlResult};

const FALLBACK_CANDIDATES: usize = 5;
const QUARANTINE_DURATION: Duration = Duration::from_secs(5 * 60);
const QUARANTINE_LIMIT: usize = 64;

pub(super) trait MonotonicClock: Send + Sync {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairCandidateFailure {
    Collision,
    Unavailable,
}

struct PairPortReservation {
    port: u16,
    _listener: Option<TcpListener>,
}

trait PairCandidates: Send + Sync {
    fn reserve_fresh(&self) -> Result<PairPortReservation, PairCandidateFailure>;
}

struct SystemPairCandidates;

impl PairCandidates for SystemPairCandidates {
    fn reserve_fresh(&self) -> Result<PairPortReservation, PairCandidateFailure> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(candidate_failure)?;
        let port = listener
            .local_addr()
            .ok()
            .map(|address| address.port())
            .filter(|port| *port != 0)
            .ok_or(PairCandidateFailure::Unavailable)?;
        Ok(PairPortReservation {
            port,
            _listener: Some(listener),
        })
    }
}

fn candidate_failure(error: io::Error) -> PairCandidateFailure {
    if error.kind() == io::ErrorKind::AddrInUse {
        PairCandidateFailure::Collision
    } else {
        PairCandidateFailure::Unavailable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PairSettlement {
    pub(super) id: CorrelationId,
    pub(super) result: Result<u16, ForwardFailure>,
}

impl PairSettlement {
    pub(super) const fn ready(id: CorrelationId, local_port: u16) -> Self {
        Self {
            id,
            result: Ok(local_port),
        }
    }

    fn failed(id: CorrelationId, failure: ForwardFailure) -> Self {
        Self {
            id,
            result: Err(failure),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PairRequest {
    Ready(PairSettlement),
    Pending { command: Option<LocalhostPairSpec> },
    Failed(PairSettlement),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct PairCompletion {
    pub(super) command: Option<LocalhostPairSpec>,
    pub(super) cancellation: Option<LocalhostPairSpec>,
    pub(super) settlements: Vec<PairSettlement>,
}

#[derive(Debug)]
enum PairMapping {
    Creating {
        pair: LocalhostPairSpec,
        waiters: BTreeSet<CorrelationId>,
        fallback_attempts: usize,
        revoked: bool,
        lru: u64,
    },
    Ready {
        pair: LocalhostPairSpec,
        lru: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct QuarantinedPort {
    port: u16,
    expires_at: Duration,
}

pub(super) struct LocalhostMappings {
    mappings: BTreeMap<u16, PairMapping>,
    quarantine: VecDeque<QuarantinedPort>,
    candidates: Arc<dyn PairCandidates>,
    clock: Arc<dyn MonotonicClock>,
    next_lru: u64,
}

impl Default for LocalhostMappings {
    fn default() -> Self {
        Self::with_parts(
            Arc::new(SystemPairCandidates),
            Arc::new(SystemMonotonicClock::default()),
        )
    }
}

impl LocalhostMappings {
    fn with_parts(candidates: Arc<dyn PairCandidates>, clock: Arc<dyn MonotonicClock>) -> Self {
        Self {
            mappings: BTreeMap::new(),
            quarantine: VecDeque::new(),
            candidates,
            clock,
            next_lru: 0,
        }
    }

    pub(super) fn request(&mut self, id: CorrelationId, remote_port: u16) -> PairRequest {
        if remote_port == 0 {
            return PairRequest::Failed(PairSettlement::failed(
                id,
                ForwardFailure::CommandRejected,
            ));
        }
        let lru = self.touch_lru();
        if let Some(mapping) = self.mappings.get_mut(&remote_port) {
            return match mapping {
                PairMapping::Creating {
                    waiters, lru: at, ..
                } => {
                    waiters.insert(id);
                    *at = lru;
                    PairRequest::Pending { command: None }
                }
                PairMapping::Ready { pair, lru: at } => {
                    *at = lru;
                    PairRequest::Ready(PairSettlement::ready(id, pair.local_port()))
                }
            };
        }

        let mut fallback_attempts = 0;
        let pair = match self.initial_candidate(remote_port, &mut fallback_attempts) {
            Ok(pair) => pair,
            Err(failure) => {
                return PairRequest::Failed(PairSettlement::failed(id, failure));
            }
        };
        self.mappings.insert(
            remote_port,
            PairMapping::Creating {
                pair,
                waiters: BTreeSet::from([id]),
                fallback_attempts,
                revoked: false,
                lru,
            },
        );
        PairRequest::Pending {
            command: Some(pair),
        }
    }

    pub(super) fn complete(
        &mut self,
        pair: LocalhostPairSpec,
        result: PairControlResult,
    ) -> PairCompletion {
        let remote_port = pair.remote_port();
        let Some(mapping) = self.mappings.remove(&remote_port) else {
            return PairCompletion::default();
        };
        let PairMapping::Creating {
            pair: active_pair,
            waiters,
            mut fallback_attempts,
            revoked,
            lru,
        } = mapping
        else {
            self.mappings.insert(remote_port, mapping);
            return PairCompletion::default();
        };
        if active_pair != pair {
            self.mappings.insert(
                remote_port,
                PairMapping::Creating {
                    pair: active_pair,
                    waiters,
                    fallback_attempts,
                    revoked,
                    lru,
                },
            );
            return PairCompletion::default();
        }

        match result {
            PairControlResult::Succeeded if revoked => PairCompletion {
                command: None,
                cancellation: Some(pair),
                settlements: Vec::new(),
            },
            PairControlResult::Succeeded => {
                let settlements = waiters
                    .iter()
                    .copied()
                    .map(|id| PairSettlement::ready(id, pair.local_port()))
                    .collect();
                self.mappings
                    .insert(remote_port, PairMapping::Ready { pair, lru });
                PairCompletion {
                    command: None,
                    cancellation: None,
                    settlements,
                }
            }
            PairControlResult::FirstBindFailed if waiters.is_empty() => PairCompletion::default(),
            PairControlResult::FirstBindFailed => {
                match self.fresh_candidate(remote_port, &mut fallback_attempts) {
                    Ok(next) => {
                        self.mappings.insert(
                            remote_port,
                            PairMapping::Creating {
                                pair: next,
                                waiters,
                                fallback_attempts,
                                revoked,
                                lru,
                            },
                        );
                        PairCompletion {
                            command: Some(next),
                            cancellation: None,
                            settlements: Vec::new(),
                        }
                    }
                    Err(failure) => PairCompletion {
                        command: None,
                        cancellation: None,
                        settlements: settle_all(waiters, failure),
                    },
                }
            }
            PairControlResult::SecondFailed => {
                self.quarantine(pair.local_port());
                PairCompletion {
                    command: None,
                    cancellation: None,
                    settlements: settle_all(waiters, ForwardFailure::AtomicCreationFailed),
                }
            }
            PairControlResult::FirstFailed => PairCompletion {
                command: None,
                cancellation: None,
                settlements: settle_all(waiters, ForwardFailure::CommandRejected),
            },
            PairControlResult::FirstTimedOut => PairCompletion {
                command: None,
                cancellation: None,
                settlements: settle_all(waiters, ForwardFailure::CommandTimedOut),
            },
        }
    }

    pub(super) fn cancel_waiter(&mut self, id: CorrelationId) -> bool {
        for mapping in self.mappings.values_mut() {
            if let PairMapping::Creating { waiters, .. } = mapping {
                if waiters.remove(&id) {
                    return true;
                }
            }
        }
        false
    }

    pub(super) fn revoke_creating(&mut self) {
        for mapping in self.mappings.values_mut() {
            if let PairMapping::Creating {
                waiters, revoked, ..
            } = mapping
            {
                waiters.clear();
                *revoked = true;
            }
        }
    }

    pub(super) fn waiter_count(&self) -> usize {
        self.mappings
            .values()
            .map(|mapping| match mapping {
                PairMapping::Creating { waiters, .. } => waiters.len(),
                PairMapping::Ready { .. } => 0,
            })
            .sum()
    }

    pub(super) fn ready_pairs_least_recently_used(&self) -> Vec<LocalhostPairSpec> {
        let mut pairs = self
            .mappings
            .values()
            .filter_map(|mapping| match mapping {
                PairMapping::Ready { pair, lru } => Some((*lru, pair.remote_port(), *pair)),
                PairMapping::Creating { .. } => None,
            })
            .collect::<Vec<_>>();
        pairs.sort_by_key(|(lru, remote_port, _)| (*lru, *remote_port));
        pairs.into_iter().map(|(_, _, pair)| pair).collect()
    }

    pub(super) fn reset(&mut self) {
        self.mappings.clear();
        self.quarantine.clear();
        self.next_lru = 0;
    }

    fn initial_candidate(
        &mut self,
        remote_port: u16,
        fallback_attempts: &mut usize,
    ) -> Result<LocalhostPairSpec, ForwardFailure> {
        if !self.is_quarantined(remote_port) {
            return LocalhostPairSpec::new(remote_port, remote_port)
                .ok_or(ForwardFailure::CommandRejected);
        }
        self.fresh_candidate(remote_port, fallback_attempts)
    }

    fn fresh_candidate(
        &mut self,
        remote_port: u16,
        fallback_attempts: &mut usize,
    ) -> Result<LocalhostPairSpec, ForwardFailure> {
        while *fallback_attempts < FALLBACK_CANDIDATES {
            *fallback_attempts += 1;
            let reservation = match self.candidates.reserve_fresh() {
                Ok(reservation) => reservation,
                Err(PairCandidateFailure::Collision) => continue,
                Err(PairCandidateFailure::Unavailable) => {
                    return Err(ForwardFailure::CommandRejected);
                }
            };
            let local_port = reservation.port;
            drop(reservation);
            if self.is_quarantined(local_port) {
                continue;
            }
            return LocalhostPairSpec::new(local_port, remote_port)
                .ok_or(ForwardFailure::CommandRejected);
        }
        Err(ForwardFailure::BindFailed)
    }

    fn quarantine(&mut self, port: u16) {
        self.expire_quarantine();
        self.quarantine.retain(|entry| entry.port != port);
        let now = self.clock.now();
        let expires_at = now
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

    fn touch_lru(&mut self) -> u64 {
        self.next_lru = self.next_lru.saturating_add(1);
        self.next_lru
    }

    #[cfg(test)]
    fn for_test(results: impl IntoIterator<Item = Result<u16, PairCandidateFailure>>) -> Self {
        Self::with_parts(
            Arc::new(QueuedPairCandidates::new(results)),
            Arc::new(FakeMonotonicClock::default()),
        )
    }

    #[cfg(test)]
    fn ready_port(&self, remote_port: u16) -> Option<u16> {
        match self.mappings.get(&remote_port) {
            Some(PairMapping::Ready { pair, .. }) => Some(pair.local_port()),
            _ => None,
        }
    }

    #[cfg(test)]
    fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

fn settle_all(waiters: BTreeSet<CorrelationId>, failure: ForwardFailure) -> Vec<PairSettlement> {
    waiters
        .into_iter()
        .map(|id| PairSettlement::failed(id, failure))
        .collect()
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
struct QueuedPairCandidates {
    results: std::sync::Mutex<VecDeque<Result<u16, PairCandidateFailure>>>,
}

#[cfg(test)]
impl QueuedPairCandidates {
    fn new(results: impl IntoIterator<Item = Result<u16, PairCandidateFailure>>) -> Self {
        Self {
            results: std::sync::Mutex::new(results.into_iter().collect()),
        }
    }
}

#[cfg(test)]
impl PairCandidates for QueuedPairCandidates {
    fn reserve_fresh(&self) -> Result<PairPortReservation, PairCandidateFailure> {
        self.results
            .lock()
            .expect("candidate results")
            .pop_front()
            .expect("queued candidate result")
            .map(|port| PairPortReservation {
                port,
                _listener: None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_candidate_publishes_only_after_atomic_success_and_reuses_one_pair() {
        let mut mappings = LocalhostMappings::for_test([]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");

        let PairRequest::Pending {
            command: Some(pair),
        } = mappings.request(first, 8080)
        else {
            panic!("first request must start the preferred pair");
        };
        assert_eq!(pair.local_port(), 8080);
        assert!(mappings.ready_port(8080).is_none());

        let completion = mappings.complete(pair, PairControlResult::Succeeded);
        assert_eq!(
            completion.settlements,
            vec![PairSettlement::ready(first, 8080)]
        );
        assert_eq!(mappings.ready_port(8080), Some(8080));
        assert_eq!(
            mappings.request(second, 8080),
            PairRequest::Ready(PairSettlement::ready(second, 8080))
        );
        assert_eq!(mappings.mapping_count(), 1);
    }

    fn pending_pair(request: PairRequest) -> LocalhostPairSpec {
        let PairRequest::Pending {
            command: Some(pair),
        } = request
        else {
            panic!("request must start a pair command");
        };
        pair
    }

    #[test]
    fn clean_first_member_collision_uses_bounded_fallback_before_publication() {
        let mut mappings = LocalhostMappings::for_test([Ok(43_123)]);
        let id = CorrelationId::new(1).expect("id");
        let preferred = pending_pair(mappings.request(id, 8080));

        let fallback = mappings.complete(preferred, PairControlResult::FirstBindFailed);
        let remapped = fallback.command.expect("fallback pair");
        assert_eq!(remapped.local_port(), 43_123);
        assert!(fallback.settlements.is_empty());
        assert!(mappings.ready_port(8080).is_none());

        let ready = mappings.complete(remapped, PairControlResult::Succeeded);
        assert_eq!(ready.settlements, vec![PairSettlement::ready(id, 43_123)]);
    }

    #[test]
    fn five_fallback_candidates_exhaust_without_starting_a_sixth() {
        let mut mappings = LocalhostMappings::for_test([
            Ok(40_001),
            Ok(40_002),
            Ok(40_003),
            Ok(40_004),
            Ok(40_005),
        ]);
        let id = CorrelationId::new(1).expect("id");
        let mut pair = pending_pair(mappings.request(id, 8080));

        for expected_port in 40_001..=40_005 {
            let completion = mappings.complete(pair, PairControlResult::FirstBindFailed);
            pair = completion.command.expect("bounded fallback");
            assert_eq!(pair.local_port(), expected_port);
        }
        let exhausted = mappings.complete(pair, PairControlResult::FirstBindFailed);
        assert!(exhausted.command.is_none());
        assert_eq!(
            exhausted.settlements,
            vec![PairSettlement::failed(id, ForwardFailure::BindFailed)]
        );
    }

    #[test]
    fn first_member_timeout_preserves_its_typed_failure() {
        let mut mappings = LocalhostMappings::for_test([]);
        let id = CorrelationId::new(1).expect("id");
        let pair = pending_pair(mappings.request(id, 8080));

        let completion = mappings.complete(pair, PairControlResult::FirstTimedOut);

        assert_eq!(
            completion.settlements,
            vec![PairSettlement::failed(id, ForwardFailure::CommandTimedOut)]
        );
    }

    #[test]
    fn second_member_failure_quarantines_candidate_and_stops_that_click() {
        let mut mappings = LocalhostMappings::for_test([Ok(43_123)]);
        let first = CorrelationId::new(1).expect("id");
        let pair = pending_pair(mappings.request(first, 8080));

        let failed = mappings.complete(pair, PairControlResult::SecondFailed);
        assert!(failed.command.is_none());
        assert_eq!(
            failed.settlements,
            vec![PairSettlement::failed(
                first,
                ForwardFailure::AtomicCreationFailed
            )]
        );

        let second = CorrelationId::new(2).expect("id");
        let retry = pending_pair(mappings.request(second, 8080));
        assert_eq!(retry.local_port(), 43_123);
    }

    #[test]
    fn quarantine_expires_at_the_exact_five_minute_monotonic_boundary() {
        let clock = Arc::new(FakeMonotonicClock::default());
        let candidates = Arc::new(QueuedPairCandidates::new([]));
        let mut mappings = LocalhostMappings::with_parts(candidates, clock.clone());
        mappings.quarantine(8080);

        clock.set(Duration::from_secs(299));
        assert!(mappings.is_quarantined(8080));
        clock.set(Duration::from_secs(300));
        assert!(!mappings.is_quarantined(8080));
    }

    #[test]
    fn quarantine_retains_the_64_most_recent_entries_in_deterministic_order() {
        let mut mappings = LocalhostMappings::for_test([]);
        for port in 1..=65 {
            mappings.quarantine(port);
        }

        assert_eq!(mappings.quarantine.len(), 64);
        assert!(!mappings.is_quarantined(1));
        assert!(mappings.is_quarantined(2));
        mappings.quarantine(2);
        assert_eq!(
            mappings
                .quarantine
                .iter()
                .map(|entry| entry.port)
                .collect::<Vec<_>>(),
            (3..=65).chain(std::iter::once(2)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn waiter_cancellation_never_interrupts_current_pair_or_other_waiters() {
        let mut mappings = LocalhostMappings::for_test([]);
        let first = CorrelationId::new(1).expect("id");
        let second = CorrelationId::new(2).expect("id");
        let pair = pending_pair(mappings.request(first, 8080));
        assert_eq!(
            mappings.request(second, 8080),
            PairRequest::Pending { command: None }
        );

        assert!(mappings.cancel_waiter(first));
        let completion = mappings.complete(pair, PairControlResult::Succeeded);
        assert_eq!(
            completion.settlements,
            vec![PairSettlement::ready(second, 8080)]
        );
        assert_eq!(mappings.ready_port(8080), Some(8080));
    }

    #[test]
    fn no_fallback_starts_after_the_last_waiter_leaves_current_candidate() {
        let mut mappings = LocalhostMappings::for_test([Ok(43_123)]);
        let id = CorrelationId::new(1).expect("id");
        let pair = pending_pair(mappings.request(id, 8080));
        assert!(mappings.cancel_waiter(id));

        let completion = mappings.complete(pair, PairControlResult::FirstBindFailed);
        assert!(completion.command.is_none());
        assert!(completion.settlements.is_empty());
        assert_eq!(mappings.mapping_count(), 0);
    }

    #[test]
    fn pair_lru_and_cleanup_identity_keep_both_exact_members_in_one_slot() {
        let mut mappings = LocalhostMappings::for_test([]);
        for (id, remote_port) in [(1, 8001), (2, 8002)] {
            let pair =
                pending_pair(mappings.request(CorrelationId::new(id).expect("id"), remote_port));
            mappings.complete(pair, PairControlResult::Succeeded);
        }
        assert!(matches!(
            mappings.request(CorrelationId::new(3).expect("id"), 8001),
            PairRequest::Ready(_)
        ));

        let cleanup = mappings.ready_pairs_least_recently_used();
        assert_eq!(
            cleanup
                .iter()
                .map(|pair| pair.remote_port())
                .collect::<Vec<_>>(),
            vec![8002, 8001]
        );
        for pair in cleanup {
            assert_eq!(pair.ipv4().local_port, pair.ipv6().local_port);
            assert_eq!(pair.ipv4().remote_port, pair.ipv6().remote_port);
            assert_eq!(
                pair.ipv4().local_address,
                super::super::protocol::LoopbackAddress::Ipv4([127, 0, 0, 1])
            );
            assert_eq!(
                pair.ipv6().local_address,
                super::super::protocol::LoopbackAddress::Ipv6
            );
        }
    }

    #[test]
    fn revocation_prevents_publication_and_requests_pair_wide_cancellation() {
        let mut mappings = LocalhostMappings::for_test([]);
        let pair = pending_pair(mappings.request(CorrelationId::new(1).expect("id"), 8080));

        mappings.revoke_creating();
        let completion = mappings.complete(pair, PairControlResult::Succeeded);

        assert_eq!(completion.cancellation, Some(pair));
        assert!(completion.settlements.is_empty());
        assert_eq!(mappings.mapping_count(), 0);
    }

    #[test]
    fn master_reset_clears_saved_pairs_and_quarantine() {
        let mut mappings = LocalhostMappings::for_test([]);
        let pair = pending_pair(mappings.request(CorrelationId::new(1).expect("id"), 8080));
        mappings.complete(pair, PairControlResult::Succeeded);
        mappings.quarantine(9000);

        mappings.reset();

        assert_eq!(mappings.mapping_count(), 0);
        assert!(mappings.quarantine.is_empty());
        assert_eq!(mappings.next_lru, 0);
    }

    #[test]
    fn generated_state_sequences_preserve_pair_identity_waiter_and_quarantine_invariants() {
        let results = (0..512).map(|offset| Ok(40_000 + (offset % 20_000) as u16));
        let mut mappings = LocalhostMappings::for_test(results);
        let mut active = BTreeMap::<u16, LocalhostPairSpec>::new();
        let mut seed = 0x9e37_79b9_u64;

        for step in 1..=512_u64 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let remote_port = 8_000 + u16::try_from(seed % 17).expect("bounded port");
            let id = CorrelationId::new(step).expect("id");
            match seed % 4 {
                0 | 1 => {
                    if let PairRequest::Pending {
                        command: Some(pair),
                    } = mappings.request(id, remote_port)
                    {
                        active.insert(remote_port, pair);
                    }
                }
                2 => {
                    if let Some(pair) = active.remove(&remote_port) {
                        let result = if seed & 0x10 == 0 {
                            PairControlResult::Succeeded
                        } else {
                            PairControlResult::SecondFailed
                        };
                        let completion = mappings.complete(pair, result);
                        if let Some(next) = completion.command {
                            active.insert(remote_port, next);
                        }
                    }
                }
                _ => {
                    let _ = mappings.cancel_waiter(id);
                }
            }

            assert!(mappings.quarantine.len() <= QUARANTINE_LIMIT);
            let mut all_waiters = BTreeSet::new();
            for (key, mapping) in &mappings.mappings {
                match mapping {
                    PairMapping::Creating { pair, waiters, .. } => {
                        assert_eq!(*key, pair.remote_port());
                        assert_eq!(pair.ipv4().local_port, pair.ipv6().local_port);
                        for waiter in waiters {
                            assert!(all_waiters.insert(*waiter));
                        }
                    }
                    PairMapping::Ready { pair, .. } => {
                        assert_eq!(*key, pair.remote_port());
                        assert_eq!(pair.ipv4().local_port, pair.ipv6().local_port);
                    }
                }
            }
        }
    }
}
