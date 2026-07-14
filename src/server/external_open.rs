use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::protocol::{ExternalOpenResult, ExternalOpenTarget};

pub(crate) const EXTERNAL_OPEN_DEADLINE: Duration = Duration::from_secs(10);
const MAX_EXTERNAL_OPENS_PER_ATTACHMENT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalOpenAdmissionError {
    NotAuthorized,
    TooManyInProgress,
    RequestIdsExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExternalOpenDispatch {
    request_id: u64,
    deadline: Instant,
}

impl ExternalOpenDispatch {
    pub(crate) const fn request_id(self) -> u64 {
        self.request_id
    }

    #[cfg(test)]
    pub(crate) const fn deadline(self) -> Instant {
        self.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalOpenTerminalOutcome {
    OpenedDirectly,
    OpenedThroughForward(crate::protocol::ExternalOpenPortStatus),
    PreparationFailed(crate::protocol::ExternalOpenPreparationFailure),
    PlatformOpenRejected,
    ClientDeliveryFailed,
    InvalidClientResult,
    TimedOutBeforeCommit,
    CancelledBeforeCommit,
    ClientDisconnectedBeforeCommit,
    CommittedOutcomeUnknown,
}

impl ExternalOpenTerminalOutcome {
    pub(crate) const fn canonical_outcome(self) -> &'static str {
        match self {
            Self::OpenedDirectly => "opened_directly",
            Self::OpenedThroughForward(_) => "opened_through_forward",
            Self::PreparationFailed(reason) => canonical_preparation_failure(reason),
            Self::PlatformOpenRejected => "platform_open_rejected",
            Self::ClientDeliveryFailed => "client_delivery_failed",
            Self::InvalidClientResult => "invalid_client_result",
            Self::TimedOutBeforeCommit => "timed_out_before_commit",
            Self::CancelledBeforeCommit => "cancelled_before_commit",
            Self::ClientDisconnectedBeforeCommit => "client_disconnected_before_commit",
            Self::CommittedOutcomeUnknown => "committed_outcome_unknown",
        }
    }

    pub(crate) const fn notice_message(self) -> Option<&'static str> {
        use crate::protocol::ExternalOpenPreparationFailure as Failure;

        match self {
            Self::OpenedDirectly
            | Self::OpenedThroughForward(_)
            | Self::CancelledBeforeCommit
            | Self::ClientDisconnectedBeforeCommit => None,
            Self::PreparationFailed(Failure::UnsupportedScheme) => {
                Some("Couldn’t open link · link type isn’t supported")
            }
            Self::PreparationFailed(Failure::AuthorityUserinfoForbidden) => {
                Some("Couldn’t open link · links with credentials aren’t allowed")
            }
            Self::PreparationFailed(Failure::InvalidPort | Failure::InvalidAbsoluteUrl) => {
                Some("Couldn’t open link · link is invalid")
            }
            Self::PreparationFailed(
                Failure::UnsupportedLoopbackForm | Failure::LoopbackUnsupportedOnPlatform,
            ) => Some("Couldn’t open link · link uses an unsupported local address"),
            Self::PreparationFailed(Failure::ManagedSshRequired) => {
                Some("Couldn’t open link · managed SSH is required")
            }
            Self::PreparationFailed(Failure::ForwardingUnavailable) => {
                Some("Couldn’t open link · local forwarding is unavailable")
            }
            Self::PreparationFailed(
                Failure::TooManyOpensInProgress
                | Failure::TooManyForwardRequests
                | Failure::TooManyMappingWaiters,
            ) => Some("Couldn’t open link · too many links are opening"),
            Self::PreparationFailed(Failure::ForwardCapacityExhausted) => {
                Some("Couldn’t open link · local forwarding limit reached")
            }
            Self::PreparationFailed(
                Failure::ForwardBindExhausted
                | Failure::AtomicForwardCreationFailed
                | Failure::ForwardCommandRejected,
            ) => Some("Couldn’t open link · local forwarding failed"),
            Self::PreparationFailed(Failure::ForwardCommandTimedOut) => {
                Some("Couldn’t open link · local forwarding timed out")
            }
            Self::PlatformOpenRejected => {
                Some("Couldn’t open link · device rejected the open request")
            }
            Self::ClientDeliveryFailed => Some("Couldn’t open link · client connection failed"),
            Self::InvalidClientResult => Some("Couldn’t open link · client response was invalid"),
            Self::TimedOutBeforeCommit => {
                Some("Couldn’t open link · request timed out before opening")
            }
            Self::CommittedOutcomeUnknown => {
                Some("Couldn’t confirm link opening · device may still have opened it")
            }
        }
    }
}

const fn canonical_preparation_failure(
    reason: crate::protocol::ExternalOpenPreparationFailure,
) -> &'static str {
    use crate::protocol::ExternalOpenPreparationFailure as Failure;

    match reason {
        Failure::UnsupportedScheme => "unsupported_scheme",
        Failure::AuthorityUserinfoForbidden => "authority_userinfo_forbidden",
        Failure::InvalidPort => "invalid_port",
        Failure::InvalidAbsoluteUrl => "invalid_absolute_url",
        Failure::UnsupportedLoopbackForm => "unsupported_loopback_form",
        Failure::LoopbackUnsupportedOnPlatform => "loopback_unsupported_on_platform",
        Failure::ManagedSshRequired => "managed_ssh_required",
        Failure::ForwardingUnavailable => "forwarding_unavailable",
        Failure::TooManyOpensInProgress => "too_many_opens_in_progress",
        Failure::TooManyForwardRequests => "too_many_forward_requests",
        Failure::TooManyMappingWaiters => "too_many_mapping_waiters",
        Failure::ForwardCapacityExhausted => "forward_capacity_exhausted",
        Failure::ForwardBindExhausted => "forward_bind_exhausted",
        Failure::AtomicForwardCreationFailed => "atomic_forward_creation_failed",
        Failure::ForwardCommandRejected => "forward_command_rejected",
        Failure::ForwardCommandTimedOut => "forward_command_timed_out",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExternalOpenClosed {
    pub(crate) request_id: u64,
    pub(crate) client_id: u64,
    pub(crate) outcome: ExternalOpenTerminalOutcome,
    accepted_at: Instant,
    phase: ExternalOpenPhase,
}

impl ExternalOpenClosed {
    pub(crate) fn elapsed_ms(self, now: Instant) -> u128 {
        now.saturating_duration_since(self.accepted_at).as_millis()
    }

    pub(crate) const fn commit_state(self) -> &'static str {
        match self.phase {
            ExternalOpenPhase::Preparing => "uncommitted",
            ExternalOpenPhase::Committed(_) => "committed",
        }
    }

    pub(crate) const fn forward_status(self) -> &'static str {
        match self.phase {
            ExternalOpenPhase::Preparing
            | ExternalOpenPhase::Committed(ExternalOpenTarget::Direct) => "no",
            ExternalOpenPhase::Committed(ExternalOpenTarget::Forwarded {
                port_status: crate::protocol::ExternalOpenPortStatus::SamePort,
            }) => "same",
            ExternalOpenPhase::Committed(ExternalOpenTarget::Forwarded {
                port_status: crate::protocol::ExternalOpenPortStatus::RemappedPort,
            }) => "remapped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalOpenTransition {
    Committed,
    Closed(ExternalOpenClosed),
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalOpenPhase {
    Preparing,
    Committed(ExternalOpenTarget),
}

#[derive(Debug, Clone, Copy)]
struct ExternalOpenRequest {
    client_id: u64,
    deadline: Instant,
    phase: ExternalOpenPhase,
}

#[derive(Default)]
struct ExternalOpenAttachment {
    connections: HashSet<u64>,
    requests: ExternalOpenRequests,
}

/// Owns external-open ledgers at the attachment seam while preserving exact
/// source-connection routing inside each ledger.
#[derive(Default)]
pub(crate) struct ExternalOpenAttachments {
    attachments: HashMap<crate::protocol::ExternalOpenAttachmentId, ExternalOpenAttachment>,
    client_attachments: HashMap<u64, crate::protocol::ExternalOpenAttachmentId>,
}

impl ExternalOpenAttachments {
    pub(crate) fn connect(
        &mut self,
        client_id: u64,
        attachment_id: crate::protocol::ExternalOpenAttachmentId,
    ) -> bool {
        if let Some(bound) = self.client_attachments.get(&client_id) {
            return *bound == attachment_id;
        }
        self.client_attachments.insert(client_id, attachment_id);
        self.attachments
            .entry(attachment_id)
            .or_default()
            .connections
            .insert(client_id)
    }

    pub(crate) fn disconnect(&mut self, client_id: u64) -> Vec<ExternalOpenClosed> {
        let Some(attachment_id) = self.client_attachments.remove(&client_id) else {
            return Vec::new();
        };
        let Some(attachment) = self.attachments.get_mut(&attachment_id) else {
            return Vec::new();
        };
        let closed = attachment.requests.connection_lost(client_id);
        attachment.connections.remove(&client_id);
        if attachment.connections.is_empty() && attachment.requests.is_empty() {
            self.attachments.remove(&attachment_id);
        }
        closed
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.attachments
            .values()
            .filter_map(|attachment| attachment.requests.next_deadline())
            .min()
    }

    pub(crate) fn expire_due(&mut self, now: Instant) -> Vec<ExternalOpenClosed> {
        let mut closed = self
            .attachments
            .values_mut()
            .flat_map(|attachment| attachment.requests.expire_due(now))
            .collect::<Vec<_>>();
        closed.sort_by_key(|request| (request.accepted_at, request.request_id));
        closed
    }

    pub(crate) fn cancel_preparing_for_client(
        &mut self,
        client_id: u64,
    ) -> Vec<ExternalOpenClosed> {
        self.requests_for_client_mut(client_id)
            .map(|requests| requests.cancel_preparing_for_client(client_id))
            .unwrap_or_default()
    }

    pub(crate) fn start(
        &mut self,
        client_id: u64,
        accepted_at: Instant,
    ) -> Result<ExternalOpenDispatch, ExternalOpenAdmissionError> {
        self.requests_for_client_mut(client_id)
            .ok_or(ExternalOpenAdmissionError::NotAuthorized)?
            .start(client_id, accepted_at)
    }

    pub(crate) fn ready(
        &mut self,
        client_id: u64,
        request_id: u64,
        target: ExternalOpenTarget,
        now: Instant,
        queue_commit: impl FnOnce(u64) -> bool,
    ) -> ExternalOpenTransition {
        self.requests_for_client_mut(client_id)
            .map(|requests| requests.ready(client_id, request_id, target, now, queue_commit))
            .unwrap_or(ExternalOpenTransition::Ignored)
    }

    pub(crate) fn delivery_failed(
        &mut self,
        client_id: u64,
        request_id: u64,
    ) -> ExternalOpenTransition {
        self.requests_for_client_mut(client_id)
            .map(|requests| requests.delivery_failed(client_id, request_id))
            .unwrap_or(ExternalOpenTransition::Ignored)
    }

    pub(crate) fn preparation_failed(
        &mut self,
        client_id: u64,
        request_id: u64,
        reason: crate::protocol::ExternalOpenPreparationFailure,
        now: Instant,
    ) -> ExternalOpenTransition {
        self.requests_for_client_mut(client_id)
            .map(|requests| requests.preparation_failed(client_id, request_id, reason, now))
            .unwrap_or(ExternalOpenTransition::Ignored)
    }

    pub(crate) fn result(
        &mut self,
        client_id: u64,
        request_id: u64,
        result: ExternalOpenResult,
        now: Instant,
    ) -> ExternalOpenTransition {
        self.requests_for_client_mut(client_id)
            .map(|requests| requests.result(client_id, request_id, result, now))
            .unwrap_or(ExternalOpenTransition::Ignored)
    }

    fn requests_for_client_mut(&mut self, client_id: u64) -> Option<&mut ExternalOpenRequests> {
        let attachment_id = *self.client_attachments.get(&client_id)?;
        self.attachments
            .get_mut(&attachment_id)
            .map(|attachment| &mut attachment.requests)
    }

    #[cfg(test)]
    pub(crate) fn attachment_count_for_test(&self) -> usize {
        self.attachments.len()
    }

    #[cfg(test)]
    pub(crate) fn active_request_count_for_test(
        &self,
        attachment_id: crate::protocol::ExternalOpenAttachmentId,
    ) -> usize {
        self.attachments
            .get(&attachment_id)
            .map(|attachment| attachment.requests.requests.len())
            .unwrap_or(0)
    }
}

pub(crate) struct ExternalOpenRequests {
    next_request_id: u64,
    requests: HashMap<u64, ExternalOpenRequest>,
}

impl Default for ExternalOpenRequests {
    fn default() -> Self {
        Self {
            next_request_id: 1,
            requests: HashMap::new(),
        }
    }
}

impl ExternalOpenRequests {
    fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.requests.values().map(|request| request.deadline).min()
    }

    pub(crate) fn expire_due(&mut self, now: Instant) -> Vec<ExternalOpenClosed> {
        let mut due = self
            .requests
            .iter()
            .filter(|(_, request)| now >= request.deadline)
            .map(|(&request_id, request)| (request.deadline, request_id))
            .collect::<Vec<_>>();
        due.sort_unstable();

        due.into_iter()
            .filter_map(|(_, request_id)| {
                let request = self.requests.remove(&request_id)?;
                let outcome = match request.phase {
                    ExternalOpenPhase::Preparing => {
                        ExternalOpenTerminalOutcome::TimedOutBeforeCommit
                    }
                    ExternalOpenPhase::Committed(_) => {
                        ExternalOpenTerminalOutcome::CommittedOutcomeUnknown
                    }
                };
                Some(Self::closed(request_id, request, outcome))
            })
            .collect()
    }

    pub(crate) fn cancel_preparing_for_client(
        &mut self,
        client_id: u64,
    ) -> Vec<ExternalOpenClosed> {
        let mut request_ids = self
            .requests
            .iter()
            .filter_map(|(&request_id, request)| {
                (request.client_id == client_id && request.phase == ExternalOpenPhase::Preparing)
                    .then_some(request_id)
            })
            .collect::<Vec<_>>();
        request_ids.sort_unstable();

        request_ids
            .into_iter()
            .filter_map(|request_id| {
                let request = self.requests.remove(&request_id)?;
                Some(Self::closed(
                    request_id,
                    request,
                    ExternalOpenTerminalOutcome::CancelledBeforeCommit,
                ))
            })
            .collect()
    }

    pub(crate) fn connection_lost(&mut self, client_id: u64) -> Vec<ExternalOpenClosed> {
        let mut request_ids = self
            .requests
            .iter()
            .filter_map(|(&request_id, request)| {
                (request.client_id == client_id).then_some(request_id)
            })
            .collect::<Vec<_>>();
        request_ids.sort_unstable();

        request_ids
            .into_iter()
            .filter_map(|request_id| {
                let request = self.requests.remove(&request_id)?;
                let outcome = match request.phase {
                    ExternalOpenPhase::Preparing => {
                        ExternalOpenTerminalOutcome::ClientDisconnectedBeforeCommit
                    }
                    ExternalOpenPhase::Committed(_) => {
                        ExternalOpenTerminalOutcome::CommittedOutcomeUnknown
                    }
                };
                Some(Self::closed(request_id, request, outcome))
            })
            .collect()
    }

    pub(crate) fn start(
        &mut self,
        client_id: u64,
        accepted_at: Instant,
    ) -> Result<ExternalOpenDispatch, ExternalOpenAdmissionError> {
        if self.requests.len() >= MAX_EXTERNAL_OPENS_PER_ATTACHMENT {
            return Err(ExternalOpenAdmissionError::TooManyInProgress);
        }
        let request_id = self.next_request_id;
        if request_id == 0 {
            return Err(ExternalOpenAdmissionError::RequestIdsExhausted);
        }
        self.next_request_id = request_id.checked_add(1).unwrap_or(0);
        let deadline = accepted_at + EXTERNAL_OPEN_DEADLINE;
        self.requests.insert(
            request_id,
            ExternalOpenRequest {
                client_id,
                deadline,
                phase: ExternalOpenPhase::Preparing,
            },
        );
        Ok(ExternalOpenDispatch {
            request_id,
            deadline,
        })
    }

    pub(crate) fn ready(
        &mut self,
        client_id: u64,
        request_id: u64,
        target: ExternalOpenTarget,
        now: Instant,
        queue_commit: impl FnOnce(u64) -> bool,
    ) -> ExternalOpenTransition {
        let Some(request) = self.requests.get(&request_id).copied() else {
            return ExternalOpenTransition::Ignored;
        };
        if request.client_id != client_id || request.phase != ExternalOpenPhase::Preparing {
            return ExternalOpenTransition::Ignored;
        }
        if now >= request.deadline {
            return self.close(
                request_id,
                ExternalOpenTerminalOutcome::TimedOutBeforeCommit,
            );
        }
        if !queue_commit(request_id) {
            return self.close(
                request_id,
                ExternalOpenTerminalOutcome::ClientDeliveryFailed,
            );
        }
        if let Some(request) = self.requests.get_mut(&request_id) {
            request.phase = ExternalOpenPhase::Committed(target);
            ExternalOpenTransition::Committed
        } else {
            ExternalOpenTransition::Ignored
        }
    }

    pub(crate) fn delivery_failed(
        &mut self,
        client_id: u64,
        request_id: u64,
    ) -> ExternalOpenTransition {
        let Some(request) = self.requests.get(&request_id).copied() else {
            return ExternalOpenTransition::Ignored;
        };
        if request.client_id != client_id || request.phase != ExternalOpenPhase::Preparing {
            return ExternalOpenTransition::Ignored;
        }
        self.close(
            request_id,
            ExternalOpenTerminalOutcome::ClientDeliveryFailed,
        )
    }

    pub(crate) fn preparation_failed(
        &mut self,
        client_id: u64,
        request_id: u64,
        reason: crate::protocol::ExternalOpenPreparationFailure,
        now: Instant,
    ) -> ExternalOpenTransition {
        let Some(request) = self.requests.get(&request_id).copied() else {
            return ExternalOpenTransition::Ignored;
        };
        if request.client_id != client_id || request.phase != ExternalOpenPhase::Preparing {
            return ExternalOpenTransition::Ignored;
        }
        if now >= request.deadline {
            return self.close(
                request_id,
                ExternalOpenTerminalOutcome::TimedOutBeforeCommit,
            );
        }
        self.close(
            request_id,
            ExternalOpenTerminalOutcome::PreparationFailed(reason),
        )
    }

    pub(crate) fn result(
        &mut self,
        client_id: u64,
        request_id: u64,
        result: ExternalOpenResult,
        now: Instant,
    ) -> ExternalOpenTransition {
        let Some(request) = self.requests.get(&request_id).copied() else {
            return ExternalOpenTransition::Ignored;
        };
        if request.client_id != client_id {
            return ExternalOpenTransition::Ignored;
        }
        let ExternalOpenPhase::Committed(target) = request.phase else {
            let outcome = if now >= request.deadline {
                ExternalOpenTerminalOutcome::TimedOutBeforeCommit
            } else {
                ExternalOpenTerminalOutcome::InvalidClientResult
            };
            return self.close(request_id, outcome);
        };
        if now >= request.deadline {
            return self.close(
                request_id,
                ExternalOpenTerminalOutcome::CommittedOutcomeUnknown,
            );
        }
        let outcome = match (target, result) {
            (ExternalOpenTarget::Direct, ExternalOpenResult::OpenedDirectly) => {
                ExternalOpenTerminalOutcome::OpenedDirectly
            }
            (
                ExternalOpenTarget::Forwarded {
                    port_status: prepared,
                },
                ExternalOpenResult::OpenedThroughForward {
                    port_status: reported,
                },
            ) if prepared == reported => {
                ExternalOpenTerminalOutcome::OpenedThroughForward(reported)
            }
            (_, ExternalOpenResult::PlatformOpenRejected) => {
                ExternalOpenTerminalOutcome::PlatformOpenRejected
            }
            _ => ExternalOpenTerminalOutcome::InvalidClientResult,
        };
        self.close(request_id, outcome)
    }

    fn close(
        &mut self,
        request_id: u64,
        outcome: ExternalOpenTerminalOutcome,
    ) -> ExternalOpenTransition {
        let Some(request) = self.requests.remove(&request_id) else {
            return ExternalOpenTransition::Ignored;
        };
        ExternalOpenTransition::Closed(Self::closed(request_id, request, outcome))
    }

    fn closed(
        request_id: u64,
        request: ExternalOpenRequest,
        outcome: ExternalOpenTerminalOutcome,
    ) -> ExternalOpenClosed {
        ExternalOpenClosed {
            request_id,
            client_id: request.client_id,
            outcome,
            accepted_at: request.deadline - EXTERNAL_OPEN_DEADLINE,
            phase: request.phase,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    use crate::protocol::{ExternalOpenResult, ExternalOpenTarget};

    use super::*;

    #[test]
    fn terminal_outcomes_translate_exhaustively_to_canonical_vocabulary() {
        use crate::protocol::ExternalOpenPreparationFailure as Failure;

        let outcomes = [
            (
                ExternalOpenTerminalOutcome::OpenedDirectly,
                "opened_directly",
            ),
            (
                ExternalOpenTerminalOutcome::OpenedThroughForward(
                    crate::protocol::ExternalOpenPortStatus::SamePort,
                ),
                "opened_through_forward",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::UnsupportedScheme),
                "unsupported_scheme",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::AuthorityUserinfoForbidden),
                "authority_userinfo_forbidden",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::InvalidPort),
                "invalid_port",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::InvalidAbsoluteUrl),
                "invalid_absolute_url",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::UnsupportedLoopbackForm),
                "unsupported_loopback_form",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(
                    Failure::LoopbackUnsupportedOnPlatform,
                ),
                "loopback_unsupported_on_platform",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ManagedSshRequired),
                "managed_ssh_required",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardingUnavailable),
                "forwarding_unavailable",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::TooManyOpensInProgress),
                "too_many_opens_in_progress",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::TooManyForwardRequests),
                "too_many_forward_requests",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::TooManyMappingWaiters),
                "too_many_mapping_waiters",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardCapacityExhausted),
                "forward_capacity_exhausted",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardBindExhausted),
                "forward_bind_exhausted",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(
                    Failure::AtomicForwardCreationFailed,
                ),
                "atomic_forward_creation_failed",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardCommandRejected),
                "forward_command_rejected",
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardCommandTimedOut),
                "forward_command_timed_out",
            ),
            (
                ExternalOpenTerminalOutcome::PlatformOpenRejected,
                "platform_open_rejected",
            ),
            (
                ExternalOpenTerminalOutcome::ClientDeliveryFailed,
                "client_delivery_failed",
            ),
            (
                ExternalOpenTerminalOutcome::InvalidClientResult,
                "invalid_client_result",
            ),
            (
                ExternalOpenTerminalOutcome::TimedOutBeforeCommit,
                "timed_out_before_commit",
            ),
            (
                ExternalOpenTerminalOutcome::CancelledBeforeCommit,
                "cancelled_before_commit",
            ),
            (
                ExternalOpenTerminalOutcome::ClientDisconnectedBeforeCommit,
                "client_disconnected_before_commit",
            ),
            (
                ExternalOpenTerminalOutcome::CommittedOutcomeUnknown,
                "committed_outcome_unknown",
            ),
        ];

        assert_eq!(
            outcomes.map(|(outcome, _)| outcome.canonical_outcome()),
            outcomes.map(|(_, canonical)| canonical),
        );
    }

    #[test]
    fn terminal_outcomes_translate_exhaustively_to_url_free_notice_copy() {
        use crate::protocol::ExternalOpenPreparationFailure as Failure;

        let cases = [
            (ExternalOpenTerminalOutcome::OpenedDirectly, None),
            (
                ExternalOpenTerminalOutcome::OpenedThroughForward(
                    crate::protocol::ExternalOpenPortStatus::SamePort,
                ),
                None,
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::UnsupportedScheme),
                Some("Couldn’t open link · link type isn’t supported"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::AuthorityUserinfoForbidden),
                Some("Couldn’t open link · links with credentials aren’t allowed"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::InvalidPort),
                Some("Couldn’t open link · link is invalid"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::InvalidAbsoluteUrl),
                Some("Couldn’t open link · link is invalid"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::UnsupportedLoopbackForm),
                Some("Couldn’t open link · link uses an unsupported local address"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(
                    Failure::LoopbackUnsupportedOnPlatform,
                ),
                Some("Couldn’t open link · link uses an unsupported local address"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ManagedSshRequired),
                Some("Couldn’t open link · managed SSH is required"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardingUnavailable),
                Some("Couldn’t open link · local forwarding is unavailable"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::TooManyOpensInProgress),
                Some("Couldn’t open link · too many links are opening"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::TooManyForwardRequests),
                Some("Couldn’t open link · too many links are opening"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::TooManyMappingWaiters),
                Some("Couldn’t open link · too many links are opening"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardCapacityExhausted),
                Some("Couldn’t open link · local forwarding limit reached"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardBindExhausted),
                Some("Couldn’t open link · local forwarding failed"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(
                    Failure::AtomicForwardCreationFailed,
                ),
                Some("Couldn’t open link · local forwarding failed"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardCommandRejected),
                Some("Couldn’t open link · local forwarding failed"),
            ),
            (
                ExternalOpenTerminalOutcome::PreparationFailed(Failure::ForwardCommandTimedOut),
                Some("Couldn’t open link · local forwarding timed out"),
            ),
            (
                ExternalOpenTerminalOutcome::PlatformOpenRejected,
                Some("Couldn’t open link · device rejected the open request"),
            ),
            (
                ExternalOpenTerminalOutcome::ClientDeliveryFailed,
                Some("Couldn’t open link · client connection failed"),
            ),
            (
                ExternalOpenTerminalOutcome::InvalidClientResult,
                Some("Couldn’t open link · client response was invalid"),
            ),
            (
                ExternalOpenTerminalOutcome::TimedOutBeforeCommit,
                Some("Couldn’t open link · request timed out before opening"),
            ),
            (ExternalOpenTerminalOutcome::CancelledBeforeCommit, None),
            (
                ExternalOpenTerminalOutcome::ClientDisconnectedBeforeCommit,
                None,
            ),
            (
                ExternalOpenTerminalOutcome::CommittedOutcomeUnknown,
                Some("Couldn’t confirm link opening · device may still have opened it"),
            ),
        ];

        for (outcome, expected) in cases {
            assert_eq!(outcome.notice_message(), expected, "{outcome:?}");
        }
    }

    #[test]
    fn terminal_diagnostic_context_uses_closed_commit_and_forward_vocabulary() {
        let accepted_at = Instant::now();
        let terminal_at = accepted_at + Duration::from_millis(1_234);
        let closed = [
            ExternalOpenClosed {
                request_id: 1,
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::InvalidClientResult,
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            },
            ExternalOpenClosed {
                request_id: 2,
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::OpenedDirectly,
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
            },
            ExternalOpenClosed {
                request_id: 3,
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::OpenedThroughForward(
                    crate::protocol::ExternalOpenPortStatus::SamePort,
                ),
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Forwarded {
                    port_status: crate::protocol::ExternalOpenPortStatus::SamePort,
                }),
            },
            ExternalOpenClosed {
                request_id: 4,
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::OpenedThroughForward(
                    crate::protocol::ExternalOpenPortStatus::RemappedPort,
                ),
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Forwarded {
                    port_status: crate::protocol::ExternalOpenPortStatus::RemappedPort,
                }),
            },
        ];

        assert_eq!(
            closed.map(|closed| (
                closed.elapsed_ms(terminal_at),
                closed.commit_state(),
                closed.forward_status(),
            )),
            [
                (1_234, "uncommitted", "no"),
                (1_234, "committed", "no"),
                (1_234, "committed", "same"),
                (1_234, "committed", "remapped"),
            ],
        );
    }

    #[test]
    fn one_attachment_shares_32_lifecycles_across_clients_until_terminal_settlement() {
        let accepted_at = Instant::now();
        let mut attachment = ExternalOpenRequests::default();
        let admitted = (0..32)
            .map(|index| {
                attachment
                    .start(7 + (index % 2), accepted_at)
                    .expect("within attachment cap")
            })
            .collect::<Vec<_>>();

        assert_eq!(
            attachment.start(7, accepted_at),
            Err(ExternalOpenAdmissionError::TooManyInProgress)
        );
        assert_eq!(
            attachment.start(8, accepted_at),
            Err(ExternalOpenAdmissionError::TooManyInProgress)
        );
        let mut distinct_attachment = ExternalOpenRequests::default();
        assert!(distinct_attachment.start(7, accepted_at).is_ok());
        assert_eq!(
            attachment.ready(
                7,
                admitted[0].request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(1),
                |_| true,
            ),
            ExternalOpenTransition::Committed
        );
        assert_eq!(
            attachment.start(8, accepted_at),
            Err(ExternalOpenAdmissionError::TooManyInProgress),
            "committed-pending work still owns its attachment slot"
        );
        assert!(matches!(
            attachment.result(
                7,
                admitted[0].request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(2),
            ),
            ExternalOpenTransition::Closed(_)
        ));
        assert!(attachment.start(8, accepted_at).is_ok());
    }

    #[test]
    fn scheduled_expiry_times_out_at_deadline_without_settling_later_requests() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let first = requests.start(7, accepted_at).expect("first request");
        let second = requests
            .start(8, accepted_at + Duration::from_secs(2))
            .expect("second request");
        assert_eq!(requests.next_deadline(), Some(first.deadline()));

        assert_eq!(
            requests.expire_due(first.deadline()),
            vec![ExternalOpenClosed {
                request_id: first.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::TimedOutBeforeCommit,
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            }]
        );
        assert_eq!(requests.next_deadline(), Some(second.deadline()));
        assert_eq!(
            requests.ready(
                7,
                first.request_id(),
                ExternalOpenTarget::Direct,
                first.deadline(),
                |_| panic!("expired request must not queue commit"),
            ),
            ExternalOpenTransition::Ignored
        );
    }

    #[test]
    fn preparation_failure_settles_only_the_matching_source_request() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let first = requests.start(7, accepted_at).expect("first request");
        let second = requests.start(8, accepted_at).expect("second request");
        let reason = crate::protocol::ExternalOpenPreparationFailure::InvalidAbsoluteUrl;

        assert_eq!(
            requests.preparation_failed(
                8,
                first.request_id(),
                reason,
                accepted_at + Duration::from_secs(1),
            ),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(
            requests.preparation_failed(
                7,
                second.request_id(),
                reason,
                accepted_at + Duration::from_secs(1),
            ),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(
            requests.preparation_failed(
                7,
                first.request_id(),
                reason,
                accepted_at + Duration::from_secs(1),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: first.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::PreparationFailed(reason),
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            })
        );
        assert_eq!(requests.next_deadline(), Some(second.deadline()));
    }

    #[test]
    fn connection_loss_closes_only_its_requests_with_phase_truthfulness() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let committed = requests.start(7, accepted_at).expect("committed request");
        let preparing = requests.start(7, accepted_at).expect("preparing request");
        let other = requests.start(8, accepted_at).expect("other request");
        assert_eq!(
            requests.ready(
                7,
                committed.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(1),
                |_| true,
            ),
            ExternalOpenTransition::Committed
        );

        assert_eq!(
            requests.connection_lost(7),
            vec![
                ExternalOpenClosed {
                    request_id: committed.request_id(),
                    client_id: 7,
                    outcome: ExternalOpenTerminalOutcome::CommittedOutcomeUnknown,
                    accepted_at,
                    phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
                },
                ExternalOpenClosed {
                    request_id: preparing.request_id(),
                    client_id: 7,
                    outcome: ExternalOpenTerminalOutcome::ClientDisconnectedBeforeCommit,
                    accepted_at,
                    phase: ExternalOpenPhase::Preparing,
                },
            ]
        );
        assert!(requests.connection_lost(7).is_empty());
        assert_eq!(requests.next_deadline(), Some(other.deadline()));
    }

    #[test]
    fn cancellation_closes_preparing_requests_without_reclassifying_committed_work() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let committed = requests.start(7, accepted_at).expect("committed request");
        let preparing = requests.start(7, accepted_at).expect("preparing request");
        let other = requests.start(8, accepted_at).expect("other request");
        assert_eq!(
            requests.ready(
                7,
                committed.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(1),
                |_| true,
            ),
            ExternalOpenTransition::Committed
        );

        assert_eq!(
            requests.cancel_preparing_for_client(7),
            vec![ExternalOpenClosed {
                request_id: preparing.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::CancelledBeforeCommit,
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            }]
        );
        assert_eq!(
            requests.result(
                7,
                committed.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(2),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: committed.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::OpenedDirectly,
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
            })
        );
        assert_eq!(requests.next_deadline(), Some(other.deadline()));
    }

    #[test]
    fn delivery_failure_closes_only_the_exact_preparing_request() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let first = requests.start(7, accepted_at).expect("first request");
        let second = requests.start(8, accepted_at).expect("second request");

        assert_eq!(
            requests.delivery_failed(8, first.request_id()),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(
            requests.delivery_failed(7, first.request_id()),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: first.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::ClientDeliveryFailed,
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            })
        );
        assert_eq!(
            requests.delivery_failed(7, first.request_id()),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(requests.next_deadline(), Some(second.deadline()));
    }

    #[test]
    fn committed_result_must_match_its_prepared_target() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let rejected = requests.start(7, accepted_at).expect("rejected direct");
        let forwarded = requests.start(7, accepted_at).expect("forwarded");
        let invalid = requests.start(7, accepted_at).expect("invalid result");
        for (dispatch, target) in [
            (rejected, ExternalOpenTarget::Direct),
            (
                forwarded,
                ExternalOpenTarget::Forwarded {
                    port_status: crate::protocol::ExternalOpenPortStatus::SamePort,
                },
            ),
            (invalid, ExternalOpenTarget::Direct),
        ] {
            assert_eq!(
                requests.ready(
                    7,
                    dispatch.request_id(),
                    target,
                    accepted_at + Duration::from_secs(1),
                    |_| true,
                ),
                ExternalOpenTransition::Committed
            );
        }

        assert_eq!(
            requests.result(
                7,
                rejected.request_id(),
                ExternalOpenResult::PlatformOpenRejected,
                accepted_at + Duration::from_secs(2),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: rejected.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::PlatformOpenRejected,
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
            })
        );
        assert_eq!(
            requests.result(
                7,
                forwarded.request_id(),
                ExternalOpenResult::OpenedThroughForward {
                    port_status: crate::protocol::ExternalOpenPortStatus::SamePort,
                },
                accepted_at + Duration::from_secs(2),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: forwarded.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::OpenedThroughForward(
                    crate::protocol::ExternalOpenPortStatus::SamePort,
                ),
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Forwarded {
                    port_status: crate::protocol::ExternalOpenPortStatus::SamePort,
                }),
            })
        );
        assert_eq!(
            requests.result(
                7,
                invalid.request_id(),
                ExternalOpenResult::OpenedThroughForward {
                    port_status: crate::protocol::ExternalOpenPortStatus::RemappedPort,
                },
                accepted_at + Duration::from_secs(2),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: invalid.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::InvalidClientResult,
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
            })
        );
    }

    #[test]
    fn matching_result_before_commit_closes_invalid_and_cannot_revive() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let dispatch = requests.start(7, accepted_at).expect("request");

        assert_eq!(
            requests.result(
                7,
                dispatch.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(1),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: dispatch.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::InvalidClientResult,
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            })
        );
        assert_eq!(
            requests.ready(
                7,
                dispatch.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(2),
                |_| panic!("closed request must not queue commit"),
            ),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(
            requests.result(
                7,
                dispatch.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(3),
            ),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(requests.next_deadline(), None);
    }

    #[test]
    fn stale_unknown_mismatched_and_late_ids_cannot_settle_another_request() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let first = requests.start(7, accepted_at).expect("first request");
        let second = requests.start(8, accepted_at).expect("second request");

        assert_eq!(
            requests.result(
                8,
                first.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(1),
            ),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(
            requests.ready(
                8,
                first.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(1),
                |_| panic!("mismatched source must not queue commit"),
            ),
            ExternalOpenTransition::Ignored
        );
        assert_eq!(
            requests.preparation_failed(
                7,
                999,
                crate::protocol::ExternalOpenPreparationFailure::InvalidAbsoluteUrl,
                accepted_at + Duration::from_secs(1),
            ),
            ExternalOpenTransition::Ignored
        );

        assert_eq!(
            requests.ready(
                7,
                first.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(2),
                |_| true,
            ),
            ExternalOpenTransition::Committed
        );
        assert_eq!(
            requests.result(
                8,
                first.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(3),
            ),
            ExternalOpenTransition::Ignored
        );
        assert!(matches!(
            requests.result(
                7,
                first.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(3),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                outcome: ExternalOpenTerminalOutcome::OpenedDirectly,
                ..
            })
        ));
        assert_eq!(
            requests.result(
                7,
                first.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_secs(4),
            ),
            ExternalOpenTransition::Ignored
        );

        assert_eq!(
            requests.expire_due(second.deadline()),
            vec![ExternalOpenClosed {
                request_id: second.request_id(),
                client_id: 8,
                outcome: ExternalOpenTerminalOutcome::TimedOutBeforeCommit,
                accepted_at,
                phase: ExternalOpenPhase::Preparing,
            }]
        );
        assert_eq!(
            requests.ready(
                8,
                second.request_id(),
                ExternalOpenTarget::Direct,
                second.deadline(),
                |_| panic!("late request must not queue commit"),
            ),
            ExternalOpenTransition::Ignored
        );
    }

    #[test]
    fn committed_deadline_closes_as_unknown_and_ignores_late_result() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let dispatch = requests.start(7, accepted_at).expect("request");
        assert_eq!(
            requests.ready(
                7,
                dispatch.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(1),
                |_| true,
            ),
            ExternalOpenTransition::Committed
        );

        assert_eq!(
            requests.expire_due(dispatch.deadline()),
            vec![ExternalOpenClosed {
                request_id: dispatch.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::CommittedOutcomeUnknown,
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
            }]
        );
        assert_eq!(
            requests.result(
                7,
                dispatch.request_id(),
                ExternalOpenResult::OpenedDirectly,
                dispatch.deadline() + Duration::from_millis(1),
            ),
            ExternalOpenTransition::Ignored
        );
    }

    #[test]
    fn matching_direct_request_commits_before_deadline_and_settles_once() {
        let accepted_at = Instant::now();
        let mut requests = ExternalOpenRequests::default();
        let dispatch = requests
            .start(7, accepted_at)
            .expect("request id should be available");
        assert_eq!(dispatch.deadline(), accepted_at + Duration::from_secs(10));

        let commit_queued = Cell::new(false);
        assert_eq!(
            requests.ready(
                7,
                dispatch.request_id(),
                ExternalOpenTarget::Direct,
                accepted_at + Duration::from_secs(9),
                |request_id| {
                    assert_eq!(request_id, dispatch.request_id());
                    commit_queued.set(true);
                    true
                },
            ),
            ExternalOpenTransition::Committed
        );
        assert!(commit_queued.get());

        assert_eq!(
            requests.result(
                7,
                dispatch.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_millis(9_500),
            ),
            ExternalOpenTransition::Closed(ExternalOpenClosed {
                request_id: dispatch.request_id(),
                client_id: 7,
                outcome: ExternalOpenTerminalOutcome::OpenedDirectly,
                accepted_at,
                phase: ExternalOpenPhase::Committed(ExternalOpenTarget::Direct),
            })
        );
        assert_eq!(
            requests.result(
                7,
                dispatch.request_id(),
                ExternalOpenResult::OpenedDirectly,
                accepted_at + Duration::from_millis(9_600),
            ),
            ExternalOpenTransition::Ignored
        );
    }
}
