use std::collections::{BTreeMap, HashMap};
use std::io;

use crate::external_open::{
    validate_external_open_url, ExternalOpenForwarding, ExternalOpenPlatform, ExternalOpenUrlError,
    ForwardingPolicyChange, ForwardingPolicySettlement, ForwardingPreparation, LoopbackTarget,
    ValidatedExternalOpenUrl,
};
use crate::protocol::{
    ClientMessage, ExternalOpenPolicy, ExternalOpenPolicyMutationFailureStage,
    ExternalOpenPortStatus, ExternalOpenPreparationFailure, ExternalOpenResult, ExternalOpenTarget,
};

struct PreparingExternalOpen {
    original_url: String,
    platform: ExternalOpenPlatform,
    remote_port: std::num::NonZeroU16,
    operation: Box<dyn ForwardingPreparation>,
}

struct PreparedExternalOpen {
    url: String,
    target: ExternalOpenTarget,
}

enum PendingPolicyReply {
    Mutation(ClientMessage),
    Reload,
}

struct PendingPolicyChange {
    requested: ExternalOpenPolicy,
    prior_effective: ExternalOpenPolicy,
    reply: PendingPolicyReply,
    operation: Box<dyn ForwardingPolicyChange>,
}

pub(super) struct ClientExternalOpen {
    policy: ExternalOpenPolicy,
    forwarding: ExternalOpenForwarding,
    preparing: BTreeMap<u64, PreparingExternalOpen>,
    prepared: HashMap<u64, PreparedExternalOpen>,
    policy_change: Option<PendingPolicyChange>,
}

impl ClientExternalOpen {
    pub(super) fn new(policy: ExternalOpenPolicy, forwarding: ExternalOpenForwarding) -> Self {
        Self {
            policy,
            forwarding,
            preparing: BTreeMap::new(),
            prepared: HashMap::new(),
            policy_change: None,
        }
    }

    pub(super) fn policy(&self) -> ExternalOpenPolicy {
        self.policy
    }

    pub(super) fn prepare(
        &mut self,
        request_id: u64,
        url: String,
        platform: ExternalOpenPlatform,
    ) -> Option<ClientMessage> {
        if self.policy != ExternalOpenPolicy::Enabled
            || request_id == 0
            || self.preparing.contains_key(&request_id)
            || self.prepared.contains_key(&request_id)
        {
            return None;
        }

        match validate_external_open_url(&url, platform) {
            Ok(ValidatedExternalOpenUrl::Ordinary(_)) => {
                let target = ExternalOpenTarget::Direct;
                self.prepared
                    .insert(request_id, PreparedExternalOpen { url, target });
                Some(ClientMessage::ExternalOpenReady { request_id, target })
            }
            Ok(ValidatedExternalOpenUrl::Loopback(loopback)) => {
                if loopback.target() == LoopbackTarget::Localhost {
                    return Some(ClientMessage::ExternalOpenPreparationFailed {
                        request_id,
                        reason: ExternalOpenPreparationFailure::ForwardingUnavailable,
                    });
                }
                let remote_port = loopback.remote_port();
                let operation = match self
                    .forwarding
                    .begin_prepare_numeric(loopback.target(), remote_port)
                {
                    Ok(operation) => operation,
                    Err(reason) => {
                        return Some(ClientMessage::ExternalOpenPreparationFailed {
                            request_id,
                            reason,
                        });
                    }
                };
                self.preparing.insert(
                    request_id,
                    PreparingExternalOpen {
                        original_url: url,
                        platform,
                        remote_port,
                        operation,
                    },
                );
                None
            }
            Err(error) => Some(ClientMessage::ExternalOpenPreparationFailed {
                request_id,
                reason: preparation_failure(error),
            }),
        }
    }

    pub(super) fn begin_policy_mutation(&mut self, result: ClientMessage) -> Vec<ClientMessage> {
        let ClientMessage::ExternalOpenPolicyMutationResult {
            requested_policy,
            persisted_policy,
            effective_policy,
            failure_stage,
            ..
        } = &result
        else {
            return Vec::new();
        };
        let requested_policy = *requested_policy;
        if failure_stage.is_some()
            || *persisted_policy != Some(requested_policy)
            || *effective_policy != requested_policy
        {
            self.apply_policy(*effective_policy);
            return vec![result];
        }
        self.begin_policy_change(requested_policy, PendingPolicyReply::Mutation(result))
    }

    pub(super) fn begin_policy_reload(
        &mut self,
        requested: ExternalOpenPolicy,
    ) -> Vec<ClientMessage> {
        self.begin_policy_change(requested, PendingPolicyReply::Reload)
    }

    fn begin_policy_change(
        &mut self,
        requested: ExternalOpenPolicy,
        reply: PendingPolicyReply,
    ) -> Vec<ClientMessage> {
        if self.policy_change.is_some() {
            return policy_change_failed(reply, self.policy);
        }
        let prior_effective = self.policy;
        if requested == ExternalOpenPolicy::Disabled {
            self.apply_policy(ExternalOpenPolicy::Disabled);
        }
        let enabled = requested == ExternalOpenPolicy::Enabled;
        match self.forwarding.begin_set_enabled(enabled) {
            Ok(Some(operation)) => {
                self.policy_change = Some(PendingPolicyChange {
                    requested,
                    prior_effective,
                    reply,
                    operation,
                });
                Vec::new()
            }
            Ok(None) => {
                self.apply_policy(requested);
                policy_change_succeeded(reply, requested)
            }
            Err(error) => policy_change_settled(
                reply,
                requested,
                prior_effective,
                ForwardingPolicySettlement {
                    requested: enabled,
                    effective: prior_effective == ExternalOpenPolicy::Enabled,
                    result: Err(error),
                },
                |policy| self.apply_policy(policy),
            ),
        }
    }

    fn apply_policy(&mut self, policy: ExternalOpenPolicy) {
        self.policy = policy;
        if policy == ExternalOpenPolicy::Disabled {
            for preparing in self.preparing.values_mut() {
                preparing.operation.cancel();
            }
            self.preparing.clear();
            self.prepared.clear();
        }
    }

    pub(super) fn poll(&mut self) -> Vec<ClientMessage> {
        let mut messages = Vec::new();
        let ids = self.preparing.keys().copied().collect::<Vec<_>>();
        for request_id in ids {
            let result = self
                .preparing
                .get_mut(&request_id)
                .and_then(|preparing| preparing.operation.poll());
            let Some(result) = result else {
                continue;
            };
            let Some(preparing) = self.preparing.remove(&request_id) else {
                continue;
            };
            match result {
                Ok(local_port) => {
                    let rewritten =
                        validate_external_open_url(&preparing.original_url, preparing.platform)
                            .ok()
                            .and_then(|validated| match validated {
                                ValidatedExternalOpenUrl::Loopback(loopback) => {
                                    Some(loopback.rewrite_with_local_port(local_port))
                                }
                                ValidatedExternalOpenUrl::Ordinary(_) => None,
                            });
                    let Some(url) = rewritten else {
                        messages.push(ClientMessage::ExternalOpenPreparationFailed {
                            request_id,
                            reason: ExternalOpenPreparationFailure::InvalidAbsoluteUrl,
                        });
                        continue;
                    };
                    let port_status = if local_port == preparing.remote_port {
                        ExternalOpenPortStatus::SamePort
                    } else {
                        ExternalOpenPortStatus::RemappedPort
                    };
                    let target = ExternalOpenTarget::Forwarded { port_status };
                    self.prepared
                        .insert(request_id, PreparedExternalOpen { url, target });
                    messages.push(ClientMessage::ExternalOpenReady { request_id, target });
                }
                Err(error) => {
                    messages.push(ClientMessage::ExternalOpenPreparationFailed {
                        request_id,
                        reason: error.into(),
                    });
                }
            }
        }

        let policy_settlement = self
            .policy_change
            .as_mut()
            .and_then(|pending| pending.operation.poll());
        if let (Some(settlement), Some(pending)) = (policy_settlement, self.policy_change.take()) {
            messages.extend(policy_change_settled(
                pending.reply,
                pending.requested,
                pending.prior_effective,
                settlement,
                |policy| self.apply_policy(policy),
            ));
        }
        messages
    }

    pub(super) fn cancel(&mut self, request_id: u64) -> bool {
        if let Some(mut preparing) = self.preparing.remove(&request_id) {
            preparing.operation.cancel();
            return true;
        }
        self.prepared.remove(&request_id).is_some()
    }

    pub(super) fn cancel_all(&mut self) {
        for preparing in self.preparing.values_mut() {
            preparing.operation.cancel();
        }
        self.preparing.clear();
        self.prepared.clear();
        if let Some(mut policy) = self.policy_change.take() {
            policy.operation.cancel();
        }
    }

    pub(super) fn commit(&mut self, request_id: u64) -> Option<CommittedExternalOpen> {
        let prepared = self.prepared.remove(&request_id)?;
        Some(CommittedExternalOpen {
            request_id,
            url: prepared.url,
            target: prepared.target,
        })
    }
}

impl Drop for ClientExternalOpen {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

fn policy_change_succeeded(
    reply: PendingPolicyReply,
    effective: ExternalOpenPolicy,
) -> Vec<ClientMessage> {
    match reply {
        PendingPolicyReply::Mutation(result) => vec![result],
        PendingPolicyReply::Reload => {
            vec![ClientMessage::ExternalOpenPolicyUpdate { policy: effective }]
        }
    }
}

fn policy_change_failed(
    reply: PendingPolicyReply,
    effective: ExternalOpenPolicy,
) -> Vec<ClientMessage> {
    match reply {
        PendingPolicyReply::Mutation(result) => {
            vec![mutation_forwarding_failed(result, effective)]
        }
        PendingPolicyReply::Reload => vec![ClientMessage::ExternalOpenPolicyReloadFailed {
            effective_policy: effective,
        }],
    }
}

fn policy_change_settled(
    reply: PendingPolicyReply,
    requested: ExternalOpenPolicy,
    prior_effective: ExternalOpenPolicy,
    settlement: ForwardingPolicySettlement,
    mut apply: impl FnMut(ExternalOpenPolicy),
) -> Vec<ClientMessage> {
    if requested == ExternalOpenPolicy::Disabled {
        apply(ExternalOpenPolicy::Disabled);
        return policy_change_succeeded(reply, ExternalOpenPolicy::Disabled);
    }

    let effective = if settlement.effective {
        ExternalOpenPolicy::Enabled
    } else {
        ExternalOpenPolicy::Disabled
    };
    let expected_requested = requested == ExternalOpenPolicy::Enabled;
    if settlement.requested == expected_requested
        && settlement.result.is_ok()
        && effective == requested
    {
        apply(requested);
        return policy_change_succeeded(reply, requested);
    }

    let retained = if settlement.requested == expected_requested {
        effective
    } else {
        prior_effective
    };
    apply(retained);
    policy_change_failed(reply, retained)
}

fn mutation_forwarding_failed(
    result: ClientMessage,
    effective_policy: ExternalOpenPolicy,
) -> ClientMessage {
    match result {
        ClientMessage::ExternalOpenPolicyMutationResult {
            request_id,
            requested_policy,
            persisted_policy,
            ..
        } => ClientMessage::ExternalOpenPolicyMutationResult {
            request_id,
            requested_policy,
            persisted_policy,
            effective_policy,
            failure_stage: Some(ExternalOpenPolicyMutationFailureStage::Reload),
        },
        message => message,
    }
}

pub(super) struct CommittedExternalOpen {
    request_id: u64,
    url: String,
    target: ExternalOpenTarget,
}

impl CommittedExternalOpen {
    pub(super) fn execute(self, opener: impl FnOnce(&str) -> io::Result<()>) -> ClientMessage {
        let result = match opener(&self.url) {
            Ok(()) => match self.target {
                ExternalOpenTarget::Direct => ExternalOpenResult::OpenedDirectly,
                ExternalOpenTarget::Forwarded { port_status } => {
                    ExternalOpenResult::OpenedThroughForward { port_status }
                }
            },
            Err(_) => ExternalOpenResult::PlatformOpenRejected,
        };
        ClientMessage::ExternalOpenResult {
            request_id: self.request_id,
            result,
        }
    }
}

fn preparation_failure(error: ExternalOpenUrlError) -> ExternalOpenPreparationFailure {
    match error {
        ExternalOpenUrlError::UnsupportedScheme => {
            ExternalOpenPreparationFailure::UnsupportedScheme
        }
        ExternalOpenUrlError::AuthorityUserinfoForbidden => {
            ExternalOpenPreparationFailure::AuthorityUserinfoForbidden
        }
        ExternalOpenUrlError::InvalidPort => ExternalOpenPreparationFailure::InvalidPort,
        ExternalOpenUrlError::InvalidAbsoluteUrl => {
            ExternalOpenPreparationFailure::InvalidAbsoluteUrl
        }
        ExternalOpenUrlError::UnsupportedLoopbackForm => {
            ExternalOpenPreparationFailure::UnsupportedLoopbackForm
        }
        ExternalOpenUrlError::LoopbackUnsupportedOnPlatform => {
            ExternalOpenPreparationFailure::LoopbackUnsupportedOnPlatform
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::num::NonZeroU16;
    use std::sync::{Arc, Mutex};

    use crate::external_open::{
        ForwardingController, ForwardingPreparation, ForwardingPreparationError,
    };

    use super::*;

    type PreparationPoll = Option<Result<NonZeroU16, ForwardingPreparationError>>;
    type PreparationResults = Arc<Mutex<VecDeque<PreparationPoll>>>;

    struct FakePreparation {
        results: PreparationResults,
        cancellations: Arc<Mutex<usize>>,
    }

    impl ForwardingPreparation for FakePreparation {
        fn poll(&mut self) -> Option<Result<NonZeroU16, ForwardingPreparationError>> {
            self.results.lock().expect("results").pop_front().flatten()
        }

        fn cancel(&mut self) {
            *self.cancellations.lock().expect("cancellations") += 1;
        }
    }

    struct FakePolicyChange {
        result: Option<ForwardingPolicySettlement>,
    }

    impl ForwardingPolicyChange for FakePolicyChange {
        fn poll(&mut self) -> Option<ForwardingPolicySettlement> {
            self.result.take()
        }
        fn cancel(&mut self) {
            self.result = None;
        }
    }

    struct FakeForwardingController {
        results: PreparationResults,
        requests: Mutex<Vec<(LoopbackTarget, NonZeroU16)>>,
        cancellations: Arc<Mutex<usize>>,
        begin_error: Mutex<Option<ForwardingPreparationError>>,
        policy_result: Mutex<Option<ForwardingPolicySettlement>>,
    }

    impl FakeForwardingController {
        fn with_results(results: impl IntoIterator<Item = PreparationPoll>) -> Self {
            Self {
                results: Arc::new(Mutex::new(results.into_iter().collect())),
                requests: Mutex::new(Vec::new()),
                cancellations: Arc::new(Mutex::new(0)),
                begin_error: Mutex::new(None),
                policy_result: Mutex::new(None),
            }
        }

        fn with_begin_error(error: ForwardingPreparationError) -> Self {
            let controller = Self::with_results([]);
            *controller.begin_error.lock().expect("begin error") = Some(error);
            controller
        }
    }

    fn persisted_mutation(request_id: u64, requested: ExternalOpenPolicy) -> ClientMessage {
        ClientMessage::ExternalOpenPolicyMutationResult {
            request_id,
            requested_policy: requested,
            persisted_policy: Some(requested),
            effective_policy: requested,
            failure_stage: None,
        }
    }

    impl ForwardingController for FakeForwardingController {
        fn begin_prepare_numeric(
            &self,
            target: LoopbackTarget,
            remote_port: NonZeroU16,
        ) -> Result<Box<dyn ForwardingPreparation>, ForwardingPreparationError> {
            self.requests
                .lock()
                .expect("requests")
                .push((target, remote_port));
            if let Some(error) = self.begin_error.lock().expect("begin error").take() {
                return Err(error);
            }
            Ok(Box::new(FakePreparation {
                results: Arc::clone(&self.results),
                cancellations: Arc::clone(&self.cancellations),
            }))
        }

        fn begin_set_enabled(
            &self,
            enabled: bool,
        ) -> Result<Box<dyn ForwardingPolicyChange>, ForwardingPreparationError> {
            let result = self
                .policy_result
                .lock()
                .expect("policy result")
                .take()
                .unwrap_or(ForwardingPolicySettlement {
                    requested: enabled,
                    effective: enabled,
                    result: Ok(()),
                });
            Ok(Box::new(FakePolicyChange {
                result: Some(result),
            }))
        }
    }

    #[test]
    fn blocked_forward_is_nonblocking_and_late_completion_requires_poll_before_commit() {
        let local_port = NonZeroU16::new(8080).expect("port");
        let controller = Arc::new(FakeForwardingController::with_results([
            None,
            Some(Ok(local_port)),
        ]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            ExternalOpenForwarding::available(controller),
        );

        assert_eq!(
            external_open.prepare(
                41,
                "http://127.0.0.1:8080/private".to_owned(),
                ExternalOpenPlatform::Linux,
            ),
            None
        );
        assert!(external_open.poll().is_empty());
        assert!(external_open.commit(41).is_none());
        assert_eq!(
            external_open.poll(),
            vec![ClientMessage::ExternalOpenReady {
                request_id: 41,
                target: ExternalOpenTarget::Forwarded {
                    port_status: ExternalOpenPortStatus::SamePort,
                },
            }]
        );
    }

    #[test]
    fn cancellation_policy_disable_and_disconnect_isolate_late_completion() {
        let controller = Arc::new(FakeForwardingController::with_results([
            None,
            Some(Ok(NonZeroU16::new(8080).expect("port"))),
        ]));
        let cancellations = Arc::clone(&controller.cancellations);
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            ExternalOpenForwarding::available(controller),
        );
        assert!(external_open
            .prepare(
                41,
                "http://127.0.0.1:8080/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_none());
        assert!(external_open.cancel(41));
        assert!(external_open.poll().is_empty());
        assert!(external_open.commit(41).is_none());
        assert_eq!(*cancellations.lock().expect("cancellations"), 1);
    }

    #[test]
    fn policy_disable_cancels_blocked_preparation_and_ignores_late_readiness() {
        let controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(8080).expect("port"),
        ))]));
        let cancellations = Arc::clone(&controller.cancellations);
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            ExternalOpenForwarding::available(controller),
        );
        assert!(external_open
            .prepare(
                41,
                "http://127.0.0.1:8080/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_none());

        assert!(external_open
            .begin_policy_mutation(persisted_mutation(7, ExternalOpenPolicy::Disabled))
            .is_empty());
        let messages = external_open.poll();

        assert_eq!(*cancellations.lock().expect("cancellations"), 1);
        assert_eq!(
            messages,
            vec![persisted_mutation(7, ExternalOpenPolicy::Disabled)]
        );
        assert!(external_open.commit(41).is_none());
    }

    #[test]
    fn deadline_cancel_and_disconnect_drop_blocked_work_without_late_commit_authority() {
        let controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(8080).expect("port"),
        ))]));
        let cancellations = Arc::clone(&controller.cancellations);
        {
            let mut external_open = ClientExternalOpen::new(
                ExternalOpenPolicy::Enabled,
                ExternalOpenForwarding::available(controller),
            );
            assert!(external_open
                .prepare(
                    41,
                    "http://127.0.0.1:8080/private".to_owned(),
                    ExternalOpenPlatform::Linux,
                )
                .is_none());
            assert!(external_open.cancel(41));
            assert!(external_open.commit(41).is_none());
        }
        assert_eq!(*cancellations.lock().expect("cancellations"), 1);
    }

    #[test]
    fn disconnect_cancels_every_blocked_preparation() {
        let controller = Arc::new(FakeForwardingController::with_results([None, None]));
        let cancellations = Arc::clone(&controller.cancellations);
        {
            let mut external_open = ClientExternalOpen::new(
                ExternalOpenPolicy::Enabled,
                ExternalOpenForwarding::available(controller),
            );
            for request_id in [41, 42] {
                assert!(external_open
                    .prepare(
                        request_id,
                        format!("http://127.0.0.1:{request_id}/private"),
                        ExternalOpenPlatform::Linux,
                    )
                    .is_none());
            }
        }
        assert_eq!(*cancellations.lock().expect("cancellations"), 2);
    }

    #[test]
    fn activation_failure_uses_the_existing_mutation_result_and_notice_stage() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        *controller.policy_result.lock().expect("policy result") =
            Some(ForwardingPolicySettlement {
                requested: true,
                effective: false,
                result: Err(ForwardingPreparationError::CommandRejected),
            });
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Disabled,
            ExternalOpenForwarding::available(controller),
        );

        assert!(external_open
            .begin_policy_mutation(persisted_mutation(10, ExternalOpenPolicy::Enabled))
            .is_empty());
        assert_eq!(
            external_open.poll(),
            vec![ClientMessage::ExternalOpenPolicyMutationResult {
                request_id: 10,
                requested_policy: ExternalOpenPolicy::Enabled,
                persisted_policy: Some(ExternalOpenPolicy::Enabled),
                effective_policy: ExternalOpenPolicy::Disabled,
                failure_stage: Some(ExternalOpenPolicyMutationFailureStage::Reload),
            }]
        );
        assert_eq!(external_open.policy(), ExternalOpenPolicy::Disabled);
    }

    #[test]
    fn confirmed_disable_emits_one_truthful_mutation_without_reload_failure() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        *controller.policy_result.lock().expect("policy result") =
            Some(ForwardingPolicySettlement {
                requested: false,
                effective: false,
                result: Err(ForwardingPreparationError::CommandRejected),
            });
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            ExternalOpenForwarding::available(controller),
        );

        assert!(external_open
            .begin_policy_mutation(persisted_mutation(11, ExternalOpenPolicy::Disabled))
            .is_empty());
        assert_eq!(
            external_open.poll(),
            vec![persisted_mutation(11, ExternalOpenPolicy::Disabled)]
        );
        assert_eq!(external_open.policy(), ExternalOpenPolicy::Disabled);
    }

    #[test]
    fn forwarded_url_is_opaque_to_opener_until_commit() {
        let controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(43_123).expect("port"),
        ))]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            ExternalOpenForwarding::available(controller),
        );
        let opened = RefCell::new(Vec::new());

        assert!(external_open
            .prepare(
                51,
                "HTTPS://[::1]:00443/a%2Fb?token=A%2BB#Frag".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_none());
        assert_eq!(external_open.poll().len(), 1);
        assert!(opened.borrow().is_empty());
        let result = external_open.commit(51).expect("commit").execute(|url| {
            opened.borrow_mut().push(url.to_owned());
            Err(io::Error::other("rejected"))
        });
        assert_eq!(
            result,
            ClientMessage::ExternalOpenResult {
                request_id: 51,
                result: ExternalOpenResult::PlatformOpenRejected,
            }
        );
        assert_eq!(
            *opened.borrow(),
            vec!["HTTPS://[::1]:43123/a%2Fb?token=A%2BB#Frag"]
        );
    }

    #[test]
    fn capability_and_async_controller_failures_are_typed_and_never_committable() {
        let immediate = [
            (
                ExternalOpenForwarding::ManagedSshRequired,
                ExternalOpenPreparationFailure::ManagedSshRequired,
            ),
            (
                ExternalOpenForwarding::Unavailable,
                ExternalOpenPreparationFailure::ForwardingUnavailable,
            ),
        ];
        for (offset, (forwarding, expected)) in immediate.into_iter().enumerate() {
            let request_id = 60 + u64::try_from(offset).expect("small offset");
            let mut external_open =
                ClientExternalOpen::new(ExternalOpenPolicy::Enabled, forwarding);
            assert_eq!(
                external_open.prepare(
                    request_id,
                    "http://127.0.0.1:8080/private".to_owned(),
                    ExternalOpenPlatform::Linux,
                ),
                Some(ClientMessage::ExternalOpenPreparationFailed {
                    request_id,
                    reason: expected,
                })
            );
            assert!(external_open.commit(request_id).is_none());
        }

        let translations = [
            (
                ForwardingPreparationError::TooManyRequests,
                ExternalOpenPreparationFailure::TooManyForwardRequests,
            ),
            (
                ForwardingPreparationError::BindExhausted,
                ExternalOpenPreparationFailure::ForwardBindExhausted,
            ),
            (
                ForwardingPreparationError::CommandRejected,
                ExternalOpenPreparationFailure::ForwardCommandRejected,
            ),
            (
                ForwardingPreparationError::CommandTimedOut,
                ExternalOpenPreparationFailure::ForwardCommandTimedOut,
            ),
            (
                ForwardingPreparationError::Unavailable,
                ExternalOpenPreparationFailure::ForwardingUnavailable,
            ),
        ];
        for (offset, (error, expected)) in translations.into_iter().enumerate() {
            for (phase_offset, controller) in [
                Arc::new(FakeForwardingController::with_begin_error(error)),
                Arc::new(FakeForwardingController::with_results([Some(Err(error))])),
            ]
            .into_iter()
            .enumerate()
            {
                let request_id =
                    70 + u64::try_from(offset * 2 + phase_offset).expect("small offset");
                let mut external_open = ClientExternalOpen::new(
                    ExternalOpenPolicy::Enabled,
                    ExternalOpenForwarding::available(controller),
                );
                let immediate = external_open.prepare(
                    request_id,
                    "http://127.0.0.1:8080/private".to_owned(),
                    ExternalOpenPlatform::Linux,
                );
                let messages = immediate
                    .into_iter()
                    .chain(external_open.poll())
                    .collect::<Vec<_>>();
                assert_eq!(
                    messages,
                    vec![ClientMessage::ExternalOpenPreparationFailed {
                        request_id,
                        reason: expected,
                    }]
                );
                assert!(external_open.commit(request_id).is_none());
            }
        }
    }

    #[test]
    fn ordinary_url_remains_immediately_ready_without_forwarding() {
        let original = "https://example.com/a%2Fb?token=A%2BB#Frag";
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            ExternalOpenForwarding::Unavailable,
        );

        assert_eq!(
            external_open.prepare(71, original.to_owned(), ExternalOpenPlatform::Linux),
            Some(ClientMessage::ExternalOpenReady {
                request_id: 71,
                target: ExternalOpenTarget::Direct,
            })
        );
    }
}
