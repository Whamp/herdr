use std::collections::{BTreeMap, HashMap};
use std::io;

use crate::config::SavedPortForwardLimit;
use crate::external_open::{
    validate_external_open_url, ExternalOpenForwarding, ExternalOpenPlatform, ExternalOpenUrlError,
    ForwardingPolicyChange, ForwardingPolicySettlement, ForwardingPreparation,
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
    Reload { report_section_failure: bool },
}

struct PendingPolicyChange {
    requested: ExternalOpenPolicy,
    requested_saved_mapping_limit: SavedPortForwardLimit,
    prior_effective: ExternalOpenPolicy,
    prior_saved_mapping_limit: SavedPortForwardLimit,
    reply: PendingPolicyReply,
    operation: Box<dyn ForwardingPolicyChange>,
}

pub(super) struct ClientExternalOpen {
    policy: ExternalOpenPolicy,
    saved_mapping_limit: SavedPortForwardLimit,
    forwarding: ExternalOpenForwarding,
    preparing: BTreeMap<u64, PreparingExternalOpen>,
    prepared: HashMap<u64, PreparedExternalOpen>,
    policy_change: Option<PendingPolicyChange>,
}

impl ClientExternalOpen {
    pub(super) fn new(
        policy: ExternalOpenPolicy,
        saved_mapping_limit: SavedPortForwardLimit,
        forwarding: ExternalOpenForwarding,
    ) -> Self {
        Self {
            policy,
            saved_mapping_limit,
            forwarding,
            preparing: BTreeMap::new(),
            prepared: HashMap::new(),
            policy_change: None,
        }
    }

    pub(super) fn policy(&self) -> ExternalOpenPolicy {
        self.policy
    }

    pub(super) fn saved_mapping_limit(&self) -> SavedPortForwardLimit {
        self.saved_mapping_limit
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
                let remote_port = loopback.remote_port();
                #[cfg(debug_assertions)]
                if let Some(result) = external_open_forward_port_for_test() {
                    let local_port = match result {
                        Ok(local_port) => local_port,
                        Err(reason) => {
                            return Some(ClientMessage::ExternalOpenPreparationFailed {
                                request_id,
                                reason,
                            });
                        }
                    };
                    let url = loopback.rewrite_with_local_port(local_port);
                    let port_status = if local_port == remote_port {
                        ExternalOpenPortStatus::SamePort
                    } else {
                        ExternalOpenPortStatus::RemappedPort
                    };
                    let target = ExternalOpenTarget::Forwarded { port_status };
                    self.prepared
                        .insert(request_id, PreparedExternalOpen { url, target });
                    return Some(ClientMessage::ExternalOpenReady { request_id, target });
                }
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
            self.apply_configuration(*effective_policy, self.saved_mapping_limit);
            return vec![result];
        }
        self.begin_policy_change(
            requested_policy,
            self.saved_mapping_limit,
            PendingPolicyReply::Mutation(result),
        )
    }

    pub(super) fn begin_policy_reload(
        &mut self,
        requested: ExternalOpenPolicy,
        saved_mapping_limit: SavedPortForwardLimit,
        report_section_failure: bool,
    ) -> Vec<ClientMessage> {
        self.begin_policy_change(
            requested,
            saved_mapping_limit,
            PendingPolicyReply::Reload {
                report_section_failure,
            },
        )
    }

    fn begin_policy_change(
        &mut self,
        requested: ExternalOpenPolicy,
        requested_saved_mapping_limit: SavedPortForwardLimit,
        reply: PendingPolicyReply,
    ) -> Vec<ClientMessage> {
        if self.policy_change.is_some() {
            return policy_change_failed(reply, self.policy);
        }
        let prior_effective = self.policy;
        let prior_saved_mapping_limit = self.saved_mapping_limit;
        let mut immediate_messages = Vec::new();
        if requested == ExternalOpenPolicy::Disabled {
            self.apply_configuration(ExternalOpenPolicy::Disabled, self.saved_mapping_limit);
            immediate_messages.push(ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Disabled,
            });
        }
        let enabled = requested == ExternalOpenPolicy::Enabled;
        match self
            .forwarding
            .begin_set_enabled(enabled, requested_saved_mapping_limit)
        {
            Ok(Some(operation)) => {
                self.policy_change = Some(PendingPolicyChange {
                    requested,
                    requested_saved_mapping_limit,
                    prior_effective,
                    prior_saved_mapping_limit,
                    reply,
                    operation,
                });
                immediate_messages
            }
            Ok(None) if requested_saved_mapping_limit == prior_saved_mapping_limit => {
                self.apply_configuration(requested, prior_saved_mapping_limit);
                immediate_messages.extend(policy_change_succeeded(reply, requested));
                immediate_messages
            }
            Ok(None) => {
                self.apply_configuration(requested, prior_saved_mapping_limit);
                immediate_messages.extend(policy_change_without_broker(reply, requested));
                immediate_messages
            }
            Err(error) => {
                immediate_messages.extend(policy_change_settled(
                    reply,
                    requested,
                    requested_saved_mapping_limit,
                    prior_effective,
                    ForwardingPolicySettlement {
                        requested: enabled,
                        effective: prior_effective == ExternalOpenPolicy::Enabled,
                        requested_saved_mapping_limit,
                        effective_saved_mapping_limit: prior_saved_mapping_limit,
                        result: Err(error),
                    },
                    prior_saved_mapping_limit,
                    |policy, limit| self.apply_configuration(policy, limit),
                ));
                immediate_messages
            }
        }
    }

    fn apply_configuration(
        &mut self,
        policy: ExternalOpenPolicy,
        saved_mapping_limit: SavedPortForwardLimit,
    ) {
        self.policy = policy;
        self.saved_mapping_limit = saved_mapping_limit;
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
        let Some(settlement) = policy_settlement else {
            return messages;
        };
        let Some(pending) = self.policy_change.take() else {
            return messages;
        };
        messages.extend(policy_change_settled(
            pending.reply,
            pending.requested,
            pending.requested_saved_mapping_limit,
            pending.prior_effective,
            settlement,
            pending.prior_saved_mapping_limit,
            |policy, limit| self.apply_configuration(policy, limit),
        ));
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

#[cfg(debug_assertions)]
fn external_open_forward_port_for_test(
) -> Option<Result<std::num::NonZeroU16, ExternalOpenPreparationFailure>> {
    let path = std::env::var_os("HERDR_TEST_EXTERNAL_OPEN_FORWARD_PORT_PATH")?;
    let value = match std::fs::read_to_string(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => {
            return Some(Err(
                ExternalOpenPreparationFailure::AtomicForwardCreationFailed,
            ));
        }
    };
    if std::fs::remove_file(path).is_err() {
        return Some(Err(
            ExternalOpenPreparationFailure::AtomicForwardCreationFailed,
        ));
    }
    Some(
        value
            .trim()
            .parse::<u16>()
            .ok()
            .and_then(std::num::NonZeroU16::new)
            .ok_or(ExternalOpenPreparationFailure::AtomicForwardCreationFailed),
    )
}

fn policy_change_succeeded(
    reply: PendingPolicyReply,
    effective: ExternalOpenPolicy,
) -> Vec<ClientMessage> {
    match reply {
        PendingPolicyReply::Mutation(result) => vec![result],
        PendingPolicyReply::Reload {
            report_section_failure,
        } => {
            let mut messages = vec![ClientMessage::ExternalOpenPolicyUpdate { policy: effective }];
            if report_section_failure {
                messages.push(ClientMessage::ExternalOpenPolicyReloadFailed {
                    effective_policy: effective,
                    cleanup_incomplete: false,
                });
            }
            messages
        }
    }
}

fn policy_change_without_broker(
    reply: PendingPolicyReply,
    effective: ExternalOpenPolicy,
) -> Vec<ClientMessage> {
    match reply {
        PendingPolicyReply::Mutation(result) => {
            vec![mutation_forwarding_failed(result, effective)]
        }
        PendingPolicyReply::Reload { .. } => vec![
            ClientMessage::ExternalOpenPolicyUpdate { policy: effective },
            ClientMessage::ExternalOpenPolicyReloadFailed {
                effective_policy: effective,
                cleanup_incomplete: false,
            },
        ],
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
        PendingPolicyReply::Reload { .. } => {
            vec![ClientMessage::ExternalOpenPolicyReloadFailed {
                effective_policy: effective,
                cleanup_incomplete: false,
            }]
        }
    }
}

fn policy_disable_cleanup_incomplete(
    reply: PendingPolicyReply,
    effective: ExternalOpenPolicy,
) -> Vec<ClientMessage> {
    match reply {
        PendingPolicyReply::Mutation(result) => {
            vec![mutation_forwarding_failed(result, effective)]
        }
        PendingPolicyReply::Reload { .. } => {
            vec![ClientMessage::ExternalOpenPolicyReloadFailed {
                effective_policy: effective,
                cleanup_incomplete: true,
            }]
        }
    }
}

fn policy_change_settled(
    reply: PendingPolicyReply,
    requested: ExternalOpenPolicy,
    requested_saved_mapping_limit: SavedPortForwardLimit,
    prior_effective: ExternalOpenPolicy,
    settlement: ForwardingPolicySettlement,
    prior_saved_mapping_limit: SavedPortForwardLimit,
    mut apply: impl FnMut(ExternalOpenPolicy, SavedPortForwardLimit),
) -> Vec<ClientMessage> {
    if requested == ExternalOpenPolicy::Disabled {
        let cleanup_incomplete = settlement.result.is_err();
        let acknowledged_limit = !settlement.requested
            && settlement.requested_saved_mapping_limit == requested_saved_mapping_limit
            && settlement.effective_saved_mapping_limit == requested_saved_mapping_limit
            && settlement.result.is_ok();
        if requested_saved_mapping_limit != prior_saved_mapping_limit && !acknowledged_limit {
            apply(ExternalOpenPolicy::Disabled, prior_saved_mapping_limit);
            return if cleanup_incomplete {
                policy_disable_cleanup_incomplete(reply, ExternalOpenPolicy::Disabled)
            } else {
                policy_change_failed(reply, ExternalOpenPolicy::Disabled)
            };
        }
        let retained_limit = if acknowledged_limit {
            requested_saved_mapping_limit
        } else {
            prior_saved_mapping_limit
        };
        apply(ExternalOpenPolicy::Disabled, retained_limit);
        return if cleanup_incomplete {
            policy_disable_cleanup_incomplete(reply, ExternalOpenPolicy::Disabled)
        } else {
            policy_change_succeeded(reply, ExternalOpenPolicy::Disabled)
        };
    }

    let effective = if settlement.effective {
        ExternalOpenPolicy::Enabled
    } else {
        ExternalOpenPolicy::Disabled
    };
    let expected_requested = requested == ExternalOpenPolicy::Enabled;
    if settlement.requested == expected_requested
        && settlement.requested_saved_mapping_limit == requested_saved_mapping_limit
        && settlement.effective_saved_mapping_limit == requested_saved_mapping_limit
        && settlement.result.is_ok()
        && effective == requested
    {
        apply(requested, requested_saved_mapping_limit);
        return policy_change_succeeded(reply, requested);
    }

    let retained = if settlement.requested == expected_requested {
        effective
    } else {
        prior_effective
    };
    apply(retained, prior_saved_mapping_limit);
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
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::num::NonZeroU16;
    #[cfg(target_os = "macos")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::config::SavedPortForwardLimit;
    use crate::external_open::{
        ForwardingController, ForwardingPreparation, ForwardingPreparationError, LoopbackTarget,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::remote::forwarding::ForwardingBrokerTestHarness;

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
        empty_polls: usize,
        result: Option<ForwardingPolicySettlement>,
    }

    impl ForwardingPolicyChange for FakePolicyChange {
        fn poll(&mut self) -> Option<ForwardingPolicySettlement> {
            if self.empty_polls > 0 {
                self.empty_polls -= 1;
                return None;
            }
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
        policy_empty_polls: Mutex<usize>,
        policy_result: Mutex<Option<ForwardingPolicySettlement>>,
    }

    #[cfg(target_os = "macos")]
    struct CountingForwardingController {
        inner: Arc<dyn ForwardingController>,
        begin_prepare_calls: AtomicUsize,
    }

    #[cfg(target_os = "macos")]
    impl CountingForwardingController {
        fn new(inner: Arc<dyn ForwardingController>) -> Self {
            Self {
                inner,
                begin_prepare_calls: AtomicUsize::new(0),
            }
        }

        fn begin_prepare_calls(&self) -> usize {
            self.begin_prepare_calls.load(Ordering::SeqCst)
        }
    }

    #[cfg(target_os = "macos")]
    impl ForwardingController for CountingForwardingController {
        fn begin_prepare_numeric(
            &self,
            target: LoopbackTarget,
            remote_port: NonZeroU16,
        ) -> Result<Box<dyn ForwardingPreparation>, ForwardingPreparationError> {
            self.begin_prepare_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.begin_prepare_numeric(target, remote_port)
        }

        fn begin_set_enabled(
            &self,
            enabled: bool,
            saved_mapping_limit: SavedPortForwardLimit,
        ) -> Result<Box<dyn ForwardingPolicyChange>, ForwardingPreparationError> {
            self.inner.begin_set_enabled(enabled, saved_mapping_limit)
        }
    }

    impl FakeForwardingController {
        fn with_results(results: impl IntoIterator<Item = PreparationPoll>) -> Self {
            Self {
                results: Arc::new(Mutex::new(results.into_iter().collect())),
                requests: Mutex::new(Vec::new()),
                cancellations: Arc::new(Mutex::new(0)),
                begin_error: Mutex::new(None),
                policy_empty_polls: Mutex::new(0),
                policy_result: Mutex::new(None),
            }
        }

        fn with_begin_error(error: ForwardingPreparationError) -> Self {
            let controller = Self::with_results([]);
            *controller.begin_error.lock().expect("begin error") = Some(error);
            controller
        }
    }

    fn saved_limit(value: u8) -> SavedPortForwardLimit {
        SavedPortForwardLimit::new(value).expect("valid saved mapping limit")
    }

    fn opener_calls_if_committed(external_open: &mut ClientExternalOpen, request_id: u64) -> usize {
        let calls = Cell::new(0);
        if let Some(committed) = external_open.commit(request_id) {
            let _ = committed.execute(|_| {
                calls.set(calls.get() + 1);
                Ok(())
            });
        }
        calls.get()
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
            saved_mapping_limit: SavedPortForwardLimit,
        ) -> Result<Box<dyn ForwardingPolicyChange>, ForwardingPreparationError> {
            let result = self
                .policy_result
                .lock()
                .expect("policy result")
                .take()
                .unwrap_or(ForwardingPolicySettlement {
                    requested: enabled,
                    effective: enabled,
                    requested_saved_mapping_limit: saved_mapping_limit,
                    effective_saved_mapping_limit: saved_mapping_limit,
                    result: Ok(()),
                });
            Ok(Box::new(FakePolicyChange {
                empty_polls: std::mem::take(
                    &mut *self.policy_empty_polls.lock().expect("policy empty polls"),
                ),
                result: Some(result),
            }))
        }
    }

    #[test]
    fn every_url_policy_failure_is_typed_and_has_zero_opener_authority() {
        let cases = [
            (
                "ftp://example.test/private",
                ExternalOpenPlatform::Linux,
                ExternalOpenPreparationFailure::UnsupportedScheme,
            ),
            (
                "http://userinfo@example.test/private",
                ExternalOpenPlatform::Linux,
                ExternalOpenPreparationFailure::AuthorityUserinfoForbidden,
            ),
            (
                "http://example.test:0/private",
                ExternalOpenPlatform::Linux,
                ExternalOpenPreparationFailure::InvalidPort,
            ),
            (
                "http:///private",
                ExternalOpenPlatform::Linux,
                ExternalOpenPreparationFailure::InvalidAbsoluteUrl,
            ),
            (
                "http://127.1/private",
                ExternalOpenPlatform::Linux,
                ExternalOpenPreparationFailure::UnsupportedLoopbackForm,
            ),
            (
                "http://127.0.0.2/private",
                ExternalOpenPlatform::MacOs,
                ExternalOpenPreparationFailure::LoopbackUnsupportedOnPlatform,
            ),
        ];

        for (offset, (url, platform, expected)) in cases.into_iter().enumerate() {
            let request_id = 1 + u64::try_from(offset).expect("small case count");
            let mut external_open = ClientExternalOpen::new(
                ExternalOpenPolicy::Enabled,
                SavedPortForwardLimit::DEFAULT,
                ExternalOpenForwarding::Unavailable,
            );
            assert_eq!(
                external_open.prepare(request_id, url.to_owned(), platform),
                Some(ClientMessage::ExternalOpenPreparationFailed {
                    request_id,
                    reason: expected,
                })
            );
            assert_eq!(opener_calls_if_committed(&mut external_open, request_id), 0);
        }
    }

    #[test]
    fn client_socket_authority_matrix_calls_recording_opener_only_after_commit() {
        fn direct_client() -> ClientExternalOpen {
            ClientExternalOpen::new(
                ExternalOpenPolicy::Enabled,
                SavedPortForwardLimit::DEFAULT,
                ExternalOpenForwarding::Unavailable,
            )
        }

        fn execute_if_committed(
            external_open: &mut ClientExternalOpen,
            request_id: u64,
            calls: &Cell<usize>,
            opener_result: io::Result<()>,
        ) -> Option<ClientMessage> {
            external_open.commit(request_id).map(|committed| {
                committed.execute(|_| {
                    calls.set(calls.get() + 1);
                    opener_result
                })
            })
        }

        let mut observed = Vec::new();
        for label in ["admission", "precommit", "invalid"] {
            let mut external_open = direct_client();
            let calls = Cell::new(0);
            if label != "admission" {
                assert!(matches!(
                    external_open.prepare(
                        1,
                        "https://example.test/private".to_owned(),
                        ExternalOpenPlatform::Linux,
                    ),
                    Some(ClientMessage::ExternalOpenReady { request_id: 1, .. })
                ));
            }
            // No commit command crossed the socket authority boundary.
            observed.push((label, calls.get()));
            external_open.cancel_all();
            assert!(execute_if_committed(&mut external_open, 1, &calls, Ok(())).is_none());
        }

        let mut preparation = direct_client();
        let preparation_calls = Cell::new(0);
        assert!(matches!(
            preparation.prepare(
                2,
                "ftp://example.test/private".to_owned(),
                ExternalOpenPlatform::Linux,
            ),
            Some(ClientMessage::ExternalOpenPreparationFailed { request_id: 2, .. })
        ));
        assert!(execute_if_committed(&mut preparation, 2, &preparation_calls, Ok(())).is_none());
        observed.push(("preparation", preparation_calls.get()));

        for label in ["cancellation", "timeout"] {
            let mut external_open = direct_client();
            let calls = Cell::new(0);
            assert!(matches!(
                external_open.prepare(
                    3,
                    "https://example.test/private".to_owned(),
                    ExternalOpenPlatform::Linux,
                ),
                Some(ClientMessage::ExternalOpenReady { request_id: 3, .. })
            ));
            assert!(external_open.cancel(3));
            assert!(execute_if_committed(&mut external_open, 3, &calls, Ok(())).is_none());
            observed.push((label, calls.get()));
        }

        let mut disabled = direct_client();
        let disabled_calls = Cell::new(0);
        assert!(disabled
            .prepare(
                4,
                "https://example.test/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_some());
        disabled.begin_policy_mutation(persisted_mutation(40, ExternalOpenPolicy::Disabled));
        assert!(execute_if_committed(&mut disabled, 4, &disabled_calls, Ok(())).is_none());
        observed.push(("disable", disabled_calls.get()));

        for label in ["disconnect", "delivery"] {
            let mut external_open = direct_client();
            let calls = Cell::new(0);
            assert!(external_open
                .prepare(
                    5,
                    "https://example.test/private".to_owned(),
                    ExternalOpenPlatform::Linux,
                )
                .is_some());
            external_open.cancel_all();
            assert!(execute_if_committed(&mut external_open, 5, &calls, Ok(())).is_none());
            observed.push((label, calls.get()));
        }

        assert_eq!(
            observed,
            vec![
                ("admission", 0),
                ("precommit", 0),
                ("invalid", 0),
                ("preparation", 0),
                ("cancellation", 0),
                ("timeout", 0),
                ("disable", 0),
                ("disconnect", 0),
                ("delivery", 0),
            ]
        );

        let mut successful = direct_client();
        assert!(successful
            .prepare(
                6,
                "https://example.test/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_some());
        let success_calls = Cell::new(0);
        assert_eq!(
            execute_if_committed(&mut successful, 6, &success_calls, Ok(())),
            Some(ClientMessage::ExternalOpenResult {
                request_id: 6,
                result: ExternalOpenResult::OpenedDirectly,
            })
        );
        assert_eq!(success_calls.get(), 1);
        assert!(
            execute_if_committed(&mut successful, 6, &success_calls, Ok(())).is_none(),
            "committed unknown must never retry an opener"
        );
        assert_eq!(success_calls.get(), 1);

        let mut rejected = direct_client();
        assert!(rejected
            .prepare(
                7,
                "https://example.test/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_some());
        let rejection_calls = Cell::new(0);
        assert!(matches!(
            execute_if_committed(
                &mut rejected,
                7,
                &rejection_calls,
                Err(io::Error::other("recording opener rejection")),
            ),
            Some(ClientMessage::ExternalOpenResult {
                request_id: 7,
                result: ExternalOpenResult::PlatformOpenRejected,
            })
        ));
        assert_eq!(rejection_calls.get(), 1);
        assert!(execute_if_committed(&mut rejected, 7, &rejection_calls, Ok(())).is_none());
        assert_eq!(rejection_calls.get(), 1);
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
            SavedPortForwardLimit::DEFAULT,
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
            SavedPortForwardLimit::DEFAULT,
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
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );
        assert!(external_open
            .prepare(
                41,
                "http://127.0.0.1:8080/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_none());

        assert_eq!(
            external_open
                .begin_policy_mutation(persisted_mutation(7, ExternalOpenPolicy::Disabled)),
            vec![ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Disabled,
            }]
        );
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
                SavedPortForwardLimit::DEFAULT,
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
                SavedPortForwardLimit::DEFAULT,
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
    fn partial_config_reload_applies_valid_policy_and_reports_invalid_remote_section() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );

        assert_eq!(
            external_open.begin_policy_reload(
                ExternalOpenPolicy::Disabled,
                SavedPortForwardLimit::DEFAULT,
                true,
            ),
            vec![ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Disabled,
            }]
        );
        assert_eq!(
            external_open.poll(),
            vec![
                ClientMessage::ExternalOpenPolicyUpdate {
                    policy: ExternalOpenPolicy::Disabled,
                },
                ClientMessage::ExternalOpenPolicyReloadFailed {
                    effective_policy: ExternalOpenPolicy::Disabled,
                    cleanup_incomplete: false,
                },
            ]
        );
        assert_eq!(external_open.policy(), ExternalOpenPolicy::Disabled);
    }

    #[test]
    fn unavailable_broker_retains_saved_limit_and_reports_one_reload_failure() {
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::Unavailable,
        );

        assert_eq!(
            external_open.begin_policy_reload(ExternalOpenPolicy::Enabled, saved_limit(64), false),
            vec![
                ClientMessage::ExternalOpenPolicyUpdate {
                    policy: ExternalOpenPolicy::Enabled,
                },
                ClientMessage::ExternalOpenPolicyReloadFailed {
                    effective_policy: ExternalOpenPolicy::Enabled,
                    cleanup_incomplete: false,
                },
            ]
        );
        assert_eq!(
            external_open.saved_mapping_limit(),
            SavedPortForwardLimit::DEFAULT
        );
        assert!(external_open.poll().is_empty());
    }

    #[test]
    fn pending_policy_mutation_survives_an_empty_poll_before_acknowledgement() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        *controller
            .policy_empty_polls
            .lock()
            .expect("policy empty polls") = 1;
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Disabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );
        let mutation = persisted_mutation(9, ExternalOpenPolicy::Enabled);

        assert!(external_open
            .begin_policy_mutation(mutation.clone())
            .is_empty());
        assert!(external_open.poll().is_empty());
        assert_eq!(external_open.poll(), vec![mutation]);
        assert_eq!(external_open.policy(), ExternalOpenPolicy::Enabled);
    }

    #[test]
    fn activation_failure_uses_the_existing_mutation_result_and_notice_stage() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        *controller.policy_result.lock().expect("policy result") =
            Some(ForwardingPolicySettlement {
                requested: true,
                effective: false,
                requested_saved_mapping_limit: SavedPortForwardLimit::DEFAULT,
                effective_saved_mapping_limit: SavedPortForwardLimit::DEFAULT,
                result: Err(ForwardingPreparationError::CommandRejected),
            });
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Disabled,
            SavedPortForwardLimit::DEFAULT,
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
    fn acknowledged_limit_increase_and_decrease_become_effective_only_after_poll() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );

        for requested in [saved_limit(64), saved_limit(1)] {
            assert!(external_open
                .begin_policy_reload(ExternalOpenPolicy::Enabled, requested, false)
                .is_empty());
            assert_ne!(external_open.saved_mapping_limit(), requested);
            assert_eq!(
                external_open.poll(),
                vec![ClientMessage::ExternalOpenPolicyUpdate {
                    policy: ExternalOpenPolicy::Enabled,
                }]
            );
            assert_eq!(external_open.saved_mapping_limit(), requested);
        }
    }

    #[test]
    fn failed_or_mismatched_limit_acknowledgements_retain_the_entire_remote_limit() {
        let cases = [
            ForwardingPolicySettlement {
                requested: true,
                effective: true,
                requested_saved_mapping_limit: saved_limit(64),
                effective_saved_mapping_limit: saved_limit(64),
                result: Err(ForwardingPreparationError::Unavailable),
            },
            ForwardingPolicySettlement {
                requested: true,
                effective: true,
                requested_saved_mapping_limit: saved_limit(64),
                effective_saved_mapping_limit: saved_limit(64),
                result: Err(ForwardingPreparationError::CommandTimedOut),
            },
            ForwardingPolicySettlement {
                requested: false,
                effective: true,
                requested_saved_mapping_limit: saved_limit(64),
                effective_saved_mapping_limit: saved_limit(64),
                result: Ok(()),
            },
            ForwardingPolicySettlement {
                requested: true,
                effective: true,
                requested_saved_mapping_limit: saved_limit(63),
                effective_saved_mapping_limit: saved_limit(63),
                result: Ok(()),
            },
        ];

        for settlement in cases {
            let controller = Arc::new(FakeForwardingController::with_results([]));
            *controller.policy_result.lock().expect("policy result") = Some(settlement);
            let mut external_open = ClientExternalOpen::new(
                ExternalOpenPolicy::Enabled,
                SavedPortForwardLimit::DEFAULT,
                ExternalOpenForwarding::available(controller),
            );
            assert!(external_open
                .begin_policy_reload(ExternalOpenPolicy::Enabled, saved_limit(64), false)
                .is_empty());
            assert_eq!(
                external_open.poll(),
                vec![ClientMessage::ExternalOpenPolicyReloadFailed {
                    effective_policy: ExternalOpenPolicy::Enabled,
                    cleanup_incomplete: false,
                }]
            );
            assert_eq!(
                external_open.saved_mapping_limit(),
                SavedPortForwardLimit::DEFAULT
            );
        }
    }

    #[test]
    fn reload_disable_cleanup_failure_keeps_off_and_reports_aggregate_cleanup_warning() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        *controller.policy_result.lock().expect("policy result") =
            Some(ForwardingPolicySettlement {
                requested: false,
                effective: false,
                requested_saved_mapping_limit: saved_limit(64),
                effective_saved_mapping_limit: saved_limit(64),
                result: Err(ForwardingPreparationError::CommandRejected),
            });
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Disabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );

        assert_eq!(
            external_open
                .begin_policy_reload(ExternalOpenPolicy::Disabled, saved_limit(64), false,),
            vec![ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Disabled,
            }]
        );
        assert_eq!(
            external_open.poll(),
            vec![ClientMessage::ExternalOpenPolicyReloadFailed {
                effective_policy: ExternalOpenPolicy::Disabled,
                cleanup_incomplete: true,
            }]
        );
        assert_eq!(external_open.policy(), ExternalOpenPolicy::Disabled);
        assert_eq!(
            external_open.saved_mapping_limit(),
            SavedPortForwardLimit::DEFAULT
        );
    }

    #[test]
    fn confirmed_disable_keeps_policy_off_and_reports_incomplete_cleanup_once() {
        let controller = Arc::new(FakeForwardingController::with_results([]));
        *controller.policy_result.lock().expect("policy result") =
            Some(ForwardingPolicySettlement {
                requested: false,
                effective: false,
                requested_saved_mapping_limit: SavedPortForwardLimit::DEFAULT,
                effective_saved_mapping_limit: SavedPortForwardLimit::DEFAULT,
                result: Err(ForwardingPreparationError::CommandRejected),
            });
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );

        assert_eq!(
            external_open
                .begin_policy_mutation(persisted_mutation(11, ExternalOpenPolicy::Disabled)),
            vec![ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Disabled,
            }]
        );
        assert_eq!(
            external_open.poll(),
            vec![ClientMessage::ExternalOpenPolicyMutationResult {
                request_id: 11,
                requested_policy: ExternalOpenPolicy::Disabled,
                persisted_policy: Some(ExternalOpenPolicy::Disabled),
                effective_policy: ExternalOpenPolicy::Disabled,
                failure_stage: Some(ExternalOpenPolicyMutationFailureStage::Reload),
            }]
        );
        assert_eq!(external_open.policy(), ExternalOpenPolicy::Disabled);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_client_rejects_canonical_127_8_before_forwarding_or_opener_authority() {
        let broker = ForwardingBrokerTestHarness::succeeding(SavedPortForwardLimit::DEFAULT);
        let controller = Arc::new(CountingForwardingController::new(broker.controller()));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller.clone()),
        );

        for (request_id, url) in [
            (50, "http://127.0.0.2:3000/private"),
            (51, "http://127.42.0.9:3000/private"),
            (52, "http://127.255.255.255:3000/private"),
        ] {
            assert_eq!(
                external_open.prepare(request_id, url.to_owned(), ExternalOpenPlatform::MacOs),
                Some(ClientMessage::ExternalOpenPreparationFailed {
                    request_id,
                    reason: ExternalOpenPreparationFailure::LoopbackUnsupportedOnPlatform,
                })
            );
            assert_eq!(controller.begin_prepare_calls(), 0);
            assert_eq!(broker.total_operations(), 0);
            assert_eq!(opener_calls_if_committed(&mut external_open, request_id), 0);
        }
    }

    #[test]
    fn localhost_readiness_is_commit_gated_and_rewrites_only_the_pair_port() {
        let controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(43_123).expect("port"),
        ))]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller.clone()),
        );
        let opened = RefCell::new(Vec::new());

        assert!(external_open
            .prepare(
                50,
                "HTTPS://LOCALHOST:00443/a%2Fb?token=A%2BB#Frag".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_none());
        assert!(opened.borrow().is_empty());
        assert_eq!(
            *controller.requests.lock().expect("requests"),
            vec![(
                LoopbackTarget::Localhost,
                NonZeroU16::new(443).expect("port")
            )]
        );
        assert_eq!(external_open.poll().len(), 1);
        assert!(opened.borrow().is_empty());

        external_open.commit(50).expect("commit").execute(|url| {
            opened.borrow_mut().push(url.to_owned());
            Ok(())
        });
        assert_eq!(
            *opened.borrow(),
            vec!["HTTPS://LOCALHOST:43123/a%2Fb?token=A%2BB#Frag"]
        );
    }

    #[test]
    fn shared_mapping_port_rewrites_each_waiters_original_url_only_after_its_commit() {
        let local_port = NonZeroU16::new(43_123).expect("port");
        let controller = Arc::new(FakeForwardingController::with_results([
            Some(Ok(local_port)),
            Some(Ok(local_port)),
        ]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );
        let opened = RefCell::new(Vec::new());

        for (request_id, url) in [
            (51, "http://127.0.0.42:8080/first?token=A%2BB#One"),
            (52, "HTTPS://127.0.0.42:8080/second%2Fpath?token=C%2BD#Two"),
        ] {
            assert!(external_open
                .prepare(request_id, url.to_owned(), ExternalOpenPlatform::Linux)
                .is_none());
        }
        assert_eq!(external_open.poll().len(), 2);
        assert!(opened.borrow().is_empty());

        for request_id in [52, 51] {
            external_open
                .commit(request_id)
                .expect("individual commit")
                .execute(|url| {
                    opened.borrow_mut().push(url.to_owned());
                    Ok(())
                });
        }
        assert_eq!(
            *opened.borrow(),
            vec![
                "HTTPS://127.0.0.42:43123/second%2Fpath?token=C%2BD#Two",
                "http://127.0.0.42:43123/first?token=A%2BB#One",
            ]
        );
        assert!(external_open.commit(51).is_none());
        assert!(external_open.commit(52).is_none());
    }

    #[test]
    fn fresh_attachment_reopens_only_from_original_remote_url_with_a_new_forward() {
        let original = "http://127.0.0.1:8080/private?token=secret#view";
        let first_controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(43_123).expect("first local port"),
        ))]));
        let mut first = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(first_controller),
        );
        assert!(first
            .prepare(1, original.to_owned(), ExternalOpenPlatform::Linux)
            .is_none());
        assert_eq!(first.poll().len(), 1);
        let first_url = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&first_url);
        first.commit(1).expect("first commit").execute(|url| {
            *captured.lock().expect("first URL") = Some(url.to_owned());
            Ok(())
        });
        assert_eq!(
            first_url.lock().expect("first URL").as_deref(),
            Some("http://127.0.0.1:43123/private?token=secret#view")
        );
        drop(first);

        let second_controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(43_124).expect("second local port"),
        ))]));
        let mut second = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(second_controller.clone()),
        );
        assert!(second.commit(1).is_none());
        assert!(second
            .prepare(2, original.to_owned(), ExternalOpenPlatform::Linux)
            .is_none());
        assert_eq!(
            *second_controller
                .requests
                .lock()
                .expect("second attachment requests"),
            vec![(
                crate::external_open::LoopbackTarget::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                NonZeroU16::new(8080).expect("remote port"),
            )]
        );
        assert_eq!(second.poll().len(), 1);
        let second_url = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&second_url);
        second.commit(2).expect("second commit").execute(|url| {
            *captured.lock().expect("second URL") = Some(url.to_owned());
            Ok(())
        });
        assert_eq!(
            second_url.lock().expect("second URL").as_deref(),
            Some("http://127.0.0.1:43124/private?token=secret#view")
        );
    }

    #[test]
    fn atomic_pair_failure_never_becomes_committable_or_invokes_opener() {
        let controller = Arc::new(FakeForwardingController::with_results([Some(Err(
            ForwardingPreparationError::AtomicCreationFailed,
        ))]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
            ExternalOpenForwarding::available(controller),
        );
        let opened = RefCell::new(Vec::<String>::new());

        assert!(external_open
            .prepare(
                50,
                "http://localhost:8080/private".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_none());
        assert_eq!(
            external_open.poll(),
            vec![ClientMessage::ExternalOpenPreparationFailed {
                request_id: 50,
                reason: ExternalOpenPreparationFailure::AtomicForwardCreationFailed,
            }]
        );
        assert_eq!(opener_calls_if_committed(&mut external_open, 50), 0);
        assert!(opened.borrow().is_empty());
    }

    #[test]
    fn forwarded_url_is_opaque_to_opener_until_commit() {
        let controller = Arc::new(FakeForwardingController::with_results([Some(Ok(
            NonZeroU16::new(43_123).expect("port"),
        ))]));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
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
            let mut external_open = ClientExternalOpen::new(
                ExternalOpenPolicy::Enabled,
                SavedPortForwardLimit::DEFAULT,
                forwarding,
            );
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
            assert_eq!(opener_calls_if_committed(&mut external_open, request_id), 0);
        }

        let translations = [
            (
                ForwardingPreparationError::TooManyRequests,
                ExternalOpenPreparationFailure::TooManyForwardRequests,
            ),
            (
                ForwardingPreparationError::TooManyWaiters,
                ExternalOpenPreparationFailure::TooManyMappingWaiters,
            ),
            (
                ForwardingPreparationError::CapacityExhausted,
                ExternalOpenPreparationFailure::ForwardCapacityExhausted,
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
                ForwardingPreparationError::AtomicCreationFailed,
                ExternalOpenPreparationFailure::AtomicForwardCreationFailed,
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
                    SavedPortForwardLimit::DEFAULT,
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
                assert_eq!(opener_calls_if_committed(&mut external_open, request_id), 0);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn collect_messages(
        external_open: &mut ClientExternalOpen,
        expected_count: usize,
    ) -> Vec<ClientMessage> {
        let mut messages = Vec::new();
        for _ in 0..100_000 {
            messages.extend(external_open.poll());
            if messages.len() >= expected_count {
                return messages;
            }
            std::thread::yield_now();
        }
        panic!("external-open messages did not settle");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn ninth_real_mapping_waiter_settles_once_without_open_authority() {
        const VALID_WAITER_COUNT: usize = 8;
        let mut broker = ForwardingBrokerTestHarness::blocked(saved_limit(64));
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            saved_limit(64),
            ExternalOpenForwarding::available(broker.controller()),
        );
        let valid_request_ids = 700..708;

        for request_id in valid_request_ids.clone() {
            assert_eq!(
                external_open.prepare(
                    request_id,
                    format!("http://127.0.0.1:8080/waiter-{request_id}"),
                    ExternalOpenPlatform::Linux,
                ),
                None
            );
            if request_id == valid_request_ids.start {
                broker.wait_until_blocked();
            }
        }

        let rejected_request_id = valid_request_ids.end;
        let opened = RefCell::new(Vec::new());
        assert_eq!(
            external_open.prepare(
                rejected_request_id,
                "http://127.0.0.1:8080/rejected-ninth".to_owned(),
                ExternalOpenPlatform::Linux,
            ),
            None
        );
        let rejection = collect_messages(&mut external_open, 1);
        assert!(matches!(
            rejection.as_slice(),
            [ClientMessage::ExternalOpenPreparationFailed {
                request_id,
                reason: ExternalOpenPreparationFailure::TooManyMappingWaiters,
            }] if *request_id == rejected_request_id
        ));
        if let Some(committed) = external_open.commit(rejected_request_id) {
            committed.execute(|url| {
                opened.borrow_mut().push(url.to_owned());
                Ok(())
            });
        }
        assert!(opened.borrow().is_empty());
        assert_eq!(broker.operations(), vec!["forward"]);

        broker.release_blocked();
        let readiness = collect_messages(&mut external_open, VALID_WAITER_COUNT);
        assert_eq!(readiness.len(), VALID_WAITER_COUNT);
        for request_id in valid_request_ids.clone() {
            assert!(readiness.contains(&ClientMessage::ExternalOpenReady {
                request_id,
                target: ExternalOpenTarget::Forwarded {
                    port_status: ExternalOpenPortStatus::SamePort,
                },
            }));
        }
        assert!(external_open.poll().is_empty());
        assert!(external_open.commit(rejected_request_id).is_none());
        assert_eq!(broker.operations(), vec!["forward"]);
        for request_id in (valid_request_ids.start + 1)..valid_request_ids.end {
            assert!(
                external_open.commit(request_id).is_some(),
                "valid waiter {request_id} lost commit authority"
            );
        }
        assert!(opened.borrow().is_empty());

        external_open
            .commit(valid_request_ids.start)
            .expect("valid waiter retains commit authority")
            .execute(|url| {
                opened.borrow_mut().push(url.to_owned());
                Ok(())
            });
        assert_eq!(*opened.borrow(), vec!["http://127.0.0.1:8080/waiter-700"]);
        assert!(external_open.commit(rejected_request_id).is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn settle_numeric_mapping(
        controller: &Arc<dyn ForwardingController>,
        remote_port: u16,
    ) -> NonZeroU16 {
        let mut operation = controller
            .begin_prepare_numeric(
                LoopbackTarget::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                NonZeroU16::new(remote_port).expect("nonzero remote port"),
            )
            .expect("mapping preparation begins");
        for _ in 0..100_000 {
            if let Some(result) = operation.poll() {
                return result.expect("successful listener settlement");
            }
            std::thread::yield_now();
        }
        panic!("numeric mapping did not settle");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn real_listener_exhaustion_rejects_new_work_but_preserves_commit_gated_ready_reuse() {
        const FIRST_REMOTE_PORT: u16 = 20_000;
        const LISTENER_CEILING: u16 = 128;
        let broker = ForwardingBrokerTestHarness::succeeding(saved_limit(1));
        let controller = broker.controller();

        for offset in 0..LISTENER_CEILING {
            let remote_port = FIRST_REMOTE_PORT + offset;
            assert_eq!(
                settle_numeric_mapping(&controller, remote_port).get(),
                remote_port
            );
        }
        assert_eq!(
            broker.operation_count("forward"),
            usize::from(LISTENER_CEILING)
        );
        assert_eq!(
            broker.operation_count("cancel"),
            usize::from(LISTENER_CEILING - 1)
        );
        let operations_at_exhaustion = broker.total_operations();

        let retained_port = FIRST_REMOTE_PORT + LISTENER_CEILING - 1;
        let rejected_request_id = 900;
        let opened = RefCell::new(Vec::new());
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            saved_limit(1),
            ExternalOpenForwarding::available(controller),
        );
        assert_eq!(
            external_open.prepare(
                rejected_request_id,
                "http://127.0.0.1:30000/rejected-at-capacity".to_owned(),
                ExternalOpenPlatform::Linux,
            ),
            None
        );
        let rejection = collect_messages(&mut external_open, 1);
        assert!(matches!(
            rejection.as_slice(),
            [ClientMessage::ExternalOpenPreparationFailed {
                request_id,
                reason: ExternalOpenPreparationFailure::ForwardCapacityExhausted,
            }] if *request_id == rejected_request_id
        ));
        if let Some(committed) = external_open.commit(rejected_request_id) {
            committed.execute(|url| {
                opened.borrow_mut().push(url.to_owned());
                Ok(())
            });
        }
        assert!(opened.borrow().is_empty());
        assert!(external_open.poll().is_empty());
        assert_eq!(broker.total_operations(), operations_at_exhaustion);

        let retained_request_id = 901;
        assert_eq!(
            external_open.prepare(
                retained_request_id,
                format!("http://127.0.0.1:{retained_port}/retained-ready"),
                ExternalOpenPlatform::Linux,
            ),
            None
        );
        let readiness = collect_messages(&mut external_open, 1);
        assert!(matches!(
            readiness.as_slice(),
            [ClientMessage::ExternalOpenReady {
                request_id,
                target: ExternalOpenTarget::Forwarded {
                    port_status: ExternalOpenPortStatus::SamePort,
                },
            }] if *request_id == retained_request_id
        ));
        assert_eq!(broker.total_operations(), operations_at_exhaustion);
        assert!(external_open.commit(rejected_request_id).is_none());
        assert!(opened.borrow().is_empty());
        external_open
            .commit(retained_request_id)
            .expect("server commit grants retained Ready mapping authority")
            .execute(|url| {
                opened.borrow_mut().push(url.to_owned());
                Ok(())
            });
        assert_eq!(
            *opened.borrow(),
            vec![format!("http://127.0.0.1:{retained_port}/retained-ready")]
        );
        assert!(external_open.poll().is_empty());
        assert!(external_open.commit(rejected_request_id).is_none());
        assert_eq!(broker.total_operations(), operations_at_exhaustion);
    }

    #[test]
    fn ordinary_url_remains_immediately_ready_without_forwarding() {
        let original = "https://example.com/a%2Fb?token=A%2BB#Frag";
        let mut external_open = ClientExternalOpen::new(
            ExternalOpenPolicy::Enabled,
            SavedPortForwardLimit::DEFAULT,
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
