use std::collections::BTreeMap;

use crate::protocol::ExternalOpenPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyMutationRequest {
    pub(crate) request_id: u64,
    pub(crate) requested_policy: ExternalOpenPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyMutationResult {
    pub(crate) request_id: u64,
    pub(crate) requested_policy: ExternalOpenPolicy,
    pub(crate) persisted_policy: Option<ExternalOpenPolicy>,
    pub(crate) effective_policy: ExternalOpenPolicy,
    pub(crate) failure_stage: Option<crate::protocol::ExternalOpenPolicyMutationFailureStage>,
}

fn is_incomplete_disable_cleanup(result: PolicyMutationResult) -> bool {
    result.requested_policy == ExternalOpenPolicy::Disabled
        && result.persisted_policy == Some(ExternalOpenPolicy::Disabled)
        && result.effective_policy == ExternalOpenPolicy::Disabled
        && result.failure_stage
            == Some(crate::protocol::ExternalOpenPolicyMutationFailureStage::Reload)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientFrameAcknowledgement {
    generation: u64,
    render_context: crate::ui::ClientRenderContext,
    policy_mutation: Option<PolicyMutationRequest>,
}

impl ClientFrameAcknowledgement {
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ClientProjectionAction {
    ConfirmPolicy(ExternalOpenPolicy),
    TogglePolicy,
    SettlePolicy {
        result: PolicyMutationResult,
        now: std::time::Instant,
    },
    ReportReloadFailure {
        effective_policy: ExternalOpenPolicy,
        cleanup_incomplete: bool,
        now: std::time::Instant,
    },
    ShowNotice {
        message: &'static str,
        now: std::time::Instant,
    },
    DismissNotice,
    FrameQueued {
        acknowledgement: ClientFrameAcknowledgement,
    },
    FrameWritten {
        acknowledgement: ClientFrameAcknowledgement,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClientProjectionEffect {
    changed: bool,
    confirmed_policy: Option<ExternalOpenPolicy>,
    mutation_request: Option<PolicyMutationRequest>,
}

impl ClientProjectionEffect {
    pub(crate) fn changed(self) -> bool {
        self.changed
    }

    pub(crate) fn confirmed_policy(self) -> Option<ExternalOpenPolicy> {
        self.confirmed_policy
    }

    pub(crate) fn mutation_request(self) -> Option<PolicyMutationRequest> {
        self.mutation_request
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientProjectionView {
    confirmed_policy: ExternalOpenPolicy,
    saving: bool,
    notice: Option<&'static str>,
}

impl ClientProjectionView {
    pub(crate) fn confirmed_policy(self) -> ExternalOpenPolicy {
        self.confirmed_policy
    }

    #[cfg(test)]
    pub(crate) fn saving(self) -> bool {
        self.saving
    }

    pub(crate) fn notice(self) -> Option<&'static str> {
        self.notice
    }

    pub(crate) fn remote_link_preference(
        self,
    ) -> crate::remote_link_preference::RemoteLinkPreferenceView {
        crate::remote_link_preference::RemoteLinkPreferenceView::projected(
            self.confirmed_policy == ExternalOpenPolicy::Enabled,
            self.saving,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientProjectionRender {
    view: ClientProjectionView,
    #[cfg(test)]
    acknowledgement: Option<PolicyMutationRequest>,
}

impl ClientProjectionRender {
    pub(crate) fn view(self) -> ClientProjectionView {
        self.view
    }

    #[cfg(test)]
    pub(crate) fn write_acknowledgement(self) -> Option<PolicyMutationRequest> {
        self.acknowledgement
    }
}

#[derive(Debug, Default)]
pub(crate) struct ClientProjections {
    projections: BTreeMap<u64, ClientProjection>,
}

impl ClientProjections {
    pub(crate) fn connect(&mut self, client_id: u64, confirmed_policy: ExternalOpenPolicy) -> bool {
        if self.projections.contains_key(&client_id) {
            return false;
        }
        self.projections
            .insert(client_id, ClientProjection::new(confirmed_policy));
        true
    }

    pub(crate) fn disconnect(&mut self, client_id: u64) -> bool {
        self.projections.remove(&client_id).is_some()
    }

    pub(crate) fn apply(
        &mut self,
        client_id: u64,
        action: ClientProjectionAction,
    ) -> ClientProjectionEffect {
        let Some(projection) = self.projections.get_mut(&client_id) else {
            return ClientProjectionEffect::default();
        };
        match action {
            ClientProjectionAction::ConfirmPolicy(policy) => ClientProjectionEffect {
                changed: projection.confirm_policy(policy),
                ..ClientProjectionEffect::default()
            },
            ClientProjectionAction::TogglePolicy => ClientProjectionEffect {
                changed: projection.toggle_policy().is_some(),
                ..ClientProjectionEffect::default()
            },
            ClientProjectionAction::SettlePolicy { result, now } => {
                let settled = projection.settle_policy_mutation(result, now);
                ClientProjectionEffect {
                    changed: settled,
                    confirmed_policy: (settled
                        && (result.failure_stage.is_none()
                            || is_incomplete_disable_cleanup(result)))
                    .then_some(result.effective_policy),
                    mutation_request: None,
                }
            }
            ClientProjectionAction::ReportReloadFailure {
                effective_policy,
                cleanup_incomplete,
                now,
            } => ClientProjectionEffect {
                changed: projection.report_reload_failure(
                    effective_policy,
                    cleanup_incomplete,
                    now,
                ),
                ..ClientProjectionEffect::default()
            },
            ClientProjectionAction::ShowNotice { message, now } => ClientProjectionEffect {
                changed: projection.project_notice(message, now),
                ..ClientProjectionEffect::default()
            },
            ClientProjectionAction::DismissNotice => ClientProjectionEffect {
                changed: projection.dismiss_notice(),
                ..ClientProjectionEffect::default()
            },
            ClientProjectionAction::FrameQueued { acknowledgement } => ClientProjectionEffect {
                changed: projection.queue_frame(acknowledgement),
                ..ClientProjectionEffect::default()
            },
            ClientProjectionAction::FrameWritten { acknowledgement } => ClientProjectionEffect {
                mutation_request: projection.acknowledge_written_frame(acknowledgement),
                ..ClientProjectionEffect::default()
            },
        }
    }

    pub(crate) fn prepare_frame_acknowledgement(
        &mut self,
        client_id: u64,
        render_context: crate::ui::ClientRenderContext,
    ) -> Option<ClientFrameAcknowledgement> {
        self.projections
            .get_mut(&client_id)?
            .prepare_frame_acknowledgement(render_context)
    }

    pub(crate) fn displayed_render_context(
        &self,
        client_id: u64,
    ) -> Option<&crate::ui::ClientRenderContext> {
        self.projections
            .get(&client_id)
            .map(|projection| &projection.displayed_render_context)
    }

    #[cfg(test)]
    pub(crate) fn first_queued_frame_acknowledgement(
        &self,
        client_id: u64,
    ) -> Option<ClientFrameAcknowledgement> {
        self.projections
            .get(&client_id)?
            .queued_frames
            .first_key_value()
            .map(|(_, acknowledgement)| acknowledgement.clone())
    }

    pub(crate) fn render(&self, client_id: u64) -> Option<ClientProjectionRender> {
        let projection = self.projections.get(&client_id)?;
        Some(ClientProjectionRender {
            view: projection.view(),
            #[cfg(test)]
            acknowledgement: projection.render_acknowledgement(),
        })
    }

    pub(crate) fn confirmed_policy(&self, client_id: u64) -> Option<ExternalOpenPolicy> {
        self.projections
            .get(&client_id)
            .map(|projection| projection.view().confirmed_policy())
    }

    pub(crate) fn retained_render_eligible(&self, client_id: u64) -> bool {
        self.projections
            .get(&client_id)
            .is_none_or(|projection| projection.view().notice().is_none())
    }

    pub(crate) fn next_deadline(&self) -> Option<std::time::Instant> {
        self.projections
            .values()
            .filter_map(ClientProjection::next_notice_deadline)
            .min()
    }

    pub(crate) fn expire_due(&mut self, now: std::time::Instant) -> Vec<u64> {
        self.projections
            .iter_mut()
            .filter_map(|(client_id, projection)| {
                projection.expire_notice(now).then_some(*client_id)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
struct LocalNotice {
    message: &'static str,
    expires_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy)]
struct PendingPolicyMutation {
    request: PolicyMutationRequest,
    presentation_queued: bool,
    presented: bool,
}

#[derive(Debug)]
struct ClientProjection {
    confirmed_policy: ExternalOpenPolicy,
    pending: Option<PendingPolicyMutation>,
    next_request_id: Option<u64>,
    notice: Option<LocalNotice>,
    next_frame_generation: Option<u64>,
    displayed_frame_generation: Option<u64>,
    displayed_render_context: crate::ui::ClientRenderContext,
    queued_frames: BTreeMap<u64, ClientFrameAcknowledgement>,
}

impl ClientProjection {
    fn new(confirmed_policy: ExternalOpenPolicy) -> Self {
        Self {
            confirmed_policy,
            pending: None,
            next_request_id: Some(1),
            notice: None,
            next_frame_generation: Some(1),
            displayed_frame_generation: None,
            displayed_render_context: crate::ui::ClientRenderContext::default(),
            queued_frames: BTreeMap::new(),
        }
    }

    fn confirm_policy(&mut self, policy: ExternalOpenPolicy) -> bool {
        if let Some(pending) = self.pending {
            if policy != ExternalOpenPolicy::Disabled
                || pending.request.requested_policy != ExternalOpenPolicy::Disabled
            {
                return false;
            }
        }
        let changed = self.confirmed_policy != policy;
        self.confirmed_policy = policy;
        changed
    }

    fn toggle_policy(&mut self) -> Option<PolicyMutationRequest> {
        if self.pending.is_some() {
            return None;
        }
        let request_id = self.next_request_id?;
        self.next_request_id = request_id.checked_add(1);
        let requested_policy = match self.confirmed_policy {
            ExternalOpenPolicy::Disabled => ExternalOpenPolicy::Enabled,
            ExternalOpenPolicy::Enabled => ExternalOpenPolicy::Disabled,
        };
        let request = PolicyMutationRequest {
            request_id,
            requested_policy,
        };
        self.pending = Some(PendingPolicyMutation {
            request,
            presentation_queued: false,
            presented: false,
        });
        Some(request)
    }

    fn render_acknowledgement(&self) -> Option<PolicyMutationRequest> {
        self.pending
            .filter(|pending| !pending.presentation_queued && !pending.presented)
            .map(|pending| pending.request)
    }

    fn prepare_frame_acknowledgement(
        &mut self,
        render_context: crate::ui::ClientRenderContext,
    ) -> Option<ClientFrameAcknowledgement> {
        let generation = self.next_frame_generation?;
        self.next_frame_generation = generation.checked_add(1);
        Some(ClientFrameAcknowledgement {
            generation,
            render_context,
            policy_mutation: self.render_acknowledgement(),
        })
    }

    fn queue_frame(&mut self, acknowledgement: ClientFrameAcknowledgement) -> bool {
        let generation = acknowledgement.generation;
        let generation_was_allocated = generation != 0
            && match self.next_frame_generation {
                Some(next_generation) => generation < next_generation,
                None => generation == u64::MAX,
            };
        let follows_queued_and_displayed = self
            .queued_frames
            .last_key_value()
            .map(|(queued_generation, _)| generation > *queued_generation)
            .unwrap_or(true)
            && self
                .displayed_frame_generation
                .is_none_or(|displayed_generation| generation > displayed_generation);
        if !generation_was_allocated || !follows_queued_and_displayed {
            return false;
        }

        if let Some(request) = acknowledgement.policy_mutation {
            let Some(pending) = self.pending.as_mut() else {
                return false;
            };
            if pending.request != request || pending.presentation_queued || pending.presented {
                return false;
            }
            pending.presentation_queued = true;
        }

        self.queued_frames.insert(generation, acknowledgement);
        true
    }

    fn acknowledge_written_frame(
        &mut self,
        acknowledgement: ClientFrameAcknowledgement,
    ) -> Option<PolicyMutationRequest> {
        let (generation, queued) = self.queued_frames.first_key_value()?;
        if *generation != acknowledgement.generation || queued != &acknowledgement {
            return None;
        }
        let generation = *generation;
        let acknowledged = self.queued_frames.remove(&generation)?;
        if self
            .displayed_frame_generation
            .is_some_and(|displayed_generation| generation <= displayed_generation)
        {
            return None;
        }

        self.displayed_frame_generation = Some(generation);
        self.displayed_render_context = acknowledged.render_context;
        let request = acknowledged.policy_mutation?;
        let pending = self.pending.as_mut()?;
        if pending.request != request || !pending.presentation_queued || pending.presented {
            return None;
        }
        pending.presentation_queued = false;
        pending.presented = true;
        Some(request)
    }

    #[cfg(test)]
    fn mark_policy_mutation_presented(&mut self) -> Option<PolicyMutationRequest> {
        let acknowledgement = self.prepare_frame_acknowledgement(Default::default())?;
        let request = acknowledgement.policy_mutation?;
        assert!(self.queue_frame(acknowledgement.clone()));
        self.acknowledge_written_frame(acknowledgement)
            .filter(|acknowledged| *acknowledged == request)
    }

    fn settle_policy_mutation(
        &mut self,
        result: PolicyMutationResult,
        now: std::time::Instant,
    ) -> bool {
        let Some(pending) = self.pending else {
            return false;
        };
        if !pending.presented
            || pending.request.request_id != result.request_id
            || pending.request.requested_policy != result.requested_policy
        {
            return false;
        }

        let notice = match result.failure_stage {
            _ if is_incomplete_disable_cleanup(result) => {
                self.confirmed_policy = ExternalOpenPolicy::Disabled;
                Some("Remote link opening turned off · some local forwards couldn’t be removed")
            }
            None if result.persisted_policy.is_some() => {
                self.confirmed_policy = result.effective_policy;
                None
            }
            Some(crate::protocol::ExternalOpenPolicyMutationFailureStage::Write)
                if result.persisted_policy.is_none() =>
            {
                Some("Couldn’t save remote link setting · previous value kept")
            }
            Some(crate::protocol::ExternalOpenPolicyMutationFailureStage::Reload)
                if result.persisted_policy.is_some() =>
            {
                Some("Couldn’t reload remote link setting · previous value kept")
            }
            _ => return false,
        };

        self.pending = None;
        if let Some(message) = notice {
            self.notice = Some(LocalNotice {
                message,
                expires_at: now + std::time::Duration::from_secs(5),
            });
        }
        true
    }

    fn report_reload_failure(
        &mut self,
        effective_policy: ExternalOpenPolicy,
        cleanup_incomplete: bool,
        now: std::time::Instant,
    ) -> bool {
        if self.confirmed_policy != effective_policy
            || (cleanup_incomplete && effective_policy != ExternalOpenPolicy::Disabled)
        {
            return false;
        }
        let message = if cleanup_incomplete {
            "Remote link opening turned off · some local forwards couldn’t be removed"
        } else {
            "Couldn’t reload remote link setting · previous value kept"
        };
        self.notice = Some(LocalNotice {
            message,
            expires_at: now + std::time::Duration::from_secs(5),
        });
        true
    }

    fn project_notice(&mut self, message: &'static str, now: std::time::Instant) -> bool {
        self.notice = Some(LocalNotice {
            message,
            expires_at: now + std::time::Duration::from_secs(5),
        });
        true
    }

    fn dismiss_notice(&mut self) -> bool {
        self.notice.take().is_some()
    }

    fn next_notice_deadline(&self) -> Option<std::time::Instant> {
        self.notice.map(|notice| notice.expires_at)
    }

    fn expire_notice(&mut self, now: std::time::Instant) -> bool {
        let expired = self.notice.is_some_and(|notice| now >= notice.expires_at);
        if expired {
            self.notice = None;
        }
        expired
    }

    fn view(&self) -> ClientProjectionView {
        ClientProjectionView {
            confirmed_policy: self.confirmed_policy,
            saving: self.pending.is_some(),
            notice: self.notice.map(|notice| notice.message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ExternalOpenPolicy;

    #[test]
    fn projections_expire_in_client_order_and_disconnect_destroys_private_state() {
        let now = std::time::Instant::now();
        let mut projections = ClientProjections::default();
        assert!(projections.connect(20, ExternalOpenPolicy::Disabled));
        assert!(projections.connect(10, ExternalOpenPolicy::Enabled));

        assert!(projections
            .apply(
                20,
                ClientProjectionAction::ShowNotice {
                    message: "notice 20",
                    now,
                },
            )
            .changed());
        assert!(projections
            .apply(
                10,
                ClientProjectionAction::ShowNotice {
                    message: "notice 10",
                    now,
                },
            )
            .changed());
        assert!(!projections.retained_render_eligible(10));
        assert_eq!(
            projections.next_deadline(),
            Some(now + std::time::Duration::from_secs(5))
        );

        assert_eq!(
            projections.expire_due(now + std::time::Duration::from_secs(5)),
            vec![10, 20]
        );
        assert!(projections.retained_render_eligible(10));
        let disconnected_frame = projections
            .prepare_frame_acknowledgement(10, Default::default())
            .expect("disconnected frame acknowledgement");
        assert!(projections
            .apply(
                10,
                ClientProjectionAction::FrameQueued {
                    acknowledgement: disconnected_frame.clone(),
                },
            )
            .changed());
        assert!(projections.disconnect(10));
        assert!(projections.render(10).is_none());
        assert_eq!(
            projections
                .apply(
                    10,
                    ClientProjectionAction::FrameWritten {
                        acknowledgement: disconnected_frame,
                    },
                )
                .mutation_request(),
            None
        );
        assert!(projections.displayed_render_context(10).is_none());
        assert!(!projections.disconnect(10));
    }

    #[test]
    fn render_acknowledgement_and_settlement_require_exact_pending_identity() {
        let now = std::time::Instant::now();
        let mut projections = ClientProjections::default();
        assert!(projections.connect(7, ExternalOpenPolicy::Disabled));
        assert!(projections
            .apply(7, ClientProjectionAction::TogglePolicy)
            .changed());
        assert!(!projections
            .apply(7, ClientProjectionAction::TogglePolicy)
            .changed());

        let pending_render = projections.render(7).expect("pending render");
        assert!(pending_render.view().saving());
        assert_eq!(
            pending_render.view().confirmed_policy(),
            ExternalOpenPolicy::Disabled
        );
        let request = pending_render
            .write_acknowledgement()
            .expect("render acknowledgement");
        let acknowledgement = projections
            .prepare_frame_acknowledgement(7, Default::default())
            .expect("frame acknowledgement");
        assert_eq!(acknowledgement.policy_mutation, Some(request));
        assert_eq!(
            projections
                .apply(
                    7,
                    ClientProjectionAction::FrameWritten {
                        acknowledgement: acknowledgement.clone(),
                    },
                )
                .mutation_request(),
            None
        );
        let mut mismatched_acknowledgement = acknowledgement.clone();
        mismatched_acknowledgement.policy_mutation = Some(PolicyMutationRequest {
            request_id: request.request_id + 1,
            ..request
        });
        assert!(!projections
            .apply(
                7,
                ClientProjectionAction::FrameQueued {
                    acknowledgement: mismatched_acknowledgement,
                },
            )
            .changed());
        assert!(projections
            .apply(
                7,
                ClientProjectionAction::FrameQueued {
                    acknowledgement: acknowledgement.clone(),
                },
            )
            .changed());
        assert_eq!(
            projections
                .apply(7, ClientProjectionAction::FrameWritten { acknowledgement },)
                .mutation_request(),
            Some(request)
        );

        let mismatched = projections.apply(
            7,
            ClientProjectionAction::SettlePolicy {
                result: PolicyMutationResult {
                    request_id: request.request_id + 1,
                    requested_policy: request.requested_policy,
                    persisted_policy: Some(ExternalOpenPolicy::Enabled),
                    effective_policy: ExternalOpenPolicy::Enabled,
                    failure_stage: None,
                },
                now,
            },
        );
        assert!(!mismatched.changed());
        assert!(projections
            .render(7)
            .expect("pending render")
            .view()
            .saving());

        let settled = projections.apply(
            7,
            ClientProjectionAction::SettlePolicy {
                result: PolicyMutationResult {
                    request_id: request.request_id,
                    requested_policy: request.requested_policy,
                    persisted_policy: Some(ExternalOpenPolicy::Enabled),
                    effective_policy: ExternalOpenPolicy::Enabled,
                    failure_stage: None,
                },
                now,
            },
        );
        assert!(settled.changed());
        assert_eq!(
            settled.confirmed_policy(),
            Some(ExternalOpenPolicy::Enabled)
        );
        let confirmed = projections.render(7).expect("confirmed render").view();
        assert_eq!(confirmed.confirmed_policy(), ExternalOpenPolicy::Enabled);
        assert!(!confirmed.saving());
    }

    fn projection_with_reload_failure(now: std::time::Instant) -> ClientProjection {
        let mut projection = ClientProjection::new(ExternalOpenPolicy::Disabled);
        let request = projection
            .toggle_policy()
            .expect("toggle should start a mutation");
        assert_eq!(projection.mark_policy_mutation_presented(), Some(request));
        assert!(projection.settle_policy_mutation(
            PolicyMutationResult {
                request_id: request.request_id,
                requested_policy: request.requested_policy,
                persisted_policy: Some(ExternalOpenPolicy::Enabled),
                effective_policy: ExternalOpenPolicy::Disabled,
                failure_stage: Some(
                    crate::protocol::ExternalOpenPolicyMutationFailureStage::Reload,
                ),
            },
            now,
        ));
        projection
    }

    #[test]
    fn unqueued_frame_cannot_present_a_policy_mutation() {
        let mut projection = ClientProjection::new(ExternalOpenPolicy::Disabled);
        let request = projection.toggle_policy().expect("policy mutation");
        let acknowledgement = projection
            .prepare_frame_acknowledgement(Default::default())
            .expect("frame acknowledgement");

        assert_eq!(
            projection.acknowledge_written_frame(acknowledgement.clone()),
            None
        );
        assert!(projection.view().saving());
        assert!(projection.queue_frame(acknowledgement.clone()));
        assert_eq!(
            projection.acknowledge_written_frame(acknowledgement),
            Some(request)
        );
    }

    #[test]
    fn displayed_context_ignores_unqueued_out_of_order_duplicate_and_stale_acknowledgements() {
        let mut projection = ClientProjection::new(ExternalOpenPolicy::Disabled);
        let app = crate::app::AppState::test_new();
        let frame_a_context = crate::ui::ClientRenderContext::compute(
            &app,
            None,
            ratatui::layout::Rect::new(0, 0, 80, 24),
        );
        let frame_b_context = crate::ui::ClientRenderContext::compute(
            &app,
            Some("client notice"),
            ratatui::layout::Rect::new(0, 0, 80, 24),
        );
        assert_ne!(frame_a_context, frame_b_context);

        let frame_a = projection
            .prepare_frame_acknowledgement(frame_a_context.clone())
            .expect("frame A acknowledgement");
        assert_eq!(frame_a.generation(), 1);
        assert!(projection.queue_frame(frame_a.clone()));
        let frame_b = projection
            .prepare_frame_acknowledgement(frame_b_context.clone())
            .expect("frame B acknowledgement");
        assert_eq!(frame_b.generation(), 2);
        assert!(projection.queue_frame(frame_b.clone()));
        let superseded = projection
            .prepare_frame_acknowledgement(Default::default())
            .expect("superseded candidate");
        assert_eq!(superseded.generation(), 3);

        assert_eq!(projection.acknowledge_written_frame(frame_b.clone()), None);
        assert_eq!(
            projection.displayed_render_context,
            crate::ui::ClientRenderContext::default()
        );
        assert_eq!(projection.acknowledge_written_frame(superseded), None);
        assert_eq!(projection.acknowledge_written_frame(frame_a.clone()), None);
        assert_eq!(projection.displayed_render_context, frame_a_context);
        assert_eq!(projection.acknowledge_written_frame(frame_a), None);
        assert_eq!(projection.displayed_render_context, frame_a_context);
        assert_eq!(projection.acknowledge_written_frame(frame_b.clone()), None);
        assert_eq!(projection.displayed_render_context, frame_b_context);
        assert_eq!(projection.acknowledge_written_frame(frame_b), None);
        assert_eq!(projection.displayed_render_context, frame_b_context);
    }

    #[test]
    fn explicit_reload_failure_retains_effective_policy_and_sets_notice() {
        let now = std::time::Instant::now();
        let mut projection = ClientProjection::new(ExternalOpenPolicy::Enabled);

        assert!(projection.report_reload_failure(ExternalOpenPolicy::Enabled, false, now));

        assert_eq!(
            projection.view().confirmed_policy(),
            ExternalOpenPolicy::Enabled
        );
        assert_eq!(
            projection.view().notice(),
            Some("Couldn’t reload remote link setting · previous value kept")
        );
    }

    #[test]
    fn mismatched_result_identity_cannot_settle_pending_projection() {
        let now = std::time::Instant::now();
        let mut projection = ClientProjection::new(ExternalOpenPolicy::Disabled);
        let request = projection.toggle_policy().expect("policy mutation");
        assert_eq!(projection.mark_policy_mutation_presented(), Some(request));

        assert!(!projection.settle_policy_mutation(
            PolicyMutationResult {
                request_id: request.request_id + 1,
                requested_policy: request.requested_policy,
                persisted_policy: Some(ExternalOpenPolicy::Enabled),
                effective_policy: ExternalOpenPolicy::Enabled,
                failure_stage: None,
            },
            now,
        ));
        assert!(projection.view().saving());
        assert_eq!(
            projection.view().confirmed_policy(),
            ExternalOpenPolicy::Disabled
        );
        assert_eq!(projection.view().notice(), None);
    }

    #[test]
    fn newer_notice_replaces_older_notice_and_owns_new_expiry() {
        let now = std::time::Instant::now();
        let mut projection = projection_with_reload_failure(now);
        let replacement_at = now + std::time::Duration::from_secs(1);
        let request = projection.toggle_policy().expect("replacement mutation");
        assert_eq!(projection.mark_policy_mutation_presented(), Some(request));
        assert!(
            projection.settle_policy_mutation(
                PolicyMutationResult {
                    request_id: request.request_id,
                    requested_policy: request.requested_policy,
                    persisted_policy: None,
                    effective_policy: ExternalOpenPolicy::Disabled,
                    failure_stage: Some(
                        crate::protocol::ExternalOpenPolicyMutationFailureStage::Write,
                    ),
                },
                replacement_at,
            )
        );

        assert_eq!(
            projection.view().notice(),
            Some("Couldn’t save remote link setting · previous value kept")
        );
        assert_eq!(
            projection.next_notice_deadline(),
            Some(replacement_at + std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn source_connection_can_explicitly_dismiss_its_notice() {
        let now = std::time::Instant::now();
        let mut projection = projection_with_reload_failure(now);

        assert!(projection.dismiss_notice());
        assert_eq!(projection.view().notice(), None);
        assert!(!projection.dismiss_notice());
    }

    #[test]
    fn notice_expires_at_the_exact_five_second_boundary() {
        let now = std::time::Instant::now();
        let mut projection = projection_with_reload_failure(now);

        assert!(!projection.expire_notice(
            now + std::time::Duration::from_secs(5) - std::time::Duration::from_nanos(1),
        ));
        assert!(projection.view().notice().is_some());
        assert!(projection.expire_notice(now + std::time::Duration::from_secs(5)));
        assert_eq!(projection.view().notice(), None);
    }

    #[test]
    fn failed_reload_result_retains_prior_effective_policy_and_creates_one_notice() {
        let now = std::time::Instant::now();
        let projection = projection_with_reload_failure(now);

        let view = projection.view();
        assert_eq!(view.confirmed_policy(), ExternalOpenPolicy::Disabled);
        assert!(!view.saving());
        assert_eq!(
            view.notice(),
            Some("Couldn’t reload remote link setting · previous value kept")
        );
    }

    #[test]
    fn toggle_keeps_confirmed_policy_visible_while_source_connection_is_saving() {
        let mut projection = ClientProjection::new(ExternalOpenPolicy::Disabled);

        let request = projection
            .toggle_policy()
            .expect("first toggle should start a mutation");

        assert_ne!(request.request_id, 0);
        assert_eq!(request.requested_policy, ExternalOpenPolicy::Enabled);
        assert_eq!(
            projection.view().confirmed_policy(),
            ExternalOpenPolicy::Disabled
        );
        assert!(projection.view().saving());
        assert!(projection.toggle_policy().is_none());
    }
}
