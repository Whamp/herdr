use std::collections::HashMap;
use std::io;

use crate::external_open::{
    validate_external_open_url, ExternalOpenPlatform, ExternalOpenUrlError,
    ValidatedExternalOpenUrl,
};
use crate::protocol::{
    ClientMessage, ExternalOpenPolicy, ExternalOpenPreparationFailure, ExternalOpenResult,
    ExternalOpenTarget,
};

struct PreparedExternalOpen {
    url: String,
    target: ExternalOpenTarget,
}

pub(super) struct ClientExternalOpen {
    policy: ExternalOpenPolicy,
    prepared: HashMap<u64, PreparedExternalOpen>,
}

impl ClientExternalOpen {
    pub(super) fn new(policy: ExternalOpenPolicy) -> Self {
        Self {
            policy,
            prepared: HashMap::new(),
        }
    }

    pub(super) fn prepare(
        &mut self,
        request_id: u64,
        url: String,
        platform: ExternalOpenPlatform,
    ) -> Option<ClientMessage> {
        if self.policy != ExternalOpenPolicy::Enabled
            || request_id == 0
            || self.prepared.contains_key(&request_id)
        {
            return None;
        }

        let target = match validate_external_open_url(&url, platform) {
            Ok(ValidatedExternalOpenUrl::Ordinary(_)) => ExternalOpenTarget::Direct,
            Ok(ValidatedExternalOpenUrl::Loopback(_)) => {
                return Some(ClientMessage::ExternalOpenPreparationFailed {
                    request_id,
                    reason: ExternalOpenPreparationFailure::ForwardingUnavailable,
                });
            }
            Err(error) => {
                return Some(ClientMessage::ExternalOpenPreparationFailed {
                    request_id,
                    reason: preparation_failure(error),
                });
            }
        };
        self.prepared
            .insert(request_id, PreparedExternalOpen { url, target });
        Some(ClientMessage::ExternalOpenReady { request_id, target })
    }

    pub(super) fn confirm_policy(&mut self, policy: ExternalOpenPolicy) -> ClientMessage {
        self.policy = policy;
        if policy == ExternalOpenPolicy::Disabled {
            self.prepared.clear();
        }
        ClientMessage::ExternalOpenPolicyUpdate { policy }
    }

    pub(super) fn cancel(&mut self, request_id: u64) -> bool {
        self.prepared.remove(&request_id).is_some()
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

    use crate::external_open::ExternalOpenPlatform;
    use crate::protocol::{
        ClientMessage, ExternalOpenPolicy, ExternalOpenResult, ExternalOpenTarget,
    };

    use super::*;

    #[test]
    fn precommit_cancellation_makes_zero_opener_calls() {
        let mut external_open = ClientExternalOpen::new(ExternalOpenPolicy::Enabled);
        assert!(external_open
            .prepare(
                41,
                "https://example.com/cancelled".to_owned(),
                ExternalOpenPlatform::Linux,
            )
            .is_some());

        assert!(external_open.cancel(41));
        assert!(!external_open.cancel(41));
        assert!(external_open.commit(41).is_none());
    }

    #[test]
    fn confirmed_policy_update_revokes_prepared_requests_before_reporting_disable() {
        let mut external_open = ClientExternalOpen::new(ExternalOpenPolicy::Enabled);
        for request_id in [41, 42] {
            assert!(external_open
                .prepare(
                    request_id,
                    format!("https://example.com/{request_id}"),
                    ExternalOpenPlatform::Linux,
                )
                .is_some());
        }

        assert_eq!(
            external_open.confirm_policy(ExternalOpenPolicy::Disabled),
            ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Disabled,
            }
        );
        assert!(external_open.commit(41).is_none());
        assert!(external_open.commit(42).is_none());
        assert_eq!(
            external_open.confirm_policy(ExternalOpenPolicy::Enabled),
            ClientMessage::ExternalOpenPolicyUpdate {
                policy: ExternalOpenPolicy::Enabled,
            }
        );
    }

    #[test]
    fn ordinary_url_opener_is_unreachable_until_matching_commit() {
        let original = "https://example.com/a%2Fb?token=a+b#frag";
        let mut external_open = ClientExternalOpen::new(ExternalOpenPolicy::Enabled);
        let opened = RefCell::new(Vec::new());

        assert_eq!(
            external_open.prepare(41, original.to_owned(), ExternalOpenPlatform::Linux),
            Some(ClientMessage::ExternalOpenReady {
                request_id: 41,
                target: ExternalOpenTarget::Direct,
            })
        );
        assert!(opened.borrow().is_empty());

        let committed = external_open.commit(41).expect("matching commit");
        assert!(external_open.commit(41).is_none());
        assert_eq!(
            committed.execute(|url| {
                opened.borrow_mut().push(url.to_owned());
                Ok(())
            }),
            ClientMessage::ExternalOpenResult {
                request_id: 41,
                result: ExternalOpenResult::OpenedDirectly,
            }
        );
        assert_eq!(*opened.borrow(), vec![original]);
    }
}
