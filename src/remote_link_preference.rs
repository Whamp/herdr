#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteLinkPreferenceAction {
    Toggle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MutationDisposition {
    Started,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteLinkPreferenceFailureStage {
    Write,
    Reload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteLinkPreferenceSettlement {
    Confirmed,
    Failed(RemoteLinkPreferenceFailureStage),
}

trait RemoteLinkPreferenceStore: Send + Sync {
    fn persist_and_reload(&self, requested: bool)
        -> Result<bool, RemoteLinkPreferenceFailureStage>;

    fn reload(&self) -> Result<bool, RemoteLinkPreferenceFailureStage>;
}

struct FileRemoteLinkPreferenceStore;

impl FileRemoteLinkPreferenceStore {
    fn write_failed(
        path: &std::path::Path,
        error: &std::io::Error,
    ) -> RemoteLinkPreferenceFailureStage {
        crate::logging::config_write_failed(
            path,
            "open remote links on this device",
            &error.to_string(),
        );
        RemoteLinkPreferenceFailureStage::Write
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PersistedRemoteLinkPreferenceMutation {
    persisted: Option<bool>,
    effective: bool,
    failure_stage: Option<RemoteLinkPreferenceFailureStage>,
}

impl PersistedRemoteLinkPreferenceMutation {
    pub(crate) fn persisted(self) -> Option<bool> {
        self.persisted
    }

    pub(crate) fn effective(self) -> bool {
        self.effective
    }

    pub(crate) fn failure_stage(self) -> Option<RemoteLinkPreferenceFailureStage> {
        self.failure_stage
    }
}

pub(crate) fn persist_remote_link_preference_mutation(
    requested: bool,
    prior_effective: bool,
) -> PersistedRemoteLinkPreferenceMutation {
    match FileRemoteLinkPreferenceStore.persist_and_reload(requested) {
        Ok(effective) => PersistedRemoteLinkPreferenceMutation {
            persisted: Some(requested),
            effective,
            failure_stage: None,
        },
        Err(stage) => PersistedRemoteLinkPreferenceMutation {
            persisted: match stage {
                RemoteLinkPreferenceFailureStage::Write => None,
                RemoteLinkPreferenceFailureStage::Reload => Some(requested),
            },
            effective: prior_effective,
            failure_stage: Some(stage),
        },
    }
}

impl RemoteLinkPreferenceStore for FileRemoteLinkPreferenceStore {
    fn persist_and_reload(
        &self,
        requested: bool,
    ) -> Result<bool, RemoteLinkPreferenceFailureStage> {
        let path = crate::config::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| Self::write_failed(&path, &error))?;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(Self::write_failed(&path, &error)),
        };
        let updated = crate::config::upsert_section_bool(
            &content,
            "experimental",
            "open_remote_links_on_client",
            requested,
        );
        std::fs::write(&path, updated).map_err(|error| Self::write_failed(&path, &error))?;

        self.reload()
    }

    fn reload(&self) -> Result<bool, RemoteLinkPreferenceFailureStage> {
        let loaded = crate::config::load_live_config()
            .map_err(|_| RemoteLinkPreferenceFailureStage::Reload)?;
        if loaded
            .invalid_sections
            .iter()
            .any(|section| section == "experimental")
        {
            return Err(RemoteLinkPreferenceFailureStage::Reload);
        }

        Ok(loaded.config.experimental.open_remote_links_on_client)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteLinkPreferenceView {
    confirmed: bool,
    effective: bool,
    saving: bool,
}

impl RemoteLinkPreferenceView {
    pub(crate) fn projected(confirmed: bool, saving: bool) -> Self {
        Self {
            confirmed,
            effective: confirmed,
            saving,
        }
    }

    pub(crate) fn confirmed(self) -> bool {
        self.confirmed
    }

    pub(crate) fn effective(self) -> bool {
        self.effective
    }

    pub(crate) fn saving(self) -> bool {
        self.saving
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingMutation {
    requested: bool,
    presented: bool,
}

pub(crate) struct RemoteLinkPreference {
    confirmed: bool,
    effective: bool,
    pending: Option<PendingMutation>,
    store: std::sync::Arc<dyn RemoteLinkPreferenceStore>,
}

impl RemoteLinkPreference {
    pub(crate) fn new(initial: bool) -> Self {
        Self::with_store(initial, std::sync::Arc::new(FileRemoteLinkPreferenceStore))
    }

    fn with_store(initial: bool, store: std::sync::Arc<dyn RemoteLinkPreferenceStore>) -> Self {
        Self {
            confirmed: initial,
            effective: initial,
            pending: None,
            store,
        }
    }

    pub(crate) fn apply(&mut self, action: RemoteLinkPreferenceAction) -> MutationDisposition {
        if self.pending.is_some() {
            return MutationDisposition::Suppressed;
        }

        let requested = match action {
            RemoteLinkPreferenceAction::Toggle => !self.effective,
        };
        self.pending = Some(PendingMutation {
            requested,
            presented: false,
        });
        MutationDisposition::Started
    }

    pub(crate) fn view(&self) -> RemoteLinkPreferenceView {
        RemoteLinkPreferenceView {
            confirmed: self.confirmed,
            effective: self.effective,
            saving: self.pending.is_some(),
        }
    }

    pub(crate) fn mark_presented(&mut self) {
        if let Some(pending) = self.pending.as_mut() {
            pending.presented = true;
        }
    }

    pub(crate) fn reload_from_disk(&mut self) -> Result<bool, RemoteLinkPreferenceFailureStage> {
        if self.pending.is_some() {
            return Ok(false);
        }

        let reloaded = self.store.reload()?;
        let changed = self.confirmed != reloaded || self.effective != reloaded;
        self.confirmed = reloaded;
        self.effective = reloaded;
        Ok(changed)
    }

    pub(crate) fn settle_presented(&mut self) -> Option<RemoteLinkPreferenceSettlement> {
        let pending = self.pending?;
        if !pending.presented {
            return None;
        }

        let result = self.store.persist_and_reload(pending.requested);
        self.pending = None;
        Some(match result {
            Ok(reloaded) => {
                self.confirmed = reloaded;
                self.effective = reloaded;
                RemoteLinkPreferenceSettlement::Confirmed
            }
            Err(stage) => RemoteLinkPreferenceSettlement::Failed(stage),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    struct RecordingStore {
        requests: Mutex<Vec<bool>>,
        result: Result<bool, RemoteLinkPreferenceFailureStage>,
    }

    impl RemoteLinkPreferenceStore for RecordingStore {
        fn persist_and_reload(
            &self,
            requested: bool,
        ) -> Result<bool, RemoteLinkPreferenceFailureStage> {
            self.requests
                .lock()
                .expect("recording store lock")
                .push(requested);
            self.result
        }

        fn reload(&self) -> Result<bool, RemoteLinkPreferenceFailureStage> {
            self.result
        }
    }

    fn preference_with_result(
        initial: bool,
        result: Result<bool, RemoteLinkPreferenceFailureStage>,
    ) -> (RemoteLinkPreference, Arc<RecordingStore>) {
        let store = Arc::new(RecordingStore {
            requests: Mutex::new(Vec::new()),
            result,
        });
        (
            RemoteLinkPreference::with_store(initial, store.clone()),
            store,
        )
    }

    #[test]
    fn toggle_keeps_confirmed_and_effective_values_visible_while_pending() {
        let mut preference = RemoteLinkPreference::new(false);

        assert_eq!(
            preference.apply(RemoteLinkPreferenceAction::Toggle),
            MutationDisposition::Started
        );
        let view = preference.view();
        assert!(!view.confirmed());
        assert!(!view.effective());
        assert!(view.saving());
    }

    #[test]
    fn duplicate_toggle_is_suppressed_until_pending_mutation_settles() {
        let mut preference = RemoteLinkPreference::new(false);
        preference.apply(RemoteLinkPreferenceAction::Toggle);

        assert_eq!(
            preference.apply(RemoteLinkPreferenceAction::Toggle),
            MutationDisposition::Suppressed
        );
    }

    #[test]
    fn pending_mutation_does_not_settle_before_a_frame_is_presented() {
        let (mut preference, store) = preference_with_result(false, Ok(true));
        preference.apply(RemoteLinkPreferenceAction::Toggle);

        assert_eq!(preference.settle_presented(), None);
        assert!(preference.view().saving());
        assert!(store
            .requests
            .lock()
            .expect("recording store lock")
            .is_empty());
    }

    #[test]
    fn explicit_reload_reflects_external_edit_without_a_watcher() {
        let _guard = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let path = std::env::temp_dir()
            .join(format!("herdr-remote-link-reload-{}", std::process::id()))
            .join("config.toml");
        std::fs::create_dir_all(path.parent().expect("config parent"))
            .expect("create config parent");
        std::fs::write(
            &path,
            "[experimental]\nopen_remote_links_on_client = false\n",
        )
        .expect("write initial config");
        std::env::set_var(crate::config::CONFIG_PATH_ENV_VAR, &path);
        let mut preference = RemoteLinkPreference::new(false);

        std::fs::write(
            &path,
            "[experimental]\nopen_remote_links_on_client = true\n",
        )
        .expect("write external edit");
        assert!(!preference.view().confirmed());

        assert_eq!(preference.reload_from_disk(), Ok(true));
        assert!(preference.view().confirmed());
        assert!(preference.view().effective());

        std::env::remove_var(crate::config::CONFIG_PATH_ENV_VAR);
        let _ = std::fs::remove_dir_all(path.parent().expect("config parent"));
    }

    #[test]
    fn presented_mutation_persists_then_confirms_the_reloaded_value() {
        let (mut preference, store) = preference_with_result(false, Ok(true));
        preference.apply(RemoteLinkPreferenceAction::Toggle);
        preference.mark_presented();

        assert_eq!(
            preference.settle_presented(),
            Some(RemoteLinkPreferenceSettlement::Confirmed)
        );
        assert_eq!(
            *store.requests.lock().expect("recording store lock"),
            vec![true]
        );
        let view = preference.view();
        assert!(view.confirmed());
        assert!(view.effective());
        assert!(!view.saving());
    }
}
