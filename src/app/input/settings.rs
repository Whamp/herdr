use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

use crate::{
    app::{
        state::{AppState, ExperimentSetting, SettingsSection, THEME_NAMES},
        App, Mode,
    },
    config::ToastDelivery,
};

#[derive(Debug, Clone, PartialEq, Eq)]
// The shared `Save` verb is semantic: these actions persist settings.
#[allow(clippy::enum_variant_names)]
pub(super) enum SettingsAction {
    SaveTheme(String),
    SaveSound(bool),
    SaveToastDelivery(ToastDelivery),
    SaveAgentBorderLabels(bool),
    SavePaneHistory(bool),
    SaveSwitchAsciiInputSourceInPrefix(bool),
    ChangeRemoteLinkPreference(crate::remote_link_preference::RemoteLinkPreferenceAction),
    InstallRecommendedIntegrations,
}

/// Map an Experiments row index to the toggle action that flips it.
fn experiment_toggle_action(state: &AppState, idx: usize) -> Option<SettingsAction> {
    match ExperimentSetting::ALL.get(idx).copied()? {
        ExperimentSetting::PaneHistory => Some(SettingsAction::SavePaneHistory(
            !state.pane_history_persistence_enabled(),
        )),
        ExperimentSetting::SwitchAsciiInputSourceInPrefix => {
            Some(SettingsAction::SaveSwitchAsciiInputSourceInPrefix(
                !state.switch_ascii_input_source_in_prefix_enabled(),
            ))
        }
        ExperimentSetting::OpenRemoteLinksOnClient => {
            Some(SettingsAction::ChangeRemoteLinkPreference(
                crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle,
            ))
        }
    }
}

impl App {
    pub(crate) fn handle_settings_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<crate::remote_link_preference::RemoteLinkPreferenceAction> {
        let previous_section = self.state.settings.section;
        let mut remote_link_action = None;
        if let Some(action) = update_settings_state(&mut self.state, key) {
            match action {
                SettingsAction::SaveTheme(name) => self.save_theme(&name),
                SettingsAction::SaveSound(enabled) => self.save_sound(enabled),
                SettingsAction::SaveToastDelivery(delivery) => self.save_toast_delivery(delivery),
                SettingsAction::SaveAgentBorderLabels(enabled) => {
                    self.save_agent_border_labels(enabled)
                }
                SettingsAction::SavePaneHistory(enabled) => {
                    self.save_pane_history_persistence(enabled)
                }
                SettingsAction::SaveSwitchAsciiInputSourceInPrefix(enabled) => {
                    self.save_switch_ascii_input_source_in_prefix(enabled)
                }
                SettingsAction::ChangeRemoteLinkPreference(action) => {
                    remote_link_action = Some(action)
                }
                SettingsAction::InstallRecommendedIntegrations => {
                    self.install_recommended_integrations()
                }
            }
        }
        if previous_section != SettingsSection::Integrations
            && self.state.settings.section == SettingsSection::Integrations
        {
            self.refresh_integration_recommendations();
        }
        remote_link_action
    }
}

fn normalize_theme_name(name: &str) -> String {
    name.to_lowercase().replace([' ', '_'], "-")
}

fn current_theme_index(theme_name: &str) -> usize {
    let normalized = normalize_theme_name(theme_name);
    THEME_NAMES
        .iter()
        .position(|name| normalize_theme_name(name) == normalized)
        .unwrap_or(0)
}

fn toast_delivery_index(delivery: ToastDelivery) -> usize {
    match delivery {
        ToastDelivery::Off => 0,
        ToastDelivery::Herdr => 1,
        ToastDelivery::Terminal => 2,
        ToastDelivery::System => 3,
    }
}

fn toast_delivery_for_index(idx: usize) -> ToastDelivery {
    match idx {
        0 => ToastDelivery::Off,
        1 => ToastDelivery::Herdr,
        2 => ToastDelivery::Terminal,
        _ => ToastDelivery::System,
    }
}

fn preview_selected_theme(state: &mut AppState) {
    use crate::app::state::Palette;

    let name = THEME_NAMES[state.settings.list.selected];
    if let Some(mut palette) = Palette::from_name(name) {
        if let Some(custom) = &state.theme_runtime.custom {
            palette = palette.with_overrides(custom);
        }
        if let Some(accent) = &state.theme_runtime.legacy_accent {
            palette.accent = crate::config::parse_color(accent);
        }
        state.palette = palette;
        state.theme_name = name.to_string();
    }
}

fn cancel_settings(state: &mut AppState) {
    if let Some(palette) = state.settings.original_palette.take() {
        state.palette = palette;
    }
    if let Some(theme_name) = state.settings.original_theme.take() {
        state.theme_name = theme_name;
    }
    super::modal::leave_modal(state);
}

fn integrations_need_install(state: &AppState) -> bool {
    state
        .integration_recommendations
        .iter()
        .any(crate::integration::IntegrationRecommendation::needs_install)
}

fn apply_settings(state: &mut AppState) -> Option<SettingsAction> {
    match state.settings.section {
        SettingsSection::Theme => {
            let theme_name = state.theme_name.clone();
            state.settings.original_palette = None;
            state.settings.original_theme = None;
            super::modal::leave_modal(state);
            Some(SettingsAction::SaveTheme(theme_name))
        }
        SettingsSection::Integrations if integrations_need_install(state) => {
            Some(SettingsAction::InstallRecommendedIntegrations)
        }
        SettingsSection::Integrations => None,
        _ => {
            super::modal::leave_modal(state);
            None
        }
    }
}

pub(super) fn update_settings_state(state: &mut AppState, key: KeyEvent) -> Option<SettingsAction> {
    match state.settings.section {
        SettingsSection::Theme => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                let previous = state.settings.list.selected;
                state.settings.list.move_prev();
                if state.settings.list.selected != previous {
                    preview_selected_theme(state);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let previous = state.settings.list.selected;
                state.settings.list.move_next(THEME_NAMES.len());
                if state.settings.list.selected != previous {
                    preview_selected_theme(state);
                }
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.settings.section = SettingsSection::Sound;
                state.settings.list.selected = usize::from(!state.sound_enabled());
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.settings.section = SettingsSection::Experiments;
                state.settings.list.selected = 0;
            }
            _ => match super::modal::modal_action_from_key(&key, super::modal::SETTINGS_ACTIONS) {
                Some(super::modal::ModalAction::Apply) => return apply_settings(state),
                Some(super::modal::ModalAction::Close) => cancel_settings(state),
                _ => {}
            },
        },
        SettingsSection::Sound => match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {
                state.settings.list.selected = 1 - state.settings.list.selected.min(1);
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let enabled = state.settings.list.selected == 0;
                return Some(SettingsAction::SaveSound(enabled));
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.settings.section = SettingsSection::Toast;
                state.settings.list.selected = toast_delivery_index(state.toast_delivery());
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.settings.section = SettingsSection::Theme;
                state.settings.list.selected = current_theme_index(&state.theme_name);
            }
            _ => {
                if let Some(super::modal::ModalAction::Close) =
                    super::modal::modal_action_from_key(&key, super::modal::SETTINGS_ACTIONS)
                {
                    cancel_settings(state);
                }
            }
        },
        SettingsSection::Toast => match key.code {
            KeyCode::Up | KeyCode::Char('k') => state.settings.list.move_prev(),
            KeyCode::Down | KeyCode::Char('j') => state.settings.list.move_next(4),
            KeyCode::Enter | KeyCode::Char(' ') => {
                let delivery = toast_delivery_for_index(state.settings.list.selected);
                return Some(SettingsAction::SaveToastDelivery(delivery));
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.settings.section = SettingsSection::Sound;
                state.settings.list.selected = usize::from(!state.sound_enabled());
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.settings.section = SettingsSection::PaneLabels;
                state.settings.list.selected = usize::from(!state.agent_border_labels_enabled());
            }
            _ => {
                if let Some(super::modal::ModalAction::Close) =
                    super::modal::modal_action_from_key(&key, super::modal::SETTINGS_ACTIONS)
                {
                    cancel_settings(state);
                }
            }
        },
        SettingsSection::PaneLabels => match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {
                state.settings.list.selected = 1 - state.settings.list.selected.min(1);
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let enabled = state.settings.list.selected == 0;
                return Some(SettingsAction::SaveAgentBorderLabels(enabled));
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.settings.section = SettingsSection::Toast;
                state.settings.list.selected = toast_delivery_index(state.toast_delivery());
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.settings.section = SettingsSection::Integrations;
                state.settings.list.selected = 0;
            }
            _ => {
                if let Some(super::modal::ModalAction::Close) =
                    super::modal::modal_action_from_key(&key, super::modal::SETTINGS_ACTIONS)
                {
                    cancel_settings(state);
                }
            }
        },
        SettingsSection::Experiments => match key.code {
            KeyCode::Up | KeyCode::Char('k') => state.settings.list.move_prev(),
            KeyCode::Down | KeyCode::Char('j') => {
                state.settings.list.move_next(ExperimentSetting::ALL.len())
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                return experiment_toggle_action(state, state.settings.list.selected);
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.settings.section = SettingsSection::Integrations;
                state.settings.list.selected = 0;
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.settings.section = SettingsSection::Theme;
                state.settings.list.selected = current_theme_index(&state.theme_name);
            }
            _ => {
                if let Some(super::modal::ModalAction::Close) =
                    super::modal::modal_action_from_key(&key, super::modal::SETTINGS_ACTIONS)
                {
                    cancel_settings(state);
                }
            }
        },
        SettingsSection::Integrations => match key.code {
            KeyCode::Enter | KeyCode::Char(' ') if integrations_need_install(state) => {
                return Some(SettingsAction::InstallRecommendedIntegrations);
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                state.settings.section = SettingsSection::PaneLabels;
                state.settings.list.selected = usize::from(!state.agent_border_labels_enabled());
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                state.settings.section = SettingsSection::Experiments;
                state.settings.list.selected = 0;
            }
            _ => match super::modal::modal_action_from_key(&key, super::modal::SETTINGS_ACTIONS) {
                Some(super::modal::ModalAction::Apply) => return apply_settings(state),
                Some(super::modal::ModalAction::Close) => cancel_settings(state),
                _ => {}
            },
        },
    }

    None
}

pub(crate) fn open_settings(state: &mut AppState) {
    open_settings_at(state, SettingsSection::Theme);
}

pub(crate) fn open_settings_at(state: &mut AppState, section: SettingsSection) {
    state.integration_install_messages.clear();
    state.settings.original_palette = Some(state.palette.clone());
    state.settings.original_theme = Some(state.theme_name.clone());
    state.settings.section = section;
    state.settings.list.selected = match section {
        SettingsSection::Theme => current_theme_index(&state.theme_name),
        SettingsSection::Sound => usize::from(!state.sound_enabled()),
        SettingsSection::Toast => toast_delivery_index(state.toast_delivery()),
        SettingsSection::PaneLabels => usize::from(!state.agent_border_labels_enabled()),
        SettingsSection::Experiments => 0,
        SettingsSection::Integrations => 0,
    };
    state.mode = Mode::Settings;
}

impl AppState {
    fn settings_popup_rect(&self) -> Rect {
        crate::ui::centered_popup_rect(
            self.screen_rect(),
            crate::ui::SETTINGS_POPUP_WIDTH,
            crate::ui::settings_popup_height(self),
        )
        .unwrap_or_default()
    }

    fn settings_inner_rect(&self) -> Rect {
        let popup = self.settings_popup_rect();
        Rect::new(
            popup.x + 1,
            popup.y + 1,
            popup.width.saturating_sub(2),
            popup.height.saturating_sub(2),
        )
    }

    fn settings_tab_at(&self, col: u16, row: u16) -> Option<SettingsSection> {
        let inner = self.settings_inner_rect();
        let tab_y = inner.y + 1;
        if row != tab_y {
            return None;
        }
        let mut x = inner.x;
        for section in SettingsSection::ALL {
            let badge_width = if self.settings_section_has_badge(*section) {
                2
            } else {
                0
            };
            let width = section.label().len() as u16 + 2 + badge_width;
            if col >= x && col < x + width {
                return Some(*section);
            }
            x += width + 1;
        }
        None
    }

    pub(crate) fn settings_content_rect(&self) -> Rect {
        let inner = self.settings_inner_rect();
        crate::ui::modal_stack_areas(inner, 3, 2, 0, 1).content
    }

    fn settings_list_index_at(&self, col: u16, row: u16) -> Option<usize> {
        let area = self.settings_content_rect();
        if row < area.y || row >= area.y + area.height || col < area.x || col >= area.x + area.width
        {
            return None;
        }

        match self.settings.section {
            SettingsSection::Theme => {
                let max_visible = area.height as usize;
                let scroll = if self.settings.list.selected >= max_visible {
                    self.settings.list.selected - max_visible + 1
                } else {
                    0
                };
                let idx = scroll + (row - area.y) as usize;
                (idx < THEME_NAMES.len()).then_some(idx)
            }
            SettingsSection::Sound => {
                let list_y = area.y + 3;
                if row >= list_y && row < list_y + 2 {
                    Some((row - list_y) as usize)
                } else {
                    None
                }
            }
            SettingsSection::Toast => {
                let list_y = area.y + 3;
                if row >= list_y && row < list_y + 8 {
                    Some(((row - list_y) / 2) as usize)
                } else {
                    None
                }
            }
            SettingsSection::PaneLabels => {
                let list_y = area.y + 3;
                if row >= list_y && row < list_y + 2 {
                    Some((row - list_y) as usize)
                } else {
                    None
                }
            }
            SettingsSection::Experiments => {
                let list_y = area.y + 3;
                if row >= list_y && row < list_y + ExperimentSetting::ALL.len() as u16 {
                    Some((row - list_y) as usize)
                } else {
                    None
                }
            }
            SettingsSection::Integrations => None,
        }
    }

    pub(super) fn handle_settings_mouse(&mut self, mouse: MouseEvent) -> Option<SettingsAction> {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(section) = self.settings_tab_at(mouse.column, mouse.row) {
                    self.settings.section = section;
                    self.settings.list.select(match section {
                        SettingsSection::Theme => current_theme_index(&self.theme_name),
                        SettingsSection::Sound => usize::from(!self.sound_enabled()),
                        SettingsSection::Toast => toast_delivery_index(self.toast_delivery()),
                        SettingsSection::PaneLabels => {
                            usize::from(!self.agent_border_labels_enabled())
                        }
                        SettingsSection::Experiments => 0,
                        SettingsSection::Integrations => 0,
                    });
                    return None;
                }
                if let Some(idx) = self.settings_list_index_at(mouse.column, mouse.row) {
                    self.settings.list.select(idx);
                    return match self.settings.section {
                        SettingsSection::Theme => {
                            preview_selected_theme(self);
                            None
                        }
                        SettingsSection::Sound => {
                            let enabled = idx == 0;
                            Some(SettingsAction::SaveSound(enabled))
                        }
                        SettingsSection::Toast => {
                            let delivery = toast_delivery_for_index(idx);
                            Some(SettingsAction::SaveToastDelivery(delivery))
                        }
                        SettingsSection::PaneLabels => {
                            let enabled = idx == 0;
                            Some(SettingsAction::SaveAgentBorderLabels(enabled))
                        }
                        SettingsSection::Experiments => experiment_toggle_action(self, idx),
                        SettingsSection::Integrations => None,
                    };
                }

                let inner = self.settings_inner_rect();
                let show_primary = crate::ui::settings_show_primary_action(self);
                let (apply, close) =
                    crate::ui::settings_button_rects(inner, self.settings.section, show_primary);
                let mut buttons = vec![(close, super::modal::ModalAction::Close)];
                if let Some(apply) = apply {
                    buttons.insert(0, (apply, super::modal::ModalAction::Apply));
                }
                match super::modal::modal_action_from_buttons(mouse.column, mouse.row, &buttons) {
                    Some(super::modal::ModalAction::Apply) => apply_settings(self),
                    Some(super::modal::ModalAction::Close) => {
                        cancel_settings(self);
                        None
                    }
                    _ => {
                        cancel_settings(self);
                        None
                    }
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEventKind};
    use ratatui::{backend::TestBackend, Terminal};

    use super::super::{app_for_mouse_test, mouse, state_with_workspaces};
    use super::*;

    struct TestConfig {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
        previous: Option<std::ffi::OsString>,
    }

    impl TestConfig {
        fn new(name: &str, content: &str) -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after unix epoch")
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("herdr-{name}-{}-{stamp}", std::process::id()));
            let path = root.join("config.toml");
            std::fs::create_dir_all(&root).expect("create test config directory");
            std::fs::write(&path, content).expect("write test config");
            let previous = std::env::var_os(crate::config::CONFIG_PATH_ENV_VAR);
            std::env::set_var(crate::config::CONFIG_PATH_ENV_VAR, &path);
            Self {
                root,
                path,
                previous,
            }
        }
    }

    impl Drop for TestConfig {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(crate::config::CONFIG_PATH_ENV_VAR, previous);
            } else {
                std::env::remove_var(crate::config::CONFIG_PATH_ENV_VAR);
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn render_foreground_settings(
        app: &mut App,
        preference: &mut crate::remote_link_preference::RemoteLinkPreference,
    ) -> String {
        let area = Rect::new(0, 0, 80, 24);
        crate::ui::compute_view_with_runtime_registry(&mut app.state, &app.terminal_runtimes, area);
        let mut terminal =
            Terminal::new(TestBackend::new(area.width, area.height)).expect("test terminal");
        terminal
            .draw(|frame| {
                crate::ui::render_with_runtime_registry_and_client_local_preference(
                    &app.state,
                    &app.terminal_runtimes,
                    Some(preference.view()),
                    frame,
                )
            })
            .expect("render foreground settings");
        preference.mark_presented();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn settings_cancel_restores_previewed_theme_from_other_sections() {
        let mut state = state_with_workspaces(&["test"]);
        let original_palette = state.palette.clone();
        let original_theme = state.theme_name.clone();

        open_settings(&mut state);
        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
        );
        assert_ne!(state.theme_name, original_theme);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()),
        );
        assert_eq!(
            state.settings.section,
            crate::app::state::SettingsSection::Sound
        );

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()),
        );

        assert_eq!(state.mode, Mode::Terminal);
        assert_eq!(state.theme_name, original_theme);
        assert_eq!(state.palette.accent, original_palette.accent);
        assert_eq!(state.palette.panel_bg, original_palette.panel_bg);
    }

    #[test]
    fn settings_sound_toggle_returns_save_action() {
        let mut state = state_with_workspaces(&["test"]);
        open_settings(&mut state);
        state.settings.section = crate::app::state::SettingsSection::Sound;
        state.settings.list.selected = 0;

        let action = update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
        );

        assert_eq!(action, Some(SettingsAction::SaveSound(true)));
        assert!(!state.sound.enabled);
        assert_eq!(state.mode, Mode::Settings);
    }

    #[test]
    fn settings_experiments_toggles_pane_history() {
        let mut state = state_with_workspaces(&["test"]);
        state.pane_history_persistence = false;
        open_settings_at(&mut state, SettingsSection::Experiments);

        let action = update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
        );

        assert_eq!(action, Some(SettingsAction::SavePaneHistory(true)));
        assert_eq!(state.mode, Mode::Settings);
    }

    #[test]
    fn settings_experiments_down_then_toggle_switches_ascii_input_source() {
        let mut state = state_with_workspaces(&["test"]);
        state.switch_ascii_input_source_in_prefix = false;
        open_settings_at(&mut state, SettingsSection::Experiments);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Down, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.list.selected, 1);

        let action = update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
        );

        assert_eq!(
            action,
            Some(SettingsAction::SaveSwitchAsciiInputSourceInPrefix(true))
        );
        assert_eq!(state.mode, Mode::Settings);
    }

    #[test]
    fn settings_experiments_enter_and_space_request_device_remote_link_toggle() {
        for code in [KeyCode::Enter, KeyCode::Char(' ')] {
            let mut state = state_with_workspaces(&["test"]);
            open_settings_at(&mut state, SettingsSection::Experiments);
            state.settings.list.selected = 2;

            let action =
                update_settings_state(&mut state, KeyEvent::new(code, KeyModifiers::empty()));

            assert_eq!(
                action,
                Some(SettingsAction::ChangeRemoteLinkPreference(
                    crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle,
                ))
            );
        }
    }

    #[test]
    fn settings_tab_cycle_places_experiments_last() {
        let mut state = state_with_workspaces(&["test"]);
        open_settings_at(&mut state, SettingsSection::PaneLabels);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.section, SettingsSection::Integrations);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.section, SettingsSection::Experiments);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.section, SettingsSection::Theme);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.section, SettingsSection::Experiments);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.section, SettingsSection::Integrations);

        update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()),
        );
        assert_eq!(state.settings.section, SettingsSection::PaneLabels);
    }

    #[test]
    fn integrations_enter_does_nothing_when_nothing_needs_install() {
        let mut state = state_with_workspaces(&["test"]);
        open_settings_at(&mut state, SettingsSection::Integrations);

        let enter_action = update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
        );
        assert_eq!(enter_action, None);

        let space_action = update_settings_state(
            &mut state,
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()),
        );
        assert_eq!(space_action, None);
    }

    #[test]
    fn settings_hover_does_not_change_selection() {
        let mut app = app_for_mouse_test();
        open_settings(&mut app.state);
        app.state.settings.list.select(0);

        let area = app.state.settings_content_rect();
        app.handle_mouse(mouse(MouseEventKind::Moved, area.x + 2, area.y + 2));

        assert_eq!(app.state.settings.list.selected, 0);
    }

    #[test]
    fn settings_mouse_click_toggles_pane_history() {
        let mut app = app_for_mouse_test();
        app.state.pane_history_persistence = false;
        open_settings_at(&mut app.state, SettingsSection::Experiments);

        let area = app.state.settings_content_rect();
        let action = app.state.handle_settings_mouse(mouse(
            MouseEventKind::Down(crossterm::event::MouseButton::Left),
            area.x + 2,
            area.y + 3,
        ));

        assert_eq!(action, Some(SettingsAction::SavePaneHistory(true)));
        assert_eq!(app.state.settings.list.selected, 0);
    }

    #[test]
    fn settings_mouse_click_toggles_switch_ascii_input_source_row() {
        let mut app = app_for_mouse_test();
        app.state.switch_ascii_input_source_in_prefix = false;
        open_settings_at(&mut app.state, SettingsSection::Experiments);

        let area = app.state.settings_content_rect();
        let action = app.state.handle_settings_mouse(mouse(
            MouseEventKind::Down(crossterm::event::MouseButton::Left),
            area.x + 2,
            area.y + 4,
        ));

        assert_eq!(
            action,
            Some(SettingsAction::SaveSwitchAsciiInputSourceInPrefix(true))
        );
        assert_eq!(app.state.settings.list.selected, 1);
    }

    #[tokio::test]
    async fn settings_keyboard_route_requests_device_remote_link_toggle() {
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;

        let action = app
            .handle_key_with_client_local_action(crate::input::TerminalKey::new(
                KeyCode::Enter,
                KeyModifiers::empty(),
            ))
            .await;

        assert_eq!(
            action,
            Some(crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle)
        );
    }

    #[tokio::test]
    async fn raw_keyboard_input_surfaces_device_remote_link_action_to_foreground() {
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;

        let (changed, action) = app
            .handle_raw_input_event_with_client_local_action(crate::raw_input::RawInputEvent::Key(
                crate::input::TerminalKey::new(KeyCode::Enter, KeyModifiers::empty()),
            ))
            .await;

        assert!(changed);
        assert_eq!(
            action,
            Some(crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle)
        );
    }

    #[test]
    fn explicit_app_reload_refreshes_separate_device_remote_link_preference() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let config = TestConfig::new(
            "remote-link-app-reload",
            "[experimental]\nopen_remote_links_on_client = false\n",
        );
        let mut app = app_for_mouse_test();
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(false);
        std::fs::write(
            &config.path,
            "[experimental]\nopen_remote_links_on_client = true\n",
        )
        .expect("write external config edit");
        assert!(!preference.view().confirmed());

        assert_eq!(
            app.reload_config().status,
            crate::config::ConfigReloadStatus::Applied
        );
        assert!(app.take_config_reloaded_from_disk());
        assert_eq!(preference.reload_from_disk(), Ok(true));
        assert!(preference.view().confirmed());
        assert!(preference.view().effective());
    }

    #[tokio::test]
    async fn duplicate_production_keyboard_toggle_is_suppressed_until_settlement() {
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(false);

        let enter = app
            .handle_key_with_client_local_action(crate::input::TerminalKey::new(
                KeyCode::Enter,
                KeyModifiers::empty(),
            ))
            .await
            .expect("enter action");
        let space = app
            .handle_key_with_client_local_action(crate::input::TerminalKey::new(
                KeyCode::Char(' '),
                KeyModifiers::empty(),
            ))
            .await
            .expect("space action");

        assert_eq!(
            preference.apply(enter),
            crate::remote_link_preference::MutationDisposition::Started
        );
        assert_eq!(
            preference.apply(space),
            crate::remote_link_preference::MutationDisposition::Suppressed
        );
        assert!(!preference.view().confirmed());
        assert!(preference.view().saving());
    }

    #[test]
    fn keyboard_toggle_without_active_session_persists_and_reloads_after_pending_frame() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let config = TestConfig::new("remote-link-keyboard", "onboarding = false\n");
        let mut app = app_for_mouse_test();
        app.state.active = None;
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(false);

        let action = app
            .handle_settings_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()))
            .expect("remote-link action");
        assert_eq!(
            preference.apply(action),
            crate::remote_link_preference::MutationDisposition::Started
        );
        let pending = render_foreground_settings(&mut app, &mut preference);
        assert!(pending.contains("open remote links on this device [ ] saving…"));

        assert_eq!(
            preference.settle_presented(),
            Some(crate::remote_link_preference::RemoteLinkPreferenceSettlement::Confirmed)
        );
        let confirmed = render_foreground_settings(&mut app, &mut preference);
        assert!(confirmed.contains("open remote links on this device [✓]"));
        assert!(!confirmed.contains("open remote links on this device [✓] saving…"));
        assert!(preference.view().effective());
        assert!(std::fs::read_to_string(&config.path)
            .expect("read persisted config")
            .contains("open_remote_links_on_client = true"));
    }

    #[test]
    fn settings_mouse_click_from_another_row_requests_device_remote_link_toggle() {
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 0;

        let area = app.state.settings_content_rect();
        let action = app.handle_mouse_with_client_local_action(mouse(
            MouseEventKind::Down(crossterm::event::MouseButton::Left),
            area.x + 2,
            area.y + 5,
        ));

        assert_eq!(
            action,
            Some(crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle)
        );
        assert_eq!(app.state.settings.list.selected, 2);
    }

    #[test]
    fn reload_failure_retains_prior_confirmed_and_effective_remote_link_value() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let _config = TestConfig::new(
            "remote-link-reload-failure",
            "[experimental]\npane_history = \"invalid\"\n",
        );
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(false);
        preference.apply(crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle);
        let pending = render_foreground_settings(&mut app, &mut preference);
        assert!(pending.contains("open remote links on this device [ ] saving…"));

        assert_eq!(
            preference.settle_presented(),
            Some(
                crate::remote_link_preference::RemoteLinkPreferenceSettlement::Failed(
                    crate::remote_link_preference::RemoteLinkPreferenceFailureStage::Reload,
                )
            )
        );
        assert!(!preference.view().confirmed());
        assert!(!preference.view().effective());
        assert!(!preference.view().saving());
        assert!(app.state.config_diagnostic.is_none());
    }

    #[test]
    fn write_failure_retains_prior_confirmed_and_effective_remote_link_value() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let config = TestConfig::new(
            "remote-link-write-failure",
            "[experimental]\nopen_remote_links_on_client = true\n",
        );
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(true);
        preference.apply(crate::remote_link_preference::RemoteLinkPreferenceAction::Toggle);
        let pending = render_foreground_settings(&mut app, &mut preference);
        assert!(pending.contains("open remote links on this device [✓] saving…"));
        std::fs::remove_file(&config.path).expect("remove config file");
        std::fs::create_dir(&config.path).expect("replace config file with directory");

        assert_eq!(
            preference.settle_presented(),
            Some(
                crate::remote_link_preference::RemoteLinkPreferenceSettlement::Failed(
                    crate::remote_link_preference::RemoteLinkPreferenceFailureStage::Write,
                )
            )
        );
        assert!(preference.view().confirmed());
        assert!(preference.view().effective());
        assert!(!preference.view().saving());
        assert!(app.state.config_diagnostic.is_none());
    }

    #[test]
    fn escape_closes_settings_without_undoing_persisted_remote_link_value() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let config = TestConfig::new("remote-link-escape", "onboarding = false\n");
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 2;
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(false);

        let action = app
            .handle_settings_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
            .expect("remote-link action");
        preference.apply(action);
        let pending = render_foreground_settings(&mut app, &mut preference);
        assert!(pending.contains("open remote links on this device [ ] saving…"));

        assert_eq!(
            app.handle_settings_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty())),
            None
        );
        assert_ne!(app.state.mode, Mode::Settings);
        assert_eq!(
            preference.settle_presented(),
            Some(crate::remote_link_preference::RemoteLinkPreferenceSettlement::Confirmed)
        );
        assert!(preference.view().confirmed());
        assert!(std::fs::read_to_string(&config.path)
            .expect("read persisted config")
            .contains("open_remote_links_on_client = true"));
    }

    #[test]
    fn mouse_toggle_from_another_row_persists_and_reloads_after_pending_frame() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .expect("config env lock");
        let config = TestConfig::new("remote-link-mouse", "onboarding = false\n");
        let mut app = app_for_mouse_test();
        open_settings_at(&mut app.state, SettingsSection::Experiments);
        app.state.settings.list.selected = 0;
        let mut preference = crate::remote_link_preference::RemoteLinkPreference::new(false);
        let _ = render_foreground_settings(&mut app, &mut preference);
        let area = app.state.settings_content_rect();

        let action = app
            .handle_mouse_with_client_local_action(mouse(
                MouseEventKind::Down(crossterm::event::MouseButton::Left),
                area.x + 2,
                area.y + 5,
            ))
            .expect("remote-link action");
        preference.apply(action);
        let pending = render_foreground_settings(&mut app, &mut preference);
        assert!(pending.contains("open remote links on this device [ ] saving…"));

        assert_eq!(
            preference.settle_presented(),
            Some(crate::remote_link_preference::RemoteLinkPreferenceSettlement::Confirmed)
        );
        assert_eq!(app.state.settings.list.selected, 2);
        assert!(preference.view().confirmed());
        assert!(std::fs::read_to_string(&config.path)
            .expect("read persisted config")
            .contains("open_remote_links_on_client = true"));
    }

    #[test]
    fn integration_update_badge_only_tracks_outdated_recommendations() {
        let mut state = state_with_workspaces(&["test"]);
        state.integration_recommendations = vec![integration_recommendation(
            crate::integration::IntegrationStatusKind::NotInstalled,
            true,
        )];
        assert!(!state.integration_updates_available());

        state.integration_recommendations = vec![integration_recommendation(
            crate::integration::IntegrationStatusKind::NotInstalled,
            false,
        )];
        assert!(!state.integration_updates_available());

        state.integration_recommendations = vec![integration_recommendation(
            crate::integration::IntegrationStatusKind::Current,
            true,
        )];
        assert!(!state.integration_updates_available());

        state.integration_recommendations = vec![integration_recommendation(
            crate::integration::IntegrationStatusKind::Outdated,
            true,
        )];
        assert!(state.integration_updates_available());
    }

    #[test]
    fn settings_tab_hit_area_includes_integration_update_badge() {
        let mut state = state_with_workspaces(&["test"]);
        state.integration_recommendations = vec![integration_recommendation(
            crate::integration::IntegrationStatusKind::Outdated,
            true,
        )];
        open_settings(&mut state);

        let inner = state.settings_inner_rect();
        let tab_y = inner.y + 1;
        let integrations_idx = SettingsSection::ALL
            .iter()
            .position(|section| *section == SettingsSection::Integrations)
            .expect("integrations section should be present");
        let integrations_x = inner.x
            + SettingsSection::ALL[..integrations_idx]
                .iter()
                .map(|section| {
                    let badge_width = if state.settings_section_has_badge(*section) {
                        2
                    } else {
                        0
                    };
                    section.label().len() as u16 + 3 + badge_width
                })
                .sum::<u16>();
        let dotted_width = SettingsSection::Integrations.label().len() as u16 + 4;

        assert_eq!(
            state.settings_tab_at(integrations_x + dotted_width - 1, tab_y),
            Some(SettingsSection::Integrations)
        );
    }

    fn integration_recommendation(
        state: crate::integration::IntegrationStatusKind,
        available: bool,
    ) -> crate::integration::IntegrationRecommendation {
        crate::integration::IntegrationRecommendation {
            target: crate::api::schema::IntegrationTarget::Claude,
            label: "claude",
            command: "claude",
            available,
            path: std::path::PathBuf::from("/tmp/herdr-test-integration"),
            state,
        }
    }
}
