//! Build identity helpers.

pub const BASE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn channel() -> &'static str {
    non_empty(option_env!("HERDR_BUILD_CHANNEL")).unwrap_or("stable")
}

pub fn build_id() -> Option<&'static str> {
    non_empty(option_env!("HERDR_BUILD_ID"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn install_name() -> &'static str {
    resolved_install_name(option_env!("HERDR_BUILD_INSTALL_NAME"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolved_install_name(configured: Option<&str>) -> &str {
    let name = configured
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("herdr");
    assert!(
        valid_install_name(name),
        "HERDR_BUILD_INSTALL_NAME must contain only ASCII letters, digits, '-' or '_'"
    );
    name
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn valid_install_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub fn version() -> String {
    match channel() {
        "stable" => BASE_VERSION.to_string(),
        channel => match build_id() {
            Some(build_id) => format!("{BASE_VERSION}-{channel}.{build_id}"),
            None => format!("{BASE_VERSION}-{channel}"),
        },
    }
}

pub fn is_preview() -> bool {
    channel() == "preview"
}

fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn stable_version_defaults_to_cargo_version() {
        assert!(!super::version().is_empty());
    }

    #[test]
    fn missing_build_install_name_resolves_to_normal_herdr() {
        assert_eq!(super::resolved_install_name(None), "herdr");
        assert_eq!(super::resolved_install_name(Some("  ")), "herdr");
    }

    #[test]
    fn side_by_side_install_names_are_closed_and_shell_safe() {
        assert_eq!(
            super::resolved_install_name(Some(" herdr-port-forward ")),
            "herdr-port-forward"
        );
        assert!(super::valid_install_name("herdr-port-forward"));
        assert!(super::valid_install_name("herdr_test2"));
        assert!(!super::valid_install_name(""));
        assert!(!super::valid_install_name("herdr/test"));
        assert!(!super::valid_install_name("herdr test"));
        assert!(!super::valid_install_name("herdr;test"));
    }
}
