#[cfg(any(target_os = "linux", target_os = "macos"))]
mod broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod controller;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod inheritance;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod pair;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod protocol;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod transport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod worker;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const INHERITED_BROKER_FD_ENV: &str = "HERDR_FORWARDING_BROKER_FD";
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const FORWARDING_LAUNCH_STATUS_ENV: &str = "HERDR_FORWARDING_LAUNCH_STATUS";
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const FORWARDING_STATUS_AVAILABLE: &str = "available";
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const FORWARDING_STATUS_MANAGED_SSH_REQUIRED: &str = "managed_ssh_required";
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const FORWARDING_STATUS_UNAVAILABLE: &str = "forwarding_unavailable";

// Follow-up external-open routing consumes the capability and closed value types.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_imports)]
pub(crate) use broker::{ForwardCall, ForwardingClient};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use controller::NumericForwardingController;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use inheritance::{adopt_external_open_forwarding, PendingBroker};
// Follow-up URL-policy routing constructs these closed forwarding requests.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_imports)]
pub(crate) use protocol::{ForwardFailure, ForwardSpec, LoopbackAddress};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use worker::ControlAuthority;
