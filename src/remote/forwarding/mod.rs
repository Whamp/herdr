#[cfg(any(target_os = "linux", target_os = "macos"))]
mod broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod inheritance;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod protocol;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod transport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod worker;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const INHERITED_BROKER_FD_ENV: &str = "HERDR_FORWARDING_BROKER_FD";

// Follow-up external-open routing consumes the capability and closed value types.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_imports)]
pub(crate) use broker::{ForwardCall, ForwardingClient};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use inheritance::{adopt_inherited_capability, PendingBroker};
// Follow-up URL-policy routing constructs these closed forwarding requests.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_imports)]
pub(crate) use protocol::{ForwardFailure, ForwardSpec, LoopbackAddress};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use worker::ControlAuthority;
