#[cfg(any(target_os = "linux", target_os = "macos"))]
mod broker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod controller;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod inheritance;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod openssh_harness;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod protocol;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod registry;
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) use broker::ForwardingBrokerTestHarness;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use controller::NumericForwardingController;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use inheritance::{adopt_external_open_forwarding, PendingBroker};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use worker::ControlAuthority;
