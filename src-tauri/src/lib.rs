pub mod agent_guard;
pub mod agent_permissions;
pub mod approval;
#[cfg(any(feature = "desktop", feature = "gtk-desktop"))]
pub(crate) mod approval_broker;
pub mod audit;
pub mod autostart;
pub mod brand;
pub mod catalog;
pub mod clients;
pub mod codemode;
pub mod codemode_worker;
#[cfg(feature = "desktop")]
mod desktop;
pub mod diagnostics_controller;
pub mod downstream;
pub mod gateway_publish;
pub mod gatewaylog;
pub mod hooks;
pub mod hostenv;
pub mod http_bridge;
pub mod inspect;
pub mod instructions;
pub mod integrity;
pub mod launcher;
#[cfg(all(target_os = "linux", feature = "gtk-desktop"))]
pub mod linux_native;
pub mod metrics;
pub mod oauth;
mod oauth_controller;
pub mod observability_controller;
pub mod pii;
pub mod playground;
pub mod rate_limits;
pub mod registry;
pub mod registry_controller;
pub mod remote;
pub mod router;
pub mod routine_advisor;
pub mod routine_candidates;
pub mod routine_catalog;
// Same gate as `approval_broker`, which it imports: without a desktop shell
// there is no broker to hold routine suggestions, and an ungated declaration
// broke `--no-default-features` for anyone building only the gateway.
#[cfg(any(feature = "desktop", feature = "gtk-desktop"))]
pub mod routine_controller;
pub mod routines;
pub mod rules;
pub mod savings;
pub mod searchtrace;
pub mod secrets;
pub mod semantic;
pub mod server_runtime;
pub mod shaping;
pub mod sharing_controller;
pub mod stacks;
pub mod teams;
pub mod teams_plan;
pub mod topology;
pub mod usage_report;
pub mod vendors;
#[cfg(target_os = "windows")]
pub mod windows_autostart;

pub(crate) use registry::redact_url_userinfo;

#[cfg(feature = "desktop")]
pub fn run() {
    desktop::run();
}
