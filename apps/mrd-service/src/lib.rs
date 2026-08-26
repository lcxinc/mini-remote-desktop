// mrd-service library
//
// This library is used by tests to access the service's internal modules.

pub mod agent_runtime;
pub mod app_state;
mod browser_preview_capture;
pub mod browser_webcodecs_preview;
#[cfg(feature = "browser-webrtc-preview")]
pub mod browser_webrtc_preview;
pub mod capabilities;
pub mod capture_source;
pub mod control_input;
pub mod display_mode;
pub mod handlers;
pub mod ipc_server;
pub mod lan_discovery;
pub mod media_adaptation;
pub mod relay;
pub mod resource_monitor;
pub mod security;
pub mod session_authorization;
pub mod shell;
pub mod signaling;
pub mod transports;
pub mod wake_on_lan;
pub mod web_bridge;
pub mod windows_service;

pub use app_state::{AppState, DeviceRegistry, SessionRegistry};
#[cfg(target_os = "macos")]
pub use shell::macos::{MacosAutostart, MacosTray, MacosUiLauncher};
pub use shell::{
    build_tray_model, default_autostart, default_tray, default_ui_launcher, service_tray,
    AutostartPort, AutostartPortRef, InMemoryUiLauncher, NoOpAutostart, NoOpTray, TrayAction,
    TrayMenuItem, TrayModel, TrayPort, UiLaunchRequest, UiLaunchResult, UiLauncherPort,
    UiLauncherPortRef,
};
#[cfg(windows)]
pub use shell::{windows::WindowsTray, WindowsAutostart};
