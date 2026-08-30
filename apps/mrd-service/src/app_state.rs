#![allow(dead_code)]

// mrd-service application state
//
// This module defines the shared state owned by mrd-service.
// After the hard-cut migration, this becomes the single source
// of truth for all session orchestration, transport runtime,
// and media control.

mod audit_log_registry;
mod capability_snapshot_registry;
mod capture_source_registry;
mod core;
mod device_identity_registry;
mod device_preference_registry;
mod device_registry;
mod display_mode_registry;
mod file_transfer_registry;
mod lan_identity;
mod media_pipeline_registry;
mod media_profile_registry;
#[cfg(any(windows, target_os = "macos"))]
mod media_render_queue_registry;
#[cfg(any(windows, target_os = "macos"))]
mod media_surface_renderer_registry;
mod media_task_registry;
mod peer_media_capability_registry;
#[cfg(any(windows, target_os = "macos"))]
mod platform_surface_renderer;
mod probe_registry;
mod session_registry;
mod shell_state;
pub(crate) use audit_log_registry::redact_audit_correlation_id;
pub use audit_log_registry::AuditLogRegistry;
pub use capability_snapshot_registry::CapabilitySnapshotRegistry;
pub use capture_source_registry::CaptureSourceRegistry;
pub use core::AppState;
pub use device_identity_registry::{
    AuthenticatedPeerTrust, DeviceIdentityRegistry, DeviceIdentityRegistryError,
};
pub use device_preference_registry::DevicePreferenceRegistry;
pub use device_registry::DeviceRegistry;
pub use display_mode_registry::DisplayModeRegistry;
pub use file_transfer_registry::FileTransferRegistry;
pub use lan_identity::default_lan_device_identity;
#[cfg(test)]
pub(crate) use lan_identity::lan_device_identity_from;
pub use media_pipeline_registry::{
    MediaPipelineRegistry, WanMediaRuntimeRole, WanMediaRuntimeSnapshot,
};
pub use media_profile_registry::MediaProfileRegistry;
#[cfg(any(windows, target_os = "macos"))]
pub use media_render_queue_registry::{
    MediaRenderFrame, MediaRenderQueueEnqueue, MediaRenderQueueRegistry,
};
#[cfg(any(windows, target_os = "macos"))]
pub use media_surface_renderer_registry::MediaSurfaceRendererRegistry;
pub use media_task_registry::MediaTaskRegistry;
pub use peer_media_capability_registry::SessionPeerMediaCapabilityRegistry;
#[cfg(any(windows, target_os = "macos"))]
pub(crate) use platform_surface_renderer::{
    create_platform_surface_renderer, surface_backend_matches_platform,
};
pub use probe_registry::{DecodedVideoFrameStats, MediaProbeFrameStats, ProbeRegistry};
pub use session_registry::SessionRegistry;
pub use shell_state::{ShellState, TrayPortRef};

const AUDIT_EVENT_LIMIT: usize = 1_000;

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
