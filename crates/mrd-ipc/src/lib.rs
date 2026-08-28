//! Local IPC protocol between Rdesk and `mrd-service`.
//!
//! This crate owns the stable request/response DTOs for local communication
//! and deliberately stays independent of Tauri types so the UI remains a thin
//! shell over the service-owned runtime.

#![warn(missing_docs)]

/// Client-side helpers for connecting to the local service IPC endpoint.
pub mod client;
/// Binary render-proxy framing used between Rdesk and mrd-service.
pub mod render_proxy;
/// Transport abstractions used by IPC client/server implementations.
pub mod transport;

use mrd_proto::{DeviceId, SessionId};
use serde::{Deserialize, Serialize};

// The current wire DTOs predate the service-kernel split and intentionally keep
// their serde field names stable. New architecture docs track the module split;
// this scoped allow keeps the existing wire shape quiet while the DTOs are
// migrated into domain modules without a noisy mechanical field-doc commit.
#[allow(missing_docs)]
mod wire {
    use super::*;

    // === Shell / Lifecycle DTOs (Phase 2) ===
    // Defined first to avoid forward references

    /// Reason for opening the UI
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum OpenUiReason {
        /// User clicked tray menu
        TrayOpen,
        /// Incoming session request
        SessionIncoming,
        /// User action (e.g., from diagnostics)
        UserRequest,
        /// Opening diagnostics/debugging view
        Diagnostics,
    }

    /// Result of UI open operation
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum UiOpenStatus {
        /// Focused existing UI window
        FocusedExisting,
        /// Spawned new UI process
        SpawnedNew,
        /// UI unavailable (e.g., not configured)
        Unavailable,
    }

    /// Reason for UI detachment
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum UiDetachReason {
        /// User closed UI window normally
        UserClose,
        /// User explicitly quit UI
        UserQuit,
        /// UI crashed
        Crash,
        /// Connection lost
        ConnectionLost,
    }

    /// Service shutdown mode
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ShutdownMode {
        /// Graceful shutdown - finish active sessions if possible
        Graceful,
        /// Force shutdown - terminate immediately
        Force,
        /// Shutdown after sessions end
        AfterSessions,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteDevicePowerAction {
        Restart,
        Shutdown,
    }

    /// Shell/service status snapshot
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ShellStatusSnapshot {
        pub service_pid: u32,
        pub ui_pid: Option<u32>,
        pub tray_available: bool,
        pub autostart_enabled: Option<bool>,
        pub active_session_count: usize,
        pub last_error: Option<String>,
    }

    /// Requested or selected media stream profile.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct MediaProfile {
        pub width: u32,
        pub height: u32,
        pub fps: u32,
        pub bitrate_mbps: u32,
        pub codec: String,
        /// Codec profile name, for example `main` or `main10`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codec_profile: Option<String>,
        /// Video bit depth. HEVC Main uses 8, HEVC Main10 uses 10.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bit_depth: Option<u8>,
        /// Chroma subsampling label such as `4:2:0`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chroma_subsampling: Option<String>,
        /// Runtime pixel format associated with this profile, for example `nv12`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pixel_format: Option<String>,
        /// Whether HDR is expected for this media profile.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hdr_enabled: Option<bool>,
        /// Optional color transform requested before encode, for example `full` or `grayscale`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub color_mode: Option<String>,
        /// Optional media color pipeline, for example `sdr8` or `hdr_main10`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub color_pipeline: Option<String>,
    }

    impl Default for MediaProfile {
        fn default() -> Self {
            Self {
                width: 0,
                height: 0,
                fps: 0,
                bitrate_mbps: 0,
                codec: "h264".to_string(),
                codec_profile: None,
                bit_depth: None,
                chroma_subsampling: None,
                pixel_format: None,
                hdr_enabled: None,
                color_mode: None,
                color_pipeline: None,
            }
        }
    }

    /// Result of media profile negotiation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct MediaProfileNegotiation {
        pub requested: MediaProfile,
        pub selected: MediaProfile,
        pub status: String,
        pub reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selected_source_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selected_width: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selected_height: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub downgrade_reason: Option<String>,
    }

    /// A native render surface attached to a media pipeline.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AttachedRenderSurface {
        pub surface_id: String,
        pub backend: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub window_handle: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub render_proxy_endpoint: Option<String>,
    }

    /// Aggregated latency metrics for one media pipeline stage.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct MediaStageMetrics {
        pub stage: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p50_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p95_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p99_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sample_count: Option<u32>,
    }

    /// Synthetic transport impairment settings and counters for test runs.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct MediaTestImpairmentSnapshot {
        pub loss_pct: f64,
        pub base_delay_ms: u64,
        pub jitter_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mtu_bytes: Option<u32>,
        pub seed: u64,
        pub datagrams_sent: u64,
        pub datagrams_dropped: u64,
        pub datagrams_delayed: u64,
        pub datagrams_fragmented_by_mtu: u64,
    }

    /// Result of a test-only cross-device E2E fault injection request.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct CrossE2EFaultInjectionResult {
        pub session_id: SessionId,
        pub fault_type: String,
        pub status: String,
        pub message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub affected_surface_ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub impairment: Option<MediaTestImpairmentSnapshot>,
    }

    /// Sender-side LAN media transport counters.
    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
    pub struct MediaSenderTransportSnapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capture_source_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capture_source_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capture_memory_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dynamic_fps_tier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_fps: Option<u32>,
        #[serde(default)]
        pub frames_completed: u64,
        #[serde(default)]
        pub repeated_latest_frames: u64,
        #[serde(default)]
        pub capture_frame_samples: u64,
        #[serde(default)]
        pub capture_cpu_frames: u64,
        #[serde(default)]
        pub capture_macos_cv_pixel_buffer_frames: u64,
        #[serde(default)]
        pub capture_bgra32_frames: u64,
        #[serde(default)]
        pub capture_rgba32_frames: u64,
        #[serde(default)]
        pub capture_rgb24_frames: u64,
        #[serde(default)]
        pub capture_nv12_frames: u64,
        #[serde(default)]
        pub access_units_encoded: u64,
        #[serde(default)]
        pub keyframes_encoded: u64,
        #[serde(default)]
        pub encoded_access_unit_bytes: u64,
        pub datagram_fragments_attempted: u64,
        pub datagram_fragments_sent: u64,
        pub datagram_fragments_delayed: u64,
        pub datagram_fragments_dropped_by_impairment: u64,
        pub datagram_fragments_dropped_for_capacity: u64,
        pub datagram_fragments_dropped_for_budget: u64,
        pub datagram_frames_cut_short_for_capacity: u64,
        pub datagram_frames_cut_short_for_budget: u64,
        pub reliable_fragments_sent: u64,
        pub reliable_frames_sent: u64,
    }

    fn default_adaptation_mode() -> String {
        "keyframe_ladder".to_string()
    }

    fn default_downshift_cooldown_ms() -> u64 {
        2_000
    }

    fn default_upshift_hold_ms() -> u64 {
        5_000
    }

    /// Runtime configuration for LAN media bitrate/FPS/resolution adaptation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AdaptiveMediaConfig {
        pub enabled: bool,
        #[serde(default = "default_adaptation_mode")]
        pub mode: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ceiling_profile: Option<MediaProfile>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub floor_profile: Option<MediaProfile>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub ladder: Vec<MediaProfile>,
        #[serde(default)]
        pub dynamic_resolution_enabled: bool,
        #[serde(default = "default_downshift_cooldown_ms")]
        pub downshift_cooldown_ms: u64,
        #[serde(default = "default_upshift_hold_ms")]
        pub upshift_hold_ms: u64,
    }

    /// Current adaptive LAN media controller state.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct MediaAdaptationSnapshot {
        pub enabled: bool,
        pub state: String,
        pub ladder_index: u32,
        pub current_profile: MediaProfile,
        pub target_profile: MediaProfile,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_reason: Option<String>,
        pub last_change_ms: u64,
        pub observed_fps: f32,
        pub drop_ratio: f32,
        pub queue_depth: u32,
    }

    /// Authenticated cumulative metrics from an Agent-owned render worker.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AgentRenderBoundarySnapshot {
        pub resource_id: [u8; 16],
        pub decoder_backend: String,
        pub enqueued_units: u64,
        pub queue_replacements: u64,
        pub decoded_frames: u64,
        pub presented_frames: u64,
    }

    /// Runtime state for a session media pipeline.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct MediaPipelineSnapshot {
        pub session_id: SessionId,
        pub attached_surfaces: Vec<AttachedRenderSurface>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_encoder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_decoder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_renderer: Option<String>,
        /// Codec currently flowing through the receiver pipeline.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_codec: Option<String>,
        /// Active codec profile, for example `main`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_codec_profile: Option<String>,
        /// Active profile bit depth, for example `8` for NV12 or `10` for P010.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_bit_depth: Option<u8>,
        /// Active chroma subsampling label, for example `4:2:0`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_chroma_subsampling: Option<String>,
        /// Active decoded pixel format, for example `d3d11_shared_nv12`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_pixel_format: Option<String>,
        /// Whether HDR metadata is enabled for the active profile.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_hdr_enabled: Option<bool>,
        /// Active color transform mode, for example `full`, `grayscale`, or `monochrome`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_color_mode: Option<String>,
        /// Active color pipeline, for example `sdr8` or `hdr_main10`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_color_pipeline: Option<String>,
        /// Active negotiated width in pixels.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_width: Option<u32>,
        /// Active negotiated height in pixels.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_height: Option<u32>,
        /// Active negotiated frame rate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_fps: Option<u32>,
        /// Active negotiated bitrate in Mbps.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_bitrate_mbps: Option<u32>,
        /// Last reason the runtime fell back from a requested codec.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codec_fallback_reason: Option<String>,
        pub queue_depth: u32,
        /// Legacy aggregate of receiver-side render drops. Prefer the explicit
        /// render counters below for diagnostics.
        pub dropped_frames: u64,
        /// Frames actually presented by the native render pipeline.
        #[serde(default)]
        pub render_presented_frames: u64,
        #[serde(default)]
        pub render_queue_replacements: u64,
        /// Stale queued render frames dropped when the render worker catches up to latest.
        #[serde(default)]
        pub render_stale_frame_drops: u64,
        #[serde(default)]
        pub render_lock_drops: u64,
        /// Frames accepted by the renderer but skipped by non-blocking present.
        #[serde(default)]
        pub render_present_skips: u64,
        /// Receiver-side render pacing target after local display refresh caps.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub render_pacing_target_fps: Option<u32>,
        /// Receiver-side render queue policy, for example `latest` or `paced_fifo`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub render_queue_policy: Option<String>,
        /// Actual swap-chain frame latency configured on the attached renderer surface.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub swap_chain_max_frame_latency: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub swap_chain_allow_tearing: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub swap_chain_waitable_object: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub swap_chain_present_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_refresh_hz: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub render_thread_priority: Option<String>,
        #[serde(default)]
        pub render_waitable_timeouts: u64,
        /// Latest authenticated Session Agent render counters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent_render_boundary: Option<AgentRenderBoundarySnapshot>,
        /// Reliable media stream stalls that were bounded by resetting the
        /// receive stream and requesting a fresh keyframe.
        #[serde(default)]
        pub reliable_hol_recoveries: u64,
        pub stage_metrics: Vec<MediaStageMetrics>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub test_impairment: Option<MediaTestImpairmentSnapshot>,
        #[serde(default)]
        pub sender_transport: MediaSenderTransportSnapshot,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub adaptation: Option<MediaAdaptationSnapshot>,
    }

    /// A capture source that can be selected for a remote session.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CaptureSource {
        pub id: String,
        pub platform: String,
        pub source_kind: String,
        pub title: String,
        pub class_name: String,
        pub width: u32,
        pub height: u32,
        pub process_id: u32,
        pub app_name: Option<String>,
        pub bundle_identifier: Option<String>,
        pub preview_data_url: Option<String>,
        pub preview_width: Option<u32>,
        pub preview_height: Option<u32>,
    }

    /// Result of selecting a capture source on the remote peer.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CaptureSourceSelection {
        pub session_id: SessionId,
        pub source: CaptureSource,
        pub status: String,
        pub reason: Option<String>,
    }

    /// File-system entry kind for service-owned file browsing.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum FileEntryKind {
        File,
        Directory,
        Symlink,
        Other,
    }

    /// File-system entry returned by a service-owned directory listing.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct FileEntry {
        pub name: String,
        pub path: String,
        pub kind: FileEntryKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub size_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub modified_ms: Option<u64>,
        pub readonly: bool,
    }

    /// Directory listing returned by the local service kernel.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DirectoryList {
        pub path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parent_path: Option<String>,
        pub entries: Vec<FileEntry>,
    }

    /// Conflict policy for service-owned file transfer writes.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
    #[serde(rename_all = "snake_case")]
    pub enum FileTransferConflictPolicy {
        Reject,
        #[default]
        Rename,
        Replace,
    }

    fn default_file_transfer_provider_kind() -> String {
        "mrd-local".to_string()
    }

    /// One source entry in a service-owned file transfer request.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct FileTransferEntry {
        pub source_path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file_name: Option<String>,
        pub kind: FileEntryKind,
    }

    /// Request to copy files through the local service runtime.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct FileTransferStartRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_device_id: Option<DeviceId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_device_id: Option<DeviceId>,
        pub entries: Vec<FileTransferEntry>,
        pub target_path: String,
        #[serde(default)]
        pub conflict_policy: FileTransferConflictPolicy,
        /// Reserved for future LAN/QUIC routing. The MVP executes `local`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport_hint: Option<String>,
        /// Reserved provider preference for future external file engines, such as R-File.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider_hint: Option<String>,
    }

    /// Reserved external handoff metadata for a file transfer provider.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct FileTransferProviderHandoffHint {
        /// External application expected to own the feature path.
        pub external_app: String,
        /// External bridge service expected to receive the handoff.
        pub bridge_service: String,
        /// Optional control-plane endpoint hint for local discovery.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub control_endpoint: Option<String>,
        /// Optional data-plane endpoint hint for local discovery.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub data_endpoint: Option<String>,
        /// External capability ids MRD reserves without executing directly.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub capabilities: Vec<String>,
    }

    /// One file transfer provider known by the local service.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct FileTransferProviderDescriptor {
        /// Stable provider id used by `FileTransferStartRequest.provider_hint`.
        pub provider_kind: String,
        /// Human-readable provider label.
        pub display_name: String,
        /// Runtime state of this provider.
        pub status: CapabilityStatus,
        /// Stable capability ids exposed by this provider.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub capabilities: Vec<String>,
        /// Short explanation when the provider is not available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// External handoff details for reserved providers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handoff_hint: Option<FileTransferProviderHandoffHint>,
    }

    /// Service-owned file transfer lifecycle status.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum FileTransferStatus {
        Queued,
        Running,
        Completed,
        Failed,
        Cancelled,
    }

    /// Snapshot of one service-owned file transfer task.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct FileTransferTaskSnapshot {
        pub transfer_id: String,
        pub status: FileTransferStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_device_id: Option<DeviceId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_device_id: Option<DeviceId>,
        pub transport_kind: String,
        #[serde(default = "default_file_transfer_provider_kind")]
        pub provider_kind: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub provider_capabilities: Vec<String>,
        pub total_entries: usize,
        pub copied_entries: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total_bytes: Option<u64>,
        pub copied_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub entries: Vec<FileEntry>,
    }

    /// A display output mode that can be applied to a remote capture display.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DisplayMode {
        /// Stable mode identifier, usually platform/source/resolution/refresh.
        pub id: String,
        /// Optional capture source id this mode belongs to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_id: Option<String>,
        /// Pixel width.
        pub width: u32,
        /// Pixel height.
        pub height: u32,
        /// Refresh rate rounded to Hz.
        pub refresh_hz: u32,
        /// Color depth when the platform exposes it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bit_depth: Option<u32>,
        /// Whether this mode is currently active.
        pub is_current: bool,
    }

    /// Result of a display mode change or restore operation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DisplayModeChange {
        /// Session associated with the temporary display mode request.
        pub session_id: SessionId,
        /// Requested mode, absent for restore-only responses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requested: Option<DisplayMode>,
        /// Mode observed before the change, used for restore.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub previous: Option<DisplayMode>,
        /// Active mode after the operation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active: Option<DisplayMode>,
        /// Machine-readable status such as changed, restored, unsupported, or failed.
        pub status: String,
        /// Human-readable reason when status is not a clean change.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// Whether the original mode should be restored when the session ends.
        pub restore_required: bool,
    }

    /// Platform identifier used by structured capability snapshots.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CapabilityPlatform {
        /// Microsoft Windows desktop.
        Windows,
        /// Apple macOS desktop.
        Macos,
        /// Linux desktop.
        Linux,
        /// Android client/host.
        Android,
        /// iOS client.
        Ios,
        /// Browser/web runtime.
        Web,
        /// Unknown or unsupported platform.
        Unknown,
    }

    /// Product capability domain.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CapabilityDomain {
        /// Screen/window capture.
        Capture,
        /// Selectable capture sources.
        CaptureSource,
        /// Video encoding.
        Encode,
        /// Video decoding.
        Decode,
        /// Frame rendering.
        Render,
        /// Frame memory/interoperability path.
        Memory,
        /// Media or control transport.
        Transport,
        /// Keyboard/mouse/control-plane input.
        Control,
        /// Audio capture/playback/media path.
        Audio,
        /// Local service lifecycle features.
        Service,
        /// Pairing, consent, and encryption features.
        Security,
    }

    /// Runtime support state for one capability.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CapabilityStatus {
        /// Product code exists but runtime validation has not proven usability.
        Supported,
        /// Runtime probe found required APIs, drivers, or permissions.
        Available,
        /// Lightweight validation succeeded.
        Usable,
        /// Usable fallback path below preferred parity.
        Degraded,
        /// Blocked by an OS permission.
        PermissionMissing,
        /// Driver/runtime library is missing.
        DriverMissing,
        /// Required hardware is absent.
        HardwareMissing,
        /// Matrix concept exists but no runner is wired.
        Unimplemented,
        /// Unsupported on this platform or product mode.
        Unsupported,
        /// Not yet probed or not recognized.
        Unknown,
    }

    /// Structured capability item shared by service, UI, and LAN discovery.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CapabilityItem {
        /// Stable capability id, for example `capture.dxgi`.
        pub id: String,
        /// Product domain for grouping and evaluation.
        pub domain: CapabilityDomain,
        /// Human-readable short label.
        pub label: String,
        /// Current support state.
        pub status: CapabilityStatus,
        /// Platform that produced the capability.
        pub platform: CapabilityPlatform,
        /// Short reason when the status is not plainly available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// Optional diagnostic detail.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
        /// Capability ids required by this item.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub requires: Vec<String>,
        /// Capability ids that conflict with this item.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub conflicts_with: Vec<String>,
        /// Capability ids this item depends on.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub depends_on: Vec<String>,
        /// Lower-parity fallback capability ids.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub fallback_ids: Vec<String>,
        /// Last probe timestamp in milliseconds since Unix epoch.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_probe_time_ms: Option<u64>,
    }

    /// Compatibility status for a cross-capability constraint.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum CapabilityConstraintStatus {
        /// Combination is allowed.
        Allow,
        /// Combination must not run.
        Block,
        /// Combination runs below preferred parity.
        Degrade,
        /// Combination needs a copy/conversion step.
        RequiresCopy,
        /// Combination requires runtime probe validation.
        RequiresProbe,
    }

    /// Rule describing whether multiple capabilities can be combined.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CapabilityConstraint {
        /// Stable constraint id.
        pub id: String,
        /// Capability ids or prefixes this rule applies to.
        pub applies_to: Vec<String>,
        /// Constraint result.
        pub status: CapabilityConstraintStatus,
        /// Deterministic explanation for UI and automation.
        pub reason: String,
        /// Fallback capability ids when applicable.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub fallback_ids: Vec<String>,
    }

    /// Named performance profile used by static and runtime validation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct CapabilityProfile {
        /// Stable profile id.
        pub id: String,
        /// Target frame width.
        pub width: u32,
        /// Target frame height.
        pub height: u32,
        /// Target frame rate.
        pub fps: u32,
        /// Target bitrate in Mbps.
        pub bitrate_mbps: u32,
        /// Requested codec, for example `h264`.
        pub codec: String,
        /// Codec profile name, for example `main` or `main10`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub codec_profile: Option<String>,
        /// Video bit depth. HEVC Main uses 8, HEVC Main10 uses 10.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bit_depth: Option<u8>,
        /// Chroma subsampling label such as `4:2:0`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chroma_subsampling: Option<String>,
        /// Runtime pixel format associated with this profile, for example `nv12`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pixel_format: Option<String>,
        /// Whether HDR is expected for this media profile.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hdr_enabled: Option<bool>,
        /// Optional color transform requested before encode, for example `full` or `grayscale`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub color_mode: Option<String>,
        /// Optional media color pipeline, for example `sdr8` or `hdr_main10`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub color_pipeline: Option<String>,
        /// Optional latency budget in milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latency_budget_ms: Option<u32>,
        /// Optional minimum stable FPS ratio.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub min_stable_fps_ratio: Option<f32>,
        /// Optional maximum frame drop ratio.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_drop_ratio: Option<f32>,
        /// Capabilities required for static support.
        pub required_capabilities: Vec<String>,
    }

    /// Structured local or peer capability snapshot.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct CapabilitySnapshot {
        /// Schema version for forward-compatible readers.
        pub schema_version: u32,
        /// Platform that produced the snapshot.
        pub platform: CapabilityPlatform,
        /// Service or application version that produced the snapshot.
        pub service_version: String,
        /// Capability items.
        pub capabilities: Vec<CapabilityItem>,
        /// Cross-capability constraints.
        pub constraints: Vec<CapabilityConstraint>,
        /// Built-in performance profiles known by the producer.
        pub profiles: Vec<CapabilityProfile>,
        /// Snapshot timestamp in milliseconds since Unix epoch.
        pub updated_at_ms: u64,
    }

    /// Readiness state for a product scenario/profile evaluation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ScenarioEvaluationStatus {
        /// All required capabilities are available for the requested scenario.
        Ready,
        /// Scenario can run, but not at preferred parity.
        Degraded,
        /// Scenario must not run until the blocker is addressed.
        Blocked,
        /// Scenario is intentionally excluded, usually for peer/version mismatch.
        Skipped,
    }

    /// One deterministic reason emitted by scenario/profile evaluation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ScenarioEvaluationReason {
        /// Stable reason code, for example `capability.missing`.
        pub code: String,
        /// Severity label such as `info`, `warning`, or `error`.
        pub severity: String,
        /// Human-readable explanation for UI and reports.
        pub message: String,
        /// Related capability id when the reason is tied to a capability.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capability_id: Option<String>,
    }

    /// Result of evaluating whether a scenario/profile should run.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ScenarioEvaluation {
        /// Stable scenario/profile id such as `lan.2k144`.
        pub scenario_id: String,
        /// Overall readiness result.
        pub status: ScenarioEvaluationStatus,
        /// Profile selected after capability/profile evaluation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub selected_profile: Option<MediaProfile>,
        /// Transport selected by the policy layer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport_kind: Option<String>,
        /// Ordered explanation list.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub reasons: Vec<ScenarioEvaluationReason>,
        /// Required capability ids for the evaluated scenario.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub required_capabilities: Vec<String>,
        /// Required capability ids not available on the evaluated side.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub missing_capabilities: Vec<String>,
        /// Optional fallback profile when the preferred profile is degraded/blocked.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback_profile: Option<MediaProfile>,
    }

    /// Runtime transport policy requested by the UI shell or automation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TransportPolicyConfig {
        /// Policy mode, usually `auto`, `lan`, or `wan`.
        pub mode: String,
        /// Optional preferred transport, for example `quic` or `webrtc`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preferred_transport: Option<String>,
        /// Whether LAN QUIC can be selected.
        pub allow_lan_quic: bool,
        /// Whether WebRTC can be selected.
        pub allow_webrtc: bool,
        /// Whether relay/TURN paths can be selected.
        pub allow_relay: bool,
    }

    /// Service-owned transport policy decision snapshot.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TransportPolicySnapshot {
        /// Optional session id associated with the decision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<SessionId>,
        /// Policy mode applied for this decision.
        pub mode: String,
        /// Transport selected by policy.
        pub selected_transport: String,
        /// Candidate transports considered by policy.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub candidate_transports: Vec<String>,
        /// Whether relay/TURN is required by the selected route.
        pub relay_required: bool,
        /// Human-readable reason for the selected route.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// Fallback reason when preferred transport was not selected.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fallback_reason: Option<String>,
    }

    /// Control channel reliability class.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ControlChannelReliability {
        /// Reliable ordered lane for non-droppable control events.
        ReliableOrdered,
        /// Low-latency lane for coalescible/droppable realtime events.
        UnreliableRealtime,
    }

    /// Runtime counters for one control channel lane.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ControlChannelLaneSnapshot {
        /// Stable lane name, for example `ctrl_rel` or `ctrl_rt`.
        pub name: String,
        /// Reliability semantics for this lane.
        pub reliability: ControlChannelReliability,
        /// Whether messages are ordered.
        pub ordered: bool,
        /// Maximum retransmits, absent for fully reliable lanes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_retransmits: Option<u16>,
        /// Messages currently queued.
        pub queued_messages: u64,
        /// Messages dropped by lane policy.
        pub dropped_messages: u64,
        /// Messages coalesced by lane policy.
        pub coalesced_messages: u64,
        /// Messages accepted by the service for this lane.
        #[serde(default)]
        pub accepted_messages: u64,
        /// Messages injected successfully on the controlled side.
        #[serde(default)]
        pub injected_messages: u64,
        /// Messages that failed injection or validation.
        #[serde(default)]
        pub failed_messages: u64,
        /// Last lane-specific error.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_error: Option<String>,
    }

    /// Runtime control channel state for a session.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ControlChannelSnapshot {
        /// Session id associated with these lanes.
        pub session_id: SessionId,
        /// Reliable control lane.
        pub reliable: ControlChannelLaneSnapshot,
        /// Realtime control lane.
        pub realtime: ControlChannelLaneSnapshot,
    }

    /// Mouse button carried by a service-owned control input request.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ControlInputButton {
        /// Primary mouse button.
        Left,
        /// Secondary mouse button.
        Right,
        /// Middle mouse button.
        Middle,
        /// First extended mouse button.
        X1,
        /// Second extended mouse button.
        X2,
    }

    /// Keyboard key carried by a service-owned control input request.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum ControlInputKey {
        /// Windows virtual-key code.
        VirtualKey {
            /// Numeric virtual-key code.
            code: u16,
        },
    }

    /// Normalized control input event sent to mrd-service.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum ControlInputEvent {
        /// Absolute mouse position in remote frame coordinates.
        MouseMove {
            /// X coordinate.
            x: i32,
            /// Y coordinate.
            y: i32,
        },
        /// Mouse button transition.
        MouseButton {
            /// Button id.
            button: ControlInputButton,
            /// Whether the button is pressed.
            pressed: bool,
        },
        /// Mouse wheel delta.
        MouseWheel {
            /// Wheel delta.
            delta: i32,
        },
        /// Horizontal mouse wheel delta.
        MouseHorizontalWheel {
            /// Horizontal wheel delta.
            delta: i32,
        },
        /// Keyboard key transition.
        Key {
            /// Key id.
            key: ControlInputKey,
            /// Whether the key is pressed.
            pressed: bool,
        },
        /// Release all pressed keys and mouse buttons tracked by the service.
        ReleaseAll,
    }

    /// Control lane selected for an accepted input event.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ControlInputLane {
        /// Reliable ordered control lane.
        Reliable,
        /// Realtime low-latency control lane.
        Realtime,
        /// Local cleanup path, for example release-all.
        Cleanup,
    }

    /// One paired device identity known by the local service.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct PairedDeviceIdentity {
        /// Paired peer device id.
        pub device_id: DeviceId,
        /// Peer display name at pairing time.
        pub display_name: String,
        /// Pinned peer certificate or key fingerprint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate_fingerprint: Option<String>,
        /// Trust status such as `pending`, `paired`, or `revoked`.
        pub trust_status: String,
        /// Last observation timestamp in milliseconds since Unix epoch.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_seen_ms: Option<u64>,
    }

    /// Local service device identity and pairing state.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DeviceIdentitySnapshot {
        /// Registered local device id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub local_device_id: Option<DeviceId>,
        /// Registered local display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display_name: Option<String>,
        /// Local certificate or key fingerprint when provisioned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate_fingerprint: Option<String>,
        /// Whether user consent is required before starting remote control.
        pub consent_required: bool,
        /// Known paired devices.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub paired_devices: Vec<PairedDeviceIdentity>,
    }

    /// Summary statistics for a telemetry metric series.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct TelemetryMetricSummary {
        /// Metric name.
        pub name: String,
        /// Display unit.
        pub unit: String,
        /// Number of samples available.
        pub sample_count: u64,
        /// Median value when available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p50: Option<f64>,
        /// 95th percentile value when available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub p95: Option<f64>,
    }

    /// File artifact associated with a telemetry run.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TelemetryArtifactRef {
        /// Artifact display name.
        pub name: String,
        /// Local or exported artifact path.
        pub path: String,
        /// Artifact kind such as `json`, `markdown`, or `log`.
        pub kind: String,
    }

    /// Compact service-facing telemetry bundle for run/session diagnostics.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct TelemetryBundle {
        /// Test or session run id.
        pub run_id: String,
        /// Optional session id linked to the run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<SessionId>,
        /// Metric summaries available for the run.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub metrics: Vec<TelemetryMetricSummary>,
        /// Number of structured events available.
        pub event_count: u64,
        /// Number of log entries available.
        pub log_count: u64,
        /// Linked report/log artifacts.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub artifacts: Vec<TelemetryArtifactRef>,
    }

    /// Endpoint that owns one resource sample in a two-sided remote session.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ExperienceEndpointSide {
        /// Controlled machine performing capture and encode.
        Target,
        /// Controlling machine performing decode and present.
        Controller,
    }

    /// One monotonic, endpoint-scoped resource observation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ExperienceResourceSample {
        pub side: ExperienceEndpointSide,
        pub monotonic_ms: f64,
        pub cpu_usage_percent: f64,
        pub rss_mb: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gpu_usage_percent: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vram_used_mb: Option<f64>,
    }

    impl ExperienceResourceSample {
        /// Whether every supplied metric is finite and in its physical domain.
        pub fn is_finite(&self) -> bool {
            self.monotonic_ms.is_finite()
                && self.monotonic_ms >= 0.0
                && self.cpu_usage_percent.is_finite()
                && (0.0..=100.0).contains(&self.cpu_usage_percent)
                && self.rss_mb.is_finite()
                && self.rss_mb >= 0.0
                && self
                    .gpu_usage_percent
                    .is_none_or(|value| value.is_finite() && (0.0..=100.0).contains(&value))
                && self
                    .vram_used_mb
                    .is_none_or(|value| value.is_finite() && value >= 0.0)
        }
    }

    /// Exact one-second visible-frame window.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ExperienceFpsWindow {
        pub start_monotonic_ms: f64,
        pub duration_ms: f64,
        pub frame_count: u32,
        pub fps: f64,
    }

    /// W3C-compatible freeze aggregation based on visible-frame gaps.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ExperienceFreezeMetrics {
        pub freeze_count: u64,
        pub total_freeze_duration_ms: f64,
    }

    /// Controller-monotonic input marker result.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ExperienceInputProbeResult {
        pub probe_id: [u8; 16],
        pub issued_monotonic_ms: f64,
        pub presented_monotonic_ms: f64,
        pub input_to_photon_ms: f64,
        /// Always absent: cross-machine wall-clock values are not accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_wall_clock_ms: Option<u64>,
    }

    /// One media adaptation completed by the first successful present.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ExperienceAdaptationTransition {
        pub transition_id: [u8; 16],
        pub started_monotonic_ms: f64,
        pub presented_monotonic_ms: f64,
        pub transition_time_ms: f64,
        pub present_stall_ms: f64,
    }

    /// Canonical end-to-end experience metrics derived only from monotonic events.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ExperienceProbeSnapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub first_visible_frame_ms: Option<f64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub fps_windows: Vec<ExperienceFpsWindow>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub frame_intervals_ms: Vec<f64>,
        pub stall_count: u64,
        pub total_stall_duration_ms: f64,
        pub freeze_metrics: ExperienceFreezeMetrics,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub input_probes: Vec<ExperienceInputProbeResult>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub resource_samples: Vec<ExperienceResourceSample>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub adaptation_transitions: Vec<ExperienceAdaptationTransition>,
    }

    /// Query used to retrieve service-owned audit events.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct AuditLogQuery {
        /// Optional session id filter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<SessionId>,
        /// Optional action filter, for example `session.start`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub action: Option<String>,
        /// Optional maximum number of newest matching events to return.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<u32>,
    }

    /// Service-owned audit event for security, control, and operations review.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AuditEvent {
        /// Monotonic event id within one service process.
        pub id: u64,
        /// Event time in milliseconds since Unix epoch.
        pub timestamp_ms: u64,
        /// Stable action id, for example `session.start`.
        pub action: String,
        /// Machine-readable outcome, usually `success` or `error`.
        pub outcome: String,
        /// Optional related session id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session_id: Option<SessionId>,
        /// Optional local actor device id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actor_device_id: Option<DeviceId>,
        /// Optional peer device id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer_device_id: Option<DeviceId>,
        /// Optional transport kind, for example `quic`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub transport_kind: Option<String>,
        /// Optional reason or error detail.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// Deterministic key/value details for UI and export.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub details: Vec<(String, String)>,
    }

    /// Canonical decimal representation of an unsigned 64-bit integer.
    ///
    /// The wire value is always a JSON string so JavaScript clients cannot lose
    /// precision. Deserialization rejects signs, leading zeroes, exponent form,
    /// and values outside the `u64` range.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DecimalU64(u64);

    impl DecimalU64 {
        /// Construct a canonical decimal value.
        pub const fn new(value: u64) -> Self {
            Self(value)
        }

        /// Return the represented integer.
        pub const fn get(self) -> u64 {
            self.0
        }
    }

    impl From<u64> for DecimalU64 {
        fn from(value: u64) -> Self {
            Self::new(value)
        }
    }

    impl std::fmt::Display for DecimalU64 {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(formatter)
        }
    }

    impl Serialize for DecimalU64 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self.0.to_string())
        }
    }

    impl<'de> Deserialize<'de> for DecimalU64 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            let raw = String::deserialize(deserializer)?;
            let value = raw.parse::<u64>().map_err(D::Error::custom)?;
            if raw != value.to_string() {
                return Err(D::Error::custom("expected a canonical decimal u64 string"));
            }
            Ok(Self(value))
        }
    }

    /// Permission scope exposed on the stable remote-session wire contract.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum RemotePermissionScope {
        #[serde(rename = "screen.view")]
        ScreenView,
        #[serde(rename = "input.pointer")]
        InputPointer,
        #[serde(rename = "input.keyboard")]
        InputKeyboard,
        #[serde(rename = "clipboard.read")]
        ClipboardRead,
        #[serde(rename = "clipboard.write")]
        ClipboardWrite,
        #[serde(rename = "file.read")]
        FileRead,
        #[serde(rename = "file.write")]
        FileWrite,
        #[serde(rename = "audio.listen")]
        AudioListen,
        #[serde(rename = "audio.talk")]
        AudioTalk,
        #[serde(rename = "display.switch")]
        DisplaySwitch,
        #[serde(rename = "display.multi_view")]
        DisplayMultiView,
        #[serde(rename = "power.restart")]
        PowerRestart,
        #[serde(rename = "power.shutdown")]
        PowerShutdown,
        #[serde(rename = "terminal.open")]
        TerminalOpen,
        #[serde(rename = "privacy.block_local_input")]
        PrivacyBlockLocalInput,
        #[serde(rename = "privacy.blank_screen")]
        PrivacyBlankScreen,
        #[serde(rename = "secure_desktop.view")]
        SecureDesktopView,
        #[serde(rename = "secure_desktop.control")]
        SecureDesktopControl,
    }

    impl From<mrd_session::PermissionScope> for RemotePermissionScope {
        fn from(scope: mrd_session::PermissionScope) -> Self {
            use mrd_session::PermissionScope as Domain;

            match scope {
                Domain::ScreenView => Self::ScreenView,
                Domain::InputPointer => Self::InputPointer,
                Domain::InputKeyboard => Self::InputKeyboard,
                Domain::ClipboardRead => Self::ClipboardRead,
                Domain::ClipboardWrite => Self::ClipboardWrite,
                Domain::FileRead => Self::FileRead,
                Domain::FileWrite => Self::FileWrite,
                Domain::AudioListen => Self::AudioListen,
                Domain::AudioTalk => Self::AudioTalk,
                Domain::DisplaySwitch => Self::DisplaySwitch,
                Domain::DisplayMultiView => Self::DisplayMultiView,
                Domain::PowerRestart => Self::PowerRestart,
                Domain::PowerShutdown => Self::PowerShutdown,
                Domain::TerminalOpen => Self::TerminalOpen,
                Domain::PrivacyBlockLocalInput => Self::PrivacyBlockLocalInput,
                Domain::PrivacyBlankScreen => Self::PrivacyBlankScreen,
                Domain::SecureDesktopView => Self::SecureDesktopView,
                Domain::SecureDesktopControl => Self::SecureDesktopControl,
            }
        }
    }

    impl From<RemotePermissionScope> for mrd_session::PermissionScope {
        fn from(scope: RemotePermissionScope) -> Self {
            match scope {
                RemotePermissionScope::ScreenView => Self::ScreenView,
                RemotePermissionScope::InputPointer => Self::InputPointer,
                RemotePermissionScope::InputKeyboard => Self::InputKeyboard,
                RemotePermissionScope::ClipboardRead => Self::ClipboardRead,
                RemotePermissionScope::ClipboardWrite => Self::ClipboardWrite,
                RemotePermissionScope::FileRead => Self::FileRead,
                RemotePermissionScope::FileWrite => Self::FileWrite,
                RemotePermissionScope::AudioListen => Self::AudioListen,
                RemotePermissionScope::AudioTalk => Self::AudioTalk,
                RemotePermissionScope::DisplaySwitch => Self::DisplaySwitch,
                RemotePermissionScope::DisplayMultiView => Self::DisplayMultiView,
                RemotePermissionScope::PowerRestart => Self::PowerRestart,
                RemotePermissionScope::PowerShutdown => Self::PowerShutdown,
                RemotePermissionScope::TerminalOpen => Self::TerminalOpen,
                RemotePermissionScope::PrivacyBlockLocalInput => Self::PrivacyBlockLocalInput,
                RemotePermissionScope::PrivacyBlankScreen => Self::PrivacyBlankScreen,
                RemotePermissionScope::SecureDesktopView => Self::SecureDesktopView,
                RemotePermissionScope::SecureDesktopControl => Self::SecureDesktopControl,
            }
        }
    }

    /// Stable machine-readable remote-session reason codes.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteReasonCode {
        IdentityMismatch,
        CertificateBindingMismatch,
        TrustRequired,
        ConsentDenied,
        CredentialInvalid,
        CredentialLocked,
        AuthorizationTimeout,
        GrantExpired,
        GrantRevoked,
        PolicyChanged,
        ReplayDetected,
        ScopeDenied,
        ProtocolDowngradeBlocked,
        LanUnreachable,
        IceDirectFailed,
        TurnAllocationFailed,
        RouteLost,
        RouteMigrationTimeout,
        EncoderUnavailable,
        DecoderUnavailable,
        CaptureSourceLost,
        ProfileDowngraded,
        CongestionDownshift,
        RenderBudgetExceeded,
    }

    /// Typed failure safe for local UI presentation and remediation.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RemoteFailure {
        pub code: RemoteReasonCode,
        pub message: String,
        pub suggested_action: Option<String>,
    }

    /// Requested authorization path for a remote session.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteAccessMode {
        Attended,
        Unattended,
    }

    /// Local role in the authoritative remote-session aggregate.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteSessionRole {
        Controller,
        Agent,
    }

    /// Explicit authorization projection for UI and IPC consumers.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteAuthorizationState {
        Discovered,
        Authenticating,
        Authorizing,
        AwaitingLocalConsent,
        VerifyingUnattendedCredential,
        Granted,
        Denied,
        Expired,
        Revoked,
        LockedOut,
        PolicyChanged,
    }

    impl From<&mrd_session::AuthorizationState> for RemoteAuthorizationState {
        fn from(state: &mrd_session::AuthorizationState) -> Self {
            match state {
                mrd_session::AuthorizationState::Pending => Self::Authorizing,
                mrd_session::AuthorizationState::Granted { .. } => Self::Granted,
                mrd_session::AuthorizationState::Denied { .. } => Self::Denied,
                mrd_session::AuthorizationState::Revoked { .. } => Self::Revoked,
            }
        }
    }

    /// Transport route selected or attempted by a remote session.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub enum RemoteRouteKind {
        #[serde(rename = "lan_quic")]
        LanQuic,
        #[serde(rename = "webrtc_direct")]
        WebRtcDirect,
        #[serde(rename = "webrtc_relay")]
        WebRtcRelay,
    }

    impl From<mrd_session::RouteKind> for RemoteRouteKind {
        fn from(kind: mrd_session::RouteKind) -> Self {
            match kind {
                mrd_session::RouteKind::LanQuic => Self::LanQuic,
                mrd_session::RouteKind::WebRtcDirect => Self::WebRtcDirect,
                mrd_session::RouteKind::WebRtcRelay => Self::WebRtcRelay,
            }
        }
    }

    /// Caller preference for selecting the initial remote-session route.
    #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteRoutePreference {
        #[default]
        Auto,
        Lan,
        WanRelay,
    }

    /// Explicit route lifecycle projection.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteRouteState {
        Idle,
        Gathering,
        Connecting,
        Connected,
        Migrating,
        Reconnecting,
        Failed,
        Closed,
    }

    impl From<&mrd_session::RouteState> for RemoteRouteState {
        fn from(state: &mrd_session::RouteState) -> Self {
            match state {
                mrd_session::RouteState::Idle => Self::Idle,
                mrd_session::RouteState::Establishing(_) => Self::Connecting,
                mrd_session::RouteState::Active(_) => Self::Connected,
                mrd_session::RouteState::Failed { .. } => Self::Failed,
            }
        }
    }

    /// Explicit media lifecycle projection.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteMediaState {
        Idle,
        Starting,
        Streaming,
        Degraded,
        Paused,
        Stopped,
        Failed,
    }

    impl From<&mrd_session::MediaState> for RemoteMediaState {
        fn from(state: &mrd_session::MediaState) -> Self {
            match state {
                mrd_session::MediaState::Idle => Self::Idle,
                mrd_session::MediaState::Starting => Self::Starting,
                mrd_session::MediaState::Streaming => Self::Streaming,
                mrd_session::MediaState::Stopped => Self::Stopped,
                mrd_session::MediaState::Failed { .. } => Self::Failed,
            }
        }
    }

    /// Truthful UI-facing state derived from authorization, route, and media state.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemotePresentationState {
        IncomingApprovalRequired,
        Authenticating,
        Connecting,
        ConnectedWithoutMedia,
        Streaming,
        Degraded,
        Reconnecting,
        Denied,
        Failed,
        Closed,
    }

    /// Request body for starting an authorized remote session.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RemoteSessionRequest {
        pub session_id: SessionId,
        pub target_device_id: DeviceId,
        pub access_mode: RemoteAccessMode,
        #[serde(default)]
        pub route_preference: RemoteRoutePreference,
        pub requested_scopes: Vec<RemotePermissionScope>,
        pub requested_profile: Option<MediaProfile>,
    }

    /// Authoritative UI-safe remote-session snapshot.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RemoteSessionSnapshot {
        pub session_id: SessionId,
        pub role: RemoteSessionRole,
        pub peer_device_id: DeviceId,
        pub peer_key_id: String,
        pub access_mode: RemoteAccessMode,
        pub authorization_state: RemoteAuthorizationState,
        pub route_state: RemoteRouteState,
        pub route_kind: Option<RemoteRouteKind>,
        pub media_state: RemoteMediaState,
        pub presentation_state: RemotePresentationState,
        pub requested_scopes: Vec<RemotePermissionScope>,
        pub granted_scopes: Vec<RemotePermissionScope>,
        /// Decimal u64 string to preserve precision in JavaScript clients.
        pub policy_revision: DecimalU64,
        pub failure: Option<RemoteFailure>,
        pub created_at_ms: u64,
        pub updated_at_ms: u64,
        /// Exact service-owned pending-authorization or active-grant deadline.
        pub authorization_expires_at_ms: Option<u64>,
    }

    /// Local user's response to an exact incoming session request.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ConsentResponse {
        pub session_id: SessionId,
        pub decision: ConsentDecision,
        pub approved_scopes: Vec<RemotePermissionScope>,
        /// Decimal u64 string used for optimistic policy concurrency.
        pub expected_policy_revision: DecimalU64,
    }

    /// Local attended-consent decision.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ConsentDecision {
        Approve,
        Deny,
    }

    /// Non-secret unattended-access policy supplied by the local user.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct UnattendedAccessPolicy {
        pub trusted_devices_only: bool,
        pub allowed_peer_key_ids: Vec<String>,
        pub permission_ceiling: Vec<RemotePermissionScope>,
        pub expires_at_ms: Option<u64>,
    }

    /// Non-secret unattended-access state. No credential or verifier is exposed.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct UnattendedAccessSnapshot {
        pub enabled: bool,
        /// Decimal u64 string.
        pub policy_revision: DecimalU64,
        /// Decimal u64 metadata for the current generated access material epoch.
        pub access_epoch: DecimalU64,
        pub policy: UnattendedAccessPolicy,
        pub locked_until_ms: Option<u64>,
        pub updated_at_ms: u64,
    }

    /// Durable trust state projected to the UI.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum TrustedDeviceState {
        Pending,
        Trusted,
        Suspended,
        Revoked,
        RotationPending,
    }

    /// UI-safe trusted-device record keyed only by its public-key identifier.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TrustedDeviceSnapshot {
        pub peer_key_id: String,
        pub display_name: Option<String>,
        /// Decimal u64 string.
        pub key_epoch: DecimalU64,
        pub state: TrustedDeviceState,
        pub permission_ceiling: Vec<RemotePermissionScope>,
        /// Decimal u64 string.
        pub trust_revision: DecimalU64,
        pub approved_at_ms: Option<u64>,
        pub updated_at_ms: u64,
    }

    /// Approval for an already authenticated pending peer key.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TrustedDeviceApproval {
        pub peer_key_id: String,
        /// Decimal u64 string.
        pub key_epoch: DecimalU64,
        pub permission_ceiling: Vec<RemotePermissionScope>,
    }

    /// Approval metadata for an already verified key-rotation transition.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TrustedDeviceRotation {
        pub peer_key_id: String,
        pub new_peer_key_id: String,
        /// Decimal u64 string.
        pub new_key_epoch: DecimalU64,
        /// Decimal u64 string.
        pub expected_trust_revision: DecimalU64,
    }

    /// Revision-checked request to replace the exact desired session scopes.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionPermissionChange {
        pub session_id: SessionId,
        pub requested_scopes: Vec<RemotePermissionScope>,
        /// Decimal u64 string.
        pub expected_policy_revision: DecimalU64,
    }

    /// Typed session event sent through the bounded subscription contract.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum RemoteSessionEvent {
        ConsentRequested {
            requested_scopes: Vec<RemotePermissionScope>,
        },
        ConsentResolved {
            decision: ConsentDecision,
            approved_scopes: Vec<RemotePermissionScope>,
        },
        AuthorizationChanged {
            state: RemoteAuthorizationState,
            failure: Option<RemoteFailure>,
        },
        PermissionsChanged {
            granted_scopes: Vec<RemotePermissionScope>,
            policy_revision: DecimalU64,
        },
        TrustChanged {
            peer_key_id: String,
            state: TrustedDeviceState,
            trust_revision: DecimalU64,
        },
        RouteChanged {
            state: RemoteRouteState,
            route: Option<RemoteRouteKind>,
            failure: Option<RemoteFailure>,
        },
        MediaChanged {
            state: RemoteMediaState,
            failure: Option<RemoteFailure>,
        },
        SessionClosed {
            failure: Option<RemoteFailure>,
        },
    }

    /// Monotonic event envelope. Sequence is a decimal u64 string for JS safety.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RemoteSessionEventEnvelope {
        pub sequence: DecimalU64,
        pub timestamp_ms: u64,
        pub session_id: SessionId,
        pub event: RemoteSessionEvent,
    }

    /// Cursor and bounds for one session-event long-poll batch.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionEventSubscriptionQuery {
        pub session_id: Option<SessionId>,
        /// Exclusive service-global cursor. Only events with greater sequence values are returned.
        pub after_sequence: Option<DecimalU64>,
        pub limit: u32,
        pub wait_timeout_ms: u32,
    }

    /// Whether a cursor was accepted or the caller must refresh authoritative state.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RemoteCursorState {
        /// The supplied cursor was accepted and this page is contiguous.
        Current,
        /// The supplied cursor predates retained history; refresh snapshots before continuing.
        ResetRequired,
    }

    /// One bounded event batch.
    ///
    /// `next_after_sequence` is the greatest sequence already delivered, not the
    /// next unseen sequence. Passing it back as `after_sequence` therefore cannot
    /// skip an event. When `cursor_state` is `reset_required`, `events` must be
    /// empty and the caller must refresh authoritative session snapshots.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionEventSubscription {
        pub events: Vec<RemoteSessionEventEnvelope>,
        /// Bounded authoritative pending consent projections included on an
        /// initial subscription or stale-cursor reset so a restarted UI cannot
        /// lose an approval request after event-history truncation.
        #[serde(default)]
        pub pending_sessions: Vec<RemoteSessionSnapshot>,
        pub next_after_sequence: Option<DecimalU64>,
        pub cursor_state: RemoteCursorState,
        pub has_more: bool,
        pub poll_after_ms: u32,
    }

    /// Outcome for one route candidate without exposing raw relay credentials or endpoints.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum RouteCandidateState {
        NotTried,
        Connecting,
        Connected,
        Failed,
    }

    /// Evidence recorded for one policy-allowed route candidate.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RouteCandidateEvidence {
        pub route: RemoteRouteKind,
        pub state: RouteCandidateState,
        pub started_at_ms: Option<u64>,
        pub completed_at_ms: Option<u64>,
        pub round_trip_ms: Option<u32>,
        pub failure: Option<RemoteFailure>,
    }

    /// Route selection and connection evidence for one authorized session.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RouteEvidence {
        pub session_id: SessionId,
        pub route_state: RemoteRouteState,
        pub selected_route: Option<RemoteRouteKind>,
        /// Decimal u64 string.
        pub policy_revision: DecimalU64,
        pub transport_fingerprint_sha256: Option<String>,
        pub candidates: Vec<RouteCandidateEvidence>,
        pub observed_at_ms: u64,
    }

    /// Cursor query for durable, redacted audit events.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AuditEventsQueryV2 {
        /// Exclusive service-global cursor.
        pub after_sequence: Option<DecimalU64>,
        pub limit: u32,
        pub session_id: Option<SessionId>,
        pub action: Option<String>,
        pub outcome: Option<String>,
        pub peer_device_id: Option<DeviceId>,
    }

    /// Allowlisted, content-free metadata for a durable audit event.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct AuditEventMetadataV2 {
        pub authorization_state: Option<RemoteAuthorizationState>,
        pub access_mode: Option<RemoteAccessMode>,
        pub route_state: Option<RemoteRouteState>,
        pub media_state: Option<RemoteMediaState>,
        pub requested_scopes: Vec<RemotePermissionScope>,
        pub granted_scopes: Vec<RemotePermissionScope>,
        pub policy_revision: Option<DecimalU64>,
        pub trust_revision: Option<DecimalU64>,
    }

    /// Durable audit record projection. Integrity HMACs and storage identifiers remain private.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AuditEventV2 {
        /// Service-global sequence encoded as a canonical decimal string.
        pub sequence: DecimalU64,
        pub timestamp_ms: u64,
        pub action: String,
        pub outcome: String,
        pub session_id: Option<SessionId>,
        pub actor_device_id: Option<DeviceId>,
        pub peer_device_id: Option<DeviceId>,
        pub peer_key_id: Option<String>,
        pub transport_kind: Option<RemoteRouteKind>,
        pub reason_code: Option<RemoteReasonCode>,
        pub metadata: AuditEventMetadataV2,
    }

    /// Cursor page of durable audit records with service-side chain verification status.
    ///
    /// `next_after_sequence` is the greatest delivered sequence. A reset-required
    /// page must not contain events and must not be treated as verified history.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AuditEventPageV2 {
        pub events: Vec<AuditEventV2>,
        pub next_after_sequence: Option<DecimalU64>,
        pub cursor_state: RemoteCursorState,
        pub has_more: bool,
        pub chain_verified: bool,
    }

    // === Core IPC Types ===

    /// IPC request from Rdesk to mrd-service
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    pub enum IpcRequest {
        /// Register local device with the service
        RegisterDevice {
            device_id: DeviceId,
            device_name: String,
        },
        /// List available devices
        ListDevices,
        /// List service-owned device preferences.
        GetDevicePreferences,
        /// Update service-owned preference flags for one device.
        UpdateDevicePreference {
            /// Target device id.
            device_id: DeviceId,
            /// Partial preference update.
            update: DevicePreferenceUpdate,
        },
        /// Get the current LAN peer discovery snapshot.
        LanDiscoverySnapshot,
        /// Send an immediate LAN discovery probe and return the current snapshot.
        RefreshLanDiscovery,
        /// List files/directories from the local service host.
        ListDirectory {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            path: Option<String>,
        },
        /// Start a local-service-owned file transfer task.
        StartFileTransfer {
            /// File transfer request.
            request: FileTransferStartRequest,
        },
        /// List service-owned file transfer task snapshots.
        ListFileTransfers,
        /// List available and reserved file transfer providers.
        ListFileTransferProviders,
        /// Cancel a service-owned file transfer task when it is still active.
        CancelFileTransfer {
            /// Transfer id returned by `StartFileTransfer`.
            transfer_id: String,
        },
        /// Send a Wake-on-LAN magic packet for a known device MAC address.
        WakeOnLan {
            /// Peer device id associated with the wake request.
            device_id: DeviceId,
            /// Target MAC address, for example `AA:BB:CC:DD:EE:FF`.
            mac_address: String,
            /// Optional UDP broadcast endpoint, defaults to `255.255.255.255:9`.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            broadcast_addr: Option<String>,
        },
        RequestRemoteDevicePowerAction {
            device_id: DeviceId,
            action: RemoteDevicePowerAction,
        },
        /// List all active sessions
        ListSessions,
        /// Get the authoritative authorization/route/media snapshot for a remote session.
        GetRemoteSession { session_id: SessionId },
        /// Request a new authorized remote session without starting media early.
        RequestRemoteSession { request: RemoteSessionRequest },
        /// Record local attended consent for exact scopes and policy revision.
        RespondToConsent { response: ConsentResponse },
        /// Enable unattended access under a non-secret local policy.
        EnableUnattendedAccess { policy: UnattendedAccessPolicy },
        /// Disable unattended access with optimistic policy concurrency.
        DisableUnattendedAccess {
            expected_policy_revision: DecimalU64,
        },
        /// Rotate generated unattended access material without exposing it over IPC.
        RotateUnattendedAccess {
            expected_policy_revision: DecimalU64,
        },
        /// List public-key-pinned trusted device projections.
        ListTrustedDevices { include_revoked: bool },
        /// Approve an already authenticated pending peer key.
        ApproveTrustedDevice { approval: TrustedDeviceApproval },
        /// Suspend a trusted peer key.
        SuspendTrustedDevice {
            peer_key_id: String,
            expected_trust_revision: DecimalU64,
        },
        /// Permanently revoke a trusted peer key.
        RevokeTrustedDevice {
            peer_key_id: String,
            expected_trust_revision: DecimalU64,
        },
        /// Approve an already verified key rotation.
        RotateTrustedDevice { rotation: TrustedDeviceRotation },
        /// Replace desired session permissions under policy-revision concurrency.
        ChangeSessionPermissions { change: SessionPermissionChange },
        /// Fetch one bounded long-poll batch of typed session events.
        SubscribeSessionEvents {
            query: SessionEventSubscriptionQuery,
        },
        /// Get evidence for actual route attempts and the selected route.
        GetRouteEvidence { session_id: SessionId },
        /// Query durable redacted audit events by monotonic cursor.
        GetAuditEventsV2 { query: AuditEventsQueryV2 },
        /// Start a new session as controller
        StartSession {
            session_id: SessionId,
            target_device_id: DeviceId,
            transport_kind: String, // "quic" or "webrtc"
        },
        /// Start a LAN P2P session as controller and ask the discovered peer to accept it.
        StartLanRemoteSession {
            session_id: SessionId,
            target_device_id: DeviceId,
            transport_kind: String, // "quic" or "webrtc"
            #[serde(default, skip_serializing_if = "Option::is_none")]
            requested_profile: Option<MediaProfile>,
        },
        /// Request a runtime media profile switch for an existing session.
        UpdateMediaProfile {
            session_id: SessionId,
            requested_profile: MediaProfile,
        },
        /// Configure LAN media bitrate/FPS/resolution adaptation for an existing session.
        ConfigureMediaAdaptation {
            session_id: SessionId,
            config: AdaptiveMediaConfig,
        },
        /// List selectable capture sources on the local service host.
        ListLocalCaptureSources {
            include_previews: bool,
            limit: Option<u32>,
        },
        /// List selectable capture sources from the remote peer for a session.
        ListRemoteCaptureSources {
            session_id: SessionId,
            include_previews: bool,
            limit: Option<u32>,
        },
        /// Select one remote capture source for a session.
        SelectRemoteCaptureSource {
            session_id: SessionId,
            source_id: String,
        },
        /// List display modes from the remote peer for a session.
        ListRemoteDisplayModes { session_id: SessionId },
        /// Temporarily set a remote display mode.
        SetRemoteDisplayMode {
            session_id: SessionId,
            mode: DisplayMode,
            restore_after_session: bool,
        },
        /// Restore the display mode saved for a session.
        RestoreRemoteDisplayMode { session_id: SessionId },
        /// Attach a native render surface to a session media pipeline.
        AttachRenderSurface {
            session_id: SessionId,
            surface_id: String,
            backend: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            window_handle: Option<i64>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            render_proxy_endpoint: Option<String>,
        },
        /// Detach a native render surface from a session media pipeline.
        DetachRenderSurface {
            session_id: SessionId,
            surface_id: String,
        },
        /// Accept an incoming session as agent
        AcceptSession {
            session_id: SessionId,
            source_device_id: DeviceId,
        },
        /// Start sending media (controller role)
        StartSender { session_id: SessionId },
        /// Start receiving media (agent role)
        StartReceiver { session_id: SessionId },
        /// Stop a session
        StopSession { session_id: SessionId },
        /// Mark a session as failed and retain its failure reason.
        FailSession {
            session_id: SessionId,
            reason: String,
        },
        /// Recover a failed or closed session back to its role-appropriate startup state.
        RecoverSession { session_id: SessionId },
        /// Get current session runtime snapshot
        SessionRuntimeSnapshot { session_id: SessionId },
        /// Get aggregated runtime snapshot
        RuntimeSnapshot,
        /// Query service-owned audit events.
        AuditLog { query: AuditLogQuery },
        /// Get structured local capability snapshot.
        CapabilitySnapshot,
        /// Evaluate a scenario/profile before starting a session.
        EvaluateScenarioProfile {
            /// Stable scenario/profile id.
            scenario_id: String,
            /// Optional peer device id to include in evaluation.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            peer_device_id: Option<DeviceId>,
            /// Optional concrete requested profile override.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            requested_profile: Option<MediaProfile>,
        },
        /// Get structured capability snapshot for a discovered peer.
        GetPeerCapabilitySnapshot {
            /// Peer device id.
            peer_device_id: DeviceId,
        },
        /// Set transport policy for a session.
        SetTransportPolicy {
            /// Target session id.
            session_id: SessionId,
            /// Requested policy.
            policy: TransportPolicyConfig,
        },
        /// Get control channel lane state for a session.
        GetControlChannelSnapshot {
            /// Target session id.
            session_id: SessionId,
        },
        /// Send a keyboard or mouse event to the service-owned control path.
        SendControlInput {
            /// Target session id.
            session_id: SessionId,
            /// Normalized input event.
            event: ControlInputEvent,
        },
        /// Inject a test-only cross-device E2E fault into an active session.
        CrossE2EInjectFault {
            /// Target session id.
            session_id: SessionId,
            /// Fault type, for example `network.pause_peer` or `renderer.detach_surface`.
            fault_type: String,
            /// Optional fault duration.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            duration_ms: Option<u64>,
        },
        /// Start or refresh local pairing intent for a device.
        PairDevice {
            /// Peer device id.
            device_id: DeviceId,
            /// Optional presented peer fingerprint.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            certificate_fingerprint: Option<String>,
        },
        /// Approve a pending pairing.
        ApprovePairing {
            /// Peer device id.
            device_id: DeviceId,
        },
        /// Revoke a paired device.
        RevokeDevice {
            /// Peer device id.
            device_id: DeviceId,
        },
        /// Get local device identity and pairing snapshot.
        GetDeviceIdentitySnapshot,
        /// Get compact telemetry bundle for a run/session.
        GetTelemetryBundle {
            /// Test or session run id.
            run_id: String,
            /// Optional linked session id.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            session_id: Option<SessionId>,
        },
        /// Get probe snapshot data
        ProbeSnapshot { session_id: SessionId },
        /// Get media pipeline snapshot data.
        MediaPipelineSnapshot { session_id: SessionId },
        /// Stream probe events
        StreamProbeEvents,
        /// Health check for service
        ServiceHealth,

        // === Shell / Lifecycle Commands (Phase 2) ===
        /// Request to open/focus the UI
        OpenUi { reason: OpenUiReason },
        /// Request to focus an existing UI window
        FocusUi,
        /// Notify service that UI has attached
        UiAttached {
            pid: u32,
            executable_path: Option<String>,
        },
        /// Notify service that UI is detaching
        UiDetached { pid: u32, reason: UiDetachReason },
        /// Get current shell/service status
        GetShellStatus,
        /// Set autostart enabled state
        SetAutostart { enabled: bool },
        /// Get autostart status
        GetAutostartStatus,
        /// Request service shutdown
        ShutdownService { mode: ShutdownMode },
    }

    impl IpcRequest {
        /// Return whether this request belongs to the secure remote-session contract.
        ///
        /// Shell passthroughs use this exact allowlist to avoid exposing unrelated
        /// filesystem, lifecycle, control, or test-only service operations.
        pub fn is_secure_remote(&self) -> bool {
            matches!(
                self,
                Self::GetRemoteSession { .. }
                    | Self::RequestRemoteSession { .. }
                    | Self::RespondToConsent { .. }
                    | Self::EnableUnattendedAccess { .. }
                    | Self::DisableUnattendedAccess { .. }
                    | Self::RotateUnattendedAccess { .. }
                    | Self::ListTrustedDevices { .. }
                    | Self::ApproveTrustedDevice { .. }
                    | Self::SuspendTrustedDevice { .. }
                    | Self::RevokeTrustedDevice { .. }
                    | Self::RotateTrustedDevice { .. }
                    | Self::ChangeSessionPermissions { .. }
                    | Self::SubscribeSessionEvents { .. }
                    | Self::GetRouteEvidence { .. }
                    | Self::GetAuditEventsV2 { .. }
            )
        }
    }

    /// IPC response from mrd-service to Rdesk
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    #[allow(clippy::large_enum_variant)]
    #[serde(tag = "type")]
    pub enum IpcResponse {
        /// Device registration successful
        DeviceRegistered { device_id: DeviceId },
        /// List of available devices
        DeviceList { devices: Vec<DeviceInfo> },
        /// Service-owned preference flags for known devices.
        DevicePreferences {
            /// Current preference records.
            preferences: Vec<DevicePreference>,
        },
        /// Updated service-owned preference for one device.
        DevicePreferenceUpdated {
            /// Preference after applying the update.
            preference: DevicePreference,
        },
        /// LAN peer discovery snapshot.
        LanDiscoverySnapshot {
            /// Current discovery state.
            snapshot: LanDiscoverySnapshot,
        },
        /// Wake-on-LAN magic packet was sent.
        WakeOnLanSent {
            /// Peer device id associated with the wake request.
            device_id: DeviceId,
            /// Normalized target MAC address.
            mac_address: String,
            /// UDP endpoint used for the magic packet.
            broadcast_addr: String,
            /// Number of bytes in the magic packet payload.
            packet_bytes: usize,
        },
        RemoteDevicePowerActionAccepted {
            device_id: DeviceId,
            action: RemoteDevicePowerAction,
        },
        /// List of active sessions
        SessionList { sessions: Vec<SessionInfo> },
        /// Authoritative secure remote-session snapshot.
        RemoteSession { session: RemoteSessionSnapshot },
        /// Newly requested secure remote-session snapshot.
        RemoteSessionRequested { session: RemoteSessionSnapshot },
        /// Snapshot after recording attended consent.
        ConsentRecorded { session: RemoteSessionSnapshot },
        /// Current unattended-access policy and non-secret metadata.
        UnattendedAccessUpdated { access: UnattendedAccessSnapshot },
        /// Trusted device projections.
        TrustedDeviceList { devices: Vec<TrustedDeviceSnapshot> },
        /// Trusted device projection after a state transition.
        TrustedDeviceUpdated { device: TrustedDeviceSnapshot },
        /// Session snapshot after a permission transition.
        SessionPermissionsChanged { session: RemoteSessionSnapshot },
        /// One bounded event subscription batch and continuation cursor.
        SessionEventsSubscribed {
            subscription: SessionEventSubscription,
        },
        /// One typed session event for transports that support unsolicited delivery.
        SessionEvent { event: RemoteSessionEventEnvelope },
        /// Actual route-attempt evidence.
        RouteEvidence { evidence: RouteEvidence },
        /// Durable redacted audit event page.
        AuditEventsV2 { page: AuditEventPageV2 },
        /// Typed secure-remote rejection that preserves stable reason codes.
        RemoteAccessError {
            session_id: Option<SessionId>,
            peer_key_id: Option<String>,
            failure: RemoteFailure,
        },
        /// Session started successfully
        SessionStarted { session_id: SessionId },
        /// Session accepted successfully
        SessionAccepted { session_id: SessionId },
        /// Sender started
        SenderStarted { session_id: SessionId },
        /// Receiver started
        ReceiverStarted { session_id: SessionId },
        /// Session stopped
        SessionStopped { session_id: SessionId },
        /// Session failed
        SessionFailed { session_id: SessionId },
        /// Session recovered
        SessionRecovered { session_id: SessionId },
        /// Media profile switch completed.
        MediaProfileUpdated {
            session_id: SessionId,
            negotiation: MediaProfileNegotiation,
        },
        /// LAN media adaptation controller configured.
        MediaAdaptationConfigured {
            session_id: SessionId,
            snapshot: MediaAdaptationSnapshot,
        },
        /// Local selectable capture sources returned by mrd-service.
        LocalCaptureSourceList { sources: Vec<CaptureSource> },
        /// Selectable capture sources returned by the remote peer.
        CaptureSourceList {
            session_id: SessionId,
            sources: Vec<CaptureSource>,
        },
        /// Capture source selection result returned by the remote peer.
        CaptureSourceSelected {
            session_id: SessionId,
            selection: CaptureSourceSelection,
        },
        /// Display modes returned by the remote peer.
        DisplayModeList {
            session_id: SessionId,
            modes: Vec<DisplayMode>,
        },
        /// Directory listing returned by the local service host.
        DirectoryList { listing: DirectoryList },
        /// File transfer task accepted or completed by the local service host.
        FileTransferStarted {
            /// Current transfer snapshot.
            transfer: FileTransferTaskSnapshot,
        },
        /// File transfer task snapshots known by the local service host.
        FileTransferList {
            /// Ordered transfer snapshots.
            transfers: Vec<FileTransferTaskSnapshot>,
        },
        /// File transfer providers known by the local service host.
        FileTransferProviderList {
            /// Ordered provider descriptors.
            providers: Vec<FileTransferProviderDescriptor>,
        },
        /// File transfer cancellation result.
        FileTransferCancelled {
            /// Current transfer snapshot.
            transfer: FileTransferTaskSnapshot,
        },
        /// Display mode change or restore result.
        DisplayModeChanged {
            session_id: SessionId,
            change: DisplayModeChange,
        },
        /// Native render surface attached.
        RenderSurfaceAttached {
            session_id: SessionId,
            surface_id: String,
        },
        /// Native render surface detached.
        RenderSurfaceDetached {
            session_id: SessionId,
            surface_id: String,
        },
        /// Session runtime snapshot
        SessionSnapshot { snapshot: SessionRuntimeSnapshot },
        /// Aggregated runtime snapshot
        RuntimeSnapshot { snapshot: RuntimeSnapshot },
        /// Service-owned audit events.
        AuditLog { events: Vec<AuditEvent> },
        /// Structured local capability snapshot.
        CapabilitySnapshot {
            /// Current local capability snapshot.
            snapshot: CapabilitySnapshot,
        },
        /// Scenario/profile preflight evaluation result.
        ScenarioProfileEvaluated {
            /// Evaluation result.
            evaluation: ScenarioEvaluation,
        },
        /// Structured peer capability snapshot.
        PeerCapabilitySnapshot {
            /// Peer device id.
            peer_device_id: DeviceId,
            /// Snapshot when the peer is known and can be mapped.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            snapshot: Option<CapabilitySnapshot>,
        },
        /// Transport policy update result.
        TransportPolicyUpdated {
            /// Service-owned policy decision snapshot.
            snapshot: TransportPolicySnapshot,
        },
        /// Control channel lane snapshot.
        ControlChannelSnapshot {
            /// Reliable/realtime lane snapshot.
            snapshot: ControlChannelSnapshot,
        },
        /// Control input event accepted by the service.
        ControlInputAccepted {
            /// Target session id.
            session_id: SessionId,
            /// Lane selected by the service.
            lane: ControlInputLane,
            /// Number of input events applied or queued.
            event_count: u32,
        },
        /// Cross-device E2E fault injection result.
        CrossE2EFaultInjected {
            /// Structured fault injection result.
            result: CrossE2EFaultInjectionResult,
        },
        /// Pairing operation result.
        PairingUpdated {
            /// Device identity snapshot after the operation.
            snapshot: DeviceIdentitySnapshot,
        },
        /// Local device identity snapshot.
        DeviceIdentitySnapshot {
            /// Current identity state.
            snapshot: DeviceIdentitySnapshot,
        },
        /// Compact telemetry bundle.
        TelemetryBundle {
            /// Requested telemetry bundle.
            bundle: TelemetryBundle,
        },
        /// Probe snapshot data
        ProbeSnapshot { snapshot: ProbeSnapshot },
        /// Media pipeline snapshot data.
        MediaPipelineSnapshot { snapshot: MediaPipelineSnapshot },
        /// Probe event data
        ProbeEvent {
            event: Vec<u8>, // Serialized probe event
        },
        /// Service health status
        ServiceHealth { status: ServiceStatus },

        // === Shell / Lifecycle Responses (Phase 2) ===
        /// Result of UI open request
        UiOpenResult {
            status: UiOpenStatus,
            pid: Option<u32>,
        },
        /// Shell/service status snapshot
        ShellStatus { status: ShellStatusSnapshot },
        /// Autostart status
        AutostartStatus { enabled: bool, supported: bool },
        /// Generic acknowledgment
        Ack,
        /// Error response
        Error { code: String, message: String },
    }

    /// Device information DTO
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DeviceInfo {
        pub device_id: DeviceId,
        pub device_name: String,
        pub is_online: bool,
    }

    /// Service-owned preference flags for one device.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct DevicePreference {
        /// Device id the preference applies to.
        pub device_id: DeviceId,
        /// Whether the device should be surfaced as a favorite.
        pub favorite: bool,
        /// Whether user actions should be blocked for this device.
        pub disabled: bool,
        /// Whether the device should be hidden from normal device lists.
        pub removed: bool,
    }

    /// Partial service-owned device preference update.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct DevicePreferenceUpdate {
        /// New favorite flag when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub favorite: Option<bool>,
        /// New disabled flag when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disabled: Option<bool>,
        /// New removed flag when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub removed: Option<bool>,
    }

    /// Discovered LAN peer information.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct LanPeerInfo {
        /// Remote device id.
        pub device_id: DeviceId,
        /// Remote display name.
        pub device_name: String,
        /// Device role/type advertised by the peer.
        pub device_type: String,
        /// Peer IP address string.
        pub ip: String,
        /// UDP port used by the LAN discovery control plane.
        pub discovery_port: u16,
        /// Direct LAN control endpoint as `ip:port`.
        pub p2p_control_addr: String,
        /// Supported media/session transports, for example `webrtc` or `quic`.
        pub transports: Vec<String>,
        /// Protocol version advertised by the peer.
        pub protocol_version: u32,
        /// Service build identifier advertised by the peer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub service_build_id: Option<String>,
        /// LAN media protocol version advertised by the peer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub media_protocol_version: Option<u32>,
        /// Structured media capabilities advertised by the peer.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub media_capabilities: Vec<String>,
        /// Optional MAC address advertised by the peer for Wake-on-LAN flows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mac_address: Option<String>,
        /// Milliseconds since this peer was last observed.
        pub age_ms: u64,
        /// Whether this peer was discovered through the local P2P LAN path.
        pub p2p_available: bool,
    }

    /// LAN discovery state exposed over IPC.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct LanDiscoverySnapshot {
        /// Whether LAN discovery is enabled in this service process.
        pub enabled: bool,
        /// Whether the UDP discovery task is currently running.
        pub running: bool,
        /// Local UDP discovery port.
        pub discovery_port: u16,
        /// Local discovery instance id.
        pub instance_id: String,
        /// Last successful announce/probe timestamp in milliseconds since Unix epoch.
        pub last_probe_ms: Option<u64>,
        /// Currently known LAN peers.
        pub peers: Vec<LanPeerInfo>,
    }

    /// Session information DTO (for list responses)
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionInfo {
        pub session_id: SessionId,
        pub role: String,  // "controller" or "agent"
        pub state: String, // "created", "listening", "connecting", "connected", "streaming", "failed", "closed"
        pub transport_kind: String,
        pub last_error: Option<String>,
        /// Whether the media sender is currently marked active.
        pub sender_active: bool,
        /// Whether the media receiver is currently marked active.
        pub receiver_active: bool,
        /// Peer device associated with this session, from the controller or agent perspective.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer_device_id: Option<DeviceId>,
    }

    /// Session runtime snapshot DTO (stable IPC contract)
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionRuntimeSnapshot {
        pub session_id: SessionId,
        pub role: String,           // "controller" or "agent"
        pub state: String, // "created", "listening", "connecting", "connected", "streaming", "failed", "closed"
        pub transport_kind: String, // "quic" or "webrtc"
        pub local_bootstrap: Option<SessionBootstrap>,
        pub remote_bootstrap: Option<SessionBootstrap>,
        pub last_error: Option<String>,
        /// Media pipeline state
        pub sender_active: bool,
        pub receiver_active: bool,
        /// Peer device associated with this session, from the controller or agent perspective.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub peer_device_id: Option<DeviceId>,
    }

    /// Session bootstrap metadata
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionBootstrap {
        pub listen_addr: Option<String>,
        pub server_name: Option<String>,
        pub cert_der: Option<String>, // Base64-encoded DER certificate
    }

    /// Aggregated runtime snapshot DTO
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct RuntimeSnapshot {
        pub sessions: Vec<SessionRuntimeSnapshot>,
        pub device_id: Option<DeviceId>,
        pub is_registered: bool,
        /// Service-owned authenticated WAN signaling health.
        #[serde(default)]
        pub signaling: SignalingRuntimeSnapshot,
    }

    /// Secret-free authenticated signaling health projection.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SignalingRuntimeSnapshot {
        /// `disabled`, `connecting`, `authenticated`, `backoff`, or `stopped`.
        pub state: String,
        /// Consecutive reconnect attempt count.
        pub reconnect_attempt: u32,
        /// Scheduled retry time in Unix milliseconds.
        pub next_retry_at_ms: Option<u64>,
        /// Most recent successful authentication time in Unix milliseconds.
        pub last_connected_at_ms: Option<u64>,
        /// Most recent accepted signaling message time in Unix milliseconds.
        pub last_message_at_ms: Option<u64>,
        /// Sanitized connection error, never a token or signaling body.
        pub last_error: Option<String>,
    }

    impl Default for SignalingRuntimeSnapshot {
        fn default() -> Self {
            Self {
                state: "disabled".to_string(),
                reconnect_attempt: 0,
                next_retry_at_ms: None,
                last_connected_at_ms: None,
                last_message_at_ms: None,
                last_error: None,
            }
        }
    }

    /// Probe snapshot DTO
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ProbeSnapshot {
        pub session_id: SessionId,
        pub frames_received: u64,
        pub frames_decoded: u64,
        pub frames_dropped: u64,
        #[serde(default)]
        pub sequence_gap_drops: u64,
        #[serde(default)]
        pub decode_error_drops: u64,
        #[serde(default)]
        pub transient_drops: u64,
        pub current_fps: Option<f32>,
        pub bitrate_mbps: Option<f32>,
        pub media_probe_valid: bool,
        pub media_probe_format: Option<String>,
        pub media_probe_width: Option<u32>,
        pub media_probe_height: Option<u32>,
        pub media_probe_target_fps: Option<u32>,
        pub media_probe_target_bitrate_mbps: Option<u32>,
        pub media_probe_payload_bytes: Option<u32>,
        pub last_media_sequence: Option<u64>,
        pub last_media_timestamp_us: Option<u64>,
        pub last_media_payload_hash: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latest_frame_data_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latest_frame_width: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latest_frame_height: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub latest_frame_pixel_format: Option<String>,
        pub last_error: Option<String>,
    }

    /// Service status DTO
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ServiceStatus {
        pub running: bool,
        pub healthy: bool,
        pub pid: Option<u32>,
    }
}

pub use wire::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_mode_ipc_round_trips_with_restore_metadata() {
        let session_id = SessionId("display-mode-session".to_string());
        let mode = DisplayMode {
            id: "windows:display:0:1920x1080@60".to_string(),
            source_id: Some("windows:display:0".to_string()),
            width: 1920,
            height: 1080,
            refresh_hz: 60,
            bit_depth: Some(32),
            is_current: false,
        };
        let change = DisplayModeChange {
            session_id: session_id.clone(),
            requested: Some(mode.clone()),
            previous: Some(DisplayMode {
                id: "windows:display:0:2560x1600@60".to_string(),
                source_id: Some("windows:display:0".to_string()),
                width: 2560,
                height: 1600,
                refresh_hz: 60,
                bit_depth: Some(32),
                is_current: true,
            }),
            active: Some(mode.clone()),
            status: "changed".to_string(),
            reason: None,
            restore_required: true,
        };

        let response = IpcResponse::DisplayModeChanged {
            session_id: session_id.clone(),
            change,
        };
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("DisplayModeChanged"));
        assert!(encoded.contains("restore_required"));

        let decoded: IpcResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn display_mode_control_requests_are_tagged_ipc_messages() {
        let session_id = SessionId("display-mode-session".to_string());
        let mode = DisplayMode {
            id: "windows:display:0:1920x1080@144".to_string(),
            source_id: Some("windows:display:0".to_string()),
            width: 1920,
            height: 1080,
            refresh_hz: 144,
            bit_depth: None,
            is_current: false,
        };

        let request = IpcRequest::SetRemoteDisplayMode {
            session_id,
            mode,
            restore_after_session: true,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("SetRemoteDisplayMode"));

        let decoded: IpcRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn media_profile_round_trips_hevc_chroma_metadata() {
        let profile = MediaProfile {
            width: 2560,
            height: 1600,
            fps: 165,
            bitrate_mbps: 120,
            codec: "hevc".to_string(),
            codec_profile: Some("main".to_string()),
            bit_depth: Some(8),
            chroma_subsampling: Some("4:2:0".to_string()),
            pixel_format: Some("nv12".to_string()),
            hdr_enabled: Some(false),
            color_mode: Some("grayscale".to_string()),
            color_pipeline: Some("sdr8".to_string()),
        };

        let encoded = serde_json::to_string(&profile).unwrap();
        assert!(encoded.contains("\"codec\":\"hevc\""));
        assert!(encoded.contains("\"chroma_subsampling\":\"4:2:0\""));
        assert!(encoded.contains("\"hdr_enabled\":false"));
        assert!(encoded.contains("\"color_mode\":\"grayscale\""));
        assert!(encoded.contains("\"color_pipeline\":\"sdr8\""));

        let decoded: MediaProfile = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn wake_on_lan_request_and_response_are_stable_ipc_messages() {
        let request = IpcRequest::WakeOnLan {
            device_id: DeviceId("agent-device".to_string()),
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            broadcast_addr: Some("192.168.1.255:9".to_string()),
        };

        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("WakeOnLan"));
        assert!(encoded.contains("\"mac_address\":\"AA:BB:CC:DD:EE:FF\""));
        assert!(encoded.contains("\"broadcast_addr\":\"192.168.1.255:9\""));

        let decoded: IpcRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);

        let response = IpcResponse::WakeOnLanSent {
            device_id: DeviceId("agent-device".to_string()),
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            broadcast_addr: "192.168.1.255:9".to_string(),
            packet_bytes: 102,
        };
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("WakeOnLanSent"));
        assert!(encoded.contains("\"packet_bytes\":102"));

        let decoded: IpcResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn remote_device_power_request_is_a_stable_ipc_message() {
        let request = IpcRequest::RequestRemoteDevicePowerAction {
            device_id: DeviceId("agent-device".to_string()),
            action: RemoteDevicePowerAction::Restart,
        };

        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains("RequestRemoteDevicePowerAction"));
        assert!(encoded.contains("\"device_id\":\"agent-device\""));
        assert!(encoded.contains("\"action\":\"restart\""));

        let decoded: IpcRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);

        let response = IpcResponse::RemoteDevicePowerActionAccepted {
            device_id: DeviceId("agent-device".to_string()),
            action: RemoteDevicePowerAction::Shutdown,
        };
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("RemoteDevicePowerActionAccepted"));
        assert!(encoded.contains("\"action\":\"shutdown\""));

        let decoded: IpcResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, response);
    }
}
