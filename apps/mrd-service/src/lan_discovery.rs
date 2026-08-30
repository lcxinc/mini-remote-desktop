use crate::app_state::{AppState, AuthenticatedPeerTrust, DeviceIdentityRegistryError};
#[cfg(all(test, any(windows, target_os = "macos")))]
use crate::app_state::{MediaRenderFrame, MediaRenderQueueEnqueue};
use crate::transports::{quic::QuicTransportMux, TransportMuxConfig};
use anyhow::{Context, Result};
use mrd_application::ports::{
    SessionLifecycleState, SessionSnapshot, TransportEnvelope, TransportLane, TransportMuxPort,
    TransportSendOutcome, VideoEnvelopeMetadata,
};
use mrd_identity::UnattendedCredential;
use mrd_ipc::{
    CaptureSource, CaptureSourceSelection, DisplayMode, DisplayModeChange, LanDiscoverySnapshot,
    MediaProfile, MediaProfileNegotiation, RemoteAccessMode, RemoteAuthorizationState,
    RemoteFailure, RemotePermissionScope, RemoteReasonCode,
};
#[cfg(test)]
use mrd_ipc::{MediaSenderTransportSnapshot, MediaStageMetrics};
#[cfg(test)]
use mrd_pipeline_core::DecodedFrame;
#[cfg(test)]
use mrd_pipeline_core::DecodedFrameData;
#[cfg(test)]
use mrd_pipeline_core::{CapturedFrame, FramePixelFormat};
use mrd_proto::{DeviceId, SessionId};
#[cfg(test)]
use mrd_render::RenderFrame;
#[cfg(test)]
use mrd_transport_quic_quinn::QuicAuReassemblerConfig;
use mrd_transport_quic_quinn::{
    certificate_fingerprint_sha256, fragment_access_unit, fragment_media_payload_v3,
    is_quic_media_v3_datagram, QuicAuReassembler, QuicMediaPayloadType, QuicMediaReassembler,
    QuinnDatagramEndpoint, QuinnPreparedServer, QuinnServerBootstrap, QuinnServerListener,
    QUIC_AU_FRAGMENT_HEADER_LEN, QUIC_MEDIA_V3_FRAGMENT_HEADER_LEN,
};
#[cfg(test)]
use mrd_transport_quic_quinn::{QuicAuFrame, QuinnDatagramPair};
#[cfg(any(test, target_os = "macos"))]
use mrd_transport_quic_quinn::{QuicAuReassemblerStats, QuicMediaCodec, QuicMediaFrame};
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(all(test, target_os = "macos"))]
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(all(test, target_os = "macos"))]
use std::sync::Condvar as StdCondvar;
#[cfg(any(windows, target_os = "macos"))]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
#[cfg(all(test, target_os = "macos"))]
use std::time::Instant as StdInstant;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{interval, timeout, Instant};

mod capture_activity;
mod capture_sources;
mod discovery_config;
mod discovery_identity;
mod dynamic_window_fps;
mod lan_control_input;
mod local_network_identity;
mod media_access_unit;
mod media_capabilities;
mod media_capture_config;
mod media_envelope;
mod media_error_policy;
mod media_frame_capture;
mod media_frame_preparation;
mod media_keyframe_request;
mod media_ordering;
mod media_probe;
mod media_profile;
mod media_receiver;
mod media_receiver_decoder;
mod media_receiver_decoder_candidates;
mod media_receiver_runtime;
mod media_render_policy;
mod media_render_worker;
pub(crate) mod media_sender;
mod media_sender_telemetry;
mod media_timing;
mod media_transport;
mod peer_format;
mod peer_lookup;
mod peer_registry;
mod protocol;
mod remote_power;
mod runtime_flags;
mod service_identity;
mod session_runtime;
mod time_utils;
use capture_activity::active_window_capture_count;
pub use discovery_config::LanDiscoveryConfig;
use discovery_identity::{is_valid_discovery_packet, new_instance_id, now_ms};
pub use discovery_identity::{DISCOVERY_APP_ID, DISCOVERY_MAGIC};
use dynamic_window_fps::{
    is_winrt_window_capture_no_frame_timeout, update_dynamic_window_fps_decision,
    window_dynamic_fps_input_for_capture_error, window_dynamic_fps_input_for_captured_frame,
    DynamicWindowFpsDecision, DynamicWindowFpsPolicy,
};
#[cfg(test)]
use dynamic_window_fps::{DynamicWindowFpsInput, DynamicWindowFpsTier};
pub(crate) use lan_control_input::request_authenticated_lan_control_input_under_security_gate;
use lan_control_input::{
    accept_or_replay_lan_control_input, process_authenticated_control_input_datagram,
    AuthenticatedControlReplayKey, AuthenticatedControlReplayState, AuthenticatedControlSenderKey,
    AuthenticatedControlSenderState, LanControlInputAckState, LanControlInputDedupeKey,
};
pub use lan_control_input::{
    request_authenticated_lan_control_input, request_lan_control_input,
    AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX,
};
use local_network_identity::local_lan_announcement_mac_address;
use media_access_unit::{h264_access_unit_is_keyframe, LanAccessUnitCodec};
use media_capabilities::{
    lan_media_capabilities, lan_media_capabilities_with_input_control,
    LAN_MEDIA_AV1_MAIN_420_8BIT_CAPABILITY, LAN_MEDIA_COLOR_MODE_CAPABILITY,
    LAN_MEDIA_HEVC_MAIN10_420_10BIT_CAPABILITY, LAN_MEDIA_HEVC_MAIN_420_8BIT_CAPABILITY,
};
#[cfg(all(test, target_os = "macos"))]
use media_capabilities::{
    macos_lan_media_capabilities_from_probe, probe_macos_lan_media_capabilities,
    MacosLanMediaCapabilityProbe, LAN_CAPTURE_MACOS_CAPABILITY, LAN_DECODE_VIDEOTOOLBOX_CAPABILITY,
    LAN_DECODE_VIDEOTOOLBOX_H264_CAPABILITY, LAN_DECODE_VIDEOTOOLBOX_HEVC_CAPABILITY,
    LAN_ENCODE_VIDEOTOOLBOX_H264_CAPABILITY, LAN_ENCODE_VIDEOTOOLBOX_HEVC_CAPABILITY,
    LAN_RENDER_MACOS_NATIVE_CAPABILITY,
};
#[cfg(all(test, windows))]
use media_capabilities::{
    LAN_CAPTURE_DXGI_CAPABILITY, LAN_DECODE_NVDEC_AV1_CAPABILITY, LAN_DECODE_NVDEC_CAPABILITY,
    LAN_DECODE_NVDEC_HEVC_CAPABILITY, LAN_DECODE_NVDEC_HEVC_MAIN10_CAPABILITY,
    LAN_ENCODE_NVENC_AV1_CAPABILITY, LAN_ENCODE_NVENC_H264_CAPABILITY,
    LAN_ENCODE_NVENC_HEVC_CAPABILITY, LAN_ENCODE_NVENC_HEVC_MAIN10_CAPABILITY,
    LAN_RENDER_D3D11_NATIVE_CAPABILITY, LAN_RENDER_D3D11_SHARED_NV12_CAPABILITY,
};
#[cfg(test)]
use media_capture_config::window_capture_source_error;
#[cfg(all(test, windows))]
use media_capture_config::windows_lan_window_capture_uses_shared_texture;
use media_capture_config::{
    dynamic_window_fps_config_key, format_capture_source_failure, is_windows_window_source_id,
    lan_capture_config_key, lan_capture_config_matches, DynamicWindowFpsConfigKey,
    LanCaptureConfigKey,
};
#[cfg(windows)]
use media_capture_config::{
    parse_windows_window_source_id, windows_lan_capture_backend,
    windows_lan_capture_backend_for_profile, windows_lan_nvenc_h264_available,
    WindowsLanCaptureBackend,
};
#[cfg(test)]
use media_envelope::LAN_MEDIA_PAYLOAD_H264_ACCESS_UNIT;
use media_envelope::{
    decode_lan_media_envelope, encode_lan_media_envelope, lan_media_profile_id, LanMediaEnvelope,
    LAN_MEDIA_CODEC_AV1, LAN_MEDIA_CODEC_H264, LAN_MEDIA_CODEC_HEVC, LAN_MEDIA_PAYLOAD_ACCESS_UNIT,
    LAN_MEDIA_PAYLOAD_PROBE_FRAME,
};
use media_error_policy::{
    should_log_media_receiver_decode_error, should_log_media_sender_frame_error,
    LAN_MEDIA_RECEIVER_MAX_CONSECUTIVE_DECODE_ERRORS,
    LAN_MEDIA_SENDER_MAX_CONSECUTIVE_FRAME_ERRORS,
};
#[cfg(target_os = "macos")]
use media_frame_capture::macos_lan_capture_stream_fps;
use media_frame_capture::{
    capture_source_kind_from_id, create_lan_frame_capture, LanSenderFrameCapture,
};
pub(crate) use media_frame_capture::{
    create_software_frame_capture, selected_capture_source_id, LanFrameCapture,
};
#[cfg(test)]
use media_frame_capture::{synthetic_capture_source, TEST_SYNTHETIC_CAPTURE_SOURCE_ID};
#[cfg(all(test, target_os = "macos"))]
use media_frame_capture::{MacosPumpedLanFrameCapture, MacosPumpedLanFrameState};
#[cfg(test)]
use media_frame_preparation::decoded_frame_to_rgb24;
#[cfg(test)]
use media_frame_preparation::window_h264_capture_dimensions;
use media_frame_preparation::{captured_frame_memory_path, h264_target_dimensions};
pub(crate) use media_frame_preparation::{
    decoded_frame_format_stage, decoded_frame_pixel_format, prepare_frame_for_h264,
};
use media_keyframe_request::{
    decode_lan_keyframe_request_datagram, encode_lan_keyframe_request_datagram,
};
use media_ordering::LanMediaFrameOrderer;
#[cfg(test)]
use media_probe::decoded_video_probe_format;
#[cfg(test)]
use media_probe::{build_media_probe_frame, media_payload_bytes};
use media_probe::{decode_media_probe_frame, fnv1a64, fnv1a64_media_metadata};
#[cfg(test)]
use media_profile::default_media_profile;
#[cfg(test)]
use media_profile::format_media_profile;
#[cfg(target_os = "macos")]
use media_profile::normalize_lan_media_profile;
use media_profile::{
    apply_lan_media_profile_defaults, default_media_profile_negotiation,
    ensure_peer_can_receive_selected_media, ensure_peer_supports_requested_media,
    lan_runtime_media_profile, normalize_lan_codec_name, validate_media_profile,
};
use media_receiver::decode_lan_desktop_frame;
#[cfg(all(test, target_os = "macos"))]
use media_receiver_decoder::create_lan_video_decoder;
use media_receiver_decoder::{
    create_lan_receiver_decoder, create_lan_receiver_decoder_with_preference,
    try_decode_h264_keyframe_with_fallback,
};
#[cfg(all(test, target_os = "macos"))]
use media_receiver_decoder_candidates::preferred_lan_receiver_decoder_candidates_from_preference;
#[cfg(test)]
use media_receiver_decoder_candidates::{
    default_lan_receiver_decoder_candidates, prioritize_lan_receiver_decoder_candidates,
};
use media_receiver_runtime::{
    quic_media_v3_frame_to_legacy_frame, receiver_should_use_local_render_fallback,
    record_lan_decoded_frames,
};
#[cfg(test)]
use media_render_policy::{
    lan_media_payload_hash_for_mode, lan_media_payload_hash_mode_for_profile_with_override,
    lan_media_payload_hash_mode_from_env_value, lan_render_pacing_from_env_value,
    LanMediaPayloadHashMode,
};
#[cfg(all(test, any(windows, target_os = "macos")))]
use media_render_policy::{
    lan_render_cap_target_fps_for_profile, lan_render_policy_allows_service_pacing,
    lan_render_queue_capacity_for_policy, lan_render_queue_capacity_for_profile,
    LanRenderQueuePolicy,
};
#[cfg(all(test, any(windows, target_os = "macos")))]
use media_render_policy::{
    lan_render_pacing_enabled_for_profile, lan_render_pacing_render_start_delay,
    lan_render_pacing_target_fps, lan_render_pacing_target_fps_from_values,
    lan_render_queue_capacity_from_env_value, lan_render_queue_policy_for_profile_with_override,
    lan_render_queue_policy_from_env_value, render_pacing_frame_interval,
    render_pacing_precise_sleep_guard, render_profile_requests_high_resolution_timer,
    should_interrupt_render_pacing_sleep,
};
#[cfg(any(windows, target_os = "macos"))]
pub(crate) use media_render_worker::render_lan_decoded_frame;
#[cfg(all(test, target_os = "macos"))]
use media_render_worker::upload_lan_render_frame;
#[cfg(all(test, any(windows, target_os = "macos")))]
use media_render_worker::{
    render_lan_frame_once, take_next_lan_render_frame_for_policy, wait_for_mutex_guard,
    LanRenderTaskOutcome,
};
#[cfg(target_os = "macos")]
use media_render_worker::{render_lan_h264_access_unit_frame, render_lan_hevc_access_unit_frame};
#[cfg(test)]
use media_sender::preferred_lan_h264_encoder_backends;
use media_sender::{
    create_lan_encoder, lan_sender_allows_h264_encoder_fallback, AgentTransportUnit,
    LanSenderEncoder, SenderMediaTurn,
};
#[cfg(test)]
use media_sender_telemetry::LanSenderStatsPayload;
use media_sender_telemetry::{
    decode_lan_sender_stats_datagram, encode_lan_sender_stats_datagram,
    send_lan_sender_stats_datagram, LanMediaTestImpairment, LanSenderDatagramFrameReport,
    LanSenderStatsTracker,
};
#[cfg(target_os = "macos")]
use media_timing::media_frame_interval_for_fps;
use media_timing::{
    media_frame_interval, media_frame_interval_for_dynamic_decision, schedule_next_media_frame,
    sleep_until_media_frame, MediaTimerResolution,
};
#[cfg(test)]
use media_timing::{
    media_frame_precise_sleep_chunk, media_frame_precise_sleep_guard,
    media_profile_requests_high_resolution_timer,
};
use media_transport::{
    lan_datagram_frame_send_budget, lan_media_datagram_size, lan_media_reassembler_config,
    reliable_whole_frame_media_override, select_reliable_media_send_mode_for_profile,
    send_lan_media_datagram, send_lan_reliable_media_fragment,
    should_send_access_unit_as_reliable_frame, should_send_access_unit_reliably,
    use_best_effort_media_datagrams, LanDatagramSendOutcome, LanReliableMediaSendMode,
};
#[cfg(test)]
use media_transport::{
    reliable_whole_frame_media_override_from_env_value, select_reliable_media_send_mode,
};
use peer_format::{format_peer_capabilities, format_peer_transports, normalize_transport_kind};
use peer_lookup::{
    local_device_id, peer_control_addr_with_capture_source_capability,
    peer_control_addr_with_display_mode_capability,
    peer_control_addr_with_input_control_capability,
    peer_control_addr_with_remote_power_capability, session_remote_peer,
};
use peer_registry::{LanPeerAuthentication, LanPeerRecord, LanPeerRegistry};
#[allow(unused_imports)]
pub use protocol::LanProtocolError;
pub use protocol::{
    media_profile_constraint_hash, unattended_transcript_bytes, LanAnnouncement,
    LanDiscoveryPacket, LanMediaBootstrap, LanQuicBootstrap, LanQuicControllerChallenge,
    LanSessionBootstrap, LanSessionGrantPayload, LanSessionRequest, LanUnattendedProof,
    SignedLanAnnouncement, SignedLanQuicControllerProof, SignedLanSessionBootstrap,
    SignedLanSessionGrant, SignedLanSessionRequest, SIGNED_LAN_PROTOCOL_VERSION,
};
use protocol::{
    DISCOVERY_PACKET_BUFFER_BYTES, LAN_CAPTURE_SOURCE_CONTROL_TRANSPORT,
    LAN_DISPLAY_MODE_CONTROL_TRANSPORT, LAN_INPUT_CONTROL_TRANSPORT,
    LAN_MEDIA_PROFILE_CONTROL_TRANSPORT, LAN_MEDIA_PROTOCOL_VERSION,
    LAN_QUIC_MEDIA_PROFILE_TRANSPORT, LAN_QUIC_MEDIA_TRANSPORT, LAN_QUIC_MEDIA_V2_TRANSPORT,
    LAN_QUIC_MEDIA_V3_TRANSPORT, LAN_QUIC_PERSISTENT_MEDIA_60FPS_TRANSPORT,
    LAN_QUIC_PERSISTENT_MEDIA_TRANSPORT, LAN_QUIC_RELIABLE_MEDIA_TRANSPORT,
    LAN_QUIC_TRANSPORT_MUX_V1,
};
#[cfg(test)]
use protocol::{
    DISCOVERY_SAFE_UDP_PAYLOAD_BYTES, LAN_INPUT_CONTROL_CAPABILITY,
    LAN_REMOTE_POWER_CONTROL_TRANSPORT, PROTOCOL_VERSION,
};
use remote_power::accept_lan_remote_device_power_action;
use runtime_flags::env_bool_override;
use service_identity::service_build_id;
#[cfg(test)]
use service_identity::{service_build_id_from_lookup, SERVICE_BUILD_ID_ENV};
use session_runtime::{
    mark_session_failed, negotiate_media_profile, selected_media_profile, session_allows_media,
};
#[cfg(target_os = "macos")]
use time_utils::duration_as_millis;
use time_utils::now_us;

const LAN_RELIABLE_WHOLE_FRAME_ENV: &str = "MRD_LAN_RELIABLE_WHOLE_FRAME";
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_ENV: &str = "MRD_LAN_CAPTURE_PUMP";
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_DRIVES_SENDER_ENV: &str = "MRD_LAN_CAPTURE_PUMP_DRIVES_SENDER";
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_REPEAT_LATEST_ENV: &str = "MRD_LAN_CAPTURE_PUMP_REPEAT_LATEST";
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_REPEAT_PACING_FPS_ENV: &str = "MRD_LAN_CAPTURE_PUMP_REPEAT_PACING_FPS";
const LAN_RENDER_PACING_ENV: &str = "MRD_LAN_RENDER_PACING";
const LAN_RENDER_MAX_FPS_ENV: &str = "MRD_LAN_RENDER_MAX_FPS";
const LAN_RENDER_QUEUE_CAPACITY_ENV: &str = "MRD_LAN_RENDER_QUEUE_CAPACITY";
const LAN_RENDER_QUEUE_POLICY_ENV: &str = "MRD_LAN_RENDER_QUEUE_POLICY";
const LAN_MEDIA_PAYLOAD_HASH_ENV: &str = "MRD_LAN_MEDIA_PAYLOAD_HASH";
#[cfg(windows)]
const D3D11_RENDER_PRESENT_BLOCKING_ENV: &str = "MRD_D3D11_RENDER_PRESENT_BLOCKING";
#[cfg(windows)]
const D3D11_RENDER_WAITABLE_OBJECT_ENV: &str = "MRD_D3D11_RENDER_WAITABLE_OBJECT";
const LAN_MEDIA_TARGET_WIDTH: u32 = 2560;
const LAN_MEDIA_TARGET_HEIGHT: u32 = 1600;
const LAN_MEDIA_TARGET_FPS: u32 = 165;
const LAN_MEDIA_MAX_FPS: u32 = 249;
const LAN_MEDIA_TARGET_BITRATE_MBPS: u32 = 120;
const LAN_QUIC_BEST_EFFORT_DATAGRAM_MAX_BITRATE_MBPS: u32 = 40;
const LAN_QUIC_FALLBACK_DATAGRAM_BYTES: usize = 1_200;
// Keep the default media fragment below common LAN/QUIC path MTU headroom.
// Larger datagrams reduce sender P95 but raised cross-device frame drop ratio.
const LAN_QUIC_LAN_HIGH_QUALITY_DATAGRAM_BYTES: usize = LAN_QUIC_FALLBACK_DATAGRAM_BYTES;
const LAN_QUIC_RELIABLE_WHOLE_FRAME_MIN_BITRATE_MBPS: u32 = 80;
const LAN_QUIC_RELIABLE_WHOLE_FRAME_DEFAULT_MIN_BITRATE_MBPS: u32 = 100;
const LAN_QUIC_RELIABLE_WHOLE_FRAME_DEFAULT_MIN_FPS: u32 = 120;
const LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES: usize = 4 * 1024 * 1024;
const LAN_RELIABLE_KEYFRAME_SEND_TASK_LIMIT: usize = 1;
const LAN_QUIC_RELIABLE_MEDIA_RETRY_DELAY: Duration = Duration::from_millis(10);
const LAN_MEDIA_AUTHORIZATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
// Only bounds an in-flight persistent-stream payload. Waiting for the next
// frame header remains unbounded because an idle capture stream is not HOL.
// Real 1080p keyframes can exceed 100 ms on a busy LAN, so keep enough margin
// to avoid a reset/keyframe-request feedback loop while still bounding a
// genuinely incomplete reliable frame.
const LAN_QUIC_PERSISTENT_MEDIA_HOL_TIMEOUT: Duration = Duration::from_millis(750);
const LAN_QUIC_PER_MESSAGE_CONCURRENT_READS: usize = 8;
const LAN_QUIC_DATAGRAM_SEND_BUDGET_MIN_BITRATE_MBPS: u32 = 80;
const LAN_QUIC_DATAGRAM_SEND_BUDGET_MIN_FPS: u32 = 120;
const LAN_QUIC_DATAGRAM_SEND_BUDGET: Duration = Duration::from_millis(4);
const LAN_RENDER_PACING_PRECISE_SLEEP_MIN_FPS: u32 = 90;
const LAN_RENDER_PACING_PRECISE_SLEEP_GUARD: Duration = Duration::from_millis(2);
const LAN_RENDER_PACING_POLL_INTERVAL: Duration = Duration::from_millis(1);
const LAN_RENDER_PACING_PRESENT_LEAD: Duration = Duration::from_micros(250);
const LAN_RENDER_PACING_DEFAULT_MIN_FPS: u32 = 120;
const LAN_RENDER_PACING_DEFAULT_MAX_PENDING_FRAMES: usize = 3;
const LAN_RENDER_PACING_MAX_PENDING_FRAMES_LIMIT: usize = 8;
const LAN_MEDIA_KEYFRAME_REQUEST_MIN_INTERVAL: Duration = Duration::from_millis(20);
const LAN_REMOTE_SESSION_ACK_TIMEOUT: Duration = Duration::from_secs(10);
const LAN_CONTROL_INPUT_ACK_TIMEOUT: Duration = Duration::from_millis(250);
const LAN_CONTROL_INPUT_REALTIME_ATTEMPTS: usize = 1;
const LAN_CONTROL_INPUT_RELIABLE_ATTEMPTS: usize = 3;
const LAN_CONTROL_INPUT_DEDUPE_WINDOW_MS: u64 = 10_000;
const LAN_CONTROL_INPUT_DEDUPE_CACHE_LIMIT: usize = 4096;
const LAN_QUIC_BOOTSTRAP_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const LAN_QUIC_BOOTSTRAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const LAN_QUIC_CONTROLLER_PROOF_TIMEOUT: Duration = Duration::from_secs(5);
const LAN_QUIC_CONTROLLER_PROOF_MAX_BYTES: usize = 16 * 1024;
const LAN_QUIC_CONTROLLER_PROOF_ACCEPTED: &[u8] = b"MRD_LAN_QUIC_CONTROLLER_PROOF_OK_V3";
#[cfg(any(windows, target_os = "macos"))]
static LOCAL_RENDER_REFRESH_HZ: OnceLock<Option<u32>> = OnceLock::new();
static LAN_CONTROL_INPUT_EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_QUEUE_CAPACITY: usize = 2;
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_REPEAT_GRACE_MAX: Duration = Duration::from_millis(4);
#[cfg(target_os = "macos")]
const LAN_CAPTURE_PUMP_ERROR_BACKOFF: Duration = Duration::from_millis(5);
const LAN_MEDIA_REASSEMBLER_FRAME_TIMEOUT_MS: u64 = 1_500;
const LAN_MEDIA_REASSEMBLER_MAX_PENDING_FRAMES: usize = 256;
const LAN_SIGNED_REPLAY_CACHE_LIMIT: usize = 4_096;
const LAN_SIGNED_REPLAY_RETENTION_SKEW_MS: u64 = 2_000;
const LAN_INCOMING_AUTHORIZATION_TASK_LIMIT: usize = 32;
const LAN_INCOMING_AUTHORIZATION_RATE_LIMIT: u32 = 16;
const LAN_INCOMING_AUTHORIZATION_GLOBAL_RATE_LIMIT: u32 = 64;
const LAN_INCOMING_AUTHORIZATION_RATE_WINDOW_MS: u64 = 10_000;
const LAN_INCOMING_AUTHORIZATION_RATE_PEER_LIMIT: usize = 256;
const LAN_PRE_AUTHORIZATION_AUDIT_WRITE_LIMIT: u32 = 17;
const LAN_PRE_AUTHORIZATION_AUDIT_DETAIL_LIMIT: u32 = LAN_PRE_AUTHORIZATION_AUDIT_WRITE_LIMIT - 1;
const LAN_PRE_AUTHORIZATION_AUDIT_WINDOW_MS: u64 = 10_000;
const LAN_INCOMING_CONTROL_TASK_LIMIT: usize = 64;
const LAN_INCOMING_CONTROL_RATE_LIMIT: u32 = 4_096;
const LAN_INCOMING_CONTROL_GLOBAL_RATE_LIMIT: u32 = 16_384;
const LAN_INCOMING_CONTROL_RATE_WINDOW_MS: u64 = 10_000;
const LAN_INCOMING_CONTROL_RATE_PEER_LIMIT: usize = 256;
const LAN_CONTROL_DENIAL_AUDIT_WRITE_LIMIT: u32 = 17;
const LAN_CONTROL_DENIAL_AUDIT_DETAIL_LIMIT: u32 = LAN_CONTROL_DENIAL_AUDIT_WRITE_LIMIT - 1;
const LAN_CONTROL_DENIAL_AUDIT_WINDOW_MS: u64 = 10_000;
// Small bounded reorder window: absorbs normal QUIC stream/datagram jitter at 144-180 Hz
// without letting a genuinely missing frame add visible input latency.
const LAN_MEDIA_RECEIVER_REORDER_MAX_PENDING_FRAMES: usize = 4;

#[derive(Debug)]
pub struct LanDiscoveryState {
    config: LanDiscoveryConfig,
    instance_id: String,
    running: AtomicBool,
    last_probe_ms: AtomicU64,
    peers: Mutex<LanPeerRegistry>,
    signed_replays: Mutex<LanSignedReplayCache>,
    pending_sessions: Arc<StdMutex<HashSet<SessionId>>>,
    recent_control_inputs: Mutex<HashMap<LanControlInputDedupeKey, LanControlInputAckState>>,
    authenticated_control_inputs:
        Mutex<HashMap<AuthenticatedControlReplayKey, AuthenticatedControlReplayState>>,
    authenticated_control_senders:
        Mutex<HashMap<AuthenticatedControlSenderKey, Arc<AuthenticatedControlSenderState>>>,
    incoming_authorization_tasks: Arc<Semaphore>,
    incoming_authorization_rates: Mutex<HashMap<IpAddr, LanIncomingAuthorizationRate>>,
    incoming_authorization_global_rate: Mutex<Option<LanIncomingAuthorizationRate>>,
    pre_authorization_audit_window: Mutex<LanPreAuthorizationAuditWindow>,
    incoming_control_tasks: Arc<Semaphore>,
    incoming_control_rates: Mutex<HashMap<IpAddr, LanIncomingAuthorizationRate>>,
    incoming_control_global_rate: Mutex<Option<LanIncomingAuthorizationRate>>,
    control_denial_audit_window: Mutex<LanPreAuthorizationAuditWindow>,
    probe_requested: Notify,
    peer_changed: Notify,
}

#[derive(Debug, Clone, Copy)]
struct LanIncomingAuthorizationRate {
    window_started_ms: u64,
    request_count: u32,
    last_seen_ms: u64,
}

#[derive(Debug, Default)]
struct LanPreAuthorizationAuditWindow {
    window_started_ms: Option<u64>,
    detailed_writes: u32,
    suppressed_denials: u64,
    overflow_marker_written: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LanPreAuthorizationAuditAdmission {
    Detailed { previous_window_suppressed: u64 },
    OverflowMarker,
    Suppressed,
}

struct LanSessionReservation {
    pending_sessions: Arc<StdMutex<HashSet<SessionId>>>,
    session_id: SessionId,
}

impl Drop for LanSessionReservation {
    fn drop(&mut self) {
        self.pending_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.session_id);
    }
}

impl LanDiscoveryState {
    pub fn new(config: LanDiscoveryConfig) -> Self {
        Self {
            config,
            instance_id: new_instance_id(),
            running: AtomicBool::new(false),
            last_probe_ms: AtomicU64::new(0),
            peers: Mutex::new(LanPeerRegistry::default()),
            signed_replays: Mutex::new(LanSignedReplayCache::default()),
            pending_sessions: Arc::new(StdMutex::new(HashSet::new())),
            recent_control_inputs: Mutex::new(HashMap::new()),
            authenticated_control_inputs: Mutex::new(HashMap::new()),
            authenticated_control_senders: Mutex::new(HashMap::new()),
            incoming_authorization_tasks: Arc::new(Semaphore::new(
                LAN_INCOMING_AUTHORIZATION_TASK_LIMIT,
            )),
            incoming_authorization_rates: Mutex::new(HashMap::new()),
            incoming_authorization_global_rate: Mutex::new(None),
            pre_authorization_audit_window: Mutex::new(LanPreAuthorizationAuditWindow::default()),
            incoming_control_tasks: Arc::new(Semaphore::new(LAN_INCOMING_CONTROL_TASK_LIMIT)),
            incoming_control_rates: Mutex::new(HashMap::new()),
            incoming_control_global_rate: Mutex::new(None),
            control_denial_audit_window: Mutex::new(LanPreAuthorizationAuditWindow::default()),
            probe_requested: Notify::new(),
            peer_changed: Notify::new(),
        }
    }

    async fn try_admit_incoming_authorization(
        &self,
        source_ip: IpAddr,
        received_at_ms: u64,
    ) -> Option<OwnedSemaphorePermit> {
        let permit = self
            .incoming_authorization_tasks
            .clone()
            .try_acquire_owned()
            .ok()?;
        let mut rates = self.incoming_authorization_rates.lock().await;
        rates.retain(|_, rate| {
            received_at_ms.saturating_sub(rate.last_seen_ms)
                <= LAN_INCOMING_AUTHORIZATION_RATE_WINDOW_MS
        });
        if !rates.contains_key(&source_ip)
            && rates.len() >= LAN_INCOMING_AUTHORIZATION_RATE_PEER_LIMIT
        {
            if let Some(oldest) = rates
                .iter()
                .min_by_key(|(_, rate)| rate.last_seen_ms)
                .map(|(ip, _)| *ip)
            {
                rates.remove(&oldest);
            }
        }
        let rate = rates
            .entry(source_ip)
            .or_insert(LanIncomingAuthorizationRate {
                window_started_ms: received_at_ms,
                request_count: 0,
                last_seen_ms: received_at_ms,
            });
        if received_at_ms.saturating_sub(rate.window_started_ms)
            >= LAN_INCOMING_AUTHORIZATION_RATE_WINDOW_MS
        {
            rate.window_started_ms = received_at_ms;
            rate.request_count = 0;
        }
        rate.last_seen_ms = received_at_ms;
        if rate.request_count >= LAN_INCOMING_AUTHORIZATION_RATE_LIMIT {
            return None;
        }
        rate.request_count = rate.request_count.saturating_add(1);
        drop(rates);

        let mut global_rate = self.incoming_authorization_global_rate.lock().await;
        let global_rate = global_rate.get_or_insert(LanIncomingAuthorizationRate {
            window_started_ms: received_at_ms,
            request_count: 0,
            last_seen_ms: received_at_ms,
        });
        if received_at_ms.saturating_sub(global_rate.window_started_ms)
            >= LAN_INCOMING_AUTHORIZATION_RATE_WINDOW_MS
        {
            global_rate.window_started_ms = received_at_ms;
            global_rate.request_count = 0;
        }
        global_rate.last_seen_ms = received_at_ms;
        if global_rate.request_count >= LAN_INCOMING_AUTHORIZATION_GLOBAL_RATE_LIMIT {
            return None;
        }
        global_rate.request_count = global_rate.request_count.saturating_add(1);
        Some(permit)
    }

    async fn admit_pre_authorization_denial_audit(
        &self,
        _source_ip: IpAddr,
        received_at_ms: u64,
    ) -> LanPreAuthorizationAuditAdmission {
        // Deliberately global: keying this quota by source would let address
        // rotation amplify durable audit writes without bound.
        let mut window = self.pre_authorization_audit_window.lock().await;
        let window_expired = window.window_started_ms.is_none_or(|window_started_ms| {
            received_at_ms.saturating_sub(window_started_ms)
                >= LAN_PRE_AUTHORIZATION_AUDIT_WINDOW_MS
        });
        if window_expired {
            let previous_window_suppressed = window.suppressed_denials;
            *window = LanPreAuthorizationAuditWindow {
                window_started_ms: Some(received_at_ms),
                detailed_writes: 1,
                suppressed_denials: 0,
                overflow_marker_written: false,
            };
            return LanPreAuthorizationAuditAdmission::Detailed {
                previous_window_suppressed,
            };
        }

        if window.detailed_writes < LAN_PRE_AUTHORIZATION_AUDIT_DETAIL_LIMIT {
            window.detailed_writes = window.detailed_writes.saturating_add(1);
            return LanPreAuthorizationAuditAdmission::Detailed {
                previous_window_suppressed: 0,
            };
        }

        window.suppressed_denials = window.suppressed_denials.saturating_add(1);
        if !window.overflow_marker_written {
            window.overflow_marker_written = true;
            LanPreAuthorizationAuditAdmission::OverflowMarker
        } else {
            LanPreAuthorizationAuditAdmission::Suppressed
        }
    }

    async fn try_admit_authenticated_control(
        &self,
        source_ip: IpAddr,
        received_at_ms: u64,
    ) -> Option<OwnedSemaphorePermit> {
        let permit = self
            .incoming_control_tasks
            .clone()
            .try_acquire_owned()
            .ok()?;
        let mut rates = self.incoming_control_rates.lock().await;
        rates.retain(|_, rate| {
            received_at_ms.saturating_sub(rate.last_seen_ms) <= LAN_INCOMING_CONTROL_RATE_WINDOW_MS
        });
        if !rates.contains_key(&source_ip) && rates.len() >= LAN_INCOMING_CONTROL_RATE_PEER_LIMIT {
            if let Some(oldest) = rates
                .iter()
                .min_by_key(|(_, rate)| rate.last_seen_ms)
                .map(|(ip, _)| *ip)
            {
                rates.remove(&oldest);
            }
        }
        let rate = rates
            .entry(source_ip)
            .or_insert(LanIncomingAuthorizationRate {
                window_started_ms: received_at_ms,
                request_count: 0,
                last_seen_ms: received_at_ms,
            });
        if received_at_ms.saturating_sub(rate.window_started_ms)
            >= LAN_INCOMING_CONTROL_RATE_WINDOW_MS
        {
            rate.window_started_ms = received_at_ms;
            rate.request_count = 0;
        }
        rate.last_seen_ms = received_at_ms;
        if rate.request_count >= LAN_INCOMING_CONTROL_RATE_LIMIT {
            return None;
        }
        rate.request_count = rate.request_count.saturating_add(1);
        drop(rates);

        let mut global_rate = self.incoming_control_global_rate.lock().await;
        let global_rate = global_rate.get_or_insert(LanIncomingAuthorizationRate {
            window_started_ms: received_at_ms,
            request_count: 0,
            last_seen_ms: received_at_ms,
        });
        if received_at_ms.saturating_sub(global_rate.window_started_ms)
            >= LAN_INCOMING_CONTROL_RATE_WINDOW_MS
        {
            global_rate.window_started_ms = received_at_ms;
            global_rate.request_count = 0;
        }
        global_rate.last_seen_ms = received_at_ms;
        if global_rate.request_count >= LAN_INCOMING_CONTROL_GLOBAL_RATE_LIMIT {
            return None;
        }
        global_rate.request_count = global_rate.request_count.saturating_add(1);
        Some(permit)
    }

    async fn admit_control_input_denial_audit(
        &self,
        received_at_ms: u64,
    ) -> LanPreAuthorizationAuditAdmission {
        let mut window = self.control_denial_audit_window.lock().await;
        let window_expired = window.window_started_ms.is_none_or(|window_started_ms| {
            received_at_ms.saturating_sub(window_started_ms) >= LAN_CONTROL_DENIAL_AUDIT_WINDOW_MS
        });
        if window_expired {
            let previous_window_suppressed = window.suppressed_denials;
            *window = LanPreAuthorizationAuditWindow {
                window_started_ms: Some(received_at_ms),
                detailed_writes: 1,
                suppressed_denials: 0,
                overflow_marker_written: false,
            };
            return LanPreAuthorizationAuditAdmission::Detailed {
                previous_window_suppressed,
            };
        }
        if window.detailed_writes < LAN_CONTROL_DENIAL_AUDIT_DETAIL_LIMIT {
            window.detailed_writes = window.detailed_writes.saturating_add(1);
            return LanPreAuthorizationAuditAdmission::Detailed {
                previous_window_suppressed: 0,
            };
        }
        window.suppressed_denials = window.suppressed_denials.saturating_add(1);
        if !window.overflow_marker_written {
            window.overflow_marker_written = true;
            LanPreAuthorizationAuditAdmission::OverflowMarker
        } else {
            LanPreAuthorizationAuditAdmission::Suppressed
        }
    }

    pub fn discovery_port(&self) -> u16 {
        self.config.discovery_port
    }

    fn reserve_session(&self, session_id: &SessionId) -> Result<LanSessionReservation> {
        let mut pending_sessions = self
            .pending_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !pending_sessions.insert(session_id.clone()) {
            anyhow::bail!("LAN session id is already pending: {}", session_id.0);
        }
        drop(pending_sessions);
        Ok(LanSessionReservation {
            pending_sessions: Arc::clone(&self.pending_sessions),
            session_id: session_id.clone(),
        })
    }

    fn probe_targets(&self, discovery_port: u16) -> Vec<SocketAddr> {
        let mut targets = Vec::with_capacity(self.config.probe_endpoints.len() + 1);
        if self.config.broadcast_enabled {
            targets.push(SocketAddr::from(([255, 255, 255, 255], discovery_port)));
        }
        for endpoint in &self.config.probe_endpoints {
            if !targets.iter().any(|target| target == endpoint) {
                targets.push(*endpoint);
            }
        }
        targets
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn request_probe(&self) {
        self.probe_requested.notify_one();
    }

    pub async fn request_probe_and_wait(&self, wait: Duration) -> LanDiscoverySnapshot {
        let notified = self.peer_changed.notified();
        self.request_probe();
        let _ = timeout(wait, notified).await;
        self.snapshot().await
    }

    #[cfg(test)]
    async fn upsert_peer(&self, announcement: LanAnnouncement, addr: SocketAddr) {
        if announcement.instance_id == self.instance_id {
            return;
        }

        let test_peer_key_id = format!("test-peer:{}", announcement.device_id);
        let peer = LanPeerRecord {
            device_id: announcement.device_id,
            device_name: announcement.device_name,
            device_type: announcement.device_type,
            ip: addr.ip(),
            discovery_port: announcement.discovery_port,
            transports: announcement.transports,
            protocol_version: announcement.protocol_version,
            service_build_id: announcement.service_build_id,
            media_protocol_version: announcement.media_protocol_version,
            media_capabilities: announcement.media_capabilities,
            mac_address: announcement.mac_address,
            peer_key_id: Some(test_peer_key_id),
            public_key: Some(vec![0; 32]),
            key_epoch: Some(1),
            authentication: peer_registry::LanPeerAuthentication::Signed(
                crate::app_state::AuthenticatedPeerTrust::Trusted,
            ),
            last_seen_ms: now_ms(),
        };

        self.peers.lock().await.upsert(peer);
        self.peer_changed.notify_one();
    }

    async fn upsert_signed_peer(
        &self,
        signed: &SignedLanAnnouncement,
        authentication: AuthenticatedPeerTrust,
    ) {
        let announcement = &signed.payload.announcement;
        let peer = LanPeerRecord {
            device_id: announcement.device_id.clone(),
            device_name: announcement.device_name.clone(),
            device_type: announcement.device_type.clone(),
            ip: signed.payload.discovery_endpoint.ip(),
            discovery_port: signed.payload.discovery_endpoint.port(),
            transports: announcement.transports.clone(),
            protocol_version: announcement.protocol_version,
            service_build_id: announcement.service_build_id.clone(),
            media_protocol_version: announcement.media_protocol_version,
            media_capabilities: announcement.media_capabilities.clone(),
            mac_address: announcement.mac_address.clone(),
            peer_key_id: Some(signed.payload.signer_key_id.clone()),
            public_key: Some(signed.public_key.clone()),
            key_epoch: Some(signed.payload.signer_key_epoch),
            authentication: LanPeerAuthentication::Signed(authentication),
            last_seen_ms: now_ms(),
        };
        self.peers.lock().await.upsert(peer);
        self.peer_changed.notify_one();
    }

    async fn upsert_legacy_peer(&self, announcement: LanAnnouncement, addr: SocketAddr) {
        let peer = LanPeerRecord {
            device_id: announcement.device_id,
            device_name: announcement.device_name,
            device_type: announcement.device_type,
            ip: addr.ip(),
            discovery_port: announcement.discovery_port,
            transports: announcement.transports,
            protocol_version: announcement.protocol_version,
            service_build_id: announcement.service_build_id,
            media_protocol_version: announcement.media_protocol_version,
            media_capabilities: announcement.media_capabilities,
            mac_address: announcement.mac_address,
            peer_key_id: None,
            public_key: None,
            key_epoch: None,
            authentication: LanPeerAuthentication::LegacyDiagnostic,
            last_seen_ms: now_ms(),
        };
        self.peers.lock().await.upsert(peer);
        self.peer_changed.notify_one();
    }

    async fn prune_stale_peers(&self) {
        let ttl_ms = self.config.peer_ttl.as_millis() as u64;
        let now = now_ms();
        self.peers.lock().await.prune_stale(now, ttl_ms);
    }

    pub async fn snapshot(&self) -> LanDiscoverySnapshot {
        self.prune_stale_peers().await;
        let now = now_ms();
        let peers = self.peers.lock().await.snapshot(now);

        let last_probe = self.last_probe_ms.load(Ordering::Relaxed);
        LanDiscoverySnapshot {
            enabled: self.config.enabled,
            running: self.running.load(Ordering::Relaxed),
            discovery_port: self.config.discovery_port,
            instance_id: self.instance_id.clone(),
            last_probe_ms: if last_probe == 0 {
                None
            } else {
                Some(last_probe)
            },
            peers,
        }
    }

    pub async fn peer_control_addr(&self, device_id: &DeviceId) -> Option<SocketAddr> {
        self.prune_stale_peers().await;
        self.peers.lock().await.control_addr(device_id)
    }

    pub async fn has_controllable_peer(&self, device_id: &DeviceId) -> bool {
        self.prune_stale_peers().await;
        self.peers
            .lock()
            .await
            .controllable_peer(device_id)
            .is_some()
    }

    /// Return fresh, authenticated LAN route evidence from the private peer
    /// registry.  The public IPC snapshot deliberately omits the signing key,
    /// key epoch, and trust revision, so callers selecting `Auto` must use this
    /// method instead of promoting `LanPeerInfo::p2p_available` themselves.
    pub async fn fresh_authenticated_peer_evidence(
        &self,
        device_id: &DeviceId,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Option<crate::wan_session::media::LanDiscoveryEvidence> {
        self.prune_stale_peers().await;
        let peer = self.peers.lock().await.controllable_peer(device_id)?;
        let peer_key_id = peer.peer_key_id?;
        let peer_public_key = peer.public_key?;
        let peer_key_epoch = peer.key_epoch?;
        let fresh = now_ms.saturating_sub(peer.last_seen_ms) <= max_age_ms;
        let supports_quic = peer
            .transports
            .iter()
            .any(|transport| transport.eq_ignore_ascii_case("quic"));
        Some(
            crate::wan_session::media::LanDiscoveryEvidence::from_authenticated_peer(
                fresh,
                supports_quic,
                peer_key_id,
                peer_public_key,
                peer_key_epoch,
            ),
        )
    }

    async fn controllable_peer(&self, device_id: &DeviceId) -> Option<LanPeerRecord> {
        self.prune_stale_peers().await;
        self.peers.lock().await.controllable_peer(device_id)
    }

    pub async fn peer_transports(&self, device_id: &DeviceId) -> Option<Vec<String>> {
        self.prune_stale_peers().await;
        self.peers.lock().await.transports(device_id)
    }

    pub async fn peer_media_capabilities(&self, device_id: &DeviceId) -> Option<Vec<String>> {
        self.prune_stale_peers().await;
        self.peers.lock().await.media_capabilities(device_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LanSignedReplayDomain {
    TrustedAnnouncement,
    DiagnosticAnnouncement,
    SessionRequest,
}

#[derive(Debug, Default)]
struct LanSignedReplayCache {
    entries: HashMap<(LanSignedReplayDomain, String, [u8; 16]), u64>,
}

impl LanSignedReplayCache {
    fn accept(
        &mut self,
        domain: LanSignedReplayDomain,
        peer_key_id: &str,
        nonce: [u8; 16],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.entries.retain(|_, expiry| *expiry >= now_ms);
        let key = (domain, peer_key_id.to_string(), nonce);
        if self.entries.contains_key(&key) {
            anyhow::bail!("replayed signed LAN message");
        }
        let domain_entry_count = self
            .entries
            .keys()
            .filter(|(entry_domain, _, _)| *entry_domain == domain)
            .count();
        if domain_entry_count >= LAN_SIGNED_REPLAY_CACHE_LIMIT {
            anyhow::bail!("signed LAN replay cache capacity exceeded");
        }
        self.entries.insert(
            key,
            expires_at_ms.saturating_add(LAN_SIGNED_REPLAY_RETENTION_SKEW_MS),
        );
        Ok(())
    }
}

impl Default for LanDiscoveryState {
    fn default() -> Self {
        Self::new(LanDiscoveryConfig::default())
    }
}

pub async fn ingest_signed_lan_announcement(
    app_state: &Arc<AppState>,
    signed: SignedLanAnnouncement,
    addr: SocketAddr,
    observed_at_ms: u64,
) -> Result<()> {
    signed.verify(observed_at_ms)?;
    if signed.payload.discovery_endpoint != addr {
        anyhow::bail!(
            "signed LAN discovery endpoint does not match UDP source: signed={}, observed={addr}",
            signed.payload.discovery_endpoint
        );
    }
    if signed.payload.announcement.instance_id == app_state.lan_discovery.instance_id()
        && app_state.device_identities.machine_key_id()
            == Some(signed.payload.signer_key_id.as_str())
    {
        return Ok(());
    }
    let trust = resolve_authenticated_peer_trust(
        app_state,
        &signed.payload.signer_key_id,
        &signed.public_key,
        signed.payload.signer_key_epoch,
    )
    .await?;
    let replay_domain = if trust.is_controllable() {
        LanSignedReplayDomain::TrustedAnnouncement
    } else {
        LanSignedReplayDomain::DiagnosticAnnouncement
    };
    app_state.lan_discovery.signed_replays.lock().await.accept(
        replay_domain,
        &signed.payload.signer_key_id,
        signed.payload.nonce,
        signed.payload.expires_at_ms,
        observed_at_ms,
    )?;
    app_state
        .lan_discovery
        .upsert_signed_peer(&signed, trust)
        .await;
    Ok(())
}

pub async fn ingest_legacy_lan_announcement(
    app_state: &Arc<AppState>,
    announcement: LanAnnouncement,
    addr: SocketAddr,
    observed_at_ms: u64,
) -> Result<()> {
    if !app_state.lan_discovery.config.allow_unsigned_diagnostics {
        anyhow::bail!("unsigned LAN diagnostics are disabled");
    }
    if !is_valid_discovery_packet(&announcement.magic, &announcement.app_id) {
        anyhow::bail!("invalid legacy LAN discovery namespace");
    }
    if announcement.instance_id == app_state.lan_discovery.instance_id() {
        return Ok(());
    }
    if announcement.timestamp_ms > observed_at_ms.saturating_add(2_000)
        || observed_at_ms.saturating_sub(announcement.timestamp_ms) > 15_000
    {
        anyhow::bail!("stale legacy LAN diagnostic announcement");
    }
    app_state
        .lan_discovery
        .upsert_legacy_peer(announcement, addr)
        .await;
    Ok(())
}

async fn resolve_authenticated_peer_trust(
    app_state: &Arc<AppState>,
    peer_key_id: &str,
    public_key: &[u8],
    epoch: u64,
) -> Result<AuthenticatedPeerTrust> {
    if !app_state.security_is_healthy() {
        anyhow::bail!("authoritative security state is unavailable");
    }
    let registry = app_state.device_identities();
    let peer_key_id = peer_key_id.to_string();
    let public_key = public_key.to_vec();
    match tokio::task::spawn_blocking(move || {
        registry.authenticated_peer_trust(&peer_key_id, &public_key, epoch)
    })
    .await
    {
        Ok(Ok(trust)) => Ok(trust),
        Ok(Err(DeviceIdentityRegistryError::Store(error))) => {
            app_state.mark_security_unhealthy();
            Err(error.into())
        }
        Ok(Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired)) => {
            anyhow::bail!("authenticated peer trust lookup is unavailable")
        }
        Err(error) => {
            app_state.mark_security_unhealthy();
            Err(anyhow::Error::new(error).context("LAN trust lookup task failed"))
        }
    }
}

fn new_signed_nonce() -> Result<[u8; 16]> {
    let mut nonce = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("failed to generate LAN protocol nonce"))?;
    Ok(nonce)
}

struct LanRemoteAcceptResult {
    accepted: bool,
    message: Option<String>,
    media: Option<LanMediaBootstrap>,
    media_profile: Option<MediaProfileNegotiation>,
    prepared: Option<PreparedLanRemoteSession>,
}

#[derive(Clone)]
pub struct LanUnattendedAccessMaterial {
    pub access_epoch: u64,
    pub credential: Arc<UnattendedCredential>,
}

impl std::fmt::Debug for LanUnattendedAccessMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LanUnattendedAccessMaterial")
            .field("access_epoch", &self.access_epoch)
            .field("credential", &"REDACTED")
            .finish()
    }
}

struct LanRemoteSessionPreparation {
    session_id: SessionId,
    source_device_id: DeviceId,
    transport: String,
    source_media_capabilities: Vec<String>,
    negotiation: MediaProfileNegotiation,
    prepared_server: QuinnPreparedServer,
    expected_peer_ip: IpAddr,
}

struct PreparedLanRemoteSession {
    session_id: SessionId,
    source_device_id: DeviceId,
    transport: String,
    source_media_capabilities: Vec<String>,
    negotiation: MediaProfileNegotiation,
    listener: QuinnServerListener,
    bootstrap: QuinnServerBootstrap,
    expected_peer_ip: IpAddr,
    controller_binding: Option<LanQuicControllerBinding>,
}

#[derive(Clone)]
struct LanQuicControllerBinding {
    controller_public_key: Vec<u8>,
    controller_key_epoch: u64,
    grant_id: [u8; 32],
    transport_fingerprint_sha256: [u8; 32],
}

#[derive(Clone)]
struct LanQuicControllerProofMaterial {
    controller_identity: Arc<mrd_identity::DeviceIdentity>,
    controller_key_epoch: u64,
    grant_id: [u8; 32],
    transport_fingerprint_sha256: [u8; 32],
}

type LanEncoderConfigKey = (
    usize,
    usize,
    u32,
    u32,
    LanAccessUnitCodec,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<u8>,
    Option<String>,
);

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl LanRemoteAcceptResult {
    fn rejected(message: impl Into<String>) -> Self {
        Self {
            accepted: false,
            message: Some(message.into()),
            media: None,
            media_profile: None,
            prepared: None,
        }
    }
}

pub async fn send_probe(
    socket: &UdpSocket,
    discovery_port: u16,
    state: &LanDiscoveryState,
) -> Result<()> {
    let packet = periodic_discovery_packet(state);
    for target in state.probe_targets(discovery_port) {
        send_packet(socket, &packet, target).await?;
    }
    state.last_probe_ms.store(now_ms(), Ordering::Relaxed);
    Ok(())
}

fn periodic_discovery_packet(state: &LanDiscoveryState) -> LanDiscoveryPacket {
    LanDiscoveryPacket::Probe {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: state.instance_id.clone(),
        device_id: None,
        timestamp_ms: now_ms(),
    }
}

pub async fn start_lan_discovery(app_state: Arc<AppState>) -> Result<()> {
    if !app_state.lan_discovery.config.enabled {
        return Ok(());
    }

    let port = app_state.lan_discovery.discovery_port();
    let socket = Arc::new(
        UdpSocket::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("failed to bind LAN discovery UDP port {port}"))?,
    );
    if app_state.lan_discovery.config.broadcast_enabled {
        socket
            .set_broadcast(true)
            .context("failed to enable LAN discovery UDP broadcast")?;
    }

    app_state
        .lan_discovery
        .running
        .store(true, Ordering::Relaxed);

    let receive_socket = socket.clone();
    let receive_state = app_state.clone();
    tokio::spawn(async move {
        receive_loop(receive_socket, receive_state).await;
    });

    let announce_socket = socket.clone();
    let announce_state = app_state.clone();
    tokio::spawn(async move {
        announce_loop(announce_socket, announce_state).await;
    });

    send_probe(&socket, port, &app_state.lan_discovery).await?;
    Ok(())
}

pub async fn request_lan_remote_session(
    app_state: &Arc<AppState>,
    target_device_id: &DeviceId,
    session_id: &SessionId,
    transport_kind: &str,
    requested_profile: Option<MediaProfile>,
) -> Result<MediaProfileNegotiation> {
    request_lan_remote_session_authorized(
        app_state,
        target_device_id,
        session_id,
        transport_kind,
        requested_profile,
        RemoteAccessMode::Attended,
        vec![RemotePermissionScope::ScreenView],
        None,
    )
    .await
}

async fn begin_outgoing_authorization_under_security_gate(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    peer_key_id: &str,
    peer_public_key: &[u8],
    peer_key_epoch: u64,
    request: crate::session_authorization::VerifiedIncomingAuthorizationRequest,
) -> Result<()> {
    let _admission_guard = app_state.authorization_security_gate.lock().await;
    let admission_trust =
        resolve_authenticated_peer_trust(app_state, peer_key_id, peer_public_key, peer_key_epoch)
            .await?;
    if !admission_trust.is_controllable() {
        anyhow::bail!("LAN peer trust changed before session admission");
    }
    if app_state.sessions.lock().await.get(session_id).is_some() {
        anyhow::bail!(
            "session id became occupied before secure LAN admission: {}",
            session_id.0
        );
    }
    let bound_at_ms = request.created_at_ms;
    app_state
        .session_authorizations
        .begin_outgoing(request)
        .await
        .map_err(|failure| anyhow::anyhow!(failure.message))?;
    app_state
        .session_authorizations
        .bind_authenticated_peer_key(session_id, peer_public_key, bound_at_ms)
        .await
        .map_err(|failure| anyhow::anyhow!(failure.message))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn request_lan_remote_session_authorized(
    app_state: &Arc<AppState>,
    target_device_id: &DeviceId,
    session_id: &SessionId,
    transport_kind: &str,
    requested_profile: Option<MediaProfile>,
    access_mode: RemoteAccessMode,
    mut requested_scopes: Vec<RemotePermissionScope>,
    unattended_material: Option<LanUnattendedAccessMaterial>,
) -> Result<MediaProfileNegotiation> {
    requested_scopes.sort_unstable();
    requested_scopes.dedup();
    if requested_scopes.is_empty() {
        anyhow::bail!("secure LAN session requires at least one permission scope");
    }
    if app_state.sessions.lock().await.get(session_id).is_some() {
        anyhow::bail!("session id is already in use: {}", session_id.0);
    }
    let _session_reservation = app_state.lan_discovery.reserve_session(session_id)?;
    if app_state.sessions.lock().await.get(session_id).is_some() {
        anyhow::bail!("session id is already in use: {}", session_id.0);
    }
    let peer = app_state
        .lan_discovery
        .controllable_peer(target_device_id)
        .await
        .with_context(|| {
            format!(
                "LAN peer is not authenticated and trusted: {}",
                target_device_id.0
            )
        })?;
    let peer_key_id = peer
        .peer_key_id
        .clone()
        .context("trusted LAN peer has no key identifier")?;
    let peer_public_key = peer
        .public_key
        .clone()
        .context("trusted LAN peer has no public key")?;
    let peer_key_epoch = peer
        .key_epoch
        .context("trusted LAN peer has no key epoch")?;
    let fresh_trust =
        resolve_authenticated_peer_trust(app_state, &peer_key_id, &peer_public_key, peer_key_epoch)
            .await?;
    if !fresh_trust.is_controllable() {
        anyhow::bail!("LAN peer trust is no longer active: {peer_key_id}");
    }
    let target = peer.control_addr();
    let peer_transports = peer.transports.clone();
    let peer_media_capabilities = peer.media_capabilities_with_transports();
    ensure_peer_supports_requested_media(
        target_device_id,
        transport_kind,
        &peer_transports,
        requested_profile.as_ref(),
        &peer_media_capabilities,
    )?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN remote request UDP socket")?;
    socket
        .connect(target)
        .await
        .with_context(|| format!("failed to bind LAN request socket to trusted peer {target}"))?;
    let source_endpoint = socket
        .local_addr()
        .context("failed to read signed LAN request source endpoint")?;

    let (source_device_id, source_device_name) = {
        let devices = app_state.devices.lock().await;
        devices
            .get_local_device()
            .map(|(id, name)| (id.0.clone(), name.clone()))
            .context("local device is not registered")?
    };

    let local_identity = app_state.device_identities.machine_identity();
    let local_key_epoch = app_state
        .device_identities
        .machine_key_epoch()
        .context("local machine key epoch is unavailable")?;
    let request_issued_at_ms = now_ms();
    let request_expires_at_ms = request_issued_at_ms.saturating_add(30_000);
    let request_nonce = new_signed_nonce()?;
    let source_media_capabilities = lan_media_capabilities();
    let mut request_payload = LanSessionRequest {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        source_device_name,
        source_key_id: local_identity.key_id().to_string(),
        source_key_epoch: local_key_epoch,
        target_device_id: target_device_id.0.clone(),
        target_key_id: peer_key_id.clone(),
        target_key_epoch: peer_key_epoch,
        transport_kind: transport_kind.to_string(),
        source_discovery_port: Some(app_state.lan_discovery.discovery_port()),
        source_endpoint,
        source_media_capabilities,
        requested_media_profile: requested_profile,
        access_mode,
        requested_scopes: requested_scopes.clone(),
        unattended_proof: None,
        timestamp_ms: request_issued_at_ms,
        expires_at_ms: request_expires_at_ms,
        nonce: request_nonce,
    };
    if access_mode == RemoteAccessMode::Unattended {
        if let Some(material) = unattended_material {
            request_payload.unattended_proof = Some(LanUnattendedProof {
                access_epoch: material.access_epoch,
                proof: Vec::new(),
            });
            let transcript = unattended_transcript_bytes(&request_payload)?;
            request_payload
                .unattended_proof
                .as_mut()
                .expect("unattended proof metadata was just installed")
                .proof = material.credential.prove(&transcript, request_nonce);
        }
    }
    let signed_request = SignedLanSessionRequest::sign(local_identity.as_ref(), request_payload)?;

    // Serialize the final trust and legacy-session checks with authorization
    // insertion. Whichever admission wins the gate prevents a second aggregate
    // with the same session id from appearing.
    begin_outgoing_authorization_under_security_gate(
        app_state,
        session_id,
        &peer_key_id,
        &peer_public_key,
        peer_key_epoch,
        crate::session_authorization::VerifiedIncomingAuthorizationRequest {
            session_id: session_id.clone(),
            peer_device_id: target_device_id.clone(),
            peer_key_id: peer_key_id.clone(),
            peer_key_epoch,
            access_mode,
            requested_scopes: requested_scopes.clone(),
            peer_permission_ceiling: requested_scopes.clone(),
            machine_permission_ceiling: requested_scopes.clone(),
            runtime_capabilities: requested_scopes,
            transport_kind: transport_kind.to_string(),
            request_nonce,
            created_at_ms: request_issued_at_ms,
            expires_at_ms: request_expires_at_ms,
        },
    )
    .await?;

    let packet = LanDiscoveryPacket::SignedRemoteSessionRequest(signed_request.clone());
    let bytes = serde_json::to_vec(&packet)?;
    let local_addr = socket
        .local_addr()
        .context("failed to inspect LAN remote request UDP socket")?;
    socket.send(&bytes).await.with_context(|| {
        format!("failed to send LAN remote request from {local_addr} to {target}")
    })?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let len = timeout(LAN_REMOTE_SESSION_ACK_TIMEOUT, socket.recv(&mut buffer))
        .await
        .context("LAN remote request timed out")?
        .with_context(|| {
            format!("failed to receive LAN remote response on {local_addr} from {target}")
        })?;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::SignedRemoteSessionBootstrap(bootstrap) => {
            if let Err(error) = bootstrap.verify_for_request(
                now_ms(),
                &signed_request,
                &peer_public_key,
                peer_key_epoch,
            ) {
                if error == LanProtocolError::CertificateFingerprintMismatch {
                    let reason = remote_reason_code_wire_name(error.remote_reason_code());
                    if app_state
                        .audit_log
                        .record(
                            "session.authorization_decision",
                            "denied",
                            Some(session_id.clone()),
                            None,
                            Some(target_device_id.clone()),
                            Some(transport_kind.to_string()),
                            Some(reason),
                            Vec::new(),
                        )
                        .is_err()
                    {
                        app_state.mark_security_unhealthy();
                        anyhow::bail!(
                            "authoritative security audit is unavailable after certificate binding rejection"
                        );
                    }
                }
                return Err(error.into());
            }
            // Keep trust stable until the verified grant and connected receiver
            // are both committed. A concurrent revoke waits, then terminates
            // the now-visible authorization and media state before returning.
            let _issuance_guard = app_state.authorization_security_gate.lock().await;
            let final_trust = resolve_authenticated_peer_trust(
                app_state,
                &peer_key_id,
                &peer_public_key,
                peer_key_epoch,
            )
            .await?;
            if !final_trust.is_controllable() {
                anyhow::bail!("LAN peer trust changed during session bootstrap");
            }
            if bootstrap.payload.accepted {
                let current_authorization = app_state
                    .session_authorizations
                    .snapshot(session_id)
                    .await
                    .context("outgoing LAN authorization disappeared before grant install")?;
                if current_authorization.authorization_state
                    != RemoteAuthorizationState::Authorizing
                {
                    anyhow::bail!(
                        "outgoing LAN authorization changed before grant install: {:?}",
                        current_authorization.authorization_state
                    );
                }
                let signed_grant = bootstrap
                    .payload
                    .grant
                    .as_ref()
                    .context("authorized LAN bootstrap omitted its signed grant")?;
                let controller_proof = LanQuicControllerProofMaterial {
                    controller_identity: local_identity.clone(),
                    controller_key_epoch: local_key_epoch,
                    grant_id: signed_grant.grant_id()?,
                    transport_fingerprint_sha256: signed_grant.payload.transport_fingerprint_sha256,
                };
                app_state
                    .session_authorizations
                    .install_verified_grant(verified_grant_projection(signed_grant)?, now_ms())
                    .await
                    .map_err(|failure| anyhow::anyhow!(failure.message))?;
                let negotiation = bootstrap
                    .payload
                    .media_profile
                    .clone()
                    .unwrap_or_else(default_media_profile_negotiation);
                if let Err(error) = start_lan_media_receiver(
                    app_state.clone(),
                    session_id.clone(),
                    transport_kind,
                    bootstrap.payload.media,
                    target.ip(),
                    target_device_id.clone(),
                    negotiation.clone(),
                    peer_media_capabilities,
                    controller_proof,
                )
                .await
                {
                    let _ = app_state
                        .session_authorizations
                        .record_failure(
                            session_id,
                            RemoteAuthorizationState::Revoked,
                            RemoteFailure {
                                code: RemoteReasonCode::RouteLost,
                                message: "authorized LAN receiver failed to start".to_string(),
                                suggested_action: Some("retry the LAN connection".to_string()),
                            },
                            now_ms(),
                        )
                        .await;
                    return Err(error);
                }
                Ok(negotiation)
            } else {
                let failure = bootstrap.payload.failure.clone().unwrap_or(RemoteFailure {
                    code: RemoteReasonCode::PolicyChanged,
                    message: bootstrap
                        .payload
                        .message
                        .clone()
                        .unwrap_or_else(|| "remote authorization was denied".to_string()),
                    suggested_action: None,
                });
                let _ = app_state
                    .session_authorizations
                    .record_failure(
                        session_id,
                        authorization_failure_state(failure.code),
                        failure.clone(),
                        now_ms(),
                    )
                    .await;
                anyhow::bail!(
                    "LAN peer rejected remote session [{}]: {}",
                    remote_reason_code_wire_name(failure.code),
                    failure.message
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN remote session response"),
    }
}

pub async fn request_lan_media_profile_update(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    requested_profile: MediaProfile,
) -> Result<MediaProfileNegotiation> {
    validate_media_profile(&requested_profile)?;
    let peer_device_id = {
        let sessions = app_state.sessions.lock().await;
        let snapshot = sessions
            .get(session_id)
            .with_context(|| format!("session not found: {}", session_id.0))?;
        snapshot
            .target_device_id
            .clone()
            .or_else(|| snapshot.source_device_id.clone())
            .with_context(|| format!("session has no remote peer: {}", session_id.0))?
    };
    let target = app_state
        .lan_discovery
        .peer_control_addr(&peer_device_id)
        .await
        .with_context(|| format!("LAN peer not found: {}", peer_device_id.0))?;
    let peer_transports = app_state
        .lan_discovery
        .peer_transports(&peer_device_id)
        .await
        .with_context(|| format!("LAN peer not found: {}", peer_device_id.0))?;
    let peer_media_capabilities = app_state
        .lan_discovery
        .peer_media_capabilities(&peer_device_id)
        .await
        .with_context(|| format!("LAN peer not found: {}", peer_device_id.0))?;
    ensure_peer_supports_requested_media(
        &peer_device_id,
        "quic",
        &peer_transports,
        Some(&requested_profile),
        &peer_media_capabilities,
    )?;

    let source_device_id = {
        let devices = app_state.devices.lock().await;
        devices
            .get_local_device()
            .map(|(id, _)| id.0.clone())
            .context("local device is not registered")?
    };

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN media profile update UDP socket")?;
    let packet = LanDiscoveryPacket::MediaProfileUpdate {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        requested_media_profile: requested_profile,
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .context("LAN media profile update timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::MediaProfileUpdateAck {
            magic,
            app_id,
            session_id: ack_session_id,
            accepted,
            message,
            media_profile,
            ..
        } if is_valid_discovery_packet(&magic, &app_id) && ack_session_id == session_id.0 => {
            if accepted {
                let negotiation =
                    media_profile.context("LAN peer accepted profile update without result")?;
                app_state
                    .media_profiles
                    .lock()
                    .await
                    .set(session_id.clone(), negotiation.clone());
                Ok(negotiation)
            } else {
                anyhow::bail!(
                    "LAN peer rejected media profile update: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN media profile update response"),
    }
}

pub async fn request_lan_capture_sources(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    include_previews: bool,
    limit: Option<u32>,
) -> Result<Vec<CaptureSource>> {
    let peer_device_id = session_remote_peer(app_state, session_id).await?;
    let target =
        peer_control_addr_with_capture_source_capability(app_state, &peer_device_id).await?;
    let source_device_id = local_device_id(app_state).await?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN capture sources request UDP socket")?;
    let packet = LanDiscoveryPacket::CaptureSourcesRequest {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        include_previews,
        limit,
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .context("LAN capture sources request timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::CaptureSourcesAck {
            magic,
            app_id,
            session_id: ack_session_id,
            accepted,
            message,
            sources,
            ..
        } if is_valid_discovery_packet(&magic, &app_id) && ack_session_id == session_id.0 => {
            if accepted {
                Ok(sources)
            } else {
                anyhow::bail!(
                    "LAN peer rejected capture source listing: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN capture sources response"),
    }
}

pub async fn request_lan_remote_device_power_action(
    app_state: &Arc<AppState>,
    target_device_id: &DeviceId,
    action: mrd_ipc::RemoteDevicePowerAction,
) -> Result<()> {
    let target =
        peer_control_addr_with_remote_power_capability(app_state, target_device_id).await?;
    let source_device_id = local_device_id(app_state).await?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN remote power UDP socket")?;
    let packet = LanDiscoveryPacket::RemoteDevicePowerAction {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        source_device_id,
        action: action.clone(),
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .context("LAN remote power request timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::RemoteDevicePowerActionAck {
            magic,
            app_id,
            device_id,
            action: ack_action,
            accepted,
            message,
            ..
        } if is_valid_discovery_packet(&magic, &app_id)
            && device_id == target_device_id.0
            && ack_action == action =>
        {
            if accepted {
                Ok(())
            } else {
                anyhow::bail!(
                    "LAN peer rejected remote power action: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN remote power response"),
    }
}

pub async fn request_lan_capture_source_select(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_id: String,
) -> Result<CaptureSourceSelection> {
    let peer_device_id = session_remote_peer(app_state, session_id).await?;
    let target =
        peer_control_addr_with_capture_source_capability(app_state, &peer_device_id).await?;
    let source_device_id = local_device_id(app_state).await?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN capture source select UDP socket")?;
    let packet = LanDiscoveryPacket::CaptureSourceSelect {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        source_id,
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .context("LAN capture source select timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::CaptureSourceSelectAck {
            magic,
            app_id,
            session_id: ack_session_id,
            accepted,
            message,
            selection,
            ..
        } if is_valid_discovery_packet(&magic, &app_id) && ack_session_id == session_id.0 => {
            if accepted {
                let selection =
                    selection.context("LAN peer accepted capture source without selection")?;
                close_existing_display_lan_receiver_sessions_for_target(
                    app_state,
                    session_id,
                    &selection.source,
                )
                .await;
                store_capture_source_selection(app_state, session_id, selection.clone()).await;
                Ok(selection)
            } else {
                anyhow::bail!(
                    "LAN peer rejected capture source select: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN capture source select response"),
    }
}

pub async fn request_lan_display_modes(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_id: Option<String>,
) -> Result<Vec<DisplayMode>> {
    let peer_device_id = session_remote_peer(app_state, session_id).await?;
    let target = peer_control_addr_with_display_mode_capability(app_state, &peer_device_id).await?;
    let source_device_id = local_device_id(app_state).await?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN display modes request UDP socket")?;
    let packet = LanDiscoveryPacket::DisplayModesRequest {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        source_id,
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .context("LAN display modes request timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::DisplayModesAck {
            magic,
            app_id,
            session_id: ack_session_id,
            accepted,
            message,
            modes,
            ..
        } if is_valid_discovery_packet(&magic, &app_id) && ack_session_id == session_id.0 => {
            if accepted {
                Ok(modes)
            } else {
                anyhow::bail!(
                    "LAN peer rejected display mode listing: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN display modes response"),
    }
}

pub async fn request_lan_display_mode_set(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    mode: DisplayMode,
    restore_after_session: bool,
) -> Result<DisplayModeChange> {
    let peer_device_id = session_remote_peer(app_state, session_id).await?;
    let target = peer_control_addr_with_display_mode_capability(app_state, &peer_device_id).await?;
    let source_device_id = local_device_id(app_state).await?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN display mode set UDP socket")?;
    let packet = LanDiscoveryPacket::DisplayModeSet {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        mode,
        restore_after_session,
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(4), socket.recv_from(&mut buffer))
        .await
        .context("LAN display mode set timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::DisplayModeSetAck {
            magic,
            app_id,
            session_id: ack_session_id,
            accepted,
            message,
            change,
            ..
        } if is_valid_discovery_packet(&magic, &app_id) && ack_session_id == session_id.0 => {
            if accepted {
                let change = change.context("LAN peer accepted display mode set without change")?;
                record_remote_display_mode_change(app_state, session_id, &change).await;
                Ok(change)
            } else {
                anyhow::bail!(
                    "LAN peer rejected display mode set: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN display mode set response"),
    }
}

pub async fn request_lan_display_mode_restore(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) -> Result<DisplayModeChange> {
    let peer_device_id = session_remote_peer(app_state, session_id).await?;
    let target = peer_control_addr_with_display_mode_capability(app_state, &peer_device_id).await?;
    let source_device_id = local_device_id(app_state).await?;

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN display mode restore UDP socket")?;
    let packet = LanDiscoveryPacket::DisplayModeRestore {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        timestamp_ms: now_ms(),
    };
    send_packet(&socket, &packet, target).await?;

    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(4), socket.recv_from(&mut buffer))
        .await
        .context("LAN display mode restore timed out")??;
    let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
    match ack {
        LanDiscoveryPacket::DisplayModeRestoreAck {
            magic,
            app_id,
            session_id: ack_session_id,
            accepted,
            message,
            change,
            ..
        } if is_valid_discovery_packet(&magic, &app_id) && ack_session_id == session_id.0 => {
            if accepted {
                let change =
                    change.context("LAN peer accepted display mode restore without change")?;
                clear_remote_display_mode_change(app_state, session_id).await;
                Ok(change)
            } else {
                anyhow::bail!(
                    "LAN peer rejected display mode restore: {}",
                    message.unwrap_or_else(|| "unknown reason".to_string())
                );
            }
        }
        _ => anyhow::bail!("unexpected LAN display mode restore response"),
    }
}

async fn record_remote_display_mode_change(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    change: &DisplayModeChange,
) {
    let Some(active) = change.active.as_ref() else {
        return;
    };
    let requested = change.requested.clone().unwrap_or_else(|| active.clone());
    app_state.display_modes.lock().await.record_change(
        session_id.clone(),
        requested,
        change.previous.clone(),
        active.clone(),
        change.restore_required,
    );
    reconcile_media_profile_to_display_mode(app_state, session_id, active).await;
}

async fn clear_remote_display_mode_change(app_state: &Arc<AppState>, session_id: &SessionId) {
    app_state.display_modes.lock().await.remove(session_id);
    let selection = app_state.capture_sources.lock().await.get(session_id);
    if let Some(selection) = selection {
        reconcile_media_profile_to_capture_source(app_state, session_id, &selection.source).await;
    }
}

async fn announce_loop(socket: Arc<UdpSocket>, app_state: Arc<AppState>) {
    let mut ticker = interval(app_state.lan_discovery.config.announce_interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let discovery_port = app_state.lan_discovery.discovery_port();
                if let Err(error) = send_probe(&socket, discovery_port, &app_state.lan_discovery).await {
                    tracing::warn!(%error, "failed to send periodic LAN discovery probe");
                }
                app_state.lan_discovery.prune_stale_peers().await;
            }
            _ = app_state.lan_discovery.probe_requested.notified() => {
                if let Err(error) = send_probe(&socket, app_state.lan_discovery.discovery_port(), &app_state.lan_discovery).await {
                    tracing::warn!(%error, "failed to send LAN discovery probe");
                }
            }
        }
    }
}

async fn receive_loop(socket: Arc<UdpSocket>, app_state: Arc<AppState>) {
    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, addr)) => {
                if buffer[..len].starts_with(AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX) {
                    let Some(admission_permit) = app_state
                        .lan_discovery
                        .try_admit_authenticated_control(addr.ip(), now_ms())
                        .await
                    else {
                        tracing::warn!(%addr, "dropped rate-limited authenticated control input");
                        continue;
                    };
                    let request_socket = socket.clone();
                    let request_state = app_state.clone();
                    let packet = buffer[..len].to_vec();
                    tokio::spawn(async move {
                        let _admission_permit = admission_permit;
                        if let Err(error) = process_lan_discovery_packet(
                            request_socket.as_ref(),
                            &request_state,
                            &packet,
                            addr,
                        )
                        .await
                        {
                            tracing::debug!(%error, %addr, "ignored authenticated control input");
                        }
                    });
                    continue;
                }
                if let Ok(LanDiscoveryPacket::SignedRemoteSessionRequest(request)) =
                    serde_json::from_slice::<LanDiscoveryPacket>(&buffer[..len])
                {
                    let Some(admission_permit) = app_state
                        .lan_discovery
                        .try_admit_incoming_authorization(addr.ip(), now_ms())
                        .await
                    else {
                        tracing::warn!(%addr, "dropped rate-limited LAN authorization request");
                        continue;
                    };
                    let request_socket = socket.clone();
                    let request_state = app_state.clone();
                    tokio::spawn(async move {
                        let _admission_permit = admission_permit;
                        if let Err(error) = handle_signed_remote_session_request(
                            request_socket.as_ref(),
                            &request_state,
                            request,
                            addr,
                        )
                        .await
                        {
                            tracing::debug!(%error, %addr, "ignored signed LAN session request");
                        }
                    });
                    continue;
                }
                if let Err(error) =
                    process_lan_discovery_packet(&socket, &app_state, &buffer[..len], addr).await
                {
                    tracing::debug!(%error, %addr, "ignored LAN discovery packet");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "LAN discovery UDP receive failed");
            }
        }
    }
}

pub async fn process_lan_discovery_packet(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    bytes: &[u8],
    addr: SocketAddr,
) -> Result<()> {
    if let Some(envelope_bytes) = bytes.strip_prefix(AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX) {
        return process_authenticated_control_input_datagram(
            socket,
            app_state,
            envelope_bytes,
            addr,
        )
        .await;
    }
    handle_packet(socket, app_state, bytes, addr).await
}

async fn handle_packet(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    bytes: &[u8],
    addr: SocketAddr,
) -> Result<()> {
    let packet: LanDiscoveryPacket = serde_json::from_slice(bytes)?;
    match packet {
        LanDiscoveryPacket::Probe {
            magic,
            app_id,
            instance_id,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }
            let discovery_endpoint =
                routed_discovery_endpoint(addr, app_state.lan_discovery.discovery_port())?;
            if let Some(announcement) = build_announcement(app_state, discovery_endpoint).await {
                send_packet(
                    socket,
                    &LanDiscoveryPacket::SignedAnnounce(announcement),
                    addr,
                )
                .await?;
            }
        }
        LanDiscoveryPacket::Announce(announcement) => {
            ingest_legacy_lan_announcement(app_state, announcement, addr, now_ms()).await?;
        }
        LanDiscoveryPacket::SignedAnnounce(announcement) => {
            ingest_signed_lan_announcement(app_state, announcement, addr, now_ms()).await?;
        }
        LanDiscoveryPacket::RemoteSessionRequest { .. } => {
            tracing::debug!(%addr, "ignored unsigned legacy LAN session request");
        }
        LanDiscoveryPacket::SignedRemoteSessionRequest(request) => {
            handle_signed_remote_session_request(socket, app_state, request, addr).await?;
        }
        LanDiscoveryPacket::RemoteSessionAck { .. }
        | LanDiscoveryPacket::SignedRemoteSessionBootstrap(_) => {}
        LanDiscoveryPacket::MediaProfileUpdate {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            requested_media_profile,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let session_id = SessionId(session_id);
            let update_result =
                accept_lan_media_profile_update(app_state, &session_id, requested_media_profile)
                    .await;
            let (accepted, message, media_profile) = match update_result {
                Ok(negotiation) => (true, Some("updated".to_string()), Some(negotiation)),
                Err(error) => (false, Some(error.to_string()), None),
            };
            tracing::info!(
                session_id = %session_id.0,
                source_device_id = %source_device_id,
                accepted,
                "handled LAN media profile update"
            );
            let ack = LanDiscoveryPacket::MediaProfileUpdateAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                session_id: session_id.0,
                accepted,
                message,
                media_profile,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::MediaProfileUpdateAck { .. } => {}
        LanDiscoveryPacket::CaptureSourcesRequest {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            include_previews,
            limit,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let sources_result = accept_lan_capture_sources_request(
                app_state,
                &SessionId(session_id.clone()),
                include_previews,
                limit,
            )
            .await;
            let (accepted, message, sources) = match sources_result {
                Ok(sources) => (true, Some("listed".to_string()), sources),
                Err(error) => (false, Some(error.to_string()), Vec::new()),
            };
            tracing::info!(
                session_id = %session_id,
                source_device_id = %source_device_id,
                accepted,
                "handled LAN capture sources request"
            );
            let ack = capture_sources::fit_capture_sources_ack_packet(
                app_state.lan_discovery.instance_id.clone(),
                session_id,
                accepted,
                message,
                sources,
            );
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::CaptureSourcesAck { .. } => {}
        LanDiscoveryPacket::CaptureSourceSelect {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            source_id,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let session_id = SessionId(session_id);
            let select_result =
                accept_lan_capture_source_select(app_state, &session_id, &source_id).await;
            let (accepted, message, selection) = match select_result {
                Ok(selection) => (true, Some("selected".to_string()), Some(selection)),
                Err(error) => (false, Some(error.to_string()), None),
            };
            tracing::info!(
                session_id = %session_id.0,
                source_device_id = %source_device_id,
                accepted,
                "handled LAN capture source select"
            );
            let ack = LanDiscoveryPacket::CaptureSourceSelectAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                session_id: session_id.0,
                accepted,
                message,
                selection,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::CaptureSourceSelectAck { .. } => {}
        LanDiscoveryPacket::DisplayModesRequest {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            source_id,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let session_id_value = SessionId(session_id.clone());
            let modes_result =
                accept_lan_display_modes_request(app_state, &session_id_value, source_id).await;
            let (accepted, message, modes) = match modes_result {
                Ok(modes) => (true, Some("listed".to_string()), modes),
                Err(error) => (false, Some(error.to_string()), Vec::new()),
            };
            tracing::info!(
                session_id = %session_id,
                source_device_id = %source_device_id,
                accepted,
                "handled LAN display modes request"
            );
            let ack = LanDiscoveryPacket::DisplayModesAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                session_id,
                accepted,
                message,
                modes,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::DisplayModesAck { .. } => {}
        LanDiscoveryPacket::DisplayModeSet {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            mode,
            restore_after_session,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let session_id_value = SessionId(session_id.clone());
            let set_result = accept_lan_display_mode_set(
                app_state,
                &session_id_value,
                mode,
                restore_after_session,
            )
            .await;
            let (accepted, message, change) = match set_result {
                Ok(change) => (true, Some("changed".to_string()), Some(change)),
                Err(error) => (false, Some(error.to_string()), None),
            };
            tracing::info!(
                session_id = %session_id,
                source_device_id = %source_device_id,
                accepted,
                "handled LAN display mode set"
            );
            let ack = LanDiscoveryPacket::DisplayModeSetAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                session_id,
                accepted,
                message,
                change,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::DisplayModeSetAck { .. } => {}
        LanDiscoveryPacket::DisplayModeRestore {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let session_id_value = SessionId(session_id.clone());
            let restore_result =
                accept_lan_display_mode_restore(app_state, &session_id_value).await;
            let (accepted, message, change) = match restore_result {
                Ok(change) => (true, Some("restored".to_string()), Some(change)),
                Err(error) => (false, Some(error.to_string()), None),
            };
            tracing::info!(
                session_id = %session_id,
                source_device_id = %source_device_id,
                accepted,
                "handled LAN display mode restore"
            );
            let ack = LanDiscoveryPacket::DisplayModeRestoreAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                session_id,
                accepted,
                message,
                change,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::DisplayModeRestoreAck { .. } => {}
        LanDiscoveryPacket::ControlInput {
            magic,
            app_id,
            instance_id,
            session_id,
            source_device_id,
            event_id,
            event,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let session_id_value = SessionId(session_id.clone());
            let ack_state = accept_or_replay_lan_control_input(
                app_state,
                &session_id_value,
                &source_device_id,
                event_id,
                &event,
            )
            .await;
            tracing::debug!(
                session_id = %session_id,
                source_device_id = %source_device_id,
                accepted = ack_state.accepted,
                "handled LAN control input"
            );
            let ack = LanDiscoveryPacket::ControlInputAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                session_id,
                event_id,
                accepted: ack_state.accepted,
                message: ack_state.message,
                lane: ack_state.lane,
                event_count: ack_state.event_count,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::ControlInputAck { .. } => {}
        LanDiscoveryPacket::RemoteDevicePowerAction {
            magic,
            app_id,
            instance_id,
            source_device_id,
            action,
            ..
        } => {
            if !is_valid_discovery_packet(&magic, &app_id)
                || instance_id == app_state.lan_discovery.instance_id()
            {
                return Ok(());
            }

            let local_device_id = local_device_id(app_state).await?;
            let action_result = accept_lan_remote_device_power_action(&action);
            let (accepted, message) = match action_result {
                Ok(()) => (true, Some("accepted".to_string())),
                Err(error) => (false, Some(error.to_string())),
            };
            tracing::warn!(
                source_device_id = %source_device_id,
                local_device_id = %local_device_id,
                action = ?action,
                accepted,
                "rejected legacy unsigned LAN remote device power action"
            );
            let ack = LanDiscoveryPacket::RemoteDevicePowerActionAck {
                magic: DISCOVERY_MAGIC.to_string(),
                app_id: DISCOVERY_APP_ID.to_string(),
                instance_id: app_state.lan_discovery.instance_id.clone(),
                device_id: local_device_id,
                action,
                accepted,
                message,
                timestamp_ms: now_ms(),
            };
            send_packet(socket, &ack, addr).await?;
        }
        LanDiscoveryPacket::RemoteDevicePowerActionAck { .. } => {}
    }

    Ok(())
}

async fn handle_signed_remote_session_request(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    request: SignedLanSessionRequest,
    addr: SocketAddr,
) -> Result<()> {
    let received_at_ms = now_ms();
    let local_key_id = app_state
        .device_identities
        .machine_key_id()
        .context("local machine signing key is unavailable")?
        .to_string();
    let local_key_epoch = app_state
        .device_identities
        .machine_key_epoch()
        .context("local machine key epoch is unavailable")?;
    request.verify_for_target(received_at_ms, &local_key_id, local_key_epoch)?;
    if request.payload.source_endpoint != addr {
        anyhow::bail!(
            "signed LAN session request source endpoint does not match UDP source: signed={}, observed={addr}",
            request.payload.source_endpoint
        );
    }
    if request.payload.instance_id == app_state.lan_discovery.instance_id() {
        anyhow::bail!("self-originated signed LAN session request");
    }
    let local_device_id = {
        let devices = app_state.devices.lock().await;
        devices
            .get_local_device()
            .map(|(device_id, _)| device_id.0.clone())
            .context("local device is not registered")?
    };
    if request.payload.target_device_id != local_device_id {
        anyhow::bail!("signed LAN session request targets another device");
    }
    // Reject plainly untrusted keys before entering the authorization security
    // gate. A second lookup under the gate below closes the trust-transition
    // race for peers that passed this inexpensive initial admission check.
    let initial_trust = resolve_authenticated_peer_trust(
        app_state,
        &request.payload.source_key_id,
        &request.public_key,
        request.payload.source_key_epoch,
    )
    .await?;
    if !initial_trust.is_controllable() {
        return audit_and_send_signed_lan_pre_authorization_denial(
            socket,
            app_state,
            &request,
            addr,
            RemoteFailure {
                code: RemoteReasonCode::TrustRequired,
                message: "the authenticated controller key is not trusted".to_string(),
                suggested_action: Some("approve the controller device locally".to_string()),
            },
        )
        .await;
    }
    if app_state
        .lan_discovery
        .signed_replays
        .lock()
        .await
        .accept(
            LanSignedReplayDomain::SessionRequest,
            &request.payload.source_key_id,
            request.payload.nonce,
            request.payload.expires_at_ms,
            received_at_ms,
        )
        .is_err()
    {
        return audit_and_send_signed_lan_pre_authorization_denial(
            socket,
            app_state,
            &request,
            addr,
            RemoteFailure {
                code: RemoteReasonCode::ReplayDetected,
                message: "the signed LAN session request was already used".to_string(),
                suggested_action: Some("start a new session request".to_string()),
            },
        )
        .await;
    }

    // Pair the final trust check with record insertion. If a trust transition
    // wins first this request is denied; if admission wins first the transition
    // sees and revokes the newly inserted record.
    let admission_guard = app_state.authorization_security_gate.lock().await;
    let admission_trust = resolve_authenticated_peer_trust(
        app_state,
        &request.payload.source_key_id,
        &request.public_key,
        request.payload.source_key_epoch,
    )
    .await?;
    if !admission_trust.is_controllable() {
        drop(admission_guard);
        return audit_and_send_signed_lan_pre_authorization_denial(
            socket,
            app_state,
            &request,
            addr,
            RemoteFailure {
                code: RemoteReasonCode::TrustRequired,
                message: "the authenticated controller trust changed before admission".to_string(),
                suggested_action: Some("approve the controller device locally".to_string()),
            },
        )
        .await;
    }

    let session_id = SessionId(request.payload.session_id.clone());
    let _session_reservation = app_state.lan_discovery.reserve_session(&session_id)?;
    if app_state.sessions.lock().await.get(&session_id).is_some() {
        anyhow::bail!("signed LAN session id is already in use");
    }

    let input_control_available =
        app_state.security_is_healthy() && app_state.control_input().lock().await.is_available();
    let authorization_capabilities =
        lan_authorization_capabilities_with_input_control(input_control_available);
    let _pending_authorization = match app_state
        .session_authorizations
        .begin_verified_incoming(
            crate::session_authorization::VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: DeviceId(request.payload.source_device_id.clone()),
                peer_key_id: request.payload.source_key_id.clone(),
                peer_key_epoch: request.payload.source_key_epoch,
                access_mode: request.payload.access_mode,
                requested_scopes: request.payload.requested_scopes.clone(),
                peer_permission_ceiling: authorization_capabilities.clone(),
                machine_permission_ceiling: authorization_capabilities.clone(),
                runtime_capabilities: authorization_capabilities,
                transport_kind: request.payload.transport_kind.clone(),
                request_nonce: request.payload.nonce,
                created_at_ms: received_at_ms,
                expires_at_ms: request.payload.expires_at_ms,
            },
        )
        .await
    {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            drop(admission_guard);
            return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                .await;
        }
    };
    if let Err(failure) = app_state
        .session_authorizations
        .bind_authenticated_peer_key(&session_id, &request.public_key, received_at_ms)
        .await
    {
        let _ = app_state
            .session_authorizations
            .record_failure(
                &session_id,
                RemoteAuthorizationState::PolicyChanged,
                failure.clone(),
                received_at_ms,
            )
            .await;
        drop(admission_guard);
        return send_signed_lan_session_denial(socket, app_state, &request, addr, failure).await;
    }
    drop(admission_guard);
    let post_admission_result: Result<()> = async {
        ensure_admitted_request_is_live(&request, now_ms())?;
        if app_state
            .audit_log
            .record(
                "session.authorization_requested",
                "pending",
                Some(session_id.clone()),
                None,
                Some(DeviceId(request.payload.source_device_id.clone())),
                Some(request.payload.transport_kind.clone()),
                None,
                vec![(
                    "requested_scope_count".to_string(),
                    request.payload.requested_scopes.len().to_string(),
                )],
            )
            .is_err()
        {
            app_state.mark_security_unhealthy();
            let failure = RemoteFailure {
                code: RemoteReasonCode::PolicyChanged,
                message: "authorization request could not be durably audited".to_string(),
                suggested_action: Some("repair the local security store".to_string()),
            };
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    RemoteAuthorizationState::PolicyChanged,
                    failure.clone(),
                    now_ms(),
                )
                .await;
            return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                .await;
        }

        let authorization = match request.payload.access_mode {
            RemoteAccessMode::Attended => {
                app_state
                    .session_authorizations
                    .wait_for_authorization_decision(&session_id)
                    .await
            }
            RemoteAccessMode::Unattended => match request.payload.unattended_proof.as_ref() {
                None => Err(RemoteFailure {
                    code: RemoteReasonCode::CredentialInvalid,
                    message: "unattended access requires a transcript-bound proof".to_string(),
                    suggested_action: Some(
                        "use attended access or enroll a credential".to_string(),
                    ),
                }),
                Some(proof) => {
                    let transcript = unattended_transcript_bytes(&request.payload)?;
                    app_state
                        .session_authorizations
                        .verify_unattended(
                            &session_id,
                            &transcript,
                            request.payload.nonce,
                            proof.access_epoch,
                            &proof.proof,
                            now_ms(),
                        )
                        .await
                }
            },
        };
        let _authorization = match authorization {
            Ok(snapshot) => snapshot,
            Err(failure) => {
                let terminal_state = authorization_failure_state(failure.code);
                if app_state
                    .audit_log
                    .record(
                        "session.authorization_decision",
                        "denied",
                        Some(session_id.clone()),
                        None,
                        Some(DeviceId(request.payload.source_device_id.clone())),
                        Some(request.payload.transport_kind.clone()),
                        Some(remote_reason_code_wire_name(failure.code)),
                        Vec::new(),
                    )
                    .is_err()
                {
                    app_state.mark_security_unhealthy();
                }
                let _ = app_state
                    .session_authorizations
                    .record_failure(&session_id, terminal_state, failure.clone(), now_ms())
                    .await;
                return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                    .await;
            }
        };
        ensure_admitted_request_is_live(&request, now_ms())?;

        // Freeze trust and unattended-policy transitions until the grant, signed
        // bootstrap, and sender session are all committed. Any transition that
        // follows will revoke and tear down the fully visible session.
        let issuance_guard = app_state.authorization_security_gate.lock().await;
        let final_trust = resolve_authenticated_peer_trust(
            app_state,
            &request.payload.source_key_id,
            &request.public_key,
            request.payload.source_key_epoch,
        )
        .await?;
        if !final_trust.is_controllable() {
            let failure = RemoteFailure {
                code: RemoteReasonCode::TrustRequired,
                message: "controller trust changed while awaiting authorization".to_string(),
                suggested_action: None,
            };
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    RemoteAuthorizationState::Revoked,
                    failure.clone(),
                    now_ms(),
                )
                .await;
            drop(issuance_guard);
            return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                .await;
        }

        let authorization = match app_state.session_authorizations.snapshot(&session_id).await {
            Some(snapshot)
                if snapshot.authorization_state == RemoteAuthorizationState::Authorizing =>
            {
                snapshot
            }
            Some(snapshot) => {
                let failure = snapshot.failure.unwrap_or(RemoteFailure {
                    code: RemoteReasonCode::PolicyChanged,
                    message: "authorization changed before grant issuance".to_string(),
                    suggested_action: Some("start a new attended session".to_string()),
                });
                let _ = app_state
                    .session_authorizations
                    .record_failure(
                        &session_id,
                        post_consent_failure_state(failure.code),
                        failure.clone(),
                        now_ms(),
                    )
                    .await;
                drop(issuance_guard);
                return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                    .await;
            }
            None => {
                drop(issuance_guard);
                return send_signed_lan_session_denial(
                    socket,
                    app_state,
                    &request,
                    addr,
                    RemoteFailure {
                        code: RemoteReasonCode::PolicyChanged,
                        message: "authorization record disappeared before grant issuance"
                            .to_string(),
                        suggested_action: Some("start a new attended session".to_string()),
                    },
                )
                .await;
            }
        };

        let preparation = match prepare_lan_remote_session(
            app_state,
            session_id.clone(),
            DeviceId(request.payload.source_device_id.clone()),
            addr.ip(),
            request.payload.transport_kind.clone(),
            request.payload.source_media_capabilities.clone(),
            request.payload.requested_media_profile.clone(),
        )
        .await
        {
            Ok(preparation) => preparation,
            Err(message) => {
                let failure = RemoteFailure {
                    code: RemoteReasonCode::EncoderUnavailable,
                    message,
                    suggested_action: Some("choose a supported LAN media profile".to_string()),
                };
                let _ = app_state
                    .session_authorizations
                    .record_failure(
                        &session_id,
                        RemoteAuthorizationState::Revoked,
                        failure.clone(),
                        now_ms(),
                    )
                    .await;
                return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                    .await;
            }
        };
        ensure_admitted_request_is_live(&request, now_ms())?;

        let transport_fingerprint_sha256 =
            preparation.prepared_server.certificate_fingerprint_sha256();
        let grant_issued_at_ms = now_ms();
        let identity = app_state.device_identities.machine_identity();
        let signed_grant = SignedLanSessionGrant::sign(
            identity.as_ref(),
            LanSessionGrantPayload {
                session_id: session_id.0.clone(),
                controller_key_id: request.payload.source_key_id.clone(),
                controller_key_epoch: request.payload.source_key_epoch,
                target_key_id: local_key_id.clone(),
                target_key_epoch: local_key_epoch,
                access_mode: request.payload.access_mode,
                granted_scopes: authorization.granted_scopes.clone(),
                issued_at_ms: grant_issued_at_ms,
                expires_at_ms: grant_issued_at_ms.saturating_add(300_000),
                policy_revision: authorization.policy_revision.get(),
                route_constraint: request.payload.transport_kind.clone(),
                profile_constraint: Some(media_profile_constraint_hash(&preparation.negotiation)?),
                request_nonce: request.payload.nonce,
                grant_nonce: new_signed_nonce()?,
                windows_session_id: None,
                transport_fingerprint_sha256,
            },
        )?;
        signed_grant.verify_for_request(
            grant_issued_at_ms,
            &request,
            identity.public_key(),
            local_key_epoch,
        )?;
        let controller_binding = LanQuicControllerBinding {
            controller_public_key: request.public_key.clone(),
            controller_key_epoch: request.payload.source_key_epoch,
            grant_id: signed_grant.grant_id()?,
            transport_fingerprint_sha256: signed_grant.payload.transport_fingerprint_sha256,
        };
        let verified_grant = verified_grant_projection(&signed_grant)?;
        if app_state
            .audit_log
            .record(
                "session.authorization_grant",
                "allowed",
                Some(session_id.clone()),
                None,
                Some(DeviceId(request.payload.source_device_id.clone())),
                Some(request.payload.transport_kind.clone()),
                None,
                vec![
                    ("grant_id".to_string(), verified_grant.grant_id.clone()),
                    (
                        "granted_scope_count".to_string(),
                        verified_grant.granted_scopes.len().to_string(),
                    ),
                ],
            )
            .is_err()
        {
            app_state.mark_security_unhealthy();
            let failure = RemoteFailure {
                code: RemoteReasonCode::PolicyChanged,
                message: "authorization grant could not be durably audited".to_string(),
                suggested_action: Some("repair the local security store".to_string()),
            };
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    RemoteAuthorizationState::Revoked,
                    failure.clone(),
                    now_ms(),
                )
                .await;
            return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                .await;
        }
        if let Err(failure) = app_state
            .session_authorizations
            .install_verified_grant(verified_grant, grant_issued_at_ms)
            .await
        {
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    post_consent_failure_state(failure.code),
                    failure.clone(),
                    now_ms(),
                )
                .await;
            drop(issuance_guard);
            return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                .await;
        }

        let accept_result = bind_prepared_lan_remote_session(preparation).await;
        let LanRemoteAcceptResult {
            accepted,
            message,
            media,
            media_profile,
            prepared,
        } = accept_result;

        if !accepted {
            let failure = RemoteFailure {
                code: RemoteReasonCode::LanUnreachable,
                message: message
                    .unwrap_or_else(|| "failed to bind authorized LAN route".to_string()),
                suggested_action: Some("retry the LAN connection".to_string()),
            };
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    RemoteAuthorizationState::Revoked,
                    failure.clone(),
                    now_ms(),
                )
                .await;
            return send_signed_lan_session_denial(socket, app_state, &request, addr, failure)
                .await;
        }
        ensure_admitted_request_is_live(&request, now_ms())?;

        let bootstrap_issued_at_ms = now_ms();
        let bootstrap = LanSessionBootstrap {
            magic: DISCOVERY_MAGIC.to_string(),
            app_id: DISCOVERY_APP_ID.to_string(),
            protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
            instance_id: app_state.lan_discovery.instance_id.clone(),
            session_id: request.payload.session_id.clone(),
            controller_key_id: request.payload.source_key_id.clone(),
            controller_key_epoch: request.payload.source_key_epoch,
            target_key_id: local_key_id,
            target_key_epoch: local_key_epoch,
            request_nonce: request.payload.nonce,
            accepted: true,
            message: Some("accepted".to_string()),
            failure: None,
            grant: Some(signed_grant),
            media,
            media_profile,
            timestamp_ms: bootstrap_issued_at_ms,
            expires_at_ms: bootstrap_issued_at_ms.saturating_add(5_000),
            nonce: new_signed_nonce()?,
        };
        let signed = SignedLanSessionBootstrap::sign(identity.as_ref(), bootstrap)?;
        ensure_admitted_request_is_live(&request, now_ms())?;
        if let Err(error) = send_packet(
            socket,
            &LanDiscoveryPacket::SignedRemoteSessionBootstrap(signed),
            addr,
        )
        .await
        {
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    RemoteAuthorizationState::Revoked,
                    RemoteFailure {
                        code: RemoteReasonCode::RouteLost,
                        message: "failed to send authorized LAN bootstrap".to_string(),
                        suggested_action: Some("retry the LAN connection".to_string()),
                    },
                    now_ms(),
                )
                .await;
            return Err(error);
        }
        if let Some(mut prepared) = prepared {
            prepared.controller_binding = Some(controller_binding);
            if let Err(error) = commit_prepared_lan_remote_session(app_state, prepared).await {
                let _ = app_state
                    .session_authorizations
                    .record_failure(
                        &session_id,
                        RemoteAuthorizationState::Revoked,
                        RemoteFailure {
                            code: RemoteReasonCode::RouteLost,
                            message: "authorized LAN sender failed to commit".to_string(),
                            suggested_action: Some("retry the LAN connection".to_string()),
                        },
                        now_ms(),
                    )
                    .await;
                return Err(error);
            }
        }
        Ok(())
    }
    .await;
    match post_admission_result {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(
                session_id = %session_id.0,
                %error,
                "finalizing failed signed LAN session after authorization admission"
            );
            match finalize_post_admission_error(
                socket,
                app_state,
                &request,
                addr,
                &session_id,
                &error,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(denial_error) => Err(error.context(format!(
                    "failed to finalize signed LAN session denial: {denial_error}"
                ))),
            }
        }
    }
}

fn ensure_admitted_request_is_live(
    request: &SignedLanSessionRequest,
    checked_at_ms: u64,
) -> Result<()> {
    if checked_at_ms > request.payload.expires_at_ms {
        anyhow::bail!("signed LAN authorization request expired after admission");
    }
    Ok(())
}

async fn finalize_post_admission_error(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    request: &SignedLanSessionRequest,
    addr: SocketAddr,
    session_id: &SessionId,
    error: &anyhow::Error,
) -> Result<()> {
    let failed_at_ms = now_ms();
    let current = app_state.session_authorizations.snapshot(session_id).await;
    let existing_terminal_failure = current.as_ref().and_then(|snapshot| {
        matches!(
            snapshot.authorization_state,
            RemoteAuthorizationState::Denied
                | RemoteAuthorizationState::Expired
                | RemoteAuthorizationState::Revoked
                | RemoteAuthorizationState::LockedOut
                | RemoteAuthorizationState::PolicyChanged
        )
        .then(|| snapshot.failure.clone())
        .flatten()
    });
    let (terminal_state, fallback_failure) = post_admission_failure_for_error(
        error,
        failed_at_ms > request.payload.expires_at_ms,
        current.as_ref().is_some_and(|snapshot| {
            matches!(
                snapshot.authorization_state,
                RemoteAuthorizationState::Authorizing | RemoteAuthorizationState::Granted
            )
        }),
    );

    let denial_failure = if let Some(existing) = existing_terminal_failure {
        existing
    } else {
        let recorded = app_state
            .session_authorizations
            .record_failure(
                session_id,
                terminal_state,
                fallback_failure.clone(),
                failed_at_ms,
            )
            .await;
        match recorded.and_then(|snapshot| snapshot.failure) {
            Some(failure) => failure,
            None => app_state
                .session_authorizations
                .snapshot(session_id)
                .await
                .and_then(|snapshot| snapshot.failure)
                .unwrap_or(fallback_failure),
        }
    };

    send_signed_lan_session_denial(socket, app_state, request, addr, denial_failure).await
}

fn post_admission_failure_for_error(
    error: &anyhow::Error,
    request_deadline_elapsed: bool,
    authorization_was_active: bool,
) -> (RemoteAuthorizationState, RemoteFailure) {
    let diagnostic = format!("{error:#}").to_ascii_lowercase();
    if request_deadline_elapsed || diagnostic.contains("expired after admission") {
        return (
            RemoteAuthorizationState::Expired,
            RemoteFailure {
                code: RemoteReasonCode::AuthorizationTimeout,
                message: "the LAN authorization request expired before bootstrap completed"
                    .to_string(),
                suggested_action: Some("start a new remote session request".to_string()),
            },
        );
    }

    let protocol_failure =
        LanProtocolError::remote_reason_code_from_diagnostic(&diagnostic).map(|code| match code {
            RemoteReasonCode::IdentityMismatch => (
                code,
                "authenticated LAN identity binding failed during grant issuance",
                "verify the paired device identity and retry",
            ),
            RemoteReasonCode::CertificateBindingMismatch => (
                code,
                "the LAN transport certificate no longer matches the signed grant",
                "verify the paired device identity and retry",
            ),
            RemoteReasonCode::ReplayDetected => (
                code,
                "the secure LAN request nonce was rejected during grant issuance",
                "start a new secure remote session request",
            ),
            _ => (
                RemoteReasonCode::ProtocolDowngradeBlocked,
                "the secure LAN grant or bootstrap could not be verified",
                "update both devices and retry the secure connection",
            ),
        });

    let (code, message, suggested_action) = if let Some(failure) = protocol_failure {
        failure
    } else if diagnostic.contains("trust") {
        (
            RemoteReasonCode::TrustRequired,
            "controller trust could not be confirmed before grant issuance",
            "approve the controller device locally and retry",
        )
    } else if diagnostic.contains("identity")
        || diagnostic.contains("public key")
        || diagnostic.contains("key epoch")
        || diagnostic.contains("fingerprint")
        || diagnostic.contains("certificate")
        || diagnostic.contains("invalid signature")
    {
        (
            RemoteReasonCode::IdentityMismatch,
            "authenticated LAN identity binding failed during grant issuance",
            "verify the paired device identity and retry",
        )
    } else if diagnostic.contains("media profile")
        || diagnostic.contains("profile constraint")
        || diagnostic.contains("codec")
    {
        (
            RemoteReasonCode::ProfileDowngraded,
            "the selected LAN media profile could not be bound to the grant",
            "choose a media profile supported by both devices",
        )
    } else if diagnostic.contains("encoder") {
        (
            RemoteReasonCode::EncoderUnavailable,
            "the authorized LAN media encoder is unavailable",
            "choose a supported LAN media profile",
        )
    } else if diagnostic.contains("decoder") {
        (
            RemoteReasonCode::DecoderUnavailable,
            "the authorized LAN media decoder is unavailable",
            "choose a supported LAN media profile",
        )
    } else if diagnostic.contains("route")
        || diagnostic.contains("listener")
        || diagnostic.contains("socket")
        || diagnostic.contains("send authorized lan bootstrap")
    {
        (
            RemoteReasonCode::RouteLost,
            "the authorized LAN route could not be committed",
            "retry the LAN connection",
        )
    } else if diagnostic.contains("protocol")
        || diagnostic.contains("signed")
        || diagnostic.contains("signing")
        || diagnostic.contains("signature")
        || diagnostic.contains("grant")
        || diagnostic.contains("bootstrap")
        || diagnostic.contains("nonce")
        || diagnostic.contains("payload")
    {
        (
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "the secure LAN grant or bootstrap could not be verified",
            "update both devices and retry the secure connection",
        )
    } else {
        (
            RemoteReasonCode::PolicyChanged,
            "the authenticated LAN authorization could not be completed",
            "retry after checking local security state",
        )
    };
    (
        if authorization_was_active {
            RemoteAuthorizationState::Revoked
        } else {
            RemoteAuthorizationState::PolicyChanged
        },
        RemoteFailure {
            code,
            message: message.to_string(),
            suggested_action: Some(suggested_action.to_string()),
        },
    )
}

#[cfg(test)]
fn lan_authorization_capabilities() -> Vec<RemotePermissionScope> {
    lan_authorization_capabilities_with_input_control(false)
}

#[cfg(test)]
fn test_lan_media_capabilities() -> Vec<String> {
    let mut capabilities = lan_media_capabilities();
    for capability in [
        "encode.nvenc_hevc".to_string(),
        LAN_MEDIA_HEVC_MAIN_420_8BIT_CAPABILITY.to_string(),
    ] {
        if !capabilities.iter().any(|existing| existing == &capability) {
            capabilities.push(capability);
        }
    }
    capabilities
}

fn lan_authorization_capabilities_with_input_control(
    input_control_available: bool,
) -> Vec<RemotePermissionScope> {
    let mut capabilities = vec![RemotePermissionScope::ScreenView];
    if input_control_available {
        capabilities.extend([
            RemotePermissionScope::InputPointer,
            RemotePermissionScope::InputKeyboard,
        ]);
    }
    capabilities
}

fn authorization_failure_state(code: RemoteReasonCode) -> RemoteAuthorizationState {
    match code {
        RemoteReasonCode::AuthorizationTimeout => RemoteAuthorizationState::Expired,
        RemoteReasonCode::CredentialLocked => RemoteAuthorizationState::LockedOut,
        RemoteReasonCode::PolicyChanged => RemoteAuthorizationState::PolicyChanged,
        RemoteReasonCode::GrantRevoked | RemoteReasonCode::TrustRequired => {
            RemoteAuthorizationState::Revoked
        }
        _ => RemoteAuthorizationState::Denied,
    }
}

fn post_consent_failure_state(code: RemoteReasonCode) -> RemoteAuthorizationState {
    if code == RemoteReasonCode::AuthorizationTimeout {
        RemoteAuthorizationState::Expired
    } else {
        RemoteAuthorizationState::Revoked
    }
}

pub(crate) fn remote_reason_code_wire_name(code: RemoteReasonCode) -> String {
    serde_json::to_string(&code)
        .unwrap_or_else(|_| "\"policy_changed\"".to_string())
        .trim_matches('"')
        .to_string()
}

fn verified_grant_projection(
    grant: &SignedLanSessionGrant,
) -> Result<crate::session_authorization::VerifiedSessionGrant> {
    Ok(crate::session_authorization::VerifiedSessionGrant {
        grant_id: format!("sha256:{}", hex_bytes(&grant.grant_id()?)),
        session_id: SessionId(grant.payload.session_id.clone()),
        granted_scopes: grant.payload.granted_scopes.clone(),
        issued_at_ms: grant.payload.issued_at_ms,
        expires_at_ms: grant.payload.expires_at_ms,
        policy_revision: grant.payload.policy_revision,
        route_constraint: grant.payload.route_constraint.clone(),
        transport_fingerprint_sha256: grant.payload.transport_fingerprint_sha256,
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn send_signed_lan_session_denial(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    request: &SignedLanSessionRequest,
    addr: SocketAddr,
    failure: RemoteFailure,
) -> Result<()> {
    let identity = app_state.device_identities.machine_identity();
    let target_key_epoch = app_state
        .device_identities
        .machine_key_epoch()
        .context("local machine key epoch is unavailable")?;
    let issued_at_ms = now_ms();
    let bootstrap = LanSessionBootstrap {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: request.payload.session_id.clone(),
        controller_key_id: request.payload.source_key_id.clone(),
        controller_key_epoch: request.payload.source_key_epoch,
        target_key_id: identity.key_id().to_string(),
        target_key_epoch,
        request_nonce: request.payload.nonce,
        accepted: false,
        message: None,
        failure: Some(failure),
        grant: None,
        media: None,
        media_profile: None,
        timestamp_ms: issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(5_000),
        nonce: new_signed_nonce()?,
    };
    let signed = SignedLanSessionBootstrap::sign(identity.as_ref(), bootstrap)?;
    send_packet(
        socket,
        &LanDiscoveryPacket::SignedRemoteSessionBootstrap(signed),
        addr,
    )
    .await
}

async fn audit_and_send_signed_lan_pre_authorization_denial(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    request: &SignedLanSessionRequest,
    addr: SocketAddr,
    failure: RemoteFailure,
) -> Result<()> {
    if !app_state.security_is_healthy() {
        anyhow::bail!("security audit is unhealthy; refusing unaudited LAN authorization denial");
    }

    let reason_code = remote_reason_code_wire_name(failure.code);
    let audit_admission = app_state
        .lan_discovery
        .admit_pre_authorization_denial_audit(addr.ip(), now_ms())
        .await;
    let audit_result = match audit_admission {
        LanPreAuthorizationAuditAdmission::Detailed {
            previous_window_suppressed,
        } => {
            let mut details = vec![(
                "requested_scope_count".to_string(),
                request.payload.requested_scopes.len().to_string(),
            )];
            if previous_window_suppressed > 0 {
                details.push((
                    "previous_window_suppressed_denials".to_string(),
                    previous_window_suppressed.to_string(),
                ));
            }
            Some(app_state.audit_log.record(
                "session.authorization_decision",
                "denied",
                Some(SessionId(request.payload.session_id.clone())),
                None,
                Some(DeviceId(request.payload.source_device_id.clone())),
                Some(request.payload.transport_kind.clone()),
                Some(reason_code.clone()),
                details,
            ))
        }
        LanPreAuthorizationAuditAdmission::OverflowMarker => Some(app_state.audit_log.record(
            "session.authorization_decision",
            "denied_aggregate",
            None,
            None,
            None,
            None,
            Some(reason_code.clone()),
            vec![
                (
                    "aggregate".to_string(),
                    "pre_authorization_denials".to_string(),
                ),
                (
                    "window_ms".to_string(),
                    LAN_PRE_AUTHORIZATION_AUDIT_WINDOW_MS.to_string(),
                ),
                (
                    "suppressed_denial_count_at_least".to_string(),
                    "1".to_string(),
                ),
            ],
        )),
        LanPreAuthorizationAuditAdmission::Suppressed => None,
    };
    if audit_result.is_some_and(|result| result.is_err()) {
        app_state.mark_security_unhealthy();
        tracing::error!(
            reason_code = %reason_code,
            "failed to persist signed LAN pre-authorization denial"
        );
        anyhow::bail!("signed LAN pre-authorization denial could not be durably audited");
    }

    send_signed_lan_session_denial(socket, app_state, request, addr, failure).await
}

#[cfg(test)]
async fn accept_lan_remote_session(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    source_device_id: DeviceId,
    expected_peer_ip: IpAddr,
    transport_kind: String,
    source_media_capabilities: Vec<String>,
    requested_profile: Option<MediaProfile>,
) -> LanRemoteAcceptResult {
    let preparation = match prepare_lan_remote_session(
        app_state,
        session_id,
        source_device_id,
        expected_peer_ip,
        transport_kind,
        source_media_capabilities,
        requested_profile,
    )
    .await
    {
        Ok(preparation) => preparation,
        Err(message) => return LanRemoteAcceptResult::rejected(message),
    };
    bind_prepared_lan_remote_session(preparation).await
}

async fn prepare_lan_remote_session(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    source_device_id: DeviceId,
    expected_peer_ip: IpAddr,
    transport_kind: String,
    source_media_capabilities: Vec<String>,
    requested_profile: Option<MediaProfile>,
) -> std::result::Result<LanRemoteSessionPreparation, String> {
    let is_registered = {
        let devices = app_state.devices.lock().await;
        devices.is_registered()
    };
    if !is_registered {
        return Err("local device is not registered".to_string());
    }

    let transport = normalize_transport_kind(&transport_kind);
    if transport == "webrtc" {
        return Err("LAN WebRTC media path is not implemented in mrd-service yet".to_string());
    }
    if transport != "quic" {
        return Err(format!("unsupported LAN media transport: {transport}"));
    }
    let negotiation =
        negotiate_media_profile(requested_profile).map_err(|error| error.to_string())?;
    if let Err(error) = ensure_peer_can_receive_selected_media(
        source_device_id.0.as_str(),
        &negotiation.selected,
        &source_media_capabilities,
    ) {
        return Err(error.to_string());
    }
    let prepared_server = QuinnPreparedServer::generate()
        .map_err(|error| format!("failed to prepare LAN QUIC identity: {error}"))?;

    Ok(LanRemoteSessionPreparation {
        session_id,
        source_device_id,
        transport,
        source_media_capabilities,
        negotiation,
        prepared_server,
        expected_peer_ip,
    })
}

async fn bind_prepared_lan_remote_session(
    preparation: LanRemoteSessionPreparation,
) -> LanRemoteAcceptResult {
    let LanRemoteSessionPreparation {
        session_id,
        source_device_id,
        transport,
        source_media_capabilities,
        negotiation,
        prepared_server,
        expected_peer_ip,
    } = preparation;
    let (listener, bootstrap) = match prepared_server.bind("0.0.0.0:0").await {
        Ok(value) => value,
        Err(error) => {
            return LanRemoteAcceptResult::rejected(format!(
                "failed to bind authorized LAN QUIC listener: {error}"
            ));
        }
    };

    let local_media = LanMediaBootstrap {
        transport_kind: "quic".to_string(),
        quic: Some(LanQuicBootstrap {
            listen_addr: bootstrap.listen_addr.to_string(),
            server_name: bootstrap.server_name.clone(),
            certificate_fingerprint_sha256: bootstrap.certificate_fingerprint_sha256(),
            cert_der: bootstrap.cert_der.clone(),
        }),
    };

    LanRemoteAcceptResult {
        accepted: true,
        message: Some("accepted".to_string()),
        media: Some(local_media),
        media_profile: Some(negotiation.clone()),
        prepared: Some(PreparedLanRemoteSession {
            session_id,
            source_device_id,
            transport,
            source_media_capabilities,
            negotiation,
            listener,
            bootstrap,
            expected_peer_ip,
            controller_binding: None,
        }),
    }
}

async fn commit_prepared_lan_remote_session(
    app_state: &Arc<AppState>,
    prepared: PreparedLanRemoteSession,
) -> Result<()> {
    commit_prepared_lan_remote_session_with_timeout(
        app_state,
        prepared,
        LAN_QUIC_BOOTSTRAP_ACCEPT_TIMEOUT,
    )
    .await
}

async fn commit_prepared_lan_remote_session_with_timeout(
    app_state: &Arc<AppState>,
    prepared: PreparedLanRemoteSession,
    accept_timeout: Duration,
) -> Result<()> {
    let PreparedLanRemoteSession {
        session_id,
        source_device_id,
        transport,
        source_media_capabilities,
        negotiation,
        listener,
        bootstrap,
        expected_peer_ip,
        controller_binding,
    } = prepared;
    if controller_binding.is_some() {
        let authorization = app_state
            .session_authorizations
            .snapshot_at(&session_id, now_ms())
            .await
            .context("remote authorization disappeared before LAN sender commit")?;
        if authorization.authorization_state != RemoteAuthorizationState::Granted
            || !authorization
                .granted_scopes
                .contains(&RemotePermissionScope::ScreenView)
        {
            anyhow::bail!("remote authorization changed before LAN sender commit");
        }
    }
    #[cfg(test)]
    let capture_selection = Some(CaptureSourceSelection {
        session_id: session_id.clone(),
        source: synthetic_capture_source(),
        status: "selected".to_string(),
        reason: Some("test synthetic capture source".to_string()),
    });
    #[cfg(not(test))]
    let capture_selection = crate::capture_source::default_capture_source(false)
        .ok()
        .map(|source| CaptureSourceSelection {
            session_id: session_id.clone(),
            source,
            status: "selected".to_string(),
            reason: Some("default fullscreen capture source".to_string()),
        });
    let snapshot = SessionSnapshot {
        session_id: session_id.clone(),
        transport,
        source_device_id: Some(source_device_id),
        target_device_id: None,
        local_listen_addr: Some(bootstrap.listen_addr.to_string()),
        local_server_name: Some(bootstrap.server_name.clone()),
        local_cert_der_b64: None,
        remote_listen_addr: None,
        remote_server_name: None,
        remote_cert_der_b64: None,
        lifecycle_state: SessionLifecycleState::Listening,
        last_error: None,
        sender_active: true,
        receiver_active: false,
    };
    let (start_tx, start_rx) = oneshot::channel();

    // Acquire every registry in one fixed order before mutating any of them. The
    // session remains invisible to stop/fail until the gated task is registered.
    let mut sessions = app_state.sessions.lock().await;
    if sessions.get(&session_id).is_some() {
        anyhow::bail!(
            "session id became occupied before LAN bootstrap commit: {}",
            session_id.0
        );
    }
    let mut media_profiles = app_state.media_profiles.lock().await;
    let mut capture_sources = app_state.capture_sources.lock().await;
    let mut peer_media_capabilities = app_state.peer_media_capabilities.lock().await;
    let mut media_tasks = app_state.media_tasks.lock().await;
    if media_profiles.get(&session_id).is_some()
        || capture_sources.get(&session_id).is_some()
        || peer_media_capabilities.get(&session_id).is_some()
        || media_tasks.active_count(&session_id) != 0
    {
        anyhow::bail!(
            "media state became occupied before LAN bootstrap commit: {}",
            session_id.0
        );
    }

    let abort_handle = spawn_quic_media_sender(
        app_state.clone(),
        session_id.clone(),
        listener,
        expected_peer_ip,
        controller_binding,
        accept_timeout,
        start_rx,
    );
    media_profiles.set(session_id.clone(), negotiation);
    if let Some(selection) = capture_selection {
        capture_sources.set(session_id.clone(), selection);
    }
    peer_media_capabilities.set(session_id.clone(), source_media_capabilities);
    media_tasks.register(session_id.clone(), abort_handle);
    sessions.insert(session_id.clone(), snapshot);
    if start_tx.send(()).is_err() {
        sessions.remove(&session_id);
        media_tasks.abort_session(&session_id);
        peer_media_capabilities.remove(&session_id);
        capture_sources.remove(&session_id);
        media_profiles.remove(&session_id);
        anyhow::bail!("LAN media sender task ended before session commit");
    }
    drop(media_tasks);
    drop(peer_media_capabilities);
    drop(capture_sources);
    drop(media_profiles);
    drop(sessions);
    Ok(())
}

async fn accept_lan_media_profile_update(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    requested_profile: MediaProfile,
) -> Result<MediaProfileNegotiation> {
    ensure_legacy_session_control_allowed(app_state, session_id, "media profile update").await?;
    validate_media_profile(&requested_profile)?;
    {
        let sessions = app_state.sessions.lock().await;
        let snapshot = sessions
            .get(session_id)
            .with_context(|| format!("session not found: {}", session_id.0))?;
        if normalize_transport_kind(&snapshot.transport) != "quic" {
            anyhow::bail!(
                "media profile update is only supported for LAN QUIC sessions, got {}",
                snapshot.transport
            );
        }
        if snapshot.lifecycle_state.is_terminal() {
            anyhow::bail!(
                "media profile update rejected for {} session",
                snapshot.lifecycle_state
            );
        }
    }

    let mut negotiation = negotiate_media_profile(Some(requested_profile))?;
    let selected_source = app_state.capture_sources.lock().await.get(session_id);
    if let Some(selection) = selected_source.as_ref() {
        reconcile_negotiation_to_capture_source(&mut negotiation, &selection.source);
    }
    let active_display_mode = app_state.display_modes.lock().await.active_mode(session_id);
    if let Some(mode) = active_display_mode.as_ref() {
        reconcile_negotiation_to_display_mode(&mut negotiation, mode);
    }
    let peer_media_capabilities = app_state
        .peer_media_capabilities
        .lock()
        .await
        .get(session_id)
        .unwrap_or_default();
    ensure_peer_can_receive_selected_media(
        session_id.0.as_str(),
        &negotiation.selected,
        &peer_media_capabilities,
    )?;
    app_state
        .media_profiles
        .lock()
        .await
        .set(session_id.clone(), negotiation.clone());
    Ok(negotiation)
}

async fn accept_lan_capture_sources_request(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    include_previews: bool,
    limit: Option<u32>,
) -> Result<Vec<CaptureSource>> {
    ensure_active_sender_session(app_state, session_id, "capture source listing").await?;
    crate::capture_source::list_capture_sources(include_previews, limit)
}

async fn accept_lan_capture_source_select(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_id: &str,
) -> Result<CaptureSourceSelection> {
    let source = crate::capture_source::find_capture_source(source_id)?;
    accept_lan_capture_source_select_from_sources(app_state, session_id, source_id, vec![source])
        .await
}

async fn accept_lan_capture_source_select_from_sources(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_id: &str,
    sources: Vec<CaptureSource>,
) -> Result<CaptureSourceSelection> {
    ensure_active_sender_session(app_state, session_id, "capture source selection").await?;
    let source = sources
        .into_iter()
        .find(|source| source.id.eq_ignore_ascii_case(source_id))
        .with_context(|| format!("capture source not found: {source_id}"))?;
    let selection = CaptureSourceSelection {
        session_id: session_id.clone(),
        source,
        status: "selected".to_string(),
        reason: None,
    };
    close_existing_display_lan_sender_sessions_for_source(app_state, session_id, &selection.source)
        .await;
    store_capture_source_selection(app_state, session_id, selection.clone()).await;
    Ok(selection)
}

async fn accept_lan_display_modes_request(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_id: Option<String>,
) -> Result<Vec<DisplayMode>> {
    ensure_active_sender_session(app_state, session_id, "display mode listing").await?;
    crate::display_mode::list_display_modes(source_id.as_deref())
}

async fn accept_lan_display_mode_set(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    mode: DisplayMode,
    restore_after_session: bool,
) -> Result<DisplayModeChange> {
    ensure_active_sender_session(app_state, session_id, "display mode set").await?;
    let (previous, active) = crate::display_mode::set_display_mode(&mode)?;
    let change = app_state.display_modes.lock().await.record_change(
        session_id.clone(),
        mode,
        previous,
        active.clone(),
        restore_after_session,
    );
    reconcile_media_profile_to_display_mode(app_state, session_id, &active).await;
    Ok(change)
}

#[cfg(test)]
async fn accept_lan_display_mode_set_from_modes(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    requested: DisplayMode,
    restore_after_session: bool,
    modes: Vec<DisplayMode>,
) -> Result<DisplayModeChange> {
    ensure_active_sender_session(app_state, session_id, "display mode set").await?;
    let previous = modes.iter().find(|mode| mode.is_current).cloned();
    let active = crate::display_mode::choose_display_mode(
        &modes,
        requested.width,
        requested.height,
        requested.refresh_hz,
    )
    .with_context(|| {
        format!(
            "no display mode matches {}x{}@{}",
            requested.width, requested.height, requested.refresh_hz
        )
    })?;
    let change = app_state.display_modes.lock().await.record_change(
        session_id.clone(),
        requested,
        previous,
        active.clone(),
        restore_after_session,
    );
    reconcile_media_profile_to_display_mode(app_state, session_id, &active).await;
    Ok(change)
}

async fn accept_lan_display_mode_restore(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) -> Result<DisplayModeChange> {
    ensure_active_sender_session(app_state, session_id, "display mode restore").await?;
    let restore_mode = app_state
        .display_modes
        .lock()
        .await
        .restore_mode(session_id)
        .with_context(|| format!("no temporary display mode recorded for {}", session_id.0))?;
    let (previous, active) = crate::display_mode::set_display_mode(&restore_mode)
        .unwrap_or_else(|_| (None, restore_mode.clone()));
    Ok(app_state.display_modes.lock().await.record_restore(
        session_id.clone(),
        previous.unwrap_or_else(|| restore_mode.clone()),
        active,
    ))
}

#[cfg(test)]
async fn accept_lan_display_mode_restore_with_mode(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    restored_mode: DisplayMode,
) -> Result<DisplayModeChange> {
    ensure_active_sender_session(app_state, session_id, "display mode restore").await?;
    let previous = app_state
        .display_modes
        .lock()
        .await
        .active_mode(session_id)
        .with_context(|| format!("no temporary display mode recorded for {}", session_id.0))?;
    Ok(app_state.display_modes.lock().await.record_restore(
        session_id.clone(),
        previous,
        restored_mode,
    ))
}

async fn store_capture_source_selection(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    selection: CaptureSourceSelection,
) {
    reconcile_media_profile_to_capture_source(app_state, session_id, &selection.source).await;
    app_state
        .capture_sources
        .lock()
        .await
        .set(session_id.clone(), selection);
}

async fn reconcile_media_profile_to_capture_source(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source: &CaptureSource,
) {
    let active_display_mode = app_state.display_modes.lock().await.active_mode(session_id);
    let mut profiles = app_state.media_profiles.lock().await;
    let mut negotiation = profiles
        .get(session_id)
        .unwrap_or_else(default_media_profile_negotiation);
    reconcile_negotiation_to_capture_source(&mut negotiation, source);
    if let Some(mode) = active_display_mode.as_ref() {
        reconcile_negotiation_to_display_mode(&mut negotiation, mode);
    }

    profiles.set(session_id.clone(), negotiation);
}

async fn reconcile_media_profile_to_display_mode(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    mode: &DisplayMode,
) {
    let mut profiles = app_state.media_profiles.lock().await;
    let mut negotiation = profiles
        .get(session_id)
        .unwrap_or_else(default_media_profile_negotiation);
    reconcile_negotiation_to_display_mode(&mut negotiation, mode);
    profiles.set(session_id.clone(), negotiation);
}

fn reconcile_negotiation_to_capture_source(
    negotiation: &mut MediaProfileNegotiation,
    source: &CaptureSource,
) {
    let capability_limited = negotiate_media_profile(Some(negotiation.requested.clone()))
        .unwrap_or_else(|_| MediaProfileNegotiation {
            requested: negotiation.requested.clone(),
            selected: negotiation.selected.clone(),
            status: negotiation.status.clone(),
            reason: negotiation.reason.clone(),
            selected_source_id: None,
            selected_width: None,
            selected_height: None,
            downgrade_reason: negotiation.downgrade_reason.clone(),
        });

    let mut selected = capability_limited.selected.clone();
    let mut downgrade_reason = capability_limited.downgrade_reason.clone();

    if source.width > 0 && source.height > 0 {
        let (selected_width, selected_height) = h264_target_dimensions(
            source.width as usize,
            source.height as usize,
            &capability_limited.selected,
        );
        if selected_width as u32 != selected.width || selected_height as u32 != selected.height {
            downgrade_reason =
                Some("matched selected capture source dimensions and aspect ratio".to_string());
        }
        selected.width = selected_width as u32;
        selected.height = selected_height as u32;
    }
    negotiation.selected = selected.clone();
    negotiation.selected_source_id = Some(source.id.clone());
    negotiation.selected_width = Some(negotiation.selected.width);
    negotiation.selected_height = Some(negotiation.selected.height);

    if negotiation.selected != negotiation.requested {
        negotiation.status = "downgraded".to_string();
        negotiation.reason = downgrade_reason
            .clone()
            .or(capability_limited.reason.clone());
        negotiation.downgrade_reason = downgrade_reason.or(capability_limited.downgrade_reason);
    } else {
        negotiation.status = "accepted".to_string();
        negotiation.reason = None;
        negotiation.downgrade_reason = None;
    }
}

fn reconcile_negotiation_to_display_mode(
    negotiation: &mut MediaProfileNegotiation,
    mode: &DisplayMode,
) {
    let mut selected = negotiation.selected.clone();
    let mut changed_for_display = false;

    if mode.width > 0 && mode.height > 0 {
        let (selected_width, selected_height) =
            h264_target_dimensions(mode.width as usize, mode.height as usize, &selected);
        if selected_width as u32 != selected.width || selected_height as u32 != selected.height {
            changed_for_display = true;
        }
        selected.width = selected_width as u32;
        selected.height = selected_height as u32;
    }

    if mode.refresh_hz > 0 && selected.fps > mode.refresh_hz {
        selected.fps = mode.refresh_hz;
        changed_for_display = true;
    }

    negotiation.selected = selected;
    negotiation.selected_width = Some(negotiation.selected.width);
    negotiation.selected_height = Some(negotiation.selected.height);

    if negotiation.selected != negotiation.requested {
        negotiation.status = "downgraded".to_string();
        if changed_for_display {
            let reason = "matched active display mode dimensions and refresh rate".to_string();
            negotiation.reason = Some(reason.clone());
            negotiation.downgrade_reason = Some(reason);
        }
    } else {
        negotiation.status = "accepted".to_string();
        negotiation.reason = None;
        negotiation.downgrade_reason = None;
    }
}

async fn ensure_active_sender_session(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    operation: &str,
) -> Result<()> {
    ensure_legacy_session_control_allowed(app_state, session_id, operation).await?;
    let sessions = app_state.sessions.lock().await;
    let snapshot = sessions
        .get(session_id)
        .with_context(|| format!("session not found: {}", session_id.0))?;
    if normalize_transport_kind(&snapshot.transport) != "quic" {
        anyhow::bail!("{operation} is only supported for LAN QUIC sessions");
    }
    if !snapshot.sender_active {
        anyhow::bail!("{operation} requires an active target sender session");
    }
    if snapshot.lifecycle_state.is_terminal() {
        anyhow::bail!(
            "{operation} rejected for {} session",
            snapshot.lifecycle_state
        );
    }
    Ok(())
}

async fn ensure_legacy_session_control_allowed(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    operation: &str,
) -> Result<()> {
    if app_state
        .session_authorizations
        .snapshot(session_id)
        .await
        .is_some()
    {
        anyhow::bail!(
            "legacy unsigned LAN session control is disabled for authorized remote sessions: {operation}"
        );
    }
    Ok(())
}

fn routed_discovery_endpoint(target: SocketAddr, discovery_port: u16) -> Result<SocketAddr> {
    let bind_addr = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        std::net::UdpSocket::bind(bind_addr).context("failed to bind LAN route probe socket")?;
    if target.is_ipv4() {
        socket
            .set_broadcast(true)
            .context("failed to enable LAN route probe broadcast")?;
    }
    socket
        .connect(target)
        .with_context(|| format!("failed to resolve LAN route to {target}"))?;
    let local_ip = socket
        .local_addr()
        .context("failed to read routed LAN source address")?
        .ip();
    if local_ip.is_unspecified() || local_ip.is_multicast() {
        anyhow::bail!("LAN route selected an invalid local address: {local_ip}");
    }
    Ok(SocketAddr::new(local_ip, discovery_port))
}

async fn build_announcement(
    app_state: &Arc<AppState>,
    discovery_endpoint: SocketAddr,
) -> Option<SignedLanAnnouncement> {
    let (device_id, device_name) = {
        let devices = app_state.devices.lock().await;
        devices
            .get_local_device()
            .map(|(id, name)| (id.0.clone(), name.clone()))
    }?;

    let input_control_available =
        app_state.security_is_healthy() && app_state.control_input().lock().await.is_available();
    let mut transports = vec![
        "quic".to_string(),
        LAN_QUIC_MEDIA_TRANSPORT.to_string(),
        LAN_QUIC_MEDIA_PROFILE_TRANSPORT.to_string(),
        LAN_QUIC_MEDIA_V2_TRANSPORT.to_string(),
        LAN_QUIC_MEDIA_V3_TRANSPORT.to_string(),
        LAN_QUIC_RELIABLE_MEDIA_TRANSPORT.to_string(),
        LAN_QUIC_PERSISTENT_MEDIA_TRANSPORT.to_string(),
        LAN_QUIC_TRANSPORT_MUX_V1.to_string(),
        LAN_QUIC_PERSISTENT_MEDIA_60FPS_TRANSPORT.to_string(),
        LAN_MEDIA_PROFILE_CONTROL_TRANSPORT.to_string(),
        LAN_CAPTURE_SOURCE_CONTROL_TRANSPORT.to_string(),
        LAN_DISPLAY_MODE_CONTROL_TRANSPORT.to_string(),
    ];
    if input_control_available {
        transports.push(LAN_INPUT_CONTROL_TRANSPORT.to_string());
    }
    // Legacy unsigned power actions remain disabled until Task 40 policy work.

    let issued_at_ms = now_ms();
    let announcement = LanAnnouncement {
        magic: DISCOVERY_MAGIC.to_string(),
        app_id: DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        device_id,
        device_name,
        device_type: "rdesk".to_string(),
        protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
        discovery_port: app_state.lan_discovery.discovery_port(),
        transports,
        service_build_id: Some(service_build_id()),
        media_protocol_version: Some(LAN_MEDIA_PROTOCOL_VERSION),
        media_capabilities: lan_media_capabilities_with_input_control(input_control_available),
        mac_address: local_lan_announcement_mac_address(),
        timestamp_ms: issued_at_ms,
    };
    let identity = app_state.device_identities.machine_identity();
    let key_epoch = app_state.device_identities.machine_key_epoch()?;
    let lifetime_ms = (app_state.lan_discovery.config.peer_ttl.as_millis() as u64).clamp(1, 15_000);
    let nonce = new_signed_nonce().ok()?;
    SignedLanAnnouncement::sign(
        identity.as_ref(),
        key_epoch,
        announcement,
        discovery_endpoint,
        issued_at_ms.saturating_add(lifetime_ms),
        nonce,
    )
    .ok()
}

async fn send_packet(
    socket: &UdpSocket,
    packet: &LanDiscoveryPacket,
    target: SocketAddr,
) -> Result<()> {
    let bytes = serde_json::to_vec(packet)?;
    socket.send_to(&bytes, target).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn start_lan_media_receiver(
    app_state: Arc<AppState>,
    session_id: SessionId,
    requested_transport: &str,
    media: Option<LanMediaBootstrap>,
    peer_ip: IpAddr,
    target_device_id: DeviceId,
    negotiation: MediaProfileNegotiation,
    peer_media_capabilities: Vec<String>,
    controller_proof: LanQuicControllerProofMaterial,
) -> Result<()> {
    start_lan_media_receiver_with_timeout(
        app_state,
        session_id,
        requested_transport,
        media,
        peer_ip,
        target_device_id,
        negotiation,
        peer_media_capabilities,
        Some(controller_proof),
        LAN_QUIC_BOOTSTRAP_CONNECT_TIMEOUT,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_lan_media_receiver_with_timeout(
    app_state: Arc<AppState>,
    session_id: SessionId,
    requested_transport: &str,
    media: Option<LanMediaBootstrap>,
    peer_ip: IpAddr,
    target_device_id: DeviceId,
    negotiation: MediaProfileNegotiation,
    peer_media_capabilities: Vec<String>,
    controller_proof: Option<LanQuicControllerProofMaterial>,
    connect_timeout: Duration,
) -> Result<()> {
    let requested_transport = normalize_transport_kind(requested_transport);
    if requested_transport == "webrtc" {
        anyhow::bail!("LAN WebRTC media path is not implemented in mrd-service yet");
    }
    if requested_transport != "quic" {
        anyhow::bail!("unsupported LAN media transport: {requested_transport}");
    }

    let media = media.context("LAN peer accepted session without media bootstrap")?;
    if normalize_transport_kind(&media.transport_kind) != "quic" {
        anyhow::bail!(
            "LAN peer returned unexpected media transport: {}",
            media.transport_kind
        );
    }
    let quic = media
        .quic
        .context("LAN peer accepted QUIC session without QUIC bootstrap")?;
    let bootstrap = quic_bootstrap_for_peer(quic.clone(), peer_ip)?;
    let endpoint = timeout(
        connect_timeout,
        QuinnDatagramEndpoint::connect_client("0.0.0.0:0", &bootstrap),
    )
    .await
    .context("timed out connecting LAN QUIC media receiver")?
    .context("failed to connect LAN QUIC media receiver")?;
    if let Some(controller_proof) = controller_proof.as_ref() {
        prove_lan_quic_controller(&endpoint, &session_id, controller_proof).await?;
    } else if !cfg!(test) {
        anyhow::bail!("authorized LAN receiver is missing its controller proof material");
    }
    if controller_proof.is_some() {
        let authorization = app_state
            .session_authorizations
            .snapshot_at(&session_id, now_ms())
            .await
            .context("remote authorization disappeared before LAN receiver commit")?;
        if authorization.authorization_state != RemoteAuthorizationState::Granted
            || !authorization
                .granted_scopes
                .contains(&RemotePermissionScope::ScreenView)
        {
            anyhow::bail!("remote authorization changed before LAN receiver commit");
        }
    }
    let snapshot = SessionSnapshot {
        session_id: session_id.clone(),
        transport: requested_transport,
        source_device_id: None,
        target_device_id: Some(target_device_id),
        local_listen_addr: None,
        local_server_name: None,
        local_cert_der_b64: None,
        remote_listen_addr: Some(bootstrap.listen_addr.to_string()),
        remote_server_name: Some(bootstrap.server_name.clone()),
        remote_cert_der_b64: None,
        lifecycle_state: SessionLifecycleState::Streaming,
        last_error: None,
        sender_active: false,
        receiver_active: true,
    };
    let (start_tx, start_rx) = oneshot::channel();

    let mut sessions = app_state.sessions.lock().await;
    if sessions.get(&session_id).is_some() {
        anyhow::bail!(
            "session id became occupied before LAN receiver commit: {}",
            session_id.0
        );
    }
    let mut media_profiles = app_state.media_profiles.lock().await;
    let capture_sources = app_state.capture_sources.lock().await;
    let mut stored_peer_capabilities = app_state.peer_media_capabilities.lock().await;
    let mut media_tasks = app_state.media_tasks.lock().await;
    if media_profiles.get(&session_id).is_some()
        || capture_sources.get(&session_id).is_some()
        || stored_peer_capabilities.get(&session_id).is_some()
        || media_tasks.active_count(&session_id) != 0
    {
        anyhow::bail!(
            "media state became occupied before LAN receiver commit: {}",
            session_id.0
        );
    }

    let abort_handle =
        spawn_quic_media_receiver(app_state.clone(), session_id.clone(), endpoint, start_rx);
    media_profiles.set(session_id.clone(), negotiation);
    stored_peer_capabilities.set(session_id.clone(), peer_media_capabilities);
    media_tasks.register(session_id.clone(), abort_handle);
    sessions.insert(session_id.clone(), snapshot);
    if start_tx.send(()).is_err() {
        sessions.remove(&session_id);
        media_tasks.abort_session(&session_id);
        stored_peer_capabilities.remove(&session_id);
        media_profiles.remove(&session_id);
        anyhow::bail!("LAN media receiver task ended before session commit");
    }
    drop(media_tasks);
    drop(stored_peer_capabilities);
    drop(capture_sources);
    drop(media_profiles);
    drop(sessions);
    let _ = app_state
        .session_authorizations
        .mark_streaming(&session_id, now_ms())
        .await;
    Ok(())
}

fn quic_bootstrap_for_peer(
    quic: LanQuicBootstrap,
    peer_ip: IpAddr,
) -> Result<QuinnServerBootstrap> {
    if certificate_fingerprint_sha256(&quic.cert_der) != quic.certificate_fingerprint_sha256 {
        anyhow::bail!("LAN QUIC certificate fingerprint does not match signed bootstrap");
    }
    let listen_addr = quic
        .listen_addr
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid LAN QUIC listen addr: {}", quic.listen_addr))?;
    Ok(QuinnServerBootstrap {
        transport: "quic_quinn",
        listen_addr: SocketAddr::new(peer_ip, listen_addr.port()),
        server_name: quic.server_name,
        cert_der: quic.cert_der,
    })
}

async fn close_existing_display_lan_receiver_sessions_for_target(
    app_state: &Arc<AppState>,
    next_session_id: &SessionId,
    next_source: &CaptureSource,
) {
    if is_window_capture_source(next_source) {
        return;
    }
    let target_device_id = {
        let sessions = app_state.sessions.lock().await;
        sessions
            .get(next_session_id)
            .and_then(|snapshot| snapshot.target_device_id.clone())
    };
    let Some(target_device_id) = target_device_id else {
        return;
    };
    let stale_sessions = {
        let sessions = app_state.sessions.lock().await;
        let capture_sources = app_state.capture_sources.lock().await;
        sessions
            .list_all()
            .into_iter()
            .filter(|snapshot| {
                snapshot.session_id != *next_session_id
                    && snapshot.target_device_id.as_ref() == Some(&target_device_id)
                    && snapshot.receiver_active
                    && !capture_sources
                        .get(&snapshot.session_id)
                        .is_some_and(|selection| is_window_capture_source(&selection.source))
                    && !snapshot.lifecycle_state.is_terminal()
            })
            .map(|snapshot| snapshot.session_id)
            .collect::<Vec<_>>()
    };
    close_lan_media_sessions(
        app_state,
        stale_sessions,
        "replaced by newer display receiver session",
    )
    .await;
}

async fn close_existing_display_lan_sender_sessions_for_source(
    app_state: &Arc<AppState>,
    next_session_id: &SessionId,
    next_source: &CaptureSource,
) {
    if is_window_capture_source(next_source) {
        return;
    }
    let source_device_id = {
        let sessions = app_state.sessions.lock().await;
        sessions
            .get(next_session_id)
            .and_then(|snapshot| snapshot.source_device_id.clone())
    };
    let Some(source_device_id) = source_device_id else {
        return;
    };
    let stale_sessions = {
        let sessions = app_state.sessions.lock().await;
        let capture_sources = app_state.capture_sources.lock().await;
        sessions
            .list_all()
            .into_iter()
            .filter(|snapshot| {
                let selected_source = capture_sources.get(&snapshot.session_id);
                let selected_source_is_window = selected_source
                    .as_ref()
                    .is_some_and(|selection| is_window_capture_source(&selection.source));
                let same_controller = snapshot.source_device_id.as_ref() == Some(&source_device_id);
                let same_capture_source = selected_source.as_ref().is_some_and(|selection| {
                    selection.source.id.eq_ignore_ascii_case(&next_source.id)
                });
                snapshot.session_id != *next_session_id
                    && (same_controller || same_capture_source)
                    && snapshot.sender_active
                    && normalize_transport_kind(&snapshot.transport) == "quic"
                    && !selected_source_is_window
                    && !snapshot.lifecycle_state.is_terminal()
            })
            .map(|snapshot| snapshot.session_id)
            .collect::<Vec<_>>()
    };
    close_lan_media_sessions(
        app_state,
        stale_sessions,
        "replaced by newer display sender session from same source device",
    )
    .await;
}

fn is_window_capture_source(source: &CaptureSource) -> bool {
    source.source_kind.eq_ignore_ascii_case("window")
}

async fn close_lan_media_sessions(
    app_state: &Arc<AppState>,
    session_ids: Vec<SessionId>,
    reason: &'static str,
) {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    terminate_lan_media_sessions(app_state, &session_ids, reason).await;
}

pub(crate) async fn terminate_authorized_remote_sessions(
    app_state: &Arc<AppState>,
    session_ids: &[SessionId],
) {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    terminate_authorized_remote_sessions_under_security_gate(app_state, session_ids).await;
}

pub(crate) async fn terminate_authorized_remote_sessions_under_security_gate(
    app_state: &Arc<AppState>,
    session_ids: &[SessionId],
) {
    terminate_lan_media_sessions(
        app_state,
        session_ids,
        "remote authorization no longer permits LAN media",
    )
    .await;
}

async fn terminate_lan_media_sessions(
    app_state: &Arc<AppState>,
    session_ids: &[SessionId],
    reason: &str,
) {
    let mut seen_session_ids = HashSet::new();
    for session_id in session_ids {
        if !seen_session_ids.insert(session_id.clone()) {
            continue;
        }
        let mut authorization = app_state.session_authorizations.snapshot(session_id).await;
        if authorization.as_ref().is_some_and(|snapshot| {
            !matches!(
                snapshot.authorization_state,
                RemoteAuthorizationState::Denied
                    | RemoteAuthorizationState::Expired
                    | RemoteAuthorizationState::Revoked
                    | RemoteAuthorizationState::LockedOut
                    | RemoteAuthorizationState::PolicyChanged
            )
        }) {
            authorization = app_state
                .session_authorizations
                .record_failure(
                    session_id,
                    RemoteAuthorizationState::Revoked,
                    RemoteFailure {
                        code: RemoteReasonCode::RouteLost,
                        message: reason.to_string(),
                        suggested_action: Some("start a new authorized LAN session".to_string()),
                    },
                    now_ms(),
                )
                .await;
        }
        if let Some(authorization) = authorization.filter(|snapshot| {
            snapshot.authorization_state == RemoteAuthorizationState::Expired
                && snapshot.failure.as_ref().map(|failure| failure.code)
                    == Some(RemoteReasonCode::GrantExpired)
        }) {
            if app_state
                .audit_log
                .record(
                    "session.authorization_expired",
                    "expired",
                    Some(session_id.clone()),
                    None,
                    Some(authorization.peer_device_id),
                    Some("quic".to_string()),
                    Some("grant_expired".to_string()),
                    Vec::new(),
                )
                .is_err()
            {
                app_state.mark_security_unhealthy();
                tracing::error!(
                    session_id = %session_id.0,
                    "failed to persist LAN authorization expiry audit"
                );
            }
        }
        tracing::info!(session_id = %session_id.0, reason, "closing stale LAN media session");
        release_control_state_for_session(app_state, session_id).await;
        {
            let mut sessions = app_state.sessions.lock().await;
            if let Some(snapshot) = sessions.get(session_id).cloned() {
                sessions.insert(
                    session_id.clone(),
                    SessionSnapshot {
                        lifecycle_state: SessionLifecycleState::Closed,
                        last_error: None,
                        sender_active: false,
                        receiver_active: false,
                        ..snapshot
                    },
                );
            }
        }
        app_state.media_tasks.lock().await.abort_session(session_id);
        cleanup_lan_media_resources(app_state, session_id).await;
    }
}

async fn release_control_state_for_session(app_state: &Arc<AppState>, session_id: &SessionId) {
    app_state
        .lan_discovery
        .authenticated_control_inputs
        .lock()
        .await
        .retain(|key, _| key.session_id != session_id.0);
    app_state
        .lan_discovery
        .authenticated_control_senders
        .lock()
        .await
        .retain(|key, _| key.session_id != session_id.0);
    let control_input = app_state.control_input();
    let mut control_input = control_input.lock().await;
    let mut last_error = None;
    for _ in 0..3 {
        match control_input.release_session_all(session_id) {
            Ok(_) => {
                last_error = None;
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        tracing::warn!(
            session_id = %session_id.0,
            %error,
            "failed to release session-scoped input during LAN termination"
        );
    }
}

async fn cleanup_lan_media_resources(app_state: &Arc<AppState>, session_id: &SessionId) {
    app_state.remove_agent_render_route(session_id).await;
    app_state.media_profiles.lock().await.remove(session_id);
    app_state.capture_sources.lock().await.remove(session_id);
    app_state
        .peer_media_capabilities
        .lock()
        .await
        .remove(session_id);
    #[cfg(any(windows, target_os = "macos"))]
    app_state
        .media_surface_renderers
        .lock()
        .await
        .detach_session(session_id);
    #[cfg(any(windows, target_os = "macos"))]
    app_state
        .media_render_queues
        .lock()
        .await
        .remove(session_id);
    app_state.media_pipelines.lock().await.remove(session_id);
}

async fn authenticate_lan_quic_controller(
    endpoint: &QuinnDatagramEndpoint,
    session_id: &SessionId,
    binding: &LanQuicControllerBinding,
) -> Result<()> {
    let issued_at_ms = now_ms();
    let challenge = LanQuicControllerChallenge {
        protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
        session_id: session_id.0.clone(),
        grant_id: binding.grant_id,
        transport_fingerprint_sha256: binding.transport_fingerprint_sha256,
        issued_at_ms,
        expires_at_ms: issued_at_ms
            .saturating_add(LAN_QUIC_CONTROLLER_PROOF_TIMEOUT.as_millis() as u64),
        nonce: new_signed_nonce()?,
    };
    let challenge_bytes =
        serde_json::to_vec(&challenge).context("failed to encode LAN QUIC controller challenge")?;
    timeout(
        LAN_QUIC_CONTROLLER_PROOF_TIMEOUT,
        endpoint.send_reliable_message(bytes::Bytes::from(challenge_bytes)),
    )
    .await
    .context("timed out sending LAN QUIC controller challenge")?
    .context("failed to send LAN QUIC controller challenge")?;
    let proof_bytes = timeout(
        LAN_QUIC_CONTROLLER_PROOF_TIMEOUT,
        endpoint.read_reliable_message(LAN_QUIC_CONTROLLER_PROOF_MAX_BYTES),
    )
    .await
    .context("timed out waiting for LAN QUIC controller proof")?
    .context("failed to read LAN QUIC controller proof")?;
    let proof = serde_json::from_slice::<SignedLanQuicControllerProof>(&proof_bytes)
        .context("invalid LAN QUIC controller proof payload")?;
    proof
        .verify(
            now_ms(),
            &binding.controller_public_key,
            binding.controller_key_epoch,
            &challenge,
        )
        .context("LAN QUIC controller proof verification failed")?;
    timeout(
        LAN_QUIC_CONTROLLER_PROOF_TIMEOUT,
        endpoint.send_reliable_message(bytes::Bytes::from_static(
            LAN_QUIC_CONTROLLER_PROOF_ACCEPTED,
        )),
    )
    .await
    .context("timed out acknowledging LAN QUIC controller proof")?
    .context("failed to acknowledge LAN QUIC controller proof")
}

async fn prove_lan_quic_controller(
    endpoint: &QuinnDatagramEndpoint,
    session_id: &SessionId,
    material: &LanQuicControllerProofMaterial,
) -> Result<()> {
    let challenge_bytes = timeout(
        LAN_QUIC_CONTROLLER_PROOF_TIMEOUT,
        endpoint.read_reliable_message(LAN_QUIC_CONTROLLER_PROOF_MAX_BYTES),
    )
    .await
    .context("timed out waiting for LAN QUIC controller challenge")?
    .context("failed to read LAN QUIC controller challenge")?;
    let challenge = serde_json::from_slice::<LanQuicControllerChallenge>(&challenge_bytes)
        .context("invalid LAN QUIC controller challenge payload")?;
    challenge
        .verify_binding(
            now_ms(),
            &session_id.0,
            &material.grant_id,
            &material.transport_fingerprint_sha256,
        )
        .context("LAN QUIC controller challenge binding failed")?;
    let proof = SignedLanQuicControllerProof::sign(
        material.controller_identity.as_ref(),
        material.controller_key_epoch,
        challenge,
    )
    .context("failed to sign LAN QUIC controller proof")?;
    let proof_bytes =
        serde_json::to_vec(&proof).context("failed to encode LAN QUIC controller proof")?;
    timeout(
        LAN_QUIC_CONTROLLER_PROOF_TIMEOUT,
        endpoint.send_reliable_message(bytes::Bytes::from(proof_bytes)),
    )
    .await
    .context("timed out sending LAN QUIC controller proof")?
    .context("failed to send LAN QUIC controller proof")?;
    let acknowledgement = timeout(
        LAN_QUIC_CONTROLLER_PROOF_TIMEOUT,
        endpoint.read_reliable_message(LAN_QUIC_CONTROLLER_PROOF_ACCEPTED.len()),
    )
    .await
    .context("timed out waiting for LAN QUIC controller proof acknowledgement")?
    .context("failed to read LAN QUIC controller proof acknowledgement")?;
    if acknowledgement.as_ref() != LAN_QUIC_CONTROLLER_PROOF_ACCEPTED {
        anyhow::bail!("invalid LAN QUIC controller proof acknowledgement");
    }
    Ok(())
}

fn spawn_quic_media_sender(
    app_state: Arc<AppState>,
    session_id: SessionId,
    listener: QuinnServerListener,
    expected_peer_ip: IpAddr,
    controller_binding: Option<LanQuicControllerBinding>,
    accept_timeout: Duration,
    start_rx: oneshot::Receiver<()>,
) -> tokio::task::AbortHandle {
    let registry = app_state.media_tasks.clone();
    let completion_registry = registry.clone();
    let task_app_state = app_state;
    let failure_app_state = task_app_state.clone();
    let task_session_id = session_id.clone();
    let failure_session_id = task_session_id.clone();
    let handle = tokio::spawn(async move {
        if start_rx.await.is_err() {
            completion_registry
                .lock()
                .await
                .forget_task(&failure_session_id, tokio::task::id());
            return;
        }
        let local_addr = listener.local_addr();
        let result = async move {
            let accept = timeout(accept_timeout, listener.accept_from(expected_peer_ip));
            tokio::pin!(accept);
            let endpoint = loop {
                tokio::select! {
                    result = &mut accept => {
                        break result
                            .context("timed out waiting for LAN QUIC media receiver")?
                            .context("LAN QUIC media listener failed to accept receiver")?;
                    }
                    _ = tokio::time::sleep(LAN_MEDIA_AUTHORIZATION_POLL_INTERVAL) => {
                        if !session_allows_media(&task_app_state, &task_session_id).await {
                            return Ok(());
                        }
                    }
                }
            };
            let controller_binding = controller_binding
                .context("authorized LAN sender is missing its controller proof binding")?;
            authenticate_lan_quic_controller(&endpoint, &task_session_id, &controller_binding)
                .await?;
            if !session_allows_media(&task_app_state, &task_session_id).await {
                return Ok(());
            }
            let _ = task_app_state
                .session_authorizations
                .mark_streaming(&task_session_id, now_ms())
                .await;
            send_quic_media_loop(task_app_state, endpoint, task_session_id).await
        }
        .await;
        completion_registry
            .lock()
            .await
            .forget_task(&failure_session_id, tokio::task::id());
        match result {
            Ok(()) => {
                terminate_authorized_remote_sessions(
                    &failure_app_state,
                    std::slice::from_ref(&failure_session_id),
                )
                .await;
            }
            Err(error) => {
                if session_allows_media(&failure_app_state, &failure_session_id).await {
                    tracing::warn!(%error, %local_addr, "LAN QUIC media sender stopped");
                    mark_session_failed(
                        &failure_app_state,
                        &failure_session_id,
                        format!("LAN QUIC media sender failed: {error}"),
                    )
                    .await;
                    cleanup_lan_media_resources(&failure_app_state, &failure_session_id).await;
                } else {
                    terminate_authorized_remote_sessions(
                        &failure_app_state,
                        std::slice::from_ref(&failure_session_id),
                    )
                    .await;
                }
            }
        }
    });
    let abort_handle = handle.abort_handle();
    drop(handle);
    abort_handle
}

async fn send_quic_media_loop(
    app_state: Arc<AppState>,
    endpoint: QuinnDatagramEndpoint,
    session_id: SessionId,
) -> Result<()> {
    let negotiated_max_datagram_size = endpoint
        .max_datagram_size()
        .unwrap_or(LAN_QUIC_FALLBACK_DATAGRAM_BYTES)
        .max(QUIC_MEDIA_V3_FRAGMENT_HEADER_LEN.max(QUIC_AU_FRAGMENT_HEADER_LEN) + 1);
    let transport_mux_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_TRANSPORT_MUX_V1);
    let transport_mux = transport_mux_supported.then(|| {
        Arc::new(QuicTransportMux::new(
            session_id.clone(),
            TransportMuxConfig::default(),
            endpoint.clone(),
        ))
    });
    let keyframe_requests = Arc::new(AtomicU64::new(0));
    let _control_reader = if let Some(mux) = transport_mux.as_ref() {
        spawn_lan_mux_control_reader(
            Arc::clone(mux),
            session_id.clone(),
            keyframe_requests.clone(),
        )
    } else {
        spawn_lan_media_control_reader(
            endpoint.clone(),
            session_id.clone(),
            keyframe_requests.clone(),
        )
    };

    let mut frame_id = 1_u64;
    let mut active_capture_config: Option<LanCaptureConfigKey> = None;
    let mut capture: Option<LanSenderFrameCapture> = None;
    let mut encoder: Option<LanSenderEncoder> = None;
    let mut encoder_config: Option<LanEncoderConfigKey> = None;
    let mut pending_keyframe_request = false;
    let mut consecutive_frame_errors = 0_u32;
    let mut next_frame_at = Instant::now();
    let mut active_frame_interval = Duration::ZERO;
    let mut media_timer_resolution = MediaTimerResolution::default();
    let mut sender_stats = LanSenderStatsTracker::new(Instant::now());
    let mut test_impairment = LanMediaTestImpairment::from_env()?;
    // Child sends are structured under the media loop. Dropping either JoinSet
    // on revoke/expiry aborts the sends before their endpoint clones can outlive
    // the authorized session. Reliable keyframe redundancy has its own strict
    // bound so a peer that stops reading streams cannot retain unbounded frames.
    let mut delayed_media_children = tokio::task::JoinSet::new();
    let mut reliable_keyframe_children = tokio::task::JoinSet::new();
    let mut dynamic_window_fps_config: Option<DynamicWindowFpsConfigKey> = None;
    let mut dynamic_window_fps_policy: Option<DynamicWindowFpsPolicy> = None;
    let mut dynamic_window_fps_decision: Option<DynamicWindowFpsDecision> = None;
    let reliable_media_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_RELIABLE_MEDIA_TRANSPORT);
    let persistent_media_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_PERSISTENT_MEDIA_TRANSPORT);
    let persistent_media_60fps_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_PERSISTENT_MEDIA_60FPS_TRANSPORT);
    let media_v3_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_MEDIA_V3_TRANSPORT);
    let high_quality_datagram_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_MEDIA_PROFILE_TRANSPORT);
    loop {
        while delayed_media_children.try_join_next().is_some() {}
        while reliable_keyframe_children.try_join_next().is_some() {}
        if !session_allows_media(&app_state, &session_id).await {
            return Ok(());
        }
        let new_keyframe_requests = keyframe_requests.swap(0, Ordering::Relaxed);
        if new_keyframe_requests > 0 {
            pending_keyframe_request = true;
            sender_stats.record_ms("sender.keyframe_request", new_keyframe_requests as f64);
        }
        let profile = selected_media_profile(&app_state, &session_id).await;
        media_timer_resolution.update_for_profile(&profile);
        let reliable_media_send_mode = select_reliable_media_send_mode_for_profile(
            reliable_media_supported,
            persistent_media_supported,
            persistent_media_60fps_supported,
            &profile,
        );
        let max_datagram_size = lan_media_datagram_size(
            negotiated_max_datagram_size,
            &profile,
            high_quality_datagram_supported,
        );
        let requested_codec = LanAccessUnitCodec::from_profile(&profile);
        let loop_started = Instant::now();
        let sender_turn = match app_state
            .take_agent_media_turn(&session_id.0, 8, requested_codec)
            .await
        {
            Ok(turn) => turn,
            Err(error) => {
                handle_media_sender_frame_error(
                    &app_state,
                    &session_id,
                    "agent-ipc",
                    &mut consecutive_frame_errors,
                    format!("rejected session-agent media unit: {error:?}"),
                    true,
                )
                .await?;
                continue;
            }
        };
        let (access_units, capture_memory_path) =
            if !media_sender::sender_turn_requires_local_capture(&sender_turn) {
                let SenderMediaTurn::Agent(access_units) = sender_turn else {
                    unreachable!("non-local sender turn must contain agent media")
                };
                capture = None;
                encoder = None;
                encoder_config = None;
                active_capture_config = None;
                dynamic_window_fps_config = None;
                dynamic_window_fps_policy = None;
                dynamic_window_fps_decision = None;
                active_frame_interval = Duration::ZERO;
                {
                    let mut pipelines = app_state.media_pipelines.lock().await;
                    pipelines.set_active_encoder(session_id.clone(), "session_agent");
                    pipelines.set_active_media_profile(
                        session_id.clone(),
                        &lan_runtime_media_profile(&profile, requested_codec),
                    );
                    pipelines.set_codec_fallback_reason(session_id.clone(), None);
                }
                if access_units.is_empty() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    sender_stats.record_elapsed("sender.agent_wait", loop_started);
                    continue;
                }
                (access_units, "agent_encoded_ipc".to_string())
            } else {
                let source_id = selected_capture_source_id(&app_state, &session_id).await?;
                let selected_config_key = lan_capture_config_key(&source_id, &profile);
                let selected_dynamic_window_fps_config_key =
                    dynamic_window_fps_config_key(&source_id, &profile);
                let selected_source_is_window = is_windows_window_source_id(&source_id);
                let selected_window_capture_count = if selected_source_is_window {
                    active_window_capture_count(&app_state).await
                } else {
                    0
                };
                if selected_source_is_window {
                    if dynamic_window_fps_config.as_ref()
                        != Some(&selected_dynamic_window_fps_config_key)
                    {
                        let policy = DynamicWindowFpsPolicy::new(profile.fps);
                        dynamic_window_fps_decision = Some(policy.current());
                        dynamic_window_fps_policy = Some(policy);
                        dynamic_window_fps_config = Some(selected_dynamic_window_fps_config_key);
                    }
                } else {
                    dynamic_window_fps_config = None;
                    dynamic_window_fps_policy = None;
                    dynamic_window_fps_decision = None;
                }
                let capture_repeats_latest_frame = capture
                    .as_ref()
                    .is_some_and(LanSenderFrameCapture::repeats_latest_frame);
                let frame_interval = if capture_repeats_latest_frame {
                    macos_capture_pump_repeat_frame_interval(&profile)
                } else if selected_source_is_window {
                    media_frame_interval_for_dynamic_decision(&profile, dynamic_window_fps_decision)
                } else {
                    media_frame_interval(&profile)
                };
                if active_frame_interval != frame_interval {
                    active_frame_interval = frame_interval;
                    next_frame_at = Instant::now() + frame_interval;
                }
                let capture_drives_sender_pacing = capture
                    .as_ref()
                    .is_some_and(LanSenderFrameCapture::drives_sender_pacing);
                if capture_drives_sender_pacing {
                    next_frame_at = Instant::now() + frame_interval;
                } else if let Some(delay_until) =
                    schedule_next_media_frame(Instant::now(), &mut next_frame_at, frame_interval)
                {
                    let pacing_started = Instant::now();
                    sleep_until_media_frame(delay_until, &profile).await;
                    sender_stats.record_elapsed("sender.pacing_wait", pacing_started);
                }
                if !session_allows_media(&app_state, &session_id).await {
                    return Ok(());
                }
                if !lan_capture_config_matches(active_capture_config.as_ref(), &source_id, &profile)
                {
                    match create_lan_frame_capture(&source_id, &profile).await {
                        Ok(next_capture) => {
                            match LanSenderFrameCapture::new(next_capture, &profile) {
                                Ok(next_sender_capture) => {
                                    capture = Some(next_sender_capture);
                                    encoder = None;
                                    encoder_config = None;
                                    active_capture_config = Some(selected_config_key.clone());
                                    consecutive_frame_errors = 0;
                                    set_session_last_error(&app_state, &session_id, None).await;
                                }
                                Err(error) => {
                                    capture = None;
                                    encoder = None;
                                    encoder_config = None;
                                    active_capture_config = None;
                                    update_dynamic_window_fps_decision(
                                        &mut dynamic_window_fps_policy,
                                        &mut dynamic_window_fps_decision,
                                        false,
                                        false,
                                        selected_window_capture_count,
                                    );
                                    handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            &source_id,
                            &mut consecutive_frame_errors,
                            format_capture_source_failure(
                                &source_id,
                                format!("failed to initialize LAN capture sender: {error:#}"),
                                is_windows_window_source_id,
                            ),
                            selected_source_is_window,
                        )
                        .await?;
                                    continue;
                                }
                            }
                        }
                        Err(error) => {
                            capture = None;
                            encoder = None;
                            encoder_config = None;
                            active_capture_config = None;
                            update_dynamic_window_fps_decision(
                                &mut dynamic_window_fps_policy,
                                &mut dynamic_window_fps_decision,
                                false,
                                false,
                                selected_window_capture_count,
                            );
                            handle_media_sender_frame_error(
                                &app_state,
                                &session_id,
                                &source_id,
                                &mut consecutive_frame_errors,
                                format_capture_source_failure(
                                    &source_id,
                                    format!("failed to create LAN capture source: {error:#}"),
                                    is_windows_window_source_id,
                                ),
                                selected_source_is_window,
                            )
                            .await?;
                            continue;
                        }
                    }
                }

                let capture_started = Instant::now();
                let raw_frame_result = capture
                    .as_mut()
                    .context("LAN media capture was not initialized")
                    .and_then(|capture| {
                        capture
                            .capture_frame()
                            .context("failed to capture LAN desktop frame")
                    });
                sender_stats.record_elapsed("sender.capture", capture_started);
                let raw_capture = match raw_frame_result {
                    Ok(capture) => capture,
                    Err(error) => {
                        let error_source_id = active_capture_config
                            .as_ref()
                            .map(|config| config.source_id.as_str())
                            .unwrap_or("<unknown>")
                            .to_string();
                        if selected_source_is_window
                            && is_winrt_window_capture_no_frame_timeout(&error)
                        {
                            if let Some(policy) = dynamic_window_fps_policy.as_mut() {
                                dynamic_window_fps_decision = Some(policy.update(
                                    window_dynamic_fps_input_for_capture_error(
                                        &error,
                                        selected_window_capture_count,
                                    ),
                                ));
                            }
                            continue;
                        }
                        capture = None;
                        encoder = None;
                        encoder_config = None;
                        active_capture_config = None;
                        update_dynamic_window_fps_decision(
                            &mut dynamic_window_fps_policy,
                            &mut dynamic_window_fps_decision,
                            false,
                            false,
                            selected_window_capture_count,
                        );
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            &error_source_id,
                            &mut consecutive_frame_errors,
                            format_capture_source_failure(
                                &error_source_id,
                                format!("{error:#}"),
                                is_windows_window_source_id,
                            ),
                            is_windows_window_source_id(&error_source_id),
                        )
                        .await?;
                        continue;
                    }
                };
                if raw_capture.repeated_latest_frame {
                    sender_stats.record_repeated_latest_frame();
                }
                let raw_frame = raw_capture.frame;
                sender_stats.record_captured_frame(&raw_frame);
                let capture_memory_path = captured_frame_memory_path(&raw_frame).to_string();
                if let Some(policy) = dynamic_window_fps_policy.as_mut() {
                    dynamic_window_fps_decision = Some(policy.update(
                        window_dynamic_fps_input_for_captured_frame(selected_window_capture_count),
                    ));
                }
                let prepare_started = Instant::now();
                let frame_result = prepare_frame_for_h264(raw_frame, &profile);
                sender_stats.record_elapsed("sender.prepare", prepare_started);
                let frame = match frame_result {
                    Ok(frame) => frame,
                    Err(error) => {
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            active_capture_config
                                .as_ref()
                                .map(|config| config.source_id.as_str())
                                .unwrap_or("<unknown>"),
                            &mut consecutive_frame_errors,
                            format!("failed to prepare captured frame for H.264: {error:#}"),
                            false,
                        )
                        .await?;
                        continue;
                    }
                };
                let expected_encoder_config = (
                    frame.width,
                    frame.height,
                    profile.fps,
                    profile.bitrate_mbps,
                    requested_codec,
                    profile.color_mode.clone(),
                    profile.color_pipeline.clone(),
                    profile.codec_profile.clone(),
                    profile.bit_depth,
                    profile.pixel_format.clone(),
                );
                if encoder_config.as_ref() != Some(&expected_encoder_config) {
                    let peer_media_capabilities = app_state
                        .peer_media_capabilities
                        .lock()
                        .await
                        .get(&session_id)
                        .unwrap_or_default();
                    let allow_h264_fallback = lan_sender_allows_h264_encoder_fallback(
                        requested_codec,
                        &peer_media_capabilities,
                    );
                    let encoder_create_started = Instant::now();
                    match create_lan_encoder(
                        requested_codec,
                        frame.width,
                        frame.height,
                        profile.fps,
                        profile.bitrate_mbps.saturating_mul(1_000_000).max(1),
                        &profile,
                        allow_h264_fallback,
                    )
                    .context("failed to create LAN media encoder")
                    {
                        Ok(next_encoder) => {
                            sender_stats
                                .record_elapsed("sender.encoder_create", encoder_create_started);
                            let runtime_profile =
                                lan_runtime_media_profile(&profile, next_encoder.codec);
                            let fallback_reason =
                                (next_encoder.codec != requested_codec).then(|| {
                                    format!(
                                        "{} unavailable; fell back to {} via {}",
                                        requested_codec.display_name(),
                                        next_encoder.codec.display_name(),
                                        next_encoder.backend
                                    )
                                });
                            {
                                let mut pipelines = app_state.media_pipelines.lock().await;
                                pipelines
                                    .set_active_encoder(session_id.clone(), next_encoder.backend);
                                pipelines
                                    .set_active_media_profile(session_id.clone(), &runtime_profile);
                                pipelines
                                    .set_codec_fallback_reason(session_id.clone(), fallback_reason);
                            }
                            encoder = Some(next_encoder);
                            encoder_config = Some(expected_encoder_config);
                        }
                        Err(error) => {
                            sender_stats
                                .record_elapsed("sender.encoder_create", encoder_create_started);
                            encoder = None;
                            encoder_config = None;
                            handle_media_sender_frame_error(
                                &app_state,
                                &session_id,
                                active_capture_config
                                    .as_ref()
                                    .map(|config| config.source_id.as_str())
                                    .unwrap_or("<unknown>"),
                                &mut consecutive_frame_errors,
                                format!("{error:#}"),
                                false,
                            )
                            .await?;
                            continue;
                        }
                    }
                }

                if pending_keyframe_request {
                    if let Some(encoder) = encoder.as_mut() {
                        encoder.encoder.request_keyframe();
                        pending_keyframe_request = false;
                    }
                }

                let encode_started = Instant::now();
                let encode_result = encoder
                    .as_mut()
                    .context("LAN media encoder was not initialized")
                    .and_then(|encoder| {
                        encoder
                            .encoder
                            .encode(&frame)
                            .context("failed to encode LAN desktop frame")
                    });
                sender_stats.record_elapsed("sender.encode", encode_started);
                let encoded_access_units = match encode_result {
                    Ok(access_units) => access_units,
                    Err(error) => {
                        encoder = None;
                        encoder_config = None;
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            active_capture_config
                                .as_ref()
                                .map(|config| config.source_id.as_str())
                                .unwrap_or("<unknown>"),
                            &mut consecutive_frame_errors,
                            format!("{error:#}"),
                            false,
                        )
                        .await?;
                        continue;
                    }
                };

                let runtime_codec = encoder
                    .as_ref()
                    .map(|encoder| encoder.codec)
                    .unwrap_or(requested_codec);
                let access_units = encoded_access_units
                    .into_iter()
                    .map(|access_unit| AgentTransportUnit {
                        codec: runtime_codec,
                        timestamp_us: access_unit.timestamp_us,
                        is_keyframe: match runtime_codec {
                            LanAccessUnitCodec::H264 => h264_access_unit_is_keyframe(
                                access_unit.is_keyframe,
                                &access_unit.bytes,
                            ),
                            LanAccessUnitCodec::Hevc | LanAccessUnitCodec::Av1 => {
                                access_unit.is_keyframe
                            }
                        },
                        bytes: access_unit.bytes,
                    })
                    .collect();
                (access_units, capture_memory_path)
            };

        for access_unit in access_units {
            let runtime_codec = access_unit.codec;
            let runtime_profile = lan_runtime_media_profile(&profile, runtime_codec);
            let transport_envelope = media_sender::transport_envelope_from_agent_unit(
                &session_id,
                frame_id,
                profile.width,
                profile.height,
                access_unit,
            );
            let video_metadata = transport_envelope
                .video
                .as_ref()
                .expect("LAN sender always creates video metadata");
            let is_keyframe = video_metadata.keyframe;
            let access_unit_payload = &transport_envelope.payload;
            sender_stats.record_encoded_access_unit(access_unit_payload.len(), is_keyframe);

            if let Some(mux) = transport_mux.as_ref() {
                // The mux owns QUIC packetization, reliable-keyframe policy, and
                // endpoint I/O. Keep authorization and test impairment at the
                // application boundary before the envelope becomes visible.
                let decision = test_impairment.next_datagram_decision();
                if decision.drop_datagram {
                    frame_id = frame_id.wrapping_add(1).max(1);
                    continue;
                }
                if !decision.delay.is_zero()
                    && run_lan_media_operation_while_authorized(
                        &app_state,
                        &session_id,
                        &endpoint,
                        tokio::time::sleep(decision.delay),
                    )
                    .await
                    .is_none()
                {
                    return Ok(());
                }
                let Some(send_result) = run_lan_media_operation_while_authorized(
                    &app_state,
                    &session_id,
                    &endpoint,
                    mux.send(transport_envelope.clone()),
                )
                .await
                else {
                    return Ok(());
                };
                match send_result.context("failed to submit LAN video envelope to transport mux")? {
                    // Enqueue acceptance is not wire-send evidence. The mux owns packetization
                    // and asynchronous endpoint I/O, so legacy fragment counters intentionally
                    // remain unchanged on this route.
                    TransportSendOutcome::Enqueued | TransportSendOutcome::ReplacedStale => {}
                    TransportSendOutcome::Backpressured => {
                        frame_id = frame_id.wrapping_add(1).max(1);
                        continue;
                    }
                    TransportSendOutcome::Closed => {
                        anyhow::bail!("LAN transport mux closed while sending video");
                    }
                }
                sender_stats.frame_completed();
                if let Some(stats_payload) = sender_stats.take_payload(
                    Instant::now(),
                    frame_id,
                    active_capture_config
                        .as_ref()
                        .map(|config| config.source_id.clone()),
                    active_capture_config
                        .as_ref()
                        .and_then(|config| capture_source_kind_from_id(&config.source_id)),
                    Some(capture_memory_path.clone()),
                    &profile,
                    dynamic_window_fps_decision,
                    test_impairment.snapshot(),
                ) {
                    {
                        let mut pipelines = app_state.media_pipelines.lock().await;
                        pipelines
                            .set_stage_metrics(session_id.clone(), stats_payload.metrics.clone());
                        pipelines.set_test_impairment(
                            session_id.clone(),
                            stats_payload.test_impairment.clone(),
                        );
                        pipelines.set_sender_transport(
                            session_id.clone(),
                            stats_payload.sender_transport.clone(),
                        );
                    }
                    let stats = encode_lan_sender_stats_datagram(&stats_payload)?;
                    if stats.len() <= negotiated_max_datagram_size {
                        if let Err(error) = mux
                            .send_passthrough_datagram(bytes::Bytes::from(stats))
                            .await
                        {
                            tracing::debug!(
                                %error,
                                session_id = %session_id.0,
                                frame_id,
                                "LAN mux sender stats datagram was dropped"
                            );
                        }
                    }
                }
                frame_id = frame_id.wrapping_add(1).max(1);
                continue;
            }

            let fragment_started = Instant::now();
            let fragments = if media_v3_supported {
                match fragment_media_payload_v3(
                    QuicMediaPayloadType::AccessUnit,
                    runtime_codec.quic_codec(),
                    lan_media_profile_id(&profile),
                    frame_id as u32,
                    video_metadata.timestamp_us,
                    is_keyframe,
                    access_unit_payload,
                    test_impairment.effective_datagram_size(max_datagram_size),
                )
                .context("failed to fragment LAN QUIC media v3 frame")
                {
                    Ok(fragments) => fragments,
                    Err(error) => {
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            active_capture_config
                                .as_ref()
                                .map(|config| config.source_id.as_str())
                                .unwrap_or("<unknown>"),
                            &mut consecutive_frame_errors,
                            format!("{error:#}"),
                            true,
                        )
                        .await?;
                        frame_id = frame_id.wrapping_add(1).max(1);
                        continue;
                    }
                }
            } else {
                let media_payload = match encode_lan_media_envelope(LanMediaEnvelope {
                    payload_type: LAN_MEDIA_PAYLOAD_ACCESS_UNIT,
                    codec: runtime_codec.envelope_codec(),
                    sequence: frame_id,
                    timestamp_us: video_metadata.timestamp_us,
                    profile: runtime_profile.clone(),
                    payload: access_unit_payload.clone(),
                }) {
                    Ok(media_payload) => media_payload,
                    Err(error) => {
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            active_capture_config
                                .as_ref()
                                .map(|config| config.source_id.as_str())
                                .unwrap_or("<unknown>"),
                            &mut consecutive_frame_errors,
                            format!("{error:#}"),
                            true,
                        )
                        .await?;
                        frame_id = frame_id.wrapping_add(1).max(1);
                        continue;
                    }
                };
                match fragment_access_unit(
                    frame_id as u32,
                    video_metadata.timestamp_us,
                    is_keyframe,
                    &media_payload,
                    test_impairment.effective_datagram_size(max_datagram_size),
                )
                .context("failed to fragment LAN QUIC media v2 frame")
                {
                    Ok(fragments) => fragments,
                    Err(error) => {
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            active_capture_config
                                .as_ref()
                                .map(|config| config.source_id.as_str())
                                .unwrap_or("<unknown>"),
                            &mut consecutive_frame_errors,
                            format!("{error:#}"),
                            true,
                        )
                        .await?;
                        frame_id = frame_id.wrapping_add(1).max(1);
                        continue;
                    }
                }
            };
            sender_stats.record_elapsed("sender.fragment", fragment_started);
            test_impairment.record_mtu_fragmentation(max_datagram_size);

            let reliable_media_enabled =
                reliable_media_send_mode != LanReliableMediaSendMode::Disabled;
            let send_as_reliable_frame = should_send_access_unit_as_reliable_frame(
                reliable_media_enabled,
                media_v3_supported,
                fragments.len(),
                &profile,
                reliable_whole_frame_media_override(),
            );
            let reliable_fragments = if send_as_reliable_frame {
                let reliable_fragment_started = Instant::now();
                let result = fragment_media_payload_v3(
                    QuicMediaPayloadType::AccessUnit,
                    runtime_codec.quic_codec(),
                    lan_media_profile_id(&profile),
                    frame_id as u32,
                    video_metadata.timestamp_us,
                    is_keyframe,
                    access_unit_payload,
                    LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES,
                )
                .context("failed to fragment LAN QUIC reliable media v3 frame");
                sender_stats.record_elapsed("sender.reliable_fragment", reliable_fragment_started);
                match result {
                    Ok(reliable_fragments) => Some(reliable_fragments),
                    Err(error) => {
                        handle_media_sender_frame_error(
                            &app_state,
                            &session_id,
                            active_capture_config
                                .as_ref()
                                .map(|config| config.source_id.as_str())
                                .unwrap_or("<unknown>"),
                            &mut consecutive_frame_errors,
                            format!("{error:#}"),
                            true,
                        )
                        .await?;
                        frame_id = frame_id.wrapping_add(1).max(1);
                        continue;
                    }
                }
            } else if should_send_access_unit_reliably(
                reliable_media_enabled,
                is_keyframe,
                access_unit_payload.len(),
                max_datagram_size,
            ) {
                Some(fragments.clone())
            } else {
                None
            };

            // Capture and encoding can outlast the grant boundary. Recheck at
            // the last frame-level boundary before any payload becomes visible
            // to the peer.
            if !session_allows_media(&app_state, &session_id).await {
                return Ok(());
            }

            let mut send_result = Ok(());
            if send_as_reliable_frame {
                let reliable_send_started = Instant::now();
                let mut reliable_fragments_sent = 0_u64;
                for reliable_fragment in reliable_fragments.unwrap_or_default() {
                    let delay = test_impairment.next_delay();
                    if !delay.is_zero()
                        && run_lan_media_operation_while_authorized(
                            &app_state,
                            &session_id,
                            &endpoint,
                            tokio::time::sleep(delay),
                        )
                        .await
                        .is_none()
                    {
                        return Ok(());
                    }
                    if !session_allows_media(&app_state, &session_id).await {
                        return Ok(());
                    }
                    let Some(send) = run_lan_media_operation_while_authorized(
                        &app_state,
                        &session_id,
                        &endpoint,
                        send_lan_reliable_media_fragment(
                            &endpoint,
                            reliable_media_send_mode,
                            reliable_fragment,
                        ),
                    )
                    .await
                    else {
                        return Ok(());
                    };
                    if let Err(error) = send {
                        send_result = Err(error).with_context(|| {
                            format!("failed to send LAN QUIC reliable media frame {}", frame_id)
                        });
                        break;
                    }
                    reliable_fragments_sent = reliable_fragments_sent.saturating_add(1);
                }
                sender_stats.record_elapsed("sender.send_reliable", reliable_send_started);
                sender_stats.record_reliable_frame(
                    reliable_fragments_sent,
                    reliable_fragments_sent > 0 && send_result.is_ok(),
                );
            } else {
                let best_effort_datagrams = use_best_effort_media_datagrams(&profile);
                let datagram_send_started = Instant::now();
                let datagram_send_deadline =
                    lan_datagram_frame_send_budget(&profile, reliable_media_enabled)
                        .and_then(|budget| datagram_send_started.checked_add(budget));
                let mut datagram_report = LanSenderDatagramFrameReport {
                    fragments_attempted: fragments.len() as u64,
                    ..LanSenderDatagramFrameReport::default()
                };
                let mut skip_unsent_datagram_frame = false;
                let mut delayed_fragments = Vec::new();
                for (fragment_index, fragment) in fragments.iter().enumerate() {
                    if !session_allows_media(&app_state, &session_id).await {
                        return Ok(());
                    }
                    let frame_send_started =
                        datagram_report.fragments_sent > 0 || datagram_report.fragments_delayed > 0;
                    let remaining_send_budget = if frame_send_started {
                        None
                    } else {
                        datagram_send_deadline
                            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                    };
                    if !frame_send_started
                        && remaining_send_budget.is_some_and(|remaining| remaining.is_zero())
                    {
                        datagram_report.fragments_dropped_for_budget = datagram_report
                            .fragments_dropped_for_budget
                            .saturating_add((fragments.len() - fragment_index) as u64);
                        datagram_report.cut_short_for_budget = true;
                        skip_unsent_datagram_frame = true;
                        break;
                    }
                    let decision = test_impairment.next_datagram_decision();
                    if decision.drop_datagram {
                        datagram_report.fragments_dropped_by_impairment = datagram_report
                            .fragments_dropped_by_impairment
                            .saturating_add(1);
                        continue;
                    }
                    if !decision.delay.is_zero() {
                        datagram_report.fragments_delayed =
                            datagram_report.fragments_delayed.saturating_add(1);
                        delayed_fragments.push((decision.delay, fragment_index, fragment.clone()));
                        continue;
                    }
                    if !session_allows_media(&app_state, &session_id).await {
                        return Ok(());
                    }
                    let Some(send_fragment_result) = run_lan_media_operation_while_authorized(
                        &app_state,
                        &session_id,
                        &endpoint,
                        send_lan_media_datagram(
                            &endpoint,
                            fragment.clone(),
                            !best_effort_datagrams,
                            remaining_send_budget,
                        ),
                    )
                    .await
                    else {
                        return Ok(());
                    };
                    match send_fragment_result {
                        Ok(LanDatagramSendOutcome::Sent) => {
                            datagram_report.fragments_sent =
                                datagram_report.fragments_sent.saturating_add(1);
                        }
                        Ok(LanDatagramSendOutcome::DroppedForCapacity) => {
                            datagram_report.fragments_dropped_for_capacity = datagram_report
                                .fragments_dropped_for_capacity
                                .saturating_add(
                                    (fragments.len() - fragment_index + delayed_fragments.len())
                                        as u64,
                                );
                            datagram_report.cut_short_for_capacity = true;
                            if !frame_send_started {
                                skip_unsent_datagram_frame = true;
                            }
                            break;
                        }
                        Err(error) => {
                            send_result = Err(error).with_context(|| {
                                format!("failed to send LAN QUIC media frame {}", frame_id)
                            });
                            break;
                        }
                    }
                }
                if !skip_unsent_datagram_frame
                    && send_result.is_ok()
                    && !delayed_fragments.is_empty()
                {
                    delayed_fragments
                        .sort_by_key(|(delay, fragment_index, _)| (*delay, *fragment_index));
                    let delayed_endpoint = endpoint.clone();
                    let delayed_app_state = app_state.clone();
                    let delayed_session_id = session_id.clone();
                    let delayed_frame_id = frame_id;
                    delayed_media_children.spawn(async move {
                        let delayed_send_started = Instant::now();
                        for (delay, _, fragment) in delayed_fragments {
                            let remaining_delay =
                                delay.saturating_sub(delayed_send_started.elapsed());
                            if !remaining_delay.is_zero() {
                                tokio::time::sleep(remaining_delay).await;
                            }
                            let Some(send_result) = run_lan_media_operation_while_authorized(
                                &delayed_app_state,
                                &delayed_session_id,
                                &delayed_endpoint,
                                send_lan_media_datagram(
                                    &delayed_endpoint,
                                    fragment,
                                    !best_effort_datagrams,
                                    None,
                                ),
                            )
                            .await
                            else {
                                break;
                            };
                            match send_result {
                                Ok(LanDatagramSendOutcome::Sent) => {}
                                Ok(LanDatagramSendOutcome::DroppedForCapacity) => {
                                    tracing::debug!(
                                        session_id = %delayed_session_id.0,
                                        frame_id = delayed_frame_id,
                                        "delayed LAN QUIC media frame cut short for capacity"
                                    );
                                    break;
                                }
                                Err(error) => {
                                    tracing::debug!(
                                        %error,
                                        session_id = %delayed_session_id.0,
                                        frame_id = delayed_frame_id,
                                        "delayed LAN QUIC media datagram send failed"
                                    );
                                    break;
                                }
                            }
                        }
                    });
                }
                sender_stats.record_datagram_frame(datagram_report);
                sender_stats.record_elapsed("sender.send_datagram", datagram_send_started);

                if skip_unsent_datagram_frame {
                    continue;
                }

                if send_result.is_ok() {
                    if let Some(reliable_fragments) = reliable_fragments {
                        if can_spawn_reliable_keyframe_child(reliable_keyframe_children.len()) {
                            let reliable_endpoint = endpoint.clone();
                            let reliable_app_state = app_state.clone();
                            let reliable_session_id = session_id.clone();
                            let reliable_frame_id = frame_id;
                            let reliable_send_mode = reliable_media_send_mode;
                            reliable_keyframe_children.spawn(async move {
                                for reliable_fragment in reliable_fragments {
                                    if !session_allows_media(
                                        &reliable_app_state,
                                        &reliable_session_id,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                    let Some(send_result) =
                                        run_lan_media_operation_while_authorized(
                                            &reliable_app_state,
                                            &reliable_session_id,
                                            &reliable_endpoint,
                                            send_lan_reliable_media_fragment(
                                                &reliable_endpoint,
                                                reliable_send_mode,
                                                reliable_fragment,
                                            ),
                                        )
                                        .await
                                    else {
                                        break;
                                    };
                                    if let Err(error) = send_result {
                                        tracing::warn!(
                                            %error,
                                            session_id = %reliable_session_id.0,
                                            frame_id = reliable_frame_id,
                                            "LAN QUIC reliable keyframe fragment send failed"
                                        );
                                        break;
                                    }
                                }
                            });
                        } else {
                            tracing::debug!(
                                session_id = %session_id.0,
                                frame_id,
                                "skipping reliable keyframe redundancy while the bounded sender is busy"
                            );
                        }
                    }
                }
            }

            if let Err(error) = send_result {
                handle_media_sender_frame_error(
                    &app_state,
                    &session_id,
                    active_capture_config
                        .as_ref()
                        .map(|config| config.source_id.as_str())
                        .unwrap_or("<unknown>"),
                    &mut consecutive_frame_errors,
                    format!("{error:#}"),
                    true,
                )
                .await?;
                frame_id = frame_id.wrapping_add(1).max(1);
                continue;
            }
            sender_stats.frame_completed();
            if !session_allows_media(&app_state, &session_id).await {
                return Ok(());
            }
            if let Some(stats_payload) = sender_stats.take_payload(
                Instant::now(),
                frame_id,
                active_capture_config
                    .as_ref()
                    .map(|config| config.source_id.clone()),
                active_capture_config
                    .as_ref()
                    .and_then(|config| capture_source_kind_from_id(&config.source_id)),
                Some(capture_memory_path.clone()),
                &profile,
                dynamic_window_fps_decision,
                test_impairment.snapshot(),
            ) {
                {
                    let mut pipelines = app_state.media_pipelines.lock().await;
                    pipelines.set_stage_metrics(session_id.clone(), stats_payload.metrics.clone());
                    pipelines.set_test_impairment(
                        session_id.clone(),
                        stats_payload.test_impairment.clone(),
                    );
                    pipelines.set_sender_transport(
                        session_id.clone(),
                        stats_payload.sender_transport.clone(),
                    );
                }
                let stats_send_started = Instant::now();
                if let Err(error) =
                    send_lan_sender_stats_datagram(&endpoint, max_datagram_size, &stats_payload)
                {
                    tracing::debug!(
                        %error,
                        session_id = %session_id.0,
                        frame_id,
                        "LAN sender stats datagram was dropped"
                    );
                }
                sender_stats.record_elapsed("sender.stats_send", stats_send_started);
            }
            frame_id = frame_id.wrapping_add(1).max(1);
        }
        sender_stats.record_elapsed("sender.loop", loop_started);

        if consecutive_frame_errors > 0 {
            consecutive_frame_errors = 0;
            set_session_last_error(&app_state, &session_id, None).await;
        }
    }
}

fn can_spawn_reliable_keyframe_child(in_flight: usize) -> bool {
    in_flight < LAN_RELIABLE_KEYFRAME_SEND_TASK_LIMIT
}

async fn run_lan_media_operation_while_authorized<F, T>(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    endpoint: &QuinnDatagramEndpoint,
    operation: F,
) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let Some(lease) = app_state
        .session_authorizations
        .acquire_scope_lease(session_id, RemotePermissionScope::ScreenView)
        .await
    else {
        endpoint.close_immediately(b"remote authorization invalid");
        return None;
    };
    let outcome = {
        let invalid = lease.wait_until_invalid();
        tokio::pin!(invalid);
        tokio::pin!(operation);
        tokio::select! {
            biased;
            _ = &mut invalid => {
                // Quinn implicitly finishes a SendStream when its future is
                // dropped. Close the connection first so a partially written
                // reliable media message is reset instead of surfacing as a
                // successful truncated message at the peer.
                endpoint.close_immediately(b"remote authorization invalid");
                None
            },
            output = &mut operation => Some(output),
        }
    };
    if outcome.is_none() {
        let _ = app_state
            .session_authorizations
            .snapshot_at(session_id, now_ms())
            .await;
    }
    outcome
}

async fn handle_media_sender_frame_error(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_id: &str,
    consecutive_frame_errors: &mut u32,
    message: String,
    fail_after_limit: bool,
) -> Result<()> {
    *consecutive_frame_errors = consecutive_frame_errors.saturating_add(1);
    let decorated_message = if fail_after_limit {
        format!(
            "LAN media sender transient frame error {}/{} for source '{}': {}",
            *consecutive_frame_errors,
            LAN_MEDIA_SENDER_MAX_CONSECUTIVE_FRAME_ERRORS,
            source_id,
            message
        )
    } else {
        format!(
            "LAN media sender recoverable frame error {} for source '{}': {}",
            *consecutive_frame_errors, source_id, message
        )
    };

    if should_log_media_sender_frame_error(*consecutive_frame_errors) {
        tracing::warn!(
            session_id = %session_id.0,
            source_id,
            consecutive_frame_errors = *consecutive_frame_errors,
            error = %message,
            "LAN media sender skipped a frame"
        );
    }
    set_session_last_error(app_state, session_id, Some(decorated_message.clone())).await;

    if fail_after_limit
        && *consecutive_frame_errors >= LAN_MEDIA_SENDER_MAX_CONSECUTIVE_FRAME_ERRORS
    {
        anyhow::bail!("{decorated_message}");
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn lan_capture_pump_enabled() -> bool {
    env_bool_override(std::env::var(LAN_CAPTURE_PUMP_ENV).ok().as_deref()).unwrap_or(true)
}

#[cfg(target_os = "macos")]
fn lan_capture_pump_drives_sender() -> bool {
    env_bool_override(
        std::env::var(LAN_CAPTURE_PUMP_DRIVES_SENDER_ENV)
            .ok()
            .as_deref(),
    )
    .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn lan_capture_pump_repeat_latest() -> bool {
    lan_capture_pump_repeat_latest_from_env_value(
        std::env::var(LAN_CAPTURE_PUMP_REPEAT_LATEST_ENV)
            .ok()
            .as_deref(),
    )
}

#[cfg(target_os = "macos")]
fn lan_capture_pump_repeat_latest_from_env_value(value: Option<&str>) -> bool {
    // ScreenCaptureKit can deliver below the requested cadence when the source display
    // refreshes slowly or its contents are mostly idle. Prefer a fresh frame during the
    // short grace window, then repeat the latest retained CVPixelBuffer so the transport
    // and renderer still keep the negotiated frame cadence.
    env_bool_override(value).unwrap_or(true)
}

#[cfg(target_os = "macos")]
fn macos_capture_pump_repeat_pacing_fps(profile: &MediaProfile) -> u32 {
    std::env::var(LAN_CAPTURE_PUMP_REPEAT_PACING_FPS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|fps| *fps > 0)
        .unwrap_or_else(|| profile.fps.max(1))
        .clamp(profile.fps.max(1), 240)
}

#[cfg(target_os = "macos")]
fn macos_capture_pump_repeat_frame_interval(profile: &MediaProfile) -> Duration {
    media_frame_interval_for_fps(macos_capture_pump_repeat_pacing_fps(profile))
}

#[cfg(target_os = "macos")]
fn macos_capture_pump_repeat_grace_timeout(profile: &MediaProfile) -> Duration {
    (media_frame_interval_for_fps(macos_lan_capture_stream_fps(profile)) / 2)
        .min(LAN_CAPTURE_PUMP_REPEAT_GRACE_MAX)
}

#[cfg(not(target_os = "macos"))]
fn macos_capture_pump_repeat_frame_interval(profile: &MediaProfile) -> Duration {
    media_frame_interval(profile)
}

#[cfg(target_os = "macos")]
fn macos_render_proxy_compressed_media_enabled() -> bool {
    media_receiver::compressed_proxy_enabled()
}

#[cfg(target_os = "macos")]
fn macos_render_proxy_compressed_media_enabled_for_profile(profile: &MediaProfile) -> bool {
    media_receiver::compressed_proxy_enabled_for_profile(profile)
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn lan_local_render_fps_cap() -> Option<u32> {
    lan_local_render_refresh_hz()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) fn lan_local_render_fps_cap() -> Option<u32> {
    None
}

#[cfg(windows)]
fn lan_local_render_refresh_hz() -> Option<u32> {
    if let Some(refresh_hz) = std::env::var(LAN_RENDER_MAX_FPS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
    {
        return Some(refresh_hz);
    }

    *LOCAL_RENDER_REFRESH_HZ.get_or_init(crate::display_mode::highest_current_refresh_hz)
}

#[cfg(target_os = "macos")]
fn lan_local_render_refresh_hz() -> Option<u32> {
    if let Some(refresh_hz) = std::env::var(LAN_RENDER_MAX_FPS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
    {
        return Some(refresh_hz);
    }

    *LOCAL_RENDER_REFRESH_HZ.get_or_init(mrd_capture_macos::highest_current_display_refresh_hz)
}

async fn maybe_send_lan_keyframe_request(
    endpoint: &QuinnDatagramEndpoint,
    transport_mux: Option<&QuicTransportMux>,
    session_id: &SessionId,
    profile: &MediaProfile,
    sequence: &mut u32,
    last_sent_at: &mut Option<Instant>,
    stats: &mut LanSenderStatsTracker,
) {
    let now = Instant::now();
    if last_sent_at.is_some_and(|last| {
        now.checked_duration_since(last)
            .is_some_and(|elapsed| elapsed < LAN_MEDIA_KEYFRAME_REQUEST_MIN_INTERVAL)
    }) {
        return;
    }
    *last_sent_at = Some(now);
    *sequence = sequence.wrapping_add(1).max(1);
    let max_datagram_size = endpoint
        .max_datagram_size()
        .unwrap_or(LAN_QUIC_FALLBACK_DATAGRAM_BYTES);
    match encode_lan_keyframe_request_datagram(profile, *sequence, max_datagram_size) {
        Ok(datagram) => {
            let send_result = if let Some(mux) = transport_mux {
                mux.send_passthrough_datagram(datagram).await
            } else {
                endpoint
                    .send_datagram(datagram)
                    .map_err(anyhow::Error::from)
            };
            match send_result {
                Ok(()) => {
                    stats.record_ms("receiver.request_keyframe", 1.0);
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        session_id = %session_id.0,
                        "LAN media receiver failed to send keyframe request"
                    );
                }
            }
        }
        Err(error) => {
            tracing::debug!(
                %error,
                session_id = %session_id.0,
                "LAN media receiver failed to encode keyframe request"
            );
        }
    }
}

fn spawn_lan_media_control_reader(
    endpoint: QuinnDatagramEndpoint,
    session_id: SessionId,
    keyframe_requests: Arc<AtomicU64>,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        loop {
            let datagram = match endpoint.read_datagram().await {
                Ok(datagram) => datagram,
                Err(error) => {
                    tracing::debug!(
                        %error,
                        session_id = %session_id.0,
                        "LAN media sender control reader stopped"
                    );
                    break;
                }
            };
            match decode_lan_keyframe_request_datagram(&datagram) {
                Ok(true) => {
                    keyframe_requests.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!(
                        %error,
                        session_id = %session_id.0,
                        bytes = datagram.len(),
                        "LAN media sender ignored invalid control datagram"
                    );
                }
            }
        }
    }))
}

fn spawn_lan_mux_control_reader(
    mux: Arc<QuicTransportMux>,
    session_id: SessionId,
    keyframe_requests: Arc<AtomicU64>,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        while let Some(datagram) = mux.recv_passthrough_datagram().await {
            match decode_lan_keyframe_request_datagram(&datagram) {
                Ok(true) => {
                    keyframe_requests.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!(
                        %error,
                        session_id = %session_id.0,
                        bytes = datagram.len(),
                        "LAN mux ignored invalid control datagram"
                    );
                }
            }
        }
    }))
}

async fn set_session_last_error(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    last_error: Option<String>,
) {
    let mut sessions = app_state.sessions.lock().await;
    let Some(snapshot) = sessions.get(session_id).cloned() else {
        return;
    };
    if snapshot.lifecycle_state.is_terminal() {
        return;
    }
    sessions.insert(
        session_id.clone(),
        SessionSnapshot {
            last_error,
            ..snapshot
        },
    );
}

fn spawn_quic_media_receiver(
    app_state: Arc<AppState>,
    session_id: SessionId,
    endpoint: QuinnDatagramEndpoint,
    start_rx: oneshot::Receiver<()>,
) -> tokio::task::AbortHandle {
    let registry = app_state.media_tasks.clone();
    let completion_registry = registry.clone();
    let failure_app_state = app_state.clone();
    let task_session_id = session_id.clone();
    let failure_session_id = task_session_id.clone();
    let handle = tokio::spawn(async move {
        if start_rx.await.is_err() {
            completion_registry
                .lock()
                .await
                .forget_task(&failure_session_id, tokio::task::id());
            return;
        }
        let result = receive_quic_media_loop(app_state, task_session_id.clone(), endpoint).await;
        completion_registry
            .lock()
            .await
            .forget_task(&failure_session_id, tokio::task::id());
        match result {
            Ok(()) => {
                terminate_authorized_remote_sessions(
                    &failure_app_state,
                    std::slice::from_ref(&failure_session_id),
                )
                .await;
            }
            Err(error) => {
                if session_allows_media(&failure_app_state, &failure_session_id).await {
                    tracing::warn!(%error, session_id = %task_session_id.0, "LAN QUIC media receiver stopped");
                    mark_session_failed(
                        &failure_app_state,
                        &failure_session_id,
                        format!("LAN QUIC media receiver failed: {error}"),
                    )
                    .await;
                    cleanup_lan_media_resources(&failure_app_state, &failure_session_id).await;
                } else {
                    terminate_authorized_remote_sessions(
                        &failure_app_state,
                        std::slice::from_ref(&failure_session_id),
                    )
                    .await;
                }
            }
        }
    });
    let abort_handle = handle.abort_handle();
    drop(handle);
    abort_handle
}

async fn receive_quic_media_loop(
    app_state: Arc<AppState>,
    session_id: SessionId,
    endpoint: QuinnDatagramEndpoint,
) -> Result<()> {
    let mut reassembler = QuicAuReassembler::new(lan_media_reassembler_config())
        .with_max_frame_bytes(LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES)
        .with_max_total_bytes(LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES * 4);
    let mut media_v3_reassembler = QuicMediaReassembler::new(lan_media_reassembler_config())
        .with_max_frame_bytes(LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES)
        .with_max_total_bytes(LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES * 4);
    let mut frame_orderer =
        LanMediaFrameOrderer::new(LAN_MEDIA_RECEIVER_REORDER_MAX_PENDING_FRAMES);
    #[cfg(target_os = "macos")]
    let mut media_v3_frame_orderer =
        LanMediaFrameOrderer::<QuicMediaFrame>::new(LAN_MEDIA_RECEIVER_REORDER_MAX_PENDING_FRAMES);
    let mut decoder = create_lan_receiver_decoder(&app_state, &session_id)
        .await
        .context("failed to create LAN media receiver decoder")?;
    let mut consecutive_decode_errors = 0_u32;
    let mut decoder_waits_for_keyframe = true;
    let transport_mux_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_TRANSPORT_MUX_V1);
    let transport_mux = transport_mux_supported.then(|| {
        Arc::new(QuicTransportMux::new(
            session_id.clone(),
            TransportMuxConfig::default(),
            endpoint.clone(),
        ))
    });
    let persistent_reliable_media_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_PERSISTENT_MEDIA_TRANSPORT);
    let persistent_reliable_media_60fps_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_PERSISTENT_MEDIA_60FPS_TRANSPORT);
    let per_message_reliable_media_supported = app_state
        .peer_media_capabilities
        .lock()
        .await
        .supports(&session_id, LAN_QUIC_RELIABLE_MEDIA_TRANSPORT);
    let initial_media_profile = selected_media_profile(&app_state, &session_id).await;
    let reliable_media_read_mode = if transport_mux.is_some() {
        LanReliableMediaSendMode::Disabled
    } else {
        select_reliable_media_send_mode_for_profile(
            per_message_reliable_media_supported,
            persistent_reliable_media_supported,
            persistent_reliable_media_60fps_supported,
            &initial_media_profile,
        )
    };
    let (mut reliable_media_rx, _reliable_media_reader) = if reliable_media_read_mode
        != LanReliableMediaSendMode::Disabled
    {
        // Keep only a short handoff queue. QUIC flow control provides the
        // upstream backpressure; a 32-frame queue alone adds over 500 ms at
        // 60 fps before the bounded render queues are even reached.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let reliable_endpoint = endpoint.clone();
        let reader = AbortOnDrop(tokio::spawn(async move {
            if reliable_media_read_mode == LanReliableMediaSendMode::PerMessage {
                let (first_stream_id, first_payload) = match reliable_endpoint
                    .read_reliable_message_with_stream_id(LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES)
                    .await
                {
                    Ok(message) => message,
                    Err(error) => {
                        let _ = tx.send(Err(error.to_string())).await;
                        return;
                    }
                };
                if tx.send(Ok(first_payload)).await.is_err() {
                    return;
                }

                let mut next_stream_id = first_stream_id.saturating_add(1);
                let mut completed = std::collections::BTreeMap::new();
                let mut reads = tokio::task::JoinSet::new();
                for _ in 0..LAN_QUIC_PER_MESSAGE_CONCURRENT_READS {
                    let endpoint = reliable_endpoint.clone();
                    reads.spawn(async move {
                        endpoint
                            .read_reliable_message_with_stream_id(LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES)
                            .await
                    });
                }
                while let Some(joined) = reads.join_next().await {
                    let (stream_id, payload) = match joined {
                        Ok(Ok(message)) => message,
                        Ok(Err(error)) => {
                            let _ = tx.send(Err(error.to_string())).await;
                            reads.abort_all();
                            break;
                        }
                        Err(error) => {
                            if error.is_cancelled() {
                                break;
                            }
                            let _ = tx
                                .send(Err(format!("reliable media read task failed: {error}")))
                                .await;
                            reads.abort_all();
                            break;
                        }
                    };
                    completed.insert(stream_id, payload);

                    while let Some(payload) = completed.remove(&next_stream_id) {
                        if tx.send(Ok(payload)).await.is_err() {
                            reads.abort_all();
                            return;
                        }
                        next_stream_id = next_stream_id.saturating_add(1);
                    }

                    while reads.len() + completed.len() < LAN_QUIC_PER_MESSAGE_CONCURRENT_READS {
                        let endpoint = reliable_endpoint.clone();
                        reads.spawn(async move {
                            endpoint
                                .read_reliable_message_with_stream_id(
                                    LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES,
                                )
                                .await
                        });
                    }
                }
                return;
            }
            loop {
                let result = match reliable_media_read_mode {
                    LanReliableMediaSendMode::Disabled => break,
                    LanReliableMediaSendMode::PerMessage => {
                        unreachable!("per-message reliable media uses concurrent stream readers")
                    }
                    LanReliableMediaSendMode::Persistent => {
                        reliable_endpoint
                            .read_reliable_message_persistent_with_timeout(
                                LAN_QUIC_RELIABLE_MEDIA_MAX_BYTES,
                                LAN_QUIC_PERSISTENT_MEDIA_HOL_TIMEOUT,
                            )
                            .await
                    }
                };
                let should_retry = result.is_err();
                if tx
                    .send(result.map_err(|error| error.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
                if should_retry {
                    tokio::time::sleep(LAN_QUIC_RELIABLE_MEDIA_RETRY_DELAY).await;
                }
            }
        }));
        (Some(rx), Some(reader))
    } else {
        (None, None)
    };
    let mut datagram_media_enabled = true;
    let mut mux_legacy_fragments = std::collections::VecDeque::new();
    let mut receiver_stats = LanSenderStatsTracker::new(Instant::now());
    let mut keyframe_request_sequence = 0_u32;
    let mut last_keyframe_request_at = None;
    maybe_send_lan_keyframe_request(
        &endpoint,
        transport_mux.as_deref(),
        &session_id,
        &initial_media_profile,
        &mut keyframe_request_sequence,
        &mut last_keyframe_request_at,
        &mut receiver_stats,
    )
    .await;
    loop {
        if !session_allows_media(&app_state, &session_id).await {
            return Ok(());
        }
        let read_started = Instant::now();
        let media_message = if let Some(fragment) = mux_legacy_fragments.pop_front() {
            fragment
        } else if let Some(mux) = transport_mux.as_ref() {
            tokio::select! {
                video = mux.recv(TransportLane::Video) => {
                    let envelope = match video.context("LAN transport mux video receive failed")? {
                        Some(envelope) => envelope,
                        None => anyhow::bail!("LAN transport mux closed while receiving video"),
                    };
                    let unit = media_receiver::transport_video_access_unit(&session_id, envelope)
                        .context("invalid LAN transport mux video envelope")?;
                    let mut profile = lan_runtime_media_profile(
                        &selected_media_profile(&app_state, &session_id).await,
                        unit.codec,
                    );
                    profile.width = unit.width;
                    profile.height = unit.height;
                    let media_payload = encode_lan_media_envelope(LanMediaEnvelope {
                        payload_type: LAN_MEDIA_PAYLOAD_ACCESS_UNIT,
                        codec: unit.codec.envelope_codec(),
                        sequence: unit.sequence,
                        timestamp_us: unit.timestamp_us,
                        profile,
                        payload: unit.bytes,
                    })?;
                    let mut fragments = fragment_access_unit(
                        unit.sequence as u32,
                        unit.timestamp_us,
                        unit.is_keyframe,
                        &media_payload,
                        mux.max_datagram_size().unwrap_or(LAN_QUIC_FALLBACK_DATAGRAM_BYTES),
                    )?;
                    let first = fragments
                        .first()
                        .cloned()
                        .context("transport mux produced no compatibility fragment")?;
                    mux_legacy_fragments.extend(fragments.drain(1..));
                    first
                }
                legacy = mux.recv_passthrough_datagram() => {
                    match legacy {
                        Some(message) => message,
                        None => anyhow::bail!("LAN transport mux passthrough closed"),
                    }
                }
                _ = tokio::time::sleep(LAN_MEDIA_AUTHORIZATION_POLL_INTERVAL) => {
                    continue;
                }
            }
        } else if let Some(rx) = reliable_media_rx.as_mut() {
            if datagram_media_enabled {
                let datagram_endpoint = endpoint.clone();
                tokio::select! {
                    result = datagram_endpoint.read_datagram() => {
                        match result {
                            Ok(message) => message,
                            Err(error) => {
                                datagram_media_enabled = false;
                                tracing::warn!(
                                    %error,
                                    session_id = %session_id.0,
                                    "LAN QUIC datagram media reader disabled while reliable media remains active"
                                );
                                continue;
                            }
                        }
                    }
                    message = rx.recv() => {
                        match message {
                            Some(Ok(message)) => message,
                            Some(Err(error)) => {
                                recover_persistent_media_hol_stall(
                                    &app_state,
                                    &session_id,
                                    &endpoint,
                                    transport_mux.as_deref(),
                                    &error,
                                    LanHolRecoveryState {
                                        receiver_stats: &mut receiver_stats,
                                        keyframe_request_sequence: &mut keyframe_request_sequence,
                                        last_keyframe_request_at: &mut last_keyframe_request_at,
                                    },
                                )
                                .await;
                                tracing::warn!(
                                    %error,
                                    session_id = %session_id.0,
                                    "LAN QUIC reliable media reader retrying"
                                );
                                continue;
                            }
                            None => {
                                reliable_media_rx = None;
                                tracing::warn!(
                                    session_id = %session_id.0,
                                    "LAN QUIC reliable media reader stopped"
                                );
                                continue;
                            }
                        }
                    }
                    _ = tokio::time::sleep(LAN_MEDIA_AUTHORIZATION_POLL_INTERVAL) => {
                        continue;
                    }
                }
            } else {
                match timeout(LAN_MEDIA_AUTHORIZATION_POLL_INTERVAL, rx.recv()).await {
                    Ok(Some(Ok(message))) => message,
                    Ok(Some(Err(error))) => {
                        recover_persistent_media_hol_stall(
                            &app_state,
                            &session_id,
                            &endpoint,
                            transport_mux.as_deref(),
                            &error,
                            LanHolRecoveryState {
                                receiver_stats: &mut receiver_stats,
                                keyframe_request_sequence: &mut keyframe_request_sequence,
                                last_keyframe_request_at: &mut last_keyframe_request_at,
                            },
                        )
                        .await;
                        tracing::warn!(
                            %error,
                            session_id = %session_id.0,
                            "LAN QUIC reliable media reader retrying"
                        );
                        continue;
                    }
                    Ok(None) => {
                        reliable_media_rx = None;
                        tracing::warn!(
                            session_id = %session_id.0,
                            "LAN QUIC reliable media reader stopped"
                        );
                        continue;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        } else {
            match timeout(
                LAN_MEDIA_AUTHORIZATION_POLL_INTERVAL,
                endpoint.read_datagram(),
            )
            .await
            {
                Ok(result) => result.context("failed to read LAN QUIC media datagram")?,
                Err(_) => continue,
            }
        };
        receiver_stats.record_elapsed("receiver.read", read_started);
        receiver_stats.record_elapsed("receiver.message_wait", read_started);
        if !session_allows_media(&app_state, &session_id).await {
            return Ok(());
        }
        match decode_lan_sender_stats_datagram(&media_message) {
            Ok(Some(stats)) => {
                let mut pipelines = app_state.media_pipelines.lock().await;
                pipelines.set_stage_metrics(session_id.clone(), stats.metrics);
                pipelines.set_test_impairment(session_id.clone(), stats.test_impairment);
                pipelines.set_sender_transport(session_id.clone(), stats.sender_transport);
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                app_state.probes.lock().await.record_probe_drop(
                    &session_id,
                    media_message.len() as u64,
                    now_ms(),
                    format!("failed to decode LAN sender stats datagram: {error}"),
                );
                continue;
            }
        }
        let reassemble_started = Instant::now();
        let reassembled_frame = if is_quic_media_v3_datagram(&media_message) {
            let reassembled_v3_frame = media_v3_reassembler
                .push_datagram(&media_message)
                .context("failed to reassemble LAN QUIC media v3 frame")?;
            receiver_stats.record_elapsed("receiver.reassemble", reassemble_started);
            let Some(frame) = reassembled_v3_frame else {
                continue;
            };

            #[cfg(target_os = "macos")]
            if quic_media_v3_compressed_direct_render_candidate(&frame)
                && macos_render_proxy_compressed_media_surface_available(&app_state, &session_id)
                    .await
            {
                let proxy_forward_started = Instant::now();
                if render_lan_quic_media_v3_compressed_access_unit_frame(
                    &app_state,
                    &session_id,
                    &mut media_v3_frame_orderer,
                    frame.clone(),
                    media_v3_reassembler.stats(),
                    &mut receiver_stats,
                    &mut consecutive_decode_errors,
                    &mut decoder_waits_for_keyframe,
                    &endpoint,
                    &mut keyframe_request_sequence,
                    &mut last_keyframe_request_at,
                )
                .await
                {
                    let proxy_forward_ms = duration_as_millis(proxy_forward_started.elapsed());
                    receiver_stats.record_ms("receiver.proxy_forward", proxy_forward_ms);
                    app_state
                        .media_pipelines
                        .lock()
                        .await
                        .record_stage_duration_ms(
                            session_id.clone(),
                            "receiver.proxy_forward_direct_v3",
                            proxy_forward_ms,
                        );
                    flush_lan_receiver_stage_metrics(&app_state, &session_id, &mut receiver_stats)
                        .await;
                    continue;
                }
            }

            quic_media_v3_frame_to_legacy_frame(
                &app_state,
                &session_id,
                frame,
                media_v3_reassembler.stats(),
            )
            .await?
        } else {
            let reassembled_frame = reassembler
                .push_datagram(&media_message)
                .context("failed to reassemble LAN QUIC media v2 frame")?;
            receiver_stats.record_elapsed("receiver.reassemble", reassemble_started);
            reassembled_frame
        };

        if let Some(frame) = reassembled_frame {
            let ready_frames = frame_orderer.push(frame);
            if frame_orderer.take_skipped_gap() {
                decoder_waits_for_keyframe = true;
            }
            receiver_stats.record_ms("receiver.ready_frames", ready_frames.len() as f64);
            for frame in ready_frames {
                let mut envelope = match decode_lan_media_envelope(&frame.payload) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        app_state.probes.lock().await.record_probe_drop(
                            &session_id,
                            frame.payload.len() as u64,
                            now_ms(),
                            format!("invalid LAN media v2 envelope: {error}"),
                        );
                        continue;
                    }
                };

                match envelope.payload_type {
                    LAN_MEDIA_PAYLOAD_ACCESS_UNIT => {
                        let frame_codec =
                            match LanAccessUnitCodec::from_envelope_codec(envelope.codec) {
                                Ok(codec) => codec,
                                Err(error) => {
                                    app_state.probes.lock().await.record_probe_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                        format!("{error:#}"),
                                    );
                                    continue;
                                }
                            };
                        let mux_envelope = TransportEnvelope {
                            session_id: session_id.clone(),
                            lane: TransportLane::Video,
                            sequence: envelope.sequence,
                            payload: std::mem::take(&mut envelope.payload),
                            video: Some(VideoEnvelopeMetadata {
                                codec: frame_codec.name().to_owned(),
                                timestamp_us: envelope.timestamp_us,
                                keyframe: frame.is_keyframe,
                                width: envelope.profile.width,
                                height: envelope.profile.height,
                            }),
                        };
                        let transport_unit = match media_receiver::transport_video_access_unit(
                            &session_id,
                            mux_envelope,
                        ) {
                            Ok(unit) => unit,
                            Err(error) => {
                                app_state.probes.lock().await.record_probe_drop(
                                    &session_id,
                                    frame.payload.len() as u64,
                                    now_ms(),
                                    format!("invalid transport video envelope: {error:#}"),
                                );
                                continue;
                            }
                        };
                        let frame_codec = transport_unit.codec;
                        debug_assert_eq!(transport_unit.is_keyframe, frame.is_keyframe);
                        envelope.sequence = transport_unit.sequence;
                        envelope.timestamp_us = transport_unit.timestamp_us;
                        envelope.profile.width = transport_unit.width;
                        envelope.profile.height = transport_unit.height;
                        envelope.payload = transport_unit.bytes;
                        if decoder.codec != frame_codec {
                            let next_decoder = create_lan_receiver_decoder_with_preference(
                                &app_state,
                                &session_id,
                                frame_codec,
                                None,
                            )
                            .await
                            .with_context(|| {
                                format!(
                                    "failed to switch LAN media receiver decoder to {}",
                                    frame_codec.display_name()
                                )
                            });
                            match next_decoder {
                                Ok(next_decoder) => {
                                    decoder = next_decoder;
                                    decoder_waits_for_keyframe = true;
                                    consecutive_decode_errors = 0;
                                }
                                Err(error) => {
                                    app_state.probes.lock().await.record_probe_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                        format!("{error:#}"),
                                    );
                                    decoder_waits_for_keyframe = true;
                                    continue;
                                }
                            }
                        }
                        if decoder_waits_for_keyframe && !frame.is_keyframe {
                            app_state.probes.lock().await.record_transient_frame_drop(
                                &session_id,
                                frame.payload.len() as u64,
                                now_ms(),
                            );
                            maybe_send_lan_keyframe_request(
                                &endpoint,
                                transport_mux.as_deref(),
                                &session_id,
                                &envelope.profile,
                                &mut keyframe_request_sequence,
                                &mut last_keyframe_request_at,
                                &mut receiver_stats,
                            )
                            .await;
                            continue;
                        }

                        let agent_codec = match frame_codec {
                            LanAccessUnitCodec::H264 => mrd_agent_ipc::MediaCodec::H264,
                            LanAccessUnitCodec::Hevc => mrd_agent_ipc::MediaCodec::Hevc,
                            LanAccessUnitCodec::Av1 => mrd_agent_ipc::MediaCodec::Av1,
                        };
                        let agent_forward_started = Instant::now();
                        let agent_dispatch = app_state
                            .dispatch_agent_render_access_unit(
                                &session_id,
                                envelope.sequence,
                                envelope.timestamp_us,
                                agent_codec,
                                frame.is_keyframe,
                                envelope.payload.clone(),
                            )
                            .await;
                        if !receiver_should_use_local_render_fallback(agent_dispatch) {
                            receiver_stats.record_elapsed(
                                "receiver.agent_render_forward",
                                agent_forward_started,
                            );
                            match agent_dispatch {
                                crate::agent_runtime::AgentRenderDispatch::Delivered => {
                                    consecutive_decode_errors = 0;
                                    decoder_waits_for_keyframe = false;
                                }
                                crate::agent_runtime::AgentRenderDispatch::Rejected => {
                                    decoder_waits_for_keyframe = true;
                                    app_state.probes.lock().await.record_probe_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                        "session-agent render route rejected encoded access unit",
                                    );
                                }
                                crate::agent_runtime::AgentRenderDispatch::Unavailable => {
                                    unreachable!("unavailable route must use local fallback")
                                }
                            }
                            continue;
                        }

                        #[cfg(target_os = "macos")]
                        if matches!(
                            frame_codec,
                            LanAccessUnitCodec::H264 | LanAccessUnitCodec::Hevc
                        ) && match frame_codec {
                            LanAccessUnitCodec::H264 => {
                                macos_render_proxy_compressed_media_enabled()
                            }
                            LanAccessUnitCodec::Hevc => {
                                macos_render_proxy_compressed_media_enabled_for_profile(
                                    &envelope.profile,
                                )
                            }
                            LanAccessUnitCodec::Av1 => false,
                        } {
                            let proxy_forward_started = Instant::now();
                            let proxy_result = match frame_codec {
                                LanAccessUnitCodec::H264 => {
                                    render_lan_h264_access_unit_frame(
                                        &app_state,
                                        &session_id,
                                        bytes::Bytes::from(envelope.payload.clone()),
                                        envelope.sequence,
                                        envelope.timestamp_us,
                                        &envelope.profile,
                                    )
                                    .await
                                }
                                LanAccessUnitCodec::Hevc => {
                                    render_lan_hevc_access_unit_frame(
                                        &app_state,
                                        &session_id,
                                        bytes::Bytes::from(envelope.payload.clone()),
                                        envelope.sequence,
                                        envelope.timestamp_us,
                                        &envelope.profile,
                                    )
                                    .await
                                }
                                LanAccessUnitCodec::Av1 => Ok(false),
                            };
                            match proxy_result {
                                Ok(true) => {
                                    receiver_stats.record_elapsed(
                                        "receiver.proxy_forward",
                                        proxy_forward_started,
                                    );
                                    consecutive_decode_errors = 0;
                                    decoder_waits_for_keyframe = false;
                                    continue;
                                }
                                Ok(false)
                                    if macos_render_proxy_compressed_media_surface_available(
                                        &app_state,
                                        &session_id,
                                    )
                                    .await =>
                                {
                                    receiver_stats.record_elapsed(
                                        "receiver.proxy_forward",
                                        proxy_forward_started,
                                    );
                                    app_state.probes.lock().await.record_transient_frame_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                    );
                                    maybe_send_lan_keyframe_request(
                                        &endpoint,
                                        transport_mux.as_deref(),
                                        &session_id,
                                        &envelope.profile,
                                        &mut keyframe_request_sequence,
                                        &mut last_keyframe_request_at,
                                        &mut receiver_stats,
                                    )
                                    .await;
                                    decoder_waits_for_keyframe = true;
                                    continue;
                                }
                                Ok(false) => {}
                                Err(error) => {
                                    receiver_stats.record_elapsed(
                                        "receiver.proxy_forward",
                                        proxy_forward_started,
                                    );
                                    tracing::warn!(
                                        %error,
                                        session_id = %session_id.0,
                                        sequence = envelope.sequence,
                                        codec = frame_codec.display_name(),
                                        "LAN media receiver failed to forward access unit to macOS render proxy"
                                    );
                                    app_state.probes.lock().await.record_probe_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                        format!(
                                            "failed to forward LAN {} access unit to macOS render proxy: {error:#}",
                                            frame_codec.display_name()
                                        ),
                                    );
                                    decoder_waits_for_keyframe = true;
                                    continue;
                                }
                            }
                        }

                        let decode_started = Instant::now();
                        match decode_lan_desktop_frame(
                            frame_codec,
                            decoder.decoder.as_mut(),
                            &envelope.payload,
                        ) {
                            Ok(decoded_frames) if !decoded_frames.is_empty() => {
                                receiver_stats.record_elapsed("receiver.decode", decode_started);
                                consecutive_decode_errors = 0;
                                decoder_waits_for_keyframe = false;
                                let record_started = Instant::now();
                                record_lan_decoded_frames(
                                    &app_state,
                                    &session_id,
                                    decoded_frames,
                                    frame.payload.len() as u64,
                                    envelope.sequence,
                                    envelope.timestamp_us,
                                    &envelope.profile,
                                    &envelope.payload,
                                )
                                .await;
                                receiver_stats.record_elapsed("receiver.record", record_started);
                            }
                            Ok(_) => {
                                receiver_stats.record_elapsed("receiver.decode", decode_started);
                            }
                            Err(error) => {
                                receiver_stats.record_elapsed("receiver.decode", decode_started);
                                let error = if frame.is_keyframe
                                    && frame_codec == LanAccessUnitCodec::H264
                                {
                                    match try_decode_h264_keyframe_with_fallback(
                                        &app_state,
                                        &session_id,
                                        decoder.backend,
                                        &envelope.payload,
                                        &error,
                                    )
                                    .await
                                    {
                                        Ok((next_decoder, decoded_frames)) => {
                                            decoder = next_decoder;
                                            consecutive_decode_errors = 0;
                                            decoder_waits_for_keyframe = false;
                                            let record_started = Instant::now();
                                            record_lan_decoded_frames(
                                                &app_state,
                                                &session_id,
                                                decoded_frames,
                                                frame.payload.len() as u64,
                                                envelope.sequence,
                                                envelope.timestamp_us,
                                                &envelope.profile,
                                                &envelope.payload,
                                            )
                                            .await;
                                            receiver_stats
                                                .record_elapsed("receiver.record", record_started);
                                            continue;
                                        }
                                        Err(fallback_error) => fallback_error,
                                    }
                                } else {
                                    error
                                };
                                consecutive_decode_errors =
                                    consecutive_decode_errors.saturating_add(1);
                                let reassembler_stats = reassembler.stats();
                                let payload_hash =
                                    format!("fnv1a64:{:016x}", fnv1a64(&envelope.payload));
                                let message = format!(
                                "failed to decode LAN {} media v2 access unit: sequence={}, keyframe={}, bytes={}, hash={}, reassembler={{completed:{}, expired:{}, evicted:{}, duplicate:{}, rejected:{}, pending:{}}}: {error}",
                                frame_codec.display_name(),
                                envelope.sequence,
                                frame.is_keyframe,
                                envelope.payload.len(),
                                payload_hash,
                                reassembler_stats.completed_frames,
                                reassembler_stats.expired_frames,
                                reassembler_stats.evicted_frames,
                                reassembler_stats.duplicate_fragments,
                                reassembler_stats.rejected_fragments,
                                reassembler_stats.pending_frames
                            );
                                if should_log_media_receiver_decode_error(consecutive_decode_errors)
                                {
                                    tracing::warn!(
                                        session_id = %session_id.0,
                                        sequence = envelope.sequence,
                                        is_keyframe = frame.is_keyframe,
                                        consecutive_decode_errors,
                                        error = %error,
                                        "LAN media receiver dropped a decoded frame"
                                    );
                                }

                                if frame.is_keyframe {
                                    app_state.probes.lock().await.record_probe_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                        message,
                                    );
                                    decoder_waits_for_keyframe = true;
                                    decoder = create_lan_receiver_decoder_with_preference(
                                        &app_state,
                                        &session_id,
                                        frame_codec,
                                        Some(decoder.backend),
                                    )
                                    .await
                                    .context(
                                        "failed to reset LAN media receiver decoder after decode error",
                                    )?;
                                    consecutive_decode_errors = 0;
                                } else {
                                    app_state.probes.lock().await.record_transient_frame_drop(
                                        &session_id,
                                        frame.payload.len() as u64,
                                        now_ms(),
                                    );
                                    if consecutive_decode_errors
                                        >= LAN_MEDIA_RECEIVER_MAX_CONSECUTIVE_DECODE_ERRORS
                                    {
                                        tracing::warn!(
                                            session_id = %session_id.0,
                                            consecutive_decode_errors,
                                            backend = decoder.backend,
                                            "LAN media receiver reset decoder after non-keyframe decode loss"
                                        );
                                        decoder_waits_for_keyframe = true;
                                        decoder = create_lan_receiver_decoder_with_preference(
                                            &app_state,
                                            &session_id,
                                            frame_codec,
                                            Some(decoder.backend),
                                        )
                                        .await
                                        .context(
                                            "failed to reset LAN media receiver decoder after decode loss",
                                        )?;
                                        consecutive_decode_errors = 0;
                                    }
                                }
                            }
                        }
                    }
                    LAN_MEDIA_PAYLOAD_PROBE_FRAME => {
                        match decode_media_probe_frame(&envelope.payload) {
                            Ok(stats) => {
                                app_state.probes.lock().await.record_media_probe_frame(
                                    &session_id,
                                    stats,
                                    now_ms(),
                                );
                            }
                            Err(error) => {
                                app_state.probes.lock().await.record_probe_drop(
                                    &session_id,
                                    frame.payload.len() as u64,
                                    now_ms(),
                                    format!("failed to decode LAN media v2 probe frame: {error}"),
                                );
                            }
                        }
                    }
                    payload_type => app_state.probes.lock().await.record_probe_drop(
                        &session_id,
                        frame.payload.len() as u64,
                        now_ms(),
                        format!("unsupported LAN media v2 payload type: {payload_type}"),
                    ),
                }
            }
        }
        flush_lan_receiver_stage_metrics(&app_state, &session_id, &mut receiver_stats).await;
    }
}

struct LanHolRecoveryState<'a> {
    receiver_stats: &'a mut LanSenderStatsTracker,
    keyframe_request_sequence: &'a mut u32,
    last_keyframe_request_at: &'a mut Option<Instant>,
}

async fn recover_persistent_media_hol_stall(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    endpoint: &QuinnDatagramEndpoint,
    transport_mux: Option<&QuicTransportMux>,
    error: &str,
    recovery: LanHolRecoveryState<'_>,
) {
    if !error.contains("persistent reliable HOL payload timeout") {
        return;
    }
    recovery.receiver_stats.record_ms(
        "receiver.reliable_hol_timeout",
        LAN_QUIC_PERSISTENT_MEDIA_HOL_TIMEOUT.as_secs_f64() * 1000.0,
    );
    app_state
        .media_pipelines
        .lock()
        .await
        .increment_reliable_hol_recoveries(session_id.clone(), 1);
    let profile = selected_media_profile(app_state, session_id).await;
    maybe_send_lan_keyframe_request(
        endpoint,
        transport_mux,
        session_id,
        &profile,
        recovery.keyframe_request_sequence,
        recovery.last_keyframe_request_at,
        recovery.receiver_stats,
    )
    .await;
}

async fn flush_lan_receiver_stage_metrics(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    receiver_stats: &mut LanSenderStatsTracker,
) {
    if let Some(metrics) = receiver_stats.take_stage_metrics(Instant::now()) {
        app_state
            .media_pipelines
            .lock()
            .await
            .set_stage_metrics(session_id.clone(), metrics);
    }
}

#[cfg(target_os = "macos")]
fn quic_media_v3_compressed_direct_render_candidate(frame: &QuicMediaFrame) -> bool {
    media_receiver::compressed_direct_render_candidate(
        macos_render_proxy_compressed_media_enabled(),
        frame.payload_type,
        frame.codec,
    )
}

#[cfg(target_os = "macos")]
async fn macos_render_proxy_compressed_media_surface_available(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) -> bool {
    if !macos_render_proxy_compressed_media_enabled() {
        return false;
    }
    app_state
        .media_surface_renderers
        .lock()
        .await
        .session_surface_count(session_id)
        > 0
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
async fn render_lan_quic_media_v3_compressed_access_unit_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    frame_orderer: &mut LanMediaFrameOrderer<QuicMediaFrame>,
    frame: QuicMediaFrame,
    reassembler_stats: QuicAuReassemblerStats,
    receiver_stats: &mut LanSenderStatsTracker,
    consecutive_decode_errors: &mut u32,
    decoder_waits_for_keyframe: &mut bool,
    endpoint: &QuinnDatagramEndpoint,
    keyframe_request_sequence: &mut u32,
    last_keyframe_request_at: &mut Option<Instant>,
) -> bool {
    if !quic_media_v3_compressed_direct_render_candidate(&frame) {
        return false;
    }

    let frame_codec = frame.codec;
    let mut profile = selected_media_profile(app_state, session_id).await;
    let expected_profile_id = lan_media_profile_id(&profile);
    if frame.profile_id != expected_profile_id {
        tracing::debug!(
            session_id = %session_id.0,
            frame_id = frame.frame_id,
            expected_profile_id,
            received_profile_id = frame.profile_id,
            completed = reassembler_stats.completed_frames,
            expired = reassembler_stats.expired_frames,
            evicted = reassembler_stats.evicted_frames,
            duplicate = reassembler_stats.duplicate_fragments,
            rejected = reassembler_stats.rejected_fragments,
            pending = reassembler_stats.pending_frames,
            codec = ?frame_codec,
            "LAN media receiver dropped stale v3 compressed profile frame before legacy envelope conversion"
        );
        app_state.probes.lock().await.record_transient_frame_drop(
            session_id,
            frame.payload.len() as u64,
            now_ms(),
        );
        return true;
    }

    profile.codec = match frame_codec {
        QuicMediaCodec::H264 => "h264".to_string(),
        QuicMediaCodec::Hevc => "hevc".to_string(),
        _ => return false,
    };
    normalize_lan_media_profile(&mut profile);
    if !macos_render_proxy_compressed_media_enabled_for_profile(&profile) {
        return false;
    }

    let ready_frames = frame_orderer.push(frame);
    if frame_orderer.take_skipped_gap() {
        *decoder_waits_for_keyframe = true;
        maybe_send_lan_keyframe_request(
            endpoint,
            None,
            session_id,
            &profile,
            keyframe_request_sequence,
            last_keyframe_request_at,
            receiver_stats,
        )
        .await;
    }
    receiver_stats.record_ms("receiver.ready_frames", ready_frames.len() as f64);
    for ready_frame in ready_frames {
        if *decoder_waits_for_keyframe && !ready_frame.is_keyframe() {
            app_state.probes.lock().await.record_transient_frame_drop(
                session_id,
                ready_frame.payload.len() as u64,
                now_ms(),
            );
            maybe_send_lan_keyframe_request(
                endpoint,
                None,
                session_id,
                &profile,
                keyframe_request_sequence,
                last_keyframe_request_at,
                receiver_stats,
            )
            .await;
            continue;
        }

        let render_result = match frame_codec {
            QuicMediaCodec::H264 => {
                render_lan_h264_access_unit_frame(
                    app_state,
                    session_id,
                    ready_frame.payload.clone(),
                    u64::from(ready_frame.frame_id),
                    ready_frame.timestamp_us,
                    &profile,
                )
                .await
            }
            QuicMediaCodec::Hevc => {
                render_lan_hevc_access_unit_frame(
                    app_state,
                    session_id,
                    ready_frame.payload.clone(),
                    u64::from(ready_frame.frame_id),
                    ready_frame.timestamp_us,
                    &profile,
                )
                .await
            }
            _ => return false,
        };
        match render_result {
            Ok(true) => {
                *consecutive_decode_errors = 0;
                *decoder_waits_for_keyframe = false;
            }
            Ok(false) => {
                app_state.probes.lock().await.record_transient_frame_drop(
                    session_id,
                    ready_frame.payload.len() as u64,
                    now_ms(),
                );
                maybe_send_lan_keyframe_request(
                    endpoint,
                    None,
                    session_id,
                    &profile,
                    keyframe_request_sequence,
                    last_keyframe_request_at,
                    receiver_stats,
                )
                .await;
                *decoder_waits_for_keyframe = true;
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    session_id = %session_id.0,
                    sequence = ready_frame.frame_id,
                    codec = ?frame_codec,
                    "LAN media receiver failed to forward v3 compressed access unit to macOS render proxy"
                );
                app_state.probes.lock().await.record_probe_drop(
                    session_id,
                    ready_frame.payload.len() as u64,
                    now_ms(),
                    format!(
                        "failed to forward LAN v3 {:?} access unit to macOS render proxy: {error:#}",
                        frame_codec
                    ),
                );
                maybe_send_lan_keyframe_request(
                    endpoint,
                    None,
                    session_id,
                    &profile,
                    keyframe_request_sequence,
                    last_keyframe_request_at,
                    receiver_stats,
                )
                .await;
                *decoder_waits_for_keyframe = true;
            }
        }
    }

    true
}

#[cfg(test)]
mod security_negative_evidence_tests;
#[cfg(test)]
mod tests;
