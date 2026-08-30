//! Test Orchestrator - Unified test execution and management
//!
//! This module provides the test orchestrator that manages test scenarios,
//! runs, metrics collection, and artifact storage.

#![allow(
    clippy::derivable_impls,
    clippy::needless_return,
    clippy::unwrap_or_default
)]

use anyhow::Result;
use base64::Engine;
use mrd_pipeline_core::{
    CapturedFrame, ColorMode, ColorPipeline, DecodedFrame, DecodedFrameData, EncodedAccessUnit,
    FramePixelFormat, VideoEncoder,
};
#[cfg(any(windows, target_os = "macos"))]
use mrd_render::{RenderFrame, RendererFactory};
use mrd_test_telemetry as telemetry;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::render_probe::{render_backend_supported, run_render_probe, RenderProbeConfig};
use crate::test_harness::{
    CaptureType, DecoderType, EncoderType, HarnessMetrics, RendererType, TestChain,
    TestConfig as HarnessConfig, TestHarness, TransportKind,
};
use std::thread;
use std::time::Duration;

/// Unique identifier for a test run
pub type RunId = String;

/// Test scenario kinds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    Capture,
    Encode,
    Decode,
    Render,
    Transport,
    #[serde(rename = "e2e_local")]
    E2eLocal,
    #[serde(rename = "e2e_remote")]
    E2eRemote,
    Custom,
}

/// Test run status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Preparing,
    Running,
    Completed,
    Failed,
    Skipped,
    Cancelled,
}

/// Test run mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Manual,
    Batch,
    Matrix,
    Replay,
}

/// Test scenario definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestScenario {
    pub scenario_id: String,
    pub scenario_kind: ScenarioKind,
    pub component_scope: Vec<String>,
    pub display_name: String,
    pub description: String,
    pub supports_matrix: bool,
    #[serde(default)]
    pub default_config: TestConfigData,
}

/// Test config data (serializable version)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TestConfigData {
    pub capture_type: Option<String>,
    pub encoder_type: Option<String>,
    pub decoder_type: Option<String>,
    pub renderer_type: Option<String>,
    pub render_display: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_hwnd",
        serialize_with = "serialize_optional_hwnd"
    )]
    pub renderer_target_hwnd: Option<isize>,
    pub zero_copy: Option<bool>,
    pub color_mode: Option<ColorMode>,
    pub color_pipeline: Option<ColorPipeline>,
    pub transport_kind: Option<String>,
    pub adaptive_media: Option<bool>,
    pub dynamic_resolution_enabled: Option<bool>,
    pub resolution: Option<[usize; 2]>,
    pub fps: Option<u32>,
    pub bitrate: Option<u32>,
    pub duration_ms: Option<u64>,
    pub warmup_ms: Option<u64>,
    pub repeat_count: Option<u32>,
    pub input_source: Option<String>,
    pub source_id: Option<String>,
    pub source_kind: Option<String>,
    pub display_id: Option<String>,
    pub window_hwnd: Option<String>,
    pub window_title: Option<String>,
    pub visual_preview: Option<bool>,
    pub output_validation: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestRunScope {
    Local,
    CrossDevice,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestMemoryPath {
    ZeroCopyD3d11Shared,
    CpuCopy,
    WebrtcMediaStream,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestAccelerationMode {
    Hardware,
    Software,
    Browser,
    None,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestTransportPath {
    None,
    Webrtc,
    Quic,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestRenderPath {
    NativeD3d11,
    NativeD3d12,
    NativeOpengl,
    NativeMacos,
    NativeLinux,
    BrowserVideo,
    Webcodecs,
    None,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TestDeviceDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_protocol_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestClassification {
    pub run_scope: TestRunScope,
    pub memory_path: TestMemoryPath,
    pub encode_accel: TestAccelerationMode,
    pub decode_accel: TestAccelerationMode,
    pub transport_path: TestTransportPath,
    pub render_path: TestRenderPath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_device: Option<TestDeviceDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_device: Option<TestDeviceDescriptor>,
}

fn deserialize_optional_hwnd<'de, D>(deserializer: D) -> Result<Option<isize>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };

    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                isize::try_from(value)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            } else if let Some(value) = number.as_u64() {
                isize::try_from(value)
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            } else {
                Err(serde::de::Error::custom(
                    "renderer_target_hwnd must be an integer handle",
                ))
            }
        }
        serde_json::Value::String(value) => parse_hwnd(&value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        _ => Err(serde::de::Error::custom(
            "renderer_target_hwnd must be a string or integer handle",
        )),
    }
}

fn serialize_optional_hwnd<S>(value: &Option<isize>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(handle) => serializer.serialize_some(&format!("0x{:X}", *handle as usize)),
        None => serializer.serialize_none(),
    }
}

/// Test run record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRun {
    pub run_id: RunId,
    pub scenario_id: String,
    pub run_mode: RunMode,
    pub status: RunStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub config_snapshot: TestConfigData,
    pub environment_snapshot: EnvironmentSnapshot,
    pub summary: Option<TestRunSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<TestClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTestRunRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    pub scenario_id: String,
    #[serde(default)]
    pub run_mode: Option<RunMode>,
    pub status: RunStatus,
    pub started_at: u64,
    #[serde(default)]
    pub finished_at: Option<u64>,
    #[serde(default)]
    pub config_snapshot: TestConfigData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_snapshot: Option<EnvironmentSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<TestRunSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<TestClassification>,
    #[serde(default)]
    pub events: Vec<TestStageEvent>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
}

/// Environment snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    pub os_type: String,
    pub cpu_brand: String,
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub gpu_info: String,
    pub available_captures: Vec<String>,
    pub available_encoders: Vec<String>,
    pub available_decoders: Vec<String>,
    pub available_renderers: Vec<String>,
    pub available_memory_modes: Vec<String>,
}

/// Test run summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunSummary {
    pub total_duration_ms: u64,
    pub first_frame_latency_ms: Option<f64>,
    pub capture_fps: Option<f64>,
    pub observed_fps: Option<f64>,
    pub decoded_fps: Option<f64>,
    pub encode_latency_p50: Option<f64>,
    pub encode_latency_p95: Option<f64>,
    pub transport_latency_p50: Option<f64>,
    pub transport_latency_p95: Option<f64>,
    pub decode_latency_p50: Option<f64>,
    pub decode_latency_p95: Option<f64>,
    pub total_latency_p95: Option<f64>,
    pub dropped_frames: usize,
    pub frame_count: usize,
    pub decoded_frames: usize,
    pub render_presented_frames: u64,
    pub render_present_skipped_frames: u64,
    pub render_present_gap_p95_ms: Option<f64>,
    pub error_message: Option<String>,
    pub failure_reason: Option<String>,
    pub cpu_p95_percent: Option<f64>,
    pub gpu_p95_percent: Option<f64>,
    pub memory_peak_mb: Option<f64>,
    pub network_peak_mbps: Option<f64>,
}

/// Test stage event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStageEvent {
    pub stage: String,
    pub status: String,
    pub timestamp: u64,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
}

/// Metric series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    pub timestamp: u64,
    pub value: f64,
}

/// Metric series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub metric_name: String,
    pub unit: String,
    pub samples: Vec<MetricDataPoint>,
    pub aggregation: Option<MetricAggregation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Metric aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricAggregation {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub mean: Option<f64>,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
}

/// Artifact record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub kind: String,
    pub run_id: String,
    pub created_at: u64,
    pub data: String,
    pub metadata: Option<ArtifactMetadata>,
}

/// Artifact metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub width: Option<usize>,
    pub height: Option<usize>,
    pub format: Option<String>,
    pub size_bytes: Option<usize>,
}

/// A visible top-level window that can be used as a platform capture target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowCaptureTarget {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub platform: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_kind: String,
    /// Backward-compatible handle field used by the existing UI and Windows path.
    pub hwnd: String,
    pub title: String,
    pub class_name: String,
    pub width: u32,
    pub height: u32,
    pub process_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_layer: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_data_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_height: Option<u32>,
}

/// A cross-platform screen sharing source that can be selected before capture starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureShareSourceTarget {
    pub id: String,
    pub platform: String,
    /// "screen", "window", or "portal" when the OS permission UI owns final selection.
    pub source_kind: String,
    pub native_id: String,
    pub title: String,
    pub subtitle: String,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
    pub requires_system_picker: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwnd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_layer: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_data_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_height: Option<u32>,
}

struct WindowCaptureItemProbe {
    hwnd: isize,
    id: String,
    platform: String,
    title: String,
    class_name: String,
    width: u32,
    height: u32,
    app_name: Option<String>,
    bundle_identifier: Option<String>,
}

struct WindowCaptureFrameProbe {
    hwnd: isize,
    id: String,
    platform: String,
    title: String,
    class_name: String,
    width: u32,
    height: u32,
    byte_len: usize,
    pixel_format: String,
    frame: mrd_pipeline_core::CapturedFrame,
    app_name: Option<String>,
    bundle_identifier: Option<String>,
}

struct SingleWindowMediaProbe {
    transport: String,
    encoded_width: usize,
    encoded_height: usize,
    access_unit_count: usize,
    encoded_bytes: usize,
    keyframe_count: usize,
    transport_rtp_packet_count: usize,
    transport_payload_bytes: usize,
    encode_latency_ms: f64,
    decode_latency_ms: f64,
    decoded_frame_count: usize,
    decoded_width: Option<usize>,
    decoded_height: Option<usize>,
    decoded_pixel_format: Option<String>,
    render_backend: Option<String>,
    render_latency_ms: Option<f64>,
    rendered_frame_count: usize,
    first_access_unit: Option<Vec<u8>>,
}

struct SingleWindowTransportProbe {
    transport: String,
    access_units: Vec<EncodedAccessUnit>,
    rtp_packet_count: usize,
    payload_bytes: usize,
}

/// Test preset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPreset {
    pub preset_id: String,
    pub name: String,
    pub description: String,
    pub scenario_id: String,
    pub config: TestConfigData,
    pub tags: Option<Vec<String>>,
    pub created_at: u64,
}

/// Test Orchestrator - manages test execution
pub struct TestOrchestrator {
    harness: Arc<Mutex<TestHarness>>,
    runs: Arc<Mutex<HashMap<RunId, TestRun>>>,
    run_metrics: Arc<Mutex<HashMap<RunId, HashMap<String, MetricSeries>>>>,
    run_events: Arc<Mutex<HashMap<RunId, Vec<TestStageEvent>>>>,
    run_artifacts: Arc<Mutex<HashMap<RunId, Vec<Artifact>>>>,
    telemetry_store: Arc<telemetry::TelemetryStore>,
    presets: Arc<Mutex<HashMap<String, TestPreset>>>,
    current_harness_chain: Arc<Mutex<Option<TestChain>>>,
    active_harness_run_id: Arc<Mutex<Option<RunId>>>,
}

impl TestOrchestrator {
    pub fn new(harness: Arc<Mutex<TestHarness>>) -> Self {
        let default_root = std::env::temp_dir()
            .join("mini-remote-desktop")
            .join("test-telemetry");
        Self::new_with_telemetry_store(
            harness,
            telemetry::TelemetryStore::from_env_or_dir(default_root),
        )
    }

    pub fn new_with_telemetry_store(
        harness: Arc<Mutex<TestHarness>>,
        telemetry_store: telemetry::TelemetryStore,
    ) -> Self {
        Self {
            harness,
            runs: Arc::new(Mutex::new(HashMap::new())),
            run_metrics: Arc::new(Mutex::new(HashMap::new())),
            run_events: Arc::new(Mutex::new(HashMap::new())),
            run_artifacts: Arc::new(Mutex::new(HashMap::new())),
            telemetry_store: Arc::new(telemetry_store),
            presets: Arc::new(Mutex::new(HashMap::new())),
            current_harness_chain: Arc::new(Mutex::new(None)),
            active_harness_run_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Convert scenario_id to TestChain
    fn scenario_to_chain(&self, scenario_id: &str, config: &TestConfigData) -> Result<TestChain> {
        validate_scenario_for_current_platform(scenario_id, config)?;

        match scenario_id {
            "capture.dxgi" => Ok(TestChain::CaptureOnly),
            "capture.winrt" => Ok(TestChain::Custom {
                capture: CaptureType::Winrt,
                encoder: EncoderType::None,
                decoder: DecoderType::None,
            }),
            "capture.macos" => Ok(TestChain::Custom {
                capture: CaptureType::Macos,
                encoder: EncoderType::None,
                decoder: DecoderType::None,
            }),
            #[cfg(target_os = "linux")]
            "capture.linux" => Ok(TestChain::Custom {
                capture: CaptureType::Linux,
                encoder: EncoderType::None,
                decoder: DecoderType::None,
            }),
            "e2e.local" => Ok(TestChain::NvencNvdec),
            "e2e.macos_local" => Ok(TestChain::Custom {
                capture: CaptureType::Macos,
                encoder: match macos_e2e_encoder_type(config) {
                    "videotoolbox_hevc" | "hevc" => EncoderType::VideoToolboxHevc,
                    "videotoolbox_h264" | "videotoolbox" | "h264" => EncoderType::VideoToolboxH264,
                    "openh264" | "software_h264" | "h264_software" | "software-h264"
                    | "h264-software" | "sw_h264" => EncoderType::OpenH264,
                    other => anyhow::bail!("Unsupported macOS E2E encoder: {}", other),
                },
                decoder: match config.decoder_type.as_deref().unwrap_or("videotoolbox") {
                    "videotoolbox" => DecoderType::VideoToolbox,
                    "software" | "software_h264" | "h264_software" | "software-h264"
                    | "h264-software" | "openh264" | "software_hevc" | "hevc_software"
                    | "software-hevc" | "hevc-software" => DecoderType::Software,
                    "ffmpeg_h264" | "ffmpeg-h264" => DecoderType::FfmpegH264,
                    "ffmpeg_hevc" | "ffmpeg-hevc" => DecoderType::FfmpegHevc,
                    "none" => DecoderType::None,
                    other => anyhow::bail!("Unsupported macOS E2E decoder: {}", other),
                },
            }),
            #[cfg(target_os = "linux")]
            "e2e.linux_local" => Ok(TestChain::Custom {
                capture: CaptureType::Linux,
                encoder: match config.encoder_type.as_deref().unwrap_or("nvenc_h264") {
                    "nvenc_h264" => EncoderType::NvencH264,
                    "openh264" | "software_h264" | "h264_software" | "software-h264"
                    | "h264-software" | "sw_h264" => EncoderType::OpenH264,
                    other => anyhow::bail!("Unsupported Linux E2E encoder: {}", other),
                },
                decoder: match config.decoder_type.as_deref().unwrap_or("linux_h264") {
                    "linux_h264" | "gstreamer_h264" | "vaapi_h264" => DecoderType::LinuxH264,
                    "software" | "software_h264" | "h264_software" | "software-h264"
                    | "h264-software" | "openh264" => DecoderType::Software,
                    "none" => DecoderType::None,
                    other => anyhow::bail!("Unsupported Linux E2E decoder: {}", other),
                },
            }),
            "encode.nvenc_h264" => Ok(TestChain::NvencOnly),
            "encode.openh264" => Ok(TestChain::OpenH264),
            "decode.nvdec_h264" => Ok(TestChain::NvencNvdec),
            #[cfg(target_os = "linux")]
            "decode.linux_h264" => Ok(TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::NvencH264,
                decoder: DecoderType::LinuxH264,
            }),
            "encode.videotoolbox_h264" => Ok(TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::VideoToolboxH264,
                decoder: DecoderType::None,
            }),
            "encode.videotoolbox_hevc" => Ok(TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::VideoToolboxHevc,
                decoder: DecoderType::None,
            }),
            "decode.videotoolbox_h264" => Ok(TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::VideoToolboxH264,
                decoder: DecoderType::VideoToolbox,
            }),
            "decode.videotoolbox_hevc" => Ok(TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::VideoToolboxHevc,
                decoder: DecoderType::VideoToolbox,
            }),
            "custom" | "matrix" => Ok(TestChain::Custom {
                capture: match config.capture_type.as_deref().unwrap_or("dxgi") {
                    "dxgi" => CaptureType::Dxgi,
                    "winrt" => CaptureType::Winrt,
                    "macos" => CaptureType::Macos,
                    #[cfg(target_os = "linux")]
                    "linux" => CaptureType::Linux,
                    "synthetic" => CaptureType::Synthetic,
                    other => anyhow::bail!("Unsupported capture for {}: {}", scenario_id, other),
                },
                encoder: match config.encoder_type.as_deref() {
                    Some("none") => EncoderType::None,
                    Some("nvenc_h264") => EncoderType::NvencH264,
                    Some("openh264")
                    | Some("software_h264")
                    | Some("h264_software")
                    | Some("software-h264")
                    | Some("h264-software")
                    | Some("sw_h264") => EncoderType::OpenH264,
                    Some("nvenc_av1") => EncoderType::NvencAv1,
                    Some("nvenc_hevc") | Some("hevc") => EncoderType::NvencHevc,
                    Some("nvenc_hevc_main10") | Some("hevc_main10") | Some("hevc-main10") => {
                        EncoderType::NvencHevcMain10
                    }
                    Some("videotoolbox_h264") | Some("videotoolbox") => {
                        EncoderType::VideoToolboxH264
                    }
                    Some("videotoolbox_hevc") => EncoderType::VideoToolboxHevc,
                    Some(other) => {
                        anyhow::bail!("Unsupported encoder for {}: {}", scenario_id, other)
                    }
                    None => anyhow::bail!("Missing encoder_type for {}", scenario_id),
                },
                decoder: match config.decoder_type.as_deref().unwrap_or("software") {
                    "none" => DecoderType::None,
                    "nvdec" => DecoderType::Nvdec,
                    "software" | "software_h264" | "h264_software" | "software-h264"
                    | "h264-software" | "openh264" => DecoderType::Software,
                    "ffmpeg_h264" | "h264_ffmpeg" => DecoderType::FfmpegH264,
                    "ffmpeg_hevc" | "hevc_ffmpeg" | "h265_ffmpeg" => DecoderType::FfmpegHevc,
                    "ffmpeg_vvc" | "vvc_ffmpeg" | "ffmpeg_h266" | "h266_ffmpeg" => {
                        DecoderType::FfmpegVvc
                    }
                    "linux_h264" | "gstreamer_h264" | "vaapi_h264" => DecoderType::LinuxH264,
                    "linux_hevc" | "gstreamer_hevc" | "vaapi_hevc" => DecoderType::LinuxHevc,
                    "linux_hevc_main10" | "gstreamer_hevc_main10" | "vaapi_hevc_main10" => {
                        DecoderType::LinuxHevcMain10
                    }
                    "videotoolbox" => DecoderType::VideoToolbox,
                    other => anyhow::bail!("Unsupported decoder for {}: {}", scenario_id, other),
                },
            }),
            other => anyhow::bail!("Unsupported test scenario: {}", other),
        }
    }

    /// List all available test scenarios
    pub fn list_scenarios(&self) -> Vec<TestScenario> {
        let window_capture_type = if cfg!(target_os = "macos") {
            "macos"
        } else {
            "winrt"
        };
        let window_capture_scope = if cfg!(target_os = "macos") {
            vec![
                "screencapturekit_window".to_string(),
                "openh264".to_string(),
                "webrtc".to_string(),
                "software_decode".to_string(),
                "metal_render".to_string(),
            ]
        } else {
            vec![
                "winrt".to_string(),
                "openh264".to_string(),
                "webrtc".to_string(),
                "software_decode".to_string(),
                "d3d11_render".to_string(),
            ]
        };

        vec![
            TestScenario {
                scenario_id: "capture.dxgi".to_string(),
                scenario_kind: ScenarioKind::Capture,
                component_scope: vec!["dxgi".to_string()],
                display_name: "DXGI 屏幕捕获测试".to_string(),
                description: "测试 DXGI 捕获性能和稳定性".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("dxgi".to_string()),
                    encoder_type: Some("none".to_string()),
                    decoder_type: Some("none".to_string()),
                    zero_copy: Some(true),
                    duration_ms: Some(30_000),
                    visual_preview: Some(false),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "capture.winrt".to_string(),
                scenario_kind: ScenarioKind::Capture,
                component_scope: vec!["winrt".to_string(), "d3d11_shared".to_string()],
                display_name: "WinRT 屏幕捕获测试".to_string(),
                description: "测试 Windows Runtime Graphics Capture 屏幕捕获性能和稳定性".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("winrt".to_string()),
                    encoder_type: Some("none".to_string()),
                    decoder_type: Some("none".to_string()),
                    zero_copy: Some(true),
                    duration_ms: Some(30_000),
                    visual_preview: Some(false),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "capture.macos".to_string(),
                scenario_kind: ScenarioKind::Capture,
                component_scope: vec!["macos_capture".to_string()],
                display_name: "macOS 屏幕捕获测试".to_string(),
                description: "测试 macOS 屏幕捕获性能和稳定性".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("macos".to_string()),
                    encoder_type: Some("none".to_string()),
                    decoder_type: Some("none".to_string()),
                    ..Default::default()
                },
            },
            #[cfg(target_os = "linux")]
            TestScenario {
                scenario_id: "capture.linux".to_string(),
                scenario_kind: ScenarioKind::Capture,
                component_scope: vec!["linux_capture".to_string()],
                display_name: "Linux 屏幕捕获测试".to_string(),
                description: "测试 Linux 屏幕捕获性能和稳定性".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("linux".to_string()),
                    encoder_type: Some("none".to_string()),
                    decoder_type: Some("none".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "encode.nvenc_h264".to_string(),
                scenario_kind: ScenarioKind::Encode,
                component_scope: vec!["nvenc".to_string()],
                display_name: "NVENC H.264 编码测试".to_string(),
                description: "测试 NVIDIA H.264 硬件编码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    encoder_type: Some("nvenc_h264".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "encode.openh264".to_string(),
                scenario_kind: ScenarioKind::Encode,
                component_scope: vec!["openh264".to_string()],
                display_name: "OpenH264 软件编码测试".to_string(),
                description: "测试 OpenH264 软件编码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    encoder_type: Some("openh264".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "encode.videotoolbox_h264".to_string(),
                scenario_kind: ScenarioKind::Encode,
                component_scope: vec!["videotoolbox".to_string()],
                display_name: "VideoToolbox H.264 编码测试".to_string(),
                description: "测试 macOS VideoToolbox H.264 硬件编码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    encoder_type: Some("videotoolbox_h264".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "encode.videotoolbox_hevc".to_string(),
                scenario_kind: ScenarioKind::Encode,
                component_scope: vec!["videotoolbox".to_string()],
                display_name: "VideoToolbox HEVC 编码测试".to_string(),
                description: "测试 macOS VideoToolbox HEVC 硬件编码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    encoder_type: Some("videotoolbox_hevc".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "decode.nvdec_h264".to_string(),
                scenario_kind: ScenarioKind::Decode,
                component_scope: vec!["nvdec".to_string()],
                display_name: "NVDEC H.264 解码测试".to_string(),
                description: "测试 NVIDIA H.264 硬件解码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    decoder_type: Some("nvdec".to_string()),
                    ..Default::default()
                },
            },
            #[cfg(target_os = "linux")]
            TestScenario {
                scenario_id: "decode.linux_h264".to_string(),
                scenario_kind: ScenarioKind::Decode,
                component_scope: vec!["linux_decode".to_string()],
                display_name: "Linux H.264 硬件解码测试".to_string(),
                description: "测试 Linux GStreamer H.264 硬件解码路径".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("synthetic".to_string()),
                    encoder_type: Some("nvenc_h264".to_string()),
                    decoder_type: Some("linux_h264".to_string()),
                    transport_kind: Some("loopback".to_string()),
                    render_display: Some(false),
                    zero_copy: Some(false),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "decode.videotoolbox_h264".to_string(),
                scenario_kind: ScenarioKind::Decode,
                component_scope: vec!["videotoolbox".to_string()],
                display_name: "VideoToolbox H.264 解码测试".to_string(),
                description: "测试 macOS VideoToolbox H.264 硬件解码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    decoder_type: Some("videotoolbox".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "decode.videotoolbox_hevc".to_string(),
                scenario_kind: ScenarioKind::Decode,
                component_scope: vec!["videotoolbox".to_string()],
                display_name: "VideoToolbox HEVC 解码测试".to_string(),
                description: "测试 macOS VideoToolbox HEVC 硬件解码器性能".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    encoder_type: Some("videotoolbox_hevc".to_string()),
                    decoder_type: Some("videotoolbox".to_string()),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "e2e.local".to_string(),
                scenario_kind: ScenarioKind::E2eLocal,
                component_scope: vec!["dxgi".to_string(), "nvenc".to_string(), "nvdec".to_string()],
                display_name: "端到端本地测试".to_string(),
                description: "测试完整的采集→编码→解码流程".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("dxgi".to_string()),
                    encoder_type: Some("nvenc_h264".to_string()),
                    decoder_type: Some("nvdec".to_string()),
                    renderer_type: Some("d3d11".to_string()),
                    render_display: Some(true),
                    zero_copy: Some(true),
                    resolution: Some([1920, 1080]),
                    fps: Some(60),
                    bitrate: Some(5000000),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "e2e.macos_local".to_string(),
                scenario_kind: ScenarioKind::E2eLocal,
                component_scope: vec![
                    "macos_capture".to_string(),
                    "videotoolbox".to_string(),
                    "metal_render".to_string(),
                ],
                display_name: "macOS 本地端到端测试".to_string(),
                description: "测试 macOS 采集→VideoToolbox 编码→软件解码→Metal 渲染流程"
                    .to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("macos".to_string()),
                    encoder_type: Some("videotoolbox_h264".to_string()),
                    decoder_type: Some("software".to_string()),
                    renderer_type: Some("macos".to_string()),
                    render_display: Some(true),
                    resolution: Some([1920, 1080]),
                    fps: Some(60),
                    bitrate: Some(5_000_000),
                    ..Default::default()
                },
            },
            #[cfg(target_os = "linux")]
            TestScenario {
                scenario_id: "e2e.linux_local".to_string(),
                scenario_kind: ScenarioKind::E2eLocal,
                component_scope: vec![
                    "linux_capture".to_string(),
                    "nvenc".to_string(),
                    "linux_decode".to_string(),
                    "linux_render".to_string(),
                ],
                display_name: "Linux 本地端到端测试".to_string(),
                description: "测试 Linux 采集→NVENC 编码→Linux 硬件解码→Linux 渲染流程"
                    .to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("linux".to_string()),
                    encoder_type: Some("nvenc_h264".to_string()),
                    decoder_type: Some("linux_h264".to_string()),
                    renderer_type: Some("linux".to_string()),
                    render_display: Some(true),
                    resolution: Some([1920, 1080]),
                    fps: Some(60),
                    bitrate: Some(20_000_000),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "render.d3d12".to_string(),
                scenario_kind: ScenarioKind::Render,
                component_scope: vec!["d3d12_render".to_string(), "window_probe".to_string()],
                display_name: "Direct3D 12 渲染 Probe".to_string(),
                description: "参考 CapTest 路径执行独立 D3D12 可见窗口 clear/present 渲染测试，不接主线渲染窗口。".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("synthetic".to_string()),
                    encoder_type: Some("none".to_string()),
                    decoder_type: Some("none".to_string()),
                    renderer_type: Some("d3d12".to_string()),
                    render_display: Some(true),
                    transport_kind: Some("loopback".to_string()),
                    resolution: Some([1920, 1080]),
                    fps: Some(144),
                    duration_ms: Some(5_000),
                    input_source: Some("synthetic".to_string()),
                    visual_preview: Some(true),
                    output_validation: Some(true),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "render.opengl".to_string(),
                scenario_kind: ScenarioKind::Render,
                component_scope: vec!["opengl_render".to_string(), "window_probe".to_string()],
                display_name: "OpenGL 渲染 Probe".to_string(),
                description: "执行独立 OpenGL/WGL 可见窗口 clear + SwapBuffers 渲染测试，不接主线渲染窗口。".to_string(),
                supports_matrix: true,
                default_config: TestConfigData {
                    capture_type: Some("synthetic".to_string()),
                    encoder_type: Some("none".to_string()),
                    decoder_type: Some("none".to_string()),
                    renderer_type: Some("opengl".to_string()),
                    render_display: Some(true),
                    transport_kind: Some("loopback".to_string()),
                    resolution: Some([1920, 1080]),
                    fps: Some(144),
                    duration_ms: Some(5_000),
                    input_source: Some("synthetic".to_string()),
                    visual_preview: Some(true),
                    output_validation: Some(true),
                    ..Default::default()
                },
            },
            TestScenario {
                scenario_id: "single_window.local".to_string(),
                scenario_kind: ScenarioKind::E2eLocal,
                component_scope: window_capture_scope,
                display_name: "Single window local probe".to_string(),
                description: "Captures one platform window frame and runs it through encode, WebRTC RTP, decode, and render."
                    .to_string(),
                supports_matrix: false,
                default_config: TestConfigData {
                    capture_type: Some(window_capture_type.to_string()),
                    encoder_type: Some("openh264".to_string()),
                    decoder_type: Some("software".to_string()),
                    transport_kind: Some("webrtc".to_string()),
                    input_source: Some("window".to_string()),
                    duration_ms: Some(1_000),
                    ..Default::default()
                },
            },
        ]
        .into_iter()
        .filter(|scenario| scenario_supported_on_current_platform(&scenario.scenario_id))
        .collect()
    }

    /// Get environment capabilities
    pub fn get_capabilities(&self) -> Result<EnvironmentSnapshot> {
        let hw_info = crate::device_info::get_hardware_info();

        // Detect available encoders
        let mut available_encoders = vec!["none".to_string(), "openh264".to_string()];

        // Try to detect NVENC
        #[cfg(windows)]
        {
            if mrd_encode_nvenc::NvencH264Encoder::new_max_speed(1920, 1080, 60).is_ok() {
                available_encoders.push("nvenc_h264".to_string());
            }
            if mrd_encode_nvenc::NvencHevcEncoder::probe_hevc_available().is_ok() {
                available_encoders.push("nvenc_hevc".to_string());
            }
            if mrd_encode_nvenc::NvencHevcEncoder::probe_hevc_main10_available().is_ok() {
                available_encoders.push("nvenc_hevc_main10".to_string());
            }
            if mrd_encode_nvenc_av1::NvencAv1Encoder::probe_av1_available().is_ok() {
                available_encoders.push("nvenc_av1".to_string());
            }
        }
        #[cfg(target_os = "linux")]
        {
            if mrd_encode_nvenc::NvencH264Encoder::probe_h264_available().is_ok() {
                available_encoders.push("nvenc_h264".to_string());
            }
            if mrd_encode_nvenc::NvencHevcEncoder::probe_hevc_available().is_ok() {
                available_encoders.push("nvenc_hevc".to_string());
            }
            if mrd_encode_nvenc::NvencHevcEncoder::probe_hevc_main10_available().is_ok() {
                available_encoders.push("nvenc_hevc_main10".to_string());
            }
            if mrd_encode_nvenc_av1::NvencAv1Encoder::probe_av1_available().is_ok() {
                available_encoders.push("nvenc_av1".to_string());
            }
        }
        #[cfg(target_os = "macos")]
        {
            if macos_videotoolbox_h264_encoder_available() {
                available_encoders.push("videotoolbox_h264".to_string());
            }
            if macos_videotoolbox_hevc_encoder_available() {
                available_encoders.push("videotoolbox_hevc".to_string());
            }
        }

        // Detect available decoders
        let mut available_decoders = vec!["none".to_string(), "software".to_string()];
        let ffmpeg_probe = mrd_ffmpeg::probe_ffmpeg(&mrd_ffmpeg::golden_settings());
        if ffmpeg_probe.available {
            available_decoders.push("ffmpeg_h264".to_string());
            available_decoders.push("ffmpeg_hevc".to_string());
        }
        #[cfg(windows)]
        {
            if mrd_decode_nvdec::NvdecDecoder::new().is_ok() {
                available_decoders.push("nvdec".to_string());
            }
        }
        #[cfg(target_os = "macos")]
        {
            append_macos_videotoolbox_decoder_capabilities(
                &mut available_decoders,
                macos_videotoolbox_h264_decoder_available(),
                macos_videotoolbox_hevc_decoder_available(),
            );
        }
        #[cfg(target_os = "linux")]
        {
            if mrd_decode::probe_linux_h264_hardware_available().is_ok() {
                available_decoders.push("linux_h264".to_string());
            }
            if mrd_decode::probe_linux_hevc_hardware_available().is_ok() {
                available_decoders.push("linux_hevc".to_string());
            }
            if mrd_decode::probe_linux_hevc_main10_hardware_available().is_ok() {
                available_decoders.push("linux_hevc_main10".to_string());
            }
        }

        // Get GPU info string
        let gpu_info = hw_info
            .gpu_info
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<_>>()
            .join(", ");

        Ok(EnvironmentSnapshot {
            os_type: std::env::consts::OS.to_string(),
            cpu_brand: hw_info.cpu_info.name,
            cpu_cores: hw_info.cpu_info.cores,
            memory_gb: (hw_info.total_memory_mb / 1024) as u32,
            gpu_info: if gpu_info.is_empty() {
                "Unknown".to_string()
            } else {
                gpu_info
            },
            available_captures: current_platform_captures()
                .into_iter()
                .map(str::to_string)
                .collect(),
            available_encoders,
            available_decoders,
            available_renderers: current_platform_renderers()
                .into_iter()
                .map(str::to_string)
                .collect(),
            available_memory_modes: current_platform_memory_modes()
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
    }

    /// Start a new test run
    pub fn start_run(&self, scenario_id: String, config: TestConfigData) -> Result<RunId> {
        validate_execution_config(&config)?;
        validate_scenario_for_current_platform(&scenario_id, &config)?;

        if scenario_id == "single_window.local" {
            return self.start_single_window_probe(scenario_id, config);
        }
        if matches!(
            scenario_id.as_str(),
            "render.probe" | "render.d3d12" | "render.opengl"
        ) {
            return self.start_render_probe(scenario_id, config);
        }

        // Resolve the scenario before recording a run. Unsupported scenarios must
        // fail fast instead of leaving a phantom running record behind.
        let chain = self.scenario_to_chain(&scenario_id, &config)?;
        let mut active_harness_run_id = self.active_harness_run_id.lock().unwrap();
        if let Some(active_run_id) = active_harness_run_id.as_ref() {
            let active_is_running = self
                .runs
                .lock()
                .unwrap()
                .get(active_run_id)
                .map(|run| run.status == RunStatus::Running)
                .unwrap_or(false);
            if active_is_running {
                anyhow::bail!(
                    "Test run {} already owns the shared test harness; stop it before starting another run",
                    active_run_id
                );
            }
            *active_harness_run_id = None;
        }

        let run_id = generate_run_id();
        let started_at = now_ms();
        let env_snapshot = self.get_capabilities()?;

        let run = TestRun {
            run_id: run_id.clone(),
            scenario_id: scenario_id.clone(),
            run_mode: RunMode::Manual,
            status: RunStatus::Running,
            started_at,
            finished_at: None,
            config_snapshot: config.clone(),
            environment_snapshot: env_snapshot.clone(),
            summary: None,
            classification: Some(derive_test_classification(
                &config,
                &env_snapshot,
                TestRunScope::Local,
                None,
            )),
        };

        self.runs.lock().unwrap().insert(run_id.clone(), run);
        self.persist_run_by_id(&run_id);

        // Record stage event
        self.record_stage_event(run_id.clone(), "prepare", "started", None, None);

        // Convert scenario to chain and start the shared harness used by legacy
        // frame/metric commands, so run state and visualization stay aligned.
        self.record_stage_event(run_id.clone(), "prepare", "chain_resolved", None, None);

        self.record_stage_event(run_id.clone(), "initialize", "started", None, None);

        let mut harness = self.harness.lock().unwrap();
        harness.set_chain(chain.clone());
        harness.set_config(harness_config_from_data(&config));
        if let Err(error) = harness.start_replacing_existing() {
            let message = format!("Failed to start test harness: {}", error);
            drop(harness);

            if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                run.status = RunStatus::Failed;
                run.finished_at = Some(now_ms());
                run.summary = Some(TestRunSummary {
                    total_duration_ms: now_ms().saturating_sub(run.started_at),
                    error_message: Some(message.clone()),
                    failure_reason: Some("initialization_failure".to_string()),
                    ..Default::default()
                });
                persist_run_to_store(&self.telemetry_store, run);
            }

            self.record_stage_event(
                run_id.clone(),
                "initialize",
                "failed",
                None,
                Some(message.clone()),
            );
            anyhow::bail!(message);
        }
        *active_harness_run_id = Some(run_id.clone());
        drop(harness);
        drop(active_harness_run_id);

        self.record_stage_event(run_id.clone(), "initialize", "completed", None, None);
        self.record_stage_event(run_id.clone(), "running", "started", None, None);

        // Store harness reference for this run
        self.set_harness_chain(chain);

        // Spawn background thread to collect metrics
        let run_id_clone = run_id.clone();
        let orchestrator_runs = self.runs.clone();
        let orchestrator_events = self.run_events.clone();
        let orchestrator_metrics = self.run_metrics.clone();
        let telemetry_store = self.telemetry_store.clone();
        let harness = self.harness.clone();
        let active_harness_run_id = self.active_harness_run_id.clone();
        let duration_ms = config.duration_ms.unwrap_or(30_000);
        let warmup_ms = config.warmup_ms.unwrap_or(0);

        thread::spawn(move || {
            let monitor_started_at = now_ms();
            let mut measurement_started_at = monitor_started_at;
            let mut warmup_completed = warmup_ms == 0;
            if !warmup_completed {
                push_stage_event(
                    &orchestrator_events,
                    &telemetry_store,
                    &run_id_clone,
                    TestStageEvent {
                        stage: "warmup".to_string(),
                        status: "started".to_string(),
                        timestamp: monitor_started_at,
                        duration_ms: Some(warmup_ms),
                        error: None,
                    },
                );
            }

            loop {
                thread::sleep(Duration::from_millis(500));

                // Check if run still exists and is running
                let is_running = {
                    let runs = orchestrator_runs.lock().unwrap();
                    runs.get(&run_id_clone)
                        .map(|r| r.status == RunStatus::Running)
                        .unwrap_or(false)
                };

                if !is_running {
                    push_stage_event(
                        &orchestrator_events,
                        &telemetry_store,
                        &run_id_clone,
                        TestStageEvent {
                            stage: "running".to_string(),
                            status: "stopped".to_string(),
                            timestamp: now_ms(),
                            duration_ms: None,
                            error: None,
                        },
                    );
                    break;
                }

                if !warmup_completed && now_ms().saturating_sub(monitor_started_at) >= warmup_ms {
                    let warmup_metrics = {
                        let owner = active_harness_run_id.lock().unwrap();
                        if owner.as_deref() != Some(run_id_clone.as_str()) {
                            break;
                        }
                        harness.lock().unwrap().get_metrics()
                    };
                    if let Some(error) = warmup_metrics.error_message.clone() {
                        let metrics =
                            stop_owned_harness(&active_harness_run_id, &harness, &run_id_clone)
                                .unwrap_or(warmup_metrics);
                        mark_run_failed(
                            &orchestrator_runs,
                            &orchestrator_events,
                            &telemetry_store,
                            &run_id_clone,
                            &metrics,
                            "warmup_failure",
                            error,
                        );
                        break;
                    }
                    if !warmup_metrics.is_running {
                        release_harness_ownership(&active_harness_run_id, &run_id_clone);
                        mark_run_failed(
                            &orchestrator_runs,
                            &orchestrator_events,
                            &telemetry_store,
                            &run_id_clone,
                            &warmup_metrics,
                            "warmup_stopped",
                            "test harness stopped during warmup".to_string(),
                        );
                        break;
                    }

                    let restart_result =
                        restart_owned_harness(&active_harness_run_id, &harness, &run_id_clone);
                    match restart_result {
                        Ok(true) => {
                            warmup_completed = true;
                            measurement_started_at = now_ms();
                            push_stage_event(
                                &orchestrator_events,
                                &telemetry_store,
                                &run_id_clone,
                                TestStageEvent {
                                    stage: "warmup".to_string(),
                                    status: "completed".to_string(),
                                    timestamp: measurement_started_at,
                                    duration_ms: Some(warmup_ms),
                                    error: None,
                                },
                            );
                            continue;
                        }
                        Ok(false) => break,
                        Err(error) => {
                            let metrics =
                                stop_owned_harness(&active_harness_run_id, &harness, &run_id_clone)
                                    .unwrap_or_default();
                            mark_run_failed(
                                &orchestrator_runs,
                                &orchestrator_events,
                                &telemetry_store,
                                &run_id_clone,
                                &metrics,
                                "warmup_restart_failure",
                                error.to_string(),
                            );
                            break;
                        }
                    }
                }

                let metrics = {
                    let owner = active_harness_run_id.lock().unwrap();
                    if owner.as_deref() != Some(run_id_clone.as_str()) {
                        break;
                    }
                    harness.lock().unwrap().get_metrics()
                };

                if let Some(error) = metrics.error_message.clone() {
                    let metrics =
                        stop_owned_harness(&active_harness_run_id, &harness, &run_id_clone)
                            .unwrap_or(metrics);
                    mark_run_failed(
                        &orchestrator_runs,
                        &orchestrator_events,
                        &telemetry_store,
                        &run_id_clone,
                        &metrics,
                        "runtime_failure",
                        error,
                    );
                    break;
                }

                if !metrics.is_running {
                    release_harness_ownership(&active_harness_run_id, &run_id_clone);
                    let message = "test harness stopped before duration elapsed".to_string();
                    mark_run_failed(
                        &orchestrator_runs,
                        &orchestrator_events,
                        &telemetry_store,
                        &run_id_clone,
                        &metrics,
                        "runtime_stopped",
                        message,
                    );
                    break;
                }

                if warmup_completed {
                    let mut series = orchestrator_metrics.lock().unwrap();
                    let run_series = series
                        .entry(run_id_clone.clone())
                        .or_insert_with(HashMap::new);
                    let timestamp =
                        push_metric_sample(run_series, "capture_fps", "fps", metrics.capture_fps);
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "capture_fps",
                        "fps",
                        timestamp,
                        metrics.capture_fps,
                    );
                    let observed_fps = metrics.observed_fps();
                    let timestamp =
                        push_metric_sample(run_series, "observed_fps", "fps", observed_fps);
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "observed_fps",
                        "fps",
                        timestamp,
                        observed_fps,
                    );
                    let timestamp =
                        push_metric_sample(run_series, "decoded_fps", "fps", metrics.decoded_fps);
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "decoded_fps",
                        "fps",
                        timestamp,
                        metrics.decoded_fps,
                    );
                    let timestamp = push_metric_sample(
                        run_series,
                        "encode_latency_p95_ms",
                        "ms",
                        metrics.encode_latency_p95_ms,
                    );
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "encode_latency_p95_ms",
                        "ms",
                        timestamp,
                        metrics.encode_latency_p95_ms,
                    );
                    let timestamp = push_metric_sample(
                        run_series,
                        "transport_latency_p95_ms",
                        "ms",
                        metrics.transport_latency_p95_ms,
                    );
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "transport_latency_p95_ms",
                        "ms",
                        timestamp,
                        metrics.transport_latency_p95_ms,
                    );
                    let timestamp = push_metric_sample(
                        run_series,
                        "decode_latency_p95_ms",
                        "ms",
                        metrics.decode_latency_p95_ms,
                    );
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "decode_latency_p95_ms",
                        "ms",
                        timestamp,
                        metrics.decode_latency_p95_ms,
                    );
                    let timestamp = push_metric_sample(
                        run_series,
                        "render_present_gap_p95_ms",
                        "ms",
                        metrics.render_present_gap_p95_ms,
                    );
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "render_present_gap_p95_ms",
                        "ms",
                        timestamp,
                        metrics.render_present_gap_p95_ms,
                    );
                    let timestamp = push_metric_sample(
                        run_series,
                        "total_latency_p95_ms",
                        "ms",
                        metrics.total_latency_p95_ms,
                    );
                    append_metric_to_store(
                        &telemetry_store,
                        &run_id_clone,
                        "total_latency_p95_ms",
                        "ms",
                        timestamp,
                        metrics.total_latency_p95_ms,
                    );
                }

                if warmup_completed
                    && now_ms().saturating_sub(measurement_started_at) >= duration_ms
                {
                    let Some(metrics) =
                        stop_owned_harness(&active_harness_run_id, &harness, &run_id_clone)
                    else {
                        break;
                    };
                    if let Some(message) = metrics.error_message.clone().or_else(|| {
                        (metrics.frame_count == 0).then(|| "No frames were produced".to_string())
                    }) {
                        let failure_reason = if metrics.frame_count == 0 {
                            "no_frames"
                        } else {
                            "runtime_failure"
                        };
                        mark_run_failed(
                            &orchestrator_runs,
                            &orchestrator_events,
                            &telemetry_store,
                            &run_id_clone,
                            &metrics,
                            failure_reason,
                            message,
                        );
                    } else {
                        let mut runs = orchestrator_runs.lock().unwrap();
                        if let Some(run) = runs.get_mut(&run_id_clone) {
                            run.status = RunStatus::Completed;
                            run.finished_at = Some(now_ms());
                            run.summary = Some(summary_from_metrics(run.started_at, &metrics));
                            persist_run_to_store(&telemetry_store, run);
                        }
                    }
                    break;
                }
            }
        });

        Ok(run_id)
    }

    fn start_render_probe(&self, scenario_id: String, config: TestConfigData) -> Result<RunId> {
        let backend = match scenario_id.as_str() {
            "render.d3d12" => "d3d12".to_string(),
            "render.opengl" => "opengl".to_string(),
            _ => config
                .renderer_type
                .clone()
                .ok_or_else(|| anyhow::anyhow!("render.probe requires renderer_type"))?,
        };
        if !render_backend_supported(&backend) {
            anyhow::bail!(
                "Render backend {} is not supported on this platform",
                backend
            );
        }
        if !matches!(backend.as_str(), "d3d12" | "opengl") {
            anyhow::bail!("Unsupported render probe backend: {}", backend);
        }

        let [width, height] = config.resolution.unwrap_or([1920, 1080]);
        let fps = config.fps.unwrap_or(144).max(1);
        let duration_ms = config.duration_ms.unwrap_or(5_000).max(1);
        let requested_frames = ((duration_ms as u128 * fps as u128) / 1_000).clamp(1, 600) as usize;
        let run_id = generate_run_id();
        let started_at = now_ms();
        let env_snapshot = self.get_capabilities()?;

        let run = TestRun {
            run_id: run_id.clone(),
            scenario_id,
            run_mode: RunMode::Manual,
            status: RunStatus::Running,
            started_at,
            finished_at: None,
            config_snapshot: config.clone(),
            environment_snapshot: env_snapshot.clone(),
            summary: None,
            classification: Some(derive_test_classification(
                &config,
                &env_snapshot,
                TestRunScope::Local,
                None,
            )),
        };

        self.runs.lock().unwrap().insert(run_id.clone(), run);
        self.persist_run_by_id(&run_id);
        self.record_stage_event(run_id.clone(), "prepare", "started", None, None);
        self.record_stage_event(run_id.clone(), "initialize", "started", None, None);

        let runs = Arc::clone(&self.runs);
        let events = Arc::clone(&self.run_events);
        let metrics = Arc::clone(&self.run_metrics);
        let artifacts = Arc::clone(&self.run_artifacts);
        let telemetry_store = Arc::clone(&self.telemetry_store);
        let run_id_clone = run_id.clone();
        thread::spawn(move || {
            events
                .lock()
                .unwrap()
                .entry(run_id_clone.clone())
                .or_insert_with(Vec::new)
                .push(TestStageEvent {
                    stage: "initialize".to_string(),
                    status: "completed".to_string(),
                    timestamp: now_ms(),
                    duration_ms: None,
                    error: None,
                });
            events
                .lock()
                .unwrap()
                .entry(run_id_clone.clone())
                .or_insert_with(Vec::new)
                .push(TestStageEvent {
                    stage: "render".to_string(),
                    status: "started".to_string(),
                    timestamp: now_ms(),
                    duration_ms: None,
                    error: None,
                });

            let result = run_render_probe(RenderProbeConfig {
                backend,
                width,
                height,
                frames: requested_frames,
                show_window: config.render_display.unwrap_or(true),
            });

            match result {
                Ok(result) => {
                    {
                        let mut all_series = metrics.lock().unwrap();
                        let run_series = all_series
                            .entry(run_id_clone.clone())
                            .or_insert_with(HashMap::new);
                        push_metric_sample(run_series, "render_fps", "fps", result.fps);
                        push_metric_sample(
                            run_series,
                            "render_frame_time_ms",
                            "ms",
                            result.avg_frame_time_ms,
                        );
                        push_metric_sample(
                            run_series,
                            "render_frame_time_p50_ms",
                            "ms",
                            result.p50_frame_time_ms,
                        );
                        push_metric_sample(
                            run_series,
                            "render_frame_time_p95_ms",
                            "ms",
                            result.p95_frame_time_ms,
                        );
                        push_metric_sample(
                            run_series,
                            "draw_calls",
                            "count",
                            result.draw_calls as f64,
                        );
                        push_metric_sample(
                            run_series,
                            "triangles",
                            "count",
                            result.triangles as f64,
                        );
                        push_metric_sample(run_series, "textures", "count", result.textures as f64);
                        push_metric_sample(run_series, "render_width", "px", result.width as f64);
                        push_metric_sample(run_series, "render_height", "px", result.height as f64);
                    }

                    let data =
                        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string());
                    let size_bytes = data.len();
                    let artifact = Artifact {
                        artifact_id: format!("render_probe_{}", now_ms()),
                        kind: "structured_log".to_string(),
                        run_id: run_id_clone.clone(),
                        created_at: now_ms(),
                        data,
                        metadata: Some(ArtifactMetadata {
                            width: Some(result.width),
                            height: Some(result.height),
                            format: Some("json".to_string()),
                            size_bytes: Some(size_bytes),
                        }),
                    };
                    artifacts
                        .lock()
                        .unwrap()
                        .entry(run_id_clone.clone())
                        .or_insert_with(Vec::new)
                        .push(artifact.clone());
                    let _ = telemetry_store.upsert_artifacts(
                        &run_id_clone,
                        &[telemetry_artifact_from_artifact(artifact)],
                    );

                    let completed = {
                        let mut runs = runs.lock().unwrap();
                        if let Some(run) = runs.get_mut(&run_id_clone) {
                            if run.status != RunStatus::Running {
                                false
                            } else {
                                run.status = RunStatus::Completed;
                                run.finished_at = Some(now_ms());
                                run.summary = Some(TestRunSummary {
                                    total_duration_ms: now_ms().saturating_sub(run.started_at),
                                    capture_fps: Some(result.fps),
                                    observed_fps: Some(result.fps),
                                    total_latency_p95: Some(result.p95_frame_time_ms),
                                    frame_count: result.frames_presented,
                                    ..Default::default()
                                });
                                persist_run_to_store(&telemetry_store, run);
                                true
                            }
                        } else {
                            false
                        }
                    };
                    if !completed {
                        return;
                    }
                    events
                        .lock()
                        .unwrap()
                        .entry(run_id_clone.clone())
                        .or_insert_with(Vec::new)
                        .push(TestStageEvent {
                            stage: "render".to_string(),
                            status: "completed".to_string(),
                            timestamp: now_ms(),
                            duration_ms: None,
                            error: None,
                        });
                    events
                        .lock()
                        .unwrap()
                        .entry(run_id_clone)
                        .or_insert_with(Vec::new)
                        .push(TestStageEvent {
                            stage: "summarize".to_string(),
                            status: "completed".to_string(),
                            timestamp: now_ms(),
                            duration_ms: None,
                            error: None,
                        });
                }
                Err(error) => {
                    let message = error.to_string();
                    let failed = {
                        let mut runs = runs.lock().unwrap();
                        if let Some(run) = runs.get_mut(&run_id_clone) {
                            if run.status != RunStatus::Running {
                                false
                            } else {
                                run.status = RunStatus::Failed;
                                run.finished_at = Some(now_ms());
                                run.summary = Some(TestRunSummary {
                                    total_duration_ms: now_ms().saturating_sub(run.started_at),
                                    error_message: Some(message.clone()),
                                    failure_reason: Some("runtime_failure".to_string()),
                                    ..Default::default()
                                });
                                persist_run_to_store(&telemetry_store, run);
                                true
                            }
                        } else {
                            false
                        }
                    };
                    if !failed {
                        return;
                    }
                    events
                        .lock()
                        .unwrap()
                        .entry(run_id_clone)
                        .or_insert_with(Vec::new)
                        .push(TestStageEvent {
                            stage: "render".to_string(),
                            status: "failed".to_string(),
                            timestamp: now_ms(),
                            duration_ms: None,
                            error: Some(message),
                        });
                }
            }
        });

        Ok(run_id)
    }

    fn start_single_window_probe(
        &self,
        scenario_id: String,
        config: TestConfigData,
    ) -> Result<RunId> {
        let run_id = generate_run_id();
        let started_at = now_ms();
        let env_snapshot = self.get_capabilities()?;
        let requested_hwnd = config.window_hwnd.clone();

        let run = TestRun {
            run_id: run_id.clone(),
            scenario_id,
            run_mode: RunMode::Manual,
            status: RunStatus::Running,
            started_at,
            finished_at: None,
            config_snapshot: config.clone(),
            environment_snapshot: env_snapshot.clone(),
            summary: None,
            classification: Some(derive_test_classification(
                &config,
                &env_snapshot,
                TestRunScope::Local,
                None,
            )),
        };

        self.runs.lock().unwrap().insert(run_id.clone(), run);
        self.persist_run_by_id(&run_id);
        self.record_stage_event(run_id.clone(), "prepare", "started", None, None);
        self.record_stage_event(run_id.clone(), "capability_check", "started", None, None);

        match list_window_capture_targets() {
            Ok(targets) => {
                self.record_stage_event(
                    run_id.clone(),
                    "capability_check",
                    "completed",
                    None,
                    None,
                );
                let mut selected_window = serde_json::Value::Null;
                let mut first_frame = serde_json::Value::Null;
                let mut media_probe = serde_json::Value::Null;
                let mut encoded_sample = None::<Vec<u8>>;

                if let Some(hwnd_text) = requested_hwnd.as_deref() {
                    self.record_stage_event(
                        run_id.clone(),
                        "capture",
                        "item_probe_started",
                        None,
                        None,
                    );
                    let hwnd = match parse_hwnd(hwnd_text) {
                        Ok(hwnd) => hwnd,
                        Err(error) => {
                            let message = error.to_string();
                            self.record_stage_event(
                                run_id.clone(),
                                "capture",
                                "item_probe_failed",
                                None,
                                Some(message.clone()),
                            );
                            if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                                run.status = RunStatus::Failed;
                                run.finished_at = Some(now_ms());
                                run.summary = Some(TestRunSummary {
                                    total_duration_ms: now_ms().saturating_sub(started_at),
                                    error_message: Some(message),
                                    failure_reason: Some("initialization_failure".to_string()),
                                    ..Default::default()
                                });
                            }
                            return Ok(run_id);
                        }
                    };

                    match probe_window_capture_item(hwnd) {
                        Ok(probe) => {
                            selected_window = serde_json::json!({
                                "requested_hwnd": hwnd_text,
                                "id": probe.id,
                                "platform": probe.platform,
                                "hwnd": format!("0x{:X}", probe.hwnd as usize),
                                "title": probe.title,
                                "class_name": probe.class_name,
                                "app_name": probe.app_name,
                                "bundle_identifier": probe.bundle_identifier,
                                "width": probe.width,
                                "height": probe.height,
                                "capture_item_created": true,
                            });
                            self.record_stage_event(
                                run_id.clone(),
                                "capture",
                                "item_probe_completed",
                                None,
                                None,
                            );
                        }
                        Err(error) => {
                            let message = error.to_string();
                            self.record_stage_event(
                                run_id.clone(),
                                "capture",
                                "item_probe_failed",
                                None,
                                Some(message.clone()),
                            );
                            if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                                run.status = RunStatus::Failed;
                                run.finished_at = Some(now_ms());
                                run.summary = Some(TestRunSummary {
                                    total_duration_ms: now_ms().saturating_sub(started_at),
                                    error_message: Some(message),
                                    failure_reason: Some("initialization_failure".to_string()),
                                    ..Default::default()
                                });
                            }
                            return Ok(run_id);
                        }
                    }

                    self.record_stage_event(
                        run_id.clone(),
                        "capture",
                        "frame_probe_started",
                        None,
                        None,
                    );
                    match probe_window_first_frame(hwnd, Duration::from_millis(1_000)) {
                        Ok(probe) => {
                            let media_result =
                                self.run_single_window_media_probe(&run_id, &probe.frame, &config);

                            first_frame = serde_json::json!({
                                "id": probe.id,
                                "platform": probe.platform,
                                "hwnd": format!("0x{:X}", probe.hwnd as usize),
                                "title": probe.title,
                                "class_name": probe.class_name,
                                "app_name": probe.app_name,
                                "bundle_identifier": probe.bundle_identifier,
                                "width": probe.width,
                                "height": probe.height,
                                "byte_len": probe.byte_len,
                                "pixel_format": probe.pixel_format,
                                "captured": true,
                            });
                            self.record_stage_event(
                                run_id.clone(),
                                "capture",
                                "frame_probe_completed",
                                None,
                                None,
                            );

                            match media_result {
                                Ok(probe) => {
                                    encoded_sample = probe.first_access_unit.clone();
                                    media_probe = serde_json::json!({
                                        "encoder": "openh264",
                                        "decoder": "h264_software",
                                        "transport": probe.transport,
                                        "encoded_width": probe.encoded_width,
                                        "encoded_height": probe.encoded_height,
                                        "access_unit_count": probe.access_unit_count,
                                        "encoded_bytes": probe.encoded_bytes,
                                        "keyframe_count": probe.keyframe_count,
                                        "transport_rtp_packet_count": probe.transport_rtp_packet_count,
                                        "transport_payload_bytes": probe.transport_payload_bytes,
                                        "encode_latency_ms": probe.encode_latency_ms,
                                        "decode_latency_ms": probe.decode_latency_ms,
                                        "decoded_frame_count": probe.decoded_frame_count,
                                        "decoded_width": probe.decoded_width,
                                        "decoded_height": probe.decoded_height,
                                        "decoded_pixel_format": probe.decoded_pixel_format,
                                        "render_backend": probe.render_backend,
                                        "render_latency_ms": probe.render_latency_ms,
                                        "rendered_frame_count": probe.rendered_frame_count,
                                    });
                                }
                                Err(error) => {
                                    let message = error.to_string();
                                    self.record_stage_event(
                                        run_id.clone(),
                                        "encode",
                                        "failed",
                                        None,
                                        Some(message.clone()),
                                    );
                                    if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                                        run.status = RunStatus::Failed;
                                        run.finished_at = Some(now_ms());
                                        run.summary = Some(TestRunSummary {
                                            total_duration_ms: now_ms().saturating_sub(started_at),
                                            error_message: Some(message),
                                            failure_reason: Some("runtime_failure".to_string()),
                                            frame_count: 1,
                                            ..Default::default()
                                        });
                                    }
                                    return Ok(run_id);
                                }
                            }
                        }
                        Err(error) => {
                            let message = error.to_string();
                            self.record_stage_event(
                                run_id.clone(),
                                "capture",
                                "frame_probe_failed",
                                None,
                                Some(message.clone()),
                            );
                            if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                                run.status = RunStatus::Failed;
                                run.finished_at = Some(now_ms());
                                run.summary = Some(TestRunSummary {
                                    total_duration_ms: now_ms().saturating_sub(started_at),
                                    error_message: Some(message),
                                    failure_reason: Some("runtime_failure".to_string()),
                                    ..Default::default()
                                });
                            }
                            return Ok(run_id);
                        }
                    }
                }

                let artifact = serde_json::json!({
                    "targets": targets,
                    "target_count": targets.len(),
                    "selected_window": selected_window,
                    "first_frame": first_frame,
                    "media_probe": media_probe,
                });
                let data =
                    serde_json::to_string_pretty(&artifact).unwrap_or_else(|_| "[]".to_string());
                let size_bytes = data.len();

                self.run_artifacts
                    .lock()
                    .unwrap()
                    .entry(run_id.clone())
                    .or_insert_with(Vec::new)
                    .push(Artifact {
                        artifact_id: format!("artifact_{}", now_ms()),
                        kind: "structured_log".to_string(),
                        run_id: run_id.clone(),
                        created_at: now_ms(),
                        data,
                        metadata: Some(ArtifactMetadata {
                            width: None,
                            height: None,
                            format: Some("json".to_string()),
                            size_bytes: Some(size_bytes),
                        }),
                    });
                self.persist_artifacts_by_id(&run_id);

                if let Some(sample) = encoded_sample {
                    let sample_size = sample.len();
                    self.run_artifacts
                        .lock()
                        .unwrap()
                        .entry(run_id.clone())
                        .or_insert_with(Vec::new)
                        .push(Artifact {
                            artifact_id: format!("encoded_{}", now_ms()),
                            kind: "encoded_sample".to_string(),
                            run_id: run_id.clone(),
                            created_at: now_ms(),
                            data: base64::engine::general_purpose::STANDARD.encode(sample),
                            metadata: Some(ArtifactMetadata {
                                width: None,
                                height: None,
                                format: Some("h264_annex_b".to_string()),
                                size_bytes: Some(sample_size),
                            }),
                        });
                    self.persist_artifacts_by_id(&run_id);
                }

                if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                    run.status = RunStatus::Completed;
                    run.finished_at = Some(now_ms());
                    run.summary = Some(TestRunSummary {
                        total_duration_ms: now_ms().saturating_sub(started_at),
                        frame_count: if first_frame.is_null() { 0 } else { 1 },
                        encode_latency_p50: media_probe
                            .get("encode_latency_ms")
                            .and_then(|value| value.as_f64()),
                        encode_latency_p95: media_probe
                            .get("encode_latency_ms")
                            .and_then(|value| value.as_f64()),
                        decode_latency_p50: media_probe
                            .get("decode_latency_ms")
                            .and_then(|value| value.as_f64()),
                        decode_latency_p95: media_probe
                            .get("decode_latency_ms")
                            .and_then(|value| value.as_f64()),
                        ..Default::default()
                    });
                }
                self.persist_run_by_id(&run_id);
                self.record_stage_event(run_id.clone(), "summarize", "completed", None, None);
            }
            Err(error) => {
                let message = error.to_string();
                self.record_stage_event(
                    run_id.clone(),
                    "capability_check",
                    "failed",
                    None,
                    Some(message.clone()),
                );
                if let Some(run) = self.runs.lock().unwrap().get_mut(&run_id) {
                    run.status = RunStatus::Failed;
                    run.finished_at = Some(now_ms());
                    run.summary = Some(TestRunSummary {
                        total_duration_ms: now_ms().saturating_sub(started_at),
                        error_message: Some(message),
                        failure_reason: Some("capability_mismatch".to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        Ok(run_id)
    }

    fn run_single_window_media_probe(
        &self,
        run_id: &str,
        frame: &CapturedFrame,
        config: &TestConfigData,
    ) -> Result<SingleWindowMediaProbe> {
        let fps = config.fps.unwrap_or(30).max(1);
        let encode_frame = Self::openh264_compatible_frame(frame)?;

        self.record_stage_event(run_id.to_string(), "encode", "started", None, None);
        let encode_started = std::time::Instant::now();
        let mut encoder =
            mrd_encode_openh264::OpenH264Encoder::new(encode_frame.width, encode_frame.height, fps)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let access_units = encoder
            .encode(&encode_frame)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let encode_latency_ms = encode_started.elapsed().as_secs_f64() * 1000.0;

        if access_units.is_empty() {
            anyhow::bail!("OpenH264 produced no access units");
        }

        self.record_stage_event(run_id.to_string(), "encode", "completed", None, None);

        let encoded_bytes = access_units
            .iter()
            .map(|unit| unit.bytes.len())
            .sum::<usize>();
        let keyframe_count = access_units.iter().filter(|unit| unit.is_keyframe).count();
        let first_access_unit = access_units.first().map(|unit| unit.bytes.clone());

        let transport_started_status = if config.transport_kind.as_deref() == Some("webrtc") {
            "webrtc_rtp_started"
        } else {
            "loopback_started"
        };
        let transport_completed_status = if config.transport_kind.as_deref() == Some("webrtc") {
            "webrtc_rtp_completed"
        } else {
            "loopback_completed"
        };
        self.record_stage_event(
            run_id.to_string(),
            "transport",
            transport_started_status,
            None,
            None,
        );
        let transport_probe =
            Self::transport_single_window_access_units(&access_units, fps, config)?;
        self.record_stage_event(
            run_id.to_string(),
            "transport",
            transport_completed_status,
            None,
            None,
        );

        self.record_stage_event(run_id.to_string(), "decode", "started", None, None);
        let decode_started = std::time::Instant::now();
        let mut decoder = mrd_decode::create_decoder("h264_software")
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        for unit in &transport_probe.access_units {
            decoder
                .push_access_unit(&unit.bytes)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        let decoded_frames = decoder.drain_decoded_frames();
        let decoded_frame_count = decoded_frames.len();
        let decode_latency_ms = decode_started.elapsed().as_secs_f64() * 1000.0;
        let decode_status = if decoded_frame_count > 0 {
            "completed"
        } else {
            "accepted_no_frame_drain"
        };
        self.record_stage_event(run_id.to_string(), "decode", decode_status, None, None);
        let decoded_width = decoded_frames.first().map(|frame| frame.width);
        let decoded_height = decoded_frames.first().map(|frame| frame.height);
        let decoded_pixel_format = decoded_frames.first().map(Self::decoded_frame_format);

        let (render_backend, render_latency_ms, rendered_frame_count) = if decoded_frames.is_empty()
        {
            self.record_stage_event(
                run_id.to_string(),
                "render",
                "skipped_no_decoded_frame",
                None,
                None,
            );
            (None, None, 0)
        } else {
            self.record_stage_event(run_id.to_string(), "render", "started", None, None);
            let render_started = std::time::Instant::now();

            #[cfg(windows)]
            let (render_backend, uploaded) = {
                let factory = mrd_render_d3d11::D3d11RendererFactory;
                let mut renderer = factory
                    .create()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                renderer
                    .attach_target(mrd_render::RenderTarget::WindowHandle(0))
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                for frame in &decoded_frames {
                    renderer
                        .upload_frame(Self::decoded_frame_to_render_frame(frame))
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                }
                (
                    Some("d3d11".to_string()),
                    renderer.snapshot().uploaded_frame_count as usize,
                )
            };

            #[cfg(target_os = "macos")]
            let (render_backend, uploaded) = {
                let factory = mrd_render_macos::MacosRendererFactory;
                let mut renderer = factory
                    .create()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                for frame in &decoded_frames {
                    renderer
                        .upload_frame(Self::decoded_frame_to_render_frame(frame))
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                }
                (
                    Some("metal".to_string()),
                    renderer.snapshot().uploaded_frame_count as usize,
                )
            };

            #[cfg(not(any(windows, target_os = "macos")))]
            let (render_backend, uploaded) = {
                self.record_stage_event(
                    run_id.to_string(),
                    "render",
                    "skipped_unsupported_platform",
                    None,
                    None,
                );
                (None, 0)
            };

            let render_latency = render_started.elapsed().as_secs_f64() * 1000.0;
            self.record_stage_event(run_id.to_string(), "render", "completed", None, None);
            (render_backend, Some(render_latency), uploaded)
        };

        Ok(SingleWindowMediaProbe {
            transport: transport_probe.transport,
            encoded_width: encode_frame.width,
            encoded_height: encode_frame.height,
            access_unit_count: transport_probe.access_units.len(),
            encoded_bytes,
            keyframe_count,
            transport_rtp_packet_count: transport_probe.rtp_packet_count,
            transport_payload_bytes: transport_probe.payload_bytes,
            encode_latency_ms,
            decode_latency_ms,
            decoded_frame_count,
            decoded_width,
            decoded_height,
            decoded_pixel_format,
            render_backend,
            render_latency_ms,
            rendered_frame_count,
            first_access_unit,
        })
    }

    fn transport_single_window_access_units(
        access_units: &[EncodedAccessUnit],
        fps: u32,
        config: &TestConfigData,
    ) -> Result<SingleWindowTransportProbe> {
        if config.transport_kind.as_deref() != Some("webrtc") {
            let payload_bytes = access_units
                .iter()
                .map(|access_unit| access_unit.bytes.len())
                .sum::<usize>();
            return Ok(SingleWindowTransportProbe {
                transport: "loopback".to_string(),
                access_units: access_units.to_vec(),
                rtp_packet_count: 0,
                payload_bytes,
            });
        }

        enum RtpLoopback {
            H264 {
                sender: mrd_transport_webrtc::H264RtpSender,
                ingress: mrd_transport_webrtc::H264RtpIngress,
            },
            Hevc {
                sender: mrd_transport_webrtc::HevcRtpSender,
                ingress: mrd_transport_webrtc::HevcRtpIngress,
            },
            Av1 {
                sender: mrd_transport_webrtc::Av1RtpSender,
                ingress: mrd_transport_webrtc::Av1RtpIngress,
            },
            Vvc {
                sender: mrd_transport_webrtc::VvcRtpSender,
                ingress: mrd_transport_webrtc::VvcRtpIngress,
            },
        }

        let codec = access_units
            .first()
            .map(|access_unit| access_unit.codec)
            .ok_or_else(|| anyhow::anyhow!("WebRTC RTP loopback received no access units"))?;
        let mut loopback = match codec {
            mrd_pipeline_core::VideoCodec::H264 => RtpLoopback::H264 {
                sender: mrd_transport_webrtc::H264RtpSender::new(
                    "single-window-video",
                    "single-window-stream",
                    fps,
                    1200,
                ),
                ingress: mrd_transport_webrtc::H264RtpIngress::default(),
            },
            mrd_pipeline_core::VideoCodec::Hevc => RtpLoopback::Hevc {
                sender: mrd_transport_webrtc::HevcRtpSender::new(
                    "single-window-video",
                    "single-window-stream",
                    fps,
                    1200,
                ),
                ingress: mrd_transport_webrtc::HevcRtpIngress::default(),
            },
            mrd_pipeline_core::VideoCodec::Av1 => RtpLoopback::Av1 {
                sender: mrd_transport_webrtc::Av1RtpSender::new(
                    "single-window-video",
                    "single-window-stream",
                    fps,
                    1200,
                ),
                ingress: mrd_transport_webrtc::Av1RtpIngress::default(),
            },
            mrd_pipeline_core::VideoCodec::Vvc => RtpLoopback::Vvc {
                sender: mrd_transport_webrtc::VvcRtpSender::new(
                    "single-window-video",
                    "single-window-stream",
                    fps,
                    1200,
                ),
                ingress: mrd_transport_webrtc::VvcRtpIngress::default(),
            },
        };
        let mut reassembled = Vec::new();
        let mut rtp_packet_count = 0usize;
        let mut payload_bytes = 0usize;

        for access_unit in access_units {
            if access_unit.codec != codec {
                anyhow::bail!("WebRTC RTP loopback cannot mix codecs in one probe");
            }
            let packets = match &mut loopback {
                RtpLoopback::H264 { sender, .. } => sender
                    .packetize_access_unit(access_unit)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                RtpLoopback::Hevc { sender, .. } => sender
                    .packetize_access_unit(access_unit)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                RtpLoopback::Av1 { sender, .. } => sender
                    .packetize_access_unit(access_unit)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                RtpLoopback::Vvc { sender, .. } => sender
                    .packetize_access_unit(access_unit)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            };
            for packet in packets {
                rtp_packet_count += 1;
                payload_bytes += packet.payload.len();
                let received = match &mut loopback {
                    RtpLoopback::H264 { ingress, .. } => ingress.push_packet(
                        &packet.payload,
                        packet.header.marker,
                        packet.header.sequence_number,
                        access_unit.timestamp_us,
                    ),
                    RtpLoopback::Hevc { ingress, .. } => ingress.push_packet(
                        &packet.payload,
                        packet.header.marker,
                        packet.header.sequence_number,
                        access_unit.timestamp_us,
                    ),
                    RtpLoopback::Av1 { ingress, .. } => ingress.push_packet(
                        &packet.payload,
                        packet.header.marker,
                        packet.header.sequence_number,
                        access_unit.timestamp_us,
                    ),
                    RtpLoopback::Vvc { ingress, .. } => ingress.push_packet(
                        &packet.payload,
                        packet.header.marker,
                        packet.header.sequence_number,
                        access_unit.timestamp_us,
                    ),
                };
                if let Some(received) = received {
                    reassembled.push(received);
                }
            }
        }

        if reassembled.is_empty() {
            anyhow::bail!("WebRTC RTP loopback produced no access units");
        }

        Ok(SingleWindowTransportProbe {
            transport: "webrtc_rtp_loopback".to_string(),
            access_units: reassembled,
            rtp_packet_count,
            payload_bytes,
        })
    }

    fn openh264_compatible_frame(frame: &CapturedFrame) -> Result<CapturedFrame> {
        let width = frame.width - (frame.width % 2);
        let height = frame.height - (frame.height % 2);

        if width == 0 || height == 0 {
            anyhow::bail!(
                "captured frame is too small for OpenH264: {}x{}",
                frame.width,
                frame.height
            );
        }

        if frame.pixel_format == FramePixelFormat::Nv12 {
            let expected_len = nv12_frame_len(frame.width, frame.height)
                .ok_or_else(|| anyhow::anyhow!("captured NV12 frame buffer size overflow"))?;
            if frame.data.len() != expected_len {
                anyhow::bail!(
                    "captured NV12 frame bytes mismatch: expected {}, got {}",
                    expected_len,
                    frame.data.len()
                );
            }
            if width == frame.width && height == frame.height {
                return Ok(frame.clone());
            }
            let rgb_frame = CapturedFrame::from_cpu(
                frame.width,
                frame.height,
                FramePixelFormat::Rgb24,
                frame.timestamp_us,
                Self::cpu_nv12_to_rgb24(&frame.data, frame.width, frame.height, frame.width),
            );
            return Self::openh264_compatible_frame(&rgb_frame);
        }

        let bytes_per_pixel = match frame.pixel_format {
            FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => 4,
            FramePixelFormat::Rgb24 => 3,
            FramePixelFormat::Nv12 => unreachable!("NV12 handled above"),
        };
        let source_stride = frame
            .width
            .checked_mul(bytes_per_pixel)
            .ok_or_else(|| anyhow::anyhow!("captured frame stride overflow"))?;
        let target_stride = width
            .checked_mul(bytes_per_pixel)
            .ok_or_else(|| anyhow::anyhow!("encoded frame stride overflow"))?;
        let expected_len = source_stride
            .checked_mul(frame.height)
            .ok_or_else(|| anyhow::anyhow!("captured frame buffer size overflow"))?;

        if frame.data.len() != expected_len {
            anyhow::bail!(
                "captured frame bytes mismatch: expected {}, got {}",
                expected_len,
                frame.data.len()
            );
        }

        if width == frame.width && height == frame.height {
            return Ok(frame.clone());
        }

        let mut data = Vec::with_capacity(target_stride * height);
        for row in 0..height {
            let start = row * source_stride;
            data.extend_from_slice(&frame.data[start..start + target_stride]);
        }

        Ok(CapturedFrame::from_cpu(
            width,
            height,
            frame.pixel_format,
            frame.timestamp_us,
            data,
        ))
    }

    fn decoded_frame_format(frame: &DecodedFrame) -> String {
        match &frame.data {
            DecodedFrameData::CpuRgb24(_) => "Rgb24".to_string(),
            DecodedFrameData::CpuBgra32(_) => "Bgra32".to_string(),
            DecodedFrameData::CpuI420 { .. } => "I420".to_string(),
            DecodedFrameData::CpuNv12 { .. } => "Nv12".to_string(),
            DecodedFrameData::CpuP010 { .. } => "P010".to_string(),
            #[cfg(windows)]
            DecodedFrameData::D3D11SharedNv12 { .. } => "D3D11SharedNv12".to_string(),
            #[cfg(windows)]
            DecodedFrameData::D3D11SharedP010 { .. } => "D3D11SharedP010".to_string(),
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn decoded_frame_to_render_frame(frame: &DecodedFrame) -> RenderFrame {
        match &frame.data {
            DecodedFrameData::CpuRgb24(data) => {
                RenderFrame::from_rgb24(frame.width, frame.height, data.clone())
            }
            DecodedFrameData::CpuBgra32(data) => {
                RenderFrame::from_bgra32(frame.width, frame.height, data.clone())
            }
            DecodedFrameData::CpuI420 {
                data,
                y_pitch,
                uv_pitch,
            } => RenderFrame::from_bgra32(
                frame.width,
                frame.height,
                Self::cpu_i420_to_bgra32(data, frame.width, frame.height, *y_pitch, *uv_pitch),
            ),
            DecodedFrameData::CpuNv12 { data, pitch } => RenderFrame::from_bgra32(
                frame.width,
                frame.height,
                Self::cpu_nv12_to_bgra32(data, frame.width, frame.height, *pitch),
            ),
            DecodedFrameData::CpuP010 { data, pitch } => RenderFrame::from_bgra32(
                frame.width,
                frame.height,
                Self::cpu_p010_to_bgra32(data, frame.width, frame.height, *pitch),
            ),
            #[cfg(windows)]
            DecodedFrameData::D3D11SharedNv12 {
                shared_handle_y,
                shared_handle_uv,
                ..
            } => RenderFrame::from_d3d11_shared_nv12(
                frame.width,
                frame.height,
                *shared_handle_y,
                *shared_handle_uv,
            ),
            #[cfg(windows)]
            DecodedFrameData::D3D11SharedP010 {
                shared_handle_y,
                shared_handle_uv,
                ..
            } => RenderFrame::from_d3d11_shared_p010(
                frame.width,
                frame.height,
                *shared_handle_y,
                *shared_handle_uv,
            ),
        }
    }

    fn cpu_nv12_to_rgb24(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
        let mut rgb = vec![0_u8; width * height * 3];
        let uv_base = pitch * height;
        let mut out_idx = 0;

        for y in 0..height {
            let uv_row_start = uv_base + (y / 2) * pitch;
            for x in 0..width {
                let y_sample = nv12[y * pitch + x] as i32 - 16;
                let uv_offset = uv_row_start + (x / 2) * 2;
                let u = nv12[uv_offset] as i32 - 128;
                let v = nv12[uv_offset + 1] as i32 - 128;

                let r = (298 * y_sample + 409 * v + 128) >> 8;
                let g = (298 * y_sample - 100 * u - 208 * v + 128) >> 8;
                let b = (298 * y_sample + 516 * u + 128) >> 8;

                rgb[out_idx] = r.clamp(0, 255) as u8;
                rgb[out_idx + 1] = g.clamp(0, 255) as u8;
                rgb[out_idx + 2] = b.clamp(0, 255) as u8;
                out_idx += 3;
            }
        }

        rgb
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn cpu_nv12_to_bgra32(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
        let mut bgra = vec![0_u8; width * height * 4];
        let uv_base = pitch * height;

        for y in (0..height).step_by(2) {
            let y0_row = y * pitch;
            let y1_row = (y + 1).min(height.saturating_sub(1)) * pitch;
            let uv_row_start = uv_base + (y / 2) * pitch;
            let out0_row = y * width * 4;
            let out1_row = (y + 1).min(height.saturating_sub(1)) * width * 4;

            for x in (0..width).step_by(2) {
                let uv_offset = uv_row_start + (x / 2) * 2;
                if uv_offset + 1 >= nv12.len() {
                    continue;
                }

                let u = nv12[uv_offset];
                let v = nv12[uv_offset + 1];
                let y0_offset = y0_row + x;
                if y0_offset < nv12.len() {
                    Self::write_limited_bgra_pixel(
                        &mut bgra,
                        out0_row + x * 4,
                        nv12[y0_offset],
                        u,
                        v,
                    );
                }
                if x + 1 < width {
                    let y0_next = y0_offset + 1;
                    if y0_next < nv12.len() {
                        Self::write_limited_bgra_pixel(
                            &mut bgra,
                            out0_row + (x + 1) * 4,
                            nv12[y0_next],
                            u,
                            v,
                        );
                    }
                }
                if y + 1 < height {
                    let y1_offset = y1_row + x;
                    if y1_offset < nv12.len() {
                        Self::write_limited_bgra_pixel(
                            &mut bgra,
                            out1_row + x * 4,
                            nv12[y1_offset],
                            u,
                            v,
                        );
                    }
                    if x + 1 < width {
                        let y1_next = y1_offset + 1;
                        if y1_next < nv12.len() {
                            Self::write_limited_bgra_pixel(
                                &mut bgra,
                                out1_row + (x + 1) * 4,
                                nv12[y1_next],
                                u,
                                v,
                            );
                        }
                    }
                }
            }
        }

        bgra
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn cpu_i420_to_bgra32(
        i420: &[u8],
        width: usize,
        height: usize,
        y_pitch: usize,
        uv_pitch: usize,
    ) -> Vec<u8> {
        let mut bgra = vec![0_u8; width * height * 4];
        let chroma_height = height.div_ceil(2);
        let u_base = y_pitch * height;
        let v_base = u_base + uv_pitch * chroma_height;

        for y in (0..height).step_by(2) {
            let y0_row = y * y_pitch;
            let y1_row = (y + 1).min(height.saturating_sub(1)) * y_pitch;
            let uv_row_start = (y / 2) * uv_pitch;
            let out0_row = y * width * 4;
            let out1_row = (y + 1).min(height.saturating_sub(1)) * width * 4;

            for x in (0..width).step_by(2) {
                let uv_offset = uv_row_start + x / 2;
                let u_offset = u_base + uv_offset;
                let v_offset = v_base + uv_offset;
                if u_offset >= i420.len() || v_offset >= i420.len() {
                    continue;
                }

                let u = i420[u_offset];
                let v = i420[v_offset];
                let y0_offset = y0_row + x;
                if y0_offset < i420.len() {
                    Self::write_limited_bgra_pixel(
                        &mut bgra,
                        out0_row + x * 4,
                        i420[y0_offset],
                        u,
                        v,
                    );
                }
                if x + 1 < width {
                    let y0_next = y0_offset + 1;
                    if y0_next < i420.len() {
                        Self::write_limited_bgra_pixel(
                            &mut bgra,
                            out0_row + (x + 1) * 4,
                            i420[y0_next],
                            u,
                            v,
                        );
                    }
                }
                if y + 1 < height {
                    let y1_offset = y1_row + x;
                    if y1_offset < i420.len() {
                        Self::write_limited_bgra_pixel(
                            &mut bgra,
                            out1_row + x * 4,
                            i420[y1_offset],
                            u,
                            v,
                        );
                    }
                    if x + 1 < width {
                        let y1_next = y1_offset + 1;
                        if y1_next < i420.len() {
                            Self::write_limited_bgra_pixel(
                                &mut bgra,
                                out1_row + (x + 1) * 4,
                                i420[y1_next],
                                u,
                                v,
                            );
                        }
                    }
                }
            }
        }

        bgra
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn cpu_p010_to_bgra32(p010: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
        let mut bgra = vec![0_u8; width * height * 4];
        let uv_base = pitch * height;

        for y in (0..height).step_by(2) {
            let y0_row = y * pitch;
            let y1_row = (y + 1).min(height.saturating_sub(1)) * pitch;
            let uv_row_start = uv_base + (y / 2) * pitch;
            let out0_row = y * width * 4;
            let out1_row = (y + 1).min(height.saturating_sub(1)) * width * 4;

            for x in (0..width).step_by(2) {
                let uv_offset = uv_row_start + (x / 2) * 4;
                if uv_offset + 3 >= p010.len() {
                    continue;
                }

                let u10 = u16::from_le_bytes([p010[uv_offset], p010[uv_offset + 1]]) >> 6;
                let v10 = u16::from_le_bytes([p010[uv_offset + 2], p010[uv_offset + 3]]) >> 6;
                let y0_offset = y0_row + x * 2;
                if y0_offset + 1 < p010.len() {
                    let y10 = u16::from_le_bytes([p010[y0_offset], p010[y0_offset + 1]]) >> 6;
                    Self::write_p010_bgra_pixel(&mut bgra, out0_row + x * 4, y10, u10, v10);
                }
                if x + 1 < width {
                    let y0_next = y0_offset + 2;
                    if y0_next + 1 < p010.len() {
                        let y10 = u16::from_le_bytes([p010[y0_next], p010[y0_next + 1]]) >> 6;
                        Self::write_p010_bgra_pixel(
                            &mut bgra,
                            out0_row + (x + 1) * 4,
                            y10,
                            u10,
                            v10,
                        );
                    }
                }
                if y + 1 < height {
                    let y1_offset = y1_row + x * 2;
                    if y1_offset + 1 < p010.len() {
                        let y10 = u16::from_le_bytes([p010[y1_offset], p010[y1_offset + 1]]) >> 6;
                        Self::write_p010_bgra_pixel(&mut bgra, out1_row + x * 4, y10, u10, v10);
                    }
                    if x + 1 < width {
                        let y1_next = y1_offset + 2;
                        if y1_next + 1 < p010.len() {
                            let y10 = u16::from_le_bytes([p010[y1_next], p010[y1_next + 1]]) >> 6;
                            Self::write_p010_bgra_pixel(
                                &mut bgra,
                                out1_row + (x + 1) * 4,
                                y10,
                                u10,
                                v10,
                            );
                        }
                    }
                }
            }
        }

        bgra
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[inline]
    fn write_limited_bgra_pixel(bgra: &mut [u8], offset: usize, y: u8, u: u8, v: u8) {
        if offset + 3 >= bgra.len() {
            return;
        }
        let y_sample = y as i32 - 16;
        let u = u as i32 - 128;
        let v = v as i32 - 128;

        let r = (298 * y_sample + 409 * v + 128) >> 8;
        let g = (298 * y_sample - 100 * u - 208 * v + 128) >> 8;
        let b = (298 * y_sample + 516 * u + 128) >> 8;

        bgra[offset] = b.clamp(0, 255) as u8;
        bgra[offset + 1] = g.clamp(0, 255) as u8;
        bgra[offset + 2] = r.clamp(0, 255) as u8;
        bgra[offset + 3] = 255;
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[inline]
    fn write_p010_bgra_pixel(bgra: &mut [u8], offset: usize, y10: u16, u10: u16, v10: u16) {
        if offset + 3 >= bgra.len() {
            return;
        }
        let y_sample = y10 as i32;
        let u = u10 as i32 - 512;
        let v = v10 as i32 - 512;

        let r = y_sample + ((1436 * v) >> 10);
        let g = y_sample - ((352 * u + 731 * v) >> 10);
        let b = y_sample + ((1815 * u) >> 10);

        bgra[offset] = Self::clamp_10bit_to_8bit(b);
        bgra[offset + 1] = Self::clamp_10bit_to_8bit(g);
        bgra[offset + 2] = Self::clamp_10bit_to_8bit(r);
        bgra[offset + 3] = 255;
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[inline]
    fn clamp_10bit_to_8bit(value: i32) -> u8 {
        (((value.clamp(0, 1023) + 2) >> 2).min(255)) as u8
    }

    /// Stop a running test
    pub fn stop_run(&self, run_id: &str) -> Result<()> {
        let owned_metrics = stop_owned_harness(&self.active_harness_run_id, &self.harness, run_id);
        let mut cancelled = false;
        {
            let mut runs = self.runs.lock().unwrap();
            if let Some(run) = runs.get_mut(run_id) {
                if run.status == RunStatus::Running {
                    run.status = RunStatus::Cancelled;
                    run.finished_at = Some(now_ms());
                    run.summary = Some(match owned_metrics.as_ref() {
                        Some(metrics) => summary_from_metrics(run.started_at, metrics),
                        None => TestRunSummary {
                            total_duration_ms: now_ms().saturating_sub(run.started_at),
                            ..Default::default()
                        },
                    });
                    persist_run_to_store(&self.telemetry_store, run);
                    cancelled = true;
                }
            }
        }

        if cancelled {
            self.record_stage_event(run_id.to_string(), "running", "cancelled", None, None);
        }
        Ok(())
    }

    pub fn record_external_run(&self, record: ExternalTestRunRecord) -> Result<RunId> {
        let run_id = record.run_id.unwrap_or_else(generate_run_id);
        let environment_snapshot = match record.environment_snapshot {
            Some(snapshot) => snapshot,
            None => self.get_capabilities()?,
        };
        let classification = record.classification.or_else(|| {
            Some(derive_test_classification(
                &record.config_snapshot,
                &environment_snapshot,
                TestRunScope::CrossDevice,
                None,
            ))
        });
        let run = TestRun {
            run_id: run_id.clone(),
            scenario_id: record.scenario_id,
            run_mode: record.run_mode.unwrap_or(RunMode::Matrix),
            status: record.status,
            started_at: record.started_at,
            finished_at: record.finished_at,
            config_snapshot: record.config_snapshot,
            environment_snapshot,
            summary: record.summary,
            classification,
        };

        self.runs.lock().unwrap().insert(run_id.clone(), run);
        self.persist_run_by_id(&run_id);

        if !record.events.is_empty() {
            let events: Vec<_> = record
                .events
                .into_iter()
                .inspect(|event| {
                    append_event_to_store(&self.telemetry_store, &run_id, event);
                })
                .collect();
            self.run_events
                .lock()
                .unwrap()
                .insert(run_id.clone(), events);
        }

        if !record.artifacts.is_empty() {
            let artifacts: Vec<_> = record
                .artifacts
                .into_iter()
                .map(|mut artifact| {
                    artifact.run_id = run_id.clone();
                    artifact
                })
                .collect();
            self.run_artifacts
                .lock()
                .unwrap()
                .insert(run_id.clone(), artifacts);
            self.persist_artifacts_by_id(&run_id);
        }

        Ok(run_id)
    }

    /// Get a test run
    pub fn get_run(&self, run_id: &str) -> Option<TestRun> {
        self.runs.lock().unwrap().get(run_id).cloned()
    }

    /// List test runs
    pub fn list_runs(
        &self,
        scenario_id: Option<String>,
        status: Option<String>,
        limit: Option<usize>,
    ) -> Vec<TestRun> {
        let runs = self.runs.lock().unwrap();
        let mut result: Vec<TestRun> = runs.values().cloned().collect();
        drop(runs);

        if let Ok(persisted_runs) = self.telemetry_store.list_runs(None) {
            let mut known = result
                .iter()
                .map(|run| run.run_id.clone())
                .collect::<std::collections::HashSet<_>>();
            for metadata in persisted_runs {
                if known.insert(metadata.run_id.clone()) {
                    result.push(test_run_from_metadata(metadata));
                }
            }
        }

        // Apply filters
        if let Some(sid) = scenario_id {
            result.retain(|r| r.scenario_id == sid);
        }
        if let Some(s) = status {
            match serde_json::from_str::<RunStatus>(&format!("\"{}\"", s)) {
                Ok(run_status) => result.retain(|r| r.status == run_status),
                Err(_) => result.clear(),
            }
        }

        // Sort by started_at descending
        result.sort_by_key(|run| std::cmp::Reverse(run.started_at));

        // Apply limit
        if let Some(limit) = limit {
            result.truncate(limit);
        }

        result
    }

    /// Update run metrics from harness
    #[allow(dead_code)]
    pub fn update_run_metrics(&self, run_id: &str, metrics: &HarnessMetrics) {
        let mut runs = self.runs.lock().unwrap();
        if let Some(run) = runs.get_mut(run_id) {
            if run.summary.is_none() {
                run.summary = Some(TestRunSummary {
                    total_duration_ms: now_ms() - run.started_at,
                    capture_fps: Some(metrics.capture_fps),
                    observed_fps: Some(metrics.observed_fps()),
                    decoded_fps: Some(metrics.decoded_fps),
                    encode_latency_p50: Some(metrics.encode_latency_p50_ms),
                    encode_latency_p95: Some(metrics.encode_latency_p95_ms),
                    transport_latency_p50: Some(metrics.transport_latency_p50_ms),
                    transport_latency_p95: Some(metrics.transport_latency_p95_ms),
                    decode_latency_p50: Some(metrics.decode_latency_p50_ms),
                    decode_latency_p95: Some(metrics.decode_latency_p95_ms),
                    total_latency_p95: Some(metrics.total_latency_p95_ms),
                    dropped_frames: metrics.dropped_frames,
                    frame_count: metrics.frame_count,
                    decoded_frames: metrics.decoded_frames,
                    render_presented_frames: metrics.render_presented_frames,
                    render_present_skipped_frames: metrics.render_present_skipped_frames,
                    render_present_gap_p95_ms: Some(metrics.render_present_gap_p95_ms),
                    ..Default::default()
                });
            }
        }
    }

    /// Record a stage event
    pub fn record_stage_event(
        &self,
        run_id: String,
        stage: &str,
        status: &str,
        duration_ms: Option<u64>,
        error: Option<String>,
    ) {
        let event = TestStageEvent {
            stage: stage.to_string(),
            status: status.to_string(),
            timestamp: now_ms(),
            duration_ms,
            error,
        };

        append_event_to_store(&self.telemetry_store, &run_id, &event);
        self.run_events
            .lock()
            .unwrap()
            .entry(run_id)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Get run events
    pub fn get_run_events(&self, run_id: &str) -> Vec<TestStageEvent> {
        self.run_events
            .lock()
            .unwrap()
            .get(run_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get run metrics.
    pub fn get_run_metrics(&self, run_id: &str) -> HashMap<String, MetricSeries> {
        self.run_metrics
            .lock()
            .unwrap()
            .get(run_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get run artifacts.
    pub fn get_run_artifacts(&self, run_id: &str) -> Vec<Artifact> {
        self.run_artifacts
            .lock()
            .unwrap()
            .get(run_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get persisted telemetry for a run.
    pub fn get_run_telemetry(
        &self,
        run_id: &str,
        query: telemetry::TelemetryQuery,
    ) -> Result<telemetry::TelemetryBundle> {
        let mut bundle = self.telemetry_store.query_bundle(run_id, query)?;

        if bundle.run.is_none() {
            if let Some(run) = self.get_run(run_id) {
                bundle.run = Some(run_metadata_from_test_run(&run));
            }
        }
        if bundle.metrics.is_empty() {
            bundle.metrics = self
                .get_run_metrics(run_id)
                .into_iter()
                .map(|(name, series)| (name, telemetry_series_from_metric_series(series)))
                .collect();
        }
        if bundle.events.is_empty() {
            bundle.events = self
                .get_run_events(run_id)
                .into_iter()
                .map(telemetry_event_from_stage_event)
                .collect();
        }
        if bundle.artifacts.is_empty() {
            bundle.artifacts = self
                .get_run_artifacts(run_id)
                .into_iter()
                .map(telemetry_artifact_from_artifact)
                .collect();
        }

        Ok(bundle)
    }

    fn persist_run_by_id(&self, run_id: &str) {
        if let Some(run) = self.get_run(run_id) {
            persist_run_to_store(&self.telemetry_store, &run);
        }
    }

    fn persist_artifacts_by_id(&self, run_id: &str) {
        let artifacts: Vec<_> = self
            .get_run_artifacts(run_id)
            .into_iter()
            .map(telemetry_artifact_from_artifact)
            .collect();
        if !artifacts.is_empty() {
            let _ = self.telemetry_store.upsert_artifacts(run_id, &artifacts);
        }
    }

    /// Save a preset
    pub fn save_preset(
        &self,
        name: String,
        description: String,
        scenario_id: String,
        config: TestConfigData,
    ) -> String {
        let preset_id = generate_preset_id();
        let preset = TestPreset {
            preset_id: preset_id.clone(),
            name,
            description,
            scenario_id,
            config,
            tags: None,
            created_at: now_ms() / 1000,
        };

        self.presets
            .lock()
            .unwrap()
            .insert(preset_id.clone(), preset);
        preset_id
    }

    /// List presets
    pub fn list_presets(&self) -> Vec<TestPreset> {
        self.presets.lock().unwrap().values().cloned().collect()
    }

    /// Delete a preset
    pub fn delete_preset(&self, preset_id: &str) -> Result<()> {
        self.presets
            .lock()
            .unwrap()
            .remove(preset_id)
            .ok_or_else(|| anyhow::anyhow!("Preset not found"))?;
        Ok(())
    }

    /// Get current harness chain
    #[allow(dead_code)]
    pub fn get_harness_chain(&self) -> Option<TestChain> {
        self.current_harness_chain.lock().unwrap().clone()
    }

    /// Set harness chain
    pub fn set_harness_chain(&self, chain: TestChain) {
        *self.current_harness_chain.lock().unwrap() = Some(chain);
    }
}

impl Default for TestOrchestrator {
    fn default() -> Self {
        Self::new(Arc::new(Mutex::new(
            TestHarness::new().expect("failed to create default TestHarness"),
        )))
    }
}

fn current_platform_captures() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        return vec!["dxgi", "winrt", "synthetic"];
    }

    #[cfg(target_os = "macos")]
    {
        return vec!["macos", "synthetic"];
    }

    #[cfg(target_os = "linux")]
    {
        return vec!["linux", "synthetic"];
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        vec!["synthetic"]
    }
}

fn current_platform_renderers() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        return vec!["none", "d3d11", "d3d12", "opengl", "webview"];
    }

    #[cfg(target_os = "macos")]
    {
        return vec!["none", "macos", "webview"];
    }

    #[cfg(target_os = "linux")]
    {
        return vec!["none", "linux", "webview"];
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        vec!["none", "webview"]
    }
}

fn current_platform_memory_modes() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        return vec!["cpu", "d3d11_shared"];
    }

    #[cfg(not(windows))]
    {
        vec!["cpu"]
    }
}

fn scenario_supported_on_current_platform(scenario_id: &str) -> bool {
    match scenario_id {
        "capture.dxgi" | "capture.winrt" | "encode.nvenc_h264" | "decode.nvdec_h264"
        | "e2e.local" => cfg!(windows),
        "render.probe" | "render.d3d12" | "render.opengl" => cfg!(windows),
        "single_window.local" => cfg!(windows) || cfg!(target_os = "macos"),
        "capture.macos" | "e2e.macos_local" => cfg!(target_os = "macos"),
        "encode.videotoolbox_h264" => macos_videotoolbox_h264_encoder_available(),
        "encode.videotoolbox_hevc" => macos_videotoolbox_hevc_encoder_available(),
        "capture.linux" | "decode.linux_h264" | "e2e.linux_local" => cfg!(target_os = "linux"),
        "decode.videotoolbox_h264" => macos_videotoolbox_h264_decoder_available(),
        "decode.videotoolbox_hevc" => macos_videotoolbox_hevc_decoder_available(),
        "encode.openh264" | "custom" | "matrix" => true,
        _ => true,
    }
}

fn macos_e2e_encoder_type(config: &TestConfigData) -> &str {
    match config
        .encoder_type
        .as_deref()
        .unwrap_or("videotoolbox_hevc")
    {
        "hevc" | "h265" | "h.265" => "videotoolbox_hevc",
        "h264" | "h.264" => "videotoolbox_h264",
        encoder_type => encoder_type,
    }
}

fn capture_supported_on_current_platform(capture_type: &str) -> bool {
    matches!(capture_type, "synthetic")
        || matches!(capture_type, "dxgi" | "winrt") && cfg!(windows)
        || matches!(capture_type, "macos") && cfg!(target_os = "macos")
        || matches!(capture_type, "linux") && cfg!(target_os = "linux")
}

fn encoder_supported_on_current_platform(encoder_type: &str) -> bool {
    matches!(
        encoder_type,
        "none"
            | "openh264"
            | "software_h264"
            | "h264_software"
            | "software-h264"
            | "h264-software"
            | "sw_h264"
    ) || matches!(
        encoder_type,
        "nvenc_h264"
            | "nvenc_av1"
            | "nvenc_hevc"
            | "nvenc_hevc_main10"
            | "hevc"
            | "hevc_main10"
            | "hevc-main10"
    ) && (cfg!(windows) || cfg!(target_os = "linux"))
        || matches!(
            encoder_type,
            "videotoolbox_h264" | "videotoolbox_hevc" | "videotoolbox"
        ) && macos_videotoolbox_encoder_available(encoder_type)
}

fn decoder_supported_on_current_platform(decoder_type: &str) -> bool {
    matches!(
        decoder_type,
        "none"
            | "software"
            | "software_h264"
            | "h264_software"
            | "software-h264"
            | "h264-software"
            | "openh264"
            | "ffmpeg_h264"
            | "h264_ffmpeg"
            | "ffmpeg_hevc"
            | "hevc_ffmpeg"
            | "h265_ffmpeg"
    ) || matches!(decoder_type, "nvdec") && cfg!(windows)
        || matches!(
            decoder_type,
            "linux_h264"
                | "gstreamer_h264"
                | "vaapi_h264"
                | "linux_hevc"
                | "gstreamer_hevc"
                | "vaapi_hevc"
                | "linux_hevc_main10"
                | "gstreamer_hevc_main10"
                | "vaapi_hevc_main10"
        ) && cfg!(target_os = "linux")
        || matches!(decoder_type, "videotoolbox")
            && cfg!(target_os = "macos")
            && videotoolbox_decoder_enabled()
}

fn decoder_supported_for_config(decoder_type: &str, encoder_type: Option<&str>) -> bool {
    if decoder_type == "videotoolbox" {
        return macos_videotoolbox_decoder_available_for_encoder(encoder_type);
    }
    decoder_supported_on_current_platform(decoder_type)
}

fn macos_videotoolbox_decoder_available_for_encoder(encoder_type: Option<&str>) -> bool {
    macos_videotoolbox_decoder_available_for_encoder_with(
        encoder_type,
        macos_videotoolbox_h264_decoder_available(),
        macos_videotoolbox_hevc_decoder_available(),
    )
}

fn macos_videotoolbox_decoder_available_for_encoder_with(
    encoder_type: Option<&str>,
    h264_decoder_available: bool,
    hevc_decoder_available: bool,
) -> bool {
    match encoder_type {
        Some("videotoolbox_hevc") | Some("hevc") | Some("h265") | Some("h.265") => {
            hevc_decoder_available
        }
        _ => h264_decoder_available,
    }
}

fn macos_videotoolbox_encoder_available(encoder_type: &str) -> bool {
    match encoder_type {
        "videotoolbox_hevc" => macos_videotoolbox_hevc_encoder_available(),
        "videotoolbox_h264" | "videotoolbox" => macos_videotoolbox_h264_encoder_available(),
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn macos_videotoolbox_h264_encoder_available() -> bool {
    mrd_codec_videotoolbox::VideoToolboxH264Encoder::new(640, 480, 30).is_ok()
}

#[cfg(not(target_os = "macos"))]
fn macos_videotoolbox_h264_encoder_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn macos_videotoolbox_hevc_encoder_available() -> bool {
    mrd_codec_videotoolbox::VideoToolboxHevcEncoder::new(640, 480, 30).is_ok()
}

#[cfg(not(target_os = "macos"))]
fn macos_videotoolbox_hevc_encoder_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn macos_videotoolbox_h264_decoder_available() -> bool {
    videotoolbox_decoder_enabled() && mrd_codec_videotoolbox::VideoToolboxH264Decoder::new().is_ok()
}

#[cfg(not(target_os = "macos"))]
fn macos_videotoolbox_h264_decoder_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn macos_videotoolbox_hevc_decoder_available() -> bool {
    videotoolbox_decoder_enabled() && mrd_codec_videotoolbox::VideoToolboxHevcDecoder::new().is_ok()
}

#[cfg(not(target_os = "macos"))]
fn macos_videotoolbox_hevc_decoder_available() -> bool {
    false
}

#[cfg(any(target_os = "macos", test))]
fn append_macos_videotoolbox_decoder_capabilities(
    available_decoders: &mut Vec<String>,
    h264_decoder_available: bool,
    hevc_decoder_available: bool,
) {
    if h264_decoder_available {
        available_decoders.push("videotoolbox_h264".to_string());
    }
    if hevc_decoder_available {
        available_decoders.push("videotoolbox_hevc".to_string());
    }
    if h264_decoder_available && hevc_decoder_available {
        available_decoders.push("videotoolbox".to_string());
    }
}

fn renderer_supported_on_current_platform(renderer_type: &str) -> bool {
    matches!(renderer_type, "none")
        || matches!(renderer_type, "d3d11") && cfg!(windows)
        || matches!(renderer_type, "d3d12" | "opengl") && cfg!(windows)
        || matches!(renderer_type, "macos" | "metal") && cfg!(target_os = "macos")
        || matches!(renderer_type, "linux") && cfg!(target_os = "linux")
}

fn validate_execution_config(config: &TestConfigData) -> Result<()> {
    if let Some([width, height]) = config.resolution {
        if width == 0 || height == 0 {
            anyhow::bail!("resolution dimensions must both be greater than zero");
        }
    }
    if config.fps == Some(0) {
        anyhow::bail!("fps must be greater than zero");
    }
    if config.bitrate == Some(0) {
        anyhow::bail!("bitrate must be greater than zero");
    }
    if config.duration_ms == Some(0) {
        anyhow::bail!("duration_ms must be greater than zero");
    }
    if let Some(repeat_count) = config.repeat_count {
        if repeat_count != 1 {
            anyhow::bail!(
                "repeat_count={} is not supported by a single test run; run the matrix or create separate runs instead",
                repeat_count
            );
        }
    }
    if config.dynamic_resolution_enabled == Some(true) && config.adaptive_media != Some(true) {
        anyhow::bail!("dynamic_resolution_enabled requires adaptive_media=true");
    }
    if config.adaptive_media == Some(true) || config.dynamic_resolution_enabled == Some(true) {
        anyhow::bail!("adaptive media controls are supported only by cross-device LAN automation");
    }
    let duration_ms = config.duration_ms.unwrap_or(30_000);
    let warmup_ms = config.warmup_ms.unwrap_or(0);
    duration_ms
        .checked_add(warmup_ms)
        .ok_or_else(|| anyhow::anyhow!("warmup_ms + duration_ms exceeds the supported range"))?;
    Ok(())
}

fn validate_scenario_for_current_platform(
    scenario_id: &str,
    config: &TestConfigData,
) -> Result<()> {
    let os_type = std::env::consts::OS;
    if !scenario_supported_on_current_platform(scenario_id) {
        anyhow::bail!("Scenario {} is not supported on {}", scenario_id, os_type);
    }

    if !matches!(scenario_id, "custom" | "matrix") {
        if scenario_id == "e2e.macos_local" {
            let encoder_type = macos_e2e_encoder_type(config);
            if !encoder_supported_on_current_platform(encoder_type) {
                anyhow::bail!(
                    "Encoder type {} is not supported for {} on {}",
                    encoder_type,
                    scenario_id,
                    os_type
                );
            }
            let decoder_type = config.decoder_type.as_deref().unwrap_or("videotoolbox");
            if !decoder_supported_for_config(decoder_type, Some(encoder_type)) {
                anyhow::bail!(
                    "Decoder type {} is not supported for {} on {}",
                    decoder_type,
                    scenario_id,
                    os_type
                );
            }
        }
        return Ok(());
    }

    let capture_type = config.capture_type.as_deref().unwrap_or("dxgi");
    if !capture_supported_on_current_platform(capture_type) {
        anyhow::bail!(
            "Capture type {} is not supported on {}",
            capture_type,
            os_type
        );
    }

    let encoder_type = config
        .encoder_type
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Missing encoder_type for {}", scenario_id))?;
    if !encoder_supported_on_current_platform(encoder_type) {
        anyhow::bail!(
            "Encoder type {} is not supported on {}",
            encoder_type,
            os_type
        );
    }
    validate_color_config_for_encoder_type(encoder_type, config)?;

    let decoder_type = config.decoder_type.as_deref().unwrap_or("software");
    if !decoder_supported_for_config(decoder_type, Some(encoder_type)) {
        anyhow::bail!(
            "Decoder type {} is not supported on {}",
            decoder_type,
            os_type
        );
    }

    let renderer_type = config.renderer_type.as_deref().unwrap_or("none");
    if !renderer_supported_on_current_platform(renderer_type) {
        anyhow::bail!(
            "Renderer type {} is not supported on {}",
            renderer_type,
            os_type
        );
    }
    if renderer_type == "d3d12" {
        anyhow::bail!(
            "Renderer type {} uses the independent render.probe path and is not supported by custom/matrix harness runs",
            renderer_type
        );
    }
    if config.zero_copy == Some(true) && !current_platform_memory_modes().contains(&"d3d11_shared")
    {
        anyhow::bail!(
            "D3D11 shared texture memory mode is not supported on {}",
            os_type
        );
    }

    if config.zero_copy == Some(true) {
        if !matches!(capture_type, "dxgi" | "winrt") {
            anyhow::bail!("D3D11 shared texture capture requires DXGI or WinRT capture");
        }
        if !matches!(
            encoder_type,
            "none"
                | "nvenc_h264"
                | "nvenc_av1"
                | "nvenc_hevc"
                | "nvenc_hevc_main10"
                | "hevc"
                | "hevc_main10"
                | "hevc-main10"
        ) {
            anyhow::bail!("D3D11 shared texture input requires direct render or an NVENC encoder");
        }
    }

    Ok(())
}

fn validate_color_config_for_encoder_type(
    encoder_type: &str,
    config: &TestConfigData,
) -> Result<()> {
    let color_mode = config.color_mode.unwrap_or_default();
    if color_mode != ColorMode::Full && !encoder_type_supports_non_full_color_mode(encoder_type) {
        anyhow::bail!(
            "color_mode={} requires Windows D3D11 NVENC H.264/HEVC GPU color transform; encoder {} is not supported",
            color_mode.as_str(),
            encoder_type_label(encoder_type)
        );
    }

    let color_pipeline = config.color_pipeline.unwrap_or_default();
    if color_pipeline == ColorPipeline::HdrMain10
        && !encoder_type_supports_hdr_main10_pipeline(encoder_type)
    {
        anyhow::bail!(
            "color_pipeline={} requires NVENC HEVC Main10; encoder {} is not supported",
            color_pipeline.as_str(),
            encoder_type_label(encoder_type)
        );
    }

    Ok(())
}

fn encoder_type_supports_non_full_color_mode(encoder_type: &str) -> bool {
    cfg!(windows)
        && matches!(
            encoder_type,
            "nvenc_h264"
                | "nvenc_hevc"
                | "nvenc_hevc_main10"
                | "hevc"
                | "hevc_main10"
                | "hevc-main10"
        )
}

fn encoder_type_supports_hdr_main10_pipeline(encoder_type: &str) -> bool {
    matches!(
        encoder_type,
        "nvenc_hevc_main10" | "hevc_main10" | "hevc-main10"
    )
}

fn encoder_type_label(encoder_type: &str) -> &'static str {
    match encoder_type {
        "none" => "none",
        "nvenc_h264" => "NVENC H.264",
        "nvenc_hevc" | "hevc" => "NVENC HEVC",
        "nvenc_hevc_main10" | "hevc_main10" | "hevc-main10" => "NVENC HEVC Main10",
        "nvenc_av1" => "NVENC AV1",
        "openh264" | "software_h264" | "h264_software" | "software-h264" | "h264-software"
        | "sw_h264" => "OpenH264",
        "videotoolbox_h264" | "videotoolbox" => "VideoToolbox H.264",
        _ => "unknown encoder",
    }
}

fn videotoolbox_decoder_enabled() -> bool {
    !matches!(
        std::env::var("MRD_DISABLE_VIDEOTOOLBOX_DECODER").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

static RUN_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PRESET_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn generate_run_id() -> String {
    format!(
        "run_{}_{}",
        now_ms(),
        RUN_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn generate_preset_id() -> String {
    format!(
        "preset_{}_{}",
        now_ms(),
        PRESET_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn list_window_capture_targets() -> Result<Vec<WindowCaptureTarget>> {
    list_window_capture_targets_impl()
}

pub fn list_window_capture_targets_with_previews(
    limit: Option<usize>,
) -> Result<Vec<WindowCaptureTarget>> {
    let mut targets = list_window_capture_targets_impl()?;
    if let Some(limit) = limit {
        targets.truncate(limit);
    }
    Ok(targets)
}

pub fn list_capture_share_sources() -> Result<Vec<CaptureShareSourceTarget>> {
    list_capture_share_sources_impl(false, None)
}

pub fn list_capture_share_sources_with_previews(
    limit: Option<usize>,
) -> Result<Vec<CaptureShareSourceTarget>> {
    list_capture_share_sources_impl(false, limit)
}

fn list_capture_share_sources_impl(
    _include_previews: bool,
    limit: Option<usize>,
) -> Result<Vec<CaptureShareSourceTarget>> {
    let mut sources = list_display_share_sources_impl()?;

    match list_window_capture_targets_impl() {
        Ok(window_targets) => sources.extend(
            window_targets
                .into_iter()
                .map(window_target_to_share_source_target),
        ),
        Err(error) => {
            if sources.is_empty() {
                return Err(error);
            }
        }
    }

    if let Some(limit) = limit {
        sources.truncate(limit);
    }

    Ok(sources)
}

fn window_target_to_share_source_target(target: WindowCaptureTarget) -> CaptureShareSourceTarget {
    let platform = if target.platform.is_empty() {
        current_platform_id().to_string()
    } else {
        target.platform.clone()
    };
    let id = if target.id.is_empty() {
        format!("{platform}:window:{}", target.hwnd)
    } else {
        target.id.clone()
    };
    let class_name = (!target.class_name.is_empty()).then_some(target.class_name.clone());
    let subtitle = if let Some(app_name) = target.app_name.as_deref() {
        format!(
            "{app_name} / {}x{} / PID {}",
            target.width, target.height, target.process_id
        )
    } else if target.width > 0 && target.height > 0 {
        format!(
            "{}x{} / PID {}",
            target.width, target.height, target.process_id
        )
    } else {
        format!("PID {}", target.process_id)
    };

    CaptureShareSourceTarget {
        id,
        platform,
        source_kind: "window".to_string(),
        native_id: target.hwnd.clone(),
        title: target.title,
        subtitle,
        width: target.width,
        height: target.height,
        is_primary: false,
        requires_system_picker: false,
        hwnd: Some(target.hwnd),
        class_name,
        process_id: Some(target.process_id),
        app_name: target.app_name,
        bundle_identifier: target.bundle_identifier,
        window_layer: target.window_layer,
        preview_data_url: target.preview_data_url,
        preview_width: target.preview_width,
        preview_height: target.preview_height,
    }
}

fn current_platform_id() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

#[cfg(windows)]
fn list_display_share_sources_impl() -> Result<Vec<CaptureShareSourceTarget>> {
    let monitor_count = mrd_capture_winrt::get_monitor_count()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok((0..monitor_count)
        .map(|index| {
            let native_id = index.to_string();
            let display_number = index + 1;
            CaptureShareSourceTarget {
                id: format!("windows:screen:{native_id}"),
                platform: "windows".to_string(),
                source_kind: "screen".to_string(),
                native_id,
                title: if index == 0 {
                    "Primary display".to_string()
                } else {
                    format!("Display {display_number}")
                },
                subtitle: "Windows.Graphics.Capture monitor source".to_string(),
                width: 0,
                height: 0,
                is_primary: index == 0,
                requires_system_picker: false,
                hwnd: None,
                class_name: None,
                process_id: None,
                app_name: None,
                bundle_identifier: None,
                window_layer: None,
                preview_data_url: None,
                preview_width: None,
                preview_height: None,
            }
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn list_display_share_sources_impl() -> Result<Vec<CaptureShareSourceTarget>> {
    let targets = mrd_capture_macos::enumerate_display_capture_targets()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(targets
        .into_iter()
        .map(|target| {
            let native_id = format!("0x{:X}", target.display_id);
            CaptureShareSourceTarget {
                id: format!("macos:screen:{native_id}"),
                platform: "macos".to_string(),
                source_kind: "screen".to_string(),
                native_id,
                title: target.title,
                subtitle: format!("{}x{} display", target.width, target.height),
                width: target.width,
                height: target.height,
                is_primary: target.is_main,
                requires_system_picker: false,
                hwnd: None,
                class_name: None,
                process_id: None,
                app_name: None,
                bundle_identifier: None,
                window_layer: None,
                preview_data_url: None,
                preview_width: None,
                preview_height: None,
            }
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn list_display_share_sources_impl() -> Result<Vec<CaptureShareSourceTarget>> {
    if mrd_capture_pipewire::PipewireScreenCapture::is_wayland_available() {
        return Ok(vec![CaptureShareSourceTarget {
            id: "linux:portal:system-picker".to_string(),
            platform: "linux".to_string(),
            source_kind: "portal".to_string(),
            native_id: "portal".to_string(),
            title: "System sharing picker".to_string(),
            subtitle: "Wayland requires the desktop portal to approve the final screen/window"
                .to_string(),
            width: 0,
            height: 0,
            is_primary: true,
            requires_system_picker: true,
            hwnd: None,
            class_name: None,
            process_id: None,
            app_name: None,
            bundle_identifier: None,
            window_layer: None,
            preview_data_url: None,
            preview_width: None,
            preview_height: None,
        }]);
    }

    let targets = mrd_capture_pipewire::PipewireScreenCapture::get_display_targets()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(targets
        .into_iter()
        .map(|target| {
            let native_id = target.id.to_string();
            CaptureShareSourceTarget {
                id: format!("linux:screen:{native_id}"),
                platform: "linux".to_string(),
                source_kind: "screen".to_string(),
                native_id,
                title: target.name,
                subtitle: format!("{}x{} display", target.width, target.height),
                width: target.width,
                height: target.height,
                is_primary: target.is_primary,
                requires_system_picker: false,
                hwnd: None,
                class_name: None,
                process_id: None,
                app_name: None,
                bundle_identifier: None,
                window_layer: None,
                preview_data_url: None,
                preview_width: None,
                preview_height: None,
            }
        })
        .collect())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn list_display_share_sources_impl() -> Result<Vec<CaptureShareSourceTarget>> {
    Ok(vec![])
}

fn parse_hwnd(input: &str) -> Result<isize> {
    let trimmed = input.trim().rsplit(':').next().unwrap_or(input).trim();
    if trimmed.is_empty() {
        anyhow::bail!("window capture handle is empty");
    }

    let value = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16).map_err(|error| {
            anyhow::anyhow!("invalid window capture handle '{trimmed}': {error}")
        })?
    } else {
        trimmed.parse::<usize>().map_err(|error| {
            anyhow::anyhow!("invalid window capture handle '{trimmed}': {error}")
        })?
    };

    Ok(value as isize)
}

#[cfg(windows)]
fn list_window_capture_targets_impl() -> Result<Vec<WindowCaptureTarget>> {
    let targets = mrd_capture_winrt::enumerate_window_capture_targets()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(targets
        .into_iter()
        .map(|target| WindowCaptureTarget {
            id: format!("windows:window:0x{:X}", target.hwnd as usize),
            platform: "windows".to_string(),
            source_kind: "window".to_string(),
            hwnd: format!("0x{:X}", target.hwnd as usize),
            title: target.title,
            class_name: target.class_name,
            width: target.width,
            height: target.height,
            process_id: target.process_id,
            app_name: None,
            bundle_identifier: None,
            window_layer: None,
            preview_data_url: None,
            preview_width: None,
            preview_height: None,
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn list_window_capture_targets_impl() -> Result<Vec<WindowCaptureTarget>> {
    let targets = mrd_capture_macos::enumerate_window_capture_targets()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(targets
        .into_iter()
        .map(|target| WindowCaptureTarget {
            id: format!("macos:window:0x{:X}", target.window_id),
            platform: "macos".to_string(),
            source_kind: "window".to_string(),
            hwnd: format!("0x{:X}", target.window_id),
            title: target.title,
            class_name: if target.bundle_identifier.is_empty() {
                target.app_name.clone()
            } else {
                target.bundle_identifier.clone()
            },
            width: target.width,
            height: target.height,
            process_id: target.process_id,
            app_name: Some(target.app_name),
            bundle_identifier: Some(target.bundle_identifier),
            window_layer: Some(target.window_layer),
            preview_data_url: None,
            preview_width: None,
            preview_height: None,
        })
        .collect())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn list_window_capture_targets_impl() -> Result<Vec<WindowCaptureTarget>> {
    anyhow::bail!("window capture is only available on Windows and macOS")
}

#[cfg(windows)]
fn probe_window_capture_item(hwnd: isize) -> Result<WindowCaptureItemProbe> {
    let probe = mrd_capture_winrt::probe_window_capture_item(hwnd)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(WindowCaptureItemProbe {
        hwnd: probe.hwnd,
        id: format!("windows:window:0x{:X}", probe.hwnd as usize),
        platform: "windows".to_string(),
        title: probe.title,
        class_name: probe.class_name,
        width: probe.width,
        height: probe.height,
        app_name: None,
        bundle_identifier: None,
    })
}

#[cfg(target_os = "macos")]
fn probe_window_capture_item(hwnd: isize) -> Result<WindowCaptureItemProbe> {
    let window_id =
        u32::try_from(hwnd).map_err(|_| anyhow::anyhow!("macOS window id out of range: {hwnd}"))?;
    let probe = mrd_capture_macos::probe_window_capture_item(window_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(WindowCaptureItemProbe {
        hwnd: probe.window_id as isize,
        id: format!("macos:window:0x{:X}", probe.window_id),
        platform: "macos".to_string(),
        title: probe.title,
        class_name: if probe.bundle_identifier.is_empty() {
            probe.app_name.clone()
        } else {
            probe.bundle_identifier.clone()
        },
        width: probe.width,
        height: probe.height,
        app_name: Some(probe.app_name),
        bundle_identifier: Some(probe.bundle_identifier),
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn probe_window_capture_item(_hwnd: isize) -> Result<WindowCaptureItemProbe> {
    anyhow::bail!("window capture is only available on Windows and macOS")
}

#[cfg(windows)]
fn probe_window_first_frame(hwnd: isize, timeout: Duration) -> Result<WindowCaptureFrameProbe> {
    let probe = mrd_capture_winrt::probe_window_first_frame(hwnd, timeout)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(WindowCaptureFrameProbe {
        hwnd: probe.hwnd,
        id: format!("windows:window:0x{:X}", probe.hwnd as usize),
        platform: "windows".to_string(),
        title: probe.title,
        class_name: probe.class_name,
        width: probe.width,
        height: probe.height,
        byte_len: probe.byte_len,
        pixel_format: format!("{:?}", probe.pixel_format),
        frame: probe.frame,
        app_name: None,
        bundle_identifier: None,
    })
}

#[cfg(target_os = "macos")]
fn probe_window_first_frame(hwnd: isize, timeout: Duration) -> Result<WindowCaptureFrameProbe> {
    let window_id =
        u32::try_from(hwnd).map_err(|_| anyhow::anyhow!("macOS window id out of range: {hwnd}"))?;
    let probe = mrd_capture_macos::probe_window_first_frame(window_id, timeout)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    Ok(WindowCaptureFrameProbe {
        hwnd: probe.window_id as isize,
        id: format!("macos:window:0x{:X}", probe.window_id),
        platform: "macos".to_string(),
        title: probe.title,
        class_name: if probe.bundle_identifier.is_empty() {
            probe.app_name.clone()
        } else {
            probe.bundle_identifier.clone()
        },
        width: probe.width,
        height: probe.height,
        byte_len: probe.byte_len,
        pixel_format: format!("{:?}", probe.pixel_format),
        frame: probe.frame,
        app_name: Some(probe.app_name),
        bundle_identifier: Some(probe.bundle_identifier),
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn probe_window_first_frame(_hwnd: isize, _timeout: Duration) -> Result<WindowCaptureFrameProbe> {
    anyhow::bail!("window capture is only available on Windows and macOS")
}

fn nv12_frame_len(width: usize, height: usize) -> Option<usize> {
    width.checked_mul(height).and_then(|y_size| {
        width
            .checked_mul(height.div_ceil(2))
            .and_then(|uv_size| y_size.checked_add(uv_size))
    })
}

impl Default for TestRunSummary {
    fn default() -> Self {
        Self {
            total_duration_ms: 0,
            first_frame_latency_ms: None,
            capture_fps: None,
            observed_fps: None,
            decoded_fps: None,
            encode_latency_p50: None,
            encode_latency_p95: None,
            transport_latency_p50: None,
            transport_latency_p95: None,
            decode_latency_p50: None,
            decode_latency_p95: None,
            total_latency_p95: None,
            dropped_frames: 0,
            frame_count: 0,
            decoded_frames: 0,
            render_presented_frames: 0,
            render_present_skipped_frames: 0,
            render_present_gap_p95_ms: None,
            error_message: None,
            failure_reason: None,
            cpu_p95_percent: None,
            gpu_p95_percent: None,
            memory_peak_mb: None,
            network_peak_mbps: None,
        }
    }
}

fn summary_from_metrics(started_at: u64, metrics: &HarnessMetrics) -> TestRunSummary {
    TestRunSummary {
        total_duration_ms: now_ms().saturating_sub(started_at),
        capture_fps: Some(metrics.capture_fps),
        observed_fps: Some(metrics.observed_fps()),
        decoded_fps: Some(metrics.decoded_fps),
        encode_latency_p50: Some(metrics.encode_latency_p50_ms),
        encode_latency_p95: Some(metrics.encode_latency_p95_ms),
        transport_latency_p50: Some(metrics.transport_latency_p50_ms),
        transport_latency_p95: Some(metrics.transport_latency_p95_ms),
        decode_latency_p50: Some(metrics.decode_latency_p50_ms),
        decode_latency_p95: Some(metrics.decode_latency_p95_ms),
        total_latency_p95: Some(metrics.total_latency_p95_ms),
        dropped_frames: metrics.dropped_frames,
        frame_count: metrics.frame_count,
        decoded_frames: metrics.decoded_frames,
        render_presented_frames: metrics.render_presented_frames,
        render_present_skipped_frames: metrics.render_present_skipped_frames,
        render_present_gap_p95_ms: Some(metrics.render_present_gap_p95_ms),
        error_message: metrics.error_message.clone(),
        ..Default::default()
    }
}

fn harness_config_from_data(config: &TestConfigData) -> HarnessConfig {
    HarnessConfig {
        resolution: config.resolution.map(|[width, height]| (width, height)),
        fps: config.fps,
        bitrate: config.bitrate,
        renderer: match (config.render_display, config.renderer_type.as_deref()) {
            (Some(true), Some("d3d11")) => Some(RendererType::D3d11),
            (Some(true), Some("macos")) | (Some(true), Some("metal")) => Some(RendererType::Macos),
            (Some(true), Some("opengl")) => Some(RendererType::Opengl),
            #[cfg(target_os = "linux")]
            (Some(true), Some("linux")) => Some(RendererType::Linux),
            _ => None,
        },
        renderer_target_hwnd: config.renderer_target_hwnd,
        zero_copy: config.zero_copy,
        color_mode: config.color_mode,
        color_pipeline: config.color_pipeline,
        pace_to_fps: None,
        input_source: config.input_source.clone(),
        source_id: config.source_id.clone(),
        display_id: config
            .display_id
            .clone()
            .or_else(|| config.source_id.clone()),
        window_handle: config.window_hwnd.clone(),
        visual_preview: config.visual_preview,
        transport: match config.transport_kind.as_deref() {
            Some("webrtc") | Some("webrtc_rtp") => Some(TransportKind::WebrtcRtp),
            Some("quic") | Some("quic_datagram") => Some(TransportKind::QuicDatagram),
            Some("loopback") | None => Some(TransportKind::Loopback),
            Some(_) => None,
        },
    }
}

fn derive_test_classification(
    config: &TestConfigData,
    environment: &EnvironmentSnapshot,
    run_scope: TestRunScope,
    peer_device: Option<TestDeviceDescriptor>,
) -> TestClassification {
    let encoder = config.encoder_type.as_deref().unwrap_or("none");
    let decoder = config.decoder_type.as_deref().unwrap_or("none");
    let transport = config.transport_kind.as_deref().unwrap_or("loopback");
    let renderer = config.renderer_type.as_deref().unwrap_or("none");
    let render_display = config.render_display.unwrap_or(false);

    let transport_path = match transport {
        "webrtc" | "webrtc_rtp" => TestTransportPath::Webrtc,
        "quic" | "quic_datagram" => TestTransportPath::Quic,
        "loopback" => TestTransportPath::Loopback,
        "none" => TestTransportPath::None,
        _ => TestTransportPath::Unknown,
    };
    let memory_path = if matches!(transport_path, TestTransportPath::Webrtc)
        && (!render_display || renderer == "webview")
    {
        TestMemoryPath::WebrtcMediaStream
    } else if config.zero_copy == Some(true) {
        TestMemoryPath::ZeroCopyD3d11Shared
    } else if encoder == "none" && decoder == "none" && renderer == "none" {
        TestMemoryPath::Unknown
    } else {
        TestMemoryPath::CpuCopy
    };
    let encode_accel = match encoder {
        "none" => TestAccelerationMode::None,
        "nvenc_h264" | "nvenc_hevc" | "nvenc_hevc_main10" | "nvenc_av1" | "videotoolbox_h264"
        | "videotoolbox_hevc" => TestAccelerationMode::Hardware,
        "openh264" => TestAccelerationMode::Software,
        _ => TestAccelerationMode::Unknown,
    };
    let decode_accel = match decoder {
        "none" if matches!(transport_path, TestTransportPath::Webrtc) => {
            TestAccelerationMode::Browser
        }
        "none" => TestAccelerationMode::None,
        "nvdec" | "linux_h264" | "linux_hevc" | "linux_hevc_main10" | "videotoolbox" => {
            TestAccelerationMode::Hardware
        }
        "software" | "ffmpeg_h264" | "ffmpeg_hevc" | "ffmpeg_vvc" => TestAccelerationMode::Software,
        _ => TestAccelerationMode::Unknown,
    };
    let render_path = if matches!(transport_path, TestTransportPath::Webrtc)
        && (!render_display || renderer == "webview")
    {
        TestRenderPath::BrowserVideo
    } else if !render_display {
        TestRenderPath::None
    } else {
        match renderer {
            "d3d11" => TestRenderPath::NativeD3d11,
            "d3d12" => TestRenderPath::NativeD3d12,
            "opengl" => TestRenderPath::NativeOpengl,
            "macos" | "metal" => TestRenderPath::NativeMacos,
            "linux" => TestRenderPath::NativeLinux,
            "webview" => TestRenderPath::BrowserVideo,
            "webcodecs" => TestRenderPath::Webcodecs,
            _ => TestRenderPath::Unknown,
        }
    };

    TestClassification {
        run_scope,
        memory_path,
        encode_accel,
        decode_accel,
        transport_path,
        render_path,
        local_device: Some(TestDeviceDescriptor {
            device_id: None,
            device_name: Some("local".to_string()),
            platform: Some(environment.os_type.clone()),
            cpu: Some(environment.cpu_brand.clone()),
            gpu: Some(environment.gpu_info.clone()),
            service_build_id: None,
            protocol_version: None,
            media_protocol_version: None,
        }),
        peer_device,
    }
}

fn unknown_environment_snapshot() -> EnvironmentSnapshot {
    EnvironmentSnapshot {
        os_type: "unknown".to_string(),
        cpu_brand: "Unknown CPU".to_string(),
        cpu_cores: 0,
        memory_gb: 0,
        gpu_info: "Unknown GPU".to_string(),
        available_captures: Vec::new(),
        available_encoders: Vec::new(),
        available_decoders: Vec::new(),
        available_renderers: Vec::new(),
        available_memory_modes: Vec::new(),
    }
}

fn test_run_from_metadata(metadata: telemetry::TelemetryRunMetadata) -> TestRun {
    let config_snapshot = metadata
        .config_snapshot
        .and_then(|value| serde_json::from_value::<TestConfigData>(value).ok())
        .unwrap_or_default();
    let environment_snapshot = metadata
        .environment_snapshot
        .and_then(|value| serde_json::from_value::<EnvironmentSnapshot>(value).ok())
        .unwrap_or_else(unknown_environment_snapshot);
    let summary = metadata
        .summary
        .and_then(|value| serde_json::from_value::<TestRunSummary>(value).ok());
    let classification = metadata
        .classification
        .and_then(|value| serde_json::from_value::<TestClassification>(value).ok())
        .or_else(|| {
            Some(derive_test_classification(
                &config_snapshot,
                &environment_snapshot,
                if metadata.tags.iter().any(|tag| tag == "cross_device") {
                    TestRunScope::CrossDevice
                } else {
                    TestRunScope::Local
                },
                None,
            ))
        });
    let status = serde_json::from_str::<RunStatus>(&format!("\"{}\"", metadata.status))
        .unwrap_or(RunStatus::Failed);
    let run_mode = metadata
        .tags
        .iter()
        .find_map(|tag| serde_json::from_str::<RunMode>(&format!("\"{}\"", tag)).ok())
        .unwrap_or(RunMode::Manual);

    TestRun {
        run_id: metadata.run_id,
        scenario_id: metadata.scenario_id,
        run_mode,
        status,
        started_at: metadata.started_at,
        finished_at: metadata.finished_at,
        config_snapshot,
        environment_snapshot,
        summary,
        classification,
    }
}

fn run_metadata_from_test_run(run: &TestRun) -> telemetry::TelemetryRunMetadata {
    let mut tags = vec![serde_json::to_value(&run.run_mode)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "manual".to_string())];
    if matches!(
        run.classification
            .as_ref()
            .map(|classification| &classification.run_scope),
        Some(TestRunScope::CrossDevice)
    ) {
        tags.push("cross_device".to_string());
    }

    telemetry::TelemetryRunMetadata {
        run_id: run.run_id.clone(),
        scenario_id: run.scenario_id.clone(),
        status: serde_json::to_value(&run.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| format!("{:?}", run.status).to_ascii_lowercase()),
        started_at: run.started_at,
        finished_at: run.finished_at,
        tags,
        config_snapshot: serde_json::to_value(&run.config_snapshot).ok(),
        environment_snapshot: serde_json::to_value(&run.environment_snapshot).ok(),
        summary: run
            .summary
            .as_ref()
            .and_then(|summary| serde_json::to_value(summary).ok()),
        classification: run
            .classification
            .as_ref()
            .and_then(|classification| serde_json::to_value(classification).ok()),
    }
}

fn persist_run_to_store(store: &telemetry::TelemetryStore, run: &TestRun) {
    let _ = store.upsert_run(&run_metadata_from_test_run(run));
}

fn telemetry_event_from_stage_event(event: TestStageEvent) -> telemetry::TelemetryStageEvent {
    telemetry::TelemetryStageEvent {
        stage: event.stage,
        status: event.status,
        timestamp: event.timestamp,
        duration_ms: event.duration_ms,
        error: event.error,
    }
}

fn telemetry_artifact_from_artifact(artifact: Artifact) -> telemetry::TelemetryArtifactRecord {
    telemetry::TelemetryArtifactRecord {
        artifact_id: artifact.artifact_id,
        kind: artifact.kind,
        run_id: artifact.run_id,
        created_at: artifact.created_at,
        data: artifact.data,
        metadata: artifact
            .metadata
            .and_then(|metadata| serde_json::to_value(metadata).ok()),
    }
}

fn telemetry_series_from_metric_series(series: MetricSeries) -> telemetry::TelemetryMetricSeries {
    telemetry::TelemetryMetricSeries {
        metric_name: series.metric_name,
        unit: series.unit,
        samples: series
            .samples
            .into_iter()
            .map(|sample| telemetry::TelemetryMetricPoint {
                timestamp: sample.timestamp,
                value: sample.value,
            })
            .collect(),
        aggregation: series
            .aggregation
            .map(|aggregation| telemetry::TelemetryMetricAggregation {
                min: aggregation.min,
                max: aggregation.max,
                mean: aggregation.mean,
                p50: aggregation.p50,
                p95: aggregation.p95,
                p99: aggregation.p99,
            }),
        category: series.category,
        display_name: series.display_name,
        source: series.source,
    }
}

fn metric_metadata(
    metric_name: &str,
    unit: &str,
) -> (Option<String>, Option<String>, Option<String>) {
    let category = if metric_name.contains("fps") {
        "fps"
    } else if metric_name.contains("bitrate") || metric_name.contains("bytes") {
        "bitrate"
    } else if metric_name.contains("latency") || metric_name.contains("time") {
        "latency"
    } else if metric_name.contains("drop") || metric_name.contains("queue") {
        "drops_queue"
    } else if metric_name.contains("transport") {
        "transport"
    } else {
        match unit {
            "fps" => "fps",
            "ms" => "latency",
            "Mbps" | "mbps" | "bps" => "bitrate",
            _ => "other",
        }
    };
    let display_name = metric_name
        .trim_end_matches("_ms")
        .replace('_', " ")
        .split_whitespace()
        .map(|part| {
            if matches!(part, "fps" | "p50" | "p95" | "p99") {
                part.to_ascii_uppercase()
            } else {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    (
        Some(category.to_string()),
        Some(display_name),
        Some("test_orchestrator".to_string()),
    )
}

fn append_metric_to_store(
    store: &telemetry::TelemetryStore,
    run_id: &str,
    metric_name: &str,
    unit: &str,
    timestamp: u64,
    value: f64,
) {
    let (category, display_name, source) = metric_metadata(metric_name, unit);
    let _ = store.append_metric(&telemetry::TelemetryMetricSample {
        run_id: run_id.to_string(),
        metric_name: metric_name.to_string(),
        timestamp,
        value,
        unit: unit.to_string(),
        category,
        source,
        display_name,
    });
}

fn append_event_to_store(store: &telemetry::TelemetryStore, run_id: &str, event: &TestStageEvent) {
    let _ = store.append_event(run_id, &telemetry_event_from_stage_event(event.clone()));
}

fn restart_owned_harness(
    active_harness_run_id: &Arc<Mutex<Option<RunId>>>,
    harness: &Arc<Mutex<TestHarness>>,
    run_id: &str,
) -> Result<bool> {
    let owner = active_harness_run_id.lock().unwrap();
    if owner.as_deref() != Some(run_id) {
        return Ok(false);
    }
    harness.lock().unwrap().start_replacing_existing()?;
    Ok(true)
}

fn stop_owned_harness(
    active_harness_run_id: &Arc<Mutex<Option<RunId>>>,
    harness: &Arc<Mutex<TestHarness>>,
    run_id: &str,
) -> Option<HarnessMetrics> {
    let mut owner = active_harness_run_id.lock().unwrap();
    if owner.as_deref() != Some(run_id) {
        return None;
    }

    let mut harness = harness.lock().unwrap();
    harness.request_stop();
    let metrics = harness.get_metrics();
    let _ = harness.stop();
    *owner = None;
    Some(metrics)
}

fn release_harness_ownership(active_harness_run_id: &Arc<Mutex<Option<RunId>>>, run_id: &str) {
    let mut owner = active_harness_run_id.lock().unwrap();
    if owner.as_deref() == Some(run_id) {
        *owner = None;
    }
}

fn push_stage_event(
    events: &Arc<Mutex<HashMap<RunId, Vec<TestStageEvent>>>>,
    store: &telemetry::TelemetryStore,
    run_id: &str,
    event: TestStageEvent,
) {
    append_event_to_store(store, run_id, &event);
    events
        .lock()
        .unwrap()
        .entry(run_id.to_string())
        .or_insert_with(Vec::new)
        .push(event);
}

fn mark_run_failed(
    runs: &Arc<Mutex<HashMap<RunId, TestRun>>>,
    events: &Arc<Mutex<HashMap<RunId, Vec<TestStageEvent>>>>,
    store: &telemetry::TelemetryStore,
    run_id: &str,
    metrics: &HarnessMetrics,
    failure_reason: &str,
    error_message: String,
) {
    let mut should_record_event = false;

    {
        let mut runs = runs.lock().unwrap();
        if let Some(run) = runs.get_mut(run_id) {
            if run.status == RunStatus::Running {
                let mut summary = summary_from_metrics(run.started_at, metrics);
                summary.error_message = Some(error_message.clone());
                summary.failure_reason = Some(failure_reason.to_string());
                run.status = RunStatus::Failed;
                run.finished_at = Some(now_ms());
                run.summary = Some(summary);
                persist_run_to_store(store, run);
                should_record_event = true;
            }
        }
    }

    if should_record_event {
        push_stage_event(
            events,
            store,
            run_id,
            TestStageEvent {
                stage: "running".to_string(),
                status: "failed".to_string(),
                timestamp: now_ms(),
                duration_ms: None,
                error: Some(error_message),
            },
        );
    }
}

fn push_metric_sample(
    run_series: &mut HashMap<String, MetricSeries>,
    metric_name: &str,
    unit: &str,
    value: f64,
) -> u64 {
    let (category, display_name, source) = metric_metadata(metric_name, unit);
    let series = run_series
        .entry(metric_name.to_string())
        .or_insert_with(|| MetricSeries {
            metric_name: metric_name.to_string(),
            unit: unit.to_string(),
            samples: Vec::new(),
            aggregation: None,
            category,
            display_name,
            source,
        });

    let timestamp = now_ms();
    series.samples.push(MetricDataPoint { timestamp, value });
    series.aggregation = Some(compute_aggregation(&series.samples));
    timestamp
}

fn compute_aggregation(samples: &[MetricDataPoint]) -> MetricAggregation {
    if samples.is_empty() {
        return MetricAggregation {
            min: None,
            max: None,
            mean: None,
            p50: None,
            p95: None,
            p99: None,
        };
    }

    let mut values: Vec<f64> = samples.iter().map(|sample| sample.value).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sum: f64 = values.iter().sum();
    let last = values.len().saturating_sub(1);

    MetricAggregation {
        min: values.first().copied(),
        max: values.last().copied(),
        mean: Some(sum / values.len() as f64),
        p50: Some(values[values.len() / 2]),
        p95: Some(values[((values.len() * 95) / 100).min(last)]),
        p99: Some(values[((values.len() * 99) / 100).min(last)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_orchestrator_with_telemetry_store(name: &str) -> TestOrchestrator {
        let root = std::env::temp_dir().join(format!(
            "mrd-test-orchestrator-telemetry-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        TestOrchestrator::new_with_telemetry_store(
            Arc::new(Mutex::new(
                TestHarness::new().expect("failed to create test harness"),
            )),
            telemetry::TelemetryStore::new(root),
        )
    }

    fn test_env() -> EnvironmentSnapshot {
        EnvironmentSnapshot {
            os_type: "test".to_string(),
            cpu_brand: "test-cpu".to_string(),
            cpu_cores: 8,
            memory_gb: 16,
            gpu_info: "test-gpu".to_string(),
            available_captures: vec!["synthetic".to_string()],
            available_encoders: vec!["openh264".to_string()],
            available_decoders: vec!["software".to_string()],
            available_renderers: vec!["none".to_string()],
            available_memory_modes: vec!["cpu".to_string()],
        }
    }

    #[test]
    fn macos_videotoolbox_decoder_capability_aliases_are_codec_specific() {
        let mut h264_only = Vec::new();
        append_macos_videotoolbox_decoder_capabilities(&mut h264_only, true, false);
        assert_eq!(h264_only, vec!["videotoolbox_h264".to_string()]);

        let mut hevc_only = Vec::new();
        append_macos_videotoolbox_decoder_capabilities(&mut hevc_only, false, true);
        assert_eq!(hevc_only, vec!["videotoolbox_hevc".to_string()]);

        let mut both = Vec::new();
        append_macos_videotoolbox_decoder_capabilities(&mut both, true, true);
        assert_eq!(
            both,
            vec![
                "videotoolbox_h264".to_string(),
                "videotoolbox_hevc".to_string(),
                "videotoolbox".to_string(),
            ]
        );
    }

    #[test]
    fn macos_videotoolbox_decoder_support_follows_encoder_codec() {
        assert!(macos_videotoolbox_decoder_available_for_encoder_with(
            Some("videotoolbox_h264"),
            true,
            false
        ));
        assert!(macos_videotoolbox_decoder_available_for_encoder_with(
            None, true, false
        ));
        assert!(!macos_videotoolbox_decoder_available_for_encoder_with(
            Some("videotoolbox_hevc"),
            true,
            false
        ));
        assert!(macos_videotoolbox_decoder_available_for_encoder_with(
            Some("videotoolbox_hevc"),
            false,
            true
        ));
        assert!(macos_videotoolbox_decoder_available_for_encoder_with(
            Some("h265"),
            false,
            true
        ));
        assert!(macos_videotoolbox_decoder_available_for_encoder_with(
            Some("h.265"),
            false,
            true
        ));
    }

    #[test]
    fn macos_e2e_default_encoder_matches_dispatch_default() {
        assert_eq!(
            macos_e2e_encoder_type(&TestConfigData::default()),
            "videotoolbox_hevc"
        );
        assert_eq!(
            macos_e2e_encoder_type(&TestConfigData {
                encoder_type: Some("videotoolbox_h264".to_string()),
                ..Default::default()
            }),
            "videotoolbox_h264"
        );
    }

    #[test]
    fn macos_e2e_codec_aliases_map_to_videotoolbox_encoders() {
        for alias in ["hevc", "h265", "h.265"] {
            assert_eq!(
                macos_e2e_encoder_type(&TestConfigData {
                    encoder_type: Some(alias.to_string()),
                    ..Default::default()
                }),
                "videotoolbox_hevc"
            );
        }

        for alias in ["h264", "h.264"] {
            assert_eq!(
                macos_e2e_encoder_type(&TestConfigData {
                    encoder_type: Some(alias.to_string()),
                    ..Default::default()
                }),
                "videotoolbox_h264"
            );
        }
    }

    #[test]
    fn scenario_dispatch_rejects_unsupported_scenarios() {
        let orchestrator = TestOrchestrator::default();
        let error = orchestrator
            .scenario_to_chain("unknown.scenario", &TestConfigData::default())
            .unwrap_err();

        assert!(error.to_string().contains("Unsupported test scenario"));
    }

    #[test]
    fn derives_local_zero_copy_hardware_classification() {
        let classification = derive_test_classification(
            &TestConfigData {
                capture_type: Some("dxgi".to_string()),
                encoder_type: Some("nvenc_h264".to_string()),
                decoder_type: Some("nvdec".to_string()),
                renderer_type: Some("d3d11".to_string()),
                render_display: Some(true),
                zero_copy: Some(true),
                transport_kind: Some("loopback".to_string()),
                ..Default::default()
            },
            &test_env(),
            TestRunScope::Local,
            None,
        );

        assert_eq!(classification.run_scope, TestRunScope::Local);
        assert_eq!(
            classification.memory_path,
            TestMemoryPath::ZeroCopyD3d11Shared
        );
        assert_eq!(classification.encode_accel, TestAccelerationMode::Hardware);
        assert_eq!(classification.decode_accel, TestAccelerationMode::Hardware);
        assert_eq!(classification.render_path, TestRenderPath::NativeD3d11);
    }

    #[test]
    fn derives_browser_webrtc_classification() {
        let classification = derive_test_classification(
            &TestConfigData {
                capture_type: Some("dxgi".to_string()),
                encoder_type: Some("nvenc_h264".to_string()),
                decoder_type: Some("none".to_string()),
                render_display: Some(false),
                zero_copy: Some(false),
                transport_kind: Some("webrtc".to_string()),
                ..Default::default()
            },
            &test_env(),
            TestRunScope::Local,
            None,
        );

        assert_eq!(
            classification.memory_path,
            TestMemoryPath::WebrtcMediaStream
        );
        assert_eq!(classification.decode_accel, TestAccelerationMode::Browser);
        assert_eq!(classification.render_path, TestRenderPath::BrowserVideo);
    }

    #[test]
    fn derives_ffmpeg_decode_as_software_classification() {
        for decoder in ["ffmpeg_h264", "ffmpeg_hevc"] {
            let classification = derive_test_classification(
                &TestConfigData {
                    capture_type: Some("dxgi".to_string()),
                    encoder_type: Some("nvenc_h264".to_string()),
                    decoder_type: Some(decoder.to_string()),
                    renderer_type: Some("d3d11".to_string()),
                    render_display: Some(true),
                    transport_kind: Some("loopback".to_string()),
                    ..Default::default()
                },
                &test_env(),
                TestRunScope::Local,
                None,
            );

            assert_eq!(classification.decode_accel, TestAccelerationMode::Software);
        }
    }

    #[test]
    fn matrix_synthetic_smoke_run_completes_without_platform_capture() {
        let orchestrator = TestOrchestrator::default();
        let run_id = orchestrator
            .start_run(
                "matrix".to_string(),
                TestConfigData {
                    capture_type: Some("synthetic".to_string()),
                    encoder_type: Some("openh264".to_string()),
                    decoder_type: Some("none".to_string()),
                    transport_kind: Some("loopback".to_string()),
                    resolution: Some([64, 64]),
                    fps: Some(30),
                    bitrate: Some(1_000_000),
                    duration_ms: Some(250),
                    warmup_ms: Some(0),
                    visual_preview: Some(false),
                    ..Default::default()
                },
            )
            .expect("start synthetic matrix smoke run");

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let run = loop {
            let run = orchestrator
                .get_run(&run_id)
                .expect("synthetic matrix run should exist");
            if !matches!(run.status, RunStatus::Running) {
                break run;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "synthetic matrix smoke run timed out"
            );
            thread::sleep(Duration::from_millis(50));
        };

        assert_eq!(run.status, RunStatus::Completed);
        let summary = run.summary.expect("completed run should include summary");
        assert!(summary.frame_count > 0);
        assert!(summary.capture_fps.unwrap_or_default() > 0.0);
    }

    #[test]
    fn summary_from_metrics_exposes_receiver_and_render_pacing_metrics() {
        let metrics = HarnessMetrics {
            capture_fps: 144.0,
            decoded_fps: 118.0,
            decoded_frames: 1_180,
            render_presented_frames: 1_170,
            render_present_skipped_frames: 3,
            render_present_gap_p95_ms: 7.4,
            ..HarnessMetrics::default()
        };

        let summary = summary_from_metrics(now_ms(), &metrics);

        assert_eq!(summary.capture_fps, Some(144.0));
        assert_eq!(summary.observed_fps, Some(118.0));
        assert_eq!(summary.decoded_fps, Some(118.0));
        assert_eq!(summary.decoded_frames, 1_180);
        assert_eq!(summary.render_presented_frames, 1_170);
        assert_eq!(summary.render_present_skipped_frames, 3);
        assert_eq!(summary.render_present_gap_p95_ms, Some(7.4));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn list_scenarios_includes_single_window_local_probe() {
        let orchestrator = TestOrchestrator::default();
        let scenario = orchestrator
            .list_scenarios()
            .into_iter()
            .find(|scenario| scenario.scenario_id == "single_window.local")
            .expect("single window probe scenario should be registered");

        assert_eq!(scenario.scenario_kind, ScenarioKind::E2eLocal);
        assert!(!scenario.supports_matrix);
        let expected_capture = if cfg!(target_os = "macos") {
            "macos"
        } else {
            "winrt"
        };
        let expected_scope = if cfg!(target_os = "macos") {
            "screencapturekit_window"
        } else {
            "winrt"
        };
        assert_eq!(
            scenario.default_config.capture_type.as_deref(),
            Some(expected_capture)
        );
        assert_eq!(
            scenario.default_config.input_source.as_deref(),
            Some("window")
        );
        assert_eq!(
            scenario.default_config.transport_kind.as_deref(),
            Some("webrtc")
        );
        assert!(scenario
            .component_scope
            .iter()
            .any(|scope| scope == expected_scope));
        assert!(scenario
            .component_scope
            .iter()
            .any(|scope| scope == "webrtc"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn list_scenarios_uses_macos_platform_entries() {
        let scenarios = TestOrchestrator::default().list_scenarios();

        assert!(scenarios
            .iter()
            .any(|scenario| scenario.scenario_id == "capture.macos"));
        assert!(scenarios
            .iter()
            .any(|scenario| scenario.scenario_id == "e2e.macos_local"));
        assert_eq!(
            scenarios
                .iter()
                .any(|scenario| scenario.scenario_id == "encode.videotoolbox_h264"),
            macos_videotoolbox_h264_encoder_available()
        );
        assert_eq!(
            scenarios
                .iter()
                .any(|scenario| scenario.scenario_id == "encode.videotoolbox_hevc"),
            macos_videotoolbox_hevc_encoder_available()
        );
        assert_eq!(
            scenarios
                .iter()
                .any(|scenario| scenario.scenario_id == "decode.videotoolbox_h264"),
            macos_videotoolbox_h264_decoder_available()
        );
        assert_eq!(
            scenarios
                .iter()
                .any(|scenario| scenario.scenario_id == "decode.videotoolbox_hevc"),
            macos_videotoolbox_hevc_decoder_available()
        );
        assert!(!scenarios
            .iter()
            .any(|scenario| scenario.scenario_id == "capture.dxgi"));
        assert!(!scenarios
            .iter()
            .any(|scenario| scenario.scenario_id == "e2e.local"));
    }

    #[test]
    fn parse_hwnd_accepts_hex_and_decimal() {
        assert_eq!(parse_hwnd("0x2A").unwrap(), 42);
        assert_eq!(parse_hwnd("42").unwrap(), 42);
    }

    #[test]
    fn renderer_target_hwnd_accepts_string_and_number_json() {
        let from_string: TestConfigData =
            serde_json::from_str(r#"{"renderer_target_hwnd":"0x2A"}"#).unwrap();
        let from_number: TestConfigData =
            serde_json::from_str(r#"{"renderer_target_hwnd":42}"#).unwrap();

        assert_eq!(from_string.renderer_target_hwnd, Some(42));
        assert_eq!(from_number.renderer_target_hwnd, Some(42));
    }

    #[test]
    fn harness_config_preserves_source_id() {
        let config = TestConfigData {
            source_id: Some("windows:display-shared:1".to_string()),
            ..Default::default()
        };

        let harness = harness_config_from_data(&config);

        assert_eq!(
            harness.source_id.as_deref(),
            Some("windows:display-shared:1")
        );
        assert_eq!(
            harness.display_id.as_deref(),
            Some("windows:display-shared:1")
        );
    }

    fn synthetic_hevc_access_unit() -> EncodedAccessUnit {
        EncodedAccessUnit {
            codec: mrd_pipeline_core::VideoCodec::Hevc,
            timestamp_us: 42_000,
            is_keyframe: true,
            bytes: vec![
                0, 0, 0, 1, 0x40, 0x01, 0xaa, 0, 0, 0, 1, 0x42, 0x01, 0xbb, 0, 0, 0, 1, 0x44, 0x01,
                0xc0, 0, 0, 0, 1, 0x26, 0x01, 0xcc, 0xdd,
            ],
        }
    }

    #[test]
    fn single_window_hevc_webrtc_transport_roundtrips_access_units() {
        let input = synthetic_hevc_access_unit();
        let config = TestConfigData {
            transport_kind: Some("webrtc".to_string()),
            ..Default::default()
        };

        let probe = TestOrchestrator::transport_single_window_access_units(
            std::slice::from_ref(&input),
            60,
            &config,
        )
        .expect("HEVC single-window WebRTC loopback");

        assert_eq!(probe.transport, "webrtc_rtp_loopback");
        assert_eq!(probe.rtp_packet_count, 2);
        assert_eq!(probe.access_units.len(), 1);
        assert_eq!(probe.access_units[0].codec, input.codec);
        assert_eq!(probe.access_units[0].timestamp_us, input.timestamp_us);
        assert_eq!(probe.access_units[0].bytes, input.bytes);
        assert!(probe.access_units[0].is_keyframe);
    }

    #[test]
    fn matrix_dispatch_maps_explicit_encoder_decoder_pairs() {
        let orchestrator = TestOrchestrator::default();
        let openh264_config = TestConfigData {
            capture_type: Some("synthetic".to_string()),
            encoder_type: Some("openh264".to_string()),
            decoder_type: Some("software".to_string()),
            ..Default::default()
        };

        assert_eq!(
            orchestrator
                .scenario_to_chain("matrix", &openh264_config)
                .unwrap(),
            TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::OpenH264,
                decoder: DecoderType::Software,
            }
        );

        let software_h264_config = TestConfigData {
            capture_type: Some("synthetic".to_string()),
            encoder_type: Some("software_h264".to_string()),
            decoder_type: Some("h264_software".to_string()),
            ..Default::default()
        };

        assert_eq!(
            orchestrator
                .scenario_to_chain("matrix", &software_h264_config)
                .unwrap(),
            TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::OpenH264,
                decoder: DecoderType::Software,
            }
        );

        let ffmpeg_h264_config = TestConfigData {
            capture_type: Some("synthetic".to_string()),
            encoder_type: Some("openh264".to_string()),
            decoder_type: Some("ffmpeg_h264".to_string()),
            ..Default::default()
        };

        assert!(
            orchestrator
                .scenario_to_chain("matrix", &ffmpeg_h264_config)
                .is_ok(),
            "matrix should accept FFmpeg H.264 decoder"
        );

        let ffmpeg_hevc_config = TestConfigData {
            capture_type: Some("synthetic".to_string()),
            encoder_type: Some(
                if cfg!(target_os = "macos") {
                    "videotoolbox_hevc"
                } else {
                    "nvenc_hevc"
                }
                .to_string(),
            ),
            decoder_type: Some("ffmpeg_hevc".to_string()),
            ..Default::default()
        };

        assert!(
            orchestrator
                .scenario_to_chain("matrix", &ffmpeg_hevc_config)
                .is_ok(),
            "matrix should accept FFmpeg HEVC decoder"
        );

        #[cfg(windows)]
        {
            let nvenc_decode_config = TestConfigData {
                capture_type: Some("dxgi".to_string()),
                encoder_type: Some("nvenc_h264".to_string()),
                decoder_type: Some("nvdec".to_string()),
                ..Default::default()
            };
            let nvenc_encode_config = TestConfigData {
                capture_type: Some("dxgi".to_string()),
                encoder_type: Some("nvenc_h264".to_string()),
                decoder_type: Some("software".to_string()),
                ..Default::default()
            };

            assert_eq!(
                orchestrator
                    .scenario_to_chain("matrix", &nvenc_decode_config)
                    .unwrap(),
                TestChain::Custom {
                    capture: CaptureType::Dxgi,
                    encoder: EncoderType::NvencH264,
                    decoder: DecoderType::Nvdec,
                }
            );
            assert_eq!(
                orchestrator
                    .scenario_to_chain("matrix", &nvenc_encode_config)
                    .unwrap(),
                TestChain::Custom {
                    capture: CaptureType::Dxgi,
                    encoder: EncoderType::NvencH264,
                    decoder: DecoderType::Software,
                }
            );
        }

        #[cfg(target_os = "macos")]
        {
            let videotoolbox_config = TestConfigData {
                capture_type: Some("macos".to_string()),
                encoder_type: Some("videotoolbox_h264".to_string()),
                decoder_type: Some("software".to_string()),
                ..Default::default()
            };

            assert_eq!(
                orchestrator
                    .scenario_to_chain("matrix", &videotoolbox_config)
                    .unwrap(),
                TestChain::Custom {
                    capture: CaptureType::Macos,
                    encoder: EncoderType::VideoToolboxH264,
                    decoder: DecoderType::Software,
                }
            );

            let videotoolbox_hevc_config = TestConfigData {
                capture_type: Some("macos".to_string()),
                encoder_type: Some("videotoolbox_hevc".to_string()),
                decoder_type: Some("videotoolbox".to_string()),
                ..Default::default()
            };

            assert_eq!(
                orchestrator
                    .scenario_to_chain("matrix", &videotoolbox_hevc_config)
                    .unwrap(),
                TestChain::Custom {
                    capture: CaptureType::Macos,
                    encoder: EncoderType::VideoToolboxHevc,
                    decoder: DecoderType::VideoToolbox,
                }
            );
        }

        #[cfg(target_os = "linux")]
        {
            let linux_hw_config = TestConfigData {
                capture_type: Some("linux".to_string()),
                encoder_type: Some("nvenc_h264".to_string()),
                decoder_type: Some("linux_h264".to_string()),
                ..Default::default()
            };

            assert_eq!(
                orchestrator
                    .scenario_to_chain("e2e.linux_local", &linux_hw_config)
                    .unwrap(),
                TestChain::Custom {
                    capture: CaptureType::Linux,
                    encoder: EncoderType::NvencH264,
                    decoder: DecoderType::LinuxH264,
                }
            );
            assert_eq!(
                orchestrator
                    .scenario_to_chain("decode.linux_h264", &TestConfigData::default())
                    .unwrap(),
                TestChain::Custom {
                    capture: CaptureType::Synthetic,
                    encoder: EncoderType::NvencH264,
                    decoder: DecoderType::LinuxH264,
                }
            );
        }
    }

    #[test]
    fn harness_config_requires_explicit_render_display_for_d3d11() {
        let legacy_config = TestConfigData {
            renderer_type: Some("d3d11".to_string()),
            ..Default::default()
        };
        let disabled_config = TestConfigData {
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(false),
            ..Default::default()
        };
        let enabled_config = TestConfigData {
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(true),
            ..Default::default()
        };

        assert_eq!(harness_config_from_data(&legacy_config).renderer, None);
        assert_eq!(harness_config_from_data(&disabled_config).renderer, None);
        assert_eq!(
            harness_config_from_data(&enabled_config).renderer,
            Some(RendererType::D3d11)
        );
    }

    #[test]
    fn harness_config_requires_explicit_render_display_for_macos_metal() {
        let legacy_config = TestConfigData {
            renderer_type: Some("macos".to_string()),
            ..Default::default()
        };
        let metal_config = TestConfigData {
            renderer_type: Some("metal".to_string()),
            render_display: Some(true),
            ..Default::default()
        };
        let macos_config = TestConfigData {
            renderer_type: Some("macos".to_string()),
            render_display: Some(true),
            ..Default::default()
        };

        assert_eq!(harness_config_from_data(&legacy_config).renderer, None);
        assert_eq!(
            harness_config_from_data(&metal_config).renderer,
            Some(RendererType::Macos)
        );
        assert_eq!(
            harness_config_from_data(&macos_config).renderer,
            Some(RendererType::Macos)
        );
    }

    #[test]
    fn harness_config_requires_explicit_render_display_for_opengl() {
        let legacy_config = TestConfigData {
            renderer_type: Some("opengl".to_string()),
            ..Default::default()
        };
        let enabled_config = TestConfigData {
            renderer_type: Some("opengl".to_string()),
            render_display: Some(true),
            ..Default::default()
        };

        assert_eq!(harness_config_from_data(&legacy_config).renderer, None);
        assert_eq!(
            harness_config_from_data(&enabled_config).renderer,
            Some(RendererType::Opengl)
        );
    }

    #[test]
    fn harness_config_passes_d3d11_renderer_target_hwnd() {
        let config = TestConfigData {
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(true),
            renderer_target_hwnd: Some(1234),
            ..Default::default()
        };
        let harness_config = harness_config_from_data(&config);

        assert_eq!(harness_config.renderer, Some(RendererType::D3d11));
        assert_eq!(harness_config.renderer_target_hwnd, Some(1234));
    }

    #[test]
    fn harness_config_passes_zero_copy_flag() {
        let enabled_config = TestConfigData {
            zero_copy: Some(true),
            ..Default::default()
        };
        let disabled_config = TestConfigData {
            zero_copy: Some(false),
            ..Default::default()
        };

        assert_eq!(
            harness_config_from_data(&enabled_config).zero_copy,
            Some(true)
        );
        assert_eq!(
            harness_config_from_data(&disabled_config).zero_copy,
            Some(false)
        );
    }

    #[test]
    fn harness_config_passes_color_mode_and_pipeline() {
        let config = TestConfigData {
            color_mode: Some(ColorMode::Monochrome),
            color_pipeline: Some(ColorPipeline::HdrMain10),
            ..Default::default()
        };
        let harness_config = harness_config_from_data(&config);

        assert_eq!(harness_config.color_mode, Some(ColorMode::Monochrome));
        assert_eq!(
            harness_config.color_pipeline,
            Some(ColorPipeline::HdrMain10)
        );
    }

    #[test]
    fn harness_config_passes_visual_preview_flag() {
        let config = TestConfigData {
            visual_preview: Some(false),
            ..Default::default()
        };

        assert_eq!(
            harness_config_from_data(&config).visual_preview,
            Some(false)
        );
    }

    #[cfg(windows)]
    #[test]
    fn validate_custom_matrix_allows_opengl_with_cpu_memory() {
        let config = TestConfigData {
            capture_type: Some("synthetic".to_string()),
            encoder_type: Some("openh264".to_string()),
            decoder_type: Some("software".to_string()),
            renderer_type: Some("opengl".to_string()),
            render_display: Some(true),
            zero_copy: Some(false),
            ..Default::default()
        };

        validate_scenario_for_current_platform("matrix", &config)
            .expect("OpenGL CPU-backed matrix run should be supported");
    }

    #[cfg(windows)]
    #[test]
    fn validate_custom_matrix_allows_opengl_with_d3d11_shared_hybrid_memory() {
        let config = TestConfigData {
            capture_type: Some("dxgi".to_string()),
            encoder_type: Some("nvenc_h264".to_string()),
            decoder_type: Some("nvdec".to_string()),
            renderer_type: Some("opengl".to_string()),
            render_display: Some(true),
            zero_copy: Some(true),
            ..Default::default()
        };

        validate_scenario_for_current_platform("matrix", &config)
            .expect("OpenGL hybrid should accept D3D11 shared texture memory");
    }

    #[test]
    fn stop_run_marks_and_persists_run_as_cancelled() {
        let orchestrator = test_orchestrator_with_telemetry_store("stop-run-persists");
        let run_id = "run-stop-smoke".to_string();
        let started_at = now_ms();
        orchestrator.runs.lock().unwrap().insert(
            run_id.clone(),
            TestRun {
                run_id: run_id.clone(),
                scenario_id: "custom".to_string(),
                run_mode: RunMode::Manual,
                status: RunStatus::Running,
                started_at,
                finished_at: None,
                config_snapshot: TestConfigData::default(),
                environment_snapshot: test_env(),
                summary: None,
                classification: None,
            },
        );
        *orchestrator.active_harness_run_id.lock().unwrap() = Some(run_id.clone());
        orchestrator.persist_run_by_id(&run_id);

        orchestrator.stop_run(&run_id).expect("stop run");

        let run = orchestrator
            .runs
            .lock()
            .unwrap()
            .get(&run_id)
            .cloned()
            .expect("run should remain recorded");
        assert_eq!(run.status, RunStatus::Cancelled);
        assert!(run.finished_at.is_some());
        assert!(run.summary.is_some());
        assert_eq!(
            orchestrator
                .active_harness_run_id
                .lock()
                .unwrap()
                .as_deref(),
            None
        );
        assert!(orchestrator
            .run_events
            .lock()
            .unwrap()
            .get(&run_id)
            .is_some_and(|events| events.iter().any(|event| event.status == "cancelled")));
        let persisted = orchestrator
            .telemetry_store
            .list_runs(None)
            .expect("list persisted runs")
            .into_iter()
            .find(|run| run.run_id == run_id)
            .expect("persisted cancelled run");
        assert_eq!(persisted.status, "cancelled");
    }

    #[test]
    fn skipped_status_round_trips_and_filters() {
        let orchestrator = test_orchestrator_with_telemetry_store("skipped-status");
        let run_id = "run-skipped".to_string();
        orchestrator
            .record_external_run(ExternalTestRunRecord {
                run_id: Some(run_id.clone()),
                scenario_id: "cross.e2e.remote_display_smoke".to_string(),
                run_mode: Some(RunMode::Matrix),
                status: RunStatus::Skipped,
                started_at: now_ms(),
                finished_at: Some(now_ms()),
                config_snapshot: TestConfigData::default(),
                environment_snapshot: Some(test_env()),
                summary: None,
                classification: None,
                events: Vec::new(),
                artifacts: Vec::new(),
            })
            .expect("record skipped run");

        let runs = orchestrator.list_runs(None, Some("skipped".to_string()), None);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].status, RunStatus::Skipped);
        assert!(orchestrator
            .list_runs(None, Some("not-a-status".to_string()), None)
            .is_empty());
    }

    #[test]
    fn generated_run_ids_are_unique_even_within_one_millisecond() {
        let first = generate_run_id();
        let second = generate_run_id();
        assert_ne!(first, second);
    }

    #[test]
    fn execution_config_rejects_silent_noop_options() {
        let adaptive = TestConfigData {
            adaptive_media: Some(true),
            ..Default::default()
        };
        assert!(validate_execution_config(&adaptive)
            .expect_err("local adaptive media should be rejected")
            .to_string()
            .contains("cross-device"));

        let repeated = TestConfigData {
            repeat_count: Some(2),
            ..Default::default()
        };
        assert!(validate_execution_config(&repeated)
            .expect_err("repeat count should be explicit")
            .to_string()
            .contains("repeat_count"));
    }

    #[cfg(windows)]
    #[test]
    fn render_probe_scenarios_are_registered_on_windows() {
        let scenarios = TestOrchestrator::default().list_scenarios();

        assert!(scenarios
            .iter()
            .any(|scenario| scenario.scenario_id == "render.d3d12"));
        assert_eq!(
            scenarios
                .iter()
                .find(|scenario| scenario.scenario_id == "render.d3d12")
                .expect("render.d3d12 scenario")
                .default_config
                .render_display,
            Some(true)
        );
        assert!(scenarios
            .iter()
            .any(|scenario| scenario.scenario_id == "render.opengl"));
        assert_eq!(
            scenarios
                .iter()
                .find(|scenario| scenario.scenario_id == "render.opengl")
                .expect("render.opengl scenario")
                .default_config
                .render_display,
            Some(true)
        );
        assert!(current_platform_renderers().contains(&"d3d12"));
        assert!(current_platform_renderers().contains(&"opengl"));
        assert!(current_platform_renderers().contains(&"webview"));
    }

    #[cfg(windows)]
    #[test]
    fn custom_harness_rejects_independent_render_probe_backends() {
        let config = TestConfigData {
            capture_type: Some("synthetic".to_string()),
            encoder_type: Some("none".to_string()),
            decoder_type: Some("none".to_string()),
            renderer_type: Some("d3d12".to_string()),
            render_display: Some(false),
            ..Default::default()
        };

        let error = validate_scenario_for_current_platform("custom", &config).unwrap_err();
        assert!(error.to_string().contains("render.probe"));
    }

    #[cfg(windows)]
    #[test]
    fn capture_dxgi_defaults_to_unthrottled_zero_copy_perf_mode() {
        let scenario = TestOrchestrator::default()
            .list_scenarios()
            .into_iter()
            .find(|scenario| scenario.scenario_id == "capture.dxgi")
            .expect("capture.dxgi scenario");

        assert_eq!(
            scenario.default_config.encoder_type.as_deref(),
            Some("none")
        );
        assert_eq!(
            scenario.default_config.decoder_type.as_deref(),
            Some("none")
        );
        assert_eq!(scenario.default_config.zero_copy, Some(true));
        assert_eq!(scenario.default_config.visual_preview, Some(false));
    }

    #[cfg(windows)]
    #[test]
    fn capture_winrt_defaults_to_screen_perf_mode() {
        let scenario = TestOrchestrator::default()
            .list_scenarios()
            .into_iter()
            .find(|scenario| scenario.scenario_id == "capture.winrt")
            .expect("capture.winrt scenario");

        assert_eq!(
            scenario.default_config.capture_type.as_deref(),
            Some("winrt")
        );
        assert_eq!(
            scenario.default_config.encoder_type.as_deref(),
            Some("none")
        );
        assert_eq!(
            scenario.default_config.decoder_type.as_deref(),
            Some("none")
        );
        assert_eq!(scenario.default_config.zero_copy, Some(true));
        assert_eq!(scenario.default_config.visual_preview, Some(false));
    }

    #[cfg(windows)]
    #[test]
    fn zero_copy_validation_allows_nvenc_av1_shared_input() {
        let config = TestConfigData {
            capture_type: Some("dxgi".to_string()),
            encoder_type: Some("nvenc_av1".to_string()),
            decoder_type: Some("nvdec".to_string()),
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(true),
            zero_copy: Some(true),
            ..Default::default()
        };

        validate_scenario_for_current_platform("matrix", &config)
            .expect("NVENC AV1 should accept D3D11 shared input");
    }

    #[cfg(windows)]
    #[test]
    fn color_validation_rejects_nvenc_av1_non_full_color_mode() {
        let config = TestConfigData {
            capture_type: Some("dxgi".to_string()),
            encoder_type: Some("nvenc_av1".to_string()),
            decoder_type: Some("nvdec".to_string()),
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(true),
            zero_copy: Some(true),
            color_mode: Some(ColorMode::Grayscale),
            ..Default::default()
        };

        let error = validate_scenario_for_current_platform("matrix", &config)
            .expect_err("NVENC AV1 should not accept non-full GPU color modes yet");

        assert!(error.to_string().contains("NVENC AV1"));
    }

    #[cfg(windows)]
    #[test]
    fn color_validation_rejects_hdr_main10_without_hevc_main10() {
        let config = TestConfigData {
            capture_type: Some("dxgi".to_string()),
            encoder_type: Some("nvenc_h264".to_string()),
            decoder_type: Some("nvdec".to_string()),
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(true),
            zero_copy: Some(true),
            color_pipeline: Some(ColorPipeline::HdrMain10),
            ..Default::default()
        };

        let error = validate_scenario_for_current_platform("matrix", &config)
            .expect_err("HDR Main10 should require NVENC HEVC Main10");

        assert!(error.to_string().contains("HEVC Main10"));
    }

    #[cfg(windows)]
    #[test]
    fn zero_copy_validation_allows_direct_capture_render() {
        let config = TestConfigData {
            capture_type: Some("dxgi".to_string()),
            encoder_type: Some("none".to_string()),
            decoder_type: Some("none".to_string()),
            renderer_type: Some("d3d11".to_string()),
            render_display: Some(true),
            zero_copy: Some(true),
            ..Default::default()
        };

        validate_scenario_for_current_platform("matrix", &config)
            .expect("direct capture to D3D11 render should accept D3D11 shared input");
    }

    #[cfg(windows)]
    #[test]
    fn e2e_local_defaults_to_d3d11_zero_copy_display() {
        let scenario = TestOrchestrator::default()
            .list_scenarios()
            .into_iter()
            .find(|scenario| scenario.scenario_id == "e2e.local")
            .expect("e2e.local scenario");

        assert_eq!(
            scenario.default_config.renderer_type.as_deref(),
            Some("d3d11")
        );
        assert_eq!(scenario.default_config.render_display, Some(true));
        assert_eq!(scenario.default_config.zero_copy, Some(true));
    }

    #[test]
    fn runtime_harness_error_marks_run_failed() {
        let orchestrator = test_orchestrator_with_telemetry_store("runtime-error");
        let run_id = "run_runtime_error".to_string();
        let started_at = now_ms();

        orchestrator.runs.lock().unwrap().insert(
            run_id.clone(),
            TestRun {
                run_id: run_id.clone(),
                scenario_id: "encode.openh264".to_string(),
                run_mode: RunMode::Manual,
                status: RunStatus::Running,
                started_at,
                finished_at: None,
                config_snapshot: TestConfigData::default(),
                environment_snapshot: test_env(),
                summary: None,
                classification: None,
            },
        );

        let metrics = HarnessMetrics {
            is_running: false,
            frame_count: 12,
            error_message: Some("gpu unavailable".to_string()),
            ..Default::default()
        };

        mark_run_failed(
            &orchestrator.runs,
            &orchestrator.run_events,
            &orchestrator.telemetry_store,
            &run_id,
            &metrics,
            "runtime_failure",
            "gpu unavailable".to_string(),
        );

        let run = orchestrator.get_run(&run_id).unwrap();
        let summary = run.summary.unwrap();
        assert_eq!(run.status, RunStatus::Failed);
        assert_eq!(summary.frame_count, 12);
        assert_eq!(summary.error_message.as_deref(), Some("gpu unavailable"));
        assert_eq!(summary.failure_reason.as_deref(), Some("runtime_failure"));

        let events = orchestrator.get_run_events(&run_id);
        assert!(events
            .iter()
            .any(|event| { event.stage == "running" && event.status == "failed" }));

        let telemetry = orchestrator
            .get_run_telemetry(&run_id, telemetry::TelemetryQuery::default())
            .expect("telemetry bundle");
        assert_eq!(telemetry.run.unwrap().status, "failed");
        assert!(telemetry
            .events
            .iter()
            .any(|event| event.stage == "running" && event.status == "failed"));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    #[ignore = "manual smoke test: requires a visible capturable window and screen capture access"]
    fn single_window_local_probe_smoke() {
        let targets = list_window_capture_targets().expect("failed to list capture targets");
        let target = targets
            .into_iter()
            .find(|target| {
                target.width >= 32 && target.height >= 32 && !target.title.trim().is_empty()
            })
            .expect("no visible capture target found");

        println!(
            "capturing hwnd={} title={:?} size={}x{} pid={}",
            target.hwnd, target.title, target.width, target.height, target.process_id
        );

        let orchestrator = TestOrchestrator::default();
        let capture_type = if cfg!(target_os = "macos") {
            "macos"
        } else {
            "winrt"
        };
        let renderer_type = if cfg!(target_os = "macos") {
            "macos"
        } else {
            "d3d11"
        };
        let run_id = orchestrator
            .start_run(
                "single_window.local".to_string(),
                TestConfigData {
                    capture_type: Some(capture_type.to_string()),
                    input_source: Some("window".to_string()),
                    window_hwnd: Some(target.hwnd.clone()),
                    window_title: Some(target.title.clone()),
                    encoder_type: Some("openh264".to_string()),
                    decoder_type: Some("software".to_string()),
                    renderer_type: Some(renderer_type.to_string()),
                    transport_kind: Some("webrtc".to_string()),
                    duration_ms: Some(1_000),
                    fps: Some(30),
                    ..Default::default()
                },
            )
            .expect("failed to start single-window probe");

        let run = orchestrator
            .get_run(&run_id)
            .expect("probe run should be recorded");
        println!(
            "run status={:?} summary={}",
            run.status,
            serde_json::to_string_pretty(&run.summary).unwrap()
        );

        let events = orchestrator.get_run_events(&run_id);
        println!("events={}", serde_json::to_string_pretty(&events).unwrap());

        let artifacts = orchestrator.get_run_artifacts(&run_id);
        for artifact in &artifacts {
            println!(
                "artifact kind={} metadata={}",
                artifact.kind,
                serde_json::to_string_pretty(&artifact.metadata).unwrap()
            );
            if artifact.kind == "structured_log" {
                println!("{}", artifact.data);
            }
        }

        assert_eq!(run.status, RunStatus::Completed);
        assert!(artifacts
            .iter()
            .any(|artifact| artifact.kind == "structured_log"
                && artifact
                    .data
                    .contains("\"transport\": \"webrtc_rtp_loopback\"")
                && artifact.data.contains("\"rendered_frame_count\"")));
    }
}
