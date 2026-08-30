//! Test harness for end-to-end pipeline visualization
//!
//! This module provides a test harness that runs the full capture→encode→decode
//! pipeline locally for visualization and testing purposes.

#![allow(
    clippy::derivable_impls,
    clippy::large_enum_variant,
    clippy::needless_return,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::while_let_loop
)]

use anyhow::Result;
use mrd_capture_dxgi::DxgiDesktopCapture;
#[cfg(windows)]
use mrd_capture_dxgi::DxgiSharedTextureCapture;
#[cfg(target_os = "macos")]
use mrd_capture_macos::MacosScreenCapture;
#[cfg(target_os = "linux")]
use mrd_capture_pipewire::PipewireScreenCapture;
#[cfg(windows)]
use mrd_capture_winrt::WinrtCapture;
#[cfg(target_os = "macos")]
use mrd_codec_videotoolbox::{
    VideoToolboxH264Decoder, VideoToolboxH264Encoder, VideoToolboxHevcDecoder,
    VideoToolboxHevcEncoder,
};
use mrd_decode_nvdec::{NvdecDecoder, NvdecOutputMode};
use mrd_encode_nvenc::{NvencH264Encoder, NvencHevcEncoder};
#[cfg(any(windows, target_os = "linux"))]
use mrd_encode_nvenc_av1::NvencAv1Encoder;
use mrd_encode_openh264::OpenH264Encoder;
use mrd_encode_vvenc::VvencSoftwareEncoder;
use mrd_observability::PipelineComparisonResult;
use mrd_pipeline_core::{
    CapturedFrame, ColorMode, ColorPipeline, DecodedFrame, DecodedFrameData, EncodedAccessUnit,
    FrameCapture, FramePixelFormat, PipelineError, VideoCodec, VideoDecoder, VideoEncoder,
};
use mrd_render::{
    RenderFrame, RenderFrameData, RenderPixelFormat, RenderTarget, RendererFactory,
    RendererInstance, RendererSnapshot,
};
#[cfg(target_os = "macos")]
use mrd_render_macos::MacosRendererFactory;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const WEB_PREVIEW_MAX_WIDTH: usize = 640;
const WEB_PREVIEW_FRAME_UPDATE_INTERVAL: usize = 8;
const ENCODED_ACCESS_UNIT_SUBSCRIBER_QUEUE_DEPTH: usize = 1;
const NATIVE_RENDER_FRAME_TIMEOUT_MS: u64 = 2_000;
const NATIVE_RENDER_THREAD_STOP_TIMEOUT_MS: u64 = 750;
const HARNESS_STOP_JOIN_TIMEOUT_MS: u64 = 10_000;
#[cfg(target_os = "linux")]
const DEFAULT_LINUX_CAPTURE_START_TIMEOUT_MS: u64 = 30_000;
const CAPTURE_NO_FRAME_TIMEOUT_MS: u64 = 2_500;

/// Test chain configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestChain {
    /// DXGI capture only, no encode/decode
    #[serde(rename = "capture_only")]
    CaptureOnly,

    /// DXGI capture + NVENC encode + NVDEC decode (fastest, full hardware)
    #[serde(rename = "nvenc_nvdec")]
    NvencNvdec,

    /// DXGI capture + NVENC encode (encode-only test)
    #[serde(rename = "nvenc_only")]
    NvencOnly,

    /// DXGI capture + OpenH264 encode (software encode test)
    #[serde(rename = "openh264")]
    OpenH264,

    /// Linux capture + OpenH264 encode (Linux test)
    #[cfg(target_os = "linux")]
    #[serde(rename = "linux_openh264")]
    LinuxOpenh264,

    /// Custom configuration with explicit parameters
    #[serde(rename = "custom")]
    Custom {
        capture: CaptureType,
        encoder: EncoderType,
        decoder: DecoderType,
    },
}

/// Available capture types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureType {
    Dxgi,
    Winrt,
    Macos,
    #[cfg(target_os = "linux")]
    Linux,
    Synthetic,
}

/// Available encoder types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EncoderType {
    None,
    NvencH264,
    NvencHevc,
    NvencHevcMain10,
    NvencAv1,
    OpenH264,
    SoftwareVvc,
    VideoToolboxH264,
    VideoToolboxHevc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NvencAv1Mode {
    LowLatency,
    UltraLowLatency,
    HighRefresh,
}

fn parse_nvenc_av1_mode_value(value: Option<&str>) -> NvencAv1Mode {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("ultra_low_latency" | "ultra-low-latency" | "ull" | "p6") => {
            NvencAv1Mode::UltraLowLatency
        }
        Some("high_refresh" | "high-refresh" | "high_refresh_rate" | "high-refresh-rate") => {
            NvencAv1Mode::HighRefresh
        }
        _ => NvencAv1Mode::LowLatency,
    }
}

fn configured_nvenc_av1_mode() -> NvencAv1Mode {
    let value = std::env::var("MRD_BENCH_NVENC_AV1_MODE")
        .ok()
        .or_else(|| std::env::var("MRD_HARNESS_NVENC_AV1_MODE").ok());
    parse_nvenc_av1_mode_value(value.as_deref())
}

fn prefer_max_speed_nvenc_for_hardware_decode(width: usize, height: usize, fps: u32) -> bool {
    fps >= 120 && width.saturating_mul(height) >= 2560usize.saturating_mul(1440)
}

fn resolved_openh264_bitrate(configured_bitrate: Option<u32>) -> u32 {
    configured_bitrate.unwrap_or(12_000_000).max(1)
}

/// Available decoder types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecoderType {
    None,
    Nvdec,
    Software,
    FfmpegH264,
    FfmpegHevc,
    FfmpegVvc,
    LinuxH264,
    LinuxHevc,
    LinuxHevcMain10,
    VideoToolbox,
}

/// Available renderer types for live test display.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RendererType {
    D3d11,
    Macos,
    Opengl,
    #[cfg(target_os = "linux")]
    Linux,
}

/// Available transport test paths for encoded access units.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Loopback,
    WebrtcRtp,
    QuicDatagram,
}

/// Test configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub resolution: Option<(usize, usize)>,
    pub fps: Option<u32>,
    pub bitrate: Option<u32>,
    pub renderer: Option<RendererType>,
    pub renderer_target_hwnd: Option<isize>,
    pub transport: Option<TransportKind>,
    pub zero_copy: Option<bool>,
    pub color_mode: Option<ColorMode>,
    pub color_pipeline: Option<ColorPipeline>,
    pub pace_to_fps: Option<bool>,
    pub input_source: Option<String>,
    pub source_id: Option<String>,
    pub display_id: Option<String>,
    pub window_handle: Option<String>,
    pub visual_preview: Option<bool>,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            resolution: None,
            fps: None,
            bitrate: None,
            renderer: None,
            renderer_target_hwnd: None,
            transport: None,
            zero_copy: None,
            color_mode: None,
            color_pipeline: None,
            pace_to_fps: None,
            input_source: None,
            source_id: None,
            display_id: None,
            window_handle: None,
            visual_preview: None,
        }
    }
}

#[allow(dead_code)]
impl TestChain {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CaptureOnly => "DXGI capture only",
            Self::NvencNvdec => "NVENC H.264 + NVDEC (全硬件加速)",
            Self::NvencOnly => "NVENC H.264 编码器测试",
            Self::OpenH264 => "OpenH264 编码器测试 (软件)",
            #[cfg(target_os = "linux")]
            Self::LinuxOpenh264 => "Linux 屏幕捕获 + OpenH264",
            Self::Custom { .. } => {
                // Build a descriptive name
                "自定义配置"
            }
        }
    }

    pub fn all() -> Vec<TestChain> {
        #[cfg(windows)]
        {
            return vec![
                Self::CaptureOnly,
                Self::NvencNvdec,
                Self::NvencOnly,
                Self::OpenH264,
            ];
        }

        #[cfg(target_os = "linux")]
        {
            return vec![Self::CaptureOnly, Self::LinuxOpenh264, Self::OpenH264];
        }

        #[cfg(target_os = "macos")]
        {
            return vec![Self::CaptureOnly, Self::OpenH264];
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            vec![Self::OpenH264]
        }
    }

    pub fn capture_type(&self) -> CaptureType {
        match self {
            Self::CaptureOnly | Self::OpenH264 => default_screen_capture_type(),
            Self::NvencNvdec | Self::NvencOnly => CaptureType::Dxgi,
            #[cfg(target_os = "linux")]
            Self::LinuxOpenh264 => CaptureType::Linux,
            Self::Custom { capture, .. } => capture.clone(),
        }
    }

    pub fn encoder_type(&self) -> EncoderType {
        match self {
            Self::CaptureOnly => EncoderType::None,
            Self::NvencNvdec | Self::NvencOnly => EncoderType::NvencH264,
            Self::OpenH264 => EncoderType::OpenH264,
            #[cfg(target_os = "linux")]
            Self::LinuxOpenh264 => EncoderType::OpenH264,
            Self::Custom { encoder, .. } => encoder.clone(),
        }
    }

    pub fn decoder_type(&self) -> DecoderType {
        match self {
            Self::NvencNvdec => DecoderType::Nvdec,
            Self::CaptureOnly | Self::NvencOnly | Self::OpenH264 => DecoderType::None,
            #[cfg(target_os = "linux")]
            Self::LinuxOpenh264 => DecoderType::None,
            Self::Custom { decoder, .. } => decoder.clone(),
        }
    }
}

impl Default for TestChain {
    fn default() -> Self {
        #[cfg(windows)]
        {
            Self::NvencNvdec
        }
        #[cfg(target_os = "linux")]
        {
            Self::LinuxOpenh264
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Self::OpenH264
        }
    }
}

#[allow(dead_code)]
fn default_screen_capture_type() -> CaptureType {
    #[cfg(windows)]
    {
        return CaptureType::Dxgi;
    }

    #[cfg(target_os = "macos")]
    {
        return CaptureType::Macos;
    }

    #[cfg(target_os = "linux")]
    {
        return CaptureType::Linux;
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        CaptureType::Synthetic
    }
}

#[cfg(target_os = "linux")]
fn start_linux_capture_session(capture: &mut PipewireScreenCapture) -> Result<()> {
    let timeout_ms = std::env::var("MRD_LINUX_CAPTURE_START_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_LINUX_CAPTURE_START_TIMEOUT_MS);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("create Linux capture runtime failed: {error}"))?;
    match runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(timeout_ms), capture.start_session()).await
    }) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow::anyhow!(
            "start Linux capture session failed: {error}"
        )),
        Err(_) => Err(anyhow::anyhow!(
            "start Linux capture session timed out after {timeout_ms} ms; select a screen/window in the system sharing prompt or set MRD_LINUX_CAPTURE_START_TIMEOUT_MS to a larger value"
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessMetrics {
    pub is_running: bool,
    pub capture_fps: f64,
    pub encoded_fps: f64,
    pub decoded_fps: f64,
    pub capture_latency_avg_ms: f64,
    pub capture_latency_p50_ms: f64,
    pub capture_latency_p95_ms: f64,
    pub source_wait_latency_avg_ms: f64,
    pub source_wait_latency_p50_ms: f64,
    pub source_wait_latency_p95_ms: f64,
    pub interactive_latency_avg_ms: f64,
    pub interactive_latency_p50_ms: f64,
    pub interactive_latency_p95_ms: f64,
    pub encode_latency_avg_ms: f64,
    pub encode_latency_p50_ms: f64,
    pub encode_latency_p95_ms: f64,
    pub transport_latency_avg_ms: f64,
    pub transport_latency_p50_ms: f64,
    pub transport_latency_p95_ms: f64,
    pub decode_latency_avg_ms: f64,
    pub decode_latency_p50_ms: f64,
    pub decode_latency_p95_ms: f64,
    pub render_latency_avg_ms: f64,
    pub render_latency_p50_ms: f64,
    pub render_latency_p95_ms: f64,
    pub render_submit_wait_latency_avg_ms: f64,
    pub render_submit_wait_latency_p50_ms: f64,
    pub render_submit_wait_latency_p95_ms: f64,
    pub render_execute_latency_avg_ms: f64,
    pub render_execute_latency_p50_ms: f64,
    pub render_execute_latency_p95_ms: f64,
    pub render_prepare_wait_latency_avg_ms: f64,
    pub render_prepare_wait_latency_p50_ms: f64,
    pub render_prepare_wait_latency_p95_ms: f64,
    pub render_shared_resource_latency_avg_ms: f64,
    pub render_shared_resource_latency_p50_ms: f64,
    pub render_shared_resource_latency_p95_ms: f64,
    pub render_draw_present_latency_avg_ms: f64,
    pub render_draw_present_latency_p50_ms: f64,
    pub render_draw_present_latency_p95_ms: f64,
    pub present_latency_avg_ms: f64,
    pub render_submitted_frames: u64,
    pub render_uploaded_frames: u64,
    pub render_presented_frames: u64,
    pub render_present_skipped_frames: u64,
    pub render_queue_replacements: u64,
    pub render_stale_frame_drops: u64,
    pub swap_chain_max_frame_latency: Option<u32>,
    pub swap_chain_allow_tearing: Option<bool>,
    pub swap_chain_waitable_object: Option<bool>,
    pub swap_chain_present_mode: Option<String>,
    pub display_refresh_hz: Option<u32>,
    pub render_thread_priority: Option<String>,
    pub render_pixel_format: Option<String>,
    pub color_mode: Option<String>,
    pub color_pipeline: Option<String>,
    pub nvdec_shared_copy_attempts: u64,
    pub nvdec_shared_copy_successes: u64,
    pub nvdec_shared_copy_failures: u64,
    pub nvdec_shared_copy_last_stage: Option<String>,
    pub nvdec_shared_copy_last_api: Option<String>,
    pub nvdec_shared_copy_last_error: Option<String>,
    pub render_present_gap_avg_ms: f64,
    pub render_present_gap_p50_ms: f64,
    pub render_present_gap_p95_ms: f64,
    /// Bounded intervals from successful renderer Present callbacks.
    pub render_present_intervals_ms: Vec<f64>,
    pub total_latency_avg_ms: f64,
    pub total_latency_p50_ms: f64,
    pub total_latency_p95_ms: f64,
    pub frame_count: usize,
    pub encoded_units: usize,
    pub decoded_frames: usize,
    pub encode_failures: usize,
    pub decode_failures: usize,
    pub total_bitstream_bytes: usize,
    pub dropped_frames: usize,
    pub resolution: (usize, usize),
    pub error_message: Option<String>,
}

impl HarnessMetrics {
    pub fn observed_fps(&self) -> f64 {
        if self.decoded_fps > 0.0 {
            self.decoded_fps
        } else {
            self.capture_fps
        }
    }

    pub fn to_pipeline_comparison_result(
        &self,
        pipeline: impl Into<String>,
        codec: impl Into<String>,
        memory_path: impl Into<String>,
        transport: impl Into<String>,
    ) -> PipelineComparisonResult {
        PipelineComparisonResult::new(pipeline, codec)
            .with_memory_path(memory_path)
            .with_transport(transport)
            .with_counts(
                self.frame_count as u64,
                self.encoded_units as u64,
                self.decoded_frames as u64,
                self.encode_failures as u64,
                self.decode_failures as u64,
            )
            .with_average_stage_ms(
                nonzero_ms(self.capture_latency_avg_ms),
                nonzero_ms(self.encode_latency_avg_ms),
                nonzero_ms(self.decode_latency_avg_ms),
                nonzero_ms(self.render_latency_avg_ms),
                nonzero_ms(self.present_latency_avg_ms),
            )
            .with_transport_stage_ms(nonzero_ms(self.transport_latency_avg_ms))
            .with_total_time_ms(nonzero_ms(self.total_latency_avg_ms))
            .with_avg_fps(nonzero_ms(self.observed_fps()))
            .with_total_bitstream_bytes(self.total_bitstream_bytes as u64)
    }
}

impl Default for HarnessMetrics {
    fn default() -> Self {
        Self {
            is_running: false,
            capture_fps: 0.0,
            encoded_fps: 0.0,
            decoded_fps: 0.0,
            capture_latency_avg_ms: 0.0,
            capture_latency_p50_ms: 0.0,
            capture_latency_p95_ms: 0.0,
            source_wait_latency_avg_ms: 0.0,
            source_wait_latency_p50_ms: 0.0,
            source_wait_latency_p95_ms: 0.0,
            interactive_latency_avg_ms: 0.0,
            interactive_latency_p50_ms: 0.0,
            interactive_latency_p95_ms: 0.0,
            encode_latency_avg_ms: 0.0,
            encode_latency_p50_ms: 0.0,
            encode_latency_p95_ms: 0.0,
            transport_latency_avg_ms: 0.0,
            transport_latency_p50_ms: 0.0,
            transport_latency_p95_ms: 0.0,
            decode_latency_avg_ms: 0.0,
            decode_latency_p50_ms: 0.0,
            decode_latency_p95_ms: 0.0,
            render_latency_avg_ms: 0.0,
            render_latency_p50_ms: 0.0,
            render_latency_p95_ms: 0.0,
            render_submit_wait_latency_avg_ms: 0.0,
            render_submit_wait_latency_p50_ms: 0.0,
            render_submit_wait_latency_p95_ms: 0.0,
            render_execute_latency_avg_ms: 0.0,
            render_execute_latency_p50_ms: 0.0,
            render_execute_latency_p95_ms: 0.0,
            render_prepare_wait_latency_avg_ms: 0.0,
            render_prepare_wait_latency_p50_ms: 0.0,
            render_prepare_wait_latency_p95_ms: 0.0,
            render_shared_resource_latency_avg_ms: 0.0,
            render_shared_resource_latency_p50_ms: 0.0,
            render_shared_resource_latency_p95_ms: 0.0,
            render_draw_present_latency_avg_ms: 0.0,
            render_draw_present_latency_p50_ms: 0.0,
            render_draw_present_latency_p95_ms: 0.0,
            present_latency_avg_ms: 0.0,
            render_submitted_frames: 0,
            render_uploaded_frames: 0,
            render_presented_frames: 0,
            render_present_skipped_frames: 0,
            render_queue_replacements: 0,
            render_stale_frame_drops: 0,
            swap_chain_max_frame_latency: None,
            swap_chain_allow_tearing: None,
            swap_chain_waitable_object: None,
            swap_chain_present_mode: None,
            display_refresh_hz: None,
            render_thread_priority: None,
            render_pixel_format: None,
            color_mode: Some(ColorMode::Full.as_str().to_string()),
            color_pipeline: Some(ColorPipeline::Sdr8.as_str().to_string()),
            nvdec_shared_copy_attempts: 0,
            nvdec_shared_copy_successes: 0,
            nvdec_shared_copy_failures: 0,
            nvdec_shared_copy_last_stage: None,
            nvdec_shared_copy_last_api: None,
            nvdec_shared_copy_last_error: None,
            render_present_gap_avg_ms: 0.0,
            render_present_gap_p50_ms: 0.0,
            render_present_gap_p95_ms: 0.0,
            render_present_intervals_ms: Vec::new(),
            total_latency_avg_ms: 0.0,
            total_latency_p50_ms: 0.0,
            total_latency_p95_ms: 0.0,
            frame_count: 0,
            encoded_units: 0,
            decoded_frames: 0,
            encode_failures: 0,
            decode_failures: 0,
            total_bitstream_bytes: 0,
            dropped_frames: 0,
            resolution: (0, 0),
            error_message: None,
        }
    }
}

struct FrameBuffer {
    captured: Option<Vec<u8>>,
    captured_width: usize,
    captured_height: usize,
    captured_generation: u64,
    rendered: Option<Vec<u8>>,
    rendered_width: usize,
    rendered_height: usize,
    rendered_generation: u64,
}

// Pipeline state - defined outside impl
struct PipelineState {
    capture: Box<dyn FrameCapture>,
    encoder: Option<Box<dyn VideoEncoder>>,
    transport: PipelineTransport,
    decoder: Option<PipelineDecoder>,
    renderer: Option<PipelineRenderer>,
    use_decoder: bool,
    visual_preview: bool,
    pace_to_fps: bool,
    fps: u32,
    width: usize,
    height: usize,
    adapted_frame: Option<CapturedFrame>,
}

#[allow(dead_code)]
enum PipelineDecoder {
    Nvdec(NvdecDecoder),
    Software(Box<dyn VideoDecoder>),
    LinuxH264(Box<dyn VideoDecoder>),
    LinuxHevc(Box<dyn VideoDecoder>),
    LinuxHevcMain10(Box<dyn VideoDecoder>),
    VideoToolbox(Box<dyn VideoDecoder>),
}

enum WebrtcRtpSender {
    H264(mrd_transport_webrtc::H264RtpSender),
    Hevc(mrd_transport_webrtc::HevcRtpSender),
    Av1(mrd_transport_webrtc::Av1RtpSender),
    Vvc(mrd_transport_webrtc::VvcRtpSender),
}

enum WebrtcRtpIngress {
    H264(mrd_transport_webrtc::H264RtpIngress),
    Hevc(mrd_transport_webrtc::HevcRtpIngress),
    Av1(mrd_transport_webrtc::Av1RtpIngress),
    Vvc(mrd_transport_webrtc::VvcRtpIngress),
}

enum PipelineTransport {
    Loopback,
    WebrtcRtp {
        sender: WebrtcRtpSender,
        ingress: WebrtcRtpIngress,
    },
    QuicDatagram {
        reassembler: mrd_transport_quic_quinn::QuicAuReassembler,
        next_frame_id: u32,
        max_datagram_size: usize,
    },
}

impl PipelineTransport {
    fn new(kind: Option<&TransportKind>, fps: u32, codec: VideoCodec) -> Result<Self> {
        Ok(match kind.unwrap_or(&TransportKind::Loopback) {
            TransportKind::Loopback => Self::Loopback,
            TransportKind::WebrtcRtp => match codec {
                VideoCodec::H264 => Self::WebrtcRtp {
                    sender: WebrtcRtpSender::H264(mrd_transport_webrtc::H264RtpSender::new(
                        "matrix-video",
                        "matrix-stream",
                        fps,
                        1200,
                    )),
                    ingress: WebrtcRtpIngress::H264(mrd_transport_webrtc::H264RtpIngress::default()),
                },
                VideoCodec::Hevc => Self::WebrtcRtp {
                    sender: WebrtcRtpSender::Hevc(mrd_transport_webrtc::HevcRtpSender::new(
                        "matrix-video",
                        "matrix-stream",
                        fps,
                        1200,
                    )),
                    ingress: WebrtcRtpIngress::Hevc(mrd_transport_webrtc::HevcRtpIngress::default()),
                },
                VideoCodec::Av1 => Self::WebrtcRtp {
                    sender: WebrtcRtpSender::Av1(mrd_transport_webrtc::Av1RtpSender::new(
                        "matrix-video",
                        "matrix-stream",
                        fps,
                        1200,
                    )),
                    ingress: WebrtcRtpIngress::Av1(mrd_transport_webrtc::Av1RtpIngress::default()),
                },
                VideoCodec::Vvc => Self::WebrtcRtp {
                    sender: WebrtcRtpSender::Vvc(mrd_transport_webrtc::VvcRtpSender::new(
                        "matrix-video",
                        "matrix-stream",
                        fps,
                        1200,
                    )),
                    ingress: WebrtcRtpIngress::Vvc(mrd_transport_webrtc::VvcRtpIngress::default()),
                },
            },
            TransportKind::QuicDatagram => Self::QuicDatagram {
                reassembler: mrd_transport_quic_quinn::QuicAuReassembler::default(),
                next_frame_id: 0,
                max_datagram_size: 1200,
            },
        })
    }

    fn transmit(&mut self, access_units: Vec<EncodedAccessUnit>) -> Result<Vec<EncodedAccessUnit>> {
        match self {
            Self::Loopback => Ok(access_units),
            Self::WebrtcRtp { sender, ingress } => {
                let mut reassembled = Vec::with_capacity(access_units.len());
                for access_unit in access_units {
                    let packets = match sender {
                        WebrtcRtpSender::H264(sender) => sender
                            .packetize_access_unit(&access_unit)
                            .map_err(|error| {
                                anyhow::anyhow!("WebRTC H264 RTP packetize failed: {error}")
                            })?,
                        WebrtcRtpSender::Hevc(sender) => sender
                            .packetize_access_unit(&access_unit)
                            .map_err(|error| {
                                anyhow::anyhow!("WebRTC HEVC RTP packetize failed: {error}")
                            })?,
                        WebrtcRtpSender::Av1(sender) => sender
                            .packetize_access_unit(&access_unit)
                            .map_err(|error| {
                                anyhow::anyhow!("WebRTC AV1 RTP packetize failed: {error}")
                            })?,
                        WebrtcRtpSender::Vvc(sender) => sender
                            .packetize_access_unit(&access_unit)
                            .map_err(|error| {
                                anyhow::anyhow!("WebRTC VVC RTP packetize failed: {error}")
                            })?,
                    };
                    for packet in packets {
                        let unit = match ingress {
                            WebrtcRtpIngress::H264(ingress) => ingress.push_packet(
                                &packet.payload,
                                packet.header.marker,
                                packet.header.sequence_number,
                                access_unit.timestamp_us,
                            ),
                            WebrtcRtpIngress::Hevc(ingress) => ingress.push_packet(
                                &packet.payload,
                                packet.header.marker,
                                packet.header.sequence_number,
                                access_unit.timestamp_us,
                            ),
                            WebrtcRtpIngress::Av1(ingress) => ingress.push_packet(
                                &packet.payload,
                                packet.header.marker,
                                packet.header.sequence_number,
                                access_unit.timestamp_us,
                            ),
                            WebrtcRtpIngress::Vvc(ingress) => ingress.push_packet(
                                &packet.payload,
                                packet.header.marker,
                                packet.header.sequence_number,
                                access_unit.timestamp_us,
                            ),
                        };
                        if let Some(unit) = unit {
                            reassembled.push(unit);
                        }
                    }
                }
                Ok(reassembled)
            }
            Self::QuicDatagram {
                reassembler,
                next_frame_id,
                max_datagram_size,
            } => {
                let mut reassembled = Vec::with_capacity(access_units.len());
                for access_unit in access_units {
                    let frame_id = *next_frame_id;
                    *next_frame_id = next_frame_id.wrapping_add(1);
                    let datagrams = mrd_transport_quic_quinn::fragment_access_unit(
                        frame_id,
                        access_unit.timestamp_us,
                        access_unit.is_keyframe,
                        &access_unit.bytes,
                        *max_datagram_size,
                    )
                    .map_err(|error| anyhow::anyhow!("QUIC AU fragment failed: {error}"))?;

                    for datagram in datagrams {
                        if let Some(frame) =
                            reassembler.push_datagram(&datagram).map_err(|error| {
                                anyhow::anyhow!("QUIC AU reassemble failed: {error}")
                            })?
                        {
                            reassembled.push(EncodedAccessUnit {
                                codec: access_unit.codec,
                                timestamp_us: frame.timestamp_us,
                                is_keyframe: frame.is_keyframe,
                                bytes: frame.payload.to_vec(),
                            });
                        }
                    }
                }
                Ok(reassembled)
            }
        }
    }
}

impl PipelineDecoder {
    fn push_access_unit(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Nvdec(decoder) => decoder.push_access_unit(bytes).map_err(|error| {
                anyhow::anyhow!("{}; diagnostics={:?}", error, decoder.diagnostics())
            }),
            Self::Software(decoder) => decoder
                .push_access_unit(bytes)
                .map_err(|error| anyhow::anyhow!(error)),
            Self::LinuxH264(decoder)
            | Self::LinuxHevc(decoder)
            | Self::LinuxHevcMain10(decoder) => decoder
                .push_access_unit(bytes)
                .map_err(|error| anyhow::anyhow!(error)),
            Self::VideoToolbox(decoder) => decoder
                .push_access_unit(bytes)
                .map_err(|error| anyhow::anyhow!(error)),
        }
    }

    fn drain_decoded_frames(&mut self) -> Vec<DecodedFrame> {
        match self {
            Self::Nvdec(decoder) => decoder
                .drain_decoded_frames()
                .into_iter()
                .map(nvdec_frame_to_decoded_frame)
                .collect(),
            Self::Software(decoder) => decoder.drain_decoded_frames(),
            Self::LinuxH264(decoder)
            | Self::LinuxHevc(decoder)
            | Self::LinuxHevcMain10(decoder) => decoder.drain_decoded_frames(),
            Self::VideoToolbox(decoder) => decoder.drain_decoded_frames(),
        }
    }

    fn nvdec_shared_copy_stats(&self) -> Option<NvdecSharedCopyStats> {
        match self {
            Self::Nvdec(decoder) => Some(NvdecSharedCopyStats::from_diagnostics(
                decoder.diagnostics(),
            )),
            Self::Software(_)
            | Self::LinuxH264(_)
            | Self::LinuxHevc(_)
            | Self::LinuxHevcMain10(_)
            | Self::VideoToolbox(_) => None,
        }
    }
}

#[derive(Clone)]
enum RenderInput {
    Decoded(DecodedFrame),
    Captured(CapturedFrame),
}

#[derive(Debug, Clone, Default)]
struct RenderPacingCounters {
    submitted_frames: u64,
    uploaded_frames: u64,
    presented_frames: u64,
    present_skipped_frames: u64,
    queue_replacements: u64,
    stale_frame_drops: u64,
    swap_chain_max_frame_latency: Option<u32>,
    swap_chain_allow_tearing: Option<bool>,
    swap_chain_waitable_object: Option<bool>,
    swap_chain_present_mode: Option<String>,
    display_refresh_hz: Option<u32>,
    render_thread_priority: Option<String>,
    render_pixel_format: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct NvdecSharedCopyStats {
    attempts: u64,
    successes: u64,
    failures: u64,
    last_stage: Option<String>,
    last_api: Option<String>,
    last_error: Option<String>,
}

impl NvdecSharedCopyStats {
    fn from_diagnostics(diagnostics: mrd_decode_nvdec::NvdecDiagnostics) -> Self {
        let last_error = diagnostics
            .last_shared_copy_error_name
            .or(diagnostics.last_shared_copy_error_description);
        Self {
            attempts: diagnostics.shared_copy_attempts as u64,
            successes: diagnostics.shared_copy_successes as u64,
            failures: diagnostics.shared_copy_failures as u64,
            last_stage: diagnostics.last_shared_copy_stage,
            last_api: diagnostics.last_shared_copy_api,
            last_error,
        }
    }
}

#[derive(Debug, Clone)]
struct RenderCompletion {
    snapshot: RendererSnapshot,
    present_events: Vec<mrd_render::RendererPresentEvent>,
    upload_started_at: Instant,
    upload_completed_at: Instant,
}

#[derive(Debug, Clone)]
struct RenderUploadTiming {
    started_at: Instant,
    completed_at: Instant,
}

struct RenderJob {
    input: RenderInput,
    completion: mpsc::SyncSender<std::result::Result<RenderCompletion, String>>,
}

enum RenderCommand {
    Frame(RenderJob),
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LatestRenderSubmit {
    replaced_pending: bool,
}

#[derive(Default)]
struct LatestRenderSlot {
    pending: Option<RenderInput>,
    stopping: bool,
}

impl LatestRenderSlot {
    fn push_latest(&mut self, input: RenderInput) -> LatestRenderSubmit {
        let replaced_pending = self.pending.replace(input).is_some();
        LatestRenderSubmit { replaced_pending }
    }

    fn take_next(&mut self) -> Option<RenderInput> {
        self.pending.take()
    }

    fn stop(&mut self) {
        self.stopping = true;
        self.pending = None;
    }
}

struct LatestRenderShared {
    slot: Mutex<LatestRenderSlot>,
    ready: Condvar,
}

impl LatestRenderShared {
    fn new() -> Self {
        Self {
            slot: Mutex::new(LatestRenderSlot::default()),
            ready: Condvar::new(),
        }
    }

    fn push_latest(&self, input: RenderInput) -> LatestRenderSubmit {
        let mut slot = self.slot.lock().unwrap();
        let submit = slot.push_latest(input);
        self.ready.notify_one();
        submit
    }

    fn stop(&self) {
        let mut slot = self.slot.lock().unwrap();
        slot.stop();
        self.ready.notify_one();
    }
}

struct AsyncRenderCompletion {
    result: std::result::Result<RenderCompletion, String>,
    started_at: Instant,
    completed_at: Instant,
}

struct LatestRenderScheduler {
    shared: Arc<LatestRenderShared>,
    completions: mpsc::Receiver<AsyncRenderCompletion>,
    worker_done: mpsc::Receiver<()>,
    returned_renderer: mpsc::Receiver<PipelineRenderer>,
    worker_finished: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl LatestRenderScheduler {
    fn new(renderer: PipelineRenderer) -> Result<Self> {
        let shared = Arc::new(LatestRenderShared::new());
        let (completion_tx, completions) = mpsc::channel();
        let (worker_done_tx, worker_done) = mpsc::channel();
        let (returned_renderer_tx, returned_renderer) = mpsc::sync_channel(1);
        let worker_shared = Arc::clone(&shared);
        let worker_finished = Arc::new(AtomicBool::new(false));
        let worker_finished_thread = Arc::clone(&worker_finished);
        // Keep this sender alive until the worker state is published.  Otherwise the
        // receiver can observe a disconnected channel in the small window between
        // `run_latest_render_worker` returning and `worker_finished` being set.
        let worker_completion_tx = completion_tx.clone();
        let worker = thread::Builder::new()
            .name("mrd-latest-render-scheduler".to_string())
            .spawn(move || {
                let renderer =
                    run_latest_render_worker(renderer, worker_shared, worker_completion_tx);
                let _ = returned_renderer_tx.send(renderer);
                worker_finished_thread.store(true, Ordering::Release);
                drop(completion_tx);
                let _ = worker_done_tx.send(());
            })
            .map_err(|error| anyhow::anyhow!("spawn latest render scheduler failed: {error}"))?;

        Ok(Self {
            shared,
            completions,
            worker_done,
            returned_renderer,
            worker_finished,
            worker: Some(worker),
        })
    }

    fn submit_latest(&self, input: RenderInput) -> LatestRenderSubmit {
        self.shared.push_latest(input)
    }

    fn try_recv_completion(&self) -> Result<Option<AsyncRenderCompletion>> {
        match self.completions.try_recv() {
            Ok(completion) => Ok(Some(completion)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                if self.worker_finished.load(Ordering::Acquire) {
                    Ok(None)
                } else {
                    anyhow::bail!("latest render scheduler stopped")
                }
            }
        }
    }

    fn stop(&self) {
        self.shared.stop();
    }

    fn is_finished(&self) -> bool {
        self.worker_finished.load(Ordering::Acquire)
    }

    fn shutdown_and_take_renderer(&mut self) -> Result<Option<PipelineRenderer>> {
        let Some(worker) = self.worker.take() else {
            return Ok(None);
        };
        self.stop();
        if !self.is_finished() {
            self.worker_done
                .recv_timeout(Duration::from_millis(HARNESS_STOP_JOIN_TIMEOUT_MS))
                .map_err(|_| anyhow::anyhow!("latest render scheduler did not stop in time"))?;
        }
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("latest render scheduler panicked"))?;
        self.returned_renderer
            .recv_timeout(Duration::from_millis(NATIVE_RENDER_THREAD_STOP_TIMEOUT_MS))
            .map(Some)
            .map_err(|_| anyhow::anyhow!("latest render scheduler did not return its renderer"))
    }
}

impl Drop for LatestRenderScheduler {
    fn drop(&mut self) {
        let _ = self.shutdown_and_take_renderer();
    }
}

struct PipelineRenderer {
    sender: Option<mpsc::SyncSender<RenderCommand>>,
    render_thread: Option<thread::JoinHandle<()>>,
    render_done: Option<mpsc::Receiver<()>>,
    last_error: Arc<Mutex<Option<String>>>,
    d3d11_device_ptr: Option<usize>,
}

impl PipelineRenderer {
    fn new(
        renderer_type: &RendererType,
        width: usize,
        height: usize,
        target_hwnd: Option<isize>,
        target_display_ref: Option<String>,
        use_shared_texture_decode: bool,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let last_error = Arc::new(Mutex::new(None));
        let thread_error = Arc::clone(&last_error);
        let renderer_type = renderer_type.clone();

        #[cfg(windows)]
        if renderer_type == RendererType::D3d11 {
            let renderer = mrd_render_d3d11::D3d11Renderer::new()
                .map_err(|error| anyhow::anyhow!("create D3D11 renderer failed: {error}"))?;
            let d3d11_device_ptr = renderer.device_ptr() as usize;
            let (render_done_tx, render_done_rx) = mpsc::channel();
            let render_thread = thread::Builder::new()
                .name("mrd-test-render".to_string())
                .spawn(move || {
                    if let Err(error) = run_d3d11_renderer_thread(
                        renderer,
                        width,
                        height,
                        target_hwnd,
                        target_display_ref.as_deref(),
                        receiver,
                    ) {
                        if let Ok(mut last_error) = thread_error.lock() {
                            *last_error = Some(error.to_string());
                        }
                    }
                    let _ = render_done_tx.send(());
                })
                .map_err(|error| anyhow::anyhow!("spawn render thread failed: {error}"))?;

            return Ok(Self {
                sender: Some(sender),
                render_thread: Some(render_thread),
                render_done: Some(render_done_rx),
                last_error,
                d3d11_device_ptr: Some(d3d11_device_ptr),
            });
        }

        #[cfg(windows)]
        if renderer_type == RendererType::Opengl && use_shared_texture_decode {
            let renderer = mrd_render_opengl::OpenglRenderer::new_hybrid().map_err(|error| {
                anyhow::anyhow!("create OpenGL hybrid renderer failed: {error}")
            })?;
            let d3d11_device_ptr = renderer.d3d11_device_ptr().map(|ptr| ptr as usize);
            let (render_done_tx, render_done_rx) = mpsc::channel();
            let render_thread = thread::Builder::new()
                .name("mrd-test-render".to_string())
                .spawn(move || {
                    if let Err(error) = run_opengl_hybrid_renderer_thread(
                        renderer,
                        width,
                        height,
                        target_hwnd,
                        target_display_ref.as_deref(),
                        receiver,
                    ) {
                        if let Ok(mut last_error) = thread_error.lock() {
                            *last_error = Some(error.to_string());
                        }
                    }
                    let _ = render_done_tx.send(());
                })
                .map_err(|error| anyhow::anyhow!("spawn render thread failed: {error}"))?;

            return Ok(Self {
                sender: Some(sender),
                render_thread: Some(render_thread),
                render_done: Some(render_done_rx),
                last_error,
                d3d11_device_ptr,
            });
        }

        let (render_done_tx, render_done_rx) = mpsc::channel();
        let render_thread = thread::Builder::new()
            .name("mrd-test-render".to_string())
            .spawn(move || {
                if let Err(error) = run_renderer_thread(
                    renderer_type,
                    width,
                    height,
                    target_hwnd,
                    target_display_ref.as_deref(),
                    receiver,
                ) {
                    if let Ok(mut last_error) = thread_error.lock() {
                        *last_error = Some(error.to_string());
                    }
                }
                let _ = render_done_tx.send(());
            })
            .map_err(|error| anyhow::anyhow!("spawn render thread failed: {error}"))?;

        Ok(Self {
            sender: Some(sender),
            render_thread: Some(render_thread),
            render_done: Some(render_done_rx),
            last_error,
            d3d11_device_ptr: None,
        })
    }

    #[cfg(windows)]
    fn d3d11_device_ptr(&self) -> Option<*mut core::ffi::c_void> {
        self.d3d11_device_ptr
            .map(|ptr| ptr as *mut core::ffi::c_void)
    }

    #[cfg(not(windows))]
    fn d3d11_device_ptr(&self) -> Option<*mut core::ffi::c_void> {
        None
    }

    fn submit_frame(&mut self, input: RenderInput) -> Result<RenderCompletion> {
        if let Some(error) = self.last_error.lock().unwrap().clone() {
            anyhow::bail!("native render thread failed: {error}");
        }

        let (completion, done) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native render thread is stopping"))?
            .send(RenderCommand::Frame(RenderJob { input, completion }))
            .map_err(|_| anyhow::anyhow!("native render thread stopped"))?;
        match done.recv_timeout(Duration::from_millis(NATIVE_RENDER_FRAME_TIMEOUT_MS)) {
            Ok(Ok(completion)) => Ok(completion),
            Ok(Err(error)) => anyhow::bail!("native render thread failed: {error}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let message = format!(
                    "native render frame timed out after {NATIVE_RENDER_FRAME_TIMEOUT_MS} ms"
                );
                if let Ok(mut last_error) = self.last_error.lock() {
                    *last_error = Some(message.clone());
                }
                anyhow::bail!(message)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("native render thread stopped before completing frame")
            }
        }
    }
}

impl Drop for PipelineRenderer {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.try_send(RenderCommand::Stop);
            // A full bounded queue can reject the stop command. Disconnecting
            // the final sender guarantees the render loop exits after any
            // already queued frame instead of blocking forever on recv().
            drop(sender);
        }
        if let Some(done) = self.render_done.take() {
            let _ = done.recv_timeout(Duration::from_millis(NATIVE_RENDER_THREAD_STOP_TIMEOUT_MS));
        }

        if let Some(render_thread) = self.render_thread.take() {
            let _ = render_thread.join();
        }
    }
}

fn run_latest_render_worker(
    mut renderer: PipelineRenderer,
    shared: Arc<LatestRenderShared>,
    completions: mpsc::Sender<AsyncRenderCompletion>,
) -> PipelineRenderer {
    loop {
        let input = {
            let mut slot = shared.slot.lock().unwrap();
            loop {
                if slot.stopping {
                    return renderer;
                }
                if let Some(input) = slot.take_next() {
                    break input;
                }
                slot = shared.ready.wait(slot).unwrap();
            }
        };

        let started_at = Instant::now();
        let result = renderer
            .submit_frame(input)
            .map_err(|error| error.to_string());
        let completed_at = Instant::now();
        let failed = result.is_err();
        if completions
            .send(AsyncRenderCompletion {
                result,
                started_at,
                completed_at,
            })
            .is_err()
        {
            return renderer;
        }
        if failed {
            return renderer;
        }
    }
}

fn run_renderer_thread(
    renderer_type: RendererType,
    width: usize,
    height: usize,
    target_hwnd: Option<isize>,
    target_display_ref: Option<&str>,
    receiver: mpsc::Receiver<RenderCommand>,
) -> Result<()> {
    match renderer_type {
        RendererType::D3d11 => {
            #[cfg(windows)]
            {
                let window = match target_hwnd {
                    Some(_) => None,
                    None => Some(D3d11TestWindow::new_on_display(
                        width,
                        height,
                        target_display_ref,
                    )?),
                };
                let hwnd = target_hwnd.unwrap_or_else(|| {
                    window
                        .as_ref()
                        .expect("D3D11 test window exists")
                        .hwnd_value()
                });
                let factory = mrd_render_d3d11::D3d11RendererFactory;
                let mut renderer = factory
                    .create()
                    .map_err(|error| anyhow::anyhow!("create D3D11 renderer failed: {error}"))?;
                renderer
                    .attach_target(RenderTarget::WindowHandle(hwnd))
                    .map_err(|error| anyhow::anyhow!("attach D3D11 renderer failed: {error}"))?;

                run_d3d11_render_loop(window, renderer, receiver)
            }

            #[cfg(not(windows))]
            {
                let _ = (width, height, target_hwnd, receiver);
                anyhow::bail!("D3D11 render display is only available on Windows");
            }
        }
        RendererType::Macos => {
            #[cfg(target_os = "macos")]
            {
                let window = match target_hwnd {
                    Some(_) => None,
                    None => Some(MacosTestWindow::new(width, height)?),
                };
                let target_hwnd = target_hwnd.unwrap_or_else(|| {
                    window
                        .as_ref()
                        .expect("macOS test window exists")
                        .ns_view_value()
                });
                let factory = MacosRendererFactory;
                let mut renderer = factory
                    .create()
                    .map_err(|error| anyhow::anyhow!("create Metal renderer failed: {error}"))?;
                renderer
                    .attach_target(RenderTarget::WindowHandle(target_hwnd))
                    .map_err(|error| anyhow::anyhow!("attach Metal renderer failed: {error}"))?;

                run_macos_render_loop(window, renderer, receiver)
            }

            #[cfg(not(target_os = "macos"))]
            {
                let _ = (width, height, target_hwnd, receiver);
                anyhow::bail!("Metal render display is only available on macOS");
            }
        }
        RendererType::Opengl => {
            #[cfg(windows)]
            {
                let window = match target_hwnd {
                    Some(_) => None,
                    None => Some(D3d11TestWindow::new_on_display(
                        width,
                        height,
                        target_display_ref,
                    )?),
                };
                let hwnd = target_hwnd.unwrap_or_else(|| {
                    window
                        .as_ref()
                        .expect("OpenGL test window exists")
                        .hwnd_value()
                });
                let factory = mrd_render_opengl::OpenglRendererFactory;
                let mut renderer = factory
                    .create()
                    .map_err(|error| anyhow::anyhow!("create OpenGL renderer failed: {error}"))?;
                renderer
                    .attach_target(RenderTarget::WindowHandle(hwnd))
                    .map_err(|error| anyhow::anyhow!("attach OpenGL renderer failed: {error}"))?;

                run_d3d11_render_loop(window, renderer, receiver)
            }

            #[cfg(not(windows))]
            {
                let _ = (width, height);
                let factory = mrd_render_opengl::OpenglRendererFactory;
                let mut renderer = factory
                    .create()
                    .map_err(|error| anyhow::anyhow!("create OpenGL renderer failed: {error}"))?;
                renderer
                    .attach_target(RenderTarget::WindowHandle(target_hwnd.unwrap_or(0)))
                    .map_err(|error| anyhow::anyhow!("attach OpenGL renderer failed: {error}"))?;

                run_renderer_upload_loop(renderer, receiver)
            }
        }
        #[cfg(target_os = "linux")]
        RendererType::Linux => {
            use mrd_render::RendererInstance;
            use mrd_render_linux::LinuxRenderer;

            let _ = (width, height);
            let mut renderer = LinuxRenderer::new()
                .map_err(|error| anyhow::anyhow!("create Linux renderer failed: {error}"))?;
            if let Some(target) = target_hwnd {
                renderer
                    .attach_target(RenderTarget::WindowHandle(target))
                    .map_err(|error| anyhow::anyhow!("attach Linux renderer failed: {error}"))?;
            } else {
                renderer
                    .create_window_with_size("MRD Linux Render Probe", width, height)
                    .map_err(|error| {
                        anyhow::anyhow!("create Linux render window failed: {error}")
                    })?;
            }

            for cmd in receiver {
                match cmd {
                    RenderCommand::Frame(job) => complete_render_job(&mut renderer, job)?,
                    RenderCommand::Stop => break,
                }
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
fn run_d3d11_renderer_thread(
    mut renderer: mrd_render_d3d11::D3d11Renderer,
    width: usize,
    height: usize,
    target_hwnd: Option<isize>,
    target_display_ref: Option<&str>,
    receiver: mpsc::Receiver<RenderCommand>,
) -> Result<()> {
    let window = match target_hwnd {
        Some(_) => None,
        None => Some(D3d11TestWindow::new_on_display(
            width,
            height,
            target_display_ref,
        )?),
    };
    let hwnd = target_hwnd.unwrap_or_else(|| {
        window
            .as_ref()
            .expect("D3D11 test window exists")
            .hwnd_value()
    });
    renderer
        .attach_target(RenderTarget::WindowHandle(hwnd))
        .map_err(|error| anyhow::anyhow!("attach D3D11 renderer failed: {error}"))?;

    run_d3d11_render_loop(window, Box::new(renderer), receiver)
}

#[cfg(windows)]
fn run_opengl_hybrid_renderer_thread(
    mut renderer: mrd_render_opengl::OpenglRenderer,
    width: usize,
    height: usize,
    target_hwnd: Option<isize>,
    target_display_ref: Option<&str>,
    receiver: mpsc::Receiver<RenderCommand>,
) -> Result<()> {
    let window = match target_hwnd {
        Some(_) => None,
        None => Some(D3d11TestWindow::new_on_display(
            width,
            height,
            target_display_ref,
        )?),
    };
    let hwnd = target_hwnd.unwrap_or_else(|| {
        window
            .as_ref()
            .expect("OpenGL hybrid test window exists")
            .hwnd_value()
    });
    renderer
        .attach_target(RenderTarget::WindowHandle(hwnd))
        .map_err(|error| anyhow::anyhow!("attach OpenGL hybrid renderer failed: {error}"))?;

    run_d3d11_render_loop(window, Box::new(renderer), receiver)
}

#[cfg(target_os = "macos")]
fn run_macos_render_loop(
    window: Option<MacosTestWindow>,
    mut renderer: Box<dyn RendererInstance>,
    receiver: mpsc::Receiver<RenderCommand>,
) -> Result<()> {
    loop {
        match receiver.recv_timeout(Duration::from_millis(8)) {
            Ok(RenderCommand::Frame(job)) => complete_render_job(&mut *renderer, job)?,
            Ok(RenderCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        if let Some(window) = window.as_ref() {
            window.pump_events()?;
        }
    }

    Ok(())
}

#[allow(dead_code)]
fn run_renderer_upload_loop(
    mut renderer: Box<dyn RendererInstance>,
    receiver: mpsc::Receiver<RenderCommand>,
) -> Result<()> {
    loop {
        match receiver.recv() {
            Ok(RenderCommand::Frame(job)) => complete_render_job(&mut *renderer, job)?,
            Ok(RenderCommand::Stop) | Err(_) => break,
        }
    }

    Ok(())
}

#[cfg(windows)]
fn run_d3d11_render_loop(
    window: Option<D3d11TestWindow>,
    mut renderer: Box<dyn RendererInstance>,
    receiver: mpsc::Receiver<RenderCommand>,
) -> Result<()> {
    match window {
        Some(window) => loop {
            window.pump_messages();
            match receiver.recv_timeout(Duration::from_millis(8)) {
                Ok(RenderCommand::Frame(job)) => {
                    complete_render_job(&mut *renderer, job)?;
                }
                Ok(RenderCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        },
        None => loop {
            match receiver.recv() {
                Ok(RenderCommand::Frame(job)) => {
                    complete_render_job(&mut *renderer, job)?;
                }
                Ok(RenderCommand::Stop) | Err(_) => break,
            }
        },
    }

    Ok(())
}

fn upload_render_input(
    renderer: &mut dyn RendererInstance,
    input: RenderInput,
) -> Result<RenderUploadTiming> {
    let frame = render_input_to_frame(input);
    let started_at = Instant::now();
    renderer
        .upload_frame(frame)
        .map_err(|error| anyhow::anyhow!("upload frame to renderer failed: {error}"))?;
    let completed_at = Instant::now();
    Ok(RenderUploadTiming {
        started_at,
        completed_at,
    })
}

fn complete_render_job(renderer: &mut dyn RendererInstance, job: RenderJob) -> Result<()> {
    match upload_render_input(renderer, job.input) {
        Ok(timing) => {
            let completion = RenderCompletion {
                snapshot: renderer.snapshot(),
                present_events: renderer.drain_present_events(),
                upload_started_at: timing.started_at,
                upload_completed_at: timing.completed_at,
            };
            let _ = job.completion.send(Ok(completion));
            Ok(())
        }
        Err(error) => {
            let _ = job.completion.send(Err(error.to_string()));
            Err(error)
        }
    }
}

#[cfg(target_os = "macos")]
#[allow(deprecated, unexpected_cfgs)]
struct MacosTestWindow {
    ns_window: isize,
    ns_view: isize,
}

#[cfg(target_os = "macos")]
#[allow(deprecated, unexpected_cfgs)]
impl MacosTestWindow {
    fn new(frame_width: usize, frame_height: usize) -> Result<Self> {
        run_on_macos_main_thread(move || unsafe {
            use cocoa::{
                appkit::{NSBackingStoreBuffered, NSView, NSWindow, NSWindowStyleMask},
                base::{id, nil, NO, YES},
                foundation::{NSPoint, NSRect, NSSize, NSString},
            };
            use objc::{msg_send, sel, sel_impl};

            let width = frame_width.clamp(320, 1280) as f64;
            let height = frame_height.clamp(240, 800) as f64;
            let frame = NSRect::new(NSPoint::new(80.0, 80.0), NSSize::new(width, height));
            let style = NSWindowStyleMask::NSTitledWindowMask
                | NSWindowStyleMask::NSClosableWindowMask
                | NSWindowStyleMask::NSResizableWindowMask;
            let window: id = NSWindow::alloc(nil).initWithContentRect_styleMask_backing_defer_(
                frame,
                style,
                NSBackingStoreBuffered,
                NO,
            );
            if window == nil {
                anyhow::bail!("create macOS Metal test window failed");
            }

            let content_frame = NSRect::new(NSPoint::new(0.0, 0.0), frame.size);
            let view: id = NSView::alloc(nil).initWithFrame_(content_frame);
            if view == nil {
                let _: () = msg_send![window, release];
                anyhow::bail!("create macOS Metal test NSView failed");
            }

            let _: () = msg_send![window, setReleasedWhenClosed: NO];
            view.setWantsLayer(YES);
            window.setContentView_(view);
            let title = NSString::alloc(nil).init_str("Rdesk Metal Render Test");
            window.setTitle_(title);
            let _: () = msg_send![title, release];
            window.center();
            window.makeKeyAndOrderFront_(nil);

            Ok(Self {
                ns_window: window as isize,
                ns_view: view as isize,
            })
        })
    }

    fn ns_view_value(&self) -> isize {
        self.ns_view
    }

    fn pump_events(&self) -> Result<()> {
        let ns_window = self.ns_window;
        run_on_macos_main_thread(move || unsafe {
            use cocoa::{
                appkit::{NSApp, NSApplication},
                base::{id, nil, YES},
                foundation::{NSAutoreleasePool, NSDefaultRunLoopMode, NSUInteger},
            };
            use objc::{msg_send, sel, sel_impl};

            let app = NSApp();
            let pool = NSAutoreleasePool::new(nil);
            loop {
                let event: id = app.nextEventMatchingMask_untilDate_inMode_dequeue_(
                    usize::MAX as NSUInteger,
                    nil,
                    NSDefaultRunLoopMode,
                    YES,
                );
                if event == nil {
                    break;
                }
                app.sendEvent_(event);
            }
            let _: () = msg_send![app, updateWindows];
            let window = ns_window as id;
            if window != nil {
                let _: () = msg_send![window, displayIfNeeded];
            }
            pool.drain();
            Ok(())
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosTestWindow {
    fn drop(&mut self) {
        let ns_window = self.ns_window;
        let ns_view = self.ns_view;
        let _ = run_on_macos_main_thread(move || unsafe {
            use cocoa::base::{id, nil};
            use objc::{msg_send, sel, sel_impl};

            let window = ns_window as id;
            let view = ns_view as id;
            if window != nil {
                let _: () = msg_send![window, orderOut: nil];
                let _: () = msg_send![window, close];
                let _: () = msg_send![window, release];
            }
            if view != nil {
                let _: () = msg_send![view, release];
            }
            Ok(())
        });
    }
}

#[cfg(target_os = "macos")]
fn run_on_macos_main_thread<T, F>(f: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
{
    if unsafe { pthread_main_np() } != 0 {
        return f();
    }

    let mut result = None;
    dispatch2::DispatchQueue::main().exec_sync(|| {
        result = Some(f());
    });
    result.unwrap_or_else(|| anyhow::bail!("macOS main-thread task did not return"))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_main_np() -> std::ffi::c_int;
}

#[cfg(windows)]
struct D3d11TestWindow {
    hwnd: windows::Win32::Foundation::HWND,
}

#[cfg(windows)]
impl D3d11TestWindow {
    fn new_on_display(
        frame_width: usize,
        frame_height: usize,
        display_ref: Option<&str>,
    ) -> Result<Self> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, LoadCursorW, RegisterClassW, ShowWindow, CS_HREDRAW,
            CS_OWNDC, CS_VREDRAW, CW_USEDEFAULT, HMENU, IDC_ARROW, SW_SHOW, WINDOW_EX_STYLE,
            WM_CLOSE, WNDCLASSW, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
        };

        unsafe extern "system" fn wnd_proc(
            hwnd: HWND,
            message: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            if message == WM_CLOSE {
                ShowWindow(hwnd, windows::Win32::UI::WindowsAndMessaging::SW_HIDE);
                return LRESULT(0);
            }

            DefWindowProcW(hwnd, message, wparam, lparam)
        }

        fn wide(value: &str) -> Vec<u16> {
            OsStr::new(value)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        let class_name = wide("RdeskD3D11TestWindow");
        let title = wide("Rdesk DX11 Render Test");
        let hmodule = unsafe { GetModuleHandleW(None) }
            .map_err(|error| anyhow::anyhow!("get module handle failed: {error}"))?;
        let hinstance = HINSTANCE(hmodule.0);
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }
            .map_err(|error| anyhow::anyhow!("load cursor failed: {error}"))?;

        let window_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW | CS_OWNDC,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance,
            hCursor: cursor,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };

        unsafe {
            RegisterClassW(&window_class);
        }

        let width = frame_width.clamp(640, 1280) as i32;
        let height = frame_height.clamp(360, 800) as i32;
        let origin = d3d11_test_window_origin(display_ref)?;
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(title.as_ptr()),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                origin.map(|(left, _)| left).unwrap_or(CW_USEDEFAULT),
                origin.map(|(_, top)| top).unwrap_or(CW_USEDEFAULT),
                width,
                height,
                HWND(0),
                HMENU(0),
                hinstance,
                None,
            )
        };

        if hwnd.0 == 0 {
            anyhow::bail!("create D3D11 render test window failed");
        }

        unsafe {
            ShowWindow(hwnd, SW_SHOW);
        }

        Ok(Self { hwnd })
    }

    fn hwnd_value(&self) -> isize {
        self.hwnd.0
    }

    fn pump_messages(&self) {
        use windows::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
        };

        let mut message = MSG::default();
        unsafe {
            while PeekMessageW(&mut message, self.hwnd, 0, 0, PM_REMOVE).as_bool() {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

#[cfg(windows)]
impl Drop for D3d11TestWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(self.hwnd);
        }
    }
}

#[cfg(windows)]
fn d3d11_test_window_origin(display_ref: Option<&str>) -> Result<Option<(i32, i32)>> {
    let Some(display_ref) = display_ref.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let selection =
        select_windows_display_ref(Some(display_ref), windows_display_device_name_for_source_id)?;
    let target = match selection {
        WindowsDisplaySelection::DeviceName(device_name) => enumerate_windows_display_targets()?
            .into_iter()
            .find(|target| target.device_name.eq_ignore_ascii_case(&device_name))
            .ok_or_else(|| {
                anyhow::anyhow!("Windows display target not found for device {device_name}")
            })?,
        WindowsDisplaySelection::Index(source_index) => {
            windows_display_target_for_source_index(source_index)?
        }
    };

    Ok(Some((target.left + 32, target.top + 32)))
}

pub struct TestHarness {
    running: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    chain: TestChain,
    config: TestConfig,
    metrics: Arc<Mutex<HarnessMetrics>>,
    frame_buffer: Arc<Mutex<FrameBuffer>>,
    encoded_subscribers: Arc<Mutex<Vec<mpsc::SyncSender<Vec<EncodedAccessUnit>>>>>,
    latest_keyframe_access_units: Arc<Mutex<Option<Vec<EncodedAccessUnit>>>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

unsafe impl Send for TestHarness {}

impl TestHarness {
    pub fn new() -> Result<Self> {
        let frame_buffer = Arc::new(Mutex::new(FrameBuffer {
            captured: None,
            captured_width: 0,
            captured_height: 0,
            captured_generation: 0,
            rendered: None,
            rendered_width: 0,
            rendered_height: 0,
            rendered_generation: 0,
        }));

        let metrics = Arc::new(Mutex::new(HarnessMetrics::default()));
        let running = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));

        Ok(Self {
            running,
            stopping,
            chain: TestChain::default(),
            config: TestConfig::default(),
            metrics,
            frame_buffer,
            encoded_subscribers: Arc::new(Mutex::new(Vec::new())),
            latest_keyframe_access_units: Arc::new(Mutex::new(None)),
            thread_handle: None,
        })
    }

    pub fn set_chain(&mut self, chain: TestChain) {
        self.chain = chain;
    }

    pub fn set_config(&mut self, config: TestConfig) {
        self.config = config;
    }

    pub fn get_chain(&self) -> TestChain {
        self.chain.clone()
    }

    pub fn subscribe_encoded_access_units(&self) -> mpsc::Receiver<Vec<EncodedAccessUnit>> {
        let (sender, receiver) = mpsc::sync_channel(ENCODED_ACCESS_UNIT_SUBSCRIBER_QUEUE_DEPTH);
        if let Some(keyframe_units) = self.latest_keyframe_access_units.lock().unwrap().clone() {
            let _ = sender.try_send(keyframe_units);
        }
        self.encoded_subscribers.lock().unwrap().push(sender);
        receiver
    }

    pub fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            anyhow::bail!("test harness is already running");
        }
        if self.thread_handle.is_some() || self.stopping.load(Ordering::Relaxed) {
            anyhow::bail!("test harness is stopping");
        }

        let chain = self.chain.clone();
        let config = self.config.clone();
        let frame_buffer = self.frame_buffer.clone();
        let metrics = self.metrics.clone();
        let encoded_subscribers = self.encoded_subscribers.clone();
        let latest_keyframe_access_units = self.latest_keyframe_access_units.clone();
        let running = self.running.clone();
        let running_for_thread = running.clone();
        {
            let mut buf = self.frame_buffer.lock().unwrap();
            buf.captured = None;
            buf.captured_width = 0;
            buf.captured_height = 0;
            buf.captured_generation = 0;
            buf.rendered = None;
            buf.rendered_width = 0;
            buf.rendered_height = 0;
            buf.rendered_generation = 0;
        }
        {
            let mut m = metrics.lock().unwrap();
            *m = HarnessMetrics::default();
            m.is_running = true;
            m.color_mode = Some(resolved_color_mode(&config).as_str().to_string());
            m.color_pipeline = Some(
                resolved_color_pipeline(&chain, &config)
                    .as_str()
                    .to_string(),
            );
        }

        running.store(true, Ordering::Relaxed);

        let handle = thread::spawn(move || {
            Self::run_pipeline(
                frame_buffer,
                metrics,
                encoded_subscribers,
                latest_keyframe_access_units,
                running_for_thread,
                chain,
                config,
            );
        });

        self.thread_handle = Some(handle);
        Ok(())
    }

    pub fn start_replacing_existing(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed)
            || self.thread_handle.is_some()
            || self.stopping.load(Ordering::Relaxed)
        {
            self.stop_and_wait()?;
        }

        self.start()
    }

    fn run_pipeline(
        frame_buffer: Arc<Mutex<FrameBuffer>>,
        metrics: Arc<Mutex<HarnessMetrics>>,
        encoded_subscribers: Arc<Mutex<Vec<mpsc::SyncSender<Vec<EncodedAccessUnit>>>>>,
        latest_keyframe_access_units: Arc<Mutex<Option<Vec<EncodedAccessUnit>>>>,
        running: Arc<AtomicBool>,
        chain: TestChain,
        config: TestConfig,
    ) {
        let state = match Self::initialize_components(&chain, &config) {
            Ok(s) => s,
            Err(e) => {
                let message = e.to_string();
                let mut m = metrics.lock().unwrap();
                m.is_running = false;
                m.error_message = Some(message.clone());
                running.store(false, Ordering::Relaxed);
                return;
            }
        };

        let (width, height) = (state.width, state.height);

        {
            let mut m = metrics.lock().unwrap();
            m.is_running = true;
            m.resolution = (width, height);
            m.error_message = None;
        }

        Self::process_loop(
            state,
            frame_buffer,
            metrics,
            encoded_subscribers,
            latest_keyframe_access_units,
            running,
        );
    }

    fn initialize_components(chain: &TestChain, config: &TestConfig) -> Result<PipelineState> {
        let use_shared_texture_decode =
            config.zero_copy.unwrap_or(false) && chain_allows_zero_copy_decode_render(chain);
        let use_shared_texture_capture =
            use_shared_texture_decode && chain_allows_zero_copy_capture(chain);
        let capture_type = match chain {
            TestChain::Custom { capture, .. } => capture,
            _ => &CaptureType::Dxgi,
        };
        let (capture, capture_width, capture_height): (Box<dyn FrameCapture>, usize, usize) =
            if use_shared_texture_capture {
                if !matches!(capture_type, CaptureType::Dxgi | CaptureType::Winrt) {
                    return Err(anyhow::anyhow!(
                        "D3D11 shared texture capture requires DXGI or WinRT capture"
                    ));
                }
                #[cfg(windows)]
                {
                    match capture_type {
                        CaptureType::Dxgi => {
                            let mut capture = create_dxgi_shared_texture_capture(config)?;
                            let (width, height) = select_pipeline_dimensions(
                                capture.width(),
                                capture.height(),
                                config,
                            );
                            capture.set_target_dimensions(width, height);
                            (Box::new(capture) as Box<dyn FrameCapture>, width, height)
                        }
                        CaptureType::Winrt => {
                            let mut capture = if config.input_source.as_deref() == Some("window") {
                                let hwnd = parse_window_handle(config.window_handle.as_deref())?;
                                WinrtCapture::from_window_handle_shared_texture(hwnd).map_err(
                                    |error| {
                                        anyhow::anyhow!(
                                            "WinRT shared window capture init failed: {error}"
                                        )
                                    },
                                )?
                            } else {
                                create_winrt_capture_for_display_ref(display_ref(config), true)?
                            };
                            let (width, height) = select_pipeline_dimensions(
                                capture.width(),
                                capture.height(),
                                config,
                            );
                            capture.set_target_dimensions(width, height);
                            capture.start().map_err(|error| {
                                anyhow::anyhow!("WinRT shared capture start failed: {error}")
                            })?;
                            (Box::new(capture) as Box<dyn FrameCapture>, width, height)
                        }
                        _ => unreachable!("shared texture capture type validated above"),
                    }
                }
                #[cfg(not(windows))]
                {
                    return Err(anyhow::anyhow!(
                        "D3D11 shared texture capture is only available on Windows"
                    ));
                }
            } else {
                match capture_type {
                    CaptureType::Dxgi => {
                        let capture = DxgiDesktopCapture::new_primary()
                            .map_err(|e| anyhow::anyhow!("DXGI capture init failed: {:?}", e))?;
                        let (width, height) =
                            select_pipeline_dimensions(capture.width(), capture.height(), config);
                        (Box::new(capture) as Box<dyn FrameCapture>, width, height)
                    }
                    CaptureType::Winrt => {
                        #[cfg(windows)]
                        {
                            let capture = if config.input_source.as_deref() == Some("window") {
                                let hwnd = parse_window_handle(config.window_handle.as_deref())?;
                                WinrtMonitorCapture::new_window(hwnd)?
                            } else {
                                WinrtMonitorCapture::new_display_ref(display_ref(config))?
                            };
                            let (width, height) = select_pipeline_dimensions(
                                capture.width(),
                                capture.height(),
                                config,
                            );
                            (Box::new(capture) as Box<dyn FrameCapture>, width, height)
                        }
                        #[cfg(not(windows))]
                        {
                            return Err(anyhow::anyhow!(
                                "WinRT capture is only available on Windows"
                            ));
                        }
                    }
                    CaptureType::Macos => {
                        #[cfg(target_os = "macos")]
                        {
                            let mut capture = if config.input_source.as_deref() == Some("window") {
                                let window_id =
                                    parse_window_handle(config.window_handle.as_deref())?;
                                let window_id = u32::try_from(window_id).map_err(|_| {
                                    anyhow::anyhow!("macOS window id out of range: {window_id}")
                                })?;
                                MacosScreenCapture::new_window(window_id).map_err(|e| {
                                    anyhow::anyhow!("macOS window capture init failed: {:?}", e)
                                })?
                            } else if let Some(display_id) = config.display_id.as_deref() {
                                let display_id = parse_display_id(display_id)?;
                                MacosScreenCapture::new_display_id(display_id).map_err(|e| {
                                    anyhow::anyhow!("macOS display capture init failed: {:?}", e)
                                })?
                            } else {
                                MacosScreenCapture::new_primary().map_err(|e| {
                                    anyhow::anyhow!("macOS capture init failed: {:?}", e)
                                })?
                            };
                            let (width, height) = select_pipeline_dimensions(
                                capture.width(),
                                capture.height(),
                                config,
                            );
                            capture.set_target_dimensions(width, height);
                            (Box::new(capture) as Box<dyn FrameCapture>, width, height)
                        }
                        #[cfg(not(target_os = "macos"))]
                        {
                            return Err(anyhow::anyhow!(
                                "macOS capture is only available on macOS"
                            ));
                        }
                    }
                    #[cfg(target_os = "linux")]
                    CaptureType::Linux => {
                        let mut capture = PipewireScreenCapture::new()
                            .map_err(|e| anyhow::anyhow!("Linux capture init failed: {:?}", e))?;
                        start_linux_capture_session(&mut capture)?;
                        let capture_dimensions = {
                            let (width, height) = capture.dimensions();
                            (width as usize, height as usize)
                        };
                        let (width, height) = config.resolution.unwrap_or(capture_dimensions);
                        (Box::new(capture) as Box<dyn FrameCapture>, width, height)
                    }
                    CaptureType::Synthetic => {
                        let (width, height) = config.resolution.unwrap_or((1280, 720));
                        (
                            Box::new(SyntheticCapture::new(width, height)) as Box<dyn FrameCapture>,
                            width,
                            height,
                        )
                    }
                }
            };

        let (width, height) = (capture_width, capture_height);
        let fps = config.fps.unwrap_or(60).max(1);
        let low_latency_bitrate = config.bitrate.unwrap_or(12_000_000).max(1);
        let speed_bitrate = config.bitrate.unwrap_or(5_000_000).max(1);
        let color_mode = resolved_color_mode(config);
        let color_pipeline = resolved_color_pipeline(chain, config);
        validate_chain_color_config(chain, color_mode, color_pipeline)?;
        let encoded_codec = match chain {
            TestChain::Custom {
                encoder: EncoderType::NvencAv1,
                ..
            } => VideoCodec::Av1,
            TestChain::Custom {
                encoder:
                    EncoderType::NvencHevc
                    | EncoderType::NvencHevcMain10
                    | EncoderType::VideoToolboxHevc,
                ..
            } => VideoCodec::Hevc,
            TestChain::Custom {
                encoder: EncoderType::SoftwareVvc,
                ..
            } => VideoCodec::Vvc,
            _ => VideoCodec::H264,
        };

        let renderer = config
            .renderer
            .as_ref()
            .map(|renderer_type| {
                PipelineRenderer::new(
                    renderer_type,
                    width,
                    height,
                    config.renderer_target_hwnd,
                    display_ref(config).map(str::to_string),
                    use_shared_texture_decode,
                )
            })
            .transpose()?;
        let renderer_d3d11_device_ptr = renderer
            .as_ref()
            .and_then(PipelineRenderer::d3d11_device_ptr);

        let (encoder, decoder, use_decoder) = match chain {
            TestChain::CaptureOnly => (None, None, false),
            TestChain::NvencNvdec => {
                let encoder = create_h264_encoder_for_hardware_decode(
                    width,
                    height,
                    fps,
                    low_latency_bitrate,
                    color_mode,
                )
                .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                let decoder =
                    create_h264_nvdec_decoder(use_shared_texture_decode, renderer_d3d11_device_ptr)
                        .map_err(|e| anyhow::anyhow!("NVDEC 解码器初始化失败: {e}"))?;
                (
                    Some(Box::new(encoder) as Box<dyn VideoEncoder>),
                    Some(PipelineDecoder::Nvdec(decoder)),
                    true,
                )
            }
            TestChain::NvencOnly => {
                let encoder =
                    NvencH264Encoder::new_max_speed_with_bitrate(width, height, fps, speed_bitrate)
                        .map(|encoder| encoder.with_color_mode(color_mode))
                        .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                (
                    Some(Box::new(encoder) as Box<dyn VideoEncoder>),
                    None,
                    false,
                )
            }
            TestChain::OpenH264 => {
                let encoder = OpenH264Encoder::new_with_bitrate(
                    width,
                    height,
                    fps,
                    resolved_openh264_bitrate(config.bitrate),
                )
                .map_err(|e| anyhow::anyhow!("OpenH264 编码器初始化失败: {:?}", e))?;
                (
                    Some(Box::new(encoder) as Box<dyn VideoEncoder>),
                    None,
                    false,
                )
            }
            #[cfg(target_os = "linux")]
            TestChain::LinuxOpenh264 => {
                let encoder = OpenH264Encoder::new_with_bitrate(
                    width,
                    height,
                    fps,
                    resolved_openh264_bitrate(config.bitrate),
                )
                .map_err(|e| anyhow::anyhow!("OpenH264 编码器初始化失败: {:?}", e))?;
                (
                    Some(Box::new(encoder) as Box<dyn VideoEncoder>),
                    None,
                    false,
                )
            }
            TestChain::Custom {
                capture: _,
                encoder,
                decoder,
            } => match encoder {
                EncoderType::None => {
                    if *decoder != DecoderType::None {
                        return Err(anyhow::anyhow!(
                            "decoder {:?} requires an encoder; use decoder=none for direct capture-render",
                            decoder
                        ));
                    }
                    (None, None, false)
                }
                EncoderType::NvencH264 => match decoder {
                    DecoderType::None => {
                        let enc = NvencH264Encoder::new_max_speed_with_bitrate(
                            width,
                            height,
                            fps,
                            speed_bitrate,
                        )
                        .map(|encoder| encoder.with_color_mode(color_mode))
                        .map_err(|e| anyhow::anyhow!("NVENC encoder init failed: {:?}", e))?;
                        (Some(Box::new(enc) as Box<dyn VideoEncoder>), None, false)
                    }
                    DecoderType::Nvdec => {
                        let enc = create_h264_encoder_for_hardware_decode(
                            width,
                            height,
                            fps,
                            low_latency_bitrate,
                            color_mode,
                        )
                        .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                        let dec = create_h264_nvdec_decoder(
                            use_shared_texture_decode,
                            renderer_d3d11_device_ptr,
                        )
                        .map_err(|e| anyhow::anyhow!("NVDEC 解码器初始化失败: {e}"))?;
                        (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(PipelineDecoder::Nvdec(dec)),
                            true,
                        )
                    }
                    DecoderType::Software => {
                        let enc = NvencH264Encoder::new_max_speed_with_bitrate(
                            width,
                            height,
                            fps,
                            speed_bitrate,
                        )
                        .map(|encoder| encoder.with_color_mode(color_mode))
                        .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                        let dec = mrd_decode::create_decoder("h264_software").map_err(|e| {
                            anyhow::anyhow!("software decoder init failed: {:?}", e)
                        })?;
                        (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(PipelineDecoder::Software(dec)),
                            true,
                        )
                    }
                    DecoderType::FfmpegH264 => {
                        let enc = NvencH264Encoder::new_max_speed_with_bitrate(
                            width,
                            height,
                            fps,
                            speed_bitrate,
                        )
                        .map(|encoder| encoder.with_color_mode(color_mode))
                        .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                        let dec = mrd_decode::create_decoder("ffmpeg_h264").map_err(|e| {
                            anyhow::anyhow!("FFmpeg H.264 decoder init failed: {:?}", e)
                        })?;
                        (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(PipelineDecoder::Software(dec)),
                            true,
                        )
                    }
                    DecoderType::FfmpegHevc => {
                        return Err(anyhow::anyhow!(
                            "FFmpeg HEVC decoder cannot decode H.264 output"
                        ));
                    }
                    DecoderType::FfmpegVvc => {
                        return Err(anyhow::anyhow!(
                            "FFmpeg VVC decoder cannot decode H.264 output"
                        ));
                    }
                    DecoderType::LinuxH264 => {
                        let enc = NvencH264Encoder::new_max_speed_with_bitrate(
                            width,
                            height,
                            fps,
                            speed_bitrate,
                        )
                        .map(|encoder| encoder.with_color_mode(color_mode))
                        .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                        (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(create_linux_h264_decoder()?),
                            true,
                        )
                    }
                    DecoderType::LinuxHevc | DecoderType::LinuxHevcMain10 => {
                        return Err(anyhow::anyhow!(
                            "Linux HEVC hardware decoder cannot decode NVENC H.264 output"
                        ));
                    }
                    DecoderType::VideoToolbox => {
                        let enc = NvencH264Encoder::new_max_speed_with_bitrate(
                            width,
                            height,
                            fps,
                            speed_bitrate,
                        )
                        .map(|encoder| encoder.with_color_mode(color_mode))
                        .map_err(|e| anyhow::anyhow!("NVENC 编码器初始化失败: {:?}", e))?;
                        (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(create_videotoolbox_h264_decoder()?),
                            true,
                        )
                    }
                },
                EncoderType::NvencHevc | EncoderType::NvencHevcMain10 => {
                    let main10 = matches!(encoder, EncoderType::NvencHevcMain10);
                    #[cfg(any(windows, target_os = "linux"))]
                    {
                        match decoder {
                            DecoderType::None => {
                                let enc = create_hevc_encoder(
                                    width,
                                    height,
                                    fps,
                                    speed_bitrate,
                                    main10,
                                    color_mode,
                                )?;
                                (Some(enc), None, false)
                            }
                            DecoderType::Nvdec => {
                                #[cfg(not(windows))]
                                {
                                    return Err(anyhow::anyhow!(
                                        "NVDEC HEVC decoder is not implemented on Linux yet"
                                    ));
                                }
                                #[cfg(windows)]
                                {
                                    let enc = create_hevc_encoder(
                                        width,
                                        height,
                                        fps,
                                        low_latency_bitrate,
                                        main10,
                                        color_mode,
                                    )?;
                                    let dec = create_hevc_nvdec_decoder(
                                        use_shared_texture_decode,
                                        renderer_d3d11_device_ptr,
                                        main10,
                                    )
                                    .map_err(|e| {
                                        anyhow::anyhow!("NVDEC HEVC decoder init failed: {e}")
                                    })?;
                                    (Some(enc), Some(PipelineDecoder::Nvdec(dec)), true)
                                }
                            }
                            DecoderType::Software => {
                                let enc = create_hevc_encoder(
                                    width,
                                    height,
                                    fps,
                                    speed_bitrate,
                                    main10,
                                    color_mode,
                                )?;
                                let decoder_id = if main10 {
                                    "software_hevc_main10"
                                } else {
                                    "software_hevc"
                                };
                                let dec = mrd_decode::create_decoder(decoder_id).map_err(|e| {
                                    anyhow::anyhow!("{decoder_id} decoder init failed: {:?}", e)
                                })?;
                                (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                            }
                            DecoderType::FfmpegHevc => {
                                let enc = create_hevc_encoder(
                                    width,
                                    height,
                                    fps,
                                    speed_bitrate,
                                    main10,
                                    color_mode,
                                )?;
                                let dec =
                                    mrd_decode::create_decoder("ffmpeg_hevc").map_err(|e| {
                                        anyhow::anyhow!("FFmpeg HEVC decoder init failed: {:?}", e)
                                    })?;
                                (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                            }
                            DecoderType::FfmpegH264 => {
                                return Err(anyhow::anyhow!(
                                    "FFmpeg H.264 decoder cannot decode NVENC HEVC output"
                                ));
                            }
                            DecoderType::FfmpegVvc => {
                                return Err(anyhow::anyhow!(
                                    "FFmpeg VVC decoder cannot decode NVENC HEVC output"
                                ));
                            }
                            DecoderType::LinuxH264 => {
                                return Err(anyhow::anyhow!(
                                    "Linux H.264 hardware decoder cannot decode NVENC HEVC output"
                                ));
                            }
                            DecoderType::LinuxHevc => {
                                if main10 {
                                    return Err(anyhow::anyhow!(
                                        "NVENC HEVC Main10 requires the Linux HEVC Main10 decoder path"
                                    ));
                                }
                                let enc = create_hevc_encoder(
                                    width,
                                    height,
                                    fps,
                                    low_latency_bitrate,
                                    main10,
                                    color_mode,
                                )?;
                                let dec = create_linux_hevc_decoder(false)?;
                                (Some(enc), Some(dec), true)
                            }
                            DecoderType::LinuxHevcMain10 => {
                                let enc = create_hevc_encoder(
                                    width,
                                    height,
                                    fps,
                                    low_latency_bitrate,
                                    main10,
                                    color_mode,
                                )?;
                                let dec = create_linux_hevc_decoder(true)?;
                                (Some(enc), Some(dec), true)
                            }
                            DecoderType::VideoToolbox => {
                                return Err(anyhow::anyhow!(
                                    "VideoToolbox H.264 decoder cannot decode NVENC HEVC output"
                                ));
                            }
                        }
                    }
                    #[cfg(not(any(windows, target_os = "linux")))]
                    {
                        let _ = main10;
                        return Err(anyhow::anyhow!(
                            "NVENC HEVC encoder is only available on Windows"
                        ));
                    }
                }
                EncoderType::OpenH264 => {
                    let enc = OpenH264Encoder::new_with_bitrate(
                        width,
                        height,
                        fps,
                        resolved_openh264_bitrate(config.bitrate),
                    )
                    .map_err(|e| anyhow::anyhow!("OpenH264 编码器初始化失败: {:?}", e))?;
                    match decoder {
                        DecoderType::None => {
                            (Some(Box::new(enc) as Box<dyn VideoEncoder>), None, false)
                        }
                        DecoderType::Nvdec => {
                            let dec = create_h264_nvdec_decoder(
                                use_shared_texture_decode,
                                renderer_d3d11_device_ptr,
                            )
                            .map_err(|e| anyhow::anyhow!("NVDEC decoder init failed: {e}"))?;
                            (
                                Some(Box::new(enc) as Box<dyn VideoEncoder>),
                                Some(PipelineDecoder::Nvdec(dec)),
                                true,
                            )
                        }
                        DecoderType::Software => {
                            let dec = mrd_decode::create_decoder("h264_software").map_err(|e| {
                                anyhow::anyhow!("software decoder init failed: {:?}", e)
                            })?;
                            (
                                Some(Box::new(enc) as Box<dyn VideoEncoder>),
                                Some(PipelineDecoder::Software(dec)),
                                true,
                            )
                        }
                        DecoderType::FfmpegH264 => {
                            let dec = mrd_decode::create_decoder("ffmpeg_h264").map_err(|e| {
                                anyhow::anyhow!("FFmpeg H.264 decoder init failed: {:?}", e)
                            })?;
                            (
                                Some(Box::new(enc) as Box<dyn VideoEncoder>),
                                Some(PipelineDecoder::Software(dec)),
                                true,
                            )
                        }
                        DecoderType::FfmpegHevc => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg HEVC decoder cannot decode OpenH264 output"
                            ));
                        }
                        DecoderType::FfmpegVvc => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg VVC decoder cannot decode OpenH264 output"
                            ));
                        }
                        DecoderType::LinuxH264 => (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(create_linux_h264_decoder()?),
                            true,
                        ),
                        DecoderType::LinuxHevc | DecoderType::LinuxHevcMain10 => {
                            return Err(anyhow::anyhow!(
                                "Linux HEVC hardware decoder cannot decode OpenH264 output"
                            ));
                        }
                        DecoderType::VideoToolbox => (
                            Some(Box::new(enc) as Box<dyn VideoEncoder>),
                            Some(create_videotoolbox_h264_decoder()?),
                            true,
                        ),
                    }
                }
                EncoderType::SoftwareVvc => {
                    let enc = create_vvenc_encoder(width, height, fps, speed_bitrate)?;
                    match decoder {
                        DecoderType::None => (Some(enc), None, false),
                        DecoderType::Software => {
                            let dec = mrd_decode::create_decoder("software_vvc").map_err(|e| {
                                anyhow::anyhow!("software_vvc decoder init failed: {:?}", e)
                            })?;
                            (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                        }
                        DecoderType::Nvdec => {
                            return Err(anyhow::anyhow!(
                                "NVDEC decoder cannot decode VVenC H.266/VVC output"
                            ));
                        }
                        DecoderType::FfmpegH264 => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg H.264 decoder cannot decode VVenC H.266/VVC output"
                            ));
                        }
                        DecoderType::FfmpegHevc => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg HEVC decoder cannot decode VVenC H.266/VVC output"
                            ));
                        }
                        DecoderType::FfmpegVvc => {
                            let dec = mrd_decode::create_decoder("ffmpeg_vvc").map_err(|e| {
                                anyhow::anyhow!("FFmpeg VVC decoder init failed: {:?}", e)
                            })?;
                            (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                        }
                        DecoderType::LinuxH264
                        | DecoderType::LinuxHevc
                        | DecoderType::LinuxHevcMain10 => {
                            return Err(anyhow::anyhow!(
                                "Linux hardware decoders cannot decode VVenC H.266/VVC output"
                            ));
                        }
                        DecoderType::VideoToolbox => {
                            return Err(anyhow::anyhow!(
                                "VideoToolbox decoder cannot decode VVenC H.266/VVC output"
                            ));
                        }
                    }
                }
                EncoderType::VideoToolboxH264 => {
                    let enc = create_videotoolbox_h264_encoder(
                        width,
                        height,
                        fps,
                        config.bitrate.unwrap_or(low_latency_bitrate),
                    )?;
                    match decoder {
                        DecoderType::None => (Some(enc), None, false),
                        DecoderType::Software => {
                            let dec = mrd_decode::create_decoder("h264_software").map_err(|e| {
                                anyhow::anyhow!("software decoder init failed: {:?}", e)
                            })?;
                            (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                        }
                        DecoderType::FfmpegH264 => {
                            let dec = mrd_decode::create_decoder("ffmpeg_h264").map_err(|e| {
                                anyhow::anyhow!("FFmpeg H.264 decoder init failed: {:?}", e)
                            })?;
                            (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                        }
                        DecoderType::FfmpegHevc => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg HEVC decoder cannot decode VideoToolbox H.264 output"
                            ));
                        }
                        DecoderType::FfmpegVvc => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg VVC decoder cannot decode VideoToolbox H.264 output"
                            ));
                        }
                        DecoderType::VideoToolbox => {
                            (Some(enc), Some(create_videotoolbox_h264_decoder()?), true)
                        }
                        DecoderType::LinuxH264 => {
                            (Some(enc), Some(create_linux_h264_decoder()?), true)
                        }
                        DecoderType::LinuxHevc | DecoderType::LinuxHevcMain10 => {
                            return Err(anyhow::anyhow!(
                                "Linux HEVC hardware decoder cannot decode VideoToolbox H.264 output"
                            ));
                        }
                        DecoderType::Nvdec => {
                            return Err(anyhow::anyhow!(
                                "VideoToolbox encoder with NVDEC decoder is not a macOS-native path"
                            ));
                        }
                    }
                }
                EncoderType::VideoToolboxHevc => {
                    let enc = create_videotoolbox_hevc_encoder(
                        width,
                        height,
                        fps,
                        config.bitrate.unwrap_or(low_latency_bitrate),
                    )?;
                    match decoder {
                        DecoderType::None => (Some(enc), None, false),
                        DecoderType::Software => {
                            let dec = mrd_decode::create_decoder("software_hevc").map_err(|e| {
                                anyhow::anyhow!("software HEVC decoder init failed: {:?}", e)
                            })?;
                            (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                        }
                        DecoderType::FfmpegHevc => {
                            let dec = mrd_decode::create_decoder("ffmpeg_hevc").map_err(|e| {
                                anyhow::anyhow!("FFmpeg HEVC decoder init failed: {:?}", e)
                            })?;
                            (Some(enc), Some(PipelineDecoder::Software(dec)), true)
                        }
                        DecoderType::FfmpegH264 => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg H.264 decoder cannot decode VideoToolbox HEVC output"
                            ));
                        }
                        DecoderType::FfmpegVvc => {
                            return Err(anyhow::anyhow!(
                                "FFmpeg VVC decoder cannot decode VideoToolbox HEVC output"
                            ));
                        }
                        DecoderType::VideoToolbox => {
                            (Some(enc), Some(create_videotoolbox_hevc_decoder()?), true)
                        }
                        DecoderType::LinuxH264 => {
                            return Err(anyhow::anyhow!(
                                "Linux H.264 hardware decoder cannot decode VideoToolbox HEVC output"
                            ));
                        }
                        DecoderType::LinuxHevc | DecoderType::LinuxHevcMain10 => {
                            return Err(anyhow::anyhow!(
                                "Linux HEVC hardware decode is not a macOS VideoToolbox local path"
                            ));
                        }
                        DecoderType::Nvdec => {
                            return Err(anyhow::anyhow!(
                                "VideoToolbox HEVC encoder with NVDEC decoder is not a macOS-native path"
                            ));
                        }
                    }
                }
                EncoderType::NvencAv1 => {
                    #[cfg(any(windows, target_os = "linux"))]
                    {
                        let mode = configured_nvenc_av1_mode();
                        let enc = match mode {
                            NvencAv1Mode::LowLatency => {
                                NvencAv1Encoder::new_low_latency_with_bitrate(
                                    width,
                                    height,
                                    fps,
                                    low_latency_bitrate,
                                )
                            }
                            NvencAv1Mode::UltraLowLatency => {
                                NvencAv1Encoder::new_ultra_low_latency_with_bitrate(
                                    width,
                                    height,
                                    fps,
                                    low_latency_bitrate,
                                )
                            }
                            NvencAv1Mode::HighRefresh => {
                                NvencAv1Encoder::new_high_refresh_rate_with_bitrate(
                                    width,
                                    height,
                                    fps,
                                    low_latency_bitrate,
                                )
                            }
                        }
                        .map_err(|e| anyhow::anyhow!("NVENC AV1 encoder init failed: {:?}", e))?;
                        match decoder {
                            DecoderType::None => {
                                (Some(Box::new(enc) as Box<dyn VideoEncoder>), None, false)
                            }
                            DecoderType::Nvdec => {
                                #[cfg(not(windows))]
                                {
                                    return Err(anyhow::anyhow!(
                                        "NVDEC AV1 decoder is not implemented on Linux yet"
                                    ));
                                }
                                #[cfg(windows)]
                                {
                                    let dec = create_av1_nvdec_decoder(
                                        use_shared_texture_decode,
                                        renderer_d3d11_device_ptr,
                                    )
                                    .map_err(|e| {
                                        anyhow::anyhow!("NVDEC AV1 decoder init failed: {e}")
                                    })?;
                                    (
                                        Some(Box::new(enc) as Box<dyn VideoEncoder>),
                                        Some(PipelineDecoder::Nvdec(dec)),
                                        true,
                                    )
                                }
                            }
                            DecoderType::Software => {
                                let dec =
                                    mrd_decode::create_decoder("software_av1").map_err(|e| {
                                        anyhow::anyhow!("software_av1 decoder init failed: {:?}", e)
                                    })?;
                                (
                                    Some(Box::new(enc) as Box<dyn VideoEncoder>),
                                    Some(PipelineDecoder::Software(dec)),
                                    true,
                                )
                            }
                            DecoderType::FfmpegH264 => {
                                return Err(anyhow::anyhow!(
                                    "FFmpeg H.264 decoder cannot decode NVENC AV1 output"
                                ));
                            }
                            DecoderType::FfmpegHevc => {
                                return Err(anyhow::anyhow!(
                                    "FFmpeg HEVC decoder cannot decode NVENC AV1 output"
                                ));
                            }
                            DecoderType::FfmpegVvc => {
                                return Err(anyhow::anyhow!(
                                    "FFmpeg VVC decoder cannot decode NVENC AV1 output"
                                ));
                            }
                            DecoderType::LinuxH264 => {
                                return Err(anyhow::anyhow!(
                                    "Linux H.264 hardware decoder cannot decode NVENC AV1 output"
                                ));
                            }
                            DecoderType::LinuxHevc | DecoderType::LinuxHevcMain10 => {
                                return Err(anyhow::anyhow!(
                                    "Linux HEVC hardware decoder cannot decode NVENC AV1 output"
                                ));
                            }
                            DecoderType::VideoToolbox => {
                                return Err(anyhow::anyhow!(
                                    "VideoToolbox H.264 decoder cannot decode NVENC AV1 output"
                                ));
                            }
                        }
                    }
                    #[cfg(not(any(windows, target_os = "linux")))]
                    {
                        return Err(anyhow::anyhow!(
                            "NVENC AV1 encoder is only available on Windows"
                        ));
                    }
                }
            },
        };

        let transport = PipelineTransport::new(config.transport.as_ref(), fps, encoded_codec)?;

        Ok(PipelineState {
            capture,
            encoder,
            transport,
            decoder,
            renderer,
            use_decoder,
            visual_preview: config.visual_preview.unwrap_or(true),
            pace_to_fps: config.pace_to_fps.unwrap_or(false),
            fps,
            width,
            height,
            adapted_frame: None,
        })
    }

    fn process_loop(
        mut state: PipelineState,
        frame_buffer: Arc<Mutex<FrameBuffer>>,
        metrics: Arc<Mutex<HarnessMetrics>>,
        encoded_subscribers: Arc<Mutex<Vec<mpsc::SyncSender<Vec<EncodedAccessUnit>>>>>,
        latest_keyframe_access_units: Arc<Mutex<Option<Vec<EncodedAccessUnit>>>>,
        running: Arc<AtomicBool>,
    ) {
        let start_time = Instant::now();
        let mut capture_latencies = Vec::with_capacity(1000);
        let mut interactive_latencies = Vec::with_capacity(1000);
        let mut encode_latencies = Vec::with_capacity(1000);
        let mut transport_latencies = Vec::with_capacity(1000);
        let mut decode_latencies = Vec::with_capacity(1000);
        let mut render_latencies = Vec::with_capacity(1000);
        let mut render_submit_wait_latencies = Vec::with_capacity(1000);
        let mut render_execute_latencies = Vec::with_capacity(1000);
        let mut render_prepare_wait_latencies = Vec::with_capacity(1000);
        let mut render_shared_resource_latencies = Vec::with_capacity(1000);
        let mut render_draw_present_latencies = Vec::with_capacity(1000);
        let mut render_present_gaps = Vec::with_capacity(1000);
        let mut total_latencies = Vec::with_capacity(1000);
        let mut render_pacing = RenderPacingCounters::default();
        let mut nvdec_shared_copy_stats = NvdecSharedCopyStats::default();
        let mut last_render_snapshot = None::<RendererSnapshot>;
        let mut last_render_present_at = None::<Instant>;
        let mut frame_count = 0_usize;
        let mut dropped_frames = 0_usize;
        let mut encoded_units_total = 0_usize;
        let mut decoded_frames_total = 0_usize;
        let mut encode_failures = 0_usize;
        let mut decode_failures = 0_usize;
        let mut total_bitstream_bytes = 0_usize;
        let mut last_decode_error = None::<String>;
        let mut last_capture_success = Instant::now();
        let mut reported_first_decoded_frame = false;
        let dump_first_access_unit_path = std::env::var("MRD_HARNESS_DUMP_FIRST_ACCESS_UNIT").ok();
        let mut dumped_first_access_unit = false;
        let update_web_preview = state.visual_preview;
        let frame_period = if state.pace_to_fps {
            Some(Duration::from_secs_f64(1.0 / state.fps.max(1) as f64))
        } else {
            None
        };
        let mut next_frame_at = Instant::now();
        let mut render_scheduler = match state.renderer.take() {
            Some(renderer) => match LatestRenderScheduler::new(renderer) {
                Ok(scheduler) => Some(scheduler),
                Err(error) => {
                    let mut m = metrics.lock().unwrap();
                    m.error_message = Some(error.to_string());
                    m.is_running = false;
                    running.store(false, Ordering::Relaxed);
                    return;
                }
            },
            None => None,
        };

        while running.load(Ordering::Relaxed) {
            if let Some(scheduler) = render_scheduler.as_ref() {
                if let Err(error) = Self::drain_render_completions(
                    scheduler,
                    &mut render_pacing,
                    &mut render_latencies,
                    &mut render_submit_wait_latencies,
                    &mut render_execute_latencies,
                    &mut render_prepare_wait_latencies,
                    &mut render_shared_resource_latencies,
                    &mut render_draw_present_latencies,
                    &mut render_present_gaps,
                    &mut last_render_snapshot,
                    &mut last_render_present_at,
                ) {
                    let mut m = metrics.lock().unwrap();
                    m.error_message = Some(error.to_string());
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            }

            if let Some(period) = frame_period {
                let now = Instant::now();
                if now < next_frame_at {
                    thread::sleep(next_frame_at - now);
                }
                next_frame_at = next_frame_at
                    .checked_add(period)
                    .unwrap_or_else(Instant::now);
                if next_frame_at < Instant::now() {
                    next_frame_at = Instant::now() + period;
                }
            }

            let pipeline_start = Instant::now();
            let next_frame_count = frame_count + 1;
            let preview_due =
                update_web_preview && next_frame_count % WEB_PREVIEW_FRAME_UPDATE_INTERVAL == 0;

            let capture_start = Instant::now();
            let captured_frame = match state.capture.capture_frame() {
                Ok(frame) => frame,
                Err(error) => {
                    dropped_frames += 1;
                    if last_capture_success.elapsed()
                        >= Duration::from_millis(CAPTURE_NO_FRAME_TIMEOUT_MS)
                    {
                        let message = format!(
                            "capture failed: {error}; no frames produced for {:.1}s",
                            last_capture_success.elapsed().as_secs_f64()
                        );
                        let mut m = metrics.lock().unwrap();
                        m.error_message = Some(message);
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
            };
            last_capture_success = Instant::now();
            let capture_latency = capture_start.elapsed();
            let interactive_start = Instant::now();

            let (encoded_units, encode_latency) = if let Some(encoder) = state.encoder.as_mut() {
                let frame_for_encode = prepare_frame_for_encode(
                    &captured_frame,
                    state.width,
                    state.height,
                    &mut state.adapted_frame,
                );
                let encode_start = Instant::now();
                let mut encoded_units = match encoder.encode(frame_for_encode) {
                    Ok(units) => units,
                    Err(error) => {
                        encode_failures += 1;
                        dropped_frames += 1;
                        {
                            let mut m = metrics.lock().unwrap();
                            m.error_message = Some(format!("encode failed: {error}"));
                        }
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                };
                let encoded_unit_count = encoded_units.len();
                encoded_units.retain(|unit| !unit.bytes.is_empty());
                dropped_frames += encoded_unit_count.saturating_sub(encoded_units.len());
                encoded_units_total += encoded_units.len();
                total_bitstream_bytes += encoded_units
                    .iter()
                    .map(|unit| unit.bytes.len())
                    .sum::<usize>();
                if !dumped_first_access_unit {
                    if let (Some(path), Some(unit)) =
                        (dump_first_access_unit_path.as_ref(), encoded_units.first())
                    {
                        let _ = std::fs::write(path, &unit.bytes);
                        dumped_first_access_unit = true;
                    }
                }
                (encoded_units, Some(encode_start.elapsed()))
            } else {
                (Vec::new(), None)
            };

            let (transported_units, transport_latency) = if encoded_units.is_empty() {
                (encoded_units, None)
            } else {
                Self::broadcast_encoded_access_units(
                    &encoded_subscribers,
                    &latest_keyframe_access_units,
                    &encoded_units,
                );
                let transport_start = Instant::now();
                match state.transport.transmit(encoded_units) {
                    Ok(units) => (units, Some(transport_start.elapsed())),
                    Err(error) => {
                        let mut m = metrics.lock().unwrap();
                        m.error_message = Some(error.to_string());
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            };

            // Decode if needed
            let mut decoded_frames = Vec::new();
            let decode_latency = if state.use_decoder && !transported_units.is_empty() {
                if let Some(decoder) = state.decoder.as_mut() {
                    let decode_start = Instant::now();
                    let mut pushed_any = false;
                    let mut failed_units = 0_usize;
                    for unit in &transported_units {
                        match decoder.push_access_unit(&unit.bytes) {
                            Ok(()) => {
                                pushed_any = true;
                                decoded_frames = decoder.drain_decoded_frames();
                                decoded_frames_total += decoded_frames.len();
                                if !decoded_frames.is_empty() {
                                    break;
                                }
                            }
                            Err(error) => {
                                let message = error.to_string();
                                if last_decode_error.as_deref() != Some(message.as_str()) {
                                    last_decode_error = Some(message.clone());
                                    let mut m = metrics.lock().unwrap();
                                    m.error_message = Some(format!("decode failed: {message}"));
                                }
                                failed_units += 1;
                            }
                        }
                    }
                    decode_failures += failed_units;

                    if !pushed_any {
                        if failed_units > 0 {
                            dropped_frames += 1;
                            Some(decode_start.elapsed())
                        } else {
                            None
                        }
                    } else {
                        Some(decode_start.elapsed())
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(decoder) = state.decoder.as_ref() {
                if let Some(stats) = decoder.nvdec_shared_copy_stats() {
                    nvdec_shared_copy_stats = stats;
                }
            }

            let should_prepare_render_input = render_scheduler.is_some() || preview_due;
            let render_input = if should_prepare_render_input {
                decoded_frames
                    .last()
                    .cloned()
                    .map(RenderInput::Decoded)
                    .or_else(|| {
                        if state.use_decoder {
                            None
                        } else {
                            let frame_for_render = prepare_captured_frame_for_direct_render(
                                &captured_frame,
                                state.width,
                                state.height,
                                &mut state.adapted_frame,
                            );
                            Some(RenderInput::Captured(frame_for_render.clone()))
                        }
                    })
            } else {
                None
            };
            let render_preview_input = render_preview_input_for_frame(&render_input, preview_due);

            if let (Some(scheduler), Some(input)) = (render_scheduler.as_ref(), render_input) {
                render_pacing.submitted_frames = render_pacing.submitted_frames.saturating_add(1);
                let submit = scheduler.submit_latest(input);
                if submit.replaced_pending {
                    render_pacing.queue_replacements =
                        render_pacing.queue_replacements.saturating_add(1);
                    render_pacing.stale_frame_drops =
                        render_pacing.stale_frame_drops.saturating_add(1);
                }

                if let Err(error) = Self::drain_render_completions(
                    scheduler,
                    &mut render_pacing,
                    &mut render_latencies,
                    &mut render_submit_wait_latencies,
                    &mut render_execute_latencies,
                    &mut render_prepare_wait_latencies,
                    &mut render_shared_resource_latencies,
                    &mut render_draw_present_latencies,
                    &mut render_present_gaps,
                    &mut last_render_snapshot,
                    &mut last_render_present_at,
                ) {
                    let mut m = metrics.lock().unwrap();
                    m.error_message = Some(error.to_string());
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            }
            let interactive_latency = interactive_start.elapsed();

            capture_latencies.push(capture_latency);
            interactive_latencies.push(interactive_latency);
            if let Some(latency) = encode_latency {
                encode_latencies.push(latency);
            }
            if let Some(latency) = transport_latency {
                transport_latencies.push(latency);
            }
            if let Some(latency) = decode_latency {
                decode_latencies.push(latency);
            }
            total_latencies.push(pipeline_start.elapsed());

            Self::trim_latency_buffers(
                &mut capture_latencies,
                &mut interactive_latencies,
                &mut encode_latencies,
                &mut transport_latencies,
                &mut decode_latencies,
                &mut render_latencies,
                &mut render_submit_wait_latencies,
                &mut render_execute_latencies,
                &mut render_prepare_wait_latencies,
                &mut render_shared_resource_latencies,
                &mut render_draw_present_latencies,
                &mut render_present_gaps,
                &mut total_latencies,
            );

            frame_count += 1;

            if preview_due && !captured_frame.data.is_empty() {
                if let Ok((captured_ds, ds_width, ds_height)) =
                    downsample_frame(&captured_frame, WEB_PREVIEW_MAX_WIDTH)
                {
                    let mut buf = frame_buffer.lock().unwrap();
                    buf.captured = Some(captured_ds);
                    buf.captured_width = ds_width;
                    buf.captured_height = ds_height;
                    buf.captured_generation = buf.captured_generation.saturating_add(1);
                }
            }
            if preview_due {
                if let Some(input) = render_preview_input {
                    if let Ok((rendered_ds, ds_width, ds_height)) =
                        render_input_to_preview_bgra(input, WEB_PREVIEW_MAX_WIDTH)
                    {
                        let mut buf = frame_buffer.lock().unwrap();
                        buf.rendered = Some(rendered_ds);
                        buf.rendered_width = ds_width;
                        buf.rendered_height = ds_height;
                        buf.rendered_generation = buf.rendered_generation.saturating_add(1);
                    }
                }
            }

            let should_publish_metrics = frame_count == 1
                || frame_count % 30 == 0
                || (!reported_first_decoded_frame && decoded_frames_total > 0);
            if should_publish_metrics {
                Self::update_metrics(
                    &metrics,
                    frame_count,
                    dropped_frames,
                    encoded_units_total,
                    decoded_frames_total,
                    encode_failures,
                    decode_failures,
                    total_bitstream_bytes,
                    &start_time,
                    &capture_latencies,
                    &interactive_latencies,
                    &encode_latencies,
                    &transport_latencies,
                    &decode_latencies,
                    &render_latencies,
                    &render_submit_wait_latencies,
                    &render_execute_latencies,
                    &render_prepare_wait_latencies,
                    &render_shared_resource_latencies,
                    &render_draw_present_latencies,
                    &render_present_gaps,
                    render_pacing.clone(),
                    nvdec_shared_copy_stats.clone(),
                    &total_latencies,
                );
                if decoded_frames_total > 0 {
                    reported_first_decoded_frame = true;
                }
            }
        }

        let retained_renderer = if let Some(scheduler) = render_scheduler.as_mut() {
            if let Err(error) = Self::stop_render_scheduler_and_drain(
                scheduler,
                &mut render_pacing,
                &mut render_latencies,
                &mut render_submit_wait_latencies,
                &mut render_execute_latencies,
                &mut render_prepare_wait_latencies,
                &mut render_shared_resource_latencies,
                &mut render_draw_present_latencies,
                &mut render_present_gaps,
                &mut last_render_snapshot,
                &mut last_render_present_at,
            ) {
                let mut m = metrics.lock().unwrap();
                m.error_message = Some(error.to_string());
            }
            match scheduler.shutdown_and_take_renderer() {
                Ok(renderer) => renderer,
                Err(error) => {
                    let mut m = metrics.lock().unwrap();
                    m.error_message = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };

        // NVDEC shared-texture decoders borrow the renderer's D3D11 device.
        // Destroy the decoder while the returned renderer still owns that
        // device, then release the renderer and device last.
        drop(state.decoder.take());
        drop(retained_renderer);

        Self::update_metrics(
            &metrics,
            frame_count,
            dropped_frames,
            encoded_units_total,
            decoded_frames_total,
            encode_failures,
            decode_failures,
            total_bitstream_bytes,
            &start_time,
            &capture_latencies,
            &interactive_latencies,
            &encode_latencies,
            &transport_latencies,
            &decode_latencies,
            &render_latencies,
            &render_submit_wait_latencies,
            &render_execute_latencies,
            &render_prepare_wait_latencies,
            &render_shared_resource_latencies,
            &render_draw_present_latencies,
            &render_present_gaps,
            render_pacing.clone(),
            nvdec_shared_copy_stats,
            &total_latencies,
        );

        let mut m = metrics.lock().unwrap();
        m.is_running = false;
    }

    fn update_metrics(
        metrics: &Arc<Mutex<HarnessMetrics>>,
        frame_count: usize,
        dropped_frames: usize,
        encoded_units: usize,
        decoded_frames: usize,
        encode_failures: usize,
        decode_failures: usize,
        total_bitstream_bytes: usize,
        start_time: &Instant,
        capture_latencies: &[Duration],
        interactive_latencies: &[Duration],
        encode_latencies: &[Duration],
        transport_latencies: &[Duration],
        decode_latencies: &[Duration],
        render_latencies: &[Duration],
        render_submit_wait_latencies: &[Duration],
        render_execute_latencies: &[Duration],
        render_prepare_wait_latencies: &[Duration],
        render_shared_resource_latencies: &[Duration],
        render_draw_present_latencies: &[Duration],
        render_present_gaps: &[Duration],
        render_pacing: RenderPacingCounters,
        nvdec_shared_copy_stats: NvdecSharedCopyStats,
        total_latencies: &[Duration],
    ) {
        let elapsed = start_time.elapsed().as_secs_f64();
        let fps = if elapsed > 0.0 {
            frame_count as f64 / elapsed
        } else {
            0.0
        };
        let encoded_fps = if elapsed > 0.0 {
            encoded_units as f64 / elapsed
        } else {
            0.0
        };
        let decoded_fps = if elapsed > 0.0 {
            decoded_frames as f64 / elapsed
        } else {
            0.0
        };

        let avg_cap = Self::compute_average(capture_latencies);
        let (p50_cap, p95_cap) = Self::compute_percentiles(capture_latencies);
        let avg_interactive = Self::compute_average(interactive_latencies);
        let (p50_interactive, p95_interactive) = Self::compute_percentiles(interactive_latencies);
        let avg_enc = Self::compute_average(encode_latencies);
        let (p50_enc, p95_enc) = Self::compute_percentiles(encode_latencies);
        let avg_transport = Self::compute_average(transport_latencies);
        let (p50_transport, p95_transport) = Self::compute_percentiles(transport_latencies);
        let avg_dec = Self::compute_average(decode_latencies);
        let (p50_dec, p95_dec) = Self::compute_percentiles(decode_latencies);
        let avg_render = Self::compute_average(render_latencies);
        let (p50_render, p95_render) = Self::compute_percentiles(render_latencies);
        let avg_render_submit_wait = Self::compute_average(render_submit_wait_latencies);
        let (p50_render_submit_wait, p95_render_submit_wait) =
            Self::compute_percentiles(render_submit_wait_latencies);
        let avg_render_execute = Self::compute_average(render_execute_latencies);
        let (p50_render_execute, p95_render_execute) =
            Self::compute_percentiles(render_execute_latencies);
        let avg_render_prepare_wait = Self::compute_average(render_prepare_wait_latencies);
        let (p50_render_prepare_wait, p95_render_prepare_wait) =
            Self::compute_percentiles(render_prepare_wait_latencies);
        let avg_render_shared_resource = Self::compute_average(render_shared_resource_latencies);
        let (p50_render_shared_resource, p95_render_shared_resource) =
            Self::compute_percentiles(render_shared_resource_latencies);
        let avg_render_draw_present = Self::compute_average(render_draw_present_latencies);
        let (p50_render_draw_present, p95_render_draw_present) =
            Self::compute_percentiles(render_draw_present_latencies);
        let avg_present_gap = Self::compute_average(render_present_gaps);
        let (p50_present_gap, p95_present_gap) = Self::compute_percentiles(render_present_gaps);
        let avg_total = Self::compute_average(total_latencies);
        let (p50_total, p95_total) = Self::compute_percentiles(total_latencies);

        let mut m = metrics.lock().unwrap();
        m.capture_fps = fps;
        m.encoded_fps = encoded_fps;
        m.decoded_fps = decoded_fps;
        m.frame_count = frame_count;
        m.encoded_units = encoded_units;
        m.decoded_frames = decoded_frames;
        m.encode_failures = encode_failures;
        m.decode_failures = decode_failures;
        m.total_bitstream_bytes = total_bitstream_bytes;
        m.dropped_frames = dropped_frames;
        m.capture_latency_avg_ms = avg_cap.as_secs_f64() * 1000.0;
        m.capture_latency_p50_ms = p50_cap.as_secs_f64() * 1000.0;
        m.capture_latency_p95_ms = p95_cap.as_secs_f64() * 1000.0;
        m.source_wait_latency_avg_ms = m.capture_latency_avg_ms;
        m.source_wait_latency_p50_ms = m.capture_latency_p50_ms;
        m.source_wait_latency_p95_ms = m.capture_latency_p95_ms;
        m.interactive_latency_avg_ms = avg_interactive.as_secs_f64() * 1000.0;
        m.interactive_latency_p50_ms = p50_interactive.as_secs_f64() * 1000.0;
        m.interactive_latency_p95_ms = p95_interactive.as_secs_f64() * 1000.0;
        m.encode_latency_avg_ms = avg_enc.as_secs_f64() * 1000.0;
        m.encode_latency_p50_ms = p50_enc.as_secs_f64() * 1000.0;
        m.encode_latency_p95_ms = p95_enc.as_secs_f64() * 1000.0;
        m.transport_latency_avg_ms = avg_transport.as_secs_f64() * 1000.0;
        m.transport_latency_p50_ms = p50_transport.as_secs_f64() * 1000.0;
        m.transport_latency_p95_ms = p95_transport.as_secs_f64() * 1000.0;
        m.decode_latency_avg_ms = avg_dec.as_secs_f64() * 1000.0;
        m.decode_latency_p50_ms = p50_dec.as_secs_f64() * 1000.0;
        m.decode_latency_p95_ms = p95_dec.as_secs_f64() * 1000.0;
        m.render_latency_avg_ms = avg_render.as_secs_f64() * 1000.0;
        m.render_latency_p50_ms = p50_render.as_secs_f64() * 1000.0;
        m.render_latency_p95_ms = p95_render.as_secs_f64() * 1000.0;
        m.render_submit_wait_latency_avg_ms = avg_render_submit_wait.as_secs_f64() * 1000.0;
        m.render_submit_wait_latency_p50_ms = p50_render_submit_wait.as_secs_f64() * 1000.0;
        m.render_submit_wait_latency_p95_ms = p95_render_submit_wait.as_secs_f64() * 1000.0;
        m.render_execute_latency_avg_ms = avg_render_execute.as_secs_f64() * 1000.0;
        m.render_execute_latency_p50_ms = p50_render_execute.as_secs_f64() * 1000.0;
        m.render_execute_latency_p95_ms = p95_render_execute.as_secs_f64() * 1000.0;
        m.render_prepare_wait_latency_avg_ms = avg_render_prepare_wait.as_secs_f64() * 1000.0;
        m.render_prepare_wait_latency_p50_ms = p50_render_prepare_wait.as_secs_f64() * 1000.0;
        m.render_prepare_wait_latency_p95_ms = p95_render_prepare_wait.as_secs_f64() * 1000.0;
        m.render_shared_resource_latency_avg_ms = avg_render_shared_resource.as_secs_f64() * 1000.0;
        m.render_shared_resource_latency_p50_ms = p50_render_shared_resource.as_secs_f64() * 1000.0;
        m.render_shared_resource_latency_p95_ms = p95_render_shared_resource.as_secs_f64() * 1000.0;
        m.render_draw_present_latency_avg_ms = avg_render_draw_present.as_secs_f64() * 1000.0;
        m.render_draw_present_latency_p50_ms = p50_render_draw_present.as_secs_f64() * 1000.0;
        m.render_draw_present_latency_p95_ms = p95_render_draw_present.as_secs_f64() * 1000.0;
        m.render_submitted_frames = render_pacing.submitted_frames;
        m.render_uploaded_frames = render_pacing.uploaded_frames;
        m.render_presented_frames = render_pacing.presented_frames;
        m.render_present_skipped_frames = render_pacing.present_skipped_frames;
        m.render_queue_replacements = render_pacing.queue_replacements;
        m.render_stale_frame_drops = render_pacing.stale_frame_drops;
        m.swap_chain_max_frame_latency = render_pacing.swap_chain_max_frame_latency;
        m.swap_chain_allow_tearing = render_pacing.swap_chain_allow_tearing;
        m.swap_chain_waitable_object = render_pacing.swap_chain_waitable_object;
        m.swap_chain_present_mode = render_pacing.swap_chain_present_mode;
        m.display_refresh_hz = render_pacing.display_refresh_hz;
        m.render_thread_priority = render_pacing.render_thread_priority;
        m.render_pixel_format = render_pacing.render_pixel_format;
        m.nvdec_shared_copy_attempts = nvdec_shared_copy_stats.attempts;
        m.nvdec_shared_copy_successes = nvdec_shared_copy_stats.successes;
        m.nvdec_shared_copy_failures = nvdec_shared_copy_stats.failures;
        m.nvdec_shared_copy_last_stage = nvdec_shared_copy_stats.last_stage;
        m.nvdec_shared_copy_last_api = nvdec_shared_copy_stats.last_api;
        m.nvdec_shared_copy_last_error = nvdec_shared_copy_stats.last_error;
        m.render_present_gap_avg_ms = avg_present_gap.as_secs_f64() * 1000.0;
        m.render_present_gap_p50_ms = p50_present_gap.as_secs_f64() * 1000.0;
        m.render_present_gap_p95_ms = p95_present_gap.as_secs_f64() * 1000.0;
        m.render_present_intervals_ms = render_present_gaps
            .iter()
            .map(|gap| gap.as_secs_f64() * 1_000.0)
            .collect();
        m.present_latency_avg_ms = m.render_present_gap_avg_ms;
        m.total_latency_avg_ms = avg_total.as_secs_f64() * 1000.0;
        m.total_latency_p50_ms = p50_total.as_secs_f64() * 1000.0;
        m.total_latency_p95_ms = p95_total.as_secs_f64() * 1000.0;
    }

    fn record_render_completion(
        render_pacing: &mut RenderPacingCounters,
        render_present_gaps: &mut Vec<Duration>,
        last_render_present_at: &mut Option<Instant>,
        previous_snapshot: Option<&RendererSnapshot>,
        current_snapshot: &RendererSnapshot,
        completed_at: Instant,
        present_events: &[mrd_render::RendererPresentEvent],
    ) {
        render_pacing.uploaded_frames = current_snapshot.uploaded_frame_count;
        render_pacing.presented_frames = current_snapshot.presented_frame_count;
        render_pacing.present_skipped_frames = current_snapshot.present_skipped_count;
        render_pacing.swap_chain_max_frame_latency = current_snapshot.swap_chain_max_frame_latency;
        render_pacing.swap_chain_allow_tearing = current_snapshot.swap_chain_allow_tearing;
        render_pacing.swap_chain_waitable_object = current_snapshot.swap_chain_waitable_object;
        render_pacing.swap_chain_present_mode = current_snapshot.swap_chain_present_mode.clone();
        render_pacing.display_refresh_hz = current_snapshot.display_refresh_hz;
        render_pacing.render_thread_priority = current_snapshot.render_thread_priority.clone();
        render_pacing.render_pixel_format = current_snapshot
            .last_pixel_format
            .map(render_pixel_format_label);

        let previous_presented = previous_snapshot
            .map(|snapshot| snapshot.presented_frame_count)
            .unwrap_or_default();
        if current_snapshot.presented_frame_count > previous_presented {
            let actual_presented_at = present_events
                .last()
                .map(|event| event.presented_at)
                .unwrap_or(completed_at);
            if let Some(last_present_at) = *last_render_present_at {
                render_present_gaps
                    .push(actual_presented_at.saturating_duration_since(last_present_at));
            }
            *last_render_present_at = Some(actual_presented_at);
        }
    }

    fn drain_render_completions(
        scheduler: &LatestRenderScheduler,
        render_pacing: &mut RenderPacingCounters,
        render_latencies: &mut Vec<Duration>,
        render_submit_wait_latencies: &mut Vec<Duration>,
        render_execute_latencies: &mut Vec<Duration>,
        render_prepare_wait_latencies: &mut Vec<Duration>,
        render_shared_resource_latencies: &mut Vec<Duration>,
        render_draw_present_latencies: &mut Vec<Duration>,
        render_present_gaps: &mut Vec<Duration>,
        last_render_snapshot: &mut Option<RendererSnapshot>,
        last_render_present_at: &mut Option<Instant>,
    ) -> Result<usize> {
        let mut drained = 0;
        while let Some(completion) = scheduler.try_recv_completion()? {
            drained += 1;
            match completion.result {
                Ok(render_completion) => {
                    let previous_snapshot = last_render_snapshot.clone();
                    Self::record_render_completion(
                        render_pacing,
                        render_present_gaps,
                        last_render_present_at,
                        previous_snapshot.as_ref(),
                        &render_completion.snapshot,
                        completion.completed_at,
                        &render_completion.present_events,
                    );
                    let upload_started_at = render_completion.upload_started_at;
                    let upload_completed_at = render_completion.upload_completed_at;
                    Self::push_optional_ms(
                        render_prepare_wait_latencies,
                        render_completion.snapshot.last_render_prepare_wait_ms,
                    );
                    Self::push_optional_ms(
                        render_shared_resource_latencies,
                        render_completion.snapshot.last_render_shared_resource_ms,
                    );
                    Self::push_optional_ms(
                        render_draw_present_latencies,
                        render_completion.snapshot.last_render_draw_present_ms,
                    );
                    *last_render_snapshot = Some(render_completion.snapshot);
                    render_latencies.push(
                        completion
                            .completed_at
                            .saturating_duration_since(completion.started_at),
                    );
                    render_submit_wait_latencies
                        .push(upload_started_at.saturating_duration_since(completion.started_at));
                    render_execute_latencies
                        .push(upload_completed_at.saturating_duration_since(upload_started_at));
                }
                Err(error) => anyhow::bail!("native render thread failed: {error}"),
            }
        }
        Ok(drained)
    }

    fn stop_render_scheduler_and_drain(
        scheduler: &LatestRenderScheduler,
        render_pacing: &mut RenderPacingCounters,
        render_latencies: &mut Vec<Duration>,
        render_submit_wait_latencies: &mut Vec<Duration>,
        render_execute_latencies: &mut Vec<Duration>,
        render_prepare_wait_latencies: &mut Vec<Duration>,
        render_shared_resource_latencies: &mut Vec<Duration>,
        render_draw_present_latencies: &mut Vec<Duration>,
        render_present_gaps: &mut Vec<Duration>,
        last_render_snapshot: &mut Option<RendererSnapshot>,
        last_render_present_at: &mut Option<Instant>,
    ) -> Result<()> {
        scheduler.stop();
        let deadline = Instant::now() + Duration::from_millis(NATIVE_RENDER_THREAD_STOP_TIMEOUT_MS);
        loop {
            let drained = Self::drain_render_completions(
                scheduler,
                render_pacing,
                render_latencies,
                render_submit_wait_latencies,
                render_execute_latencies,
                render_prepare_wait_latencies,
                render_shared_resource_latencies,
                render_draw_present_latencies,
                render_present_gaps,
                last_render_snapshot,
                last_render_present_at,
            )?;
            if scheduler.is_finished() || Instant::now() >= deadline {
                break;
            }
            if drained == 0 {
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }

    fn broadcast_encoded_access_units(
        subscribers: &Arc<Mutex<Vec<mpsc::SyncSender<Vec<EncodedAccessUnit>>>>>,
        latest_keyframe_access_units: &Arc<Mutex<Option<Vec<EncodedAccessUnit>>>>,
        encoded_units: &[EncodedAccessUnit],
    ) {
        if encoded_units.is_empty() {
            return;
        }
        if encoded_units.iter().any(|unit| unit.is_keyframe) {
            *latest_keyframe_access_units.lock().unwrap() = Some(encoded_units.to_vec());
        }

        let mut subscribers = subscribers.lock().unwrap();
        subscribers.retain(
            |subscriber| match subscriber.try_send(encoded_units.to_vec()) {
                Ok(()) | Err(mpsc::TrySendError::Full(_)) => true,
                Err(mpsc::TrySendError::Disconnected(_)) => false,
            },
        );
    }

    fn compute_percentiles(latencies: &[Duration]) -> (Duration, Duration) {
        if latencies.is_empty() {
            return (Duration::ZERO, Duration::ZERO);
        }
        let mut sorted = latencies.to_vec();
        sorted.sort_by_key(|d| d.as_nanos());
        let p50_idx = sorted.len() / 2;
        let p95_idx = ((sorted.len() * 95) / 100).min(sorted.len().saturating_sub(1));
        (sorted[p50_idx], sorted[p95_idx])
    }

    fn compute_average(latencies: &[Duration]) -> Duration {
        if latencies.is_empty() {
            return Duration::ZERO;
        }
        let total_nanos = latencies.iter().map(Duration::as_nanos).sum::<u128>();
        Duration::from_nanos((total_nanos / latencies.len() as u128).min(u64::MAX as u128) as u64)
    }

    fn push_optional_ms(latencies: &mut Vec<Duration>, value_ms: Option<f64>) {
        let Some(value_ms) = value_ms else {
            return;
        };
        if value_ms.is_finite() && value_ms >= 0.0 {
            latencies.push(Duration::from_secs_f64(value_ms / 1000.0));
        }
    }

    fn trim_latency_buffers(
        capture_latencies: &mut Vec<Duration>,
        interactive_latencies: &mut Vec<Duration>,
        encode_latencies: &mut Vec<Duration>,
        transport_latencies: &mut Vec<Duration>,
        decode_latencies: &mut Vec<Duration>,
        render_latencies: &mut Vec<Duration>,
        render_submit_wait_latencies: &mut Vec<Duration>,
        render_execute_latencies: &mut Vec<Duration>,
        render_prepare_wait_latencies: &mut Vec<Duration>,
        render_shared_resource_latencies: &mut Vec<Duration>,
        render_draw_present_latencies: &mut Vec<Duration>,
        render_present_gaps: &mut Vec<Duration>,
        total_latencies: &mut Vec<Duration>,
    ) {
        if capture_latencies.len() > 1000 {
            capture_latencies.remove(0);
        }
        if interactive_latencies.len() > 1000 {
            interactive_latencies.remove(0);
        }
        if encode_latencies.len() > 1000 {
            encode_latencies.remove(0);
        }
        if transport_latencies.len() > 1000 {
            transport_latencies.remove(0);
        }
        if decode_latencies.len() > 1000 {
            decode_latencies.remove(0);
        }
        if render_latencies.len() > 1000 {
            render_latencies.remove(0);
        }
        if render_submit_wait_latencies.len() > 1000 {
            render_submit_wait_latencies.remove(0);
        }
        if render_execute_latencies.len() > 1000 {
            render_execute_latencies.remove(0);
        }
        if render_prepare_wait_latencies.len() > 1000 {
            render_prepare_wait_latencies.remove(0);
        }
        if render_shared_resource_latencies.len() > 1000 {
            render_shared_resource_latencies.remove(0);
        }
        if render_draw_present_latencies.len() > 1000 {
            render_draw_present_latencies.remove(0);
        }
        if render_present_gaps.len() > 1000 {
            render_present_gaps.remove(0);
        }
        if total_latencies.len() > 1000 {
            total_latencies.remove(0);
        }
    }

    pub fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.thread_handle.take() {
            self.stopping.store(true, Ordering::Relaxed);
            let stopping = Arc::clone(&self.stopping);
            let metrics = Arc::clone(&self.metrics);
            thread::spawn(move || {
                let join_result = handle
                    .join()
                    .map_err(|_| "test harness worker thread panicked".to_string());
                if let Err(message) = join_result {
                    let mut m = metrics.lock().unwrap();
                    m.error_message = Some(message);
                }
                stopping.store(false, Ordering::Relaxed);
            });
        }

        {
            let mut m = self.metrics.lock().unwrap();
            m.is_running = false;
        }

        Ok(())
    }

    pub fn stop_and_wait(&mut self) -> Result<()> {
        self.stop()?;
        let started = Instant::now();
        while self.stopping.load(Ordering::Relaxed) {
            if started.elapsed() >= Duration::from_millis(HARNESS_STOP_JOIN_TIMEOUT_MS) {
                anyhow::bail!(
                    "test harness is still stopping after {} ms",
                    HARNESS_STOP_JOIN_TIMEOUT_MS
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    pub fn request_stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn get_metrics(&self) -> HarnessMetrics {
        self.metrics.lock().unwrap().clone()
    }

    pub fn get_pipeline_comparison_result(&self) -> PipelineComparisonResult {
        let metrics = self.get_metrics();
        let (pipeline, codec) = comparison_labels(&self.chain);
        let transport = comparison_transport_label(&self.chain, self.config.transport.as_ref());
        let memory_path = if self.config.zero_copy.unwrap_or(false) {
            "d3d11-shared"
        } else {
            "cpu"
        };
        metrics.to_pipeline_comparison_result(pipeline, codec, memory_path, transport)
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(windows)]
fn enable_nvdec_shared_texture(decoder: &mut NvdecDecoder) {
    decoder.enable_shared_texture(true);
}

#[cfg(not(windows))]
fn enable_nvdec_shared_texture(_decoder: &mut NvdecDecoder) {}

fn create_h264_nvdec_decoder(
    use_shared_texture_decode: bool,
    d3d11_device_ptr: Option<*mut core::ffi::c_void>,
) -> Result<NvdecDecoder> {
    #[cfg(windows)]
    {
        if use_shared_texture_decode {
            if let Some(d3d11_device_ptr) = d3d11_device_ptr {
                return unsafe {
                    NvdecDecoder::new_with_output_mode_and_d3d11_device_ptr(
                        NvdecOutputMode::CpuNv12,
                        d3d11_device_ptr,
                    )
                }
                .map_err(|e| anyhow::anyhow!("{e}"));
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = d3d11_device_ptr;
    }

    let mut decoder = NvdecDecoder::new_with_output_mode(NvdecOutputMode::CpuNv12)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if use_shared_texture_decode {
        enable_nvdec_shared_texture(&mut decoder);
    }
    Ok(decoder)
}

fn create_linux_h264_decoder() -> Result<PipelineDecoder> {
    #[cfg(target_os = "linux")]
    {
        let decoder = mrd_decode::create_decoder("linux_h264")
            .map_err(|e| anyhow::anyhow!("Linux H.264 hardware decoder init failed: {e}"))?;
        Ok(PipelineDecoder::LinuxH264(decoder))
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Linux H.264 hardware decoder is only available on Linux")
    }
}

fn create_linux_hevc_decoder(main10: bool) -> Result<PipelineDecoder> {
    #[cfg(target_os = "linux")]
    {
        let decoder_id = if main10 {
            "linux_hevc_main10"
        } else {
            "linux_hevc"
        };
        let decoder = mrd_decode::create_decoder(decoder_id).map_err(|e| {
            anyhow::anyhow!("Linux HEVC hardware decoder init failed ({decoder_id}): {e}")
        })?;
        Ok(if main10 {
            PipelineDecoder::LinuxHevcMain10(decoder)
        } else {
            PipelineDecoder::LinuxHevc(decoder)
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = main10;
        anyhow::bail!("Linux HEVC hardware decoder is only available on Linux")
    }
}

fn create_hevc_encoder(
    width: usize,
    height: usize,
    fps: u32,
    bitrate: u32,
    main10: bool,
    color_mode: ColorMode,
) -> Result<Box<dyn VideoEncoder>> {
    #[cfg(any(windows, target_os = "linux"))]
    {
        let encoder = create_hevc_nvenc_encoder(width, height, fps, bitrate, main10, color_mode)
            .map_err(|e| anyhow::anyhow!("NVENC HEVC encoder init failed: {:?}", e))?;
        Ok(Box::new(encoder) as Box<dyn VideoEncoder>)
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (width, height, fps, bitrate, main10, color_mode);
        anyhow::bail!("NVENC HEVC encoder is only available on Windows")
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn create_hevc_nvenc_encoder(
    width: usize,
    height: usize,
    fps: u32,
    bitrate: u32,
    main10: bool,
    color_mode: ColorMode,
) -> Result<NvencHevcEncoder, PipelineError> {
    let encoder = if main10 {
        NvencHevcEncoder::new_main10_with_bitrate(width, height, fps, bitrate)
    } else if prefer_max_speed_nvenc_for_hardware_decode(width, height, fps) {
        NvencHevcEncoder::new_max_speed_with_bitrate(width, height, fps, bitrate)
    } else {
        NvencHevcEncoder::new_main_with_bitrate(width, height, fps, bitrate)
    }?;
    Ok(encoder.with_color_mode(color_mode))
}

fn create_h264_encoder_for_hardware_decode(
    width: usize,
    height: usize,
    fps: u32,
    bitrate: u32,
    color_mode: ColorMode,
) -> Result<NvencH264Encoder, PipelineError> {
    let encoder = if prefer_max_speed_nvenc_for_hardware_decode(width, height, fps) {
        NvencH264Encoder::new_max_speed_with_bitrate(width, height, fps, bitrate)
    } else {
        NvencH264Encoder::new_with_bitrate(width, height, fps, bitrate)
    }?;
    Ok(encoder.with_color_mode(color_mode))
}

fn create_vvenc_encoder(
    width: usize,
    height: usize,
    fps: u32,
    bitrate: u32,
) -> Result<Box<dyn VideoEncoder>> {
    let encoder = VvencSoftwareEncoder::new_with_bitrate(width, height, fps, bitrate)
        .map_err(|e| anyhow::anyhow!("VVenC H.266/VVC encoder init failed: {:?}", e))?;
    Ok(Box::new(encoder) as Box<dyn VideoEncoder>)
}

fn create_hevc_nvdec_decoder(
    use_shared_texture_decode: bool,
    d3d11_device_ptr: Option<*mut core::ffi::c_void>,
    main10: bool,
) -> Result<NvdecDecoder> {
    #[cfg(windows)]
    {
        if use_shared_texture_decode {
            if let Some(d3d11_device_ptr) = d3d11_device_ptr {
                return unsafe {
                    if main10 {
                        NvdecDecoder::new_hevc_main10_with_output_mode_and_d3d11_device_ptr(
                            NvdecOutputMode::CpuNv12,
                            d3d11_device_ptr,
                        )
                    } else {
                        NvdecDecoder::new_hevc_with_output_mode_and_d3d11_device_ptr(
                            NvdecOutputMode::CpuNv12,
                            d3d11_device_ptr,
                        )
                    }
                }
                .map_err(|e| anyhow::anyhow!("{e}"));
            }
        }

        let mut decoder = if main10 {
            NvdecDecoder::new_hevc_main10_with_output_mode(NvdecOutputMode::CpuNv12)
        } else {
            NvdecDecoder::new_hevc_with_output_mode(NvdecOutputMode::CpuNv12)
        }
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        if use_shared_texture_decode {
            enable_nvdec_shared_texture(&mut decoder);
        }
        return Ok(decoder);
    }

    #[cfg(not(windows))]
    {
        let _ = (use_shared_texture_decode, d3d11_device_ptr, main10);
        anyhow::bail!("NVDEC HEVC decoder is only available on Windows")
    }
}

fn create_av1_nvdec_decoder(
    use_shared_texture_decode: bool,
    d3d11_device_ptr: Option<*mut core::ffi::c_void>,
) -> Result<NvdecDecoder> {
    #[cfg(windows)]
    {
        if use_shared_texture_decode {
            if let Some(d3d11_device_ptr) = d3d11_device_ptr {
                return unsafe {
                    NvdecDecoder::new_av1_with_output_mode_and_d3d11_device_ptr(
                        NvdecOutputMode::CpuNv12,
                        d3d11_device_ptr,
                    )
                }
                .map_err(|e| anyhow::anyhow!("{e}"));
            }
        }

        let mut decoder = NvdecDecoder::new_av1_with_output_mode(NvdecOutputMode::CpuNv12)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if use_shared_texture_decode {
            enable_nvdec_shared_texture(&mut decoder);
        }
        return Ok(decoder);
    }

    #[cfg(not(windows))]
    {
        let _ = (use_shared_texture_decode, d3d11_device_ptr);
        anyhow::bail!("NVDEC AV1 decoder is only available on Windows")
    }
}

fn create_videotoolbox_h264_encoder(
    width: usize,
    height: usize,
    fps: u32,
    bitrate: u32,
) -> Result<Box<dyn VideoEncoder>> {
    #[cfg(target_os = "macos")]
    {
        let encoder = VideoToolboxH264Encoder::new_with_bitrate(width, height, fps, bitrate)
            .map_err(|e| anyhow::anyhow!("VideoToolbox H.264 encoder init failed: {:?}", e))?;
        Ok(Box::new(encoder) as Box<dyn VideoEncoder>)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (width, height, fps, bitrate);
        anyhow::bail!("VideoToolbox H.264 encoder is only available on macOS")
    }
}

fn create_videotoolbox_hevc_encoder(
    width: usize,
    height: usize,
    fps: u32,
    bitrate: u32,
) -> Result<Box<dyn VideoEncoder>> {
    #[cfg(target_os = "macos")]
    {
        let encoder = VideoToolboxHevcEncoder::new_with_bitrate(width, height, fps, bitrate)
            .map_err(|e| anyhow::anyhow!("VideoToolbox HEVC encoder init failed: {:?}", e))?;
        Ok(Box::new(encoder) as Box<dyn VideoEncoder>)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (width, height, fps, bitrate);
        anyhow::bail!("VideoToolbox HEVC encoder is only available on macOS")
    }
}

fn create_videotoolbox_h264_decoder() -> Result<PipelineDecoder> {
    #[cfg(target_os = "macos")]
    {
        if !videotoolbox_decoder_enabled() {
            anyhow::bail!("VideoToolbox decoder is disabled by MRD_DISABLE_VIDEOTOOLBOX_DECODER");
        }

        let decoder = VideoToolboxH264Decoder::new()
            .map_err(|e| anyhow::anyhow!("VideoToolbox H.264 decoder init failed: {:?}", e))?;
        Ok(PipelineDecoder::VideoToolbox(Box::new(decoder)))
    }

    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("VideoToolbox H.264 decoder is only available on macOS")
    }
}

fn create_videotoolbox_hevc_decoder() -> Result<PipelineDecoder> {
    #[cfg(target_os = "macos")]
    {
        if !videotoolbox_decoder_enabled() {
            anyhow::bail!("VideoToolbox decoder is disabled by MRD_DISABLE_VIDEOTOOLBOX_DECODER");
        }

        let decoder = VideoToolboxHevcDecoder::new()
            .map_err(|e| anyhow::anyhow!("VideoToolbox HEVC decoder init failed: {:?}", e))?;
        Ok(PipelineDecoder::VideoToolbox(Box::new(decoder)))
    }

    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("VideoToolbox HEVC decoder is only available on macOS")
    }
}

#[allow(dead_code)]
fn videotoolbox_decoder_enabled() -> bool {
    !matches!(
        std::env::var("MRD_DISABLE_VIDEOTOOLBOX_DECODER").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn nonzero_ms(value: f64) -> Option<f64> {
    (value > 0.0).then_some(value)
}

fn comparison_labels(chain: &TestChain) -> (&'static str, &'static str) {
    match chain {
        TestChain::CaptureOnly => ("capture-render", "none"),
        TestChain::NvencOnly => ("capture-encode", "h264"),
        TestChain::NvencNvdec => ("capture-encode-decode-render", "h264"),
        TestChain::OpenH264 => ("capture-encode", "h264-software"),
        #[cfg(target_os = "linux")]
        TestChain::LinuxOpenh264 => ("capture-encode", "h264-software"),
        TestChain::Custom {
            encoder, decoder, ..
        } => {
            let pipeline = match (encoder, decoder) {
                (EncoderType::None, _) => "capture-render",
                (_, DecoderType::None) => "capture-encode",
                _ => "capture-encode-decode-render",
            };
            let codec = match encoder {
                EncoderType::None => "none",
                EncoderType::NvencAv1 => "av1",
                EncoderType::NvencHevc => "hevc",
                EncoderType::NvencHevcMain10 => "hevc-main10",
                EncoderType::OpenH264 => "h264-software",
                EncoderType::SoftwareVvc => "vvc-software",
                EncoderType::NvencH264 | EncoderType::VideoToolboxH264 => "h264",
                EncoderType::VideoToolboxHevc => "hevc",
            };
            (pipeline, codec)
        }
    }
}

fn comparison_transport_label(
    chain: &TestChain,
    transport: Option<&TransportKind>,
) -> &'static str {
    let uses_encoded_transport = match chain {
        TestChain::CaptureOnly => false,
        TestChain::Custom { encoder, .. } => !matches!(encoder, EncoderType::None),
        _ => true,
    };
    if !uses_encoded_transport {
        return "none";
    }
    match transport.unwrap_or(&TransportKind::Loopback) {
        TransportKind::Loopback => "loopback",
        TransportKind::WebrtcRtp => "webrtc-rtp",
        TransportKind::QuicDatagram => "quic-datagram",
    }
}

fn encoder_allows_zero_copy_capture(encoder: &EncoderType) -> bool {
    matches!(
        encoder,
        EncoderType::None
            | EncoderType::NvencH264
            | EncoderType::NvencHevc
            | EncoderType::NvencHevcMain10
            | EncoderType::NvencAv1
    )
}

fn chain_allows_zero_copy_capture(chain: &TestChain) -> bool {
    match chain {
        TestChain::CaptureOnly | TestChain::NvencNvdec | TestChain::NvencOnly => true,
        TestChain::OpenH264 => false,
        #[cfg(target_os = "linux")]
        TestChain::LinuxOpenh264 => false,
        TestChain::Custom { encoder, .. } => encoder_allows_zero_copy_capture(encoder),
    }
}

fn chain_allows_zero_copy_decode_render(chain: &TestChain) -> bool {
    match chain {
        TestChain::CaptureOnly | TestChain::NvencNvdec | TestChain::NvencOnly => true,
        TestChain::OpenH264 => true,
        #[cfg(target_os = "linux")]
        TestChain::LinuxOpenh264 => true,
        TestChain::Custom { encoder, .. } => encoder_allows_zero_copy_decode_render(encoder),
    }
}

fn encoder_allows_zero_copy_decode_render(encoder: &EncoderType) -> bool {
    matches!(
        encoder,
        EncoderType::None
            | EncoderType::NvencH264
            | EncoderType::NvencHevc
            | EncoderType::NvencHevcMain10
            | EncoderType::NvencAv1
            | EncoderType::OpenH264
    )
}

fn render_pixel_format_label(pixel_format: RenderPixelFormat) -> String {
    match pixel_format {
        RenderPixelFormat::Rgb24 => "Rgb24",
        RenderPixelFormat::Bgra32 => "Bgra32",
        RenderPixelFormat::Nv12 => "Nv12",
        #[cfg(windows)]
        RenderPixelFormat::D3D11SharedBgra => "D3D11SharedBgra",
        #[cfg(windows)]
        RenderPixelFormat::D3D11SharedNv12 => "D3D11SharedNv12",
        #[cfg(windows)]
        RenderPixelFormat::D3D11SharedP010 => "D3D11SharedP010",
    }
    .to_string()
}

fn resolved_color_mode(config: &TestConfig) -> ColorMode {
    config.color_mode.unwrap_or_default()
}

fn validate_chain_color_config(
    chain: &TestChain,
    color_mode: ColorMode,
    color_pipeline: ColorPipeline,
) -> Result<()> {
    match chain {
        TestChain::CaptureOnly => validate_named_encoder_color_config(
            "direct capture-render",
            false,
            false,
            color_mode,
            color_pipeline,
        ),
        TestChain::NvencNvdec | TestChain::NvencOnly => validate_named_encoder_color_config(
            "NVENC H.264",
            cfg!(windows),
            false,
            color_mode,
            color_pipeline,
        ),
        TestChain::OpenH264 => validate_named_encoder_color_config(
            "OpenH264",
            false,
            false,
            color_mode,
            color_pipeline,
        ),
        #[cfg(target_os = "linux")]
        TestChain::LinuxOpenh264 => validate_named_encoder_color_config(
            "OpenH264",
            false,
            false,
            color_mode,
            color_pipeline,
        ),
        TestChain::Custom { encoder, .. } => {
            validate_encoder_color_mode(Some(encoder), color_mode)?;
            validate_encoder_color_pipeline(Some(encoder), color_pipeline)
        }
    }
}

fn validate_encoder_color_mode(encoder: Option<&EncoderType>, color_mode: ColorMode) -> Result<()> {
    validate_named_encoder_color_mode(
        encoder_color_label(encoder),
        encoder_supports_non_full_color_mode(encoder),
        color_mode,
    )
}

fn validate_encoder_color_pipeline(
    encoder: Option<&EncoderType>,
    color_pipeline: ColorPipeline,
) -> Result<()> {
    validate_named_encoder_color_pipeline(
        encoder_color_label(encoder),
        encoder_supports_hdr_main10_color_pipeline(encoder),
        color_pipeline,
    )
}

fn validate_named_encoder_color_config(
    encoder_label: &'static str,
    supports_non_full_color_mode: bool,
    supports_hdr_main10_pipeline: bool,
    color_mode: ColorMode,
    color_pipeline: ColorPipeline,
) -> Result<()> {
    validate_named_encoder_color_mode(encoder_label, supports_non_full_color_mode, color_mode)?;
    validate_named_encoder_color_pipeline(
        encoder_label,
        supports_hdr_main10_pipeline,
        color_pipeline,
    )
}

fn validate_named_encoder_color_mode(
    encoder_label: &'static str,
    supports_non_full_color_mode: bool,
    color_mode: ColorMode,
) -> Result<()> {
    if color_mode == ColorMode::Full || supports_non_full_color_mode {
        return Ok(());
    }

    anyhow::bail!(
        "color_mode={} requires Windows D3D11 NVENC H.264/HEVC GPU color transform; encoder {} is not supported",
        color_mode.as_str(),
        encoder_label
    );
}

fn validate_named_encoder_color_pipeline(
    encoder_label: &'static str,
    supports_hdr_main10_pipeline: bool,
    color_pipeline: ColorPipeline,
) -> Result<()> {
    if color_pipeline == ColorPipeline::Sdr8 || supports_hdr_main10_pipeline {
        return Ok(());
    }

    anyhow::bail!(
        "color_pipeline={} requires NVENC HEVC Main10; encoder {} is not supported",
        color_pipeline.as_str(),
        encoder_label
    );
}

fn encoder_supports_non_full_color_mode(encoder: Option<&EncoderType>) -> bool {
    cfg!(windows)
        && matches!(
            encoder,
            Some(EncoderType::NvencH264 | EncoderType::NvencHevc | EncoderType::NvencHevcMain10)
        )
}

fn encoder_supports_hdr_main10_color_pipeline(encoder: Option<&EncoderType>) -> bool {
    matches!(encoder, Some(EncoderType::NvencHevcMain10))
}

fn encoder_color_label(encoder: Option<&EncoderType>) -> &'static str {
    match encoder {
        Some(EncoderType::None) => "none",
        Some(EncoderType::NvencH264) => "NVENC H.264",
        Some(EncoderType::NvencHevc) => "NVENC HEVC",
        Some(EncoderType::NvencHevcMain10) => "NVENC HEVC Main10",
        Some(EncoderType::NvencAv1) => "NVENC AV1",
        Some(EncoderType::OpenH264) => "OpenH264",
        Some(EncoderType::SoftwareVvc) => "software VVC",
        Some(EncoderType::VideoToolboxH264) => "VideoToolbox H.264",
        Some(EncoderType::VideoToolboxHevc) => "VideoToolbox HEVC",
        None => "direct capture-render",
    }
}

fn resolved_color_pipeline(chain: &TestChain, config: &TestConfig) -> ColorPipeline {
    config.color_pipeline.unwrap_or_else(|| {
        if chain_uses_hevc_main10(chain) {
            ColorPipeline::HdrMain10
        } else {
            ColorPipeline::Sdr8
        }
    })
}

fn chain_uses_hevc_main10(chain: &TestChain) -> bool {
    matches!(
        chain,
        TestChain::Custom {
            encoder: EncoderType::NvencHevcMain10,
            ..
        }
    )
}

fn nvdec_frame_to_decoded_frame(frame: mrd_decode_nvdec::NvdecDecodedFrame) -> DecodedFrame {
    match frame.data {
        mrd_decode_nvdec::NvdecDecodedFrameData::CpuRgb24(data) => {
            DecodedFrame::from_cpu_rgb24(frame.width, frame.height, 0, data)
        }
        mrd_decode_nvdec::NvdecDecodedFrameData::CpuNv12 { data, pitch } => {
            DecodedFrame::from_cpu_nv12(frame.width, frame.height, 0, pitch, data)
        }
        mrd_decode_nvdec::NvdecDecodedFrameData::CpuP010 { data, pitch } => {
            DecodedFrame::from_cpu_p010(frame.width, frame.height, 0, pitch, data)
        }
        #[cfg(windows)]
        mrd_decode_nvdec::NvdecDecodedFrameData::D3D11SharedNv12 {
            shared_handle_y,
            shared_handle_uv,
            width: _,
            height: _,
        } => DecodedFrame::from_d3d11_shared_nv12(
            frame.width,
            frame.height,
            0,
            shared_handle_y,
            shared_handle_uv,
        ),
        #[cfg(windows)]
        mrd_decode_nvdec::NvdecDecodedFrameData::D3D11SharedP010 {
            shared_handle_y,
            shared_handle_uv,
            width: _,
            height: _,
        } => DecodedFrame::from_d3d11_shared_p010(
            frame.width,
            frame.height,
            0,
            shared_handle_y,
            shared_handle_uv,
        ),
    }
}

fn render_input_to_frame(input: RenderInput) -> RenderFrame {
    match input {
        RenderInput::Decoded(frame) => decoded_frame_to_render_frame(&frame),
        RenderInput::Captured(frame) => captured_frame_to_render_frame(&frame),
    }
}

fn render_preview_input_for_frame(
    render_input: &Option<RenderInput>,
    preview_due: bool,
) -> Option<RenderInput> {
    if preview_due {
        render_input.clone()
    } else {
        None
    }
}

fn render_input_to_preview_bgra(
    input: RenderInput,
    max_width: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    let frame = render_input_to_frame(input);
    let (bgra, width, height) = match frame.data {
        RenderFrameData::Bgra32(data) => (data, frame.width, frame.height),
        RenderFrameData::Rgb24(data) => (
            rgb24_to_bgra32(&data, frame.width, frame.height),
            frame.width,
            frame.height,
        ),
        RenderFrameData::Nv12 { .. } | RenderFrameData::Nv12Bytes { .. } => {
            anyhow::bail!("NV12 render preview conversion is not implemented")
        }
        #[cfg(windows)]
        RenderFrameData::D3D11SharedBgra { .. } => {
            anyhow::bail!("D3D11 shared texture preview is not CPU-readable")
        }
        #[cfg(windows)]
        RenderFrameData::D3D11SharedNv12 { .. } => {
            anyhow::bail!("D3D11 shared texture preview is not CPU-readable")
        }
        #[cfg(windows)]
        RenderFrameData::D3D11SharedP010 { .. } => {
            anyhow::bail!("D3D11 shared texture preview is not CPU-readable")
        }
    };
    downsample_bgra(&bgra, width, height, max_width)
}

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
            cpu_i420_to_bgra32(data, frame.width, frame.height, *y_pitch, *uv_pitch),
        ),
        DecodedFrameData::CpuNv12 { data, pitch } => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            cpu_nv12_to_bgra32(data, frame.width, frame.height, *pitch),
        ),
        DecodedFrameData::CpuP010 { data, pitch } => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            cpu_p010_to_bgra32(data, frame.width, frame.height, *pitch),
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

fn captured_frame_to_render_frame(frame: &CapturedFrame) -> RenderFrame {
    #[cfg(windows)]
    if let Some(shared) = frame.d3d11_shared_bgra() {
        return RenderFrame::from_d3d11_shared_bgra(
            frame.width,
            frame.height,
            shared.shared_handle,
            shared.row_pitch,
        );
    }

    match frame.pixel_format {
        FramePixelFormat::Bgra32 => {
            RenderFrame::from_bgra32(frame.width, frame.height, frame.data.clone())
        }
        FramePixelFormat::Rgb24 => {
            RenderFrame::from_rgb24(frame.width, frame.height, frame.data.clone())
        }
        FramePixelFormat::Rgba32 => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            rgba32_to_bgra32(&frame.data, frame.width, frame.height),
        ),
        FramePixelFormat::Nv12 => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            cpu_nv12_to_bgra32(&frame.data, frame.width, frame.height, frame.width),
        ),
    }
}

fn rgba32_to_bgra32(rgba: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    for (src, dst) in rgba.chunks_exact(4).zip(bgra.chunks_exact_mut(4)) {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = src[3];
    }
    bgra
}

fn rgb24_to_bgra32(rgb: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    for (src, dst) in rgb.chunks_exact(3).zip(bgra.chunks_exact_mut(4)) {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = 255;
    }
    bgra
}

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
                write_limited_bgra_pixel(&mut bgra, out0_row + x * 4, nv12[y0_offset], u, v);
            }
            if x + 1 < width {
                let y0_next = y0_offset + 1;
                if y0_next < nv12.len() {
                    write_limited_bgra_pixel(
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
                    write_limited_bgra_pixel(&mut bgra, out1_row + x * 4, nv12[y1_offset], u, v);
                }
                if x + 1 < width {
                    let y1_next = y1_offset + 1;
                    if y1_next < nv12.len() {
                        write_limited_bgra_pixel(
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

fn cpu_nv12_to_rgb24(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
    let mut rgb = vec![0_u8; width * height * 3];
    let uv_base = pitch * height;
    let mut out_idx = 0;

    for y in 0..height {
        let y_row_start = y * pitch;
        let uv_row_start = uv_base + (y / 2) * pitch;
        for x in 0..width {
            let y_offset = y_row_start + x;
            let uv_offset = uv_row_start + (x / 2) * 2;
            if y_offset >= nv12.len() || uv_offset + 1 >= nv12.len() {
                out_idx += 3;
                continue;
            }

            let y_sample = nv12[y_offset] as i32 - 16;
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
                write_limited_bgra_pixel(&mut bgra, out0_row + x * 4, i420[y0_offset], u, v);
            }
            if x + 1 < width {
                let y0_next = y0_offset + 1;
                if y0_next < i420.len() {
                    write_limited_bgra_pixel(
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
                    write_limited_bgra_pixel(&mut bgra, out1_row + x * 4, i420[y1_offset], u, v);
                }
                if x + 1 < width {
                    let y1_next = y1_offset + 1;
                    if y1_next < i420.len() {
                        write_limited_bgra_pixel(
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
                write_p010_bgra_pixel(&mut bgra, out0_row + x * 4, y10, u10, v10);
            }
            if x + 1 < width {
                let y0_next = y0_offset + 2;
                if y0_next + 1 < p010.len() {
                    let y10 = u16::from_le_bytes([p010[y0_next], p010[y0_next + 1]]) >> 6;
                    write_p010_bgra_pixel(&mut bgra, out0_row + (x + 1) * 4, y10, u10, v10);
                }
            }
            if y + 1 < height {
                let y1_offset = y1_row + x * 2;
                if y1_offset + 1 < p010.len() {
                    let y10 = u16::from_le_bytes([p010[y1_offset], p010[y1_offset + 1]]) >> 6;
                    write_p010_bgra_pixel(&mut bgra, out1_row + x * 4, y10, u10, v10);
                }
                if x + 1 < width {
                    let y1_next = y1_offset + 2;
                    if y1_next + 1 < p010.len() {
                        let y10 = u16::from_le_bytes([p010[y1_next], p010[y1_next + 1]]) >> 6;
                        write_p010_bgra_pixel(&mut bgra, out1_row + (x + 1) * 4, y10, u10, v10);
                    }
                }
            }
        }
    }

    bgra
}

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

    bgra[offset] = clamp_10bit_to_8bit(b);
    bgra[offset + 1] = clamp_10bit_to_8bit(g);
    bgra[offset + 2] = clamp_10bit_to_8bit(r);
    bgra[offset + 3] = 255;
}

#[inline]
fn clamp_10bit_to_8bit(value: i32) -> u8 {
    (((value.clamp(0, 1023) + 2) >> 2).min(255)) as u8
}

fn downsample_frame(frame: &CapturedFrame, max_width: usize) -> Result<(Vec<u8>, usize, usize)> {
    downsample_bgra(&frame.data, frame.width, frame.height, max_width)
}

fn downsample_bgra(
    bgra: &[u8],
    width: usize,
    height: usize,
    max_width: usize,
) -> Result<(Vec<u8>, usize, usize)> {
    let scale = if width > max_width {
        max_width as f32 / width as f32
    } else {
        1.0_f32
    };

    if scale >= 1.0 {
        return Ok((bgra.to_vec(), width, height));
    }

    let new_width = (width as f32 * scale) as usize;
    let new_height = (height as f32 * scale) as usize;

    let mut result = vec![0u8; new_width * new_height * 4];

    for y in 0..new_height {
        for x in 0..new_width {
            let src_x = ((x as f32) / scale) as usize;
            let src_y = ((y as f32) / scale) as usize;
            let src_idx = (src_y * width + src_x) * 4;
            let dst_idx = (y * new_width + x) * 4;

            if src_idx + 3 < bgra.len() && dst_idx + 3 < result.len() {
                result[dst_idx..dst_idx + 4].copy_from_slice(&bgra[src_idx..src_idx + 4]);
            }
        }
    }

    Ok((result, new_width, new_height))
}

struct SyntheticCapture {
    tick: u64,
    width: usize,
    height: usize,
}

impl SyntheticCapture {
    fn new(width: usize, height: usize) -> Self {
        Self {
            tick: 0,
            width: even_dimension(width),
            height: even_dimension(height),
        }
    }
}

impl FrameCapture for SyntheticCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, mrd_pipeline_core::PipelineError> {
        self.tick = self.tick.wrapping_add(1);

        let byte_len = self
            .width
            .checked_mul(self.height)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| {
                mrd_pipeline_core::PipelineError::message("synthetic frame size overflow")
            })?;
        let mut data = vec![0_u8; byte_len];
        let phase = (self.tick & 0xff) as u8;

        for y in 0..self.height {
            for x in 0..self.width {
                let idx = (y * self.width + x) * 4;
                data[idx] = ((x as u8).wrapping_add(phase)) ^ ((y as u8) >> 1);
                data[idx + 1] = (y as u8).wrapping_add(phase / 2);
                data[idx + 2] = 192_u8.wrapping_sub(phase / 3);
                data[idx + 3] = 255;
            }
        }

        Ok(CapturedFrame::from_cpu(
            self.width,
            self.height,
            FramePixelFormat::Bgra32,
            self.tick.saturating_mul(16_667),
            data,
        ))
    }
}

#[cfg(windows)]
struct WinrtMonitorCapture {
    inner: WinrtCapture,
    width: usize,
    height: usize,
}

#[cfg(windows)]
impl WinrtMonitorCapture {
    #[allow(dead_code)]
    fn new_primary() -> Result<Self> {
        Self::new_monitor(0)
    }

    fn new_monitor(monitor_index: u32) -> Result<Self> {
        let inner = WinrtCapture::from_monitor_index(monitor_index)
            .map_err(|error| anyhow::anyhow!("WinRT capture init failed: {error}"))?;
        Self::from_inner(inner, "WinRT capture")
    }

    fn new_display_ref(display_ref: Option<&str>) -> Result<Self> {
        let inner = create_winrt_capture_for_display_ref(display_ref, false)?;
        Self::from_inner(inner, "WinRT capture")
    }

    fn new_window(hwnd: isize) -> Result<Self> {
        let inner = WinrtCapture::from_window_handle(hwnd)
            .map_err(|error| anyhow::anyhow!("WinRT window capture init failed: {error}"))?;
        Self::from_inner(inner, "WinRT window capture")
    }

    fn from_inner(mut inner: WinrtCapture, label: &str) -> Result<Self> {
        let width = inner.width();
        let height = inner.height();
        inner
            .start()
            .map_err(|error| anyhow::anyhow!("{label} start failed: {error}"))?;
        Ok(Self {
            inner,
            width,
            height,
        })
    }

    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }
}

#[cfg(windows)]
impl FrameCapture for WinrtMonitorCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, mrd_pipeline_core::PipelineError> {
        self.inner.capture_frame()
    }
}

fn select_pipeline_dimensions(
    capture_width: usize,
    capture_height: usize,
    config: &TestConfig,
) -> (usize, usize) {
    let (width, height) = config.resolution.unwrap_or((capture_width, capture_height));

    (even_dimension(width), even_dimension(height))
}

fn parse_window_handle(input: Option<&str>) -> Result<isize> {
    let input = input.ok_or_else(|| anyhow::anyhow!("window capture requires a window handle"))?;
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

fn parse_display_index(input: Option<&str>) -> Result<u32> {
    let Some(input) = input else {
        return Ok(0);
    };
    let value = parse_numeric_capture_source_id(input, "display index")?;
    u32::try_from(value).map_err(|_| anyhow::anyhow!("display index out of range: {value}"))
}

fn display_ref(config: &TestConfig) -> Option<&str> {
    config.display_id.as_deref().or(config.source_id.as_deref())
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsDisplaySelection {
    DeviceName(String),
    Index(u32),
}

#[cfg(windows)]
fn create_winrt_capture_for_display_ref(
    display_ref: Option<&str>,
    shared_texture: bool,
) -> Result<WinrtCapture> {
    match select_windows_display_ref(display_ref, windows_display_device_name_for_source_id)? {
        WindowsDisplaySelection::DeviceName(device_name) => {
            if shared_texture {
                WinrtCapture::from_monitor_device_name_shared_texture(&device_name).map_err(
                    |error| {
                        anyhow::anyhow!(
                            "WinRT shared capture init failed for {device_name}: {error}"
                        )
                    },
                )
            } else {
                WinrtCapture::from_monitor_device_name(&device_name).map_err(|error| {
                    anyhow::anyhow!("WinRT capture init failed for {device_name}: {error}")
                })
            }
        }
        WindowsDisplaySelection::Index(monitor_index) => {
            if shared_texture {
                WinrtCapture::from_monitor_index_shared_texture(monitor_index)
                    .map_err(|error| anyhow::anyhow!("WinRT shared capture init failed: {error}"))
            } else {
                WinrtCapture::from_monitor_index(monitor_index)
                    .map_err(|error| anyhow::anyhow!("WinRT capture init failed: {error}"))
            }
        }
    }
}

#[cfg(windows)]
fn select_windows_display_ref(
    display_ref: Option<&str>,
    resolve_device_name: impl FnOnce(&str) -> Result<String>,
) -> Result<WindowsDisplaySelection> {
    let Some(display_ref) = display_ref.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(WindowsDisplaySelection::Index(0));
    };

    if is_windows_display_source_id(display_ref) {
        return Ok(WindowsDisplaySelection::DeviceName(resolve_device_name(
            display_ref,
        )?));
    }

    Ok(WindowsDisplaySelection::Index(parse_display_index(Some(
        display_ref,
    ))?))
}

#[cfg(windows)]
fn is_windows_display_source_id(display_ref: &str) -> bool {
    let parts = display_ref.trim().split(':').collect::<Vec<_>>();
    matches!(
        parts.as_slice(),
        ["windows", "display", index] | ["windows", "display-shared", index]
            if index.parse::<u32>().is_ok()
    )
}

#[cfg(windows)]
fn windows_display_device_name_for_source_id(source_id: &str) -> Result<String> {
    let source_index = parse_display_index(Some(source_id))?;
    windows_display_target_for_source_index(source_index)
        .map(|target| target.device_name)
        .map_err(|error| {
            anyhow::anyhow!("resolve Windows display source {source_id} failed: {error}")
        })
}

#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowsDisplayTarget {
    source_index: u32,
    device_name: String,
    primary: bool,
    left: i32,
    top: i32,
}

#[cfg(windows)]
fn windows_display_target_for_source_index(source_index: u32) -> Result<WindowsDisplayTarget> {
    enumerate_windows_display_targets()?
        .into_iter()
        .find(|target| target.source_index == source_index)
        .ok_or_else(|| anyhow::anyhow!("Windows display target not found for index {source_index}"))
}

#[cfg(windows)]
fn enumerate_windows_display_targets() -> Result<Vec<WindowsDisplayTarget>> {
    let monitor_targets = enumerate_monitor_display_targets()?;
    if !monitor_targets.is_empty() {
        return Ok(assign_windows_display_source_indices(monitor_targets));
    }

    let device_targets = enumerate_display_device_targets();
    if device_targets.is_empty() {
        anyhow::bail!("no Windows displays found")
    } else {
        Ok(assign_windows_display_source_indices(device_targets))
    }
}

#[cfg(windows)]
fn enumerate_monitor_display_targets() -> Result<Vec<WindowsDisplayTarget>> {
    use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
    use windows::Win32::Graphics::Gdi::{
        EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO, MONITORINFOEXW,
    };

    unsafe extern "system" fn collect_monitor(
        monitor: HMONITOR,
        _hdc: HDC,
        _rect: *mut RECT,
        data: LPARAM,
    ) -> BOOL {
        let targets = &mut *(data.0 as *mut Vec<WindowsDisplayTarget>);
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;

        if !GetMonitorInfoW(
            monitor,
            (&mut info as *mut MONITORINFOEXW).cast::<MONITORINFO>(),
        )
        .as_bool()
        {
            return BOOL(1);
        }

        let rect = info.monitorInfo.rcMonitor;
        let width = rect.right.saturating_sub(rect.left);
        let height = rect.bottom.saturating_sub(rect.top);
        if width <= 0 || height <= 0 {
            return BOOL(1);
        }

        let Some(device_name) = windows_display_device_name_from_raw(&info.szDevice) else {
            return BOOL(1);
        };

        targets.push(WindowsDisplayTarget {
            source_index: 0,
            device_name,
            primary: info.monitorInfo.dwFlags & 1 != 0,
            left: rect.left,
            top: rect.top,
        });
        BOOL(1)
    }

    let mut targets = Vec::<WindowsDisplayTarget>::new();
    let ok = unsafe {
        EnumDisplayMonitors(
            None,
            None,
            Some(collect_monitor),
            LPARAM(&mut targets as *mut _ as isize),
        )
        .as_bool()
    };
    if !ok {
        anyhow::bail!(
            "EnumDisplayMonitors failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(targets)
}

#[cfg(windows)]
fn enumerate_display_device_targets() -> Vec<WindowsDisplayTarget> {
    use windows::core::PCWSTR;
    use windows::Win32::Graphics::Gdi::{
        EnumDisplayDevicesW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
        DISPLAY_DEVICE_PRIMARY_DEVICE,
    };

    let mut targets = Vec::new();
    for device_index in 0..32 {
        let mut device = DISPLAY_DEVICEW {
            cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
            ..Default::default()
        };
        let ok =
            unsafe { EnumDisplayDevicesW(PCWSTR::null(), device_index, &mut device, 0).as_bool() };
        if !ok {
            break;
        }
        if device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP == 0 {
            continue;
        }
        let Some(device_name) = windows_display_device_name_from_raw(&device.DeviceName) else {
            continue;
        };

        targets.push(WindowsDisplayTarget {
            source_index: 0,
            device_name,
            primary: device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE != 0,
            left: device_index as i32,
            top: 0,
        });
    }
    targets
}

#[cfg(windows)]
fn assign_windows_display_source_indices(
    mut targets: Vec<WindowsDisplayTarget>,
) -> Vec<WindowsDisplayTarget> {
    targets.sort_by_key(|target| {
        (
            !target.primary,
            target.left,
            target.top,
            target.device_name.to_ascii_lowercase(),
        )
    });
    for (index, target) in targets.iter_mut().enumerate() {
        target.source_index = index as u32;
    }
    targets
}

#[cfg(windows)]
fn windows_display_device_name_from_raw(raw: &[u16]) -> Option<String> {
    let end = raw.iter().position(|unit| *unit == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    let value = String::from_utf16_lossy(&raw[..end]);
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(windows)]
fn create_dxgi_shared_texture_capture(config: &TestConfig) -> Result<DxgiSharedTextureCapture> {
    let Some(source_id) = display_ref(config) else {
        return DxgiSharedTextureCapture::new_primary()
            .map_err(|e| anyhow::anyhow!("DXGI shared texture capture init failed: {:?}", e));
    };
    let device_name = dxgi_device_name_for_source_id(source_id)?;
    DxgiSharedTextureCapture::new_for_device_name(&device_name).map_err(|e| {
        anyhow::anyhow!(
            "DXGI shared texture capture init failed for {source_id} ({device_name}): {:?}",
            e
        )
    })
}

#[cfg(windows)]
fn dxgi_device_name_for_source_id(source_id: &str) -> Result<String> {
    let source_index = match select_windows_display_ref(
        Some(source_id),
        windows_display_device_name_for_source_id,
    )? {
        WindowsDisplaySelection::DeviceName(device_name) => return Ok(device_name),
        WindowsDisplaySelection::Index(source_index) => source_index as usize,
    };
    let targets = mrd_capture_dxgi::enumerate_dxgi_output_targets()
        .map_err(|error| anyhow::anyhow!("DXGI output enumeration failed: {error}"))?;
    targets
        .get(source_index)
        .map(|target| target.device_name.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "DXGI output source {source_id} resolved to index {source_index}, but only {} attached outputs were found",
                targets.len()
            )
        })
}

#[cfg(test)]
mod display_source_tests {
    use super::*;

    #[test]
    fn parse_display_index_accepts_windows_display_source_ids() {
        assert_eq!(
            parse_display_index(Some("windows:display-shared:1")).unwrap(),
            1
        );
        assert_eq!(parse_display_index(Some("windows:display:0")).unwrap(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_display_ref_selection_prefers_device_names_for_source_ids() {
        let selection = select_windows_display_ref(Some("windows:display-shared:2"), |source_id| {
            Ok(format!("device:{source_id}"))
        })
        .unwrap();
        assert_eq!(
            selection,
            WindowsDisplaySelection::DeviceName("device:windows:display-shared:2".to_string())
        );

        assert_eq!(
            select_windows_display_ref(Some("3"), |_| unreachable!()).unwrap(),
            WindowsDisplaySelection::Index(3)
        );
        assert_eq!(
            select_windows_display_ref(None, |_| unreachable!()).unwrap(),
            WindowsDisplaySelection::Index(0)
        );
    }
}

#[allow(dead_code)]
fn parse_display_id(input: &str) -> Result<u32> {
    let value = parse_numeric_capture_source_id(input, "display id")?;
    u32::try_from(value).map_err(|_| anyhow::anyhow!("display id out of range: {value}"))
}

fn parse_numeric_capture_source_id(input: &str, label: &str) -> Result<usize> {
    let trimmed = input.trim().rsplit(':').next().unwrap_or(input).trim();
    if trimmed.is_empty() {
        anyhow::bail!("{label} is empty");
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return usize::from_str_radix(hex, 16)
            .map_err(|error| anyhow::anyhow!("invalid {label} '{trimmed}': {error}"));
    }

    trimmed
        .parse::<usize>()
        .map_err(|error| anyhow::anyhow!("invalid {label} '{trimmed}': {error}"))
}

fn even_dimension(value: usize) -> usize {
    let value = value.max(2);
    if value % 2 == 0 {
        value
    } else {
        value - 1
    }
}

fn prepare_frame_for_encode<'a>(
    frame: &'a CapturedFrame,
    target_width: usize,
    target_height: usize,
    scratch: &'a mut Option<CapturedFrame>,
) -> &'a CapturedFrame {
    if frame.width == target_width && frame.height == target_height {
        return frame;
    }

    #[cfg(windows)]
    if frame.d3d11_shared_bgra().is_some() {
        return frame;
    }

    if frame.data.is_empty() {
        return frame;
    }

    adapt_frame_dimensions_into(frame, target_width, target_height, scratch);
    scratch
        .as_ref()
        .expect("adapt_frame_dimensions_into must initialize scratch")
}

fn prepare_captured_frame_for_direct_render<'a>(
    frame: &'a CapturedFrame,
    target_width: usize,
    target_height: usize,
    scratch: &'a mut Option<CapturedFrame>,
) -> &'a CapturedFrame {
    if frame.width == target_width && frame.height == target_height {
        return frame;
    }

    #[cfg(windows)]
    if frame.d3d11_shared_bgra().is_some() {
        return frame;
    }

    if frame.data.is_empty() {
        return frame;
    }

    adapt_frame_dimensions_into(frame, target_width, target_height, scratch);
    scratch
        .as_ref()
        .expect("adapt_frame_dimensions_into must initialize scratch")
}

fn adapt_frame_dimensions_into(
    frame: &CapturedFrame,
    target_width: usize,
    target_height: usize,
    scratch: &mut Option<CapturedFrame>,
) {
    if frame.pixel_format == FramePixelFormat::Nv12 {
        let rgb_frame = CapturedFrame::from_cpu(
            frame.width,
            frame.height,
            FramePixelFormat::Rgb24,
            frame.timestamp_us,
            cpu_nv12_to_rgb24(&frame.data, frame.width, frame.height, frame.width),
        );
        adapt_frame_dimensions_into(&rgb_frame, target_width, target_height, scratch);
        return;
    }

    let bytes_per_pixel = bytes_per_pixel(frame.pixel_format);
    let required_len = target_width * target_height * bytes_per_pixel;
    let output = scratch.get_or_insert_with(|| {
        CapturedFrame::from_cpu(
            target_width,
            target_height,
            frame.pixel_format,
            frame.timestamp_us,
            vec![0_u8; required_len],
        )
    });

    output.width = target_width;
    output.height = target_height;
    output.pixel_format = frame.pixel_format;
    output.timestamp_us = frame.timestamp_us;
    if output.data.len() != required_len {
        output.data.resize(required_len, 0);
    }

    if target_width <= frame.width && target_height <= frame.height {
        crop_frame_center_into(frame, target_width, target_height, &mut output.data);
    } else {
        resize_frame_nearest_into(frame, target_width, target_height, &mut output.data);
    }
}

#[cfg(test)]
fn resize_frame_nearest(
    frame: &CapturedFrame,
    target_width: usize,
    target_height: usize,
) -> CapturedFrame {
    let bytes_per_pixel = bytes_per_pixel(frame.pixel_format);
    let mut data = vec![0_u8; target_width * target_height * bytes_per_pixel];

    if frame.width == 0 || frame.height == 0 || bytes_per_pixel == 0 {
        return CapturedFrame::from_cpu(
            target_width,
            target_height,
            frame.pixel_format,
            frame.timestamp_us,
            data,
        );
    }

    for y in 0..target_height {
        let src_y = (y * frame.height / target_height).min(frame.height.saturating_sub(1));
        for x in 0..target_width {
            let src_x = (x * frame.width / target_width).min(frame.width.saturating_sub(1));
            let src_idx = (src_y * frame.width + src_x) * bytes_per_pixel;
            let dst_idx = (y * target_width + x) * bytes_per_pixel;
            if src_idx + bytes_per_pixel <= frame.data.len()
                && dst_idx + bytes_per_pixel <= data.len()
            {
                data[dst_idx..dst_idx + bytes_per_pixel]
                    .copy_from_slice(&frame.data[src_idx..src_idx + bytes_per_pixel]);
            }
        }
    }

    CapturedFrame::from_cpu(
        target_width,
        target_height,
        frame.pixel_format,
        frame.timestamp_us,
        data,
    )
}

fn resize_frame_nearest_into(
    frame: &CapturedFrame,
    target_width: usize,
    target_height: usize,
    data: &mut [u8],
) {
    let bytes_per_pixel = bytes_per_pixel(frame.pixel_format);

    if frame.width == 0 || frame.height == 0 || bytes_per_pixel == 0 {
        data.fill(0);
        return;
    }

    for y in 0..target_height {
        let src_y = (y * frame.height / target_height).min(frame.height.saturating_sub(1));
        for x in 0..target_width {
            let src_x = (x * frame.width / target_width).min(frame.width.saturating_sub(1));
            let src_idx = (src_y * frame.width + src_x) * bytes_per_pixel;
            let dst_idx = (y * target_width + x) * bytes_per_pixel;
            if src_idx + bytes_per_pixel <= frame.data.len()
                && dst_idx + bytes_per_pixel <= data.len()
            {
                data[dst_idx..dst_idx + bytes_per_pixel]
                    .copy_from_slice(&frame.data[src_idx..src_idx + bytes_per_pixel]);
            }
        }
    }
}

#[cfg(test)]
fn adapt_frame_dimensions(
    frame: &CapturedFrame,
    target_width: usize,
    target_height: usize,
) -> CapturedFrame {
    if target_width <= frame.width && target_height <= frame.height {
        crop_frame_center(frame, target_width, target_height)
    } else {
        resize_frame_nearest(frame, target_width, target_height)
    }
}

fn crop_frame_center_into(
    frame: &CapturedFrame,
    target_width: usize,
    target_height: usize,
    data: &mut [u8],
) {
    let bytes_per_pixel = bytes_per_pixel(frame.pixel_format);

    if frame.width == 0 || frame.height == 0 || bytes_per_pixel == 0 {
        data.fill(0);
        return;
    }

    let src_x = frame.width.saturating_sub(target_width) / 2;
    let src_y = frame.height.saturating_sub(target_height) / 2;
    let row_bytes = target_width * bytes_per_pixel;

    for y in 0..target_height {
        let src_idx = ((src_y + y) * frame.width + src_x) * bytes_per_pixel;
        let dst_idx = y * row_bytes;
        if src_idx + row_bytes <= frame.data.len() && dst_idx + row_bytes <= data.len() {
            data[dst_idx..dst_idx + row_bytes]
                .copy_from_slice(&frame.data[src_idx..src_idx + row_bytes]);
        }
    }
}

#[cfg(test)]
fn crop_frame_center(
    frame: &CapturedFrame,
    target_width: usize,
    target_height: usize,
) -> CapturedFrame {
    let bytes_per_pixel = bytes_per_pixel(frame.pixel_format);
    let mut data = vec![0_u8; target_width * target_height * bytes_per_pixel];

    if frame.width == 0 || frame.height == 0 || bytes_per_pixel == 0 {
        return CapturedFrame::from_cpu(
            target_width,
            target_height,
            frame.pixel_format,
            frame.timestamp_us,
            data,
        );
    }

    let src_x = frame.width.saturating_sub(target_width) / 2;
    let src_y = frame.height.saturating_sub(target_height) / 2;
    let row_bytes = target_width * bytes_per_pixel;

    for y in 0..target_height {
        let src_idx = ((src_y + y) * frame.width + src_x) * bytes_per_pixel;
        let dst_idx = y * row_bytes;
        if src_idx + row_bytes <= frame.data.len() && dst_idx + row_bytes <= data.len() {
            data[dst_idx..dst_idx + row_bytes]
                .copy_from_slice(&frame.data[src_idx..src_idx + row_bytes]);
        }
    }

    CapturedFrame::from_cpu(
        target_width,
        target_height,
        frame.pixel_format,
        frame.timestamp_us,
        data,
    )
}

fn bytes_per_pixel(format: FramePixelFormat) -> usize {
    match format {
        FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => 4,
        FramePixelFormat::Rgb24 => 3,
        FramePixelFormat::Nv12 => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_render::{
        RenderError, RenderFrame, RenderFrameData, RenderPixelFormat, RenderTarget,
        RendererInstance, RendererSnapshot,
    };

    #[derive(Default)]
    struct RecordingRenderer {
        uploaded: usize,
    }

    impl RendererInstance for RecordingRenderer {
        fn attach_target(&mut self, _target: RenderTarget) -> Result<(), RenderError> {
            Ok(())
        }

        fn upload_frame(&mut self, _frame: RenderFrame) -> Result<(), RenderError> {
            self.uploaded += 1;
            Ok(())
        }

        fn snapshot(&self) -> RendererSnapshot {
            RendererSnapshot {
                attached_to_target: true,
                uploaded_frame_count: self.uploaded as u64,
                presented_frame_count: self.uploaded as u64,
                present_skipped_count: 0,
                render_queue_replacements: None,
                last_present_status: Some("presented".to_string()),
                low_latency_frame_latency_target: None,
                swap_chain_max_frame_latency: None,
                swap_chain_allow_tearing: None,
                swap_chain_waitable_object: None,
                swap_chain_present_mode: None,
                display_refresh_hz: None,
                render_thread_priority: None,
                waitable_wait_count: None,
                waitable_wait_total_ms: None,
                waitable_timeout_count: None,
                last_waitable_wait_ms: None,
                last_render_prepare_wait_ms: None,
                last_render_shared_resource_ms: None,
                last_render_wait_for_drawable_ms: None,
                last_render_encode_commit_ms: None,
                last_render_draw_present_ms: None,
                last_width: 1,
                last_height: 1,
                last_pixel_format: Some(RenderPixelFormat::Bgra32),
            }
        }
    }

    fn renderer_snapshot(
        uploaded_frame_count: u64,
        presented_frame_count: u64,
        present_skipped_count: u64,
    ) -> RendererSnapshot {
        RendererSnapshot {
            attached_to_target: true,
            uploaded_frame_count,
            presented_frame_count,
            present_skipped_count,
            render_queue_replacements: None,
            last_present_status: Some("presented".to_string()),
            low_latency_frame_latency_target: None,
            swap_chain_max_frame_latency: None,
            swap_chain_allow_tearing: None,
            swap_chain_waitable_object: None,
            swap_chain_present_mode: None,
            display_refresh_hz: None,
            render_thread_priority: None,
            waitable_wait_count: None,
            waitable_wait_total_ms: None,
            waitable_timeout_count: None,
            last_waitable_wait_ms: None,
            last_render_prepare_wait_ms: None,
            last_render_shared_resource_ms: None,
            last_render_wait_for_drawable_ms: None,
            last_render_encode_commit_ms: None,
            last_render_draw_present_ms: None,
            last_width: 1,
            last_height: 1,
            last_pixel_format: Some(RenderPixelFormat::Bgra32),
        }
    }

    #[test]
    fn record_render_completion_tracks_present_gap_only_on_new_present() {
        let previous = renderer_snapshot(7, 3, 1);
        let current = renderer_snapshot(8, 4, 1);
        let same_present = renderer_snapshot(9, 4, 2);
        let mut counters = RenderPacingCounters::default();
        let mut present_gaps = Vec::new();
        let previous_present_at = Instant::now();
        let mut last_present_at = Some(previous_present_at);

        TestHarness::record_render_completion(
            &mut counters,
            &mut present_gaps,
            &mut last_present_at,
            Some(&previous),
            &current,
            previous_present_at + Duration::from_millis(7),
            &[],
        );

        assert_eq!(counters.uploaded_frames, 8);
        assert_eq!(counters.presented_frames, 4);
        assert_eq!(counters.present_skipped_frames, 1);
        assert_eq!(present_gaps, vec![Duration::from_millis(7)]);

        TestHarness::record_render_completion(
            &mut counters,
            &mut present_gaps,
            &mut last_present_at,
            Some(&current),
            &same_present,
            previous_present_at + Duration::from_millis(12),
            &[],
        );

        assert_eq!(counters.uploaded_frames, 9);
        assert_eq!(counters.presented_frames, 4);
        assert_eq!(counters.present_skipped_frames, 2);
        assert_eq!(present_gaps, vec![Duration::from_millis(7)]);
    }

    #[test]
    fn record_render_completion_tracks_swapchain_pacing_metadata() {
        let previous = renderer_snapshot(7, 3, 1);
        let mut current = renderer_snapshot(8, 4, 1);
        current.swap_chain_max_frame_latency = Some(1);
        current.swap_chain_allow_tearing = Some(true);
        current.swap_chain_waitable_object = Some(true);
        current.swap_chain_present_mode = Some("waitable".to_string());
        current.display_refresh_hz = Some(144);
        current.render_thread_priority = Some("above_normal".to_string());
        let expected_pixel_format = {
            #[cfg(windows)]
            {
                current.last_pixel_format = Some(RenderPixelFormat::D3D11SharedP010);
                "D3D11SharedP010"
            }
            #[cfg(not(windows))]
            {
                current.last_pixel_format = Some(RenderPixelFormat::Bgra32);
                "Bgra32"
            }
        };
        let mut counters = RenderPacingCounters::default();
        let mut present_gaps = Vec::new();
        let mut last_present_at = None;

        TestHarness::record_render_completion(
            &mut counters,
            &mut present_gaps,
            &mut last_present_at,
            Some(&previous),
            &current,
            Instant::now(),
            &[],
        );

        assert_eq!(counters.swap_chain_max_frame_latency, Some(1));
        assert_eq!(counters.swap_chain_allow_tearing, Some(true));
        assert_eq!(counters.swap_chain_waitable_object, Some(true));
        assert_eq!(
            counters.swap_chain_present_mode.as_deref(),
            Some("waitable")
        );
        assert_eq!(counters.display_refresh_hz, Some(144));
        assert_eq!(
            counters.render_thread_priority.as_deref(),
            Some("above_normal")
        );
        assert_eq!(
            counters.render_pixel_format.as_deref(),
            Some(expected_pixel_format)
        );
    }

    fn captured_render_input_with_marker(marker: u8) -> RenderInput {
        RenderInput::Captured(CapturedFrame::from_cpu(
            1,
            1,
            FramePixelFormat::Bgra32,
            1,
            vec![marker, 0, 0, 255],
        ))
    }

    fn render_input_marker(input: &RenderInput) -> u8 {
        match input {
            RenderInput::Captured(frame) => frame.data[0],
            RenderInput::Decoded(frame) => match &frame.data {
                DecodedFrameData::CpuRgb24(data) | DecodedFrameData::CpuBgra32(data) => data[0],
                DecodedFrameData::CpuNv12 { data, .. }
                | DecodedFrameData::CpuI420 { data, .. }
                | DecodedFrameData::CpuP010 { data, .. } => data[0],
                #[cfg(windows)]
                DecodedFrameData::D3D11SharedNv12 { .. }
                | DecodedFrameData::D3D11SharedP010 { .. } => 0,
            },
        }
    }

    #[test]
    fn latest_render_slot_replaces_pending_frame_with_newest() {
        let mut slot = LatestRenderSlot::default();

        assert!(
            !slot
                .push_latest(captured_render_input_with_marker(1))
                .replaced_pending
        );
        assert_eq!(
            render_input_marker(&slot.take_next().expect("first frame")),
            1
        );

        assert!(
            !slot
                .push_latest(captured_render_input_with_marker(2))
                .replaced_pending
        );
        assert!(
            slot.push_latest(captured_render_input_with_marker(3))
                .replaced_pending
        );

        assert_eq!(
            render_input_marker(&slot.take_next().expect("latest frame")),
            3
        );
        assert!(slot.take_next().is_none());
    }

    #[test]
    fn latest_render_slot_does_not_report_replacement_after_pending_is_taken() {
        let mut slot = LatestRenderSlot::default();

        slot.push_latest(captured_render_input_with_marker(7));
        assert_eq!(render_input_marker(&slot.take_next().expect("frame")), 7);

        assert!(
            !slot
                .push_latest(captured_render_input_with_marker(8))
                .replaced_pending
        );
    }

    #[test]
    fn render_preview_input_is_only_cloned_when_preview_is_due() {
        let input = Some(captured_render_input_with_marker(9));

        assert!(render_preview_input_for_frame(&input, false).is_none());
        assert_eq!(
            render_input_marker(&render_preview_input_for_frame(&input, true).expect("preview")),
            9
        );
    }

    #[test]
    fn render_job_sends_completion_after_upload() {
        let mut renderer = RecordingRenderer::default();
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let input = RenderInput::Captured(CapturedFrame::from_cpu(
            1,
            1,
            FramePixelFormat::Bgra32,
            1,
            vec![0, 0, 0, 255],
        ));

        complete_render_job(
            &mut renderer,
            RenderJob {
                input,
                completion: completion_tx,
            },
        )
        .expect("render job");

        let completion = completion_rx
            .recv()
            .expect("completion")
            .expect("successful completion");
        assert_eq!(completion.snapshot.uploaded_frame_count, 1);
        assert_eq!(completion.snapshot.presented_frame_count, 1);
        assert!(completion.upload_completed_at >= completion.upload_started_at);
        assert_eq!(renderer.uploaded, 1);
    }

    #[test]
    fn nvenc_av1_mode_parser_accepts_latency_modes() {
        assert_eq!(
            parse_nvenc_av1_mode_value(Some("ultra_low_latency")),
            NvencAv1Mode::UltraLowLatency
        );
        assert_eq!(
            parse_nvenc_av1_mode_value(Some("ull")),
            NvencAv1Mode::UltraLowLatency
        );
        assert_eq!(
            parse_nvenc_av1_mode_value(Some("high_refresh")),
            NvencAv1Mode::HighRefresh
        );
        assert_eq!(
            parse_nvenc_av1_mode_value(Some("p6")),
            NvencAv1Mode::UltraLowLatency
        );
        assert_eq!(parse_nvenc_av1_mode_value(None), NvencAv1Mode::LowLatency);
    }

    #[test]
    fn high_refresh_hardware_decode_prefers_max_speed_nvenc_for_2k_and_above() {
        assert!(prefer_max_speed_nvenc_for_hardware_decode(2560, 1440, 120));
        assert!(prefer_max_speed_nvenc_for_hardware_decode(3840, 2160, 120));
        assert!(!prefer_max_speed_nvenc_for_hardware_decode(2560, 1440, 60));
        assert!(!prefer_max_speed_nvenc_for_hardware_decode(1920, 1080, 144));
    }

    #[test]
    fn openh264_defaults_to_remote_desktop_bitrate_control() {
        assert_eq!(resolved_openh264_bitrate(None), 12_000_000);
        assert_eq!(resolved_openh264_bitrate(Some(5_000_000)), 5_000_000);
        assert_eq!(resolved_openh264_bitrate(Some(0)), 1);
    }

    #[cfg(windows)]
    #[test]
    fn shared_bgra_capture_maps_to_shared_render_frame() {
        let frame = CapturedFrame::from_d3d11_shared_bgra(1280, 720, 123, 77, 1280 * 4);
        let render_frame = captured_frame_to_render_frame(&frame);

        assert!(render_frame.is_shared_texture());
        assert_eq!(render_frame.shared_bgra_handle(), Some(77));
    }

    #[test]
    fn decoded_cpu_nv12_maps_to_bgra_render_frame() {
        let frame = DecodedFrame::from_cpu_nv12(2, 2, 0, 2, vec![16, 235, 16, 235, 128, 128]);

        let render_frame = decoded_frame_to_render_frame(&frame);

        assert_eq!(render_frame.pixel_format, RenderPixelFormat::Bgra32);
        assert_eq!(
            render_frame.data,
            RenderFrameData::Bgra32(vec![
                0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255,
            ])
        );
    }

    #[test]
    fn decoded_cpu_i420_maps_to_bgra_render_frame() {
        let frame = DecodedFrame::from_cpu_i420(2, 2, 0, 2, 1, vec![16, 235, 16, 235, 128, 128]);

        let render_frame = decoded_frame_to_render_frame(&frame);

        assert_eq!(render_frame.pixel_format, RenderPixelFormat::Bgra32);
        assert_eq!(
            render_frame.data,
            RenderFrameData::Bgra32(vec![
                0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255,
            ])
        );
    }

    #[test]
    fn decoded_cpu_p010_maps_to_bgra_render_frame() {
        let frame = DecodedFrame::from_cpu_p010(
            2,
            2,
            0,
            4,
            vec![0, 0, 192, 255, 0, 0, 192, 255, 0, 128, 0, 128],
        );

        let render_frame = decoded_frame_to_render_frame(&frame);

        assert_eq!(render_frame.pixel_format, RenderPixelFormat::Bgra32);
        assert_eq!(
            render_frame.data,
            RenderFrameData::Bgra32(vec![
                0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255,
            ])
        );
    }

    #[test]
    fn captured_cpu_nv12_maps_to_bgra_render_frame() {
        let frame = CapturedFrame::from_cpu(
            2,
            2,
            FramePixelFormat::Nv12,
            0,
            vec![16, 235, 16, 235, 128, 128],
        );

        let render_frame = captured_frame_to_render_frame(&frame);

        assert_eq!(render_frame.pixel_format, RenderPixelFormat::Bgra32);
        assert_eq!(
            render_frame.data,
            RenderFrameData::Bgra32(vec![
                0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255,
            ])
        );
    }

    #[cfg(windows)]
    #[test]
    fn prepare_frame_for_encode_preserves_d3d11_shared_frame_when_dimensions_differ() {
        let frame = CapturedFrame::from_d3d11_shared_bgra(1280, 720, 123, 77, 1280 * 4);
        let mut scratch = None;

        let prepared = prepare_frame_for_encode(&frame, 640, 360, &mut scratch);

        assert!(prepared.d3d11_shared_bgra().is_some());
        assert!(scratch.is_none());
    }

    #[test]
    fn cpu_nv12_to_bgra32_preserves_bgra_channel_order() {
        let bgra = cpu_nv12_to_bgra32(&[81, 90, 240], 1, 1, 1);

        assert_eq!(bgra, vec![0, 0, 255, 255]);
    }

    #[test]
    fn nvenc_av1_allows_zero_copy_policy() {
        assert!(encoder_allows_zero_copy_capture(&EncoderType::NvencAv1));
        assert!(encoder_allows_zero_copy_decode_render(
            &EncoderType::NvencAv1
        ));
    }

    #[test]
    fn nvenc_av1_rejects_non_full_color_mode_policy() {
        let error = validate_encoder_color_mode(Some(&EncoderType::NvencAv1), ColorMode::Grayscale)
            .expect_err("NVENC AV1 does not implement GPU color transforms yet");

        assert!(error.to_string().contains("NVENC AV1"));
    }

    #[test]
    fn hdr_main10_pipeline_requires_hevc_main10_policy() {
        let error = validate_encoder_color_pipeline(
            Some(&EncoderType::NvencH264),
            ColorPipeline::HdrMain10,
        )
        .expect_err("HDR Main10 should require NVENC HEVC Main10");

        assert!(error.to_string().contains("HEVC Main10"));
    }

    #[test]
    fn nvenc_hevc_allows_zero_copy_policy() {
        assert!(encoder_allows_zero_copy_capture(&EncoderType::NvencHevc));
        assert!(encoder_allows_zero_copy_decode_render(
            &EncoderType::NvencHevc
        ));
        assert!(encoder_allows_zero_copy_capture(
            &EncoderType::NvencHevcMain10
        ));
        assert!(encoder_allows_zero_copy_decode_render(
            &EncoderType::NvencHevcMain10
        ));
    }

    #[cfg(windows)]
    #[test]
    fn create_h264_encoder_for_hardware_decode_applies_color_mode() {
        let Ok(encoder) =
            create_h264_encoder_for_hardware_decode(16, 16, 30, 5_000_000, ColorMode::LowChroma)
        else {
            return;
        };

        assert_eq!(encoder.color_mode(), ColorMode::LowChroma);
    }

    #[cfg(windows)]
    #[test]
    fn create_hevc_nvenc_encoder_applies_color_mode() {
        let Ok(encoder) =
            create_hevc_nvenc_encoder(16, 16, 30, 5_000_000, false, ColorMode::Monochrome)
        else {
            return;
        };

        assert_eq!(encoder.color_mode(), ColorMode::Monochrome);
    }

    #[test]
    fn resolved_color_pipeline_defaults_main10_to_hdr_main10() {
        let chain = TestChain::Custom {
            capture: CaptureType::Dxgi,
            encoder: EncoderType::NvencHevcMain10,
            decoder: DecoderType::Nvdec,
        };

        assert_eq!(
            resolved_color_pipeline(&chain, &TestConfig::default()),
            ColorPipeline::HdrMain10
        );
    }

    #[test]
    fn software_h264_encoder_aliases_map_to_openh264() {
        assert_eq!(
            parse_harness_encoder_type(Some("openh264")),
            EncoderType::OpenH264
        );
        assert_eq!(
            parse_harness_encoder_type(Some("software_h264")),
            EncoderType::OpenH264
        );
        assert_eq!(
            parse_harness_encoder_type(Some("h264_software")),
            EncoderType::OpenH264
        );
        assert_eq!(
            parse_harness_encoder_type(Some("software-h264")),
            EncoderType::OpenH264
        );
        assert!(!encoder_allows_zero_copy_capture(&EncoderType::OpenH264));
        assert!(encoder_allows_zero_copy_decode_render(
            &EncoderType::OpenH264
        ));
        assert_eq!(
            comparison_labels(&TestChain::OpenH264),
            ("capture-encode", "h264-software")
        );
    }

    #[test]
    fn videotoolbox_hevc_encoder_alias_maps_to_hevc() {
        assert_eq!(
            parse_harness_encoder_type(Some("videotoolbox_hevc")),
            EncoderType::VideoToolboxHevc
        );
        assert!(!encoder_allows_zero_copy_capture(
            &EncoderType::VideoToolboxHevc
        ));
        assert!(!encoder_allows_zero_copy_decode_render(
            &EncoderType::VideoToolboxHevc
        ));
        assert_eq!(
            comparison_labels(&TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::VideoToolboxHevc,
                decoder: DecoderType::None,
            }),
            ("capture-encode", "hevc")
        );
    }

    #[test]
    fn software_vvc_encoder_aliases_map_to_vvenc() {
        assert_eq!(
            parse_harness_encoder_type(Some("software_vvc")),
            EncoderType::SoftwareVvc
        );
        assert_eq!(
            parse_harness_encoder_type(Some("vvc_software")),
            EncoderType::SoftwareVvc
        );
        assert_eq!(
            parse_harness_encoder_type(Some("software_h266")),
            EncoderType::SoftwareVvc
        );
        assert_eq!(
            parse_harness_encoder_type(Some("vvenc")),
            EncoderType::SoftwareVvc
        );
        assert!(!encoder_allows_zero_copy_capture(&EncoderType::SoftwareVvc));
        assert!(!encoder_allows_zero_copy_decode_render(
            &EncoderType::SoftwareVvc
        ));
        assert_eq!(
            comparison_labels(&TestChain::Custom {
                capture: CaptureType::Synthetic,
                encoder: EncoderType::SoftwareVvc,
                decoder: DecoderType::None,
            }),
            ("capture-encode", "vvc-software")
        );
    }

    #[test]
    fn hevc_custom_chains_export_captest_comparison_labels() {
        let hevc = TestChain::Custom {
            capture: CaptureType::Dxgi,
            encoder: EncoderType::NvencHevc,
            decoder: DecoderType::Nvdec,
        };
        let hevc_main10 = TestChain::Custom {
            capture: CaptureType::Dxgi,
            encoder: EncoderType::NvencHevcMain10,
            decoder: DecoderType::Nvdec,
        };

        assert_eq!(
            comparison_labels(&hevc),
            ("capture-encode-decode-render", "hevc")
        );
        assert_eq!(
            comparison_labels(&hevc_main10),
            ("capture-encode-decode-render", "hevc-main10")
        );
    }

    fn synthetic_hevc_access_unit() -> EncodedAccessUnit {
        EncodedAccessUnit {
            codec: VideoCodec::Hevc,
            timestamp_us: 42_000,
            is_keyframe: true,
            bytes: vec![
                0, 0, 0, 1, 0x40, 0x01, 0xaa, 0, 0, 0, 1, 0x42, 0x01, 0xbb, 0, 0, 0, 1, 0x44, 0x01,
                0xc0, 0, 0, 0, 1, 0x26, 0x01, 0xcc, 0xdd,
            ],
        }
    }

    #[test]
    fn hevc_webrtc_transport_initializes_for_matrix_runs() {
        assert!(
            PipelineTransport::new(Some(&TransportKind::WebrtcRtp), 60, VideoCodec::Hevc).is_ok()
        );
    }

    #[test]
    fn hevc_webrtc_transport_roundtrips_hevc_access_units() {
        let input = synthetic_hevc_access_unit();
        let mut transport =
            PipelineTransport::new(Some(&TransportKind::WebrtcRtp), 60, input.codec)
                .expect("HEVC WebRTC transport");

        let output = transport
            .transmit(vec![input.clone()])
            .expect("transmit HEVC access unit");

        assert_eq!(output.len(), 1);
        assert_eq!(output[0].codec, VideoCodec::Hevc);
        assert_eq!(output[0].timestamp_us, input.timestamp_us);
        assert_eq!(output[0].bytes, input.bytes);
        assert!(output[0].is_keyframe);
    }

    #[test]
    fn harness_metrics_export_captest_compatible_comparison_result() {
        let metrics = HarnessMetrics {
            capture_fps: 228.0,
            capture_latency_avg_ms: 0.4,
            encode_latency_avg_ms: 2.1,
            transport_latency_avg_ms: 0.05,
            decode_latency_avg_ms: 1.7,
            render_latency_avg_ms: 0.8,
            present_latency_avg_ms: 0.2,
            total_latency_avg_ms: 5.25,
            frame_count: 120,
            encoded_units: 120,
            decoded_frames: 118,
            encode_failures: 1,
            decode_failures: 2,
            total_bitstream_bytes: 5_000_000,
            ..HarnessMetrics::default()
        };

        let result = metrics.to_pipeline_comparison_result(
            "capture-encode-decode-render",
            "av1",
            "d3d11-shared",
            "quic-datagram",
        );

        assert_eq!(result.pipeline, "capture-encode-decode-render");
        assert_eq!(result.codec, "av1");
        assert_eq!(result.memory_path, "d3d11-shared");
        assert_eq!(result.transport, "quic-datagram");
        assert_eq!(result.frames, 120);
        assert_eq!(result.encoded_units, 120);
        assert_eq!(result.decoded_frames, 118);
        assert_eq!(result.encode_failures, 1);
        assert_eq!(result.decode_failures, 2);
        assert_eq!(result.avg_capture_time_ms, Some(0.4));
        assert_eq!(result.avg_encode_time_ms, Some(2.1));
        assert_eq!(result.avg_decode_time_ms, Some(1.7));
        assert_eq!(result.avg_render_time_ms, Some(0.8));
        assert_eq!(result.avg_present_time_ms, Some(0.2));
        assert_eq!(result.avg_transport_time_ms, Some(0.05));
        assert_eq!(result.avg_total_time_ms, Some(5.25));
        assert_eq!(result.avg_fps, Some(228.0));
        assert_eq!(result.total_bitstream_bytes, 5_000_000);
    }

    #[test]
    fn harness_metrics_export_prefers_decoded_fps_for_receiver_observed_fps() {
        let metrics = HarnessMetrics {
            capture_fps: 144.0,
            decoded_fps: 118.0,
            ..HarnessMetrics::default()
        };

        let result = metrics.to_pipeline_comparison_result(
            "capture-encode-decode-render",
            "h264",
            "d3d11-shared",
            "webrtc",
        );

        assert_eq!(result.avg_fps, Some(118.0));
    }

    #[test]
    fn harness_metrics_serializes_d3d11_render_execute_breakdown_fields() {
        let value = serde_json::to_value(HarnessMetrics::default()).expect("serialize metrics");
        let object = value.as_object().expect("metrics object");

        for key in [
            "render_prepare_wait_latency_avg_ms",
            "render_prepare_wait_latency_p50_ms",
            "render_prepare_wait_latency_p95_ms",
            "render_shared_resource_latency_avg_ms",
            "render_shared_resource_latency_p50_ms",
            "render_shared_resource_latency_p95_ms",
            "render_draw_present_latency_avg_ms",
            "render_draw_present_latency_p50_ms",
            "render_draw_present_latency_p95_ms",
            "swap_chain_max_frame_latency",
            "swap_chain_allow_tearing",
            "swap_chain_waitable_object",
            "swap_chain_present_mode",
            "display_refresh_hz",
            "render_thread_priority",
            "render_pixel_format",
            "color_mode",
            "color_pipeline",
        ] {
            assert!(object.contains_key(key), "{key} must be serialized");
        }
    }

    #[test]
    fn test_config_deserializes_color_mode_and_pipeline() {
        use mrd_pipeline_core::{ColorMode, ColorPipeline};

        let config: TestConfig = serde_json::from_value(serde_json::json!({
            "color_mode": "grayscale",
            "color_pipeline": "sdr8"
        }))
        .expect("deserialize color config");

        assert_eq!(config.color_mode, Some(ColorMode::Grayscale));
        assert_eq!(config.color_pipeline, Some(ColorPipeline::Sdr8));
    }

    #[test]
    fn trim_latency_buffers_handles_encode_only_samples() {
        let mut capture_latencies = Vec::new();
        let mut interactive_latencies = Vec::new();
        let mut encode_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut transport_latencies = Vec::new();
        let mut decode_latencies = Vec::new();
        let mut render_latencies = Vec::new();
        let mut render_submit_wait_latencies = Vec::new();
        let mut render_execute_latencies = Vec::new();
        let mut render_prepare_wait_latencies = Vec::new();
        let mut render_shared_resource_latencies = Vec::new();
        let mut render_draw_present_latencies = Vec::new();
        let mut render_present_gaps = Vec::new();
        let mut total_latencies = Vec::new();

        TestHarness::trim_latency_buffers(
            &mut capture_latencies,
            &mut interactive_latencies,
            &mut encode_latencies,
            &mut transport_latencies,
            &mut decode_latencies,
            &mut render_latencies,
            &mut render_submit_wait_latencies,
            &mut render_execute_latencies,
            &mut render_prepare_wait_latencies,
            &mut render_shared_resource_latencies,
            &mut render_draw_present_latencies,
            &mut render_present_gaps,
            &mut total_latencies,
        );

        assert!(capture_latencies.is_empty());
        assert!(interactive_latencies.is_empty());
        assert_eq!(encode_latencies.len(), 1000);
        assert_eq!(encode_latencies[0], Duration::from_millis(1));
        assert!(transport_latencies.is_empty());
        assert!(decode_latencies.is_empty());
        assert!(render_latencies.is_empty());
        assert!(render_prepare_wait_latencies.is_empty());
        assert!(render_shared_resource_latencies.is_empty());
        assert!(render_draw_present_latencies.is_empty());
        assert!(render_present_gaps.is_empty());
        assert!(total_latencies.is_empty());
    }

    #[test]
    fn trim_latency_buffers_trims_each_populated_series_independently() {
        let mut capture_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut interactive_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut encode_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut transport_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut decode_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_submit_wait_latencies =
            (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_execute_latencies =
            (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_prepare_wait_latencies =
            (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_shared_resource_latencies =
            (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_draw_present_latencies =
            (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut render_present_gaps = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();
        let mut total_latencies = (0..=1000).map(Duration::from_millis).collect::<Vec<_>>();

        TestHarness::trim_latency_buffers(
            &mut capture_latencies,
            &mut interactive_latencies,
            &mut encode_latencies,
            &mut transport_latencies,
            &mut decode_latencies,
            &mut render_latencies,
            &mut render_submit_wait_latencies,
            &mut render_execute_latencies,
            &mut render_prepare_wait_latencies,
            &mut render_shared_resource_latencies,
            &mut render_draw_present_latencies,
            &mut render_present_gaps,
            &mut total_latencies,
        );

        assert_eq!(capture_latencies.len(), 1000);
        assert_eq!(interactive_latencies.len(), 1000);
        assert_eq!(encode_latencies.len(), 1000);
        assert_eq!(transport_latencies.len(), 1000);
        assert_eq!(decode_latencies.len(), 1000);
        assert_eq!(render_latencies.len(), 1000);
        assert_eq!(render_submit_wait_latencies.len(), 1000);
        assert_eq!(render_execute_latencies.len(), 1000);
        assert_eq!(render_prepare_wait_latencies.len(), 1000);
        assert_eq!(render_shared_resource_latencies.len(), 1000);
        assert_eq!(render_draw_present_latencies.len(), 1000);
        assert_eq!(render_present_gaps.len(), 1000);
        assert_eq!(total_latencies.len(), 1000);
        assert_eq!(capture_latencies[0], Duration::from_millis(1));
        assert_eq!(interactive_latencies[0], Duration::from_millis(1));
        assert_eq!(encode_latencies[0], Duration::from_millis(1));
        assert_eq!(transport_latencies[0], Duration::from_millis(1));
        assert_eq!(decode_latencies[0], Duration::from_millis(1));
        assert_eq!(render_latencies[0], Duration::from_millis(1));
        assert_eq!(render_submit_wait_latencies[0], Duration::from_millis(1));
        assert_eq!(render_execute_latencies[0], Duration::from_millis(1));
        assert_eq!(render_prepare_wait_latencies[0], Duration::from_millis(1));
        assert_eq!(
            render_shared_resource_latencies[0],
            Duration::from_millis(1)
        );
        assert_eq!(render_draw_present_latencies[0], Duration::from_millis(1));
        assert_eq!(render_present_gaps[0], Duration::from_millis(1));
        assert_eq!(total_latencies[0], Duration::from_millis(1));
    }

    #[test]
    fn stop_preserves_last_metrics_snapshot() {
        let mut harness = TestHarness::new().expect("create harness");
        {
            let mut metrics = harness.metrics.lock().unwrap();
            metrics.is_running = true;
            metrics.capture_fps = 12.5;
            metrics.frame_count = 7;
        }

        harness.stop().expect("stop harness");

        let metrics = harness.get_metrics();
        assert!(!metrics.is_running);
        assert_eq!(metrics.capture_fps, 12.5);
        assert_eq!(metrics.frame_count, 7);
    }

    #[test]
    fn stop_does_not_hold_harness_while_join_waits() {
        let mut harness = TestHarness::new().expect("create harness");
        let (release_join_tx, release_join_rx) = mpsc::channel();
        let stopping = Arc::clone(&harness.stopping);
        harness.running.store(true, Ordering::Relaxed);
        harness.thread_handle = Some(thread::spawn(move || {
            let _ = release_join_rx.recv();
        }));

        let started = Instant::now();
        harness.stop().expect("stop harness");

        assert!(
            started.elapsed() < Duration::from_millis(100),
            "stop should not wait for pipeline thread join"
        );
        assert!(!harness.get_metrics().is_running);
        assert!(harness
            .start()
            .unwrap_err()
            .to_string()
            .contains("stopping"));

        release_join_tx.send(()).expect("release join");
        for _ in 0..50 {
            if !stopping.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!stopping.load(Ordering::Relaxed));
    }

    #[test]
    fn stop_and_wait_returns_after_pipeline_thread_cleanup() {
        let mut harness = TestHarness::new().expect("create harness");
        let cleanup_finished = Arc::new(AtomicBool::new(false));
        let cleanup_finished_thread = Arc::clone(&cleanup_finished);
        harness.running.store(true, Ordering::Relaxed);
        harness.thread_handle = Some(thread::spawn(move || {
            thread::sleep(Duration::from_millis(25));
            cleanup_finished_thread.store(true, Ordering::Relaxed);
        }));

        harness.stop_and_wait().expect("stop and wait");

        assert!(cleanup_finished.load(Ordering::Relaxed));
        assert!(!harness.stopping.load(Ordering::Relaxed));
    }

    #[test]
    fn stop_and_wait_allows_native_cleanup_beyond_two_seconds() {
        let mut harness = TestHarness::new().expect("create harness");
        harness.running.store(true, Ordering::Relaxed);
        harness.thread_handle = Some(thread::spawn(move || {
            thread::sleep(Duration::from_millis(2_100));
        }));

        harness
            .stop_and_wait()
            .expect("native codec cleanup may exceed the legacy two-second budget");

        assert!(!harness.stopping.load(Ordering::Relaxed));
    }

    #[test]
    fn pipeline_renderer_drop_waits_for_native_render_thread_cleanup() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (render_done_tx, render_done_rx) = mpsc::channel();
        let cleanup_finished = Arc::new(AtomicBool::new(false));
        let cleanup_finished_thread = Arc::clone(&cleanup_finished);
        let render_thread = thread::spawn(move || {
            let _ = receiver.recv();
            thread::sleep(Duration::from_millis(
                NATIVE_RENDER_THREAD_STOP_TIMEOUT_MS + 50,
            ));
            cleanup_finished_thread.store(true, Ordering::Relaxed);
            let _ = render_done_tx.send(());
        });
        let renderer = PipelineRenderer {
            sender: Some(sender),
            render_thread: Some(render_thread),
            render_done: Some(render_done_rx),
            last_error: Arc::new(Mutex::new(None)),
            d3d11_device_ptr: None,
        };

        drop(renderer);

        assert!(cleanup_finished.load(Ordering::Relaxed));
    }

    #[test]
    fn pipeline_renderer_drop_disconnects_a_full_command_queue_before_join() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(RenderCommand::Stop)
            .expect("fill render command queue");
        let (render_done_tx, render_done_rx) = mpsc::channel();
        let render_thread = thread::spawn(move || {
            while receiver.recv().is_ok() {}
            let _ = render_done_tx.send(());
        });
        let renderer = PipelineRenderer {
            sender: Some(sender),
            render_thread: Some(render_thread),
            render_done: Some(render_done_rx),
            last_error: Arc::new(Mutex::new(None)),
            d3d11_device_ptr: None,
        };
        let (drop_done_tx, drop_done_rx) = mpsc::channel();

        thread::spawn(move || {
            drop(renderer);
            let _ = drop_done_tx.send(());
        });

        drop_done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("full render queue must not deadlock renderer drop");
    }

    #[test]
    fn start_returns_before_initialization_errors_are_reported() {
        let mut harness = TestHarness::new().expect("create harness");
        harness.set_chain(TestChain::Custom {
            capture: CaptureType::Synthetic,
            encoder: EncoderType::NvencH264,
            decoder: DecoderType::None,
        });
        harness.set_config(TestConfig {
            zero_copy: Some(true),
            ..Default::default()
        });

        harness.start().expect("start harness worker");

        let mut last_metrics = harness.get_metrics();
        for _ in 0..50 {
            last_metrics = harness.get_metrics();
            if last_metrics.error_message.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(!last_metrics.is_running);
        assert!(last_metrics
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("D3D11 shared texture capture requires DXGI or WinRT capture"));
        harness.stop().expect("stop failed harness");
    }

    #[test]
    fn update_metrics_splits_source_wait_from_interactive_latency() {
        let metrics = Arc::new(Mutex::new(HarnessMetrics::default()));
        let start_time = Instant::now() - Duration::from_secs(1);
        let source_wait_latencies = vec![Duration::from_millis(8), Duration::from_millis(20)];
        let interactive_latencies = vec![Duration::from_millis(2), Duration::from_millis(4)];
        let total_latencies = vec![Duration::from_millis(10), Duration::from_millis(24)];

        TestHarness::update_metrics(
            &metrics,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            &start_time,
            &source_wait_latencies,
            &interactive_latencies,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            RenderPacingCounters::default(),
            NvdecSharedCopyStats::default(),
            &total_latencies,
        );

        let snapshot = metrics.lock().unwrap();
        assert_eq!(snapshot.source_wait_latency_p95_ms, 20.0);
        assert_eq!(snapshot.interactive_latency_p95_ms, 4.0);
        assert_eq!(snapshot.total_latency_p95_ms, 24.0);
    }

    #[test]
    fn update_metrics_reports_encoded_unit_throughput() {
        let metrics = Arc::new(Mutex::new(HarnessMetrics::default()));
        let start_time = Instant::now() - Duration::from_secs(2);

        TestHarness::update_metrics(
            &metrics,
            100,
            0,
            50,
            0,
            0,
            0,
            0,
            &start_time,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            RenderPacingCounters::default(),
            NvdecSharedCopyStats::default(),
            &[],
        );

        let snapshot = metrics.lock().unwrap();
        assert!(snapshot.capture_fps > 49.0 && snapshot.capture_fps <= 50.0);
        assert!(snapshot.encoded_fps > 24.0 && snapshot.encoded_fps <= 25.0);
    }

    #[test]
    fn update_metrics_reports_decoded_frame_throughput() {
        let metrics = Arc::new(Mutex::new(HarnessMetrics::default()));
        let start_time = Instant::now() - Duration::from_secs(4);

        TestHarness::update_metrics(
            &metrics,
            240,
            0,
            200,
            100,
            0,
            0,
            0,
            &start_time,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            RenderPacingCounters::default(),
            NvdecSharedCopyStats::default(),
            &[],
        );

        let snapshot = metrics.lock().unwrap();
        assert!(snapshot.capture_fps > 59.0 && snapshot.capture_fps <= 60.0);
        assert!(snapshot.decoded_fps > 24.0 && snapshot.decoded_fps <= 25.0);
    }

    #[test]
    fn update_metrics_reports_render_present_gap_distribution() {
        let metrics = Arc::new(Mutex::new(HarnessMetrics::default()));
        let start_time = Instant::now() - Duration::from_secs(1);
        let render_latencies = vec![
            Duration::from_micros(180),
            Duration::from_micros(210),
            Duration::from_micros(350),
        ];
        let render_submit_wait_latencies = vec![
            Duration::from_micros(30),
            Duration::from_micros(60),
            Duration::from_micros(90),
        ];
        let render_execute_latencies = vec![
            Duration::from_micros(150),
            Duration::from_micros(180),
            Duration::from_micros(260),
        ];
        let render_present_gaps = vec![
            Duration::from_millis(6),
            Duration::from_millis(7),
            Duration::from_millis(9),
        ];
        let render_pacing = RenderPacingCounters {
            submitted_frames: 12,
            uploaded_frames: 11,
            presented_frames: 10,
            present_skipped_frames: 1,
            queue_replacements: 2,
            stale_frame_drops: 2,
            ..RenderPacingCounters::default()
        };

        TestHarness::update_metrics(
            &metrics,
            12,
            0,
            12,
            12,
            0,
            0,
            0,
            &start_time,
            &[],
            &[],
            &[],
            &[],
            &[],
            &render_latencies,
            &render_submit_wait_latencies,
            &render_execute_latencies,
            &[],
            &[],
            &[],
            &render_present_gaps,
            render_pacing,
            NvdecSharedCopyStats::default(),
            &[],
        );

        let snapshot = metrics.lock().unwrap();
        assert!((snapshot.render_latency_p50_ms - 0.21).abs() < 0.001);
        assert!((snapshot.render_latency_p95_ms - 0.35).abs() < 0.001);
        assert!((snapshot.render_submit_wait_latency_p50_ms - 0.06).abs() < 0.001);
        assert!((snapshot.render_submit_wait_latency_p95_ms - 0.09).abs() < 0.001);
        assert!((snapshot.render_execute_latency_p50_ms - 0.18).abs() < 0.001);
        assert!((snapshot.render_execute_latency_p95_ms - 0.26).abs() < 0.001);
        assert_eq!(snapshot.render_submitted_frames, 12);
        assert_eq!(snapshot.render_uploaded_frames, 11);
        assert_eq!(snapshot.render_presented_frames, 10);
        assert_eq!(snapshot.render_present_skipped_frames, 1);
        assert_eq!(snapshot.render_queue_replacements, 2);
        assert_eq!(snapshot.render_stale_frame_drops, 2);
        assert!((snapshot.render_present_gap_avg_ms - (7.0 + (1.0 / 3.0))).abs() < 0.001);
        assert_eq!(snapshot.render_present_gap_p50_ms, 7.0);
        assert_eq!(snapshot.render_present_gap_p95_ms, 9.0);
        assert_eq!(
            snapshot.present_latency_avg_ms,
            snapshot.render_present_gap_avg_ms
        );
    }

    #[test]
    fn update_metrics_reports_d3d11_render_execute_breakdown_distribution() {
        let metrics = Arc::new(Mutex::new(HarnessMetrics::default()));
        let start_time = Instant::now() - Duration::from_secs(1);
        let render_prepare_wait_latencies = vec![
            Duration::from_micros(10),
            Duration::from_micros(20),
            Duration::from_micros(30),
        ];
        let render_shared_resource_latencies = vec![
            Duration::from_micros(800),
            Duration::from_micros(1_200),
            Duration::from_micros(1_500),
        ];
        let render_draw_present_latencies = vec![
            Duration::from_micros(1_400),
            Duration::from_micros(1_700),
            Duration::from_micros(2_100),
        ];

        TestHarness::update_metrics(
            &metrics,
            12,
            0,
            12,
            12,
            0,
            0,
            0,
            &start_time,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &render_prepare_wait_latencies,
            &render_shared_resource_latencies,
            &render_draw_present_latencies,
            &[],
            RenderPacingCounters::default(),
            NvdecSharedCopyStats::default(),
            &[],
        );

        let snapshot = metrics.lock().unwrap();
        assert!((snapshot.render_prepare_wait_latency_p50_ms - 0.02).abs() < 0.001);
        assert!((snapshot.render_prepare_wait_latency_p95_ms - 0.03).abs() < 0.001);
        assert!((snapshot.render_shared_resource_latency_p50_ms - 1.2).abs() < 0.001);
        assert!((snapshot.render_shared_resource_latency_p95_ms - 1.5).abs() < 0.001);
        assert!((snapshot.render_draw_present_latency_p50_ms - 1.7).abs() < 0.001);
        assert!((snapshot.render_draw_present_latency_p95_ms - 2.1).abs() < 0.001);
    }

    #[test]
    fn encoded_access_unit_subscriber_receives_latest_harness_output() {
        let harness = TestHarness::new().expect("create harness");
        let receiver = harness.subscribe_encoded_access_units();
        let units = vec![EncodedAccessUnit {
            codec: VideoCodec::H264,
            timestamp_us: 1,
            is_keyframe: true,
            bytes: vec![0, 0, 1, 0x65],
        }];

        TestHarness::broadcast_encoded_access_units(
            &harness.encoded_subscribers,
            &harness.latest_keyframe_access_units,
            &units,
        );

        assert_eq!(receiver.try_recv().expect("encoded access unit"), units);
    }

    #[test]
    fn encoded_access_unit_subscriber_replays_latest_keyframe_on_late_subscribe() {
        let harness = TestHarness::new().expect("create harness");
        let keyframe = vec![EncodedAccessUnit {
            codec: VideoCodec::H264,
            timestamp_us: 1,
            is_keyframe: true,
            bytes: vec![0, 0, 1, 0x65],
        }];
        let delta = vec![EncodedAccessUnit {
            codec: VideoCodec::H264,
            timestamp_us: 2,
            is_keyframe: false,
            bytes: vec![0, 0, 1, 0x41],
        }];

        TestHarness::broadcast_encoded_access_units(
            &harness.encoded_subscribers,
            &harness.latest_keyframe_access_units,
            &keyframe,
        );
        TestHarness::broadcast_encoded_access_units(
            &harness.encoded_subscribers,
            &harness.latest_keyframe_access_units,
            &delta,
        );
        let receiver = harness.subscribe_encoded_access_units();

        assert_eq!(
            receiver.try_recv().expect("replayed keyframe access unit"),
            keyframe
        );
    }

    #[test]
    fn encoded_access_unit_broadcast_removes_disconnected_subscribers() {
        let harness = TestHarness::new().expect("create harness");
        let receiver = harness.subscribe_encoded_access_units();
        drop(receiver);
        let units = vec![EncodedAccessUnit {
            codec: VideoCodec::H264,
            timestamp_us: 1,
            is_keyframe: false,
            bytes: vec![0, 0, 1, 0x41],
        }];

        TestHarness::broadcast_encoded_access_units(
            &harness.encoded_subscribers,
            &harness.latest_keyframe_access_units,
            &units,
        );

        assert!(harness.encoded_subscribers.lock().unwrap().is_empty());
    }

    #[test]
    fn select_pipeline_dimensions_rounds_to_even_values() {
        let config = TestConfig::default();
        assert_eq!(
            select_pipeline_dimensions(1707, 1067, &config),
            (1706, 1066)
        );

        let config = TestConfig {
            resolution: Some((1921, 1081)),
            ..Default::default()
        };
        assert_eq!(
            select_pipeline_dimensions(1707, 1067, &config),
            (1920, 1080)
        );
    }

    #[test]
    fn resize_frame_nearest_outputs_requested_shape() {
        let frame = CapturedFrame::from_cpu(
            3,
            2,
            FramePixelFormat::Bgra32,
            42,
            vec![
                1, 0, 0, 255, 2, 0, 0, 255, 3, 0, 0, 255, 4, 0, 0, 255, 5, 0, 0, 255, 6, 0, 0, 255,
            ],
        );

        let resized = resize_frame_nearest(&frame, 2, 2);

        assert_eq!(resized.width, 2);
        assert_eq!(resized.height, 2);
        assert_eq!(resized.timestamp_us, 42);
        assert_eq!(resized.data.len(), 2 * 2 * 4);
        assert_eq!(resized.data[0], 1);
        assert_eq!(resized.data[4], 2);
        assert_eq!(resized.data[8], 4);
        assert_eq!(resized.data[12], 5);
    }

    #[test]
    fn adapt_frame_dimensions_crops_when_target_fits_source() {
        let pixels = (1_u8..=12)
            .flat_map(|value| [value, 0, 0, 255])
            .collect::<Vec<_>>();
        let frame = CapturedFrame::from_cpu(4, 3, FramePixelFormat::Bgra32, 99, pixels);

        let cropped = adapt_frame_dimensions(&frame, 2, 2);

        assert_eq!(cropped.width, 2);
        assert_eq!(cropped.height, 2);
        assert_eq!(cropped.timestamp_us, 99);
        assert_eq!(cropped.data.len(), 2 * 2 * 4);
        assert_eq!(cropped.data[0], 2);
        assert_eq!(cropped.data[4], 3);
        assert_eq!(cropped.data[8], 6);
        assert_eq!(cropped.data[12], 7);
    }

    #[test]
    fn direct_render_uses_configured_pipeline_dimensions_for_cpu_frames() {
        let pixels = (1_u8..=16)
            .flat_map(|value| [value, 0, 0, 255])
            .collect::<Vec<_>>();
        let frame = CapturedFrame::from_cpu(4, 4, FramePixelFormat::Bgra32, 123, pixels);
        let mut scratch = None;

        let render_frame = prepare_captured_frame_for_direct_render(&frame, 2, 2, &mut scratch);

        assert_eq!(render_frame.width, 2);
        assert_eq!(render_frame.height, 2);
        assert_eq!(render_frame.timestamp_us, 123);
        assert_eq!(render_frame.data.len(), 2 * 2 * 4);
    }

    fn env_capture_type() -> CaptureType {
        match std::env::var("MRD_HARNESS_CAPTURE").as_deref() {
            Ok("winrt") => CaptureType::Winrt,
            Ok("macos") => CaptureType::Macos,
            #[cfg(target_os = "linux")]
            Ok("linux") => CaptureType::Linux,
            Ok("synthetic") => CaptureType::Synthetic,
            _ => CaptureType::Dxgi,
        }
    }

    fn parse_harness_encoder_type(value: Option<&str>) -> EncoderType {
        match value {
            Some("none") => EncoderType::None,
            Some("openh264")
            | Some("software_h264")
            | Some("h264_software")
            | Some("software-h264")
            | Some("h264-software")
            | Some("sw_h264") => EncoderType::OpenH264,
            Some("software_vvc")
            | Some("vvc_software")
            | Some("software_h266")
            | Some("h266_software")
            | Some("software-vvc")
            | Some("vvc-software")
            | Some("software-h266")
            | Some("h266-software")
            | Some("vvenc")
            | Some("vvc")
            | Some("h266")
            | Some("h.266") => EncoderType::SoftwareVvc,
            Some("nvenc_av1") => EncoderType::NvencAv1,
            Some("nvenc_hevc") | Some("hevc") => EncoderType::NvencHevc,
            Some("nvenc_hevc_main10") | Some("hevc_main10") | Some("hevc-main10") => {
                EncoderType::NvencHevcMain10
            }
            Some("videotoolbox_h264") | Some("videotoolbox") => EncoderType::VideoToolboxH264,
            Some("videotoolbox_hevc") => EncoderType::VideoToolboxHevc,
            _ => EncoderType::NvencH264,
        }
    }

    fn env_encoder_type() -> EncoderType {
        let value = std::env::var("MRD_HARNESS_ENCODER").ok();
        parse_harness_encoder_type(value.as_deref())
    }

    fn env_decoder_type() -> DecoderType {
        match std::env::var("MRD_HARNESS_DECODER").as_deref() {
            Ok("none") => DecoderType::None,
            Ok("software") | Ok("software_h264") | Ok("h264_software") | Ok("software-h264")
            | Ok("h264-software") | Ok("openh264") => DecoderType::Software,
            Ok("ffmpeg_h264") | Ok("h264_ffmpeg") => DecoderType::FfmpegH264,
            Ok("ffmpeg_hevc") | Ok("hevc_ffmpeg") | Ok("h265_ffmpeg") => DecoderType::FfmpegHevc,
            Ok("ffmpeg_vvc") | Ok("vvc_ffmpeg") | Ok("ffmpeg_h266") | Ok("h266_ffmpeg") => {
                DecoderType::FfmpegVvc
            }
            Ok("linux_h264") | Ok("gstreamer_h264") | Ok("vaapi_h264") => DecoderType::LinuxH264,
            Ok("linux_hevc") | Ok("gstreamer_hevc") | Ok("vaapi_hevc") => DecoderType::LinuxHevc,
            Ok("linux_hevc_main10") | Ok("gstreamer_hevc_main10") | Ok("vaapi_hevc_main10") => {
                DecoderType::LinuxHevcMain10
            }
            Ok("videotoolbox") => DecoderType::VideoToolbox,
            _ => DecoderType::Nvdec,
        }
    }

    #[test]
    #[ignore = "manual perf probe: requires DXGI, NVENC, and NVDEC on the host"]
    fn nvenc_nvdec_harness_prints_stage_metrics() {
        let seconds = std::env::var("MRD_HARNESS_PROBE_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(5);
        let chain = match std::env::var("MRD_HARNESS_CHAIN").as_deref() {
            Ok("capture_only") => TestChain::CaptureOnly,
            Ok("nvenc_only") => TestChain::NvencOnly,
            Ok("openh264") => TestChain::OpenH264,
            Ok("custom") | Ok("matrix") => TestChain::Custom {
                capture: env_capture_type(),
                encoder: env_encoder_type(),
                decoder: env_decoder_type(),
            },
            _ => TestChain::NvencNvdec,
        };
        let require_decode_success = matches!(
            std::env::var("MRD_HARNESS_REQUIRE_DECODE").as_deref(),
            Ok("1") | Ok("true")
        ) && match &chain {
            TestChain::NvencNvdec => true,
            TestChain::Custom { decoder, .. } => !matches!(decoder, DecoderType::None),
            _ => false,
        };
        let mut harness = TestHarness::new().expect("create harness");
        harness.set_chain(chain);
        harness.set_config(TestConfig {
            resolution: match (
                std::env::var("MRD_HARNESS_WIDTH")
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok()),
                std::env::var("MRD_HARNESS_HEIGHT")
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok()),
            ) {
                (Some(width), Some(height)) => Some((width, height)),
                _ => None,
            },
            fps: std::env::var("MRD_HARNESS_FPS")
                .ok()
                .and_then(|value| value.parse::<u32>().ok()),
            bitrate: std::env::var("MRD_HARNESS_BITRATE")
                .ok()
                .and_then(|value| value.parse::<u32>().ok()),
            renderer: match std::env::var("MRD_HARNESS_RENDERER").as_deref() {
                Ok("d3d11") => Some(RendererType::D3d11),
                Ok("macos") | Ok("metal") => Some(RendererType::Macos),
                Ok("opengl") => Some(RendererType::Opengl),
                #[cfg(target_os = "linux")]
                Ok("linux") => Some(RendererType::Linux),
                _ => None,
            },
            renderer_target_hwnd: None,
            transport: match std::env::var("MRD_HARNESS_TRANSPORT").as_deref() {
                Ok("webrtc") | Ok("webrtc_rtp") => Some(TransportKind::WebrtcRtp),
                Ok("quic") | Ok("quic_datagram") => Some(TransportKind::QuicDatagram),
                Ok("loopback") => Some(TransportKind::Loopback),
                _ => None,
            },
            zero_copy: match std::env::var("MRD_HARNESS_ZERO_COPY").as_deref() {
                Ok("1") | Ok("true") | Ok("d3d11_shared") => Some(true),
                Ok("0") | Ok("false") | Ok("cpu") => Some(false),
                _ => None,
            },
            color_mode: None,
            color_pipeline: None,
            pace_to_fps: match std::env::var("MRD_HARNESS_PACE_TO_FPS").as_deref() {
                Ok("1") | Ok("true") | Ok("yes") => Some(true),
                Ok("0") | Ok("false") | Ok("no") => Some(false),
                _ => None,
            },
            input_source: std::env::var("MRD_HARNESS_INPUT_SOURCE").ok(),
            source_id: std::env::var("MRD_HARNESS_SOURCE_ID").ok(),
            display_id: std::env::var("MRD_HARNESS_DISPLAY_ID").ok(),
            window_handle: std::env::var("MRD_HARNESS_WINDOW_HANDLE").ok(),
            visual_preview: match std::env::var("MRD_HARNESS_VISUAL_PREVIEW").as_deref() {
                Ok("1") | Ok("true") | Ok("yes") => Some(true),
                Ok("0") | Ok("false") | Ok("no") => Some(false),
                _ => None,
            },
        });
        harness.start().expect("start harness");
        thread::sleep(Duration::from_secs(seconds));
        harness.stop_and_wait().expect("stop harness");
        let metrics = harness.get_metrics();
        let comparison = harness.get_pipeline_comparison_result();
        println!("{metrics:#?}");
        println!(
            "{}",
            serde_json::to_string_pretty(&comparison).expect("serialize comparison result")
        );
        if let Ok(path) = std::env::var("MRD_HARNESS_RESULT_PATH") {
            std::fs::write(
                path,
                serde_json::to_string_pretty(&comparison).expect("serialize comparison result"),
            )
            .expect("write comparison result");
        }
        assert!(metrics.frame_count > 0);
        if require_decode_success {
            assert_eq!(
                metrics.decode_failures, 0,
                "decoder reported failures: {:?}",
                metrics.error_message
            );
            assert!(
                metrics.decoded_frames > 0,
                "decoder produced no frames: {:?}",
                metrics.error_message
            );
        }
    }
}
