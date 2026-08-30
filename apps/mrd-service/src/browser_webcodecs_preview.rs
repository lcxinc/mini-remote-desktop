#[cfg(windows)]
use crate::browser_preview_capture::open_browser_preview_dxgi_capture;
use bytes::Bytes;
#[cfg(windows)]
use mrd_encode_nvenc::{NvencH264Encoder, NvencHevcEncoder};
#[cfg(windows)]
use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};
#[cfg(windows)]
use mrd_pipeline_core::{FrameCapture, VideoEncoder};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[cfg(windows)]
use std::{
    hint, thread,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};
#[cfg(windows)]
use tracing::info;

const DEFAULT_BROWSER_WEBCODECS_FPS: u32 = 120;
const MAX_BROWSER_WEBCODECS_FPS: u32 = 249;
const DEFAULT_BROWSER_WEBCODECS_BITRATE_MBPS: u32 = 20;
const MAX_BROWSER_WEBCODECS_BITRATE_MBPS: u32 = 120;
const WEBCODECS_CHUNK_MAGIC: &[u8; 8] = b"MRDWC01\0";
const WEBCODECS_BINARY_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserWebcodecsPreviewCodec {
    H264,
    Hevc,
    #[serde(alias = "hevc-main10", alias = "h265_main10", alias = "h265-main10")]
    HevcMain10,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrowserWebcodecsPreviewStartRequest {
    pub session_id: String,
    pub fps: Option<u32>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bitrate_mbps: Option<u32>,
    pub codec: Option<BrowserWebcodecsPreviewCodec>,
    pub h264_profile: Option<String>,
    #[serde(default)]
    pub source_id: Option<String>,
}

impl BrowserWebcodecsPreviewStartRequest {
    pub fn selected_codec(&self) -> BrowserWebcodecsPreviewCodec {
        self.codec.unwrap_or(BrowserWebcodecsPreviewCodec::H264)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum BrowserWebcodecsPreviewControlMessage {
    #[serde(rename = "start")]
    Start(BrowserWebcodecsPreviewStartRequest),
    #[serde(rename = "request_keyframe")]
    RequestKeyframe,
    #[serde(rename = "stop")]
    Stop,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserWebcodecsPreviewReadyMessage {
    #[serde(rename = "type")]
    message_type: &'static str,
    session_id: String,
    codec: &'static str,
    codec_format: &'static str,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_mbps: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserWebcodecsPreviewErrorMessage {
    #[serde(rename = "type")]
    message_type: &'static str,
    session_id: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrowserWebcodecsFrameHeader {
    #[serde(rename = "type")]
    message_type: &'static str,
    sequence: u64,
    timestamp_us: u64,
    duration_us: u64,
    capture_unix_us: u64,
    keyframe: bool,
    codec: &'static str,
    codec_format: &'static str,
    width: u32,
    height: u32,
}

#[derive(Debug)]
pub enum BrowserWebcodecsPreviewOutbound {
    Text(String),
    Binary(Bytes),
}

impl BrowserWebcodecsPreviewOutbound {
    pub fn text_json<T: Serialize>(value: &T) -> Option<Self> {
        serde_json::to_string(value).ok().map(Self::Text)
    }
}

pub fn sanitize_browser_webcodecs_preview_fps(fps: Option<u32>) -> u32 {
    fps.unwrap_or(DEFAULT_BROWSER_WEBCODECS_FPS)
        .clamp(1, MAX_BROWSER_WEBCODECS_FPS)
}

pub fn sanitize_browser_webcodecs_preview_bitrate_mbps(bitrate_mbps: Option<u32>) -> u32 {
    bitrate_mbps
        .unwrap_or(DEFAULT_BROWSER_WEBCODECS_BITRATE_MBPS)
        .clamp(1, MAX_BROWSER_WEBCODECS_BITRATE_MBPS)
}

pub fn browser_webcodecs_h264_codec_string(profile: Option<&str>) -> &'static str {
    match profile {
        Some("high" | "nvenc" | "nvenc_h264") => "avc1.640034",
        _ => "avc1.42e034",
    }
}

pub fn browser_webcodecs_hevc_codec_string() -> &'static str {
    "hev1.1.6.L156.B0"
}

pub fn browser_webcodecs_hevc_main10_codec_string() -> &'static str {
    "hev1.2.4.L156.B0"
}

pub fn browser_webcodecs_codec_string(
    codec: BrowserWebcodecsPreviewCodec,
    h264_profile: Option<&str>,
) -> &'static str {
    match codec {
        BrowserWebcodecsPreviewCodec::H264 => browser_webcodecs_h264_codec_string(h264_profile),
        BrowserWebcodecsPreviewCodec::Hevc => browser_webcodecs_hevc_codec_string(),
        BrowserWebcodecsPreviewCodec::HevcMain10 => browser_webcodecs_hevc_main10_codec_string(),
    }
}

pub fn encode_webcodecs_chunk_message(
    header: &BrowserWebcodecsFrameHeader,
    payload: &[u8],
) -> Result<Bytes, serde_json::Error> {
    let header_json = serde_json::to_vec(header)?;
    let mut bytes =
        Vec::with_capacity(WEBCODECS_BINARY_HEADER_LEN + header_json.len() + payload.len());
    bytes.extend_from_slice(WEBCODECS_CHUNK_MAGIC);
    bytes.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&header_json);
    bytes.extend_from_slice(payload);
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
pub fn validate_webcodecs_chunk_message(bytes: &[u8]) -> bool {
    if bytes.len() < WEBCODECS_BINARY_HEADER_LEN {
        return false;
    }
    if &bytes[..8] != WEBCODECS_CHUNK_MAGIC {
        return false;
    }
    let header_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    WEBCODECS_BINARY_HEADER_LEN
        .checked_add(header_len)
        .is_some_and(|payload_offset| payload_offset <= bytes.len())
}

pub fn spawn_browser_webcodecs_capture_sender(
    request: BrowserWebcodecsPreviewStartRequest,
    outbound: mpsc::Sender<BrowserWebcodecsPreviewOutbound>,
    running: Arc<AtomicBool>,
    request_keyframe: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        run_browser_webcodecs_capture_sender(request, outbound, running, request_keyframe);
    })
}

#[cfg(windows)]
enum BrowserWebcodecsEncoder {
    H264(NvencH264Encoder),
    Hevc(NvencHevcEncoder),
    HevcMain10(NvencHevcEncoder),
}

#[cfg(windows)]
impl BrowserWebcodecsEncoder {
    fn request_keyframe(&mut self) {
        match self {
            Self::H264(encoder) => encoder.request_keyframe(),
            Self::Hevc(_) | Self::HevcMain10(_) => {}
        }
    }

    fn encode(
        &mut self,
        frame: &mrd_pipeline_core::CapturedFrame,
    ) -> Result<Vec<EncodedAccessUnit>, mrd_pipeline_core::PipelineError> {
        match self {
            Self::H264(encoder) => encoder.encode(frame),
            Self::Hevc(encoder) => encoder.encode(frame),
            Self::HevcMain10(encoder) => encoder.encode(frame),
        }
    }
}

#[cfg(windows)]
fn run_browser_webcodecs_capture_sender(
    request: BrowserWebcodecsPreviewStartRequest,
    outbound: mpsc::Sender<BrowserWebcodecsPreviewOutbound>,
    running: Arc<AtomicBool>,
    request_keyframe: Arc<AtomicBool>,
) {
    let session_id = request.session_id.clone();
    let fps = sanitize_browser_webcodecs_preview_fps(request.fps);
    let bitrate_mbps = sanitize_browser_webcodecs_preview_bitrate_mbps(request.bitrate_mbps);
    let bitrate_bps = bitrate_mbps.saturating_mul(1_000_000);
    let selected_codec = request.selected_codec();
    let codec = browser_webcodecs_codec_string(selected_codec, request.h264_profile.as_deref());
    let mut capture = match open_browser_preview_dxgi_capture(request.source_id.as_deref()) {
        Ok(capture) => capture,
        Err(error) => {
            send_error(
                &outbound,
                &session_id,
                format!("WebCodecs DXGI capture failed: {error}"),
            );
            running.store(false, Ordering::Relaxed);
            return;
        }
    };
    let source_width = capture.width();
    let source_height = capture.height();
    let (target_width, target_height) =
        sanitize_target_dimensions(request.width, request.height, source_width, source_height);
    capture.set_target_dimensions(target_width, target_height);
    let width = capture.width() as u32;
    let height = capture.height() as u32;
    let encoder_result = match selected_codec {
        BrowserWebcodecsPreviewCodec::H264 => NvencH264Encoder::new_max_speed_with_bitrate(
            capture.width(),
            capture.height(),
            fps,
            bitrate_bps,
        )
        .map(BrowserWebcodecsEncoder::H264),
        BrowserWebcodecsPreviewCodec::Hevc => NvencHevcEncoder::new_max_speed_with_bitrate(
            capture.width(),
            capture.height(),
            fps,
            bitrate_bps,
        )
        .map(BrowserWebcodecsEncoder::Hevc),
        BrowserWebcodecsPreviewCodec::HevcMain10 => NvencHevcEncoder::new_main10_with_bitrate(
            capture.width(),
            capture.height(),
            fps,
            bitrate_bps,
        )
        .map(BrowserWebcodecsEncoder::HevcMain10),
    };
    let mut encoder = match encoder_result {
        Ok(encoder) => encoder,
        Err(error) => {
            send_error(
                &outbound,
                &session_id,
                format!(
                    "WebCodecs NVENC {} failed: {error}",
                    match selected_codec {
                        BrowserWebcodecsPreviewCodec::H264 => "H.264",
                        BrowserWebcodecsPreviewCodec::Hevc => "HEVC",
                        BrowserWebcodecsPreviewCodec::HevcMain10 => "HEVC Main10",
                    }
                ),
            );
            running.store(false, Ordering::Relaxed);
            return;
        }
    };

    let ready = BrowserWebcodecsPreviewReadyMessage {
        message_type: "mrd.webcodecs.ready.v1",
        session_id: session_id.clone(),
        codec,
        codec_format: "annexb",
        width,
        height,
        fps,
        bitrate_mbps,
    };
    let _ = BrowserWebcodecsPreviewOutbound::text_json(&ready)
        .and_then(|message| outbound.blocking_send(message).ok());
    info!(
        "browser WebCodecs preview sender started for {} at {}x{} @ {} fps / {} Mbps (source_id {}, source {}x{})",
        session_id,
        width,
        height,
        fps,
        bitrate_mbps,
        request.source_id.as_deref().unwrap_or("<primary>"),
        source_width,
        source_height
    );

    let frame_interval = Duration::from_nanos(1_000_000_000u64 / fps.max(1) as u64);
    let duration_us = 1_000_000u64 / fps.max(1) as u64;
    let mut next_frame_at = Instant::now();
    let mut sequence = 0u64;
    let mut sent = 0u64;
    let mut dropped = 0u64;
    let mut request_next_keyframe = false;
    let mut last_report_at = Instant::now();

    while running.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now < next_frame_at {
            sleep_until_frame_deadline(next_frame_at);
        } else if now.duration_since(next_frame_at) > frame_interval {
            next_frame_at = now;
        }
        next_frame_at += frame_interval;

        let frame = match capture.capture_frame() {
            Ok(frame) => frame,
            Err(error) => {
                send_error(
                    &outbound,
                    &session_id,
                    format!("WebCodecs capture failed: {error}"),
                );
                running.store(false, Ordering::Relaxed);
                break;
            }
        };
        if request_next_keyframe || request_keyframe.swap(false, Ordering::Relaxed) {
            encoder.request_keyframe();
            request_next_keyframe = false;
        }
        let access_units = match encoder.encode(&frame) {
            Ok(access_units) => access_units,
            Err(error) => {
                send_error(
                    &outbound,
                    &session_id,
                    format!("WebCodecs encode failed: {error}"),
                );
                running.store(false, Ordering::Relaxed);
                break;
            }
        };

        for access_unit in access_units {
            if access_unit.codec != video_codec_for_webcodecs_preview(selected_codec) {
                continue;
            }
            sequence = sequence.saturating_add(1);
            let header = frame_header(&access_unit, sequence, duration_us, width, height, codec);
            let Ok(binary) = encode_webcodecs_chunk_message(&header, &access_unit.bytes) else {
                continue;
            };
            match outbound.try_send(BrowserWebcodecsPreviewOutbound::Binary(binary)) {
                Ok(()) => sent = sent.saturating_add(1),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped = dropped.saturating_add(1);
                    request_next_keyframe = true;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }

        if last_report_at.elapsed() >= Duration::from_secs(2) {
            info!(
                "browser WebCodecs preview sender progress for {}: sent={} dropped={} sequence={}",
                session_id, sent, dropped, sequence
            );
            sent = 0;
            dropped = 0;
            last_report_at = Instant::now();
        }
    }
}

#[cfg(not(windows))]
fn run_browser_webcodecs_capture_sender(
    request: BrowserWebcodecsPreviewStartRequest,
    outbound: mpsc::Sender<BrowserWebcodecsPreviewOutbound>,
    running: Arc<AtomicBool>,
    _request_keyframe: Arc<AtomicBool>,
) {
    send_error(
        &outbound,
        &request.session_id,
        "browser WebCodecs preview currently requires Windows DXGI + NVENC H.264/HEVC".to_string(),
    );
    running.store(false, Ordering::Relaxed);
}

#[cfg(windows)]
fn video_codec_for_webcodecs_preview(codec: BrowserWebcodecsPreviewCodec) -> VideoCodec {
    match codec {
        BrowserWebcodecsPreviewCodec::H264 => VideoCodec::H264,
        BrowserWebcodecsPreviewCodec::Hevc | BrowserWebcodecsPreviewCodec::HevcMain10 => {
            VideoCodec::Hevc
        }
    }
}

#[cfg(windows)]
fn frame_header(
    access_unit: &EncodedAccessUnit,
    sequence: u64,
    duration_us: u64,
    width: u32,
    height: u32,
    codec: &'static str,
) -> BrowserWebcodecsFrameHeader {
    BrowserWebcodecsFrameHeader {
        message_type: "mrd.webcodecs.frame.v1",
        sequence,
        timestamp_us: sequence.saturating_mul(duration_us),
        duration_us,
        capture_unix_us: access_unit.timestamp_us,
        keyframe: access_unit.is_keyframe,
        codec,
        codec_format: "annexb",
        width,
        height,
    }
}

fn send_error(
    outbound: &mpsc::Sender<BrowserWebcodecsPreviewOutbound>,
    session_id: &str,
    message: String,
) {
    let error = BrowserWebcodecsPreviewErrorMessage {
        message_type: "mrd.webcodecs.error.v1",
        session_id: session_id.to_string(),
        message,
    };
    let _ = BrowserWebcodecsPreviewOutbound::text_json(&error)
        .and_then(|message| outbound.blocking_send(message).ok());
}

#[cfg(windows)]
fn sanitize_target_dimensions(
    width: Option<u32>,
    height: Option<u32>,
    source_width: usize,
    source_height: usize,
) -> (usize, usize) {
    let source_width = source_width.max(2);
    let source_height = source_height.max(2);
    let (Some(width), Some(height)) = (width, height) else {
        return (source_width & !1, source_height & !1);
    };
    let target_width = (width as usize).clamp(2, source_width) & !1;
    let target_height = (height as usize).clamp(2, source_height) & !1;
    (target_width.max(2), target_height.max(2))
}

#[cfg(windows)]
fn sleep_until_frame_deadline(deadline: Instant) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let remaining = deadline - now;
        if remaining > Duration::from_millis(2) {
            thread::sleep(remaining - Duration::from_millis(1));
        } else if remaining > Duration::from_micros(350) {
            thread::yield_now();
        } else {
            hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webcodecs_preview_allows_high_refresh_fps_but_clamps_above_it() {
        assert_eq!(sanitize_browser_webcodecs_preview_fps(Some(144)), 144);
        assert_eq!(sanitize_browser_webcodecs_preview_fps(Some(180)), 180);
        assert_eq!(sanitize_browser_webcodecs_preview_fps(Some(249)), 249);
        assert_eq!(sanitize_browser_webcodecs_preview_fps(Some(300)), 249);
        assert_eq!(sanitize_browser_webcodecs_preview_fps(None), 120);
    }

    #[test]
    fn browser_webcodecs_preview_start_deserializes_source_id() {
        let message: BrowserWebcodecsPreviewControlMessage = serde_json::from_str(
            r#"{"type":"start","session_id":"s1","source_id":"windows:display-shared:1"}"#,
        )
        .unwrap();

        let BrowserWebcodecsPreviewControlMessage::Start(request) = message else {
            panic!("expected start message");
        };
        assert_eq!(
            request.source_id.as_deref(),
            Some("windows:display-shared:1")
        );
    }

    #[test]
    fn browser_webcodecs_preview_start_deserializes_hevc_codec() {
        let message: BrowserWebcodecsPreviewControlMessage =
            serde_json::from_str(r#"{"type":"start","session_id":"s1","codec":"hevc"}"#).unwrap();

        let BrowserWebcodecsPreviewControlMessage::Start(request) = message else {
            panic!("expected start message");
        };
        assert_eq!(request.codec, Some(BrowserWebcodecsPreviewCodec::Hevc));
        assert_eq!(
            browser_webcodecs_codec_string(
                request.selected_codec(),
                request.h264_profile.as_deref()
            ),
            "hev1.1.6.L156.B0"
        );
    }

    #[test]
    fn browser_webcodecs_preview_start_deserializes_hevc_main10_codec() {
        let message: BrowserWebcodecsPreviewControlMessage =
            serde_json::from_str(r#"{"type":"start","session_id":"s1","codec":"hevc_main10"}"#)
                .unwrap();

        let BrowserWebcodecsPreviewControlMessage::Start(request) = message else {
            panic!("expected start message");
        };
        assert_eq!(
            request.codec,
            Some(BrowserWebcodecsPreviewCodec::HevcMain10)
        );
        assert_eq!(
            browser_webcodecs_codec_string(
                request.selected_codec(),
                request.h264_profile.as_deref()
            ),
            "hev1.2.4.L156.B0"
        );
    }

    #[test]
    fn webcodecs_preview_binary_message_has_magic_header_and_payload() {
        let header = BrowserWebcodecsFrameHeader {
            message_type: "mrd.webcodecs.frame.v1",
            sequence: 7,
            timestamp_us: 77_000,
            duration_us: 6_944,
            capture_unix_us: 1_779_423_300_000_000,
            keyframe: true,
            codec: "avc1.640034",
            codec_format: "annexb",
            width: 2560,
            height: 1440,
        };

        let payload = [0, 0, 0, 1, 0x65, 0x88];
        let bytes = encode_webcodecs_chunk_message(&header, &payload).expect("encode chunk");

        assert!(validate_webcodecs_chunk_message(&bytes));
        assert_eq!(&bytes[..8], WEBCODECS_CHUNK_MAGIC);
        let header_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        assert!(header_len > 0);
        assert_eq!(&bytes[WEBCODECS_BINARY_HEADER_LEN + header_len..], &payload);
    }

    #[test]
    fn webcodecs_preview_codec_string_prefers_high_for_nvenc() {
        assert_eq!(
            browser_webcodecs_h264_codec_string(Some("nvenc_h264")),
            "avc1.640034"
        );
        assert_eq!(browser_webcodecs_h264_codec_string(None), "avc1.42e034");
        assert_eq!(
            browser_webcodecs_codec_string(BrowserWebcodecsPreviewCodec::Hevc, None),
            "hev1.1.6.L156.B0"
        );
        assert_eq!(
            browser_webcodecs_codec_string(BrowserWebcodecsPreviewCodec::HevcMain10, None),
            "hev1.2.4.L156.B0"
        );
    }

    #[test]
    fn webcodecs_preview_control_message_parses_keyframe_request() {
        let message: BrowserWebcodecsPreviewControlMessage =
            serde_json::from_str(r#"{"type":"request_keyframe"}"#).expect("parse request");
        assert!(matches!(
            message,
            BrowserWebcodecsPreviewControlMessage::RequestKeyframe
        ));
    }
}
