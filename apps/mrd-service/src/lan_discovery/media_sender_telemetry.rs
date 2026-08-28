use super::{captured_frame_memory_path, DynamicWindowFpsDecision};
use anyhow::{Context, Result};
use mrd_ipc::{
    MediaProfile, MediaSenderTransportSnapshot, MediaStageMetrics, MediaTestImpairmentSnapshot,
};
use mrd_pipeline_core::{CapturedFrame, FramePixelFormat};
use mrd_transport_quic_quinn::{
    QuinnDatagramEndpoint, QUIC_AU_FRAGMENT_HEADER_LEN, QUIC_MEDIA_V3_FRAGMENT_HEADER_LEN,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::time::Instant;

const LAN_TEST_IMPAIRMENT_LOSS_PCT_ENV: &str = "MRD_LAN_TEST_IMPAIRMENT_LOSS_PCT";
const LAN_TEST_IMPAIRMENT_BASE_DELAY_MS_ENV: &str = "MRD_LAN_TEST_IMPAIRMENT_BASE_DELAY_MS";
const LAN_TEST_IMPAIRMENT_JITTER_MS_ENV: &str = "MRD_LAN_TEST_IMPAIRMENT_JITTER_MS";
const LAN_TEST_IMPAIRMENT_MTU_BYTES_ENV: &str = "MRD_LAN_TEST_IMPAIRMENT_MTU_BYTES";
const LAN_TEST_IMPAIRMENT_SEED_ENV: &str = "MRD_LAN_TEST_IMPAIRMENT_SEED";
const LAN_MEDIA_SENDER_STATS_MAGIC: &[u8; 8] = b"MRDMSTG1";
const LAN_MEDIA_SENDER_STATS_HEADER_BYTES: usize = 12;
const LAN_MEDIA_SENDER_STATS_INTERVAL: Duration = Duration::from_secs(1);
const LAN_MEDIA_SENDER_STATS_SAMPLE_LIMIT: usize = 240;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct LanSenderStatsPayload {
    pub(super) sequence: u64,
    pub(super) frame_count: u64,
    pub(super) source_id: Option<String>,
    pub(super) target_fps: u32,
    pub(super) target_bitrate_mbps: u32,
    pub(super) metrics: Vec<MediaStageMetrics>,
    #[serde(default)]
    pub(super) sender_transport: MediaSenderTransportSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) test_impairment: Option<MediaTestImpairmentSnapshot>,
}

#[derive(Debug)]
pub(super) struct LanSenderStatsTracker {
    samples: HashMap<&'static str, VecDeque<f64>>,
    frame_count: u64,
    pub(super) sender_transport: MediaSenderTransportSnapshot,
    last_emit: Instant,
}

#[derive(Debug, Clone, Default)]
pub(super) struct LanSenderDatagramFrameReport {
    pub(super) fragments_attempted: u64,
    pub(super) fragments_sent: u64,
    pub(super) fragments_delayed: u64,
    pub(super) fragments_dropped_by_impairment: u64,
    pub(super) fragments_dropped_for_capacity: u64,
    pub(super) fragments_dropped_for_budget: u64,
    pub(super) cut_short_for_capacity: bool,
    pub(super) cut_short_for_budget: bool,
}

#[derive(Debug, Clone)]
pub(super) struct LanMediaTestImpairment {
    loss_pct: f64,
    base_delay: Duration,
    jitter: Duration,
    mtu_bytes: Option<usize>,
    seed: u64,
    rng_state: u64,
    datagrams_sent: u64,
    datagrams_dropped: u64,
    datagrams_delayed: u64,
    datagrams_fragmented_by_mtu: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LanMediaDatagramDecision {
    pub(super) drop_datagram: bool,
    pub(super) delay: Duration,
}

impl LanSenderStatsTracker {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            samples: HashMap::new(),
            frame_count: 0,
            sender_transport: MediaSenderTransportSnapshot::default(),
            last_emit: now,
        }
    }

    pub(super) fn record_elapsed(&mut self, stage: &'static str, start: Instant) {
        self.record_ms(stage, start.elapsed().as_secs_f64() * 1000.0);
    }

    pub(super) fn record_ms(&mut self, stage: &'static str, duration_ms: f64) {
        if !duration_ms.is_finite() || duration_ms < 0.0 {
            return;
        }
        let samples = self.samples.entry(stage).or_default();
        samples.push_back(duration_ms);
        while samples.len() > LAN_MEDIA_SENDER_STATS_SAMPLE_LIMIT {
            samples.pop_front();
        }
    }

    pub(super) fn frame_completed(&mut self) {
        self.frame_count = self.frame_count.saturating_add(1);
        self.sender_transport.frames_completed =
            self.sender_transport.frames_completed.saturating_add(1);
    }

    pub(super) fn record_repeated_latest_frame(&mut self) {
        self.sender_transport.repeated_latest_frames = self
            .sender_transport
            .repeated_latest_frames
            .saturating_add(1);
    }

    pub(super) fn record_captured_frame(&mut self, frame: &CapturedFrame) {
        self.sender_transport.capture_frame_samples = self
            .sender_transport
            .capture_frame_samples
            .saturating_add(1);
        match captured_frame_memory_path(frame) {
            "macos_cv_pixel_buffer" => {
                self.sender_transport.capture_macos_cv_pixel_buffer_frames = self
                    .sender_transport
                    .capture_macos_cv_pixel_buffer_frames
                    .saturating_add(1);
            }
            "cpu" => {
                self.sender_transport.capture_cpu_frames =
                    self.sender_transport.capture_cpu_frames.saturating_add(1);
            }
            _ => {}
        }
        match frame.pixel_format {
            FramePixelFormat::Bgra32 => {
                self.sender_transport.capture_bgra32_frames = self
                    .sender_transport
                    .capture_bgra32_frames
                    .saturating_add(1);
            }
            FramePixelFormat::Rgba32 => {
                self.sender_transport.capture_rgba32_frames = self
                    .sender_transport
                    .capture_rgba32_frames
                    .saturating_add(1);
            }
            FramePixelFormat::Rgb24 => {
                self.sender_transport.capture_rgb24_frames =
                    self.sender_transport.capture_rgb24_frames.saturating_add(1);
            }
            FramePixelFormat::Nv12 => {
                self.sender_transport.capture_nv12_frames =
                    self.sender_transport.capture_nv12_frames.saturating_add(1);
            }
        }
    }

    pub(super) fn record_encoded_access_unit(&mut self, bytes: usize, is_keyframe: bool) {
        self.sender_transport.access_units_encoded =
            self.sender_transport.access_units_encoded.saturating_add(1);
        if is_keyframe {
            self.sender_transport.keyframes_encoded =
                self.sender_transport.keyframes_encoded.saturating_add(1);
        }
        self.sender_transport.encoded_access_unit_bytes = self
            .sender_transport
            .encoded_access_unit_bytes
            .saturating_add(bytes as u64);
    }

    pub(super) fn record_datagram_frame(&mut self, report: LanSenderDatagramFrameReport) {
        self.sender_transport.datagram_fragments_attempted = self
            .sender_transport
            .datagram_fragments_attempted
            .saturating_add(report.fragments_attempted);
        self.sender_transport.datagram_fragments_sent = self
            .sender_transport
            .datagram_fragments_sent
            .saturating_add(report.fragments_sent);
        self.sender_transport.datagram_fragments_delayed = self
            .sender_transport
            .datagram_fragments_delayed
            .saturating_add(report.fragments_delayed);
        self.sender_transport
            .datagram_fragments_dropped_by_impairment = self
            .sender_transport
            .datagram_fragments_dropped_by_impairment
            .saturating_add(report.fragments_dropped_by_impairment);
        self.sender_transport
            .datagram_fragments_dropped_for_capacity = self
            .sender_transport
            .datagram_fragments_dropped_for_capacity
            .saturating_add(report.fragments_dropped_for_capacity);
        self.sender_transport.datagram_fragments_dropped_for_budget = self
            .sender_transport
            .datagram_fragments_dropped_for_budget
            .saturating_add(report.fragments_dropped_for_budget);
        if report.cut_short_for_capacity {
            self.sender_transport.datagram_frames_cut_short_for_capacity = self
                .sender_transport
                .datagram_frames_cut_short_for_capacity
                .saturating_add(1);
        }
        if report.cut_short_for_budget {
            self.sender_transport.datagram_frames_cut_short_for_budget = self
                .sender_transport
                .datagram_frames_cut_short_for_budget
                .saturating_add(1);
        }
    }

    pub(super) fn record_reliable_frame(&mut self, fragments_sent: u64, frame_sent: bool) {
        self.sender_transport.reliable_fragments_sent = self
            .sender_transport
            .reliable_fragments_sent
            .saturating_add(fragments_sent);
        if frame_sent {
            self.sender_transport.reliable_frames_sent =
                self.sender_transport.reliable_frames_sent.saturating_add(1);
        }
    }

    pub(super) fn take_stage_metrics(&mut self, now: Instant) -> Option<Vec<MediaStageMetrics>> {
        if now.duration_since(self.last_emit) < LAN_MEDIA_SENDER_STATS_INTERVAL {
            return None;
        }
        self.last_emit = now;
        Some(self.stage_metrics())
    }

    fn stage_metrics(&self) -> Vec<MediaStageMetrics> {
        let mut metrics = self
            .samples
            .iter()
            .map(|(stage, samples)| MediaStageMetrics {
                stage: (*stage).to_string(),
                p50_ms: sender_stats_percentile(samples, 0.50),
                p95_ms: sender_stats_percentile(samples, 0.95),
            })
            .collect::<Vec<_>>();
        metrics.sort_by(|left, right| left.stage.cmp(&right.stage));
        metrics
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn take_payload(
        &mut self,
        now: Instant,
        sequence: u64,
        source_id: Option<String>,
        capture_source_kind: Option<String>,
        capture_memory_path: Option<String>,
        profile: &MediaProfile,
        dynamic_fps_decision: Option<DynamicWindowFpsDecision>,
        test_impairment: Option<MediaTestImpairmentSnapshot>,
    ) -> Option<LanSenderStatsPayload> {
        let metrics = self.take_stage_metrics(now)?;
        let mut sender_transport = self.sender_transport.clone();
        sender_transport.capture_source_id = source_id.clone();
        sender_transport.capture_source_kind = capture_source_kind;
        sender_transport.capture_memory_path = capture_memory_path;
        sender_transport.dynamic_fps_tier =
            dynamic_fps_decision.map(|decision| decision.tier.as_str().to_string());
        sender_transport.target_fps = Some(
            dynamic_fps_decision
                .map(|decision| decision.target_fps)
                .unwrap_or(profile.fps),
        );
        Some(LanSenderStatsPayload {
            sequence,
            frame_count: self.frame_count,
            source_id,
            target_fps: profile.fps,
            target_bitrate_mbps: profile.bitrate_mbps,
            metrics,
            sender_transport,
            test_impairment,
        })
    }
}

impl LanMediaTestImpairment {
    pub(super) fn from_env() -> Result<Self> {
        Self::from_env_lookup(|key| std::env::var(key).ok())
    }

    pub(super) fn from_env_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let loss_pct =
            parse_env_f64(&lookup, LAN_TEST_IMPAIRMENT_LOSS_PCT_ENV, 0.0)?.clamp(0.0, 100.0);
        let base_delay_ms = parse_env_u64(&lookup, LAN_TEST_IMPAIRMENT_BASE_DELAY_MS_ENV, 0)?;
        let jitter_ms = parse_env_u64(&lookup, LAN_TEST_IMPAIRMENT_JITTER_MS_ENV, 0)?;
        let mtu_bytes = lookup(LAN_TEST_IMPAIRMENT_MTU_BYTES_ENV)
            .and_then(|value| {
                let trimmed = value.trim().to_string();
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .map(|value| {
                value.parse::<usize>().with_context(|| {
                    format!("invalid {LAN_TEST_IMPAIRMENT_MTU_BYTES_ENV}: {value}")
                })
            })
            .transpose()?;
        let seed = parse_env_u64(&lookup, LAN_TEST_IMPAIRMENT_SEED_ENV, 0x4d52_444c_414e)?;
        Ok(Self {
            loss_pct,
            base_delay: Duration::from_millis(base_delay_ms),
            jitter: Duration::from_millis(jitter_ms),
            mtu_bytes,
            seed,
            rng_state: seed.max(1),
            datagrams_sent: 0,
            datagrams_dropped: 0,
            datagrams_delayed: 0,
            datagrams_fragmented_by_mtu: 0,
        })
    }

    pub(super) fn enabled(&self) -> bool {
        self.loss_pct > 0.0
            || !self.base_delay.is_zero()
            || !self.jitter.is_zero()
            || self.mtu_bytes.is_some()
    }

    pub(super) fn effective_datagram_size(&self, negotiated_size: usize) -> usize {
        let minimum = QUIC_MEDIA_V3_FRAGMENT_HEADER_LEN.max(QUIC_AU_FRAGMENT_HEADER_LEN) + 1;
        self.mtu_bytes
            .map(|mtu| mtu.clamp(minimum, negotiated_size))
            .unwrap_or(negotiated_size)
    }

    pub(super) fn record_mtu_fragmentation(&mut self, negotiated_size: usize) {
        if self.effective_datagram_size(negotiated_size) < negotiated_size {
            self.datagrams_fragmented_by_mtu = self.datagrams_fragmented_by_mtu.saturating_add(1);
        }
    }

    pub(super) fn next_datagram_decision(&mut self) -> LanMediaDatagramDecision {
        let loss_roll = self.next_unit_f64() * 100.0;
        let drop_datagram = self.loss_pct > 0.0 && loss_roll < self.loss_pct;
        let delay = self.next_delay();

        if drop_datagram {
            self.datagrams_dropped = self.datagrams_dropped.saturating_add(1);
        } else {
            self.datagrams_sent = self.datagrams_sent.saturating_add(1);
        }

        LanMediaDatagramDecision {
            drop_datagram,
            delay,
        }
    }

    pub(super) fn next_delay(&mut self) -> Duration {
        let jitter_ms = if self.jitter.is_zero() {
            0
        } else {
            let jitter_bound = self.jitter.as_millis() as u64;
            self.next_u64() % (jitter_bound.saturating_add(1))
        };
        let delay = self.base_delay + Duration::from_millis(jitter_ms);
        if !delay.is_zero() {
            self.datagrams_delayed = self.datagrams_delayed.saturating_add(1);
        }
        delay
    }

    pub(super) fn snapshot(&self) -> Option<MediaTestImpairmentSnapshot> {
        self.enabled().then(|| MediaTestImpairmentSnapshot {
            loss_pct: self.loss_pct,
            base_delay_ms: self.base_delay.as_millis() as u64,
            jitter_ms: self.jitter.as_millis() as u64,
            mtu_bytes: self.mtu_bytes.map(|value| value as u32),
            seed: self.seed,
            datagrams_sent: self.datagrams_sent,
            datagrams_dropped: self.datagrams_dropped,
            datagrams_delayed: self.datagrams_delayed,
            datagrams_fragmented_by_mtu: self.datagrams_fragmented_by_mtu,
        })
    }

    fn next_unit_f64(&mut self) -> f64 {
        (self.next_u64() as f64) / (u64::MAX as f64)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x.max(1);
        self.rng_state
    }
}

pub(super) fn send_lan_sender_stats_datagram(
    endpoint: &QuinnDatagramEndpoint,
    max_datagram_size: usize,
    payload: &LanSenderStatsPayload,
) -> Result<()> {
    let datagram = encode_lan_sender_stats_datagram(payload)?;
    if datagram.len() > max_datagram_size {
        anyhow::bail!(
            "LAN sender stats datagram too large: {} > {}",
            datagram.len(),
            max_datagram_size
        );
    }
    endpoint
        .send_datagram(datagram.into())
        .context("failed to send LAN sender stats datagram")
}

pub(super) fn encode_lan_sender_stats_datagram(payload: &LanSenderStatsPayload) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(payload).context("failed to encode LAN sender stats payload")?;
    let payload_len =
        u32::try_from(json.len()).context("LAN sender stats payload exceeds u32 length")?;
    let mut frame = Vec::with_capacity(LAN_MEDIA_SENDER_STATS_HEADER_BYTES + json.len());
    frame.extend_from_slice(LAN_MEDIA_SENDER_STATS_MAGIC);
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

pub(super) fn decode_lan_sender_stats_datagram(
    frame: &[u8],
) -> Result<Option<LanSenderStatsPayload>> {
    if !frame.starts_with(LAN_MEDIA_SENDER_STATS_MAGIC) {
        return Ok(None);
    }
    if frame.len() < LAN_MEDIA_SENDER_STATS_HEADER_BYTES {
        anyhow::bail!("LAN sender stats datagram is too small");
    }
    let payload_len = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
    let Some(expected_len) = LAN_MEDIA_SENDER_STATS_HEADER_BYTES.checked_add(payload_len) else {
        anyhow::bail!("LAN sender stats datagram payload length overflow");
    };
    if frame.len() != expected_len {
        anyhow::bail!(
            "LAN sender stats datagram payload length mismatch: expected {}, got {}",
            expected_len,
            frame.len()
        );
    }
    let payload = serde_json::from_slice(&frame[LAN_MEDIA_SENDER_STATS_HEADER_BYTES..])
        .context("failed to decode LAN sender stats payload")?;
    Ok(Some(payload))
}

fn parse_env_u64(
    lookup: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    default: u64,
) -> Result<u64> {
    let Some(value) = lookup(key) else {
        return Ok(default);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse::<u64>()
        .with_context(|| format!("invalid {key}: {value}"))
}

fn parse_env_f64(
    lookup: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    default: f64,
) -> Result<f64> {
    let Some(value) = lookup(key) else {
        return Ok(default);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse::<f64>()
        .with_context(|| format!("invalid {key}: {value}"))
}

fn sender_stats_percentile(samples: &VecDeque<f64>, quantile: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.iter().copied().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let last = sorted.len().saturating_sub(1);
    let index = ((last as f64) * quantile.clamp(0.0, 1.0)).round() as usize;
    sorted.get(index).copied()
}
