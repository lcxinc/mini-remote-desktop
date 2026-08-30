use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use mrd_encode_nvenc::NvencH264Encoder;
use mrd_encode_openh264::OpenH264Encoder;
use mrd_observability::{PipelineProbeSnapshot, ProbeRegistry, StageId};
use mrd_pipeline_core::{
    CapturedFrame, DecodedFrameData, FrameCapture, FramePixelFormat, PipelineError, VideoEncoder,
};
use mrd_proto::SessionId;
use mrd_transport_quic_quinn::{
    fragment_access_unit, QuicAuReassembler, QuicAuReassemblerConfig, QuicAuReassemblerStats,
    QuinnDatagramPair,
};

use crate::frame_sink::{DecodedFrameSink, DecodedFrameSnapshot, DEFAULT_SOURCE_ID};

mod tests {
    use super::*;

    #[tokio::test]
    async fn quic_single_process_pipeline_delivers_remote_frames() {
        let mut harness = QuicHostedPairHarness::new("session-quic-frames")
            .await
            .expect("create quic harness");

        harness.start().await.expect("start quic harness");
        harness
            .wait_for_first_frame(Duration::from_secs(5))
            .await
            .expect("remote frame");

        let sink_snapshot = harness.sink_snapshot().expect("sink snapshot");
        let sender_probe = harness.sender_probe();
        let receiver_probe = harness.receiver_probe();

        assert!(sink_snapshot.frame_count > 0);
        assert!(sender_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::SendWrite && stats.count > 0));
        assert!(receiver_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::DecodeTotal && stats.count > 0));
    }

    #[tokio::test]
    async fn quic_single_process_pipeline_exposes_probe_stages() {
        let mut harness = QuicHostedPairHarness::new("session-quic-probe")
            .await
            .expect("create quic harness");

        harness.start().await.expect("start quic harness");
        harness
            .wait_for_first_frame(Duration::from_secs(5))
            .await
            .expect("remote frame");

        let sender_probe = harness.sender_probe();
        let receiver_probe = harness.receiver_probe();

        assert!(sender_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::CaptureCopy && stats.count > 0));
        assert!(sender_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::EncodeTotal && stats.count > 0));
        assert!(sender_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::SendWrite && stats.count > 0));
        assert!(receiver_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::NetworkIngress && stats.count > 0));
        assert!(receiver_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::DecodeTotal && stats.count > 0));
        assert!(receiver_probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::FrameSinkIngest && stats.count > 0));
        assert!(receiver_probe
            .counters
            .iter()
            .any(|(name, _)| name == "quic_receiver_completed_frames"));
        assert!(receiver_probe
            .counters
            .iter()
            .any(|(name, _)| name == "quic_receiver_pending_frames"));
    }

    #[tokio::test]
    async fn quic_single_process_pipeline_runs_for_fixed_duration_without_stalling() {
        let mut harness = QuicHostedPairHarness::new("session-quic-stable")
            .await
            .expect("create quic harness");

        harness.start().await.expect("start quic harness");
        harness
            .wait_for_first_frame(Duration::from_secs(5))
            .await
            .expect("remote frame");

        let progress = harness
            .sample_frame_progress(Duration::from_secs(2), Duration::from_millis(250))
            .await;

        assert!(progress.start_frame_count > 0);
        assert!(progress.end_frame_count > progress.start_frame_count);
        assert!(progress.observed_samples > 0);
    }
}

struct FakeCapture {
    tick: u8,
}

impl FrameCapture for FakeCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, mrd_pipeline_core::PipelineError> {
        self.tick = self.tick.wrapping_add(1);
        let mut data = vec![0_u8; 16 * 16 * 4];
        for chunk in data.as_chunks_mut::<4>().0 {
            chunk[0] = self.tick;
            chunk[1] = 64;
            chunk[2] = 192;
            chunk[3] = 255;
        }

        Ok(CapturedFrame::from_cpu(
            16,
            16,
            FramePixelFormat::Bgra32,
            self.tick as u64 * 33_000,
            data,
        ))
    }
}

struct FrameProgressSample {
    start_frame_count: u64,
    end_frame_count: u64,
    observed_samples: usize,
}

pub(crate) struct QuicBenchmarkOutcome {
    pub sender_probe: PipelineProbeSnapshot,
    pub receiver_probe: PipelineProbeSnapshot,
    pub sink_snapshot: DecodedFrameSnapshot,
    pub first_frame_time_ms: f64,
    #[allow(dead_code)]
    pub transport_label: String,
}

struct QuicHostedPairHarness {
    pair: QuinnDatagramPair,
    sink: Arc<Mutex<DecodedFrameSink>>,
    probe_registry: ProbeRegistry,
    session_id: SessionId,
    running: Arc<AtomicBool>,
    sender_task: Option<tokio::task::JoinHandle<()>>,
    receiver_task: Option<tokio::task::JoinHandle<()>>,
}

impl QuicHostedPairHarness {
    async fn new(session_id: &str) -> Result<Self, String> {
        let pair = QuinnDatagramPair::loopback()
            .await
            .map_err(|error| format!("create quic loopback pair failed: {error}"))?;
        Ok(Self {
            pair,
            sink: Arc::new(Mutex::new(DecodedFrameSink::default())),
            probe_registry: ProbeRegistry::default(),
            session_id: SessionId(session_id.into()),
            running: Arc::new(AtomicBool::new(false)),
            sender_task: None,
            receiver_task: None,
        })
    }

    async fn start(&mut self) -> Result<(), String> {
        self.start_with_capture(FakeCapture { tick: 0 }, 16, 16, 30, "openh264")
            .await
    }

    async fn start_with_capture<C>(
        &mut self,
        mut capture: C,
        width: usize,
        height: usize,
        fps: u32,
        encode_backend: &str,
    ) -> Result<(), String>
    where
        C: FrameCapture + Send + 'static,
    {
        if self.running.swap(true, Ordering::Relaxed) {
            return Ok(());
        }

        let mut encoder = create_test_encoder(encode_backend, width, height, fps)
            .map_err(|error| format!("create encoder failed: {error}"))?;
        let sender_probe = self.probe_registry.session_handle(
            self.session_id.clone(),
            format!("{DEFAULT_SOURCE_ID}-sender"),
        );
        sender_probe.set_backend("synthetic");
        sender_probe.set_codec("h264");
        sender_probe.set_transport("quic_quinn");
        sender_probe.set_counter("quic_sender_encode_backend", 0);

        let receiver_probe = self
            .probe_registry
            .session_handle(self.session_id.clone(), DEFAULT_SOURCE_ID);
        receiver_probe.set_codec("h264");
        receiver_probe.set_transport("quic_quinn");

        let running = self.running.clone();
        let client = self.pair.client.clone();
        let encode_backend = encode_backend.to_string();
        let sender_task = tokio::spawn(async move {
            sender_probe.set_backend(format!("synthetic+{encode_backend}"));
            let mut last_tick = tokio::time::Instant::now();
            let mut frame_id = 0_u32;
            let max_datagram_size = client.max_datagram_size().unwrap_or(1200);
            while running.load(Ordering::Relaxed) {
                sender_probe.record_stage(StageId::CaptureWait, last_tick.elapsed(), 0, false);
                last_tick = tokio::time::Instant::now();

                let capture_started_at = std::time::Instant::now();
                let frame = match capture.capture_frame() {
                    Ok(frame) => frame,
                    Err(_) => break,
                };
                sender_probe.record_stage(
                    StageId::CaptureCopy,
                    capture_started_at.elapsed(),
                    frame.data.len(),
                    false,
                );

                let encode_started_at = std::time::Instant::now();
                let access_units = match encoder.encode(&frame) {
                    Ok(access_units) => access_units,
                    Err(_) => break,
                };
                for access_unit in access_units {
                    sender_probe.record_stage(
                        StageId::EncodeTotal,
                        encode_started_at.elapsed(),
                        access_unit.bytes.len(),
                        access_unit.is_keyframe,
                    );
                    let datagrams = match fragment_access_unit(
                        frame_id,
                        access_unit.timestamp_us,
                        access_unit.is_keyframe,
                        &access_unit.bytes,
                        max_datagram_size,
                    ) {
                        Ok(datagrams) => datagrams,
                        Err(_) => break,
                    };
                    let send_started_at = std::time::Instant::now();
                    let mut send_failed = false;
                    sender_probe.set_counter("quic_sender_fragments", datagrams.len() as u64);
                    for datagram in datagrams {
                        if client.send_datagram(datagram).is_err() {
                            send_failed = true;
                            break;
                        }
                    }
                    if send_failed {
                        break;
                    }
                    sender_probe.record_stage(
                        StageId::SendWrite,
                        send_started_at.elapsed(),
                        access_unit.bytes.len(),
                        access_unit.is_keyframe,
                    );
                    frame_id = frame_id.wrapping_add(1);
                }

                tokio::time::sleep(Duration::from_millis((1000 / fps.max(1)) as u64)).await;
            }
        });

        let running = self.running.clone();
        let sink = self.sink.clone();
        let session_id = self.session_id.clone();
        let server = self.pair.server.clone();
        let receiver_task = tokio::spawn(async move {
            let mut decoder = mrd_decode::create_decoder("h264_software").expect("decoder");
            let mut reassembler = QuicAuReassembler::new(QuicAuReassemblerConfig {
                frame_timeout: Duration::from_millis(250),
                max_pending_frames: 64,
            });
            let mut last_reassembly_drop_total = 0_u64;
            while running.load(Ordering::Relaxed) {
                let receive_started_at = std::time::Instant::now();
                let payload =
                    match tokio::time::timeout(Duration::from_millis(25), server.read_datagram())
                        .await
                    {
                        Ok(Ok(payload)) => payload,
                        Ok(Err(_)) => break,
                        Err(_) => {
                            reassembler.prune_expired();
                            let total_drops =
                                sync_reassembly_probe(&receiver_probe, reassembler.stats());
                            if total_drops > last_reassembly_drop_total {
                                receiver_probe.increment_dropped_frames(
                                    total_drops - last_reassembly_drop_total,
                                );
                                last_reassembly_drop_total = total_drops;
                            }
                            continue;
                        }
                    };
                receiver_probe.record_stage(
                    StageId::NetworkIngress,
                    receive_started_at.elapsed(),
                    payload.len(),
                    false,
                );

                let Some(frame) = (match reassembler.push_datagram(&payload) {
                    Ok(frame) => {
                        let total_drops =
                            sync_reassembly_probe(&receiver_probe, reassembler.stats());
                        if total_drops > last_reassembly_drop_total {
                            receiver_probe
                                .increment_dropped_frames(total_drops - last_reassembly_drop_total);
                            last_reassembly_drop_total = total_drops;
                        }
                        frame
                    }
                    Err(_) => {
                        receiver_probe.increment_dropped_frames(1);
                        receiver_probe.increment_counter("quic_receiver_reassembly_errors", 1);
                        let total_drops =
                            sync_reassembly_probe(&receiver_probe, reassembler.stats());
                        last_reassembly_drop_total = total_drops;
                        continue;
                    }
                }) else {
                    continue;
                };
                let decode_started_at = std::time::Instant::now();
                if decoder.push_access_unit(frame.payload.as_ref()).is_err() {
                    receiver_probe.increment_dropped_frames(1);
                    continue;
                }
                let frames = decoder.drain_decoded_frames();
                receiver_probe.record_stage(
                    StageId::DecodeTotal,
                    decode_started_at.elapsed(),
                    frame.payload.len(),
                    frame.is_keyframe,
                );
                for frame in frames {
                    let bytes = decoded_frame_data_len(&frame.data);
                    sink.lock().expect("lock sink").ingest_frame_for_source(
                        session_id.clone(),
                        DEFAULT_SOURCE_ID.to_string(),
                        frame,
                    );
                    receiver_probe.record_stage(
                        StageId::FrameSinkIngest,
                        Duration::from_millis(0),
                        bytes,
                        false,
                    );
                }
                let total_drops = sync_reassembly_probe(&receiver_probe, reassembler.stats());
                if total_drops > last_reassembly_drop_total {
                    receiver_probe
                        .increment_dropped_frames(total_drops - last_reassembly_drop_total);
                    last_reassembly_drop_total = total_drops;
                }
            }
        });

        self.sender_task = Some(sender_task);
        self.receiver_task = Some(receiver_task);
        Ok(())
    }

    async fn wait_for_first_frame(&self, timeout: Duration) -> Result<(), String> {
        tokio::time::timeout(timeout, async {
            loop {
                if self
                    .sink
                    .lock()
                    .expect("lock sink")
                    .snapshot(&self.session_id)
                    .map(|snapshot| snapshot.frame_count > 0)
                    .unwrap_or(false)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| {
            format!(
                "timed out waiting for first QUIC frame for {}",
                self.session_id.0
            )
        })
    }

    async fn sample_frame_progress(
        &self,
        duration: Duration,
        step: Duration,
    ) -> FrameProgressSample {
        let start_frame_count = self
            .sink_snapshot()
            .map(|snapshot| snapshot.frame_count)
            .unwrap_or(0);
        let started_at = tokio::time::Instant::now();
        let mut observed_samples = 0usize;
        while started_at.elapsed() < duration {
            tokio::time::sleep(step).await;
            observed_samples += 1;
        }
        let end_frame_count = self
            .sink_snapshot()
            .map(|snapshot| snapshot.frame_count)
            .unwrap_or(0);

        FrameProgressSample {
            start_frame_count,
            end_frame_count,
            observed_samples,
        }
    }

    fn sender_probe(&self) -> PipelineProbeSnapshot {
        self.probe_registry
            .snapshot(&self.session_id, &format!("{DEFAULT_SOURCE_ID}-sender"))
            .expect("sender probe snapshot")
    }

    fn receiver_probe(&self) -> PipelineProbeSnapshot {
        self.probe_registry
            .snapshot(&self.session_id, DEFAULT_SOURCE_ID)
            .expect("receiver probe snapshot")
    }

    fn sink_snapshot(&self) -> Option<DecodedFrameSnapshot> {
        self.sink
            .lock()
            .expect("lock sink")
            .snapshot(&self.session_id)
            .cloned()
    }
}

fn sync_reassembly_probe(
    receiver_probe: &mrd_observability::ProbeSessionHandle,
    stats: QuicAuReassemblerStats,
) -> u64 {
    receiver_probe.set_counter("quic_receiver_completed_frames", stats.completed_frames);
    receiver_probe.set_counter("quic_receiver_expired_frames", stats.expired_frames);
    receiver_probe.set_counter("quic_receiver_evicted_frames", stats.evicted_frames);
    receiver_probe.set_counter(
        "quic_receiver_duplicate_fragments",
        stats.duplicate_fragments,
    );
    receiver_probe.set_counter("quic_receiver_rejected_fragments", stats.rejected_fragments);
    receiver_probe.set_counter("quic_receiver_pending_frames", stats.pending_frames);
    let dropped = stats
        .expired_frames
        .saturating_add(stats.evicted_frames)
        .saturating_add(stats.rejected_fragments);
    receiver_probe.set_counter("quic_receiver_reassembly_drops", dropped);
    dropped
}

fn decoded_frame_data_len(data: &DecodedFrameData) -> usize {
    match data {
        DecodedFrameData::CpuRgb24(bytes) | DecodedFrameData::CpuBgra32(bytes) => bytes.len(),
        DecodedFrameData::CpuNv12 { data, .. }
        | DecodedFrameData::CpuI420 { data, .. }
        | DecodedFrameData::CpuP010 { data, .. } => data.len(),
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedNv12 { .. } => 0,
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedP010 { .. } => 0,
    }
}

pub(crate) async fn run_quic_benchmark_pipeline(
    session_id: SessionId,
    width: usize,
    height: usize,
    fps: u32,
    duration_secs: u64,
    encode_backend: &str,
    decode_backend: &str,
) -> Result<QuicBenchmarkOutcome, String> {
    let sink = Arc::new(Mutex::new(DecodedFrameSink::default()));
    let mut agent = crate::quic_host::QuicHost::default();
    let mut controller = crate::quic_host::QuicHost::with_frame_sink(sink.clone());
    let bootstrap = agent
        .prepare_listener(session_id.clone(), "127.0.0.1:0")
        .await?;
    controller
        .connect_to_peer(
            session_id.clone(),
            "127.0.0.1:0",
            &bootstrap,
            decode_backend,
        )
        .await?;
    agent.accept_peer(session_id.clone()).await?;
    agent
        .start_test_video_sender_with_backend(
            session_id.clone(),
            width,
            height,
            fps,
            encode_backend,
        )
        .await?;
    let started_at = std::time::Instant::now();
    controller
        .wait_for_first_frame(&session_id, Duration::from_secs(8))
        .await?;
    let first_frame_time_ms = started_at.elapsed().as_secs_f64() * 1000.0;
    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    let sender_probe = agent
        .sender_probe_snapshot(&session_id)
        .ok_or_else(|| format!("missing quic sender probe: {}", session_id.0))?;
    let receiver_probe = controller
        .probe_snapshot(&session_id)
        .ok_or_else(|| format!("missing quic receiver probe: {}", session_id.0))?;
    let sink_snapshot = sink
        .lock()
        .expect("lock decoded frame sink")
        .snapshot(&session_id)
        .cloned()
        .ok_or_else(|| format!("missing quic sink snapshot: {}", session_id.0))?;
    controller.close_session(&session_id).await?;
    agent.close_session(&session_id).await?;
    Ok(QuicBenchmarkOutcome {
        sender_probe,
        receiver_probe,
        sink_snapshot,
        first_frame_time_ms,
        transport_label: "quic_quinn".to_string(),
    })
}

enum QuicBenchmarkEncoder {
    OpenH264(Box<OpenH264Encoder>),
    Nvenc(Box<NvencH264Encoder>),
}

impl VideoEncoder for QuicBenchmarkEncoder {
    fn encode(
        &mut self,
        frame: &CapturedFrame,
    ) -> Result<Vec<mrd_pipeline_core::EncodedAccessUnit>, PipelineError> {
        match self {
            Self::OpenH264(encoder) => encoder.encode(frame),
            Self::Nvenc(encoder) => encoder.encode(frame),
        }
    }
}

fn create_test_encoder(
    backend: &str,
    width: usize,
    height: usize,
    fps: u32,
) -> Result<QuicBenchmarkEncoder, PipelineError> {
    match backend {
        "nvenc" => Ok(QuicBenchmarkEncoder::Nvenc(Box::new(
            NvencH264Encoder::new(width, height, fps)?,
        ))),
        "nvenc_ll_p1" => Ok(QuicBenchmarkEncoder::Nvenc(Box::new(
            NvencH264Encoder::new_low_latency_p1(width, height, fps)?,
        ))),
        "nvenc_hq_p5" => Ok(QuicBenchmarkEncoder::Nvenc(Box::new(
            NvencH264Encoder::new_high_quality_p5(width, height, fps)?,
        ))),
        "openh264" => Ok(QuicBenchmarkEncoder::OpenH264(Box::new(
            OpenH264Encoder::new(width, height, fps)?,
        ))),
        "openh264_speed" => Ok(QuicBenchmarkEncoder::OpenH264(Box::new(
            OpenH264Encoder::new_speed(width, height, fps)?,
        ))),
        other => Err(PipelineError::message(format!(
            "unsupported test encoder backend: {other}"
        ))),
    }
}

impl Drop for QuicHostedPairHarness {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(task) = self.sender_task.take() {
            task.abort();
        }
        if let Some(task) = self.receiver_task.take() {
            task.abort();
        }
    }
}
