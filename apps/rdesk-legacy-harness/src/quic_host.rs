use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use mrd_capture_dxgi::DxgiDesktopCapture;
use mrd_decode::VideoDecoder;
use mrd_encode_nvenc::NvencH264Encoder;
use mrd_encode_openh264::OpenH264Encoder;
use mrd_observability::{
    MediaProbeEvent, PipelineProbeSnapshot, ProbeRegistry, ProbeSessionHandle, StageId,
};
use mrd_pipeline_core::{
    CapturedFrame, DecodedFrame, FrameCapture, FramePixelFormat, PipelineError, VideoEncoder,
};
use mrd_proto::SessionId;
use mrd_transport_quic_quinn::{
    fragment_access_unit, QuicAuReassembler, QuicAuReassemblerConfig, QuicAuReassemblerStats,
    QuinnDatagramEndpoint, QuinnServerBootstrap, QuinnServerListener,
};
use tokio::task::JoinHandle;

use crate::frame_sink::{DecodedFrameSink, DEFAULT_SOURCE_ID};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicHostSnapshot {
    pub transport: String,
    pub local_addr: Option<String>,
    pub peer_addr: Option<String>,
    pub remote_datagram_count: u64,
    pub remote_access_unit_count: u64,
    pub decoded_frame_count: u64,
    pub last_decoded_width: usize,
    pub last_decoded_height: usize,
    pub last_decoded_pixel_format: Option<String>,
    pub sent_access_unit_count: u64,
    pub sender_running: bool,
    pub receiver_running: bool,
    pub active_decode_backend: Option<String>,
    pub last_error: Option<String>,
}

struct PendingServerSession {
    bootstrap: QuinnServerBootstrap,
    accept_task: JoinHandle<Result<QuinnDatagramEndpoint, String>>,
}

struct HostedQuicPeer {
    snapshot: Arc<Mutex<QuicHostSnapshot>>,
    endpoint: Option<QuinnDatagramEndpoint>,
    pending_server: Option<PendingServerSession>,
    sender_running: Arc<AtomicBool>,
    receiver_running: Arc<AtomicBool>,
    sender_task: Option<JoinHandle<()>>,
    receiver_task: Option<JoinHandle<()>>,
}

impl HostedQuicPeer {
    fn new() -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(QuicHostSnapshot::default())),
            endpoint: None,
            pending_server: None,
            sender_running: Arc::new(AtomicBool::new(false)),
            receiver_running: Arc::new(AtomicBool::new(false)),
            sender_task: None,
            receiver_task: None,
        }
    }

    fn stop_tasks(&mut self) {
        self.sender_running.store(false, Ordering::Relaxed);
        self.receiver_running.store(false, Ordering::Relaxed);
        if let Some(task) = self.sender_task.take() {
            task.abort();
        }
        if let Some(task) = self.receiver_task.take() {
            task.abort();
        }
        if let Some(pending_server) = self.pending_server.take() {
            pending_server.accept_task.abort();
        }
    }
}

#[derive(Default)]
pub struct QuicHost {
    sessions: HashMap<SessionId, HostedQuicPeer>,
    frame_sink: Option<Arc<Mutex<DecodedFrameSink>>>,
    probe_registry: ProbeRegistry,
}

impl QuicHost {
    pub fn with_frame_sink(frame_sink: Arc<Mutex<DecodedFrameSink>>) -> Self {
        Self::with_frame_sink_and_probes(frame_sink, ProbeRegistry::default())
    }

    pub fn with_frame_sink_and_probes(
        frame_sink: Arc<Mutex<DecodedFrameSink>>,
        probe_registry: ProbeRegistry,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            frame_sink: Some(frame_sink),
            probe_registry,
        }
    }

    pub async fn prepare_listener(
        &mut self,
        session_id: SessionId,
        bind_addr: &str,
    ) -> Result<QuinnServerBootstrap, String> {
        let (listener, bootstrap) = QuinnServerListener::bind(bind_addr)
            .await
            .map_err(|error| format!("bind quic listener failed: {error}"))?;
        let local_addr = bootstrap.listen_addr.to_string();
        let accept_task = tokio::spawn(async move {
            listener
                .accept()
                .await
                .map_err(|error| format!("accept quic peer failed: {error}"))
        });
        let session = self
            .sessions
            .entry(session_id)
            .or_insert_with(HostedQuicPeer::new);
        session.stop_tasks();
        session.pending_server = Some(PendingServerSession {
            bootstrap: bootstrap.clone(),
            accept_task,
        });
        let mut snapshot = session.snapshot.lock().expect("lock quic snapshot");
        snapshot.transport = bootstrap.transport.to_string();
        snapshot.local_addr = Some(local_addr);
        Ok(bootstrap)
    }

    pub async fn accept_peer(&mut self, session_id: SessionId) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("unknown quic session: {}", session_id.0))?;
        let pending = session
            .pending_server
            .take()
            .ok_or_else(|| format!("missing pending quic listener: {}", session_id.0))?;
        let endpoint = pending
            .accept_task
            .await
            .map_err(|error| format!("join quic accept task failed: {error}"))??;
        {
            let mut snapshot = session.snapshot.lock().expect("lock quic snapshot");
            snapshot.transport = pending.bootstrap.transport.to_string();
            snapshot.local_addr = Some(endpoint.metadata().local_addr.to_string());
            snapshot.peer_addr = Some(endpoint.metadata().peer_addr.to_string());
        }
        session.endpoint = Some(endpoint);
        Ok(())
    }

    pub async fn connect_to_peer(
        &mut self,
        session_id: SessionId,
        bind_addr: &str,
        bootstrap: &QuinnServerBootstrap,
        decode_backend: &str,
    ) -> Result<(), String> {
        let endpoint = QuinnDatagramEndpoint::connect_client(bind_addr, bootstrap)
            .await
            .map_err(|error| format!("connect quic client failed: {error}"))?;
        let session = self
            .sessions
            .entry(session_id.clone())
            .or_insert_with(HostedQuicPeer::new);
        session.endpoint = Some(endpoint.clone());
        {
            let mut snapshot = session.snapshot.lock().expect("lock quic snapshot");
            snapshot.transport = bootstrap.transport.to_string();
            snapshot.local_addr = Some(endpoint.metadata().local_addr.to_string());
            snapshot.peer_addr = Some(endpoint.metadata().peer_addr.to_string());
            snapshot.active_decode_backend = Some(decode_backend.to_string());
        }
        self.start_receiver_task(session_id, decode_backend)
    }

    pub async fn start_test_video_sender_with_backend(
        &mut self,
        session_id: SessionId,
        width: usize,
        height: usize,
        fps: u32,
        encode_backend: &str,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("unknown quic session: {}", session_id.0))?;
        let endpoint = session
            .endpoint
            .clone()
            .ok_or_else(|| format!("quic session missing endpoint: {}", session_id.0))?;
        let encoder = create_test_encoder(encode_backend, width, height, fps)
            .map_err(|error| format!("create encoder failed: {error}"))?;
        let capture = BenchmarkCapture {
            tick: 0,
            width,
            height,
        };
        let snapshot = session.snapshot.clone();
        let sender_running = session.sender_running.clone();
        sender_running.store(true, Ordering::Relaxed);
        let probe = self
            .probe_registry
            .session_handle(session_id.clone(), format!("{DEFAULT_SOURCE_ID}-sender"));
        probe.set_backend(format!("synthetic+{encode_backend}"));
        probe.set_codec("h264");
        probe.set_transport("quic_quinn");
        let task = tokio::spawn(async move {
            run_sender_loop(
                endpoint,
                snapshot,
                sender_running,
                probe,
                capture,
                encoder,
                fps,
            )
            .await;
        });
        session.sender_task = Some(task);
        Ok(())
    }

    pub async fn start_embedded_desktop_sender(
        &mut self,
        session_id: SessionId,
        fps: u32,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("unknown quic session: {}", session_id.0))?;
        if session.sender_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        let endpoint = session
            .endpoint
            .clone()
            .ok_or_else(|| format!("quic session missing endpoint: {}", session_id.0))?;
        let snapshot = session.snapshot.clone();
        let sender_running = session.sender_running.clone();
        sender_running.store(true, Ordering::Relaxed);
        let probe = self
            .probe_registry
            .session_handle(session_id, format!("{DEFAULT_SOURCE_ID}-sender"));
        probe.set_backend("dxgi");
        probe.set_codec("h264");
        probe.set_transport("quic_quinn");
        let frame_interval = Duration::from_millis((1000 / fps.max(1)) as u64);
        let task = tokio::task::spawn_blocking(move || {
            let mut capture = match DxgiDesktopCapture::new_primary() {
                Ok(capture) => capture,
                Err(error) => {
                    let mut snapshot = snapshot.lock().expect("lock quic snapshot");
                    snapshot.sender_running = false;
                    snapshot.last_error = Some(format!("create dxgi capture failed: {error}"));
                    sender_running.store(false, Ordering::Relaxed);
                    return;
                }
            };
            let mut encoder = match OpenH264Encoder::new(capture.width(), capture.height(), fps) {
                Ok(encoder) => encoder,
                Err(error) => {
                    let mut snapshot = snapshot.lock().expect("lock quic snapshot");
                    snapshot.sender_running = false;
                    snapshot.last_error = Some(format!("create openh264 encoder failed: {error}"));
                    sender_running.store(false, Ordering::Relaxed);
                    return;
                }
            };
            run_blocking_sender_loop(
                &mut capture,
                &mut encoder,
                frame_interval,
                endpoint,
                snapshot,
                sender_running,
                probe,
            );
        });
        session.sender_task = Some(task);
        Ok(())
    }

    pub async fn wait_for_first_frame(
        &self,
        session_id: &SessionId,
        timeout: Duration,
    ) -> Result<(), String> {
        let frame_sink = self
            .frame_sink
            .as_ref()
            .ok_or_else(|| "quic host missing frame sink".to_string())?
            .clone();
        tokio::time::timeout(timeout, async move {
            loop {
                if frame_sink
                    .lock()
                    .expect("lock decoded frame sink")
                    .snapshot(session_id)
                    .map(|snapshot| snapshot.frame_count > 0)
                    .unwrap_or(false)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| {
            format!(
                "timed out waiting for first QUIC frame for {}",
                session_id.0
            )
        })
    }

    pub fn snapshot(&self, session_id: &SessionId) -> Option<QuicHostSnapshot> {
        self.sessions
            .get(session_id)
            .map(|session| session.snapshot.lock().expect("lock quic snapshot").clone())
    }

    pub fn probe_snapshot(&self, session_id: &SessionId) -> Option<PipelineProbeSnapshot> {
        self.probe_registry.snapshot(session_id, DEFAULT_SOURCE_ID)
    }

    pub fn sender_probe_snapshot(&self, session_id: &SessionId) -> Option<PipelineProbeSnapshot> {
        self.probe_registry
            .snapshot(session_id, &format!("{DEFAULT_SOURCE_ID}-sender"))
    }

    pub fn probe_recent_events(
        &self,
        session_id: &SessionId,
        limit: usize,
    ) -> Vec<MediaProbeEvent> {
        self.probe_registry
            .recent_events(session_id, DEFAULT_SOURCE_ID, limit)
    }

    pub async fn close_session(&mut self, session_id: &SessionId) -> Result<(), String> {
        let Some(mut session) = self.sessions.remove(session_id) else {
            return Ok(());
        };
        session.stop_tasks();
        Ok(())
    }

    pub async fn stop_embedded_video_sender(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| format!("unknown quic session: {}", session_id.0))?;
        session.sender_running.store(false, Ordering::Relaxed);
        if let Some(task) = session.sender_task.take() {
            task.abort();
            let _ = task.await;
        }
        session
            .snapshot
            .lock()
            .expect("lock quic snapshot")
            .sender_running = false;
        Ok(())
    }

    fn start_receiver_task(
        &mut self,
        session_id: SessionId,
        decode_backend: &str,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| format!("unknown quic session: {}", session_id.0))?;
        let endpoint = session
            .endpoint
            .clone()
            .ok_or_else(|| format!("quic session missing endpoint: {}", session_id.0))?;
        let decoder = mrd_decode::create_decoder(decode_backend)
            .map_err(|error| format!("create decoder failed: {error}"))?;
        let snapshot = session.snapshot.clone();
        let frame_sink = self.frame_sink.clone();
        let receiver_running = session.receiver_running.clone();
        receiver_running.store(true, Ordering::Relaxed);
        let probe = self
            .probe_registry
            .session_handle(session_id.clone(), DEFAULT_SOURCE_ID);
        probe.set_codec("h264");
        probe.set_transport("quic_quinn");
        let task = tokio::spawn(async move {
            run_receiver_loop(
                session_id,
                endpoint,
                snapshot,
                frame_sink,
                receiver_running,
                probe,
                decoder,
            )
            .await;
        });
        session.receiver_task = Some(task);
        Ok(())
    }
}

impl Drop for QuicHost {
    fn drop(&mut self) {
        for session in self.sessions.values_mut() {
            session.stop_tasks();
        }
    }
}

async fn run_sender_loop(
    endpoint: QuinnDatagramEndpoint,
    snapshot: Arc<Mutex<QuicHostSnapshot>>,
    running: Arc<AtomicBool>,
    probe: ProbeSessionHandle,
    mut capture: BenchmarkCapture,
    mut encoder: QuicHostEncoder,
    fps: u32,
) {
    let mut frame_id = 0_u32;
    let mut last_tick = tokio::time::Instant::now();
    let max_datagram_size = endpoint.max_datagram_size().unwrap_or(1200);
    snapshot.lock().expect("lock quic snapshot").sender_running = true;
    while running.load(Ordering::Relaxed) {
        probe.record_stage(StageId::CaptureWait, last_tick.elapsed(), 0, false);
        last_tick = tokio::time::Instant::now();

        let capture_started_at = std::time::Instant::now();
        let frame = match capture.capture_frame() {
            Ok(frame) => frame,
            Err(error) => {
                snapshot.lock().expect("lock quic snapshot").last_error =
                    Some(format!("capture_frame failed: {error}"));
                break;
            }
        };
        probe.record_stage(
            StageId::CaptureCopy,
            capture_started_at.elapsed(),
            frame.data.len(),
            false,
        );

        let encode_started_at = std::time::Instant::now();
        let access_units = match encoder.encode(&frame) {
            Ok(access_units) => access_units,
            Err(error) => {
                snapshot.lock().expect("lock quic snapshot").last_error =
                    Some(format!("encode failed: {error}"));
                break;
            }
        };
        for access_unit in access_units {
            probe.record_stage(
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
                Err(error) => {
                    snapshot.lock().expect("lock quic snapshot").last_error =
                        Some(format!("fragment_access_unit failed: {error}"));
                    break;
                }
            };
            let send_started_at = std::time::Instant::now();
            let mut send_failed = false;
            for datagram in datagrams {
                if endpoint.send_datagram(datagram).is_err() {
                    snapshot.lock().expect("lock quic snapshot").last_error =
                        Some("send_datagram failed".to_string());
                    send_failed = true;
                    break;
                }
            }
            if send_failed {
                break;
            }
            {
                let mut snapshot = snapshot.lock().expect("lock quic snapshot");
                snapshot.sender_running = true;
                snapshot.sent_access_unit_count += 1;
            }
            probe.record_stage(
                StageId::SendWrite,
                send_started_at.elapsed(),
                access_unit.bytes.len(),
                access_unit.is_keyframe,
            );
            frame_id = frame_id.wrapping_add(1);
        }

        tokio::time::sleep(Duration::from_millis((1000 / fps.max(1)) as u64)).await;
    }
    snapshot.lock().expect("lock quic snapshot").sender_running = false;
}

async fn run_receiver_loop(
    session_id: SessionId,
    endpoint: QuinnDatagramEndpoint,
    snapshot: Arc<Mutex<QuicHostSnapshot>>,
    frame_sink: Option<Arc<Mutex<DecodedFrameSink>>>,
    running: Arc<AtomicBool>,
    probe: ProbeSessionHandle,
    mut decoder: Box<dyn VideoDecoder>,
) {
    let mut reassembler = QuicAuReassembler::new(QuicAuReassemblerConfig {
        frame_timeout: Duration::from_millis(250),
        max_pending_frames: 64,
    });
    let mut last_reassembly_drop_total = 0_u64;
    while running.load(Ordering::Relaxed) {
        let receive_started_at = std::time::Instant::now();
        let payload =
            match tokio::time::timeout(Duration::from_millis(25), endpoint.read_datagram()).await {
                Ok(Ok(payload)) => payload,
                Ok(Err(error)) => {
                    snapshot.lock().expect("lock quic snapshot").last_error =
                        Some(format!("read_datagram failed: {error}"));
                    break;
                }
                Err(_) => {
                    reassembler.prune_expired();
                    last_reassembly_drop_total = sync_reassembly_probe(
                        &probe,
                        reassembler.stats(),
                        last_reassembly_drop_total,
                    );
                    continue;
                }
            };
        {
            let mut snapshot = snapshot.lock().expect("lock quic snapshot");
            snapshot.receiver_running = true;
            snapshot.remote_datagram_count += 1;
        }
        probe.record_stage(
            StageId::NetworkIngress,
            receive_started_at.elapsed(),
            payload.len(),
            false,
        );

        let Some(frame) = (match reassembler.push_datagram(&payload) {
            Ok(frame) => {
                last_reassembly_drop_total =
                    sync_reassembly_probe(&probe, reassembler.stats(), last_reassembly_drop_total);
                frame
            }
            Err(_) => {
                probe.increment_dropped_frames(1);
                probe.increment_counter("quic_receiver_reassembly_errors", 1);
                last_reassembly_drop_total =
                    sync_reassembly_probe(&probe, reassembler.stats(), last_reassembly_drop_total);
                continue;
            }
        }) else {
            continue;
        };
        {
            let mut snapshot = snapshot.lock().expect("lock quic snapshot");
            snapshot.remote_access_unit_count += 1;
        }
        let decode_started_at = std::time::Instant::now();
        if decoder.push_access_unit(frame.payload.as_ref()).is_err() {
            snapshot.lock().expect("lock quic snapshot").last_error =
                Some("decoder push_access_unit failed".to_string());
            probe.increment_dropped_frames(1);
            continue;
        }
        let frames = decoder.drain_decoded_frames();
        probe.record_stage(
            StageId::DecodeTotal,
            decode_started_at.elapsed(),
            frame.payload.len(),
            frame.is_keyframe,
        );
        apply_decoded_frames_to_snapshot(
            session_id.clone(),
            snapshot.clone(),
            frame_sink.clone(),
            probe.clone(),
            frames,
        );
        last_reassembly_drop_total =
            sync_reassembly_probe(&probe, reassembler.stats(), last_reassembly_drop_total);
    }
    snapshot
        .lock()
        .expect("lock quic snapshot")
        .receiver_running = false;
}

fn apply_decoded_frames_to_snapshot(
    session_id: SessionId,
    snapshot: Arc<Mutex<QuicHostSnapshot>>,
    frame_sink: Option<Arc<Mutex<DecodedFrameSink>>>,
    probe: ProbeSessionHandle,
    frames: Vec<DecodedFrame>,
) {
    if frames.is_empty() {
        return;
    }

    let mut snapshot_guard = snapshot.lock().expect("lock quic snapshot");
    for frame in frames {
        snapshot_guard.decoded_frame_count += 1;
        snapshot_guard.last_decoded_width = frame.width;
        snapshot_guard.last_decoded_height = frame.height;
        use mrd_pipeline_core::DecodedFrameData;
        snapshot_guard.last_decoded_pixel_format = Some(match &frame.data {
            DecodedFrameData::CpuRgb24(_) => "Rgb24".to_string(),
            DecodedFrameData::CpuBgra32(_) => "Bgra32".to_string(),
            DecodedFrameData::CpuI420 { .. } => "I420".to_string(),
            DecodedFrameData::CpuNv12 { .. } => "Nv12".to_string(),
            DecodedFrameData::CpuP010 { .. } => "P010".to_string(),
            #[cfg(windows)]
            DecodedFrameData::D3D11SharedNv12 { .. } => "D3d11Texture".to_string(),
            #[cfg(windows)]
            DecodedFrameData::D3D11SharedP010 { .. } => "D3d11Texture".to_string(),
        });
        if let Some(frame_sink) = frame_sink.as_ref() {
            let bytes = frame.cpu_bytes().map(|b| b.len()).unwrap_or(0);
            let started_at = std::time::Instant::now();
            frame_sink
                .lock()
                .expect("lock decoded frame sink")
                .ingest_frame_for_source(session_id.clone(), DEFAULT_SOURCE_ID.to_string(), frame);
            probe.record_stage(StageId::FrameSinkIngest, started_at.elapsed(), bytes, false);
        }
    }
}

fn sync_reassembly_probe(
    receiver_probe: &ProbeSessionHandle,
    stats: QuicAuReassemblerStats,
    last_reassembly_drop_total: u64,
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
    if dropped > last_reassembly_drop_total {
        receiver_probe.increment_dropped_frames(dropped - last_reassembly_drop_total);
    }
    dropped
}

fn run_blocking_sender_loop<C, E>(
    capture: &mut C,
    encoder: &mut E,
    frame_interval: Duration,
    endpoint: QuinnDatagramEndpoint,
    snapshot: Arc<Mutex<QuicHostSnapshot>>,
    running: Arc<AtomicBool>,
    probe: ProbeSessionHandle,
) where
    C: FrameCapture,
    E: VideoEncoder,
{
    let mut frame_id = 0_u32;
    let mut last_tick = std::time::Instant::now();
    let max_datagram_size = endpoint.max_datagram_size().unwrap_or(1200);
    snapshot.lock().expect("lock quic snapshot").sender_running = true;
    while running.load(Ordering::Relaxed) {
        probe.record_stage(StageId::CaptureWait, last_tick.elapsed(), 0, false);
        last_tick = std::time::Instant::now();

        let capture_started_at = std::time::Instant::now();
        let frame = match capture.capture_frame() {
            Ok(frame) => frame,
            Err(error) => {
                snapshot.lock().expect("lock quic snapshot").last_error =
                    Some(format!("capture_frame failed: {error}"));
                break;
            }
        };
        probe.record_stage(
            StageId::CaptureCopy,
            capture_started_at.elapsed(),
            frame.data.len(),
            false,
        );

        let encode_started_at = std::time::Instant::now();
        let access_units = match encoder.encode(&frame) {
            Ok(access_units) => access_units,
            Err(error) => {
                snapshot.lock().expect("lock quic snapshot").last_error =
                    Some(format!("encode failed: {error}"));
                break;
            }
        };
        for access_unit in access_units {
            probe.record_stage(
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
                Err(error) => {
                    snapshot.lock().expect("lock quic snapshot").last_error =
                        Some(format!("fragment_access_unit failed: {error}"));
                    break;
                }
            };
            let send_started_at = std::time::Instant::now();
            let mut send_failed = false;
            for datagram in datagrams {
                if endpoint.send_datagram(datagram).is_err() {
                    snapshot.lock().expect("lock quic snapshot").last_error =
                        Some("send_datagram failed".to_string());
                    send_failed = true;
                    break;
                }
            }
            if send_failed {
                break;
            }
            {
                let mut snapshot = snapshot.lock().expect("lock quic snapshot");
                snapshot.sender_running = true;
                snapshot.sent_access_unit_count += 1;
            }
            probe.record_stage(
                StageId::SendWrite,
                send_started_at.elapsed(),
                access_unit.bytes.len(),
                access_unit.is_keyframe,
            );
            frame_id = frame_id.wrapping_add(1);
        }

        std::thread::sleep(frame_interval);
    }
    snapshot.lock().expect("lock quic snapshot").sender_running = false;
}

enum QuicHostEncoder {
    OpenH264(Box<OpenH264Encoder>),
    Nvenc(Box<NvencH264Encoder>),
}

impl VideoEncoder for QuicHostEncoder {
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
) -> Result<QuicHostEncoder, PipelineError> {
    match backend {
        "nvenc" => Ok(QuicHostEncoder::Nvenc(Box::new(NvencH264Encoder::new(
            width, height, fps,
        )?))),
        "nvenc_ll_p1" => Ok(QuicHostEncoder::Nvenc(Box::new(
            NvencH264Encoder::new_low_latency_p1(width, height, fps)?,
        ))),
        "nvenc_hq_p5" => Ok(QuicHostEncoder::Nvenc(Box::new(
            NvencH264Encoder::new_high_quality_p5(width, height, fps)?,
        ))),
        "openh264" => Ok(QuicHostEncoder::OpenH264(Box::new(OpenH264Encoder::new(
            width, height, fps,
        )?))),
        "openh264_speed" => Ok(QuicHostEncoder::OpenH264(Box::new(
            OpenH264Encoder::new_speed(width, height, fps)?,
        ))),
        other => Err(PipelineError::message(format!(
            "unsupported quic host encoder backend: {other}"
        ))),
    }
}

struct BenchmarkCapture {
    tick: u8,
    width: usize,
    height: usize,
}

impl FrameCapture for BenchmarkCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        self.tick = self.tick.wrapping_add(1);
        let mut data = vec![0_u8; self.width * self.height * 4];
        for chunk in data.chunks_exact_mut(4) {
            chunk[0] = self.tick;
            chunk[1] = 64;
            chunk[2] = 192;
            chunk[3] = 255;
        }
        Ok(CapturedFrame::from_cpu(
            self.width,
            self.height,
            FramePixelFormat::Bgra32,
            self.tick as u64 * 33_000,
            data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use mrd_observability::StageId;
    use mrd_proto::SessionId;

    use super::QuicHost;
    use crate::frame_sink::DecodedFrameSink;

    #[tokio::test]
    async fn quic_single_process_pipeline_delivers_remote_frames() {
        let sink = Arc::new(Mutex::new(DecodedFrameSink::default()));
        let mut agent = QuicHost::default();
        let mut controller = QuicHost::with_frame_sink(sink.clone());
        let session_id = SessionId("session-quic-live".into());

        let bootstrap = agent
            .prepare_listener(session_id.clone(), "127.0.0.1:0")
            .await
            .expect("prepare agent listener");
        controller
            .connect_to_peer(
                session_id.clone(),
                "127.0.0.1:0",
                &bootstrap,
                "h264_software",
            )
            .await
            .expect("connect controller");
        agent
            .accept_peer(session_id.clone())
            .await
            .expect("accept controller");

        agent
            .start_test_video_sender_with_backend(session_id.clone(), 16, 16, 30, "openh264")
            .await
            .expect("start sender");
        if let Err(error) = controller
            .wait_for_first_frame(&session_id, Duration::from_secs(5))
            .await
        {
            let snapshot = controller.snapshot(&session_id);
            let probe = controller.probe_snapshot(&session_id);
            let agent_snapshot = agent.snapshot(&session_id);
            let agent_probe = agent.probe_snapshot(&session_id);
            let agent_sender_probe = agent.sender_probe_snapshot(&session_id);
            panic!(
                "wait for first frame: {error}; controller_snapshot={snapshot:?}; controller_probe={probe:?}; agent_snapshot={agent_snapshot:?}; agent_probe={agent_probe:?}; agent_sender_probe={agent_sender_probe:?}"
            );
        }

        let snapshot = controller
            .snapshot(&session_id)
            .expect("controller snapshot");
        let probe = controller
            .probe_snapshot(&session_id)
            .expect("controller probe snapshot");

        assert!(snapshot.remote_datagram_count > 0);
        assert!(snapshot.remote_access_unit_count > 0);
        assert!(snapshot.decoded_frame_count > 0);
        assert!(probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::NetworkIngress && stats.count > 0));
        assert!(probe
            .stages
            .iter()
            .any(|(stage, stats)| *stage == StageId::DecodeTotal && stats.count > 0));
        assert!(sink
            .lock()
            .expect("lock sink")
            .snapshot(&session_id)
            .map(|value| value.frame_count > 0)
            .unwrap_or(false));

        controller
            .close_session(&session_id)
            .await
            .expect("close controller session");
        agent
            .close_session(&session_id)
            .await
            .expect("close agent session");
    }
}
