#![allow(dead_code)]

use anyhow::{anyhow, Result};
use mrd_decode::DecodedFrameData;
use mrd_encode_openh264::OpenH264Encoder;
use mrd_pipeline_core::{
    CapturedFrame, DecodedFrame, EncodedAccessUnit, FrameCapture, FramePixelFormat, PipelineError,
    VideoCodec, VideoEncoder,
};
#[cfg(any(target_os = "macos", windows))]
use mrd_render::RendererFactory;
#[cfg(not(any(target_os = "macos", windows)))]
use mrd_render::{RenderError, RendererSnapshot};
use mrd_render::{RenderFrame, RenderPixelFormat, RendererInstance};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const MEDIA_V3_PROFILE_ID: u32 = 1;
const RECEIVER_IDLE_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_RECEIVER_GLOBAL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct E2ePipelineCase {
    pub name: &'static str,
    pub width: usize,
    pub height: usize,
    pub fps: u32,
    pub frame_count: usize,
    pub bitrate_bps: u32,
    pub mtu: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct E2ePipelineReport {
    pub name: &'static str,
    pub width: usize,
    pub height: usize,
    pub fps: u32,
    pub frame_count: usize,
    pub bitrate_bps: u32,
    pub mtu: usize,
    pub encoded_access_units: usize,
    pub encoded_bytes: usize,
    pub quic_datagrams: usize,
    pub transported_access_units: usize,
    pub decoded_frames: usize,
    pub rendered_frames: usize,
    pub elapsed_ms: f64,
    pub render_fps: f64,
    pub frame_avg_ms: f64,
    pub frame_p50_ms: f64,
    pub frame_p95_ms: f64,
    pub renderer: &'static str,
    pub last_pixel_format: Option<RenderPixelFormat>,
}

#[derive(Debug, Clone)]
pub struct ThreadedTransportPipelineCase {
    pub name: &'static str,
    pub width: usize,
    pub height: usize,
    pub fps: u32,
    pub frame_count: usize,
    pub bitrate_bps: u32,
    pub mtu: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ThreadedTransportPipelineReport {
    pub name: &'static str,
    pub width: usize,
    pub height: usize,
    pub fps: u32,
    pub frame_count: usize,
    pub bitrate_bps: u32,
    pub mtu: usize,
    pub transport: &'static str,
    pub media_protocol: &'static str,
    pub sender_node: &'static str,
    pub receiver_node: &'static str,
    pub sender_local_addr: String,
    pub sender_peer_addr: String,
    pub receiver_local_addr: String,
    pub receiver_peer_addr: String,
    pub encoded_access_units: usize,
    pub encoded_bytes: usize,
    pub quic_datagrams_sent: usize,
    pub quic_datagrams_received: usize,
    pub transported_access_units: usize,
    pub decoded_frames: usize,
    pub rendered_frames: usize,
    pub elapsed_ms: f64,
    pub sender_elapsed_ms: f64,
    pub receiver_elapsed_ms: f64,
    pub sender_fps: f64,
    pub render_fps: f64,
    pub renderer: &'static str,
    pub last_pixel_format: Option<RenderPixelFormat>,
    pub reassembler_completed_frames: u64,
    pub reassembler_expired_frames: u64,
    pub reassembler_evicted_frames: u64,
    pub reassembler_duplicate_fragments: u64,
    pub reassembler_rejected_fragments: u64,
}

pub fn run_pipeline_case(case: &E2ePipelineCase) -> Result<E2ePipelineReport> {
    let mut capture = DeterministicCapture::new(case.width, case.height);
    let mut encoder =
        OpenH264Encoder::new_with_bitrate(case.width, case.height, case.fps, case.bitrate_bps)?;
    let mut decoder = mrd_decode::create_decoder("h264_software")?;
    let mut renderer = create_renderer()?;

    let mut encoded_access_units = 0usize;
    let mut encoded_bytes = 0usize;
    let mut quic_datagrams = 0usize;
    let mut transported_access_units = 0usize;
    let mut decoded_frames = 0usize;
    let mut rendered_frames = 0usize;
    let mut frame_latencies = Vec::with_capacity(case.frame_count);

    let case_start = Instant::now();
    for frame_index in 0..case.frame_count {
        let frame_start = Instant::now();
        let captured = capture.capture_frame()?;
        let encoded_units = encoder.encode(&captured)?;
        encoded_access_units += encoded_units.len();
        encoded_bytes += encoded_units
            .iter()
            .map(|unit| unit.bytes.len())
            .sum::<usize>();

        let transported = transmit_quic_datagrams(frame_index as u32, encoded_units, case.mtu)?;
        quic_datagrams += transported.datagram_count;
        transported_access_units += transported.access_units.len();

        for unit in transported.access_units {
            decoder.push_access_unit(&unit.bytes)?;
            for decoded in decoder.drain_decoded_frames() {
                let render_frame = decoded_frame_to_render_frame(&decoded);
                renderer.upload_frame(render_frame)?;
                decoded_frames += 1;
                rendered_frames += 1;
            }
        }
        frame_latencies.push(frame_start.elapsed());
    }

    let elapsed = case_start.elapsed();
    let snapshot = renderer.snapshot();
    validate_pipeline_report(
        case,
        &snapshot,
        encoded_access_units,
        transported_access_units,
        decoded_frames,
        rendered_frames,
    )?;

    Ok(E2ePipelineReport {
        name: case.name,
        width: case.width,
        height: case.height,
        fps: case.fps,
        frame_count: case.frame_count,
        bitrate_bps: case.bitrate_bps,
        mtu: case.mtu,
        encoded_access_units,
        encoded_bytes,
        quic_datagrams,
        transported_access_units,
        decoded_frames,
        rendered_frames,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        render_fps: rendered_frames as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
        frame_avg_ms: average_ms(&frame_latencies),
        frame_p50_ms: percentile_ms(&frame_latencies, 0.50),
        frame_p95_ms: percentile_ms(&frame_latencies, 0.95),
        renderer: renderer_label(),
        last_pixel_format: snapshot.last_pixel_format,
    })
}

pub fn run_threaded_transport_pipeline_case(
    case: &ThreadedTransportPipelineCase,
) -> Result<ThreadedTransportPipelineReport> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("mrd-threaded-transport-e2e")
        .worker_threads(4)
        .enable_all()
        .build()?;

    runtime.block_on(run_threaded_transport_pipeline_case_async(case.clone()))
}

async fn run_threaded_transport_pipeline_case_async(
    case: ThreadedTransportPipelineCase,
) -> Result<ThreadedTransportPipelineReport> {
    let pair = mrd_transport_quic_quinn::QuinnDatagramPair::loopback().await?;
    let sender_done = Arc::new(AtomicBool::new(false));
    let case_start = Instant::now();

    let sender_case = case.clone();
    let sender_endpoint = pair.client.clone();
    let sender_done_for_task = Arc::clone(&sender_done);
    let sender_handle = tokio::spawn(async move {
        let result = run_threaded_sender_node(sender_endpoint, sender_case).await;
        sender_done_for_task.store(true, Ordering::SeqCst);
        result
    });

    let receiver_case = case.clone();
    let receiver_endpoint = pair.server.clone();
    let receiver_handle = tokio::spawn(async move {
        run_threaded_receiver_node(receiver_endpoint, receiver_case, sender_done).await
    });

    let (sender_join, receiver_join) = tokio::try_join!(sender_handle, receiver_handle)
        .map_err(|error| anyhow!("threaded transport task join failed: {error}"))?;
    let sender = sender_join?;
    let receiver = receiver_join?;
    let elapsed = case_start.elapsed();

    validate_threaded_transport_report(&case, &sender, &receiver)?;

    Ok(ThreadedTransportPipelineReport {
        name: case.name,
        width: case.width,
        height: case.height,
        fps: case.fps,
        frame_count: case.frame_count,
        bitrate_bps: case.bitrate_bps,
        mtu: sender.effective_mtu,
        transport: "quic_quinn_loopback",
        media_protocol: "quic_media_v3_datagram",
        sender_node: "capture-encode-send",
        receiver_node: "receive-reassemble-decode-render",
        sender_local_addr: sender.local_addr,
        sender_peer_addr: sender.peer_addr,
        receiver_local_addr: receiver.local_addr,
        receiver_peer_addr: receiver.peer_addr,
        encoded_access_units: sender.encoded_access_units,
        encoded_bytes: sender.encoded_bytes,
        quic_datagrams_sent: sender.quic_datagrams_sent,
        quic_datagrams_received: receiver.quic_datagrams_received,
        transported_access_units: receiver.transported_access_units,
        decoded_frames: receiver.decoded_frames,
        rendered_frames: receiver.rendered_frames,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        sender_elapsed_ms: sender.elapsed_ms,
        receiver_elapsed_ms: receiver.elapsed_ms,
        sender_fps: case.frame_count as f64 / (sender.elapsed_ms / 1000.0).max(f64::EPSILON),
        render_fps: receiver.rendered_frames as f64
            / (receiver.elapsed_ms / 1000.0).max(f64::EPSILON),
        renderer: renderer_label(),
        last_pixel_format: receiver.snapshot.last_pixel_format,
        reassembler_completed_frames: receiver.reassembler_stats.completed_frames,
        reassembler_expired_frames: receiver.reassembler_stats.expired_frames,
        reassembler_evicted_frames: receiver.reassembler_stats.evicted_frames,
        reassembler_duplicate_fragments: receiver.reassembler_stats.duplicate_fragments,
        reassembler_rejected_fragments: receiver.reassembler_stats.rejected_fragments,
    })
}

struct ThreadedSenderNodeReport {
    local_addr: String,
    peer_addr: String,
    effective_mtu: usize,
    encoded_access_units: usize,
    encoded_bytes: usize,
    quic_datagrams_sent: usize,
    elapsed_ms: f64,
}

struct ThreadedReceiverNodeReport {
    local_addr: String,
    peer_addr: String,
    quic_datagrams_received: usize,
    transported_access_units: usize,
    decoded_frames: usize,
    rendered_frames: usize,
    elapsed_ms: f64,
    snapshot: mrd_render::RendererSnapshot,
    reassembler_stats: mrd_transport_quic_quinn::QuicAuReassemblerStats,
}

async fn run_threaded_sender_node(
    endpoint: mrd_transport_quic_quinn::QuinnDatagramEndpoint,
    case: ThreadedTransportPipelineCase,
) -> Result<ThreadedSenderNodeReport> {
    let metadata = endpoint.metadata().clone();
    let effective_mtu = endpoint
        .max_datagram_size()
        .unwrap_or(case.mtu)
        .min(case.mtu);
    if effective_mtu <= mrd_transport_quic_quinn::QUIC_MEDIA_V3_FRAGMENT_HEADER_LEN {
        return Err(anyhow!(
            "{}: effective QUIC datagram MTU {} is too small for media v3",
            case.name,
            effective_mtu
        ));
    }

    let mut capture = DeterministicCapture::new(case.width, case.height);
    let mut encoder =
        OpenH264Encoder::new_with_bitrate(case.width, case.height, case.fps, case.bitrate_bps)?;
    let frame_interval = if case.fps == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(1.0 / case.fps as f64)
    };

    let mut encoded_access_units = 0usize;
    let mut encoded_bytes = 0usize;
    let mut quic_datagrams_sent = 0usize;
    let mut media_frame_id = 0u32;
    let start = Instant::now();
    let mut next_frame_at = tokio::time::Instant::now();

    for frame_index in 0..case.frame_count {
        if frame_index > 0 && !frame_interval.is_zero() {
            next_frame_at += frame_interval;
            tokio::time::sleep_until(next_frame_at).await;
        }

        let captured = capture.capture_frame()?;
        let encoded_units = encoder.encode(&captured)?;

        for access_unit in encoded_units {
            let frame_id = media_frame_id;
            media_frame_id = media_frame_id
                .checked_add(1)
                .ok_or_else(|| anyhow!("{}: media frame id overflow", case.name))?;
            encoded_access_units = encoded_access_units.saturating_add(1);
            encoded_bytes = encoded_bytes.saturating_add(access_unit.bytes.len());

            let datagrams = mrd_transport_quic_quinn::fragment_media_payload_v3(
                mrd_transport_quic_quinn::QuicMediaPayloadType::AccessUnit,
                mrd_transport_quic_quinn::QuicMediaCodec::H264,
                MEDIA_V3_PROFILE_ID,
                frame_id,
                access_unit.timestamp_us,
                access_unit.is_keyframe,
                &access_unit.bytes,
                effective_mtu,
            )?;
            for datagram in datagrams {
                endpoint.send_datagram_wait(datagram).await?;
                quic_datagrams_sent = quic_datagrams_sent.saturating_add(1);
            }
        }
    }

    Ok(ThreadedSenderNodeReport {
        local_addr: metadata.local_addr.to_string(),
        peer_addr: metadata.peer_addr.to_string(),
        effective_mtu,
        encoded_access_units,
        encoded_bytes,
        quic_datagrams_sent,
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
    })
}

async fn run_threaded_receiver_node(
    endpoint: mrd_transport_quic_quinn::QuinnDatagramEndpoint,
    case: ThreadedTransportPipelineCase,
    sender_done: Arc<AtomicBool>,
) -> Result<ThreadedReceiverNodeReport> {
    let metadata = endpoint.metadata().clone();
    let mut reassembler = mrd_transport_quic_quinn::QuicMediaReassembler::new(
        mrd_transport_quic_quinn::QuicAuReassemblerConfig {
            frame_timeout: Duration::from_millis(250),
            max_pending_frames: 128,
        },
    );
    let mut decoder = mrd_decode::create_decoder("h264_software")?;
    let mut renderer = create_renderer()?;

    let mut quic_datagrams_received = 0usize;
    let mut transported_access_units = 0usize;
    let mut decoded_frames = 0usize;
    let mut rendered_frames = 0usize;
    let start = Instant::now();
    let receiver_global_timeout = receiver_global_timeout();

    loop {
        if start.elapsed() > receiver_global_timeout {
            return Err(anyhow!(
                "{}: receiver timed out after {:?}; datagrams={}, access_units={}, decoded={}",
                case.name,
                receiver_global_timeout,
                quic_datagrams_received,
                transported_access_units,
                decoded_frames
            ));
        }

        match tokio::time::timeout(RECEIVER_IDLE_TIMEOUT, endpoint.read_datagram()).await {
            Ok(Ok(datagram)) => {
                quic_datagrams_received = quic_datagrams_received.saturating_add(1);
                if !mrd_transport_quic_quinn::is_quic_media_v3_datagram(&datagram) {
                    continue;
                }
                let Some(frame) = reassembler.push_datagram(&datagram)? else {
                    continue;
                };
                if frame.payload_type != mrd_transport_quic_quinn::QuicMediaPayloadType::AccessUnit
                    || frame.codec != mrd_transport_quic_quinn::QuicMediaCodec::H264
                    || frame.profile_id != MEDIA_V3_PROFILE_ID
                {
                    continue;
                }

                transported_access_units = transported_access_units.saturating_add(1);
                decoder.push_access_unit(&frame.payload)?;
                for decoded in decoder.drain_decoded_frames() {
                    let render_frame = decoded_frame_to_render_frame(&decoded);
                    renderer.upload_frame(render_frame)?;
                    decoded_frames = decoded_frames.saturating_add(1);
                    rendered_frames = rendered_frames.saturating_add(1);
                }
            }
            Ok(Err(error)) => {
                if sender_done.load(Ordering::SeqCst) && decoded_frames > 0 {
                    break;
                }
                return Err(anyhow!("{}: QUIC receiver read failed: {error}", case.name));
            }
            Err(_) => {
                reassembler.prune_expired();
                if sender_done.load(Ordering::SeqCst) && decoded_frames > 0 {
                    break;
                }
            }
        }
    }

    Ok(ThreadedReceiverNodeReport {
        local_addr: metadata.local_addr.to_string(),
        peer_addr: metadata.peer_addr.to_string(),
        quic_datagrams_received,
        transported_access_units,
        decoded_frames,
        rendered_frames,
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        snapshot: renderer.snapshot(),
        reassembler_stats: reassembler.stats(),
    })
}

fn validate_threaded_transport_report(
    case: &ThreadedTransportPipelineCase,
    sender: &ThreadedSenderNodeReport,
    receiver: &ThreadedReceiverNodeReport,
) -> Result<()> {
    if sender.encoded_access_units == 0 {
        return Err(anyhow!("{}: sender produced no access units", case.name));
    }
    if sender.quic_datagrams_sent == 0 {
        return Err(anyhow!("{}: sender emitted no QUIC datagrams", case.name));
    }
    if receiver.quic_datagrams_received == 0 {
        return Err(anyhow!("{}: receiver read no QUIC datagrams", case.name));
    }
    if receiver.transported_access_units == 0 {
        return Err(anyhow!(
            "{}: media v3 reassembler produced no access units",
            case.name
        ));
    }
    if receiver.decoded_frames == 0 {
        return Err(anyhow!("{}: receiver decoded no frames", case.name));
    }
    if receiver.snapshot.uploaded_frame_count as usize != receiver.rendered_frames {
        return Err(anyhow!(
            "{}: renderer uploaded {} frames, expected {}",
            case.name,
            receiver.snapshot.uploaded_frame_count,
            receiver.rendered_frames
        ));
    }
    if receiver.snapshot.last_width != case.width || receiver.snapshot.last_height != case.height {
        return Err(anyhow!(
            "{}: renderer dimensions {}x{}, expected {}x{}",
            case.name,
            receiver.snapshot.last_width,
            receiver.snapshot.last_height,
            case.width,
            case.height
        ));
    }
    if !matches!(
        receiver.snapshot.last_pixel_format,
        Some(RenderPixelFormat::Rgb24 | RenderPixelFormat::Bgra32)
    ) {
        return Err(anyhow!(
            "{}: renderer received unsupported pixel format {:?}",
            case.name,
            receiver.snapshot.last_pixel_format
        ));
    }
    Ok(())
}

fn receiver_global_timeout() -> Duration {
    std::env::var("MRD_THREADED_TRANSPORT_RECEIVER_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_RECEIVER_GLOBAL_TIMEOUT)
}

fn validate_pipeline_report(
    case: &E2ePipelineCase,
    snapshot: &mrd_render::RendererSnapshot,
    encoded_access_units: usize,
    transported_access_units: usize,
    decoded_frames: usize,
    rendered_frames: usize,
) -> Result<()> {
    if encoded_access_units == 0 {
        return Err(anyhow!("{}: encoder produced no access units", case.name));
    }
    if transported_access_units == 0 {
        return Err(anyhow!(
            "{}: QUIC transport loopback produced no access units",
            case.name
        ));
    }
    if decoded_frames == 0 {
        return Err(anyhow!("{}: decoder produced no frames", case.name));
    }
    if snapshot.uploaded_frame_count as usize != rendered_frames {
        return Err(anyhow!(
            "{}: renderer uploaded {} frames, expected {}",
            case.name,
            snapshot.uploaded_frame_count,
            rendered_frames
        ));
    }
    if snapshot.last_width != case.width || snapshot.last_height != case.height {
        return Err(anyhow!(
            "{}: renderer dimensions {}x{}, expected {}x{}",
            case.name,
            snapshot.last_width,
            snapshot.last_height,
            case.width,
            case.height
        ));
    }
    if !matches!(
        snapshot.last_pixel_format,
        Some(RenderPixelFormat::Rgb24 | RenderPixelFormat::Bgra32)
    ) {
        return Err(anyhow!(
            "{}: renderer received unsupported pixel format {:?}",
            case.name,
            snapshot.last_pixel_format
        ));
    }
    Ok(())
}

struct TransportedAccessUnits {
    access_units: Vec<EncodedAccessUnit>,
    datagram_count: usize,
}

fn transmit_quic_datagrams(
    frame_id: u32,
    access_units: Vec<EncodedAccessUnit>,
    mtu: usize,
) -> Result<TransportedAccessUnits> {
    let mut reassembler = mrd_transport_quic_quinn::QuicAuReassembler::new(
        mrd_transport_quic_quinn::QuicAuReassemblerConfig {
            frame_timeout: Duration::from_millis(250),
            max_pending_frames: 64,
        },
    );
    let mut reassembled = Vec::new();
    let mut datagram_count = 0usize;

    for (unit_index, access_unit) in access_units.into_iter().enumerate() {
        let datagrams = mrd_transport_quic_quinn::fragment_access_unit(
            frame_id
                .checked_mul(16)
                .and_then(|base| base.checked_add(unit_index as u32))
                .ok_or_else(|| anyhow!("QUIC frame id overflow"))?,
            access_unit.timestamp_us,
            access_unit.is_keyframe,
            &access_unit.bytes,
            mtu,
        )?;
        datagram_count += datagrams.len();

        for datagram in datagrams {
            if let Some(frame) = reassembler.push_datagram(&datagram)? {
                reassembled.push(EncodedAccessUnit {
                    codec: VideoCodec::H264,
                    timestamp_us: frame.timestamp_us,
                    is_keyframe: frame.is_keyframe,
                    bytes: frame.payload.to_vec(),
                });
            }
        }
    }

    Ok(TransportedAccessUnits {
        access_units: reassembled,
        datagram_count,
    })
}

fn create_renderer() -> Result<Box<dyn RendererInstance>> {
    #[cfg(target_os = "macos")]
    {
        let factory = mrd_render_macos::MacosRendererFactory;
        return factory.create().map_err(|error| anyhow!(error));
    }

    #[cfg(windows)]
    {
        use mrd_render::RenderTarget;

        let factory = mrd_render_d3d11::D3d11RendererFactory;
        let mut renderer = factory.create().map_err(|error| anyhow!(error))?;
        renderer
            .attach_target(RenderTarget::WindowHandle(0))
            .map_err(|error| anyhow!(error))?;
        Ok(renderer)
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Ok(Box::<InMemoryRenderer>::default())
    }
}

fn renderer_label() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos-metal"
    }
    #[cfg(windows)]
    {
        "d3d11"
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        "memory"
    }
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
        } => RenderFrame::from_rgb24(
            frame.width,
            frame.height,
            cpu_i420_to_rgb24(data, frame.width, frame.height, *y_pitch, *uv_pitch),
        ),
        DecodedFrameData::CpuNv12 { data, pitch } => RenderFrame::from_rgb24(
            frame.width,
            frame.height,
            cpu_nv12_to_rgb24(data, frame.width, frame.height, *pitch),
        ),
        DecodedFrameData::CpuP010 { .. } => {
            unreachable!("automated OpenH264 software decode path should not emit P010 frames")
        }
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedNv12 { .. } | DecodedFrameData::D3D11SharedP010 { .. } => {
            unreachable!("automated OpenH264 software decode path should not emit D3D11 frames")
        }
    }
}

fn cpu_nv12_to_rgb24(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
    let mut rgb = vec![0_u8; width * height * 3];
    let uv_base = pitch * height;
    let mut out_idx = 0usize;

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

fn cpu_i420_to_rgb24(
    i420: &[u8],
    width: usize,
    height: usize,
    y_pitch: usize,
    uv_pitch: usize,
) -> Vec<u8> {
    let mut rgb = vec![0_u8; width * height * 3];
    let chroma_height = height.div_ceil(2);
    let u_base = y_pitch * height;
    let v_base = u_base + uv_pitch * chroma_height;
    let mut out_idx = 0usize;

    for y in 0..height {
        let y_row_start = y * y_pitch;
        let uv_row_start = (y / 2) * uv_pitch;
        for x in 0..width {
            let y_offset = y_row_start + x;
            let u_offset = u_base + uv_row_start + x / 2;
            let v_offset = v_base + uv_row_start + x / 2;
            if y_offset >= i420.len() || u_offset >= i420.len() || v_offset >= i420.len() {
                out_idx += 3;
                continue;
            }

            let y_sample = i420[y_offset] as i32 - 16;
            let u = i420[u_offset] as i32 - 128;
            let v = i420[v_offset] as i32 - 128;

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

fn average_ms(samples: &[Duration]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples
        .iter()
        .map(|sample| sample.as_secs_f64() * 1000.0)
        .sum::<f64>()
        / samples.len() as f64
}

fn percentile_ms(samples: &[Duration], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut values = samples.to_vec();
    values.sort_unstable();
    let index = ((values.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(values.len() - 1);
    values[index].as_secs_f64() * 1000.0
}

struct DeterministicCapture {
    tick: u64,
    width: usize,
    height: usize,
}

impl DeterministicCapture {
    fn new(width: usize, height: usize) -> Self {
        Self {
            tick: 0,
            width,
            height,
        }
    }
}

impl FrameCapture for DeterministicCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        self.tick = self.tick.saturating_add(1);
        let mut data = vec![0_u8; self.width * self.height * 4];
        let phase = (self.tick & 0xff) as u8;

        for y in 0..self.height {
            for x in 0..self.width {
                let idx = (y * self.width + x) * 4;
                data[idx] = (x as u8).wrapping_add(phase);
                data[idx + 1] = (y as u8).wrapping_add(phase / 2);
                data[idx + 2] = 255_u8.wrapping_sub(phase);
                data[idx + 3] = 255;
            }
        }

        Ok(CapturedFrame::from_cpu(
            self.width,
            self.height,
            FramePixelFormat::Bgra32,
            self.tick.saturating_mul(33_333),
            data,
        ))
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
#[derive(Default)]
struct InMemoryRenderer {
    uploaded_frame_count: u64,
    last_width: usize,
    last_height: usize,
    last_pixel_format: Option<RenderPixelFormat>,
}

#[cfg(not(any(target_os = "macos", windows)))]
impl RendererInstance for InMemoryRenderer {
    fn attach_target(&mut self, _target: mrd_render::RenderTarget) -> Result<(), RenderError> {
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), RenderError> {
        self.uploaded_frame_count = self.uploaded_frame_count.saturating_add(1);
        self.last_width = frame.width;
        self.last_height = frame.height;
        self.last_pixel_format = Some(frame.pixel_format);
        Ok(())
    }

    fn snapshot(&self) -> RendererSnapshot {
        RendererSnapshot {
            attached_to_target: false,
            uploaded_frame_count: self.uploaded_frame_count,
            presented_frame_count: self.uploaded_frame_count,
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
            last_width: self.last_width,
            last_height: self.last_height,
            last_pixel_format: self.last_pixel_format,
        }
    }
}
