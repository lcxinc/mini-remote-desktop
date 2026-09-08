use crate::core::metrics::Series;
use crate::core::pipeline_udp::{p95_from_samples, PipelineConfig, PipelineReport};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::media_engine::MIME_TYPE_H264;
use webrtc::api::APIBuilder;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::rtp::packet::Packet as RtpPacket;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::TrackLocalWriter;

#[derive(Debug, Clone, Copy)]
struct FramePacket {
    frame_id: u64,
    capture_ts_us: u64,
    encode_done_ts_us: u64,
}

impl FramePacket {
    const LEN: usize = 24;

    fn encode(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..8].copy_from_slice(&self.frame_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.capture_ts_us.to_le_bytes());
        out[16..24].copy_from_slice(&self.encode_done_ts_us.to_le_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        let mut c = [0u8; 8];
        a.copy_from_slice(&buf[0..8]);
        b.copy_from_slice(&buf[8..16]);
        c.copy_from_slice(&buf[16..24]);
        Some(Self {
            frame_id: u64::from_le_bytes(a),
            capture_ts_us: u64::from_le_bytes(b),
            encode_done_ts_us: u64::from_le_bytes(c),
        })
    }
}

pub fn run_webrtc_pipeline(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| format!("build tokio runtime: {e}"))?;
    rt.block_on(run_webrtc_pipeline_async(cfg))
}

async fn run_webrtc_pipeline_async(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let stages = cfg.stages;
    let chain_name = cfg.chain_name.clone();

    let mut m = MediaEngine::default();
    m.register_default_codecs()
        .map_err(|e| format!("webrtc register codecs: {e}"))?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)
        .map_err(|e| format!("webrtc register interceptors: {e}"))?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let pc1 = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .map_err(|e| format!("webrtc pc1: {e}"))?,
    );
    let pc2 = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .map_err(|e| format!("webrtc pc2: {e}"))?,
    );

    let (pc1_connected_tx, pc1_connected_rx) = oneshot::channel::<()>();
    let (pc2_connected_tx, pc2_connected_rx) = oneshot::channel::<()>();
    let pc1_connected_tx = Arc::new(Mutex::new(Some(pc1_connected_tx)));
    let pc2_connected_tx = Arc::new(Mutex::new(Some(pc2_connected_tx)));

    {
        let tx = Arc::clone(&pc1_connected_tx);
        pc1.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            if s == RTCPeerConnectionState::Connected {
                if let Ok(mut guard) = tx.lock() {
                    if let Some(done) = guard.take() {
                        let _ = done.send(());
                    }
                }
            }
            Box::pin(async {})
        }));
    }
    {
        let tx = Arc::clone(&pc2_connected_tx);
        pc2.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            if s == RTCPeerConnectionState::Connected {
                if let Ok(mut guard) = tx.lock() {
                    if let Some(done) = guard.take() {
                        let _ = done.send(());
                    }
                }
            }
            Box::pin(async {})
        }));
    }

    {
        let pc2_for_ice = Arc::clone(&pc2);
        pc1.on_ice_candidate(Box::new(move |c| {
            let pc2_for_ice = Arc::clone(&pc2_for_ice);
            Box::pin(async move {
                if let Some(c) = c {
                    let json = c.to_json().ok();
                    if let Some(v) = json {
                        let _ = pc2_for_ice.add_ice_candidate(v).await;
                    }
                }
            })
        }));
    }
    {
        let pc1_for_ice = Arc::clone(&pc1);
        pc2.on_ice_candidate(Box::new(move |c| {
            let pc1_for_ice = Arc::clone(&pc1_for_ice);
            Box::pin(async move {
                if let Some(c) = c {
                    let json = c.to_json().ok();
                    if let Some(v) = json {
                        let _ = pc1_for_ice.add_ice_candidate(v).await;
                    }
                }
            })
        }));
    }

    let (rx_tx, mut rx_rx) = mpsc::channel::<(FramePacket, usize)>(4096);
    let running = Arc::new(AtomicBool::new(true));
    let running_rx = running.clone();

    pc2.on_track(Box::new(move |track, _receiver, _transceiver| {
        let tx = rx_tx.clone();
        let running_rx = running_rx.clone();
        Box::pin(async move {
            while running_rx.load(Ordering::Relaxed) {
                match track.read_rtp().await {
                    Ok((pkt, _)) => {
                        if let Some(fp) = FramePacket::decode(&pkt.payload) {
                            let _ = tx.try_send((fp, pkt.payload.len()));
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    }));

    let video_track = Arc::new(TrackLocalStaticRTP::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_H264.to_string(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        "video".to_string(),
        "gpu-bench".to_string(),
    ));
    let rtp_sender = pc1
        .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(|e| format!("webrtc add_track: {e}"))?;

    tokio::spawn(async move {
        let mut rtcp_buf = vec![0u8; 1500];
        while rtp_sender.read(&mut rtcp_buf).await.is_ok() {}
    });

    let offer = pc1
        .create_offer(None)
        .await
        .map_err(|e| format!("webrtc create offer: {e}"))?;
    let mut gather1 = pc1.gathering_complete_promise().await;
    pc1.set_local_description(offer)
        .await
        .map_err(|e| format!("webrtc set pc1 local: {e}"))?;
    let _ = gather1.recv().await;
    let local_offer = pc1
        .local_description()
        .await
        .ok_or_else(|| "webrtc pc1 local desc none".to_string())?;

    pc2.set_remote_description(local_offer)
        .await
        .map_err(|e| format!("webrtc set pc2 remote: {e}"))?;
    let answer = pc2
        .create_answer(None)
        .await
        .map_err(|e| format!("webrtc create answer: {e}"))?;
    let mut gather2 = pc2.gathering_complete_promise().await;
    pc2.set_local_description(answer)
        .await
        .map_err(|e| format!("webrtc set pc2 local: {e}"))?;
    let _ = gather2.recv().await;
    let local_answer = pc2
        .local_description()
        .await
        .ok_or_else(|| "webrtc pc2 local desc none".to_string())?;
    pc1.set_remote_description(local_answer)
        .await
        .map_err(|e| format!("webrtc set pc1 remote: {e}"))?;

    let _ = tokio::time::timeout(Duration::from_secs(5), pc1_connected_rx)
        .await
        .map_err(|_| "webrtc pc1 connect timeout".to_string())?;
    let _ = tokio::time::timeout(Duration::from_secs(5), pc2_connected_rx)
        .await
        .map_err(|_| "webrtc pc2 connect timeout".to_string())?;

    let mut recv_wait = Series::default();
    let mut decode = Series::default();
    let mut render = Series::default();
    let mut present = Series::default();
    let mut e2e = Series::default();
    let mut capture = Series::default();
    let mut encode = Series::default();
    let mut send = Series::default();
    let mut frames_received = 0u64;
    let mut frames_dropped = 0u64;
    let mut last_frame_id = 0u64;
    let mut frame_id = 0u64;
    let mut rx_bytes = 0u64;
    let mut sec_bytes = 0u64;
    let mut sec_bitrate_mbps = Vec::<f64>::new();

    let frame_interval = if cfg.target_fps == 0 {
        Duration::from_millis(16)
    } else {
        Duration::from_secs_f64(1.0 / cfg.target_fps as f64)
    };
    let run_start = Instant::now();
    let warmup = Duration::from_millis(800);
    let mut next_tick = Instant::now();
    let mut sec_window_start = Instant::now();
    let mut sec_count = 0u64;
    let ssrc = 0xAABBCCDD;
    let mut seq: u16 = 1;
    let mut rtp_ts: u32 = 1;

    while run_start.elapsed() < Duration::from_secs(cfg.duration_sec) {
        if next_tick > Instant::now() {
            tokio::time::sleep(next_tick - Instant::now()).await;
        }
        next_tick += frame_interval;
        frame_id = frame_id.wrapping_add(1);

        let cap_t0 = Instant::now();
        let capture_ts_us = unix_us();
        emulate_work_us(stages.capture_us);
        capture.push(cap_t0.elapsed().as_secs_f64() * 1000.0);

        let enc_t0 = Instant::now();
        emulate_work_us(stages.encode_us);
        let encode_done_ts_us = unix_us();
        encode.push(enc_t0.elapsed().as_secs_f64() * 1000.0);

        let payload = FramePacket {
            frame_id,
            capture_ts_us,
            encode_done_ts_us,
        }
        .encode()
        .to_vec();
        let pkt = RtpPacket {
            header: webrtc::rtp::header::Header {
                version: 2,
                payload_type: 102,
                sequence_number: seq,
                timestamp: rtp_ts,
                ssrc,
                marker: true,
                ..Default::default()
            },
            payload: payload.into(),
            ..Default::default()
        };
        seq = seq.wrapping_add(1);
        rtp_ts = rtp_ts.wrapping_add(3000);

        let send_t0 = Instant::now();
        video_track
            .write_rtp(&pkt)
            .await
            .map_err(|e| format!("webrtc write_rtp: {e}"))?;
        send.push(send_t0.elapsed().as_secs_f64() * 1000.0);

        while let Ok((fp, payload_len)) = rx_rx.try_recv() {
            let now_us = unix_us();
            frames_received += 1;
            rx_bytes = rx_bytes.saturating_add(payload_len as u64);
            sec_bytes = sec_bytes.saturating_add(payload_len as u64);
            if last_frame_id > 0 && fp.frame_id > last_frame_id + 1 {
                frames_dropped += fp.frame_id - (last_frame_id + 1);
            }
            last_frame_id = fp.frame_id;
            if run_start.elapsed() >= warmup {
                recv_wait.push((now_us.saturating_sub(fp.encode_done_ts_us) as f64) / 1000.0);

                let t0 = Instant::now();
                emulate_work_us(stages.decode_us);
                decode.push(t0.elapsed().as_secs_f64() * 1000.0);

                let t1 = Instant::now();
                emulate_work_us(stages.render_us);
                render.push(t1.elapsed().as_secs_f64() * 1000.0);

                let t2 = Instant::now();
                emulate_work_us(stages.present_us);
                present.push(t2.elapsed().as_secs_f64() * 1000.0);

                e2e.push((unix_us().saturating_sub(fp.capture_ts_us) as f64) / 1000.0);
            }
            sec_count += 1;
        }
        if sec_window_start.elapsed() >= Duration::from_secs(1) {
            let sec_elapsed = sec_window_start.elapsed().as_secs_f64().max(1e-6);
            sec_bitrate_mbps.push((sec_bytes as f64 * 8.0) / sec_elapsed / 1_000_000.0);
            let fps = sec_count as f64 / sec_elapsed;
            eprintln!(
                "[DECODE-RUNTIME] transport=webrtc chain={} fps={:.2}",
                chain_name, fps
            );
            sec_count = 0;
            sec_bytes = 0;
            sec_window_start = Instant::now();
        }
    }

    running.store(false, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(100)).await;
    while let Ok((fp, payload_len)) = rx_rx.try_recv() {
        let now_us = unix_us();
        frames_received += 1;
        rx_bytes = rx_bytes.saturating_add(payload_len as u64);
        sec_bytes = sec_bytes.saturating_add(payload_len as u64);
        if last_frame_id > 0 && fp.frame_id > last_frame_id + 1 {
            frames_dropped += fp.frame_id - (last_frame_id + 1);
        }
        last_frame_id = fp.frame_id;
        if run_start.elapsed() >= warmup {
            recv_wait.push((now_us.saturating_sub(fp.encode_done_ts_us) as f64) / 1000.0);
            e2e.push((unix_us().saturating_sub(fp.capture_ts_us) as f64) / 1000.0);
        }
    }

    let _ = pc1.close().await;
    let _ = pc2.close().await;
    if sec_bytes > 0 {
        let sec_elapsed = sec_window_start.elapsed().as_secs_f64().max(1e-6);
        sec_bitrate_mbps.push((sec_bytes as f64 * 8.0) / sec_elapsed / 1_000_000.0);
    }
    let sec_total = run_start.elapsed().as_secs_f64().max(1e-6);
    let bitrate_avg_mbps = (rx_bytes as f64 * 8.0) / sec_total / 1_000_000.0;
    let bitrate_p95_mbps = p95_from_samples(sec_bitrate_mbps);
    let wire_overhead_est_mbps = (frames_received as f64 * 60.0 * 8.0) / sec_total / 1_000_000.0;

    let mut report = PipelineReport {
        transport: "webrtc".to_string(),
        profile: cfg.profile,
        width: cfg.width,
        height: cfg.height,
        target_fps: cfg.target_fps,
        bitrate_avg_mbps,
        bitrate_p95_mbps,
        wire_overhead_est_mbps,
        frames_total: frame_id,
        frames_received,
        frames_dropped,
        capture: capture.summary(),
        encode: encode.summary(),
        send: send.summary(),
        recv_wait: recv_wait.summary(),
        decode: decode.summary(),
        render: render.summary(),
        present_call: present.summary(),
        e2e: e2e.summary(),
        pass: true,
        fail_reason: String::new(),
    };
    apply_low_latency_gate(&mut report);
    Ok(report)
}

fn apply_low_latency_gate(report: &mut PipelineReport) {
    let mut fails = Vec::new();
    if report.frames_received == 0 {
        fails.push("frames_received=0".to_string());
    }
    if report.e2e.p50 >= 10.0 {
        fails.push(format!("e2e_p50={:.3}", report.e2e.p50));
    }
    if report.e2e.p95 >= 20.0 {
        fails.push(format!("e2e_p95={:.3}", report.e2e.p95));
    }
    if report.e2e.p99 >= 30.0 {
        fails.push(format!("e2e_p99={:.3}", report.e2e.p99));
    }
    if report.present_call.p95 >= 1.0 {
        fails.push(format!("present_call_p95={:.3}", report.present_call.p95));
    }
    if report.decode.p95 >= 6.0 {
        fails.push(format!("decode_p95={:.3}", report.decode.p95));
    }
    if report.send.jitter >= 2.5 {
        fails.push(format!("send_jitter={:.3}", report.send.jitter));
    }
    let drop_ratio = if report.frames_total == 0 {
        1.0
    } else {
        report.frames_dropped as f64 / report.frames_total as f64
    };
    if drop_ratio >= 0.01 {
        fails.push(format!("drop_ratio={:.4}", drop_ratio));
    }
    if !fails.is_empty() {
        report.pass = false;
        report.fail_reason = fails.join("|");
    }
}

fn emulate_work_us(us: u64) {
    let until = Instant::now() + Duration::from_micros(us);
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

fn unix_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
