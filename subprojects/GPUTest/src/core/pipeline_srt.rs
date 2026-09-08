use crate::core::metrics::Series;
use crate::core::pipeline_udp::{p95_from_samples, PipelineConfig, PipelineReport};
use srt_rs as srt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

struct SrtSessionGuard;

impl SrtSessionGuard {
    fn startup() -> Result<Self, String> {
        srt::startup().map_err(|e| format!("srt startup: {e}"))?;
        Ok(Self)
    }
}

impl Drop for SrtSessionGuard {
    fn drop(&mut self) {
        let _ = srt::cleanup();
    }
}

pub fn run_srt_pipeline(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    let _srt_guard = SrtSessionGuard::startup()?;

    let listener = srt::builder()
        .set_file_transmission_type()
        .set_connection_timeout(1500)
        .listen("127.0.0.1:0", 1)
        .map_err(|e| format!("srt listen: {e}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|e| format!("srt local_addr: {e}"))?;

    let (tx_conn, rx_conn) = mpsc::channel::<Result<srt::SrtStream, String>>();
    thread::spawn(move || match listener.accept() {
        Ok((stream, _addr)) => {
            let _ = tx_conn.send(Ok(stream));
        }
        Err(e) => {
            let _ = tx_conn.send(Err(format!("srt accept: {e}")));
        }
    });

    let mut sender = srt::builder()
        .set_file_transmission_type()
        .set_connection_timeout(1500)
        .connect(listen_addr)
        .map_err(|e| format!("srt connect: {e}"))?;
    sender
        .set_send_timeout(100)
        .map_err(|e| format!("srt sender set_send_timeout: {e}"))?;

    let mut receiver = rx_conn
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "srt accept timeout".to_string())??;
    receiver
        .set_receive_timeout(100)
        .map_err(|e| format!("srt receiver set_receive_timeout: {e}"))?;

    let running = Arc::new(AtomicBool::new(true));
    let running_rx = running.clone();
    let chain_name = cfg.chain_name.clone();
    let stages = cfg.stages;
    let (tx_report, rx_report) =
        mpsc::channel::<(u64, u64, Series, Series, Series, Series, Series, u64, f64)>();

    let rx_thread = thread::spawn(move || {
        let mut recv_wait = Series::default();
        let mut decode = Series::default();
        let mut render = Series::default();
        let mut present = Series::default();
        let mut e2e = Series::default();
        let mut received = 0u64;
        let mut dropped = 0u64;
        let mut last_frame_id = 0u64;
        let mut rx_bytes = 0u64;
        let mut sec_window_start = Instant::now();
        let mut sec_count = 0u64;
        let mut sec_bytes = 0u64;
        let mut sec_bitrate_mbps = Vec::<f64>::new();
        let mut buf = [0u8; FramePacket::LEN];

        while running_rx.load(Ordering::Relaxed) {
            match receiver.read_exact(&mut buf) {
                Ok(()) => {
                    rx_bytes = rx_bytes.saturating_add(FramePacket::LEN as u64);
                    sec_bytes = sec_bytes.saturating_add(FramePacket::LEN as u64);
                    if let Some(pkt) = FramePacket::decode(&buf) {
                        let now_us = unix_us();
                        received += 1;
                        if last_frame_id > 0 && pkt.frame_id > last_frame_id + 1 {
                            dropped += pkt.frame_id - (last_frame_id + 1);
                        }
                        last_frame_id = pkt.frame_id;

                        recv_wait
                            .push((now_us.saturating_sub(pkt.encode_done_ts_us) as f64) / 1000.0);

                        let t0 = Instant::now();
                        emulate_work_us(stages.decode_us);
                        decode.push(t0.elapsed().as_secs_f64() * 1000.0);

                        let t1 = Instant::now();
                        emulate_work_us(stages.render_us);
                        render.push(t1.elapsed().as_secs_f64() * 1000.0);

                        let t2 = Instant::now();
                        emulate_work_us(stages.present_us);
                        present.push(t2.elapsed().as_secs_f64() * 1000.0);

                        e2e.push((unix_us().saturating_sub(pkt.capture_ts_us) as f64) / 1000.0);
                        sec_count += 1;
                        if sec_window_start.elapsed() >= Duration::from_secs(1) {
                            let sec_elapsed = sec_window_start.elapsed().as_secs_f64().max(1e-6);
                            sec_bitrate_mbps
                                .push((sec_bytes as f64 * 8.0) / sec_elapsed / 1_000_000.0);
                            let fps = sec_count as f64 / sec_elapsed;
                            eprintln!(
                                "[DECODE-RUNTIME] transport=srt chain={} fps={:.2}",
                                chain_name, fps
                            );
                            sec_count = 0;
                            sec_bytes = 0;
                            sec_window_start = Instant::now();
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        if sec_bytes > 0 {
            let sec_elapsed = sec_window_start.elapsed().as_secs_f64().max(1e-6);
            sec_bitrate_mbps.push((sec_bytes as f64 * 8.0) / sec_elapsed / 1_000_000.0);
        }
        let _ = tx_report.send((
            received,
            dropped,
            recv_wait,
            decode,
            render,
            present,
            e2e,
            rx_bytes,
            p95_from_samples(sec_bitrate_mbps),
        ));
    });

    let mut capture = Series::default();
    let mut encode = Series::default();
    let mut send = Series::default();
    let frame_interval = if cfg.target_fps == 0 {
        Duration::from_millis(16)
    } else {
        Duration::from_secs_f64(1.0 / cfg.target_fps as f64)
    };
    let run_start = Instant::now();
    let mut next_tick = Instant::now();
    let mut frame_id = 0u64;

    while run_start.elapsed() < Duration::from_secs(cfg.duration_sec) {
        if next_tick > Instant::now() {
            thread::sleep(next_tick - Instant::now());
        }
        next_tick += frame_interval;
        frame_id = frame_id.wrapping_add(1);

        let cap_t0 = Instant::now();
        let capture_ts_us = unix_us();
        emulate_work_us(cfg.stages.capture_us);
        capture.push(cap_t0.elapsed().as_secs_f64() * 1000.0);

        let enc_t0 = Instant::now();
        emulate_work_us(cfg.stages.encode_us);
        let encode_done_ts_us = unix_us();
        encode.push(enc_t0.elapsed().as_secs_f64() * 1000.0);

        let data = FramePacket {
            frame_id,
            capture_ts_us,
            encode_done_ts_us,
        }
        .encode();
        let send_t0 = Instant::now();
        sender
            .write_all(&data)
            .map_err(|e| format!("srt write_all: {e}"))?;
        send.push(send_t0.elapsed().as_secs_f64() * 1000.0);
    }

    running.store(false, Ordering::Relaxed);
    let _ = sender.close();
    let _ = rx_thread.join();
    let (
        frames_received,
        frames_dropped,
        recv_wait,
        decode,
        render,
        present,
        e2e,
        rx_bytes,
        bitrate_p95_mbps,
    ) = rx_report
        .recv()
        .map_err(|_| "srt report recv failed".to_string())?;
    let sec_total = run_start.elapsed().as_secs_f64().max(1e-6);
    let bitrate_avg_mbps = (rx_bytes as f64 * 8.0) / sec_total / 1_000_000.0;
    let wire_overhead_est_mbps = (frames_received as f64 * 44.0 * 8.0) / sec_total / 1_000_000.0;

    let mut report = PipelineReport {
        transport: "srt".to_string(),
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
