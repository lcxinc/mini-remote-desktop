use crate::core::metrics::Series;
use crate::core::pipeline_udp::{p95_from_samples, PipelineConfig, PipelineReport};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

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

pub fn run_quic_pipeline(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| format!("build tokio runtime: {e}"))?;
    rt.block_on(run_quic_pipeline_async(cfg))
}

async fn run_quic_pipeline_async(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    let stages = cfg.stages;
    let chain_name = cfg.chain_name.clone();
    install_rustls_provider();
    let (server_config, client_config) = make_quic_configs()?;
    let server_addr = "127.0.0.1:0"
        .parse()
        .map_err(|e| format!("parse server addr: {e}"))?;
    let server_ep = Endpoint::server(server_config, server_addr)
        .map_err(|e| format!("server endpoint: {e}"))?;
    let listen_addr = server_ep
        .local_addr()
        .map_err(|e| format!("server local_addr: {e}"))?;
    let client_bind = "127.0.0.1:0"
        .parse()
        .map_err(|e| format!("parse client bind: {e}"))?;
    let mut client_ep =
        Endpoint::client(client_bind).map_err(|e| format!("client endpoint: {e}"))?;
    client_ep.set_default_client_config(client_config);

    let server_task = tokio::spawn(async move {
        let incoming = server_ep
            .accept()
            .await
            .ok_or_else(|| "server accept None".to_string())?;
        incoming
            .await
            .map_err(|e| format!("server incoming await: {e}"))
    });
    let client_conn = client_ep
        .connect(listen_addr, "localhost")
        .map_err(|e| format!("client connect: {e}"))?
        .await
        .map_err(|e| format!("client connect await: {e}"))?;
    let server_conn = server_task
        .await
        .map_err(|e| format!("server join: {e}"))??;

    let mut send_stream = client_conn
        .open_uni()
        .await
        .map_err(|e| format!("open uni: {e}"))?;

    let running = Arc::new(AtomicBool::new(true));
    let running_rx = running.clone();
    let (tx_report, rx_report) =
        oneshot::channel::<(u64, u64, Series, Series, Series, Series, Series, u64, f64)>();

    tokio::spawn(async move {
        let mut recv_stream = match server_conn.accept_uni().await {
            Ok(s) => s,
            Err(_) => {
                let _ = tx_report.send((
                    0,
                    0,
                    Series::default(),
                    Series::default(),
                    Series::default(),
                    Series::default(),
                    Series::default(),
                    0,
                    0.0,
                ));
                return;
            }
        };
        let mut recv_wait = Series::default();
        let mut decode = Series::default();
        let mut render = Series::default();
        let mut present = Series::default();
        let mut e2e = Series::default();
        let mut received = 0u64;
        let mut last_frame_id = 0u64;
        let mut dropped = 0u64;
        let mut rx_bytes = 0u64;
        let mut buf = [0u8; FramePacket::LEN];
        let mut sec_window_start = Instant::now();
        let mut sec_count = 0u64;
        let mut sec_bytes = 0u64;
        let mut sec_bitrate_mbps = Vec::<f64>::new();

        loop {
            if !running_rx.load(Ordering::Relaxed) {
                break;
            }
            match recv_stream.read_exact(&mut buf).await {
                Ok(_) => {
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
                                "[DECODE-RUNTIME] transport=quic chain={} fps={:.2}",
                                chain_name, fps
                            );
                            sec_count = 0;
                            sec_bytes = 0;
                            sec_window_start = Instant::now();
                        }
                    }
                }
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

        let data = FramePacket {
            frame_id,
            capture_ts_us,
            encode_done_ts_us,
        }
        .encode();
        let send_t0 = Instant::now();
        send_stream
            .write_all(&data)
            .await
            .map_err(|e| format!("quic write_all: {e}"))?;
        send.push(send_t0.elapsed().as_secs_f64() * 1000.0);
    }

    running.store(false, Ordering::Relaxed);
    let _ = send_stream.finish();
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
        .await
        .map_err(|_| "quic recv report channel closed".to_string())?;
    let sec_total = run_start.elapsed().as_secs_f64().max(1e-6);
    let bitrate_avg_mbps = (rx_bytes as f64 * 8.0) / sec_total / 1_000_000.0;
    let wire_overhead_est_mbps = (frames_received as f64 * 56.0 * 8.0) / sec_total / 1_000_000.0;

    let mut report = PipelineReport {
        transport: "quic".to_string(),
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
    client_conn.close(0u32.into(), b"done");
    client_ep.wait_idle().await;
    Ok(report)
}

fn install_rustls_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn make_quic_configs() -> Result<(ServerConfig, ClientConfig), String> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("generate cert: {e}"))?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())
        .map_err(|e| format!("server config: {e}"))?;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert_der)
        .map_err(|e| format!("add root cert: {e}"))?;
    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| format!("client quic config: {e}"))?,
    ));
    Ok((server_config, client_config))
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
