use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use gpu_test_2::capture::CapturedFrame;
use gpu_test_2::encoder::{EncoderConfig, PersistentNvencEncoder};
use gpu_test_2::protocol::FrameHeader;
use gpu_test_2::transport::write_frame_message;
use quinn::{ClientConfig, Endpoint};
use tokio::sync::watch;
use tokio::task::spawn_blocking;

/// Drain any queued frames from the channel, keeping only the latest.
/// Returns the latest frame (original if no newer frames available).
fn drain_latest_frame(
    rx: &mpsc::Receiver<(CapturedFrame, u64, u64)>,
    initial_frame: CapturedFrame,
    initial_pts: u64,
    initial_capture_time_ns: u64,
    telemetry: &Arc<std::sync::Mutex<Telemetry>>,
) -> (CapturedFrame, u64, u64) {
    let mut frame = initial_frame;
    let mut pts = initial_pts;
    let mut capture_time_ns = initial_capture_time_ns;
    let mut dropped = 0u64;

    while let Ok((latest, latest_pts, latest_capture_time_ns)) = rx.try_recv() {
        frame = latest;
        pts = latest_pts;
        capture_time_ns = latest_capture_time_ns;  // Use the latest frame's capture time
        dropped += 1;
    }

    if dropped > 0 {
        if let Ok(mut t) = telemetry.lock() {
            t.encode_dropped += dropped;
        }
    }

    (frame, pts, capture_time_ns)
}

/// Frame encoded by NVENC (must be Send for tokio spawn)
#[derive(Debug, Clone)]
struct EncodedData {
    bitstream: Vec<u8>,
    width: u32,
    height: u32,
    pts: u64,
    capture_time_ns: u64,  // Nanoseconds since frame capture for latency tracking
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect("127.0.0.1:4433".parse()?, "localhost")?
        .await?;
    println!("connected to receiver");

    let (send, mut recv) = connection.open_bi().await?;

    // Get dimensions from a temporary capture session
    let (width, height) = {
        let session = gpu_test_2::capture::CaptureSession::new()?;
        (session.width(), session.height())
    };
    let encoder_config = EncoderConfig::new(width, height)?;

    println!("streaming at {}x{} with multi-threaded low-latency pipeline (mpsc + watch)", width, height);

    // Channels for pipeline stages:
    // capture -> encode: mpsc with latest-frame semantics (try_recv drops old)
    // (frame, pts, capture_time_ns) - capture_time_ns recorded at actual capture time
    let (capture_tx, capture_rx) = mpsc::channel::<(CapturedFrame, u64, u64)>();

    // encode -> network: watch channel (always holds latest value)
    let (encode_tx, encode_rx) = watch::channel::<Option<EncodedData>>(None);

    // Stop flag for encoder thread
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Telemetry shared between tasks
    let telemetry = Arc::new(std::sync::Mutex::new(Telemetry::default()));

    // ENCODER TASK: runs in blocking thread pool, receives from mpsc
    let telemetry_encode = telemetry.clone();
    let stop_encode = stop_flag.clone();
    let encode_handle = spawn_blocking(move || {
        let mut encoder = match PersistentNvencEncoder::new(encoder_config) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("encoder init failed: {e}");
                return;
            }
        };

        while !stop_encode.load(std::sync::atomic::Ordering::Acquire) {
            match capture_rx.recv_timeout(Duration::from_millis(100)) {
                Ok((frame, pts, capture_time_ns)) => {
                    // Drain any queued frames (latest-frame semantics)
                    let (frame, pts, capture_time_ns) = drain_latest_frame(
                        &capture_rx, frame, pts, capture_time_ns, &telemetry_encode
                    );

                    match encoder.encode_frame(&frame, pts) {
                        Ok(encoded) => {
                            let encode_data = Some(EncodedData {
                                bitstream: encoded.bitstream,
                                width: encoded.width,
                                height: encoded.height,
                                pts,
                                capture_time_ns,  // Recorded at actual capture time in capture loop
                            });

                            // Send to watch channel (overwrites previous)
                            let _ = encode_tx.send(encode_data);

                            if let Ok(mut t) = telemetry_encode.lock() {
                                t.frames_encoded += 1;
                            }
                        }
                        Err(e) => {
                            if let Ok(mut t) = telemetry_encode.lock() {
                                t.encode_errors += 1;
                            }
                            eprintln!("encode error: {e}");
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Check stop flag and continue
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    // Channel closed, exit
                    break;
                }
            }
        }

        eprintln!("encoder task: shutdown");
    });

    // NETWORK TASK: runs in async runtime, waits on watch channel
    let telemetry_net = telemetry.clone();
    let stop_net = stop_flag.clone();
    let mut encode_rx = encode_rx.clone();
    let network_handle = tokio::spawn(async move {
        let mut send = send;
        let mut frames_sent = 0u64;
        let mut last_pts = None;

        while !stop_net.load(std::sync::atomic::Ordering::Acquire) {
            // Wait for new encoded value (async, no blocking!)
            tokio::select! {
                result = encode_rx.changed() => {
                    if result.is_err() {
                        // Sender closed
                        break;
                    }

                    let data = encode_rx.borrow().clone();
                    if let Some(data) = data {
                        let pts = data.pts;

                        // Only send if it's a new frame
                        if last_pts.map_or(true, |last| pts != last) {
                            let header = FrameHeader::new(
                                data.width,
                                data.height,
                                data.pts,
                                data.capture_time_ns,
                                data.bitstream.len() as u32,
                            );

                            match write_frame_message(&mut send, &header, &data.bitstream).await {
                                Ok(_) => {
                                    frames_sent += 1;
                                    last_pts = Some(pts);
                                    if let Ok(mut t) = telemetry_net.lock() {
                                        t.frames_sent = frames_sent;
                                    }
                                }
                                Err(e) => {
                                    if let Ok(mut t) = telemetry_net.lock() {
                                        t.send_errors += 1;
                                    }
                                    eprintln!("send error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Timeout to check stop flag periodically
                    continue;
                }
            }
        }

        eprintln!("network task: shutdown");
        drop(send);
    });

    // CAPTURE LOOP: runs in main task, captures as fast as possible
    let mut capture_session = gpu_test_2::capture::CaptureSession::new()?;
    let start_time = Instant::now();
    let mut last_report = Instant::now();
    let mut frame_count = 0u64;
    let mut last_sent = 0u64;
    let mut last_report_capture = 0u64;

    // Run for 30 seconds
    while start_time.elapsed() < Duration::from_secs(30) {
        match capture_session.capture_next_frame() {
            Ok(frame) => {
                frame_count += 1;
                if let Ok(mut t) = telemetry.lock() {
                    t.frames_captured = frame_count;
                }

                // Record capture time immediately after capturing the frame
                // This captures the true end-to-end latency including:
                // - capture processing time
                // - mpsc queue wait time
                // - encode time
                // - network transmission time
                // - decode time
                let capture_time_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

                // Send to encoder channel (unbounded, never drops here)
                // Latest-frame drops happen in encoder thread's drain_latest_frame()
                if capture_tx.send((frame, frame_count, capture_time_ns)).is_err() {
                    // Encoder thread exited
                    break;
                }
            }
            Err(_) => {
                if let Ok(mut t) = telemetry.lock() {
                    t.capture_timeouts += 1;
                }
            }
        }

        // Report stats every second
        if last_report.elapsed() >= Duration::from_secs(1) {
            let t = telemetry.lock().unwrap();
            let sent_delta = t.frames_sent - last_sent;
            let fps = sent_delta as f64 / last_report.elapsed().as_secs_f64();
            let capture_delta = t.frames_captured - last_report_capture;
            let capture_fps = capture_delta as f64 / last_report.elapsed().as_secs_f64();

            println!("sender: {:.1} fps out | {:.1} fps cap | enc: {} sent: {} | enc_drop: {}",
                fps,
                capture_fps,
                t.frames_encoded,
                t.frames_sent,
                t.encode_dropped
            );

            last_sent = t.frames_sent;
            last_report_capture = t.frames_captured;
            last_report = Instant::now();
        }

        // Small sleep to avoid 100% CPU
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Signal shutdown
    println!("\nsignaling shutdown...");
    stop_flag.store(true, std::sync::atomic::Ordering::Release);
    drop(capture_tx); // Close capture channel so encoder exits

    // Wait for tasks to finish
    let _ = tokio::time::timeout(Duration::from_secs(2), encode_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), network_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(usize::MAX)).await;

    // Final stats AFTER all tasks finished
    let (t, elapsed) = {
        let t = telemetry.lock().unwrap();
        (t, start_time.elapsed())
    };
    println!("\nsender stats ({}s):", elapsed.as_secs());
    println!("  captured: {} ({:.1} fps)", t.frames_captured,
        t.frames_captured as f64 / elapsed.as_secs_f64());
    println!("  encoded: {} ({:.1} fps) | dropped: {}", t.frames_encoded,
        t.frames_encoded as f64 / elapsed.as_secs_f64(), t.encode_dropped);
    println!("  sent: {} ({:.1} fps)", t.frames_sent,
        t.frames_sent as f64 / elapsed.as_secs_f64());
    println!("  capture_timeouts: {} | encode_errors: {} | send_errors: {}",
        t.capture_timeouts, t.encode_errors, t.send_errors);

    println!("shutdown complete");
    Ok(())
}

#[derive(Debug, Default)]
struct Telemetry {
    frames_captured: u64,
    frames_encoded: u64,
    frames_sent: u64,
    encode_dropped: u64,
    capture_timeouts: u64,
    encode_errors: u64,
    send_errors: u64,
}

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
