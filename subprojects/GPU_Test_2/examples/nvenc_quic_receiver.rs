use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use gpu_test_2::artifacts::{encode_ppm, write_artifact};
use gpu_test_2::decode::StreamingDecoder;
use gpu_test_2::transport::read_frame_message;
use quinn::{Endpoint, ServerConfig};

/// Tracks moving average latency for reporting.
///
/// Uses a circular buffer to store the last N samples, providing a true
/// moving average that smoothly updates without sudden jumps at window boundaries.
struct LatencyTracker {
    samples: Vec<u64>,
    index: usize,
    count: u64,
    sum_ns: u64,
}

impl LatencyTracker {
    fn new(window_size: usize) -> Self {
        Self {
            samples: vec![0; window_size],
            index: 0,
            count: 0,
            sum_ns: 0,
        }
    }

    fn add(&mut self, latency_ns: u64) {
        // Subtract the oldest sample from sum (if we've wrapped around)
        if self.count >= self.samples.len() as u64 {
            self.sum_ns -= self.samples[self.index];
        }

        // Add new sample
        self.sum_ns += latency_ns;
        self.samples[self.index] = latency_ns;
        self.index = (self.index + 1) % self.samples.len();
        self.count += 1;
    }

    fn average_ms(&self) -> f64 {
        let n = self.count.min(self.samples.len() as u64) as usize;
        if n == 0 {
            0.0
        } else {
            (self.sum_ns / n as u64) as f64 / 1_000_000.0
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key = cert.key_pair.serialize_der();

    let mut server_config = ServerConfig::with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::try_from(priv_key)
            .map_err(|err| anyhow::anyhow!("invalid private key: {err}"))?,
    )?;

    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("unable to access transport config"))?;
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    let endpoint = Endpoint::server(server_config, "0.0.0.0:4433".parse()?)?;
    println!("receiver listening on 0.0.0.0:4433");

    let Some(connecting) = endpoint.accept().await else {
        anyhow::bail!("receiver stopped before a connection arrived");
    };
    let connection = connecting.await?;
    println!("accepted connection from {}", connection.remote_address());

    let (send, mut recv) = connection.accept_bi().await?;

    // Initialize streaming decoder
    let mut decoder = StreamingDecoder::new()?;

    let mut frame_count = 0u64;
    let mut decoded_count = 0u64;
    let mut last_report = Instant::now();
    let mut frames_received = 0u64;
    let mut total_bytes = 0u64;
    let mut last_artifact = Instant::now();
    let start_time = Instant::now();

    // Latency tracking (moving average over last 60 frames ~1 second at 60fps)
    let mut latency_tracker = LatencyTracker::new(60);

    // Read frames continuously until sender closes
    loop {
        match read_frame_message(&mut recv).await {
            Ok(frame) => {
                frame_count += 1;
                frames_received += 1;
                total_bytes += frame.header.payload_len as u64;

                // Decode the frame using streaming decoder
                match decoder.decode_packet(&frame.payload) {
                    Ok(Some(decoded)) => {
                        decoded_count += 1;

                        // Calculate end-to-end latency (capture to decode)
                        let decode_time_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64;
                        let latency_ns = decode_time_ns.saturating_sub(frame.header.capture_time_ns);
                        latency_tracker.add(latency_ns);

                        // Write artifact once per second
                        if last_artifact.elapsed() >= Duration::from_secs(1) {
                            if let Ok(ppm) = encode_ppm(decoded.width, decoded.height, &decoded.rgb) {
                                if let Ok(path) = write_artifact("artifacts/latest.ppm", &ppm) {
                                    println!("wrote {}", path.display());
                                }
                            }
                            last_artifact = Instant::now();
                        }
                    }
                    Ok(None) => {
                        // Packet processed but no frame produced yet
                    }
                    Err(e) => {
                        eprintln!("decode error: {e}");
                    }
                }

                // Log first frame details
                if frame_count == 1 {
                    println!("first frame: {}x{}, pts={}, capture_time_ns={}, {} bytes",
                        frame.header.width,
                        frame.header.height,
                        frame.header.pts,
                        frame.header.capture_time_ns,
                        frame.header.payload_len);
                }
            }
            Err(e) => {
                // Check if it's an EOF error (sender closed)
                if e.downcast_ref::<std::io::Error>().map(|io| io.kind())
                    == Some(std::io::ErrorKind::UnexpectedEof) {
                    println!("sender closed stream");
                    break;
                }
                eprintln!("receive error: {e}");
                break;
            }
        }

        // Report stats every second
        if last_report.elapsed() >= Duration::from_secs(1) {
            let fps = frames_received as f64 / last_report.elapsed().as_secs_f64();
            let decode_fps = decoded_count as f64 / last_report.elapsed().as_secs_f64();
            let bitrate_mbps = (total_bytes as f64 * 8.0 / 1_000_000.0)
                / last_report.elapsed().as_secs_f64();
            println!("receiver: {:.1} fps recv, {:.1} fps decode, {:.2} mbps, {:.1} ms avg latency, total: {}",
                fps, decode_fps, bitrate_mbps, latency_tracker.average_ms(), frame_count);
            frames_received = 0;
            decoded_count = 0;
            total_bytes = 0;
            last_report = Instant::now();
        }
    }

    // Write final artifact
    if let Some(decoded) = decoder.latest_frame() {
        if let Ok(ppm) = encode_ppm(decoded.width, decoded.height, &decoded.rgb) {
            if let Ok(path) = write_artifact("artifacts/final.ppm", &ppm) {
                println!("wrote {}", path.display());
            }
        }
    }

    let elapsed = start_time.elapsed();
    println!("receiver finished: received {} frames in {:.1}s ({:.1} avg fps)",
        frame_count, elapsed.as_secs_f64(),
        frame_count as f64 / elapsed.as_secs_f64());

    // Graceful shutdown
    drop(send);

    Ok(())
}
