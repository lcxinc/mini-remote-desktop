use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use gpu_test_2::capture::CaptureSession;
use gpu_test_2::encoder::{EncoderConfig, PersistentNvencEncoder};
use gpu_test_2::protocol::FrameHeader;
use gpu_test_2::transport::write_frame_message;
use quinn::{ClientConfig, Endpoint};
use tokio::time::sleep;

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

    let (mut send, mut recv) = connection.open_bi().await?;

    // Initialize persistent capture and encoder
    let mut capture_session = CaptureSession::new()?;
    let encoder_config = EncoderConfig::new(capture_session.width(), capture_session.height())?;
    let mut encoder = PersistentNvencEncoder::new(encoder_config)?;

    println!("streaming at {}x{} with low-latency pipeline", capture_session.width(), capture_session.height());

    // Pipeline stage counters
    let mut frames_captured = 0u64;
    let mut frames_encoded = 0u64;
    let mut frames_sent = 0u64;
    let mut capture_timeouts = 0u64;
    let mut encode_errors = 0u64;
    let mut send_errors = 0u64;

    let mut last_report = Instant::now();
    let mut frames_since_report = 0u64;
    let start_time = Instant::now();

    // Stream frames for 30 seconds
    while start_time.elapsed() < Duration::from_secs(30) {
        // Capture stage
        let captured = match capture_session.capture_next_frame() {
            Ok(c) => c,
            Err(_) => {
                capture_timeouts += 1;
                sleep(Duration::from_millis(1)).await;
                continue;
            }
        };

        frames_captured += 1;

        // Capture time for latency measurement
        let capture_time_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Encode stage
        match encoder.encode_frame(&captured, frames_captured) {
            Ok(encoded) => {
                frames_encoded += 1;

                let header = FrameHeader::new(
                    encoded.width,
                    encoded.height,
                    encoded.pts,
                    capture_time_ns,
                    encoded.bitstream.len() as u32,
                );

                // Network stage
                match write_frame_message(&mut send, &header, &encoded.bitstream).await {
                    Ok(_) => {
                        frames_sent += 1;
                        frames_since_report += 1;
                    }
                    Err(e) => {
                        send_errors += 1;
                        eprintln!("send error: {e}");
                        break;
                    }
                }
            }
            Err(e) => {
                encode_errors += 1;
                eprintln!("encode error: {e}");
            }
        }

        // Report stats every second
        if last_report.elapsed() >= Duration::from_secs(1) {
            let fps = frames_since_report as f64 / last_report.elapsed().as_secs_f64();
            println!("sender: {:.1} fps | captured: {} encoded: {} sent: {} | timeouts: {} encode_errs: {} send_errs: {}",
                fps, frames_captured, frames_encoded, frames_sent,
                capture_timeouts, encode_errors, send_errors);
            frames_since_report = 0;
            last_report = Instant::now();
        }

        // Target ~60 fps
        sleep(Duration::from_millis(16)).await;
    }

    // Final stats
    let elapsed = start_time.elapsed();
    println!("\nsender stats ({}s):", elapsed.as_secs());
    println!("  captured: {} ({:.1} fps)", frames_captured,
        frames_captured as f64 / elapsed.as_secs_f64());
    println!("  encoded: {} ({:.1} fps)", frames_encoded,
        frames_encoded as f64 / elapsed.as_secs_f64());
    println!("  sent: {} ({:.1} fps)", frames_sent,
        frames_sent as f64 / elapsed.as_secs_f64());
    println!("  capture_timeouts: {}", capture_timeouts);
    println!("  encode_errors: {}", encode_errors);
    println!("  send_errors: {}", send_errors);

    // Graceful shutdown
    drop(send);
    let _ = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(usize::MAX)).await;

    Ok(())
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
