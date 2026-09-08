//! QUIC 客户端 - 接收桌面画面
//!
//! 连接 QUIC 服务端并接收桌面画面数据

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use quinn::{Endpoint, ClientConfig};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    println!("QUIC 客户端 - 接收桌面画面");
    println!("========================");
    println!();

    // 配置客户端（跳过证书验证）
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    // 创建客户端端点
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // 连接到服务端
    println!("连接到 127.0.0.1:4433...");
    let connection = endpoint.connect(
        "127.0.0.1:4433".parse()?,
        "localhost",
    )?.await?;

    println!("连接成功!");
    println!();
    println!("开始接收桌面画面数据...");
    println!();

    let mut last_report = Instant::now();
    let mut frames_received = 0u64;
    let mut bytes_received = 0u64;

    loop {
        // 接受双向流
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // 读取帧大小
                let mut size_buf = [0u8; 4];
                recv.read_exact(&mut size_buf).await?;
                let frame_size = u32::from_le_bytes(size_buf) as usize;

                // 读取帧数据
                let frame_data = recv.read_to_end(frame_size).await?;

                frames_received += 1;
                bytes_received += frame_data.len() as u64;

                // 每秒报告一次
                if last_report.elapsed() >= Duration::from_secs(1) {
                    let fps = frames_received as f64 / last_report.elapsed().as_secs_f64();
                    let mbps = (bytes_received as f64 * 8.0) / (last_report.elapsed().as_secs_f64() * 1_000_000.0);
                    
                    println!("接收帧率: {:.1} fps, 带宽: {:.2} Mbps", fps, mbps);
                    
                    frames_received = 0;
                    bytes_received = 0;
                    last_report = Instant::now();
                }
            }
            Err(e) => {
                println!("连接错误: {}", e);
                break;
            }
        }
    }

    println!("程序退出");
    Ok(())
}

// 跳过证书验证的实现
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
