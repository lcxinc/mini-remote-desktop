//! QUIC 传输层 - 客户端
//!
//! 连接 QUIC 服务端并接收数据

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use quinn::{Endpoint, ClientConfig};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    println!("QUIC 传输层 - 客户端");
    println!("==================");
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

    // 发送请求
    for i in 0..10 {
        let (mut send, mut recv) = connection.open_bi().await?;
        
        let request = format!("请求 #{}", i + 1);
        send.write_all(request.as_bytes()).await?;
        send.finish().await?;

        // 接收响应
        let response = recv.read_to_end(1024).await?;
        let response_str = String::from_utf8_lossy(&response);
        
        println!("发送: {}", request);
        println!("接收: {}", response_str);
        println!();

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    println!("测试完成");
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
