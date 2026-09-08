//! QUIC 传输层 - 服务端
//!
//! 采集桌面画面并通过 QUIC 协议传输

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use quinn::{Endpoint, ServerConfig, Connection};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    println!("QUIC 传输层 - 服务端");
    println!("==================");
    println!();

    // 生成自签名证书
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();

    // 配置服务端
    let mut server_config = ServerConfig::with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(priv_key)?,
    )?;
    
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("无法获取传输配置"))?;
    transport_config.max_concurrent_uni_streams(100u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    // 创建服务端端点
    let endpoint = Endpoint::server(
        server_config,
        "0.0.0.0:4433".parse()?,
    )?;

    println!("服务端启动在 0.0.0.0:4433");
    println!("等待客户端连接...");
    println!();

    // 等待客户端连接
    while let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        let remote_addr = connection.remote_address();
        println!("客户端连接: {}", remote_addr);

        // 处理连接
        tokio::spawn(handle_connection(connection));
    }

    Ok(())
}

async fn handle_connection(connection: Connection) -> Result<()> {
    let connection = Arc::new(connection);
    
    loop {
        // 接受双向流
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // 读取客户端请求
                let request = recv.read_to_end(1024).await?;
                let request_str = String::from_utf8_lossy(&request);
                
                println!("收到请求: {}", request_str);
                
                // 发送响应
                let response = format!("服务端时间: {:?}", Instant::now());
                send.write_all(response.as_bytes()).await?;
                send.finish().await?;
            }
            Err(e) => {
                println!("连接错误: {}", e);
                break;
            }
        }
    }

    Ok(())
}
