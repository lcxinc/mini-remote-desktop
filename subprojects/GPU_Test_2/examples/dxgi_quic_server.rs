//! DXGI Desktop Duplication + QUIC 传输
//!
//! 采集桌面画面并通过 QUIC 协议传输

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use quinn::{Endpoint, ServerConfig, Connection};
use anyhow::Result;
use windows::Win32::Foundation::{HWND, LRESULT, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING, D3D11_CPU_ACCESS_READ,
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ,
};
use windows::Win32::Graphics::Dxgi::{
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    IDXGIOutputDuplication, IDXGIOutput1, IDXGIResource, IDXGIDevice, IDXGIOutput,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DispatchMessageA, GetClientRect, PeekMessageA,
    PostQuitMessage, RegisterClassA, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
    MSG, PM_REMOVE, WM_DESTROY, WM_QUIT, WNDCLASSA, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::Interface;
use windows::core::PCSTR;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    println!("DXGI Desktop Duplication + QUIC 传输");
    println!("====================================");
    println!();

    // 启动 QUIC 服务端
    let endpoint = start_quic_server().await?;
    println!("QUIC 服务端启动在 0.0.0.0:4433");

    // 创建窗口
    let hwnd = create_window()?;
    println!("窗口创建成功");

    // 创建 D3D11 设备
    let (device, context) = create_d3d11_device()?;
    println!("D3D11 设备创建成功");

    // 创建 DXGI Desktop Duplication
    let (duplication, width, height) = create_dxgi_duplication(&device)?;
    println!("桌面分辨率: {}x{}", width, height);

    // 创建暂存纹理
    let staging_texture = create_staging_texture(&device, width, height)?;

    // 等待客户端连接
    println!();
    println!("等待客户端连接...");
    
    let connection = if let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        println!("客户端连接: {}", connection.remote_address());
        Arc::new(connection)
    } else {
        return Err(anyhow::anyhow!("无法接受连接"));
    };

    println!();
    println!("开始采集和传输，按 Ctrl+C 退出...");

    // 主循环
    let mut running = true;
    let mut last_report = Instant::now();
    let mut frames_since_report = 0u64;

    while running {
        // 处理窗口消息
        let mut msg = MSG::default();
        while unsafe { PeekMessageA(&mut msg, None, 0, 0, PM_REMOVE) }.into() {
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }

            if msg.message == WM_QUIT {
                running = false;
                break;
            }
        }

        if !running {
            break;
        }

        // 采集桌面画面
        let mut frame_resource = None;
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let acquire_result = unsafe {
            duplication.AcquireNextFrame(0, &mut frame_info, &mut frame_resource)
        };

        match acquire_result {
            Ok(()) => {
                if let Some(resource) = frame_resource {
                    // 获取桌面纹理
                    let desktop_texture: ID3D11Texture2D = resource.cast()?;

                    // 复制到暂存纹理
                    unsafe {
                        context.CopyResource(&staging_texture, &desktop_texture);
                    }

                    // 读取暂存纹理数据
                    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    unsafe {
                        context.Map(
                            &staging_texture,
                            0,
                            D3D11_MAP_READ,
                            0,
                            Some(&mut mapped),
                        )?;
                    }

                    // 获取帧数据
                    let frame_data = unsafe {
                        std::slice::from_raw_parts(
                            mapped.pData as *const u8,
                            (mapped.RowPitch as usize) * (height as usize),
                        )
                    };

                    // 通过 QUIC 传输帧数据
                    let conn = connection.clone();
                    let data = frame_data.to_vec();
                    tokio::spawn(async move {
                        if let Err(e) = send_frame(&conn, &data).await {
                            eprintln!("传输失败: {}", e);
                        }
                    });

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    frames_since_report += 1;
                }

                // 释放帧
                unsafe {
                    duplication.ReleaseFrame()?;
                }
            }
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                // 没有新帧
            }
            Err(e) => {
                eprintln!("采集失败: {}", e);
            }
        }

        // 每秒报告一次
        if last_report.elapsed() >= Duration::from_secs(1) {
            println!("传输帧率: {} fps", frames_since_report);
            frames_since_report = 0;
            last_report = Instant::now();
        }
    }

    println!("程序退出");
    Ok(())
}

async fn start_quic_server() -> Result<Endpoint> {
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

    Ok(endpoint)
}

async fn send_frame(connection: &Connection, data: &[u8]) -> Result<()> {
    let (mut send, _recv) = connection.open_bi().await?;
    
    // 发送帧大小
    let size = data.len() as u32;
    send.write_all(&size.to_le_bytes()).await?;
    
    // 发送帧数据
    send.write_all(data).await?;
    send.finish().await?;

    Ok(())
}

fn create_window() -> Result<HWND> {
    let class_name = PCSTR::from_raw("DXGICaptureClass\0".as_ptr());
    let hinstance = unsafe { GetModuleHandleA(None)? };

    let wnd_class = WNDCLASSA {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        hInstance: hinstance.into(),
        lpszClassName: class_name,
        hbrBackground: HBRUSH(std::ptr::null_mut()),
        ..Default::default()
    };

    unsafe { RegisterClassA(&wnd_class) };

    let hwnd = unsafe {
        CreateWindowExA(
            Default::default(),
            class_name,
            PCSTR::from_raw("DXGI + QUIC\0".as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1280,
            720,
            None,
            None,
            Some(hinstance.into()),
            None,
        )?
    };

    Ok(hwnd)
}

fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            windows::Win32::Foundation::HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
    }

    Ok((device.unwrap(), context.unwrap()))
}

fn create_dxgi_duplication(device: &ID3D11Device) -> Result<(IDXGIOutputDuplication, u32, u32)> {
    let dxgi_device: IDXGIDevice = device.cast()?;
    let adapter = unsafe { dxgi_device.GetAdapter()? };
    let output: IDXGIOutput = unsafe { adapter.EnumOutputs(0)? };
    let output1: IDXGIOutput1 = output.cast()?;

    let duplication = unsafe { output1.DuplicateOutput(device)? };
    
    let desc = unsafe { output.GetDesc()? };
    let width = (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32;
    let height = (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32;

    Ok((duplication, width, height))
}

fn create_staging_texture(device: &ID3D11Device, width: u32, height: u32) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };

    let mut texture: Option<ID3D11Texture2D> = None;
    unsafe {
        device.CreateTexture2D(&desc, None, Some(&mut texture))?;
    }

    Ok(texture.unwrap())
}

unsafe extern "system" fn wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> LRESULT {
    match msg {
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcA(hwnd, msg, wparam, lparam),
    }
}
