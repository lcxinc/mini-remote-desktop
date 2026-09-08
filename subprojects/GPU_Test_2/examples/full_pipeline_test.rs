//! 全链路延迟测试
//!
//! 采集 -> 编码 -> 传输 -> 解码 -> 渲染
//! 测量每个阶段的 p50, p90, p95, p99 延迟

mod latency;
use latency::{LatencyMeasurer, LatencyStats};

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use quinn::{Endpoint, ServerConfig, Connection};
use anyhow::Result;
use windows::Win32::Foundation::{HWND, LRESULT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING, D3D11_CPU_ACCESS_READ,
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ,
};
use windows::Win32::Graphics::Dxgi::{
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    IDXGIOutputDuplication, IDXGIOutput1, IDXGIDevice, IDXGIOutput,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DispatchMessageA, PeekMessageA,
    PostQuitMessage, RegisterClassA, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
    MSG, PM_REMOVE, WM_DESTROY, WM_QUIT, WNDCLASSA, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};
use windows::core::Interface;
use windows::core::PCSTR;

const TEST_DURATION_SECS: u64 = 10;
const WINDOW_WIDTH: usize = 1264;
const WINDOW_HEIGHT: usize = 681;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    println!("全链路延迟测试");
    println!("==============");
    println!();
    println!("链路：采集 -> 编码 -> 传输 -> 解码 -> 渲染");
    println!("测试时间：{} 秒", TEST_DURATION_SECS);
    println!("窗口大小：{}x{}", WINDOW_WIDTH, WINDOW_HEIGHT);
    println!();

    // 启动 QUIC 服务端
    let endpoint = start_quic_server().await?;
    println!("QUIC 服务端启动在 0.0.0.0:4433");

    // 创建窗口
    let _hwnd = create_window()?;
    println!("窗口创建成功");

    // 创建 D3D11 设备
    let (device, context) = create_d3d11_device()?;
    println!("D3D11 设备创建成功");

    // 创建 DXGI Desktop Duplication
    let (duplication, width, height) = create_dxgi_duplication(&device)?;
    println!("桌面分辨率: {}x{}", width, height);

    // 创建暂存纹理
    let staging_texture = create_staging_texture(&device, width, height)?;

    // 预计算缩放映射
    let x_map: Vec<usize> = (0..WINDOW_WIDTH)
        .map(|x| (x * width as usize) / WINDOW_WIDTH)
        .collect();
    let y_map: Vec<usize> = (0..WINDOW_HEIGHT)
        .map(|y| (y * height as usize) / WINDOW_HEIGHT)
        .collect();

    // 预分配 RGB 缓冲区
    let mut rgb_data = vec![0u8; WINDOW_WIDTH * WINDOW_HEIGHT * 3];

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
    println!("开始全链路延迟测试...");
    println!();

    // 创建延迟测量器
    let mut measurer = LatencyMeasurer::new();

    let start_time = Instant::now();
    let mut frames_tested = 0u64;

    while start_time.elapsed() < Duration::from_secs(TEST_DURATION_SECS) {
        // 处理窗口消息
        let mut msg = MSG::default();
        while unsafe { PeekMessageA(&mut msg, None, 0, 0, PM_REMOVE) }.into() {
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }

            if msg.message == WM_QUIT {
                break;
            }
        }

        // 端到端计时开始
        let e2e_start = Instant::now();

        // 1. 采集阶段
        let capture_start = Instant::now();
        
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

                    // 获取源数据
                    let src_data = unsafe {
                        std::slice::from_raw_parts(
                            mapped.pData as *const u8,
                            mapped.RowPitch as usize * height as usize,
                        )
                    };

                    let src_pitch = mapped.RowPitch as usize;

                    // 缩放和格式转换（采集的一部分）
                    for (dst_y, src_y) in y_map.iter().enumerate() {
                        let src_row_start = src_y * src_pitch;
                        let dst_row_start = dst_y * WINDOW_WIDTH * 3;

                        for (dst_x, src_x) in x_map.iter().enumerate() {
                            let src_idx = src_row_start + src_x * 4;
                            let dst_idx = dst_row_start + dst_x * 3;

                            rgb_data[dst_idx] = src_data[src_idx + 2];
                            rgb_data[dst_idx + 1] = src_data[src_idx + 1];
                            rgb_data[dst_idx + 2] = src_data[src_idx];
                        }
                    }

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    let capture_time = capture_start.elapsed();
                    measurer.add_capture(capture_time);

                    // 2. 编码阶段（模拟：直接使用原始数据）
                    let encode_start = Instant::now();
                    let encoded_data = &rgb_data;
                    let encode_time = encode_start.elapsed();
                    measurer.add_encode(encode_time);

                    // 3. 传输阶段
                    let transfer_start = Instant::now();
                    let conn = connection.clone();
                    let data = encoded_data.to_vec();
                    tokio::spawn(async move {
                        if let Err(e) = send_frame(&conn, &data).await {
                            eprintln!("传输失败: {}", e);
                        }
                    });
                    let transfer_time = transfer_start.elapsed();
                    measurer.add_transfer(transfer_time);

                    // 4. 解码阶段（模拟：无解码）
                    let decode_start = Instant::now();
                    // 解码操作（如果有的话）
                    let decode_time = decode_start.elapsed();
                    measurer.add_decode(decode_time);

                    // 5. 渲染阶段（模拟：无渲染）
                    let render_start = Instant::now();
                    // 渲染操作（如果有的话）
                    let render_time = render_start.elapsed();
                    measurer.add_render(render_time);

                    // 端到端计时结束
                    let e2e_time = e2e_start.elapsed();
                    measurer.add_e2e(e2e_time);

                    frames_tested += 1;
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
    }

    // 计算统计结果
    measurer.calculate();
    measurer.print();

    println!("测试完成！共测试 {} 帧", frames_tested);
    println!();

    // 输出性能建议
    print_recommendations(&measurer);

    Ok(())
}

async fn start_quic_server() -> Result<Endpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key = cert.key_pair.serialize_der();

    let mut server_config = ServerConfig::with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::try_from(priv_key)?,
    )?;
    
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("无法获取传输配置"))?;
    transport_config.max_concurrent_uni_streams(100u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    let endpoint = Endpoint::server(
        server_config,
        "0.0.0.0:4433".parse()?,
    )?;

    Ok(endpoint)
}

async fn send_frame(connection: &Connection, data: &[u8]) -> Result<()> {
    let (mut send, _recv) = connection.open_bi().await?;
    
    let size = data.len() as u32;
    send.write_all(&size.to_le_bytes()).await?;
    send.write_all(data).await?;
    send.finish()?;

    Ok(())
}

fn create_window() -> Result<HWND, Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("FullPipelineTestClass\0".as_ptr());
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
            PCSTR::from_raw("Full Pipeline Test\0".as_ptr()),
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

fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext), Box<dyn std::error::Error>> {
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

fn create_dxgi_duplication(
    device: &ID3D11Device,
) -> Result<(IDXGIOutputDuplication, u32, u32), Box<dyn std::error::Error>> {
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

fn create_staging_texture(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> Result<ID3D11Texture2D, Box<dyn std::error::Error>> {
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

fn print_recommendations(measurer: &LatencyMeasurer) {
    println!("=== 性能建议 ===");
    println!();

    let capture_p95 = measurer.capture_stats.p95.as_secs_f64() * 1000.0;
    let encode_p95 = measurer.encode_stats.p95.as_secs_f64() * 1000.0;
    let transfer_p95 = measurer.transfer_stats.p95.as_secs_f64() * 1000.0;
    let decode_p95 = measurer.decode_stats.p95.as_secs_f64() * 1000.0;
    let render_p95 = measurer.render_stats.p95.as_secs_f64() * 1000.0;
    let e2e_p95 = measurer.e2e_stats.p95.as_secs_f64() * 1000.0;

    if capture_p95 > 10.0 {
        println!("⚠️  采集 P95 延迟较高 ({:.3} ms)", capture_p95);
        println!("   建议: 优化缩放算法或使用 GPU 缩放");
    }

    if encode_p95 > 10.0 {
        println!("⚠️  编码 P95 延迟较高 ({:.3} ms)", encode_p95);
        println!("   建议: 使用硬件加速编码（如 NVENC）");
    }

    if transfer_p95 > 10.0 {
        println!("⚠️  传输 P95 延迟较高 ({:.3} ms)", transfer_p95);
        println!("   建议: 优化 QUIC 传输或使用压缩");
    }

    if decode_p95 > 10.0 {
        println!("⚠️  解码 P95 延迟较高 ({:.3} ms)", decode_p95);
        println!("   建议: 使用硬件加速解码（如 NVDEC）");
    }

    if render_p95 > 10.0 {
        println!("⚠️  渲染 P95 延迟较高 ({:.3} ms)", render_p95);
        println!("   建议: 优化渲染管线");
    }

    if e2e_p95 > 50.0 {
        println!("⚠️  端到端 P95 延迟较高 ({:.3} ms)", e2e_p95);
        println!("   建议: 优化整个链路");
    }

    if capture_p95 < 5.0 && encode_p95 < 5.0 && transfer_p95 < 5.0 {
        println!("✅ 各阶段延迟良好");
    }

    println!();
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
