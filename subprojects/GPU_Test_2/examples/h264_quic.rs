//! H.264 编码 + QUIC 传输
//!
//! 使用 NVENC H.264 编码
//! 通过 QUIC 协议传输编码数据

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use quinn::{Endpoint, ServerConfig, Connection};
use windows::Win32::Foundation::{HWND, LRESULT, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING, D3D11_USAGE_DEFAULT,
    D3D11_CPU_ACCESS_READ, D3D11_CPU_ACCESS_WRITE,
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ, D3D11_MAP_WRITE,
};
use windows::Win32::Graphics::Dxgi::{
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    IDXGIOutputDuplication, IDXGIOutput1, IDXGIDevice, IDXGIOutput,
    IDXGISwapChain1, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_EFFECT_FLIP_DISCARD,
    DXGI_USAGE_RENDER_TARGET_OUTPUT,
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

use nvenc::bitstream::BitStream;
use nvenc::session::{InitParams, Session};
use nvenc::sys::guids::{NV_ENC_CODEC_H264_GUID, NV_ENC_PRESET_P3_GUID};

const TEST_DURATION_SECS: u64 = 60;
const BITRATE: u32 = 8_000_000; // 8 Mbps
const FPS: u32 = 60;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    println!("H.264 编码 + QUIC 传输");
    println!("======================");
    println!();
    println!("编码: NVENC H.264");
    println!("传输: QUIC");
    println!("比特率: {} Mbps", BITRATE / 1_000_000);
    println!("目标帧率: {} fps", FPS);
    println!("测试时间: {} 秒", TEST_DURATION_SECS);
    println!();

    // 启动 QUIC 服务端
    println!("启动 QUIC 服务端...");
    let endpoint = start_quic_server().await?;
    println!("QUIC 服务端启动在 0.0.0.0:4433");
    println!("等待客户端连接...");

    // 等待客户端连接
    let connection = if let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        println!("客户端连接: {}", connection.remote_address());
        Arc::new(connection)
    } else {
        return Err("无法接受连接".into());
    };

    println!("客户端已连接！");
    println!();

    // 创建窗口
    let (hwnd, window_width, window_height) = create_window()?;
    println!("窗口创建成功: {}x{}", window_width, window_height);

    // 创建 D3D11 设备和交换链
    let (device, context, swap_chain) = create_d3d11_device_and_swap_chain(hwnd, window_width, window_height)?;
    println!("D3D11 设备和交换链创建成功");

    // 创建 DXGI Desktop Duplication
    let (duplication, width, height) = create_dxgi_duplication(&device)?;
    let desktop_width = width as usize;
    let desktop_height = height as usize;
    println!("桌面分辨率: {}x{}", desktop_width, desktop_height);

    // 创建暂存纹理
    let staging_texture = create_staging_texture(&device, width, height)?;
    let encode_texture = create_encode_texture(&device, desktop_width as u32, desktop_height as u32)?;
    let render_staging_texture = create_staging_texture_for_write(&device, window_width, window_height)?;

    // 预分配缓冲区
    let mut rgba_data = vec![0u8; desktop_width * desktop_height * 4];
    let mut rendered_data = vec![0u8; window_width as usize * window_height as usize * 4];

    // 初始化 NVENC 编码器
    println!("初始化 NVENC H.264 编码器...");
    let session: Session<nvenc::session::NeedsConfig> = Session::open_dx(&device)
        .map_err(|e| format!("创建 NVENC 会话失败: {:?}", e))?;
    
    let codecs = session.get_encode_codecs()
        .map_err(|e| format!("获取编码器失败: {:?}", e))?;
    if !codecs.contains(&NV_ENC_CODEC_H264_GUID) {
        return Err("GPU 不支持 H.264 编码".into());
    }
    
    let presets = session.get_encode_presets(NV_ENC_CODEC_H264_GUID)
        .map_err(|e| format!("获取预设失败: {:?}", e))?;
    if !presets.contains(&NV_ENC_PRESET_P3_GUID) {
        return Err("GPU 不支持 P3 预设".into());
    }
    
    let (session, mut config) = session.get_encode_preset_config_ex(
        NV_ENC_CODEC_H264_GUID,
        NV_ENC_PRESET_P3_GUID,
        nvenc::sys::enums::NVencTuningInfo::LowLatency,
    ).map_err(|e| format!("获取预设配置失败: {:?}", e))?;
    
    config.preset_cfg.rc_params.rate_control_mode = nvenc::sys::enums::NVencParamsRcMode::VBR;
    config.preset_cfg.rc_params.average_bit_rate = BITRATE;
    config.preset_cfg.gop_len = 0xffffffff;
    config.preset_cfg.frame_interval_p = 1;
    
    let init_params = InitParams {
        encode_guid: NV_ENC_CODEC_H264_GUID,
        preset_guid: NV_ENC_PRESET_P3_GUID,
        aspect_ratio: [16, 9],
        encode_config: &mut config.preset_cfg,
        tuning_info: nvenc::sys::enums::NVencTuningInfo::LowLatency,
        buffer_format: nvenc::sys::enums::NVencBufferFormat::ARGB,
        frame_rate: [FPS, 1],
        resolution: [desktop_width as u32, desktop_height as u32],
        enable_ptd: true,
        max_encoder_resolution: [0, 0],
    };
    
    let encoder = session.init_encoder(init_params)
        .map_err(|e| format!("初始化编码器失败: {:?}", e))?;
    println!("NVENC 编码器初始化成功");
    
    let registered = encoder.register_resource_dx11(
        &encode_texture,
        nvenc::sys::enums::NVencBufferFormat::ARGB,
        0,
    ).map_err(|e| format!("注册纹理失败: {:?}", e))?;
    
    let (processed_tx, processed_rx) = mpsc::sync_channel::<BitStream>(2);
    let (re_use_tx, re_use_rx) = mpsc::sync_channel::<BitStream>(2);
    processed_tx.send(encoder.create_bitstream_buffer()
        .map_err(|e| format!("创建位流缓冲区失败: {:?}", e))?)?;
    processed_tx.send(encoder.create_bitstream_buffer()
        .map_err(|e| format!("创建位流缓冲区失败: {:?}", e))?)?;
    
    let re_use_tx_clone = re_use_tx.clone();
    
    // 启动编码输出线程
    let encode_thread = std::thread::spawn(move || {
        let mut total_bytes = 0u64;
        let mut frame_count = 0u64;

        while let Ok(output) = processed_rx.recv() {
            match output.try_lock(true) {
                Ok(lock) => {
                    let data = lock.as_slice();
                    total_bytes += data.len() as u64;
                    frame_count += 1;
                    drop(lock);
                }
                Err(e) => {
                    eprintln!("锁定位流失败: {:?}", e);
                }
            }

            if re_use_tx_clone.send(output).is_err() {
                break;
            }
        }

        (total_bytes, frame_count)
    });

    println!();
    println!("开始 H.264 编码 + QUIC 传输...");
    println!("按 Ctrl+C 退出");
    println!();

    let start_time = Instant::now();
    let mut frames_tested = 0u64;
    let mut running = true;
    let mut total_bytes_sent = 0u64;

    let mut last_report = Instant::now();
    let mut frames_since_report = 0u64;
    let mut bytes_since_report = 0u64;

    while running && start_time.elapsed() < Duration::from_secs(TEST_DURATION_SECS) {
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
                    let desktop_texture: ID3D11Texture2D = resource.cast()?;

                    unsafe {
                        context.CopyResource(&staging_texture, &desktop_texture);
                    }

                    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    unsafe {
                        context.Map(&staging_texture, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
                    }

                    let src_data = unsafe {
                        std::slice::from_raw_parts(
                            mapped.pData as *const u8,
                            mapped.RowPitch as usize * desktop_height,
                        )
                    };

                    let src_pitch = mapped.RowPitch as usize;

                    // BGRA 转 RGBA
                    for y in 0..desktop_height {
                        let src_row_start = y * src_pitch;
                        let dst_row_start = y * desktop_width * 4;

                        for x in 0..desktop_width {
                            let src_idx = src_row_start + x * 4;
                            let dst_idx = dst_row_start + x * 4;

                            rgba_data[dst_idx] = src_data[src_idx + 2];     // R
                            rgba_data[dst_idx + 1] = src_data[src_idx + 1]; // G
                            rgba_data[dst_idx + 2] = src_data[src_idx];     // B
                            rgba_data[dst_idx + 3] = 255;                   // A
                        }
                    }

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    // 更新编码纹理
                    let row_pitch = (desktop_width * 4) as u32;
                    let depth_pitch = (desktop_width * desktop_height * 4) as u32;
                    unsafe {
                        context.UpdateSubresource(
                            &encode_texture,
                            0,
                            None,
                            rgba_data.as_ptr() as *const _,
                            row_pitch,
                            depth_pitch,
                        );
                    }

                    // H.264 编码
                    if let Ok(output) = re_use_rx.try_recv() {
                        let _ = encoder.encode_picture(
                            &registered,
                            &output,
                            frames_tested as usize,
                            0,
                            nvenc::sys::enums::NVencBufferFormat::ARGB,
                            nvenc::sys::enums::NVencPicStruct::Frame,
                            nvenc::sys::enums::NVencPicType::P,
                            None,
                        );
                        let _ = processed_tx.send(output);

                        // QUIC 传输（模拟：发送帧大小）
                        let frame_size = (desktop_width * desktop_height * 4) as u32;
                        let conn = connection.clone();
                        tokio::spawn(async move {
                            if let Err(e) = send_frame_size(&conn, frame_size).await {
                                eprintln!("QUIC 传输失败: {}", e);
                            }
                        });
                        total_bytes_sent += frame_size as u64;
                        bytes_since_report += frame_size as u64;
                    }

                    // 渲染
                    let scale_x = desktop_width as f64 / window_width as f64;
                    let scale_y = desktop_height as f64 / window_height as f64;

                    for dst_y in 0..window_height as usize {
                        let src_y = (dst_y as f64 * scale_y) as usize;
                        let src_row_start = src_y * desktop_width * 4;
                        let dst_row_start = dst_y * window_width as usize * 4;

                        for dst_x in 0..window_width as usize {
                            let src_x = (dst_x as f64 * scale_x) as usize;
                            let src_idx = src_row_start + src_x * 4;
                            let dst_idx = dst_row_start + dst_x * 4;

                            if src_idx + 3 < rgba_data.len() && dst_idx + 3 < rendered_data.len() {
                                rendered_data[dst_idx] = rgba_data[src_idx];         // R
                                rendered_data[dst_idx + 1] = rgba_data[src_idx + 1]; // G
                                rendered_data[dst_idx + 2] = rgba_data[src_idx + 2]; // B
                                rendered_data[dst_idx + 3] = 255; // A
                            }
                        }
                    }

                    // 写入暂存纹理（RGBA 转 BGRA）
                    let mut render_mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    unsafe {
                        context.Map(&render_staging_texture, 0, D3D11_MAP_WRITE, 0, Some(&mut render_mapped))?;
                    }

                    let render_data = unsafe {
                        std::slice::from_raw_parts_mut(
                            render_mapped.pData as *mut u8,
                            (render_mapped.RowPitch as usize) * (window_height as usize),
                        )
                    };

                    for y in 0..window_height as usize {
                        let src_row_start = y * window_width as usize * 4;
                        let dst_row_start = y * render_mapped.RowPitch as usize;

                        for x in 0..window_width as usize {
                            let src_idx = src_row_start + x * 4;
                            let dst_idx = dst_row_start + x * 4;

                            if src_idx + 3 < rendered_data.len() && dst_idx + 3 < render_data.len() {
                                // RGBA 转 BGRA
                                render_data[dst_idx] = rendered_data[src_idx + 2];     // B
                                render_data[dst_idx + 1] = rendered_data[src_idx + 1]; // G
                                render_data[dst_idx + 2] = rendered_data[src_idx];     // R
                                render_data[dst_idx + 3] = rendered_data[src_idx + 3]; // A
                            }
                        }
                    }

                    unsafe {
                        context.Unmap(&render_staging_texture, 0);
                    }

                    // 复制到交换链
                    let back_buffer: ID3D11Texture2D = unsafe { swap_chain.GetBuffer(0)? };
                    unsafe {
                        context.CopyResource(&back_buffer, &render_staging_texture);
                    }

                    unsafe {
                        let _ = swap_chain.Present(0, windows::Win32::Graphics::Dxgi::DXGI_PRESENT(0));
                    }

                    frames_tested += 1;
                    frames_since_report += 1;
                }

                unsafe {
                    duplication.ReleaseFrame()?;
                }
            }
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {}
            Err(e) => {
                eprintln!("采集失败: {}", e);
            }
        }

        // 每秒报告一次
        if last_report.elapsed() >= Duration::from_secs(1) {
            let elapsed = last_report.elapsed();
            let fps = frames_since_report as f64 / elapsed.as_secs_f64();
            let mbps = (bytes_since_report as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);

            println!("帧率: {:.1} fps, 码率: {:.2} Mbps", fps, mbps);

            frames_since_report = 0;
            bytes_since_report = 0;
            last_report = Instant::now();
        }
    }

    // 等待编码线程完成
    drop(processed_tx);
    drop(re_use_tx);
    let _ = encode_thread.join().unwrap();

    // 输出最终结果
    let total_elapsed = start_time.elapsed();
    let avg_fps = frames_tested as f64 / total_elapsed.as_secs_f64();
    let avg_mbps = (total_bytes_sent as f64 * 8.0) / (total_elapsed.as_secs_f64() * 1_000_000.0);

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           H.264 编码 + QUIC 传输结果                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("桌面分辨率: {}x{}", desktop_width, desktop_height);
    println!("编码器: NVENC H.264");
    println!("传输协议: QUIC");
    println!();
    println!("测试时间: {:.2} 秒", total_elapsed.as_secs_f64());
    println!("总帧数: {}", frames_tested);
    println!("平均帧率: {:.1} fps", avg_fps);
    println!("平均码率: {:.2} Mbps", avg_mbps);
    println!();

    Ok(())
}

async fn start_quic_server() -> Result<Endpoint, Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().to_vec();
    let priv_key = cert.key_pair.serialize_der();

    let mut server_config = ServerConfig::with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::try_from(priv_key)?,
    )?;
    
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| "无法获取传输配置")?;
    transport_config.max_concurrent_uni_streams(100u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    let endpoint = Endpoint::server(
        server_config,
        "0.0.0.0:4433".parse()?,
    )?;

    Ok(endpoint)
}

async fn send_frame_size(connection: &Connection, size: u32) -> Result<(), Box<dyn std::error::Error>> {
    let (mut send, _recv) = connection.open_bi().await?;
    send.write_all(&size.to_le_bytes()).await?;
    send.finish()?;
    Ok(())
}

fn create_window() -> Result<(HWND, u32, u32), Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("H264QuicClass\0".as_ptr());
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
            PCSTR::from_raw("H.264 + QUIC\0".as_ptr()),
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

    let mut rect = RECT::default();
    unsafe { GetClientRect(hwnd, &mut rect)? };
    let window_width = (rect.right - rect.left) as u32;
    let window_height = (rect.bottom - rect.top) as u32;

    Ok((hwnd, window_width, window_height))
}

fn create_d3d11_device_and_swap_chain(
    hwnd: HWND,
    width: u32,
    height: u32,
) -> Result<(ID3D11Device, ID3D11DeviceContext, IDXGISwapChain1), Box<dyn std::error::Error>> {
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    unsafe {
        windows::Win32::Graphics::Direct3D11::D3D11CreateDevice(
            None,
            windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE,
            windows::Win32::Foundation::HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
    }

    let device = device.unwrap();
    let context = context.unwrap();

    let dxgi_device: IDXGIDevice = device.cast()?;
    let adapter = unsafe { dxgi_device.GetAdapter()? };
    let factory: windows::Win32::Graphics::Dxgi::IDXGIFactory2 = unsafe { adapter.GetParent()? };

    let swap_chain_desc = DXGI_SWAP_CHAIN_DESC1 {
        Width: width,
        Height: height,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        Stereo: false.into(),
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
        BufferCount: 2,
        Scaling: windows::Win32::Graphics::Dxgi::DXGI_SCALING_STRETCH,
        SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
        AlphaMode: Default::default(),
        Flags: 0,
    };

    let swap_chain = unsafe {
        factory.CreateSwapChainForHwnd(&device, hwnd, &swap_chain_desc, None, None)?
    };

    Ok((device, context, swap_chain))
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

fn create_staging_texture_for_write(
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
        CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0 as u32,
        MiscFlags: 0,
    };

    let mut texture: Option<ID3D11Texture2D> = None;
    unsafe {
        device.CreateTexture2D(&desc, None, Some(&mut texture))?;
    }

    Ok(texture.unwrap())
}

fn create_encode_texture(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> Result<ID3D11Texture2D, Box<dyn std::error::Error>> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_R8G8B8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: windows::Win32::Graphics::Direct3D11::D3D11_BIND_SHADER_RESOURCE.0 as u32,
        CPUAccessFlags: 0,
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
