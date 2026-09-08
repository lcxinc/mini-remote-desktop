//! 高帧率 + 带宽测量
//!
//! 采集 -> 编码 -> 解码 -> 渲染
//! 使用完整桌面分辨率（2560x1440）
//! 测量帧率和码率（带宽）

use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HWND, LRESULT, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_BIND_SHADER_RESOURCE,
    D3D11_CPU_ACCESS_READ, D3D11_CPU_ACCESS_WRITE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
    D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGISwapChain1,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_SWAP_CHAIN_DESC1,
    DXGI_SWAP_EFFECT_FLIP_DISCARD, DXGI_USAGE_RENDER_TARGET_OUTPUT,
};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DispatchMessageA, GetClientRect, PeekMessageA,
    PostQuitMessage, RegisterClassA, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, MSG,
    PM_REMOVE, WM_DESTROY, WM_QUIT, WNDCLASSA, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

const TEST_DURATION_SECS: u64 = 10;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("高帧率 + 带宽测量");
    println!("=================");
    println!();
    println!("链路：采集 -> 编码 -> 解码 -> 渲染（无 VSync）");
    println!("测试时间：{} 秒", TEST_DURATION_SECS);
    println!();

    // 创建窗口
    let (hwnd, window_width, window_height) = create_window()?;
    println!("窗口创建成功: {}x{}", window_width, window_height);

    // 创建 D3D11 设备和交换链
    let (device, context, swap_chain) =
        create_d3d11_device_and_swap_chain(hwnd, window_width, window_height)?;
    println!("D3D11 设备和交换链创建成功");

    // 创建 DXGI Desktop Duplication
    let (duplication, width, height) = create_dxgi_duplication(&device)?;
    let desktop_width = width as usize;
    let desktop_height = height as usize;
    println!("桌面分辨率: {}x{}", desktop_width, desktop_height);
    println!(
        "像素数量: {} MP",
        (desktop_width * desktop_height) as f64 / 1_000_000.0
    );

    // 创建暂存纹理
    let staging_texture = create_staging_texture(&device, width, height)?;

    // 创建渲染纹理
    let render_texture =
        create_render_texture(&device, desktop_width as u32, desktop_height as u32)?;

    // 预分配缓冲区
    let mut rgb_data = vec![0u8; desktop_width * desktop_height * 3];
    let mut encoded_data = vec![0u8; desktop_width * desktop_height * 3 / 2];
    let mut decoded_data = vec![0u8; desktop_width * desktop_height * 3];
    let mut rendered_data = vec![0u8; desktop_width * desktop_height * 4]; // RGBA

    println!();
    println!("开始高帧率测试...");
    println!("按 Ctrl+C 退出");
    println!();

    let start_time = Instant::now();
    let mut frames_tested = 0u64;
    let mut total_bytes_encoded = 0u64;
    let mut total_bytes_transferred = 0u64;
    let mut running = true;

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
        let acquire_result =
            unsafe { duplication.AcquireNextFrame(0, &mut frame_info, &mut frame_resource) };

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
                        context.Map(&staging_texture, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
                    }

                    // 获取源数据
                    let src_data = unsafe {
                        std::slice::from_raw_parts(
                            mapped.pData as *const u8,
                            mapped.RowPitch as usize * desktop_height,
                        )
                    };

                    let src_pitch = mapped.RowPitch as usize;

                    // BGRA 转 RGB
                    for y in 0..desktop_height {
                        let src_row_start = y * src_pitch;
                        let dst_row_start = y * desktop_width * 3;

                        for x in 0..desktop_width {
                            let src_idx = src_row_start + x * 4;
                            let dst_idx = dst_row_start + x * 3;

                            rgb_data[dst_idx] = src_data[src_idx + 2]; // R
                            rgb_data[dst_idx + 1] = src_data[src_idx + 1]; // G
                            rgb_data[dst_idx + 2] = src_data[src_idx]; // B
                        }
                    }

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    // 编码（模拟：压缩数据）
                    let mut encode_idx = 0;
                    for i in (0..rgb_data.len()).step_by(6) {
                        if i + 5 < rgb_data.len() && encode_idx + 2 < encoded_data.len() {
                            encoded_data[encode_idx] =
                                ((rgb_data[i] as u16 + rgb_data[i + 3] as u16) / 2) as u8;
                            encoded_data[encode_idx + 1] =
                                ((rgb_data[i + 1] as u16 + rgb_data[i + 4] as u16) / 2) as u8;
                            encoded_data[encode_idx + 2] =
                                ((rgb_data[i + 2] as u16 + rgb_data[i + 5] as u16) / 2) as u8;
                            encode_idx += 3;
                        }
                    }
                    total_bytes_encoded += encode_idx as u64;

                    // 传输（模拟：内存拷贝）
                    let transfer_data = encoded_data[..encode_idx].to_vec();
                    total_bytes_transferred += transfer_data.len() as u64;
                    bytes_since_report += transfer_data.len() as u64;

                    // 解码（模拟：解压缩）
                    let mut decode_idx = 0;
                    for i in (0..transfer_data.len()).step_by(3) {
                        if i + 2 < transfer_data.len() && decode_idx + 5 < decoded_data.len() {
                            decoded_data[decode_idx] = transfer_data[i];
                            decoded_data[decode_idx + 1] = transfer_data[i + 1];
                            decoded_data[decode_idx + 2] = transfer_data[i + 2];
                            decoded_data[decode_idx + 3] = transfer_data[i];
                            decoded_data[decode_idx + 4] = transfer_data[i + 1];
                            decoded_data[decode_idx + 5] = transfer_data[i + 2];
                            decode_idx += 6;
                        }
                    }

                    // 渲染
                    // 转换 RGB 到 RGBA
                    let mut rgba_idx = 0;
                    for i in (0..decode_idx).step_by(3) {
                        if i + 2 < decode_idx && rgba_idx + 3 < rendered_data.len() {
                            rendered_data[rgba_idx] = decoded_data[i]; // R
                            rendered_data[rgba_idx + 1] = decoded_data[i + 1]; // G
                            rendered_data[rgba_idx + 2] = decoded_data[i + 2]; // B
                            rendered_data[rgba_idx + 3] = 255; // A
                            rgba_idx += 4;
                        }
                    }

                    // 将 RGBA 数据写入渲染纹理
                    let row_pitch = (desktop_width * 4) as u32;
                    let depth_pitch = (desktop_width * desktop_height * 4) as u32;
                    unsafe {
                        context.UpdateSubresource(
                            &render_texture,
                            0,
                            None,
                            rendered_data.as_ptr() as *const _,
                            row_pitch,
                            depth_pitch,
                        );
                    }

                    // 复制到交换链后备缓冲区
                    let back_buffer: ID3D11Texture2D = unsafe { swap_chain.GetBuffer(0)? };

                    let src_box = windows::Win32::Graphics::Direct3D11::D3D11_BOX {
                        left: 0,
                        top: 0,
                        front: 0,
                        right: desktop_width as u32,
                        bottom: desktop_height as u32,
                        back: 1,
                    };

                    unsafe {
                        context.CopySubresourceRegion(
                            &back_buffer,
                            0,
                            0,
                            0,
                            0,
                            &render_texture,
                            0,
                            Some(&src_box),
                        );
                    }

                    // 呈现（无 VSync）
                    unsafe {
                        let _ =
                            swap_chain.Present(0, windows::Win32::Graphics::Dxgi::DXGI_PRESENT(0));
                        // 无 VSync
                    }

                    frames_tested += 1;
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
            let elapsed = last_report.elapsed();
            let fps = frames_since_report as f64 / elapsed.as_secs_f64();
            let mbps = (bytes_since_report as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);

            println!("帧率: {:.1} fps, 码率: {:.2} Mbps", fps, mbps);

            frames_since_report = 0;
            bytes_since_report = 0;
            last_report = Instant::now();
        }
    }

    // 输出最终结果
    let total_elapsed = start_time.elapsed();
    let avg_fps = frames_tested as f64 / total_elapsed.as_secs_f64();
    let avg_bps_encoded = (total_bytes_encoded as f64 * 8.0) / total_elapsed.as_secs_f64();
    let avg_bps_transferred = (total_bytes_transferred as f64 * 8.0) / total_elapsed.as_secs_f64();
    let avg_bytes_per_frame = if frames_tested > 0 {
        total_bytes_encoded as f64 / frames_tested as f64
    } else {
        0.0
    };

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                高帧率 + 带宽测量结果                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("桌面分辨率: {}x{}", desktop_width, desktop_height);
    println!(
        "像素数量: {} MP",
        (desktop_width * desktop_height) as f64 / 1_000_000.0
    );
    println!();
    println!("测试时间: {:.2} 秒", total_elapsed.as_secs_f64());
    println!("总帧数: {}", frames_tested);
    println!();
    println!("=== 性能指标 ===");
    println!("| 指标 | 值 |");
    println!("|------|-----|");
    println!("| 平均帧率 | {:.1} fps |", avg_fps);
    println!(
        "| 平均码率（编码后） | {:.2} Mbps |",
        avg_bps_encoded / 1_000_000.0
    );
    println!(
        "| 平均码率（传输） | {:.2} Mbps |",
        avg_bps_transferred / 1_000_000.0
    );
    println!("| 平均每帧大小 | {:.2} KB |", avg_bytes_per_frame / 1024.0);
    println!(
        "| 压缩比 | {:.1}x |",
        (desktop_width * desktop_height * 3) as f64 / avg_bytes_per_frame
    );
    println!();

    // 输出原始数据带宽
    let raw_bps = (desktop_width * desktop_height * 3) as f64 * 8.0 * avg_fps;
    println!("=== 带宽对比 ===");
    println!("| 类型 | 带宽 |");
    println!("|------|------|");
    println!("| 原始数据 (RGB) | {:.2} Mbps |", raw_bps / 1_000_000.0);
    println!("| 编码后数据 | {:.2} Mbps |", avg_bps_encoded / 1_000_000.0);
    println!(
        "| 传输数据 | {:.2} Mbps |",
        avg_bps_transferred / 1_000_000.0
    );
    println!("| 压缩率 | {:.1}% |", (avg_bps_encoded / raw_bps) * 100.0);
    println!();

    Ok(())
}

fn create_window() -> Result<(HWND, u32, u32), Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("HighFPSBandwidthClass\0".as_ptr());
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
            PCSTR::from_raw("High FPS + Bandwidth Test\0".as_ptr()),
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

    // 获取窗口客户区大小
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
    // 创建 D3D11 设备
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    unsafe {
        windows::Win32::Graphics::Direct3D11::D3D11CreateDevice(
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

    let device = device.unwrap();
    let context = context.unwrap();

    // 获取 DXGI 工厂
    let dxgi_device: IDXGIDevice = device.cast()?;
    let adapter = unsafe { dxgi_device.GetAdapter()? };
    let factory: windows::Win32::Graphics::Dxgi::IDXGIFactory2 = unsafe { adapter.GetParent()? };

    // 创建交换链
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

    let swap_chain =
        unsafe { factory.CreateSwapChainForHwnd(&device, hwnd, &swap_chain_desc, None, None)? };

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

fn create_render_texture(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> Result<ID3D11Texture2D, Box<dyn std::error::Error>> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32 | D3D11_CPU_ACCESS_WRITE.0 as u32,
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
