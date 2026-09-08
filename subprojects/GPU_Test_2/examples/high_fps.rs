//! 高性能桌面采集示例 - 目标 200+ FPS
//!
//! 优化策略：
//! 1. 移除帧率限制
//! 2. 使用 GPU 缩放（如果有）
//! 3. 减少数据拷贝
//! 4. 使用更高效的像素处理

use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HWND, LRESULT, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DispatchMessageA, GetClientRect, PeekMessageA,
    PostQuitMessage, RegisterClassA, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, MSG,
    PM_REMOVE, WM_DESTROY, WM_QUIT, WNDCLASSA, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("高性能桌面采集示例 - 目标 200+ FPS");
    println!("==================================");
    println!();

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

    // 预计算缩放映射（优化：使用 usize 而不是 Vec）
    let window_width = 1264usize;
    let window_height = 681usize;

    let x_map: Vec<usize> = (0..window_width)
        .map(|x| (x * width as usize) / window_width)
        .collect();
    let y_map: Vec<usize> = (0..window_height)
        .map(|y| (y * height as usize) / window_height)
        .collect();

    // 预分配 RGB 缓冲区（避免每次分配）
    let mut rgb_data = vec![0u8; window_width * window_height * 3];

    println!("开始采集，按 Ctrl+C 退出...");
    println!();

    let mut last_report = Instant::now();
    let mut frames_since_report = 0u64;
    let mut running = true;

    // 主循环（移除帧率限制）
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
                            mapped.RowPitch as usize * height as usize,
                        )
                    };

                    // 优化：使用更高效的像素处理
                    // 直接使用预分配的缓冲区
                    let src_width = width as usize;
                    let src_pitch = mapped.RowPitch as usize;

                    for (dst_y, src_y) in y_map.iter().enumerate() {
                        let src_row_start = src_y * src_pitch;
                        let dst_row_start = dst_y * window_width * 3;

                        for (dst_x, src_x) in x_map.iter().enumerate() {
                            let src_idx = src_row_start + src_x * 4;
                            let dst_idx = dst_row_start + dst_x * 3;

                            // BGRA 转 RGB（直接访问）
                            rgb_data[dst_idx] = src_data[src_idx + 2]; // R
                            rgb_data[dst_idx + 1] = src_data[src_idx + 1]; // G
                            rgb_data[dst_idx + 2] = src_data[src_idx]; // B
                        }
                    }

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    // 在这里可以处理 rgb_data（例如渲染或传输）
                    // 示例：打印帧信息
                    // println!("采集到 {}x{} 帧", window_width, window_height);

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
            let fps = frames_since_report as f64 / last_report.elapsed().as_secs_f64();
            println!("采集帧率: {:.1} fps", fps);
            frames_since_report = 0;
            last_report = Instant::now();
        }
    }

    println!("程序退出");
    Ok(())
}

fn create_window() -> Result<HWND, Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("HighFPSCaptureClass\0".as_ptr());
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
            PCSTR::from_raw("High FPS Capture\0".as_ptr()),
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

fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext), Box<dyn std::error::Error>>
{
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
