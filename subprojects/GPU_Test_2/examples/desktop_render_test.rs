//! 桌面渲染测试
//!
//! 采集桌面画面并直接渲染到窗口（不缩放）

use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HWND, LRESULT, RECT};
use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL_11_0;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CPU_ACCESS_WRITE, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ, D3D11_MAP_WRITE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("桌面渲染测试");
    println!("============");
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

    // 创建暂存纹理（用于读取桌面数据）
    let staging_texture = create_staging_texture(&device, width, height)?;

    // 创建渲染暂存纹理（用于写入数据）
    let render_staging_texture =
        create_staging_texture_for_write(&device, window_width, window_height)?;

    // 预分配缓冲区
    let mut rgba_data = vec![0u8; desktop_width * desktop_height * 4];
    let mut rendered_data = vec![0u8; window_width as usize * window_height as usize * 4];

    println!();
    println!("开始桌面渲染测试...");
    println!("按 Ctrl+C 退出");
    println!();

    let mut running = true;
    let mut frame_count = 0u64;
    let mut last_report = Instant::now();

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
                            mapped.RowPitch as usize * desktop_height,
                        )
                    };

                    let src_pitch = mapped.RowPitch as usize;

                    // BGRA 转 RGBA（完整桌面分辨率）
                    for y in 0..desktop_height {
                        let src_row_start = y * src_pitch;
                        let dst_row_start = y * desktop_width * 4;

                        for x in 0..desktop_width {
                            let src_idx = src_row_start + x * 4;
                            let dst_idx = dst_row_start + x * 4;

                            rgba_data[dst_idx] = src_data[src_idx + 2]; // R
                            rgba_data[dst_idx + 1] = src_data[src_idx + 1]; // G
                            rgba_data[dst_idx + 2] = src_data[src_idx]; // B
                            rgba_data[dst_idx + 3] = 255; // A
                        }
                    }

                    unsafe {
                        context.Unmap(&staging_texture, 0);
                    }

                    // 缩放到窗口大小
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
                                rendered_data[dst_idx] = rgba_data[src_idx]; // R
                                rendered_data[dst_idx + 1] = rgba_data[src_idx + 1]; // G
                                rendered_data[dst_idx + 2] = rgba_data[src_idx + 2]; // B
                                rendered_data[dst_idx + 3] = 255; // A
                            }
                        }
                    }

                    // 写入渲染暂存纹理
                    let mut render_mapped = D3D11_MAPPED_SUBRESOURCE::default();
                    unsafe {
                        context.Map(
                            &render_staging_texture,
                            0,
                            D3D11_MAP_WRITE,
                            0,
                            Some(&mut render_mapped),
                        )?;
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

                            if src_idx + 3 < rendered_data.len() && dst_idx + 3 < render_data.len()
                            {
                                render_data[dst_idx] = rendered_data[src_idx]; // R
                                render_data[dst_idx + 1] = rendered_data[src_idx + 1]; // G
                                render_data[dst_idx + 2] = rendered_data[src_idx + 2]; // B
                                render_data[dst_idx + 3] = rendered_data[src_idx + 3];
                                // A
                            }
                        }
                    }

                    unsafe {
                        context.Unmap(&render_staging_texture, 0);
                    }

                    // 复制到交换链后备缓冲区
                    let back_buffer: ID3D11Texture2D = unsafe { swap_chain.GetBuffer(0)? };

                    unsafe {
                        context.CopyResource(&back_buffer, &render_staging_texture);
                    }

                    // 呈现
                    unsafe {
                        let _ =
                            swap_chain.Present(0, windows::Win32::Graphics::Dxgi::DXGI_PRESENT(0));
                    }

                    frame_count += 1;
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
            let fps = frame_count as f64 / last_report.elapsed().as_secs_f64();
            println!("帧率: {:.1} fps", fps);
            frame_count = 0;
            last_report = Instant::now();
        }
    }

    println!("程序退出");
    Ok(())
}

fn create_window() -> Result<(HWND, u32, u32), Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("DesktopRenderTestClass\0".as_ptr());
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
            PCSTR::from_raw("Desktop Render Test\0".as_ptr()),
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
