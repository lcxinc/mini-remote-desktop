//! 简单渲染测试
//!
//! 测试 D3D11 渲染是否工作正常

use windows::core::Interface;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HWND, LRESULT, RECT};
use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL_11_0;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_BIND_RENDER_TARGET,
    D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_WRITE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    IDXGISwapChain1, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_EFFECT_FLIP_DISCARD,
    DXGI_USAGE_RENDER_TARGET_OUTPUT,
};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DispatchMessageA, GetClientRect, PeekMessageA,
    PostQuitMessage, RegisterClassA, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, MSG,
    PM_REMOVE, WM_DESTROY, WM_QUIT, WNDCLASSA, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("简单渲染测试");
    println!("============");
    println!();

    // 创建窗口
    let (hwnd, window_width, window_height) = create_window()?;
    println!("窗口创建成功: {}x{}", window_width, window_height);

    // 创建 D3D11 设备和交换链
    let (device, context, swap_chain) =
        create_d3d11_device_and_swap_chain(hwnd, window_width, window_height)?;
    println!("D3D11 设备和交换链创建成功");

    // 创建测试纹理（红色）
    let test_texture = create_test_texture(&device, window_width, window_height)?;
    println!("测试纹理创建成功");

    println!();
    println!("开始渲染测试...");
    println!("按 Ctrl+C 退出");
    println!();

    let mut running = true;
    let mut frame_count = 0u64;

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

        // 更新纹理内容（动态变化）
        update_texture(
            &device,
            &context,
            &test_texture,
            window_width,
            window_height,
            frame_count,
        )?;

        // 复制到交换链后备缓冲区
        let back_buffer: ID3D11Texture2D = unsafe { swap_chain.GetBuffer(0)? };
        unsafe {
            context.CopyResource(&back_buffer, &test_texture);
        }

        // 呈现
        unsafe {
            let _ = swap_chain.Present(0, windows::Win32::Graphics::Dxgi::DXGI_PRESENT(0));
        }

        frame_count += 1;

        // 每秒报告一次
        if frame_count % 60 == 0 {
            println!("帧率: 60 fps (估计)");
        }
    }

    println!("程序退出");
    Ok(())
}

fn update_texture(
    device: &ID3D11Device,
    context: &ID3D11DeviceContext,
    texture: &ID3D11Texture2D,
    width: u32,
    height: u32,
    frame_count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建暂存纹理
    let staging_desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: windows::Win32::Graphics::Direct3D11::D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: windows::Win32::Graphics::Direct3D11::D3D11_CPU_ACCESS_WRITE.0 as u32,
        MiscFlags: 0,
    };

    let mut staging_texture: Option<ID3D11Texture2D> = None;
    unsafe {
        device.CreateTexture2D(&staging_desc, None, Some(&mut staging_texture))?;
    }
    let staging_texture = staging_texture.unwrap();

    // 映射暂存纹理
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    unsafe {
        context.Map(&staging_texture, 0, D3D11_MAP_WRITE, 0, Some(&mut mapped))?;
    }

    // 写入动态颜色
    let data = unsafe {
        std::slice::from_raw_parts_mut(
            mapped.pData as *mut u8,
            (mapped.RowPitch as usize) * (height as usize),
        )
    };

    let t = (frame_count % 256) as u8;
    for y in 0..height as usize {
        for x in 0..width as usize {
            let idx = y * mapped.RowPitch as usize + x * 4;
            if idx + 3 < data.len() {
                // 创建渐变效果
                let r = ((x as f64 / width as f64) * 255.0) as u8;
                let g = ((y as f64 / height as f64) * 255.0) as u8;
                let b = t;
                data[idx] = r; // R
                data[idx + 1] = g; // G
                data[idx + 2] = b; // B
                data[idx + 3] = 255; // A
            }
        }
    }

    unsafe {
        context.Unmap(&staging_texture, 0);
    }

    // 复制到目标纹理
    unsafe {
        context.CopyResource(texture, &staging_texture);
    }

    Ok(())
}

fn create_window() -> Result<(HWND, u32, u32), Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("SimpleRenderTestClass\0".as_ptr());
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
            PCSTR::from_raw("Simple Render Test\0".as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            600,
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
    let dxgi_device: windows::Win32::Graphics::Dxgi::IDXGIDevice = device.cast()?;
    let adapter = unsafe { dxgi_device.GetAdapter()? };
    let factory: windows::Win32::Graphics::Dxgi::IDXGIFactory2 = unsafe { adapter.GetParent()? };

    // 创建交换链
    let swap_chain_desc = DXGI_SWAP_CHAIN_DESC1 {
        Width: width,
        Height: height,
        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
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

fn create_test_texture(
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
        BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32 | D3D11_BIND_RENDER_TARGET.0 as u32,
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
