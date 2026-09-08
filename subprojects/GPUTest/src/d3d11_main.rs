#![windows_subsystem = "windows"]

//! D3D11 版本 - 使用 CPU 生成帧数据并通过 GPU 渲染

use std::time::{Duration, Instant};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::UI::WindowsAndMessaging::*;

const WINDOW_WIDTH: u32 = 1280;
const WINDOW_HEIGHT: u32 = 720;

/// 生成动态帧数据 - CPU 端渲染
fn generate_frame_data(width: u32, height: u32, time_sec: f32) -> Vec<u8> {
    let mut data = Vec::with_capacity((width * height * 4) as usize);

    let t = time_sec;
    let offset_x = ((t * 100.0).sin() * 200.0) as i32;
    let offset_y = ((t * 80.0).cos() * 150.0) as i32;

    for y in 0..height {
        for x in 0..width {
            // 渐变背景
            let bg_r = (x as f32 / width as f32 * 100.0) as u8;
            let bg_g = (y as f32 / height as f32 * 150.0) as u8;
            let bg_b = (100.0 + (t * 50.0).sin() * 50.0) as u8;

            let mut r = bg_r;
            let mut g = bg_g;
            let mut b = bg_b;

            // 移动的方块
            let square_x = (width as i32 / 2 - 100 + offset_x) as u32;
            let square_y = (height as i32 / 2 - 75 + offset_y) as u32;

            if x >= square_x && x < square_x + 200 && y >= square_y && y < square_y + 150 {
                // 方块内：彩虹色
                let local_x = x - square_x;
                let local_y = y - square_y;
                r = ((local_x as f32 / 200.0) * 255.0) as u8;
                g = ((local_y as f32 / 150.0) * 255.0) as u8;
                b = ((t * 100.0).sin() * 127.0 + 128.0) as u8;
            }

            // 添加一些动态圆圈
            let cx = width as i32 / 2 + ((t * 60.0).cos() * 300.0) as i32;
            let cy = height as i32 / 2 + ((t * 50.0).sin() * 200.0) as i32;
            let dx = x as i32 - cx;
            let dy = y as i32 - cy;
            let dist = (dx * dx + dy * dy) as f32;
            if dist < 10000.0 {
                let blend = (1.0 - dist / 10000.0) * 0.5;
                r = (r as f32 * (1.0 - blend) + 255.0 * blend) as u8;
                g = (g as f32 * (1.0 - blend) + 100.0 * blend) as u8;
                b = (b as f32 * (1.0 - blend) + 200.0 * blend) as u8;
            }

            data.push(r);
            data.push(g);
            data.push(b);
            data.push(255);
        }
    }
    data
}

/// D3D11 渲染上下文
struct D3D11Context {
    device: ID3D11Device,
    device_context: ID3D11DeviceContext,
    swap_chain: IDXGISwapChain,
    texture: ID3D11Texture2D,
}

impl D3D11Context {
    fn new(hwnd: HWND) -> Result<Self> {
        unsafe {
            eprintln!("Creating D3D11 device...");

            // 创建 D3D11 设备
            let mut device: Option<ID3D11Device> = None;
            let mut feature_level = D3D_FEATURE_LEVEL_11_0;
            let mut device_context: Option<ID3D11DeviceContext> = None;

            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_FLAG(0),
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                Some(&mut feature_level),
                Some(&mut device_context),
            )?;

            let device = device.ok_or(Error::from(E_FAIL))?;
            eprintln!("Device created");

            let device_context = device_context.ok_or(Error::from(E_FAIL))?;
            eprintln!("Device context created");

            // 创建交换链
            let dxgi_device: IDXGIDevice = device.cast()?;
            let dxgi_adapter = dxgi_device.GetAdapter()?;
            let dxgi_factory: IDXGIFactory = dxgi_adapter.GetParent()?;

            let swap_chain_desc = DXGI_SWAP_CHAIN_DESC {
                BufferDesc: DXGI_MODE_DESC {
                    Width: WINDOW_WIDTH,
                    Height: WINDOW_HEIGHT,
                    RefreshRate: DXGI_RATIONAL {
                        Numerator: 60,
                        Denominator: 1,
                    },
                    Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    ScanlineOrdering: DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED,
                    Scaling: DXGI_MODE_SCALING_UNSPECIFIED,
                },
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: 1,
                OutputWindow: hwnd,
                Windowed: TRUE,
                SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
                ..Default::default()
            };

            let mut swap_chain: Option<IDXGISwapChain> = None;
            let hr = dxgi_factory.CreateSwapChain(&device, &swap_chain_desc, &mut swap_chain);
            if hr.is_err() {
                return Err(Error::from(hr));
            }
            let swap_chain = swap_chain.ok_or(Error::from(E_FAIL))?;
            let _ = dxgi_factory.MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);

            // 创建动态纹理用于 CPU 数据上传
            let texture_desc = D3D11_TEXTURE2D_DESC {
                Width: WINDOW_WIDTH,
                Height: WINDOW_HEIGHT,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DYNAMIC,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                CPUAccessFlags: D3D11_CPU_ACCESS_WRITE.0 as u32,
                MiscFlags: 0,
            };
            let mut texture: Option<ID3D11Texture2D> = None;
            device.CreateTexture2D(&texture_desc, None, Some(&mut texture as *mut _))?;
            let texture = texture.ok_or(Error::from(E_FAIL))?;

            Ok(Self {
                device,
                device_context,
                swap_chain,
                texture,
            })
        }
    }

    /// 渲染一帧 - 使用 CPU 生成的数据绘制到渲染目标
    fn render(&mut self, frame_data: &[u8]) -> Result<()> {
        unsafe {
            // 1. 将 CPU 数据上传到纹理
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.device_context.Map(
                &self.texture,
                0,
                D3D11_MAP_WRITE_DISCARD,
                0,
                Some(&mut mapped),
            )?;

            let row_pitch = (WINDOW_WIDTH * 4) as usize;
            for y in 0..WINDOW_HEIGHT as usize {
                let src_offset = y * row_pitch;
                let dst_offset = y * mapped.RowPitch as usize;
                let src_slice = &frame_data[src_offset..src_offset + row_pitch];
                let dst_slice = std::slice::from_raw_parts_mut(
                    (mapped.pData as *mut u8).add(dst_offset),
                    row_pitch,
                );
                // 转换 RGBA 到 BGRA
                for x in 0..WINDOW_WIDTH as usize {
                    let src_idx = x * 4;
                    dst_slice[src_idx] = src_slice[src_idx + 2]; // B = R
                    dst_slice[src_idx + 1] = src_slice[src_idx + 1]; // G = G
                    dst_slice[src_idx + 2] = src_slice[src_idx]; // R = B
                    dst_slice[src_idx + 3] = src_slice[src_idx + 3]; // A = A
                }
            }
            self.device_context.Unmap(&self.texture, 0);

            // 2. 获取渲染目标并复制纹理内容
            let back_buffer: ID3D11Texture2D = self.swap_chain.GetBuffer(0)?;

            // 使用 CopyResource 直接复制
            self.device_context
                .CopyResource(&back_buffer, &self.texture);

            // 3. 呈现
            let _ = self.swap_chain.Present(1, DXGI_PRESENT(0));

            Ok(())
        }
    }
}

/// 获取窗口模块实例
fn create_window_instance() -> Result<HINSTANCE> {
    unsafe { Ok(GetModuleHandleW(PCWSTR::null())?.into()) }
}

/// 注册窗口类
fn register_window_class(hinstance: HINSTANCE) -> Result<()> {
    unsafe {
        let class_name = w!("D3D11WindowClass");

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: hinstance,
            hCursor: LoadCursorW(None, IDC_ARROW)
                .ok()
                .expect("Failed to load cursor"),
            lpszClassName: class_name,
            ..Default::default()
        };

        if RegisterClassExW(&wc) == 0 {
            let error = GetLastError();
            if error != ERROR_CLASS_ALREADY_EXISTS {
                return Err(Error::from_win32());
            }
        }

        Ok(())
    }
}

/// 窗口过程函数
extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                BeginPaint(hwnd, &mut ps);
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// 创建窗口
fn create_window(hinstance: HINSTANCE) -> Result<HWND> {
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("D3D11WindowClass"),
            w!("D3D11 Stream Test"),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH as i32,
            WINDOW_HEIGHT as i32,
            None,
            None,
            Some(hinstance),
            None,
        )
    }
}

/// 主函数
fn main() -> Result<()> {
    unsafe {
        // 创建窗口
        let hinstance = create_window_instance()?;
        register_window_class(hinstance)?;
        let hwnd = create_window(hinstance)?;

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);

        // 初始化 D3D11
        let mut d3d11 = D3D11Context::new(hwnd)?;

        // 主循环
        let mut msg = MSG::default();
        let start_time = Instant::now();

        loop {
            if PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).into() {
                if msg.message == WM_QUIT {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            } else {
                // 1. CPU 生成动态帧数据
                let elapsed = start_time.elapsed().as_secs_f32();
                let frame_data = generate_frame_data(WINDOW_WIDTH, WINDOW_HEIGHT, elapsed);

                // 2. 上传到 GPU 并渲染
                if let Err(e) = d3d11.render(&frame_data) {
                    eprintln!("Render error: {:?}", e);
                    break;
                }

                // 限制到约 60 FPS
                std::thread::sleep(Duration::from_millis(16));
            }
        }

        Ok(())
    }
}
