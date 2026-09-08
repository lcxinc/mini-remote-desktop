//! 全链路延迟测试（完整桌面分辨率 + 真实渲染）
//!
//! 采集 -> 编码 -> 解码 -> 渲染（真实渲染到窗口）
//! 使用完整桌面分辨率（2560x1440）
//! 测量每个阶段的 p50, p90, p95, p99 延迟

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

/// 延迟统计
#[derive(Debug, Clone)]
struct LatencyStats {
    samples: Vec<Duration>,
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn add(&mut self, latency: Duration) {
        self.samples.push(latency);
    }

    fn calculate(&self) -> (Duration, Duration, Duration, Duration, Duration, Duration) {
        if self.samples.is_empty() {
            return (
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
            );
        }

        let mut sorted = self.samples.clone();
        sorted.sort();

        let len = sorted.len();
        let min = sorted[0];
        let max = sorted[len - 1];
        let p50 = sorted[(len as f64 * 0.50) as usize];
        let p90 = sorted[(len as f64 * 0.90) as usize];
        let p95 = sorted[(len as f64 * 0.95) as usize];
        let p99 = sorted[(len as f64 * 0.99) as usize];

        (min, max, p50, p90, p95, p99)
    }
}

/// 全链路延迟测量器
struct PipelineLatencyMeasurer {
    capture_stats: LatencyStats,
    encode_stats: LatencyStats,
    transfer_stats: LatencyStats,
    decode_stats: LatencyStats,
    render_stats: LatencyStats,
    e2e_stats: LatencyStats,
}

impl PipelineLatencyMeasurer {
    fn new() -> Self {
        Self {
            capture_stats: LatencyStats::new(),
            encode_stats: LatencyStats::new(),
            transfer_stats: LatencyStats::new(),
            decode_stats: LatencyStats::new(),
            render_stats: LatencyStats::new(),
            e2e_stats: LatencyStats::new(),
        }
    }

    fn print(&self, desktop_width: usize, desktop_height: usize) {
        let (capture_min, capture_max, capture_p50, capture_p90, capture_p95, capture_p99) =
            self.capture_stats.calculate();
        let (encode_min, encode_max, encode_p50, encode_p90, encode_p95, encode_p99) =
            self.encode_stats.calculate();
        let (transfer_min, transfer_max, transfer_p50, transfer_p90, transfer_p95, transfer_p99) =
            self.transfer_stats.calculate();
        let (decode_min, decode_max, decode_p50, decode_p90, decode_p95, decode_p99) =
            self.decode_stats.calculate();
        let (render_min, render_max, render_p50, render_p90, render_p95, render_p99) =
            self.render_stats.calculate();
        let (e2e_min, e2e_max, e2e_p50, e2e_p90, e2e_p95, e2e_p99) = self.e2e_stats.calculate();

        println!("\n");
        println!(
            "╔══════════════════════════════════════════════════════════════════════════════╗"
        );
        println!("║        全链路延迟测试报告（完整桌面分辨率 + 真实渲染）                      ║");
        println!(
            "╚══════════════════════════════════════════════════════════════════════════════╝"
        );
        println!();
        println!("桌面分辨率: {}x{}", desktop_width, desktop_height);
        println!(
            "像素数量: {} MP",
            (desktop_width * desktop_height) as f64 / 1_000_000.0
        );
        println!();

        println!("=== 延迟汇总 ===");
        println!("| 阶段   | 最小值 | 最大值 | P50 (ms) | P90 (ms) | P95 (ms) | P99 (ms) |");
        println!("|--------|--------|--------|----------|----------|----------|----------|");
        println!(
            "| 采集   | {:6.3} | {:6.3} | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            capture_min.as_secs_f64() * 1000.0,
            capture_max.as_secs_f64() * 1000.0,
            capture_p50.as_secs_f64() * 1000.0,
            capture_p90.as_secs_f64() * 1000.0,
            capture_p95.as_secs_f64() * 1000.0,
            capture_p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 编码   | {:6.3} | {:6.3} | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            encode_min.as_secs_f64() * 1000.0,
            encode_max.as_secs_f64() * 1000.0,
            encode_p50.as_secs_f64() * 1000.0,
            encode_p90.as_secs_f64() * 1000.0,
            encode_p95.as_secs_f64() * 1000.0,
            encode_p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 传输   | {:6.3} | {:6.3} | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            transfer_min.as_secs_f64() * 1000.0,
            transfer_max.as_secs_f64() * 1000.0,
            transfer_p50.as_secs_f64() * 1000.0,
            transfer_p90.as_secs_f64() * 1000.0,
            transfer_p95.as_secs_f64() * 1000.0,
            transfer_p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 解码   | {:6.3} | {:6.3} | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            decode_min.as_secs_f64() * 1000.0,
            decode_max.as_secs_f64() * 1000.0,
            decode_p50.as_secs_f64() * 1000.0,
            decode_p90.as_secs_f64() * 1000.0,
            decode_p95.as_secs_f64() * 1000.0,
            decode_p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 渲染   | {:6.3} | {:6.3} | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            render_min.as_secs_f64() * 1000.0,
            render_max.as_secs_f64() * 1000.0,
            render_p50.as_secs_f64() * 1000.0,
            render_p90.as_secs_f64() * 1000.0,
            render_p95.as_secs_f64() * 1000.0,
            render_p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 端到端 | {:6.3} | {:6.3} | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            e2e_min.as_secs_f64() * 1000.0,
            e2e_max.as_secs_f64() * 1000.0,
            e2e_p50.as_secs_f64() * 1000.0,
            e2e_p90.as_secs_f64() * 1000.0,
            e2e_p95.as_secs_f64() * 1000.0,
            e2e_p99.as_secs_f64() * 1000.0
        );
        println!();
    }
}

const TEST_DURATION_SECS: u64 = 10;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("全链路延迟测试（完整桌面分辨率 + 真实渲染）");
    println!("==========================================");
    println!();
    println!("链路：采集 -> 编码 -> 解码 -> 渲染（真实渲染）");
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

    // 创建渲染纹理（RGB 格式）
    let render_texture =
        create_render_texture(&device, desktop_width as u32, desktop_height as u32)?;

    // 预分配缓冲区（完整桌面分辨率）
    let mut rgb_data = vec![0u8; desktop_width * desktop_height * 3];
    let mut encoded_data = vec![0u8; desktop_width * desktop_height * 3 / 2];
    let mut decoded_data = vec![0u8; desktop_width * desktop_height * 3];
    let mut rendered_data = vec![0u8; desktop_width * desktop_height * 4]; // RGBA

    println!();
    println!("开始全链路延迟测试...");
    println!("按 Ctrl+C 退出");
    println!();

    // 创建延迟测量器
    let mut measurer = PipelineLatencyMeasurer::new();

    let start_time = Instant::now();
    let mut frames_tested = 0u64;
    let mut running = true;

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

        // 端到端计时开始
        let e2e_start = Instant::now();

        // 1. 采集阶段
        let capture_start = Instant::now();

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

                    // BGRA 转 RGB（无缩放）
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

                    let capture_time = capture_start.elapsed();
                    measurer.capture_stats.add(capture_time);

                    // 2. 编码阶段（模拟：压缩数据）
                    let encode_start = Instant::now();
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
                    let encode_time = encode_start.elapsed();
                    measurer.encode_stats.add(encode_time);

                    // 3. 传输阶段（模拟：内存拷贝）
                    let transfer_start = Instant::now();
                    let transfer_data = encoded_data[..encode_idx].to_vec();
                    let transfer_time = transfer_start.elapsed();
                    measurer.transfer_stats.add(transfer_time);

                    // 4. 解码阶段（模拟：解压缩）
                    let decode_start = Instant::now();
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
                    let decode_time = decode_start.elapsed();
                    measurer.decode_stats.add(decode_time);

                    // 5. 渲染阶段（真实渲染到窗口）
                    let render_start = Instant::now();

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

                    // 将 RGBA 数据写入渲染纹理（使用 UpdateSubresource）
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

                    // 计算缩放（将桌面分辨率缩放到窗口大小）
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

                    // 呈现
                    unsafe {
                        let _ =
                            swap_chain.Present(1, windows::Win32::Graphics::Dxgi::DXGI_PRESENT(0));
                        // VSync
                    }

                    let render_time = render_start.elapsed();
                    measurer.render_stats.add(render_time);

                    // 端到端计时结束
                    let e2e_time = e2e_start.elapsed();
                    measurer.e2e_stats.add(e2e_time);

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

    // 输出结果
    measurer.print(desktop_width, desktop_height);

    println!("测试完成！共测试 {} 帧", frames_tested);
    println!();

    // 输出性能建议
    let (_, _, capture_p95, _, _, _) = measurer.capture_stats.calculate();
    let (_, _, encode_p95, _, _, _) = measurer.encode_stats.calculate();
    let (_, _, transfer_p95, _, _, _) = measurer.transfer_stats.calculate();
    let (_, _, decode_p95, _, _, _) = measurer.decode_stats.calculate();
    let (_, _, render_p95, _, _, _) = measurer.render_stats.calculate();
    let (_, _, e2e_p95, _, _, _) = measurer.e2e_stats.calculate();

    println!("=== 性能建议 ===");
    println!();

    if capture_p95.as_secs_f64() * 1000.0 > 10.0 {
        println!(
            "⚠️  采集 P95 延迟较高 ({:.3} ms)",
            capture_p95.as_secs_f64() * 1000.0
        );
    }

    if encode_p95.as_secs_f64() * 1000.0 > 10.0 {
        println!(
            "⚠️  编码 P95 延迟较高 ({:.3} ms)",
            encode_p95.as_secs_f64() * 1000.0
        );
    }

    if render_p95.as_secs_f64() * 1000.0 > 20.0 {
        println!(
            "⚠️  渲染 P95 延迟较高 ({:.3} ms)",
            render_p95.as_secs_f64() * 1000.0
        );
        println!("   建议: 使用 GPU 缩放或减少 VSync");
    }

    if e2e_p95.as_secs_f64() * 1000.0 > 50.0 {
        println!(
            "⚠️  端到端 P95 延迟较高 ({:.3} ms)",
            e2e_p95.as_secs_f64() * 1000.0
        );
    } else {
        println!("✅ 各阶段延迟良好");
    }

    println!();

    Ok(())
}

fn create_window() -> Result<(HWND, u32, u32), Box<dyn std::error::Error>> {
    let class_name = PCSTR::from_raw("FullDesktopRenderClass\0".as_ptr());
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
            PCSTR::from_raw("Full Desktop Render Test\0".as_ptr()),
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
