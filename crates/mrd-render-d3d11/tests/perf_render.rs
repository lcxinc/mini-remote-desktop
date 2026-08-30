#![cfg(windows)]

use std::{fs, path::Path, time::Instant};

use mrd_observability::{ComponentKind, ComponentResult};
use mrd_render::{RenderFrame, RenderTarget, RendererFactory};
use mrd_render_d3d11::D3d11RendererFactory;

#[test]
#[ignore]
fn perf_d3d11_render_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120);
    let case_name =
        std::env::var("MRD_COMPONENT_CASE_NAME").unwrap_or_else(|_| "render.d3d11".into());
    let width = 1280usize;
    let height = 720usize;
    let frame_bytes = width * height * 3;
    let factory = D3d11RendererFactory;
    let mut renderer = factory.create().expect("create d3d11 renderer");
    renderer
        .attach_target(RenderTarget::WindowHandle(0))
        .expect("attach render target");
    let frame = RenderFrame::from_rgb24(width, height, synthetic_rgb24_frame(width, height));

    let mut latencies_ms = Vec::with_capacity(sample_count as usize);
    let mut success_count = 0_u64;
    let mut failure_count = 0_u64;
    let started_at = Instant::now();

    for _ in 0..sample_count {
        let iter_started_at = Instant::now();
        match renderer.upload_frame(frame.clone()) {
            Ok(()) => {
                latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
                success_count += 1;
            }
            Err(_) => {
                failure_count += 1;
            }
        }
    }

    let result = ComponentResult::new(
        ComponentKind::Render,
        "d3d11",
        case_name,
        started_at.elapsed().as_secs_f64(),
        success_count,
        failure_count,
        &latencies_ms,
        Some(width as u32),
        Some(height as u32),
        Some(frame_bytes),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    if let Ok(result_path) = std::env::var("MRD_COMPONENT_RESULT_PATH") {
        fs::write(
            Path::new(&result_path),
            serde_json::to_string_pretty(&result).expect("serialize render perf result"),
        )
        .expect("write render perf result");
    }

    assert!(result.sample_count > 0);
    assert!(result.latency_ms.p50_ms.is_some());
    assert!(result.latency_ms.p95_ms.is_some());
    assert!(result.latency_ms.p99_ms.is_some());
    assert!(result.success_ratio.is_some());
}

#[test]
#[ignore]
fn perf_d3d11_visible_window_present_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(600);
    let width = 1280usize;
    let height = 720usize;
    let _window = create_probe_window("MrdD3d11PresentPerfWindow", width, height);
    let present_interval = present_interval_from_env();

    let factory = D3d11RendererFactory;
    let mut renderer = factory.create().expect("create d3d11 renderer");
    renderer
        .attach_target(RenderTarget::WindowHandle(_window.hwnd()))
        .expect("attach visible render target");
    let frame = RenderFrame::from_bgra32(width, height, synthetic_bgra32_frame(width, height));

    let mut latencies_ms = Vec::with_capacity(sample_count);
    let started_at = Instant::now();
    for _ in 0..sample_count {
        pump_window_messages();
        let iter_started_at = Instant::now();
        renderer.upload_frame(frame.clone()).expect("upload frame");
        latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
        sleep_for_present_interval(present_interval, iter_started_at);
    }
    pump_window_messages();

    let snapshot = renderer.snapshot();
    let elapsed = started_at.elapsed().as_secs_f64();
    let (avg, p50, p95, p99) = latency_summary(&latencies_ms);
    let submitted_fps = sample_count as f64 / elapsed.max(f64::EPSILON);
    let presented_fps = snapshot.presented_frame_count as f64 / elapsed.max(f64::EPSILON);

    println!(
        "D3D11 visible window present: {width}x{height}, samples={sample_count}, submitted_fps={submitted_fps:.2}, presented_fps={presented_fps:.2}"
    );
    println!("  avg={avg:.4}ms p50={p50:.4}ms p95={p95:.4}ms p99={p99:.4}ms");
    println!(
        "  uploaded={} presented={} skipped={} last_status={:?} target_latency={:?} configured_latency={:?} allow_tearing={:?}",
        snapshot.uploaded_frame_count,
        snapshot.presented_frame_count,
        snapshot.present_skipped_count,
        snapshot.last_present_status,
        snapshot.low_latency_frame_latency_target,
        snapshot.swap_chain_max_frame_latency,
        snapshot.swap_chain_allow_tearing,
    );

    assert_eq!(snapshot.low_latency_frame_latency_target, Some(1));
    if std::env::var("MRD_D3D11_RENDER_MAX_FRAME_LATENCY")
        .ok()
        .is_some_and(|value| value == "0" || value.eq_ignore_ascii_case("off"))
    {
        assert_eq!(snapshot.swap_chain_max_frame_latency, None);
    } else {
        assert_eq!(snapshot.swap_chain_max_frame_latency, Some(1));
    }
    assert!(snapshot.uploaded_frame_count > 0);
}

#[test]
#[ignore]
fn perf_d3d11_visible_window_shared_bgra_present_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(600);
    let width = 1280usize;
    let height = 720usize;
    let _window = create_probe_window("MrdD3d11SharedBgraPresentPerfWindow", width, height);
    let shared_texture = create_shared_bgra_texture(width as u32, height as u32);
    let present_interval = present_interval_from_env();

    let factory = D3d11RendererFactory;
    let mut renderer = factory.create().expect("create d3d11 renderer");
    renderer
        .attach_target(RenderTarget::WindowHandle(_window.hwnd()))
        .expect("attach visible render target");
    let frame = RenderFrame::from_d3d11_shared_bgra(
        width,
        height,
        shared_texture.shared_handle(),
        (width * 4) as u32,
    );

    let mut latencies_ms = Vec::with_capacity(sample_count);
    let started_at = Instant::now();
    for _ in 0..sample_count {
        pump_window_messages();
        let iter_started_at = Instant::now();
        renderer
            .upload_frame(frame.clone())
            .expect("upload shared frame");
        latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
        sleep_for_present_interval(present_interval, iter_started_at);
    }
    pump_window_messages();

    let snapshot = renderer.snapshot();
    let elapsed = started_at.elapsed().as_secs_f64();
    let (avg, p50, p95, p99) = latency_summary(&latencies_ms);
    let submitted_fps = sample_count as f64 / elapsed.max(f64::EPSILON);
    let presented_fps = snapshot.presented_frame_count as f64 / elapsed.max(f64::EPSILON);

    println!(
        "D3D11 visible shared BGRA present: {width}x{height}, samples={sample_count}, submitted_fps={submitted_fps:.2}, presented_fps={presented_fps:.2}"
    );
    println!("  avg={avg:.4}ms p50={p50:.4}ms p95={p95:.4}ms p99={p99:.4}ms");
    println!(
        "  uploaded={} presented={} skipped={} last_status={:?} target_latency={:?} configured_latency={:?} allow_tearing={:?}",
        snapshot.uploaded_frame_count,
        snapshot.presented_frame_count,
        snapshot.present_skipped_count,
        snapshot.last_present_status,
        snapshot.low_latency_frame_latency_target,
        snapshot.swap_chain_max_frame_latency,
        snapshot.swap_chain_allow_tearing,
    );

    assert_eq!(snapshot.low_latency_frame_latency_target, Some(1));
    assert!(snapshot.uploaded_frame_count > 0);
    assert!(snapshot.presented_frame_count > 0 || snapshot.present_skipped_count > 0);
}

#[test]
#[ignore]
fn perf_d3d11_render_bgra32_vs_rgb24() {
    let sample_count = 500;
    let width = 1920usize;
    let height = 1080usize;

    let factory = D3d11RendererFactory;
    let mut renderer = factory.create().expect("create d3d11 renderer");
    renderer
        .attach_target(RenderTarget::WindowHandle(0))
        .expect("attach render target");

    println!("Performance Test: {width}x{height}, {sample_count} samples\n");

    // Test RGB24
    let rgb_frame = RenderFrame::from_rgb24(width, height, synthetic_rgb24_frame(width, height));

    let mut rgb_latencies = Vec::with_capacity(sample_count);
    let rgb_started = Instant::now();

    for _ in 0..sample_count {
        let start = Instant::now();
        let _ = renderer.upload_frame(rgb_frame.clone());
        rgb_latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let rgb_total = rgb_started.elapsed();

    // Test BGRA32
    let bgra_frame = RenderFrame::from_bgra32(width, height, synthetic_bgra32_frame(width, height));

    let mut bgra_latencies = Vec::with_capacity(sample_count);
    let bgra_started = Instant::now();

    for _ in 0..sample_count {
        let start = Instant::now();
        let _ = renderer.upload_frame(bgra_frame.clone());
        bgra_latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let bgra_total = bgra_started.elapsed();

    // Calculate statistics
    let rgb_latencies_sorted = {
        let mut v = rgb_latencies.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    };
    let bgra_latencies_sorted = {
        let mut v = bgra_latencies.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    };

    let rgb_p50 = rgb_latencies_sorted[sample_count / 2];
    let rgb_p95 = rgb_latencies_sorted[(sample_count * 95) / 100];
    let rgb_p99 = rgb_latencies_sorted[(sample_count * 99) / 100];
    let rgb_avg: f64 = rgb_latencies.iter().sum::<f64>() / sample_count as f64;

    let bgra_p50 = bgra_latencies_sorted[sample_count / 2];
    let bgra_p95 = bgra_latencies_sorted[(sample_count * 95) / 100];
    let bgra_p99 = bgra_latencies_sorted[(sample_count * 99) / 100];
    let bgra_avg: f64 = bgra_latencies.iter().sum::<f64>() / sample_count as f64;

    println!("RGB24 Results:");
    println!(
        "  Total:  {:.2}s ({:.2} FPS)",
        rgb_total.as_secs_f64(),
        sample_count as f64 / rgb_total.as_secs_f64()
    );
    println!("  Avg:    {:.3}ms", rgb_avg);
    println!("  P50:    {:.3}ms", rgb_p50);
    println!("  P95:    {:.3}ms", rgb_p95);
    println!("  P99:    {:.3}ms", rgb_p99);

    println!("\nBGRA32 Results:");
    println!(
        "  Total:  {:.2}s ({:.2} FPS)",
        bgra_total.as_secs_f64(),
        sample_count as f64 / bgra_total.as_secs_f64()
    );
    println!("  Avg:    {:.3}ms", bgra_avg);
    println!("  P50:    {:.3}ms", bgra_p50);
    println!("  P95:    {:.3}ms", bgra_p95);
    println!("  P99:    {:.3}ms", bgra_p99);

    println!("\nImprovement (BGRA32 vs RGB24):");
    println!("  Avg:  {:.2}%", ((rgb_avg - bgra_avg) / rgb_avg) * 100.0);
    println!("  P50:  {:.2}%", ((rgb_p50 - bgra_p50) / rgb_p50) * 100.0);
    println!("  P95:  {:.2}%", ((rgb_p95 - bgra_p95) / rgb_p95) * 100.0);
    println!("  P99:  {:.2}%", ((rgb_p99 - bgra_p99) / rgb_p99) * 100.0);
    println!(
        "  FPS:  +{:.1}%",
        (sample_count as f64
            / bgra_total.as_secs_f64()
            / (sample_count as f64 / rgb_total.as_secs_f64())
            - 1.0)
            * 100.0
    );
}

#[test]
#[ignore]
fn perf_d3d11_render_rgb24_optimized() {
    let sample_count = 500;
    let width = 1920usize;
    let height = 1080usize;

    let factory = D3d11RendererFactory;
    let mut renderer = factory.create().expect("create d3d11 renderer");
    renderer
        .attach_target(RenderTarget::WindowHandle(0))
        .expect("attach render target");

    let rgb_frame = RenderFrame::from_rgb24(width, height, synthetic_rgb24_frame(width, height));

    let mut latencies = Vec::with_capacity(sample_count);
    let started = Instant::now();

    for _ in 0..sample_count {
        let start = Instant::now();
        let _ = renderer.upload_frame(rgb_frame.clone());
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let total = started.elapsed();

    let mut sorted = latencies.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let avg = latencies.iter().sum::<f64>() / sample_count as f64;
    let p50 = sorted[sample_count / 2];
    let p95 = sorted[(sample_count * 95) / 100];
    let p99 = sorted[(sample_count * 99) / 100];

    println!("RGB24 Optimized (SIMD) Performance: {width}x{height}, {sample_count} samples");
    println!(
        "  Total:  {:.2}s ({:.2} FPS)",
        total.as_secs_f64(),
        sample_count as f64 / total.as_secs_f64()
    );
    println!("  Avg:    {:.3}ms", avg);
    println!("  P50:    {:.3}ms", p50);
    println!("  P95:    {:.3}ms", p95);
    println!("  P99:    {:.3}ms", p99);
}

#[test]
#[ignore]
fn perf_rgb24_to_bgra_conversion() {
    let sample_count = 1000;
    let width = 1920usize;
    let height = 1080usize;
    let pixels = width * height;

    let src: Vec<u8> = (0..pixels * 3).map(|i| (i % 256) as u8).collect();

    println!(
        "RGB24->BGRA Conversion Performance Test: {width}x{height}, {sample_count} iterations\n"
    );

    // Test scalar version
    let mut scalar_dst = vec![0_u8; pixels * 4];
    let scalar_started = Instant::now();

    for _ in 0..sample_count {
        for (src_idx, dst_idx) in (0..pixels).map(|i| (i * 3, i * 4)) {
            scalar_dst[dst_idx] = src[src_idx + 2];
            scalar_dst[dst_idx + 1] = src[src_idx + 1];
            scalar_dst[dst_idx + 2] = src[src_idx];
            scalar_dst[dst_idx + 3] = 255;
        }
    }

    let scalar_total = scalar_started.elapsed();

    // Test SIMD version
    let mut simd_dst = vec![0_u8; pixels * 4];
    let simd_started = Instant::now();

    for _ in 0..sample_count {
        mrd_render_d3d11::simd::rgb24_to_bgra(&src, &mut simd_dst, width, height);
    }

    let simd_total = simd_started.elapsed();

    let scalar_ms = scalar_total.as_secs_f64() * 1000.0;
    let simd_ms = simd_total.as_secs_f64() * 1000.0;

    println!("Scalar version:");
    println!("  Total:  {:.3}s", scalar_total.as_secs_f64());
    println!("  Per iteration: {:.3}ms", scalar_ms / sample_count as f64);

    println!("\nSIMD version:");
    println!("  Total:  {:.3}s", simd_total.as_secs_f64());
    println!("  Per iteration: {:.3}ms", simd_ms / sample_count as f64);

    println!("\nImprovement:");
    println!("  Speedup: {:.2}x", scalar_ms / simd_ms);
    println!(
        "  Time saved: {:.3}ms per frame",
        (scalar_ms - simd_ms) / sample_count as f64
    );
}

fn synthetic_rgb24_frame(width: usize, height: usize) -> Vec<u8> {
    let mut data = vec![0_u8; width * height * 3];
    for (index, chunk) in data.as_chunks_mut::<3>().0.iter_mut().enumerate() {
        chunk[0] = (index % 255) as u8;
        chunk[1] = ((index / 2) % 255) as u8;
        chunk[2] = ((index / 3) % 255) as u8;
    }
    data
}

fn synthetic_bgra32_frame(width: usize, height: usize) -> Vec<u8> {
    let mut data = vec![0_u8; width * height * 4];
    for (index, chunk) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        chunk[0] = ((index / 3) % 255) as u8; // B
        chunk[1] = ((index / 2) % 255) as u8; // G
        chunk[2] = (index % 255) as u8; // R
        chunk[3] = 255; // A
    }
    data
}

fn latency_summary(latencies_ms: &[f64]) -> (f64, f64, f64, f64) {
    let mut sorted = latencies_ms.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("latency is finite"));
    let avg = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[(sorted.len() * 95 / 100).min(sorted.len() - 1)];
    let p99 = sorted[(sorted.len() * 99 / 100).min(sorted.len() - 1)];
    (avg, p50, p95, p99)
}

fn present_interval_from_env() -> Option<std::time::Duration> {
    std::env::var("MRD_COMPONENT_PRESENT_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .map(|value| std::time::Duration::from_secs_f64(value / 1000.0))
}

fn sleep_for_present_interval(interval: Option<std::time::Duration>, frame_started_at: Instant) {
    let Some(interval) = interval else {
        return;
    };
    let elapsed = frame_started_at.elapsed();
    if interval > elapsed {
        std::thread::sleep(interval - elapsed);
    }
}

struct SharedBgraTexture {
    _device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    _context: windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext,
    _texture: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
    shared_handle: isize,
}

impl SharedBgraTexture {
    fn shared_handle(&self) -> isize {
        self.shared_handle
    }
}

fn create_shared_bgra_texture(width: u32, height: u32) -> SharedBgraTexture {
    use windows::core::ComInterface;
    use windows::Win32::Foundation::{HANDLE, HMODULE};
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
        D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        D3D11_RESOURCE_MISC_SHARED, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
    use windows::Win32::Graphics::Dxgi::IDXGIResource;

    let mut device = None::<ID3D11Device>;
    let mut context = None::<ID3D11DeviceContext>;
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE(0),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    }
    .expect("create d3d11 device for shared texture");
    let device = device.expect("shared texture device");
    let context = context.expect("shared texture context");

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
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: (D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0) as u32,
        CPUAccessFlags: 0,
        MiscFlags: D3D11_RESOURCE_MISC_SHARED.0 as u32,
    };
    let mut texture = None::<ID3D11Texture2D>;
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }
        .expect("create shared bgra texture");
    let texture = texture.expect("shared bgra texture");
    let dxgi_resource: IDXGIResource = texture.cast().expect("cast texture to dxgi resource");
    let shared_handle = unsafe { dxgi_resource.GetSharedHandle() }.expect("get shared handle");

    assert_ne!(shared_handle, HANDLE::default(), "shared handle is null");

    SharedBgraTexture {
        _device: device,
        _context: context,
        _texture: texture,
        shared_handle: shared_handle.0,
    }
}

struct ProbeWindow {
    hwnd: isize,
}

impl ProbeWindow {
    fn hwnd(&self) -> isize {
        self.hwnd
    }
}

impl Drop for ProbeWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(
                windows::Win32::Foundation::HWND(self.hwnd),
            );
        }
    }
}

fn create_probe_window(class_name: &str, width: usize, height: usize) -> ProbeWindow {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, RegisterClassW, ShowWindow, CS_OWNDC, CW_USEDEFAULT, HMENU, SW_SHOW,
        WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    unsafe extern "system" fn wnd_proc(
        hwnd: windows::Win32::Foundation::HWND,
        message: u32,
        wparam: windows::Win32::Foundation::WPARAM,
        lparam: windows::Win32::Foundation::LPARAM,
    ) -> windows::Win32::Foundation::LRESULT {
        windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, message, wparam, lparam)
    }

    let wide = |value: &str| -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };

    unsafe {
        let class_name = wide(class_name);
        let title = wide("MRD D3D11 Present Perf");
        let hmodule = GetModuleHandleW(None).expect("get module handle");
        let hinstance = HINSTANCE(hmodule.0);
        let window_class = WNDCLASSW {
            style: CS_OWNDC,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        RegisterClassW(&window_class);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            width.clamp(64, 4096) as i32,
            height.clamp(64, 4096) as i32,
            HWND(0),
            HMENU(0),
            hinstance,
            None,
        );
        assert_ne!(hwnd.0, 0, "create probe window");
        ShowWindow(hwnd, SW_SHOW);

        ProbeWindow { hwnd: hwnd.0 }
    }
}

fn pump_window_messages() {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    unsafe {
        let mut message = MSG::default();
        while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}
