use std::time::{Duration, Instant};
use windows::core::{w, Error, Interface, Result};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_SDK_VERSION,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_DESC, DXGI_MODE_SCALING_UNSPECIFIED,
    DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    IDXGIAdapter, IDXGIDevice, IDXGIFactory, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource, IDXGISwapChain, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_PRESENT,
    DXGI_SWAP_CHAIN_DESC, DXGI_SWAP_EFFECT_DISCARD, DXGI_USAGE_RENDER_TARGET_OUTPUT,
};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::*;

struct ZeroCopyPoc {
    context: ID3D11DeviceContext,
    swap_chain: IDXGISwapChain,
    duplication: IDXGIOutputDuplication,
    width: u32,
    height: u32,
}

impl ZeroCopyPoc {
    fn new(hwnd: HWND) -> Result<Self> {
        unsafe {
            let mut device: Option<ID3D11Device> = None;
            let mut ctx: Option<ID3D11DeviceContext> = None;
            let mut feature_level = D3D_FEATURE_LEVEL_11_0;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                windows::Win32::Graphics::Direct3D11::D3D11_CREATE_DEVICE_FLAG(0),
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                Some(&mut feature_level),
                Some(&mut ctx),
            )?;
            let device = device.ok_or(Error::from(E_FAIL))?;
            let context = ctx.ok_or(Error::from(E_FAIL))?;

            let dxgi_device: IDXGIDevice = device.cast()?;
            let adapter: IDXGIAdapter = dxgi_device.GetAdapter()?;
            let output: IDXGIOutput = adapter.EnumOutputs(0)?;
            let output1: IDXGIOutput1 = output.cast()?;
            let duplication = output1.DuplicateOutput(&device)?;
            let dup_desc = duplication.GetDesc();
            let width = dup_desc.ModeDesc.Width;
            let height = dup_desc.ModeDesc.Height;

            let factory: IDXGIFactory = adapter.GetParent()?;
            let desc = DXGI_SWAP_CHAIN_DESC {
                BufferDesc: DXGI_MODE_DESC {
                    Width: width,
                    Height: height,
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
            let hr = factory.CreateSwapChain(&device, &desc, &mut swap_chain);
            if hr.is_err() {
                return Err(Error::from(hr));
            }
            let swap_chain = swap_chain.ok_or(Error::from(E_FAIL))?;
            let _ = factory
                .MakeWindowAssociation(hwnd, windows::Win32::Graphics::Dxgi::DXGI_MWA_NO_ALT_ENTER);

            Ok(Self {
                context,
                swap_chain,
                duplication,
                width,
                height,
            })
        }
    }

    fn tick(&mut self) -> Result<(f64, f64, bool)> {
        unsafe {
            let copy_start = Instant::now();
            let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource: Option<IDXGIResource> = None;
            let mut copied = false;

            match self
                .duplication
                .AcquireNextFrame(0, &mut frame_info, &mut resource)
            {
                Ok(()) => {
                    if let Some(r) = resource {
                        let src: ID3D11Texture2D = r.cast()?;
                        let back_buffer: ID3D11Texture2D = self.swap_chain.GetBuffer(0)?;
                        self.context.CopyResource(&back_buffer, &src);
                        copied = true;
                    }
                    self.duplication.ReleaseFrame()?;
                }
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {}
                Err(e) => return Err(e),
            }
            let copy_ms = copy_start.elapsed().as_secs_f64() * 1000.0;

            let present_start = Instant::now();
            let _ = self.swap_chain.Present(0, DXGI_PRESENT(0));
            let present_ms = present_start.elapsed().as_secs_f64() * 1000.0;
            Ok((copy_ms, present_ms, copied))
        }
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn create_window() -> Result<HWND> {
    unsafe {
        let hinstance: HINSTANCE = GetModuleHandleW(None)?.into();
        let class_name = w!("DesktopZeroCopyPocWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance,
            lpszClassName: class_name,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            ..Default::default()
        };
        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("Desktop Zero Copy PoC"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1280,
            720,
            None,
            None,
            Some(hinstance),
            None,
        )?;
        Ok(hwnd)
    }
}

fn draw_overlay(hwnd: HWND, text: &str) -> Result<()> {
    unsafe {
        let hdc = GetDC(Some(hwnd));
        if hdc.0.is_null() {
            return Ok(());
        }
        let rect = RECT {
            left: 12,
            top: 12,
            right: 420,
            bottom: 132,
        };
        let bg = HBRUSH(GetStockObject(BLACK_BRUSH).0);
        FillRect(hdc, &rect, bg);
        let _ = SetBkMode(hdc, TRANSPARENT);
        let _ = SetTextColor(hdc, COLORREF(0x00F0F0F0));
        let mut draw_rect = rect;
        let mut wtext: Vec<u16> = text.encode_utf16().collect();
        let _ = DrawTextW(
            hdc,
            &mut wtext,
            &mut draw_rect,
            DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOCLIP,
        );
        let _ = ReleaseDC(Some(hwnd), hdc);
    }
    Ok(())
}

fn main() -> Result<()> {
    unsafe {
        let duration_sec = std::env::var("POC_DURATION_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let hwnd = create_window()?;
        let _ = ShowWindow(hwnd, SW_SHOW);
        let mut poc = ZeroCopyPoc::new(hwnd)?;
        SetWindowTextW(
            hwnd,
            &windows::core::HSTRING::from(format!(
                "Desktop Zero Copy PoC - {}x{}",
                poc.width, poc.height
            )),
        )?;

        let mut msg = MSG::default();
        let mut last_print = Instant::now();
        let run_start = Instant::now();
        let mut frames = 0u64;
        let mut copied_frames = 0u64;
        let mut sum_copy_ms = 0.0f64;
        let mut sum_present_ms = 0.0f64;
        let mut total_frames = 0u64;
        let mut total_copied_frames = 0u64;
        let mut total_copy_ms = 0.0f64;
        let mut total_present_ms = 0.0f64;
        let mut overlay_text = String::from("warming up...");

        loop {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_QUIT {
                    return Ok(());
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            let (copy_ms, present_ms, copied) = poc.tick()?;
            frames += 1;
            total_frames += 1;
            if copied {
                copied_frames += 1;
                total_copied_frames += 1;
            }
            sum_copy_ms += copy_ms;
            sum_present_ms += present_ms;
            total_copy_ms += copy_ms;
            total_present_ms += present_ms;

            let _ = draw_overlay(hwnd, &overlay_text);

            if last_print.elapsed() >= Duration::from_secs(1) {
                let sec = last_print.elapsed().as_secs_f64().max(1e-6);
                let fps = frames as f64 / sec;
                let copy_hit = copied_frames as f64 / frames.max(1) as f64 * 100.0;
                let avg_copy = sum_copy_ms / frames.max(1) as f64;
                let avg_present = sum_present_ms / frames.max(1) as f64;
                overlay_text = format!(
                    "Live Stats\nFPS: {:.2}\nCopy Hit: {:.1}%\nAvg Copy: {:.3} ms\nAvg Present: {:.3} ms",
                    fps, copy_hit, avg_copy, avg_present
                );
                eprintln!(
                    "[ZERO-COPY-POC] fps={:.2} copy_hit={:.1}% avg_copy_ms={:.3} avg_present_ms={:.3}",
                    fps, copy_hit, avg_copy, avg_present
                );
                frames = 0;
                copied_frames = 0;
                sum_copy_ms = 0.0;
                sum_present_ms = 0.0;
                last_print = Instant::now();
            }

            if duration_sec > 0 && run_start.elapsed() >= Duration::from_secs(duration_sec) {
                let run_sec = run_start.elapsed().as_secs_f64().max(1e-6);
                let fps = total_frames as f64 / run_sec;
                let copy_hit = total_copied_frames as f64 / total_frames.max(1) as f64 * 100.0;
                let avg_copy = total_copy_ms / total_frames.max(1) as f64;
                let avg_present = total_present_ms / total_frames.max(1) as f64;
                eprintln!(
                    "[ZERO-COPY-POC-FINAL] duration_s={} fps={:.2} copy_hit={:.1}% avg_copy_ms={:.3} avg_present_ms={:.3} frames={} copied_frames={}",
                    duration_sec, fps, copy_hit, avg_copy, avg_present, total_frames, total_copied_frames
                );
                break;
            }
        }
        Ok(())
    }
}
