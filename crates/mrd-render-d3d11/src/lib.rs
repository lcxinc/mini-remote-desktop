use mrd_render::{
    d3d11_descriptor, BoxedRenderer, RenderError, RenderFrame, RenderPixelFormat, RenderTarget,
    RendererDescriptor, RendererFactory, RendererInstance, RendererPresentEvent, RendererSnapshot,
};
use std::collections::VecDeque;

pub mod simd;

#[cfg(windows)]
use windows::core::ComInterface;

pub struct D3d11RendererFactory;

impl RendererFactory for D3d11RendererFactory {
    fn descriptor(&self) -> RendererDescriptor {
        d3d11_descriptor()
    }

    fn create(&self) -> Result<BoxedRenderer, RenderError> {
        Ok(Box::new(D3d11Renderer::new()?))
    }
}

#[cfg(windows)]
struct RenderSurface {
    swap_chain: windows::Win32::Graphics::Dxgi::IDXGISwapChain1,
    back_buffer: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
    render_target_view: windows::Win32::Graphics::Direct3D11::ID3D11RenderTargetView,
    max_frame_latency: Option<u32>,
    allow_tearing: bool,
    waitable_object: bool,
    frame_latency_waitable_object: Option<windows::Win32::Foundation::HANDLE>,
    present_mode: D3d11PresentMode,
    display_refresh_hz: Option<u32>,
    width: u32,
    height: u32,
}

#[cfg(windows)]
struct SharedNv12Pipeline {
    vertex_shader: windows::Win32::Graphics::Direct3D11::ID3D11VertexShader,
    pixel_shader: windows::Win32::Graphics::Direct3D11::ID3D11PixelShader,
    sampler: windows::Win32::Graphics::Direct3D11::ID3D11SamplerState,
}

#[cfg(windows)]
struct SharedNv12SrvCache {
    y_handle: isize,
    uv_handle: isize,
    y_srv: windows::Win32::Graphics::Direct3D11::ID3D11ShaderResourceView,
    uv_srv: windows::Win32::Graphics::Direct3D11::ID3D11ShaderResourceView,
}

#[cfg(windows)]
struct SharedBgraResourceCache {
    shared_handle: isize,
    resource: windows::Win32::Graphics::Direct3D11::ID3D11Resource,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum D3d11PresentStatus {
    Presented,
    SkippedStillDrawing,
    SkippedFrameLatencyWait,
    NoTarget,
}

#[cfg(windows)]
impl D3d11PresentStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Presented => "presented",
            Self::SkippedStillDrawing => "skipped_still_drawing",
            Self::SkippedFrameLatencyWait => "skipped_frame_latency_wait",
            Self::NoTarget => "no_target",
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum D3d11PresentMode {
    Nonblocking,
    Blocking,
    Waitable,
}

#[cfg(windows)]
impl D3d11PresentMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nonblocking => "nonblocking",
            Self::Blocking => "blocking",
            Self::Waitable => "waitable",
        }
    }
}

#[cfg(windows)]
const SHARED_NV12_VERTEX_SHADER: &str = r#"
struct VsOut {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD0;
};

VsOut main(uint vertex_id : SV_VertexID) {
    float2 positions[3] = {
        float2(-1.0, -1.0),
        float2(-1.0,  3.0),
        float2( 3.0, -1.0)
    };
    float2 uvs[3] = {
        float2(0.0, 1.0),
        float2(0.0, -1.0),
        float2(2.0, 1.0)
    };

    VsOut output;
    output.position = float4(positions[vertex_id], 0.0, 1.0);
    output.uv = uvs[vertex_id];
    return output;
}
"#;

#[cfg(windows)]
const SHARED_NV12_PIXEL_SHADER: &str = r#"
Texture2D y_texture : register(t0);
Texture2D uv_texture : register(t1);
SamplerState linear_sampler : register(s0);

struct PsIn {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD0;
};

float4 main(PsIn input) : SV_TARGET {
    float y = y_texture.Sample(linear_sampler, input.uv).r;
    float2 uv = uv_texture.Sample(linear_sampler, input.uv).rg - float2(0.5, 0.5);

    float r = y + 1.5748 * uv.y;
    float g = y - 0.1873 * uv.x - 0.4681 * uv.y;
    float b = y + 1.8556 * uv.x;
    return float4(saturate(float3(r, g, b)), 1.0);
}
"#;

#[cfg(windows)]
const SHARED_NV12_SRV_CACHE_LIMIT: usize = 32;
#[cfg(windows)]
const SHARED_BGRA_RESOURCE_CACHE_LIMIT: usize = 16;
#[cfg(windows)]
const D3D11_LOW_LATENCY_MAX_FRAME_LATENCY: u32 = 1;
#[cfg(windows)]
const D3D11_WAITABLE_PRESENT_TIMEOUT_MS: u32 = 8;

pub struct D3d11Renderer {
    #[cfg(windows)]
    device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    #[cfg(windows)]
    context: windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext,
    #[cfg(windows)]
    surface: Option<RenderSurface>,
    #[cfg(windows)]
    shared_nv12_pipeline: Option<SharedNv12Pipeline>,
    #[cfg(windows)]
    shared_nv12_srv_cache: Vec<SharedNv12SrvCache>,
    #[cfg(windows)]
    shared_bgra_resource_cache: Vec<SharedBgraResourceCache>,
    attached_to_target: bool,
    uploaded_frame_count: u64,
    presented_frame_count: u64,
    present_skipped_count: u64,
    last_present_status: Option<&'static str>,
    waitable_wait_count: u64,
    waitable_wait_total_ms: f64,
    waitable_timeout_count: u64,
    last_waitable_wait_ms: Option<f64>,
    last_render_prepare_wait_ms: Option<f64>,
    last_render_shared_resource_ms: Option<f64>,
    last_render_draw_present_ms: Option<f64>,
    last_width: usize,
    last_height: usize,
    last_pixel_format: Option<RenderPixelFormat>,
    present_events: VecDeque<RendererPresentEvent>,
}

fn fit_viewport_rect(
    surface_width: u32,
    surface_height: u32,
    frame_width: usize,
    frame_height: usize,
) -> (f32, f32, f32, f32) {
    if surface_width == 0 || surface_height == 0 || frame_width == 0 || frame_height == 0 {
        return (0.0, 0.0, surface_width as f32, surface_height as f32);
    }

    let surface_width = surface_width as f32;
    let surface_height = surface_height as f32;
    let frame_aspect = frame_width as f32 / frame_height as f32;
    let surface_aspect = surface_width / surface_height;

    if surface_aspect > frame_aspect {
        let height = surface_height;
        let width = height * frame_aspect;
        ((surface_width - width) * 0.5, 0.0, width, height)
    } else {
        let width = surface_width;
        let height = width / frame_aspect;
        (0.0, (surface_height - height) * 0.5, width, height)
    }
}

impl D3d11Renderer {
    pub fn new() -> Result<Self, RenderError> {
        #[cfg(windows)]
        {
            use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
            use windows::Win32::Graphics::Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
            };

            let mut device = None::<ID3D11Device>;
            let mut context = None::<ID3D11DeviceContext>;

            unsafe {
                D3D11CreateDevice(
                    None,
                    D3D_DRIVER_TYPE_HARDWARE,
                    None,
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )
            }
            .map_err(|error| RenderError::Message(format!("创建 D3D11 设备失败: {error}")))?;

            let device = device.ok_or_else(|| RenderError::Message("缺少 D3D11 device".into()))?;
            let context =
                context.ok_or_else(|| RenderError::Message("缺少 D3D11 device context".into()))?;

            Ok(Self {
                device,
                context,
                surface: None,
                shared_nv12_pipeline: None,
                shared_nv12_srv_cache: Vec::new(),
                shared_bgra_resource_cache: Vec::new(),
                attached_to_target: false,
                uploaded_frame_count: 0,
                presented_frame_count: 0,
                present_skipped_count: 0,
                last_present_status: None,
                waitable_wait_count: 0,
                waitable_wait_total_ms: 0.0,
                waitable_timeout_count: 0,
                last_waitable_wait_ms: None,
                last_render_prepare_wait_ms: None,
                last_render_shared_resource_ms: None,
                last_render_draw_present_ms: None,
                last_width: 0,
                last_height: 0,
                last_pixel_format: None,
                present_events: VecDeque::new(),
            })
        }

        #[cfg(not(windows))]
        {
            Err(RenderError::Message(
                "d3d11 renderer 仅支持 Windows".to_string(),
            ))
        }
    }

    #[cfg(windows)]
    pub fn device_ptr(&self) -> *mut core::ffi::c_void {
        use windows::core::Interface;
        self.device.as_raw()
    }

    #[cfg(not(windows))]
    pub fn device_ptr(&self) -> *mut core::ffi::c_void {
        core::ptr::null_mut()
    }

    #[cfg(windows)]
    fn env_bool(key: &str) -> bool {
        matches!(
            std::env::var(key),
            Ok(value) if value == "1" || value.eq_ignore_ascii_case("true")
        )
    }

    #[cfg(windows)]
    fn present_mode() -> D3d11PresentMode {
        if Self::env_bool("MRD_D3D11_RENDER_PRESENT_BLOCKING") {
            D3d11PresentMode::Blocking
        } else if Self::env_bool("MRD_D3D11_RENDER_WAITABLE_OBJECT") {
            D3d11PresentMode::Waitable
        } else {
            D3d11PresentMode::Nonblocking
        }
    }

    #[cfg(windows)]
    fn waitable_present_timeout_ms() -> u32 {
        std::env::var("MRD_D3D11_RENDER_WAITABLE_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|timeout| *timeout > 0)
            .unwrap_or(D3D11_WAITABLE_PRESENT_TIMEOUT_MS)
    }

    #[cfg(windows)]
    fn present_flags(present_mode: D3d11PresentMode, allow_tearing: bool) -> u32 {
        use windows::Win32::Graphics::Dxgi::{
            DXGI_PRESENT_ALLOW_TEARING, DXGI_PRESENT_DO_NOT_WAIT,
        };

        if present_mode == D3d11PresentMode::Blocking {
            0
        } else {
            let mut flags = DXGI_PRESENT_DO_NOT_WAIT;
            if allow_tearing {
                flags |= DXGI_PRESENT_ALLOW_TEARING;
            }
            flags
        }
    }

    #[cfg(windows)]
    fn wait_for_frame_latency(
        waitable_object: Option<windows::Win32::Foundation::HANDLE>,
    ) -> Result<(bool, f64), RenderError> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;

        let Some(waitable_object) = waitable_object else {
            return Ok((true, 0.0));
        };
        let started = std::time::Instant::now();
        let result =
            unsafe { WaitForSingleObject(waitable_object, Self::waitable_present_timeout_ms()) };
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        if result == WAIT_OBJECT_0 {
            Ok((true, elapsed_ms))
        } else if result == WAIT_TIMEOUT {
            Ok((false, elapsed_ms))
        } else {
            Err(RenderError::Message(format!(
                "wait for DXGI frame latency object failed: {result:?}"
            )))
        }
    }

    #[cfg(windows)]
    fn validated_frame_latency_waitable_object(
        handle: windows::Win32::Foundation::HANDLE,
    ) -> Result<windows::Win32::Foundation::HANDLE, RenderError> {
        if handle.0 == 0 {
            Err(RenderError::Message(
                "DXGI frame latency waitable object was not created".to_string(),
            ))
        } else {
            Ok(handle)
        }
    }

    #[cfg(windows)]
    fn present_swap_chain(
        swap_chain: &windows::Win32::Graphics::Dxgi::IDXGISwapChain1,
        allow_tearing: bool,
        present_mode: D3d11PresentMode,
    ) -> Result<D3d11PresentStatus, RenderError> {
        use windows::Win32::Graphics::Dxgi::DXGI_ERROR_WAS_STILL_DRAWING;

        let hr = unsafe { swap_chain.Present(0, Self::present_flags(present_mode, allow_tearing)) };
        if hr == DXGI_ERROR_WAS_STILL_DRAWING {
            return Ok(D3d11PresentStatus::SkippedStillDrawing);
        }
        hr.ok()
            .map_err(|error| RenderError::Message(format!("present 失败: {error}")))?;
        Ok(D3d11PresentStatus::Presented)
    }

    #[cfg(windows)]
    fn low_latency_frame_latency_target() -> u32 {
        D3D11_LOW_LATENCY_MAX_FRAME_LATENCY
    }

    #[cfg(windows)]
    fn max_frame_latency_target() -> Option<u32> {
        match std::env::var("MRD_D3D11_RENDER_MAX_FRAME_LATENCY") {
            Ok(value) if value == "0" || value.eq_ignore_ascii_case("off") => None,
            Ok(value) => value
                .parse::<u32>()
                .ok()
                .filter(|latency| *latency > 0)
                .or(Some(D3D11_LOW_LATENCY_MAX_FRAME_LATENCY)),
            Err(_) => Some(D3D11_LOW_LATENCY_MAX_FRAME_LATENCY),
        }
    }

    #[cfg(windows)]
    fn configure_low_latency_device(
        dxgi_device: &windows::Win32::Graphics::Dxgi::IDXGIDevice,
    ) -> Result<Option<u32>, RenderError> {
        use windows::Win32::Graphics::Dxgi::IDXGIDevice1;

        let Some(max_frame_latency) = Self::max_frame_latency_target() else {
            return Ok(None);
        };
        let dxgi_device1: IDXGIDevice1 = dxgi_device
            .cast()
            .map_err(|error| RenderError::Message(format!("转换 IDXGIDevice1 失败: {error}")))?;
        unsafe { dxgi_device1.SetMaximumFrameLatency(max_frame_latency) }.map_err(|error| {
            RenderError::Message(format!("配置 DXGI device 帧延迟失败: {error}"))
        })?;
        Ok(Some(max_frame_latency))
    }

    #[cfg(windows)]
    fn current_thread_priority_label() -> &'static str {
        use windows::Win32::System::Threading::{
            GetCurrentThread, GetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
            THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_IDLE,
            THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_TIME_CRITICAL,
        };

        let priority = unsafe { GetThreadPriority(GetCurrentThread()) };
        match priority {
            value if value == THREAD_PRIORITY_IDLE.0 => "idle",
            value if value == THREAD_PRIORITY_LOWEST.0 => "lowest",
            value if value == THREAD_PRIORITY_BELOW_NORMAL.0 => "below_normal",
            value if value == THREAD_PRIORITY_NORMAL.0 => "normal",
            value if value == THREAD_PRIORITY_ABOVE_NORMAL.0 => "above_normal",
            value if value == THREAD_PRIORITY_HIGHEST.0 => "highest",
            value if value == THREAD_PRIORITY_TIME_CRITICAL.0 => "time_critical",
            _ => "unknown",
        }
    }

    #[cfg(windows)]
    fn render_thread_priority_from_env() -> Option<(
        &'static str,
        windows::Win32::System::Threading::THREAD_PRIORITY,
    )> {
        use windows::Win32::System::Threading::{
            THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_NORMAL,
        };

        match std::env::var("MRD_RENDER_THREAD_PRIORITY")
            .ok()?
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "normal" => Some(("normal", THREAD_PRIORITY_NORMAL)),
            "above_normal" | "above-normal" => Some(("above_normal", THREAD_PRIORITY_ABOVE_NORMAL)),
            "highest" => Some(("highest", THREAD_PRIORITY_HIGHEST)),
            _ => None,
        }
    }

    #[cfg(windows)]
    fn configure_render_thread_priority() -> Result<(), RenderError> {
        use windows::Win32::System::Threading::{GetCurrentThread, SetThreadPriority};

        let Some((_, priority)) = Self::render_thread_priority_from_env() else {
            return Ok(());
        };
        unsafe { SetThreadPriority(GetCurrentThread(), priority) }.map_err(|error| {
            RenderError::Message(format!("configure render thread priority failed: {error}"))
        })
    }

    #[cfg(windows)]
    fn record_waitable_wait_metrics(&mut self, wait_ms: f64, timed_out: bool) {
        self.waitable_wait_count = self.waitable_wait_count.saturating_add(1);
        self.waitable_wait_total_ms += wait_ms.max(0.0);
        self.last_waitable_wait_ms = Some(wait_ms.max(0.0));
        if timed_out {
            self.waitable_timeout_count = self.waitable_timeout_count.saturating_add(1);
        }
    }

    #[cfg(windows)]
    fn duration_ms(duration: std::time::Duration) -> f64 {
        duration.as_secs_f64() * 1000.0
    }

    #[cfg(windows)]
    fn reset_last_render_breakdown(&mut self) {
        self.last_render_prepare_wait_ms = None;
        self.last_render_shared_resource_ms = None;
        self.last_render_draw_present_ms = None;
    }

    #[cfg(windows)]
    fn record_draw_present<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, RenderError>,
    ) -> Result<T, RenderError> {
        let started = std::time::Instant::now();
        let result = operation(self);
        self.last_render_draw_present_ms = Some(Self::duration_ms(started.elapsed()));
        result
    }

    #[cfg(windows)]
    fn prepare_waitable_frame_latency(
        &mut self,
    ) -> Result<Option<D3d11PresentStatus>, RenderError> {
        let Some(surface) = self.surface.as_ref() else {
            return Ok(None);
        };
        if surface.present_mode != D3d11PresentMode::Waitable {
            return Ok(None);
        }

        let (ready, wait_ms) = Self::wait_for_frame_latency(surface.frame_latency_waitable_object)?;
        self.record_waitable_wait_metrics(wait_ms, !ready);
        if ready {
            Ok(None)
        } else {
            Ok(Some(D3d11PresentStatus::SkippedFrameLatencyWait))
        }
    }

    #[cfg(windows)]
    fn display_refresh_hz_for_window(hwnd: windows::Win32::Foundation::HWND) -> Option<u32> {
        use windows::core::PCWSTR;
        use windows::Win32::Graphics::Gdi::{
            EnumDisplaySettingsW, GetMonitorInfoW, MonitorFromWindow, DEVMODEW,
            ENUM_CURRENT_SETTINGS, MONITORINFOEXW, MONITOR_DEFAULTTONEAREST,
        };

        let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
        if monitor.0 == 0 {
            return None;
        }

        let mut monitor_info = MONITORINFOEXW::default();
        monitor_info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        if !unsafe { GetMonitorInfoW(monitor, (&mut monitor_info as *mut MONITORINFOEXW).cast()) }
            .as_bool()
        {
            return None;
        }

        let mut dev_mode = DEVMODEW {
            dmSize: std::mem::size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        let ok = unsafe {
            EnumDisplaySettingsW(
                PCWSTR(monitor_info.szDevice.as_ptr()),
                ENUM_CURRENT_SETTINGS,
                &mut dev_mode,
            )
            .as_bool()
        };
        ok.then_some(dev_mode.dmDisplayFrequency)
            .filter(|refresh_hz| *refresh_hz > 0)
    }

    #[cfg(windows)]
    fn window_swap_chain_desc(
        width: u32,
        height: u32,
        allow_tearing: bool,
        waitable_object: bool,
    ) -> windows::Win32::Graphics::Dxgi::DXGI_SWAP_CHAIN_DESC1 {
        use windows::Win32::Graphics::Dxgi::Common::{
            DXGI_ALPHA_MODE_IGNORE, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
        };
        use windows::Win32::Graphics::Dxgi::{
            DXGI_SCALING_STRETCH, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING,
            DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT, DXGI_SWAP_EFFECT_FLIP_DISCARD,
            DXGI_USAGE_RENDER_TARGET_OUTPUT,
        };

        let mut flags = 0_u32;
        if allow_tearing {
            flags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING.0 as u32;
        }
        if waitable_object {
            flags |= DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT.0 as u32;
        }

        DXGI_SWAP_CHAIN_DESC1 {
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
            Scaling: DXGI_SCALING_STRETCH,
            SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
            AlphaMode: DXGI_ALPHA_MODE_IGNORE,
            Flags: flags,
        }
    }

    #[cfg(windows)]
    fn check_tearing_support(factory: &windows::Win32::Graphics::Dxgi::IDXGIFactory2) -> bool {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::Graphics::Dxgi::{IDXGIFactory5, DXGI_FEATURE_PRESENT_ALLOW_TEARING};

        let Ok(factory5): Result<IDXGIFactory5, _> = factory.cast() else {
            return false;
        };
        let mut allow_tearing = BOOL(0);
        unsafe {
            factory5
                .CheckFeatureSupport(
                    DXGI_FEATURE_PRESENT_ALLOW_TEARING,
                    &mut allow_tearing as *mut BOOL as *mut core::ffi::c_void,
                    core::mem::size_of::<BOOL>() as u32,
                )
                .is_ok()
                && allow_tearing.as_bool()
        }
    }

    #[cfg(windows)]
    fn attach_window_surface(
        &mut self,
        window_handle: isize,
    ) -> Result<Option<RenderSurface>, RenderError> {
        use windows::Win32::Foundation::{HWND, RECT};
        use windows::Win32::Graphics::Direct3D11::{ID3D11RenderTargetView, ID3D11Texture2D};
        use windows::Win32::Graphics::Dxgi::{
            IDXGIDevice, IDXGIFactory2, IDXGISwapChain1, IDXGISwapChain2,
        };
        use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

        if window_handle == 0 {
            return Ok(None);
        }

        let hwnd = HWND(window_handle);
        let mut rect = RECT::default();
        unsafe { GetClientRect(hwnd, &mut rect) }
            .map_err(|error| RenderError::Message(format!("读取窗口大小失败: {error}")))?;
        let width = (rect.right - rect.left).max(1) as u32;
        let height = (rect.bottom - rect.top).max(1) as u32;

        Self::configure_render_thread_priority()?;

        let dxgi_device: IDXGIDevice = self
            .device
            .cast()
            .map_err(|error| RenderError::Message(format!("转换 IDXGIDevice 失败: {error}")))?;
        let max_frame_latency = Self::configure_low_latency_device(&dxgi_device)?;
        let adapter = unsafe { dxgi_device.GetAdapter() }
            .map_err(|error| RenderError::Message(format!("获取 DXGI adapter 失败: {error}")))?;
        let factory: IDXGIFactory2 = unsafe { adapter.GetParent() }
            .map_err(|error| RenderError::Message(format!("获取 DXGI factory 失败: {error}")))?;
        let allow_tearing = Self::check_tearing_support(&factory);
        let present_mode = Self::present_mode();
        let waitable_object = present_mode == D3d11PresentMode::Waitable;
        let swap_chain_desc =
            Self::window_swap_chain_desc(width, height, allow_tearing, waitable_object);

        let swap_chain: IDXGISwapChain1 = unsafe {
            factory.CreateSwapChainForHwnd(
                &self.device,
                hwnd,
                &swap_chain_desc,
                None,
                None::<&windows::Win32::Graphics::Dxgi::IDXGIOutput>,
            )
        }
        .map_err(|error| RenderError::Message(format!("创建 SwapChain 失败: {error}")))?;
        let frame_latency_waitable_object = if waitable_object {
            let swap_chain2: IDXGISwapChain2 = swap_chain.cast().map_err(|error| {
                RenderError::Message(format!("转换 IDXGISwapChain2 失败: {error}"))
            })?;
            unsafe {
                swap_chain2
                    .SetMaximumFrameLatency(
                        max_frame_latency.unwrap_or(D3D11_LOW_LATENCY_MAX_FRAME_LATENCY),
                    )
                    .map_err(|error| {
                        RenderError::Message(format!("配置 DXGI swapchain 帧延迟失败: {error}"))
                    })?
            };
            let handle = unsafe { swap_chain2.GetFrameLatencyWaitableObject() };
            Some(Self::validated_frame_latency_waitable_object(handle)?)
        } else {
            None
        };
        let display_refresh_hz = Self::display_refresh_hz_for_window(hwnd);

        let back_buffer: ID3D11Texture2D = unsafe { swap_chain.GetBuffer(0) }
            .map_err(|error| RenderError::Message(format!("获取 back buffer 失败: {error}")))?;
        let mut render_target_view = None::<ID3D11RenderTargetView>;
        unsafe {
            self.device
                .CreateRenderTargetView(&back_buffer, None, Some(&mut render_target_view))
        }
        .map_err(|error| RenderError::Message(format!("创建 RTV 失败: {error}")))?;
        let render_target_view = render_target_view
            .ok_or_else(|| RenderError::Message("缺少 render target view".into()))?;

        Ok(Some(RenderSurface {
            swap_chain,
            back_buffer,
            render_target_view,
            max_frame_latency,
            allow_tearing,
            waitable_object,
            frame_latency_waitable_object,
            present_mode,
            display_refresh_hz,
            width,
            height,
        }))
    }

    #[cfg(windows)]
    fn average_clear_color(frame: &RenderFrame) -> [f32; 4] {
        use mrd_render::RenderFrameData;
        let data = match &frame.data {
            RenderFrameData::Rgb24(data) => data,
            RenderFrameData::Bgra32(data) => data,
            RenderFrameData::Nv12 { .. } | RenderFrameData::Nv12Bytes { .. } => {
                return [0.05, 0.05, 0.05, 1.0];
            }
            #[cfg(windows)]
            RenderFrameData::D3D11SharedBgra { .. } => {
                return [0.05, 0.05, 0.05, 1.0];
            }
            #[cfg(windows)]
            RenderFrameData::D3D11SharedNv12 { .. } => {
                return [0.05, 0.05, 0.05, 1.0];
            }
            #[cfg(windows)]
            RenderFrameData::D3D11SharedP010 { .. } => {
                return [0.05, 0.05, 0.05, 1.0];
            }
        };

        if data.is_empty() {
            return [0.05, 0.05, 0.05, 1.0];
        }

        let mut r: u64 = 0;
        let mut g: u64 = 0;
        let mut b: u64 = 0;
        let mut pixels: u64 = 0;

        for chunk in data.as_chunks::<3>().0 {
            r += chunk[0] as u64;
            g += chunk[1] as u64;
            b += chunk[2] as u64;
            pixels += 1;
        }

        if pixels == 0 {
            return [0.05, 0.05, 0.05, 1.0];
        }

        [
            (r as f32 / pixels as f32) / 255.0,
            (g as f32 / pixels as f32) / 255.0,
            (b as f32 / pixels as f32) / 255.0,
            1.0,
        ]
    }

    #[cfg(windows)]
    fn present_clear_frame(&self, frame: &RenderFrame) -> Result<D3d11PresentStatus, RenderError> {
        let Some(surface) = self.surface.as_ref() else {
            return Ok(D3d11PresentStatus::NoTarget);
        };

        let clear = Self::average_clear_color(frame);
        unsafe {
            self.context
                .OMSetRenderTargets(Some(&[Some(surface.render_target_view.clone())]), None);
            self.context
                .ClearRenderTargetView(&surface.render_target_view, &clear);
        }
        Self::present_swap_chain(
            &surface.swap_chain,
            surface.allow_tearing,
            surface.present_mode,
        )
    }

    #[cfg(windows)]
    fn present_uploaded_frame_bgra(
        &self,
        frame: &RenderFrame,
    ) -> Result<D3d11PresentStatus, RenderError> {
        use mrd_render::RenderFrameData;
        use windows::Win32::Graphics::Direct3D11::D3D11_BOX;
        let Some(surface) = self.surface.as_ref() else {
            return Ok(D3d11PresentStatus::NoTarget);
        };

        let data = match &frame.data {
            RenderFrameData::Bgra32(data) => data,
            _ => return Err(RenderError::Message("Expected Bgra32 frame data".into())),
        };

        let expected = frame
            .width
            .checked_mul(frame.height)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| RenderError::Message("frame size overflow".into()))?;
        if data.len() != expected {
            return Err(RenderError::Message(format!(
                "Bgra32 frame bytes mismatch: expected {expected}, got {}",
                data.len()
            )));
        }

        let surface_width = surface.width as usize;
        let surface_height = surface.height as usize;
        let upload_data;
        let (data, upload_width, upload_height) =
            if frame.width == surface_width && frame.height == surface_height {
                (data.as_slice(), frame.width, frame.height)
            } else {
                upload_data = Self::scale_bgra_to_fit(
                    data,
                    frame.width,
                    frame.height,
                    surface_width,
                    surface_height,
                )?;
                (upload_data.as_slice(), surface_width, surface_height)
            };
        let row_pitch = upload_width
            .checked_mul(4)
            .ok_or_else(|| RenderError::Message("row pitch overflow".into()))?
            as u32;
        let copy_width = upload_width.min(surface_width);
        let copy_height = upload_height.min(surface_height);
        if copy_width == 0 || copy_height == 0 {
            return Ok(D3d11PresentStatus::NoTarget);
        }
        let copy_box = D3D11_BOX {
            left: 0,
            top: 0,
            front: 0,
            right: copy_width as u32,
            bottom: copy_height as u32,
            back: 1,
        };

        unsafe {
            self.context.UpdateSubresource(
                &surface.back_buffer,
                0,
                Some(&copy_box as *const D3D11_BOX),
                data.as_ptr() as *const core::ffi::c_void,
                row_pitch,
                0,
            );
        }
        Self::present_swap_chain(
            &surface.swap_chain,
            surface.allow_tearing,
            surface.present_mode,
        )
    }

    #[cfg(windows)]
    fn rgb24_to_bgra(frame: &RenderFrame) -> Result<Vec<u8>, RenderError> {
        use mrd_render::RenderFrameData;
        let data = match &frame.data {
            RenderFrameData::Rgb24(data) => data,
            _ => return Err(RenderError::Message("Expected Rgb24 frame data".into())),
        };

        let expected = frame
            .width
            .checked_mul(frame.height)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or_else(|| RenderError::Message("frame size overflow".into()))?;
        if data.len() != expected {
            return Err(RenderError::Message(format!(
                "Rgb24 frame bytes mismatch: expected {expected}, got {}",
                data.len()
            )));
        }

        let mut bgra = vec![0_u8; frame.width * frame.height * 4];
        simd::rgb24_to_bgra(data, &mut bgra, frame.width, frame.height);
        Ok(bgra)
    }

    #[cfg(windows)]
    fn scale_bgra_to_fit(
        source: &[u8],
        source_width: usize,
        source_height: usize,
        target_width: usize,
        target_height: usize,
    ) -> Result<Vec<u8>, RenderError> {
        if source_width == 0 || source_height == 0 || target_width == 0 || target_height == 0 {
            return Ok(Vec::new());
        }

        let source_len = source_width
            .checked_mul(source_height)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| RenderError::Message("source frame size overflow".into()))?;
        if source.len() != source_len {
            return Err(RenderError::Message(format!(
                "BGRA source bytes mismatch: expected {source_len}, got {}",
                source.len()
            )));
        }

        let target_len = target_width
            .checked_mul(target_height)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| RenderError::Message("target frame size overflow".into()))?;
        let mut target = vec![0_u8; target_len];

        let width_limited_height =
            ((target_width as u128 * source_height as u128) / source_width as u128) as usize;
        let (draw_width, draw_height) = if width_limited_height <= target_height {
            (target_width, width_limited_height.max(1))
        } else {
            let height_limited_width =
                ((target_height as u128 * source_width as u128) / source_height as u128) as usize;
            (height_limited_width.max(1), target_height)
        };
        let offset_x = (target_width - draw_width) / 2;
        let offset_y = (target_height - draw_height) / 2;

        for y in 0..draw_height {
            let source_y = (y * source_height / draw_height).min(source_height - 1);
            for x in 0..draw_width {
                let source_x = (x * source_width / draw_width).min(source_width - 1);
                let source_idx = (source_y * source_width + source_x) * 4;
                let target_idx = ((offset_y + y) * target_width + offset_x + x) * 4;
                target[target_idx..target_idx + 4]
                    .copy_from_slice(&source[source_idx..source_idx + 4]);
            }
        }

        Ok(target)
    }

    #[cfg(windows)]
    fn present_uploaded_frame(
        &self,
        frame: &RenderFrame,
    ) -> Result<D3d11PresentStatus, RenderError> {
        use windows::Win32::Graphics::Direct3D11::D3D11_BOX;
        let Some(surface) = self.surface.as_ref() else {
            return Ok(D3d11PresentStatus::NoTarget);
        };

        let bgra = Self::rgb24_to_bgra(frame)?;
        let surface_width = surface.width as usize;
        let surface_height = surface.height as usize;
        let upload_data;
        let (data, upload_width, upload_height) =
            if frame.width == surface_width && frame.height == surface_height {
                (bgra.as_slice(), frame.width, frame.height)
            } else {
                upload_data = Self::scale_bgra_to_fit(
                    &bgra,
                    frame.width,
                    frame.height,
                    surface_width,
                    surface_height,
                )?;
                (upload_data.as_slice(), surface_width, surface_height)
            };
        let row_pitch = upload_width
            .checked_mul(4)
            .ok_or_else(|| RenderError::Message("row pitch overflow".into()))?
            as u32;
        let copy_width = upload_width.min(surface_width);
        let copy_height = upload_height.min(surface_height);
        if copy_width == 0 || copy_height == 0 {
            return Ok(D3d11PresentStatus::NoTarget);
        }
        let copy_box = D3D11_BOX {
            left: 0,
            top: 0,
            front: 0,
            right: copy_width as u32,
            bottom: copy_height as u32,
            back: 1,
        };

        unsafe {
            self.context.UpdateSubresource(
                &surface.back_buffer,
                0,
                Some(&copy_box as *const D3D11_BOX),
                data.as_ptr() as *const core::ffi::c_void,
                row_pitch,
                0,
            );
        }
        Self::present_swap_chain(
            &surface.swap_chain,
            surface.allow_tearing,
            surface.present_mode,
        )
    }

    #[cfg(windows)]
    fn compile_shader(
        source: &str,
        target: &'static core::ffi::CStr,
    ) -> Result<Vec<u8>, RenderError> {
        use windows::core::PCSTR;
        use windows::Win32::Graphics::Direct3D::{Fxc::D3DCompile, ID3DBlob, ID3DInclude};

        let mut code = None::<ID3DBlob>;
        let mut errors = None::<ID3DBlob>;
        let result = unsafe {
            D3DCompile(
                source.as_ptr() as *const core::ffi::c_void,
                source.len(),
                PCSTR::null(),
                None,
                None::<&ID3DInclude>,
                PCSTR(c"main".as_ptr().cast()),
                PCSTR(target.as_ptr().cast()),
                0,
                0,
                &mut code,
                Some(&mut errors),
            )
        };

        if let Err(error) = result {
            let details = errors
                .as_ref()
                .map(|blob| unsafe {
                    let bytes = core::slice::from_raw_parts(
                        blob.GetBufferPointer() as *const u8,
                        blob.GetBufferSize(),
                    );
                    String::from_utf8_lossy(bytes).trim().to_string()
                })
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| error.to_string());
            return Err(RenderError::Message(format!(
                "compile D3D11 shared NV12 shader failed: {details}"
            )));
        }

        let code = code.ok_or_else(|| RenderError::Message("missing shader bytecode".into()))?;
        let bytes = unsafe {
            core::slice::from_raw_parts(code.GetBufferPointer() as *const u8, code.GetBufferSize())
        };
        Ok(bytes.to_vec())
    }

    #[cfg(windows)]
    fn create_shared_nv12_pipeline(&self) -> Result<SharedNv12Pipeline, RenderError> {
        use windows::Win32::Graphics::Direct3D11::{
            ID3D11ClassLinkage, ID3D11PixelShader, ID3D11SamplerState, ID3D11VertexShader,
            D3D11_COMPARISON_NEVER, D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_SAMPLER_DESC,
            D3D11_TEXTURE_ADDRESS_CLAMP,
        };

        let vertex_code = Self::compile_shader(SHARED_NV12_VERTEX_SHADER, c"vs_5_0")?;
        let pixel_code = Self::compile_shader(SHARED_NV12_PIXEL_SHADER, c"ps_5_0")?;

        let mut vertex_shader = None::<ID3D11VertexShader>;
        let mut pixel_shader = None::<ID3D11PixelShader>;
        unsafe {
            self.device
                .CreateVertexShader(
                    &vertex_code,
                    None::<&ID3D11ClassLinkage>,
                    Some(&mut vertex_shader),
                )
                .map_err(|error| {
                    RenderError::Message(format!(
                        "create shared NV12 vertex shader failed: {error}"
                    ))
                })?;
            self.device
                .CreatePixelShader(
                    &pixel_code,
                    None::<&ID3D11ClassLinkage>,
                    Some(&mut pixel_shader),
                )
                .map_err(|error| {
                    RenderError::Message(format!("create shared NV12 pixel shader failed: {error}"))
                })?;
        }

        let sampler_desc = D3D11_SAMPLER_DESC {
            Filter: D3D11_FILTER_MIN_MAG_MIP_LINEAR,
            AddressU: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressV: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressW: D3D11_TEXTURE_ADDRESS_CLAMP,
            MipLODBias: 0.0,
            MaxAnisotropy: 1,
            ComparisonFunc: D3D11_COMPARISON_NEVER,
            BorderColor: [0.0, 0.0, 0.0, 0.0],
            MinLOD: 0.0,
            MaxLOD: f32::MAX,
        };
        let mut sampler = None::<ID3D11SamplerState>;
        unsafe {
            self.device
                .CreateSamplerState(&sampler_desc, Some(&mut sampler))
                .map_err(|error| {
                    RenderError::Message(format!("create shared NV12 sampler failed: {error}"))
                })?;
        }

        Ok(SharedNv12Pipeline {
            vertex_shader: vertex_shader
                .ok_or_else(|| RenderError::Message("missing vertex shader".into()))?,
            pixel_shader: pixel_shader
                .ok_or_else(|| RenderError::Message("missing pixel shader".into()))?,
            sampler: sampler.ok_or_else(|| RenderError::Message("missing sampler".into()))?,
        })
    }

    #[cfg(windows)]
    fn ensure_shared_nv12_pipeline(&mut self) -> Result<&SharedNv12Pipeline, RenderError> {
        if self.shared_nv12_pipeline.is_none() {
            self.shared_nv12_pipeline = Some(self.create_shared_nv12_pipeline()?);
        }
        Ok(self.shared_nv12_pipeline.as_ref().unwrap())
    }

    #[cfg(windows)]
    fn open_shared_texture(
        &self,
        shared_handle: isize,
    ) -> Result<windows::Win32::Graphics::Direct3D11::ID3D11Texture2D, RenderError> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;

        if shared_handle == 0 {
            return Err(RenderError::Message("shared texture handle is zero".into()));
        }

        let mut texture = None::<ID3D11Texture2D>;
        unsafe {
            self.device
                .OpenSharedResource(HANDLE(shared_handle), &mut texture)
                .map_err(|error| {
                    RenderError::Message(format!("open shared D3D11 texture failed: {error}"))
                })?;
        }
        texture.ok_or_else(|| RenderError::Message("missing shared texture".into()))
    }

    #[cfg(windows)]
    fn open_shared_texture_srv(
        &self,
        shared_handle: isize,
    ) -> Result<windows::Win32::Graphics::Direct3D11::ID3D11ShaderResourceView, RenderError> {
        use windows::Win32::Graphics::Direct3D11::{ID3D11Resource, ID3D11ShaderResourceView};

        let texture = self.open_shared_texture(shared_handle)?;
        let resource: ID3D11Resource = texture.cast().map_err(|error| {
            RenderError::Message(format!("cast shared texture to resource failed: {error}"))
        })?;

        let mut srv = None::<ID3D11ShaderResourceView>;
        unsafe {
            self.device
                .CreateShaderResourceView(&resource, None, Some(&mut srv))
                .map_err(|error| {
                    RenderError::Message(format!("create shared texture SRV failed: {error}"))
                })?;
        }
        srv.ok_or_else(|| RenderError::Message("missing shared texture SRV".into()))
    }

    #[cfg(windows)]
    fn shared_bgra_resource(
        &mut self,
        shared_handle: isize,
    ) -> Result<windows::Win32::Graphics::Direct3D11::ID3D11Resource, RenderError> {
        if let Some(position) = self
            .shared_bgra_resource_cache
            .iter()
            .position(|cache| cache.shared_handle == shared_handle)
        {
            let cache = self.shared_bgra_resource_cache.remove(position);
            let resource = cache.resource.clone();
            self.shared_bgra_resource_cache.push(cache);
            return Ok(resource);
        }

        let texture = self.open_shared_texture(shared_handle)?;
        let resource: windows::Win32::Graphics::Direct3D11::ID3D11Resource =
            texture.cast().map_err(|error| {
                RenderError::Message(format!(
                    "cast shared BGRA texture to resource failed: {error}"
                ))
            })?;
        self.shared_bgra_resource_cache
            .push(SharedBgraResourceCache {
                shared_handle,
                resource: resource.clone(),
            });
        while self.shared_bgra_resource_cache.len() > SHARED_BGRA_RESOURCE_CACHE_LIMIT {
            self.shared_bgra_resource_cache.remove(0);
        }

        Ok(resource)
    }

    #[cfg(windows)]
    fn shared_nv12_srvs(
        &mut self,
        y_handle: isize,
        uv_handle: isize,
    ) -> Result<
        (
            windows::Win32::Graphics::Direct3D11::ID3D11ShaderResourceView,
            windows::Win32::Graphics::Direct3D11::ID3D11ShaderResourceView,
        ),
        RenderError,
    > {
        if let Some(position) = self
            .shared_nv12_srv_cache
            .iter()
            .position(|cache| cache.y_handle == y_handle && cache.uv_handle == uv_handle)
        {
            let cache = self.shared_nv12_srv_cache.remove(position);
            let result = (cache.y_srv.clone(), cache.uv_srv.clone());
            self.shared_nv12_srv_cache.push(cache);
            return Ok(result);
        }

        let y_srv = self.open_shared_texture_srv(y_handle)?;
        let uv_srv = self.open_shared_texture_srv(uv_handle)?;
        self.shared_nv12_srv_cache.push(SharedNv12SrvCache {
            y_handle,
            uv_handle,
            y_srv: y_srv.clone(),
            uv_srv: uv_srv.clone(),
        });
        while self.shared_nv12_srv_cache.len() > SHARED_NV12_SRV_CACHE_LIMIT {
            self.shared_nv12_srv_cache.remove(0);
        }

        Ok((y_srv, uv_srv))
    }

    #[cfg(windows)]
    fn present_shared_bgra_frame(
        &mut self,
        frame: &RenderFrame,
    ) -> Result<D3d11PresentStatus, RenderError> {
        use mrd_render::RenderFrameData;
        use windows::Win32::Graphics::Direct3D11::{ID3D11Resource, D3D11_BOX};

        let Some(surface) = self.surface.as_ref() else {
            return Ok(D3d11PresentStatus::NoTarget);
        };
        let surface_width = surface.width;
        let surface_height = surface.height;
        let back_buffer = surface.back_buffer.clone();
        let swap_chain = surface.swap_chain.clone();
        let allow_tearing = surface.allow_tearing;
        let present_mode = surface.present_mode;

        let shared_handle = match &frame.data {
            RenderFrameData::D3D11SharedBgra { shared_handle, .. } => *shared_handle,
            _ => {
                return Err(RenderError::Message(
                    "Expected D3D11SharedBgra frame data".into(),
                ))
            }
        };

        let shared_started = std::time::Instant::now();
        let source_resource = self.shared_bgra_resource(shared_handle)?;
        self.last_render_shared_resource_ms = Some(Self::duration_ms(shared_started.elapsed()));
        let target_resource: ID3D11Resource = back_buffer.cast().map_err(|error| {
            RenderError::Message(format!("cast back buffer to resource failed: {error}"))
        })?;

        let copy_width = frame.width.min(surface_width as usize);
        let copy_height = frame.height.min(surface_height as usize);
        if copy_width == 0 || copy_height == 0 {
            return Ok(D3d11PresentStatus::NoTarget);
        }

        let draw_started = std::time::Instant::now();
        unsafe {
            if frame.width == surface_width as usize && frame.height == surface_height as usize {
                self.context
                    .CopyResource(&target_resource, &source_resource);
            } else {
                let source_box = D3D11_BOX {
                    left: 0,
                    top: 0,
                    front: 0,
                    right: copy_width as u32,
                    bottom: copy_height as u32,
                    back: 1,
                };
                self.context.CopySubresourceRegion(
                    &target_resource,
                    0,
                    0,
                    0,
                    0,
                    &source_resource,
                    0,
                    Some(&source_box),
                );
            }
        }
        let present_status = Self::present_swap_chain(&swap_chain, allow_tearing, present_mode)?;
        self.last_render_draw_present_ms = Some(Self::duration_ms(draw_started.elapsed()));
        Ok(present_status)
    }

    #[cfg(windows)]
    fn present_shared_texture_frame(
        &mut self,
        frame: &RenderFrame,
    ) -> Result<D3d11PresentStatus, RenderError> {
        use mrd_render::RenderFrameData;
        use windows::Win32::Graphics::Direct3D::D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST;
        use windows::Win32::Graphics::Direct3D11::{ID3D11ShaderResourceView, D3D11_VIEWPORT};

        let Some(surface) = self.surface.as_ref() else {
            return Ok(D3d11PresentStatus::NoTarget);
        };

        let (shared_handle_y, shared_handle_uv) = match &frame.data {
            RenderFrameData::D3D11SharedNv12 {
                shared_handle_y,
                shared_handle_uv,
                width: _,
                height: _,
            }
            | RenderFrameData::D3D11SharedP010 {
                shared_handle_y,
                shared_handle_uv,
                width: _,
                height: _,
            } => (*shared_handle_y, *shared_handle_uv),
            _ => {
                return Err(RenderError::Message(
                    "Expected D3D11SharedNv12 or D3D11SharedP010 frame data".into(),
                ))
            }
        };

        let surface_width = surface.width;
        let surface_height = surface.height;
        let render_target_view = surface.render_target_view.clone();
        let swap_chain = surface.swap_chain.clone();
        let allow_tearing = surface.allow_tearing;
        let present_mode = surface.present_mode;
        let shared_started = std::time::Instant::now();
        let (y_srv, uv_srv) = self.shared_nv12_srvs(shared_handle_y, shared_handle_uv)?;
        let (vertex_shader, pixel_shader, sampler) = {
            let pipeline = self.ensure_shared_nv12_pipeline()?;
            (
                pipeline.vertex_shader.clone(),
                pipeline.pixel_shader.clone(),
                pipeline.sampler.clone(),
            )
        };
        self.last_render_shared_resource_ms = Some(Self::duration_ms(shared_started.elapsed()));

        let (viewport_x, viewport_y, viewport_width, viewport_height) =
            fit_viewport_rect(surface_width, surface_height, frame.width, frame.height);
        let viewport = D3D11_VIEWPORT {
            TopLeftX: viewport_x,
            TopLeftY: viewport_y,
            Width: viewport_width,
            Height: viewport_height,
            MinDepth: 0.0,
            MaxDepth: 1.0,
        };
        let srvs = [Some(y_srv), Some(uv_srv)];
        let samplers = [Some(sampler)];
        let empty_srvs: [Option<ID3D11ShaderResourceView>; 2] = [None, None];

        let draw_started = std::time::Instant::now();
        unsafe {
            if should_clear_shared_present_surface(
                surface_width,
                surface_height,
                frame.width,
                frame.height,
            ) {
                let clear = [0.0_f32, 0.0, 0.0, 1.0];
                self.context
                    .ClearRenderTargetView(&render_target_view, &clear);
            }
            self.context
                .OMSetRenderTargets(Some(&[Some(render_target_view)]), None);
            self.context.RSSetViewports(Some(&[viewport]));
            self.context
                .IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            self.context.VSSetShader(&vertex_shader, None);
            self.context.PSSetShader(&pixel_shader, None);
            self.context.PSSetSamplers(0, Some(&samplers));
            self.context.PSSetShaderResources(0, Some(&srvs));
            self.context.Draw(3, 0);
            self.context.PSSetShaderResources(0, Some(&empty_srvs));
        }
        let present_status = Self::present_swap_chain(&swap_chain, allow_tearing, present_mode)?;
        self.last_render_draw_present_ms = Some(Self::duration_ms(draw_started.elapsed()));
        Ok(present_status)
    }
}

#[cfg(windows)]
fn should_clear_shared_present_surface(
    surface_width: u32,
    surface_height: u32,
    frame_width: usize,
    frame_height: usize,
) -> bool {
    let (x, y, width, height) =
        fit_viewport_rect(surface_width, surface_height, frame_width, frame_height);
    let epsilon = 0.5_f32;
    x.abs() > epsilon
        || y.abs() > epsilon
        || ((surface_width as f32) - width).abs() > epsilon
        || ((surface_height as f32) - height).abs() > epsilon
}

impl RendererInstance for D3d11Renderer {
    fn attach_target(&mut self, target: RenderTarget) -> Result<(), RenderError> {
        #[cfg(windows)]
        {
            self.surface = match target {
                RenderTarget::WindowHandle(window_handle) => {
                    self.attach_window_surface(window_handle)?
                }
            };
        }

        self.attached_to_target = true;
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), RenderError> {
        #[cfg(not(windows))]
        {
            let _ = frame;
            return Err(RenderError::Message(
                "d3d11 renderer 仅支持 Windows".to_string(),
            ));
        }

        #[cfg(windows)]
        {
            use mrd_render::RenderFrameData;
            self.reset_last_render_breakdown();
            let prepare_started = std::time::Instant::now();
            let waitable_skip = self.prepare_waitable_frame_latency()?;
            self.last_render_prepare_wait_ms = Some(Self::duration_ms(prepare_started.elapsed()));
            if let Some(present_status) = waitable_skip {
                self.present_skipped_count += 1;
                self.last_present_status = Some(present_status.as_str());
                self.last_width = frame.width;
                self.last_height = frame.height;
                self.last_pixel_format = Some(frame.pixel_format);
                return Ok(());
            }
            self.last_render_shared_resource_ms = Some(0.0);

            let present_status = match &frame.data {
                RenderFrameData::Rgb24(_) => {
                    if self.surface.is_some() {
                        self.record_draw_present(|renderer| {
                            renderer.present_uploaded_frame(&frame)
                        })?
                    } else {
                        self.record_draw_present(|renderer| renderer.present_clear_frame(&frame))?
                    }
                }
                RenderFrameData::Bgra32(_) => {
                    if self.surface.is_some() {
                        self.record_draw_present(|renderer| {
                            renderer.present_uploaded_frame_bgra(&frame)
                        })?
                    } else {
                        self.record_draw_present(|renderer| renderer.present_clear_frame(&frame))?
                    }
                }
                RenderFrameData::Nv12 { .. } | RenderFrameData::Nv12Bytes { .. } => {
                    return Err(RenderError::Message(
                        "D3D11 renderer does not accept CPU NV12 frame data".to_string(),
                    ));
                }
                #[cfg(windows)]
                RenderFrameData::D3D11SharedBgra { .. } => {
                    if self.surface.is_some() {
                        self.present_shared_bgra_frame(&frame)?
                    } else {
                        self.record_draw_present(|renderer| renderer.present_clear_frame(&frame))?
                    }
                }
                #[cfg(windows)]
                RenderFrameData::D3D11SharedNv12 { .. }
                | RenderFrameData::D3D11SharedP010 { .. } => {
                    if self.surface.is_some() {
                        self.present_shared_texture_frame(&frame)?
                    } else {
                        self.record_draw_present(|renderer| renderer.present_clear_frame(&frame))?
                    }
                }
            };

            self.uploaded_frame_count += 1;
            match present_status {
                D3d11PresentStatus::Presented => {
                    self.presented_frame_count += 1;
                    if self.present_events.len() == 64 {
                        self.present_events.pop_front();
                    }
                    self.present_events.push_back(RendererPresentEvent {
                        ordinal: self.presented_frame_count,
                        presented_at: std::time::Instant::now(),
                    });
                }
                D3d11PresentStatus::SkippedStillDrawing
                | D3d11PresentStatus::SkippedFrameLatencyWait => {
                    self.present_skipped_count += 1;
                }
                D3d11PresentStatus::NoTarget => {}
            }
            self.last_present_status = Some(present_status.as_str());
            self.last_width = frame.width;
            self.last_height = frame.height;
            self.last_pixel_format = Some(frame.pixel_format);
            Ok(())
        }
    }

    fn snapshot(&self) -> RendererSnapshot {
        #[cfg(windows)]
        let swap_chain_max_frame_latency = self
            .surface
            .as_ref()
            .and_then(|surface| surface.max_frame_latency);
        #[cfg(windows)]
        let swap_chain_allow_tearing = self.surface.as_ref().map(|surface| surface.allow_tearing);
        #[cfg(windows)]
        let swap_chain_waitable_object =
            self.surface.as_ref().map(|surface| surface.waitable_object);
        #[cfg(windows)]
        let swap_chain_present_mode = self
            .surface
            .as_ref()
            .map(|surface| surface.present_mode.as_str().to_string());
        #[cfg(windows)]
        let display_refresh_hz = self
            .surface
            .as_ref()
            .and_then(|surface| surface.display_refresh_hz);
        #[cfg(windows)]
        let render_thread_priority = Some(Self::current_thread_priority_label().to_string());
        #[cfg(windows)]
        let waitable_wait_count = Some(self.waitable_wait_count);
        #[cfg(windows)]
        let waitable_wait_total_ms = Some(self.waitable_wait_total_ms);
        #[cfg(windows)]
        let waitable_timeout_count = Some(self.waitable_timeout_count);
        #[cfg(windows)]
        let last_waitable_wait_ms = self.last_waitable_wait_ms;
        #[cfg(not(windows))]
        let swap_chain_max_frame_latency = None;
        #[cfg(not(windows))]
        let swap_chain_allow_tearing = None;
        #[cfg(not(windows))]
        let swap_chain_waitable_object = None;
        #[cfg(not(windows))]
        let swap_chain_present_mode = None;
        #[cfg(not(windows))]
        let display_refresh_hz = None;
        #[cfg(not(windows))]
        let render_thread_priority = None;
        #[cfg(not(windows))]
        let waitable_wait_count = None;
        #[cfg(not(windows))]
        let waitable_wait_total_ms = None;
        #[cfg(not(windows))]
        let waitable_timeout_count = None;
        #[cfg(not(windows))]
        let last_waitable_wait_ms = None;

        RendererSnapshot {
            attached_to_target: self.attached_to_target,
            uploaded_frame_count: self.uploaded_frame_count,
            presented_frame_count: self.presented_frame_count,
            present_skipped_count: self.present_skipped_count,
            render_queue_replacements: None,
            last_present_status: self.last_present_status.map(str::to_string),
            #[cfg(windows)]
            low_latency_frame_latency_target: Some(Self::low_latency_frame_latency_target()),
            #[cfg(not(windows))]
            low_latency_frame_latency_target: None,
            swap_chain_max_frame_latency,
            swap_chain_allow_tearing,
            swap_chain_waitable_object,
            swap_chain_present_mode,
            display_refresh_hz,
            render_thread_priority,
            waitable_wait_count,
            waitable_wait_total_ms,
            waitable_timeout_count,
            last_waitable_wait_ms,
            last_render_prepare_wait_ms: self.last_render_prepare_wait_ms,
            last_render_shared_resource_ms: self.last_render_shared_resource_ms,
            last_render_wait_for_drawable_ms: None,
            last_render_encode_commit_ms: None,
            last_render_draw_present_ms: self.last_render_draw_present_ms,
            last_width: self.last_width,
            last_height: self.last_height,
            last_pixel_format: self.last_pixel_format,
        }
    }

    fn drain_present_events(&mut self) -> Vec<RendererPresentEvent> {
        self.present_events.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{fit_viewport_rect, D3d11RendererFactory};
    #[cfg(windows)]
    use super::{
        should_clear_shared_present_surface, D3d11PresentMode, D3d11PresentStatus, D3d11Renderer,
    };
    use mrd_render::{
        RenderFrame, RenderPixelFormat, RenderTarget, RendererFactory, RendererInstance,
    };

    #[test]
    fn fit_viewport_rect_preserves_source_aspect_ratio() {
        let viewport = fit_viewport_rect(1200, 1200, 1920, 1080);

        assert_eq!(viewport, (0.0, 262.5, 1200.0, 675.0));
    }

    #[cfg(windows)]
    #[test]
    fn shared_present_clears_only_when_letterboxed() {
        assert!(!should_clear_shared_present_surface(1920, 1080, 1920, 1080));
        assert!(should_clear_shared_present_surface(
            1920,
            1080,
            2560,
            1440 + 120
        ));
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_present_status_labels_are_stable_for_metrics() {
        assert_eq!(D3d11PresentStatus::Presented.as_str(), "presented");
        assert_eq!(
            D3d11PresentStatus::SkippedStillDrawing.as_str(),
            "skipped_still_drawing"
        );
        assert_eq!(D3d11PresentStatus::NoTarget.as_str(), "no_target");
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_renderer_defaults_to_nonblocking_present() {
        use windows::Win32::Graphics::Dxgi::{
            DXGI_PRESENT_ALLOW_TEARING, DXGI_PRESENT_DO_NOT_WAIT,
        };

        std::env::remove_var("MRD_D3D11_RENDER_PRESENT_BLOCKING");
        assert_eq!(
            D3d11Renderer::present_flags(D3d11PresentMode::Nonblocking, false),
            DXGI_PRESENT_DO_NOT_WAIT
        );
        assert_eq!(
            D3d11Renderer::present_flags(D3d11PresentMode::Nonblocking, true),
            DXGI_PRESENT_DO_NOT_WAIT | DXGI_PRESENT_ALLOW_TEARING
        );

        std::env::set_var("MRD_D3D11_RENDER_PRESENT_BLOCKING", "1");
        assert_eq!(
            D3d11Renderer::present_flags(D3d11PresentMode::Blocking, false),
            0
        );
        assert_eq!(
            D3d11Renderer::present_flags(D3d11PresentMode::Blocking, true),
            0
        );
        std::env::remove_var("MRD_D3D11_RENDER_PRESENT_BLOCKING");
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_renderer_allows_max_frame_latency_override_for_perf_debugging() {
        std::env::remove_var("MRD_D3D11_RENDER_MAX_FRAME_LATENCY");
        assert_eq!(D3d11Renderer::max_frame_latency_target(), Some(1));

        std::env::set_var("MRD_D3D11_RENDER_MAX_FRAME_LATENCY", "0");
        assert_eq!(D3d11Renderer::max_frame_latency_target(), None);

        std::env::set_var("MRD_D3D11_RENDER_MAX_FRAME_LATENCY", "2");
        assert_eq!(D3d11Renderer::max_frame_latency_target(), Some(2));
        std::env::remove_var("MRD_D3D11_RENDER_MAX_FRAME_LATENCY");
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_renderer_reports_low_latency_frame_latency_target() {
        let factory = D3d11RendererFactory;
        let renderer = factory.create().expect("d3d11 renderer");

        let snapshot = renderer.snapshot();

        assert_eq!(snapshot.low_latency_frame_latency_target, Some(1));
        assert_eq!(snapshot.swap_chain_max_frame_latency, None);
        assert_eq!(snapshot.swap_chain_allow_tearing, None);
        assert_eq!(snapshot.swap_chain_waitable_object, None);
        assert_eq!(snapshot.swap_chain_present_mode, None);
        assert_eq!(snapshot.display_refresh_hz, None);
        assert_eq!(snapshot.render_thread_priority.as_deref(), Some("normal"));
        assert_eq!(snapshot.waitable_wait_count, Some(0));
        assert_eq!(snapshot.waitable_wait_total_ms, Some(0.0));
        assert_eq!(snapshot.waitable_timeout_count, Some(0));
        assert_eq!(snapshot.last_waitable_wait_ms, None);
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_records_waitable_wait_metrics_for_snapshots() {
        let mut renderer = D3d11Renderer::new().expect("d3d11 renderer");

        renderer.record_waitable_wait_metrics(0.75, false);
        renderer.record_waitable_wait_metrics(1.25, true);

        let snapshot = renderer.snapshot();

        assert_eq!(snapshot.waitable_wait_count, Some(2));
        assert_eq!(snapshot.waitable_wait_total_ms, Some(2.0));
        assert_eq!(snapshot.waitable_timeout_count, Some(1));
        assert_eq!(snapshot.last_waitable_wait_ms, Some(1.25));
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_swap_chain_desc_keeps_waitable_object_off_for_nonblocking_present() {
        use windows::Win32::Graphics::Dxgi::DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;

        let desc = D3d11Renderer::window_swap_chain_desc(16, 16, false, false);

        assert_eq!(
            desc.Flags & DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT.0 as u32,
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_swap_chain_desc_enables_waitable_object_when_requested() {
        use windows::Win32::Graphics::Dxgi::DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;

        let desc = D3d11Renderer::window_swap_chain_desc(16, 16, false, true);

        assert_ne!(
            desc.Flags & DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT.0 as u32,
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_present_mode_uses_waitable_object_when_requested() {
        std::env::remove_var("MRD_D3D11_RENDER_PRESENT_BLOCKING");
        std::env::remove_var("MRD_D3D11_RENDER_WAITABLE_OBJECT");
        assert_eq!(D3d11Renderer::present_mode().as_str(), "nonblocking");

        std::env::set_var("MRD_D3D11_RENDER_WAITABLE_OBJECT", "1");
        assert_eq!(D3d11Renderer::present_mode().as_str(), "waitable");

        std::env::set_var("MRD_D3D11_RENDER_PRESENT_BLOCKING", "1");
        assert_eq!(D3d11Renderer::present_mode().as_str(), "blocking");
        std::env::remove_var("MRD_D3D11_RENDER_PRESENT_BLOCKING");
        std::env::remove_var("MRD_D3D11_RENDER_WAITABLE_OBJECT");
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_waitable_object_requires_valid_handle() {
        use windows::Win32::Foundation::HANDLE;

        let err = D3d11Renderer::validated_frame_latency_waitable_object(HANDLE(0))
            .expect_err("zero waitable handle must fail");

        assert!(err
            .to_string()
            .contains("DXGI frame latency waitable object was not created"));
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_render_thread_priority_env_accepts_safe_opt_in_values() {
        std::env::remove_var("MRD_RENDER_THREAD_PRIORITY");
        assert_eq!(D3d11Renderer::render_thread_priority_from_env(), None);

        std::env::set_var("MRD_RENDER_THREAD_PRIORITY", "above_normal");
        assert_eq!(
            D3d11Renderer::render_thread_priority_from_env(),
            Some((
                "above_normal",
                windows::Win32::System::Threading::THREAD_PRIORITY_ABOVE_NORMAL
            ))
        );

        std::env::set_var("MRD_RENDER_THREAD_PRIORITY", "highest");
        assert_eq!(
            D3d11Renderer::render_thread_priority_from_env(),
            Some((
                "highest",
                windows::Win32::System::Threading::THREAD_PRIORITY_HIGHEST
            ))
        );

        std::env::set_var("MRD_RENDER_THREAD_PRIORITY", "time_critical");
        assert_eq!(D3d11Renderer::render_thread_priority_from_env(), None);
        std::env::remove_var("MRD_RENDER_THREAD_PRIORITY");
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_swap_chain_desc_enables_tearing_when_supported() {
        use windows::Win32::Graphics::Dxgi::DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;

        let desc = D3d11Renderer::window_swap_chain_desc(16, 16, true, false);

        assert_ne!(desc.Flags & DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING.0 as u32, 0);
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_factory_creates_backend_and_tracks_uploads() {
        let factory = D3d11RendererFactory;
        let mut renderer = factory.create().expect("d3d11 renderer");

        renderer
            .attach_target(RenderTarget::WindowHandle(0))
            .expect("attach target");
        renderer
            .upload_frame(RenderFrame::from_rgb24(16, 16, vec![128; 16 * 16 * 3]))
            .expect("upload frame");

        let snapshot = renderer.snapshot();
        assert!(snapshot.attached_to_target);
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(snapshot.presented_frame_count, 0);
        assert_eq!(snapshot.present_skipped_count, 0);
        assert_eq!(snapshot.last_present_status.as_deref(), Some("no_target"));
        assert_eq!(snapshot.last_width, 16);
        assert_eq!(snapshot.last_height, 16);
        assert_eq!(snapshot.last_pixel_format, Some(RenderPixelFormat::Rgb24));
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_renderer_tracks_shared_bgra_upload_without_cpu_readback() {
        let factory = D3d11RendererFactory;
        let mut renderer = factory.create().expect("d3d11 renderer");

        renderer
            .upload_frame(RenderFrame::from_d3d11_shared_bgra(16, 16, 42, 16 * 4))
            .expect("upload shared bgra frame");

        let snapshot = renderer.snapshot();
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(
            snapshot.last_pixel_format,
            Some(RenderPixelFormat::D3D11SharedBgra)
        );
    }

    #[cfg(windows)]
    #[test]
    fn d3d11_renderer_exposes_device_pointer_for_same_device_decode() {
        let renderer = D3d11Renderer::new().expect("d3d11 renderer");

        assert_ne!(renderer.device_ptr(), core::ptr::null_mut());
    }

    #[cfg(not(windows))]
    #[test]
    fn d3d11_factory_reports_platform_error_off_windows() {
        let factory = D3d11RendererFactory;
        let error = match factory.create() {
            Ok(_) => panic!("expected platform error"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("Windows"));
    }
}
