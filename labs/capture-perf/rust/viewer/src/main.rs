use serde::Serialize;
use std::ffi::c_void;
use std::fs::File;
use std::mem::{size_of, transmute_copy, zeroed, ManuallyDrop};
use std::path::{Path, PathBuf};
use std::ptr::addr_of_mut;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::core::{w, Interface, PCSTR, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HINSTANCE, HMODULE, HWND, LPARAM, LRESULT, RECT, S_FALSE, S_OK, WPARAM,
};
use windows::Win32::Graphics::Direct3D::Fxc::D3DCompile;
use windows::Win32::Graphics::Direct3D::{
    ID3DBlob, D3D11_SRV_DIMENSION_TEXTURE2D, D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_UNKNOWN,
    D3D_FEATURE_LEVEL, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
    D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP,
};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Direct3D12::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows_capture::capture::{Context, GraphicsCaptureApiHandler};
use windows_capture::frame::Frame;
use windows_capture::graphics_capture_api::InternalCaptureControl;
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
    MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
};

const WINDOW_WIDTH: i32 = 1280;
const WINDOW_HEIGHT: i32 = 720;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureSourceKind {
    DesktopDuplication,
    WindowsGraphicsCapture,
    SharedMemoryDesktopDuplication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RendererKind {
    D3D11,
    D3D12,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ViewerOptions {
    source: CaptureSourceKind,
    renderer: RendererKind,
    duration_secs: u64,
}

impl Default for ViewerOptions {
    fn default() -> Self {
        Self {
            source: CaptureSourceKind::DesktopDuplication,
            renderer: RendererKind::D3D11,
            duration_secs: 0,
        }
    }
}

fn parse_args<I, S>(args: I) -> ViewerOptions
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut options = ViewerOptions::default();
    let mut iter = args.into_iter().skip(1).peekable();

    while let Some(arg) = iter.next() {
        let arg = arg.as_ref().to_string();
        let (key, inline_value) = match arg.split_once('=') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (arg, None),
        };

        match key.as_str() {
            "--source" => {
                let value = inline_value.or_else(|| iter.next().map(|v| v.as_ref().to_string()));
                if let Some(value) = value {
                    options.source = match value.as_str() {
                        "wgc" | "graphics-capture" => CaptureSourceKind::WindowsGraphicsCapture,
                        "shared-memory" | "shared" => {
                            CaptureSourceKind::SharedMemoryDesktopDuplication
                        }
                        _ => CaptureSourceKind::DesktopDuplication,
                    };
                }
            }
            "--renderer" => {
                let value = inline_value.or_else(|| iter.next().map(|v| v.as_ref().to_string()));
                options.renderer = match value.as_deref() {
                    Some("d3d12") => RendererKind::D3D12,
                    _ => RendererKind::D3D11,
                };
            }
            "--duration" => {
                let value = inline_value.or_else(|| iter.next().map(|v| v.as_ref().to_string()));
                if let Some(value) = value {
                    options.duration_secs = value.parse().unwrap_or(0);
                }
            }
            _ => {}
        }
    }

    options
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FrameStatus {
    Captured,
    Timeout,
    AccessLost,
    Error,
}

impl FrameStatus {
    fn as_str(self) -> &'static str {
        match self {
            FrameStatus::Captured => "captured",
            FrameStatus::Timeout => "timeout",
            FrameStatus::AccessLost => "access_lost",
            FrameStatus::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
struct CaptureFrame {
    status: FrameStatus,
    texture: Option<ID3D11Texture2D>,
    capture_time_ms: f64,
    hr: i32,
}

impl CaptureFrame {
    fn timeout() -> Self {
        Self {
            status: FrameStatus::Timeout,
            texture: None,
            capture_time_ms: 0.0,
            hr: DXGI_ERROR_WAIT_TIMEOUT.0,
        }
    }

    fn error(hr: i32) -> Self {
        Self {
            status: FrameStatus::Error,
            texture: None,
            capture_time_ms: 0.0,
            hr,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct FrameMetrics {
    frame_number: u64,
    status: String,
    capture_time_ms: f64,
    render_time_ms: f64,
    present_time_ms: f64,
    total_time_ms: f64,
    fps: f64,
    memory_mb: f64,
    width: u32,
    height: u32,
}

#[derive(Debug, Clone, Serialize)]
struct Statistics {
    avg_capture_time_ms: f64,
    avg_render_time_ms: f64,
    avg_present_time_ms: f64,
    avg_total_time_ms: f64,
    avg_fps: f64,
    avg_memory_mb: f64,
    captured_frames: u64,
    timeout_frames: u64,
    access_lost_frames: u64,
    error_frames: u64,
}

#[derive(Debug, Clone)]
struct MetricsConfig {
    api: String,
    language: String,
    renderer: String,
    duration_sec: u64,
    width: u32,
    height: u32,
}

#[derive(Serialize)]
struct JsonConfig<'a> {
    api: &'a str,
    language: &'a str,
    renderer: &'a str,
    duration_sec: u64,
    width: u32,
    height: u32,
    total_frames: usize,
}

#[derive(Serialize)]
struct JsonResult<'a> {
    test_config: JsonConfig<'a>,
    statistics: Statistics,
}

struct MetricsCollector {
    config: MetricsConfig,
    frames: Vec<FrameMetrics>,
}

impl MetricsCollector {
    fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            frames: Vec::new(),
        }
    }

    fn record(&mut self, metrics: FrameMetrics) {
        self.frames.push(metrics);
    }

    fn statistics(&self) -> Statistics {
        if self.frames.is_empty() {
            return Statistics {
                avg_capture_time_ms: 0.0,
                avg_render_time_ms: 0.0,
                avg_present_time_ms: 0.0,
                avg_total_time_ms: 0.0,
                avg_fps: 0.0,
                avg_memory_mb: 0.0,
                captured_frames: 0,
                timeout_frames: 0,
                access_lost_frames: 0,
                error_frames: 0,
            };
        }

        let mut stats = Statistics {
            avg_capture_time_ms: 0.0,
            avg_render_time_ms: 0.0,
            avg_present_time_ms: 0.0,
            avg_total_time_ms: 0.0,
            avg_fps: 0.0,
            avg_memory_mb: 0.0,
            captured_frames: 0,
            timeout_frames: 0,
            access_lost_frames: 0,
            error_frames: 0,
        };

        for frame in &self.frames {
            stats.avg_capture_time_ms += frame.capture_time_ms;
            stats.avg_render_time_ms += frame.render_time_ms;
            stats.avg_present_time_ms += frame.present_time_ms;
            stats.avg_total_time_ms += frame.total_time_ms;
            stats.avg_fps += frame.fps;
            stats.avg_memory_mb += frame.memory_mb;

            match frame.status.as_str() {
                "captured" => stats.captured_frames += 1,
                "timeout" => stats.timeout_frames += 1,
                "access_lost" => stats.access_lost_frames += 1,
                _ => stats.error_frames += 1,
            }
        }

        let count = self.frames.len() as f64;
        stats.avg_capture_time_ms /= count;
        stats.avg_render_time_ms /= count;
        stats.avg_present_time_ms /= count;
        stats.avg_total_time_ms /= count;
        stats.avg_fps /= count;
        stats.avg_memory_mb /= count;
        stats
    }

    fn save(&self) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let results_dir = find_results_dir();
        std::fs::create_dir_all(&results_dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let stem = format!(
            "{}_rust_{}_{}_capture_render",
            timestamp, self.config.api, self.config.renderer
        );
        let csv_path = results_dir.join(format!("{}.csv", stem));
        let json_path = results_dir.join(format!("{}.json", stem));

        let mut writer = csv::Writer::from_path(&csv_path)?;
        writer.write_record([
            "timestamp",
            "api",
            "language",
            "renderer",
            "frame_number",
            "status",
            "capture_time_ms",
            "render_time_ms",
            "present_time_ms",
            "total_time_ms",
            "fps",
            "memory_mb",
            "width",
            "height",
        ])?;
        for frame in &self.frames {
            writer.write_record([
                timestamp.to_string(),
                self.config.api.clone(),
                self.config.language.clone(),
                self.config.renderer.clone(),
                frame.frame_number.to_string(),
                frame.status.clone(),
                format!("{:.3}", frame.capture_time_ms),
                format!("{:.3}", frame.render_time_ms),
                format!("{:.3}", frame.present_time_ms),
                format!("{:.3}", frame.total_time_ms),
                format!("{:.3}", frame.fps),
                format!("{:.3}", frame.memory_mb),
                frame.width.to_string(),
                frame.height.to_string(),
            ])?;
        }
        writer.flush()?;

        let (summary_width, summary_height) = self
            .frames
            .iter()
            .rev()
            .find(|frame| frame.width != 0 && frame.height != 0)
            .map(|frame| (frame.width, frame.height))
            .unwrap_or((self.config.width, self.config.height));

        let result = JsonResult {
            test_config: JsonConfig {
                api: &self.config.api,
                language: &self.config.language,
                renderer: &self.config.renderer,
                duration_sec: self.config.duration_sec,
                width: summary_width,
                height: summary_height,
                total_frames: self.frames.len(),
            },
            statistics: self.statistics(),
        };
        serde_json::to_writer_pretty(File::create(&json_path)?, &result)?;
        Ok((csv_path, json_path))
    }
}

trait CaptureSource {
    fn initialize(&mut self, device: &ID3D11Device) -> windows::core::Result<()>;
    fn acquire_next_frame(&mut self, timeout_ms: u32) -> CaptureFrame;
    fn release_frame(&mut self);
    fn reset(&mut self);
    fn width(&self) -> u32;
    fn height(&self) -> u32;
    fn api_name(&self) -> &'static str;
}

struct DesktopDuplicationSource {
    device: Option<ID3D11Device>,
    duplication: Option<IDXGIOutputDuplication>,
    acquired: bool,
    width: u32,
    height: u32,
}

impl DesktopDuplicationSource {
    fn new() -> Self {
        Self {
            device: None,
            duplication: None,
            acquired: false,
            width: 0,
            height: 0,
        }
    }
}

impl CaptureSource for DesktopDuplicationSource {
    fn initialize(&mut self, device: &ID3D11Device) -> windows::core::Result<()> {
        self.reset();
        unsafe {
            let dxgi_device: IDXGIDevice = device.cast()?;
            let adapter = dxgi_device.GetAdapter()?;
            let output = adapter.EnumOutputs(0)?;
            let desc = output.GetDesc()?;
            self.width = (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32;
            self.height = (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32;
            let output1: IDXGIOutput1 = output.cast()?;
            self.duplication = Some(output1.DuplicateOutput(device)?);
            self.device = Some(device.clone());
        }
        Ok(())
    }

    fn acquire_next_frame(&mut self, timeout_ms: u32) -> CaptureFrame {
        let Some(duplication) = &self.duplication else {
            return CaptureFrame {
                status: FrameStatus::AccessLost,
                texture: None,
                capture_time_ms: 0.0,
                hr: DXGI_ERROR_ACCESS_LOST.0,
            };
        };

        let start = Instant::now();
        unsafe {
            let mut frame_info = zeroed();
            let mut resource = None;
            match duplication.AcquireNextFrame(timeout_ms, &mut frame_info, &mut resource) {
                Ok(()) => {
                    self.acquired = true;
                    match resource.and_then(|r| r.cast::<ID3D11Texture2D>().ok()) {
                        Some(texture) => CaptureFrame {
                            status: FrameStatus::Captured,
                            texture: Some(texture),
                            capture_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                            hr: 0,
                        },
                        None => {
                            self.release_frame();
                            CaptureFrame::error(0)
                        }
                    }
                }
                Err(error) if error.code() == DXGI_ERROR_WAIT_TIMEOUT => CaptureFrame::timeout(),
                Err(error) if error.code() == DXGI_ERROR_ACCESS_LOST => {
                    self.reset();
                    CaptureFrame {
                        status: FrameStatus::AccessLost,
                        texture: None,
                        capture_time_ms: start.elapsed().as_secs_f64() * 1000.0,
                        hr: error.code().0,
                    }
                }
                Err(error) => CaptureFrame::error(error.code().0),
            }
        }
    }

    fn release_frame(&mut self) {
        if self.acquired {
            if let Some(duplication) = &self.duplication {
                unsafe {
                    let _ = duplication.ReleaseFrame();
                }
            }
            self.acquired = false;
        }
    }

    fn reset(&mut self) {
        self.release_frame();
        self.duplication = None;
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn api_name(&self) -> &'static str {
        "DesktopDuplication"
    }
}

struct SharedMemoryDesktopDuplicationSource {
    capture: DesktopDuplicationSource,
    device: Option<ID3D11Device>,
    context: Option<ID3D11DeviceContext>,
    staging: Option<ID3D11Texture2D>,
    output: Option<ID3D11Texture2D>,
    mapping: Option<windows::Win32::Foundation::HANDLE>,
    mapped: *mut u8,
    mapped_size: usize,
    width: u32,
    height: u32,
    format: DXGI_FORMAT,
}

impl SharedMemoryDesktopDuplicationSource {
    fn new() -> Self {
        Self {
            capture: DesktopDuplicationSource::new(),
            device: None,
            context: None,
            staging: None,
            output: None,
            mapping: None,
            mapped: std::ptr::null_mut(),
            mapped_size: 0,
            width: 0,
            height: 0,
            format: DXGI_FORMAT_UNKNOWN,
        }
    }

    fn ensure_buffers(&mut self, desc: &D3D11_TEXTURE2D_DESC) -> windows::core::Result<()> {
        if self.output.is_some()
            && self.width == desc.Width
            && self.height == desc.Height
            && self.format == desc.Format
        {
            return Ok(());
        }

        self.staging = None;
        self.output = None;
        self.close_mapping();

        let device = self.device.as_ref().unwrap();
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
            ..*desc
        };
        let mut staging = None;
        unsafe {
            device.CreateTexture2D(&staging_desc, None, Some(&mut staging))?;
        }

        let output_desc = D3D11_TEXTURE2D_DESC {
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
            ..*desc
        };
        let mut output = None;
        unsafe {
            device.CreateTexture2D(&output_desc, None, Some(&mut output))?;
        }

        let size = desc.Width as usize * desc.Height as usize * 4;
        let mapping = unsafe {
            CreateFileMappingW(
                windows::Win32::Foundation::INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                (size >> 32) as u32,
                (size & 0xffff_ffff) as u32,
                w!("Local\\CapTestRustCaptureRenderSharedMemory"),
            )?
        };
        let mapped = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size) };
        if mapped.Value.is_null() {
            unsafe {
                CloseHandle(mapping)?;
            }
            return Err(windows::core::Error::from_win32());
        }

        self.staging = staging;
        self.output = output;
        self.mapping = Some(mapping);
        self.mapped = mapped.Value.cast();
        self.mapped_size = size;
        self.width = desc.Width;
        self.height = desc.Height;
        self.format = desc.Format;
        Ok(())
    }

    fn close_mapping(&mut self) {
        unsafe {
            if !self.mapped.is_null() {
                let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.mapped.cast(),
                });
                self.mapped = std::ptr::null_mut();
            }
            if let Some(mapping) = self.mapping.take() {
                let _ = CloseHandle(mapping);
            }
        }
        self.mapped_size = 0;
    }
}

impl Drop for SharedMemoryDesktopDuplicationSource {
    fn drop(&mut self) {
        self.close_mapping();
    }
}

impl CaptureSource for SharedMemoryDesktopDuplicationSource {
    fn initialize(&mut self, device: &ID3D11Device) -> windows::core::Result<()> {
        self.reset();
        let context = unsafe { device.GetImmediateContext()? };
        self.context = Some(context);
        self.device = Some(device.clone());
        self.capture.initialize(device)
    }

    fn acquire_next_frame(&mut self, timeout_ms: u32) -> CaptureFrame {
        let source = self.capture.acquire_next_frame(timeout_ms);
        if source.status != FrameStatus::Captured {
            return source;
        }
        let Some(texture) = source.texture else {
            return CaptureFrame::error(0);
        };

        let copy_start = Instant::now();
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe {
            texture.GetDesc(&mut desc);
        }

        if self.ensure_buffers(&desc).is_err() {
            self.capture.release_frame();
            return CaptureFrame::error(0);
        }

        let context = self.context.as_ref().unwrap();
        let staging = self.staging.as_ref().unwrap();
        let output = self.output.as_ref().unwrap();
        unsafe {
            context.CopyResource(staging, &texture);
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            if context
                .Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .is_err()
            {
                self.capture.release_frame();
                return CaptureFrame::error(0);
            }

            let row_bytes = desc.Width as usize * 4;
            for row in 0..desc.Height as usize {
                std::ptr::copy_nonoverlapping(
                    (mapped.pData as *const u8).add(row * mapped.RowPitch as usize),
                    self.mapped.add(row * row_bytes),
                    row_bytes,
                );
            }
            context.Unmap(staging, 0);
            self.capture.release_frame();
            context.UpdateSubresource(
                output,
                0,
                None,
                self.mapped.cast::<c_void>(),
                row_bytes as u32,
                0,
            );
        }

        CaptureFrame {
            status: FrameStatus::Captured,
            texture: Some(output.clone()),
            capture_time_ms: source.capture_time_ms + copy_start.elapsed().as_secs_f64() * 1000.0,
            hr: 0,
        }
    }

    fn release_frame(&mut self) {}

    fn reset(&mut self) {
        self.capture.reset();
        self.staging = None;
        self.output = None;
        self.close_mapping();
    }

    fn width(&self) -> u32 {
        if self.width != 0 {
            self.width
        } else {
            self.capture.width()
        }
    }

    fn height(&self) -> u32 {
        if self.height != 0 {
            self.height
        } else {
            self.capture.height()
        }
    }

    fn api_name(&self) -> &'static str {
        "DesktopDuplicationSharedMemory"
    }
}

#[derive(Debug)]
struct WgcFrame {
    shared_handle: usize,
    width: u32,
    height: u32,
    capture_time_ms: f64,
}

static WGC_SENDER: OnceLock<Mutex<Option<mpsc::Sender<WgcFrame>>>> = OnceLock::new();

struct WgcHandler {
    shared_texture: Option<ID3D11Texture2D>,
    shared_copy_query: Option<ID3D11Query>,
    width: u32,
    height: u32,
    format: DXGI_FORMAT,
}

impl WgcHandler {
    fn ensure_shared_texture(
        &mut self,
        source_texture: &ID3D11Texture2D,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut source_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe {
            source_texture.GetDesc(&mut source_desc);
        }
        let format = normalize_texture_format(source_desc.Format);
        if self.shared_texture.is_some()
            && self.width == source_desc.Width
            && self.height == source_desc.Height
            && self.format == format
        {
            return Ok(());
        }

        self.shared_texture = None;
        self.shared_copy_query = None;

        unsafe {
            let device = source_texture.GetDevice()?;
            let shared_desc = D3D11_TEXTURE2D_DESC {
                Width: source_desc.Width,
                Height: source_desc.Height,
                MipLevels: 1,
                ArraySize: 1,
                Format: format,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: (D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET).0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: (D3D11_RESOURCE_MISC_SHARED_NTHANDLE
                    | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX)
                    .0 as u32,
            };
            let mut shared_texture = None;
            device
                .CreateTexture2D(&shared_desc, None, Some(&mut shared_texture))
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "WGC CreateTexture2D shared {}x{} format {:?} failed: {error}",
                            shared_desc.Width, shared_desc.Height, shared_desc.Format
                        ),
                    )
                })?;

            let query_desc = D3D11_QUERY_DESC {
                Query: D3D11_QUERY_EVENT,
                MiscFlags: 0,
            };
            let mut query = None;
            device
                .CreateQuery(&query_desc, Some(&mut query))
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("WGC CreateQuery failed: {error}"),
                    )
                })?;

            self.shared_texture = shared_texture;
            self.shared_copy_query = query;
            self.width = source_desc.Width;
            self.height = source_desc.Height;
            self.format = format;
        }

        Ok(())
    }
}

impl GraphicsCaptureApiHandler for WgcHandler {
    type Flags = ();
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn new(_ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
        Ok(Self {
            shared_texture: None,
            shared_copy_query: None,
            width: 0,
            height: 0,
            format: DXGI_FORMAT_UNKNOWN,
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut Frame,
        _capture_control: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        let start = Instant::now();
        let width = frame.width();
        let height = frame.height();
        let shared_handle = unsafe {
            let source_texture = frame.as_raw_texture().clone();
            self.ensure_shared_texture(&source_texture)?;
            let shared_texture = self.shared_texture.as_ref().unwrap();
            let query = self.shared_copy_query.as_ref().unwrap();
            let device = source_texture.GetDevice().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("WGC source GetDevice failed: {error}"),
                )
            })?;
            let context = device.GetImmediateContext().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("WGC GetImmediateContext failed: {error}"),
                )
            })?;
            context.CopyResource(shared_texture, &source_texture);
            context.End(query);
            loop {
                let hr = (Interface::vtable(&context).GetData)(
                    Interface::as_raw(&context),
                    Interface::as_raw(query),
                    std::ptr::null_mut(),
                    0,
                    0,
                );
                if hr == S_OK {
                    break;
                }
                if hr != S_FALSE {
                    hr.ok().map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("WGC D3D11 GetData failed: {error}"),
                        )
                    })?;
                    break;
                }
                std::thread::yield_now();
            }

            let dxgi_resource: IDXGIResource1 = shared_texture.cast().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("WGC shared texture IDXGIResource1 cast failed: {error}"),
                )
            })?;
            dxgi_resource
                .CreateSharedHandle(
                    None,
                    DXGI_SHARED_RESOURCE_READ.0 | DXGI_SHARED_RESOURCE_WRITE.0,
                    PCWSTR::null(),
                )
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("WGC CreateSharedHandle failed: {error}"),
                    )
                })?
        };
        let capture_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        let lock = WGC_SENDER.get_or_init(|| Mutex::new(None));
        if let Some(sender) = lock.lock().unwrap().as_ref() {
            if sender
                .send(WgcFrame {
                    shared_handle: shared_handle.0 as usize,
                    width,
                    height,
                    capture_time_ms,
                })
                .is_err()
            {
                unsafe {
                    let _ = CloseHandle(shared_handle);
                }
            }
        } else {
            unsafe {
                let _ = CloseHandle(shared_handle);
            }
        }
        Ok(())
    }

    fn on_closed(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct WindowsGraphicsCaptureSource {
    receiver: Option<mpsc::Receiver<WgcFrame>>,
    device: Option<ID3D11Device>,
    output: Option<ID3D11Texture2D>,
    width: u32,
    height: u32,
}

impl WindowsGraphicsCaptureSource {
    fn new() -> Self {
        Self {
            receiver: None,
            device: None,
            output: None,
            width: 0,
            height: 0,
        }
    }

    fn open_shared_frame(&self, shared_handle: usize) -> windows::core::Result<ID3D11Texture2D> {
        unsafe {
            let handle = HANDLE(shared_handle as *mut c_void);
            let device1: ID3D11Device1 = self.device.as_ref().unwrap().cast()?;
            let texture = device1.OpenSharedResource1(handle);
            let _ = CloseHandle(handle);
            texture
        }
    }
}

impl CaptureSource for WindowsGraphicsCaptureSource {
    fn initialize(&mut self, device: &ID3D11Device) -> windows::core::Result<()> {
        self.reset();
        let (sender, receiver) = mpsc::channel();
        *WGC_SENDER.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(sender);

        let monitor = Monitor::primary().map_err(|_| windows::core::Error::from_win32())?;
        let settings = Settings::new(
            monitor,
            CursorCaptureSettings::WithoutCursor,
            DrawBorderSettings::WithoutBorder,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Custom(Duration::from_micros(6_944)),
            DirtyRegionSettings::Default,
            ColorFormat::Rgba8,
            (),
        );
        std::thread::spawn(move || {
            if let Err(error) = WgcHandler::start(settings) {
                eprintln!("wgc capture stopped: {error}");
            }
        });

        self.receiver = Some(receiver);
        self.device = Some(device.clone());
        std::thread::sleep(Duration::from_millis(250));
        Ok(())
    }

    fn acquire_next_frame(&mut self, timeout_ms: u32) -> CaptureFrame {
        let Some(receiver) = &self.receiver else {
            return CaptureFrame::error(0);
        };
        let frame = match receiver.recv_timeout(Duration::from_millis(timeout_ms as u64)) {
            Ok(frame) => frame,
            Err(mpsc::RecvTimeoutError::Timeout) => return CaptureFrame::timeout(),
            Err(_) => return CaptureFrame::error(0),
        };

        let texture = match self.open_shared_frame(frame.shared_handle) {
            Ok(texture) => texture,
            Err(error) => return CaptureFrame::error(error.code().0),
        };

        self.output = Some(texture);
        self.width = frame.width;
        self.height = frame.height;

        CaptureFrame {
            status: FrameStatus::Captured,
            texture: self.output.clone(),
            capture_time_ms: frame.capture_time_ms,
            hr: 0,
        }
    }

    fn release_frame(&mut self) {}

    fn reset(&mut self) {
        self.output = None;
        self.receiver = None;
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn api_name(&self) -> &'static str {
        "WindowsGraphicsCapture"
    }
}

trait RenderBackend {
    fn capture_device(&self) -> &ID3D11Device;
    fn renderer_name(&self) -> &'static str;
    fn render(&mut self, texture: &ID3D11Texture2D) -> windows::core::Result<()>;
    fn present(&mut self) -> windows::core::Result<()>;
}

struct D3D11Renderer {
    _hwnd: HWND,
    width: i32,
    height: i32,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    swap_chain: IDXGISwapChain,
    render_target: ID3D11RenderTargetView,
    vertex_shader: ID3D11VertexShader,
    pixel_shader: ID3D11PixelShader,
    input_layout: ID3D11InputLayout,
    vertex_buffer: ID3D11Buffer,
    sampler: ID3D11SamplerState,
}

impl D3D11Renderer {
    fn initialize(hwnd: HWND, width: i32, height: i32) -> windows::core::Result<Self> {
        unsafe {
            let swap_desc = DXGI_SWAP_CHAIN_DESC {
                BufferDesc: DXGI_MODE_DESC {
                    Width: width as u32,
                    Height: height as u32,
                    RefreshRate: DXGI_RATIONAL {
                        Numerator: 60,
                        Denominator: 1,
                    },
                    Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                    ScanlineOrdering: DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED,
                    Scaling: DXGI_MODE_SCALING_UNSPECIFIED,
                },
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: 2,
                OutputWindow: hwnd,
                Windowed: true.into(),
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
                Flags: 0,
            };

            let feature_levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
            let mut swap_chain = None;
            let mut device = None;
            let mut feature_level = D3D_FEATURE_LEVEL::default();
            let mut context = None;
            D3D11CreateDeviceAndSwapChain(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&feature_levels),
                D3D11_SDK_VERSION,
                Some(&swap_desc),
                Some(&mut swap_chain),
                Some(&mut device),
                Some(&mut feature_level),
                Some(&mut context),
            )?;

            let device = device.unwrap();
            let context = context.unwrap();
            let swap_chain = swap_chain.unwrap();
            let render_target = create_render_target(&device, &swap_chain)?;
            let (vertex_shader, pixel_shader, input_layout) = create_shaders(&device)?;
            let vertex_buffer = create_vertex_buffer(&device)?;
            let sampler = create_sampler(&device)?;

            Ok(Self {
                _hwnd: hwnd,
                width,
                height,
                device,
                context,
                swap_chain,
                render_target,
                vertex_shader,
                pixel_shader,
                input_layout,
                vertex_buffer,
                sampler,
            })
        }
    }

    fn device(&self) -> &ID3D11Device {
        &self.device
    }

    fn render(&self, texture: &ID3D11Texture2D) -> windows::core::Result<()> {
        unsafe {
            let mut srv = None;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            texture.GetDesc(&mut desc);
            let srv_desc = D3D11_SHADER_RESOURCE_VIEW_DESC {
                Format: desc.Format,
                ViewDimension: D3D11_SRV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_SHADER_RESOURCE_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_SRV {
                        MostDetailedMip: 0,
                        MipLevels: 1,
                    },
                },
            };
            self.device
                .CreateShaderResourceView(texture, Some(&srv_desc), Some(&mut srv))?;
            let srv = srv.unwrap();

            let clear = [0.0, 0.0, 0.0, 1.0];
            self.context
                .ClearRenderTargetView(&self.render_target, &clear);
            self.context
                .OMSetRenderTargets(Some(&[Some(self.render_target.clone())]), None);

            let viewport = D3D11_VIEWPORT {
                TopLeftX: 0.0,
                TopLeftY: 0.0,
                Width: self.width as f32,
                Height: self.height as f32,
                MinDepth: 0.0,
                MaxDepth: 1.0,
            };
            self.context.RSSetViewports(Some(&[viewport]));

            let stride = size_of::<Vertex>() as u32;
            let offset = 0u32;
            self.context.IASetInputLayout(&self.input_layout);
            self.context.IASetVertexBuffers(
                0,
                1,
                Some(&Some(self.vertex_buffer.clone())),
                Some(&stride),
                Some(&offset),
            );
            self.context
                .IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
            self.context.VSSetShader(&self.vertex_shader, None);
            self.context.PSSetShader(&self.pixel_shader, None);
            self.context
                .PSSetSamplers(0, Some(&[Some(self.sampler.clone())]));
            self.context.PSSetShaderResources(0, Some(&[Some(srv)]));
            self.context.Draw(4, 0);
            self.context.PSSetShaderResources(0, Some(&[None]));
        }
        Ok(())
    }

    fn present(&self) -> windows::core::Result<()> {
        unsafe {
            self.swap_chain.Present(1, DXGI_PRESENT(0)).ok()?;
        }
        Ok(())
    }
}

impl RenderBackend for D3D11Renderer {
    fn capture_device(&self) -> &ID3D11Device {
        self.device()
    }

    fn renderer_name(&self) -> &'static str {
        "D3D11"
    }

    fn render(&mut self, texture: &ID3D11Texture2D) -> windows::core::Result<()> {
        D3D11Renderer::render(self, texture)
    }

    fn present(&mut self) -> windows::core::Result<()> {
        D3D11Renderer::present(self)
    }
}

const D3D12_FRAME_COUNT: usize = 2;

struct D3D12Renderer {
    _hwnd: HWND,
    width: i32,
    height: i32,
    device: ID3D12Device,
    command_queue: ID3D12CommandQueue,
    command_allocator: ID3D12CommandAllocator,
    command_list: ID3D12GraphicsCommandList,
    swap_chain: IDXGISwapChain3,
    rtv_heap: ID3D12DescriptorHeap,
    srv_heap: ID3D12DescriptorHeap,
    pipeline_state: ID3D12PipelineState,
    root_signature: ID3D12RootSignature,
    render_targets: [Option<ID3D12Resource>; D3D12_FRAME_COUNT],
    _vertex_buffer: ID3D12Resource,
    vertex_buffer_view: D3D12_VERTEX_BUFFER_VIEW,
    fence: ID3D12Fence,
    fence_value: u64,
    fence_event: HANDLE,
    rtv_descriptor_size: u32,
    frame_index: u32,
    d3d11_device: ID3D11Device,
    d3d11_context: ID3D11DeviceContext,
    shared_texture11: Option<ID3D11Texture2D>,
    shared_texture12: Option<ID3D12Resource>,
    shared_copy_query: Option<ID3D11Query>,
    texture_width: u32,
    texture_height: u32,
    texture_format: DXGI_FORMAT,
}

impl D3D12Renderer {
    fn initialize(hwnd: HWND, width: i32, height: i32) -> windows::core::Result<Self> {
        unsafe {
            let factory: IDXGIFactory6 = CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0))?;
            let adapter = select_d3d12_adapter(&factory)?;

            let mut device = None;
            D3D12CreateDevice(&adapter, D3D_FEATURE_LEVEL_11_0, &mut device)?;
            let device: ID3D12Device = device.unwrap();

            let queue_desc = D3D12_COMMAND_QUEUE_DESC {
                Type: D3D12_COMMAND_LIST_TYPE_DIRECT,
                Priority: D3D12_COMMAND_QUEUE_PRIORITY_NORMAL.0,
                Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
                NodeMask: 0,
            };
            let command_queue: ID3D12CommandQueue = device.CreateCommandQueue(&queue_desc)?;

            let swap_factory: IDXGIFactory4 = CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0))?;
            let swap_desc = DXGI_SWAP_CHAIN_DESC1 {
                Width: width as u32,
                Height: height as u32,
                Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                Stereo: false.into(),
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: D3D12_FRAME_COUNT as u32,
                Scaling: DXGI_SCALING_STRETCH,
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
                AlphaMode: DXGI_ALPHA_MODE_IGNORE,
                Flags: 0,
            };
            let swap_chain1 = swap_factory.CreateSwapChainForHwnd(
                &command_queue,
                hwnd,
                &swap_desc,
                None,
                None,
            )?;
            swap_factory.MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER)?;
            let swap_chain: IDXGISwapChain3 = swap_chain1.cast()?;
            let frame_index = swap_chain.GetCurrentBackBufferIndex();

            let rtv_heap_desc = D3D12_DESCRIPTOR_HEAP_DESC {
                Type: D3D12_DESCRIPTOR_HEAP_TYPE_RTV,
                NumDescriptors: D3D12_FRAME_COUNT as u32,
                Flags: D3D12_DESCRIPTOR_HEAP_FLAG_NONE,
                NodeMask: 0,
            };
            let rtv_heap: ID3D12DescriptorHeap = device.CreateDescriptorHeap(&rtv_heap_desc)?;
            let rtv_descriptor_size =
                device.GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
            let render_targets =
                create_d3d12_render_targets(&device, &swap_chain, &rtv_heap, rtv_descriptor_size)?;

            let command_allocator: ID3D12CommandAllocator =
                device.CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT)?;
            let command_list: ID3D12GraphicsCommandList = device.CreateCommandList(
                0,
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                &command_allocator,
                None,
            )?;
            command_list.Close()?;

            let srv_heap_desc = D3D12_DESCRIPTOR_HEAP_DESC {
                Type: D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV,
                NumDescriptors: 1,
                Flags: D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE,
                NodeMask: 0,
            };
            let srv_heap: ID3D12DescriptorHeap = device.CreateDescriptorHeap(&srv_heap_desc)?;

            let (root_signature, pipeline_state) = create_d3d12_pipeline_state(&device)?;
            let (vertex_buffer, vertex_buffer_view) = create_d3d12_vertex_buffer(&device)?;

            let fence: ID3D12Fence = device.CreateFence(0, D3D12_FENCE_FLAG_NONE)?;
            let fence_event = CreateEventW(None, false, false, PCWSTR::null())?;

            let (d3d11_device, d3d11_context) = create_d3d11_capture_device_for_adapter(&adapter)?;

            Ok(Self {
                _hwnd: hwnd,
                width,
                height,
                device,
                command_queue,
                command_allocator,
                command_list,
                swap_chain,
                rtv_heap,
                srv_heap,
                pipeline_state,
                root_signature,
                render_targets,
                _vertex_buffer: vertex_buffer,
                vertex_buffer_view,
                fence,
                fence_value: 1,
                fence_event,
                rtv_descriptor_size,
                frame_index,
                d3d11_device,
                d3d11_context,
                shared_texture11: None,
                shared_texture12: None,
                shared_copy_query: None,
                texture_width: 0,
                texture_height: 0,
                texture_format: DXGI_FORMAT_UNKNOWN,
            })
        }
    }

    fn ensure_shared_texture(
        &mut self,
        source_desc: &D3D11_TEXTURE2D_DESC,
    ) -> windows::core::Result<()> {
        let format = normalize_texture_format(source_desc.Format);
        if self.shared_texture12.is_some()
            && self.texture_width == source_desc.Width
            && self.texture_height == source_desc.Height
            && self.texture_format == format
        {
            return Ok(());
        }

        self.wait_for_gpu()?;
        self.shared_copy_query = None;
        self.shared_texture11 = None;
        self.shared_texture12 = None;

        let shared_desc = D3D11_TEXTURE2D_DESC {
            Width: source_desc.Width,
            Height: source_desc.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: D3D11_RESOURCE_MISC_SHARED_NTHANDLE.0 as u32,
        };
        let mut shared_texture11 = None;
        unsafe {
            self.d3d11_device
                .CreateTexture2D(&shared_desc, None, Some(&mut shared_texture11))?;
        }
        let shared_texture11 = shared_texture11.unwrap();
        let dxgi_resource: IDXGIResource1 = shared_texture11.cast()?;
        let shared_handle = unsafe {
            dxgi_resource.CreateSharedHandle(
                None,
                DXGI_SHARED_RESOURCE_READ.0 | DXGI_SHARED_RESOURCE_WRITE.0,
                PCWSTR::null(),
            )?
        };

        let mut shared_texture12 = None;
        let open_result = unsafe {
            self.device
                .OpenSharedHandle(shared_handle, &mut shared_texture12)
        };
        unsafe {
            let _ = CloseHandle(shared_handle);
        }
        open_result?;

        let query_desc = D3D11_QUERY_DESC {
            Query: D3D11_QUERY_EVENT,
            MiscFlags: 0,
        };
        let mut query = None;
        unsafe {
            self.d3d11_device
                .CreateQuery(&query_desc, Some(&mut query))?;
        }

        self.shared_texture11 = Some(shared_texture11);
        self.shared_texture12 = shared_texture12;
        self.shared_copy_query = query;
        self.texture_width = source_desc.Width;
        self.texture_height = source_desc.Height;
        self.texture_format = format;
        Ok(())
    }

    fn resolve_source_resource(
        &mut self,
        source_texture: &ID3D11Texture2D,
    ) -> windows::core::Result<ID3D12Resource> {
        let mut source_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe {
            source_texture.GetDesc(&mut source_desc);
        }
        self.ensure_shared_texture(&source_desc)?;

        let shared11 = self.shared_texture11.as_ref().unwrap();
        let query = self.shared_copy_query.as_ref().unwrap();
        unsafe {
            self.d3d11_context.CopyResource(shared11, source_texture);
            self.d3d11_context.End(query);
            loop {
                let hr = (Interface::vtable(&self.d3d11_context).GetData)(
                    Interface::as_raw(&self.d3d11_context),
                    Interface::as_raw(query),
                    std::ptr::null_mut(),
                    0,
                    0,
                );
                if hr == S_OK {
                    break;
                }
                if hr != S_FALSE {
                    hr.ok()?;
                    break;
                }
                std::thread::yield_now();
            }
        }

        Ok(self.shared_texture12.as_ref().unwrap().clone())
    }

    fn wait_for_gpu(&mut self) -> windows::core::Result<()> {
        let signal_value = self.fence_value;
        self.fence_value += 1;
        unsafe {
            self.command_queue.Signal(&self.fence, signal_value)?;
            if self.fence.GetCompletedValue() < signal_value {
                self.fence
                    .SetEventOnCompletion(signal_value, self.fence_event)?;
                let _ = WaitForSingleObject(self.fence_event, INFINITE);
            }
        }
        Ok(())
    }
}

impl Drop for D3D12Renderer {
    fn drop(&mut self) {
        let _ = self.wait_for_gpu();
        unsafe {
            let _ = CloseHandle(self.fence_event);
        }
    }
}

impl RenderBackend for D3D12Renderer {
    fn capture_device(&self) -> &ID3D11Device {
        &self.d3d11_device
    }

    fn renderer_name(&self) -> &'static str {
        "D3D12"
    }

    fn render(&mut self, texture: &ID3D11Texture2D) -> windows::core::Result<()> {
        let source12 = self.resolve_source_resource(texture)?;
        let source_desc = unsafe { source12.GetDesc() };
        let srv_desc = D3D12_SHADER_RESOURCE_VIEW_DESC {
            Format: source_desc.Format,
            ViewDimension: D3D12_SRV_DIMENSION_TEXTURE2D,
            Shader4ComponentMapping: D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING,
            Anonymous: D3D12_SHADER_RESOURCE_VIEW_DESC_0 {
                Texture2D: D3D12_TEX2D_SRV {
                    MostDetailedMip: 0,
                    MipLevels: 1,
                    PlaneSlice: 0,
                    ResourceMinLODClamp: 0.0,
                },
            },
        };

        unsafe {
            self.device.CreateShaderResourceView(
                &source12,
                Some(&srv_desc),
                self.srv_heap.GetCPUDescriptorHandleForHeapStart(),
            );

            self.command_allocator.Reset()?;
            self.command_list
                .Reset(&self.command_allocator, &self.pipeline_state)?;

            let render_target = self.render_targets[self.frame_index as usize]
                .as_ref()
                .unwrap();
            let to_render_target = transition_barrier(
                render_target,
                D3D12_RESOURCE_STATE_PRESENT,
                D3D12_RESOURCE_STATE_RENDER_TARGET,
            );
            self.command_list.ResourceBarrier(&[to_render_target]);

            let mut rtv_handle = self.rtv_heap.GetCPUDescriptorHandleForHeapStart();
            rtv_handle.ptr += self.frame_index as usize * self.rtv_descriptor_size as usize;
            self.command_list
                .OMSetRenderTargets(1, Some(&rtv_handle as *const _), false, None);
            self.command_list
                .ClearRenderTargetView(rtv_handle, &[0.0, 0.0, 0.0, 1.0], None);

            let viewport = D3D12_VIEWPORT {
                TopLeftX: 0.0,
                TopLeftY: 0.0,
                Width: self.width as f32,
                Height: self.height as f32,
                MinDepth: 0.0,
                MaxDepth: 1.0,
            };
            let scissor = RECT {
                left: 0,
                top: 0,
                right: self.width,
                bottom: self.height,
            };
            self.command_list.RSSetViewports(&[viewport]);
            self.command_list.RSSetScissorRects(&[scissor]);
            self.command_list
                .SetDescriptorHeaps(&[Some(self.srv_heap.clone())]);
            self.command_list
                .SetGraphicsRootSignature(&self.root_signature);
            self.command_list.SetGraphicsRootDescriptorTable(
                0,
                self.srv_heap.GetGPUDescriptorHandleForHeapStart(),
            );
            self.command_list.SetPipelineState(&self.pipeline_state);
            self.command_list
                .IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
            self.command_list
                .IASetVertexBuffers(0, Some(&[self.vertex_buffer_view]));
            self.command_list.DrawInstanced(4, 1, 0, 0);

            let to_present = transition_barrier(
                render_target,
                D3D12_RESOURCE_STATE_RENDER_TARGET,
                D3D12_RESOURCE_STATE_PRESENT,
            );
            self.command_list.ResourceBarrier(&[to_present]);
            self.command_list.Close()?;

            let command_list: ID3D12CommandList = self.command_list.cast()?;
            self.command_queue
                .ExecuteCommandLists(&[Some(command_list)]);
        }
        Ok(())
    }

    fn present(&mut self) -> windows::core::Result<()> {
        unsafe {
            self.swap_chain.Present(1, DXGI_PRESENT(0)).ok()?;
            self.frame_index = self.swap_chain.GetCurrentBackBufferIndex();
        }
        self.wait_for_gpu()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Vertex {
    position: [f32; 3],
    uv: [f32; 2],
}

fn create_render_target(
    device: &ID3D11Device,
    swap_chain: &IDXGISwapChain,
) -> windows::core::Result<ID3D11RenderTargetView> {
    unsafe {
        let back_buffer: ID3D11Texture2D = swap_chain.GetBuffer(0)?;
        let mut render_target = None;
        device.CreateRenderTargetView(&back_buffer, None, Some(&mut render_target))?;
        Ok(render_target.unwrap())
    }
}

fn compile_shader(source: &str, entry: PCSTR, target: PCSTR) -> windows::core::Result<ID3DBlob> {
    unsafe {
        let mut shader = None;
        let mut error = None;
        D3DCompile(
            source.as_ptr().cast(),
            source.len(),
            PCSTR::null(),
            None,
            None,
            entry,
            target,
            0,
            0,
            &mut shader,
            Some(&mut error),
        )?;
        Ok(shader.unwrap())
    }
}

fn create_shaders(
    device: &ID3D11Device,
) -> windows::core::Result<(ID3D11VertexShader, ID3D11PixelShader, ID3D11InputLayout)> {
    const VS: &str = r#"
struct VSInput {
    float3 position : POSITION;
    float2 uv : TEXCOORD;
};
struct PSInput {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};
PSInput main(VSInput input) {
    PSInput output;
    output.position = float4(input.position, 1.0);
    output.uv = input.uv;
    return output;
}
"#;
    const PS: &str = r#"
Texture2D tex : register(t0);
SamplerState samplerState : register(s0);
struct PSInput {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};
float4 main(PSInput input) : SV_TARGET {
    return tex.Sample(samplerState, input.uv);
}
"#;

    let vs_blob = compile_shader(VS, PCSTR(b"main\0".as_ptr()), PCSTR(b"vs_5_0\0".as_ptr()))?;
    let ps_blob = compile_shader(PS, PCSTR(b"main\0".as_ptr()), PCSTR(b"ps_5_0\0".as_ptr()))?;
    unsafe {
        let vs_bytes = std::slice::from_raw_parts(
            vs_blob.GetBufferPointer().cast::<u8>(),
            vs_blob.GetBufferSize(),
        );
        let ps_bytes = std::slice::from_raw_parts(
            ps_blob.GetBufferPointer().cast::<u8>(),
            ps_blob.GetBufferSize(),
        );
        let mut vertex_shader = None;
        let mut pixel_shader = None;
        device.CreateVertexShader(vs_bytes, None, Some(&mut vertex_shader))?;
        device.CreatePixelShader(ps_bytes, None, Some(&mut pixel_shader))?;

        let input_elements = [
            D3D11_INPUT_ELEMENT_DESC {
                SemanticName: PCSTR(b"POSITION\0".as_ptr()),
                SemanticIndex: 0,
                Format: DXGI_FORMAT_R32G32B32_FLOAT,
                InputSlot: 0,
                AlignedByteOffset: 0,
                InputSlotClass: D3D11_INPUT_PER_VERTEX_DATA,
                InstanceDataStepRate: 0,
            },
            D3D11_INPUT_ELEMENT_DESC {
                SemanticName: PCSTR(b"TEXCOORD\0".as_ptr()),
                SemanticIndex: 0,
                Format: DXGI_FORMAT_R32G32_FLOAT,
                InputSlot: 0,
                AlignedByteOffset: 12,
                InputSlotClass: D3D11_INPUT_PER_VERTEX_DATA,
                InstanceDataStepRate: 0,
            },
        ];
        let mut input_layout = None;
        device.CreateInputLayout(&input_elements, vs_bytes, Some(&mut input_layout))?;
        Ok((
            vertex_shader.unwrap(),
            pixel_shader.unwrap(),
            input_layout.unwrap(),
        ))
    }
}

fn create_vertex_buffer(device: &ID3D11Device) -> windows::core::Result<ID3D11Buffer> {
    let vertices = [
        Vertex {
            position: [-1.0, 1.0, 0.0],
            uv: [0.0, 0.0],
        },
        Vertex {
            position: [1.0, 1.0, 0.0],
            uv: [1.0, 0.0],
        },
        Vertex {
            position: [-1.0, -1.0, 0.0],
            uv: [0.0, 1.0],
        },
        Vertex {
            position: [1.0, -1.0, 0.0],
            uv: [1.0, 1.0],
        },
    ];
    let desc = D3D11_BUFFER_DESC {
        ByteWidth: size_of::<[Vertex; 4]>() as u32,
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_VERTEX_BUFFER.0 as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
        StructureByteStride: 0,
    };
    let data = D3D11_SUBRESOURCE_DATA {
        pSysMem: vertices.as_ptr().cast(),
        SysMemPitch: 0,
        SysMemSlicePitch: 0,
    };
    unsafe {
        let mut buffer = None;
        device.CreateBuffer(&desc, Some(&data), Some(&mut buffer))?;
        Ok(buffer.unwrap())
    }
}

fn create_sampler(device: &ID3D11Device) -> windows::core::Result<ID3D11SamplerState> {
    let desc = D3D11_SAMPLER_DESC {
        Filter: D3D11_FILTER_MIN_MAG_MIP_LINEAR,
        AddressU: D3D11_TEXTURE_ADDRESS_CLAMP,
        AddressV: D3D11_TEXTURE_ADDRESS_CLAMP,
        AddressW: D3D11_TEXTURE_ADDRESS_CLAMP,
        ComparisonFunc: D3D11_COMPARISON_NEVER,
        MinLOD: 0.0,
        MaxLOD: f32::MAX,
        ..Default::default()
    };
    unsafe {
        let mut sampler = None;
        device.CreateSamplerState(&desc, Some(&mut sampler))?;
        Ok(sampler.unwrap())
    }
}

fn select_d3d12_adapter(factory: &IDXGIFactory6) -> windows::core::Result<IDXGIAdapter1> {
    unsafe {
        let mut index = 0;
        while let Ok(adapter) = factory.EnumAdapters1(index) {
            index += 1;
            let desc = adapter.GetDesc1()?;
            if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0 {
                continue;
            }

            let mut test_device: Option<ID3D12Device> = None;
            if D3D12CreateDevice(&adapter, D3D_FEATURE_LEVEL_11_0, &mut test_device).is_ok() {
                return Ok(adapter);
            }
        }
    }

    Err(windows::core::Error::from_hresult(DXGI_ERROR_NOT_FOUND))
}

fn create_d3d12_render_targets(
    device: &ID3D12Device,
    swap_chain: &IDXGISwapChain3,
    rtv_heap: &ID3D12DescriptorHeap,
    rtv_descriptor_size: u32,
) -> windows::core::Result<[Option<ID3D12Resource>; D3D12_FRAME_COUNT]> {
    unsafe {
        let mut render_targets: [Option<ID3D12Resource>; D3D12_FRAME_COUNT] = [None, None];
        let mut handle = rtv_heap.GetCPUDescriptorHandleForHeapStart();
        for (index, target) in render_targets.iter_mut().enumerate() {
            let back_buffer: ID3D12Resource = swap_chain.GetBuffer(index as u32)?;
            device.CreateRenderTargetView(&back_buffer, None, handle);
            *target = Some(back_buffer);
            handle.ptr += rtv_descriptor_size as usize;
        }
        Ok(render_targets)
    }
}

fn create_d3d12_pipeline_state(
    device: &ID3D12Device,
) -> windows::core::Result<(ID3D12RootSignature, ID3D12PipelineState)> {
    const VS: &str = r#"
struct VSInput {
    float3 position : POSITION;
    float2 uv : TEXCOORD;
};
struct PSInput {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};
PSInput main(VSInput input) {
    PSInput output;
    output.position = float4(input.position, 1.0);
    output.uv = input.uv;
    return output;
}
"#;
    const PS: &str = r#"
Texture2D tex : register(t0);
SamplerState samplerState : register(s0);
struct PSInput {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};
float4 main(PSInput input) : SV_TARGET {
    return tex.Sample(samplerState, input.uv);
}
"#;

    unsafe {
        let srv_range = D3D12_DESCRIPTOR_RANGE {
            RangeType: D3D12_DESCRIPTOR_RANGE_TYPE_SRV,
            NumDescriptors: 1,
            BaseShaderRegister: 0,
            RegisterSpace: 0,
            OffsetInDescriptorsFromTableStart: D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND,
        };
        let root_parameter = D3D12_ROOT_PARAMETER {
            ParameterType: D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE,
            Anonymous: D3D12_ROOT_PARAMETER_0 {
                DescriptorTable: D3D12_ROOT_DESCRIPTOR_TABLE {
                    NumDescriptorRanges: 1,
                    pDescriptorRanges: &srv_range,
                },
            },
            ShaderVisibility: D3D12_SHADER_VISIBILITY_PIXEL,
        };
        let sampler_desc = D3D12_STATIC_SAMPLER_DESC {
            Filter: D3D12_FILTER_MIN_MAG_MIP_LINEAR,
            AddressU: D3D12_TEXTURE_ADDRESS_MODE_CLAMP,
            AddressV: D3D12_TEXTURE_ADDRESS_MODE_CLAMP,
            AddressW: D3D12_TEXTURE_ADDRESS_MODE_CLAMP,
            MipLODBias: 0.0,
            MaxAnisotropy: 1,
            ComparisonFunc: D3D12_COMPARISON_FUNC_ALWAYS,
            BorderColor: D3D12_STATIC_BORDER_COLOR_OPAQUE_BLACK,
            MinLOD: 0.0,
            MaxLOD: D3D12_FLOAT32_MAX,
            ShaderRegister: 0,
            RegisterSpace: 0,
            ShaderVisibility: D3D12_SHADER_VISIBILITY_PIXEL,
        };
        let root_desc = D3D12_ROOT_SIGNATURE_DESC {
            NumParameters: 1,
            pParameters: &root_parameter,
            NumStaticSamplers: 1,
            pStaticSamplers: &sampler_desc,
            Flags: D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT,
        };

        let mut signature = None;
        let mut error = None;
        D3D12SerializeRootSignature(
            &root_desc,
            D3D_ROOT_SIGNATURE_VERSION_1,
            &mut signature,
            Some(&mut error),
        )?;
        let signature = signature.unwrap();
        let signature_bytes = std::slice::from_raw_parts(
            signature.GetBufferPointer().cast::<u8>(),
            signature.GetBufferSize(),
        );
        let root_signature: ID3D12RootSignature = device.CreateRootSignature(0, signature_bytes)?;

        let vs_blob = compile_shader(VS, PCSTR(b"main\0".as_ptr()), PCSTR(b"vs_5_0\0".as_ptr()))?;
        let ps_blob = compile_shader(PS, PCSTR(b"main\0".as_ptr()), PCSTR(b"ps_5_0\0".as_ptr()))?;
        let input_elements = [
            D3D12_INPUT_ELEMENT_DESC {
                SemanticName: PCSTR(b"POSITION\0".as_ptr()),
                SemanticIndex: 0,
                Format: DXGI_FORMAT_R32G32B32_FLOAT,
                InputSlot: 0,
                AlignedByteOffset: 0,
                InputSlotClass: D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA,
                InstanceDataStepRate: 0,
            },
            D3D12_INPUT_ELEMENT_DESC {
                SemanticName: PCSTR(b"TEXCOORD\0".as_ptr()),
                SemanticIndex: 0,
                Format: DXGI_FORMAT_R32G32_FLOAT,
                InputSlot: 0,
                AlignedByteOffset: 12,
                InputSlotClass: D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA,
                InstanceDataStepRate: 0,
            },
        ];

        let mut blend_desc = D3D12_BLEND_DESC::default();
        blend_desc.RenderTarget[0] = D3D12_RENDER_TARGET_BLEND_DESC {
            BlendEnable: false.into(),
            LogicOpEnable: false.into(),
            SrcBlend: D3D12_BLEND_ONE,
            DestBlend: D3D12_BLEND_ZERO,
            BlendOp: D3D12_BLEND_OP_ADD,
            SrcBlendAlpha: D3D12_BLEND_ONE,
            DestBlendAlpha: D3D12_BLEND_ZERO,
            BlendOpAlpha: D3D12_BLEND_OP_ADD,
            LogicOp: D3D12_LOGIC_OP_NOOP,
            RenderTargetWriteMask: D3D12_COLOR_WRITE_ENABLE_ALL.0 as u8,
        };

        let pso_desc = D3D12_GRAPHICS_PIPELINE_STATE_DESC {
            pRootSignature: ManuallyDrop::new(Some(transmute_copy(&root_signature))),
            VS: D3D12_SHADER_BYTECODE {
                pShaderBytecode: vs_blob.GetBufferPointer(),
                BytecodeLength: vs_blob.GetBufferSize(),
            },
            PS: D3D12_SHADER_BYTECODE {
                pShaderBytecode: ps_blob.GetBufferPointer(),
                BytecodeLength: ps_blob.GetBufferSize(),
            },
            BlendState: blend_desc,
            SampleMask: u32::MAX,
            RasterizerState: D3D12_RASTERIZER_DESC {
                FillMode: D3D12_FILL_MODE_SOLID,
                CullMode: D3D12_CULL_MODE_NONE,
                FrontCounterClockwise: false.into(),
                DepthBias: D3D12_DEFAULT_DEPTH_BIAS,
                DepthBiasClamp: D3D12_DEFAULT_DEPTH_BIAS_CLAMP,
                SlopeScaledDepthBias: D3D12_DEFAULT_SLOPE_SCALED_DEPTH_BIAS,
                DepthClipEnable: true.into(),
                MultisampleEnable: false.into(),
                AntialiasedLineEnable: false.into(),
                ForcedSampleCount: 0,
                ConservativeRaster: D3D12_CONSERVATIVE_RASTERIZATION_MODE_OFF,
            },
            DepthStencilState: D3D12_DEPTH_STENCIL_DESC {
                DepthEnable: false.into(),
                StencilEnable: false.into(),
                ..Default::default()
            },
            InputLayout: D3D12_INPUT_LAYOUT_DESC {
                pInputElementDescs: input_elements.as_ptr(),
                NumElements: input_elements.len() as u32,
            },
            PrimitiveTopologyType: D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE,
            NumRenderTargets: 1,
            RTVFormats: [
                DXGI_FORMAT_R8G8B8A8_UNORM,
                DXGI_FORMAT_UNKNOWN,
                DXGI_FORMAT_UNKNOWN,
                DXGI_FORMAT_UNKNOWN,
                DXGI_FORMAT_UNKNOWN,
                DXGI_FORMAT_UNKNOWN,
                DXGI_FORMAT_UNKNOWN,
                DXGI_FORMAT_UNKNOWN,
            ],
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            ..Default::default()
        };
        let pipeline_state: ID3D12PipelineState = device.CreateGraphicsPipelineState(&pso_desc)?;
        Ok((root_signature, pipeline_state))
    }
}

fn create_d3d12_vertex_buffer(
    device: &ID3D12Device,
) -> windows::core::Result<(ID3D12Resource, D3D12_VERTEX_BUFFER_VIEW)> {
    let vertices = [
        Vertex {
            position: [-1.0, 1.0, 0.0],
            uv: [0.0, 0.0],
        },
        Vertex {
            position: [1.0, 1.0, 0.0],
            uv: [1.0, 0.0],
        },
        Vertex {
            position: [-1.0, -1.0, 0.0],
            uv: [0.0, 1.0],
        },
        Vertex {
            position: [1.0, -1.0, 0.0],
            uv: [1.0, 1.0],
        },
    ];
    let buffer_size = size_of::<[Vertex; 4]>();
    let heap_props = D3D12_HEAP_PROPERTIES {
        Type: D3D12_HEAP_TYPE_UPLOAD,
        CPUPageProperty: D3D12_CPU_PAGE_PROPERTY_UNKNOWN,
        MemoryPoolPreference: D3D12_MEMORY_POOL_UNKNOWN,
        CreationNodeMask: 1,
        VisibleNodeMask: 1,
    };
    let resource_desc = D3D12_RESOURCE_DESC {
        Dimension: D3D12_RESOURCE_DIMENSION_BUFFER,
        Width: buffer_size as u64,
        Height: 1,
        DepthOrArraySize: 1,
        MipLevels: 1,
        Format: DXGI_FORMAT_UNKNOWN,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Layout: D3D12_TEXTURE_LAYOUT_ROW_MAJOR,
        ..Default::default()
    };

    unsafe {
        let mut vertex_buffer = None;
        device.CreateCommittedResource(
            &heap_props,
            D3D12_HEAP_FLAG_NONE,
            &resource_desc,
            D3D12_RESOURCE_STATE_GENERIC_READ,
            None,
            &mut vertex_buffer,
        )?;
        let vertex_buffer: ID3D12Resource = vertex_buffer.unwrap();

        let read_range = D3D12_RANGE { Begin: 0, End: 0 };
        let mut data: *mut c_void = std::ptr::null_mut();
        vertex_buffer.Map(0, Some(&read_range as *const _), Some(&mut data as *mut _))?;
        std::ptr::copy_nonoverlapping(vertices.as_ptr(), data.cast::<Vertex>(), vertices.len());
        vertex_buffer.Unmap(0, None);

        let view = D3D12_VERTEX_BUFFER_VIEW {
            BufferLocation: vertex_buffer.GetGPUVirtualAddress(),
            SizeInBytes: buffer_size as u32,
            StrideInBytes: size_of::<Vertex>() as u32,
        };
        Ok((vertex_buffer, view))
    }
}

fn create_d3d11_capture_device_for_adapter(
    adapter: &IDXGIAdapter1,
) -> windows::core::Result<(ID3D11Device, ID3D11DeviceContext)> {
    unsafe {
        let adapter: IDXGIAdapter = adapter.cast()?;
        let feature_levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
        let mut device = None;
        let mut feature_level = D3D_FEATURE_LEVEL::default();
        let mut context = None;
        D3D11CreateDevice(
            &adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&feature_levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut feature_level),
            Some(&mut context),
        )?;
        Ok((device.unwrap(), context.unwrap()))
    }
}

fn normalize_texture_format(format: DXGI_FORMAT) -> DXGI_FORMAT {
    match format {
        DXGI_FORMAT_B8G8R8A8_UNORM | DXGI_FORMAT_R8G8B8A8_UNORM => format,
        _ => DXGI_FORMAT_B8G8R8A8_UNORM,
    }
}

fn transition_barrier(
    resource: &ID3D12Resource,
    before: D3D12_RESOURCE_STATES,
    after: D3D12_RESOURCE_STATES,
) -> D3D12_RESOURCE_BARRIER {
    unsafe {
        D3D12_RESOURCE_BARRIER {
            Type: D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
            Flags: D3D12_RESOURCE_BARRIER_FLAG_NONE,
            Anonymous: D3D12_RESOURCE_BARRIER_0 {
                Transition: ManuallyDrop::new(D3D12_RESOURCE_TRANSITION_BARRIER {
                    pResource: ManuallyDrop::new(Some(transmute_copy(resource))),
                    Subresource: D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
                    StateBefore: before,
                    StateAfter: after,
                }),
            },
        }
    }
}

extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

fn create_window() -> windows::core::Result<HWND> {
    unsafe {
        let module = GetModuleHandleW(PCWSTR::null())?;
        let instance = HINSTANCE(module.0);
        let class_name = w!("CapTestRustViewerWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance.into(),
            lpszClassName: class_name,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            style: CS_HREDRAW | CS_VREDRAW,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("CapTest Rust Capture Render Base (D3D11)"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            None,
            None,
            Some(instance),
            None,
        )?;
        let _ = ShowWindow(hwnd, SW_SHOW);
        Ok(hwnd)
    }
}

fn pump_messages() -> bool {
    unsafe {
        let mut msg = MSG::default();
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            if msg.message == WM_QUIT {
                return false;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    true
}

fn make_capture_source(kind: CaptureSourceKind) -> Box<dyn CaptureSource> {
    match kind {
        CaptureSourceKind::DesktopDuplication => Box::new(DesktopDuplicationSource::new()),
        CaptureSourceKind::WindowsGraphicsCapture => Box::new(WindowsGraphicsCaptureSource::new()),
        CaptureSourceKind::SharedMemoryDesktopDuplication => {
            Box::new(SharedMemoryDesktopDuplicationSource::new())
        }
    }
}

fn find_results_dir() -> PathBuf {
    let mut current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..8 {
        let candidate = current.join("results");
        if candidate.is_dir() {
            return candidate;
        }
        if !current.pop() {
            break;
        }
    }
    Path::new("D:/Project/TestProject/CapTest/results").to_path_buf()
}

fn get_memory_mb() -> f64 {
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = zeroed();
        if GetProcessMemoryInfo(
            GetCurrentProcess(),
            addr_of_mut!(pmc).cast(),
            size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
        .is_ok()
        {
            pmc.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(std::env::args());
    let hwnd = create_window()?;
    let mut renderer: Box<dyn RenderBackend> = match options.renderer {
        RendererKind::D3D11 => Box::new(D3D11Renderer::initialize(
            hwnd,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
        )?),
        RendererKind::D3D12 => Box::new(D3D12Renderer::initialize(
            hwnd,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
        )?),
    };
    let mut capture = make_capture_source(options.source);
    capture.initialize(renderer.capture_device())?;

    let mut collector = MetricsCollector::new(MetricsConfig {
        api: capture.api_name().to_string(),
        language: "Rust".to_string(),
        renderer: renderer.renderer_name().to_string(),
        duration_sec: options.duration_secs,
        width: capture.width(),
        height: capture.height(),
    });

    let start = Instant::now();
    let mut frame_number = 0u64;
    let mut captured_since_fps = 0u64;
    let mut last_fps_update = Instant::now();
    let mut current_fps = 0.0;

    while pump_messages() {
        if options.duration_secs > 0
            && start.elapsed() >= Duration::from_secs(options.duration_secs)
        {
            break;
        }

        let frame_start = Instant::now();
        let frame = capture.acquire_next_frame(16);
        frame_number += 1;

        let mut render_ms = 0.0;
        if frame.status == FrameStatus::Captured {
            if let Some(texture) = frame.texture.as_ref() {
                let render_start = Instant::now();
                let _ = renderer.render(texture);
                render_ms = render_start.elapsed().as_secs_f64() * 1000.0;
                capture.release_frame();
                captured_since_fps += 1;
            }
        } else if frame.status == FrameStatus::AccessLost {
            let _ = capture.initialize(renderer.capture_device());
        } else if frame.status == FrameStatus::Error {
            eprintln!("capture error: 0x{:08x}", frame.hr as u32);
            std::thread::sleep(Duration::from_millis(16));
        }

        let present_start = Instant::now();
        let _ = renderer.present();
        let present_ms = present_start.elapsed().as_secs_f64() * 1000.0;

        let fps_elapsed = last_fps_update.elapsed().as_secs_f64();
        if fps_elapsed >= 0.5 {
            current_fps = captured_since_fps as f64 / fps_elapsed;
            captured_since_fps = 0;
            last_fps_update = Instant::now();
        }

        collector.record(FrameMetrics {
            frame_number,
            status: frame.status.as_str().to_string(),
            capture_time_ms: frame.capture_time_ms,
            render_time_ms: render_ms,
            present_time_ms: present_ms,
            total_time_ms: frame_start.elapsed().as_secs_f64() * 1000.0,
            fps: current_fps,
            memory_mb: get_memory_mb(),
            width: capture.width(),
            height: capture.height(),
        });
    }

    capture.release_frame();
    let (csv_path, json_path) = collector.save()?;
    println!("Saved Rust capture-render metrics:");
    println!("  {}", csv_path.display());
    println!("  {}", json_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_viewer_options() {
        let options = parse_args(["viewer"]);
        assert_eq!(options.source, CaptureSourceKind::DesktopDuplication);
        assert_eq!(options.renderer, RendererKind::D3D11);
        assert_eq!(options.duration_secs, 0);
    }

    #[test]
    fn parses_source_renderer_and_duration() {
        let options = parse_args([
            "viewer",
            "--source",
            "wgc",
            "--renderer=d3d11",
            "--duration",
            "5",
        ]);
        assert_eq!(options.source, CaptureSourceKind::WindowsGraphicsCapture);
        assert_eq!(options.renderer, RendererKind::D3D11);
        assert_eq!(options.duration_secs, 5);
    }

    #[test]
    fn parses_d3d12_renderer() {
        let options = parse_args(["viewer", "--renderer", "d3d12"]);
        assert_eq!(options.renderer, RendererKind::D3D12);
    }

    #[test]
    fn parses_shared_memory_with_d3d12_renderer() {
        let options = parse_args([
            "viewer",
            "--source=shared-memory",
            "--renderer",
            "d3d12",
            "--duration=3",
        ]);
        assert_eq!(
            options.source,
            CaptureSourceKind::SharedMemoryDesktopDuplication
        );
        assert_eq!(options.renderer, RendererKind::D3D12);
        assert_eq!(options.duration_secs, 3);
    }
}
