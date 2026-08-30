#![cfg(target_os = "macos")]

use core_graphics::{
    display::CGDisplay,
    geometry::{CGPoint, CGRect as CgRect, CGSize},
};
use mrd_pipeline_core::{
    CapturedFrame, FrameCapture, FrameMemoryKind, FramePixelFormat, PipelineError,
};
use screencapturekit::{
    cg::CGRect as ScRect,
    cm::SCFrameStatus,
    cv::{CVPixelBufferLockFlags, CVPixelBufferLockGuard},
    prelude::*,
    shareable_content::{SCDisplay, SCWindow},
};
use std::{
    env,
    ffi::c_void,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BGRA_FOURCC: u32 = u32::from_be_bytes(*b"BGRA");
const NV12_VIDEO_RANGE_FOURCC: u32 = u32::from_be_bytes(*b"420v");
const DEFAULT_STREAM_FPS: u32 = 60;
const DEFAULT_QUEUE_DEPTH: u32 = 8;
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_millis(1_000);
const NEXT_FRAME_TIMEOUT: Duration = Duration::from_millis(500);
const CV_RETURN_SUCCESS: CVReturn = 0;
const CV_TIME_IS_INDEFINITE: CVTimeFlags = 1 << 0;

type CVDisplayLinkRef = *mut c_void;
type CVReturn = i32;
type CVTimeFlags = i32;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CVTime {
    time_value: i64,
    time_scale: i32,
    flags: i32,
}

#[link(name = "CoreVideo", kind = "framework")]
extern "C" {
    fn CVDisplayLinkCreateWithCGDisplay(
        display_id: u32,
        display_link_out: *mut CVDisplayLinkRef,
    ) -> CVReturn;
    fn CVDisplayLinkGetNominalOutputVideoRefreshPeriod(display_link: CVDisplayLinkRef) -> CVTime;
    fn CVDisplayLinkRelease(display_link: CVDisplayLinkRef);
}

pub struct MacosScreenCapture {
    coregraphics: Option<CoreGraphicsScreenCapture>,
    screencapturekit: Option<ScreenCaptureKitCapture>,
    active_backend: MacosCaptureBackend,
    require_screencapturekit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosCaptureBackend {
    ScreenCaptureKit,
    CoreGraphics,
}

#[derive(Debug, Clone)]
pub struct MacosDisplayCaptureTarget {
    pub display_id: u32,
    pub title: String,
    pub width: u32,
    pub height: u32,
    pub refresh_hz: Option<u32>,
    pub is_main: bool,
}

#[derive(Debug, Clone)]
pub struct MacosWindowCaptureTarget {
    pub window_id: u32,
    pub title: String,
    pub app_name: String,
    pub bundle_identifier: String,
    pub width: u32,
    pub height: u32,
    pub process_id: u32,
    pub window_layer: i32,
    pub is_on_screen: bool,
}

#[derive(Debug, Clone)]
pub struct MacosWindowCaptureItemProbe {
    pub window_id: u32,
    pub title: String,
    pub app_name: String,
    pub bundle_identifier: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct MacosWindowCaptureFrameProbe {
    pub window_id: u32,
    pub title: String,
    pub app_name: String,
    pub bundle_identifier: String,
    pub width: u32,
    pub height: u32,
    pub byte_len: usize,
    pub pixel_format: FramePixelFormat,
    pub frame: CapturedFrame,
}

struct CoreGraphicsScreenCapture {
    display: CGDisplay,
    display_id: u32,
    source_width: usize,
    source_height: usize,
    width: usize,
    height: usize,
}

impl MacosScreenCapture {
    pub fn new_primary() -> Result<Self, PipelineError> {
        let display = CGDisplay::main();
        Self::new(display)
    }

    pub fn new_display_id(display_id: u32) -> Result<Self, PipelineError> {
        Self::new(CGDisplay::new(display_id))
    }

    pub fn new(display: CGDisplay) -> Result<Self, PipelineError> {
        let coregraphics = CoreGraphicsScreenCapture::new(display)?;
        let preference = capture_backend_preference();
        let use_screencapturekit = !preference.force_coregraphics && !screencapturekit_disabled();
        let screencapturekit = use_screencapturekit.then(|| {
            ScreenCaptureKitCapture::new_display(
                coregraphics.display_id,
                coregraphics.source_width,
                coregraphics.source_height,
            )
        });
        let active_backend = if screencapturekit.is_some() {
            MacosCaptureBackend::ScreenCaptureKit
        } else {
            MacosCaptureBackend::CoreGraphics
        };

        Ok(Self {
            coregraphics: Some(coregraphics),
            screencapturekit,
            active_backend,
            require_screencapturekit: preference.require_screencapturekit,
        })
    }

    pub fn new_window(window_id: u32) -> Result<Self, PipelineError> {
        if screencapturekit_disabled() {
            return Err(PipelineError::message(
                "ScreenCaptureKit is required for macOS window capture",
            ));
        }

        let target = find_window_capture_target(window_id)?;
        let screencapturekit = ScreenCaptureKitCapture::new_window(
            window_id,
            target.width as usize,
            target.height as usize,
        );

        Ok(Self {
            coregraphics: None,
            screencapturekit: Some(screencapturekit),
            active_backend: MacosCaptureBackend::ScreenCaptureKit,
            require_screencapturekit: true,
        })
    }

    pub fn width(&self) -> usize {
        match (&self.active_backend, &self.screencapturekit) {
            (MacosCaptureBackend::ScreenCaptureKit, Some(capture)) => capture.width(),
            _ => self
                .coregraphics
                .as_ref()
                .map(CoreGraphicsScreenCapture::width)
                .unwrap_or(0),
        }
    }

    pub fn height(&self) -> usize {
        match (&self.active_backend, &self.screencapturekit) {
            (MacosCaptureBackend::ScreenCaptureKit, Some(capture)) => capture.height(),
            _ => self
                .coregraphics
                .as_ref()
                .map(CoreGraphicsScreenCapture::height)
                .unwrap_or(0),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self.active_backend {
            MacosCaptureBackend::ScreenCaptureKit => "screencapturekit",
            MacosCaptureBackend::CoreGraphics => "coregraphics",
        }
    }

    pub fn set_target_dimensions(&mut self, width: usize, height: usize) {
        if let Some(capture) = self.coregraphics.as_mut() {
            capture.set_target_dimensions(width, height);
        }
        if let Some(capture) = self.screencapturekit.as_mut() {
            capture.set_target_dimensions(width, height);
        }
    }

    pub fn set_target_fps(&mut self, fps: u32) {
        if let Some(capture) = self.screencapturekit.as_mut() {
            capture.set_target_fps(fps);
        }
    }

    /// Force CPU-backed frames even when direct CVPixelBuffer output is
    /// enabled globally. Software encoders use this per-capture override.
    pub fn force_cpu_output(&mut self) {
        if let Some(capture) = self.screencapturekit.as_mut() {
            capture.set_direct_cv_pixel_buffer(false);
        }
    }

    pub fn capture_frame_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<CapturedFrame, PipelineError> {
        if self.active_backend == MacosCaptureBackend::ScreenCaptureKit {
            if let Some(capture) = self.screencapturekit.as_mut() {
                match capture.capture_frame_with_timeout(timeout) {
                    Ok(frame) => return Ok(frame),
                    Err(error) if self.require_screencapturekit => return Err(error),
                    Err(_) => {
                        capture.stop_stream();
                        self.active_backend = MacosCaptureBackend::CoreGraphics;
                    }
                }
            }
        }

        self.coregraphics
            .as_mut()
            .ok_or_else(|| PipelineError::message("macOS capture has no fallback backend"))?
            .capture_frame()
    }
}

impl FrameCapture for MacosScreenCapture {
    fn output_memory_kind(&self) -> FrameMemoryKind {
        if self.active_backend == MacosCaptureBackend::ScreenCaptureKit
            && self
                .screencapturekit
                .as_ref()
                .is_some_and(|capture| capture.direct_cv_pixel_buffer)
        {
            return FrameMemoryKind::MacosCvPixelBuffer;
        }
        FrameMemoryKind::Cpu
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        if self.active_backend == MacosCaptureBackend::ScreenCaptureKit {
            if let Some(capture) = self.screencapturekit.as_mut() {
                match capture.capture_frame() {
                    Ok(frame) => return Ok(frame),
                    Err(error) if self.require_screencapturekit => return Err(error),
                    Err(_) => {
                        capture.stop_stream();
                        self.active_backend = MacosCaptureBackend::CoreGraphics;
                    }
                }
            }
        }

        self.coregraphics
            .as_mut()
            .ok_or_else(|| PipelineError::message("macOS capture has no fallback backend"))?
            .capture_frame()
    }
}

pub fn enumerate_display_capture_targets() -> Result<Vec<MacosDisplayCaptureTarget>, PipelineError>
{
    let display_ids = CGDisplay::active_displays().map_err(|error| {
        PipelineError::message(format!("CoreGraphics active display query failed: {error}"))
    })?;
    let main_display_id = CGDisplay::main().id;
    let mut targets = Vec::with_capacity(display_ids.len());

    for (index, display_id) in display_ids.into_iter().enumerate() {
        let display = CGDisplay::new(display_id);
        let width = u32::try_from(display.pixels_wide())
            .map_err(|_| PipelineError::message("macOS display width is too large"))?;
        let height = u32::try_from(display.pixels_high())
            .map_err(|_| PipelineError::message("macOS display height is too large"))?;
        let refresh_hz = display_refresh_hz(&display);
        if width == 0 || height == 0 {
            continue;
        }

        let display_number = index + 1;
        let is_main = display_id == main_display_id;
        let title = if is_main {
            format!("Main Display ({display_number})")
        } else {
            format!("Display {display_number}")
        };
        targets.push(MacosDisplayCaptureTarget {
            display_id,
            title,
            width,
            height,
            refresh_hz,
            is_main,
        });
    }

    Ok(targets)
}

pub fn highest_current_display_refresh_hz() -> Option<u32> {
    enumerate_display_capture_targets()
        .ok()?
        .into_iter()
        .filter_map(|target| target.refresh_hz)
        .max()
}

fn display_refresh_hz(display: &CGDisplay) -> Option<u32> {
    display
        .display_mode()
        .and_then(|mode| display_refresh_hz_from_rate(mode.refresh_rate()))
        .or_else(|| display_refresh_hz_from_core_video(display.id))
}

fn display_refresh_hz_from_core_video(display_id: u32) -> Option<u32> {
    let mut display_link: CVDisplayLinkRef = std::ptr::null_mut();
    let created = unsafe { CVDisplayLinkCreateWithCGDisplay(display_id, &mut display_link) };
    if created != CV_RETURN_SUCCESS || display_link.is_null() {
        return None;
    }

    let time = unsafe { CVDisplayLinkGetNominalOutputVideoRefreshPeriod(display_link) };
    unsafe { CVDisplayLinkRelease(display_link) };
    display_refresh_hz_from_core_video_time(time)
}

fn display_refresh_hz_from_core_video_time(time: CVTime) -> Option<u32> {
    if time.time_value <= 0 || time.time_scale <= 0 || time.flags & CV_TIME_IS_INDEFINITE != 0 {
        return None;
    }
    display_refresh_hz_from_rate(time.time_scale as f64 / time.time_value as f64)
}

fn display_refresh_hz_from_rate(refresh_rate: f64) -> Option<u32> {
    if !refresh_rate.is_finite() || refresh_rate <= 0.0 {
        return None;
    }
    let refresh_hz = refresh_rate.round();
    if refresh_hz < 1.0 || refresh_hz > u32::MAX as f64 {
        return None;
    }
    Some(refresh_hz as u32)
}

pub fn enumerate_window_capture_targets() -> Result<Vec<MacosWindowCaptureTarget>, PipelineError> {
    let content = shareable_content_for_windows()?;
    let displays = content.displays();
    let mut targets = content
        .windows()
        .into_iter()
        .filter(|window| is_user_window(window))
        .filter_map(|window| window_capture_target(&window, &displays))
        .collect::<Vec<_>>();

    targets.sort_by(|left, right| {
        left.app_name
            .cmp(&right.app_name)
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.window_id.cmp(&right.window_id))
    });
    Ok(targets)
}

pub fn probe_window_capture_item(
    window_id: u32,
) -> Result<MacosWindowCaptureItemProbe, PipelineError> {
    let target = find_window_capture_target(window_id)?;

    Ok(MacosWindowCaptureItemProbe {
        window_id: target.window_id,
        title: target.title,
        app_name: target.app_name,
        bundle_identifier: target.bundle_identifier,
        width: target.width,
        height: target.height,
    })
}

pub fn probe_window_first_frame(
    window_id: u32,
    timeout: Duration,
) -> Result<MacosWindowCaptureFrameProbe, PipelineError> {
    let target = find_window_capture_target(window_id)?;
    let mut capture = MacosScreenCapture::new_window(window_id)?;
    let frame = capture.capture_frame_with_timeout(timeout)?;

    Ok(MacosWindowCaptureFrameProbe {
        window_id,
        title: target.title,
        app_name: target.app_name,
        bundle_identifier: target.bundle_identifier,
        width: frame.width as u32,
        height: frame.height as u32,
        byte_len: frame.data.len(),
        pixel_format: frame.pixel_format,
        frame,
    })
}

fn shareable_content_for_windows() -> Result<SCShareableContent, PipelineError> {
    SCShareableContent::create()
        .with_exclude_desktop_windows(true)
        .with_on_screen_windows_only(true)
        .get()
        .map_err(|error| {
            PipelineError::message(format!(
                "ScreenCaptureKit shareable window query failed: {error}"
            ))
        })
}

fn find_window_capture_target(window_id: u32) -> Result<MacosWindowCaptureTarget, PipelineError> {
    enumerate_window_capture_targets()?
        .into_iter()
        .find(|target| target.window_id == window_id)
        .ok_or_else(|| {
            PipelineError::message(format!(
                "ScreenCaptureKit found no capturable window with id 0x{window_id:X}"
            ))
        })
}

fn find_window(content: &SCShareableContent, window_id: u32) -> Result<SCWindow, PipelineError> {
    content
        .windows()
        .into_iter()
        .find(|window| window.window_id() == window_id)
        .ok_or_else(|| {
            PipelineError::message(format!(
                "ScreenCaptureKit found no window with id 0x{window_id:X}"
            ))
        })
}

fn is_user_window(window: &SCWindow) -> bool {
    let frame = window.frame();
    window.is_on_screen()
        && window.window_layer() == 0
        && frame.width >= 2.0
        && frame.height >= 2.0
        && (window
            .title()
            .map(|title| !title.trim().is_empty())
            .unwrap_or(false)
            || window.owning_application().is_some())
}

fn window_capture_target(
    window: &SCWindow,
    displays: &[SCDisplay],
) -> Option<MacosWindowCaptureTarget> {
    let app = window.owning_application();
    let app_name = app
        .as_ref()
        .map(|app| app.application_name())
        .unwrap_or_default();
    let bundle_identifier = app
        .as_ref()
        .map(|app| app.bundle_identifier())
        .unwrap_or_default();
    let process_id = app
        .as_ref()
        .map(|app| app.process_id().max(0) as u32)
        .unwrap_or_default();
    let title = window
        .title()
        .filter(|title| !title.trim().is_empty())
        .unwrap_or_else(|| app_name.clone());
    if title.trim().is_empty() {
        return None;
    }

    let (width, height) = window_pixel_dimensions(window.frame(), displays);
    Some(MacosWindowCaptureTarget {
        window_id: window.window_id(),
        title,
        app_name,
        bundle_identifier,
        width,
        height,
        process_id,
        window_layer: window.window_layer(),
        is_on_screen: window.is_on_screen(),
    })
}

fn window_pixel_dimensions(frame: ScRect, displays: &[SCDisplay]) -> (u32, u32) {
    let scale = display_scale_for_rect(frame, displays).unwrap_or(1.0);
    pixel_dimensions_for_scale(frame.width, frame.height, scale)
}

fn display_scale_for_rect(frame: ScRect, displays: &[SCDisplay]) -> Option<f64> {
    let center_x = frame.x + frame.width / 2.0;
    let center_y = frame.y + frame.height / 2.0;
    displays
        .iter()
        .find(|display| {
            let display_frame = display.frame();
            center_x >= display_frame.x
                && center_x <= display_frame.max_x()
                && center_y >= display_frame.y
                && center_y <= display_frame.max_y()
        })
        .or_else(|| displays.first())
        .map(display_scale)
        .filter(|scale| scale.is_finite() && *scale > 0.0)
}

fn display_scale(display: &SCDisplay) -> f64 {
    let frame = display.frame();
    let scale_x = display.width() as f64 / frame.width.max(1.0);
    let scale_y = display.height() as f64 / frame.height.max(1.0);
    scale_x.max(scale_y).max(1.0)
}

fn pixel_dimensions_for_scale(width_points: f64, height_points: f64, scale: f64) -> (u32, u32) {
    let width = (width_points * scale).round().clamp(2.0, u32::MAX as f64) as u32;
    let height = (height_points * scale).round().clamp(2.0, u32::MAX as f64) as u32;
    (width, height)
}

impl CoreGraphicsScreenCapture {
    fn new(display: CGDisplay) -> Result<Self, PipelineError> {
        let width = usize::try_from(display.pixels_wide())
            .map_err(|_| PipelineError::message("macOS display width is too large"))?;
        let height = usize::try_from(display.pixels_high())
            .map_err(|_| PipelineError::message("macOS display height is too large"))?;
        let display_id = display.id;

        Ok(Self {
            display,
            display_id,
            source_width: width,
            source_height: height,
            width,
            height,
        })
    }

    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    fn set_target_dimensions(&mut self, width: usize, height: usize) {
        self.width = width.clamp(2, self.source_width.max(2));
        self.height = height.clamp(2, self.source_height.max(2));
    }

    fn capture_rect(&self) -> CgRect {
        let bounds = self.display.bounds();
        let scale_x = self.source_width as f64 / bounds.size.width.max(1.0);
        let scale_y = self.source_height as f64 / bounds.size.height.max(1.0);
        let target_width = (self.width as f64 / scale_x).min(bounds.size.width);
        let target_height = (self.height as f64 / scale_y).min(bounds.size.height);
        let origin_x = bounds.origin.x + ((bounds.size.width - target_width) / 2.0).max(0.0);
        let origin_y = bounds.origin.y + ((bounds.size.height - target_height) / 2.0).max(0.0);

        CgRect::new(
            &CGPoint::new(origin_x, origin_y),
            &CGSize::new(target_width, target_height),
        )
    }
}

impl CoreGraphicsScreenCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        let image = if self.width == self.source_width && self.height == self.source_height {
            self.display.image()
        } else {
            self.display.image_for_rect(self.capture_rect())
        }
        .ok_or_else(|| {
            PipelineError::message(
                "macOS screen capture returned no image; Screen Recording permission may be required",
            )
        })?;
        let width = image.width();
        let height = image.height();

        if image.bits_per_pixel() != 32 || image.bits_per_component() != 8 {
            return Err(PipelineError::message(format!(
                "unsupported macOS screenshot format: {} bits/pixel, {} bits/component",
                image.bits_per_pixel(),
                image.bits_per_component()
            )));
        }

        let bytes_per_row = image.bytes_per_row();
        let data = image.data();
        let packed = repack_bgra(data.bytes(), width, height, bytes_per_row)?;

        self.width = width;
        self.height = height;

        Ok(CapturedFrame::from_cpu(
            width,
            height,
            FramePixelFormat::Bgra32,
            now_us()?,
            packed,
        ))
    }
}

struct ScreenCaptureKitCapture {
    source: ScreenCaptureKitSource,
    source_width: usize,
    source_height: usize,
    width: usize,
    height: usize,
    fps: u32,
    queue_depth: u32,
    direct_cv_pixel_buffer: bool,
    stream: Option<SCStream>,
    queue: Option<DispatchQueue>,
    shared: Arc<(Mutex<ScreenCaptureKitState>, Condvar)>,
    last_sequence: u64,
}

#[derive(Debug, Clone, Copy)]
enum ScreenCaptureKitSource {
    Display { display_id: u32 },
    Window { window_id: u32 },
}

struct ScreenCaptureKitState {
    latest: Option<CapturedFrame>,
    sequence: u64,
    error: Option<String>,
}

impl ScreenCaptureKitCapture {
    fn new_display(display_id: u32, source_width: usize, source_height: usize) -> Self {
        Self::new(
            ScreenCaptureKitSource::Display { display_id },
            source_width,
            source_height,
        )
    }

    fn new_window(window_id: u32, source_width: usize, source_height: usize) -> Self {
        Self::new(
            ScreenCaptureKitSource::Window { window_id },
            source_width,
            source_height,
        )
    }

    fn new(source: ScreenCaptureKitSource, source_width: usize, source_height: usize) -> Self {
        let width = source_width.max(2);
        let height = source_height.max(2);
        Self {
            source,
            source_width: width,
            source_height: height,
            width,
            height,
            fps: env_u32("MRD_MACOS_CAPTURE_FPS", DEFAULT_STREAM_FPS).clamp(1, 240),
            queue_depth: env_u32("MRD_MACOS_CAPTURE_QUEUE_DEPTH", DEFAULT_QUEUE_DEPTH).clamp(2, 8),
            direct_cv_pixel_buffer: macos_capture_direct_cv_pixel_buffer_enabled(),
            stream: None,
            queue: None,
            shared: Arc::new((
                Mutex::new(ScreenCaptureKitState {
                    latest: None,
                    sequence: 0,
                    error: None,
                }),
                Condvar::new(),
            )),
            last_sequence: 0,
        }
    }

    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    fn set_target_dimensions(&mut self, width: usize, height: usize) {
        let width = width.clamp(2, self.source_width.max(2));
        let height = height.clamp(2, self.source_height.max(2));
        if self.width == width && self.height == height {
            return;
        }

        self.width = width;
        self.height = height;
        self.stop_stream();
        self.reset_state();
    }

    fn set_target_fps(&mut self, fps: u32) {
        let fps = fps.clamp(1, 240);
        if self.fps == fps {
            return;
        }

        self.fps = fps;
        self.stop_stream();
        self.reset_state();
    }

    fn set_direct_cv_pixel_buffer(&mut self, enabled: bool) {
        if self.direct_cv_pixel_buffer == enabled {
            return;
        }
        self.direct_cv_pixel_buffer = enabled;
        self.stop_stream();
        self.reset_state();
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        let timeout = if self.last_sequence == 0 {
            FIRST_FRAME_TIMEOUT
        } else {
            NEXT_FRAME_TIMEOUT
        };
        self.capture_frame_with_timeout(timeout)
    }

    fn capture_frame_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<CapturedFrame, PipelineError> {
        self.start_if_needed()?;

        let deadline = Instant::now() + timeout;
        let (lock, cvar) = &*self.shared;
        let mut state = lock
            .lock()
            .map_err(|_| PipelineError::message("ScreenCaptureKit capture state poisoned"))?;

        loop {
            if let Some(error) = state.error.take() {
                return Err(PipelineError::message(error));
            }

            if state.sequence > self.last_sequence {
                let frame = state.latest.clone().ok_or_else(|| {
                    PipelineError::message("ScreenCaptureKit produced no frame data")
                })?;
                self.last_sequence = state.sequence;
                self.width = frame.width;
                self.height = frame.height;
                return Ok(frame);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(PipelineError::message(
                    "ScreenCaptureKit timed out waiting for a screen frame; Screen Recording permission may be required",
                ));
            }

            let wait = deadline.saturating_duration_since(now);
            let (guard, _) = cvar
                .wait_timeout(state, wait)
                .map_err(|_| PipelineError::message("ScreenCaptureKit capture state poisoned"))?;
            state = guard;
        }
    }

    fn start_if_needed(&mut self) -> Result<(), PipelineError> {
        if self.stream.is_some() {
            return Ok(());
        }

        self.reset_state();
        let content = SCShareableContent::get().map_err(|error| {
            PipelineError::message(format!(
                "ScreenCaptureKit shareable content query failed: {error}"
            ))
        })?;
        let filter = self.content_filter(&content)?;
        let width = u32::try_from(self.width)
            .map_err(|_| PipelineError::message("ScreenCaptureKit capture width is too large"))?;
        let height = u32::try_from(self.height)
            .map_err(|_| PipelineError::message("ScreenCaptureKit capture height is too large"))?;
        let config = SCStreamConfiguration::new()
            .with_width(width)
            .with_height(height)
            .with_pixel_format(screencapturekit_pixel_format())
            .with_shows_cursor(true)
            .with_scales_to_fit(true)
            .with_queue_depth(self.queue_depth)
            .with_fps(self.fps);
        let queue = DispatchQueue::new(
            "com.a1112.rdesk.capture.screencapturekit",
            DispatchQoS::UserInteractive,
        );
        let shared = self.shared.clone();
        let direct_cv_pixel_buffer = self.direct_cv_pixel_buffer;
        let mut stream = SCStream::new(&filter, &config);
        let handler_id = stream.add_output_handler_with_queue(
            move |sample, output_type| {
                handle_screencapturekit_sample(&shared, sample, output_type, direct_cv_pixel_buffer)
            },
            SCStreamOutputType::Screen,
            Some(&queue),
        );

        if handler_id.is_none() {
            return Err(PipelineError::message(
                "ScreenCaptureKit failed to register screen output handler",
            ));
        }

        stream.start_capture().map_err(|error| {
            PipelineError::message(format!("ScreenCaptureKit stream start failed: {error}"))
        })?;

        self.queue = Some(queue);
        self.stream = Some(stream);
        Ok(())
    }

    fn content_filter(
        &mut self,
        content: &SCShareableContent,
    ) -> Result<SCContentFilter, PipelineError> {
        match self.source {
            ScreenCaptureKitSource::Display { display_id } => {
                let displays = content.displays();
                let display = displays
                    .into_iter()
                    .find(|display| display.display_id() == display_id)
                    .or_else(|| content.displays().into_iter().next())
                    .ok_or_else(|| {
                        PipelineError::message("ScreenCaptureKit found no capture display")
                    })?;
                Ok(SCContentFilter::create()
                    .with_display(&display)
                    .with_excluding_windows(&[])
                    .build())
            }
            ScreenCaptureKitSource::Window { window_id } => {
                let window = find_window(content, window_id)?;
                let displays = content.displays();
                let (width, height) = window_pixel_dimensions(window.frame(), &displays);
                self.source_width = width as usize;
                self.source_height = height as usize;
                self.width = self.width.clamp(2, self.source_width.max(2));
                self.height = self.height.clamp(2, self.source_height.max(2));
                Ok(SCContentFilter::create().with_window(&window).build())
            }
        }
    }

    fn reset_state(&mut self) {
        if let Ok(mut state) = self.shared.0.lock() {
            state.latest = None;
            state.sequence = 0;
            state.error = None;
        }
        self.last_sequence = 0;
    }

    fn stop_stream(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.stop_capture();
        }
        self.queue = None;
    }
}

impl Drop for ScreenCaptureKitCapture {
    fn drop(&mut self) {
        self.stop_stream();
    }
}

fn handle_screencapturekit_sample(
    shared: &Arc<(Mutex<ScreenCaptureKitState>, Condvar)>,
    sample: CMSampleBuffer,
    output_type: SCStreamOutputType,
    direct_cv_pixel_buffer: bool,
) {
    if output_type != SCStreamOutputType::Screen {
        return;
    }

    if matches!(
        sample.frame_status(),
        Some(SCFrameStatus::Blank | SCFrameStatus::Suspended | SCFrameStatus::Stopped)
    ) {
        return;
    }

    let Some(buffer) = sample.image_buffer() else {
        return;
    };

    let pixel_format = buffer.pixel_format();
    if pixel_format != BGRA_FOURCC && pixel_format != NV12_VIDEO_RANGE_FOURCC {
        set_screencapturekit_error(
            shared,
            format!(
                "ScreenCaptureKit returned unsupported pixel format 0x{:08x}",
                pixel_format
            ),
        );
        return;
    }

    if pixel_format == NV12_VIDEO_RANGE_FOURCC && direct_cv_pixel_buffer {
        let width = buffer.width();
        let height = buffer.height();
        let timestamp_us = match now_us() {
            Ok(timestamp_us) => timestamp_us,
            Err(error) => {
                set_screencapturekit_error(
                    shared,
                    format!("ScreenCaptureKit timestamp failed: {error}"),
                );
                return;
            }
        };
        let Some(frame) = CapturedFrame::from_macos_cv_pixel_buffer(
            width,
            height,
            FramePixelFormat::Nv12,
            timestamp_us,
            buffer.as_ptr(),
        ) else {
            set_screencapturekit_error(
                shared,
                "ScreenCaptureKit returned a null CVPixelBuffer".to_string(),
            );
            return;
        };
        publish_screencapturekit_frame(shared, frame);
        return;
    }

    let guard = match buffer.lock(CVPixelBufferLockFlags::READ_ONLY) {
        Ok(guard) => guard,
        Err(status) => {
            set_screencapturekit_error(
                shared,
                format!("ScreenCaptureKit pixel buffer lock failed: {status}"),
            );
            return;
        }
    };
    let width = guard.width();
    let height = guard.height();
    let frame_result = match pixel_format {
        BGRA_FOURCC => repack_bgra(guard.as_slice(), width, height, guard.bytes_per_row())
            .map(|packed| (FramePixelFormat::Bgra32, packed)),
        NV12_VIDEO_RANGE_FOURCC => {
            repack_nv12(&guard, width, height).map(|packed| (FramePixelFormat::Nv12, packed))
        }
        _ => unreachable!("unsupported ScreenCaptureKit pixel format was checked above"),
    };
    let (frame_pixel_format, packed) = match frame_result {
        Ok(frame) => frame,
        Err(error) => {
            set_screencapturekit_error(
                shared,
                format!("ScreenCaptureKit frame copy failed: {error}"),
            );
            return;
        }
    };
    let timestamp_us = match now_us() {
        Ok(timestamp_us) => timestamp_us,
        Err(error) => {
            set_screencapturekit_error(
                shared,
                format!("ScreenCaptureKit timestamp failed: {error}"),
            );
            return;
        }
    };

    let frame = CapturedFrame::from_cpu(width, height, frame_pixel_format, timestamp_us, packed);
    publish_screencapturekit_frame(shared, frame);
}

fn publish_screencapturekit_frame(
    shared: &Arc<(Mutex<ScreenCaptureKitState>, Condvar)>,
    frame: CapturedFrame,
) {
    let (lock, cvar) = &**shared;
    if let Ok(mut state) = lock.lock() {
        state.latest = Some(frame);
        state.sequence = state.sequence.saturating_add(1);
        state.error = None;
        cvar.notify_all();
    }
}

fn set_screencapturekit_error(
    shared: &Arc<(Mutex<ScreenCaptureKitState>, Condvar)>,
    message: String,
) {
    let (lock, cvar) = &**shared;
    if let Ok(mut state) = lock.lock() {
        state.error = Some(message);
        cvar.notify_all();
    }
}

fn repack_bgra(
    frame: &[u8],
    width: usize,
    height: usize,
    stride: usize,
) -> Result<Vec<u8>, PipelineError> {
    let row_bytes = width
        .checked_mul(4)
        .ok_or_else(|| PipelineError::message("captured frame width overflow"))?;

    if stride < row_bytes || frame.len() < stride * height {
        return Err(PipelineError::message("invalid captured frame stride"));
    }

    if stride == row_bytes {
        return Ok(frame[..row_bytes * height].to_vec());
    }

    let mut packed = Vec::with_capacity(row_bytes * height);
    for row in 0..height {
        let start = row * stride;
        packed.extend_from_slice(&frame[start..start + row_bytes]);
    }
    Ok(packed)
}

fn repack_nv12(
    guard: &CVPixelBufferLockGuard<'_>,
    width: usize,
    height: usize,
) -> Result<Vec<u8>, PipelineError> {
    if guard.plane_count() < 2 {
        return Err(PipelineError::message(format!(
            "NV12 pixel buffer has {} planes; expected at least 2",
            guard.plane_count()
        )));
    }

    let y_size = width
        .checked_mul(height)
        .ok_or_else(|| PipelineError::message("NV12 luma plane size overflow"))?;
    let uv_height = height.div_ceil(2);
    let uv_size = width
        .checked_mul(uv_height)
        .ok_or_else(|| PipelineError::message("NV12 chroma plane size overflow"))?;
    let mut packed = vec![0_u8; y_size + uv_size];

    for row_index in 0..height {
        let row = guard.plane_row(0, row_index).ok_or_else(|| {
            PipelineError::message(format!("NV12 luma plane row {row_index} is unavailable"))
        })?;
        if row.len() < width {
            return Err(PipelineError::message(format!(
                "NV12 luma row too short: {} < {width}",
                row.len()
            )));
        }
        let dst_start = row_index * width;
        packed[dst_start..dst_start + width].copy_from_slice(&row[..width]);
    }

    for row_index in 0..uv_height {
        let row = guard.plane_row(1, row_index).ok_or_else(|| {
            PipelineError::message(format!("NV12 chroma plane row {row_index} is unavailable"))
        })?;
        if row.len() < width {
            return Err(PipelineError::message(format!(
                "NV12 chroma row too short: {} < {width}",
                row.len()
            )));
        }
        let dst_start = y_size + row_index * width;
        packed[dst_start..dst_start + width].copy_from_slice(&row[..width]);
    }

    Ok(packed)
}

fn screencapturekit_pixel_format() -> PixelFormat {
    match env::var("MRD_MACOS_CAPTURE_PIXEL_FORMAT")
        .unwrap_or_else(|_| String::from("nv12"))
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "bgra" | "argb" => PixelFormat::BGRA,
        _ => PixelFormat::YCbCr_420v,
    }
}

fn macos_capture_direct_cv_pixel_buffer_enabled() -> bool {
    env::var("MRD_MACOS_CAPTURE_DIRECT_CVPIXELBUFFER")
        .ok()
        .as_deref()
        .map(str::trim)
        .map(|value| !matches!(value, "0" | "false" | "FALSE" | "off" | "OFF" | "no" | "NO"))
        .unwrap_or(true)
}

#[derive(Debug, Clone, Copy)]
struct CaptureBackendPreference {
    force_coregraphics: bool,
    require_screencapturekit: bool,
}

fn capture_backend_preference() -> CaptureBackendPreference {
    let value = env::var("MRD_MACOS_CAPTURE_BACKEND")
        .unwrap_or_else(|_| String::from("auto"))
        .to_ascii_lowercase();
    CaptureBackendPreference {
        force_coregraphics: matches!(value.as_str(), "coregraphics" | "cg" | "legacy"),
        require_screencapturekit: matches!(
            value.as_str(),
            "screencapturekit" | "screen_capture_kit" | "sck"
        ),
    }
}

fn screencapturekit_disabled() -> bool {
    env_bool("MRD_DISABLE_SCREENCAPTUREKIT")
}

fn env_bool(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_u32(name: &str, default_value: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default_value)
}

fn now_us() -> Result<u64, PipelineError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| PipelineError::message(format!("system time failed: {error}")))?
        .as_micros() as u64)
}

#[cfg(test)]
mod tests {
    use super::{
        capture_backend_preference, display_refresh_hz_from_core_video_time,
        display_refresh_hz_from_rate, pixel_dimensions_for_scale, repack_bgra, CVTime,
    };
    use std::{env, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn repack_bgra_strips_padding_stride() {
        let frame = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0,
        ];

        let packed = repack_bgra(&frame, 2, 2, 12).expect("packed frame");

        assert_eq!(
            packed,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn repack_bgra_uses_contiguous_rows() {
        let frame = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let packed = repack_bgra(&frame, 2, 1, 8).expect("packed frame");

        assert_eq!(packed, frame);
    }

    #[test]
    fn backend_preference_defaults_to_auto_screencapturekit() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        env::remove_var("MRD_MACOS_CAPTURE_BACKEND");

        let preference = capture_backend_preference();

        assert!(!preference.force_coregraphics);
        assert!(!preference.require_screencapturekit);
    }

    #[test]
    fn backend_preference_supports_explicit_coregraphics() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        env::set_var("MRD_MACOS_CAPTURE_BACKEND", "coregraphics");

        let preference = capture_backend_preference();

        assert!(preference.force_coregraphics);
        assert!(!preference.require_screencapturekit);
        env::remove_var("MRD_MACOS_CAPTURE_BACKEND");
    }

    #[test]
    fn backend_preference_supports_strict_screencapturekit() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        env::set_var("MRD_MACOS_CAPTURE_BACKEND", "sck");

        let preference = capture_backend_preference();

        assert!(!preference.force_coregraphics);
        assert!(preference.require_screencapturekit);
        env::remove_var("MRD_MACOS_CAPTURE_BACKEND");
    }

    #[test]
    fn window_pixel_dimensions_apply_display_scale() {
        assert_eq!(pixel_dimensions_for_scale(640.0, 360.0, 2.0), (1280, 720));
        assert_eq!(pixel_dimensions_for_scale(0.0, 1.0, 2.0), (2, 2));
    }

    #[test]
    fn display_refresh_hz_from_rate_uses_positive_rounded_rates() {
        assert_eq!(display_refresh_hz_from_rate(59.94), Some(60));
        assert_eq!(display_refresh_hz_from_rate(120.0), Some(120));
        assert_eq!(display_refresh_hz_from_rate(0.0), None);
        assert_eq!(display_refresh_hz_from_rate(f64::NAN), None);
    }

    #[test]
    fn display_refresh_hz_from_core_video_time_uses_nominal_period() {
        assert_eq!(
            display_refresh_hz_from_core_video_time(CVTime {
                time_value: 1,
                time_scale: 120,
                flags: 0,
            }),
            Some(120)
        );
        assert_eq!(
            display_refresh_hz_from_core_video_time(CVTime {
                time_value: 1001,
                time_scale: 120_000,
                flags: 0,
            }),
            Some(120)
        );
        assert_eq!(
            display_refresh_hz_from_core_video_time(CVTime {
                time_value: 0,
                time_scale: 120,
                flags: 0,
            }),
            None
        );
    }
}
