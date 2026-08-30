#[cfg(any(test, target_os = "macos"))]
use super::media_frame_preparation::even_dimension;
#[cfg(target_os = "macos")]
use super::media_frame_preparation::h264_target_dimensions;
#[cfg(windows)]
use super::media_frame_preparation::window_h264_capture_dimensions;
#[cfg(test)]
use super::now_ms;
#[cfg(target_os = "macos")]
use super::{
    lan_capture_pump_drives_sender, lan_capture_pump_enabled, lan_capture_pump_repeat_latest,
    macos_capture_pump_repeat_grace_timeout, now_us, LAN_CAPTURE_PUMP_ERROR_BACKOFF,
    LAN_CAPTURE_PUMP_QUEUE_CAPACITY, LAN_CAPTURE_PUMP_WAIT_TIMEOUT,
};
#[cfg(windows)]
use super::{
    parse_windows_window_source_id, windows_lan_capture_backend,
    windows_lan_capture_backend_for_profile, windows_lan_nvenc_h264_available,
    WindowsLanCaptureBackend,
};
use crate::app_state::AppState;
use anyhow::{Context, Result};
#[cfg(test)]
use mrd_ipc::CaptureSource;
#[cfg(not(test))]
use mrd_ipc::CaptureSourceSelection;
use mrd_ipc::MediaProfile;
use mrd_pipeline_core::CapturedFrame;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use mrd_pipeline_core::FrameCapture;
#[cfg(any(test, target_os = "macos"))]
use mrd_pipeline_core::FramePixelFormat;
use mrd_proto::SessionId;
#[cfg(target_os = "macos")]
use std::collections::VecDeque;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::Condvar as StdCondvar;
#[cfg(target_os = "macos")]
use std::sync::Mutex as StdMutex;
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant as StdInstant;

pub(crate) enum LanFrameCapture {
    #[cfg(windows)]
    DxgiShared(mrd_capture_dxgi::DxgiSharedTextureCapture),
    #[cfg(windows)]
    Winrt(mrd_capture_winrt::WinrtCapture),
    #[cfg(target_os = "macos")]
    Macos(mrd_capture_macos::MacosScreenCapture),
    #[cfg(target_os = "macos")]
    MacosSyntheticCv(MacosSyntheticCvPixelBufferCapture),
    #[cfg(target_os = "linux")]
    Pipewire(mrd_capture_pipewire::PipewireScreenCapture),
    #[cfg(test)]
    Synthetic(SyntheticFrameCapture),
}

#[cfg(windows)]
unsafe impl Send for LanFrameCapture {}

impl LanFrameCapture {
    pub(crate) fn capture_frame(&mut self) -> Result<CapturedFrame> {
        match self {
            #[cfg(windows)]
            LanFrameCapture::DxgiShared(capture) => {
                mrd_pipeline_core::FrameCapture::capture_frame(capture)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))
            }
            #[cfg(windows)]
            LanFrameCapture::Winrt(capture) => capture
                .capture_frame()
                .map_err(|error| anyhow::anyhow!(error.to_string())),
            #[cfg(target_os = "macos")]
            LanFrameCapture::Macos(capture) => capture
                .capture_frame()
                .map_err(|error| anyhow::anyhow!(error.to_string())),
            #[cfg(target_os = "macos")]
            LanFrameCapture::MacosSyntheticCv(capture) => capture.capture_frame(),
            #[cfg(target_os = "linux")]
            LanFrameCapture::Pipewire(capture) => capture
                .capture_frame()
                .map_err(|error| anyhow::anyhow!(error.to_string())),
            #[cfg(test)]
            LanFrameCapture::Synthetic(capture) => {
                Ok(mrd_pipeline_core::FrameCapture::capture_frame(capture)?)
            }
            #[cfg(not(any(windows, target_os = "macos", target_os = "linux", test)))]
            _ => anyhow::bail!("Frame capture not supported on this platform"),
        }
    }
}

pub(super) enum LanSenderFrameCapture {
    Direct(LanFrameCapture),
    #[cfg(target_os = "macos")]
    Pumped(MacosPumpedLanFrameCapture),
}

pub(super) struct LanCapturedSenderFrame {
    pub(super) frame: CapturedFrame,
    pub(super) repeated_latest_frame: bool,
}

impl LanSenderFrameCapture {
    pub(super) fn new(capture: LanFrameCapture, _profile: &MediaProfile) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            if matches!(capture, LanFrameCapture::Macos(_)) && lan_capture_pump_enabled() {
                return Ok(Self::Pumped(MacosPumpedLanFrameCapture::new(
                    capture,
                    macos_capture_pump_repeat_grace_timeout(_profile),
                )?));
            }
        }

        Ok(Self::Direct(capture))
    }

    pub(super) fn capture_frame(&mut self) -> Result<LanCapturedSenderFrame> {
        match self {
            Self::Direct(capture) => Ok(LanCapturedSenderFrame {
                frame: capture.capture_frame()?,
                repeated_latest_frame: false,
            }),
            #[cfg(target_os = "macos")]
            Self::Pumped(capture) => capture.capture_frame(),
        }
    }

    pub(super) fn drives_sender_pacing(&self) -> bool {
        match self {
            Self::Direct(_) => false,
            #[cfg(target_os = "macos")]
            Self::Pumped(_) => lan_capture_pump_drives_sender(),
        }
    }

    pub(super) fn repeats_latest_frame(&self) -> bool {
        match self {
            Self::Direct(_) => false,
            #[cfg(target_os = "macos")]
            Self::Pumped(_) => lan_capture_pump_repeat_latest(),
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) struct MacosPumpedLanFrameCapture {
    pub(super) shared: Arc<(StdMutex<MacosPumpedLanFrameState>, StdCondvar)>,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) worker: Option<thread::JoinHandle<()>>,
    pub(super) repeat_grace_timeout: Duration,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(super) struct MacosPumpedLanFrameState {
    pub(super) frames: VecDeque<CapturedFrame>,
    pub(super) latest_frame: Option<CapturedFrame>,
    pub(super) sequence: u64,
    pub(super) error: Option<String>,
}

#[cfg(target_os = "macos")]
impl MacosPumpedLanFrameCapture {
    fn new(mut capture: LanFrameCapture, repeat_grace_timeout: Duration) -> Result<Self> {
        let shared = Arc::new((
            StdMutex::new(MacosPumpedLanFrameState {
                frames: VecDeque::new(),
                latest_frame: None,
                sequence: 0,
                error: None,
            }),
            StdCondvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_shared = shared.clone();
        let worker_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("mrd-lan-capture-pump".to_string())
            .spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match capture.capture_frame() {
                        Ok(frame) => {
                            let (lock, cvar) = &*worker_shared;
                            if let Ok(mut state) = lock.lock() {
                                while state.frames.len() >= LAN_CAPTURE_PUMP_QUEUE_CAPACITY {
                                    state.frames.pop_front();
                                }
                                state.latest_frame = Some(frame.clone());
                                state.frames.push_back(frame);
                                state.sequence = state.sequence.wrapping_add(1).max(1);
                                state.error = None;
                                cvar.notify_all();
                            }
                        }
                        Err(error) => {
                            let (lock, cvar) = &*worker_shared;
                            if let Ok(mut state) = lock.lock() {
                                state.error = Some(format!("{error:#}"));
                                cvar.notify_all();
                            }
                            thread::sleep(LAN_CAPTURE_PUMP_ERROR_BACKOFF);
                        }
                    }
                }
            })
            .context("failed to start macOS LAN capture pump")?;

        Ok(Self {
            shared,
            stop,
            worker: Some(worker),
            repeat_grace_timeout,
        })
    }

    pub(super) fn capture_frame(&mut self) -> Result<LanCapturedSenderFrame> {
        let deadline = StdInstant::now() + LAN_CAPTURE_PUMP_WAIT_TIMEOUT;
        let (lock, cvar) = &*self.shared;
        let mut state = lock
            .lock()
            .map_err(|_| anyhow::anyhow!("macOS LAN capture pump state poisoned"))?;
        let mut waited_for_repeat_grace = false;

        loop {
            if let Some(frame) = state.frames.pop_back() {
                state.frames.clear();
                return Ok(LanCapturedSenderFrame {
                    frame,
                    repeated_latest_frame: false,
                });
            }

            if let Some(error) = state.error.take() {
                anyhow::bail!("macOS LAN capture pump failed: {error}");
            }

            if lan_capture_pump_repeat_latest() {
                if state.latest_frame.is_some()
                    && !waited_for_repeat_grace
                    && !self.repeat_grace_timeout.is_zero()
                {
                    let now = StdInstant::now();
                    if now < deadline {
                        let wait = self
                            .repeat_grace_timeout
                            .min(deadline.saturating_duration_since(now));
                        let (guard, _) = cvar.wait_timeout(state, wait).map_err(|_| {
                            anyhow::anyhow!("macOS LAN capture pump state poisoned")
                        })?;
                        state = guard;
                        waited_for_repeat_grace = true;
                        continue;
                    }
                }

                if let Some(frame) = state.latest_frame.as_ref() {
                    let mut repeated = frame.clone();
                    repeated.timestamp_us = now_us();
                    return Ok(LanCapturedSenderFrame {
                        frame: repeated,
                        repeated_latest_frame: true,
                    });
                }
            }

            let now = StdInstant::now();
            if now >= deadline {
                anyhow::bail!("macOS LAN capture pump timed out waiting for a captured frame");
            }

            let wait = deadline.saturating_duration_since(now);
            let (guard, _) = cvar
                .wait_timeout(state, wait)
                .map_err(|_| anyhow::anyhow!("macOS LAN capture pump state poisoned"))?;
            state = guard;
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosPumpedLanFrameCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.shared.1.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(target_os = "macos")]
#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    fn CVPixelBufferCreate(
        allocator: *const std::ffi::c_void,
        width: usize,
        height: usize,
        pixel_format_type: u32,
        pixel_buffer_attributes: *const std::ffi::c_void,
        pixel_buffer_out: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn CVPixelBufferLockBaseAddress(pixel_buffer: *mut std::ffi::c_void, lock_flags: u64) -> i32;
    fn CVPixelBufferUnlockBaseAddress(pixel_buffer: *mut std::ffi::c_void, lock_flags: u64) -> i32;
    fn CVPixelBufferGetBaseAddressOfPlane(
        pixel_buffer: *mut std::ffi::c_void,
        plane_index: usize,
    ) -> *mut std::ffi::c_void;
    fn CVPixelBufferGetBytesPerRowOfPlane(
        pixel_buffer: *mut std::ffi::c_void,
        plane_index: usize,
    ) -> usize;
    fn CVPixelBufferGetHeightOfPlane(
        pixel_buffer: *mut std::ffi::c_void,
        plane_index: usize,
    ) -> usize;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: *const std::ffi::c_void);
}

#[cfg(target_os = "macos")]
const MACOS_SYNTHETIC_CV_SUCCESS: i32 = 0;
#[cfg(target_os = "macos")]
const MACOS_SYNTHETIC_CV_PIXEL_FORMAT_NV12_VIDEO_RANGE: u32 = u32::from_be_bytes(*b"420v");
#[cfg(target_os = "macos")]
const MACOS_SYNTHETIC_CV_BUFFER_POOL_CAPACITY: usize = 16;

#[cfg(target_os = "macos")]
struct MacosSyntheticCvPixelBuffer {
    ptr: *mut std::ffi::c_void,
}

#[cfg(target_os = "macos")]
unsafe impl Send for MacosSyntheticCvPixelBuffer {}

#[cfg(target_os = "macos")]
impl MacosSyntheticCvPixelBuffer {
    fn new_nv12(width: usize, height: usize) -> Result<Self> {
        let mut pixel_buffer = std::ptr::null_mut();
        let status = unsafe {
            CVPixelBufferCreate(
                std::ptr::null(),
                width,
                height,
                MACOS_SYNTHETIC_CV_PIXEL_FORMAT_NV12_VIDEO_RANGE,
                std::ptr::null(),
                &mut pixel_buffer,
            )
        };
        if status != MACOS_SYNTHETIC_CV_SUCCESS || pixel_buffer.is_null() {
            anyhow::bail!("CVPixelBufferCreate(NV12 synthetic capture) failed: status={status}");
        }
        Ok(Self { ptr: pixel_buffer })
    }

    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.ptr
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosSyntheticCvPixelBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                CFRelease(self.ptr.cast_const());
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

#[cfg(target_os = "macos")]
struct MacosSyntheticCvPixelBufferCapture {
    width: usize,
    height: usize,
    frame_index: u64,
    buffers: Vec<MacosSyntheticCvPixelBuffer>,
}

#[cfg(target_os = "macos")]
impl MacosSyntheticCvPixelBufferCapture {
    fn new(profile: &MediaProfile) -> Result<Self> {
        let width = even_dimension(profile.width as usize).max(2);
        let height = even_dimension(profile.height as usize).max(2);
        let mut buffers = Vec::with_capacity(MACOS_SYNTHETIC_CV_BUFFER_POOL_CAPACITY);
        for _ in 0..MACOS_SYNTHETIC_CV_BUFFER_POOL_CAPACITY {
            buffers.push(MacosSyntheticCvPixelBuffer::new_nv12(width, height)?);
        }
        tracing::info!(
            source_id = crate::capture_source::TEST_SYNTHETIC_CV_CAPTURE_SOURCE_ID,
            width,
            height,
            pool_capacity = buffers.len(),
            "created macOS synthetic CVPixelBuffer LAN capture"
        );
        Ok(Self {
            width,
            height,
            frame_index: 0,
            buffers,
        })
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame> {
        let buffer_index = (self.frame_index as usize) % self.buffers.len();
        let pixel_buffer = self.buffers[buffer_index].as_ptr();
        self.fill_pixel_buffer(pixel_buffer)?;
        let timestamp_us = now_us();
        self.frame_index = self.frame_index.wrapping_add(1);
        CapturedFrame::from_macos_cv_pixel_buffer(
            self.width,
            self.height,
            FramePixelFormat::Nv12,
            timestamp_us,
            pixel_buffer,
        )
        .ok_or_else(|| anyhow::anyhow!("failed to retain synthetic macOS CVPixelBuffer frame"))
    }

    fn fill_pixel_buffer(&self, pixel_buffer: *mut std::ffi::c_void) -> Result<()> {
        let status = unsafe { CVPixelBufferLockBaseAddress(pixel_buffer, 0) };
        if status != MACOS_SYNTHETIC_CV_SUCCESS {
            anyhow::bail!("CVPixelBufferLockBaseAddress(synthetic) failed: status={status}");
        }

        let y_value = 16_u8.saturating_add((self.frame_index % 220) as u8);
        let fill_result = Self::fill_plane(pixel_buffer, 0, y_value)
            .and_then(|_| Self::fill_plane(pixel_buffer, 1, 128));
        let unlock_status = unsafe { CVPixelBufferUnlockBaseAddress(pixel_buffer, 0) };
        if let Err(error) = fill_result {
            return Err(error);
        }
        if unlock_status != MACOS_SYNTHETIC_CV_SUCCESS {
            anyhow::bail!(
                "CVPixelBufferUnlockBaseAddress(synthetic) failed: status={unlock_status}"
            );
        }
        Ok(())
    }

    fn fill_plane(
        pixel_buffer: *mut std::ffi::c_void,
        plane_index: usize,
        value: u8,
    ) -> Result<()> {
        let base = unsafe { CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, plane_index) };
        if base.is_null() {
            anyhow::bail!("synthetic CVPixelBuffer plane {plane_index} base address is null");
        }
        let stride = unsafe { CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, plane_index) };
        let rows = unsafe { CVPixelBufferGetHeightOfPlane(pixel_buffer, plane_index) };
        let len = stride
            .checked_mul(rows)
            .ok_or_else(|| anyhow::anyhow!("synthetic CVPixelBuffer plane size overflow"))?;
        let plane = unsafe { std::slice::from_raw_parts_mut(base.cast::<u8>(), len) };
        plane.fill(value);
        Ok(())
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct SyntheticFrameCapture {
    width: usize,
    height: usize,
    frame_index: u64,
}

#[cfg(test)]
impl SyntheticFrameCapture {
    fn new(profile: &MediaProfile) -> Self {
        let width = even_dimension(profile.width as usize).clamp(2, 640);
        let height = even_dimension(profile.height as usize).clamp(2, 360);
        Self {
            width,
            height,
            frame_index: 0,
        }
    }
}

#[cfg(test)]
impl mrd_pipeline_core::FrameCapture for SyntheticFrameCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, mrd_pipeline_core::PipelineError> {
        let mut rgb = vec![0_u8; self.width * self.height * 3];
        for y in 0..self.height {
            for x in 0..self.width {
                let index = (y * self.width + x) * 3;
                rgb[index] = ((x + self.frame_index as usize * 3) % 256) as u8;
                rgb[index + 1] = ((y + self.frame_index as usize * 5) % 256) as u8;
                rgb[index + 2] = (((x ^ y) + self.frame_index as usize * 7) % 256) as u8;
            }
        }
        self.frame_index = self.frame_index.wrapping_add(1);
        Ok(CapturedFrame::from_cpu(
            self.width,
            self.height,
            FramePixelFormat::Rgb24,
            now_ms().saturating_mul(1_000),
            rgb,
        ))
    }
}

#[cfg(test)]
pub(super) const TEST_SYNTHETIC_CAPTURE_SOURCE_ID: &str = "test:synthetic";

#[cfg(test)]
pub(super) fn synthetic_capture_source() -> CaptureSource {
    CaptureSource {
        id: TEST_SYNTHETIC_CAPTURE_SOURCE_ID.to_string(),
        platform: "test".to_string(),
        source_kind: "display".to_string(),
        title: "Synthetic desktop frame source".to_string(),
        class_name: "SyntheticCapture".to_string(),
        width: 640,
        height: 360,
        process_id: 0,
        app_name: Some("mrd-service test source".to_string()),
        bundle_identifier: None,
        preview_data_url: None,
        preview_width: None,
        preview_height: None,
    }
}

pub(crate) async fn selected_capture_source_id(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) -> Result<String> {
    if let Some(selection) = app_state.capture_sources.lock().await.get(session_id) {
        return Ok(selection.source.id);
    }

    #[cfg(test)]
    {
        Ok(TEST_SYNTHETIC_CAPTURE_SOURCE_ID.to_string())
    }

    #[cfg(not(test))]
    {
        let source = crate::capture_source::default_capture_source(false)
            .context("no default capture source is available for LAN media sender")?;
        app_state.capture_sources.lock().await.set(
            session_id.clone(),
            CaptureSourceSelection {
                session_id: session_id.clone(),
                source: source.clone(),
                status: "selected".to_string(),
                reason: Some("default fullscreen capture source".to_string()),
            },
        );
        Ok(source.id)
    }
}

pub(super) async fn create_lan_frame_capture(
    source_id: &str,
    _profile: &MediaProfile,
) -> Result<LanFrameCapture> {
    #[cfg(test)]
    if source_id == TEST_SYNTHETIC_CAPTURE_SOURCE_ID {
        return Ok(LanFrameCapture::Synthetic(SyntheticFrameCapture::new(
            _profile,
        )));
    }

    #[cfg(windows)]
    {
        create_windows_lan_frame_capture(source_id, _profile)
    }

    #[cfg(target_os = "macos")]
    {
        if crate::capture_source::test_synthetic_cv_capture_enabled()
            && crate::capture_source::is_test_synthetic_cv_capture_source_id(source_id)
        {
            return Ok(LanFrameCapture::MacosSyntheticCv(
                MacosSyntheticCvPixelBufferCapture::new(_profile)?,
            ));
        }
        return create_macos_lan_frame_capture(source_id, _profile);
    }

    #[cfg(target_os = "linux")]
    {
        return Ok(LanFrameCapture::Pipewire(
            crate::capture_source::create_frame_capture_async(source_id).await?,
        ));
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!(
            "remote desktop capture is currently only available on Windows, macOS, and Linux"
        )
    }
}

/// Build a CPU-backed capture path for software encoders. This deliberately
/// bypasses platform shared-texture selection used by the LAN hardware path.
pub(crate) async fn create_software_frame_capture(
    source_id: &str,
    profile: &MediaProfile,
) -> Result<LanFrameCapture> {
    #[cfg(windows)]
    {
        let _ = profile;
        create_windows_lan_winrt_capture(source_id)
    }

    #[cfg(target_os = "macos")]
    {
        let mut capture = create_macos_lan_frame_capture(source_id, profile)?;
        if let LanFrameCapture::Macos(capture) = &mut capture {
            capture.force_cpu_output();
        }
        Ok(capture)
    }

    #[cfg(target_os = "linux")]
    {
        let _ = profile;
        Ok(LanFrameCapture::Pipewire(
            crate::capture_source::create_frame_capture_async(source_id).await?,
        ))
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (source_id, profile);
        anyhow::bail!(
            "remote desktop capture is currently only available on Windows, macOS, and Linux"
        )
    }
}

#[cfg(target_os = "macos")]
fn create_macos_lan_frame_capture(
    source_id: &str,
    profile: &MediaProfile,
) -> Result<LanFrameCapture> {
    let mut capture = crate::capture_source::create_frame_capture(source_id)?;
    let (target_width, target_height) =
        h264_target_dimensions(capture.width(), capture.height(), profile);
    capture.set_target_dimensions(target_width, target_height);
    if std::env::var("MRD_MACOS_CAPTURE_FPS").is_err() {
        capture.set_target_fps(macos_lan_capture_stream_fps(profile));
    }
    Ok(LanFrameCapture::Macos(capture))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_lan_capture_stream_fps(profile: &MediaProfile) -> u32 {
    let requested_fps = if lan_capture_pump_enabled() && lan_capture_pump_drives_sender() {
        profile.fps.max(1)
    } else {
        profile.fps.max(1).saturating_mul(2)
    };
    requested_fps.clamp(1, 240)
}

#[cfg(windows)]
fn create_windows_lan_frame_capture(
    source_id: &str,
    profile: &MediaProfile,
) -> Result<LanFrameCapture> {
    let nvenc_h264_available = windows_lan_nvenc_h264_available();
    match windows_lan_capture_backend(source_id, nvenc_h264_available) {
        WindowsLanCaptureBackend::DxgiShared => {
            let device_name = crate::display_mode::display_device_name_for_source_id(source_id)
                .with_context(|| format!("failed to resolve Windows display for {source_id}"))?;
            let mut capture =
                mrd_capture_dxgi::DxgiSharedTextureCapture::new_for_device_name(&device_name)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))
                    .with_context(|| {
                        format!(
                            "failed to create DXGI shared capture for {source_id} ({device_name})"
                        )
                    })?;
            if windows_lan_capture_backend_for_profile(
                source_id,
                capture.width(),
                capture.height(),
                profile,
                nvenc_h264_available,
            ) != WindowsLanCaptureBackend::DxgiShared
            {
                return create_windows_lan_winrt_capture(source_id);
            }
            capture.set_target_dimensions(profile.width as usize, profile.height as usize);
            Ok(LanFrameCapture::DxgiShared(capture))
        }
        WindowsLanCaptureBackend::WinrtWindowShared => {
            let hwnd = parse_windows_window_source_id(source_id)?;
            let mut capture =
                mrd_capture_winrt::WinrtCapture::from_window_handle_shared_texture(hwnd)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))
                    .with_context(|| {
                        format!("failed to create WinRT shared window capture for {source_id}")
                    })?;
            if windows_lan_capture_backend_for_profile(
                source_id,
                capture.width(),
                capture.height(),
                profile,
                nvenc_h264_available,
            ) != WindowsLanCaptureBackend::WinrtWindowShared
            {
                return create_windows_lan_winrt_capture(source_id);
            }
            let (target_width, target_height) =
                window_h264_capture_dimensions(profile.width as usize, profile.height as usize);
            capture.set_target_dimensions(target_width, target_height);
            capture
                .start()
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .with_context(|| {
                    format!(
                        "failed to start WinRT shared window capture for {source_id} (WinrtWindowShared, hwnd=0x{hwnd:x})"
                    )
                })?;
            Ok(LanFrameCapture::Winrt(capture))
        }
        WindowsLanCaptureBackend::Winrt => create_windows_lan_winrt_capture(source_id),
    }
}

#[cfg(windows)]
fn create_windows_lan_winrt_capture(source_id: &str) -> Result<LanFrameCapture> {
    Ok(LanFrameCapture::Winrt(
        crate::capture_source::create_frame_capture(source_id)?,
    ))
}

pub(super) fn capture_source_kind_from_id(source_id: &str) -> Option<String> {
    source_id
        .trim()
        .split(':')
        .nth(1)
        .filter(|kind| !kind.is_empty())
        .map(|kind| kind.replace('-', "_"))
}
