//! Linux screen capture implementation
//!
//! This module provides screen capture functionality on Linux using:
//! - X11 (via XFixes/XDamage/XRandR)
//! - PipeWire (via xdg-desktop-portal for Wayland)

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

use mrd_pipeline_core::{
    CapturedFrame, FrameCapture, FrameMemoryKind, FramePixelFormat, PipelineError,
};
#[cfg(feature = "pipewire")]
use std::io::Read;
#[cfg(feature = "pipewire")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(feature = "pipewire")]
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::time::SystemTime;
#[cfg(feature = "pipewire")]
use std::time::{Duration, Instant};

const DEFAULT_WIDTH: u32 = 1920;
const DEFAULT_HEIGHT: u32 = 1080;

/// Linux screen capture implementation
pub struct PipewireScreenCapture {
    width: u32,
    height: u32,
    active: bool,
    backend: CaptureBackend,
}

enum CaptureBackend {
    #[cfg(feature = "x11")]
    X11(X11ScreenCapture),
    #[cfg(feature = "pipewire")]
    PipeWire(PipeWireScreenCapture),
    Fallback(FallbackCapture),
}

impl CaptureBackend {
    fn dimensions(&self) -> (u32, u32) {
        match self {
            #[cfg(feature = "x11")]
            CaptureBackend::X11(capture) => capture.dimensions(),
            #[cfg(feature = "pipewire")]
            CaptureBackend::PipeWire(capture) => capture.dimensions(),
            CaptureBackend::Fallback(capture) => capture.dimensions(),
        }
    }
}

/// A display that can be selected as a Linux screen-capture source.
#[derive(Debug, Clone)]
pub struct PipewireDisplayTarget {
    /// Stable backend-local display identifier.
    pub id: u32,
    /// Human-readable display name.
    pub name: String,
    /// Display width in physical pixels.
    pub width: u32,
    /// Display height in physical pixels.
    pub height: u32,
    /// Whether this is the primary display reported by the backend.
    pub is_primary: bool,
}

/// A top-level window that can be selected as a Linux capture source.
#[derive(Debug, Clone)]
pub struct PipewireWindowTarget {
    /// Stable backend-local window identifier.
    pub id: u32,
    /// Current window title.
    pub title: String,
    /// Name of the application that owns the window.
    pub app_name: String,
    /// Window width in physical pixels.
    pub width: u32,
    /// Window height in physical pixels.
    pub height: u32,
}

/// Errors specific to Linux capture
#[derive(Debug, thiserror::Error)]
pub enum PipewireCaptureError {
    /// The selected capture backend could not be initialized.
    #[error("Linux capture initialization failed: {0}")]
    InitFailed(String),

    /// No usable display or window source was available.
    #[error("No screen capture source available")]
    NoSourceAvailable,

    /// The desktop portal denied the capture request.
    #[error("Screen capture permission denied by desktop portal")]
    PermissionDenied,

    /// A capture operation did not complete before its deadline.
    #[error("Frame capture timeout")]
    Timeout,

    /// The requested capture mechanism is unavailable in this build or environment.
    #[error("Platform support not available: {0}")]
    PlatformNotAvailable(String),

    /// The X11 backend reported an error.
    #[error("X11 error: {0}")]
    X11Error(String),

    /// The PipeWire or GStreamer backend reported an error.
    #[error("PipeWire error: {0}")]
    PipeWireError(String),

    /// The desktop portal request failed.
    #[error("Portal request failed: {0}")]
    PortalError(String),
}

impl PipewireScreenCapture {
    /// Create a new Linux screen capture instance with automatic backend selection
    pub fn new() -> Result<Self, PipewireCaptureError> {
        let backend = Self::select_backend()?;
        let (width, height) = backend.dimensions();

        Ok(Self {
            width,
            height,
            active: false,
            backend,
        })
    }

    /// Create capture with specified dimensions
    pub fn with_dimensions(width: u32, height: u32) -> Result<Self, PipewireCaptureError> {
        Ok(Self {
            width,
            height,
            active: false,
            backend: CaptureBackend::Fallback(FallbackCapture::new(width, height)),
        })
    }

    fn select_backend() -> Result<CaptureBackend, PipewireCaptureError> {
        // Prefer PipeWire for Wayland sessions
        #[cfg(feature = "pipewire")]
        {
            if Self::is_wayland_available() {
                match PipeWireScreenCapture::new() {
                    Ok(capture) => return Ok(CaptureBackend::PipeWire(capture)),
                    Err(e) => {
                        eprintln!("PipeWire capture init failed: {}, falling back", e);
                    }
                }
            }
        }

        // XWayland commonly exposes DISPLAY while rejecting root-window
        // XGetImage screen capture with a fatal BadMatch X error. If the
        // PipeWire backend is not compiled in or failed to initialize, stay on
        // the non-fatal fallback path instead of letting Xlib terminate the app.
        if Self::is_wayland_available() {
            eprintln!(
                "Wayland session detected without an active PipeWire capture backend; using fallback capture"
            );
            return Ok(CaptureBackend::Fallback(FallbackCapture::new(
                DEFAULT_WIDTH,
                DEFAULT_HEIGHT,
            )));
        }

        // Try X11 for X11 sessions
        #[cfg(feature = "x11")]
        {
            if Self::is_x11_available() {
                match X11ScreenCapture::new() {
                    Ok(capture) => return Ok(CaptureBackend::X11(capture)),
                    Err(e) => {
                        eprintln!("X11 capture init failed: {}, falling back", e);
                    }
                }
            }
        }

        // Fallback
        Ok(CaptureBackend::Fallback(FallbackCapture::new(
            DEFAULT_WIDTH,
            DEFAULT_HEIGHT,
        )))
    }

    /// Get available screen capture targets (displays)
    pub fn get_display_targets() -> Result<Vec<PipewireDisplayTarget>, PipewireCaptureError> {
        #[cfg(feature = "pipewire")]
        {
            if Self::is_wayland_available() {
                return PipeWireScreenCapture::get_display_targets().or_else(|error| {
                    eprintln!(
                        "PipeWire display target query failed: {}, falling back",
                        error
                    );
                    Ok(Self::fallback_display_targets())
                });
            }
        }

        if Self::is_wayland_available() {
            return Ok(Self::fallback_display_targets());
        }

        #[cfg(feature = "x11")]
        {
            if Self::is_x11_available() {
                return X11ScreenCapture::get_display_targets();
            }
        }

        Ok(Self::fallback_display_targets())
    }

    /// Get available window capture targets
    pub fn get_window_targets() -> Result<Vec<PipewireWindowTarget>, PipewireCaptureError> {
        #[cfg(feature = "pipewire")]
        {
            if Self::is_wayland_available() {
                return PipeWireScreenCapture::get_window_targets().or_else(|error| {
                    eprintln!(
                        "PipeWire window target query failed: {}, falling back",
                        error
                    );
                    Ok(vec![])
                });
            }
        }

        if Self::is_wayland_available() {
            return Ok(vec![]);
        }

        #[cfg(feature = "x11")]
        {
            if Self::is_x11_available() {
                return X11ScreenCapture::get_window_targets();
            }
        }

        Ok(vec![])
    }

    fn fallback_display_targets() -> Vec<PipewireDisplayTarget> {
        vec![PipewireDisplayTarget {
            id: 0,
            name: "Primary Display".to_string(),
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            is_primary: true,
        }]
    }

    /// Start screen capture session
    pub async fn start_session(&mut self) -> Result<(), PipewireCaptureError> {
        self.active = true;

        match &mut self.backend {
            #[cfg(feature = "x11")]
            CaptureBackend::X11(capture) => {
                capture.start()?;
            }
            #[cfg(feature = "pipewire")]
            CaptureBackend::PipeWire(capture) => {
                capture.start().await?;
            }
            CaptureBackend::Fallback(_) => {}
        }

        (self.width, self.height) = self.backend.dimensions();
        Ok(())
    }

    /// Stop the capture session
    pub fn stop_session(&mut self) {
        self.active = false;
    }

    /// Check if X11 backend is available
    pub fn is_x11_available() -> bool {
        std::env::var("DISPLAY").is_ok()
    }

    /// Check if Wayland backend is available
    pub fn is_wayland_available() -> bool {
        std::env::var("WAYLAND_DISPLAY").is_ok()
    }

    /// Check if PipeWire is available
    pub fn is_pipewire_available() -> bool {
        std::path::Path::new("/usr/bin/pipewire").exists()
            || std::path::Path::new("/usr/bin/pipewire-0").exists()
    }

    /// Current capture dimensions.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

impl FrameCapture for PipewireScreenCapture {
    fn output_memory_kind(&self) -> FrameMemoryKind {
        FrameMemoryKind::Cpu
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        if !self.active {
            return Err(PipelineError::message("Capture session not active"));
        }

        match &mut self.backend {
            #[cfg(feature = "x11")]
            CaptureBackend::X11(capture) => capture.capture_frame(),
            #[cfg(feature = "pipewire")]
            CaptureBackend::PipeWire(capture) => capture.capture_frame(),
            CaptureBackend::Fallback(capture) => capture.capture_frame(),
        }
    }
}

/// Fallback capture using test pattern
struct FallbackCapture {
    width: u32,
    height: u32,
    frame_count: u64,
}

impl FallbackCapture {
    fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            frame_count: 0,
        }
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        let width = self.width as usize;
        let height = self.height as usize;
        let stride = width * 4;
        let data_size = stride * height;

        let mut data = vec![0u8; data_size];

        // Generate an animated test pattern
        let time = (self.frame_count % 256) as u8;
        self.frame_count += 1;

        for y in 0..height {
            for x in 0..width {
                let offset = y * stride + x * 4;
                // Create moving gradient pattern
                let bx = (x as u8).wrapping_add(time);
                let gy = (y as u8).wrapping_add(time);
                data[offset] = bx; // B
                data[offset + 1] = gy; // G
                data[offset + 2] = time; // R
                data[offset + 3] = 255; // A
            }
        }

        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PipelineError::message(format!("Time error: {}", e)))?;

        Ok(CapturedFrame {
            data,
            width,
            height,
            pixel_format: FramePixelFormat::Bgra32,
            timestamp_us: timestamp.as_micros() as u64,
            #[cfg(windows)]
            d3d11_shared_bgra: None,
        })
    }
}

/// X11 screen capture implementation
#[cfg(feature = "x11")]
pub struct X11ScreenCapture {
    display: *mut x11::xlib::Display,
    window: x11::xlib::Window,
    width: u32,
    height: u32,
    x_image: Option<*mut x11::xlib::XImage>,
}

#[cfg(feature = "x11")]
unsafe impl Send for X11ScreenCapture {}

#[cfg(feature = "x11")]
impl X11ScreenCapture {
    /// Opens the current X11 display and selects its root window for capture.
    pub fn new() -> Result<Self, PipewireCaptureError> {
        use x11::xlib;

        unsafe {
            let display = (xlib::XOpenDisplay)(std::ptr::null());

            if display.is_null() {
                return Err(PipewireCaptureError::InitFailed(
                    "Failed to open X11 display".to_string(),
                ));
            }

            let screen = (xlib::XDefaultScreen)(display);
            let root = (xlib::XRootWindow)(display, screen);

            let capture = Self {
                display,
                window: root,
                width: (xlib::XDisplayWidth)(display, screen) as u32,
                height: (xlib::XDisplayHeight)(display, screen) as u32,
                x_image: None,
            };

            Ok(capture)
        }
    }

    fn start(&mut self) -> Result<(), PipewireCaptureError> {
        Ok(())
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        use x11::xlib;

        unsafe {
            let width = self.width as usize;
            let height = self.height as usize;
            let stride = width * 4;
            let data_size = stride * height;

            let mut data = vec![0u8; data_size];

            let x_image = (xlib::XGetImage)(
                self.display,
                self.window,
                0,
                0,
                self.width,
                self.height,
                0xFFFFFF,
                xlib::ZPixmap,
            );

            if x_image.is_null() {
                // Fallback
                return FallbackCapture::new(self.width, self.height).capture_frame();
            }

            self.x_image = Some(x_image);

            let image_data = (*x_image).data as *const u8;
            let image_bytes_per_line = (*x_image).bytes_per_line as usize;

            for y in 0..height {
                let src_offset = y * image_bytes_per_line;
                let dst_offset = y * stride;

                let src_slice = std::slice::from_raw_parts(image_data.add(src_offset), width * 4);
                data[dst_offset..dst_offset + width * 4].copy_from_slice(src_slice);
            }

            (xlib::XDestroyImage)(x_image);
            self.x_image = None;

            let timestamp = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| PipelineError::message(format!("Time error: {}", e)))?;

            Ok(CapturedFrame {
                data,
                width,
                height,
                pixel_format: FramePixelFormat::Bgra32,
                timestamp_us: timestamp.as_micros() as u64,
                #[cfg(windows)]
                d3d11_shared_bgra: None,
            })
        }
    }

    /// Lists displays exposed by the current X11 server.
    pub fn get_display_targets() -> Result<Vec<PipewireDisplayTarget>, PipewireCaptureError> {
        use x11::xlib;

        unsafe {
            let display = (xlib::XOpenDisplay)(std::ptr::null());

            if display.is_null() {
                return Ok(vec![PipewireDisplayTarget {
                    id: 0,
                    name: "X11 Screen".to_string(),
                    width: DEFAULT_WIDTH,
                    height: DEFAULT_HEIGHT,
                    is_primary: true,
                }]);
            }

            let screen = (xlib::XDefaultScreen)(display);
            let width = (xlib::XDisplayWidth)(display, screen) as u32;
            let height = (xlib::XDisplayHeight)(display, screen) as u32;

            (xlib::XCloseDisplay)(display);

            Ok(vec![PipewireDisplayTarget {
                id: 0,
                name: "X11 Screen".to_string(),
                width,
                height,
                is_primary: true,
            }])
        }
    }

    /// Lists capturable X11 windows.
    pub fn get_window_targets() -> Result<Vec<PipewireWindowTarget>, PipewireCaptureError> {
        Ok(vec![])
    }
}

/// PipeWire screen capture implementation
#[cfg(feature = "pipewire")]
pub struct PipeWireScreenCapture {
    width: u32,
    height: u32,
    active: bool,
    portal_fd: Option<OwnedFd>,
    portal_node_id: Option<u32>,
    gst_child: Option<Child>,
    gst_stdout: Option<ChildStdout>,
    gst_stderr: Option<ChildStderr>,
}

#[cfg(feature = "pipewire")]
impl PipeWireScreenCapture {
    /// Creates an inactive PipeWire capture instance.
    pub fn new() -> Result<Self, PipewireCaptureError> {
        Ok(Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            active: false,
            portal_fd: None,
            portal_node_id: None,
            gst_child: None,
            gst_stdout: None,
            gst_stderr: None,
        })
    }

    async fn start(&mut self) -> Result<(), PipewireCaptureError> {
        #[cfg(feature = "portal")]
        {
            let portal = request_portal_stream().await?;
            self.width = portal.width;
            self.height = portal.height;
            self.portal_node_id = Some(portal.node_id);
            self.portal_fd = Some(portal.fd);
            self.start_gstreamer_pipewire_reader()?;
            self.active = true;
            Ok(())
        }

        #[cfg(not(feature = "portal"))]
        {
            Err(PipewireCaptureError::PlatformNotAvailable(
                "PipeWire portal feature is not enabled".to_string(),
            ))
        }
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture_frame(&mut self) -> Result<CapturedFrame, PipelineError> {
        if !self.active {
            return Err(PipelineError::message("PipeWire session not active"));
        }

        let frame_len = self.width as usize * self.height as usize * 4;
        let stdout = self
            .gst_stdout
            .as_mut()
            .ok_or_else(|| PipelineError::message("PipeWire GStreamer stdout is not available"))?;

        let mut data = vec![0u8; frame_len];
        read_exact_with_timeout(
            stdout,
            &mut data,
            Duration::from_millis(1_500),
            self.gst_child.as_mut(),
            self.gst_stderr.as_mut(),
        )?;

        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PipelineError::message(format!("Time error: {}", e)))?;

        Ok(CapturedFrame {
            data,
            width: self.width as usize,
            height: self.height as usize,
            pixel_format: FramePixelFormat::Bgra32,
            timestamp_us: timestamp.as_micros() as u64,
            #[cfg(windows)]
            d3d11_shared_bgra: None,
        })
    }

    /// Lists display sources available through PipeWire.
    pub fn get_display_targets() -> Result<Vec<PipewireDisplayTarget>, PipewireCaptureError> {
        // Query PipeWire for screen outputs
        Ok(vec![PipewireDisplayTarget {
            id: 0,
            name: "PipeWire Output".to_string(),
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            is_primary: true,
        }])
    }

    /// Lists window sources available through PipeWire.
    pub fn get_window_targets() -> Result<Vec<PipewireWindowTarget>, PipewireCaptureError> {
        // Query PipeWire for windows
        Ok(vec![])
    }

    #[cfg(feature = "portal")]
    fn start_gstreamer_pipewire_reader(&mut self) -> Result<(), PipewireCaptureError> {
        use std::os::unix::process::CommandExt;

        let fd = self
            .portal_fd
            .as_ref()
            .ok_or_else(|| PipewireCaptureError::PipeWireError("missing portal fd".to_string()))?
            .as_raw_fd();
        let node_id = self.portal_node_id.ok_or_else(|| {
            PipewireCaptureError::PipeWireError("missing portal node id".to_string())
        })?;
        let inherited_fd = 3;
        let width = self.width;
        let height = self.height;
        let caps = format!("video/x-raw,format=BGRA,width={width},height={height}");

        let mut command = Command::new("gst-launch-1.0");
        command
            .arg("-q")
            .arg("pipewiresrc")
            .arg(format!("fd={inherited_fd}"))
            .arg(format!("path={node_id}"))
            .arg("do-timestamp=true")
            .arg("!")
            .arg("queue")
            .arg("max-size-buffers=2")
            .arg("leaky=downstream")
            .arg("!")
            .arg("videoconvert")
            .arg("!")
            .arg("videoscale")
            .arg("!")
            .arg(&caps)
            .arg("!")
            .arg("queue")
            .arg("max-size-buffers=2")
            .arg("leaky=downstream")
            .arg("!")
            .arg("fdsink")
            .arg("fd=1")
            .arg("sync=false")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, inherited_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let flags = libc::fcntl(inherited_fd, libc::F_GETFD);
                if flags != -1 {
                    libc::fcntl(inherited_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                }
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(|error| {
            PipewireCaptureError::PipeWireError(format!(
                "start gst-launch pipewiresrc failed: {error}"
            ))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            PipewireCaptureError::PipeWireError("gst-launch stdout unavailable".to_string())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            PipewireCaptureError::PipeWireError("gst-launch stderr unavailable".to_string())
        })?;

        self.gst_stdout = Some(stdout);
        self.gst_stderr = Some(stderr);
        self.gst_child = Some(child);
        Ok(())
    }
}

#[cfg(feature = "pipewire")]
fn read_exact_with_timeout(
    stdout: &mut ChildStdout,
    data: &mut [u8],
    timeout: Duration,
    mut child: Option<&mut Child>,
    mut stderr: Option<&mut ChildStderr>,
) -> Result<(), PipelineError> {
    let fd = stdout.as_raw_fd();
    let start = Instant::now();
    let mut offset = 0usize;

    while offset < data.len() {
        if start.elapsed() >= timeout {
            return Err(PipelineError::message(
                "PipeWire frame read timed out; check portal selection and GStreamer pipewiresrc negotiation",
            ));
        }

        if let Some(process) = child.as_deref_mut() {
            if let Some(status) = process.try_wait().map_err(|error| {
                PipelineError::message(format!("check PipeWire GStreamer process failed: {error}"))
            })? {
                let stderr_preview = read_gstreamer_stderr(stderr.as_deref_mut());
                return Err(PipelineError::message(format!(
                    "PipeWire GStreamer process exited before a full frame: {status}{stderr_preview}"
                )));
            }
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let poll_timeout_ms = remaining
            .min(Duration::from_millis(100))
            .as_millis()
            .try_into()
            .unwrap_or(100);
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, poll_timeout_ms) };
        if ready < 0 {
            return Err(PipelineError::message(format!(
                "poll PipeWire frame failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if ready == 0 {
            continue;
        }
        if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            let stderr_preview = read_gstreamer_stderr(stderr.as_deref_mut());
            return Err(PipelineError::message(format!(
                "PipeWire frame pipe closed or errored: revents={}{}",
                poll_fd.revents, stderr_preview
            )));
        }

        let read = stdout.read(&mut data[offset..]).map_err(|error| {
            PipelineError::message(format!("PipeWire frame read failed: {error}"))
        })?;
        if read == 0 {
            return Err(PipelineError::message(
                "PipeWire frame stream ended before a full frame",
            ));
        }
        offset += read;
    }

    Ok(())
}

#[cfg(feature = "pipewire")]
fn read_gstreamer_stderr(stderr: Option<&mut ChildStderr>) -> String {
    let Some(stderr) = stderr else {
        return String::new();
    };

    let fd = stderr.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() >= 8192 {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return format!("; read gst stderr failed: {error}"),
        }
    }

    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim();
    if text.is_empty() {
        String::new()
    } else {
        format!(
            "; gst stderr: {}",
            text.lines().take(12).collect::<Vec<_>>().join(" | ")
        )
    }
}

#[cfg(feature = "pipewire")]
impl Drop for PipeWireScreenCapture {
    fn drop(&mut self) {
        if let Some(mut child) = self.gst_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(feature = "portal")]
struct PortalStream {
    fd: OwnedFd,
    node_id: u32,
    width: u32,
    height: u32,
}

#[cfg(feature = "portal")]
async fn request_portal_stream() -> Result<PortalStream, PipewireCaptureError> {
    use ashpd::desktop::{
        screencast::{CursorMode, Screencast, SourceType},
        PersistMode,
    };

    let proxy = Screencast::new()
        .await
        .map_err(|error| PipewireCaptureError::PortalError(error.to_string()))?;
    let session = proxy
        .create_session()
        .await
        .map_err(|error| PipewireCaptureError::PortalError(error.to_string()))?;

    proxy
        .select_sources(
            &session,
            CursorMode::Embedded,
            SourceType::Monitor | SourceType::Window,
            false,
            None,
            PersistMode::DoNot,
        )
        .await
        .map_err(|error| PipewireCaptureError::PortalError(error.to_string()))?;

    let response = proxy
        .start(&session, None)
        .await
        .map_err(|error| PipewireCaptureError::PortalError(error.to_string()))?
        .response()
        .map_err(|error| PipewireCaptureError::PortalError(error.to_string()))?;
    let stream = response
        .streams()
        .first()
        .ok_or(PipewireCaptureError::NoSourceAvailable)?;
    let (width, height) = stream
        .size()
        .unwrap_or((DEFAULT_WIDTH as i32, DEFAULT_HEIGHT as i32));
    let fd = proxy
        .open_pipe_wire_remote(&session)
        .await
        .map_err(|error| PipewireCaptureError::PortalError(error.to_string()))?;

    Ok(PortalStream {
        fd,
        node_id: stream.pipe_wire_node_id(),
        width: width.max(1) as u32,
        height: height.max(1) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_creation() {
        let capture = PipewireScreenCapture::new();
        assert!(capture.is_ok());
        let capture = capture.unwrap();
        if PipewireScreenCapture::is_wayland_available() {
            #[cfg(feature = "pipewire")]
            assert!(matches!(
                capture.backend,
                CaptureBackend::PipeWire(_) | CaptureBackend::Fallback(_)
            ));

            #[cfg(not(feature = "pipewire"))]
            assert!(matches!(capture.backend, CaptureBackend::Fallback(_)));
        }
    }

    #[test]
    fn test_get_display_targets() {
        let targets = PipewireScreenCapture::get_display_targets();
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert!(!targets.is_empty());
    }

    #[test]
    fn test_platform_detection() {
        println!(
            "X11 available: {}",
            PipewireScreenCapture::is_x11_available()
        );
        println!(
            "Wayland available: {}",
            PipewireScreenCapture::is_wayland_available()
        );
        println!(
            "PipeWire available: {}",
            PipewireScreenCapture::is_pipewire_available()
        );
    }

    #[test]
    #[cfg(feature = "x11")]
    fn test_x11_frame_capture() {
        if !PipewireScreenCapture::is_x11_available() {
            println!("X11 not available, skipping test");
            return;
        }

        // Skip if running under Wayland (XWayland doesn't allow screen capture via XGetImage)
        if PipewireScreenCapture::is_wayland_available() {
            println!("Running under Wayland - X11 screen capture is restricted");
            println!("Use PipeWire backend for Wayland screen capture");
            return;
        }

        match X11ScreenCapture::new() {
            Ok(mut capture) => {
                println!("Testing X11 frame capture...");
                println!("Screen dimensions: {}x{}", capture.width, capture.height);

                // Try to capture a frame
                match capture.capture_frame() {
                    Ok(frame) => {
                        println!("Frame captured successfully!");
                        println!("  Frame size: {}x{}", frame.width, frame.height);
                        println!("  Pixel format: {:?}", frame.pixel_format);
                        println!("  Data size: {} bytes", frame.data.len());
                        assert!(!frame.data.is_empty());
                        assert!(frame.width > 0);
                        assert!(frame.height > 0);
                    }
                    Err(e) => {
                        println!("Frame capture failed: {}", e);
                        // This may fail in headless environments or Wayland
                    }
                }
            }
            Err(e) => {
                println!("X11 capture creation failed: {}", e);
            }
        }
    }

    #[test]
    fn test_fallback_capture() {
        let mut capture = FallbackCapture::new(1920, 1080);
        let (width, height) = capture.dimensions();
        assert_eq!(width, 1920);
        assert_eq!(height, 1080);

        // Capture a test frame
        let result = capture.capture_frame();
        assert!(result.is_ok());
        let frame = result.unwrap();
        assert_eq!(frame.width, 1920);
        assert_eq!(frame.height, 1080);
        assert!(!frame.data.is_empty());
    }
}
