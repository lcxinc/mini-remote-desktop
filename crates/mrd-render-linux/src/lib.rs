//! Linux frame rendering implementation
//!
//! Provides frame rendering on Linux using various backends:
//! - X11 (traditional)
//! - Software (fallback)

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

use mrd_render::{
    RenderFrame, RenderPixelFormat, RenderTarget, RendererDescriptor, RendererFactory,
    RendererInstance, RendererSnapshot, RuntimeStatus,
};
use thiserror::Error;

const SUPPORTED_FORMATS: &[RenderPixelFormat] =
    &[RenderPixelFormat::Rgb24, RenderPixelFormat::Bgra32];

/// Linux frame renderer supporting multiple backends
pub struct LinuxRenderer {
    width: u32,
    height: u32,
    last_pixel_format: Option<RenderPixelFormat>,
    backend: RendererBackend,
    frame_count: u64,
    attached: bool,
}

enum RendererBackend {
    Software(SoftwareRenderer),
    #[cfg(feature = "x11")]
    X11(X11Renderer),
}

impl RendererBackend {
    fn dimensions(&self) -> (u32, u32) {
        match self {
            RendererBackend::Software(r) => r.dimensions(),
            #[cfg(feature = "x11")]
            RendererBackend::X11(r) => r.dimensions(),
        }
    }
}

/// Linux renderer factory
pub struct LinuxRendererFactory;

impl RendererFactory for LinuxRendererFactory {
    fn descriptor(&self) -> RendererDescriptor {
        RendererDescriptor {
            id: "linux",
            runtime_status: RuntimeStatus::RuntimeBacked,
            supported_formats: SUPPORTED_FORMATS,
        }
    }

    fn create(&self) -> Result<Box<dyn RendererInstance>, mrd_render::RenderError> {
        Ok(Box::new(LinuxRenderer::new().map_err(|e| {
            mrd_render::RenderError::Message(e.to_string())
        })?))
    }
}

impl LinuxRenderer {
    /// Create a renderer using the best available Linux backend.
    ///
    /// X11 is preferred when the feature and display are available; otherwise
    /// the renderer falls back to the software backend.
    pub fn new() -> Result<Self, LinuxRenderError> {
        let backend = Self::select_backend()?;
        let (width, height) = backend.dimensions();

        Ok(Self {
            width,
            height,
            last_pixel_format: None,
            backend,
            frame_count: 0,
            attached: false,
        })
    }

    fn select_backend() -> Result<RendererBackend, LinuxRenderError> {
        #[cfg(feature = "x11")]
        {
            if std::env::var("DISPLAY").is_ok() {
                match X11Renderer::new() {
                    Ok(renderer) => return Ok(RendererBackend::X11(renderer)),
                    Err(e) => {
                        eprintln!("X11 renderer init failed: {}, falling back to software", e);
                    }
                }
            }
        }

        Ok(RendererBackend::Software(SoftwareRenderer::new()?))
    }

    /// Return the stable identifier of the active rendering backend.
    pub fn backend_name(&self) -> &'static str {
        match &self.backend {
            RendererBackend::Software(_) => "software",
            #[cfg(feature = "x11")]
            RendererBackend::X11(_) => "x11",
        }
    }

    /// Create a backend-owned native test window when the active backend supports it.
    pub fn create_window(&mut self, title: &str) -> Result<(), LinuxRenderError> {
        self.create_window_with_size(title, self.width as usize, self.height as usize)
    }

    /// Create a backend-owned native test window with the requested client size.
    pub fn create_window_with_size(
        &mut self,
        title: &str,
        width: usize,
        height: usize,
    ) -> Result<(), LinuxRenderError> {
        #[cfg(not(feature = "x11"))]
        let _ = title;

        self.width = width.max(1) as u32;
        self.height = height.max(1) as u32;
        match &mut self.backend {
            RendererBackend::Software(_) => {
                self.attached = true;
                Ok(())
            }
            #[cfg(feature = "x11")]
            RendererBackend::X11(renderer) => {
                renderer.create_window(title, self.width, self.height)?;
                self.attached = true;
                Ok(())
            }
        }
    }
}

impl RendererInstance for LinuxRenderer {
    fn attach_target(&mut self, target: RenderTarget) -> Result<(), mrd_render::RenderError> {
        self.attached = match &mut self.backend {
            RendererBackend::Software(renderer) => renderer.attach_target(target).is_ok(),
            #[cfg(feature = "x11")]
            RendererBackend::X11(renderer) => renderer.attach_target(target).is_ok(),
        };
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), mrd_render::RenderError> {
        self.frame_count += 1;
        self.width = frame.width.max(1) as u32;
        self.height = frame.height.max(1) as u32;
        self.last_pixel_format = Some(frame.pixel_format);
        match &mut self.backend {
            RendererBackend::Software(renderer) => renderer.upload_frame(frame),
            #[cfg(feature = "x11")]
            RendererBackend::X11(renderer) => renderer.upload_frame(frame),
        }
    }

    fn snapshot(&self) -> RendererSnapshot {
        RendererSnapshot {
            attached_to_target: self.attached,
            uploaded_frame_count: self.frame_count,
            presented_frame_count: self.frame_count,
            present_skipped_count: 0,
            render_queue_replacements: None,
            last_present_status: Some("presented".to_string()),
            low_latency_frame_latency_target: None,
            swap_chain_max_frame_latency: None,
            swap_chain_allow_tearing: None,
            swap_chain_waitable_object: None,
            swap_chain_present_mode: None,
            display_refresh_hz: None,
            render_thread_priority: None,
            waitable_wait_count: None,
            waitable_wait_total_ms: None,
            waitable_timeout_count: None,
            last_waitable_wait_ms: None,
            last_render_prepare_wait_ms: None,
            last_render_shared_resource_ms: None,
            last_render_wait_for_drawable_ms: None,
            last_render_encode_commit_ms: None,
            last_render_draw_present_ms: None,
            last_width: self.width as usize,
            last_height: self.height as usize,
            last_pixel_format: self.last_pixel_format,
        }
    }
}

/// Software renderer (fallback)
pub struct SoftwareRenderer {
    buffer: Vec<u8>,
    frame_count: u64,
    last_width: usize,
    last_height: usize,
    last_pixel_format: Option<RenderPixelFormat>,
}

impl SoftwareRenderer {
    /// Create an empty software renderer with the default frame dimensions.
    pub fn new() -> Result<Self, LinuxRenderError> {
        Ok(Self {
            buffer: Vec::new(),
            frame_count: 0,
            last_width: 1920,
            last_height: 1080,
            last_pixel_format: None,
        })
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.last_width as u32, self.last_height as u32)
    }
}

impl RendererInstance for SoftwareRenderer {
    fn attach_target(&mut self, _target: RenderTarget) -> Result<(), mrd_render::RenderError> {
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), mrd_render::RenderError> {
        self.frame_count += 1;
        self.last_width = frame.width;
        self.last_height = frame.height;
        self.last_pixel_format = Some(frame.pixel_format);
        // Store frame data
        if let Some(data) = frame.as_bgra32() {
            self.buffer = data.to_vec();
        } else if let Some(data) = frame.as_rgb24() {
            // Convert RGB24 to BGRA32
            self.buffer = data
                .as_chunks::<3>()
                .0
                .iter()
                .flat_map(|rgb| [rgb[2], rgb[1], rgb[0], 255])
                .collect();
        }
        Ok(())
    }

    fn snapshot(&self) -> RendererSnapshot {
        RendererSnapshot {
            attached_to_target: false,
            uploaded_frame_count: self.frame_count,
            presented_frame_count: self.frame_count,
            present_skipped_count: 0,
            render_queue_replacements: None,
            last_present_status: Some("presented".to_string()),
            low_latency_frame_latency_target: None,
            swap_chain_max_frame_latency: None,
            swap_chain_allow_tearing: None,
            swap_chain_waitable_object: None,
            swap_chain_present_mode: None,
            display_refresh_hz: None,
            render_thread_priority: None,
            waitable_wait_count: None,
            waitable_wait_total_ms: None,
            waitable_timeout_count: None,
            last_waitable_wait_ms: None,
            last_render_prepare_wait_ms: None,
            last_render_shared_resource_ms: None,
            last_render_wait_for_drawable_ms: None,
            last_render_encode_commit_ms: None,
            last_render_draw_present_ms: None,
            last_width: self.last_width,
            last_height: self.last_height,
            last_pixel_format: self.last_pixel_format,
        }
    }
}

/// X11 renderer implementation
#[cfg(feature = "x11")]
pub struct X11Renderer {
    display: *mut x11::xlib::Display,
    window: Option<x11::xlib::Window>,
    owns_window: bool,
    wm_protocols: x11::xlib::Atom,
    wm_delete_window: x11::xlib::Atom,
    visual: *mut x11::xlib::Visual,
    gc: x11::xlib::GC,
    width: u32,
    height: u32,
    frame_count: u64,
    last_pixel_format: Option<RenderPixelFormat>,
    scaled_buffer: Vec<u8>,
}

#[cfg(feature = "x11")]
unsafe impl Send for X11Renderer {}

#[cfg(feature = "x11")]
impl X11Renderer {
    /// Connect to the current X11 display and initialize its graphics context.
    pub fn new() -> Result<Self, LinuxRenderError> {
        use std::ptr;
        use x11::xlib;

        unsafe {
            init_x11_threads();
            let display = (xlib::XOpenDisplay)(ptr::null());

            if display.is_null() {
                return Err(LinuxRenderError::InitFailed(
                    "Failed to open X11 display".to_string(),
                ));
            }

            let screen = (xlib::XDefaultScreen)(display);
            let visual = (xlib::XDefaultVisual)(display, screen);
            let root = (xlib::XRootWindow)(display, screen);
            let width = (xlib::XDisplayWidth)(display, screen) as u32;
            let height = (xlib::XDisplayHeight)(display, screen) as u32;
            let wm_protocols = atom(display, "WM_PROTOCOLS");
            let wm_delete_window = atom(display, "WM_DELETE_WINDOW");

            // Create graphics context
            let mut gc_values: x11::xlib::XGCValues = std::mem::zeroed();
            let gc = (xlib::XCreateGC)(display, root, 0, &mut gc_values);

            if gc.is_null() {
                (xlib::XCloseDisplay)(display);
                return Err(LinuxRenderError::InitFailed(
                    "Failed to create GC".to_string(),
                ));
            }

            Ok(Self {
                display,
                window: None,
                owns_window: false,
                wm_protocols,
                wm_delete_window,
                visual,
                gc,
                width,
                height,
                frame_count: 0,
                last_pixel_format: None,
                scaled_buffer: Vec::new(),
            })
        }
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Create and map an X11 window owned by this renderer.
    pub fn create_window(
        &mut self,
        title: &str,
        width: u32,
        height: u32,
    ) -> Result<(), LinuxRenderError> {
        use x11::xlib;

        unsafe {
            let screen = (xlib::XDefaultScreen)(self.display);
            let root = (xlib::XRootWindow)(self.display, screen);

            let mut attrs: x11::xlib::XSetWindowAttributes = std::mem::zeroed();
            attrs.background_pixel = (xlib::XWhitePixel)(self.display, screen);
            attrs.event_mask =
                x11::xlib::ExposureMask | x11::xlib::StructureNotifyMask | x11::xlib::KeyPressMask;
            self.width = width.max(1);
            self.height = height.max(1);

            let window = (xlib::XCreateWindow)(
                self.display,
                root,
                0,
                0,
                self.width,
                self.height,
                0,
                (xlib::XDefaultDepth)(self.display, screen),
                x11::xlib::InputOutput as u32,
                self.visual as *mut _,
                x11::xlib::CWBackPixel | x11::xlib::CWEventMask,
                &mut attrs,
            );

            if window == 0 {
                return Err(LinuxRenderError::InitFailed(
                    "Failed to create window".to_string(),
                ));
            }

            // Set window title
            let title_cstr = std::ffi::CString::new(title).unwrap();
            (xlib::XStoreName)(self.display, window, title_cstr.as_ptr());
            let mut protocols = [self.wm_delete_window];
            (xlib::XSetWMProtocols)(
                self.display,
                window,
                protocols.as_mut_ptr(),
                protocols.len() as std::os::raw::c_int,
            );

            // Map window
            (xlib::XMapWindow)(self.display, window);
            (xlib::XFlush)(self.display);

            self.window = Some(window);
            self.owns_window = true;
            Ok(())
        }
    }

    fn pump_events(&mut self) {
        use x11::xlib;

        unsafe {
            while (xlib::XPending)(self.display) > 0 {
                let mut event: x11::xlib::XEvent = std::mem::zeroed();
                (xlib::XNextEvent)(self.display, &mut event);
                match event.get_type() {
                    xlib::ClientMessage => {
                        let client = x11::xlib::XClientMessageEvent::from(event);
                        if self.owns_window
                            && client.message_type == self.wm_protocols
                            && client.format == 32
                            && client.data.get_long(0) as x11::xlib::Atom == self.wm_delete_window
                        {
                            if let Some(window) = self.window.take() {
                                (xlib::XDestroyWindow)(self.display, window);
                                (xlib::XFlush)(self.display);
                            }
                            self.owns_window = false;
                        }
                    }
                    xlib::DestroyNotify => {
                        let destroyed = event.destroy_window.window;
                        if self.window == Some(destroyed) {
                            self.window = None;
                            self.owns_window = false;
                        }
                    }
                    xlib::ConfigureNotify => {
                        let configure = event.configure;
                        if configure.width > 0 && configure.height > 0 {
                            self.width = configure.width as u32;
                            self.height = configure.height as u32;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn put_image(
        &mut self,
        data: &[u8],
        width: usize,
        height: usize,
    ) -> Result<(), LinuxRenderError> {
        use x11::xlib;

        unsafe {
            self.pump_events();
            let window = match self.window {
                Some(w) => w,
                None => return Ok(()), // No window to render to
            };
            let display = self.display;
            let visual = self.visual;
            let gc = self.gc;
            let (target_width, target_height) =
                self.target_window_dimensions(window, width, height);
            let (image_data, image_width, image_height) =
                self.prepare_image_data(data, width, height, target_width, target_height);

            let image = (xlib::XCreateImage)(
                display,
                visual,
                24, // depth
                x11::xlib::ZPixmap,
                0,
                image_data.as_ptr() as *mut i8,
                image_width as u32,
                image_height as u32,
                32, // bitmap_pad
                0,  // bytes_per_line (0 = auto)
            );

            if image.is_null() {
                return Err(LinuxRenderError::X11Error(
                    "Failed to create XImage".to_string(),
                ));
            }

            (xlib::XPutImage)(
                display,
                window,
                gc,
                image,
                0,
                0,
                0,
                0,
                image_width as u32,
                image_height as u32,
            );

            (*image).data = std::ptr::null_mut();
            (xlib::XDestroyImage)(image);

            (xlib::XFlush)(display);
            Ok(())
        }
    }

    fn target_window_dimensions(
        &mut self,
        window: x11::xlib::Window,
        fallback_width: usize,
        fallback_height: usize,
    ) -> (usize, usize) {
        use x11::xlib;

        unsafe {
            let mut attrs: x11::xlib::XWindowAttributes = std::mem::zeroed();
            if (xlib::XGetWindowAttributes)(self.display, window, &mut attrs) != 0
                && attrs.width > 0
                && attrs.height > 0
            {
                self.width = attrs.width as u32;
                self.height = attrs.height as u32;
                return (attrs.width as usize, attrs.height as usize);
            }
        }

        (fallback_width.max(1), fallback_height.max(1))
    }

    fn prepare_image_data<'a>(
        &'a mut self,
        data: &'a [u8],
        width: usize,
        height: usize,
        target_width: usize,
        target_height: usize,
    ) -> (&'a [u8], usize, usize) {
        if width == target_width && height == target_height {
            return (data, width, height);
        }

        let target_len = target_width.saturating_mul(target_height).saturating_mul(4);
        if target_len == 0 || data.len() < width.saturating_mul(height).saturating_mul(4) {
            return (data, width, height);
        }

        self.scaled_buffer.resize(target_len, 0);
        scale_bgra_nearest(
            data,
            width,
            height,
            &mut self.scaled_buffer,
            target_width,
            target_height,
        );
        (&self.scaled_buffer, target_width, target_height)
    }
}

#[cfg(feature = "x11")]
fn scale_bgra_nearest(
    src: &[u8],
    src_width: usize,
    src_height: usize,
    dst: &mut [u8],
    dst_width: usize,
    dst_height: usize,
) {
    if src_width == 0 || src_height == 0 || dst_width == 0 || dst_height == 0 {
        return;
    }

    for y in 0..dst_height {
        let src_y = y.saturating_mul(src_height) / dst_height;
        let src_row = src_y.saturating_mul(src_width).saturating_mul(4);
        let dst_row = y.saturating_mul(dst_width).saturating_mul(4);
        for x in 0..dst_width {
            let src_offset = src_row + (x.saturating_mul(src_width) / dst_width) * 4;
            let dst_offset = dst_row + x * 4;
            dst[dst_offset..dst_offset + 4].copy_from_slice(&src[src_offset..src_offset + 4]);
        }
    }
}

#[cfg(feature = "x11")]
impl Drop for X11Renderer {
    fn drop(&mut self) {
        use x11::xlib;

        unsafe {
            if self.owns_window {
                if let Some(window) = self.window {
                    (xlib::XDestroyWindow)(self.display, window);
                }
            }
            if !self.gc.is_null() {
                (xlib::XFreeGC)(self.display, self.gc);
            }
            (xlib::XCloseDisplay)(self.display);
        }
    }
}

#[cfg(feature = "x11")]
fn atom(display: *mut x11::xlib::Display, name: &str) -> x11::xlib::Atom {
    let name = std::ffi::CString::new(name).expect("X11 atom names must not contain NUL");
    unsafe { (x11::xlib::XInternAtom)(display, name.as_ptr(), x11::xlib::False) }
}

#[cfg(feature = "x11")]
fn init_x11_threads() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        let _ = x11::xlib::XInitThreads();
    });
}

#[cfg(feature = "x11")]
impl RendererInstance for X11Renderer {
    fn attach_target(&mut self, target: RenderTarget) -> Result<(), mrd_render::RenderError> {
        use mrd_render::RenderTarget;

        match target {
            RenderTarget::WindowHandle(handle) => {
                if self.owns_window {
                    if let Some(window) = self.window.take() {
                        unsafe {
                            (x11::xlib::XDestroyWindow)(self.display, window);
                        }
                    }
                }
                self.window = Some(handle as x11::xlib::Window);
                self.owns_window = false;
                Ok(())
            }
        }
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), mrd_render::RenderError> {
        self.frame_count += 1;
        self.last_pixel_format = Some(frame.pixel_format);

        // Get frame data
        let data = if let Some(bgra) = frame.as_bgra32() {
            bgra.to_vec()
        } else if let Some(rgb) = frame.as_rgb24() {
            // Convert RGB24 to BGRA32
            rgb.as_chunks::<3>()
                .0
                .iter()
                .flat_map(|rgb| [rgb[2], rgb[1], rgb[0], 255])
                .collect()
        } else {
            return Ok(());
        };
        self.width = frame.width.max(1) as u32;
        self.height = frame.height.max(1) as u32;

        // Render to X11 window
        if let Err(e) = self.put_image(&data, frame.width, frame.height) {
            eprintln!("X11 render error: {}", e);
        }

        Ok(())
    }

    fn snapshot(&self) -> RendererSnapshot {
        RendererSnapshot {
            attached_to_target: self.window.is_some(),
            uploaded_frame_count: self.frame_count,
            presented_frame_count: self.frame_count,
            present_skipped_count: 0,
            render_queue_replacements: None,
            last_present_status: Some("presented".to_string()),
            low_latency_frame_latency_target: None,
            swap_chain_max_frame_latency: None,
            swap_chain_allow_tearing: None,
            swap_chain_waitable_object: None,
            swap_chain_present_mode: None,
            display_refresh_hz: None,
            render_thread_priority: None,
            waitable_wait_count: None,
            waitable_wait_total_ms: None,
            waitable_timeout_count: None,
            last_waitable_wait_ms: None,
            last_render_prepare_wait_ms: None,
            last_render_shared_resource_ms: None,
            last_render_wait_for_drawable_ms: None,
            last_render_encode_commit_ms: None,
            last_render_draw_present_ms: None,
            last_width: self.width as usize,
            last_height: self.height as usize,
            last_pixel_format: self.last_pixel_format,
        }
    }
}

/// Linux-specific render errors
#[derive(Debug, Error)]
pub enum LinuxRenderError {
    /// A rendering backend could not be initialized.
    #[error("Failed to initialize Linux renderer: {0}")]
    InitFailed(String),

    /// No supported rendering backend was available.
    #[error("No suitable rendering backend available")]
    NoBackend,

    /// An X11 operation failed.
    #[error("X11 rendering failed: {0}")]
    X11Error(String),
}

/// Create a Linux renderer descriptor
pub fn linux_renderer_descriptor() -> RendererDescriptor {
    RendererDescriptor {
        id: "linux",
        runtime_status: RuntimeStatus::RuntimeBacked,
        supported_formats: SUPPORTED_FORMATS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renderer_factory() {
        let factory = LinuxRendererFactory;
        let descriptor = factory.descriptor();
        assert_eq!(descriptor.id, "linux");
    }

    #[test]
    fn test_renderer_creation() {
        let factory = LinuxRendererFactory;
        let renderer = factory.create();
        assert!(renderer.is_ok());
    }

    #[test]
    fn test_snapshot() {
        let factory = LinuxRendererFactory;
        let renderer = factory.create().unwrap();
        let snapshot = renderer.snapshot();
        // Check for valid dimensions (any reasonable screen size)
        assert!(snapshot.last_width >= 800);
        assert!(snapshot.last_height >= 600);
    }

    #[test]
    #[cfg(feature = "x11")]
    fn test_x11_renderer() {
        if std::env::var("DISPLAY").is_err() {
            return;
        }

        match X11Renderer::new() {
            Ok(renderer) => {
                println!("X11 renderer created successfully");
                println!("Dimensions: {}x{}", renderer.width, renderer.height);
            }
            Err(e) => {
                println!("X11 renderer creation failed (may be expected): {}", e);
            }
        }
    }
}
