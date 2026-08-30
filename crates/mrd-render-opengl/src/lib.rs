use mrd_render::{
    BoxedRenderer, RenderError, RenderFrame, RenderFrameData, RenderPixelFormat, RenderTarget,
    RendererDescriptor, RendererFactory, RendererInstance, RendererSnapshot, RuntimeStatus,
};

#[cfg(windows)]
use std::ffi::{c_char, c_void, CString};
#[cfg(windows)]
use windows::core::{ComInterface, Interface, PCSTR};

const SUPPORTED_FORMATS: &[RenderPixelFormat] = &[
    RenderPixelFormat::Rgb24,
    RenderPixelFormat::Bgra32,
    #[cfg(windows)]
    RenderPixelFormat::D3D11SharedBgra,
    #[cfg(windows)]
    RenderPixelFormat::D3D11SharedNv12,
    #[cfg(windows)]
    RenderPixelFormat::D3D11SharedP010,
];

#[cfg(any(windows, test))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct TextureCache {
    width: usize,
    height: usize,
    pixel_format: Option<RenderPixelFormat>,
    parameters_configured: bool,
}

#[cfg(any(windows, test))]
impl TextureCache {
    fn needs_reallocate(
        &self,
        width: usize,
        height: usize,
        pixel_format: RenderPixelFormat,
    ) -> bool {
        self.width != width || self.height != height || self.pixel_format != Some(pixel_format)
    }

    fn record_allocation(&mut self, width: usize, height: usize, pixel_format: RenderPixelFormat) {
        self.width = width;
        self.height = height;
        self.pixel_format = Some(pixel_format);
    }

    fn needs_parameter_setup(&self) -> bool {
        !self.parameters_configured
    }

    fn record_parameters_configured(&mut self) {
        self.parameters_configured = true;
    }
}

pub fn opengl_descriptor() -> RendererDescriptor {
    RendererDescriptor {
        id: "opengl",
        runtime_status: RuntimeStatus::RuntimeBacked,
        supported_formats: SUPPORTED_FORMATS,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OpenglRendererFactory;

impl RendererFactory for OpenglRendererFactory {
    fn descriptor(&self) -> RendererDescriptor {
        opengl_descriptor()
    }

    fn create(&self) -> Result<BoxedRenderer, RenderError> {
        Ok(Box::new(OpenglRenderer::new()))
    }
}

#[derive(Debug)]
pub struct OpenglRenderer {
    target_hwnd: Option<isize>,
    #[cfg(windows)]
    surface: Option<WindowsGlSurface>,
    #[cfg(windows)]
    d3d11_bridge: Option<D3d11ReadbackBridge>,
    snapshot: RendererSnapshot,
}

impl Default for OpenglRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenglRenderer {
    pub fn new() -> Self {
        Self {
            target_hwnd: None,
            #[cfg(windows)]
            surface: None,
            #[cfg(windows)]
            d3d11_bridge: None,
            snapshot: RendererSnapshot {
                attached_to_target: false,
                uploaded_frame_count: 0,
                presented_frame_count: 0,
                present_skipped_count: 0,
                render_queue_replacements: None,
                last_present_status: None,
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
                last_width: 0,
                last_height: 0,
                last_pixel_format: None,
            },
        }
    }

    pub fn target_hwnd(&self) -> Option<isize> {
        self.target_hwnd
    }

    #[cfg(windows)]
    pub fn new_hybrid() -> Result<Self, RenderError> {
        let mut renderer = Self::new();
        renderer.d3d11_bridge = Some(D3d11ReadbackBridge::new()?);
        Ok(renderer)
    }

    #[cfg(windows)]
    pub fn d3d11_device_ptr(&self) -> Option<*mut core::ffi::c_void> {
        self.d3d11_bridge
            .as_ref()
            .map(D3d11ReadbackBridge::device_ptr)
    }

    #[cfg(windows)]
    fn ensure_d3d11_bridge(&mut self) -> Result<&mut D3d11ReadbackBridge, RenderError> {
        if self.d3d11_bridge.is_none() {
            self.d3d11_bridge = Some(D3d11ReadbackBridge::new()?);
        }
        Ok(self.d3d11_bridge.as_mut().unwrap())
    }

    #[cfg(windows)]
    fn readback_shared_frame_to_bgra(
        &mut self,
        frame: &RenderFrame,
    ) -> Result<RenderFrame, RenderError> {
        let bgra = self.ensure_d3d11_bridge()?.readback_frame_to_bgra(frame)?;
        Ok(RenderFrame::from_bgra32(frame.width, frame.height, bgra))
    }
}

impl RendererInstance for OpenglRenderer {
    fn attach_target(&mut self, target: RenderTarget) -> Result<(), RenderError> {
        let RenderTarget::WindowHandle(hwnd) = target;
        self.target_hwnd = Some(hwnd);
        #[cfg(windows)]
        {
            self.surface = if hwnd == 0 {
                None
            } else {
                Some(WindowsGlSurface::attach(hwnd)?)
            };
        }
        self.snapshot.attached_to_target = hwnd != 0;
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), RenderError> {
        let original_pixel_format = frame.pixel_format;

        if frame.is_shared_texture() {
            #[cfg(windows)]
            {
                if let Some(mut surface) = self.surface.take() {
                    let path = {
                        let bridge = self.ensure_d3d11_bridge()?;
                        surface.present_shared_frame(&frame, bridge)?
                    };
                    if path == SharedTexturePath::ReadbackFallback {
                        let cpu_frame = self.readback_shared_frame_to_bgra(&frame)?;
                        surface.present_frame(&cpu_frame)?;
                    }
                    self.surface = Some(surface);
                }
            }
            #[cfg(not(windows))]
            {
                return Err(RenderError::Message(
                    "OpenGL shared texture hybrid path is only available on Windows".to_string(),
                ));
            }
        } else {
            validate_cpu_frame(&frame)?;
            #[cfg(windows)]
            if let Some(surface) = self.surface.as_mut() {
                surface.present_frame(&frame)?;
            }
        }

        self.snapshot.uploaded_frame_count += 1;
        self.snapshot.presented_frame_count += 1;
        self.snapshot.last_present_status = Some("presented".to_string());
        self.snapshot.last_width = frame.width;
        self.snapshot.last_height = frame.height;
        self.snapshot.last_pixel_format = Some(original_pixel_format);
        Ok(())
    }

    fn snapshot(&self) -> RendererSnapshot {
        self.snapshot.clone()
    }
}

fn validate_cpu_frame(frame: &RenderFrame) -> Result<(), RenderError> {
    if frame.is_shared_texture() {
        return Err(RenderError::Message(
            "OpenGL renderer accepts CPU-backed frames only; D3D11 shared texture input is unsupported"
                .to_string(),
        ));
    }

    match (&frame.pixel_format, &frame.data) {
        (RenderPixelFormat::Rgb24, RenderFrameData::Rgb24(data)) => {
            validate_len(frame.width, frame.height, 3, data.len(), "Rgb24")
        }
        (RenderPixelFormat::Bgra32, RenderFrameData::Bgra32(data)) => {
            validate_len(frame.width, frame.height, 4, data.len(), "Bgra32")
        }
        _ => Err(RenderError::Message(
            "OpenGL renderer only accepts CPU Rgb24 or Bgra32 frame data".to_string(),
        )),
    }
}

fn validate_len(
    width: usize,
    height: usize,
    bytes_per_pixel: usize,
    actual_len: usize,
    label: &str,
) -> Result<(), RenderError> {
    let expected_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(bytes_per_pixel))
        .ok_or_else(|| RenderError::Message(format!("{label} frame dimensions overflow")))?;
    if actual_len != expected_len {
        return Err(RenderError::Message(format!(
            "{label} frame byte length mismatch: expected {expected_len}, got {actual_len}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedTexturePath {
    MetadataOnly,
    WglDxInterop,
    ReadbackFallback,
}

#[cfg(windows)]
fn choose_shared_texture_path(
    surface_attached: bool,
    wgl_dx_interop_available: bool,
) -> SharedTexturePath {
    if !surface_attached {
        SharedTexturePath::MetadataOnly
    } else if wgl_dx_interop_available {
        SharedTexturePath::WglDxInterop
    } else {
        SharedTexturePath::ReadbackFallback
    }
}

#[cfg(windows)]
fn allow_shared_texture_readback_fallback() -> bool {
    std::env::var("MRD_OPENGL_ALLOW_READBACK_FALLBACK")
        .ok()
        .as_deref()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InteropNv12Key {
    y_handle: isize,
    uv_handle: isize,
    width: usize,
    height: usize,
}

#[cfg(windows)]
impl InteropNv12Key {
    fn from_frame(frame: &RenderFrame) -> Option<Self> {
        match &frame.data {
            RenderFrameData::D3D11SharedNv12 {
                shared_handle_y,
                shared_handle_uv,
                ..
            } => Some(Self {
                y_handle: *shared_handle_y,
                uv_handle: *shared_handle_uv,
                width: frame.width,
                height: frame.height,
            }),
            _ => None,
        }
    }
}

#[cfg(windows)]
const NV12_VERTEX_SHADER: &str = r#"#version 120
varying vec2 v_tex_coord;

void main() {
    gl_Position = gl_Vertex;
    v_tex_coord = gl_MultiTexCoord0.xy;
}
"#;

#[cfg(windows)]
const NV12_FRAGMENT_SHADER: &str = r#"#version 120
uniform sampler2D y_tex;
uniform sampler2D uv_tex;
varying vec2 v_tex_coord;

void main() {
    float y = 1.16438356 * (texture2D(y_tex, v_tex_coord).r - 0.0625);
    vec2 uv = texture2D(uv_tex, v_tex_coord).rg - vec2(0.5, 0.5);
    float r = y + 1.79274107 * uv.y;
    float g = y - 0.21324861 * uv.x - 0.53290933 * uv.y;
    float b = y + 2.11240179 * uv.x;
    gl_FragColor = vec4(clamp(vec3(r, g, b), 0.0, 1.0), 1.0);
}
"#;

#[cfg(windows)]
type WglDxOpenDeviceNv = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
#[cfg(windows)]
type WglDxCloseDeviceNv = unsafe extern "system" fn(*mut c_void) -> i32;
#[cfg(windows)]
type WglDxRegisterObjectNv =
    unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, u32) -> *mut c_void;
#[cfg(windows)]
type WglDxUnregisterObjectNv = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
#[cfg(windows)]
type WglDxLockObjectsNv = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32;
#[cfg(windows)]
type WglDxUnlockObjectsNv = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32;

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct WglDxInteropFns {
    open_device: WglDxOpenDeviceNv,
    close_device: WglDxCloseDeviceNv,
    register_object: WglDxRegisterObjectNv,
    unregister_object: WglDxUnregisterObjectNv,
    lock_objects: WglDxLockObjectsNv,
    unlock_objects: WglDxUnlockObjectsNv,
}

#[cfg(windows)]
impl WglDxInteropFns {
    fn load() -> Result<Self, RenderError> {
        unsafe {
            Ok(Self {
                open_device: load_wgl_proc(b"wglDXOpenDeviceNV\0")?,
                close_device: load_wgl_proc(b"wglDXCloseDeviceNV\0")?,
                register_object: load_wgl_proc(b"wglDXRegisterObjectNV\0")?,
                unregister_object: load_wgl_proc(b"wglDXUnregisterObjectNV\0")?,
                lock_objects: load_wgl_proc(b"wglDXLockObjectsNV\0")?,
                unlock_objects: load_wgl_proc(b"wglDXUnlockObjectsNV\0")?,
            })
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct WglDxInteropDevice {
    fns: WglDxInteropFns,
    handle: *mut c_void,
}

#[cfg(windows)]
unsafe impl Send for WglDxInteropDevice {}

#[cfg(windows)]
impl WglDxInteropDevice {
    fn open(d3d11_device_ptr: *mut c_void) -> Result<Self, RenderError> {
        let fns = WglDxInteropFns::load()?;
        let handle = unsafe { (fns.open_device)(d3d11_device_ptr) };
        if handle.is_null() {
            return Err(RenderError::Message(
                "wglDXOpenDeviceNV returned null".to_string(),
            ));
        }
        Ok(Self { fns, handle })
    }
}

#[cfg(windows)]
impl Drop for WglDxInteropDevice {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = (self.fns.close_device)(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
const GL_TEXTURE0_LOCAL: u32 = 0x84C0;
#[cfg(windows)]
const GL_TEXTURE1_LOCAL: u32 = GL_TEXTURE0_LOCAL + 1;
#[cfg(windows)]
const GL_VERTEX_SHADER_LOCAL: u32 = 0x8B31;
#[cfg(windows)]
const GL_FRAGMENT_SHADER_LOCAL: u32 = 0x8B30;
#[cfg(windows)]
const GL_COMPILE_STATUS_LOCAL: u32 = 0x8B81;
#[cfg(windows)]
const GL_LINK_STATUS_LOCAL: u32 = 0x8B82;
#[cfg(windows)]
const GL_INFO_LOG_LENGTH_LOCAL: u32 = 0x8B84;
#[cfg(windows)]
const WGL_ACCESS_READ_ONLY_NV: u32 = 0x0000;

#[cfg(windows)]
type GlCreateShader = unsafe extern "system" fn(u32) -> u32;
#[cfg(windows)]
type GlShaderSource = unsafe extern "system" fn(u32, i32, *const *const c_char, *const i32);
#[cfg(windows)]
type GlCompileShader = unsafe extern "system" fn(u32);
#[cfg(windows)]
type GlGetShaderIv = unsafe extern "system" fn(u32, u32, *mut i32);
#[cfg(windows)]
type GlGetShaderInfoLog = unsafe extern "system" fn(u32, i32, *mut i32, *mut c_char);
#[cfg(windows)]
type GlDeleteShader = unsafe extern "system" fn(u32);
#[cfg(windows)]
type GlCreateProgram = unsafe extern "system" fn() -> u32;
#[cfg(windows)]
type GlAttachShader = unsafe extern "system" fn(u32, u32);
#[cfg(windows)]
type GlLinkProgram = unsafe extern "system" fn(u32);
#[cfg(windows)]
type GlGetProgramIv = unsafe extern "system" fn(u32, u32, *mut i32);
#[cfg(windows)]
type GlGetProgramInfoLog = unsafe extern "system" fn(u32, i32, *mut i32, *mut c_char);
#[cfg(windows)]
type GlUseProgram = unsafe extern "system" fn(u32);
#[cfg(windows)]
type GlDeleteProgram = unsafe extern "system" fn(u32);
#[cfg(windows)]
type GlGetUniformLocation = unsafe extern "system" fn(u32, *const c_char) -> i32;
#[cfg(windows)]
type GlUniform1i = unsafe extern "system" fn(i32, i32);
#[cfg(windows)]
type GlActiveTexture = unsafe extern "system" fn(u32);

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct GlShaderFns {
    create_shader: GlCreateShader,
    shader_source: GlShaderSource,
    compile_shader: GlCompileShader,
    get_shader_iv: GlGetShaderIv,
    get_shader_info_log: GlGetShaderInfoLog,
    delete_shader: GlDeleteShader,
    create_program: GlCreateProgram,
    attach_shader: GlAttachShader,
    link_program: GlLinkProgram,
    get_program_iv: GlGetProgramIv,
    get_program_info_log: GlGetProgramInfoLog,
    use_program: GlUseProgram,
    delete_program: GlDeleteProgram,
    get_uniform_location: GlGetUniformLocation,
    uniform1i: GlUniform1i,
    active_texture: GlActiveTexture,
}

#[cfg(windows)]
impl GlShaderFns {
    fn load() -> Result<Self, RenderError> {
        unsafe {
            Ok(Self {
                create_shader: load_wgl_proc(b"glCreateShader\0")?,
                shader_source: load_wgl_proc(b"glShaderSource\0")?,
                compile_shader: load_wgl_proc(b"glCompileShader\0")?,
                get_shader_iv: load_wgl_proc(b"glGetShaderiv\0")?,
                get_shader_info_log: load_wgl_proc(b"glGetShaderInfoLog\0")?,
                delete_shader: load_wgl_proc(b"glDeleteShader\0")?,
                create_program: load_wgl_proc(b"glCreateProgram\0")?,
                attach_shader: load_wgl_proc(b"glAttachShader\0")?,
                link_program: load_wgl_proc(b"glLinkProgram\0")?,
                get_program_iv: load_wgl_proc(b"glGetProgramiv\0")?,
                get_program_info_log: load_wgl_proc(b"glGetProgramInfoLog\0")?,
                use_program: load_wgl_proc(b"glUseProgram\0")?,
                delete_program: load_wgl_proc(b"glDeleteProgram\0")?,
                get_uniform_location: load_wgl_proc(b"glGetUniformLocation\0")?,
                uniform1i: load_wgl_proc(b"glUniform1i\0")?,
                active_texture: load_wgl_proc(b"glActiveTexture\0")?,
            })
        }
    }
}

#[cfg(windows)]
unsafe fn load_wgl_proc<T: Copy>(name: &'static [u8]) -> Result<T, RenderError> {
    let proc = windows::Win32::Graphics::OpenGL::wglGetProcAddress(PCSTR(name.as_ptr()));
    let proc = proc.ok_or_else(|| {
        RenderError::Message(format!(
            "OpenGL extension function is unavailable: {}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        ))
    })?;
    let addr = proc as *const () as usize;
    if matches!(addr, 0..=3) || addr == usize::MAX {
        return Err(RenderError::Message(format!(
            "OpenGL extension function returned invalid pointer: {}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
        )));
    }
    Ok(std::mem::transmute_copy(&proc))
}

#[cfg(windows)]
#[derive(Debug)]
struct Nv12ShaderProgram {
    fns: GlShaderFns,
    program: u32,
    y_location: i32,
    uv_location: i32,
}

#[cfg(windows)]
unsafe impl Send for Nv12ShaderProgram {}

#[cfg(windows)]
impl Nv12ShaderProgram {
    fn new() -> Result<Self, RenderError> {
        let fns = GlShaderFns::load()?;
        let vertex = compile_shader(&fns, GL_VERTEX_SHADER_LOCAL, NV12_VERTEX_SHADER)?;
        let fragment = compile_shader(&fns, GL_FRAGMENT_SHADER_LOCAL, NV12_FRAGMENT_SHADER)?;
        let program = unsafe { (fns.create_program)() };
        if program == 0 {
            unsafe {
                (fns.delete_shader)(vertex);
                (fns.delete_shader)(fragment);
            }
            return Err(RenderError::Message(
                "create OpenGL NV12 shader program failed".to_string(),
            ));
        }
        unsafe {
            (fns.attach_shader)(program, vertex);
            (fns.attach_shader)(program, fragment);
            (fns.link_program)(program);
            (fns.delete_shader)(vertex);
            (fns.delete_shader)(fragment);
        }

        let mut status = 0_i32;
        unsafe {
            (fns.get_program_iv)(program, GL_LINK_STATUS_LOCAL, &mut status);
        }
        if status == 0 {
            let log = program_info_log(&fns, program);
            unsafe {
                (fns.delete_program)(program);
            }
            return Err(RenderError::Message(format!(
                "link OpenGL NV12 shader program failed: {log}"
            )));
        }

        let y_name = CString::new("y_tex").expect("static uniform name");
        let uv_name = CString::new("uv_tex").expect("static uniform name");
        let y_location = unsafe { (fns.get_uniform_location)(program, y_name.as_ptr()) };
        let uv_location = unsafe { (fns.get_uniform_location)(program, uv_name.as_ptr()) };
        if y_location < 0 || uv_location < 0 {
            unsafe {
                (fns.delete_program)(program);
            }
            return Err(RenderError::Message(
                "OpenGL NV12 shader uniform lookup failed".to_string(),
            ));
        }

        Ok(Self {
            fns,
            program,
            y_location,
            uv_location,
        })
    }
}

#[cfg(windows)]
impl Drop for Nv12ShaderProgram {
    fn drop(&mut self) {
        if self.program != 0 {
            unsafe {
                (self.fns.delete_program)(self.program);
            }
            self.program = 0;
        }
    }
}

#[cfg(windows)]
fn compile_shader(fns: &GlShaderFns, shader_type: u32, source: &str) -> Result<u32, RenderError> {
    let shader = unsafe { (fns.create_shader)(shader_type) };
    if shader == 0 {
        return Err(RenderError::Message(
            "create OpenGL shader object failed".to_string(),
        ));
    }
    let source = CString::new(source)
        .map_err(|_| RenderError::Message("shader source contains NUL".to_string()))?;
    let source_ptr = source.as_ptr();
    let source_len = source.as_bytes().len() as i32;
    unsafe {
        (fns.shader_source)(shader, 1, &source_ptr, &source_len);
        (fns.compile_shader)(shader);
    }
    let mut status = 0_i32;
    unsafe {
        (fns.get_shader_iv)(shader, GL_COMPILE_STATUS_LOCAL, &mut status);
    }
    if status == 0 {
        let log = shader_info_log(fns, shader);
        unsafe {
            (fns.delete_shader)(shader);
        }
        return Err(RenderError::Message(format!(
            "compile OpenGL shader failed: {log}"
        )));
    }
    Ok(shader)
}

#[cfg(windows)]
fn shader_info_log(fns: &GlShaderFns, shader: u32) -> String {
    let mut len = 0_i32;
    unsafe {
        (fns.get_shader_iv)(shader, GL_INFO_LOG_LENGTH_LOCAL, &mut len);
    }
    gl_info_log(len, |capacity, written, buffer| unsafe {
        (fns.get_shader_info_log)(shader, capacity, written, buffer);
    })
}

#[cfg(windows)]
fn program_info_log(fns: &GlShaderFns, program: u32) -> String {
    let mut len = 0_i32;
    unsafe {
        (fns.get_program_iv)(program, GL_INFO_LOG_LENGTH_LOCAL, &mut len);
    }
    gl_info_log(len, |capacity, written, buffer| unsafe {
        (fns.get_program_info_log)(program, capacity, written, buffer);
    })
}

#[cfg(windows)]
fn gl_info_log(len: i32, fill: impl FnOnce(i32, *mut i32, *mut c_char)) -> String {
    if len <= 1 {
        return String::new();
    }
    let mut buffer = vec![0_i8; len as usize];
    let mut written = 0_i32;
    fill(len, &mut written, buffer.as_mut_ptr());
    let bytes = buffer
        .into_iter()
        .take(written.max(0) as usize)
        .map(|value| value as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(windows)]
#[derive(Debug)]
struct InteropRegisteredTexture {
    gl_texture: u32,
    object_handle: *mut c_void,
    _texture: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
}

#[cfg(windows)]
unsafe impl Send for InteropRegisteredTexture {}

#[cfg(windows)]
impl InteropRegisteredTexture {
    fn register(
        interop: &WglDxInteropDevice,
        texture: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
    ) -> Result<Self, RenderError> {
        use windows::Win32::Graphics::OpenGL::{
            glBindTexture, glGenTextures, glTexParameteri, GL_CLAMP, GL_LINEAR, GL_TEXTURE_2D,
            GL_TEXTURE_MAG_FILTER, GL_TEXTURE_MIN_FILTER, GL_TEXTURE_WRAP_S, GL_TEXTURE_WRAP_T,
        };

        let mut gl_texture = 0_u32;
        unsafe {
            glGenTextures(1, &mut gl_texture);
            glBindTexture(GL_TEXTURE_2D, gl_texture);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR as i32);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR as i32);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP as i32);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP as i32);
            glBindTexture(GL_TEXTURE_2D, 0);
        }
        if gl_texture == 0 {
            return Err(RenderError::Message(
                "create OpenGL interop texture failed".to_string(),
            ));
        }

        let object_handle = unsafe {
            (interop.fns.register_object)(
                interop.handle,
                texture.as_raw(),
                gl_texture,
                GL_TEXTURE_2D,
                WGL_ACCESS_READ_ONLY_NV,
            )
        };
        if object_handle.is_null() {
            unsafe {
                windows::Win32::Graphics::OpenGL::glDeleteTextures(1, &gl_texture);
            }
            return Err(RenderError::Message(
                "wglDXRegisterObjectNV returned null".to_string(),
            ));
        }

        Ok(Self {
            gl_texture,
            object_handle,
            _texture: texture,
        })
    }

    fn unregister(&mut self, interop: &WglDxInteropDevice) {
        unsafe {
            if !self.object_handle.is_null() {
                let _ = (interop.fns.unregister_object)(interop.handle, self.object_handle);
                self.object_handle = std::ptr::null_mut();
            }
            if self.gl_texture != 0 {
                windows::Win32::Graphics::OpenGL::glDeleteTextures(1, &self.gl_texture);
                self.gl_texture = 0;
            }
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct InteropNv12Textures {
    key: InteropNv12Key,
    y: InteropRegisteredTexture,
    uv: InteropRegisteredTexture,
}

#[cfg(windows)]
unsafe impl Send for InteropNv12Textures {}

#[cfg(windows)]
impl InteropNv12Textures {
    fn register(
        interop: &WglDxInteropDevice,
        bridge: &D3d11ReadbackBridge,
        key: InteropNv12Key,
    ) -> Result<Self, RenderError> {
        let y_texture = bridge.open_shared_texture(key.y_handle)?;
        let uv_texture = bridge.open_shared_texture(key.uv_handle)?;
        let mut y = InteropRegisteredTexture::register(interop, y_texture)?;
        let uv = match InteropRegisteredTexture::register(interop, uv_texture) {
            Ok(uv) => uv,
            Err(error) => {
                y.unregister(interop);
                return Err(error);
            }
        };
        Ok(Self { key, y, uv })
    }

    fn unregister(&mut self, interop: &WglDxInteropDevice) {
        self.y.unregister(interop);
        self.uv.unregister(interop);
    }

    fn lock(&self, interop: &WglDxInteropDevice) -> Result<(), RenderError> {
        let mut objects = [self.y.object_handle, self.uv.object_handle];
        let ok = unsafe { (interop.fns.lock_objects)(interop.handle, 2, objects.as_mut_ptr()) };
        if ok == 0 {
            return Err(RenderError::Message(
                "wglDXLockObjectsNV failed for NV12 textures".to_string(),
            ));
        }
        Ok(())
    }

    fn unlock(&self, interop: &WglDxInteropDevice) -> Result<(), RenderError> {
        let mut objects = [self.y.object_handle, self.uv.object_handle];
        let ok = unsafe { (interop.fns.unlock_objects)(interop.handle, 2, objects.as_mut_ptr()) };
        if ok == 0 {
            return Err(RenderError::Message(
                "wglDXUnlockObjectsNV failed for NV12 textures".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct D3d11TextureReadback {
    data: Vec<u8>,
    width: usize,
    height: usize,
    bytes_per_texel: usize,
    format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT,
}

#[cfg(windows)]
impl D3d11TextureReadback {
    fn row_pitch(&self) -> usize {
        self.width * self.bytes_per_texel
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct D3d11ReadbackBridge {
    device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    context: windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext,
}

#[cfg(windows)]
unsafe impl Send for D3d11ReadbackBridge {}

#[cfg(windows)]
impl D3d11ReadbackBridge {
    fn new() -> Result<Self, RenderError> {
        use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
        use windows::Win32::Graphics::Direct3D11::{
            D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            D3D11_SDK_VERSION,
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
        .map_err(|error| {
            RenderError::Message(format!("create OpenGL hybrid D3D11 bridge failed: {error}"))
        })?;

        Ok(Self {
            device: device
                .ok_or_else(|| RenderError::Message("missing D3D11 device".to_string()))?,
            context: context
                .ok_or_else(|| RenderError::Message("missing D3D11 context".to_string()))?,
        })
    }

    fn device_ptr(&self) -> *mut core::ffi::c_void {
        self.device.as_raw()
    }

    fn readback_frame_to_bgra(&mut self, frame: &RenderFrame) -> Result<Vec<u8>, RenderError> {
        match &frame.data {
            RenderFrameData::D3D11SharedBgra { shared_handle, .. } => {
                self.readback_shared_bgra_to_bgra(*shared_handle, frame.width, frame.height)
            }
            RenderFrameData::D3D11SharedNv12 {
                shared_handle_y,
                shared_handle_uv,
                ..
            } => self.readback_shared_nv12_to_bgra(
                *shared_handle_y,
                *shared_handle_uv,
                frame.width,
                frame.height,
            ),
            RenderFrameData::D3D11SharedP010 {
                shared_handle_y,
                shared_handle_uv,
                ..
            } => self.readback_shared_p010_to_bgra(
                *shared_handle_y,
                *shared_handle_uv,
                frame.width,
                frame.height,
            ),
            _ => Err(RenderError::Message(
                "expected D3D11 shared texture frame".to_string(),
            )),
        }
    }

    fn open_shared_texture(
        &self,
        shared_handle: isize,
    ) -> Result<windows::Win32::Graphics::Direct3D11::ID3D11Texture2D, RenderError> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;

        if shared_handle == 0 {
            return Err(RenderError::Message(
                "shared texture handle is zero".to_string(),
            ));
        }

        let mut texture = None::<ID3D11Texture2D>;
        unsafe {
            self.device
                .OpenSharedResource(HANDLE(shared_handle), &mut texture)
                .map_err(|error| {
                    RenderError::Message(format!("open shared D3D11 texture failed: {error}"))
                })?;
        }
        texture.ok_or_else(|| RenderError::Message("missing shared texture".to_string()))
    }

    fn readback_shared_texture(
        &self,
        shared_handle: isize,
    ) -> Result<D3d11TextureReadback, RenderError> {
        use windows::Win32::Graphics::Direct3D11::{
            ID3D11Resource, ID3D11Texture2D, D3D11_CPU_ACCESS_READ, D3D11_MAPPED_SUBRESOURCE,
            D3D11_MAP_READ, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
        };

        let texture = self.open_shared_texture(shared_handle)?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe {
            texture.GetDesc(&mut desc);
        }
        let bytes_per_texel = bytes_per_texel_for_dxgi(desc.Format)?;

        let mut staging_desc = desc;
        staging_desc.Usage = D3D11_USAGE_STAGING;
        staging_desc.BindFlags = 0;
        staging_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        staging_desc.MiscFlags = 0;

        let mut staging = None::<ID3D11Texture2D>;
        unsafe {
            self.device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
                .map_err(|error| {
                    RenderError::Message(format!(
                        "create OpenGL hybrid staging texture failed: {error}"
                    ))
                })?;
        }
        let staging =
            staging.ok_or_else(|| RenderError::Message("missing staging texture".to_string()))?;

        let source_resource: ID3D11Resource = texture.cast().map_err(|error| {
            RenderError::Message(format!("cast shared texture to resource failed: {error}"))
        })?;
        let staging_resource: ID3D11Resource = staging.cast().map_err(|error| {
            RenderError::Message(format!("cast staging texture to resource failed: {error}"))
        })?;

        unsafe {
            self.context
                .CopyResource(&staging_resource, &source_resource);
        }

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe {
            self.context
                .Map(&staging_resource, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|error| {
                    RenderError::Message(format!(
                        "map OpenGL hybrid staging texture failed: {error}"
                    ))
                })?;
        }

        let copy_result = copy_mapped_texture_rows(
            &mapped,
            desc.Width as usize,
            desc.Height as usize,
            bytes_per_texel,
        );
        unsafe {
            self.context.Unmap(&staging_resource, 0);
        }
        let data = copy_result?;

        Ok(D3d11TextureReadback {
            data,
            width: desc.Width as usize,
            height: desc.Height as usize,
            bytes_per_texel,
            format: desc.Format,
        })
    }

    fn readback_shared_bgra_to_bgra(
        &self,
        shared_handle: isize,
        width: usize,
        height: usize,
    ) -> Result<Vec<u8>, RenderError> {
        use windows::Win32::Graphics::Dxgi::Common::{
            DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R8G8B8A8_UNORM,
        };

        let readback = self.readback_shared_texture(shared_handle)?;
        if readback.width < width || readback.height < height {
            return Err(RenderError::Message(format!(
                "shared BGRA texture too small: {}x{} for {width}x{height}",
                readback.width, readback.height
            )));
        }
        match readback.format {
            DXGI_FORMAT_B8G8R8A8_UNORM => Ok(readback.data),
            DXGI_FORMAT_R8G8B8A8_UNORM => Ok(rgba_to_bgra(&readback.data, width, height)),
            other => Err(RenderError::Message(format!(
                "unsupported shared BGRA texture format: {other:?}"
            ))),
        }
    }

    fn readback_shared_nv12_to_bgra(
        &self,
        y_handle: isize,
        uv_handle: isize,
        width: usize,
        height: usize,
    ) -> Result<Vec<u8>, RenderError> {
        use windows::Win32::Graphics::Dxgi::Common::{
            DXGI_FORMAT_R8G8_UNORM, DXGI_FORMAT_R8_UNORM,
        };

        let y = self.readback_shared_texture(y_handle)?;
        let uv = self.readback_shared_texture(uv_handle)?;
        if y.format != DXGI_FORMAT_R8_UNORM || uv.format != DXGI_FORMAT_R8G8_UNORM {
            return Err(RenderError::Message(format!(
                "unsupported shared NV12 texture formats: y={:?}, uv={:?}",
                y.format, uv.format
            )));
        }
        Ok(nv12_planes_to_bgra(
            &y.data,
            y.row_pitch(),
            &uv.data,
            uv.row_pitch(),
            width,
            height,
        ))
    }

    fn readback_shared_p010_to_bgra(
        &self,
        y_handle: isize,
        uv_handle: isize,
        width: usize,
        height: usize,
    ) -> Result<Vec<u8>, RenderError> {
        use windows::Win32::Graphics::Dxgi::Common::{
            DXGI_FORMAT_R16G16_UNORM, DXGI_FORMAT_R16_UNORM,
        };

        let y = self.readback_shared_texture(y_handle)?;
        let uv = self.readback_shared_texture(uv_handle)?;
        if y.format != DXGI_FORMAT_R16_UNORM || uv.format != DXGI_FORMAT_R16G16_UNORM {
            return Err(RenderError::Message(format!(
                "unsupported shared P010 texture formats: y={:?}, uv={:?}",
                y.format, uv.format
            )));
        }
        Ok(p010_planes_to_bgra(
            &y.data,
            y.row_pitch(),
            &uv.data,
            uv.row_pitch(),
            width,
            height,
        ))
    }
}

#[cfg(windows)]
fn bytes_per_texel_for_dxgi(
    format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT,
) -> Result<usize, RenderError> {
    use windows::Win32::Graphics::Dxgi::Common::{
        DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R16G16_UNORM, DXGI_FORMAT_R16_UNORM,
        DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_FORMAT_R8G8_UNORM, DXGI_FORMAT_R8_UNORM,
    };

    match format {
        DXGI_FORMAT_R8_UNORM => Ok(1),
        DXGI_FORMAT_R8G8_UNORM | DXGI_FORMAT_R16_UNORM => Ok(2),
        DXGI_FORMAT_R16G16_UNORM | DXGI_FORMAT_B8G8R8A8_UNORM | DXGI_FORMAT_R8G8B8A8_UNORM => Ok(4),
        other => Err(RenderError::Message(format!(
            "unsupported OpenGL hybrid readback format: {other:?}"
        ))),
    }
}

#[cfg(windows)]
fn copy_mapped_texture_rows(
    mapped: &windows::Win32::Graphics::Direct3D11::D3D11_MAPPED_SUBRESOURCE,
    width: usize,
    height: usize,
    bytes_per_texel: usize,
) -> Result<Vec<u8>, RenderError> {
    if mapped.pData.is_null() {
        return Err(RenderError::Message(
            "mapped OpenGL hybrid texture pointer is null".to_string(),
        ));
    }
    let row_bytes = width
        .checked_mul(bytes_per_texel)
        .ok_or_else(|| RenderError::Message("mapped row size overflow".to_string()))?;
    let row_pitch = mapped.RowPitch as usize;
    if row_pitch < row_bytes {
        return Err(RenderError::Message(format!(
            "mapped row pitch {row_pitch} is smaller than row bytes {row_bytes}"
        )));
    }
    let mut data = vec![0_u8; row_bytes * height];
    for row in 0..height {
        let source = unsafe {
            std::slice::from_raw_parts((mapped.pData as *const u8).add(row * row_pitch), row_bytes)
        };
        let start = row * row_bytes;
        data[start..start + row_bytes].copy_from_slice(source);
    }
    Ok(data)
}

#[cfg(windows)]
fn rgba_to_bgra(rgba: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    for (src, dst) in rgba
        .as_chunks::<4>()
        .0
        .iter()
        .zip(bgra.as_chunks_mut::<4>().0.iter_mut())
    {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = src[3];
    }
    bgra
}

#[cfg(windows)]
fn nv12_planes_to_bgra(
    y_plane: &[u8],
    y_pitch: usize,
    uv_plane: &[u8],
    uv_pitch: usize,
    width: usize,
    height: usize,
) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    for y in 0..height {
        let y_row = y * y_pitch;
        let uv_row = (y / 2) * uv_pitch;
        for x in 0..width {
            let y_offset = y_row + x;
            let uv_offset = uv_row + (x / 2) * 2;
            if y_offset >= y_plane.len() || uv_offset + 1 >= uv_plane.len() {
                continue;
            }
            let y_sample = y_plane[y_offset] as i32 - 16;
            let u = uv_plane[uv_offset] as i32 - 128;
            let v = uv_plane[uv_offset + 1] as i32 - 128;
            let r = (298 * y_sample + 409 * v + 128) >> 8;
            let g = (298 * y_sample - 100 * u - 208 * v + 128) >> 8;
            let b = (298 * y_sample + 516 * u + 128) >> 8;
            let out = (y * width + x) * 4;
            bgra[out] = b.clamp(0, 255) as u8;
            bgra[out + 1] = g.clamp(0, 255) as u8;
            bgra[out + 2] = r.clamp(0, 255) as u8;
            bgra[out + 3] = 255;
        }
    }
    bgra
}

#[cfg(windows)]
fn p010_planes_to_bgra(
    y_plane: &[u8],
    y_pitch: usize,
    uv_plane: &[u8],
    uv_pitch: usize,
    width: usize,
    height: usize,
) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    for y in 0..height {
        let y_row = y * y_pitch;
        let uv_row = (y / 2) * uv_pitch;
        for x in 0..width {
            let y_offset = y_row + x * 2;
            let uv_offset = uv_row + (x / 2) * 4;
            if y_offset + 1 >= y_plane.len() || uv_offset + 3 >= uv_plane.len() {
                continue;
            }
            let y10 = u16::from_le_bytes([y_plane[y_offset], y_plane[y_offset + 1]]) >> 6;
            let u10 = u16::from_le_bytes([uv_plane[uv_offset], uv_plane[uv_offset + 1]]) >> 6;
            let v10 = u16::from_le_bytes([uv_plane[uv_offset + 2], uv_plane[uv_offset + 3]]) >> 6;
            let y_sample = y10 as i32;
            let u = u10 as i32 - 512;
            let v = v10 as i32 - 512;
            let r = y_sample + ((1436 * v) >> 10);
            let g = y_sample - ((352 * u + 731 * v) >> 10);
            let b = y_sample + ((1815 * u) >> 10);
            let out = (y * width + x) * 4;
            bgra[out] = clamp_10bit_to_8bit(b);
            bgra[out + 1] = clamp_10bit_to_8bit(g);
            bgra[out + 2] = clamp_10bit_to_8bit(r);
            bgra[out + 3] = 255;
        }
    }
    bgra
}

#[inline]
#[cfg(windows)]
fn clamp_10bit_to_8bit(value: i32) -> u8 {
    ((value.clamp(0, 1023) + 2) >> 2) as u8
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsGlSurface {
    hwnd: windows::Win32::Foundation::HWND,
    hdc: windows::Win32::Graphics::Gdi::HDC,
    context: windows::Win32::Graphics::OpenGL::HGLRC,
    texture_id: u32,
    texture_cache: TextureCache,
    interop: Option<WglDxInteropDevice>,
    interop_disabled: bool,
    interop_nv12: Option<InteropNv12Textures>,
    nv12_program: Option<Nv12ShaderProgram>,
}

#[cfg(windows)]
unsafe impl Send for WindowsGlSurface {}

#[cfg(windows)]
impl WindowsGlSurface {
    fn attach(hwnd: isize) -> Result<Self, RenderError> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::Graphics::Gdi::GetDC;
        use windows::Win32::Graphics::OpenGL::{
            wglCreateContext, wglMakeCurrent, ChoosePixelFormat, SetPixelFormat, PFD_DOUBLEBUFFER,
            PFD_DRAW_TO_WINDOW, PFD_FLAGS, PFD_MAIN_PLANE, PFD_SUPPORT_OPENGL, PFD_TYPE_RGBA,
            PIXELFORMATDESCRIPTOR,
        };

        unsafe {
            let hwnd = HWND(hwnd);
            let hdc = GetDC(hwnd);
            if hdc.0 == 0 {
                return Err(RenderError::Message(
                    "get OpenGL render target device context failed".to_string(),
                ));
            }

            let pfd = PIXELFORMATDESCRIPTOR {
                nSize: std::mem::size_of::<PIXELFORMATDESCRIPTOR>() as u16,
                nVersion: 1,
                dwFlags: PFD_FLAGS(
                    PFD_DRAW_TO_WINDOW.0 | PFD_SUPPORT_OPENGL.0 | PFD_DOUBLEBUFFER.0,
                ),
                iPixelType: PFD_TYPE_RGBA,
                cColorBits: 32,
                cDepthBits: 0,
                cStencilBits: 0,
                iLayerType: PFD_MAIN_PLANE.0 as u8,
                ..Default::default()
            };
            let pixel_format = ChoosePixelFormat(hdc, &pfd);
            if pixel_format == 0 {
                let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc);
                return Err(RenderError::Message(
                    "choose OpenGL pixel format failed".to_string(),
                ));
            }
            SetPixelFormat(hdc, pixel_format, &pfd).map_err(|error| {
                let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc);
                RenderError::Message(format!("set OpenGL pixel format failed: {error}"))
            })?;

            let context = wglCreateContext(hdc).map_err(|error| {
                let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc);
                RenderError::Message(format!("create OpenGL context failed: {error}"))
            })?;
            wglMakeCurrent(hdc, context).map_err(|error| {
                let _ = windows::Win32::Graphics::OpenGL::wglDeleteContext(context);
                let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc);
                RenderError::Message(format!("make OpenGL context current failed: {error}"))
            })?;

            let mut texture_id = 0_u32;
            windows::Win32::Graphics::OpenGL::glGenTextures(1, &mut texture_id);
            if texture_id == 0 {
                let _ = windows::Win32::Graphics::OpenGL::wglMakeCurrent(
                    windows::Win32::Graphics::Gdi::HDC(0),
                    windows::Win32::Graphics::OpenGL::HGLRC(0),
                );
                let _ = windows::Win32::Graphics::OpenGL::wglDeleteContext(context);
                let _ = windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc);
                return Err(RenderError::Message(
                    "create OpenGL texture failed".to_string(),
                ));
            }

            Ok(Self {
                hwnd,
                hdc,
                context,
                texture_id,
                texture_cache: TextureCache::default(),
                interop: None,
                interop_disabled: false,
                interop_nv12: None,
                nv12_program: None,
            })
        }
    }

    fn present_shared_frame(
        &mut self,
        frame: &RenderFrame,
        bridge: &D3d11ReadbackBridge,
    ) -> Result<SharedTexturePath, RenderError> {
        let path = choose_shared_texture_path(true, !self.interop_disabled);
        let allow_readback_fallback = allow_shared_texture_readback_fallback();
        if path != SharedTexturePath::WglDxInterop {
            if path == SharedTexturePath::ReadbackFallback && !allow_readback_fallback {
                return Err(RenderError::Message(
                    "OpenGL hybrid D3D11 readback fallback is disabled; set MRD_OPENGL_ALLOW_READBACK_FALLBACK=1 to allow the slow GPU readback path"
                        .to_string(),
                ));
            }
            return Ok(path);
        }

        if InteropNv12Key::from_frame(frame).is_none() {
            if !allow_readback_fallback {
                return Err(RenderError::Message(
                    "OpenGL hybrid readback fallback for non-NV12 shared textures is disabled; set MRD_OPENGL_ALLOW_READBACK_FALLBACK=1 to allow the slow GPU readback path"
                        .to_string(),
                ));
            }
            return Ok(SharedTexturePath::ReadbackFallback);
        }

        unsafe {
            windows::Win32::Graphics::OpenGL::wglMakeCurrent(self.hdc, self.context).map_err(
                |error| {
                    RenderError::Message(format!("make OpenGL context current failed: {error}"))
                },
            )?;
        }

        match self.present_nv12_interop(frame, bridge) {
            Ok(()) => Ok(SharedTexturePath::WglDxInterop),
            Err(error) => {
                if !allow_readback_fallback {
                    return Err(RenderError::Message(format!(
                        "OpenGL WGL/DX interop unavailable and readback fallback is disabled: {error}"
                    )));
                }
                eprintln!("OpenGL WGL/DX interop unavailable; falling back to readback: {error}");
                self.interop_disabled = true;
                Ok(SharedTexturePath::ReadbackFallback)
            }
        }
    }

    fn present_nv12_interop(
        &mut self,
        frame: &RenderFrame,
        bridge: &D3d11ReadbackBridge,
    ) -> Result<(), RenderError> {
        let key = InteropNv12Key::from_frame(frame).ok_or_else(|| {
            RenderError::Message("OpenGL interop currently supports D3D11 shared NV12".to_string())
        })?;

        if self.interop.is_none() {
            self.interop = Some(WglDxInteropDevice::open(bridge.device_ptr())?);
        }
        if self.nv12_program.is_none() {
            self.nv12_program = Some(Nv12ShaderProgram::new()?);
        }

        let interop = self.interop.as_ref().expect("interop device initialized");
        if self
            .interop_nv12
            .as_ref()
            .map(|textures| textures.key != key)
            .unwrap_or(true)
        {
            if let Some(mut old) = self.interop_nv12.take() {
                old.unregister(interop);
            }
            self.interop_nv12 = Some(InteropNv12Textures::register(interop, bridge, key)?);
        }

        let textures = self
            .interop_nv12
            .as_ref()
            .expect("NV12 textures initialized");
        let program = self.nv12_program.as_ref().expect("NV12 shader initialized");
        textures.lock(interop)?;
        let draw_result = self.draw_nv12_interop(program, textures, frame.width, frame.height);
        let unlock_result = textures.unlock(interop);
        draw_result?;
        unlock_result?;
        Ok(())
    }

    fn draw_nv12_interop(
        &self,
        program: &Nv12ShaderProgram,
        textures: &InteropNv12Textures,
        width: usize,
        height: usize,
    ) -> Result<(), RenderError> {
        use windows::Win32::Graphics::OpenGL::{
            glBegin, glBindTexture, glColor4f, glDisable, glEnable, glEnd, glTexCoord2f,
            glVertex2f, glViewport, SwapBuffers, GL_QUADS, GL_TEXTURE_2D,
        };

        let width = i32::try_from(width)
            .map_err(|_| RenderError::Message("OpenGL frame width exceeds i32".to_string()))?;
        let height = i32::try_from(height)
            .map_err(|_| RenderError::Message("OpenGL frame height exceeds i32".to_string()))?;

        unsafe {
            glViewport(0, 0, width, height);
            (program.fns.use_program)(program.program);

            (program.fns.active_texture)(GL_TEXTURE0_LOCAL);
            glEnable(GL_TEXTURE_2D);
            glBindTexture(GL_TEXTURE_2D, textures.y.gl_texture);
            (program.fns.uniform1i)(program.y_location, 0);

            (program.fns.active_texture)(GL_TEXTURE1_LOCAL);
            glEnable(GL_TEXTURE_2D);
            glBindTexture(GL_TEXTURE_2D, textures.uv.gl_texture);
            (program.fns.uniform1i)(program.uv_location, 1);

            (program.fns.active_texture)(GL_TEXTURE0_LOCAL);
            glColor4f(1.0, 1.0, 1.0, 1.0);
            glBegin(GL_QUADS);
            glTexCoord2f(0.0, 1.0);
            glVertex2f(-1.0, -1.0);
            glTexCoord2f(1.0, 1.0);
            glVertex2f(1.0, -1.0);
            glTexCoord2f(1.0, 0.0);
            glVertex2f(1.0, 1.0);
            glTexCoord2f(0.0, 0.0);
            glVertex2f(-1.0, 1.0);
            glEnd();

            (program.fns.active_texture)(GL_TEXTURE1_LOCAL);
            glBindTexture(GL_TEXTURE_2D, 0);
            glDisable(GL_TEXTURE_2D);
            (program.fns.active_texture)(GL_TEXTURE0_LOCAL);
            glBindTexture(GL_TEXTURE_2D, 0);
            glDisable(GL_TEXTURE_2D);
            (program.fns.use_program)(0);

            SwapBuffers(self.hdc).map_err(|error| {
                RenderError::Message(format!("OpenGL SwapBuffers failed: {error}"))
            })?;
        }

        Ok(())
    }

    fn present_frame(&mut self, frame: &RenderFrame) -> Result<(), RenderError> {
        use std::ffi::c_void;
        use windows::Win32::Graphics::OpenGL::{
            glBegin, glBindTexture, glColor4f, glDisable, glEnable, glEnd, glPixelStorei,
            glTexCoord2f, glTexImage2D, glTexParameteri, glTexSubImage2D, glVertex2f, glViewport,
            wglMakeCurrent, SwapBuffers, GL_BGRA_EXT, GL_CLAMP, GL_LINEAR, GL_QUADS, GL_RGB,
            GL_RGBA, GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_TEXTURE_MIN_FILTER,
            GL_TEXTURE_WRAP_S, GL_TEXTURE_WRAP_T, GL_UNPACK_ALIGNMENT, GL_UNSIGNED_BYTE,
        };

        let (format, pixels) = match &frame.data {
            RenderFrameData::Rgb24(data) => (GL_RGB, data.as_ptr()),
            RenderFrameData::Bgra32(data) => (GL_BGRA_EXT, data.as_ptr()),
            _ => {
                return Err(RenderError::Message(
                    "OpenGL present only accepts CPU Rgb24 or Bgra32 frame data".to_string(),
                ))
            }
        };
        let pixel_format = frame.pixel_format;

        let width = i32::try_from(frame.width)
            .map_err(|_| RenderError::Message("OpenGL frame width exceeds i32".to_string()))?;
        let height = i32::try_from(frame.height)
            .map_err(|_| RenderError::Message("OpenGL frame height exceeds i32".to_string()))?;

        unsafe {
            wglMakeCurrent(self.hdc, self.context).map_err(|error| {
                RenderError::Message(format!("make OpenGL context current failed: {error}"))
            })?;
            glViewport(0, 0, width, height);
            glEnable(GL_TEXTURE_2D);
            glBindTexture(GL_TEXTURE_2D, self.texture_id);
            glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
            if self.texture_cache.needs_parameter_setup() {
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR as i32);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR as i32);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP as i32);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP as i32);
                self.texture_cache.record_parameters_configured();
            }

            let pixels = pixels.cast::<c_void>();
            if self
                .texture_cache
                .needs_reallocate(frame.width, frame.height, pixel_format)
            {
                glTexImage2D(
                    GL_TEXTURE_2D,
                    0,
                    GL_RGBA as i32,
                    width,
                    height,
                    0,
                    format,
                    GL_UNSIGNED_BYTE,
                    pixels,
                );
                self.texture_cache
                    .record_allocation(frame.width, frame.height, pixel_format);
            } else {
                glTexSubImage2D(
                    GL_TEXTURE_2D,
                    0,
                    0,
                    0,
                    width,
                    height,
                    format,
                    GL_UNSIGNED_BYTE,
                    pixels,
                );
            }

            glColor4f(1.0, 1.0, 1.0, 1.0);
            glBegin(GL_QUADS);
            glTexCoord2f(0.0, 1.0);
            glVertex2f(-1.0, -1.0);
            glTexCoord2f(1.0, 1.0);
            glVertex2f(1.0, -1.0);
            glTexCoord2f(1.0, 0.0);
            glVertex2f(1.0, 1.0);
            glTexCoord2f(0.0, 0.0);
            glVertex2f(-1.0, 1.0);
            glEnd();
            glBindTexture(GL_TEXTURE_2D, 0);
            glDisable(GL_TEXTURE_2D);

            SwapBuffers(self.hdc).map_err(|error| {
                RenderError::Message(format!("OpenGL SwapBuffers failed: {error}"))
            })?;
        }

        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsGlSurface {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Graphics::OpenGL::wglMakeCurrent(self.hdc, self.context);
            if let Some(mut textures) = self.interop_nv12.take() {
                if let Some(interop) = self.interop.as_ref() {
                    textures.unregister(interop);
                }
            }
            self.nv12_program = None;
            self.interop = None;
            if self.texture_id != 0 {
                windows::Win32::Graphics::OpenGL::glDeleteTextures(1, &self.texture_id);
            }
            let _ = windows::Win32::Graphics::OpenGL::wglMakeCurrent(
                windows::Win32::Graphics::Gdi::HDC(0),
                windows::Win32::Graphics::OpenGL::HGLRC(0),
            );
            let _ = windows::Win32::Graphics::OpenGL::wglDeleteContext(self.context);
            let _ = windows::Win32::Graphics::Gdi::ReleaseDC(self.hwnd, self.hdc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_reports_cpu_backed_opengl_formats() {
        let descriptor = opengl_descriptor();

        assert_eq!(descriptor.id, "opengl");
        assert_eq!(descriptor.runtime_status, RuntimeStatus::RuntimeBacked);
        assert!(descriptor
            .supported_formats
            .contains(&RenderPixelFormat::Rgb24));
        assert!(descriptor
            .supported_formats
            .contains(&RenderPixelFormat::Bgra32));
        #[cfg(windows)]
        assert!(descriptor
            .supported_formats
            .contains(&RenderPixelFormat::D3D11SharedNv12));
    }

    #[test]
    fn upload_rgb24_frame_updates_snapshot() {
        let mut renderer = OpenglRenderer::new();
        renderer
            .attach_target(RenderTarget::WindowHandle(0))
            .expect("attach headless OpenGL target");
        renderer
            .upload_frame(RenderFrame::from_rgb24(2, 2, vec![0; 2 * 2 * 3]))
            .expect("upload RGB frame");

        let snapshot = renderer.snapshot();
        assert!(!snapshot.attached_to_target);
        assert_eq!(renderer.target_hwnd(), Some(0));
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(snapshot.last_width, 2);
        assert_eq!(snapshot.last_height, 2);
        assert_eq!(snapshot.last_pixel_format, Some(RenderPixelFormat::Rgb24));
    }

    #[test]
    fn texture_cache_reuses_matching_frame_shape() {
        let mut cache = TextureCache::default();

        assert!(cache.needs_reallocate(1280, 720, RenderPixelFormat::Bgra32));

        cache.record_allocation(1280, 720, RenderPixelFormat::Bgra32);

        assert!(!cache.needs_reallocate(1280, 720, RenderPixelFormat::Bgra32));
        assert!(cache.needs_reallocate(1280, 720, RenderPixelFormat::Rgb24));
        assert!(cache.needs_reallocate(1920, 1080, RenderPixelFormat::Bgra32));
    }

    #[test]
    fn texture_cache_tracks_parameter_setup() {
        let mut cache = TextureCache::default();

        assert!(cache.needs_parameter_setup());

        cache.record_parameters_configured();

        assert!(!cache.needs_parameter_setup());
        cache.record_allocation(1280, 720, RenderPixelFormat::Bgra32);
        assert!(!cache.needs_parameter_setup());
    }

    #[test]
    fn upload_rejects_truncated_cpu_frame() {
        let mut renderer = OpenglRenderer::new();
        let error = renderer
            .upload_frame(RenderFrame::from_bgra32(2, 2, vec![0; 7]))
            .expect_err("truncated BGRA frame should fail");

        assert!(error.to_string().contains("byte length mismatch"));
        assert_eq!(renderer.snapshot().uploaded_frame_count, 0);
    }

    #[cfg(windows)]
    #[test]
    fn upload_accepts_d3d11_shared_texture_input_for_hybrid_path() {
        let mut renderer = OpenglRenderer::new();

        renderer
            .upload_frame(RenderFrame::from_d3d11_shared_nv12(1920, 1080, 1, 2))
            .expect("headless hybrid path should accept shared texture metadata");

        let snapshot = renderer.snapshot();
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(
            snapshot.last_pixel_format,
            Some(RenderPixelFormat::D3D11SharedNv12)
        );
    }

    #[cfg(windows)]
    #[test]
    fn hybrid_opengl_renderer_exposes_d3d11_device_pointer() {
        let renderer = OpenglRenderer::new_hybrid().expect("hybrid OpenGL renderer");

        assert_ne!(renderer.d3d11_device_ptr(), None);
    }

    #[cfg(windows)]
    #[test]
    fn shared_texture_path_prefers_wgl_dx_interop_when_available() {
        assert_eq!(
            choose_shared_texture_path(true, true),
            SharedTexturePath::WglDxInterop
        );
        assert_eq!(
            choose_shared_texture_path(true, false),
            SharedTexturePath::ReadbackFallback
        );
        assert_eq!(
            choose_shared_texture_path(false, true),
            SharedTexturePath::MetadataOnly
        );
    }

    #[cfg(windows)]
    #[test]
    fn nv12_shader_samples_y_and_uv_planes_on_gpu() {
        let fragment = NV12_FRAGMENT_SHADER;

        assert!(fragment.contains("uniform sampler2D y_tex"));
        assert!(fragment.contains("uniform sampler2D uv_tex"));
        assert!(fragment.contains("texture2D(y_tex"));
        assert!(fragment.contains("texture2D(uv_tex"));
        assert!(fragment.contains("gl_FragColor"));
    }

    #[cfg(windows)]
    #[test]
    fn interop_nv12_key_tracks_handles_and_dimensions() {
        let frame = RenderFrame::from_d3d11_shared_nv12(1920, 1080, 11, 22);
        let key = InteropNv12Key::from_frame(&frame).expect("NV12 key");

        assert_eq!(
            key,
            InteropNv12Key {
                y_handle: 11,
                uv_handle: 22,
                width: 1920,
                height: 1080,
            }
        );
        assert_eq!(
            InteropNv12Key::from_frame(&RenderFrame::from_rgb24(1, 1, vec![0; 3])),
            None
        );
    }
}
#[cfg(all(test, windows))]
mod readback_fallback_policy_tests {
    use super::allow_shared_texture_readback_fallback;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn readback_fallback_is_disabled_unless_explicitly_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("MRD_OPENGL_ALLOW_READBACK_FALLBACK");
        }
        assert!(!allow_shared_texture_readback_fallback());

        unsafe {
            std::env::set_var("MRD_OPENGL_ALLOW_READBACK_FALLBACK", "1");
        }
        assert!(allow_shared_texture_readback_fallback());

        unsafe {
            std::env::set_var("MRD_OPENGL_ALLOW_READBACK_FALLBACK", "false");
        }
        assert!(!allow_shared_texture_readback_fallback());
        unsafe {
            std::env::remove_var("MRD_OPENGL_ALLOW_READBACK_FALLBACK");
        }
    }
}
