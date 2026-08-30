#![allow(unexpected_cfgs)]

#[cfg(target_os = "macos")]
use metal::foreign_types::ForeignType;
use mrd_render::{
    BoxedRenderer, RenderError, RenderPixelFormat, RendererDescriptor, RendererFactory,
    RuntimeStatus,
};
#[cfg(target_os = "macos")]
use mrd_render::{RenderFrame, RenderFrameData, RenderTarget, RendererInstance, RendererSnapshot};
#[cfg(target_os = "macos")]
use std::{
    collections::VecDeque,
    ffi::c_void,
    ptr::NonNull,
    sync::Arc,
    time::{Duration, Instant},
};

const MACOS_SUPPORTED_FORMATS: &[RenderPixelFormat] = &[
    RenderPixelFormat::Rgb24,
    RenderPixelFormat::Bgra32,
    RenderPixelFormat::Nv12,
];
#[cfg(target_os = "macos")]
const MACOS_LAYER_GEOMETRY_SYNC_INTERVAL: Duration = Duration::from_millis(500);
#[cfg(target_os = "macos")]
const MACOS_LAYER_GEOMETRY_SYNC_INTERVAL_MS_ENV: &str = "MRD_MACOS_METAL_GEOMETRY_SYNC_INTERVAL_MS";
#[cfg(target_os = "macos")]
const MACOS_METAL_DISPLAY_SYNC_ENV: &str = "MRD_MACOS_METAL_DISPLAY_SYNC";
#[cfg(target_os = "macos")]
const MACOS_METAL_MAX_DRAWABLE_COUNT_ENV: &str = "MRD_MACOS_METAL_MAX_DRAWABLE_COUNT";
#[cfg(target_os = "macos")]
const MACOS_METAL_NV12_BUFFER_UPLOAD_ENV: &str = "MRD_MACOS_METAL_NV12_BUFFER_UPLOAD";
#[cfg(target_os = "macos")]
const MACOS_METAL_INVALIDATE_VIEW_ON_GEOMETRY_SYNC_ENV: &str =
    "MRD_MACOS_METAL_INVALIDATE_VIEW_ON_GEOMETRY_SYNC";
#[cfg(target_os = "macos")]
const MACOS_METAL_STATIC_FULLSCREEN_GEOMETRY_ENV: &str =
    "MRD_MACOS_METAL_STATIC_FULLSCREEN_GEOMETRY";
#[cfg(target_os = "macos")]
const MACOS_METAL_RETAINED_BUFFER_FRAMES: usize = 8;
#[cfg(target_os = "macos")]
const MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT: u32 = 3;

pub struct MacosRendererFactory;

impl RendererFactory for MacosRendererFactory {
    fn descriptor(&self) -> RendererDescriptor {
        RendererDescriptor {
            id: "metal",
            runtime_status: RuntimeStatus::RuntimeBacked,
            supported_formats: MACOS_SUPPORTED_FORMATS,
        }
    }

    fn create(&self) -> Result<BoxedRenderer, RenderError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Box::new(MacosMetalRenderer::new()?))
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(RenderError::Message(
                "Metal renderer is only available on macOS".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub struct MacosMetalRenderer {
    device: metal::Device,
    command_queue: metal::CommandQueue,
    bgra_pipeline_state: metal::RenderPipelineState,
    nv12_pipeline_state: metal::RenderPipelineState,
    nv12_buffer_pipeline_state: metal::RenderPipelineState,
    cv_metal_texture_cache: Option<MacosRetainedCfType>,
    layer: Option<metal::MetalLayer>,
    target_ns_view: Option<isize>,
    texture: Option<metal::Texture>,
    texture_width: usize,
    texture_height: usize,
    nv12_y_texture: Option<metal::Texture>,
    nv12_uv_texture: Option<metal::Texture>,
    nv12_width: usize,
    nv12_height: usize,
    retained_nv12_buffers: VecDeque<MacosNv12BufferSource>,
    retained_cv_pixel_buffers: VecDeque<MacosCvPixelBufferSource>,
    h264_pixel_buffer_decoder: Option<mrd_codec_videotoolbox::VideoToolboxH264PixelBufferDecoder>,
    hevc_pixel_buffer_decoder: Option<mrd_codec_videotoolbox::VideoToolboxHevcPixelBufferDecoder>,
    active_source: Option<MacosTextureSource>,
    scratch_bgra: Vec<u8>,
    attached_to_target: bool,
    drawable_width: usize,
    drawable_height: usize,
    last_geometry_sync_at: Option<Instant>,
    uploaded_frame_count: u64,
    presented_frame_count: u64,
    present_skipped_count: u64,
    last_present_status: Option<String>,
    last_render_wait_for_drawable_ms: Option<f64>,
    last_render_encode_commit_ms: Option<f64>,
    last_render_draw_present_ms: Option<f64>,
    last_width: usize,
    last_height: usize,
    last_pixel_format: Option<RenderPixelFormat>,
    display_sync_enabled: bool,
    max_drawable_count: u32,
    static_fullscreen_geometry: bool,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
enum MacosTextureSource {
    Bgra,
    Nv12,
    Nv12Buffer(MacosNv12BufferSource),
    CvPixelBufferNv12(MacosCvPixelBufferSource),
}

#[cfg(target_os = "macos")]
enum MacosPresentSource {
    Bgra(metal::Texture),
    Nv12 {
        y_texture: metal::Texture,
        uv_texture: metal::Texture,
    },
    Nv12Buffer(MacosNv12BufferSource),
    CvPixelBufferNv12(MacosCvPixelBufferSource),
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Nv12PlaneLayout {
    y_bytes: usize,
    uv_width: usize,
    uv_height: usize,
    expected_len: usize,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct MacosNv12BufferSource {
    buffer: metal::Buffer,
    data: Arc<Vec<u8>>,
    width: usize,
    height: usize,
    pitch: usize,
    uv_offset: usize,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct MacosCvPixelBufferSource {
    pixel_buffer: MacosRetainedCfType,
    y_cv_texture: MacosRetainedCfType,
    uv_cv_texture: MacosRetainedCfType,
    y_texture: metal::Texture,
    uv_texture: metal::Texture,
    width: usize,
    height: usize,
}

#[cfg(target_os = "macos")]
struct MacosRetainedCfType {
    ptr: NonNull<c_void>,
}

#[cfg(target_os = "macos")]
impl MacosRetainedCfType {
    unsafe fn retain(ptr: *mut c_void, label: &str) -> Result<Self, RenderError> {
        let ptr = NonNull::new(ptr)
            .ok_or_else(|| RenderError::Message(format!("{label} pointer is null")))?;
        unsafe {
            CFRetain(ptr.as_ptr().cast_const());
        }
        Ok(Self { ptr })
    }

    unsafe fn wrap_create_rule(ptr: *mut c_void, label: &str) -> Result<Self, RenderError> {
        let ptr = NonNull::new(ptr)
            .ok_or_else(|| RenderError::Message(format!("{label} pointer is null")))?;
        Ok(Self { ptr })
    }

    fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}

#[cfg(target_os = "macos")]
impl Clone for MacosRetainedCfType {
    fn clone(&self) -> Self {
        unsafe {
            CFRetain(self.ptr.as_ptr().cast_const());
        }
        Self { ptr: self.ptr }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosRetainedCfType {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.ptr.as_ptr().cast_const());
        }
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Nv12BufferUniforms {
    width: u32,
    height: u32,
    pitch: u32,
    uv_offset: u32,
}

#[cfg(target_os = "macos")]
unsafe impl Send for MacosMetalRenderer {}

#[cfg(target_os = "macos")]
impl MacosMetalRenderer {
    pub fn new() -> Result<Self, RenderError> {
        let device = metal::Device::system_default()
            .ok_or_else(|| RenderError::Message("Metal device is not available".to_string()))?;
        let command_queue = device.new_command_queue();
        let bgra_pipeline_state = create_fullscreen_pipeline(&device, "fragment_bgra")?;
        let nv12_pipeline_state = create_fullscreen_pipeline(&device, "fragment_nv12")?;
        let nv12_buffer_pipeline_state =
            create_fullscreen_pipeline(&device, "fragment_nv12_buffer")?;

        Ok(Self {
            device,
            command_queue,
            bgra_pipeline_state,
            nv12_pipeline_state,
            nv12_buffer_pipeline_state,
            cv_metal_texture_cache: None,
            layer: None,
            target_ns_view: None,
            texture: None,
            texture_width: 0,
            texture_height: 0,
            nv12_y_texture: None,
            nv12_uv_texture: None,
            nv12_width: 0,
            nv12_height: 0,
            retained_nv12_buffers: VecDeque::new(),
            retained_cv_pixel_buffers: VecDeque::new(),
            h264_pixel_buffer_decoder: None,
            hevc_pixel_buffer_decoder: None,
            active_source: None,
            scratch_bgra: Vec::new(),
            attached_to_target: false,
            drawable_width: 0,
            drawable_height: 0,
            last_geometry_sync_at: None,
            uploaded_frame_count: 0,
            presented_frame_count: 0,
            present_skipped_count: 0,
            last_present_status: None,
            last_render_wait_for_drawable_ms: None,
            last_render_encode_commit_ms: None,
            last_render_draw_present_ms: None,
            last_width: 0,
            last_height: 0,
            last_pixel_format: None,
            display_sync_enabled: true,
            max_drawable_count: MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT,
            static_fullscreen_geometry: false,
        })
    }

    fn ensure_texture(&mut self, width: usize, height: usize) {
        if self.texture.is_some() && self.texture_width == width && self.texture_height == height {
            return;
        }

        let descriptor = metal::TextureDescriptor::new();
        descriptor.set_texture_type(metal::MTLTextureType::D2);
        descriptor.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
        descriptor.set_width(width as u64);
        descriptor.set_height(height as u64);
        descriptor.set_storage_mode(metal::MTLStorageMode::Shared);
        descriptor.set_usage(metal::MTLTextureUsage::ShaderRead);

        self.texture = Some(self.device.new_texture(&descriptor));
        self.texture_width = width;
        self.texture_height = height;
    }

    fn ensure_nv12_textures(&mut self, width: usize, height: usize) {
        if self.nv12_y_texture.is_some()
            && self.nv12_uv_texture.is_some()
            && self.nv12_width == width
            && self.nv12_height == height
        {
            return;
        }

        let y_descriptor = metal::TextureDescriptor::new();
        y_descriptor.set_texture_type(metal::MTLTextureType::D2);
        y_descriptor.set_pixel_format(metal::MTLPixelFormat::R8Unorm);
        y_descriptor.set_width(width as u64);
        y_descriptor.set_height(height as u64);
        y_descriptor.set_storage_mode(metal::MTLStorageMode::Shared);
        y_descriptor.set_usage(metal::MTLTextureUsage::ShaderRead);

        let uv_descriptor = metal::TextureDescriptor::new();
        uv_descriptor.set_texture_type(metal::MTLTextureType::D2);
        uv_descriptor.set_pixel_format(metal::MTLPixelFormat::RG8Unorm);
        uv_descriptor.set_width(width.div_ceil(2) as u64);
        uv_descriptor.set_height(height.div_ceil(2) as u64);
        uv_descriptor.set_storage_mode(metal::MTLStorageMode::Shared);
        uv_descriptor.set_usage(metal::MTLTextureUsage::ShaderRead);

        self.nv12_y_texture = Some(self.device.new_texture(&y_descriptor));
        self.nv12_uv_texture = Some(self.device.new_texture(&uv_descriptor));
        self.nv12_width = width;
        self.nv12_height = height;
    }

    fn upload_bgra(&mut self, width: usize, height: usize, data: &[u8]) -> Result<(), RenderError> {
        let expected = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| RenderError::Message("Metal frame size overflow".to_string()))?;
        if data.len() != expected {
            return Err(RenderError::Message(format!(
                "Metal BGRA frame bytes mismatch: expected {expected}, got {}",
                data.len()
            )));
        }

        self.ensure_texture(width, height);
        let upload_data = if bgra_contains_non_opaque_alpha(data) {
            if self.scratch_bgra.len() != expected {
                self.scratch_bgra.resize(expected, 0);
            }
            for (src, dst) in data
                .as_chunks::<4>()
                .0
                .iter()
                .zip(self.scratch_bgra.as_chunks_mut::<4>().0.iter_mut())
            {
                dst[0] = src[0];
                dst[1] = src[1];
                dst[2] = src[2];
                dst[3] = 255;
            }
            self.scratch_bgra.as_slice()
        } else {
            data
        };
        let texture = self
            .texture
            .as_ref()
            .ok_or_else(|| RenderError::Message("Metal texture was not created".to_string()))?;
        let region = metal::MTLRegion::new_2d(0, 0, width as u64, height as u64);
        texture.replace_region(region, 0, upload_data.as_ptr().cast(), (width * 4) as u64);
        self.active_source = Some(MacosTextureSource::Bgra);
        Ok(())
    }

    fn upload_nv12(
        &mut self,
        width: usize,
        height: usize,
        data: &[u8],
        pitch: usize,
    ) -> Result<(), RenderError> {
        let layout = nv12_plane_layout(width, height, pitch)?;
        if data.len() < layout.expected_len {
            return Err(RenderError::Message(format!(
                "Metal NV12 frame bytes mismatch: expected at least {}, got {}",
                layout.expected_len,
                data.len()
            )));
        }

        self.ensure_nv12_textures(width, height);
        let y_texture = self
            .nv12_y_texture
            .as_ref()
            .ok_or_else(|| RenderError::Message("Metal NV12 Y texture was not created".into()))?;
        let uv_texture = self.nv12_uv_texture.as_ref().ok_or_else(|| {
            RenderError::Message("Metal NV12 UV texture was not created".to_string())
        })?;

        let y_region = metal::MTLRegion::new_2d(0, 0, width as u64, height as u64);
        y_texture.replace_region(y_region, 0, data.as_ptr().cast(), pitch as u64);

        let uv_region =
            metal::MTLRegion::new_2d(0, 0, layout.uv_width as u64, layout.uv_height as u64);
        let uv_data = &data[layout.y_bytes..];
        uv_texture.replace_region(uv_region, 0, uv_data.as_ptr().cast(), pitch as u64);

        self.active_source = Some(MacosTextureSource::Nv12);
        Ok(())
    }

    fn upload_nv12_buffer(
        &mut self,
        width: usize,
        height: usize,
        data: Vec<u8>,
        pitch: usize,
    ) -> Result<(), RenderError> {
        let layout = nv12_plane_layout(width, height, pitch)?;
        if data.len() < layout.expected_len {
            return Err(RenderError::Message(format!(
                "Metal NV12 buffer bytes mismatch: expected at least {}, got {}",
                layout.expected_len,
                data.len()
            )));
        }
        let data = Arc::new(data);
        let buffer = self.device.new_buffer_with_bytes_no_copy(
            data.as_ptr().cast(),
            data.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
            None,
        );
        let source = MacosNv12BufferSource {
            buffer,
            data,
            width,
            height,
            pitch,
            uv_offset: layout.y_bytes,
        };
        self.active_source = Some(MacosTextureSource::Nv12Buffer(source.clone()));
        self.retained_nv12_buffers.push_back(source);
        while self.retained_nv12_buffers.len() > MACOS_METAL_RETAINED_BUFFER_FRAMES {
            self.retained_nv12_buffers.pop_front();
        }
        Ok(())
    }

    fn upload_h264_pixel_buffer_access_unit(
        &mut self,
        access_unit: &[u8],
    ) -> Result<(), RenderError> {
        if self.h264_pixel_buffer_decoder.is_none() {
            let decoder = mrd_codec_videotoolbox::VideoToolboxH264PixelBufferDecoder::new()
                .map_err(|error| {
                    RenderError::Message(format!(
                        "create VideoToolbox CVPixelBuffer H.264 decoder failed: {error}"
                    ))
                })?;
            self.h264_pixel_buffer_decoder = Some(decoder);
        }
        let decoded_frames = {
            let decoder = self.h264_pixel_buffer_decoder.as_mut().ok_or_else(|| {
                RenderError::Message("VideoToolbox CVPixelBuffer H.264 decoder missing".to_string())
            })?;
            match decoder.push_access_unit(access_unit) {
                Ok(()) => decoder.drain_decoded_frames(),
                Err(error) => {
                    self.h264_pixel_buffer_decoder = None;
                    return Err(RenderError::Message(format!(
                        "VideoToolbox CVPixelBuffer H.264 decode failed: {error}"
                    )));
                }
            }
        };
        self.upload_decoded_pixel_buffer_frames(decoded_frames)
    }

    fn upload_hevc_pixel_buffer_access_unit(
        &mut self,
        access_unit: &[u8],
    ) -> Result<(), RenderError> {
        if self.hevc_pixel_buffer_decoder.is_none() {
            let decoder = mrd_codec_videotoolbox::VideoToolboxHevcPixelBufferDecoder::new()
                .map_err(|error| {
                    RenderError::Message(format!(
                        "create VideoToolbox CVPixelBuffer HEVC decoder failed: {error}"
                    ))
                })?;
            self.hevc_pixel_buffer_decoder = Some(decoder);
        }
        let decoded_frames = {
            let decoder = self.hevc_pixel_buffer_decoder.as_mut().ok_or_else(|| {
                RenderError::Message("VideoToolbox CVPixelBuffer HEVC decoder missing".to_string())
            })?;
            match decoder.push_access_unit(access_unit) {
                Ok(()) => decoder.drain_decoded_frames(),
                Err(error) => {
                    self.hevc_pixel_buffer_decoder = None;
                    return Err(RenderError::Message(format!(
                        "VideoToolbox CVPixelBuffer HEVC decode failed: {error}"
                    )));
                }
            }
        };
        self.upload_decoded_pixel_buffer_frames(decoded_frames)
    }

    fn upload_decoded_pixel_buffer_frames(
        &mut self,
        decoded_frames: Vec<mrd_codec_videotoolbox::VideoToolboxPixelBufferFrame>,
    ) -> Result<(), RenderError> {
        for decoded_frame in decoded_frames {
            unsafe {
                self.upload_cv_pixel_buffer_nv12(
                    decoded_frame.width(),
                    decoded_frame.height(),
                    decoded_frame.pixel_buffer_ptr(),
                )?;
            }
        }
        Ok(())
    }

    /// Upload an NV12 `CVPixelBufferRef` by creating Metal textures backed by
    /// the pixel buffer planes. The pointer must be a valid Core Video pixel
    /// buffer for the duration of the call; the renderer retains it before
    /// returning.
    ///
    /// # Safety
    ///
    /// `pixel_buffer` must point to a live NV12-compatible `CVPixelBufferRef`.
    /// Passing any other pointer is undefined behavior in Core Video.
    pub unsafe fn upload_cv_pixel_buffer_nv12(
        &mut self,
        width: usize,
        height: usize,
        pixel_buffer: *mut c_void,
    ) -> Result<(), RenderError> {
        let source = unsafe { self.cv_pixel_buffer_nv12_source(width, height, pixel_buffer)? };
        self.active_source = Some(MacosTextureSource::CvPixelBufferNv12(source.clone()));
        self.retained_cv_pixel_buffers.push_back(source);
        while self.retained_cv_pixel_buffers.len() > MACOS_METAL_RETAINED_BUFFER_FRAMES {
            self.retained_cv_pixel_buffers.pop_front();
        }
        self.uploaded_frame_count = self.uploaded_frame_count.saturating_add(1);
        self.last_width = width;
        self.last_height = height;
        self.last_pixel_format = Some(RenderPixelFormat::Nv12);
        self.present_if_attached(width, height);
        Ok(())
    }

    unsafe fn cv_pixel_buffer_nv12_source(
        &mut self,
        width: usize,
        height: usize,
        pixel_buffer: *mut c_void,
    ) -> Result<MacosCvPixelBufferSource, RenderError> {
        if width == 0 || height == 0 {
            return Err(RenderError::Message(
                "Metal CVPixelBuffer dimensions must be non-zero".to_string(),
            ));
        }
        let pixel_buffer = unsafe { MacosRetainedCfType::retain(pixel_buffer, "CVPixelBuffer")? };
        let cache = self.cv_metal_texture_cache()?;
        let y_cv_texture = unsafe {
            create_cv_metal_texture(
                &cache,
                &pixel_buffer,
                metal::MTLPixelFormat::R8Unorm,
                width,
                height,
                0,
            )?
        };
        let uv_cv_texture = unsafe {
            create_cv_metal_texture(
                &cache,
                &pixel_buffer,
                metal::MTLPixelFormat::RG8Unorm,
                width.div_ceil(2),
                height.div_ceil(2),
                1,
            )?
        };
        let y_texture = unsafe { metal_texture_from_cv_texture(&y_cv_texture, "Y")? };
        let uv_texture = unsafe { metal_texture_from_cv_texture(&uv_cv_texture, "UV")? };
        Ok(MacosCvPixelBufferSource {
            pixel_buffer,
            y_cv_texture,
            uv_cv_texture,
            y_texture,
            uv_texture,
            width,
            height,
        })
    }

    fn cv_metal_texture_cache(&mut self) -> Result<MacosRetainedCfType, RenderError> {
        if let Some(cache) = self.cv_metal_texture_cache.as_ref() {
            return Ok(cache.clone());
        }
        let mut cache: *mut c_void = std::ptr::null_mut();
        let status = unsafe {
            CVMetalTextureCacheCreate(
                std::ptr::null(),
                std::ptr::null(),
                self.device.as_ptr().cast(),
                std::ptr::null(),
                &mut cache,
            )
        };
        if status != 0 {
            return Err(RenderError::Message(format!(
                "CVMetalTextureCacheCreate failed: status={status}"
            )));
        }
        let cache = unsafe { MacosRetainedCfType::wrap_create_rule(cache, "CVMetalTextureCache")? };
        self.cv_metal_texture_cache = Some(cache.clone());
        Ok(cache)
    }

    pub fn attach_target_with_max_drawable_count(
        &mut self,
        target: RenderTarget,
        max_drawable_count: u32,
    ) -> Result<(), RenderError> {
        let RenderTarget::WindowHandle(window_handle) = target;
        self.attach_ns_view_with_max_drawable_count(
            window_handle,
            macos_metal_sanitize_max_drawable_count(max_drawable_count),
        )?;
        self.attached_to_target = self.layer.is_some();
        Ok(())
    }

    fn attach_ns_view(&mut self, ns_view: isize) -> Result<(), RenderError> {
        self.attach_ns_view_with_max_drawable_count(ns_view, macos_metal_max_drawable_count())
    }

    fn attach_ns_view_with_max_drawable_count(
        &mut self,
        ns_view: isize,
        max_drawable_count: u32,
    ) -> Result<(), RenderError> {
        if ns_view == 0 {
            return Err(RenderError::Message(
                "Metal renderer requires a non-null NSView render target".to_string(),
            ));
        }

        let device = self.device.clone();
        let display_sync_enabled = macos_metal_display_sync_enabled();
        let (layer, drawable_width, drawable_height, static_fullscreen_geometry) =
            run_on_main_thread_sync(move || unsafe {
                use objc::runtime::Object;

                let mut layer = metal::MetalLayer::new();
                let invalidate_view_on_geometry_sync =
                    macos_metal_invalidate_view_on_geometry_sync_enabled();
                layer.set_device(&device);
                layer.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
                layer.set_presents_with_transaction(false);
                layer.set_framebuffer_only(false);
                layer.set_display_sync_enabled(display_sync_enabled);
                layer.set_maximum_drawable_count(max_drawable_count as u64);
                layer.set_masks_to_bounds(true);
                layer.set_opaque(true);
                layer.remove_all_animations();

                let layer_object = layer.as_mut() as *mut _ as *mut Object as usize;
                let (drawable_width, drawable_height) = sync_layer_geometry_on_main(
                    layer_object,
                    ns_view,
                    true,
                    invalidate_view_on_geometry_sync,
                )?;
                layer.set_drawable_size(core_graphics_types::geometry::CGSize::new(
                    drawable_width as f64,
                    drawable_height as f64,
                ));
                let static_fullscreen_geometry =
                    macos_view_uses_static_fullscreen_geometry(ns_view);
                Ok((
                    layer,
                    drawable_width,
                    drawable_height,
                    static_fullscreen_geometry,
                ))
            })
            .map_err(RenderError::Message)?;

        self.layer = Some(layer);
        self.target_ns_view = Some(ns_view);
        self.drawable_width = drawable_width;
        self.drawable_height = drawable_height;
        self.last_geometry_sync_at = Some(Instant::now());
        self.display_sync_enabled = display_sync_enabled;
        self.max_drawable_count = max_drawable_count;
        self.static_fullscreen_geometry = static_fullscreen_geometry;
        Ok(())
    }

    fn present_if_attached(&mut self, width: usize, height: usize) {
        objc::rc::autoreleasepool(|| self.present_if_attached_inner(width, height));
    }

    fn present_if_attached_inner(&mut self, width: usize, height: usize) {
        let source = match self.active_source.clone() {
            Some(MacosTextureSource::Bgra) => {
                let Some(texture) = self.texture.as_ref().cloned() else {
                    return;
                };
                MacosPresentSource::Bgra(texture)
            }
            Some(MacosTextureSource::Nv12) => {
                let Some(y_texture) = self.nv12_y_texture.as_ref().cloned() else {
                    return;
                };
                let Some(uv_texture) = self.nv12_uv_texture.as_ref().cloned() else {
                    return;
                };
                MacosPresentSource::Nv12 {
                    y_texture,
                    uv_texture,
                }
            }
            Some(MacosTextureSource::Nv12Buffer(source)) => MacosPresentSource::Nv12Buffer(source),
            Some(MacosTextureSource::CvPixelBufferNv12(source)) => {
                MacosPresentSource::CvPixelBufferNv12(source)
            }
            None => return,
        };
        let Some(layer) = self.layer.as_ref().cloned() else {
            return;
        };
        let present_started = Instant::now();
        self.last_render_wait_for_drawable_ms = None;
        self.last_render_encode_commit_ms = None;

        self.sync_layer_geometry_if_due(&layer, present_started);

        let next_drawable_started = Instant::now();
        let drawable = layer.next_drawable();
        self.last_render_wait_for_drawable_ms =
            Some(next_drawable_started.elapsed().as_secs_f64() * 1000.0);
        let Some(drawable) = drawable else {
            self.present_skipped_count = self.present_skipped_count.saturating_add(1);
            self.last_present_status = Some("no_drawable".to_string());
            self.last_render_draw_present_ms =
                Some(present_started.elapsed().as_secs_f64() * 1000.0);
            return;
        };
        let drawable_texture = drawable.texture();
        let dst_width = drawable_texture.width() as usize;
        let dst_height = drawable_texture.height() as usize;
        let Some((copy_width, copy_height)) =
            copy_region_size(width, height, dst_width, dst_height)
        else {
            self.present_skipped_count = self.present_skipped_count.saturating_add(1);
            self.last_present_status = Some("empty_drawable".to_string());
            self.last_render_draw_present_ms =
                Some(present_started.elapsed().as_secs_f64() * 1000.0);
            return;
        };

        let encode_commit_started = Instant::now();
        let command_buffer = self.command_queue.new_command_buffer();
        match source {
            MacosPresentSource::Bgra(texture) => draw_bgra_fullscreen(
                &command_buffer,
                &self.bgra_pipeline_state,
                &texture,
                drawable_texture,
                copy_width,
                copy_height,
            ),
            MacosPresentSource::Nv12 {
                y_texture,
                uv_texture,
            } => draw_nv12_fullscreen(
                &command_buffer,
                &self.nv12_pipeline_state,
                &y_texture,
                &uv_texture,
                drawable_texture,
                copy_width,
                copy_height,
            ),
            MacosPresentSource::Nv12Buffer(source) => draw_nv12_buffer_fullscreen(
                &command_buffer,
                &self.nv12_buffer_pipeline_state,
                &source,
                drawable_texture,
                copy_width,
                copy_height,
            ),
            MacosPresentSource::CvPixelBufferNv12(source) => {
                let _keep_core_video_refs_alive = (
                    &source.pixel_buffer,
                    &source.y_cv_texture,
                    &source.uv_cv_texture,
                    source.width,
                    source.height,
                );
                draw_nv12_fullscreen(
                    &command_buffer,
                    &self.nv12_pipeline_state,
                    &source.y_texture,
                    &source.uv_texture,
                    drawable_texture,
                    copy_width,
                    copy_height,
                )
            }
        }
        command_buffer.present_drawable(drawable);
        command_buffer.commit();
        self.last_render_encode_commit_ms =
            Some(encode_commit_started.elapsed().as_secs_f64() * 1000.0);
        self.presented_frame_count = self.presented_frame_count.saturating_add(1);
        self.last_present_status = Some("presented".to_string());
        self.last_render_draw_present_ms = Some(present_started.elapsed().as_secs_f64() * 1000.0);
    }

    fn sync_layer_geometry_if_due(&mut self, layer: &metal::MetalLayer, now: Instant) {
        if self.static_fullscreen_geometry && macos_metal_static_fullscreen_geometry_enabled() {
            return;
        }
        let Some(sync_interval) = macos_layer_geometry_sync_interval() else {
            return;
        };
        let due = self
            .last_geometry_sync_at
            .map(|last_sync| now.saturating_duration_since(last_sync) >= sync_interval)
            .unwrap_or(true);
        if !due {
            return;
        }

        let Some(ns_view) = self.target_ns_view else {
            return;
        };
        let layer_object = layer.as_ptr() as *mut objc::runtime::Object as usize;
        let layer_for_geometry = layer.clone();
        if let Ok(drawable_size) = run_on_main_thread_sync(move || {
            objc::rc::autoreleasepool(|| {
                let drawable_size = unsafe {
                    sync_layer_geometry_on_main(
                        layer_object,
                        ns_view,
                        false,
                        macos_metal_invalidate_view_on_geometry_sync_enabled(),
                    )?
                };
                layer_for_geometry.set_drawable_size(core_graphics_types::geometry::CGSize::new(
                    drawable_size.0 as f64,
                    drawable_size.1 as f64,
                ));
                Ok(drawable_size)
            })
        }) {
            self.drawable_width = drawable_size.0;
            self.drawable_height = drawable_size.1;
            self.last_geometry_sync_at = Some(now);
        }
    }
}

#[cfg(target_os = "macos")]
fn create_fullscreen_pipeline(
    device: &metal::Device,
    fragment_name: &str,
) -> Result<metal::RenderPipelineState, RenderError> {
    let library = device
        .new_library_with_source(METAL_FULLSCREEN_SHADER, &metal::CompileOptions::new())
        .map_err(|error| {
            RenderError::Message(format!("compile Metal display shader failed: {error}"))
        })?;
    let vertex = library.get_function("vertex_main", None).map_err(|error| {
        RenderError::Message(format!("load Metal vertex shader failed: {error}"))
    })?;
    let fragment = library.get_function(fragment_name, None).map_err(|error| {
        RenderError::Message(format!("load Metal fragment shader failed: {error}"))
    })?;
    let descriptor = metal::RenderPipelineDescriptor::new();
    descriptor.set_vertex_function(Some(&vertex));
    descriptor.set_fragment_function(Some(&fragment));
    descriptor
        .color_attachments()
        .object_at(0)
        .ok_or_else(|| RenderError::Message("Metal pipeline missing color attachment 0".into()))?
        .set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
    device
        .new_render_pipeline_state(&descriptor)
        .map_err(|error| {
            RenderError::Message(format!("create Metal display pipeline failed: {error}"))
        })
}

#[cfg(target_os = "macos")]
fn draw_bgra_fullscreen(
    command_buffer: &metal::CommandBufferRef,
    pipeline_state: &metal::RenderPipelineStateRef,
    source: &metal::TextureRef,
    target: &metal::TextureRef,
    _copy_width: usize,
    _copy_height: usize,
) {
    let pass = metal::RenderPassDescriptor::new();
    let Some(color) = pass.color_attachments().object_at(0) else {
        return;
    };
    color.set_texture(Some(target));
    color.set_load_action(metal::MTLLoadAction::Clear);
    color.set_store_action(metal::MTLStoreAction::Store);
    color.set_clear_color(metal::MTLClearColor::new(0.0, 0.0, 0.0, 1.0));

    let encoder = command_buffer.new_render_command_encoder(pass);
    encoder.set_render_pipeline_state(pipeline_state);
    encoder.set_fragment_texture(0, Some(source));
    encoder.draw_primitives(metal::MTLPrimitiveType::TriangleStrip, 0, 4);
    encoder.end_encoding();
}

#[cfg(target_os = "macos")]
fn draw_nv12_fullscreen(
    command_buffer: &metal::CommandBufferRef,
    pipeline_state: &metal::RenderPipelineStateRef,
    y_source: &metal::TextureRef,
    uv_source: &metal::TextureRef,
    target: &metal::TextureRef,
    _copy_width: usize,
    _copy_height: usize,
) {
    let pass = metal::RenderPassDescriptor::new();
    let Some(color) = pass.color_attachments().object_at(0) else {
        return;
    };
    color.set_texture(Some(target));
    color.set_load_action(metal::MTLLoadAction::Clear);
    color.set_store_action(metal::MTLStoreAction::Store);
    color.set_clear_color(metal::MTLClearColor::new(0.0, 0.0, 0.0, 1.0));

    let encoder = command_buffer.new_render_command_encoder(pass);
    encoder.set_render_pipeline_state(pipeline_state);
    encoder.set_fragment_texture(0, Some(y_source));
    encoder.set_fragment_texture(1, Some(uv_source));
    encoder.draw_primitives(metal::MTLPrimitiveType::TriangleStrip, 0, 4);
    encoder.end_encoding();
}

#[cfg(target_os = "macos")]
fn draw_nv12_buffer_fullscreen(
    command_buffer: &metal::CommandBufferRef,
    pipeline_state: &metal::RenderPipelineStateRef,
    source: &MacosNv12BufferSource,
    target: &metal::TextureRef,
    _copy_width: usize,
    _copy_height: usize,
) {
    let Ok(uniforms) = nv12_buffer_uniforms(source) else {
        return;
    };
    let pass = metal::RenderPassDescriptor::new();
    let Some(color) = pass.color_attachments().object_at(0) else {
        return;
    };
    color.set_texture(Some(target));
    color.set_load_action(metal::MTLLoadAction::Clear);
    color.set_store_action(metal::MTLStoreAction::Store);
    color.set_clear_color(metal::MTLClearColor::new(0.0, 0.0, 0.0, 1.0));

    let encoder = command_buffer.new_render_command_encoder(pass);
    encoder.set_render_pipeline_state(pipeline_state);
    encoder.set_fragment_buffer(0, Some(&source.buffer), 0);
    encoder.set_fragment_bytes(
        1,
        std::mem::size_of::<Nv12BufferUniforms>() as u64,
        (&uniforms as *const Nv12BufferUniforms).cast(),
    );
    encoder.draw_primitives(metal::MTLPrimitiveType::TriangleStrip, 0, 4);
    encoder.end_encoding();
}

#[cfg(target_os = "macos")]
unsafe fn create_cv_metal_texture(
    cache: &MacosRetainedCfType,
    pixel_buffer: &MacosRetainedCfType,
    pixel_format: metal::MTLPixelFormat,
    width: usize,
    height: usize,
    plane_index: usize,
) -> Result<MacosRetainedCfType, RenderError> {
    let mut cv_texture: *mut c_void = std::ptr::null_mut();
    let status = unsafe {
        CVMetalTextureCacheCreateTextureFromImage(
            std::ptr::null(),
            cache.as_ptr(),
            pixel_buffer.as_ptr(),
            std::ptr::null(),
            pixel_format as u64,
            width,
            height,
            plane_index,
            &mut cv_texture,
        )
    };
    if status != 0 {
        return Err(RenderError::Message(format!(
            "CVMetalTextureCacheCreateTextureFromImage plane {plane_index} failed: status={status}"
        )));
    }
    unsafe { MacosRetainedCfType::wrap_create_rule(cv_texture, "CVMetalTexture") }
}

#[cfg(target_os = "macos")]
unsafe fn metal_texture_from_cv_texture(
    cv_texture: &MacosRetainedCfType,
    label: &str,
) -> Result<metal::Texture, RenderError> {
    use objc::{msg_send, sel, sel_impl};

    let texture = unsafe { CVMetalTextureGetTexture(cv_texture.as_ptr()) };
    let texture = NonNull::new(texture).ok_or_else(|| {
        RenderError::Message(format!(
            "CVMetalTextureGetTexture returned null for {label} plane"
        ))
    })?;
    let texture_object = texture.as_ptr().cast::<objc::runtime::Object>();
    let retained: *mut objc::runtime::Object = unsafe { msg_send![texture_object, retain] };
    let retained = NonNull::new(retained)
        .ok_or_else(|| RenderError::Message(format!("retain MTLTexture {label} failed")))?;
    Ok(unsafe { metal::Texture::from_ptr(retained.as_ptr().cast()) })
}

#[cfg(target_os = "macos")]
fn nv12_buffer_uniforms(source: &MacosNv12BufferSource) -> Result<Nv12BufferUniforms, RenderError> {
    let _retained_bytes = source.data.len();
    Ok(Nv12BufferUniforms {
        width: u32::try_from(source.width)
            .map_err(|_| RenderError::Message("Metal NV12 buffer width overflow".to_string()))?,
        height: u32::try_from(source.height)
            .map_err(|_| RenderError::Message("Metal NV12 buffer height overflow".to_string()))?,
        pitch: u32::try_from(source.pitch)
            .map_err(|_| RenderError::Message("Metal NV12 buffer pitch overflow".to_string()))?,
        uv_offset: u32::try_from(source.uv_offset).map_err(|_| {
            RenderError::Message("Metal NV12 buffer chroma offset overflow".to_string())
        })?,
    })
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRetain(cf: *const c_void) -> *const c_void;
    fn CFRelease(cf: *const c_void);
}

#[cfg(target_os = "macos")]
#[link(name = "CoreVideo", kind = "framework")]
unsafe extern "C" {
    fn CVMetalTextureCacheCreate(
        allocator: *const c_void,
        cache_attributes: *const c_void,
        metal_device: *mut c_void,
        texture_attributes: *const c_void,
        cache_out: *mut *mut c_void,
    ) -> i32;

    fn CVMetalTextureCacheCreateTextureFromImage(
        allocator: *const c_void,
        texture_cache: *mut c_void,
        source_image: *mut c_void,
        texture_attributes: *const c_void,
        pixel_format: u64,
        width: usize,
        height: usize,
        plane_index: usize,
        texture_out: *mut *mut c_void,
    ) -> i32;

    fn CVMetalTextureGetTexture(image: *mut c_void) -> *mut c_void;
}

#[cfg(target_os = "macos")]
const METAL_FULLSCREEN_SHADER: &str = r#"
#include <metal_stdlib>
using namespace metal;

struct VertexOut {
    float4 position [[position]];
    float2 tex_coord;
};

vertex VertexOut vertex_main(uint vertex_id [[vertex_id]]) {
    constexpr float2 positions[4] = {
        float2(-1.0, -1.0),
        float2( 1.0, -1.0),
        float2(-1.0,  1.0),
        float2( 1.0,  1.0),
    };
    constexpr float2 tex_coords[4] = {
        float2(0.0, 1.0),
        float2(1.0, 1.0),
        float2(0.0, 0.0),
        float2(1.0, 0.0),
    };
    VertexOut out;
    out.position = float4(positions[vertex_id], 0.0, 1.0);
    out.tex_coord = tex_coords[vertex_id];
    return out;
}

fragment half4 fragment_bgra(VertexOut in [[stage_in]], texture2d<half> frame [[texture(0)]]) {
    constexpr sampler frame_sampler(coord::normalized, address::clamp_to_edge, filter::linear);
    return frame.sample(frame_sampler, in.tex_coord);
}

fragment half4 fragment_nv12(
    VertexOut in [[stage_in]],
    texture2d<float> y_texture [[texture(0)]],
    texture2d<float> uv_texture [[texture(1)]]
) {
    constexpr sampler frame_sampler(coord::normalized, address::clamp_to_edge, filter::linear);
    float y = y_texture.sample(frame_sampler, in.tex_coord).r * 255.0;
    float2 uv = uv_texture.sample(frame_sampler, in.tex_coord).rg * 255.0;
    float c = max(y - 16.0, 0.0);
    float d = uv.x - 128.0;
    float e = uv.y - 128.0;
    float3 rgb = float3(
        (298.0 * c + 409.0 * e + 128.0) / 65280.0,
        (298.0 * c - 100.0 * d - 208.0 * e + 128.0) / 65280.0,
        (298.0 * c + 516.0 * d + 128.0) / 65280.0
    );
    rgb = clamp(rgb, float3(0.0), float3(1.0));
    return half4(half(rgb.r), half(rgb.g), half(rgb.b), half(1.0));
}

struct Nv12BufferUniforms {
    uint width;
    uint height;
    uint pitch;
    uint uv_offset;
};

fragment half4 fragment_nv12_buffer(
    VertexOut in [[stage_in]],
    const device uchar* nv12 [[buffer(0)]],
    constant Nv12BufferUniforms& params [[buffer(1)]]
) {
    uint x = min(uint(floor(in.tex_coord.x * float(params.width))), params.width - 1);
    uint y_index = min(uint(floor(in.tex_coord.y * float(params.height))), params.height - 1);
    uint uv_x = (x / 2) * 2;
    uint uv_y = y_index / 2;
    float y = float(nv12[y_index * params.pitch + x]);
    uint uv_index = params.uv_offset + uv_y * params.pitch + uv_x;
    float2 uv = float2(float(nv12[uv_index]), float(nv12[uv_index + 1]));
    float c = max(y - 16.0, 0.0);
    float d = uv.x - 128.0;
    float e = uv.y - 128.0;
    float3 rgb = float3(
        (298.0 * c + 409.0 * e + 128.0) / 65280.0,
        (298.0 * c - 100.0 * d - 208.0 * e + 128.0) / 65280.0,
        (298.0 * c + 516.0 * d + 128.0) / 65280.0
    );
    rgb = clamp(rgb, float3(0.0), float3(1.0));
    return half4(half(rgb.r), half(rgb.g), half(rgb.b), half(1.0));
}
"#;

#[cfg(target_os = "macos")]
unsafe fn sync_layer_geometry_on_main(
    layer_object: usize,
    ns_view: isize,
    attach_to_view: bool,
    invalidate_view: bool,
) -> Result<(usize, usize), String> {
    use objc::{
        msg_send,
        runtime::{Object, YES},
        sel, sel_impl,
    };

    let view = ns_view as *mut Object;
    let layer_object = layer_object as *mut Object;
    if view.is_null() || layer_object.is_null() {
        return Err("macOS render layer target became null".to_string());
    }

    let _: () = msg_send![view, setWantsLayer: YES];
    let bounds: core_graphics_types::geometry::CGRect = msg_send![view, bounds];
    let window: *mut Object = msg_send![view, window];
    let contents_scale = if window.is_null() {
        1.0
    } else {
        msg_send![window, backingScaleFactor]
    };
    let _: () = msg_send![layer_object, setFrame: bounds];
    let _: () = msg_send![layer_object, setContentsScale: contents_scale];
    if attach_to_view {
        if invalidate_view {
            let _: () = msg_send![layer_object, setNeedsDisplayOnBoundsChange: YES];
        }
        let _: () = msg_send![layer_object, setZPosition: 1000.0_f64];
        let _: () = msg_send![view, setLayer: layer_object];
    }
    if invalidate_view {
        let _: () = msg_send![view, setNeedsDisplay: YES];
    }

    Ok((
        scaled_drawable_dimension(bounds.size.width, contents_scale),
        scaled_drawable_dimension(bounds.size.height, contents_scale),
    ))
}

#[cfg(target_os = "macos")]
fn scaled_drawable_dimension(points: f64, scale: f64) -> usize {
    let pixels = (points * scale).round();
    if pixels.is_finite() && pixels > 0.0 {
        pixels as usize
    } else {
        1
    }
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
unsafe fn macos_view_uses_static_fullscreen_geometry(ns_view: isize) -> bool {
    use core_graphics_types::geometry::CGRect;
    use objc::{class, msg_send, runtime::Object, sel, sel_impl};

    let view = ns_view as *mut Object;
    if view.is_null() {
        return false;
    }

    let window: *mut Object = msg_send![view, window];
    if window.is_null() {
        return false;
    }

    let screen: *mut Object = msg_send![window, screen];
    let screen: *mut Object = if screen.is_null() {
        msg_send![class!(NSScreen), mainScreen]
    } else {
        screen
    };
    if screen.is_null() {
        return false;
    }

    let bounds: CGRect = msg_send![view, bounds];
    let window_frame: CGRect = msg_send![window, frame];
    let screen_frame: CGRect = msg_send![screen, frame];
    macos_rect_has_positive_size(bounds)
        && macos_rect_size_close(bounds, screen_frame)
        && macos_rect_close(window_frame, screen_frame)
}

#[cfg(target_os = "macos")]
fn macos_rect_has_positive_size(rect: core_graphics_types::geometry::CGRect) -> bool {
    rect.size.width > 0.0 && rect.size.height > 0.0
}

#[cfg(target_os = "macos")]
fn macos_rect_size_close(
    left: core_graphics_types::geometry::CGRect,
    right: core_graphics_types::geometry::CGRect,
) -> bool {
    macos_points_close(left.size.width, right.size.width)
        && macos_points_close(left.size.height, right.size.height)
}

#[cfg(target_os = "macos")]
fn macos_rect_close(
    left: core_graphics_types::geometry::CGRect,
    right: core_graphics_types::geometry::CGRect,
) -> bool {
    macos_points_close(left.origin.x, right.origin.x)
        && macos_points_close(left.origin.y, right.origin.y)
        && macos_rect_size_close(left, right)
}

#[cfg(target_os = "macos")]
fn macos_points_close(left: f64, right: f64) -> bool {
    (left - right).abs() <= 2.0
}

#[cfg(target_os = "macos")]
fn macos_layer_geometry_sync_interval() -> Option<Duration> {
    macos_layer_geometry_sync_interval_from_env_value(
        std::env::var(MACOS_LAYER_GEOMETRY_SYNC_INTERVAL_MS_ENV).ok(),
    )
}

#[cfg(target_os = "macos")]
fn macos_layer_geometry_sync_interval_from_env_value(value: Option<String>) -> Option<Duration> {
    let Some(value) = value.as_deref().map(str::trim) else {
        return Some(MACOS_LAYER_GEOMETRY_SYNC_INTERVAL);
    };
    if value.is_empty() {
        return Some(MACOS_LAYER_GEOMETRY_SYNC_INTERVAL);
    }

    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "0" | "false" | "no" | "off" | "none") {
        return None;
    }

    let millis = value
        .parse::<u64>()
        .unwrap_or(MACOS_LAYER_GEOMETRY_SYNC_INTERVAL.as_millis() as u64);
    if millis == 0 {
        None
    } else {
        Some(Duration::from_millis(millis))
    }
}

#[cfg(target_os = "macos")]
fn copy_region_size(
    src_width: usize,
    src_height: usize,
    dst_width: usize,
    dst_height: usize,
) -> Option<(usize, usize)> {
    let width = src_width.min(dst_width);
    let height = src_height.min(dst_height);
    if width == 0 || height == 0 {
        None
    } else {
        Some((width, height))
    }
}

#[cfg(target_os = "macos")]
fn bgra_contains_non_opaque_alpha(data: &[u8]) -> bool {
    data.as_chunks::<4>().0.iter().any(|pixel| pixel[3] != 255)
}

#[cfg(target_os = "macos")]
fn nv12_plane_layout(
    width: usize,
    height: usize,
    pitch: usize,
) -> Result<Nv12PlaneLayout, RenderError> {
    if width == 0 || height == 0 {
        return Err(RenderError::Message(
            "Metal NV12 frame dimensions must be non-zero".to_string(),
        ));
    }
    if pitch < width {
        return Err(RenderError::Message(
            "Metal NV12 pitch is smaller than frame width".to_string(),
        ));
    }
    let uv_width = width.div_ceil(2);
    if pitch < uv_width.saturating_mul(2) {
        return Err(RenderError::Message(
            "Metal NV12 pitch is smaller than chroma row width".to_string(),
        ));
    }
    let y_bytes = pitch
        .checked_mul(height)
        .ok_or_else(|| RenderError::Message("Metal NV12 luma byte size overflow".to_string()))?;
    let uv_height = height.div_ceil(2);
    let uv_bytes = pitch
        .checked_mul(uv_height)
        .ok_or_else(|| RenderError::Message("Metal NV12 chroma byte size overflow".to_string()))?;
    let expected_len = y_bytes
        .checked_add(uv_bytes)
        .ok_or_else(|| RenderError::Message("Metal NV12 byte size overflow".to_string()))?;
    Ok(Nv12PlaneLayout {
        y_bytes,
        uv_width,
        uv_height,
        expected_len,
    })
}

#[cfg(target_os = "macos")]
fn macos_metal_display_sync_enabled() -> bool {
    macos_metal_display_sync_enabled_from_env_value(
        std::env::var(MACOS_METAL_DISPLAY_SYNC_ENV).ok(),
    )
}

#[cfg(target_os = "macos")]
fn macos_metal_display_sync_enabled_from_env_value(value: Option<String>) -> bool {
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        _ => true,
    }
}

#[cfg(target_os = "macos")]
fn macos_metal_max_drawable_count() -> u32 {
    macos_metal_max_drawable_count_from_env_value(
        std::env::var(MACOS_METAL_MAX_DRAWABLE_COUNT_ENV).ok(),
    )
}

#[cfg(target_os = "macos")]
fn macos_metal_max_drawable_count_from_env_value(value: Option<String>) -> u32 {
    match value.as_deref().map(str::trim) {
        Some(value) => macos_metal_sanitize_max_drawable_count(value.parse().unwrap_or(0)),
        None => MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT,
    }
}

#[cfg(target_os = "macos")]
fn macos_metal_sanitize_max_drawable_count(value: u32) -> u32 {
    match value {
        2 | 3 => value,
        _ => MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT,
    }
}

#[cfg(target_os = "macos")]
fn macos_metal_nv12_buffer_upload_enabled() -> bool {
    macos_metal_nv12_buffer_upload_enabled_from_env_value(
        std::env::var(MACOS_METAL_NV12_BUFFER_UPLOAD_ENV).ok(),
    )
}

#[cfg(target_os = "macos")]
fn macos_metal_nv12_buffer_upload_enabled_from_env_value(value: Option<String>) -> bool {
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn macos_metal_invalidate_view_on_geometry_sync_enabled() -> bool {
    macos_metal_invalidate_view_on_geometry_sync_enabled_from_env_value(
        std::env::var(MACOS_METAL_INVALIDATE_VIEW_ON_GEOMETRY_SYNC_ENV).ok(),
    )
}

#[cfg(target_os = "macos")]
fn macos_metal_invalidate_view_on_geometry_sync_enabled_from_env_value(
    value: Option<String>,
) -> bool {
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn macos_metal_static_fullscreen_geometry_enabled() -> bool {
    macos_metal_static_fullscreen_geometry_enabled_from_env_value(
        std::env::var(MACOS_METAL_STATIC_FULLSCREEN_GEOMETRY_ENV).ok(),
    )
}

#[cfg(target_os = "macos")]
fn macos_metal_static_fullscreen_geometry_enabled_from_env_value(value: Option<String>) -> bool {
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => true,
    }
}

#[cfg(target_os = "macos")]
fn run_on_main_thread_sync<T, F>(f: F) -> Result<T, String>
where
    T: Send,
    F: FnOnce() -> Result<T, String> + Send,
{
    if unsafe { pthread_main_np() } != 0 {
        return f();
    }

    let mut result: Option<Result<T, String>> = None;
    dispatch2::DispatchQueue::main().exec_sync(|| {
        result = Some(f());
    });
    result.unwrap_or_else(|| Err("macOS main-thread task did not return".to_string()))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_main_np() -> std::ffi::c_int;
}

#[cfg(target_os = "macos")]
impl RendererInstance for MacosMetalRenderer {
    fn attach_target(&mut self, target: RenderTarget) -> Result<(), RenderError> {
        let RenderTarget::WindowHandle(window_handle) = target;
        self.attach_ns_view(window_handle)?;
        self.attached_to_target = self.layer.is_some();
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), RenderError> {
        let width = frame.width;
        let height = frame.height;
        let pixel_format = frame.pixel_format;
        match frame.data {
            RenderFrameData::Bgra32(data) => {
                self.upload_bgra(width, height, &data)?;
            }
            RenderFrameData::Rgb24(data) => {
                let expected = width
                    .checked_mul(height)
                    .and_then(|pixels| pixels.checked_mul(3))
                    .ok_or_else(|| RenderError::Message("Metal RGB frame size overflow".into()))?;
                if data.len() != expected {
                    return Err(RenderError::Message(format!(
                        "Metal RGB frame bytes mismatch: expected {expected}, got {}",
                        data.len()
                    )));
                }
                let output_len = width * height * 4;
                if self.scratch_bgra.len() != output_len {
                    self.scratch_bgra.resize(output_len, 0);
                }
                for (src, dst) in data
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .zip(self.scratch_bgra.as_chunks_mut::<4>().0.iter_mut())
                {
                    dst[0] = src[2];
                    dst[1] = src[1];
                    dst[2] = src[0];
                    dst[3] = 255;
                }
                let bgra = std::mem::take(&mut self.scratch_bgra);
                self.upload_bgra(width, height, &bgra)?;
                self.scratch_bgra = bgra;
            }
            RenderFrameData::Nv12 { data, pitch } => {
                if macos_metal_nv12_buffer_upload_enabled() {
                    self.upload_nv12_buffer(width, height, data, pitch)?;
                } else {
                    self.upload_nv12(width, height, &data, pitch)?;
                }
            }
            RenderFrameData::Nv12Bytes { data, pitch } => {
                self.upload_nv12(width, height, data.as_ref(), pitch)?;
            }
            #[cfg(windows)]
            RenderFrameData::D3D11SharedNv12 { .. } | RenderFrameData::D3D11SharedP010 { .. } => {
                return Err(RenderError::Message(
                    "Metal renderer does not accept D3D11 shared textures".to_string(),
                ));
            }
        }

        self.uploaded_frame_count = self.uploaded_frame_count.saturating_add(1);
        self.last_width = width;
        self.last_height = height;
        self.last_pixel_format = Some(pixel_format);
        self.present_if_attached(width, height);
        Ok(())
    }

    fn upload_h264_access_unit(
        &mut self,
        _width: usize,
        _height: usize,
        _timestamp_us: u64,
        payload: bytes::Bytes,
    ) -> Result<(), RenderError> {
        self.upload_h264_pixel_buffer_access_unit(&payload)
    }

    fn upload_hevc_access_unit(
        &mut self,
        _width: usize,
        _height: usize,
        _timestamp_us: u64,
        payload: bytes::Bytes,
    ) -> Result<(), RenderError> {
        self.upload_hevc_pixel_buffer_access_unit(&payload)
    }

    fn snapshot(&self) -> RendererSnapshot {
        RendererSnapshot {
            attached_to_target: self.attached_to_target,
            uploaded_frame_count: self.uploaded_frame_count,
            presented_frame_count: self.presented_frame_count,
            present_skipped_count: self.present_skipped_count,
            render_queue_replacements: None,
            last_present_status: self.last_present_status.clone(),
            low_latency_frame_latency_target: None,
            swap_chain_max_frame_latency: Some(self.max_drawable_count),
            swap_chain_allow_tearing: Some(!self.display_sync_enabled),
            swap_chain_waitable_object: None,
            swap_chain_present_mode: Some(
                if self.display_sync_enabled {
                    "metal_display_sync"
                } else {
                    "metal_immediate"
                }
                .to_string(),
            ),
            display_refresh_hz: None,
            render_thread_priority: None,
            waitable_wait_count: None,
            waitable_wait_total_ms: None,
            waitable_timeout_count: None,
            last_waitable_wait_ms: None,
            last_render_prepare_wait_ms: None,
            last_render_shared_resource_ms: None,
            last_render_wait_for_drawable_ms: self.last_render_wait_for_drawable_ms,
            last_render_encode_commit_ms: self.last_render_encode_commit_ms,
            last_render_draw_present_ms: self.last_render_draw_present_ms,
            last_width: self.last_width,
            last_height: self.last_height,
            last_pixel_format: self.last_pixel_format,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_reports_metal_runtime() {
        let descriptor = MacosRendererFactory.descriptor();

        assert_eq!(descriptor.id, "metal");
        assert_eq!(descriptor.runtime_status, RuntimeStatus::RuntimeBacked);
        assert!(descriptor
            .supported_formats
            .contains(&RenderPixelFormat::Bgra32));
        assert!(descriptor
            .supported_formats
            .contains(&RenderPixelFormat::Rgb24));
        assert!(descriptor
            .supported_formats
            .contains(&RenderPixelFormat::Nv12));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn copy_region_size_clamps_to_drawable() {
        assert_eq!(copy_region_size(1920, 1080, 1280, 720), Some((1280, 720)));
        assert_eq!(copy_region_size(640, 360, 1280, 720), Some((640, 360)));
        assert_eq!(copy_region_size(0, 360, 1280, 720), None);
        assert_eq!(copy_region_size(640, 360, 1280, 0), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scaled_drawable_dimension_never_returns_zero() {
        assert_eq!(scaled_drawable_dimension(640.0, 2.0), 1280);
        assert_eq!(scaled_drawable_dimension(0.0, 2.0), 1);
        assert_eq!(scaled_drawable_dimension(f64::NAN, 2.0), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bgra_alpha_detection_flags_transparent_desktop_frames() {
        assert!(!bgra_contains_non_opaque_alpha(&[
            1, 2, 3, 255, 4, 5, 6, 255
        ]));
        assert!(bgra_contains_non_opaque_alpha(&[1, 2, 3, 0, 4, 5, 6, 255]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_display_sync_env_defaults_on_and_accepts_falsey_override() {
        assert!(macos_metal_display_sync_enabled_from_env_value(None));
        assert!(macos_metal_display_sync_enabled_from_env_value(Some(
            "true".to_string()
        )));
        assert!(!macos_metal_display_sync_enabled_from_env_value(Some(
            "false".to_string()
        )));
        assert!(!macos_metal_display_sync_enabled_from_env_value(Some(
            "0".to_string()
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_max_drawable_count_env_defaults_to_three_and_accepts_two_or_three() {
        assert_eq!(
            macos_metal_max_drawable_count_from_env_value(None),
            MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT
        );
        assert_eq!(
            macos_metal_max_drawable_count_from_env_value(Some("2".to_string())),
            2
        );
        assert_eq!(
            macos_metal_max_drawable_count_from_env_value(Some("3".to_string())),
            3
        );
        assert_eq!(
            macos_metal_max_drawable_count_from_env_value(Some("1".to_string())),
            MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT
        );
        assert_eq!(
            macos_metal_max_drawable_count_from_env_value(Some("4".to_string())),
            MACOS_METAL_DEFAULT_MAX_DRAWABLE_COUNT
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_nv12_buffer_upload_env_defaults_off_and_accepts_truthy_override() {
        assert!(!macos_metal_nv12_buffer_upload_enabled_from_env_value(None));
        assert!(macos_metal_nv12_buffer_upload_enabled_from_env_value(Some(
            "true".to_string()
        )));
        assert!(macos_metal_nv12_buffer_upload_enabled_from_env_value(Some(
            "1".to_string()
        )));
        assert!(!macos_metal_nv12_buffer_upload_enabled_from_env_value(
            Some("false".to_string())
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_view_invalidation_on_geometry_sync_env_defaults_off() {
        assert!(!macos_metal_invalidate_view_on_geometry_sync_enabled_from_env_value(None));
        assert!(
            macos_metal_invalidate_view_on_geometry_sync_enabled_from_env_value(Some(
                "true".to_string()
            ))
        );
        assert!(
            macos_metal_invalidate_view_on_geometry_sync_enabled_from_env_value(Some(
                "1".to_string()
            ))
        );
        assert!(
            !macos_metal_invalidate_view_on_geometry_sync_enabled_from_env_value(Some(
                "false".to_string()
            ))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_static_fullscreen_geometry_env_defaults_on_and_accepts_falsey_override() {
        assert!(macos_metal_static_fullscreen_geometry_enabled_from_env_value(None));
        assert!(
            macos_metal_static_fullscreen_geometry_enabled_from_env_value(Some("true".to_string()))
        );
        assert!(
            macos_metal_static_fullscreen_geometry_enabled_from_env_value(Some("1".to_string()))
        );
        assert!(
            !macos_metal_static_fullscreen_geometry_enabled_from_env_value(Some(
                "false".to_string()
            ))
        );
        assert!(
            !macos_metal_static_fullscreen_geometry_enabled_from_env_value(Some("off".to_string()))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_geometry_sync_interval_env_defaults_to_500ms_and_accepts_zero_disable() {
        assert_eq!(
            macos_layer_geometry_sync_interval_from_env_value(None),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            macos_layer_geometry_sync_interval_from_env_value(Some("250".to_string())),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            macos_layer_geometry_sync_interval_from_env_value(Some("0".to_string())),
            None
        );
        assert_eq!(
            macos_layer_geometry_sync_interval_from_env_value(Some("off".to_string())),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_uploads_bgra32_texture_and_normalizes_alpha() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        renderer
            .upload_frame(RenderFrame::from_bgra32(
                2,
                1,
                vec![10, 20, 30, 0, 40, 50, 60, 255],
            ))
            .expect("upload BGRA frame");

        assert_eq!(
            read_uploaded_bgra_texture(&renderer, 2, 1),
            vec![10, 20, 30, 255, 40, 50, 60, 255]
        );

        let snapshot = renderer.snapshot();
        assert!(!snapshot.attached_to_target);
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(snapshot.presented_frame_count, 0);
        assert_eq!(snapshot.present_skipped_count, 0);
        assert_eq!(snapshot.last_present_status, None);
        assert_eq!(snapshot.last_width, 2);
        assert_eq!(snapshot.last_height, 1);
        assert_eq!(snapshot.last_pixel_format, Some(RenderPixelFormat::Bgra32));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_converts_rgb24_to_bgra32_texture() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        renderer
            .upload_frame(RenderFrame::from_rgb24(2, 1, vec![1, 2, 3, 4, 5, 6]))
            .expect("upload RGB frame");

        assert_eq!(
            read_uploaded_bgra_texture(&renderer, 2, 1),
            vec![3, 2, 1, 255, 6, 5, 4, 255]
        );

        let snapshot = renderer.snapshot();
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(snapshot.last_width, 2);
        assert_eq!(snapshot.last_height, 1);
        assert_eq!(snapshot.last_pixel_format, Some(RenderPixelFormat::Rgb24));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_uploads_nv12_planes_and_shades_to_bgra() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        renderer
            .upload_frame(RenderFrame::from_nv12(
                2,
                2,
                vec![16, 235, 81, 145, 128, 128],
                2,
            ))
            .expect("upload NV12 frame");

        assert!(matches!(
            renderer.active_source,
            Some(MacosTextureSource::Nv12)
        ));
        assert!(renderer.texture.is_none());
        assert!(renderer.scratch_bgra.is_empty());
        assert_eq!(renderer.nv12_y_texture.as_ref().unwrap().width(), 2);
        assert_eq!(renderer.nv12_y_texture.as_ref().unwrap().height(), 2);
        assert_eq!(renderer.nv12_uv_texture.as_ref().unwrap().width(), 1);
        assert_eq!(renderer.nv12_uv_texture.as_ref().unwrap().height(), 1);
        assert_bgra_pixels_close(
            &render_nv12_to_bgra_for_test(&renderer, 2, 2),
            &[
                0, 0, 0, 255, 255, 255, 255, 255, 76, 76, 76, 255, 150, 150, 150, 255,
            ],
            2,
        );

        let snapshot = renderer.snapshot();
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(snapshot.last_pixel_format, Some(RenderPixelFormat::Nv12));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_accepts_nv12_bytes_frame() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        renderer
            .upload_frame(RenderFrame::from_nv12_bytes(
                2,
                2,
                bytes::Bytes::from_static(&[16, 235, 81, 145, 128, 128]),
                2,
            ))
            .expect("upload NV12 bytes frame");

        assert!(matches!(
            renderer.active_source,
            Some(MacosTextureSource::Nv12)
        ));
        assert_eq!(renderer.nv12_y_texture.as_ref().unwrap().width(), 2);
        assert_eq!(renderer.nv12_uv_texture.as_ref().unwrap().width(), 1);
        assert_bgra_pixels_close(
            &render_nv12_to_bgra_for_test(&renderer, 2, 2),
            &[
                0, 0, 0, 255, 255, 255, 255, 255, 76, 76, 76, 255, 150, 150, 150, 255,
            ],
            2,
        );

        let snapshot = renderer.snapshot();
        assert_eq!(snapshot.uploaded_frame_count, 1);
        assert_eq!(snapshot.last_pixel_format, Some(RenderPixelFormat::Nv12));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_can_stage_nv12_as_shared_buffer_source() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        renderer
            .upload_nv12_buffer(2, 2, vec![16, 235, 81, 145, 128, 128], 2)
            .expect("upload NV12 buffer");

        let Some(MacosTextureSource::Nv12Buffer(source)) = renderer.active_source.as_ref() else {
            panic!("expected NV12 buffer active source");
        };
        assert_eq!(source.data.as_slice(), &[16, 235, 81, 145, 128, 128]);
        assert_eq!(source.width, 2);
        assert_eq!(source.height, 2);
        assert_eq!(source.pitch, 2);
        assert_eq!(source.uv_offset, 4);
        assert_eq!(renderer.retained_nv12_buffers.len(), 1);
        assert!(renderer.nv12_y_texture.is_none());
        assert!(renderer.nv12_uv_texture.is_none());
        assert_eq!(
            nv12_buffer_uniforms(source).expect("uniforms"),
            Nv12BufferUniforms {
                width: 2,
                height: 2,
                pitch: 2,
                uv_offset: 4,
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_rejects_null_cv_pixel_buffer_source() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        let error = unsafe { renderer.upload_cv_pixel_buffer_nv12(2, 2, std::ptr::null_mut()) }
            .expect_err("null CVPixelBuffer should fail");

        assert!(
            error.to_string().contains("CVPixelBuffer pointer is null"),
            "unexpected error: {error}"
        );
        assert_eq!(renderer.snapshot().uploaded_frame_count, 0);
        assert!(renderer.retained_cv_pixel_buffers.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_accepts_compressed_access_unit_entrypoints() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        renderer
            .upload_h264_access_unit(2, 2, 0, bytes::Bytes::from_static(&[0, 0, 0, 1, 9, 0]))
            .expect("accept H.264 access unit entrypoint");
        renderer
            .upload_hevc_access_unit(2, 2, 0, bytes::Bytes::from_static(&[0, 0, 0, 1, 70, 1, 0]))
            .expect("accept HEVC access unit entrypoint");

        assert!(renderer.h264_pixel_buffer_decoder.is_some());
        assert!(renderer.hevc_pixel_buffer_decoder.is_some());
        assert_eq!(renderer.snapshot().uploaded_frame_count, 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_rejects_mismatched_frame_byte_lengths() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        let error = renderer
            .upload_frame(RenderFrame::from_bgra32(2, 2, vec![1, 2, 3, 4]))
            .expect_err("BGRA byte mismatch should fail");

        assert!(
            error
                .to_string()
                .contains("Metal BGRA frame bytes mismatch"),
            "unexpected error: {error}"
        );
        assert_eq!(renderer.snapshot().uploaded_frame_count, 0);
        assert!(renderer.texture.is_none());

        let error = renderer
            .upload_frame(RenderFrame::from_rgb24(2, 2, vec![1, 2, 3]))
            .expect_err("RGB byte mismatch should fail");

        assert!(
            error.to_string().contains("Metal RGB frame bytes mismatch"),
            "unexpected error: {error}"
        );
        assert_eq!(renderer.snapshot().uploaded_frame_count, 0);
        assert!(renderer.texture.is_none());

        let error = renderer
            .upload_frame(RenderFrame::from_nv12(2, 2, vec![16, 235, 81], 2))
            .expect_err("NV12 byte mismatch should fail");

        assert!(
            error
                .to_string()
                .contains("Metal NV12 frame bytes mismatch"),
            "unexpected error: {error}"
        );
        assert_eq!(renderer.snapshot().uploaded_frame_count, 0);
        assert!(renderer.nv12_y_texture.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metal_renderer_rejects_null_native_target() {
        let mut renderer = MacosMetalRenderer::new().expect("create Metal renderer");

        let error = renderer
            .attach_target(RenderTarget::WindowHandle(0))
            .expect_err("null NSView target should fail");

        assert!(
            error
                .to_string()
                .contains("requires a non-null NSView render target"),
            "unexpected error: {error}"
        );
        assert!(!renderer.snapshot().attached_to_target);
    }

    #[cfg(target_os = "macos")]
    fn read_uploaded_bgra_texture(
        renderer: &MacosMetalRenderer,
        width: usize,
        height: usize,
    ) -> Vec<u8> {
        let texture = renderer.texture.as_ref().expect("uploaded texture");
        assert_eq!(texture.width() as usize, width);
        assert_eq!(texture.height() as usize, height);

        read_bgra_texture(texture, width, height)
    }

    #[cfg(target_os = "macos")]
    fn render_nv12_to_bgra_for_test(
        renderer: &MacosMetalRenderer,
        width: usize,
        height: usize,
    ) -> Vec<u8> {
        let descriptor = metal::TextureDescriptor::new();
        descriptor.set_texture_type(metal::MTLTextureType::D2);
        descriptor.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
        descriptor.set_width(width as u64);
        descriptor.set_height(height as u64);
        descriptor.set_storage_mode(metal::MTLStorageMode::Shared);
        descriptor
            .set_usage(metal::MTLTextureUsage::RenderTarget | metal::MTLTextureUsage::ShaderRead);
        let target = renderer.device.new_texture(&descriptor);
        let command_buffer = renderer.command_queue.new_command_buffer();
        draw_nv12_fullscreen(
            &command_buffer,
            &renderer.nv12_pipeline_state,
            renderer.nv12_y_texture.as_ref().expect("NV12 Y texture"),
            renderer.nv12_uv_texture.as_ref().expect("NV12 UV texture"),
            &target,
            width,
            height,
        );
        command_buffer.commit();
        command_buffer.wait_until_completed();
        read_bgra_texture(&target, width, height)
    }

    #[cfg(target_os = "macos")]
    fn read_bgra_texture(texture: &metal::TextureRef, width: usize, height: usize) -> Vec<u8> {
        let mut bytes = vec![0; width * height * 4];
        let region = metal::MTLRegion::new_2d(0, 0, width as u64, height as u64);
        texture.get_bytes(bytes.as_mut_ptr().cast(), (width * 4) as u64, region, 0);
        bytes
    }

    #[cfg(target_os = "macos")]
    fn assert_bgra_pixels_close(actual: &[u8], expected: &[u8], tolerance: u8) {
        assert_eq!(actual.len(), expected.len());
        for (index, (&actual_byte, &expected_byte)) in
            actual.iter().zip(expected.iter()).enumerate()
        {
            let delta = actual_byte.abs_diff(expected_byte);
            assert!(
                delta <= tolerance,
                "byte {index} differs: expected {expected_byte}, got {actual_byte}, full actual={actual:?}"
            );
        }
    }
}
