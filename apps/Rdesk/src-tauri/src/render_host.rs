use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use mrd_observability::{ProbeRegistry, StageId};
use mrd_pipeline_core::{DecodedFrame, DecodedFrameData};
use mrd_proto::SessionId;
use mrd_render::{
    BoxedRenderer, RenderError, RenderFrame, RenderFrameData, RenderPixelFormat, RenderTarget,
    RendererFactory, RendererSnapshot,
};
#[cfg(windows)]
use mrd_render_d3d11::D3d11RendererFactory;
use serde::{Deserialize, Serialize};

use crate::frame_sink::{DecodedFrameSink, DEFAULT_SOURCE_ID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrameSnapshotResponse {
    pub frame_count: u64,
    pub width: usize,
    pub height: usize,
    pub pixel_format: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderHostSnapshot {
    pub attached: bool,
    pub surface_count: usize,
    pub attached_surface_ids: Vec<String>,
    pub frame: Option<DecodedFrameSnapshotResponse>,
    pub renderer_backend: Option<String>,
    pub renderer_snapshot: Option<RendererSnapshotResponse>,
    pub surface_source_bindings: Vec<SurfaceSourceBindingResponse>,
    pub available_source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendererSnapshotResponse {
    pub attached_to_target: bool,
    pub uploaded_frame_count: u64,
    pub low_latency_frame_latency_target: Option<u32>,
    pub swap_chain_max_frame_latency: Option<u32>,
    pub swap_chain_allow_tearing: Option<bool>,
    pub last_width: usize,
    pub last_height: usize,
    pub last_pixel_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceSourceBindingResponse {
    pub surface_id: String,
    pub source_id: String,
}

#[derive(Default)]
pub struct RenderHost {
    renderers: HashMap<SessionId, HashMap<String, BoxedRenderer>>,
    surface_sources: HashMap<SessionId, HashMap<String, String>>,
    frame_sink: Option<Arc<Mutex<DecodedFrameSink>>>,
    probe_registry: Option<ProbeRegistry>,
}

impl RenderHost {
    pub fn with_frame_sink(frame_sink: Arc<Mutex<DecodedFrameSink>>) -> Self {
        Self::with_frame_sink_and_probes(frame_sink, None)
    }

    pub fn with_frame_sink_and_probes(
        frame_sink: Arc<Mutex<DecodedFrameSink>>,
        probe_registry: Option<ProbeRegistry>,
    ) -> Self {
        Self {
            renderers: HashMap::new(),
            surface_sources: HashMap::new(),
            frame_sink: Some(frame_sink),
            probe_registry,
        }
    }

    pub fn attach_session(
        &mut self,
        session_id: SessionId,
        surface_id: String,
        window_handle: isize,
    ) -> Result<(), String> {
        let renderers = self.renderers.entry(session_id.clone()).or_default();
        if !renderers.contains_key(&surface_id) {
            let renderer = create_native_renderer(window_handle)?;
            renderers.insert(surface_id.clone(), renderer);
        }
        self.surface_sources
            .entry(session_id)
            .or_default()
            .entry(surface_id)
            .or_insert_with(|| DEFAULT_SOURCE_ID.to_string());
        Ok(())
    }

    pub fn snapshot(&mut self, session_id: &SessionId) -> Result<RenderHostSnapshot, String> {
        let attached_surface_ids = self
            .renderers
            .get(session_id)
            .map(|renderers| renderers.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let attached = !attached_surface_ids.is_empty();
        let surface_count = attached_surface_ids.len();
        let Some(frame_sink) = self.frame_sink.as_ref() else {
            return Ok(RenderHostSnapshot {
                attached,
                surface_count,
                attached_surface_ids,
                frame: None,
                renderer_backend: None,
                renderer_snapshot: None,
                surface_source_bindings: Vec::new(),
                available_source_ids: Vec::new(),
            });
        };

        let (frame, latest_frame) = {
            let frame_sink = frame_sink.lock().expect("lock decoded frame sink");
            (
                frame_sink
                    .snapshot(session_id)
                    .map(decoded_frame_snapshot_response),
                frame_sink.latest_frame(session_id).cloned(),
            )
        };
        let available_source_ids = {
            let frame_sink = frame_sink.lock().expect("lock decoded frame sink");
            frame_sink.list_sources(session_id)
        };
        let surface_source_bindings = self
            .surface_sources
            .get(session_id)
            .map(|bindings| {
                bindings
                    .iter()
                    .map(|(surface_id, source_id)| SurfaceSourceBindingResponse {
                        surface_id: surface_id.clone(),
                        source_id: source_id.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if let (Some(surface_renderers), Some(frame_to_upload)) =
            (self.renderers.get_mut(session_id), latest_frame.as_ref())
        {
            let latest_source_frames = {
                let frame_sink = frame_sink.lock().expect("lock decoded frame sink");
                available_source_ids
                    .iter()
                    .filter_map(|source_id| {
                        frame_sink
                            .latest_frame_for_source(session_id, source_id)
                            .cloned()
                            .map(|frame| (source_id.clone(), frame))
                    })
                    .collect::<HashMap<_, _>>()
            };
            for (surface_id, renderer) in surface_renderers.iter_mut() {
                let source_bound_frame = self
                    .surface_sources
                    .get(session_id)
                    .and_then(|bindings| bindings.get(surface_id))
                    .and_then(|source_id| latest_source_frames.get(source_id));
                let render_frame =
                    decoded_frame_to_render_frame(source_bound_frame.unwrap_or(frame_to_upload));
                let bytes = render_frame_byte_len(&render_frame);
                let started_at = std::time::Instant::now();
                renderer
                    .upload_frame(render_frame)
                    .map_err(|error| format!("upload latest frame to renderer failed: {error}"))?;
                if let Some(probe_registry) = self.probe_registry.as_ref() {
                    probe_registry
                        .session_handle(session_id.clone(), DEFAULT_SOURCE_ID)
                        .record_stage(StageId::RenderUpload, started_at.elapsed(), bytes, false);
                }
            }
        }

        let renderer_snapshot = self
            .renderers
            .get(session_id)
            .and_then(|renderers| renderers.values().next())
            .map(|renderer| renderer_snapshot_response(renderer.snapshot()));

        Ok(RenderHostSnapshot {
            attached,
            surface_count,
            attached_surface_ids,
            frame,
            renderer_backend: self
                .renderers
                .get(session_id)
                .and_then(|renderers| (!renderers.is_empty()).then(native_renderer_backend)),
            renderer_snapshot,
            surface_source_bindings,
            available_source_ids,
        })
    }
}

fn decoded_frame_snapshot_response(
    snapshot: &crate::frame_sink::DecodedFrameSnapshot,
) -> DecodedFrameSnapshotResponse {
    DecodedFrameSnapshotResponse {
        frame_count: snapshot.frame_count,
        width: snapshot.width,
        height: snapshot.height,
        pixel_format: match snapshot.pixel_format {
            mrd_decode::PixelFormat::Rgb24 => "Rgb24".to_string(),
            mrd_decode::PixelFormat::Bgra32 => "Bgra32".to_string(),
            mrd_decode::PixelFormat::I420 => "I420".to_string(),
            mrd_decode::PixelFormat::Nv12 => "Nv12".to_string(),
            mrd_decode::PixelFormat::P010 => "P010".to_string(),
            mrd_decode::PixelFormat::D3d11Texture => "D3d11Texture".to_string(),
        },
        bytes: snapshot.bytes,
    }
}

fn create_native_renderer(window_handle: isize) -> Result<BoxedRenderer, String> {
    #[cfg(test)]
    if window_handle == 0 {
        return Ok(Box::<TestRenderer>::default());
    }

    let mut renderer = create_native_renderer_instance().map_err(|error| {
        format!(
            "create {} renderer failed: {error}",
            native_renderer_backend()
        )
    })?;
    renderer
        .attach_target(RenderTarget::WindowHandle(window_handle))
        .map_err(|error| {
            format!(
                "attach {} renderer target failed: {error}",
                native_renderer_backend()
            )
        })?;
    Ok(renderer)
}

#[cfg(windows)]
fn create_native_renderer_instance() -> Result<BoxedRenderer, RenderError> {
    D3d11RendererFactory.create()
}

#[cfg(target_os = "macos")]
fn create_native_renderer_instance() -> Result<BoxedRenderer, RenderError> {
    mrd_render_macos::MacosRendererFactory.create()
}

#[cfg(target_os = "linux")]
fn create_native_renderer_instance() -> Result<BoxedRenderer, RenderError> {
    mrd_render_linux::LinuxRendererFactory.create()
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn create_native_renderer_instance() -> Result<BoxedRenderer, RenderError> {
    Err(RenderError::Message(
        "native renderer is not available on this platform".to_string(),
    ))
}

fn native_renderer_backend() -> String {
    #[cfg(windows)]
    {
        "d3d11".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "metal".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        "none".to_string()
    }
}

fn decoded_frame_to_render_frame(frame: &DecodedFrame) -> RenderFrame {
    match &frame.data {
        DecodedFrameData::CpuRgb24(data) => {
            RenderFrame::from_rgb24(frame.width, frame.height, data.clone())
        }
        DecodedFrameData::CpuBgra32(data) => {
            RenderFrame::from_bgra32(frame.width, frame.height, data.clone())
        }
        DecodedFrameData::CpuI420 {
            data,
            y_pitch,
            uv_pitch,
        } => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            cpu_i420_to_bgra32(data, frame.width, frame.height, *y_pitch, *uv_pitch),
        ),
        DecodedFrameData::CpuNv12 { data, pitch } => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            cpu_nv12_to_bgra32(data, frame.width, frame.height, *pitch),
        ),
        DecodedFrameData::CpuP010 { data, pitch } => RenderFrame::from_bgra32(
            frame.width,
            frame.height,
            cpu_p010_to_bgra32(data, frame.width, frame.height, *pitch),
        ),
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedNv12 {
            shared_handle_y,
            shared_handle_uv,
            ..
        } => RenderFrame::from_d3d11_shared_nv12(
            frame.width,
            frame.height,
            *shared_handle_y,
            *shared_handle_uv,
        ),
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedP010 {
            shared_handle_y,
            shared_handle_uv,
            ..
        } => RenderFrame::from_d3d11_shared_p010(
            frame.width,
            frame.height,
            *shared_handle_y,
            *shared_handle_uv,
        ),
    }
}

fn render_frame_byte_len(frame: &RenderFrame) -> usize {
    match &frame.data {
        RenderFrameData::Rgb24(data) | RenderFrameData::Bgra32(data) => data.len(),
        RenderFrameData::Nv12 { data, .. } => data.len(),
        RenderFrameData::Nv12Bytes { data, .. } => data.len(),
        #[cfg(windows)]
        RenderFrameData::D3D11SharedBgra { .. }
        | RenderFrameData::D3D11SharedNv12 { .. }
        | RenderFrameData::D3D11SharedP010 { .. } => 0,
    }
}

fn renderer_snapshot_response(snapshot: RendererSnapshot) -> RendererSnapshotResponse {
    RendererSnapshotResponse {
        attached_to_target: snapshot.attached_to_target,
        uploaded_frame_count: snapshot.uploaded_frame_count,
        low_latency_frame_latency_target: snapshot.low_latency_frame_latency_target,
        swap_chain_max_frame_latency: snapshot.swap_chain_max_frame_latency,
        swap_chain_allow_tearing: snapshot.swap_chain_allow_tearing,
        last_width: snapshot.last_width,
        last_height: snapshot.last_height,
        last_pixel_format: snapshot.last_pixel_format.map(render_pixel_format_label),
    }
}

fn render_pixel_format_label(format: RenderPixelFormat) -> String {
    match format {
        RenderPixelFormat::Rgb24 => "Rgb24".to_string(),
        RenderPixelFormat::Bgra32 => "Bgra32".to_string(),
        RenderPixelFormat::Nv12 => "Nv12".to_string(),
        #[cfg(windows)]
        RenderPixelFormat::D3D11SharedBgra => "D3D11SharedBgra".to_string(),
        #[cfg(windows)]
        RenderPixelFormat::D3D11SharedNv12 => "D3D11SharedNv12".to_string(),
        #[cfg(windows)]
        RenderPixelFormat::D3D11SharedP010 => "D3D11SharedP010".to_string(),
    }
}

fn cpu_nv12_to_bgra32(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    let uv_base = pitch * height;

    for y in (0..height).step_by(2) {
        let y0_row = y * pitch;
        let y1_row = (y + 1).min(height.saturating_sub(1)) * pitch;
        let uv_row_start = uv_base + (y / 2) * pitch;
        let out0_row = y * width * 4;
        let out1_row = (y + 1).min(height.saturating_sub(1)) * width * 4;

        for x in (0..width).step_by(2) {
            let uv_offset = uv_row_start + (x / 2) * 2;
            if uv_offset + 1 >= nv12.len() {
                continue;
            }

            let u = nv12[uv_offset];
            let v = nv12[uv_offset + 1];
            let y0_offset = y0_row + x;
            if y0_offset < nv12.len() {
                write_limited_bgra_pixel(&mut bgra, out0_row + x * 4, nv12[y0_offset], u, v);
            }
            if x + 1 < width {
                let y0_next = y0_offset + 1;
                if y0_next < nv12.len() {
                    write_limited_bgra_pixel(
                        &mut bgra,
                        out0_row + (x + 1) * 4,
                        nv12[y0_next],
                        u,
                        v,
                    );
                }
            }
            if y + 1 < height {
                let y1_offset = y1_row + x;
                if y1_offset < nv12.len() {
                    write_limited_bgra_pixel(&mut bgra, out1_row + x * 4, nv12[y1_offset], u, v);
                }
                if x + 1 < width {
                    let y1_next = y1_offset + 1;
                    if y1_next < nv12.len() {
                        write_limited_bgra_pixel(
                            &mut bgra,
                            out1_row + (x + 1) * 4,
                            nv12[y1_next],
                            u,
                            v,
                        );
                    }
                }
            }
        }
    }

    bgra
}

fn cpu_i420_to_bgra32(
    i420: &[u8],
    width: usize,
    height: usize,
    y_pitch: usize,
    uv_pitch: usize,
) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    let chroma_height = height.div_ceil(2);
    let u_base = y_pitch * height;
    let v_base = u_base + uv_pitch * chroma_height;

    for y in (0..height).step_by(2) {
        let y0_row = y * y_pitch;
        let y1_row = (y + 1).min(height.saturating_sub(1)) * y_pitch;
        let uv_row_start = (y / 2) * uv_pitch;
        let out0_row = y * width * 4;
        let out1_row = (y + 1).min(height.saturating_sub(1)) * width * 4;

        for x in (0..width).step_by(2) {
            let uv_offset = uv_row_start + x / 2;
            let u_offset = u_base + uv_offset;
            let v_offset = v_base + uv_offset;
            if u_offset >= i420.len() || v_offset >= i420.len() {
                continue;
            }

            let u = i420[u_offset];
            let v = i420[v_offset];
            let y0_offset = y0_row + x;
            if y0_offset < i420.len() {
                write_limited_bgra_pixel(&mut bgra, out0_row + x * 4, i420[y0_offset], u, v);
            }
            if x + 1 < width {
                let y0_next = y0_offset + 1;
                if y0_next < i420.len() {
                    write_limited_bgra_pixel(
                        &mut bgra,
                        out0_row + (x + 1) * 4,
                        i420[y0_next],
                        u,
                        v,
                    );
                }
            }
            if y + 1 < height {
                let y1_offset = y1_row + x;
                if y1_offset < i420.len() {
                    write_limited_bgra_pixel(&mut bgra, out1_row + x * 4, i420[y1_offset], u, v);
                }
                if x + 1 < width {
                    let y1_next = y1_offset + 1;
                    if y1_next < i420.len() {
                        write_limited_bgra_pixel(
                            &mut bgra,
                            out1_row + (x + 1) * 4,
                            i420[y1_next],
                            u,
                            v,
                        );
                    }
                }
            }
        }
    }

    bgra
}

fn cpu_p010_to_bgra32(p010: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
    let mut bgra = vec![0_u8; width * height * 4];
    let uv_base = pitch * height;

    for y in (0..height).step_by(2) {
        let y0_row = y * pitch;
        let y1_row = (y + 1).min(height.saturating_sub(1)) * pitch;
        let uv_row_start = uv_base + (y / 2) * pitch;
        let out0_row = y * width * 4;
        let out1_row = (y + 1).min(height.saturating_sub(1)) * width * 4;

        for x in (0..width).step_by(2) {
            let uv_offset = uv_row_start + (x / 2) * 4;
            if uv_offset + 3 >= p010.len() {
                continue;
            }

            let u10 = u16::from_le_bytes([p010[uv_offset], p010[uv_offset + 1]]) >> 6;
            let v10 = u16::from_le_bytes([p010[uv_offset + 2], p010[uv_offset + 3]]) >> 6;
            let y0_offset = y0_row + x * 2;
            if y0_offset + 1 < p010.len() {
                let y10 = u16::from_le_bytes([p010[y0_offset], p010[y0_offset + 1]]) >> 6;
                write_p010_bgra_pixel(&mut bgra, out0_row + x * 4, y10, u10, v10);
            }
            if x + 1 < width {
                let y0_next = y0_offset + 2;
                if y0_next + 1 < p010.len() {
                    let y10 = u16::from_le_bytes([p010[y0_next], p010[y0_next + 1]]) >> 6;
                    write_p010_bgra_pixel(&mut bgra, out0_row + (x + 1) * 4, y10, u10, v10);
                }
            }
            if y + 1 < height {
                let y1_offset = y1_row + x * 2;
                if y1_offset + 1 < p010.len() {
                    let y10 = u16::from_le_bytes([p010[y1_offset], p010[y1_offset + 1]]) >> 6;
                    write_p010_bgra_pixel(&mut bgra, out1_row + x * 4, y10, u10, v10);
                }
                if x + 1 < width {
                    let y1_next = y1_offset + 2;
                    if y1_next + 1 < p010.len() {
                        let y10 = u16::from_le_bytes([p010[y1_next], p010[y1_next + 1]]) >> 6;
                        write_p010_bgra_pixel(&mut bgra, out1_row + (x + 1) * 4, y10, u10, v10);
                    }
                }
            }
        }
    }

    bgra
}

#[inline]
fn write_limited_bgra_pixel(bgra: &mut [u8], offset: usize, y: u8, u: u8, v: u8) {
    if offset + 3 >= bgra.len() {
        return;
    }
    let y_sample = y as i32 - 16;
    let u = u as i32 - 128;
    let v = v as i32 - 128;

    let r = (298 * y_sample + 409 * v + 128) >> 8;
    let g = (298 * y_sample - 100 * u - 208 * v + 128) >> 8;
    let b = (298 * y_sample + 516 * u + 128) >> 8;

    bgra[offset] = b.clamp(0, 255) as u8;
    bgra[offset + 1] = g.clamp(0, 255) as u8;
    bgra[offset + 2] = r.clamp(0, 255) as u8;
    bgra[offset + 3] = 255;
}

#[inline]
fn write_p010_bgra_pixel(bgra: &mut [u8], offset: usize, y10: u16, u10: u16, v10: u16) {
    if offset + 3 >= bgra.len() {
        return;
    }
    let y_sample = y10 as i32;
    let u = u10 as i32 - 512;
    let v = v10 as i32 - 512;

    let r = y_sample + ((1436 * v) >> 10);
    let g = y_sample - ((352 * u + 731 * v) >> 10);
    let b = y_sample + ((1815 * u) >> 10);

    bgra[offset] = clamp_10bit_to_8bit(b);
    bgra[offset + 1] = clamp_10bit_to_8bit(g);
    bgra[offset + 2] = clamp_10bit_to_8bit(r);
    bgra[offset + 3] = 255;
}

#[inline]
fn clamp_10bit_to_8bit(value: i32) -> u8 {
    (((value.clamp(0, 1023) + 2) >> 2).min(255)) as u8
}

#[cfg(test)]
struct TestRenderer {
    snapshot: RendererSnapshot,
}

#[cfg(test)]
impl Default for TestRenderer {
    fn default() -> Self {
        Self {
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
}

#[cfg(test)]
impl mrd_render::RendererInstance for TestRenderer {
    fn attach_target(&mut self, _target: RenderTarget) -> Result<(), RenderError> {
        self.snapshot.attached_to_target = true;
        Ok(())
    }

    fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), RenderError> {
        self.snapshot.attached_to_target = true;
        self.snapshot.uploaded_frame_count = self.snapshot.uploaded_frame_count.saturating_add(1);
        self.snapshot.presented_frame_count = self.snapshot.presented_frame_count.saturating_add(1);
        self.snapshot.last_width = frame.width;
        self.snapshot.last_height = frame.height;
        self.snapshot.last_pixel_format = Some(frame.pixel_format);
        Ok(())
    }

    fn snapshot(&self) -> RendererSnapshot {
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{RenderHost, SurfaceSourceBindingResponse};
    use crate::frame_sink::{DecodedFrameSink, DEFAULT_SOURCE_ID};
    use mrd_pipeline_core::DecodedFrame;
    use mrd_proto::SessionId;

    #[test]
    fn attached_session_exposes_frame_snapshot_without_preview_image() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(DecodedFrameSink::default()));
        sink.lock().expect("lock frame sink").ingest_frame(
            SessionId("session-render".into()),
            DecodedFrame::from_cpu_rgb24(4, 4, 0, vec![128; 4 * 4 * 3]),
        );

        let mut render_host = RenderHost::with_frame_sink(sink);
        render_host
            .attach_session(SessionId("session-render".into()), "surface-1".into(), 0)
            .expect("attach session");

        let snapshot = render_host
            .snapshot(&SessionId("session-render".into()))
            .expect("render host snapshot");

        assert!(snapshot.attached);
        assert_eq!(snapshot.surface_count, 1);
        assert_eq!(snapshot.attached_surface_ids, vec!["surface-1".to_string()]);
        assert_eq!(
            snapshot.surface_source_bindings,
            vec![SurfaceSourceBindingResponse {
                surface_id: "surface-1".to_string(),
                source_id: DEFAULT_SOURCE_ID.to_string(),
            }]
        );
        assert_eq!(snapshot.frame.as_ref().map(|frame| frame.width), Some(4));
        assert!(snapshot.renderer_backend.is_some());
        assert_eq!(
            snapshot
                .renderer_snapshot
                .as_ref()
                .map(|renderer| renderer.uploaded_frame_count),
            Some(1)
        );
    }

    #[test]
    fn decoded_nv12_frame_maps_to_bgra_render_frame_without_png() {
        let frame = DecodedFrame::from_cpu_nv12(2, 2, 0, 2, vec![235, 235, 235, 235, 128, 128]);
        let render_frame = super::decoded_frame_to_render_frame(&frame);

        assert_eq!(
            render_frame.pixel_format,
            mrd_render::RenderPixelFormat::Bgra32
        );
        assert_eq!(super::render_frame_byte_len(&render_frame), 2 * 2 * 4);
    }
}
