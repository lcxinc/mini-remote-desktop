//! Windows decoder and D3D11 presentation adapter.

use crate::{
    media::MediaResource,
    render::{RenderAdapter, RenderAdapterMetrics},
};
use mrd_agent_ipc::{MediaCodec, RenderAccessUnit};
use mrd_pipeline_core::{DecodedFrame, DecodedFrameData, PipelineError, VideoDecoder};
use mrd_proto::SessionId;
use mrd_render::{BoxedRenderer, RenderError, RenderFrame, RenderTarget, RendererFactory as _};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::JoinHandle,
};
use thiserror::Error;

/// A decoded frame cannot be represented faithfully by the D3D11 renderer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameConversionError {
    /// The decoder produced a CPU YUV format that requires an explicit color
    /// converter before it can be presented.
    #[error("decoded CPU YUV frame requires conversion before D3D11 presentation")]
    CpuYuvRequiresConversion,
    /// Frame dimensions must be non-zero and even for 4:2:0 sampling.
    #[error("I420 frame dimensions are invalid")]
    InvalidI420Dimensions,
    /// Plane pitches or backing storage cannot describe the declared frame.
    #[error("I420 frame planes are undersized or invalid")]
    InvalidI420Planes,
}

/// Result of admitting one encoded unit into the bounded render queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueAdmission {
    /// Unit was appended without dropping queued work.
    Accepted,
    /// An older disposable interframe was replaced.
    Replaced,
    /// Queue contained only protected keyframes.
    Rejected,
}

/// Bounded queue that never replaces a queued keyframe with an interframe.
#[derive(Debug)]
pub struct RenderAccessUnitQueue {
    capacity: usize,
    units: VecDeque<mrd_agent_ipc::RenderAccessUnit>,
    replacements: u64,
}

impl RenderAccessUnitQueue {
    /// Create a non-empty bounded queue.
    pub fn new(capacity: usize) -> Option<Self> {
        (capacity != 0).then(|| Self {
            capacity,
            units: VecDeque::with_capacity(capacity),
            replacements: 0,
        })
    }

    /// Admit a unit, replacing only the oldest disposable interframe at capacity.
    pub fn push(&mut self, unit: mrd_agent_ipc::RenderAccessUnit) -> QueueAdmission {
        if self.units.len() < self.capacity {
            self.units.push_back(unit);
            return QueueAdmission::Accepted;
        }
        let Some(index) = self.units.iter().position(|queued| !queued.is_keyframe) else {
            return QueueAdmission::Rejected;
        };
        self.units.remove(index);
        self.units.push_back(unit);
        self.replacements = self.replacements.saturating_add(1);
        QueueAdmission::Replaced
    }

    /// Pop the oldest retained unit.
    pub fn pop(&mut self) -> Option<mrd_agent_ipc::RenderAccessUnit> {
        self.units.pop_front()
    }

    /// Number of interframes replaced since queue creation.
    pub fn replacements(&self) -> u64 {
        self.replacements
    }

    fn clear(&mut self) {
        self.units.clear();
    }
}

/// Convert limited-range BT.601 I420 into renderer-native BGRA.
pub fn i420_to_bgra(
    width: usize,
    height: usize,
    y_pitch: usize,
    uv_pitch: usize,
    data: &[u8],
) -> Result<Vec<u8>, FrameConversionError> {
    if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(FrameConversionError::InvalidI420Dimensions);
    }
    let chroma_width = width / 2;
    let chroma_height = height / 2;
    if y_pitch < width || uv_pitch < chroma_width {
        return Err(FrameConversionError::InvalidI420Planes);
    }
    let y_len = y_pitch
        .checked_mul(height)
        .ok_or(FrameConversionError::InvalidI420Planes)?;
    let chroma_len = uv_pitch
        .checked_mul(chroma_height)
        .ok_or(FrameConversionError::InvalidI420Planes)?;
    let u_offset = y_len;
    let v_offset = u_offset
        .checked_add(chroma_len)
        .ok_or(FrameConversionError::InvalidI420Planes)?;
    let required = v_offset
        .checked_add(chroma_len)
        .ok_or(FrameConversionError::InvalidI420Planes)?;
    if data.len() < required {
        return Err(FrameConversionError::InvalidI420Planes);
    }
    let output_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(FrameConversionError::InvalidI420Dimensions)?;
    let mut output = Vec::with_capacity(output_len);
    for row in 0..height {
        for column in 0..width {
            let y = i32::from(data[row * y_pitch + column]);
            let chroma_index = (row / 2) * uv_pitch + column / 2;
            let u = i32::from(data[u_offset + chroma_index]);
            let v = i32::from(data[v_offset + chroma_index]);
            let c = (y - 16).max(0);
            let d = u - 128;
            let e = v - 128;
            let red = ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u8;
            let green = ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u8;
            let blue = ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u8;
            output.extend_from_slice(&[blue, green, red, 255]);
        }
    }
    Ok(output)
}

/// Move renderer-native decoded storage into a D3D11 render frame without
/// relabeling or copying its pixels.
pub fn decoded_frame_to_render_frame(
    frame: DecodedFrame,
) -> Result<RenderFrame, FrameConversionError> {
    let width = frame.width;
    let height = frame.height;
    match frame.data {
        DecodedFrameData::CpuRgb24(data) => Ok(RenderFrame::from_rgb24(width, height, data)),
        DecodedFrameData::CpuBgra32(data) => Ok(RenderFrame::from_bgra32(width, height, data)),
        DecodedFrameData::D3D11SharedNv12 {
            shared_handle_y,
            shared_handle_uv,
            ..
        } => Ok(RenderFrame::from_d3d11_shared_nv12(
            width,
            height,
            shared_handle_y,
            shared_handle_uv,
        )),
        DecodedFrameData::D3D11SharedP010 {
            shared_handle_y,
            shared_handle_uv,
            ..
        } => Ok(RenderFrame::from_d3d11_shared_p010(
            width,
            height,
            shared_handle_y,
            shared_handle_uv,
        )),
        DecodedFrameData::CpuI420 {
            data,
            y_pitch,
            uv_pitch,
        } => Ok(RenderFrame::from_bgra32(
            width,
            height,
            i420_to_bgra(width, height, y_pitch, uv_pitch, &data)?,
        )),
        DecodedFrameData::CpuNv12 { .. } | DecodedFrameData::CpuP010 { .. } => {
            Err(FrameConversionError::CpuYuvRequiresConversion)
        }
    }
}

/// Selected H.264 decoder and the backend that produced it.
pub struct SelectedDecoder {
    backend: &'static str,
    decoder: Box<dyn VideoDecoder>,
}

impl SelectedDecoder {
    /// Backend identifier selected for diagnostics.
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// Consume the selection and return the initialized decoder.
    pub fn into_decoder(self) -> Box<dyn VideoDecoder> {
        self.decoder
    }
}

/// Create the production H.264 decoder, preferring shared-texture NVDEC and
/// falling back to the always-built software decoder.
pub fn create_hybrid_h264_decoder() -> Result<SelectedDecoder, PipelineError> {
    select_h264_decoder(mrd_decode::create_decoder)
}

impl fmt::Debug for SelectedDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedDecoder")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

pub(crate) fn select_h264_decoder<F>(mut create: F) -> Result<SelectedDecoder, PipelineError>
where
    F: FnMut(&str) -> Result<Box<dyn VideoDecoder>, PipelineError>,
{
    match create("nvdec_d3d11_shared") {
        Ok(decoder) => Ok(SelectedDecoder {
            backend: "nvdec_d3d11_shared",
            decoder,
        }),
        Err(hardware_error) => create("h264_software")
            .map(|decoder| SelectedDecoder {
                backend: "h264_software",
                decoder,
            })
            .map_err(|software_error| {
                PipelineError::Message(format!(
                    "H.264 decoder initialization failed: hardware={hardware_error}; software={software_error}"
                ))
            }),
    }
}

/// Factory boundary for one decoder per render worker.
pub trait RenderDecoderFactory: Clone + Send + Sync + 'static {
    /// Whether this factory proved a viable decoder during construction.
    fn is_available(&self) -> bool;
    /// Create a fresh decoder for one exact render resource.
    fn create(&self) -> Result<SelectedDecoder, PipelineError>;
}

/// Factory boundary for one native renderer per render worker.
pub trait AgentRendererFactory: Clone + Send + Sync + 'static {
    /// Whether this factory proved a viable renderer during construction.
    fn is_available(&self) -> bool;
    /// Create a fresh native renderer for one exact render resource.
    fn create(&self) -> Result<BoxedRenderer, RenderError>;
}

/// Cached production hybrid decoder factory.
#[derive(Debug, Clone, Copy)]
pub struct ProductionDecoderFactory {
    available: bool,
}

impl ProductionDecoderFactory {
    fn probe() -> Self {
        Self {
            available: create_hybrid_h264_decoder().is_ok(),
        }
    }
}

impl RenderDecoderFactory for ProductionDecoderFactory {
    fn is_available(&self) -> bool {
        self.available
    }

    fn create(&self) -> Result<SelectedDecoder, PipelineError> {
        create_hybrid_h264_decoder()
    }
}

/// Cached production D3D11 renderer factory.
#[derive(Debug, Clone, Copy)]
pub struct ProductionRendererFactory {
    available: bool,
}

impl ProductionRendererFactory {
    fn probe() -> Self {
        Self {
            available: mrd_render_d3d11::D3d11RendererFactory.create().is_ok(),
        }
    }
}

impl AgentRendererFactory for ProductionRendererFactory {
    fn is_available(&self) -> bool {
        self.available
    }

    fn create(&self) -> Result<BoxedRenderer, RenderError> {
        mrd_render_d3d11::D3d11RendererFactory.create()
    }
}

struct SharedRenderQueue {
    state: Mutex<RenderQueueState>,
    wake: Condvar,
}

struct RenderQueueState {
    queue: RenderAccessUnitQueue,
    stopping: bool,
}

struct RenderWorker {
    session_id: SessionId,
    queue: Arc<SharedRenderQueue>,
    failed: Arc<AtomicBool>,
    decoder_backend: &'static str,
    metrics: Arc<RenderWorkerCounters>,
    join: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct RenderWorkerCounters {
    enqueued_units: AtomicU64,
    queue_replacements: AtomicU64,
    decoded_frames: AtomicU64,
    presented_frames: AtomicU64,
}

/// Point-in-time process-boundary render diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderWorkerMetrics {
    /// Decoder backend selected for this resource.
    pub decoder_backend: &'static str,
    /// Encoded units admitted from agent IPC.
    pub enqueued_units: u64,
    /// Disposable interframes replaced at the bounded queue.
    pub queue_replacements: u64,
    /// Frames emitted by the decoder.
    pub decoded_frames: u64,
    /// Frames accepted by the renderer.
    pub presented_frames: u64,
}

/// Windows resource adapter that owns one decoder/render thread per HWND.
pub struct WindowsRenderAdapter<
    D: RenderDecoderFactory = ProductionDecoderFactory,
    R: AgentRendererFactory = ProductionRendererFactory,
> {
    decoder_factory: D,
    renderer_factory: R,
    queue_capacity: usize,
    workers: HashMap<[u8; 16], RenderWorker>,
}

impl WindowsRenderAdapter<ProductionDecoderFactory, ProductionRendererFactory> {
    /// Probe and construct the production hybrid decoder plus D3D11 adapter.
    pub fn new() -> Self {
        Self::with_factories(
            ProductionDecoderFactory::probe(),
            ProductionRendererFactory::probe(),
            3,
        )
    }
}

impl Default for WindowsRenderAdapter<ProductionDecoderFactory, ProductionRendererFactory> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: RenderDecoderFactory, R: AgentRendererFactory> WindowsRenderAdapter<D, R> {
    /// Construct an adapter from explicit factories and queue bound.
    pub fn with_factories(decoder_factory: D, renderer_factory: R, queue_capacity: usize) -> Self {
        Self {
            decoder_factory,
            renderer_factory,
            queue_capacity,
            workers: HashMap::new(),
        }
    }

    fn stop_worker(mut worker: RenderWorker) -> bool {
        let Ok(mut state) = worker.queue.state.lock() else {
            return false;
        };
        state.stopping = true;
        state.queue.clear();
        worker.queue.wake.notify_all();
        drop(state);
        worker.join.take().is_none_or(|join| join.join().is_ok())
    }

    /// Read counters for one live render worker.
    pub fn metrics(&self, resource_id: &[u8; 16]) -> Option<RenderWorkerMetrics> {
        let worker = self.workers.get(resource_id)?;
        Some(RenderWorkerMetrics {
            decoder_backend: worker.decoder_backend,
            enqueued_units: worker.metrics.enqueued_units.load(Ordering::Acquire),
            queue_replacements: worker.metrics.queue_replacements.load(Ordering::Acquire),
            decoded_frames: worker.metrics.decoded_frames.load(Ordering::Acquire),
            presented_frames: worker.metrics.presented_frames.load(Ordering::Acquire),
        })
    }
}

impl<D: RenderDecoderFactory, R: AgentRendererFactory> RenderAdapter
    for WindowsRenderAdapter<D, R>
{
    fn is_available(&self) -> bool {
        self.queue_capacity != 0
            && self.decoder_factory.is_available()
            && self.renderer_factory.is_available()
    }

    fn metrics(&self) -> Vec<RenderAdapterMetrics> {
        self.workers
            .iter()
            .map(|(resource_id, worker)| RenderAdapterMetrics {
                resource_id: *resource_id,
                session_id: worker.session_id.clone(),
                decoder_backend: worker.decoder_backend.to_owned(),
                enqueued_units: worker.metrics.enqueued_units.load(Ordering::Acquire),
                queue_replacements: worker.metrics.queue_replacements.load(Ordering::Acquire),
                decoded_frames: worker.metrics.decoded_frames.load(Ordering::Acquire),
                presented_frames: worker.metrics.presented_frames.load(Ordering::Acquire),
            })
            .collect()
    }

    fn start(&mut self, resource: &MediaResource, session_id: &SessionId) -> bool {
        if !self.is_available()
            || resource.session_id() != session_id
            || self.workers.contains_key(resource.resource_id())
        {
            return false;
        }
        let Some(surface) = resource.render_surface() else {
            return false;
        };
        let Ok(window_handle) = isize::try_from(surface.window_handle) else {
            return false;
        };
        if window_handle == 0 {
            return false;
        }
        let Some(queue) = RenderAccessUnitQueue::new(self.queue_capacity) else {
            return false;
        };
        let shared = Arc::new(SharedRenderQueue {
            state: Mutex::new(RenderQueueState {
                queue,
                stopping: false,
            }),
            wake: Condvar::new(),
        });
        let failed = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(RenderWorkerCounters::default());
        let thread_queue = Arc::clone(&shared);
        let thread_failed = Arc::clone(&failed);
        let thread_metrics = Arc::clone(&metrics);
        let decoder_factory = self.decoder_factory.clone();
        let renderer_factory = self.renderer_factory.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::Builder::new()
            .name("mrd-agent-d3d11-render".into())
            .spawn(move || {
                let initialized = decoder_factory.create().and_then(|selected| {
                    renderer_factory
                        .create()
                        .map_err(|error| PipelineError::Message(error.to_string()))
                        .and_then(|mut renderer| {
                            renderer
                                .attach_target(RenderTarget::WindowHandle(window_handle))
                                .map_err(|error| PipelineError::Message(error.to_string()))?;
                            Ok((selected, renderer))
                        })
                });
                let Ok((selected, mut renderer)) = initialized else {
                    thread_failed.store(true, Ordering::Release);
                    let _ = ready_tx.send(None);
                    return;
                };
                let backend = selected.backend();
                let mut decoder = selected.into_decoder();
                if ready_tx.send(Some(backend)).is_err() {
                    return;
                }
                loop {
                    let unit = {
                        let Ok(mut state) = thread_queue.state.lock() else {
                            thread_failed.store(true, Ordering::Release);
                            return;
                        };
                        while !state.stopping && state.queue.units.is_empty() {
                            let Ok(next) = thread_queue.wake.wait(state) else {
                                thread_failed.store(true, Ordering::Release);
                                return;
                            };
                            state = next;
                        }
                        if state.stopping {
                            return;
                        }
                        state.queue.pop()
                    };
                    let Some(unit) = unit else {
                        continue;
                    };
                    if decoder.push_access_unit(&unit.payload).is_err() {
                        thread_failed.store(true, Ordering::Release);
                        return;
                    }
                    for frame in decoder.drain_decoded_frames() {
                        thread_metrics.decoded_frames.fetch_add(1, Ordering::AcqRel);
                        let Ok(frame) = decoded_frame_to_render_frame(frame) else {
                            thread_failed.store(true, Ordering::Release);
                            return;
                        };
                        if renderer.upload_frame(frame).is_err() {
                            thread_failed.store(true, Ordering::Release);
                            return;
                        }
                        thread_metrics
                            .presented_frames
                            .fetch_add(1, Ordering::AcqRel);
                    }
                }
            });
        let Ok(join) = join else {
            return false;
        };
        let Ok(Some(decoder_backend)) = ready_rx.recv() else {
            let _ = join.join();
            return false;
        };
        self.workers.insert(
            *resource.resource_id(),
            RenderWorker {
                session_id: session_id.clone(),
                queue: shared,
                failed,
                decoder_backend,
                metrics,
                join: Some(join),
            },
        );
        true
    }

    fn push_access_unit(&mut self, resource: &MediaResource, unit: &RenderAccessUnit) -> bool {
        if unit.codec != MediaCodec::H264
            || unit.resource_id != *resource.resource_id()
            || unit.session_id != resource.session_id().0
        {
            return false;
        }
        let Some(worker) = self.workers.get(resource.resource_id()) else {
            return false;
        };
        if worker.session_id != *resource.session_id() || worker.failed.load(Ordering::Acquire) {
            return false;
        }
        let Ok(mut state) = worker.queue.state.lock() else {
            return false;
        };
        if state.stopping {
            return false;
        }
        let admission = state.queue.push(unit.clone());
        if admission == QueueAdmission::Rejected {
            return false;
        }
        worker.metrics.enqueued_units.fetch_add(1, Ordering::AcqRel);
        if admission == QueueAdmission::Replaced {
            worker
                .metrics
                .queue_replacements
                .fetch_add(1, Ordering::AcqRel);
        }
        worker.queue.wake.notify_one();
        true
    }

    fn stop(&mut self, resource_id: &[u8; 16], session_id: &SessionId) -> bool {
        if self
            .workers
            .get(resource_id)
            .is_none_or(|worker| worker.session_id != *session_id)
        {
            return false;
        }
        self.workers
            .remove(resource_id)
            .is_some_and(Self::stop_worker)
    }
}

impl<D: RenderDecoderFactory, R: AgentRendererFactory> Drop for WindowsRenderAdapter<D, R> {
    fn drop(&mut self) {
        for worker in self.workers.drain().map(|(_, worker)| worker) {
            let _ = Self::stop_worker(worker);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        media::{MediaResourceKind, MediaResourceMutation, MediaResourceRegistry},
        render::RenderAdapter,
    };
    use mrd_agent_ipc::{MediaCodec, RenderAccessUnit};
    use mrd_pipeline_core::{DecodedFrame, DecodedFrameData, PipelineError, VideoDecoder};
    use mrd_proto::SessionId;
    use mrd_render::{
        BoxedRenderer, RenderError, RenderFrame, RenderFrameData, RenderPixelFormat, RenderTarget,
        RendererInstance, RendererSnapshot,
    };
    use std::sync::{Arc, Condvar, Mutex};

    fn unit(sequence: u64, keyframe: bool) -> RenderAccessUnit {
        RenderAccessUnit {
            resource_id: [7; 16],
            session_id: "session-7".into(),
            sequence,
            timestamp_us: sequence * 10,
            codec: MediaCodec::H264,
            is_keyframe: keyframe,
            payload: vec![sequence as u8],
        }
    }

    #[test]
    fn decoded_frame_conversion_preserves_renderer_native_formats() {
        let rgb = DecodedFrame::from_cpu_rgb24(2, 1, 7, vec![1, 2, 3, 4, 5, 6]);
        let converted = super::decoded_frame_to_render_frame(rgb).expect("RGB24 conversion");
        assert_eq!(converted.pixel_format, RenderPixelFormat::Rgb24);
        assert_eq!(
            converted.data,
            RenderFrameData::Rgb24(vec![1, 2, 3, 4, 5, 6])
        );

        let bgra = DecodedFrame::from_cpu_bgra32(1, 1, 8, vec![1, 2, 3, 4]);
        let converted = super::decoded_frame_to_render_frame(bgra).expect("BGRA conversion");
        assert_eq!(converted.pixel_format, RenderPixelFormat::Bgra32);
        assert_eq!(converted.data, RenderFrameData::Bgra32(vec![1, 2, 3, 4]));

        let shared = DecodedFrame {
            width: 4,
            height: 2,
            timestamp_us: 9,
            data: DecodedFrameData::D3D11SharedNv12 {
                shared_handle_y: 11,
                shared_handle_uv: 12,
                width: 4,
                height: 2,
            },
        };
        let converted = super::decoded_frame_to_render_frame(shared).expect("shared NV12");
        assert_eq!(converted.pixel_format, RenderPixelFormat::D3D11SharedNv12);
        assert!(matches!(
            converted.data,
            RenderFrameData::D3D11SharedNv12 {
                shared_handle_y: 11,
                shared_handle_uv: 12,
                width: 4,
                height: 2,
            }
        ));

        let shared = DecodedFrame {
            width: 4,
            height: 2,
            timestamp_us: 10,
            data: DecodedFrameData::D3D11SharedP010 {
                shared_handle_y: 21,
                shared_handle_uv: 22,
                width: 4,
                height: 2,
            },
        };
        let converted = super::decoded_frame_to_render_frame(shared).expect("shared P010");
        assert_eq!(converted.pixel_format, RenderPixelFormat::D3D11SharedP010);
    }

    #[test]
    fn decoded_frame_conversion_converts_i420_and_rejects_other_cpu_yuv() {
        let i420 = DecodedFrame::from_cpu_i420(2, 2, 1, 2, 1, vec![16, 16, 16, 16, 128, 128]);
        let converted = super::decoded_frame_to_render_frame(i420).expect("I420 conversion");
        assert_eq!(
            converted.data,
            RenderFrameData::Bgra32([0, 0, 0, 255].repeat(4))
        );

        let nv12 = DecodedFrame::from_cpu_nv12(2, 2, 1, 2, vec![0; 6]);
        assert!(super::decoded_frame_to_render_frame(nv12).is_err());
    }

    struct EmptyDecoder;

    impl VideoDecoder for EmptyDecoder {
        fn push_access_unit(&mut self, _access_unit: &[u8]) -> Result<(), PipelineError> {
            Ok(())
        }

        fn drain_decoded_frames(&mut self) -> Vec<DecodedFrame> {
            Vec::new()
        }
    }

    #[derive(Clone)]
    struct FrameDecoderFactory;

    impl super::RenderDecoderFactory for FrameDecoderFactory {
        fn is_available(&self) -> bool {
            true
        }

        fn create(&self) -> Result<super::SelectedDecoder, PipelineError> {
            Ok(super::SelectedDecoder {
                backend: "test_decoder",
                decoder: Box::new(FrameDecoder { frames: Vec::new() }),
            })
        }
    }

    struct FrameDecoder {
        frames: Vec<DecodedFrame>,
    }

    impl VideoDecoder for FrameDecoder {
        fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
            self.frames.push(DecodedFrame::from_cpu_rgb24(
                1,
                1,
                0,
                vec![access_unit[0], 2, 3],
            ));
            Ok(())
        }

        fn drain_decoded_frames(&mut self) -> Vec<DecodedFrame> {
            std::mem::take(&mut self.frames)
        }
    }

    #[derive(Default)]
    struct RenderObservation {
        target: Option<isize>,
        frames: Vec<RenderFrame>,
    }

    #[derive(Clone)]
    struct RecordingRendererFactory {
        observation: Arc<(Mutex<RenderObservation>, Condvar)>,
    }

    impl super::AgentRendererFactory for RecordingRendererFactory {
        fn is_available(&self) -> bool {
            true
        }

        fn create(&self) -> Result<BoxedRenderer, RenderError> {
            Ok(Box::new(RecordingRenderer {
                observation: Arc::clone(&self.observation),
            }))
        }
    }

    struct RecordingRenderer {
        observation: Arc<(Mutex<RenderObservation>, Condvar)>,
    }

    impl RendererInstance for RecordingRenderer {
        fn attach_target(&mut self, target: RenderTarget) -> Result<(), RenderError> {
            let RenderTarget::WindowHandle(handle) = target;
            self.observation.0.lock().unwrap().target = Some(handle);
            Ok(())
        }

        fn upload_frame(&mut self, frame: RenderFrame) -> Result<(), RenderError> {
            let mut observation = self.observation.0.lock().unwrap();
            observation.frames.push(frame);
            self.observation.1.notify_all();
            Ok(())
        }

        fn snapshot(&self) -> RendererSnapshot {
            panic!("snapshot is not used by this adapter test")
        }
    }

    fn render_resource() -> (MediaResourceRegistry, SessionId, [u8; 16]) {
        let session_id = SessionId("session-7".into());
        let resource_id = [7; 16];
        let mut registry = MediaResourceRegistry::new();
        assert_eq!(
            registry.start(
                resource_id,
                session_id.clone(),
                0,
                MediaResourceKind::Render,
                Some(mrd_agent_ipc::RenderSurfaceTarget {
                    surface_id: "surface-7".into(),
                    window_handle: 0x1234,
                }),
            ),
            MediaResourceMutation::Started
        );
        (registry, session_id, resource_id)
    }

    #[test]
    fn render_worker_attaches_exact_hwnd_presents_and_stops_exact_resource() {
        let observation = Arc::new((Mutex::new(RenderObservation::default()), Condvar::new()));
        let mut adapter = super::WindowsRenderAdapter::with_factories(
            FrameDecoderFactory,
            RecordingRendererFactory {
                observation: Arc::clone(&observation),
            },
            2,
        );
        let (registry, session_id, resource_id) = render_resource();
        let resource = registry.get(&resource_id).unwrap();

        assert!(adapter.is_available());
        assert!(adapter.start(resource, &session_id));
        assert!(adapter.push_access_unit(resource, &unit(1, true)));

        let observed = observation
            .1
            .wait_timeout_while(
                observation.0.lock().unwrap(),
                std::time::Duration::from_secs(1),
                |state| state.frames.is_empty(),
            )
            .unwrap()
            .0;
        assert_eq!(observed.target, Some(0x1234));
        assert_eq!(observed.frames.len(), 1);
        assert_eq!(
            observed.frames[0].data,
            RenderFrameData::Rgb24(vec![1, 2, 3])
        );
        drop(observed);

        let metrics = adapter.metrics(&resource_id).expect("live worker metrics");
        assert_eq!(metrics.decoder_backend, "test_decoder");
        assert_eq!(metrics.enqueued_units, 1);
        assert_eq!(metrics.decoded_frames, 1);
        assert_eq!(metrics.presented_frames, 1);

        assert!(!adapter.stop(&resource_id, &SessionId("other".into())));
        assert!(adapter.stop(&resource_id, &session_id));
        assert!(!adapter.push_access_unit(resource, &unit(2, false)));
    }

    #[test]
    fn hybrid_decoder_prefers_shared_nvdec_and_falls_back_to_software() {
        let mut attempts = Vec::new();
        let selected = super::select_h264_decoder(|id| {
            attempts.push(id.to_owned());
            Ok(Box::new(EmptyDecoder) as Box<dyn VideoDecoder>)
        })
        .expect("hardware decoder");
        assert_eq!(attempts, ["nvdec_d3d11_shared"]);
        assert_eq!(selected.backend(), "nvdec_d3d11_shared");

        let mut attempts = Vec::new();
        let selected = super::select_h264_decoder(|id| {
            attempts.push(id.to_owned());
            if id == "nvdec_d3d11_shared" {
                Err(PipelineError::Message("no NVIDIA device".into()))
            } else {
                Ok(Box::new(EmptyDecoder) as Box<dyn VideoDecoder>)
            }
        })
        .expect("software fallback");
        assert_eq!(attempts, ["nvdec_d3d11_shared", "h264_software"]);
        assert_eq!(selected.backend(), "h264_software");
    }

    #[test]
    fn hybrid_decoder_is_unavailable_when_both_backends_fail() {
        let mut attempts = Vec::new();
        let error = super::select_h264_decoder(|id| {
            attempts.push(id.to_owned());
            Err(PipelineError::Message(format!("{id} unavailable")))
        })
        .expect_err("both backends must fail");
        assert_eq!(attempts, ["nvdec_d3d11_shared", "h264_software"]);
        assert!(error.to_string().contains("h264_software unavailable"));
    }

    #[test]
    fn software_i420_conversion_validates_planes_and_outputs_bgra() {
        let black =
            super::i420_to_bgra(2, 2, 2, 1, &[16, 16, 16, 16, 128, 128]).expect("valid I420");
        assert_eq!(black, [0, 0, 0, 255].repeat(4));

        assert!(super::i420_to_bgra(0, 2, 2, 1, &[]).is_err());
        assert!(super::i420_to_bgra(3, 2, 3, 2, &[0; 10]).is_err());
        assert!(super::i420_to_bgra(2, 2, 1, 1, &[0; 6]).is_err());
        assert!(super::i420_to_bgra(2, 2, 2, 1, &[0; 5]).is_err());
    }

    #[test]
    fn bounded_render_queue_replaces_only_disposable_interframes() {
        let mut queue = super::RenderAccessUnitQueue::new(2).expect("bounded queue");
        assert_eq!(queue.push(unit(1, true)), super::QueueAdmission::Accepted);
        assert_eq!(queue.push(unit(2, false)), super::QueueAdmission::Accepted);
        assert_eq!(queue.push(unit(3, false)), super::QueueAdmission::Replaced);
        assert_eq!(queue.replacements(), 1);
        assert_eq!(queue.pop().unwrap().sequence, 1);
        assert_eq!(queue.pop().unwrap().sequence, 3);

        assert_eq!(queue.push(unit(4, true)), super::QueueAdmission::Accepted);
        assert_eq!(queue.push(unit(5, true)), super::QueueAdmission::Accepted);
        assert_eq!(queue.push(unit(6, false)), super::QueueAdmission::Rejected);
        assert_eq!(queue.pop().unwrap().sequence, 4);
        assert_eq!(queue.pop().unwrap().sequence, 5);
    }
}
