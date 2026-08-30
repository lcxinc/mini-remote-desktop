use mrd_ipc::{
    AgentRenderBoundarySnapshot, AttachedRenderSurface, MediaAdaptationSnapshot,
    MediaPipelineSnapshot, MediaProfile, MediaSenderTransportSnapshot, MediaStageMetrics,
    MediaTestImpairmentSnapshot,
};
use mrd_proto::SessionId;
#[cfg(any(windows, target_os = "macos"))]
use mrd_render::RendererSnapshot;
use std::collections::{HashMap, VecDeque};

const MEDIA_STAGE_SAMPLE_LIMIT: usize = 240;

/// Role-specific WAN media runtime owned by one authenticated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanMediaRuntimeRole {
    /// Captures and encodes the local target desktop for the controller.
    TargetSender,
    /// Receives, decodes, and hands frames to the controller render boundary.
    ControllerReceiver,
}

/// Internal readiness and ownership evidence for an active WAN media runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanMediaRuntimeSnapshot {
    /// Installed relay generation used by the runtime.
    pub generation: u64,
    /// Role-specific direction of the runtime.
    pub role: WanMediaRuntimeRole,
    /// Number of service-owned tasks registered for this runtime.
    pub owned_tasks: usize,
    /// Whether real media evidence has crossed the codec/mux boundary.
    pub ready: bool,
    /// First envelope sequence that established readiness.
    pub ready_sequence: Option<u64>,
}

/// Runtime receiver media pipeline state keyed by session.
#[derive(Debug, Default)]
pub struct MediaPipelineRegistry {
    pipelines: HashMap<SessionId, MediaPipelineState>,
    cumulative_sender_packets_sent: u64,
    cumulative_render_presented_frames: u64,
}

#[derive(Debug, Clone, Default)]
struct MediaPipelineState {
    wan_media_runtime: Option<WanMediaRuntimeSnapshot>,
    attached_surfaces: HashMap<String, AttachedRenderSurface>,
    active_encoder: Option<String>,
    active_decoder: Option<String>,
    active_renderer: Option<String>,
    active_codec: Option<String>,
    active_codec_profile: Option<String>,
    active_bit_depth: Option<u8>,
    active_chroma_subsampling: Option<String>,
    active_pixel_format: Option<String>,
    active_hdr_enabled: Option<bool>,
    active_color_mode: Option<String>,
    active_color_pipeline: Option<String>,
    active_width: Option<u32>,
    active_height: Option<u32>,
    active_fps: Option<u32>,
    active_bitrate_mbps: Option<u32>,
    codec_fallback_reason: Option<String>,
    queue_depth: u32,
    dropped_frames: u64,
    render_presented_frames: u64,
    render_queue_replacements: u64,
    render_stale_frame_drops: u64,
    render_lock_drops: u64,
    render_present_skips: u64,
    render_pacing_target_fps: Option<u32>,
    render_queue_policy: Option<String>,
    swap_chain_max_frame_latency: Option<u32>,
    swap_chain_allow_tearing: Option<bool>,
    swap_chain_waitable_object: Option<bool>,
    swap_chain_present_mode: Option<String>,
    display_refresh_hz: Option<u32>,
    render_thread_priority: Option<String>,
    render_waitable_timeouts: u64,
    agent_render_boundary: Option<AgentRenderBoundarySnapshot>,
    reliable_hol_recoveries: u64,
    estimated_frame_age_baseline_ms: Option<f64>,
    stage_samples: HashMap<String, VecDeque<f64>>,
    stage_summaries: HashMap<String, MediaStageMetrics>,
    test_impairment: Option<MediaTestImpairmentSnapshot>,
    sender_transport: MediaSenderTransportSnapshot,
    adaptation: Option<MediaAdaptationSnapshot>,
}

impl MediaPipelineRegistry {
    /// Reserve one pipeline entry for a role-specific WAN media runtime.
    ///
    /// Returns `false` when a runtime already owns the session, preventing a
    /// duplicate activation from replacing live task/readiness evidence.
    pub fn begin_wan_media_runtime(
        &mut self,
        session_id: SessionId,
        generation: u64,
        role: WanMediaRuntimeRole,
        owned_tasks: usize,
    ) -> bool {
        let state = self.pipelines.entry(session_id).or_default();
        if state.wan_media_runtime.is_some() {
            return false;
        }
        state.wan_media_runtime = Some(WanMediaRuntimeSnapshot {
            generation,
            role,
            owned_tasks,
            ready: false,
            ready_sequence: None,
        });
        true
    }

    /// Publish first-frame readiness for the exact installed WAN generation.
    pub fn mark_wan_media_ready(
        &mut self,
        session_id: &SessionId,
        generation: u64,
        role: WanMediaRuntimeRole,
        sequence: u64,
    ) -> bool {
        let Some(runtime) = self
            .pipelines
            .get_mut(session_id)
            .and_then(|state| state.wan_media_runtime.as_mut())
        else {
            return false;
        };
        if runtime.generation != generation || runtime.role != role {
            return false;
        }
        if !runtime.ready {
            runtime.ready = true;
            runtime.ready_sequence = Some(sequence);
        }
        true
    }

    /// Return the current WAN media ownership/readiness evidence.
    pub fn wan_media_runtime(&self, session_id: &SessionId) -> Option<WanMediaRuntimeSnapshot> {
        self.pipelines
            .get(session_id)
            .and_then(|state| state.wan_media_runtime.clone())
    }

    pub fn attach_surface(&mut self, session_id: SessionId, surface: AttachedRenderSurface) {
        let session_id_label = session_id.0.clone();
        let surface_id = surface.surface_id.clone();
        let backend = surface.backend.clone();
        let state = self.pipelines.entry(session_id).or_default();
        if state.active_renderer.is_none() {
            state.active_renderer = Some(surface.backend.clone());
        }
        let replaced = state
            .attached_surfaces
            .insert(surface.surface_id.clone(), surface)
            .is_some();
        tracing::info!(
            session_id = %session_id_label,
            surface_id = %surface_id,
            backend = %backend,
            replaced,
            attached_surface_count = state.attached_surfaces.len(),
            "render-surface pipeline attach"
        );
    }

    pub fn detach_surface(&mut self, session_id: &SessionId, surface_id: &str) -> bool {
        let Some(state) = self.pipelines.get_mut(session_id) else {
            tracing::info!(
                session_id = %session_id.0,
                surface_id = %surface_id,
                "render-surface pipeline detach skipped: missing pipeline"
            );
            return false;
        };
        let removed = state.attached_surfaces.remove(surface_id).is_some();
        if state.attached_surfaces.is_empty() {
            state.active_renderer = None;
        }
        tracing::info!(
            session_id = %session_id.0,
            surface_id = %surface_id,
            removed,
            attached_surface_count = state.attached_surfaces.len(),
            "render-surface pipeline detach"
        );
        removed
    }

    pub fn set_active_decoder(&mut self, session_id: SessionId, decoder: impl Into<String>) {
        self.pipelines.entry(session_id).or_default().active_decoder = Some(decoder.into());
    }

    pub fn set_active_encoder(&mut self, session_id: SessionId, encoder: impl Into<String>) {
        self.pipelines.entry(session_id).or_default().active_encoder = Some(encoder.into());
    }

    pub fn set_active_media_profile(&mut self, session_id: SessionId, profile: &MediaProfile) {
        let state = self.pipelines.entry(session_id).or_default();
        set_active_media_profile(state, profile);
    }

    pub fn record_active_media_sample(
        &mut self,
        session_id: SessionId,
        profile: &MediaProfile,
        width: u32,
        height: u32,
        pixel_format: impl Into<String>,
    ) {
        let state = self.pipelines.entry(session_id).or_default();
        set_active_media_profile(state, profile);
        state.active_width = Some(width);
        state.active_height = Some(height);
        state.active_pixel_format = Some(pixel_format.into());
    }

    /// Record a decoded-frame sample and its format stage with one pipeline lookup.
    pub fn record_decoded_media_sample(
        &mut self,
        session_id: SessionId,
        profile: &MediaProfile,
        width: u32,
        height: u32,
        pixel_format: &'static str,
        format_stage: &'static str,
    ) {
        let state = self.pipelines.entry(session_id).or_default();
        set_active_media_profile(state, profile);
        state.active_width = Some(width);
        state.active_height = Some(height);
        set_active_string(&mut state.active_pixel_format, pixel_format);
        record_static_stage_sample(state, format_stage, 1.0);
    }

    pub fn set_codec_fallback_reason(&mut self, session_id: SessionId, reason: Option<String>) {
        self.pipelines
            .entry(session_id)
            .or_default()
            .codec_fallback_reason = reason;
    }

    pub fn record_queue_depth(&mut self, session_id: SessionId, queue_depth: u32) {
        self.pipelines.entry(session_id).or_default().queue_depth = queue_depth;
    }

    pub fn increment_dropped_frames(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.dropped_frames = state.dropped_frames.saturating_add(count);
    }

    pub fn increment_render_presented_frames(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_presented_frames = state.render_presented_frames.saturating_add(count);
        self.cumulative_render_presented_frames = self
            .cumulative_render_presented_frames
            .saturating_add(count);
    }

    pub fn increment_render_queue_replacements(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_queue_replacements = state.render_queue_replacements.saturating_add(count);
        state.dropped_frames = state.dropped_frames.saturating_add(count);
    }

    pub fn record_render_queue_replacements(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_queue_replacements = state.render_queue_replacements.saturating_add(count);
    }

    pub fn increment_render_stale_frame_drops(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_stale_frame_drops = state.render_stale_frame_drops.saturating_add(count);
        state.dropped_frames = state.dropped_frames.saturating_add(count);
    }

    pub fn increment_render_lock_drops(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_lock_drops = state.render_lock_drops.saturating_add(count);
        state.dropped_frames = state.dropped_frames.saturating_add(count);
    }

    pub fn increment_render_present_skips(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_present_skips = state.render_present_skips.saturating_add(count);
        state.dropped_frames = state.dropped_frames.saturating_add(count);
    }

    pub fn set_render_pacing_target_fps(&mut self, session_id: SessionId, fps: Option<u32>) {
        self.pipelines
            .entry(session_id)
            .or_default()
            .render_pacing_target_fps = fps;
    }

    pub fn set_render_queue_policy(
        &mut self,
        session_id: SessionId,
        policy: Option<impl Into<String>>,
    ) {
        self.pipelines
            .entry(session_id)
            .or_default()
            .render_queue_policy = policy.map(Into::into);
    }

    #[cfg(any(windows, target_os = "macos"))]
    pub fn record_renderer_snapshot(&mut self, session_id: SessionId, snapshot: &RendererSnapshot) {
        let state = self.pipelines.entry(session_id).or_default();
        state.swap_chain_max_frame_latency = snapshot.swap_chain_max_frame_latency;
        state.swap_chain_allow_tearing = snapshot.swap_chain_allow_tearing;
        state.swap_chain_waitable_object = snapshot.swap_chain_waitable_object;
        state.swap_chain_present_mode = snapshot.swap_chain_present_mode.clone();
        state.display_refresh_hz = snapshot.display_refresh_hz;
        state.render_thread_priority = snapshot.render_thread_priority.clone();
    }

    pub fn increment_render_waitable_timeouts(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.render_waitable_timeouts = state.render_waitable_timeouts.saturating_add(count);
    }

    pub fn increment_reliable_hol_recoveries(&mut self, session_id: SessionId, count: u64) {
        let state = self.pipelines.entry(session_id).or_default();
        state.reliable_hol_recoveries = state.reliable_hol_recoveries.saturating_add(count);
    }

    /// Records both the wall-clock frame-age estimate and its excess over the
    /// best value observed in this session. The absolute estimate includes
    /// sender/receiver clock skew; the relative value removes that stable
    /// offset and is therefore the useful cross-device queue/jitter signal.
    pub fn record_estimated_frame_age_ms(&mut self, session_id: SessionId, frame_age_ms: f64) {
        if !frame_age_ms.is_finite() || frame_age_ms < 0.0 {
            return;
        }
        let state = self.pipelines.entry(session_id).or_default();
        let baseline_ms = state
            .estimated_frame_age_baseline_ms
            .map_or(frame_age_ms, |baseline| baseline.min(frame_age_ms));
        state.estimated_frame_age_baseline_ms = Some(baseline_ms);
        record_stage_sample(state, "receiver.estimated_frame_age", frame_age_ms);
        record_stage_sample(
            state,
            "receiver.relative_frame_age",
            (frame_age_ms - baseline_ms).max(0.0),
        );
    }

    pub fn record_stage_duration_ms(
        &mut self,
        session_id: SessionId,
        stage: impl Into<String>,
        duration_ms: f64,
    ) {
        if !duration_ms.is_finite() || duration_ms < 0.0 {
            return;
        }
        let state = self.pipelines.entry(session_id).or_default();
        record_stage_sample(state, stage, duration_ms);
    }

    pub fn set_stage_metrics(
        &mut self,
        session_id: SessionId,
        metrics: impl IntoIterator<Item = MediaStageMetrics>,
    ) {
        let state = self.pipelines.entry(session_id).or_default();
        for metric in metrics {
            state.stage_summaries.insert(metric.stage.clone(), metric);
        }
    }

    pub fn set_test_impairment(
        &mut self,
        session_id: SessionId,
        impairment: Option<MediaTestImpairmentSnapshot>,
    ) {
        self.pipelines
            .entry(session_id)
            .or_default()
            .test_impairment = impairment;
    }

    pub fn set_sender_transport(
        &mut self,
        session_id: SessionId,
        transport: MediaSenderTransportSnapshot,
    ) {
        let next_packets = sender_packets_sent(&transport);
        let packet_delta = {
            let state = self.pipelines.entry(session_id).or_default();
            let previous_packets = sender_packets_sent(&state.sender_transport);
            state.sender_transport = transport;
            if next_packets >= previous_packets {
                next_packets - previous_packets
            } else {
                next_packets
            }
        };
        self.cumulative_sender_packets_sent = self
            .cumulative_sender_packets_sent
            .saturating_add(packet_delta);
    }

    /// Apply the latest authenticated cumulative Session Agent render counters.
    pub fn set_agent_render_boundary(
        &mut self,
        session_id: SessionId,
        metrics: mrd_agent_ipc::RenderBoundaryMetrics,
    ) {
        let state = self.pipelines.entry(session_id).or_default();
        state.active_decoder = Some(metrics.decoder_backend.clone());
        state.active_renderer = Some("session_agent_d3d11".to_owned());
        state.queue_depth = u32::try_from(
            metrics
                .enqueued_units
                .saturating_sub(metrics.decoded_frames),
        )
        .unwrap_or(u32::MAX);
        state.render_presented_frames = metrics.presented_frames;
        state.render_queue_replacements = metrics.queue_replacements;
        state.agent_render_boundary = Some(AgentRenderBoundarySnapshot {
            resource_id: metrics.resource_id,
            decoder_backend: metrics.decoder_backend,
            enqueued_units: metrics.enqueued_units,
            queue_replacements: metrics.queue_replacements,
            decoded_frames: metrics.decoded_frames,
            presented_frames: metrics.presented_frames,
        });
    }

    pub fn cumulative_sender_packets_sent(&self) -> u64 {
        self.cumulative_sender_packets_sent
    }

    pub fn cumulative_render_presented_frames(&self) -> u64 {
        self.cumulative_render_presented_frames
    }

    pub fn set_adaptation(
        &mut self,
        session_id: SessionId,
        adaptation: Option<MediaAdaptationSnapshot>,
    ) {
        self.pipelines.entry(session_id).or_default().adaptation = adaptation;
    }

    pub fn adaptation(&self, session_id: &SessionId) -> Option<MediaAdaptationSnapshot> {
        self.pipelines
            .get(session_id)
            .and_then(|state| state.adaptation.clone())
    }

    pub fn snapshot(&self, session_id: &SessionId) -> MediaPipelineSnapshot {
        let state = self.pipelines.get(session_id);
        let stage_metrics = state.map(media_pipeline_stage_metrics).unwrap_or_default();
        MediaPipelineSnapshot {
            session_id: session_id.clone(),
            attached_surfaces: state
                .map(|state| state.attached_surfaces.values().cloned().collect())
                .unwrap_or_default(),
            active_encoder: state.and_then(|state| state.active_encoder.clone()),
            active_decoder: state.and_then(|state| state.active_decoder.clone()),
            active_renderer: state.and_then(|state| state.active_renderer.clone()),
            active_codec: state.and_then(|state| state.active_codec.clone()),
            active_codec_profile: state.and_then(|state| state.active_codec_profile.clone()),
            active_bit_depth: state.and_then(|state| state.active_bit_depth),
            active_chroma_subsampling: state
                .and_then(|state| state.active_chroma_subsampling.clone()),
            active_pixel_format: state.and_then(|state| state.active_pixel_format.clone()),
            active_hdr_enabled: state.and_then(|state| state.active_hdr_enabled),
            active_color_mode: state.and_then(|state| state.active_color_mode.clone()),
            active_color_pipeline: state.and_then(|state| state.active_color_pipeline.clone()),
            active_width: state.and_then(|state| state.active_width),
            active_height: state.and_then(|state| state.active_height),
            active_fps: state.and_then(|state| state.active_fps),
            active_bitrate_mbps: state.and_then(|state| state.active_bitrate_mbps),
            codec_fallback_reason: state.and_then(|state| state.codec_fallback_reason.clone()),
            queue_depth: state.map_or(0, |state| state.queue_depth),
            dropped_frames: state.map_or(0, |state| state.dropped_frames),
            render_presented_frames: state.map_or(0, |state| state.render_presented_frames),
            render_queue_replacements: state.map_or(0, |state| state.render_queue_replacements),
            render_stale_frame_drops: state.map_or(0, |state| state.render_stale_frame_drops),
            render_lock_drops: state.map_or(0, |state| state.render_lock_drops),
            render_present_skips: state.map_or(0, |state| state.render_present_skips),
            render_pacing_target_fps: state.and_then(|state| state.render_pacing_target_fps),
            render_queue_policy: state.and_then(|state| state.render_queue_policy.clone()),
            swap_chain_max_frame_latency: state
                .and_then(|state| state.swap_chain_max_frame_latency),
            swap_chain_allow_tearing: state.and_then(|state| state.swap_chain_allow_tearing),
            swap_chain_waitable_object: state.and_then(|state| state.swap_chain_waitable_object),
            swap_chain_present_mode: state.and_then(|state| state.swap_chain_present_mode.clone()),
            display_refresh_hz: state.and_then(|state| state.display_refresh_hz),
            render_thread_priority: state.and_then(|state| state.render_thread_priority.clone()),
            render_waitable_timeouts: state.map_or(0, |state| state.render_waitable_timeouts),
            agent_render_boundary: state.and_then(|state| state.agent_render_boundary.clone()),
            reliable_hol_recoveries: state.map_or(0, |state| state.reliable_hol_recoveries),
            stage_metrics,
            test_impairment: state.and_then(|state| state.test_impairment.clone()),
            sender_transport: state
                .map(|state| state.sender_transport.clone())
                .unwrap_or_default(),
            adaptation: state.and_then(|state| state.adaptation.clone()),
        }
    }

    pub fn remove(&mut self, session_id: &SessionId) {
        self.pipelines.remove(session_id);
    }
}

fn sender_packets_sent(snapshot: &MediaSenderTransportSnapshot) -> u64 {
    snapshot
        .datagram_fragments_sent
        .saturating_add(snapshot.reliable_fragments_sent)
}

fn set_active_media_profile(state: &mut MediaPipelineState, profile: &MediaProfile) {
    set_active_string(&mut state.active_codec, &profile.codec);
    set_optional_string(&mut state.active_codec_profile, &profile.codec_profile);
    state.active_bit_depth = profile.bit_depth;
    set_optional_string(
        &mut state.active_chroma_subsampling,
        &profile.chroma_subsampling,
    );
    set_optional_string(&mut state.active_pixel_format, &profile.pixel_format);
    state.active_hdr_enabled = profile.hdr_enabled;
    set_optional_string(&mut state.active_color_mode, &profile.color_mode);
    set_optional_string(&mut state.active_color_pipeline, &profile.color_pipeline);
    state.active_width = Some(profile.width);
    state.active_height = Some(profile.height);
    state.active_fps = Some(profile.fps);
    state.active_bitrate_mbps = Some(profile.bitrate_mbps);
}

fn set_active_string(destination: &mut Option<String>, value: &str) {
    if destination.as_deref() != Some(value) {
        *destination = Some(value.to_owned());
    }
}

fn set_optional_string(destination: &mut Option<String>, value: &Option<String>) {
    if destination.as_ref() != value.as_ref() {
        *destination = value.clone();
    }
}

fn record_stage_sample(state: &mut MediaPipelineState, stage: impl Into<String>, duration_ms: f64) {
    let samples = state.stage_samples.entry(stage.into()).or_default();
    samples.push_back(duration_ms);
    while samples.len() > MEDIA_STAGE_SAMPLE_LIMIT {
        samples.pop_front();
    }
}

fn record_static_stage_sample(
    state: &mut MediaPipelineState,
    stage: &'static str,
    duration_ms: f64,
) {
    if let Some(samples) = state.stage_samples.get_mut(stage) {
        samples.push_back(duration_ms);
        while samples.len() > MEDIA_STAGE_SAMPLE_LIMIT {
            samples.pop_front();
        }
        return;
    }

    state
        .stage_samples
        .insert(stage.to_owned(), VecDeque::from([duration_ms]));
}

fn media_pipeline_stage_metrics(state: &MediaPipelineState) -> Vec<MediaStageMetrics> {
    let mut metrics = state.stage_summaries.clone();
    for (stage, samples) in &state.stage_samples {
        metrics.insert(
            stage.clone(),
            MediaStageMetrics {
                stage: stage.clone(),
                p50_ms: percentile(samples, 0.50),
                p95_ms: percentile(samples, 0.95),
                p99_ms: percentile(samples, 0.99),
                max_ms: percentile(samples, 1.0),
                sample_count: Some(samples.len().min(u32::MAX as usize) as u32),
            },
        );
    }

    let mut metrics = metrics.into_values().collect::<Vec<_>>();
    metrics.sort_by(|left, right| left.stage.cmp(&right.stage));
    metrics
}

fn percentile(samples: &VecDeque<f64>, quantile: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.iter().copied().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let last = sorted.len().saturating_sub(1);
    let index = ((last as f64) * quantile.clamp(0.0, 1.0)).round() as usize;
    sorted.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_proto::SessionId;

    #[test]
    fn stage_metrics_keep_sliding_window_and_sorted_snapshot() {
        let mut registry = MediaPipelineRegistry::default();
        let session_id = SessionId("pipeline-stage-window-session".to_string());

        for index in 0..260 {
            registry.record_stage_duration_ms(session_id.clone(), "sender.capture", index as f64);
        }
        registry.record_stage_duration_ms(session_id.clone(), "receiver.decode", 2.0);

        let snapshot = registry.snapshot(&session_id);
        let stages = snapshot
            .stage_metrics
            .iter()
            .map(|metric| metric.stage.as_str())
            .collect::<Vec<_>>();

        assert_eq!(stages, vec!["receiver.decode", "sender.capture"]);
        let capture = snapshot
            .stage_metrics
            .iter()
            .find(|metric| metric.stage == "sender.capture")
            .expect("sender capture metrics");
        assert_eq!(capture.p50_ms, Some(140.0));
        assert_eq!(capture.p95_ms, Some(247.0));
        assert_eq!(capture.p99_ms, Some(257.0));
        assert_eq!(capture.max_ms, Some(259.0));
        assert_eq!(capture.sample_count, Some(240));
    }

    #[test]
    fn decoded_samples_preserve_active_metadata_and_stage_metrics() {
        let mut registry = MediaPipelineRegistry::default();
        let session_id = SessionId("decoded-sample-session".to_string());
        let profile = MediaProfile {
            width: 1920,
            height: 1080,
            codec: "h264".to_string(),
            ..MediaProfile::default()
        };

        registry.record_decoded_media_sample(
            session_id.clone(),
            &profile,
            1280,
            720,
            "cpu_nv12",
            "receiver.format.cpu_nv12",
        );
        registry.record_decoded_media_sample(
            session_id.clone(),
            &profile,
            1280,
            720,
            "cpu_nv12",
            "receiver.format.cpu_nv12",
        );

        let snapshot = registry.snapshot(&session_id);
        assert_eq!(snapshot.active_codec.as_deref(), Some("h264"));
        assert_eq!(snapshot.active_pixel_format.as_deref(), Some("cpu_nv12"));
        assert_eq!(snapshot.active_width, Some(1280));
        assert_eq!(snapshot.active_height, Some(720));
        let stage = snapshot
            .stage_metrics
            .iter()
            .find(|stage| stage.stage == "receiver.format.cpu_nv12")
            .expect("decoded format stage");
        assert_eq!(stage.sample_count, Some(2));
        assert_eq!(stage.p50_ms, Some(1.0));
    }

    #[test]
    fn cumulative_activity_survives_pipeline_removal() {
        let mut registry = MediaPipelineRegistry::default();
        let session_id = SessionId("pipeline-cumulative-session".to_string());

        registry.set_sender_transport(
            session_id.clone(),
            MediaSenderTransportSnapshot {
                datagram_fragments_sent: 3,
                reliable_fragments_sent: 2,
                ..Default::default()
            },
        );
        registry.set_sender_transport(
            session_id.clone(),
            MediaSenderTransportSnapshot {
                datagram_fragments_sent: 4,
                reliable_fragments_sent: 3,
                ..Default::default()
            },
        );
        registry.increment_render_presented_frames(session_id.clone(), 4);

        assert_eq!(registry.cumulative_sender_packets_sent(), 7);
        assert_eq!(registry.cumulative_render_presented_frames(), 4);

        registry.remove(&session_id);

        assert_eq!(registry.cumulative_sender_packets_sent(), 7);
        assert_eq!(registry.cumulative_render_presented_frames(), 4);
    }
}
