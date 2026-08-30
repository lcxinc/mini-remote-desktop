#[cfg(target_os = "macos")]
use super::discovery_identity::now_ms;
#[cfg(target_os = "macos")]
use super::macos_render_proxy_compressed_media_enabled_for_profile;
#[cfg(any(windows, target_os = "macos"))]
use super::media_frame_preparation::decoded_frame_to_render_frame;
#[cfg(target_os = "macos")]
use super::media_probe::decoded_video_probe_format;
#[cfg(any(windows, target_os = "macos"))]
use super::media_receiver;
#[cfg(target_os = "macos")]
use super::media_render_policy::lan_media_payload_hash_for_profile;
#[cfg(any(windows, target_os = "macos"))]
use super::media_render_policy::{
    lan_render_cap_target_fps_for_profile, lan_render_pacing_render_start_delay,
    lan_render_pacing_should_wait, lan_render_pacing_target_fps,
    lan_render_policy_allows_service_pacing, lan_render_queue_capacity_for_policy,
    lan_render_queue_capacity_for_profile, lan_render_queue_policy_for_profile,
    native_render_waitable_swapchain_pacing_enabled, render_pacing_precise_sleep_guard,
    render_profile_requests_high_resolution_timer, should_interrupt_render_pacing_sleep,
    LanRenderQueuePolicy,
};
#[cfg(any(windows, target_os = "macos"))]
use super::media_timing::MediaTimerResolution;
#[cfg(any(windows, target_os = "macos"))]
use super::selected_media_profile;
#[cfg(any(windows, target_os = "macos"))]
use super::time_utils::duration_as_millis;
#[cfg(target_os = "macos")]
use super::time_utils::now_us;
#[cfg(target_os = "macos")]
use crate::app_state::DecodedVideoFrameStats;
#[cfg(any(windows, target_os = "macos"))]
use crate::app_state::{
    AppState, MediaRenderFrame, MediaRenderQueueEnqueue, MediaRenderQueueRegistry,
};
#[cfg(any(windows, target_os = "macos"))]
use anyhow::Result;
#[cfg(any(windows, target_os = "macos"))]
use mrd_ipc::MediaProfile;
#[cfg(any(windows, target_os = "macos"))]
use mrd_pipeline_core::DecodedFrame;
#[cfg(any(windows, target_os = "macos"))]
use mrd_proto::SessionId;
#[cfg(any(windows, target_os = "macos"))]
use mrd_render::RendererSnapshot;
#[cfg(any(windows, target_os = "macos"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(windows, target_os = "macos"))]
use std::sync::{Arc, Mutex as StdMutex};
#[cfg(any(windows, target_os = "macos"))]
use std::sync::{MutexGuard as StdMutexGuard, TryLockError};
#[cfg(any(windows, target_os = "macos"))]
use std::thread;
#[cfg(any(windows, target_os = "macos"))]
use std::time::Duration;
#[cfg(any(windows, target_os = "macos"))]
use tokio::time::Instant;

#[cfg(any(windows, target_os = "macos"))]
const LAN_RENDER_PACING_POLL_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(any(windows, target_os = "macos"))]
const LAN_RENDER_SURFACE_RENDERER_LOCK_TIMEOUT: Duration = Duration::from_millis(2);
#[cfg(any(windows, target_os = "macos"))]
const LAN_RENDER_SURFACE_RENDERER_LOCK_POLL_INTERVAL: Duration = Duration::from_micros(100);
#[cfg(any(windows, target_os = "macos"))]
static LAN_RENDER_NO_SURFACE_LOG_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(any(windows, target_os = "macos"))]
static LAN_RENDER_PRESENT_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(any(windows, target_os = "macos"))]
#[derive(Debug)]
pub(super) enum LanRenderTaskOutcome {
    Rendered {
        upload_duration_ms: f64,
        render_proxy_upload_ms: Option<f64>,
        render_proxy_transport_ms: Option<f64>,
        render_proxy_decode_ms: Option<f64>,
        render_proxy_draw_present_ms: Option<f64>,
        render_proxy_next_drawable_ms: Option<f64>,
        render_proxy_encode_commit_ms: Option<f64>,
        lock_wait_ms: f64,
        presented_frames: u64,
        present_skips: u64,
        waitable_wait_ms: f64,
        waitable_waits: u64,
        waitable_timeouts: u64,
    },
    Dropped,
    Idle,
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) async fn render_lan_decoded_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    decoded_frame: DecodedFrame,
) -> Result<()> {
    if app_state
        .media_surface_renderers
        .lock()
        .await
        .session_surface_count(session_id)
        == 0
    {
        return Ok(());
    }

    let render_frame = MediaRenderFrame::Decoded(decoded_frame_to_render_frame(decoded_frame)?);
    let render_profile = selected_media_profile(app_state, session_id).await;
    let render_queue_policy = lan_render_queue_policy_for_profile(&render_profile);
    let max_pending_frames =
        lan_render_queue_capacity_for_policy(&render_profile, render_queue_policy);
    let render_pacing_target_fps = lan_render_cap_target_fps_for_profile(&render_profile);
    let (enqueue, enqueue_gap_ms) = {
        let mut render_queues = app_state.media_render_queues.lock().await;
        let now = Instant::now();
        let enqueue_gap_ms = render_queues
            .record_enqueued(session_id, now)
            .map(duration_as_millis);
        let enqueue =
            render_queues.enqueue_bounded(session_id.clone(), render_frame, max_pending_frames);
        (enqueue, enqueue_gap_ms)
    };
    if let Some(enqueue_gap_ms) = enqueue_gap_ms {
        let mut pipelines = app_state.media_pipelines.lock().await;
        pipelines.set_render_pacing_target_fps(session_id.clone(), render_pacing_target_fps);
        pipelines.set_render_queue_policy(session_id.clone(), Some(render_queue_policy.as_str()));
        pipelines.record_stage_duration_ms(
            session_id.clone(),
            "render_enqueue_gap",
            enqueue_gap_ms,
        );
    } else {
        app_state
            .media_pipelines
            .lock()
            .await
            .set_render_pacing_target_fps(session_id.clone(), render_pacing_target_fps);
        app_state
            .media_pipelines
            .lock()
            .await
            .set_render_queue_policy(session_id.clone(), Some(render_queue_policy.as_str()));
    }
    match enqueue {
        MediaRenderQueueEnqueue::Start(frame) => {
            spawn_lan_render_worker(app_state.clone(), session_id.clone(), frame);
        }
        MediaRenderQueueEnqueue::Queued { replaced, depth } => {
            let mut pipelines = app_state.media_pipelines.lock().await;
            pipelines.record_queue_depth(session_id.clone(), depth as u32);
            if replaced {
                if render_queue_policy == LanRenderQueuePolicy::Latest {
                    pipelines.record_render_queue_replacements(session_id.clone(), 1);
                    pipelines.increment_render_stale_frame_drops(session_id.clone(), 1);
                } else {
                    pipelines.increment_render_queue_replacements(session_id.clone(), 1);
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) async fn render_lan_h264_access_unit_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    payload: bytes::Bytes,
    sequence: u64,
    timestamp_us: u64,
    profile: &MediaProfile,
) -> Result<bool> {
    if !macos_render_proxy_compressed_media_enabled_for_profile(profile) {
        return Ok(false);
    }
    if app_state
        .media_surface_renderers
        .lock()
        .await
        .session_surface_count(session_id)
        == 0
    {
        return Ok(false);
    }

    let payload_len = payload.len();
    let payload_hash =
        lan_media_payload_hash_for_profile(profile, sequence, timestamp_us, &payload);
    let render_queue_policy = lan_render_queue_policy_for_profile(profile);
    let max_pending_frames = lan_render_queue_capacity_for_policy(profile, render_queue_policy);
    let render_pacing_target_fps = lan_render_cap_target_fps_for_profile(profile);
    let render_frame = MediaRenderFrame::H264AccessUnit {
        width: profile.width as usize,
        height: profile.height as usize,
        timestamp_us,
        payload,
    };
    let (enqueue, enqueue_gap_ms) = {
        let mut render_queues = app_state.media_render_queues.lock().await;
        let now = Instant::now();
        let enqueue_gap_ms = render_queues
            .record_enqueued(session_id, now)
            .map(duration_as_millis);
        let enqueue =
            render_queues.enqueue_bounded(session_id.clone(), render_frame, max_pending_frames);
        (enqueue, enqueue_gap_ms)
    };

    {
        let mut pipelines = app_state.media_pipelines.lock().await;
        pipelines.set_active_decoder(session_id.clone(), "rdesk_videotoolbox");
        pipelines.record_active_media_sample(
            session_id.clone(),
            profile,
            profile.width,
            profile.height,
            "proxy_h264",
        );
        pipelines.record_stage_duration_ms(session_id.clone(), "receiver.format.proxy_h264", 1.0);
        pipelines.set_render_pacing_target_fps(session_id.clone(), render_pacing_target_fps);
        pipelines.set_render_queue_policy(session_id.clone(), Some(render_queue_policy.as_str()));
        if let Some(enqueue_gap_ms) = enqueue_gap_ms {
            pipelines.record_stage_duration_ms(
                session_id.clone(),
                "render_enqueue_gap",
                enqueue_gap_ms,
            );
        }
        if let Some(frame_age_ms) = estimated_cross_device_frame_age_ms(timestamp_us) {
            pipelines.record_estimated_frame_age_ms(session_id.clone(), frame_age_ms);
        }
    }

    match enqueue {
        MediaRenderQueueEnqueue::Start(frame) => {
            spawn_lan_render_worker(app_state.clone(), session_id.clone(), frame);
        }
        MediaRenderQueueEnqueue::Queued { replaced, depth } => {
            let mut pipelines = app_state.media_pipelines.lock().await;
            pipelines.record_queue_depth(session_id.clone(), depth as u32);
            if replaced {
                if render_queue_policy == LanRenderQueuePolicy::Latest {
                    pipelines.record_render_queue_replacements(session_id.clone(), 1);
                    pipelines.increment_render_stale_frame_drops(session_id.clone(), 1);
                } else {
                    pipelines.increment_render_queue_replacements(session_id.clone(), 1);
                }
            }
        }
    }

    app_state.probes.lock().await.record_decoded_video_frame(
        session_id,
        DecodedVideoFrameStats {
            bytes_received: payload_len as u64,
            sequence,
            timestamp_us,
            width: profile.width,
            height: profile.height,
            target_fps: profile.fps,
            target_bitrate_mbps: profile.bitrate_mbps,
            encoded_bytes: payload_len as u32,
            format: decoded_video_probe_format(&profile.codec),
            pixel_format: "proxy_h264".to_string(),
            payload_hash,
            preview_width: None,
            preview_height: None,
            rgb24: None,
        },
        now_ms(),
    );
    Ok(true)
}

#[cfg(target_os = "macos")]
pub(super) async fn render_lan_hevc_access_unit_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    payload: bytes::Bytes,
    sequence: u64,
    timestamp_us: u64,
    profile: &MediaProfile,
) -> Result<bool> {
    if !macos_render_proxy_compressed_media_enabled_for_profile(profile) {
        return Ok(false);
    }
    if app_state
        .media_surface_renderers
        .lock()
        .await
        .session_surface_count(session_id)
        == 0
    {
        return Ok(false);
    }

    let payload_len = payload.len();
    let payload_hash =
        lan_media_payload_hash_for_profile(profile, sequence, timestamp_us, &payload);
    let render_queue_policy = lan_render_queue_policy_for_profile(profile);
    let max_pending_frames = lan_render_queue_capacity_for_policy(profile, render_queue_policy);
    let render_pacing_target_fps = lan_render_cap_target_fps_for_profile(profile);
    let render_frame = MediaRenderFrame::HevcAccessUnit {
        width: profile.width as usize,
        height: profile.height as usize,
        timestamp_us,
        payload,
    };
    let (enqueue, enqueue_gap_ms) = {
        let mut render_queues = app_state.media_render_queues.lock().await;
        let now = Instant::now();
        let enqueue_gap_ms = render_queues
            .record_enqueued(session_id, now)
            .map(duration_as_millis);
        let enqueue =
            render_queues.enqueue_bounded(session_id.clone(), render_frame, max_pending_frames);
        (enqueue, enqueue_gap_ms)
    };

    {
        let mut pipelines = app_state.media_pipelines.lock().await;
        pipelines.set_active_decoder(session_id.clone(), "rdesk_videotoolbox_hevc");
        pipelines.record_active_media_sample(
            session_id.clone(),
            profile,
            profile.width,
            profile.height,
            "proxy_hevc",
        );
        pipelines.record_stage_duration_ms(session_id.clone(), "receiver.format.proxy_hevc", 1.0);
        pipelines.set_render_pacing_target_fps(session_id.clone(), render_pacing_target_fps);
        pipelines.set_render_queue_policy(session_id.clone(), Some(render_queue_policy.as_str()));
        if let Some(enqueue_gap_ms) = enqueue_gap_ms {
            pipelines.record_stage_duration_ms(
                session_id.clone(),
                "render_enqueue_gap",
                enqueue_gap_ms,
            );
        }
        if let Some(frame_age_ms) = estimated_cross_device_frame_age_ms(timestamp_us) {
            pipelines.record_estimated_frame_age_ms(session_id.clone(), frame_age_ms);
        }
    }

    match enqueue {
        MediaRenderQueueEnqueue::Start(frame) => {
            spawn_lan_render_worker(app_state.clone(), session_id.clone(), frame);
        }
        MediaRenderQueueEnqueue::Queued { replaced, depth } => {
            let mut pipelines = app_state.media_pipelines.lock().await;
            pipelines.record_queue_depth(session_id.clone(), depth as u32);
            if replaced {
                if render_queue_policy == LanRenderQueuePolicy::Latest {
                    pipelines.record_render_queue_replacements(session_id.clone(), 1);
                    pipelines.increment_render_stale_frame_drops(session_id.clone(), 1);
                } else {
                    pipelines.increment_render_queue_replacements(session_id.clone(), 1);
                }
            }
        }
    }

    app_state.probes.lock().await.record_decoded_video_frame(
        session_id,
        DecodedVideoFrameStats {
            bytes_received: payload_len as u64,
            sequence,
            timestamp_us,
            width: profile.width,
            height: profile.height,
            target_fps: profile.fps,
            target_bitrate_mbps: profile.bitrate_mbps,
            encoded_bytes: payload_len as u32,
            format: decoded_video_probe_format(&profile.codec),
            pixel_format: "proxy_hevc".to_string(),
            payload_hash,
            preview_width: None,
            preview_height: None,
            rgb24: None,
        },
        now_ms(),
    );
    Ok(true)
}

#[cfg(target_os = "macos")]
fn estimated_cross_device_frame_age_ms(timestamp_us: u64) -> Option<f64> {
    // Sender timestamps use wall clock. Keep the metric explicitly labelled as
    // an estimate and reject implausible clock skew instead of reporting it as
    // transport latency.
    let age_us = now_us().checked_sub(timestamp_us)?;
    (age_us <= 30_000_000).then_some(age_us as f64 / 1_000.0)
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn spawn_lan_render_worker(
    app_state: Arc<AppState>,
    session_id: SessionId,
    first_frame: MediaRenderFrame,
) {
    let fallback_app_state = app_state.clone();
    let fallback_session_id = session_id.clone();
    let fallback_first_frame = first_frame.clone();
    let handle = tokio::runtime::Handle::current();
    let spawn_result = thread::Builder::new()
        .name("mrd-lan-render".to_string())
        .spawn(move || {
            #[cfg(windows)]
            configure_lan_render_thread_priority();
            handle.block_on(run_lan_render_worker(app_state, session_id, first_frame));
        });

    if let Err(error) = spawn_result {
        tracing::warn!(
            %error,
            session_id = %fallback_session_id.0,
            "failed to spawn dedicated LAN render thread; falling back to Tokio task"
        );
        tokio::spawn(run_lan_render_worker(
            fallback_app_state,
            fallback_session_id,
            fallback_first_frame,
        ));
    }
}

#[cfg(windows)]
fn configure_lan_render_thread_priority() {
    use windows::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_HIGHEST,
    };

    if unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST) }.is_err() {
        tracing::debug!("failed to raise LAN render thread priority");
    }
}

#[cfg(any(windows, target_os = "macos"))]
async fn run_lan_render_worker(
    app_state: Arc<AppState>,
    session_id: SessionId,
    first_frame: MediaRenderFrame,
) {
    let mut frame = first_frame;
    let mut timer_resolution = MediaTimerResolution::default();
    loop {
        let render_profile = selected_media_profile(&app_state, &session_id).await;
        let render_queue_policy = lan_render_queue_policy_for_profile(&render_profile);
        if render_profile_requests_high_resolution_timer(&render_profile) {
            timer_resolution.request();
        } else {
            timer_resolution.release();
        }
        pace_lan_render_frame(
            &app_state,
            &session_id,
            &render_profile,
            render_queue_policy,
        )
        .await;
        match render_lan_frame_once(app_state.clone(), session_id.clone(), frame).await {
            Ok(LanRenderTaskOutcome::Rendered {
                upload_duration_ms,
                render_proxy_upload_ms,
                render_proxy_transport_ms,
                render_proxy_decode_ms,
                render_proxy_draw_present_ms,
                render_proxy_next_drawable_ms,
                render_proxy_encode_commit_ms,
                lock_wait_ms,
                presented_frames,
                present_skips,
                waitable_wait_ms,
                waitable_waits,
                waitable_timeouts,
            }) => {
                {
                    let mut pipelines = app_state.media_pipelines.lock().await;
                    pipelines.record_stage_duration_ms(
                        session_id.clone(),
                        "render_upload",
                        upload_duration_ms,
                    );
                    if let Some(render_proxy_upload_ms) = render_proxy_upload_ms {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_proxy_upload",
                            render_proxy_upload_ms,
                        );
                    }
                    if let Some(render_proxy_transport_ms) = render_proxy_transport_ms {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_proxy_transport",
                            render_proxy_transport_ms,
                        );
                    }
                    if let Some(render_proxy_decode_ms) = render_proxy_decode_ms {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_proxy_decode",
                            render_proxy_decode_ms,
                        );
                    }
                    if let Some(render_proxy_draw_present_ms) = render_proxy_draw_present_ms {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_proxy_draw_present",
                            render_proxy_draw_present_ms,
                        );
                    }
                    if let Some(render_proxy_next_drawable_ms) = render_proxy_next_drawable_ms {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_proxy_next_drawable",
                            render_proxy_next_drawable_ms,
                        );
                    }
                    if let Some(render_proxy_encode_commit_ms) = render_proxy_encode_commit_ms {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_proxy_encode_commit",
                            render_proxy_encode_commit_ms,
                        );
                    }
                    if lock_wait_ms > 0.0 {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_lock_wait",
                            lock_wait_ms,
                        );
                    }
                    if presented_frames > 0 {
                        pipelines.increment_render_presented_frames(
                            session_id.clone(),
                            presented_frames,
                        );
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_present",
                            upload_duration_ms,
                        );
                    }
                    if present_skips > 0 {
                        pipelines.increment_render_present_skips(session_id.clone(), present_skips);
                    }
                    if waitable_waits > 0 {
                        pipelines.record_stage_duration_ms(
                            session_id.clone(),
                            "render_waitable_wait",
                            waitable_wait_ms / waitable_waits as f64,
                        );
                    }
                    if waitable_timeouts > 0 {
                        pipelines.increment_render_waitable_timeouts(
                            session_id.clone(),
                            waitable_timeouts,
                        );
                    }
                }
                if presented_frames > 0 {
                    let present_gap_ms = app_state
                        .media_render_queues
                        .lock()
                        .await
                        .record_presented(&session_id, Instant::now())
                        .map(duration_as_millis);
                    if let Some(present_gap_ms) = present_gap_ms {
                        app_state
                            .media_pipelines
                            .lock()
                            .await
                            .record_stage_duration_ms(
                                session_id.clone(),
                                "render_present_gap",
                                present_gap_ms,
                            );
                    }
                }
            }
            Ok(LanRenderTaskOutcome::Dropped) => {
                app_state
                    .media_pipelines
                    .lock()
                    .await
                    .increment_render_lock_drops(session_id.clone(), 1);
            }
            Ok(LanRenderTaskOutcome::Idle) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    session_id = %session_id.0,
                    "LAN media receiver failed to present decoded frame"
                );
            }
        }

        let (next_frame, stale_drops) = {
            let mut render_queues = app_state.media_render_queues.lock().await;
            take_next_lan_render_frame_for_policy(
                &mut render_queues,
                &session_id,
                render_queue_policy,
            )
        };
        if stale_drops > 0 {
            app_state
                .media_pipelines
                .lock()
                .await
                .increment_render_stale_frame_drops(session_id.clone(), stale_drops as u64);
        }
        match next_frame {
            Some(next_frame) => {
                let mut pipelines = app_state.media_pipelines.lock().await;
                pipelines.record_queue_depth(session_id.clone(), 0);
                frame = next_frame;
            }
            None => {
                app_state
                    .media_pipelines
                    .lock()
                    .await
                    .record_queue_depth(session_id.clone(), 0);
                break;
            }
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
async fn pace_lan_render_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    profile: &MediaProfile,
    policy: LanRenderQueuePolicy,
) {
    if !lan_render_policy_allows_service_pacing(
        policy,
        profile,
        native_render_waitable_swapchain_pacing_enabled(),
    ) {
        return;
    }

    let target_fps = lan_render_pacing_target_fps(profile);
    let max_pending_frames = lan_render_queue_capacity_for_profile(profile);
    let delay = app_state.media_render_queues.lock().await.pacing_delay(
        session_id,
        target_fps,
        Instant::now(),
    );
    let delay = lan_render_pacing_render_start_delay(delay, target_fps);
    if !lan_render_pacing_should_wait(delay) {
        return;
    }

    let started = Instant::now();
    let interrupted = sleep_until_lan_render_frame(
        app_state,
        session_id,
        target_fps,
        max_pending_frames,
        started + delay,
    )
    .await;
    app_state
        .media_pipelines
        .lock()
        .await
        .record_stage_duration_ms(
            session_id.clone(),
            "render_pacing_wait",
            started.elapsed().as_secs_f64() * 1000.0,
        );
    if interrupted {
        app_state
            .media_pipelines
            .lock()
            .await
            .record_stage_duration_ms(session_id.clone(), "render_pacing_interrupt", 1.0);
    }
}

#[cfg(any(windows, target_os = "macos"))]
async fn sleep_until_lan_render_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    target_fps: u32,
    max_pending_frames: usize,
    deadline: Instant,
) -> bool {
    let guard = render_pacing_precise_sleep_guard(target_fps);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }

        let pending_depth = app_state
            .media_render_queues
            .lock()
            .await
            .pending_depth(session_id);
        if should_interrupt_render_pacing_sleep(pending_depth, max_pending_frames) {
            return true;
        }

        let remaining = deadline - now;
        if remaining > guard {
            let sleep_for = (remaining - guard).min(LAN_RENDER_PACING_POLL_INTERVAL);
            std::thread::sleep(sleep_for);
        } else {
            std::hint::spin_loop();
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn take_next_lan_render_frame_for_policy(
    render_queues: &mut MediaRenderQueueRegistry,
    session_id: &SessionId,
    policy: LanRenderQueuePolicy,
) -> (Option<MediaRenderFrame>, usize) {
    match policy {
        LanRenderQueuePolicy::Latest => render_queues.take_latest_or_finish(session_id),
        LanRenderQueuePolicy::PacedFifo => (render_queues.take_next_or_finish(session_id), 0),
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) async fn render_lan_frame_once(
    app_state: Arc<AppState>,
    session_id: SessionId,
    frame: MediaRenderFrame,
) -> Result<LanRenderTaskOutcome> {
    let renderers = {
        let render_registry = app_state.media_surface_renderers.lock().await;
        render_registry.renderers_for_session(&session_id)
    };
    if renderers.is_empty() {
        let no_surface_count = LAN_RENDER_NO_SURFACE_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if no_surface_count <= 5 || no_surface_count.is_multiple_of(120) {
            tracing::warn!(
                session_id = %session_id.0,
                no_surface_count,
                "lan-render no surface renderer for session"
            );
        }
        return Ok(LanRenderTaskOutcome::Idle);
    }

    let mut rendered = 0;
    let mut upload_duration_ms = 0.0_f64;
    let mut lock_wait_ms = 0.0_f64;
    let mut presented_frames = 0_u64;
    let mut present_skips = 0_u64;
    let mut render_queue_replacements = 0_u64;
    let mut waitable_wait_ms = 0.0_f64;
    let mut waitable_waits = 0_u64;
    let mut waitable_timeouts = 0_u64;
    let mut render_proxy_upload_ms = 0.0_f64;
    let mut render_proxy_transport_ms = 0.0_f64;
    let mut render_proxy_decode_ms = 0.0_f64;
    let mut render_proxy_draw_present_ms = 0.0_f64;
    let mut render_proxy_next_drawable_ms = 0.0_f64;
    let mut render_proxy_encode_commit_ms = 0.0_f64;
    let mut render_proxy_samples = 0_u64;
    let mut render_proxy_decode_samples = 0_u64;
    let mut render_proxy_draw_present_samples = 0_u64;
    let mut render_proxy_next_drawable_samples = 0_u64;
    let mut render_proxy_encode_commit_samples = 0_u64;
    let mut renderer_snapshots = Vec::<RendererSnapshot>::new();
    let renderer_count = renderers.len();
    let mut frame_for_last_renderer = Some(frame);
    for (renderer_index, renderer) in renderers.iter().enumerate() {
        let lock_started = Instant::now();
        let Some(mut renderer) =
            wait_for_mutex_guard(renderer.as_ref(), LAN_RENDER_SURFACE_RENDERER_LOCK_TIMEOUT)
                .map_err(|error| anyhow::anyhow!(error))?
        else {
            lock_wait_ms += lock_started.elapsed().as_secs_f64() * 1000.0;
            if rendered == 0 {
                return Ok(LanRenderTaskOutcome::Dropped);
            }
            continue;
        };
        lock_wait_ms += lock_started.elapsed().as_secs_f64() * 1000.0;
        let before = renderer.snapshot();
        let upload_started = Instant::now();
        let frame_for_renderer = if renderer_index + 1 == renderer_count {
            frame_for_last_renderer
                .take()
                .ok_or_else(|| anyhow::anyhow!("render frame was already consumed"))?
        } else {
            frame_for_last_renderer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("render frame was already consumed"))?
                .clone()
        };
        upload_lan_render_frame(renderer.as_mut(), frame_for_renderer)
            .map_err(|error| anyhow::anyhow!("upload frame to native renderer failed: {error}"))?;
        let after = renderer.snapshot();
        let wait_delta = media_receiver::renderer_snapshot_waitable_delta(&before, &after);
        let upload_elapsed_ms = upload_started.elapsed().as_secs_f64() * 1000.0;
        let upload_without_wait_ms = (upload_elapsed_ms - wait_delta.wait_ms).max(0.0);
        upload_duration_ms += upload_without_wait_ms;
        if media_receiver::renderer_snapshot_uses_render_proxy(&after) {
            if let Some(proxy_upload_ms) = after.last_render_draw_present_ms {
                render_proxy_upload_ms += proxy_upload_ms;
                render_proxy_transport_ms += (upload_without_wait_ms - proxy_upload_ms).max(0.0);
                if let Some(proxy_decode_ms) = after.last_render_prepare_wait_ms {
                    render_proxy_decode_ms += proxy_decode_ms;
                    render_proxy_decode_samples = render_proxy_decode_samples.saturating_add(1);
                }
                if let Some(proxy_draw_present_ms) = after.last_render_shared_resource_ms {
                    render_proxy_draw_present_ms += proxy_draw_present_ms;
                    render_proxy_draw_present_samples =
                        render_proxy_draw_present_samples.saturating_add(1);
                }
                if let Some(proxy_next_drawable_ms) = after.last_render_wait_for_drawable_ms {
                    render_proxy_next_drawable_ms += proxy_next_drawable_ms;
                    render_proxy_next_drawable_samples =
                        render_proxy_next_drawable_samples.saturating_add(1);
                }
                if let Some(proxy_encode_commit_ms) = after.last_render_encode_commit_ms {
                    render_proxy_encode_commit_ms += proxy_encode_commit_ms;
                    render_proxy_encode_commit_samples =
                        render_proxy_encode_commit_samples.saturating_add(1);
                }
                render_proxy_samples = render_proxy_samples.saturating_add(1);
            }
        }
        waitable_wait_ms += wait_delta.wait_ms;
        waitable_waits = waitable_waits.saturating_add(wait_delta.waits);
        waitable_timeouts = waitable_timeouts.saturating_add(wait_delta.timeouts);
        render_queue_replacements = render_queue_replacements.saturating_add(
            media_receiver::renderer_snapshot_render_queue_replacement_delta(&before, &after),
        );
        let uploaded_delta = after
            .uploaded_frame_count
            .saturating_sub(before.uploaded_frame_count);
        let mut presented_delta = after
            .presented_frame_count
            .saturating_sub(before.presented_frame_count);
        let skipped_delta = after
            .present_skipped_count
            .saturating_sub(before.present_skipped_count);
        if uploaded_delta > 0
            && presented_delta == 0
            && skipped_delta == 0
            && after.last_present_status.is_none()
        {
            presented_delta = uploaded_delta;
        }
        presented_frames = presented_frames.saturating_add(presented_delta);
        present_skips = present_skips.saturating_add(skipped_delta);
        renderer_snapshots.push(after);
        rendered += 1;
    }

    if rendered > 0 {
        {
            let mut pipelines = app_state.media_pipelines.lock().await;
            for snapshot in &renderer_snapshots {
                pipelines.record_renderer_snapshot(session_id.clone(), snapshot);
            }
            pipelines
                .record_render_queue_replacements(session_id.clone(), render_queue_replacements);
        }
        let present_log_count = LAN_RENDER_PRESENT_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if present_log_count <= 5 || present_log_count.is_multiple_of(120) {
            tracing::info!(
                session_id = %session_id.0,
                renderer_count = renderers.len(),
                rendered,
                presented_frames,
                present_skips,
                "lan-render uploaded frame to native surface"
            );
        }
        Ok(LanRenderTaskOutcome::Rendered {
            upload_duration_ms,
            render_proxy_upload_ms: (render_proxy_samples > 0).then_some(render_proxy_upload_ms),
            render_proxy_transport_ms: (render_proxy_samples > 0)
                .then_some(render_proxy_transport_ms),
            render_proxy_decode_ms: (render_proxy_decode_samples > 0)
                .then_some(render_proxy_decode_ms),
            render_proxy_draw_present_ms: (render_proxy_draw_present_samples > 0)
                .then_some(render_proxy_draw_present_ms),
            render_proxy_next_drawable_ms: (render_proxy_next_drawable_samples > 0)
                .then_some(render_proxy_next_drawable_ms),
            render_proxy_encode_commit_ms: (render_proxy_encode_commit_samples > 0)
                .then_some(render_proxy_encode_commit_ms),
            lock_wait_ms,
            presented_frames,
            present_skips,
            waitable_wait_ms,
            waitable_waits,
            waitable_timeouts,
        })
    } else {
        Ok(LanRenderTaskOutcome::Idle)
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn upload_lan_render_frame(
    renderer: &mut dyn mrd_render::RendererInstance,
    frame: MediaRenderFrame,
) -> Result<(), mrd_render::RenderError> {
    match frame {
        MediaRenderFrame::Decoded(frame) => renderer.upload_frame(frame),
        #[cfg(target_os = "macos")]
        MediaRenderFrame::H264AccessUnit {
            width,
            height,
            timestamp_us,
            payload,
        } => renderer.upload_h264_access_unit(width, height, timestamp_us, payload),
        #[cfg(target_os = "macos")]
        MediaRenderFrame::HevcAccessUnit {
            width,
            height,
            timestamp_us,
            payload,
        } => renderer.upload_hevc_access_unit(width, height, timestamp_us, payload),
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn wait_for_mutex_guard<'a, T>(
    mutex: &'a StdMutex<T>,
    wait_timeout: Duration,
) -> Result<Option<StdMutexGuard<'a, T>>, String> {
    let started = std::time::Instant::now();
    let mut spins = 0;
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(Some(guard)),
            Err(TryLockError::Poisoned(_)) => {
                return Err("native renderer lock was poisoned".into())
            }
            Err(TryLockError::WouldBlock) => {
                if started.elapsed() >= wait_timeout {
                    return Ok(None);
                }
                if spins < 16 {
                    spins += 1;
                    std::hint::spin_loop();
                } else {
                    std::thread::sleep(LAN_RENDER_SURFACE_RENDERER_LOCK_POLL_INTERVAL);
                }
            }
        }
    }
}
