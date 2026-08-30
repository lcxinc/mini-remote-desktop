//! Service-owned WAN media tasks backed by the authenticated transport mux.

use super::{
    media::{
        ipc_media_profile, WanMediaActivationError, WanMediaActivationReceipt, WanMediaAuthority,
        WanMediaReadyEvidence, WanMediaReadySender,
    },
    model::WanSessionFailure,
};
use crate::{
    app_state::{AppState, WanMediaRuntimeRole},
    lan_discovery::{
        create_software_frame_capture, decoded_frame_format_stage, decoded_frame_pixel_format,
        prepare_frame_for_h264, selected_capture_source_id, LanFrameCapture,
    },
};
use mrd_application::ports::{
    TransportEnvelope, TransportLane, TransportMuxPort, TransportSendOutcome, VideoEnvelopeMetadata,
};
use mrd_decode::H264SoftwareDecoder;
use mrd_encode_openh264::OpenH264Encoder;
use mrd_ipc::{MediaProfile, MediaProfileNegotiation};
#[cfg(any(test, debug_assertions))]
use mrd_pipeline_core::FramePixelFormat;
use mrd_pipeline_core::{CapturedFrame, VideoDecoder, VideoEncoder};
use mrd_proto::SessionId;
use std::{sync::Arc, time::Duration};

const DEFAULT_WAN_MEDIA_WIDTH: u32 = 1280;
const DEFAULT_WAN_MEDIA_HEIGHT: u32 = 720;
const DEFAULT_WAN_MEDIA_FPS: u32 = 30;
const DEFAULT_WAN_MEDIA_BITRATE_MBPS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WanMediaRuntimeError {
    Capture,
    Codec,
    Transport,
    Evidence,
}

enum WanFrameCapture {
    Platform(Box<LanFrameCapture>),
    #[cfg(any(test, debug_assertions))]
    Synthetic(SyntheticWanFrameCapture),
}

impl WanFrameCapture {
    fn capture_frame(&mut self) -> Result<CapturedFrame, WanMediaRuntimeError> {
        match self {
            Self::Platform(capture) => capture
                .capture_frame()
                .map_err(|_| WanMediaRuntimeError::Capture),
            #[cfg(any(test, debug_assertions))]
            Self::Synthetic(capture) => Ok(capture.capture_frame()),
        }
    }
}

#[cfg(any(test, debug_assertions))]
struct SyntheticWanFrameCapture {
    width: usize,
    height: usize,
    frame_index: u64,
}

#[cfg(any(test, debug_assertions))]
impl SyntheticWanFrameCapture {
    fn new(profile: &MediaProfile) -> Self {
        Self {
            width: profile.width as usize,
            height: profile.height as usize,
            frame_index: 0,
        }
    }

    fn capture_frame(&mut self) -> CapturedFrame {
        let shade = 0x40_u8.wrapping_add(self.frame_index as u8);
        self.frame_index = self.frame_index.wrapping_add(1);
        CapturedFrame::from_cpu(
            self.width,
            self.height,
            FramePixelFormat::Rgb24,
            now_unix_us(),
            vec![shade; self.width.saturating_mul(self.height).saturating_mul(3)],
        )
    }
}

pub(crate) async fn start_target_runtime(
    app_state: Arc<AppState>,
    authority: WanMediaAuthority,
    mux: Arc<dyn TransportMuxPort>,
    test_synthetic_capture: bool,
) -> Result<WanMediaActivationReceipt, WanMediaActivationError> {
    let profile = install_runtime_metadata(
        &app_state,
        &authority,
        WanMediaRuntimeRole::TargetSender,
        "openh264_software",
    )
    .await?;
    let session_id = authority.session_id().clone();
    let (receipt, ready) = WanMediaActivationReceipt::pending();
    let task_app_state = Arc::clone(&app_state);
    let task_session_id = session_id.clone();
    let task = tokio::spawn(async move {
        let task_id = tokio::task::id();
        let mut ready = Some(ready);
        let result = run_target_runtime(
            Arc::clone(&task_app_state),
            authority,
            profile,
            mux,
            test_synthetic_capture,
            &mut ready,
        )
        .await;
        let became_ready = ready.is_none();
        if result.is_err() {
            send_startup_failure(&mut ready);
        }
        task_app_state
            .media_tasks
            .lock()
            .await
            .forget_task(&task_session_id, task_id);
        if result.is_err() && became_ready {
            terminalize_background_failure(task_app_state, task_session_id);
        }
    });
    app_state
        .media_tasks
        .lock()
        .await
        .register(session_id, task.abort_handle());
    Ok(receipt)
}

pub(crate) async fn start_controller_runtime(
    app_state: Arc<AppState>,
    authority: WanMediaAuthority,
    mux: Arc<dyn TransportMuxPort>,
) -> Result<WanMediaActivationReceipt, WanMediaActivationError> {
    let profile = install_runtime_metadata(
        &app_state,
        &authority,
        WanMediaRuntimeRole::ControllerReceiver,
        "openh264_software",
    )
    .await?;
    let session_id = authority.session_id().clone();
    let (receipt, ready) = WanMediaActivationReceipt::pending();
    let task_app_state = Arc::clone(&app_state);
    let task_session_id = session_id.clone();
    let task = tokio::spawn(async move {
        let task_id = tokio::task::id();
        let mut ready = Some(ready);
        let result = run_controller_runtime(
            Arc::clone(&task_app_state),
            authority,
            profile,
            mux,
            &mut ready,
        )
        .await;
        let became_ready = ready.is_none();
        if result.is_err() {
            send_startup_failure(&mut ready);
        }
        task_app_state
            .media_tasks
            .lock()
            .await
            .forget_task(&task_session_id, task_id);
        if result.is_err() && became_ready {
            terminalize_background_failure(task_app_state, task_session_id);
        }
    });
    app_state
        .media_tasks
        .lock()
        .await
        .register(session_id, task.abort_handle());
    Ok(receipt)
}

async fn install_runtime_metadata(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    role: WanMediaRuntimeRole,
    codec_backend: &str,
) -> Result<MediaProfile, WanMediaActivationError> {
    let profile = authority
        .approved_profile()
        .map(ipc_media_profile)
        .unwrap_or_else(default_wan_media_profile);
    validate_h264_profile(&profile)?;

    let inserted = app_state
        .media_pipelines
        .lock()
        .await
        .begin_wan_media_runtime(
            authority.session_id().clone(),
            authority.generation(),
            role,
            1,
        );
    if !inserted {
        return Err(WanMediaActivationError::StartupFailed);
    }

    app_state.media_profiles.lock().await.set(
        authority.session_id().clone(),
        MediaProfileNegotiation {
            requested: profile.clone(),
            selected: profile.clone(),
            status: "accepted".to_owned(),
            reason: None,
            selected_source_id: None,
            selected_width: Some(profile.width),
            selected_height: Some(profile.height),
            downgrade_reason: None,
        },
    );
    let mut pipelines = app_state.media_pipelines.lock().await;
    pipelines.set_active_media_profile(authority.session_id().clone(), &profile);
    match role {
        WanMediaRuntimeRole::TargetSender => {
            pipelines.set_active_encoder(authority.session_id().clone(), codec_backend)
        }
        WanMediaRuntimeRole::ControllerReceiver => {
            pipelines.set_active_decoder(authority.session_id().clone(), codec_backend)
        }
    }
    Ok(profile)
}

async fn run_target_runtime(
    app_state: Arc<AppState>,
    authority: WanMediaAuthority,
    profile: MediaProfile,
    mux: Arc<dyn TransportMuxPort>,
    test_synthetic_capture: bool,
    ready: &mut Option<WanMediaReadySender>,
) -> Result<(), WanMediaRuntimeError> {
    let mut capture = create_target_capture(
        &app_state,
        authority.session_id(),
        &profile,
        test_synthetic_capture,
    )
    .await?;
    let mut encoder = OpenH264Encoder::new_with_bitrate(
        profile.width as usize,
        profile.height as usize,
        profile.fps,
        profile.bitrate_mbps.saturating_mul(1_000_000),
    )
    .map_err(|_| WanMediaRuntimeError::Codec)?;
    let mut sequence = 0_u64;
    let frame_period = Duration::from_micros(1_000_000 / u64::from(profile.fps.max(1)));
    let mut pacing = tokio::time::interval(frame_period);
    pacing.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        pacing.tick().await;
        let blocking_profile = profile.clone();
        let (next_capture, next_encoder, access_units) = tokio::task::spawn_blocking(move || {
            let result = capture.capture_frame().and_then(|frame| {
                let prepared = prepare_frame_for_h264(frame, &blocking_profile)
                    .map_err(|_| WanMediaRuntimeError::Capture)?;
                encoder
                    .encode(&prepared)
                    .map_err(|_| WanMediaRuntimeError::Codec)
            });
            (capture, encoder, result)
        })
        .await
        .map_err(|_| WanMediaRuntimeError::Capture)?;
        capture = next_capture;
        encoder = next_encoder;
        let access_units = access_units?;
        for access_unit in access_units {
            if access_unit.bytes.is_empty() {
                continue;
            }
            sequence = sequence.saturating_add(1);
            let outcome = mux
                .send(TransportEnvelope {
                    session_id: authority.session_id().clone(),
                    lane: TransportLane::Video,
                    sequence,
                    payload: access_unit.bytes,
                    video: Some(VideoEnvelopeMetadata {
                        codec: "h264".to_owned(),
                        timestamp_us: access_unit.timestamp_us,
                        keyframe: access_unit.is_keyframe,
                        width: profile.width,
                        height: profile.height,
                    }),
                })
                .await
                .map_err(|_| WanMediaRuntimeError::Transport)?;
            match outcome {
                TransportSendOutcome::Enqueued | TransportSendOutcome::ReplacedStale => {
                    publish_ready(
                        &app_state,
                        &authority,
                        WanMediaRuntimeRole::TargetSender,
                        sequence,
                        ready,
                    )
                    .await?;
                }
                TransportSendOutcome::Backpressured => {
                    app_state
                        .media_pipelines
                        .lock()
                        .await
                        .increment_dropped_frames(authority.session_id().clone(), 1);
                }
                TransportSendOutcome::Closed => return Err(WanMediaRuntimeError::Transport),
            }
        }
    }
}

async fn run_controller_runtime(
    app_state: Arc<AppState>,
    authority: WanMediaAuthority,
    profile: MediaProfile,
    mux: Arc<dyn TransportMuxPort>,
    ready: &mut Option<WanMediaReadySender>,
) -> Result<(), WanMediaRuntimeError> {
    let mut decoder = H264SoftwareDecoder::new().map_err(|_| WanMediaRuntimeError::Codec)?;
    let mut last_sequence = None;
    loop {
        let envelope = mux
            .recv(TransportLane::Video)
            .await
            .map_err(|_| WanMediaRuntimeError::Transport)?
            .ok_or(WanMediaRuntimeError::Transport)?;
        if envelope.session_id != *authority.session_id()
            || envelope.lane != TransportLane::Video
            || last_sequence.is_some_and(|previous| envelope.sequence <= previous)
        {
            return Err(WanMediaRuntimeError::Evidence);
        }
        let metadata = envelope.video.ok_or(WanMediaRuntimeError::Evidence)?;
        if !metadata.codec.eq_ignore_ascii_case("h264")
            || metadata.width != profile.width
            || metadata.height != profile.height
        {
            return Err(WanMediaRuntimeError::Evidence);
        }
        last_sequence = Some(envelope.sequence);
        let payload = envelope.payload;
        let (next_decoder, decoded_frames) = tokio::task::spawn_blocking(move || {
            let result = decoder
                .push_access_unit(&payload)
                .map(|()| decoder.drain_decoded_frames())
                .map_err(|_| WanMediaRuntimeError::Codec);
            (decoder, result)
        })
        .await
        .map_err(|_| WanMediaRuntimeError::Codec)?;
        decoder = next_decoder;
        let mut decoded_frames = decoded_frames?;
        if decoded_frames.is_empty() {
            continue;
        }
        for frame in &mut decoded_frames {
            frame.timestamp_us = metadata.timestamp_us;
        }
        for frame in decoded_frames {
            let width = frame.width as u32;
            let height = frame.height as u32;
            let pixel_format = decoded_frame_pixel_format(&frame);
            let format_stage = decoded_frame_format_stage(&frame);
            #[cfg(any(windows, target_os = "macos"))]
            crate::lan_discovery::render_lan_decoded_frame(
                &app_state,
                authority.session_id(),
                frame,
            )
            .await
            .map_err(|_| WanMediaRuntimeError::Transport)?;
            app_state
                .media_pipelines
                .lock()
                .await
                .record_decoded_media_sample(
                    authority.session_id().clone(),
                    &profile,
                    width,
                    height,
                    pixel_format,
                    format_stage,
                );
        }
        publish_ready(
            &app_state,
            &authority,
            WanMediaRuntimeRole::ControllerReceiver,
            envelope.sequence,
            ready,
        )
        .await?;
    }
}

async fn create_target_capture(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    profile: &MediaProfile,
    test_synthetic_capture: bool,
) -> Result<WanFrameCapture, WanMediaRuntimeError> {
    #[cfg(any(test, debug_assertions))]
    if test_synthetic_capture {
        return Ok(WanFrameCapture::Synthetic(SyntheticWanFrameCapture::new(
            profile,
        )));
    }
    #[cfg(not(any(test, debug_assertions)))]
    let _ = test_synthetic_capture;

    let source_id = selected_capture_source_id(app_state, session_id)
        .await
        .map_err(|_| WanMediaRuntimeError::Capture)?;
    create_software_frame_capture(&source_id, profile)
        .await
        .map(Box::new)
        .map(WanFrameCapture::Platform)
        .map_err(|_| WanMediaRuntimeError::Capture)
}

async fn publish_ready(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    role: WanMediaRuntimeRole,
    sequence: u64,
    ready: &mut Option<WanMediaReadySender>,
) -> Result<(), WanMediaRuntimeError> {
    if ready.is_none() {
        return Ok(());
    }
    if !app_state.media_pipelines.lock().await.mark_wan_media_ready(
        authority.session_id(),
        authority.generation(),
        role,
        sequence,
    ) {
        return Err(WanMediaRuntimeError::Evidence);
    }
    let sender = ready.take().ok_or(WanMediaRuntimeError::Evidence)?;
    sender
        .send(Ok(WanMediaReadyEvidence::from_authority(
            authority, sequence,
        )))
        .map_err(|_| WanMediaRuntimeError::Evidence)
}

fn send_startup_failure(ready: &mut Option<WanMediaReadySender>) {
    if let Some(sender) = ready.take() {
        let _ = sender.send(Err(WanMediaActivationError::StartupFailed));
    }
}

fn terminalize_background_failure(app_state: Arc<AppState>, session_id: SessionId) {
    tokio::spawn(async move {
        let _ =
            super::service::fail_wan_session(&app_state, &session_id, WanSessionFailure::Transport)
                .await;
    });
}

fn validate_h264_profile(profile: &MediaProfile) -> Result<(), WanMediaActivationError> {
    if !profile.codec.eq_ignore_ascii_case("h264")
        || profile.width < 2
        || profile.height < 2
        || !profile.width.is_multiple_of(2)
        || !profile.height.is_multiple_of(2)
        || profile.fps == 0
        || profile.bitrate_mbps == 0
    {
        return Err(WanMediaActivationError::StartupFailed);
    }
    Ok(())
}

fn default_wan_media_profile() -> MediaProfile {
    MediaProfile {
        width: DEFAULT_WAN_MEDIA_WIDTH,
        height: DEFAULT_WAN_MEDIA_HEIGHT,
        fps: DEFAULT_WAN_MEDIA_FPS,
        bitrate_mbps: DEFAULT_WAN_MEDIA_BITRATE_MBPS,
        codec: "h264".to_owned(),
        ..MediaProfile::default()
    }
}

#[cfg(any(test, debug_assertions))]
fn now_unix_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
