use std::{sync::Arc, time::Duration};

use mrd_application::ports::{
    TransportEnvelope, TransportLane, TransportMuxPort, TransportSendOutcome, VideoEnvelopeMetadata,
};
use mrd_encode_openh264::OpenH264Encoder;
use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoEncoder};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::{
    app_state::WanMediaRuntimeRole,
    transports::{memory::MemoryTransportMux, TransportMuxConfig},
    wan_session::{
        coordinator::{NoopWanSessionCleanup, WanSessionClock, WanSessionCoordinator},
        media::start_verified_media,
        model::{
            GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionEvent, WanSessionIdentity,
            WanSessionPhase, WanSessionRole, WanSessionState,
        },
        service::ServiceWanMediaActivationPort,
    },
    AppState,
};
use mrd_signal_proto::{WanMediaProfileV3, WanPermissionScopeV3, WanRoutePolicyV3};

const TEST_NOW_MS: u64 = 1_000;

struct FixedClock;

impl WanSessionClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        TEST_NOW_MS
    }
}

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn media_profile() -> WanMediaProfileV3 {
    WanMediaProfileV3 {
        width: 64,
        height: 64,
        fps: 10,
        bitrate_mbps: 1,
        codec: "h264".to_owned(),
        codec_profile: None,
        bit_depth: None,
        chroma_subsampling: None,
        pixel_format: None,
        hdr_enabled: None,
        color_mode: None,
        color_pipeline: None,
    }
}

fn relay_verified_state(session_id: SessionId, role: WanSessionRole) -> WanSessionState {
    let identity = WanSessionIdentity::new(
        session_id,
        DeviceId("controller-media-device".to_owned()),
        DeviceId("target-media-device".to_owned()),
        digest('a'),
        digest('b'),
        20_000,
    )
    .expect("valid media identity");
    let mut state = WanSessionState::new(role, identity);
    state
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: digest('c'),
            },
            1_000,
        )
        .expect("backend bound");
    state
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: digest('d'),
            },
            1_001,
        )
        .expect("awaiting consent");
    let grant = GrantBinding::with_profile(
        digest('c'),
        vec![WanPermissionScopeV3::ScreenView],
        Some(media_profile()),
        7,
        19_000,
        18_000,
        WanRoutePolicyV3::RelayOnly,
    )
    .expect("valid media grant")
    .with_grant_commitment(digest('e'))
    .expect("signed media grant");
    let access = RelayAccessBinding::generation_zero(
        7,
        "media-directory".to_owned(),
        "media-relay".to_owned(),
        digest('f'),
    )
    .expect("valid media access");
    state
        .apply(WanSessionEvent::Granted(grant), 1_002)
        .expect("granted");
    state
        .apply(WanSessionEvent::AccessBound(access.clone()), 1_003)
        .expect("access bound");
    state
        .apply(WanSessionEvent::Negotiating, 1_004)
        .expect("negotiating");
    state
        .apply(
            WanSessionEvent::RelayVerified(
                RelayRouteProof::for_test(&access, true, true).expect("relay proof"),
            ),
            1_005,
        )
        .expect("relay verified");
    state
}

async fn coordinator_with_state(state: &WanSessionState) -> Arc<WanSessionCoordinator> {
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            Default::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(FixedClock),
        )
        .expect("media coordinator"),
    );
    coordinator
        .begin(state.clone())
        .await
        .expect("register media state");
    coordinator
}

async fn wait_for_active_tasks(app_state: &AppState, session_id: &SessionId, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if app_state.media_tasks.lock().await.active_count(session_id) == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("media task count converges");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_streaming_requires_first_encoded_mux_envelope_and_stop_cancels_task() {
    let session_id = SessionId("wan-media-target".to_owned());
    let state = relay_verified_state(session_id.clone(), WanSessionRole::Target);
    let coordinator = coordinator_with_state(&state).await;
    let app_state = Arc::new(AppState::new());
    let (local_mux, peer_mux) = MemoryTransportMux::pair(
        session_id.clone(),
        TransportMuxConfig {
            lane_capacity: 2,
            video_byte_capacity: 512 * 1024,
            ..TransportMuxConfig::test()
        },
    );
    let local_mux: Arc<dyn TransportMuxPort> = Arc::new(local_mux);
    let media = Arc::new(ServiceWanMediaActivationPort::with_test_mux(
        &app_state,
        session_id.clone(),
        local_mux,
    ));

    let activation = {
        let coordinator = Arc::clone(&coordinator);
        let media = Arc::clone(&media);
        let state = state.clone();
        tokio::spawn(
            async move { start_verified_media(&coordinator, &state, media.as_ref()).await },
        )
    };

    let envelope =
        tokio::time::timeout(Duration::from_secs(5), peer_mux.recv(TransportLane::Video))
            .await
            .expect("target emits video before deadline")
            .expect("memory mux receive")
            .expect("target video envelope");
    assert_eq!(envelope.session_id, session_id);
    assert_eq!(envelope.lane, TransportLane::Video);
    assert!(!envelope.payload.is_empty());
    assert_eq!(
        envelope
            .video
            .as_ref()
            .map(|metadata| metadata.codec.as_str()),
        Some("h264")
    );

    activation
        .await
        .expect("activation task joins")
        .expect("target media activates after evidence");
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Streaming
    );
    let runtime = app_state
        .media_pipelines
        .lock()
        .await
        .wan_media_runtime(&session_id)
        .expect("target runtime evidence");
    assert_eq!(runtime.role, WanMediaRuntimeRole::TargetSender);
    assert!(runtime.ready);
    assert!(runtime.ready_sequence.is_some());
    wait_for_active_tasks(&app_state, &session_id, 1).await;

    media.stop_media_for_test(&session_id).await.unwrap();
    wait_for_active_tasks(&app_state, &session_id, 0).await;
    assert!(app_state
        .media_pipelines
        .lock()
        .await
        .wan_media_runtime(&session_id)
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_stays_relay_verified_until_a_frame_is_decoded_and_render_ready() {
    let session_id = SessionId("wan-media-controller".to_owned());
    let state = relay_verified_state(session_id.clone(), WanSessionRole::Controller);
    let coordinator = coordinator_with_state(&state).await;
    let app_state = Arc::new(AppState::new());
    let (local_mux, peer_mux) =
        MemoryTransportMux::pair(session_id.clone(), TransportMuxConfig::test());
    let local_mux: Arc<dyn TransportMuxPort> = Arc::new(local_mux);
    let media = Arc::new(ServiceWanMediaActivationPort::with_test_mux(
        &app_state,
        session_id.clone(),
        local_mux,
    ));

    let activation = {
        let coordinator = Arc::clone(&coordinator);
        let media = Arc::clone(&media);
        let state = state.clone();
        tokio::spawn(
            async move { start_verified_media(&coordinator, &state, media.as_ref()).await },
        )
    };
    wait_for_active_tasks(&app_state, &session_id, 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::RelayVerified,
        "transport installation alone is not streaming evidence"
    );

    let mut encoder =
        OpenH264Encoder::new_with_bitrate(64, 64, 10, 1_000_000).expect("software test encoder");
    let frame = CapturedFrame::from_cpu(
        64,
        64,
        FramePixelFormat::Rgb24,
        123_000,
        vec![0x70; 64 * 64 * 3],
    );
    let access_unit = encoder
        .encode(&frame)
        .expect("encode controller fixture")
        .into_iter()
        .find(|unit| !unit.bytes.is_empty())
        .expect("encoded access unit");
    assert_eq!(
        peer_mux
            .send(TransportEnvelope {
                session_id: session_id.clone(),
                lane: TransportLane::Video,
                sequence: 1,
                payload: access_unit.bytes,
                video: Some(VideoEnvelopeMetadata {
                    codec: "h264".to_owned(),
                    timestamp_us: access_unit.timestamp_us,
                    keyframe: access_unit.is_keyframe,
                    width: 64,
                    height: 64,
                }),
            })
            .await
            .expect("send encoded controller fixture"),
        TransportSendOutcome::Enqueued
    );

    activation
        .await
        .expect("activation task joins")
        .expect("controller media activates after decode evidence");
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Streaming
    );
    let runtime = app_state
        .media_pipelines
        .lock()
        .await
        .wan_media_runtime(&session_id)
        .expect("controller runtime evidence");
    assert_eq!(runtime.role, WanMediaRuntimeRole::ControllerReceiver);
    assert!(runtime.ready);
    assert_eq!(runtime.ready_sequence, Some(1));
    assert!(app_state
        .media_pipelines
        .lock()
        .await
        .snapshot(&session_id)
        .active_decoder
        .is_some());

    media.stop_media_for_test(&session_id).await.unwrap();
    wait_for_active_tasks(&app_state, &session_id, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_rejects_non_granted_codec_without_publishing_streaming() {
    let session_id = SessionId("wan-media-controller-wrong-codec".to_owned());
    let state = relay_verified_state(session_id.clone(), WanSessionRole::Controller);
    let coordinator = coordinator_with_state(&state).await;
    let app_state = Arc::new(AppState::new());
    let (local_mux, peer_mux) =
        MemoryTransportMux::pair(session_id.clone(), TransportMuxConfig::test());
    let local_mux: Arc<dyn TransportMuxPort> = Arc::new(local_mux);
    let media = Arc::new(ServiceWanMediaActivationPort::with_test_mux(
        &app_state,
        session_id.clone(),
        local_mux,
    ));

    let activation = {
        let coordinator = Arc::clone(&coordinator);
        let media = Arc::clone(&media);
        let state = state.clone();
        tokio::spawn(
            async move { start_verified_media(&coordinator, &state, media.as_ref()).await },
        )
    };
    wait_for_active_tasks(&app_state, &session_id, 1).await;
    assert_eq!(
        peer_mux
            .send(TransportEnvelope {
                session_id: session_id.clone(),
                lane: TransportLane::Video,
                sequence: 1,
                payload: vec![1, 2, 3, 4],
                video: Some(VideoEnvelopeMetadata {
                    codec: "hevc".to_owned(),
                    timestamp_us: 1,
                    keyframe: true,
                    width: 64,
                    height: 64,
                }),
            })
            .await
            .expect("send wrong-codec fixture"),
        TransportSendOutcome::Enqueued
    );

    assert!(activation.await.expect("activation task joins").is_err());
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Failed
    );
    wait_for_active_tasks(&app_state, &session_id, 0).await;
    media.stop_media_for_test(&session_id).await.unwrap();
}
