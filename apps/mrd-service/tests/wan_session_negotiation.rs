use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use mrd_application::{
    AuthenticatedSessionSignal, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_proto::{DeviceId, SessionId};
use mrd_relay_control::{
    RelayDirectoryCandidate, RelayDirectoryEndpoint, RelayDirectoryPayload,
    RelayDirectoryTransport, RelayReservation, SignedRelayDirectory,
    RELAY_DIRECTORY_FORMAT_VERSION,
};
use mrd_service::relay::{
    relay_peer_digest, RelayAccessBackend, RelayAccessContext, RelayBackendError,
    RelayClientConfig, RelayClock, RelayDirectoryClient,
};
use mrd_service::wan_session::{
    coordinator::{
        NoopWanSessionCleanup, WanSessionCleanup, WanSessionClock, WanSessionCoordinator,
    },
    model::{
        GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionEvent, WanSessionFailure,
        WanSessionIdentity, WanSessionPhase, WanSessionRole, WanSessionState,
    },
    webrtc::{
        GenerationZeroClock, GenerationZeroInstallReceipt, GenerationZeroNegotiationAuthority,
        GenerationZeroNegotiationContext, GenerationZeroNegotiationError, GenerationZeroNegotiator,
        GenerationZeroRouteProof, GenerationZeroSessionInstaller, GenerationZeroSignaling,
        GenerationZeroSignalingError, GenerationZeroSignalingSubscription,
        GenerationZeroWebRtcHost, GenerationZeroWebRtcHostError,
    },
};
use mrd_signal_proto::{
    webrtc_candidate_fingerprint_v3, AuthClaims, SessionGrantV3, SessionGrantV3Payload,
    SessionIntentV3, SessionIntentV3Payload, SignedSignal, WanAccessModeV3, WanPermissionScopeV3,
    WanRoutePolicyV3, WanSessionRequestV3, WebRtcAnswerV3, WebRtcAnswerV3Payload,
    WebRtcCandidateV3, WebRtcCandidateV3Payload, WebRtcDescriptionRoleV3, WebRtcOfferV3,
    WebRtcOfferV3Payload,
};
use mrd_transport_webrtc::{IceCandidate, PeerConnectionConfig, SessionDescription};
use ring::digest::{digest, SHA256};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{mpsc, watch, Notify};

const NOW: u64 = 1_800_000_000_000;
const REQUEST_COMMITMENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const INTENT_COMMITMENT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const GRANT_COMMITMENT: &str = "3333333333333333333333333333333333333333333333333333333333333333";

static NEXT_TEST_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn test_session_id() -> SessionId {
    SessionId(format!(
        "negotiation-session-{}",
        NEXT_TEST_SESSION_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn identity_for_session(role: WanSessionRole, session_id: &SessionId) -> WanSessionIdentity {
    WanSessionIdentity::new(
        session_id.clone(),
        DeviceId("controller-device".into()),
        DeviceId("target-device".into()),
        "11".repeat(32),
        "22".repeat(32),
        20_000,
    )
    .expect(match role {
        WanSessionRole::Controller => "valid controller identity",
        WanSessionRole::Target => "valid target identity",
    })
}

fn access_binding() -> RelayAccessBinding {
    RelayAccessBinding::generation_zero(
        7,
        "directory-zero".into(),
        "relay-primary".into(),
        primary_digest(),
    )
    .expect("valid generation-zero route")
}

fn state_at_access_bound(
    session_id: &SessionId,
    role: WanSessionRole,
    bind_commitment: bool,
) -> WanSessionState {
    let mut state = WanSessionState::new(role, identity_for_session(role, session_id));
    state
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: REQUEST_COMMITMENT.into(),
            },
            1_000,
        )
        .unwrap();
    state
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: INTENT_COMMITMENT.into(),
            },
            1_001,
        )
        .unwrap();
    let grant = GrantBinding::new(
        REQUEST_COMMITMENT.into(),
        vec![WanPermissionScopeV3::ScreenView],
        7,
        10_000,
        9_000,
        WanRoutePolicyV3::RelayOnly,
    )
    .unwrap();
    let grant = if bind_commitment {
        grant
            .with_grant_commitment(GRANT_COMMITMENT.into())
            .unwrap()
    } else {
        grant
    };
    state.apply(WanSessionEvent::Granted(grant), 1_002).unwrap();
    state
        .apply(WanSessionEvent::AccessBound(access_binding()), 1_003)
        .unwrap();
    state
}

fn signed_identity(session_id: &SessionId) -> (WanSessionIdentity, DeviceIdentity, DeviceIdentity) {
    let controller =
        DeviceIdentity::generate(&ring::rand::SystemRandom::new()).expect("controller identity");
    let target =
        DeviceIdentity::generate(&ring::rand::SystemRandom::new()).expect("target identity");
    let identity = WanSessionIdentity::new(
        session_id.clone(),
        DeviceId("controller-device".into()),
        DeviceId("target-device".into()),
        controller.key_id().to_owned(),
        target.key_id().to_owned(),
        20_000,
    )
    .expect("signed session identity");
    (identity, controller, target)
}

fn signed_state_at_access_bound(
    session_id: &SessionId,
    role: WanSessionRole,
) -> (WanSessionState, DeviceIdentity, DeviceIdentity) {
    let (session_identity, controller, target) = signed_identity(session_id);
    let mut state = WanSessionState::new(role, session_identity);
    state
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: REQUEST_COMMITMENT.into(),
            },
            1_000,
        )
        .unwrap();
    state
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: INTENT_COMMITMENT.into(),
            },
            1_001,
        )
        .unwrap();
    let grant = GrantBinding::new(
        REQUEST_COMMITMENT.into(),
        vec![WanPermissionScopeV3::ScreenView],
        7,
        10_000,
        9_000,
        WanRoutePolicyV3::RelayOnly,
    )
    .unwrap()
    .with_grant_commitment(GRANT_COMMITMENT.into())
    .unwrap();
    state.apply(WanSessionEvent::Granted(grant), 1_002).unwrap();
    state
        .apply(WanSessionEvent::AccessBound(access_binding()), 1_003)
        .unwrap();
    (state, controller, target)
}

#[test]
fn generation_zero_negotiator_is_present_and_bounded() {
    let _ = std::mem::size_of::<GenerationZeroNegotiator>();
    assert!(GenerationZeroNegotiator::new(
        Arc::new(StubHost::default()),
        Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
        Arc::new(CountingInstaller::default()),
        Duration::from_millis(99),
    )
    .is_err());
}

#[test]
fn generation_zero_context_requires_access_bound_state() {
    let session_id = test_session_id();
    let state = WanSessionState::new(
        WanSessionRole::Controller,
        identity_for_session(WanSessionRole::Controller, &session_id),
    );
    assert_eq!(
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000),
        Err(GenerationZeroNegotiationError::NotReady)
    );
}

#[test]
fn generation_zero_context_requires_verified_grant_commitment() {
    let session_id = test_session_id();
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, false);
    assert_eq!(
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000),
        Err(GenerationZeroNegotiationError::InvalidBinding)
    );
}

#[test]
fn generation_zero_context_rejects_mutated_commitment_and_preserves_role_peer() {
    let session_id = test_session_id();
    let state = state_at_access_bound(&session_id, WanSessionRole::Target, true);
    assert_eq!(
        GenerationZeroNegotiationContext::from_state(
            &state,
            "4444444444444444444444444444444444444444444444444444444444444444".into(),
            1_000,
        ),
        Err(GenerationZeroNegotiationError::InvalidBinding)
    );
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    assert_eq!(context.role(), WanSessionRole::Target);
    assert_eq!(context.local_device_id(), &DeviceId("target-device".into()));
    assert_eq!(
        context.peer_device_id(),
        &DeviceId("controller-device".into())
    );
}

#[test]
fn route_proof_is_relay_only_and_debug_redacts_digest() {
    let digest = primary_digest();
    let proof = GenerationZeroRouteProof::for_test(
        test_session_id(),
        "directory-zero".into(),
        "relay-primary".into(),
        digest.clone(),
    )
    .unwrap();
    let debug = format!("{proof:?}");
    assert!(proof.is_relay_to_relay());
    assert!(!debug.contains(&digest));
    assert!(GenerationZeroRouteProof::for_test(
        test_session_id(),
        "directory-zero".into(),
        "relay-primary".into(),
        "not-a-digest".into(),
    )
    .is_err());
}

#[tokio::test]
async fn no_peer_opens_before_verified_access_and_authorization() {
    let session_id = test_session_id();
    let host = Arc::new(StubHost::default());
    let bus = Arc::new(mrd_service::signaling::RelaySignalingBus::default());
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        bus,
        Arc::new(CountingInstaller::default()),
        Duration::from_millis(100),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));
    let state = WanSessionState::new(
        WanSessionRole::Controller,
        identity_for_session(WanSessionRole::Controller, &session_id),
    );
    // Context construction is the authorization gate. No access-bound
    // context means the executor cannot reach the host at all.
    assert_eq!(
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000),
        Err(GenerationZeroNegotiationError::NotReady)
    );
    assert_eq!(host.open_count.load(Ordering::Acquire), 0);
    drop(negotiator);
}

#[tokio::test]
async fn primary_only_signed_relay_url_is_used_for_generation_zero() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let config = context.primary_peer_config(&access).unwrap();
    assert_eq!(
        config.ice_transport_policy,
        mrd_transport_webrtc::IceTransportPolicy::Relay
    );
    assert_eq!(config.ice_servers.len(), 1);
    assert_eq!(config.ice_servers[0].urls.len(), 1);
    assert_eq!(
        config.ice_servers[0].urls[0],
        "turn:relay-primary.example.test:3478?transport=udp"
    );
}

#[tokio::test]
async fn authority_revocation_is_rechecked_before_peer_open() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(StubHost::default());
    let authority = Arc::new(CountingAuthority {
        calls: AtomicUsize::new(0),
        revoke: AtomicBool::new(true),
    });
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
        Arc::new(CountingInstaller::default()),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock))
    .with_authority(authority.clone());
    assert_eq!(
        negotiator.negotiate(context, &access).await,
        Err(GenerationZeroNegotiationError::InvalidBinding)
    );
    assert_eq!(authority.calls.load(Ordering::Acquire), 1);
    assert_eq!(host.open_count.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn timeout_and_cancel_close_physical_peer_without_install() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(BlockingHost::default());
    let installer = Arc::new(CountingInstaller::default());
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
        installer.clone(),
        Duration::from_millis(100),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    let result = negotiator
        .negotiate_with_cancellation(context, &access, cancel_rx)
        .await;
    assert_eq!(result, Err(GenerationZeroNegotiationError::Timeout));
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
    assert_eq!(installer.installs.load(Ordering::Acquire), 0);

    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(BlockingHost::default());
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
        Arc::new(CountingInstaller::default()),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        negotiator
            .negotiate_with_cancellation(context, &access, cancel_rx)
            .await
    });
    host.started.notified().await;
    cancel_tx.send(true).unwrap();
    assert_eq!(
        task.await.unwrap(),
        Err(GenerationZeroNegotiationError::Cancelled)
    );
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn single_owner_rejects_parallel_install_and_releases_after_failure() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(BlockingHost::default());
    let negotiator = Arc::new(
        GenerationZeroNegotiator::new(
            host.clone(),
            Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
            Arc::new(CountingInstaller::default()),
            Duration::from_secs(1),
        )
        .unwrap()
        .with_clock(Arc::new(TestClock)),
    );
    let (cancel_tx, rx) = watch::channel(false);
    let first = tokio::spawn({
        let negotiator = Arc::clone(&negotiator);
        let access = Arc::clone(&access);
        let context = context.clone();
        async move {
            negotiator
                .negotiate_with_cancellation(context, &access, rx)
                .await
        }
    });
    host.started.notified().await;
    let second = negotiator
        .negotiate(context, &access)
        .await
        .expect_err("one session owner");
    assert_eq!(second, GenerationZeroNegotiationError::AlreadyOwned);
    cancel_tx.send(false).unwrap();
    host.release.notify_one();
    assert_eq!(
        first.await.unwrap(),
        Err(GenerationZeroNegotiationError::TransportUnavailable)
    );

    // The failed attempt releases ownership so a bounded retry can start.
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let retry_context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let retry = negotiator.negotiate(retry_context, &access).await;
    assert_eq!(
        retry,
        Err(GenerationZeroNegotiationError::TransportUnavailable)
    );
}

#[tokio::test]
async fn separate_negotiators_share_session_ownership_lease() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(BlockingHost::default());
    let (signaling, _commands) = ScriptedSignaling::new();
    let first = Arc::new(
        GenerationZeroNegotiator::new(
            host.clone(),
            signaling.clone(),
            Arc::new(CountingInstaller::default()),
            Duration::from_secs(1),
        )
        .unwrap()
        .with_clock(Arc::new(TestClock)),
    );
    let second = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        Arc::new(CountingInstaller::default()),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let first_task = tokio::spawn({
        let first = Arc::clone(&first);
        let context = context.clone();
        let first_access = Arc::clone(&access);
        async move {
            first
                .negotiate_with_cancellation(context, &first_access, cancel_rx)
                .await
        }
    });
    host.started.notified().await;

    assert_eq!(
        second.negotiate(context, &access).await,
        Err(GenerationZeroNegotiationError::AlreadyOwned)
    );
    assert_eq!(host.open_count.load(Ordering::Acquire), 1);

    cancel_tx.send(true).unwrap();
    assert_eq!(
        first_task.await.unwrap(),
        Err(GenerationZeroNegotiationError::Cancelled)
    );
}

#[tokio::test]
async fn controller_executor_orders_manifest_candidates_connection_proof_and_install() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, commands) = ScriptedSignaling::new();
    signaling.publish(history_grant_event(
        &target,
        context.identity().session_id(),
        context.identity().controller_device_id(),
        context.identity().target_device_id(),
    ));
    let driver = spawn_answer_driver(
        Arc::clone(&signaling),
        Arc::clone(&order),
        target,
        false,
        commands,
    );
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));

    let result = negotiator.negotiate(context, &access).await;
    assert!(
        result.is_ok(),
        "executor happy path should complete: {result:?}"
    );
    driver.abort();
    let _ = driver.await;

    let order = order.lock().unwrap().clone();
    assert_order(
        &order,
        &[
            "open",
            "create_offer",
            "send:offer",
            "send:candidate",
            "accept_answer",
            "add_remote_candidate",
            "wait_connected",
            "prove_route",
            "install",
        ],
    );
    assert_eq!(installer.installs.load(Ordering::Acquire), 1);
    assert_eq!(host.close_count.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn target_executor_buffers_candidate_before_offer_and_skips_history_intent() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "controller-device").await;
    let (state, controller, _target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Target);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::target(
        Arc::clone(&order),
        proof,
        vec![local_candidate("target-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, _commands) = ScriptedSignaling::with_order(Arc::clone(&order));
    signaling.publish(history_intent_event(
        &controller,
        context.identity().session_id(),
        context.identity().controller_device_id(),
        context.identity().target_device_id(),
    ));
    let remote_candidate = signed_candidate_event_with_role(
        &controller,
        context.identity().session_id(),
        context.identity().controller_device_id(),
        context.identity().target_device_id(),
        context.grant_commitment(),
        WebRtcDescriptionRoleV3::Offer,
        "candidate:remote-controller 1 UDP 1 192.0.2.2 9 typ relay",
        2,
    );
    let remote_fingerprint = match &remote_candidate.signal {
        AuthenticatedSessionSignal::WebRtcCandidateV3 { message } => {
            message.payload.candidate_fingerprint.clone()
        }
        _ => unreachable!("candidate helper returned candidate"),
    };
    signaling.publish(remote_candidate);
    signaling.publish(signed_offer_event(
        &controller,
        context.identity().session_id(),
        context.identity().controller_device_id(),
        context.identity().target_device_id(),
        context.grant_commitment(),
        vec![remote_fingerprint],
        1,
    ));

    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));
    let result = negotiator.negotiate(context, &access).await;
    assert!(
        result.is_ok(),
        "target executor should complete after manifest: {result:?}"
    );
    assert_order(
        &order.lock().unwrap(),
        &[
            "open",
            "accept_offer",
            "add_remote_candidate",
            "send:answer",
            "send:candidate",
            "wait_connected",
            "prove_route",
            "install",
        ],
    );
    assert_eq!(installer.installs.load(Ordering::Acquire), 1);
    assert_eq!(host.close_count.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn coordinator_commit_advances_success_to_relay_verified() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            Default::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(CoordinatorTestClock),
        )
        .unwrap(),
    );
    coordinator.begin(state).await.unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_answer_driver(
        Arc::clone(&signaling),
        Arc::clone(&order),
        target,
        false,
        commands,
    );
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock))
    .with_coordinator(Arc::clone(&coordinator));
    let result = negotiator.negotiate(context, &access).await;
    driver.abort();
    let _ = driver.await;
    assert!(result.is_ok(), "coordinator-backed negotiation: {result:?}");
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::RelayVerified
    );
    assert_eq!(installer.installs.load(Ordering::Acquire), 1);
    assert_eq!(host.close_count.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn coordinator_commit_rejects_an_unbound_backend_grant_before_install() {
    let session_id = test_session_id();
    let mut state = state_at_access_bound(&session_id, WanSessionRole::Controller, false);
    state.apply(WanSessionEvent::Negotiating, 1_004).unwrap();
    let identity = state.identity().clone();
    let grant = state.grant().unwrap().clone();
    let access = state.access().unwrap().clone();
    let proof = RelayRouteProof::for_test(&access, true, true).unwrap();
    let coordinator = WanSessionCoordinator::new(
        Default::default(),
        Arc::new(NoopWanSessionCleanup),
        Arc::new(CoordinatorTestClock),
    )
    .unwrap();
    coordinator.begin(state).await.unwrap();
    let installed = Arc::new(AtomicBool::new(false));
    let installed_for_call = Arc::clone(&installed);

    assert!(matches!(
        coordinator
            .commit_generation_zero(
                identity.session_id(),
                WanSessionRole::Controller,
                &identity,
                &grant,
                &access,
                proof,
                move || async move {
                    installed_for_call.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .await,
        Err(mrd_service::wan_session::coordinator::WanSessionCoordinatorError::BackendBindingMismatch)
    ));
    assert!(!installed.load(Ordering::Acquire));
}

#[tokio::test]
async fn coordinator_recheck_after_install_returns_deadline_error_and_cleans_up() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let clock = AdvancingClock::new(1_000);
    let cleanup = Arc::new(RecordingCleanup::default());
    let coordinator = Arc::new(
        WanSessionCoordinator::new(Default::default(), cleanup.clone(), clock.clone()).unwrap(),
    );
    coordinator.begin(state).await.unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(DeadlineAdvancingInstaller::new(
        Arc::clone(&clock),
        context.identity().deadline_unix_ms(),
    ));
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_answer_driver(
        Arc::clone(&signaling),
        Arc::clone(&order),
        target,
        false,
        commands,
    );
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(clock.clone())
    .with_coordinator(Arc::clone(&coordinator));

    let result = negotiator.negotiate(context, &access).await;
    driver.abort();
    let _ = driver.await;

    assert_eq!(
        result,
        Err(GenerationZeroNegotiationError::DeadlineExceeded)
    );
    assert_eq!(installer.installs.load(Ordering::Acquire), 1);
    assert_eq!(installer.rollbacks.load(Ordering::Acquire), 1);
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
    assert_eq!(cleanup.calls.load(Ordering::Acquire), 6);
    let snapshot = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(snapshot.phase(), WanSessionPhase::Failed);
    assert_eq!(
        snapshot.failure(),
        Some(WanSessionFailure::DeadlineExceeded)
    );
}

#[tokio::test]
async fn post_install_authority_failure_rolls_back_install_receipt() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_answer_driver(
        Arc::clone(&signaling),
        Arc::clone(&order),
        target,
        false,
        commands,
    );
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock))
    .with_authority(Arc::new(RevokeAfterInstallAuthority::default()));

    assert_eq!(
        negotiator.negotiate(context, &access).await,
        Err(GenerationZeroNegotiationError::InvalidBinding)
    );
    driver.abort();
    let _ = driver.await;
    assert_eq!(installer.installs.load(Ordering::Acquire), 1);
    assert_eq!(installer.rollbacks.load(Ordering::Acquire), 1);
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn installer_cancellation_fails_coordinator_and_runs_cleanup() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            Default::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(CoordinatorTestClock),
        )
        .unwrap(),
    );
    coordinator.begin(state).await.unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(HangingInstaller::default());
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_answer_driver(
        Arc::clone(&signaling),
        Arc::clone(&order),
        target,
        false,
        commands,
    );
    let negotiator = Arc::new(
        GenerationZeroNegotiator::new(
            host.clone(),
            signaling,
            installer.clone(),
            Duration::from_secs(1),
        )
        .unwrap()
        .with_clock(Arc::new(TestClock))
        .with_coordinator(Arc::clone(&coordinator)),
    );
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let task = tokio::spawn({
        let negotiator = Arc::clone(&negotiator);
        async move {
            negotiator
                .negotiate_with_cancellation(context, &access, cancel_rx)
                .await
        }
    });
    installer.started.notified().await;
    cancel_tx.send(true).unwrap();
    assert_eq!(
        task.await.unwrap(),
        Err(GenerationZeroNegotiationError::Cancelled)
    );
    driver.abort();
    let _ = driver.await;
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
    assert_eq!(installer.rollbacks.load(Ordering::Acquire), 1);
    let snapshot = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(snapshot.phase(), WanSessionPhase::Failed);
    assert_eq!(snapshot.failure(), Some(WanSessionFailure::Cancelled));
}

#[tokio::test]
async fn exact_grant_deadline_rejects_before_opening_or_installing() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(StubHost::default());
    let installer = Arc::new(CountingInstaller::default());
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(FixedGenerationZeroClock(9_000)));
    assert_eq!(
        negotiator.negotiate(context, &access).await,
        Err(GenerationZeroNegotiationError::DeadlineExceeded)
    );
    assert_eq!(host.open_count.load(Ordering::Acquire), 0);
    assert_eq!(installer.installs.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn executor_rejects_extra_candidate_after_exact_manifest_and_closes_without_install() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_answer_driver(
        Arc::clone(&signaling),
        Arc::clone(&order),
        target,
        true,
        commands,
    );
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));

    let result = negotiator.negotiate(context, &access).await;
    assert_eq!(
        result,
        Err(GenerationZeroNegotiationError::CandidateManifestMismatch)
    );
    driver.abort();
    let _ = driver.await;
    assert_eq!(installer.installs.load(Ordering::Acquire), 0);
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn executor_rejects_duplicate_remote_candidate_and_closes_without_install() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_duplicate_candidate_driver(Arc::clone(&signaling), target, commands);
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));

    let result = negotiator.negotiate(context, &access).await;
    driver.abort();
    let _ = driver.await;

    assert_eq!(
        result,
        Err(GenerationZeroNegotiationError::CandidateDuplicate)
    );
    assert_eq!(installer.installs.load(Ordering::Acquire), 0);
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn executor_rejects_wrong_remote_description_role_and_closes_without_install() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let (state, _controller, target) =
        signed_state_at_access_bound(&session_id, WanSessionRole::Controller);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let proof = GenerationZeroRouteProof::for_test(
        context.identity().session_id().clone(),
        context.access().directory_id().into(),
        context.access().primary_node_id().into(),
        context.access().relay_url_digest().into(),
    )
    .unwrap();
    let host = Arc::new(ScriptedHost::new(
        Arc::clone(&order),
        proof,
        vec![local_candidate("controller-candidate")],
    ));
    let installer = Arc::new(OrderedInstaller::new(Arc::clone(&order)));
    let (signaling, commands) = ScriptedSignaling::new();
    let driver = spawn_wrong_description_driver(Arc::clone(&signaling), target, commands);
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        signaling,
        installer.clone(),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));

    let result = negotiator.negotiate(context, &access).await;
    driver.abort();
    let _ = driver.await;

    assert_eq!(
        result,
        Err(GenerationZeroNegotiationError::CandidateWrongRole)
    );
    assert_eq!(installer.installs.load(Ordering::Acquire), 0);
    assert_eq!(host.close_count.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn rejected_open_does_not_close_an_existing_peer_session() {
    let session_id = test_session_id();
    let access = relay_access(&session_id, "target-device").await;
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    let host = Arc::new(StubHost::default());
    let negotiator = GenerationZeroNegotiator::new(
        host.clone(),
        Arc::new(mrd_service::signaling::RelaySignalingBus::default()),
        Arc::new(CountingInstaller::default()),
        Duration::from_secs(1),
    )
    .unwrap()
    .with_clock(Arc::new(TestClock));

    assert_eq!(
        negotiator.negotiate(context, &access).await,
        Err(GenerationZeroNegotiationError::TransportUnavailable)
    );
    assert_eq!(host.close_count.load(Ordering::Acquire), 0);
}

#[test]
fn all_terminal_candidate_and_route_failures_are_closed_errors() {
    let errors = [
        GenerationZeroNegotiationError::CandidateManifestMismatch,
        GenerationZeroNegotiationError::CandidateDuplicate,
        GenerationZeroNegotiationError::CandidateWrongRole,
        GenerationZeroNegotiationError::RouteEvidenceMismatch,
    ];
    for error in errors {
        let text = error.to_string();
        assert!(!text.contains("candidate:"));
        assert!(!text.contains("turn:"));
        assert!(!text.contains(GRANT_COMMITMENT));
    }
}

#[test]
fn context_state_is_immutable_generation_zero_and_deadline_bound() {
    let session_id = test_session_id();
    let state = state_at_access_bound(&session_id, WanSessionRole::Controller, true);
    let context =
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 1_000)
            .unwrap();
    assert_eq!(context.access().generation(), 0);
    assert!(
        GenerationZeroNegotiationContext::from_state(&state, GRANT_COMMITMENT.into(), 20_000)
            .is_err()
    );
    assert_eq!(state.phase(), WanSessionPhase::AccessBound);
}

struct ScriptedSignaling {
    commands: mpsc::UnboundedSender<mrd_service::signaling::AuthenticatedSessionSignalingCommand>,
    events: Arc<Mutex<VecDeque<VerifiedSignalingEvent>>>,
    events_ready: Arc<Notify>,
    command_order: Option<Arc<Mutex<Vec<String>>>>,
}

impl ScriptedSignaling {
    fn new() -> (
        Arc<Self>,
        mpsc::UnboundedReceiver<mrd_service::signaling::AuthenticatedSessionSignalingCommand>,
    ) {
        Self::with_command_order(None)
    }

    fn with_order(
        order: Arc<Mutex<Vec<String>>>,
    ) -> (
        Arc<Self>,
        mpsc::UnboundedReceiver<mrd_service::signaling::AuthenticatedSessionSignalingCommand>,
    ) {
        Self::with_command_order(Some(order))
    }

    fn with_command_order(
        command_order: Option<Arc<Mutex<Vec<String>>>>,
    ) -> (
        Arc<Self>,
        mpsc::UnboundedReceiver<mrd_service::signaling::AuthenticatedSessionSignalingCommand>,
    ) {
        let (commands, receiver) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                commands,
                events: Arc::new(Mutex::new(VecDeque::new())),
                events_ready: Arc::new(Notify::new()),
                command_order,
            }),
            receiver,
        )
    }

    fn publish(&self, event: VerifiedSignalingEvent) {
        self.events.lock().unwrap().push_back(event);
        self.events_ready.notify_waiters();
    }
}

struct ScriptedSubscription {
    session_id: SessionId,
    peer_device_id: DeviceId,
    events: Arc<Mutex<VecDeque<VerifiedSignalingEvent>>>,
    events_ready: Arc<Notify>,
}

impl ScriptedSubscription {
    fn take_matching(&self) -> Option<VerifiedSignalingEvent> {
        let mut events = self.events.lock().unwrap();
        while let Some(event) = events.pop_front() {
            if event.signal.session_id() == &self.session_id
                && event.sender.device_id == self.peer_device_id
            {
                return Some(event);
            }
        }
        None
    }
}

#[async_trait]
impl GenerationZeroSignalingSubscription for ScriptedSubscription {
    async fn recv(&mut self) -> Result<VerifiedSignalingEvent, GenerationZeroSignalingError> {
        loop {
            let notified = self.events_ready.notified();
            if let Some(event) = self.take_matching() {
                return Ok(event);
            }
            notified.await;
        }
    }

    async fn try_recv(
        &mut self,
    ) -> Result<Option<VerifiedSignalingEvent>, GenerationZeroSignalingError> {
        Ok(self.take_matching())
    }
}

#[async_trait]
impl GenerationZeroSignaling for ScriptedSignaling {
    fn subscribe(
        self: Arc<Self>,
        session_id: SessionId,
        peer_device_id: DeviceId,
    ) -> Box<dyn GenerationZeroSignalingSubscription> {
        Box::new(ScriptedSubscription {
            session_id,
            peer_device_id,
            events: Arc::clone(&self.events),
            events_ready: Arc::clone(&self.events_ready),
        })
    }

    async fn send(
        &self,
        command: mrd_service::signaling::AuthenticatedSessionSignalingCommand,
    ) -> Result<(), GenerationZeroSignalingError> {
        if let Some(order) = &self.command_order {
            match &command.signal {
                mrd_service::signaling::OutboundAuthenticatedSessionSignal::WebRtcAnswer {
                    ..
                } => order.lock().unwrap().push("send:answer".into()),
                mrd_service::signaling::OutboundAuthenticatedSessionSignal::WebRtcCandidate {
                    ..
                } => order.lock().unwrap().push("send:candidate".into()),
                _ => {}
            }
        }
        self.commands
            .send(command)
            .map_err(|_| GenerationZeroSignalingError::Unavailable)
    }
}

#[derive(Clone, Copy)]
enum ScriptedHostRole {
    Controller,
    Target,
}

struct ScriptedHost {
    role: ScriptedHostRole,
    order: Arc<Mutex<Vec<String>>>,
    proof: GenerationZeroRouteProof,
    local_candidates: Mutex<VecDeque<IceCandidate>>,
    close_count: AtomicUsize,
}

impl ScriptedHost {
    fn new(
        order: Arc<Mutex<Vec<String>>>,
        proof: GenerationZeroRouteProof,
        local_candidates: Vec<IceCandidate>,
    ) -> Self {
        Self {
            role: ScriptedHostRole::Controller,
            order,
            proof,
            local_candidates: Mutex::new(local_candidates.into()),
            close_count: AtomicUsize::new(0),
        }
    }

    fn target(
        order: Arc<Mutex<Vec<String>>>,
        proof: GenerationZeroRouteProof,
        local_candidates: Vec<IceCandidate>,
    ) -> Self {
        Self {
            role: ScriptedHostRole::Target,
            order,
            proof,
            local_candidates: Mutex::new(local_candidates.into()),
            close_count: AtomicUsize::new(0),
        }
    }

    fn record(&self, step: &str) {
        self.order.lock().unwrap().push(step.to_owned());
    }
}

#[async_trait]
impl GenerationZeroWebRtcHost for ScriptedHost {
    async fn open_generation_zero(
        &self,
        _: &SessionId,
        config: PeerConnectionConfig,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        if config.ice_transport_policy != mrd_transport_webrtc::IceTransportPolicy::Relay
            || config.ice_servers.len() != 1
        {
            return Err(GenerationZeroWebRtcHostError::Rejected);
        }
        self.record("open");
        Ok(())
    }

    async fn create_offer(
        &self,
        _: &SessionId,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        if matches!(self.role, ScriptedHostRole::Target) {
            return Err(GenerationZeroWebRtcHostError::Rejected);
        }
        self.record("create_offer");
        SessionDescription::from_wire(
            mrd_transport_webrtc::SessionDescriptionType::Offer,
            "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0".into(),
            0,
            None,
        )
        .map_err(|_| GenerationZeroWebRtcHostError::Rejected)
    }

    async fn accept_offer(
        &self,
        _: &SessionId,
        _: SessionDescription,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        if matches!(self.role, ScriptedHostRole::Controller) {
            self.record("accept_offer");
            return Err(GenerationZeroWebRtcHostError::Unavailable);
        }
        self.record("accept_offer");
        SessionDescription::from_wire(
            mrd_transport_webrtc::SessionDescriptionType::Answer,
            "v=0\\r\\no=- 2 2 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0".into(),
            0,
            None,
        )
        .map_err(|_| GenerationZeroWebRtcHostError::Rejected)
    }

    async fn accept_answer(
        &self,
        _: &SessionId,
        _: SessionDescription,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        if matches!(self.role, ScriptedHostRole::Target) {
            return Err(GenerationZeroWebRtcHostError::Rejected);
        }
        self.record("accept_answer");
        Ok(())
    }

    async fn next_local_candidate(
        &self,
        _: &SessionId,
    ) -> Result<Option<IceCandidate>, GenerationZeroWebRtcHostError> {
        Ok(self.local_candidates.lock().unwrap().pop_front())
    }

    async fn add_remote_candidate(
        &self,
        _: &SessionId,
        _: IceCandidate,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        self.record("add_remote_candidate");
        Ok(())
    }

    async fn wait_connected(&self, _: &SessionId) -> Result<(), GenerationZeroWebRtcHostError> {
        self.record("wait_connected");
        Ok(())
    }

    async fn prove_generation_zero_route(
        &self,
        _: &mrd_service::relay::RelayRouteEvidence,
        _: &SessionId,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroWebRtcHostError> {
        self.record("prove_route");
        Ok(self.proof.clone())
    }

    async fn close_session(&self, _: &SessionId) -> Result<(), GenerationZeroWebRtcHostError> {
        self.close_count.fetch_add(1, Ordering::AcqRel);
        self.record("close");
        Ok(())
    }
}

struct OrderedInstaller {
    order: Arc<Mutex<Vec<String>>>,
    installs: AtomicUsize,
    rollbacks: Arc<AtomicUsize>,
}

impl OrderedInstaller {
    fn new(order: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            order,
            installs: AtomicUsize::new(0),
            rollbacks: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct TestInstallReceipt {
    rollbacks: Arc<AtomicUsize>,
}

#[async_trait]
impl GenerationZeroInstallReceipt for TestInstallReceipt {
    async fn rollback(&self) -> Result<(), GenerationZeroNegotiationError> {
        self.rollbacks.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[async_trait]
impl GenerationZeroSessionInstaller for OrderedInstaller {
    async fn install_generation_zero(
        &self,
        _: &GenerationZeroRouteProof,
    ) -> Result<Box<dyn GenerationZeroInstallReceipt>, GenerationZeroNegotiationError> {
        self.installs.fetch_add(1, Ordering::AcqRel);
        self.order.lock().unwrap().push("install".into());
        Ok(Box::new(TestInstallReceipt {
            rollbacks: Arc::clone(&self.rollbacks),
        }))
    }
}

#[derive(Default)]
struct HangingInstaller {
    started: Notify,
    rollbacks: AtomicUsize,
}

#[async_trait]
impl GenerationZeroSessionInstaller for HangingInstaller {
    async fn install_generation_zero(
        &self,
        _: &GenerationZeroRouteProof,
    ) -> Result<Box<dyn GenerationZeroInstallReceipt>, GenerationZeroNegotiationError> {
        self.started.notify_waiters();
        std::future::pending::<()>().await;
        unreachable!("hanging installer never returns")
    }

    async fn rollback_generation_zero(
        &self,
        _: &GenerationZeroRouteProof,
    ) -> Result<(), GenerationZeroNegotiationError> {
        self.rollbacks.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn assert_order(actual: &[String], expected: &[&str]) {
    let mut cursor = 0;
    for step in expected {
        let position = actual[cursor..]
            .iter()
            .position(|actual_step| actual_step == step)
            .unwrap_or_else(|| panic!("missing step {step:?} in {actual:?}"));
        cursor += position + 1;
    }
}

fn local_candidate(label: &str) -> IceCandidate {
    IceCandidate::from_wire(
        format!("candidate:{label} 1 UDP 1 192.0.2.1 9 typ host"),
        Some("0".into()),
        Some(0),
        Some(format!("{label}-fragment")),
        0,
        None,
    )
    .expect("test ICE candidate")
}

fn spawn_answer_driver(
    signaling: Arc<ScriptedSignaling>,
    order: Arc<Mutex<Vec<String>>>,
    target: DeviceIdentity,
    include_extra: bool,
    mut commands: mpsc::UnboundedReceiver<
        mrd_service::signaling::AuthenticatedSessionSignalingCommand,
    >,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(command) = commands.recv().await {
            match command.signal {
                mrd_service::signaling::OutboundAuthenticatedSessionSignal::WebRtcOffer {
                    session_id,
                    controller_device_id,
                    target_device_id,
                    grant_commitment,
                    candidate_fingerprints,
                    ..
                } => {
                    order.lock().unwrap().push("send:offer".into());
                    let expected_candidate = signed_candidate_event(
                        &target,
                        &session_id,
                        &controller_device_id,
                        &target_device_id,
                        &grant_commitment,
                        "candidate:remote 1 UDP 1 192.0.2.2 9 typ relay",
                        2,
                    );
                    assert_eq!(candidate_fingerprints.len(), 1);
                    let remote_fingerprint = match &expected_candidate.signal {
                        AuthenticatedSessionSignal::WebRtcCandidateV3 { message } => {
                            message.payload.candidate_fingerprint.clone()
                        }
                        _ => unreachable!("candidate helper returned candidate"),
                    };
                    let answer = signed_answer_event(
                        &target,
                        &session_id,
                        &controller_device_id,
                        &target_device_id,
                        &grant_commitment,
                        vec![remote_fingerprint],
                        1,
                    );
                    // Candidate arrives before its description on purpose;
                    // the executor must buffer it until the manifest lands.
                    signaling.publish(expected_candidate);
                    signaling.publish(answer);
                    if include_extra {
                        // History may contain same-session protocol messages
                        // interleaved with the WebRTC manifest. The executor
                        // must keep the bounded quiescence drain alive until
                        // it observes the trailing candidate, rather than
                        // treating the first history item as the end.
                        signaling.publish(history_grant_event(
                            &target,
                            &session_id,
                            &controller_device_id,
                            &target_device_id,
                        ));
                        signaling.publish(signed_candidate_event(
                            &target,
                            &session_id,
                            &controller_device_id,
                            &target_device_id,
                            &grant_commitment,
                            "candidate:extra 1 UDP 1 192.0.2.3 9 typ relay",
                            3,
                        ));
                    }
                }
                mrd_service::signaling::OutboundAuthenticatedSessionSignal::WebRtcCandidate {
                    ..
                } => order.lock().unwrap().push("send:candidate".into()),
                _ => {}
            }
        }
    })
}

fn spawn_duplicate_candidate_driver(
    signaling: Arc<ScriptedSignaling>,
    target: DeviceIdentity,
    mut commands: mpsc::UnboundedReceiver<
        mrd_service::signaling::AuthenticatedSessionSignalingCommand,
    >,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(command) = commands.recv().await {
            if let mrd_service::signaling::OutboundAuthenticatedSessionSignal::WebRtcOffer {
                session_id,
                controller_device_id,
                target_device_id,
                grant_commitment,
                ..
            } = command.signal
            {
                let candidate = "candidate:remote 1 UDP 1 192.0.2.2 9 typ relay";
                signaling.publish(signed_candidate_event(
                    &target,
                    &session_id,
                    &controller_device_id,
                    &target_device_id,
                    &grant_commitment,
                    candidate,
                    2,
                ));
                signaling.publish(signed_candidate_event(
                    &target,
                    &session_id,
                    &controller_device_id,
                    &target_device_id,
                    &grant_commitment,
                    candidate,
                    2,
                ));
                break;
            }
        }
    })
}

fn spawn_wrong_description_driver(
    signaling: Arc<ScriptedSignaling>,
    target: DeviceIdentity,
    mut commands: mpsc::UnboundedReceiver<
        mrd_service::signaling::AuthenticatedSessionSignalingCommand,
    >,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(command) = commands.recv().await {
            if let mrd_service::signaling::OutboundAuthenticatedSessionSignal::WebRtcOffer {
                session_id,
                controller_device_id,
                target_device_id,
                grant_commitment,
                ..
            } = command.signal
            {
                signaling.publish(signed_wrong_role_offer_event(
                    &target,
                    &session_id,
                    &controller_device_id,
                    &target_device_id,
                    &grant_commitment,
                    vec!["aa".repeat(32)],
                    1,
                ));
                break;
            }
        }
    })
}

fn signed_answer_event(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    candidate_fingerprints: Vec<String>,
    counter: u64,
) -> VerifiedSignalingEvent {
    let claims = responder_claims(signer, target_device_id, controller_device_id, counter);
    let message = WebRtcAnswerV3::sign(
        signer,
        WebRtcAnswerV3Payload {
            claims: claims.clone(),
            session_id: session_id.clone(),
            controller_device_id: controller_device_id.clone(),
            target_device_id: target_device_id.clone(),
            grant_commitment: grant_commitment.into(),
            sdp: "v=0\\r\\no=- 2 2 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0".into(),
            candidate_fingerprints,
        },
    )
    .expect("signed answer");
    VerifiedSignalingEvent {
        sender: verified_sender(signer, &claims),
        signal: AuthenticatedSessionSignal::WebRtcAnswerV3 { message },
    }
}

fn signed_candidate_event(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    candidate: &str,
    counter: u64,
) -> VerifiedSignalingEvent {
    signed_candidate_event_with_role(
        signer,
        session_id,
        controller_device_id,
        target_device_id,
        grant_commitment,
        WebRtcDescriptionRoleV3::Answer,
        candidate,
        counter,
    )
}

fn signed_candidate_event_with_role(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    role: WebRtcDescriptionRoleV3,
    candidate: &str,
    counter: u64,
) -> VerifiedSignalingEvent {
    let sdp_mid = Some("0".to_owned());
    let sdp_mline_index = Some(0);
    let username_fragment = Some("remote-fragment".to_owned());
    let candidate_fingerprint = webrtc_candidate_fingerprint_v3(
        session_id,
        grant_commitment,
        role,
        candidate,
        sdp_mid.as_deref(),
        sdp_mline_index,
        username_fragment.as_deref(),
    );
    let claims = match role {
        WebRtcDescriptionRoleV3::Offer => {
            responder_claims(signer, controller_device_id, target_device_id, counter)
        }
        WebRtcDescriptionRoleV3::Answer => {
            responder_claims(signer, target_device_id, controller_device_id, counter)
        }
    };
    let message = WebRtcCandidateV3::sign(
        signer,
        WebRtcCandidateV3Payload {
            claims: claims.clone(),
            session_id: session_id.clone(),
            controller_device_id: controller_device_id.clone(),
            target_device_id: target_device_id.clone(),
            grant_commitment: grant_commitment.into(),
            description_role: role,
            candidate: candidate.into(),
            sdp_mid,
            sdp_mline_index,
            username_fragment,
            candidate_fingerprint,
        },
    )
    .expect("signed candidate");
    VerifiedSignalingEvent {
        sender: verified_sender(signer, &claims),
        signal: AuthenticatedSessionSignal::WebRtcCandidateV3 { message },
    }
}

fn signed_offer_event(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    candidate_fingerprints: Vec<String>,
    counter: u64,
) -> VerifiedSignalingEvent {
    let claims = responder_claims(signer, controller_device_id, target_device_id, counter);
    let message = WebRtcOfferV3::sign(
        signer,
        WebRtcOfferV3Payload {
            claims: claims.clone(),
            session_id: session_id.clone(),
            controller_device_id: controller_device_id.clone(),
            target_device_id: target_device_id.clone(),
            grant_commitment: grant_commitment.into(),
            sdp: "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0".into(),
            candidate_fingerprints,
        },
    )
    .expect("signed offer");
    VerifiedSignalingEvent {
        sender: verified_sender(signer, &claims),
        signal: AuthenticatedSessionSignal::WebRtcOfferV3 { message },
    }
}

fn signed_wrong_role_offer_event(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    candidate_fingerprints: Vec<String>,
    counter: u64,
) -> VerifiedSignalingEvent {
    let claims = responder_claims(signer, target_device_id, controller_device_id, counter);
    let message = SignedSignal {
        payload: WebRtcOfferV3Payload {
            claims: claims.clone(),
            session_id: session_id.clone(),
            controller_device_id: controller_device_id.clone(),
            target_device_id: target_device_id.clone(),
            grant_commitment: grant_commitment.into(),
            sdp: "v=0\\r\\no=- 1 1 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0".into(),
            candidate_fingerprints,
        },
        signer_public_key: signer.public_key().to_vec(),
        signature: Vec::new(),
    };
    VerifiedSignalingEvent {
        sender: verified_sender(signer, &claims),
        signal: AuthenticatedSessionSignal::WebRtcOfferV3 { message },
    }
}

fn history_intent_event(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
) -> VerifiedSignalingEvent {
    let request = WanSessionRequestV3 {
        session_id: session_id.clone(),
        idempotency_key: [9; 16],
        controller_device_id: controller_device_id.clone(),
        target_device_id: target_device_id.clone(),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![WanPermissionScopeV3::ScreenView],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    };
    let request_commitment = request.commitment().expect("history request commitment");
    let claims = responder_claims(signer, controller_device_id, target_device_id, 40);
    let message = SessionIntentV3::sign(
        signer,
        SessionIntentV3Payload {
            claims: claims.clone(),
            request,
            request_commitment,
        },
    )
    .expect("history intent");
    VerifiedSignalingEvent {
        sender: verified_sender(signer, &claims),
        signal: AuthenticatedSessionSignal::SessionIntentV3 { message },
    }
}

fn history_grant_event(
    signer: &DeviceIdentity,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
) -> VerifiedSignalingEvent {
    let claims = responder_claims(signer, target_device_id, controller_device_id, 41);
    let message = SessionGrantV3::sign(
        signer,
        SessionGrantV3Payload {
            claims: claims.clone(),
            session_id: session_id.clone(),
            controller_device_id: controller_device_id.clone(),
            target_device_id: target_device_id.clone(),
            intent_commitment: INTENT_COMMITMENT.into(),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: None,
            backend_policy_revision: 7,
            policy_expires_at_ms: 9_000,
            relay_generation: 0,
            relay_directory_id: "directory-zero".into(),
            primary_relay_node_id: "relay-primary".into(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .expect("history grant");
    VerifiedSignalingEvent {
        sender: verified_sender(signer, &claims),
        signal: AuthenticatedSessionSignal::SessionGrantV3 { message },
    }
}

fn responder_claims(
    signer: &DeviceIdentity,
    issuer: &DeviceId,
    intended_peer: &DeviceId,
    counter: u64,
) -> AuthClaims {
    AuthClaims {
        issuer_device_id: issuer.clone(),
        issuer_key_id: signer.key_id().to_owned(),
        intended_peer_device_id: intended_peer.clone(),
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
        counter,
        nonce: [counter as u8; 16],
    }
}

fn verified_sender(signer: &DeviceIdentity, claims: &AuthClaims) -> VerifiedSignalingIdentity {
    VerifiedSignalingIdentity {
        device_id: claims.issuer_device_id.clone(),
        key_id: claims.issuer_key_id.clone(),
        public_key: signer.public_key().to_vec(),
        counter: claims.counter,
        nonce: claims.nonce,
        issued_at_ms: claims.issued_at_ms,
        expires_at_ms: claims.expires_at_ms,
    }
}

#[derive(Default)]
struct StubHost {
    open_count: AtomicUsize,
    close_count: AtomicUsize,
}

#[async_trait]
impl GenerationZeroWebRtcHost for StubHost {
    async fn open_generation_zero(
        &self,
        _: &SessionId,
        _: PeerConnectionConfig,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        self.open_count.fetch_add(1, Ordering::AcqRel);
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn create_offer(
        &self,
        _: &SessionId,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn accept_offer(
        &self,
        _: &SessionId,
        _: SessionDescription,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn accept_answer(
        &self,
        _: &SessionId,
        _: SessionDescription,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn next_local_candidate(
        &self,
        _: &SessionId,
    ) -> Result<Option<IceCandidate>, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn add_remote_candidate(
        &self,
        _: &SessionId,
        _: IceCandidate,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn wait_connected(&self, _: &SessionId) -> Result<(), GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn prove_generation_zero_route(
        &self,
        _: &mrd_service::relay::RelayRouteEvidence,
        _: &SessionId,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::RouteEvidenceMismatch)
    }

    async fn close_session(&self, _: &SessionId) -> Result<(), GenerationZeroWebRtcHostError> {
        self.close_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[derive(Default)]
struct BlockingHost {
    open_count: AtomicUsize,
    close_count: AtomicUsize,
    started: Notify,
    release: Notify,
}

#[async_trait]
impl GenerationZeroWebRtcHost for BlockingHost {
    async fn open_generation_zero(
        &self,
        _: &SessionId,
        _: PeerConnectionConfig,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        self.open_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn create_offer(
        &self,
        _: &SessionId,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        if self.open_count.load(Ordering::Acquire) > 1 {
            return Err(GenerationZeroWebRtcHostError::Unavailable);
        }
        self.started.notify_one();
        self.release.notified().await;
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn accept_offer(
        &self,
        _: &SessionId,
        _: SessionDescription,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn accept_answer(
        &self,
        _: &SessionId,
        _: SessionDescription,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn next_local_candidate(
        &self,
        _: &SessionId,
    ) -> Result<Option<IceCandidate>, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn add_remote_candidate(
        &self,
        _: &SessionId,
        _: IceCandidate,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn wait_connected(&self, _: &SessionId) -> Result<(), GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::Unavailable)
    }

    async fn prove_generation_zero_route(
        &self,
        _: &mrd_service::relay::RelayRouteEvidence,
        _: &SessionId,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroWebRtcHostError> {
        Err(GenerationZeroWebRtcHostError::RouteEvidenceMismatch)
    }

    async fn close_session(&self, _: &SessionId) -> Result<(), GenerationZeroWebRtcHostError> {
        self.close_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

#[derive(Default)]
struct CountingInstaller {
    installs: AtomicUsize,
    rollbacks: Arc<AtomicUsize>,
}

#[async_trait]
impl GenerationZeroSessionInstaller for CountingInstaller {
    async fn install_generation_zero(
        &self,
        _: &GenerationZeroRouteProof,
    ) -> Result<Box<dyn GenerationZeroInstallReceipt>, GenerationZeroNegotiationError> {
        self.installs.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(TestInstallReceipt {
            rollbacks: Arc::clone(&self.rollbacks),
        }))
    }
}

#[async_trait]
impl GenerationZeroNegotiationAuthority for CountingAuthority {
    async fn revalidate_generation_zero(
        &self,
        _: &GenerationZeroNegotiationContext,
        _: u64,
    ) -> Result<(), GenerationZeroNegotiationError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.revoke.load(Ordering::Acquire) {
            Err(GenerationZeroNegotiationError::InvalidBinding)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct CountingAuthority {
    calls: AtomicUsize,
    revoke: AtomicBool,
}

#[derive(Default)]
struct RevokeAfterInstallAuthority {
    calls: AtomicUsize,
}

#[async_trait]
impl GenerationZeroNegotiationAuthority for RevokeAfterInstallAuthority {
    async fn revalidate_generation_zero(
        &self,
        _: &GenerationZeroNegotiationContext,
        _: u64,
    ) -> Result<(), GenerationZeroNegotiationError> {
        if self.calls.fetch_add(1, Ordering::AcqRel) < 2 {
            Ok(())
        } else {
            Err(GenerationZeroNegotiationError::InvalidBinding)
        }
    }
}

struct FakeRelayBackend {
    responses: Mutex<VecDeque<Result<Vec<u8>, RelayBackendError>>>,
}

#[async_trait]
impl RelayAccessBackend for FakeRelayBackend {
    async fn fetch(
        &self,
        _: &RelayAccessContext,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, RelayBackendError> {
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(RelayBackendError::Unavailable))
            .map(zeroize::Zeroizing::new)
    }
}

struct FakeRelayClock;

impl RelayClock for FakeRelayClock {
    fn now_ms(&self) -> u64 {
        NOW
    }
}

struct TestClock;

impl mrd_service::wan_session::webrtc::GenerationZeroClock for TestClock {
    fn now_unix_ms(&self) -> u64 {
        1_000
    }
}

struct FixedGenerationZeroClock(u64);

impl mrd_service::wan_session::webrtc::GenerationZeroClock for FixedGenerationZeroClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

struct CoordinatorTestClock;

impl WanSessionClock for CoordinatorTestClock {
    fn now_unix_ms(&self) -> u64 {
        1_000
    }
}

struct AdvancingClock {
    now: AtomicU64,
}

impl AdvancingClock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
        })
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::Release);
    }
}

impl GenerationZeroClock for AdvancingClock {
    fn now_unix_ms(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
}

impl WanSessionClock for AdvancingClock {
    fn now_unix_ms(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct RecordingCleanup {
    calls: AtomicUsize,
}

impl RecordingCleanup {
    fn record(&self) {
        self.calls.fetch_add(1, Ordering::AcqRel);
    }
}

#[async_trait]
impl WanSessionCleanup for RecordingCleanup {
    async fn freeze_input(
        &self,
        _: &SessionId,
    ) -> Result<(), mrd_service::wan_session::coordinator::WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn stop_media(
        &self,
        _: &SessionId,
    ) -> Result<(), mrd_service::wan_session::coordinator::WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn close_transport(
        &self,
        _: &SessionId,
    ) -> Result<(), mrd_service::wan_session::coordinator::WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn remove_failover(
        &self,
        _: &SessionId,
    ) -> Result<(), mrd_service::wan_session::coordinator::WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn clear_signaling(
        &self,
        _: &SessionId,
    ) -> Result<(), mrd_service::wan_session::coordinator::WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn close_backend(
        &self,
        _: &SessionId,
        _: bool,
    ) -> Result<(), mrd_service::wan_session::coordinator::WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }
}

struct DeadlineAdvancingInstaller {
    clock: Arc<AdvancingClock>,
    deadline: u64,
    installs: AtomicUsize,
    rollbacks: Arc<AtomicUsize>,
}

impl DeadlineAdvancingInstaller {
    fn new(clock: Arc<AdvancingClock>, deadline: u64) -> Self {
        Self {
            clock,
            deadline,
            installs: AtomicUsize::new(0),
            rollbacks: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl GenerationZeroSessionInstaller for DeadlineAdvancingInstaller {
    async fn install_generation_zero(
        &self,
        _: &GenerationZeroRouteProof,
    ) -> Result<Box<dyn GenerationZeroInstallReceipt>, GenerationZeroNegotiationError> {
        self.installs.fetch_add(1, Ordering::AcqRel);
        self.clock.set(self.deadline);
        Ok(Box::new(TestInstallReceipt {
            rollbacks: Arc::clone(&self.rollbacks),
        }))
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn relay_config() -> RelayClientConfig {
    RelayClientConfig::new(
        "https://control.example.test/api/v1/relays/access",
        "device-token",
        std::collections::BTreeMap::from([(
            "relay-signing-key".into(),
            signing_key().verifying_key().to_bytes().to_vec(),
        )]),
        Duration::from_secs(2),
        4,
    )
    .unwrap()
}

fn url_digest(urls: &[String]) -> String {
    let mut urls = urls.iter().map(String::as_str).collect::<Vec<_>>();
    urls.sort();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MRD_RELAY_URLS_V1\0");
    for url in urls {
        bytes.extend_from_slice(&(url.len() as u32).to_be_bytes());
        bytes.extend_from_slice(url.as_bytes());
    }
    digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn primary_digest() -> String {
    url_digest(&["turn:relay-primary.example.test:3478?transport=udp".into()])
}

fn access_response(session_id: &str, peer: &str) -> Vec<u8> {
    let primary_url = "turn:relay-primary.example.test:3478?transport=udp".to_owned();
    let backup_url = "turn:relay-backup.example.test:3478?transport=udp".to_owned();
    let payload = RelayDirectoryPayload {
        format_version: RELAY_DIRECTORY_FORMAT_VERSION,
        policy_revision: 7,
        directory_id: "directory-zero".into(),
        issued_at_ms: NOW - 1_000,
        expires_at_ms: NOW + 30_000,
        session_id: session_id.into(),
        intended_peer_digest: relay_peer_digest(peer).unwrap(),
        candidates: vec![
            RelayDirectoryCandidate {
                node_id: "relay-backup".into(),
                region: "cn-north".into(),
                failure_domain: "domain-b".into(),
                endpoints: vec![RelayDirectoryEndpoint {
                    transport: RelayDirectoryTransport::Udp,
                    host: "relay-backup.example.test".into(),
                    port: 3478,
                }],
                capabilities: 1,
                load_class: 2,
                selection_reason: "eligible".into(),
                reservation: RelayReservation {
                    reservation_id: "reservation-backup".into(),
                    expires_at_ms: NOW + 30_000,
                },
            },
            RelayDirectoryCandidate {
                node_id: "relay-primary".into(),
                region: "cn-east".into(),
                failure_domain: "domain-a".into(),
                endpoints: vec![RelayDirectoryEndpoint {
                    transport: RelayDirectoryTransport::Udp,
                    host: "relay-primary.example.test".into(),
                    port: 3478,
                }],
                capabilities: 1,
                load_class: 1,
                selection_reason: "preferred-region".into(),
                reservation: RelayReservation {
                    reservation_id: "reservation-primary".into(),
                    expires_at_ms: NOW + 30_000,
                },
            },
        ],
    };
    let signature = signing_key().sign(&payload.canonical_signing_bytes().unwrap());
    let directory = SignedRelayDirectory {
        payload,
        signing_key_id: "relay-signing-key".into(),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    };
    serde_json::to_vec(&serde_json::json!({
        "generation": 0,
        "directory_id": "directory-zero",
        "relay_url_digest": url_digest(std::slice::from_ref(&primary_url)),
        "directory": directory,
        "credentials": [
            {
                "node_id": "relay-primary",
                "urls": [primary_url],
                "username": "primary-user",
                "credential": "primary-password",
                "expires_at_unix_seconds": (NOW / 1000) + 60
            },
            {
                "node_id": "relay-backup",
                "urls": [backup_url],
                "username": "backup-user",
                "credential": "backup-password",
                "expires_at_unix_seconds": (NOW / 1000) + 60
            }
        ]
    }))
    .unwrap()
}

async fn relay_access(
    session_id: &SessionId,
    peer: &str,
) -> Arc<mrd_service::relay::VerifiedRelayAccess> {
    let backend = Arc::new(FakeRelayBackend {
        responses: Mutex::new(VecDeque::from([Ok(access_response(&session_id.0, peer))])),
    });
    let client =
        RelayDirectoryClient::with_backend(relay_config(), backend, Arc::new(FakeRelayClock));
    client
        .access(RelayAccessContext::for_generation(&session_id.0, 7, peer, 0).unwrap())
        .await
        .unwrap()
}
