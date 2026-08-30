use async_trait::async_trait;
use mrd_application::{
    AuthenticatedSessionSignal, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_ipc::{
    ConsentDecision, ConsentResponse, DecimalU64, IpcResponse, LanDiscoverySnapshot, LanPeerInfo,
    RemoteAccessMode, RemoteAuthorizationState, RemotePermissionScope, RemoteRouteKind,
    RemoteRoutePreference, RemoteSessionRequest,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::{
    handlers::session::request_remote_session,
    wan_session::{
        backend::{WanSessionApproval, WanSessionBinding},
        coordinator::{
            NoopWanSessionCleanup, SystemWanSessionClock, WanBackendSessionSnapshot,
            WanSessionClock, WanSessionConsentPublisher, WanSessionCoordinator,
            WanSessionCoordinatorConfig, WanSessionPortError, WanSessionWorkflowBackend,
            WanSessionWorkflowPorts, WanSessionWorkflowSignaling,
        },
        media::{
            enable_input_after_control_evidence, select_route, start_verified_media,
            ControlEvidenceBarrier, LanDiscoveryEvidence, WanInputActivationPort,
            WanMediaActivationError, WanMediaActivationPort, WanMediaAuthority, WanRouteSelection,
        },
        model::{
            GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionEvent, WanSessionIdentity,
            WanSessionPhase, WanSessionRole, WanSessionState,
        },
        service::{apply_verified_controller_grant_for_service, ServiceWanSessionConsentPublisher},
    },
    AppState,
};
use mrd_signal_proto::{
    AuthClaims, SessionGrantV3, SessionGrantV3Payload, WanAccessModeV3, WanMediaProfileV3,
    WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
};
use ring::rand::SystemRandom;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

const REQUEST_COMMITMENT: &str = "11";
const INTENT_COMMITMENT: &str = "22";
const GRANT_COMMITMENT: &str = "33";
const RELAY_URL_DIGEST: &str = "44";

struct ControllerRequestBackend {
    request: Mutex<Option<WanSessionRequestV3>>,
    grant_deadlines: Mutex<Option<(u64, u64)>>,
    reject_create: bool,
}

impl ControllerRequestBackend {
    fn new() -> Self {
        Self {
            request: Mutex::new(None),
            grant_deadlines: Mutex::new(None),
            reject_create: false,
        }
    }

    fn rejecting() -> Self {
        Self {
            request: Mutex::new(None),
            grant_deadlines: Mutex::new(None),
            reject_create: true,
        }
    }

    fn configure_grant_deadlines(&self, policy_expires_at_ms: u64, grant_expires_at_ms: u64) {
        *self.grant_deadlines.lock().unwrap() = Some((policy_expires_at_ms, grant_expires_at_ms));
    }
}

#[async_trait]
impl WanSessionWorkflowBackend for ControllerRequestBackend {
    async fn create(
        &self,
        request: &WanSessionRequestV3,
        _: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError> {
        if self.reject_create {
            return Err(WanSessionPortError::Rejected);
        }
        *self.request.lock().unwrap() = Some(request.clone());
        let commitment = request
            .commitment()
            .map_err(|_| WanSessionPortError::Rejected)?;
        WanBackendSessionSnapshot::requested(request.clone(), commitment)
            .map_err(|_| WanSessionPortError::Rejected)
    }

    async fn inspect(
        &self,
        _: &WanSessionBinding,
        _: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError> {
        let request = self
            .request
            .lock()
            .unwrap()
            .clone()
            .ok_or(WanSessionPortError::Rejected)?;
        let (policy_expires_at_ms, grant_expires_at_ms) = self
            .grant_deadlines
            .lock()
            .unwrap()
            .ok_or(WanSessionPortError::Rejected)?;
        let commitment = request
            .commitment()
            .map_err(|_| WanSessionPortError::Rejected)?;
        let grant = GrantBinding::new(
            commitment.clone(),
            vec![WanPermissionScopeV3::ScreenView],
            7,
            policy_expires_at_ms,
            grant_expires_at_ms,
            WanRoutePolicyV3::RelayOnly,
        )
        .map_err(|_| WanSessionPortError::Rejected)?;
        WanBackendSessionSnapshot::approved(request, commitment, grant)
            .map_err(|_| WanSessionPortError::Rejected)
    }

    async fn approve(
        &self,
        _: &WanSessionBinding,
        _: &WanSessionApproval,
        _: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError> {
        Err(WanSessionPortError::Rejected)
    }

    async fn access_generation_zero(
        &self,
        _: &WanSessionBinding,
        _: u64,
        _: u64,
    ) -> Result<RelayAccessBinding, WanSessionPortError> {
        RelayAccessBinding::generation_zero(
            7,
            "controller-authorization-directory".to_owned(),
            "controller-authorization-relay".to_owned(),
            digest("6"),
        )
        .map_err(|_| WanSessionPortError::Rejected)
    }
}

struct AuthorizationObservingSignaling {
    authorizations: Arc<mrd_service::session_authorization::SessionAuthorizationRegistry>,
    observed_exact_authorization: AtomicBool,
    controller_identity: Mutex<Option<WanSessionIdentity>>,
}

#[async_trait]
impl WanSessionWorkflowSignaling for AuthorizationObservingSignaling {
    async fn send_intent(
        &self,
        identity: &WanSessionIdentity,
        _: &WanSessionRequestV3,
        _: &str,
        _: u64,
    ) -> Result<String, WanSessionPortError> {
        *self.controller_identity.lock().unwrap() = Some(identity.clone());
        let observed = self
            .authorizations
            .snapshot(identity.session_id())
            .await
            .is_some_and(|authorization| {
                authorization.authorization_state == RemoteAuthorizationState::Authorizing
                    && authorization.peer_device_id == *identity.target_device_id()
                    && authorization.requested_scopes == vec![RemotePermissionScope::ScreenView]
            });
        self.observed_exact_authorization
            .store(observed, Ordering::SeqCst);
        Ok(digest("5"))
    }

    async fn send_grant_with_commitment(
        &self,
        _: &WanSessionIdentity,
        _: &str,
        _: &GrantBinding,
        _: &RelayAccessBinding,
        _: u64,
    ) -> Result<String, WanSessionPortError> {
        Err(WanSessionPortError::Rejected)
    }
}

struct UnusedControllerConsent;

#[async_trait]
impl WanSessionConsentPublisher for UnusedControllerConsent {
    async fn publish_attended_request(
        &self,
        _: &WanSessionIdentity,
        _: &WanSessionRequestV3,
        _: u64,
    ) -> Result<(), WanSessionPortError> {
        Err(WanSessionPortError::Rejected)
    }

    async fn load_attended_approval(
        &self,
        _: &WanSessionIdentity,
        _: u64,
    ) -> Result<WanSessionApproval, WanSessionPortError> {
        Err(WanSessionPortError::Rejected)
    }
}

fn digest(value: &str) -> String {
    assert!(!value.is_empty() && 64 % value.len() == 0);
    value.repeat(64 / value.len())
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct ControllerAuthorizationFixture {
    app_state: Arc<AppState>,
    coordinator: Arc<WanSessionCoordinator>,
    controller_device_id: DeviceId,
    target_device_id: DeviceId,
    session_id: SessionId,
    identity: WanSessionIdentity,
    target_identity: DeviceIdentity,
    signed_expires_at_ms: u64,
    policy_expires_at_ms: u64,
    grant_expires_at_ms: u64,
}

async fn controller_authorization_fixture(suffix: &str) -> ControllerAuthorizationFixture {
    let app_state = Arc::new(AppState::default());
    let controller_device_id = DeviceId(format!("controller-wan-{suffix}"));
    let target_device_id = DeviceId(format!("target-wan-{suffix}"));
    let session_id = SessionId(format!("controller-wan-{suffix}"));
    app_state
        .devices
        .lock()
        .await
        .register(controller_device_id.clone(), "Controller".to_string());

    let backend = Arc::new(ControllerRequestBackend::new());
    let signaling = Arc::new(AuthorizationObservingSignaling {
        authorizations: Arc::clone(&app_state.session_authorizations),
        observed_exact_authorization: AtomicBool::new(false),
        controller_identity: Mutex::new(None),
    });
    let coordinator = Arc::new(
        WanSessionCoordinator::with_workflow_ports(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            WanSessionWorkflowPorts::new(
                backend.clone(),
                signaling.clone(),
                Arc::new(UnusedControllerConsent),
                Arc::new(SystemWanSessionClock),
            ),
        )
        .expect("controller workflow coordinator"),
    );
    app_state
        .bind_wan_session_coordinator(coordinator.clone())
        .expect("bind controller workflow coordinator");

    let response = request_remote_session(
        &app_state,
        RemoteSessionRequest {
            session_id: session_id.clone(),
            target_device_id: target_device_id.clone(),
            access_mode: RemoteAccessMode::Attended,
            route_preference: RemoteRoutePreference::WanRelay,
            requested_scopes: vec![RemotePermissionScope::ScreenView],
            requested_profile: None,
        },
    )
    .await;
    assert!(
        matches!(response, IpcResponse::RemoteSessionRequested { .. }),
        "WAN controller request should enter the authenticated workflow: {response:?}"
    );
    assert!(
        signaling
            .observed_exact_authorization
            .load(Ordering::SeqCst),
        "the exact outgoing authorization must exist before intent signaling"
    );
    let identity = signaling
        .controller_identity
        .lock()
        .unwrap()
        .clone()
        .expect("signaled controller identity");
    let signed_expires_at_ms = identity.deadline_unix_ms().saturating_sub(1_000);
    let policy_expires_at_ms = identity.deadline_unix_ms().saturating_sub(2_000);
    let grant_expires_at_ms = identity.deadline_unix_ms().saturating_sub(3_000);
    backend.configure_grant_deadlines(policy_expires_at_ms, grant_expires_at_ms);

    ControllerAuthorizationFixture {
        app_state,
        coordinator,
        controller_device_id,
        target_device_id,
        session_id,
        identity,
        target_identity: DeviceIdentity::generate(&SystemRandom::new()).unwrap(),
        signed_expires_at_ms,
        policy_expires_at_ms,
        grant_expires_at_ms,
    }
}

#[derive(Clone, Copy)]
enum ControllerGrantMutation {
    Valid,
    Peer,
    Scope,
    Profile,
    Commitment,
    Deadline,
}

fn controller_grant_event(
    fixture: &ControllerAuthorizationFixture,
    mutation: ControllerGrantMutation,
) -> VerifiedSignalingEvent {
    let target_device_id = if matches!(mutation, ControllerGrantMutation::Peer) {
        DeviceId(format!("other-{}", fixture.target_device_id.0))
    } else {
        fixture.target_device_id.clone()
    };
    let mut approved_scopes = vec![WanPermissionScopeV3::ScreenView];
    if matches!(mutation, ControllerGrantMutation::Scope) {
        approved_scopes.push(WanPermissionScopeV3::InputKeyboard);
        approved_scopes.sort_unstable();
    }
    let approved_profile =
        matches!(mutation, ControllerGrantMutation::Profile).then(|| WanMediaProfileV3 {
            width: 1_280,
            height: 720,
            fps: 30,
            bitrate_mbps: 8,
            codec: "h264".to_owned(),
            codec_profile: None,
            bit_depth: None,
            chroma_subsampling: None,
            pixel_format: None,
            hdr_enabled: None,
            color_mode: None,
            color_pipeline: None,
        });
    let claims = AuthClaims {
        issuer_device_id: target_device_id.clone(),
        issuer_key_id: fixture.target_identity.key_id().to_owned(),
        intended_peer_device_id: fixture.controller_device_id.clone(),
        issued_at_ms: now_unix_ms(),
        expires_at_ms: if matches!(mutation, ControllerGrantMutation::Deadline) {
            fixture.identity.deadline_unix_ms().saturating_add(1)
        } else {
            fixture.signed_expires_at_ms
        },
        counter: 1,
        nonce: [0x65; 16],
    };
    let message = SessionGrantV3::sign(
        &fixture.target_identity,
        SessionGrantV3Payload {
            claims: claims.clone(),
            session_id: fixture.session_id.clone(),
            controller_device_id: fixture.controller_device_id.clone(),
            target_device_id,
            intent_commitment: if matches!(mutation, ControllerGrantMutation::Commitment) {
                digest("7")
            } else {
                digest("5")
            },
            approved_scopes,
            approved_profile,
            backend_policy_revision: 7,
            policy_expires_at_ms: fixture.policy_expires_at_ms,
            relay_generation: 0,
            relay_directory_id: "controller-authorization-directory".to_owned(),
            primary_relay_node_id: "controller-authorization-relay".to_owned(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .expect("signed controller grant");
    VerifiedSignalingEvent {
        sender: VerifiedSignalingIdentity {
            device_id: claims.issuer_device_id,
            key_id: claims.issuer_key_id,
            public_key: fixture.target_identity.public_key().to_vec(),
            counter: claims.counter,
            nonce: claims.nonce,
            issued_at_ms: claims.issued_at_ms,
            expires_at_ms: claims.expires_at_ms,
        },
        signal: AuthenticatedSessionSignal::SessionGrantV3 { message },
    }
}

fn identity(suffix: &str) -> WanSessionIdentity {
    WanSessionIdentity::new(
        SessionId(format!("dispatch-{suffix}")),
        DeviceId(format!("controller-{suffix}")),
        DeviceId(format!("target-{suffix}")),
        digest("a"),
        digest("b"),
        20_000,
    )
    .expect("valid test identity")
}

fn relay_verified_state(role: WanSessionRole, suffix: &str) -> WanSessionState {
    let mut state = WanSessionState::new(role, identity(suffix));
    state
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: digest(REQUEST_COMMITMENT),
            },
            1_000,
        )
        .unwrap();
    state
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: digest(INTENT_COMMITMENT),
            },
            1_001,
        )
        .unwrap();
    let grant = GrantBinding::new(
        digest(REQUEST_COMMITMENT),
        vec![
            WanPermissionScopeV3::InputKeyboard,
            WanPermissionScopeV3::ScreenView,
        ],
        7,
        19_000,
        18_000,
        WanRoutePolicyV3::RelayOnly,
    )
    .unwrap()
    .with_grant_commitment(digest(GRANT_COMMITMENT))
    .unwrap();
    let access = RelayAccessBinding::generation_zero(
        7,
        "dispatch-directory".to_string(),
        "dispatch-relay".to_string(),
        digest(RELAY_URL_DIGEST),
    )
    .unwrap();
    state.apply(WanSessionEvent::Granted(grant), 1_002).unwrap();
    state
        .apply(WanSessionEvent::AccessBound(access.clone()), 1_003)
        .unwrap();
    state.apply(WanSessionEvent::Negotiating, 1_004).unwrap();
    state
        .apply(
            WanSessionEvent::RelayVerified(RelayRouteProof::for_test(&access, true, true).unwrap()),
            1_005,
        )
        .unwrap();
    state
}

#[test]
fn explicit_lan_and_wan_relay_are_never_rewritten_to_a_fallback() {
    assert_eq!(
        select_route(RemoteRoutePreference::Lan, None),
        WanRouteSelection::Lan
    );
    assert_eq!(
        select_route(RemoteRoutePreference::WanRelay, None),
        WanRouteSelection::WanRelay
    );
}

#[test]
fn auto_uses_only_fresh_signed_key_pinned_discovery_and_never_waits() {
    let fresh = LanDiscoveryEvidence::for_test(true, true, true, true);
    let stale = LanDiscoveryEvidence::for_test(false, true, true, true);
    let unsigned = LanDiscoveryEvidence::for_test(true, false, true, true);
    let unpinned = LanDiscoveryEvidence::for_test(true, true, false, true);

    assert_eq!(
        select_route(RemoteRoutePreference::Auto, Some(fresh)),
        WanRouteSelection::Lan
    );
    for record in [
        stale,
        unsigned,
        unpinned,
        LanDiscoveryEvidence::for_test(true, true, true, false),
    ] {
        assert_eq!(
            select_route(RemoteRoutePreference::Auto, Some(record)),
            WanRouteSelection::WanRelay
        );
    }
    assert_eq!(
        select_route(RemoteRoutePreference::Auto, None),
        WanRouteSelection::WanRelay
    );
}

#[test]
fn public_discovery_snapshot_cannot_mint_authenticated_route_evidence() {
    let snapshot = LanDiscoverySnapshot {
        enabled: true,
        running: false,
        discovery_port: 21_116,
        instance_id: "dispatch-instance".to_string(),
        last_probe_ms: None,
        peers: vec![LanPeerInfo {
            device_id: DeviceId("target".to_string()),
            device_name: "Target".to_string(),
            device_type: "rdesk".to_string(),
            ip: "192.0.2.10".to_string(),
            discovery_port: 21_116,
            p2p_control_addr: "192.0.2.10:21116".to_string(),
            transports: vec!["quic".to_string()],
            protocol_version: 3,
            service_build_id: None,
            media_protocol_version: Some(3),
            media_capabilities: vec![],
            mac_address: None,
            age_ms: 100,
            p2p_available: true,
        }],
    };
    let evidence = LanDiscoveryEvidence::from_snapshot(
        &snapshot,
        &DeviceId("target".to_string()),
        1_000,
        5_000,
    )
    .expect("fresh target evidence");
    assert_eq!(
        select_route(RemoteRoutePreference::Auto, Some(evidence)),
        WanRouteSelection::WanRelay
    );
}

#[tokio::test]
async fn controller_wan_request_creates_and_grants_exact_authorization() {
    let fixture = controller_authorization_fixture("authorization").await;
    let authorization = fixture
        .app_state
        .session_authorizations
        .snapshot(&fixture.session_id)
        .await
        .expect("controller authorization must remain queryable");
    assert_eq!(authorization.peer_device_id, fixture.target_device_id);
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Authorizing
    );
    assert_eq!(
        authorization.requested_scopes,
        vec![RemotePermissionScope::ScreenView]
    );

    let grant_event = controller_grant_event(&fixture, ControllerGrantMutation::Valid);
    apply_verified_controller_grant_for_service(
        &fixture.app_state,
        &fixture.coordinator,
        grant_event.clone(),
    )
    .await
    .expect("verified grant must install through the production boundary");
    apply_verified_controller_grant_for_service(
        &fixture.app_state,
        &fixture.coordinator,
        grant_event,
    )
    .await
    .expect("the exact verified grant replay must remain idempotent");

    let granted = fixture
        .app_state
        .session_authorizations
        .snapshot(&fixture.session_id)
        .await
        .expect("granted controller authorization");
    assert_eq!(
        granted.authorization_state,
        RemoteAuthorizationState::Granted
    );
    assert_eq!(granted.peer_key_id, fixture.target_identity.key_id());
    assert_eq!(granted.route_kind, Some(RemoteRouteKind::WebRtcRelay));
    assert_eq!(
        granted.granted_scopes,
        vec![RemotePermissionScope::ScreenView]
    );
    assert_eq!(
        granted.authorization_expires_at_ms,
        Some(fixture.grant_expires_at_ms)
    );
}

#[tokio::test]
async fn controller_wan_authorization_rejects_every_mismatched_grant_binding() {
    for (suffix, mutation) in [
        ("peer-mismatch", ControllerGrantMutation::Peer),
        ("scope-mismatch", ControllerGrantMutation::Scope),
        ("profile-mismatch", ControllerGrantMutation::Profile),
        ("commitment-mismatch", ControllerGrantMutation::Commitment),
        ("deadline-mismatch", ControllerGrantMutation::Deadline),
    ] {
        let fixture = controller_authorization_fixture(suffix).await;
        assert!(
            apply_verified_controller_grant_for_service(
                &fixture.app_state,
                &fixture.coordinator,
                controller_grant_event(&fixture, mutation),
            )
            .await
            .is_err(),
            "{suffix} must be rejected"
        );
        let authorization = fixture
            .app_state
            .session_authorizations
            .snapshot(&fixture.session_id)
            .await
            .expect("mismatched grant authorization remains queryable");
        assert_eq!(
            authorization.authorization_state,
            RemoteAuthorizationState::Denied,
            "{suffix} must terminalize the rejected authorization"
        );
        assert!(
            fixture
                .app_state
                .session_authorizations
                .active_grant(&fixture.session_id)
                .await
                .is_none(),
            "{suffix} must not install an active grant"
        );
    }
}

#[tokio::test]
async fn controller_wan_start_failure_terminalizes_pre_signaling_authorization() {
    let app_state = Arc::new(AppState::default());
    let controller_device_id = DeviceId("controller-wan-start-failure".to_owned());
    let target_device_id = DeviceId("target-wan-start-failure".to_owned());
    let session_id = SessionId("controller-wan-start-failure".to_owned());
    app_state
        .devices
        .lock()
        .await
        .register(controller_device_id, "Controller".to_owned());
    let signaling = Arc::new(AuthorizationObservingSignaling {
        authorizations: Arc::clone(&app_state.session_authorizations),
        observed_exact_authorization: AtomicBool::new(false),
        controller_identity: Mutex::new(None),
    });
    let coordinator = Arc::new(
        WanSessionCoordinator::with_workflow_ports(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            WanSessionWorkflowPorts::new(
                Arc::new(ControllerRequestBackend::rejecting()),
                signaling,
                Arc::new(UnusedControllerConsent),
                Arc::new(SystemWanSessionClock),
            ),
        )
        .expect("controller workflow coordinator"),
    );
    app_state
        .bind_wan_session_coordinator(coordinator)
        .expect("bind controller workflow coordinator");

    let response = request_remote_session(
        &app_state,
        RemoteSessionRequest {
            session_id: session_id.clone(),
            target_device_id,
            access_mode: RemoteAccessMode::Attended,
            route_preference: RemoteRoutePreference::WanRelay,
            requested_scopes: vec![RemotePermissionScope::ScreenView],
            requested_profile: None,
        },
    )
    .await;
    assert!(matches!(response, IpcResponse::RemoteAccessError { .. }));
    let authorization = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .expect("failed authorization remains queryable for diagnostics");
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Denied
    );
    assert!(
        app_state
            .session_authorizations
            .active_grant(&session_id)
            .await
            .is_none(),
        "failed startup must leave no active authorization"
    );
}

#[derive(Default)]
struct RecordingMediaPort {
    calls: Mutex<Vec<String>>,
    fail: bool,
}

#[async_trait]
impl WanMediaActivationPort for RecordingMediaPort {
    async fn start_target_capture_send(
        &self,
        _authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError> {
        self.calls
            .lock()
            .unwrap()
            .push("target-capture-send".to_string());
        if self.fail {
            Err(WanMediaActivationError::StartupFailed)
        } else {
            Ok(())
        }
    }

    async fn start_controller_receive_render(
        &self,
        _authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError> {
        self.calls
            .lock()
            .unwrap()
            .push("controller-receive-render".to_string());
        if self.fail {
            Err(WanMediaActivationError::StartupFailed)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct RecordingInputPort {
    enabled: Mutex<bool>,
}

#[async_trait]
impl WanInputActivationPort for RecordingInputPort {
    async fn enable_input(
        &self,
        _authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError> {
        *self.enabled.lock().unwrap() = true;
        Ok(())
    }
}

struct FixedClock;

impl WanSessionClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        1_000
    }
}

#[tokio::test]
async fn media_starts_only_after_relay_verified_and_input_remains_frozen() {
    let state = relay_verified_state(WanSessionRole::Target, "target");
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            Default::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(FixedClock),
        )
        .unwrap(),
    );
    coordinator.begin(state.clone()).await.unwrap();
    let media = RecordingMediaPort::default();

    let activation = start_verified_media(&coordinator, &state, &media).await;
    assert!(activation.is_ok());
    assert_eq!(
        media.calls.lock().unwrap().as_slice(),
        &["target-capture-send"]
    );
    assert_eq!(
        coordinator
            .snapshot(state.identity().session_id())
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::Streaming
    );
}

#[derive(Default)]
struct EvidenceBarrier {
    verified: bool,
}

#[async_trait]
impl ControlEvidenceBarrier for EvidenceBarrier {
    async fn is_verified(&self, _session_id: &SessionId) -> bool {
        self.verified
    }
}

#[tokio::test]
async fn input_cannot_start_before_control_evidence_barrier() {
    let state = relay_verified_state(WanSessionRole::Controller, "controller");
    let authority = WanMediaAuthority::from_relay_verified(&state).unwrap();
    let input = RecordingInputPort::default();
    let barrier = EvidenceBarrier::default();

    assert_eq!(
        enable_input_after_control_evidence(&authority, &barrier, &input).await,
        Err(WanMediaActivationError::ControlEvidenceRequired)
    );
    assert!(!*input.enabled.lock().unwrap());
}

#[tokio::test]
async fn media_start_failure_fails_the_exact_session() {
    let state = relay_verified_state(WanSessionRole::Controller, "failure");
    let session_id = state.identity().session_id().clone();
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            Default::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(FixedClock),
        )
        .unwrap(),
    );
    coordinator.begin(state.clone()).await.unwrap();
    let media = RecordingMediaPort {
        calls: Mutex::new(Vec::new()),
        fail: true,
    };

    assert!(start_verified_media(&coordinator, &state, &media)
        .await
        .is_err());
    let failed = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(failed.phase(), WanSessionPhase::Failed);
}

#[tokio::test]
async fn production_consent_port_resolves_only_the_exact_wan_session() {
    use mrd_service::wan_session::coordinator::WanSessionConsentPublisher;

    let app_state = mrd_service::AppState::default();
    let adapter = Arc::new(ServiceWanSessionConsentPublisher::new(Arc::clone(
        &app_state.session_authorizations,
    )));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let identity = WanSessionIdentity::new(
        SessionId("dispatch-consent".into()),
        DeviceId("controller-consent".into()),
        DeviceId("target-consent".into()),
        digest("a"),
        digest("b"),
        now + 30_000,
    )
    .unwrap();
    let request = WanSessionRequestV3 {
        session_id: identity.session_id().clone(),
        idempotency_key: [9; 16],
        controller_device_id: identity.controller_device_id().clone(),
        target_device_id: identity.target_device_id().clone(),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![WanPermissionScopeV3::ScreenView],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    };
    adapter
        .publish_attended_request(&identity, &request, identity.deadline_unix_ms())
        .await
        .unwrap();
    let pending = app_state
        .session_authorizations
        .snapshot(identity.session_id())
        .await
        .unwrap();
    assert_eq!(
        pending.authorization_state,
        RemoteAuthorizationState::AwaitingLocalConsent
    );

    app_state
        .session_authorizations
        .respond_to_consent(
            ConsentResponse {
                session_id: identity.session_id().clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
            now + 1,
        )
        .await
        .unwrap();
    let approval = adapter
        .load_attended_approval(&identity, identity.deadline_unix_ms())
        .await
        .unwrap();
    assert_eq!(
        approval.approved_scopes(),
        &[WanPermissionScopeV3::ScreenView]
    );
}
