use async_trait::async_trait;
use mrd_application::{
    AuthenticatedSessionSignal, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_ipc::{
    AuditLogQuery, ConsentDecision, ConsentResponse, DecimalU64, IpcRequest, IpcResponse,
    LanDiscoverySnapshot, LanPeerInfo, RemoteAccessMode, RemoteAuthorizationState,
    RemotePermissionScope, RemoteRouteKind, RemoteRoutePreference, RemoteSessionRequest,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::{
    handlers::session::{
        fail_session, get_remote_session, get_route_evidence, list_sessions,
        request_remote_session, respond_to_consent, runtime_snapshot, session_snapshot,
        stop_session,
    },
    ipc_server::IpcServer,
    wan_session::{
        backend::{WanSessionApproval, WanSessionBinding},
        coordinator::{
            NoopWanSessionCleanup, SystemWanSessionClock, WanBackendSessionSnapshot,
            WanSessionCleanup, WanSessionClock, WanSessionConsentPublisher, WanSessionCoordinator,
            WanSessionCoordinatorConfig, WanSessionCoordinatorError, WanSessionPortError,
            WanSessionWorkflowBackend, WanSessionWorkflowPorts, WanSessionWorkflowSignaling,
        },
        media::{
            enable_input_after_control_evidence, select_route, start_verified_media,
            ControlEvidenceBarrier, LanDiscoveryEvidence, WanInputActivationPort,
            WanMediaActivationError, WanMediaActivationPort, WanMediaAuthority, WanRouteSelection,
        },
        model::{
            GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionEvent, WanSessionFailure,
            WanSessionIdentity, WanSessionPhase, WanSessionRole, WanSessionState,
        },
        service::{apply_verified_controller_grant_for_service, ServiceWanSessionConsentPublisher},
    },
    AppState,
};
use mrd_signal_proto::{
    AuthClaims, SessionGrantV3, SessionGrantV3Payload, WanAccessModeV3, WanMediaProfileV3,
    WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
};
use mrd_store_sqlite::TrustState;
use ring::rand::SystemRandom;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::{
    sync::Barrier,
    time::{timeout, Duration},
};

const REQUEST_COMMITMENT: &str = "11";
const INTENT_COMMITMENT: &str = "22";
const GRANT_COMMITMENT: &str = "33";
const RELAY_URL_DIGEST: &str = "44";

struct ControllerRequestBackend {
    request: Mutex<Option<WanSessionRequestV3>>,
    grant_deadlines: Mutex<Option<(u64, u64)>>,
    reject_create: bool,
    create_entered: Option<Arc<Barrier>>,
    create_release: Option<Arc<Barrier>>,
}

impl ControllerRequestBackend {
    fn new() -> Self {
        Self {
            request: Mutex::new(None),
            grant_deadlines: Mutex::new(None),
            reject_create: false,
            create_entered: None,
            create_release: None,
        }
    }

    fn rejecting() -> Self {
        Self {
            request: Mutex::new(None),
            grant_deadlines: Mutex::new(None),
            reject_create: true,
            create_entered: None,
            create_release: None,
        }
    }

    fn gate_controlled_rejection(
        create_entered: Arc<Barrier>,
        create_release: Arc<Barrier>,
    ) -> Self {
        Self {
            request: Mutex::new(None),
            grant_deadlines: Mutex::new(None),
            reject_create: true,
            create_entered: Some(create_entered),
            create_release: Some(create_release),
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
        if let Some(create_entered) = &self.create_entered {
            create_entered.wait().await;
        }
        if let Some(create_release) = &self.create_release {
            create_release.wait().await;
        }
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

struct AdjustableClock {
    now_unix_ms: AtomicU64,
}

impl AdjustableClock {
    fn new(now_unix_ms: u64) -> Self {
        Self {
            now_unix_ms: AtomicU64::new(now_unix_ms),
        }
    }

    fn set(&self, now_unix_ms: u64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::SeqCst);
    }
}

impl WanSessionClock for AdjustableClock {
    fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms.load(Ordering::SeqCst)
    }
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
async fn controller_wan_grant_rechecks_a_revoked_target_key_before_admission() {
    let fixture = controller_authorization_fixture("revoked-key").await;
    fixture
        .app_state
        .device_identities
        .trust_authenticated_peer_for_test(&fixture.target_identity, 1, TrustState::Revoked);

    assert!(
        apply_verified_controller_grant_for_service(
            &fixture.app_state,
            &fixture.coordinator,
            controller_grant_event(&fixture, ControllerGrantMutation::Valid),
        )
        .await
        .is_err(),
        "a durably revoked target key must not cross the grant admission gate"
    );
    let authorization = fixture
        .app_state
        .session_authorizations
        .snapshot(&fixture.session_id)
        .await
        .expect("rejected controller authorization remains queryable");
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Denied
    );
    assert!(fixture
        .app_state
        .session_authorizations
        .active_grant(&fixture.session_id)
        .await
        .is_none());
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
        .bind_wan_session_coordinator(coordinator.clone())
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
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Failed
    );
    let sessions = app_state.sessions.lock().await;
    let projection = sessions
        .get(&session_id)
        .expect("failed WAN startup projection retained");
    assert!(matches!(
        projection.lifecycle_state,
        mrd_application::ports::SessionLifecycleState::Failed { .. }
    ));
}

#[tokio::test]
async fn controller_wan_start_failure_waits_for_authorization_security_gate() {
    let app_state = Arc::new(AppState::default());
    let controller_device_id = DeviceId("controller-wan-start-gate".to_owned());
    let target_device_id = DeviceId("target-wan-start-gate".to_owned());
    let session_id = SessionId("controller-wan-start-gate".to_owned());
    app_state
        .devices
        .lock()
        .await
        .register(controller_device_id, "Controller".to_owned());

    let create_entered = Arc::new(Barrier::new(2));
    let create_release = Arc::new(Barrier::new(2));
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
                Arc::new(ControllerRequestBackend::gate_controlled_rejection(
                    Arc::clone(&create_entered),
                    Arc::clone(&create_release),
                )),
                signaling,
                Arc::new(UnusedControllerConsent),
                Arc::new(SystemWanSessionClock),
            ),
        )
        .expect("controller workflow coordinator"),
    );
    app_state
        .bind_wan_session_coordinator(Arc::clone(&coordinator))
        .expect("bind controller workflow coordinator");

    let request_app_state = Arc::clone(&app_state);
    let request_session_id = session_id.clone();
    let request_target_device_id = target_device_id.clone();
    let request_task = tokio::spawn(async move {
        request_remote_session(
            &request_app_state,
            RemoteSessionRequest {
                session_id: request_session_id,
                target_device_id: request_target_device_id,
                access_mode: RemoteAccessMode::Attended,
                route_preference: RemoteRoutePreference::WanRelay,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                requested_profile: None,
            },
        )
        .await
    });

    create_entered.wait().await;
    let authorization_guard = app_state.authorization_security_gate.lock().await;
    create_release.wait().await;
    timeout(Duration::from_secs(1), async {
        loop {
            if coordinator
                .snapshot(&session_id)
                .await
                .is_ok_and(|state| state.phase() == WanSessionPhase::Failed)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("coordinator failure must finish while the security gate is held");
    tokio::task::yield_now().await;

    let authorization = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .expect("pre-signaling authorization remains queryable");
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Authorizing,
        "terminal authorization and WAN projection must wait for the same security gate"
    );

    drop(authorization_guard);
    let response = timeout(Duration::from_secs(1), request_task)
        .await
        .expect("request must finish after the security gate is released")
        .expect("request task must not panic");
    assert!(matches!(response, IpcResponse::RemoteAccessError { .. }));
    assert_eq!(
        app_state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("terminal authorization remains queryable")
            .authorization_state,
        RemoteAuthorizationState::Denied
    );
}

#[tokio::test]
async fn controller_wan_query_list_and_repeated_stop_converge_on_closed() {
    let fixture = controller_authorization_fixture("lifecycle-stop").await;
    assert!(matches!(
        get_remote_session(&fixture.app_state, fixture.session_id.clone()).await,
        IpcResponse::RemoteSession { .. }
    ));
    let IpcResponse::SessionSnapshot { snapshot } =
        session_snapshot(&fixture.app_state, fixture.session_id.clone()).await
    else {
        panic!("live WAN workflow must have a runtime projection");
    };
    assert_eq!(snapshot.role, "controller");
    assert_eq!(snapshot.state, "connecting");
    assert_eq!(snapshot.transport_kind, "webrtc_relay");
    assert_eq!(
        snapshot.peer_device_id,
        Some(fixture.target_device_id.clone())
    );
    let IpcResponse::SessionList { sessions } = list_sessions(&fixture.app_state).await else {
        panic!("expected WAN-aware session list");
    };
    let listed = sessions
        .iter()
        .find(|session| session.session_id == fixture.session_id)
        .expect("live WAN controller must be listed before media starts");
    assert_eq!(listed.role, "controller");
    assert_eq!(listed.transport_kind, "webrtc_relay");
    assert_eq!(listed.state, "connecting");

    assert!(matches!(
        stop_session(&fixture.app_state, fixture.session_id.clone()).await,
        IpcResponse::SessionStopped { .. }
    ));
    assert!(matches!(
        stop_session(&fixture.app_state, fixture.session_id.clone()).await,
        IpcResponse::SessionStopped { .. }
    ));
    assert_eq!(
        fixture
            .coordinator
            .snapshot(&fixture.session_id)
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::Closed
    );
    let IpcResponse::RemoteSession { session } =
        get_remote_session(&fixture.app_state, fixture.session_id.clone()).await
    else {
        panic!("closed WAN authorization must remain queryable");
    };
    assert_eq!(
        session.authorization_state,
        RemoteAuthorizationState::Revoked
    );
    let IpcResponse::SessionList { sessions } = list_sessions(&fixture.app_state).await else {
        panic!("expected WAN-aware terminal session list");
    };
    assert_eq!(
        sessions
            .iter()
            .find(|session| session.session_id == fixture.session_id)
            .map(|session| session.state.as_str()),
        Some("closed")
    );
}

#[tokio::test]
async fn runtime_queries_reconcile_a_streaming_wan_coordinator_before_projection() {
    let app_state = Arc::new(AppState::default());
    let mut state = relay_verified_state(WanSessionRole::Controller, "runtime-reconcile");
    state
        .apply(WanSessionEvent::Streaming, 1_006)
        .expect("advance coordinator authority to streaming");
    let session_id = state.identity().session_id().clone();
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(FixedClock),
        )
        .expect("runtime projection coordinator"),
    );
    coordinator
        .begin(state)
        .await
        .expect("register streaming WAN authority");
    app_state
        .bind_wan_session_coordinator(coordinator)
        .expect("bind runtime projection coordinator");
    assert!(app_state.sessions.lock().await.get(&session_id).is_none());

    let IpcResponse::SessionSnapshot { snapshot } =
        session_snapshot(&app_state, session_id.clone()).await
    else {
        panic!("session snapshot must reconcile coordinator-owned WAN state");
    };
    assert_eq!(snapshot.state, "streaming");
    assert_eq!(snapshot.transport_kind, "webrtc_relay");

    app_state.sessions.lock().await.remove(&session_id);
    let IpcResponse::RuntimeSnapshot { snapshot } = runtime_snapshot(&app_state).await else {
        panic!("expected aggregate runtime snapshot");
    };
    let projected = snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .expect("runtime snapshot must reconcile coordinator-owned WAN state");
    assert_eq!(projected.state, "streaming");
    assert_eq!(projected.transport_kind, "webrtc_relay");
}

#[tokio::test]
async fn pending_wan_stop_without_coordinator_never_cleans_a_colliding_lan_projection() {
    let app_state = Arc::new(AppState::default());
    let session_id = SessionId("pending-wan-stop-collision".to_owned());
    let peer_device_id = DeviceId("pending-wan-stop-target".to_owned());
    let now = now_unix_ms();
    app_state
        .session_authorizations
        .begin_outgoing(
            mrd_service::session_authorization::VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: peer_device_id.clone(),
                peer_key_id: format!("pending_authenticated_peer:{}", peer_device_id.0),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                runtime_capabilities: vec![RemotePermissionScope::ScreenView],
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [91; 16],
                created_at_ms: now,
                expires_at_ms: now.saturating_add(30_000),
            },
        )
        .await
        .expect("pending outgoing WAN authorization");
    app_state.sessions.lock().await.insert(
        session_id.clone(),
        mrd_application::ports::SessionSnapshot {
            session_id: session_id.clone(),
            transport: "quic".to_owned(),
            source_device_id: Some(DeviceId("unrelated-lan-source".to_owned())),
            target_device_id: Some(DeviceId("unrelated-lan-target".to_owned())),
            local_listen_addr: None,
            local_server_name: None,
            local_cert_der_b64: None,
            remote_listen_addr: None,
            remote_server_name: None,
            remote_cert_der_b64: None,
            lifecycle_state: mrd_application::ports::SessionLifecycleState::Streaming,
            last_error: None,
            sender_active: true,
            receiver_active: false,
        },
    );
    let media_task = tokio::spawn(std::future::pending::<()>());
    app_state
        .media_tasks
        .lock()
        .await
        .register(session_id.clone(), media_task.abort_handle());

    assert!(matches!(
        stop_session(&app_state, session_id.clone()).await,
        IpcResponse::SessionStopped { .. }
    ));
    assert_eq!(
        app_state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("stopped WAN authorization retained")
            .authorization_state,
        RemoteAuthorizationState::Revoked
    );
    let sessions = app_state.sessions.lock().await;
    let unrelated_lan = sessions
        .get(&session_id)
        .expect("colliding LAN projection retained");
    assert_eq!(
        unrelated_lan.lifecycle_state,
        mrd_application::ports::SessionLifecycleState::Streaming
    );
    assert!(unrelated_lan.sender_active);
    drop(sessions);
    assert_eq!(
        app_state.media_tasks.lock().await.active_count(&session_id),
        1
    );
    media_task.abort();
    let _ = media_task.await;
}

#[tokio::test]
async fn controller_wan_repeated_failure_converges_on_one_failed_result() {
    let fixture = controller_authorization_fixture("lifecycle-fail").await;

    assert!(matches!(
        fail_session(
            &fixture.app_state,
            fixture.session_id.clone(),
            "test route loss".to_owned(),
        )
        .await,
        IpcResponse::SessionFailed { .. }
    ));
    assert!(matches!(
        fail_session(
            &fixture.app_state,
            fixture.session_id.clone(),
            "conflicting retry reason".to_owned(),
        )
        .await,
        IpcResponse::SessionFailed { .. }
    ));
    let state = fixture
        .coordinator
        .snapshot(&fixture.session_id)
        .await
        .unwrap();
    assert_eq!(state.phase(), WanSessionPhase::Failed);
    assert_eq!(
        state.failure(),
        Some(mrd_service::wan_session::model::WanSessionFailure::Transport)
    );
    let authorization = fixture
        .app_state
        .session_authorizations
        .snapshot(&fixture.session_id)
        .await
        .unwrap();
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Revoked
    );
    assert_eq!(
        authorization.failure.as_ref().map(|failure| failure.code),
        Some(mrd_ipc::RemoteReasonCode::RouteLost)
    );
}

#[tokio::test]
async fn terminal_authorization_query_fences_the_live_wan_workflow() {
    let fixture = controller_authorization_fixture("authorization-revoked").await;
    let authorization = fixture
        .app_state
        .session_authorizations
        .snapshot(&fixture.session_id)
        .await
        .expect("pending controller authorization");
    assert_eq!(
        fixture
            .app_state
            .session_authorizations
            .revoke_peer_authorizations(&authorization.peer_key_id, now_unix_ms())
            .await,
        vec![fixture.session_id.clone()]
    );

    let IpcResponse::RemoteSession { session } =
        get_remote_session(&fixture.app_state, fixture.session_id.clone()).await
    else {
        panic!("revoked WAN authorization must remain queryable");
    };
    assert_eq!(
        session.authorization_state,
        RemoteAuthorizationState::Revoked
    );
    let workflow = fixture
        .coordinator
        .snapshot(&fixture.session_id)
        .await
        .expect("terminal WAN workflow");
    assert_eq!(workflow.phase(), WanSessionPhase::Failed);
    assert_eq!(workflow.failure(), Some(WanSessionFailure::Cancelled));
}

#[tokio::test]
async fn terminal_authorization_route_query_fences_the_live_wan_workflow() {
    let fixture = controller_authorization_fixture("route-revoked").await;
    let authorization = fixture
        .app_state
        .session_authorizations
        .snapshot(&fixture.session_id)
        .await
        .expect("pending controller authorization");
    fixture
        .app_state
        .session_authorizations
        .revoke_peer_authorizations(&authorization.peer_key_id, now_unix_ms())
        .await;

    assert!(matches!(
        get_route_evidence(&fixture.app_state, fixture.session_id.clone()).await,
        IpcResponse::RemoteAccessError { .. }
    ));
    let workflow = fixture
        .coordinator
        .snapshot(&fixture.session_id)
        .await
        .expect("terminal WAN workflow");
    assert_eq!(workflow.phase(), WanSessionPhase::Failed);
    assert_eq!(workflow.failure(), Some(WanSessionFailure::Cancelled));
}

#[tokio::test]
async fn target_wan_list_and_stop_use_agent_lifecycle_projection() {
    let app_state = Arc::new(AppState::default());
    let controller_device_id = DeviceId("target-list-controller".to_owned());
    let target_device_id = DeviceId("target-list-local".to_owned());
    let session_id = SessionId("target-list-session".to_owned());
    let deadline_unix_ms = now_unix_ms().saturating_add(30_000);
    let identity = WanSessionIdentity::new(
        session_id.clone(),
        controller_device_id.clone(),
        target_device_id,
        digest("a"),
        digest("b"),
        deadline_unix_ms,
    )
    .expect("target WAN identity");
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(SystemWanSessionClock),
        )
        .expect("target WAN coordinator"),
    );
    coordinator
        .begin(WanSessionState::new(
            WanSessionRole::Target,
            identity.clone(),
        ))
        .await
        .expect("begin target WAN workflow");
    app_state
        .bind_wan_session_coordinator(coordinator.clone())
        .expect("bind target WAN coordinator");
    app_state
        .session_authorizations
        .begin_verified_incoming(
            mrd_service::session_authorization::VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: controller_device_id.clone(),
                peer_key_id: identity.controller_key_fingerprint().to_owned(),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                runtime_capabilities: vec![RemotePermissionScope::ScreenView],
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [0x61; 16],
                created_at_ms: now_unix_ms(),
                expires_at_ms: deadline_unix_ms,
            },
        )
        .await
        .expect("target authorization");

    let IpcResponse::SessionList { sessions } = list_sessions(&app_state).await else {
        panic!("target WAN list response");
    };
    let target = sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .expect("target WAN session projection");
    assert_eq!(target.role, "agent");
    assert_eq!(target.state, "listening");
    assert_eq!(target.transport_kind, "webrtc_relay");
    assert_eq!(target.peer_device_id, Some(controller_device_id));

    assert!(matches!(
        stop_session(&app_state, session_id.clone()).await,
        IpcResponse::SessionStopped { .. }
    ));
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Closed
    );
}

#[tokio::test]
async fn target_wan_consent_denial_converges_authorization_workflow_and_projection() {
    let app_state = Arc::new(AppState::default());
    let session_id = SessionId("target-consent-denial".to_owned());
    let controller_device_id = DeviceId("target-consent-controller".to_owned());
    let created_at_ms = now_unix_ms();
    let deadline_unix_ms = created_at_ms.saturating_add(30_000);
    let identity = WanSessionIdentity::new(
        session_id.clone(),
        controller_device_id.clone(),
        DeviceId("target-consent-local".to_owned()),
        digest("a"),
        digest("b"),
        deadline_unix_ms,
    )
    .expect("target consent identity");
    let mut workflow = WanSessionState::new(WanSessionRole::Target, identity.clone());
    workflow
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: digest("1"),
            },
            created_at_ms,
        )
        .unwrap();
    workflow
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: digest("2"),
            },
            created_at_ms.saturating_add(1),
        )
        .unwrap();
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(SystemWanSessionClock),
        )
        .expect("target consent coordinator"),
    );
    coordinator.begin(workflow).await.unwrap();
    app_state
        .bind_wan_session_coordinator(coordinator.clone())
        .expect("bind target consent coordinator");
    app_state
        .session_authorizations
        .begin_verified_incoming(
            mrd_service::session_authorization::VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: controller_device_id,
                peer_key_id: identity.controller_key_fingerprint().to_owned(),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                runtime_capabilities: vec![RemotePermissionScope::ScreenView],
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [0x64; 16],
                created_at_ms,
                expires_at_ms: deadline_unix_ms,
            },
        )
        .await
        .expect("target consent authorization");

    assert!(matches!(
        respond_to_consent(
            &app_state,
            ConsentResponse {
                session_id: session_id.clone(),
                decision: ConsentDecision::Deny,
                approved_scopes: Vec::new(),
                expected_policy_revision: DecimalU64::new(1),
            },
        )
        .await,
        IpcResponse::ConsentRecorded { .. }
    ));
    let workflow = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(workflow.phase(), WanSessionPhase::Failed);
    assert_eq!(workflow.failure(), Some(WanSessionFailure::Cancelled));
    let authorization = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .unwrap();
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Denied
    );
    let sessions = app_state.sessions.lock().await;
    let projection = sessions
        .get(&session_id)
        .expect("target consent terminal projection");
    assert!(matches!(
        projection.lifecycle_state,
        mrd_application::ports::SessionLifecycleState::Failed { .. }
    ));
    assert_eq!(projection.transport, "webrtc_relay");
}

#[tokio::test]
async fn service_expiry_converges_workflow_authorization_and_projection() {
    let app_state = Arc::new(AppState::default());
    let session_id = SessionId("service-expiry-session".to_owned());
    let controller_device_id = DeviceId("service-expiry-controller".to_owned());
    let target_device_id = DeviceId("service-expiry-target".to_owned());
    let deadline_unix_ms = 2_000;
    let clock = Arc::new(AdjustableClock::new(1_000));
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            clock.clone(),
        )
        .expect("expiry coordinator"),
    );
    coordinator
        .begin(WanSessionState::new(
            WanSessionRole::Controller,
            WanSessionIdentity::new(
                session_id.clone(),
                controller_device_id,
                target_device_id.clone(),
                digest("a"),
                digest("b"),
                deadline_unix_ms,
            )
            .expect("expiry identity"),
        ))
        .await
        .expect("begin expiring workflow");
    app_state
        .bind_wan_session_coordinator(coordinator.clone())
        .expect("bind expiry coordinator");
    app_state
        .session_authorizations
        .begin_outgoing(
            mrd_service::session_authorization::VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: target_device_id,
                peer_key_id: digest("b"),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                runtime_capabilities: vec![RemotePermissionScope::ScreenView],
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [0x62; 16],
                created_at_ms: 1_000,
                expires_at_ms: deadline_unix_ms,
            },
        )
        .await
        .expect("expiring authorization");
    clock.set(deadline_unix_ms);

    assert_eq!(
        mrd_service::wan_session::service::expire_due_wan_sessions(&app_state).await,
        1
    );
    let workflow = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(workflow.phase(), WanSessionPhase::Failed);
    assert_eq!(
        workflow.failure(),
        Some(WanSessionFailure::DeadlineExceeded)
    );
    let authorization = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .expect("expired authorization retained");
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Expired
    );
    assert_eq!(
        authorization.failure.as_ref().map(|failure| failure.code),
        Some(mrd_ipc::RemoteReasonCode::AuthorizationTimeout)
    );
    let IpcResponse::SessionList { sessions } = list_sessions(&app_state).await else {
        panic!("expiry list response");
    };
    assert_eq!(
        sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .map(|session| session.state.as_str()),
        Some("failed")
    );
}

#[tokio::test]
async fn service_shutdown_converges_workflow_authorization_and_projection() {
    let app_state = Arc::new(AppState::default());
    let session_id = SessionId("service-shutdown-session".to_owned());
    let controller_device_id = DeviceId("service-shutdown-controller".to_owned());
    let target_device_id = DeviceId("service-shutdown-target".to_owned());
    let created_at_ms = now_unix_ms();
    let deadline_unix_ms = created_at_ms.saturating_add(30_000);
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(SystemWanSessionClock),
        )
        .expect("shutdown coordinator"),
    );
    coordinator
        .begin(WanSessionState::new(
            WanSessionRole::Controller,
            WanSessionIdentity::new(
                session_id.clone(),
                controller_device_id,
                target_device_id.clone(),
                digest("a"),
                digest("b"),
                deadline_unix_ms,
            )
            .expect("shutdown identity"),
        ))
        .await
        .expect("begin shutdown workflow");
    app_state
        .bind_wan_session_coordinator(coordinator.clone())
        .expect("bind shutdown coordinator");
    app_state
        .session_authorizations
        .begin_outgoing(
            mrd_service::session_authorization::VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: target_device_id,
                peer_key_id: digest("b"),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                runtime_capabilities: vec![RemotePermissionScope::ScreenView],
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [0x63; 16],
                created_at_ms,
                expires_at_ms: deadline_unix_ms,
            },
        )
        .await
        .expect("shutdown authorization");

    assert_eq!(
        mrd_service::wan_session::service::shutdown_active_wan_sessions(&app_state).await,
        1
    );
    let workflow = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(workflow.phase(), WanSessionPhase::Failed);
    assert_eq!(workflow.failure(), Some(WanSessionFailure::Cancelled));
    let authorization = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .expect("shutdown authorization retained");
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Revoked
    );
    assert_eq!(
        authorization.failure.as_ref().map(|failure| failure.code),
        Some(mrd_ipc::RemoteReasonCode::GrantRevoked)
    );
}

#[tokio::test]
async fn wan_request_audit_uses_wan_action_and_transport() {
    let app_state = Arc::new(AppState::default());
    let controller_device_id = DeviceId("wan-audit-controller".to_owned());
    let target_device_id = DeviceId("wan-audit-target".to_owned());
    let session_id = SessionId("wan-audit-session".to_owned());
    app_state
        .devices
        .lock()
        .await
        .register(controller_device_id, "Controller".to_owned());
    let coordinator = Arc::new(
        WanSessionCoordinator::with_workflow_ports(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            WanSessionWorkflowPorts::new(
                Arc::new(ControllerRequestBackend::new()),
                Arc::new(AuthorizationObservingSignaling {
                    authorizations: Arc::clone(&app_state.session_authorizations),
                    observed_exact_authorization: AtomicBool::new(false),
                    controller_identity: Mutex::new(None),
                }),
                Arc::new(UnusedControllerConsent),
                Arc::new(SystemWanSessionClock),
            ),
        )
        .expect("WAN audit coordinator"),
    );
    app_state
        .bind_wan_session_coordinator(coordinator)
        .expect("bind WAN audit coordinator");

    let server = IpcServer::new(app_state.clone());
    let response = server
        .handle_request(IpcRequest::RequestRemoteSession {
            request: RemoteSessionRequest {
                session_id: session_id.clone(),
                target_device_id,
                access_mode: RemoteAccessMode::Attended,
                route_preference: RemoteRoutePreference::WanRelay,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                requested_profile: None,
            },
        })
        .await;
    assert!(matches!(
        response,
        IpcResponse::RemoteSessionRequested { .. }
    ));
    let events = app_state
        .audit_log
        .query(&AuditLogQuery {
            session_id: Some(session_id.clone()),
            action: Some("session.start_wan".to_owned()),
            limit: Some(10),
        })
        .expect("WAN start audit query");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].transport_kind.as_deref(), Some("webrtc_relay"));

    assert!(matches!(
        server
            .handle_request(IpcRequest::StopSession {
                session_id: session_id.clone(),
            })
            .await,
        IpcResponse::SessionStopped { .. }
    ));
    let stopped = app_state
        .audit_log
        .query(&AuditLogQuery {
            session_id: Some(session_id),
            action: Some("session.stop".to_owned()),
            limit: Some(10),
        })
        .expect("WAN stop audit query");
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0].transport_kind.as_deref(), Some("webrtc_relay"));
    assert_eq!(
        stopped[0].peer_device_id.as_ref(),
        Some(&DeviceId("wan-audit-target".to_owned()))
    );
}

#[tokio::test]
async fn auto_request_audit_uses_the_selected_wan_route_even_before_registration() {
    let app_state = Arc::new(AppState::default());
    let session_id = SessionId("auto-selected-wan-audit".to_owned());
    let server = IpcServer::new(app_state.clone());

    let response = server
        .handle_request(IpcRequest::RequestRemoteSession {
            request: RemoteSessionRequest {
                session_id: session_id.clone(),
                target_device_id: DeviceId("auto-selected-wan-target".to_owned()),
                access_mode: RemoteAccessMode::Attended,
                route_preference: RemoteRoutePreference::Auto,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                requested_profile: None,
            },
        })
        .await;
    assert!(matches!(response, IpcResponse::RemoteAccessError { .. }));

    let wan_events = app_state
        .audit_log
        .query(&AuditLogQuery {
            session_id: Some(session_id.clone()),
            action: Some("session.start_wan".to_owned()),
            limit: Some(10),
        })
        .expect("selected WAN audit query");
    assert_eq!(wan_events.len(), 1);
    assert_eq!(
        wan_events[0].transport_kind.as_deref(),
        Some("webrtc_relay")
    );
    assert!(
        app_state
            .audit_log
            .query(&AuditLogQuery {
                session_id: Some(session_id),
                action: Some("session.start_lan".to_owned()),
                limit: Some(10),
            })
            .expect("LAN audit query")
            .is_empty(),
        "Auto selected WAN must never be mis-audited as LAN"
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

    async fn stop_media(&self, _session_id: &SessionId) -> Result<(), WanMediaActivationError> {
        self.calls.lock().unwrap().push("stop-media".to_owned());
        Ok(())
    }

    async fn remove_failover(
        &self,
        _session_id: &SessionId,
    ) -> Result<(), WanMediaActivationError> {
        self.calls
            .lock()
            .unwrap()
            .push("remove-failover".to_owned());
        Ok(())
    }
}

struct MediaCleanupAdapter {
    media: Arc<RecordingMediaPort>,
}

#[async_trait]
impl WanSessionCleanup for MediaCleanupAdapter {
    async fn freeze_input(
        &self,
        _session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn stop_media(&self, session_id: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        WanMediaActivationPort::stop_media(self.media.as_ref(), session_id)
            .await
            .map_err(|_| WanSessionCoordinatorError::CleanupFailed)
    }

    async fn close_transport(
        &self,
        _session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn remove_failover(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        WanMediaActivationPort::remove_failover(self.media.as_ref(), session_id)
            .await
            .map_err(|_| WanSessionCoordinatorError::CleanupFailed)
    }

    async fn clear_signaling(
        &self,
        _session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn close_backend(
        &self,
        _session_id: &SessionId,
        _failed: bool,
    ) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
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
async fn media_start_failure_leaves_cleanup_owned_by_the_coordinator_once() {
    let state = relay_verified_state(WanSessionRole::Controller, "failure-cleanup-owner");
    let session_id = state.identity().session_id().clone();
    let media = Arc::new(RecordingMediaPort {
        calls: Mutex::new(Vec::new()),
        fail: true,
    });
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            Default::default(),
            Arc::new(MediaCleanupAdapter {
                media: Arc::clone(&media),
            }),
            Arc::new(FixedClock),
        )
        .unwrap(),
    );
    coordinator.begin(state.clone()).await.unwrap();

    assert!(start_verified_media(&coordinator, &state, media.as_ref())
        .await
        .is_err());
    {
        let calls = media.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.as_str() == "stop-media")
                .count(),
            1,
            "the coordinator cleanup receipt must own media stop exactly once"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.as_str() == "remove-failover")
                .count(),
            1,
            "the coordinator cleanup receipt must own failover removal exactly once"
        );
    }
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Failed
    );
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
