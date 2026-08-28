use async_trait::async_trait;
use mrd_ipc::{
    ConsentDecision, ConsentResponse, DecimalU64, LanDiscoverySnapshot, LanPeerInfo,
    RemoteAuthorizationState, RemotePermissionScope, RemoteRoutePreference,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::wan_session::{
    coordinator::{NoopWanSessionCleanup, WanSessionClock, WanSessionCoordinator},
    media::{
        enable_input_after_control_evidence, select_route, start_verified_media,
        ControlEvidenceBarrier, LanDiscoveryEvidence, WanInputActivationPort,
        WanMediaActivationError, WanMediaActivationPort, WanMediaAuthority, WanRouteSelection,
    },
    model::{
        GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionEvent, WanSessionIdentity,
        WanSessionPhase, WanSessionRole, WanSessionState,
    },
    service::ServiceWanSessionConsentPublisher,
};
use mrd_signal_proto::{
    WanAccessModeV3, WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
};
use std::sync::{Arc, Mutex};

const REQUEST_COMMITMENT: &str = "11";
const INTENT_COMMITMENT: &str = "22";
const GRANT_COMMITMENT: &str = "33";
const RELAY_URL_DIGEST: &str = "44";

fn digest(value: &str) -> String {
    assert!(!value.is_empty() && 64 % value.len() == 0);
    value.repeat(64 / value.len())
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
