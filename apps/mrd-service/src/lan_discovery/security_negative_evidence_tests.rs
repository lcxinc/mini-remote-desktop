use super::*;
use crate::{
    handlers::session,
    ipc_server::IpcServer,
    session_authorization::{VerifiedIncomingAuthorizationRequest, VerifiedSessionGrant},
};
use mrd_identity::DeviceIdentity;
use mrd_ipc::{
    AuditEventsQueryV2, AuditLogQuery, ControlInputEvent, ControlInputKey, DecimalU64, IpcRequest,
    IpcResponse, RemoteAuthorizationState, RemoteCursorState, RemoteMediaState, RemoteRouteState,
};
use mrd_store_sqlite::TrustState;
use serde_json::json;
use std::{env, fs, path::PathBuf};

const INVOCATION_ENV: &str = "MRD_SECURITY_NEGATIVE_INVOCATION_ID";
const CASE_ENV: &str = "MRD_SECURITY_NEGATIVE_CASE";
const ARTIFACT_ENV: &str = "MRD_SECURITY_NEGATIVE_ARTIFACT";

struct NegativeCase<'a> {
    id: &'a str,
    scenario: &'a str,
    identity_state: &'a str,
    authorization_outcome: &'a str,
    reason: &'a str,
    audit_action: &'a str,
}

#[derive(Debug, Clone, Copy)]
struct NegativeSideEffects {
    sender_tasks_started: u64,
    receiver_tasks_started: u64,
    media_tasks_registered: u64,
    active_media_tasks: usize,
    media_packets_sent: u64,
    media_frames_presented: u64,
    control_events_injected: u64,
    route_started: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct NegativeSideEffectTotals {
    sender_tasks_started: u64,
    receiver_tasks_started: u64,
    media_tasks_registered: u64,
    media_packets_sent: u64,
    media_frames_presented: u64,
    control_events_injected: u64,
}

impl NegativeSideEffectTotals {
    fn delta_since(self, baseline: Self) -> Self {
        Self {
            sender_tasks_started: self
                .sender_tasks_started
                .saturating_sub(baseline.sender_tasks_started),
            receiver_tasks_started: self
                .receiver_tasks_started
                .saturating_sub(baseline.receiver_tasks_started),
            media_tasks_registered: self
                .media_tasks_registered
                .saturating_sub(baseline.media_tasks_registered),
            media_packets_sent: self
                .media_packets_sent
                .saturating_sub(baseline.media_packets_sent),
            media_frames_presented: self
                .media_frames_presented
                .saturating_sub(baseline.media_frames_presented),
            control_events_injected: self
                .control_events_injected
                .saturating_sub(baseline.control_events_injected),
        }
    }
}

fn audit_sequence_baseline(app_state: &Arc<AppState>) -> u64 {
    app_state
        .audit_log
        .query(&AuditLogQuery {
            session_id: None,
            action: None,
            limit: Some(1),
        })
        .expect("query audit baseline")
        .last()
        .map_or(0, |event| event.id)
}

async fn capture_side_effect_totals(app_state: &Arc<AppState>) -> NegativeSideEffectTotals {
    let (sender_tasks_started, receiver_tasks_started) = {
        let sessions = app_state.sessions.lock().await;
        (
            sessions.sender_activation_count(),
            sessions.receiver_activation_count(),
        )
    };
    let media_tasks_registered = app_state
        .media_tasks
        .lock()
        .await
        .successful_registration_count();
    let (media_packets_sent, media_frames_presented) = {
        let pipelines = app_state.media_pipelines.lock().await;
        (
            pipelines.cumulative_sender_packets_sent(),
            pipelines.cumulative_render_presented_frames(),
        )
    };
    let control_events_injected = app_state
        .control_input()
        .lock()
        .await
        .injected_message_count();
    NegativeSideEffectTotals {
        sender_tasks_started,
        receiver_tasks_started,
        media_tasks_registered,
        media_packets_sent,
        media_frames_presented,
        control_events_injected,
    }
}

async fn capture_side_effects_since(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    baseline: NegativeSideEffectTotals,
) -> NegativeSideEffects {
    let delta = capture_side_effect_totals(app_state)
        .await
        .delta_since(baseline);
    let compatibility = app_state.sessions.lock().await.get(session_id).cloned();
    let authorization = app_state.session_authorizations.snapshot(session_id).await;
    NegativeSideEffects {
        sender_tasks_started: delta.sender_tasks_started,
        receiver_tasks_started: delta.receiver_tasks_started,
        media_tasks_registered: delta.media_tasks_registered,
        active_media_tasks: app_state.media_tasks.lock().await.active_count(session_id),
        media_packets_sent: delta.media_packets_sent,
        media_frames_presented: delta.media_frames_presented,
        control_events_injected: delta.control_events_injected,
        route_started: compatibility.as_ref().is_some_and(|snapshot| {
            !snapshot.lifecycle_state.is_terminal()
                && (snapshot.sender_active || snapshot.receiver_active)
        }) || authorization.as_ref().is_some_and(|snapshot| {
            matches!(
                snapshot.route_state,
                RemoteRouteState::Gathering
                    | RemoteRouteState::Connecting
                    | RemoteRouteState::Connected
                    | RemoteRouteState::Migrating
                    | RemoteRouteState::Reconnecting
            )
        }),
    }
}

async fn emit_authoritative_artifact(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    audit_baseline: u64,
    side_effect_baseline: NegativeSideEffectTotals,
    side_effects: NegativeSideEffects,
    case: NegativeCase<'_>,
) {
    app_state
        .audit_log
        .verify_integrity()
        .expect("verify security-negative audit chain");
    let audit_page = app_state
        .audit_log
        .query_v2(&AuditEventsQueryV2 {
            after_sequence: Some(DecimalU64::new(audit_baseline)),
            limit: 32,
            session_id: Some(session_id.clone()),
            action: Some(case.audit_action.to_string()),
            outcome: None,
            peer_device_id: None,
        })
        .expect("query verified security-negative audit evidence");
    assert_eq!(audit_page.cursor_state, RemoteCursorState::Current);
    assert!(audit_page.chain_verified, "audit chain is not verified");
    assert!(
        !audit_page.has_more,
        "negative case audit page is incomplete"
    );
    let matching_audit = audit_page
        .events
        .iter()
        .filter(|event| event.outcome == "denied" || event.outcome == "rejected")
        .filter(|event| {
            event
                .reason_code
                .is_some_and(|reason| remote_reason_code_wire_name(reason) == case.reason)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching_audit.len(),
        1,
        "the product attempt must emit one exact session-bound rejection audit"
    );

    assert!(
        matching_audit[0].sequence.get() > audit_baseline,
        "negative audit did not follow this invocation baseline"
    );
    let authorization = app_state.session_authorizations.snapshot(session_id).await;
    let authorization_is_terminal = authorization.as_ref().is_none_or(|snapshot| {
        snapshot.authorization_state != RemoteAuthorizationState::Granted
            && snapshot.route_state != RemoteRouteState::Connected
            && snapshot.media_state != RemoteMediaState::Streaming
    });
    let post_cleanup =
        capture_side_effects_since(app_state, session_id, side_effect_baseline).await;
    let cleanup_completed = side_effects.sender_tasks_started == 0
        && side_effects.receiver_tasks_started == 0
        && side_effects.media_tasks_registered == 0
        && side_effects.active_media_tasks == 0
        && side_effects.media_packets_sent == 0
        && side_effects.media_frames_presented == 0
        && side_effects.control_events_injected == 0
        && !side_effects.route_started
        && post_cleanup.sender_tasks_started == 0
        && post_cleanup.receiver_tasks_started == 0
        && post_cleanup.media_tasks_registered == 0
        && post_cleanup.active_media_tasks == 0
        && post_cleanup.media_packets_sent == 0
        && post_cleanup.media_frames_presented == 0
        && post_cleanup.control_events_injected == 0
        && !post_cleanup.route_started
        && authorization_is_terminal;

    assert_eq!(
        side_effects.sender_tasks_started, 0,
        "rejection started a sender"
    );
    assert_eq!(
        side_effects.receiver_tasks_started, 0,
        "rejection started a receiver"
    );
    assert_eq!(
        side_effects.media_tasks_registered, 0,
        "rejection registered a media task"
    );
    assert_eq!(
        side_effects.active_media_tasks, 0,
        "rejection left a media task active"
    );
    assert_eq!(
        side_effects.media_packets_sent, 0,
        "rejection sent media packets"
    );
    assert_eq!(
        side_effects.media_frames_presented, 0,
        "rejection presented a media frame"
    );
    assert_eq!(
        side_effects.control_events_injected, 0,
        "rejection injected a control event"
    );
    assert!(!side_effects.route_started, "rejection started a route");
    assert!(cleanup_completed, "rejection cleanup did not complete");

    let invocation_id = match env::var(INVOCATION_ENV) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return,
        Err(error) => panic!("invalid {INVOCATION_ENV}: {error}"),
    };
    assert!(!invocation_id.trim().is_empty(), "invocation id is empty");
    assert_eq!(
        env::var(CASE_ENV).expect("security-negative case binding"),
        case.id,
        "test case does not match the requested evidence case"
    );
    let artifact_path = PathBuf::from(env::var(ARTIFACT_ENV).expect("artifact output path"));
    let run_id = format!("security-negative-{invocation_id}-{}", case.id);
    let artifact = json!({
        "schema_version": "remote-experience-run.v2",
        "run_id": run_id,
        "scenario": {"id": case.scenario, "required": true},
        "route": {"requested": "quic", "selected": "none", "candidate_pair": "not-selected"},
        "media": {"requested_profile": "1080p60-h264", "selected_profile": "none", "profile_downgraded": false},
        "present": {"visible_first_frame_ms": null, "input_to_photon_ms": [], "fps_windows": [], "freeze_count": 0, "stall_ms": []},
        "resources": {"cpu_percent": [], "gpu_percent": [], "rss_bytes": [], "vram_bytes": []},
        "producer_status": "completed",
        "gate_status": "PASS",
        "audit_event_ids": matching_audit.iter().map(|event| event.sequence.get().to_string()).collect::<Vec<_>>(),
        "security": {
            "attempt_kind": case.id,
            "identity_state": case.identity_state,
            "authorization_outcome": case.authorization_outcome,
            "authorization_basis": "none",
            "scope_authorized": false,
            "quic_peer_authenticated": false,
            "control_input_authenticated": false,
            "rejected": true,
            "rejection_reason": case.reason,
            "cleanup_completed": cleanup_completed
        },
        "side_effects": {
            "sender_tasks_started": side_effects.sender_tasks_started,
            "receiver_tasks_started": side_effects.receiver_tasks_started,
            "media_packets_sent": side_effects.media_packets_sent,
            "media_frames_presented": side_effects.media_frames_presented,
            "control_events_injected": side_effects.control_events_injected
        }
    });
    fs::write(
        &artifact_path,
        serde_json::to_vec_pretty(&artifact).expect("serialize authoritative artifact"),
    )
    .unwrap_or_else(|error| panic!("write {}: {error}", artifact_path.display()));
}

fn new_identity() -> DeviceIdentity {
    DeviceIdentity::generate(&SystemRandom::new()).expect("test identity")
}

fn signed_session_request(
    app_state: &Arc<AppState>,
    controller: &DeviceIdentity,
    session_id: &SessionId,
    source_endpoint: SocketAddr,
    nonce: [u8; 16],
) -> SignedLanSessionRequest {
    let issued_at_ms = now_ms();
    SignedLanSessionRequest::sign(
        controller,
        LanSessionRequest {
            magic: DISCOVERY_MAGIC.to_string(),
            app_id: DISCOVERY_APP_ID.to_string(),
            protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
            instance_id: format!("{}-controller", session_id.0),
            session_id: session_id.0.clone(),
            source_device_id: format!("{}-controller-device", session_id.0),
            source_device_name: "Security Negative Controller".to_string(),
            source_key_id: controller.key_id().to_string(),
            source_key_epoch: 1,
            target_device_id: "security-negative-target".to_string(),
            target_key_id: app_state
                .device_identities
                .machine_key_id()
                .expect("target key id")
                .to_string(),
            target_key_epoch: app_state
                .device_identities
                .machine_key_epoch()
                .expect("target key epoch"),
            transport_kind: "quic".to_string(),
            source_discovery_port: Some(21_116),
            source_endpoint,
            source_media_capabilities: lan_media_capabilities(),
            requested_media_profile: Some(MediaProfile::default()),
            access_mode: RemoteAccessMode::Unattended,
            requested_scopes: vec![RemotePermissionScope::ScreenView],
            unattended_proof: None,
            timestamp_ms: issued_at_ms,
            expires_at_ms: issued_at_ms.saturating_add(5_000),
            nonce,
        },
    )
    .expect("signed security-negative request")
}

#[tokio::test]
async fn security_negative_untrusted_emits_authoritative_evidence() {
    let app_state = Arc::new(AppState::new());
    app_state.devices.lock().await.register(
        DeviceId("security-negative-target".to_string()),
        "Security Negative Target".to_string(),
    );
    let controller = new_identity();
    let reply_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session_id = SessionId("security-negative-untrusted".to_string());
    let request = signed_session_request(
        &app_state,
        &controller,
        &session_id,
        reply_socket.local_addr().unwrap(),
        [0x31; 16],
    );
    let audit_baseline = audit_sequence_baseline(&app_state);
    let side_effect_baseline = capture_side_effect_totals(&app_state).await;

    let service_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    process_lan_discovery_packet(
        &service_socket,
        &app_state,
        &serde_json::to_vec(&LanDiscoveryPacket::SignedRemoteSessionRequest(
            request.clone(),
        ))
        .unwrap(),
        reply_socket.local_addr().unwrap(),
    )
    .await
    .expect("untrusted request receives signed denial");
    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(1), reply_socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let LanDiscoveryPacket::SignedRemoteSessionBootstrap(denial) =
        serde_json::from_slice(&buffer[..len]).unwrap()
    else {
        panic!("expected signed denial");
    };
    assert_eq!(
        denial.payload.failure.map(|failure| failure.code),
        Some(RemoteReasonCode::TrustRequired)
    );
    let side_effects =
        capture_side_effects_since(&app_state, &session_id, side_effect_baseline).await;
    emit_authoritative_artifact(
        &app_state,
        &session_id,
        audit_baseline,
        side_effect_baseline,
        side_effects,
        NegativeCase {
            id: "untrusted",
            scenario: "security.negative.untrusted",
            identity_state: "untrusted",
            authorization_outcome: "denied",
            reason: "trust_required",
            audit_action: "session.authorization_decision",
        },
    )
    .await;
}

#[tokio::test]
async fn security_negative_replay_emits_authoritative_evidence() {
    let app_state = Arc::new(AppState::new());
    app_state.devices.lock().await.register(
        DeviceId("security-negative-target".to_string()),
        "Security Negative Target".to_string(),
    );
    let controller = new_identity();
    app_state
        .device_identities
        .trust_authenticated_peer_for_test(&controller, 1, TrustState::Trusted);
    let reply_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session_id = SessionId("security-negative-replay".to_string());
    let request = signed_session_request(
        &app_state,
        &controller,
        &session_id,
        reply_socket.local_addr().unwrap(),
        [0x32; 16],
    );
    app_state
        .lan_discovery
        .signed_replays
        .lock()
        .await
        .accept(
            LanSignedReplayDomain::SessionRequest,
            controller.key_id(),
            request.payload.nonce,
            request.payload.expires_at_ms,
            request.payload.timestamp_ms,
        )
        .expect("seed previously accepted request");
    let audit_baseline = audit_sequence_baseline(&app_state);
    let side_effect_baseline = capture_side_effect_totals(&app_state).await;
    let service_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    process_lan_discovery_packet(
        &service_socket,
        &app_state,
        &serde_json::to_vec(&LanDiscoveryPacket::SignedRemoteSessionRequest(request)).unwrap(),
        reply_socket.local_addr().unwrap(),
    )
    .await
    .expect("replay receives signed denial");
    let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
    let (len, _) = timeout(Duration::from_secs(1), reply_socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let LanDiscoveryPacket::SignedRemoteSessionBootstrap(denial) =
        serde_json::from_slice(&buffer[..len]).unwrap()
    else {
        panic!("expected signed replay denial");
    };
    assert_eq!(
        denial.payload.failure.map(|failure| failure.code),
        Some(RemoteReasonCode::ReplayDetected)
    );
    let side_effects =
        capture_side_effects_since(&app_state, &session_id, side_effect_baseline).await;
    emit_authoritative_artifact(
        &app_state,
        &session_id,
        audit_baseline,
        side_effect_baseline,
        side_effects,
        NegativeCase {
            id: "replay",
            scenario: "security.negative.replay",
            identity_state: "trusted",
            authorization_outcome: "denied",
            reason: "replay_detected",
            audit_action: "session.authorization_decision",
        },
    )
    .await;
}

async fn install_outgoing_control_grant(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    granted_scopes: Vec<RemotePermissionScope>,
) {
    let peer = new_identity();
    let now = now_ms();
    app_state
        .session_authorizations
        .begin_outgoing(VerifiedIncomingAuthorizationRequest {
            session_id: session_id.clone(),
            peer_device_id: DeviceId("security-negative-peer".to_string()),
            peer_key_id: peer.key_id().to_string(),
            peer_key_epoch: 1,
            access_mode: RemoteAccessMode::Attended,
            requested_scopes: vec![
                RemotePermissionScope::ScreenView,
                RemotePermissionScope::InputKeyboard,
            ],
            peer_permission_ceiling: vec![
                RemotePermissionScope::ScreenView,
                RemotePermissionScope::InputKeyboard,
            ],
            machine_permission_ceiling: vec![
                RemotePermissionScope::ScreenView,
                RemotePermissionScope::InputKeyboard,
            ],
            runtime_capabilities: vec![
                RemotePermissionScope::ScreenView,
                RemotePermissionScope::InputKeyboard,
            ],
            transport_kind: "quic".to_string(),
            request_nonce: [0x41; 16],
            created_at_ms: now,
            expires_at_ms: now.saturating_add(60_000),
        })
        .await
        .expect("outgoing authorization");
    app_state
        .session_authorizations
        .bind_authenticated_peer_key(session_id, peer.public_key(), now)
        .await
        .expect("peer key binding");
    app_state
        .session_authorizations
        .install_verified_grant(
            VerifiedSessionGrant {
                grant_id: format!("sha256:{}", "55".repeat(32)),
                session_id: session_id.clone(),
                granted_scopes,
                issued_at_ms: now,
                expires_at_ms: now.saturating_add(30_000),
                policy_revision: 7,
                route_constraint: "quic".to_string(),
                transport_fingerprint_sha256: [0x66; 32],
            },
            now,
        )
        .await
        .expect("verified grant");
    app_state
        .session_authorizations
        .mark_streaming(session_id, now)
        .await
        .expect("streaming authorization");
}

fn keyboard_event() -> ControlInputEvent {
    ControlInputEvent::Key {
        key: ControlInputKey::VirtualKey { code: 0x41 },
        pressed: true,
    }
}

#[tokio::test]
async fn security_negative_wrong_scope_emits_authoritative_evidence() {
    let app_state = Arc::new(AppState::new());
    app_state.devices.lock().await.register(
        DeviceId("security-negative-target".to_string()),
        "Security Negative Target".to_string(),
    );
    let session_id = SessionId("security-negative-wrong-scope".to_string());
    let controller = new_identity();
    let created_at_ms = now_ms();
    let pending = app_state
        .session_authorizations
        .begin_verified_incoming(VerifiedIncomingAuthorizationRequest {
            session_id: session_id.clone(),
            peer_device_id: DeviceId("security-negative-controller".to_string()),
            peer_key_id: controller.key_id().to_string(),
            peer_key_epoch: 1,
            access_mode: RemoteAccessMode::Attended,
            requested_scopes: vec![RemotePermissionScope::ScreenView],
            peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
            machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
            runtime_capabilities: vec![RemotePermissionScope::ScreenView],
            transport_kind: "quic".to_string(),
            request_nonce: [0x43; 16],
            created_at_ms,
            expires_at_ms: created_at_ms.saturating_add(30_000),
        })
        .await
        .expect("pending incoming consent");
    app_state
        .session_authorizations
        .bind_authenticated_peer_key(&session_id, controller.public_key(), created_at_ms)
        .await
        .expect("incoming peer key binding");
    let audit_baseline = audit_sequence_baseline(&app_state);
    let side_effect_baseline = capture_side_effect_totals(&app_state).await;
    let response = IpcServer::new(app_state.clone())
        .handle_request(IpcRequest::RespondToConsent {
            response: mrd_ipc::ConsentResponse {
                session_id: session_id.clone(),
                decision: mrd_ipc::ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::InputKeyboard],
                expected_policy_revision: pending.policy_revision,
            },
        })
        .await;
    assert!(matches!(
        response,
        IpcResponse::RemoteAccessError { ref failure, .. }
            if failure.code == RemoteReasonCode::ScopeDenied
    ));
    let side_effects =
        capture_side_effects_since(&app_state, &session_id, side_effect_baseline).await;
    let _ = session::stop_session(&app_state, session_id.clone()).await;
    emit_authoritative_artifact(
        &app_state,
        &session_id,
        audit_baseline,
        side_effect_baseline,
        side_effects,
        NegativeCase {
            id: "wrong_scope",
            scenario: "security.negative.wrong_scope",
            identity_state: "trusted",
            authorization_outcome: "denied",
            reason: "scope_denied",
            audit_action: "session.consent_decision",
        },
    )
    .await;
}

#[tokio::test]
async fn security_negative_revoked_emits_authoritative_evidence() {
    let app_state = Arc::new(AppState::new());
    app_state.devices.lock().await.register(
        DeviceId("security-negative-controller".to_string()),
        "Security Negative Controller".to_string(),
    );
    let session_id = SessionId("security-negative-revoked".to_string());
    install_outgoing_control_grant(
        &app_state,
        &session_id,
        vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputKeyboard,
        ],
    )
    .await;
    app_state
        .session_authorizations
        .record_failure(
            &session_id,
            RemoteAuthorizationState::Revoked,
            RemoteFailure {
                code: RemoteReasonCode::GrantRevoked,
                message: "the active grant was revoked".to_string(),
                suggested_action: None,
            },
            now_ms(),
        )
        .await
        .expect("revoke active grant");
    let audit_baseline = audit_sequence_baseline(&app_state);
    let side_effect_baseline = capture_side_effect_totals(&app_state).await;
    let response = IpcServer::new(app_state.clone())
        .handle_request(IpcRequest::SendControlInput {
            session_id: session_id.clone(),
            event: keyboard_event(),
        })
        .await;
    assert!(matches!(
        response,
        IpcResponse::RemoteAccessError { ref failure, .. }
            if failure.code == RemoteReasonCode::GrantRevoked
    ));
    let side_effects =
        capture_side_effects_since(&app_state, &session_id, side_effect_baseline).await;
    let _ = session::stop_session(&app_state, session_id.clone()).await;
    emit_authoritative_artifact(
        &app_state,
        &session_id,
        audit_baseline,
        side_effect_baseline,
        side_effects,
        NegativeCase {
            id: "revoked",
            scenario: "security.negative.revoked",
            identity_state: "trusted",
            authorization_outcome: "revoked",
            reason: "grant_revoked",
            audit_action: "session.control_input_decision",
        },
    )
    .await;
}

#[tokio::test]
async fn security_negative_certificate_substitution_emits_authoritative_evidence() {
    let app_state = Arc::new(AppState::new());
    app_state.devices.lock().await.register(
        DeviceId("security-negative-controller".to_string()),
        "Security Negative Controller".to_string(),
    );
    let target = Arc::new(new_identity());
    app_state
        .device_identities
        .trust_authenticated_peer_for_test(&target, 1, TrustState::Trusted);
    let target_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target_addr = target_socket.local_addr().unwrap();
    let announced_at = now_ms();
    let announcement = SignedLanAnnouncement::sign(
        &target,
        1,
        LanAnnouncement {
            magic: DISCOVERY_MAGIC.to_string(),
            app_id: DISCOVERY_APP_ID.to_string(),
            instance_id: "certificate-substitution-target".to_string(),
            device_id: "security-negative-target".to_string(),
            device_name: "Security Negative Target".to_string(),
            device_type: "rdesk".to_string(),
            protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
            discovery_port: target_addr.port(),
            transports: vec![
                "quic".to_string(),
                LAN_QUIC_MEDIA_TRANSPORT.to_string(),
                LAN_QUIC_MEDIA_PROFILE_TRANSPORT.to_string(),
                LAN_QUIC_MEDIA_V2_TRANSPORT.to_string(),
                LAN_QUIC_MEDIA_V3_TRANSPORT.to_string(),
                LAN_QUIC_RELIABLE_MEDIA_TRANSPORT.to_string(),
                LAN_QUIC_PERSISTENT_MEDIA_TRANSPORT.to_string(),
                LAN_MEDIA_PROFILE_CONTROL_TRANSPORT.to_string(),
            ],
            service_build_id: Some(service_build_id()),
            media_protocol_version: Some(LAN_MEDIA_PROTOCOL_VERSION),
            media_capabilities: test_lan_media_capabilities(),
            mac_address: None,
            timestamp_ms: announced_at,
        },
        target_addr,
        announced_at.saturating_add(5_000),
        [0x51; 16],
    )
    .expect("signed target announcement");
    ingest_signed_lan_announcement(&app_state, announcement, target_addr, announced_at)
        .await
        .expect("trusted target discovery");

    let responder_socket = target_socket.clone();
    let responder_identity = target.clone();
    let mut responder = tokio::spawn(async move {
        let mut buffer = vec![0_u8; DISCOVERY_PACKET_BUFFER_BYTES];
        let (len, controller_addr) = responder_socket.recv_from(&mut buffer).await.unwrap();
        let LanDiscoveryPacket::SignedRemoteSessionRequest(request) =
            serde_json::from_slice(&buffer[..len]).unwrap()
        else {
            panic!("expected signed session request");
        };
        let requested = request
            .payload
            .requested_media_profile
            .clone()
            .unwrap_or_default();
        let negotiation = MediaProfileNegotiation {
            requested: requested.clone(),
            selected: requested,
            status: "accepted".to_string(),
            reason: None,
            selected_source_id: None,
            selected_width: None,
            selected_height: None,
            downgrade_reason: None,
        };
        let grant = SignedLanSessionGrant::sign(
            &responder_identity,
            LanSessionGrantPayload {
                session_id: request.payload.session_id.clone(),
                controller_key_id: request.payload.source_key_id.clone(),
                controller_key_epoch: request.payload.source_key_epoch,
                target_key_id: responder_identity.key_id().to_string(),
                target_key_epoch: 1,
                access_mode: request.payload.access_mode,
                granted_scopes: request.payload.requested_scopes.clone(),
                issued_at_ms: now_ms(),
                expires_at_ms: now_ms().saturating_add(30_000),
                policy_revision: 1,
                route_constraint: "quic".to_string(),
                profile_constraint: Some(
                    media_profile_constraint_hash(&negotiation).expect("profile commitment"),
                ),
                request_nonce: request.payload.nonce,
                grant_nonce: [0x52; 16],
                windows_session_id: None,
                transport_fingerprint_sha256: [0xA5; 32],
            },
        )
        .expect("signed grant");
        let substituted_cert = vec![9, 8, 7, 6];
        let payload = LanSessionBootstrap {
            magic: DISCOVERY_MAGIC.to_string(),
            app_id: DISCOVERY_APP_ID.to_string(),
            protocol_version: SIGNED_LAN_PROTOCOL_VERSION,
            instance_id: "certificate-substitution-target".to_string(),
            session_id: request.payload.session_id.clone(),
            controller_key_id: request.payload.source_key_id.clone(),
            controller_key_epoch: request.payload.source_key_epoch,
            target_key_id: responder_identity.key_id().to_string(),
            target_key_epoch: 1,
            request_nonce: request.payload.nonce,
            accepted: true,
            message: Some("accepted".to_string()),
            failure: None,
            grant: Some(grant),
            media: Some(LanMediaBootstrap {
                transport_kind: "quic".to_string(),
                quic: Some(LanQuicBootstrap {
                    listen_addr: "127.0.0.1:9".to_string(),
                    server_name: "security-negative.invalid".to_string(),
                    certificate_fingerprint_sha256: certificate_fingerprint_sha256(
                        &substituted_cert,
                    ),
                    cert_der: substituted_cert,
                }),
            }),
            media_profile: Some(negotiation),
            timestamp_ms: now_ms(),
            expires_at_ms: now_ms().saturating_add(5_000),
            nonce: [0x53; 16],
        };
        let response = SignedLanSessionBootstrap::sign(&responder_identity, payload)
            .expect("target signs substituted certificate bootstrap");
        let bytes = serde_json::to_vec(&LanDiscoveryPacket::SignedRemoteSessionBootstrap(response))
            .unwrap();
        responder_socket
            .send_to(&bytes, controller_addr)
            .await
            .unwrap();
    });

    let session_id = SessionId("security-negative-certificate-substitution".to_string());
    let audit_baseline = audit_sequence_baseline(&app_state);
    let side_effect_baseline = capture_side_effect_totals(&app_state).await;
    let response = IpcServer::new(app_state.clone())
        .handle_request(IpcRequest::StartLanRemoteSession {
            session_id: session_id.clone(),
            target_device_id: DeviceId("security-negative-target".to_string()),
            transport_kind: "quic".to_string(),
            // Keep this security-negative test independent of host media
            // capability preflight; Linux CI intentionally has no hardware
            // encoder/decoder, but the certificate binding check is portable.
            requested_profile: None,
        })
        .await;
    match timeout(Duration::from_secs(5), &mut responder).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("certificate substitution responder failed: {error}"),
        Err(_) => {
            responder.abort();
            let _ = responder.await;
            panic!("certificate substitution responder did not receive the request");
        }
    }
    assert!(matches!(
        response,
        IpcResponse::RemoteAccessError { ref failure, .. }
            if failure.code == RemoteReasonCode::CertificateBindingMismatch
    ));
    let side_effects =
        capture_side_effects_since(&app_state, &session_id, side_effect_baseline).await;
    emit_authoritative_artifact(
        &app_state,
        &session_id,
        audit_baseline,
        side_effect_baseline,
        side_effects,
        NegativeCase {
            id: "certificate_substitution",
            scenario: "security.negative.certificate_substitution",
            identity_state: "trusted",
            authorization_outcome: "denied",
            reason: "certificate_binding_mismatch",
            audit_action: "session.start_lan",
        },
    )
    .await;
}

#[test]
fn cumulative_side_effect_totals_report_attempt_delta() {
    let baseline = NegativeSideEffectTotals {
        sender_tasks_started: 5,
        receiver_tasks_started: 7,
        media_tasks_registered: 11,
        media_packets_sent: 13,
        media_frames_presented: 17,
        control_events_injected: 19,
    };
    let after = NegativeSideEffectTotals {
        sender_tasks_started: 6,
        receiver_tasks_started: 9,
        media_tasks_registered: 14,
        media_packets_sent: 18,
        media_frames_presented: 24,
        control_events_injected: 30,
    };

    assert_eq!(
        after.delta_since(baseline),
        NegativeSideEffectTotals {
            sender_tasks_started: 1,
            receiver_tasks_started: 2,
            media_tasks_registered: 3,
            media_packets_sent: 5,
            media_frames_presented: 7,
            control_events_injected: 11,
        }
    );
}
