use mrd_identity::DeviceIdentity;
use mrd_proto::{BackendRole, DeviceId, SessionId};
use mrd_signal_proto::{
    relay_candidate_fingerprint, webrtc_candidate_fingerprint_v3, AuthClaims,
    AuthenticatedRegister, AuthenticatedSignalMessage, PresenceHeartbeat, PresenceHeartbeatPayload,
    ProtocolReasonCode, RegisterPayload, RelayMigrationAnswer, RelayMigrationAnswerPayload,
    RelayMigrationCandidate, RelayMigrationCandidatePayload, RelayMigrationOffer,
    RelayMigrationOfferPayload, SessionClose, SessionClosePayload, SessionGrantV3,
    SessionGrantV3Payload, SessionIntentPayload, SessionIntentV3, SessionIntentV3Payload,
    SignalEnvelope, SignedSignal, WanAccessModeV3, WanPermissionScopeV3, WanRoutePolicyV3,
    WanSessionRequestV3, WebRtcAnswerV3, WebRtcAnswerV3Payload, WebRtcCandidateV3,
    WebRtcCandidateV3Payload, WebRtcDescriptionRoleV3, WebRtcOfferV3, WebRtcOfferV3Payload,
    SIGNAL_PROTOCOL_V2,
};
use realtime_server::{
    BackendTokenError, BackendTokenVerifier, ConnectionId, CoreConfig, DeliveryTarget,
    RealtimeCore, VerifiedBackendToken,
};
use ring::rand::SystemRandom;
use std::{collections::BTreeSet, collections::HashMap, sync::Arc};

const NOW: u64 = 10_000;

#[derive(Default)]
struct FakeTokens {
    tokens: HashMap<String, VerifiedBackendToken>,
}

impl BackendTokenVerifier for FakeTokens {
    fn verify(&self, token: &str, _now_ms: u64) -> Result<VerifiedBackendToken, BackendTokenError> {
        self.tokens
            .get(token)
            .cloned()
            .ok_or(BackendTokenError::Invalid)
    }
}

struct TestDevice {
    device_id: DeviceId,
    identity: DeviceIdentity,
    token: String,
    connection_id: ConnectionId,
    counter: u64,
}

impl TestDevice {
    fn new(name: &str, slot: u8) -> Self {
        Self {
            device_id: DeviceId(name.into()),
            identity: DeviceIdentity::generate(&SystemRandom::new()).unwrap(),
            token: format!("token-{name}"),
            connection_id: ConnectionId::from_bytes([slot; 16]).unwrap(),
            counter: 1,
        }
    }

    fn claims(&mut self, intended_peer: &DeviceId) -> AuthClaims {
        let counter = self.counter;
        self.counter += 1;
        AuthClaims {
            issuer_device_id: self.device_id.clone(),
            issuer_key_id: self.identity.key_id().into(),
            intended_peer_device_id: intended_peer.clone(),
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            counter,
            nonce: [counter as u8; 16],
        }
    }
}

fn config() -> CoreConfig {
    CoreConfig {
        server_device_id: DeviceId("signal-server".into()),
        challenge_ttl_ms: 10_000,
        presence_ttl_ms: 30_000,
        route_ttl_ms: 60_000,
        max_connections: 32,
        max_messages_per_window: 64,
        rate_window_ms: 1_000,
    }
}

fn token(device: &TestDevice, role: BackendRole, expires_at_ms: u64) -> VerifiedBackendToken {
    VerifiedBackendToken {
        device_id: device.device_id.clone(),
        device_key_id: device.identity.key_id().into(),
        role,
        expires_at_ms,
    }
}

fn core_with(devices: &[(&TestDevice, BackendRole)]) -> RealtimeCore {
    let mut tokens = FakeTokens::default();
    for (device, role) in devices {
        tokens.tokens.insert(
            device.token.clone(),
            token(device, role.clone(), NOW + 120_000),
        );
    }
    RealtimeCore::new(config(), Arc::new(tokens)).unwrap()
}

fn register(core: &mut RealtimeCore, device: &mut TestDevice, role: BackendRole) {
    let challenge = core.open_connection(device.connection_id, NOW).unwrap();
    let server = core.config().server_device_id.clone();
    let claims = device.claims(&server);
    let register = AuthenticatedRegister::sign(
        &device.identity,
        RegisterPayload {
            claims,
            role,
            device_name: device.device_id.0.clone(),
            backend_device_token: device.token.clone(),
            challenge_id: challenge.challenge_id,
            challenge_nonce: challenge.challenge_nonce,
        },
    )
    .unwrap();
    let deliveries = core
        .handle(
            device.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::Register(register)),
            NOW + 1,
        )
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(
        deliveries[0].target,
        DeliveryTarget::Connection(device.connection_id)
    );
    assert!(matches!(
        deliveries[0].envelope.message,
        AuthenticatedSignalMessage::Registered(_)
    ));
}

fn wan_request(
    controller: &TestDevice,
    target: &TestDevice,
    session_id: &str,
    idempotency_key: [u8; 16],
) -> WanSessionRequestV3 {
    WanSessionRequestV3 {
        session_id: SessionId(session_id.into()),
        idempotency_key,
        controller_device_id: controller.device_id.clone(),
        target_device_id: target.device_id.clone(),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![
            WanPermissionScopeV3::InputKeyboard,
            WanPermissionScopeV3::ScreenView,
        ],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    }
}

fn signed_intent_v3(
    controller: &mut TestDevice,
    target: &TestDevice,
    session_id: &str,
    idempotency_key: [u8; 16],
) -> SessionIntentV3 {
    let request = wan_request(controller, target, session_id, idempotency_key);
    signed_intent_request_v3(controller, target, request)
}

fn signed_intent_request_v3(
    controller: &mut TestDevice,
    target: &TestDevice,
    request: WanSessionRequestV3,
) -> SessionIntentV3 {
    let request_commitment = request.commitment().unwrap();
    let claims = controller.claims(&target.device_id);
    SessionIntentV3::sign(
        &controller.identity,
        SessionIntentV3Payload {
            claims,
            request,
            request_commitment,
        },
    )
    .unwrap()
}

fn signed_grant_v3(
    target: &mut TestDevice,
    controller: &TestDevice,
    intent: &SessionIntentV3,
) -> SessionGrantV3 {
    let request = &intent.payload.request;
    let claims = target.claims(&controller.device_id);
    SessionGrantV3::sign(
        &target.identity,
        SessionGrantV3Payload {
            claims,
            session_id: request.session_id.clone(),
            controller_device_id: controller.device_id.clone(),
            target_device_id: target.device_id.clone(),
            intent_commitment: intent.commitment().unwrap(),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: None,
            backend_policy_revision: 7,
            policy_expires_at_ms: NOW + 60_000,
            relay_generation: 0,
            relay_directory_id: "directory-1".into(),
            primary_relay_node_id: "relay-1".into(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .unwrap()
}

fn signed_offer_v3(
    controller: &mut TestDevice,
    target_device_id: DeviceId,
    session_id: &str,
    grant_commitment: String,
    candidate_fingerprints: Vec<String>,
) -> WebRtcOfferV3 {
    let claims = controller.claims(&target_device_id);
    WebRtcOfferV3::sign(
        &controller.identity,
        WebRtcOfferV3Payload {
            claims,
            session_id: SessionId(session_id.into()),
            controller_device_id: controller.device_id.clone(),
            target_device_id,
            grant_commitment,
            sdp: "opaque-controller-description".into(),
            candidate_fingerprints,
        },
    )
    .unwrap()
}

fn signed_answer_v3(
    target: &mut TestDevice,
    controller: &TestDevice,
    session_id: &str,
    grant_commitment: String,
    candidate_fingerprints: Vec<String>,
) -> WebRtcAnswerV3 {
    let claims = target.claims(&controller.device_id);
    WebRtcAnswerV3::sign(
        &target.identity,
        WebRtcAnswerV3Payload {
            claims,
            session_id: SessionId(session_id.into()),
            controller_device_id: controller.device_id.clone(),
            target_device_id: target.device_id.clone(),
            grant_commitment,
            sdp: "opaque-target-description".into(),
            candidate_fingerprints,
        },
    )
    .unwrap()
}

fn signed_candidate_v3(
    controller_device_id: DeviceId,
    target_device_id: DeviceId,
    sender: &mut TestDevice,
    grant_commitment: String,
    role: WebRtcDescriptionRoleV3,
) -> WebRtcCandidateV3 {
    let intended_peer = match role {
        WebRtcDescriptionRoleV3::Offer => &target_device_id,
        WebRtcDescriptionRoleV3::Answer => &controller_device_id,
    };
    let session_id = SessionId("session-1".into());
    let candidate = "opaque-relay-candidate".to_string();
    let sdp_mid = Some("0".to_string());
    let sdp_mline_index = Some(0);
    let username_fragment = Some("opaque-fragment".to_string());
    let candidate_fingerprint = webrtc_candidate_fingerprint_v3(
        &session_id,
        &grant_commitment,
        role,
        &candidate,
        sdp_mid.as_deref(),
        sdp_mline_index,
        username_fragment.as_deref(),
    );
    let claims = sender.claims(intended_peer);
    WebRtcCandidateV3::sign(
        &sender.identity,
        WebRtcCandidateV3Payload {
            claims,
            session_id,
            controller_device_id,
            target_device_id,
            grant_commitment,
            description_role: role,
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment,
            candidate_fingerprint,
        },
    )
    .unwrap()
}

fn assert_routes_to(
    core: &mut RealtimeCore,
    sender: ConnectionId,
    recipient: ConnectionId,
    message: AuthenticatedSignalMessage,
    now_ms: u64,
) {
    let envelope = SignalEnvelope::new(message);
    let deliveries = core.handle(sender, envelope.clone(), now_ms).unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].target, DeliveryTarget::Connection(recipient));
    assert_eq!(deliveries[0].envelope, envelope);
}

#[test]
fn register_requires_challenge_key_proof_and_unexpired_backend_token() {
    let mut controller = TestDevice::new("controller-1", 1);
    let mut core = core_with(&[(&controller, BackendRole::Controller)]);
    register(&mut core, &mut controller, BackendRole::Controller);
    assert!(core.is_present(&controller.device_id));

    let mut impostor = TestDevice::new("impostor", 2);
    let mut tokens = FakeTokens::default();
    tokens.tokens.insert(
        impostor.token.clone(),
        VerifiedBackendToken {
            device_id: DeviceId("claimed-victim".into()),
            device_key_id: "victim-key-id".into(),
            role: BackendRole::Controller,
            expires_at_ms: NOW + 10_000,
        },
    );
    let mut guarded = RealtimeCore::new(config(), Arc::new(tokens)).unwrap();
    let challenge = guarded
        .open_connection(impostor.connection_id, NOW)
        .unwrap();
    let mut claims = impostor.claims(&guarded.config().server_device_id.clone());
    claims.issuer_device_id = DeviceId("claimed-victim".into());
    let forged = AuthenticatedRegister::sign(
        &impostor.identity,
        RegisterPayload {
            claims,
            role: BackendRole::Controller,
            device_name: "victim".into(),
            backend_device_token: impostor.token.clone(),
            challenge_id: challenge.challenge_id,
            challenge_nonce: challenge.challenge_nonce,
        },
    )
    .unwrap();
    assert_eq!(
        guarded
            .handle(
                impostor.connection_id,
                SignalEnvelope::new(AuthenticatedSignalMessage::Register(forged)),
                NOW + 1,
            )
            .unwrap_err()
            .reason_code(),
        ProtocolReasonCode::AuthenticationFailed
    );

    let mut expired = TestDevice::new("expired", 3);
    let mut tokens = FakeTokens::default();
    tokens.tokens.insert(
        expired.token.clone(),
        token(&expired, BackendRole::Controller, NOW),
    );
    let mut guarded = RealtimeCore::new(config(), Arc::new(tokens)).unwrap();
    let challenge = guarded.open_connection(expired.connection_id, NOW).unwrap();
    let expired_claims = expired.claims(&guarded.config().server_device_id.clone());
    let register = AuthenticatedRegister::sign(
        &expired.identity,
        RegisterPayload {
            claims: expired_claims,
            role: BackendRole::Controller,
            device_name: "expired".into(),
            backend_device_token: expired.token.clone(),
            challenge_id: challenge.challenge_id,
            challenge_nonce: challenge.challenge_nonce,
        },
    )
    .unwrap();
    assert_eq!(
        guarded
            .handle(
                expired.connection_id,
                SignalEnvelope::new(AuthenticatedSignalMessage::Register(register)),
                NOW + 1,
            )
            .unwrap_err()
            .reason_code(),
        ProtocolReasonCode::Expired
    );
}

#[test]
fn v3_initial_all_five_messages_route_unchanged_only_to_the_signed_peer() {
    let mut controller = TestDevice::new("controller-1", 1);
    let mut target = TestDevice::new("target-1", 2);
    let mut core = core_with(&[
        (&controller, BackendRole::Controller),
        (&target, BackendRole::Agent),
    ]);
    register(&mut core, &mut controller, BackendRole::Controller);
    register(&mut core, &mut target, BackendRole::Agent);

    let intent = signed_intent_v3(&mut controller, &target, "session-1", [44; 16]);
    assert_routes_to(
        &mut core,
        controller.connection_id,
        target.connection_id,
        AuthenticatedSignalMessage::SessionIntentV3(intent.clone()),
        NOW + 2,
    );
    let duplicate = signed_intent_v3(&mut controller, &target, "session-1", [44; 16]);
    assert_routes_to(
        &mut core,
        controller.connection_id,
        target.connection_id,
        AuthenticatedSignalMessage::SessionIntentV3(duplicate),
        NOW + 2,
    );
    assert_eq!(core.route_count(), 1);
    let mut conflicting_request = wan_request(&controller, &target, "session-1", [44; 16]);
    conflicting_request.requested_scopes = vec![WanPermissionScopeV3::ScreenView];
    let conflicting = signed_intent_request_v3(&mut controller, &target, conflicting_request);
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntentV3(conflicting)),
            NOW + 2,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::Conflict
    );
    let grant = signed_grant_v3(&mut target, &controller, &intent);
    assert_routes_to(
        &mut core,
        target.connection_id,
        controller.connection_id,
        AuthenticatedSignalMessage::SessionGrantV3(grant.clone()),
        NOW + 3,
    );
    let grant_commitment = grant.commitment().unwrap();
    let offer_fingerprint = "a".repeat(64);
    let offer = signed_offer_v3(
        &mut controller,
        target.device_id.clone(),
        "session-1",
        grant_commitment.clone(),
        vec![offer_fingerprint],
    );
    assert_routes_to(
        &mut core,
        controller.connection_id,
        target.connection_id,
        AuthenticatedSignalMessage::WebrtcOfferV3(offer),
        NOW + 4,
    );
    let answer = signed_answer_v3(
        &mut target,
        &controller,
        "session-1",
        grant_commitment.clone(),
        vec!["b".repeat(64)],
    );
    assert_routes_to(
        &mut core,
        target.connection_id,
        controller.connection_id,
        AuthenticatedSignalMessage::WebrtcAnswerV3(answer),
        NOW + 5,
    );
    let candidate = signed_candidate_v3(
        controller.device_id.clone(),
        target.device_id.clone(),
        &mut controller,
        grant_commitment,
        WebRtcDescriptionRoleV3::Offer,
    );
    assert_routes_to(
        &mut core,
        controller.connection_id,
        target.connection_id,
        AuthenticatedSignalMessage::WebrtcCandidateV3(candidate),
        NOW + 6,
    );
    assert_eq!(core.route_count(), 1);
}

#[test]
fn v3_initial_rejects_v2_cross_version_wrong_route_oversize_and_invalid_signature() {
    let mut controller = TestDevice::new("controller-1", 1);
    let mut target = TestDevice::new("target-1", 2);
    let mut core = core_with(&[
        (&controller, BackendRole::Controller),
        (&target, BackendRole::Agent),
    ]);
    register(&mut core, &mut controller, BackendRole::Controller);
    register(&mut core, &mut target, BackendRole::Agent);
    let intent = signed_intent_v3(&mut controller, &target, "session-1", [45; 16]);
    assert_routes_to(
        &mut core,
        controller.connection_id,
        target.connection_id,
        AuthenticatedSignalMessage::SessionIntentV3(intent.clone()),
        NOW + 2,
    );
    let grant = signed_grant_v3(&mut target, &controller, &intent);
    assert_routes_to(
        &mut core,
        target.connection_id,
        controller.connection_id,
        AuthenticatedSignalMessage::SessionGrantV3(grant.clone()),
        NOW + 3,
    );
    let grant_commitment = grant.commitment().unwrap();

    let legacy = SignedSignal {
        payload: SessionIntentPayload {
            claims: controller.claims(&target.device_id),
            session_id: SessionId("legacy-session".into()),
            idempotency_key: [46; 16],
            target_device_id: target.device_id.clone(),
            requested_transport: "webrtc".into(),
        },
        signer_public_key: Vec::new(),
        signature: Vec::new(),
    };
    let legacy_error = core
        .handle(
            controller.connection_id,
            SignalEnvelope {
                version: SIGNAL_PROTOCOL_V2,
                message: AuthenticatedSignalMessage::SessionIntent(legacy),
            },
            NOW + 4,
        )
        .unwrap_err();
    assert_eq!(
        legacy_error.reason_code(),
        ProtocolReasonCode::UnsupportedVersion
    );

    let cross_version = signed_offer_v3(
        &mut controller,
        target.device_id.clone(),
        "session-1",
        grant_commitment.clone(),
        vec!["a".repeat(64)],
    );
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope {
                version: SIGNAL_PROTOCOL_V2,
                message: AuthenticatedSignalMessage::WebrtcOfferV3(cross_version),
            },
            NOW + 5,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::UnsupportedVersion
    );

    let wrong_room = signed_offer_v3(
        &mut controller,
        target.device_id.clone(),
        "other-session",
        grant_commitment.clone(),
        vec!["a".repeat(64)],
    );
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(wrong_room)),
            NOW + 6,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::UnknownSession
    );

    let wrong_peer = signed_offer_v3(
        &mut controller,
        DeviceId("other-target".into()),
        "session-1",
        grant_commitment.clone(),
        vec!["a".repeat(64)],
    );
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(wrong_peer)),
            NOW + 7,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::UnauthorizedRoute
    );

    let mut oversized = signed_offer_v3(
        &mut controller,
        target.device_id.clone(),
        "session-1",
        grant_commitment.clone(),
        vec!["a".repeat(64)],
    );
    oversized.payload.candidate_fingerprints =
        (0..257).map(|index| format!("{index:064x}")).collect();
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(oversized)),
            NOW + 8,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::Malformed
    );

    let mut invalid_signature = signed_offer_v3(
        &mut controller,
        target.device_id.clone(),
        "session-1",
        grant_commitment,
        vec!["a".repeat(64)],
    );
    invalid_signature.signature[0] ^= 1;
    let signature_error = core
        .handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(invalid_signature)),
            NOW + 9,
        )
        .unwrap_err();
    assert_eq!(
        signature_error.reason_code(),
        ProtocolReasonCode::AuthenticationFailed
    );
    let error_text = format!("{legacy_error} {signature_error}");
    assert!(!error_text.contains("opaque-controller-description"));
}

fn authorize_route(
    core: &mut RealtimeCore,
    controller: &mut TestDevice,
    target: &mut TestDevice,
) -> SessionIntentV3 {
    let intent = signed_intent_v3(controller, target, "session-1", [45; 16]);
    core.handle(
        controller.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntentV3(intent.clone())),
        NOW + 2,
    )
    .unwrap();
    let grant = signed_grant_v3(target, controller, &intent);
    core.handle(
        target.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::SessionGrantV3(grant)),
        NOW + 3,
    )
    .unwrap();
    intent
}

#[test]
fn relay_migration_enforces_generation_binding_grant_participants_and_close() {
    let mut controller = TestDevice::new("controller-1", 1);
    let mut target = TestDevice::new("target-1", 2);
    let mut random = TestDevice::new("random-1", 3);
    let mut core = core_with(&[
        (&controller, BackendRole::Controller),
        (&target, BackendRole::Agent),
        (&random, BackendRole::Controller),
    ]);
    register(&mut core, &mut controller, BackendRole::Controller);
    register(&mut core, &mut target, BackendRole::Agent);
    register(&mut core, &mut random, BackendRole::Controller);
    let intent = authorize_route(&mut core, &mut controller, &mut target);

    let session_id = SessionId("session-1".into());
    let fingerprint = "a".repeat(64);
    let target_candidate_fingerprint = relay_candidate_fingerprint(
        &session_id,
        1,
        "opaque-relay-candidate",
        Some("0"),
        Some(0),
        Some("restart-ufrag"),
        &"1".repeat(64),
    );
    let offer = |sender: &mut TestDevice,
                 intended_peer: &DeviceId,
                 generation: u64,
                 directory_id: &str,
                 node_id: &str,
                 fingerprint: &str| {
        let claims = sender.claims(intended_peer);
        RelayMigrationOffer::sign(
            &sender.identity,
            RelayMigrationOfferPayload {
                claims,
                session_id: session_id.clone(),
                migration_generation: generation,
                directory_id: directory_id.into(),
                node_id: node_id.into(),
                sdp: "opaque-migration-offer".into(),
                restart_route_token: "1".repeat(64),
                candidate_fingerprints: BTreeSet::from([fingerprint.to_owned()]),
            },
        )
        .unwrap()
    };

    let first = offer(
        &mut controller,
        &target.device_id,
        1,
        "directory-1",
        "relay-1",
        &fingerprint,
    );
    let deliveries = core
        .handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(first)),
            NOW + 4,
        )
        .unwrap();
    assert_eq!(
        deliveries[0].target,
        DeliveryTarget::Connection(target.connection_id)
    );

    let answer_claims = target.claims(&controller.device_id);
    let answer = RelayMigrationAnswer::sign(
        &target.identity,
        RelayMigrationAnswerPayload {
            claims: answer_claims,
            session_id: session_id.clone(),
            migration_generation: 1,
            directory_id: "directory-1".into(),
            node_id: "relay-1".into(),
            sdp: "opaque-migration-answer".into(),
            restart_route_token: "1".repeat(64),
            candidate_fingerprints: BTreeSet::from([target_candidate_fingerprint.clone()]),
        },
    )
    .unwrap();
    core.handle(
        target.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationAnswer(answer)),
        NOW + 5,
    )
    .unwrap();

    let candidate_claims = target.claims(&controller.device_id);
    let candidate = RelayMigrationCandidate::sign(
        &target.identity,
        RelayMigrationCandidatePayload {
            claims: candidate_claims,
            session_id: session_id.clone(),
            migration_generation: 1,
            directory_id: "directory-1".into(),
            node_id: "relay-1".into(),
            candidate: "opaque-relay-candidate".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("restart-ufrag".into()),
            restart_route_token: "1".repeat(64),
            candidate_fingerprint: target_candidate_fingerprint,
        },
    )
    .unwrap();
    core.handle(
        target.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationCandidate(
            candidate,
        )),
        NOW + 6,
    )
    .unwrap();

    for generation in [1, 3] {
        let invalid = offer(
            &mut controller,
            &target.device_id,
            generation,
            "directory-2",
            "relay-2",
            &fingerprint,
        );
        assert_eq!(
            core.handle(
                controller.connection_id,
                SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(invalid)),
                NOW + 7,
            )
            .unwrap_err()
            .reason_code(),
            ProtocolReasonCode::Conflict
        );
    }

    let newly_committed = offer(
        &mut controller,
        &target.device_id,
        2,
        "directory-2",
        "relay-2",
        &"b".repeat(64),
    );
    core.handle(
        controller.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(
            newly_committed,
        )),
        NOW + 8,
    )
    .unwrap();

    let mismatched_claims = target.claims(&controller.device_id);
    let mismatched = RelayMigrationAnswer::sign(
        &target.identity,
        RelayMigrationAnswerPayload {
            claims: mismatched_claims,
            session_id: session_id.clone(),
            migration_generation: 2,
            directory_id: "different-directory".into(),
            node_id: "relay-2".into(),
            sdp: "opaque-migration-answer".into(),
            restart_route_token: "1".repeat(64),
            candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
        },
    )
    .unwrap();
    assert_eq!(
        core.handle(
            target.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationAnswer(mismatched)),
            NOW + 10,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::Conflict
    );

    let refreshed_grant = signed_grant_v3(&mut target, &controller, &intent);
    assert_eq!(
        core.handle(
            target.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::SessionGrantV3(refreshed_grant)),
            NOW + 11,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::Conflict
    );

    let stale_answer_claims = target.claims(&controller.device_id);
    let stale_answer = RelayMigrationAnswer::sign(
        &target.identity,
        RelayMigrationAnswerPayload {
            claims: stale_answer_claims,
            session_id: session_id.clone(),
            migration_generation: 2,
            directory_id: "directory-2".into(),
            node_id: "relay-2".into(),
            sdp: "opaque-migration-answer".into(),
            restart_route_token: "1".repeat(64),
            candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
        },
    )
    .unwrap();
    let deliveries = core
        .handle(
            target.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationAnswer(
                stale_answer,
            )),
            NOW + 12,
        )
        .unwrap();
    assert_eq!(
        deliveries[0].target,
        DeliveryTarget::Connection(controller.connection_id)
    );

    let injected = offer(
        &mut random,
        &target.device_id,
        2,
        "directory-3",
        "relay-3",
        &fingerprint,
    );
    assert_eq!(
        core.handle(
            random.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(injected)),
            NOW + 14,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::UnauthorizedRoute
    );

    let close_claims = controller.claims(&target.device_id);
    let close = SessionClose::sign(
        &controller.identity,
        SessionClosePayload {
            claims: close_claims,
            session_id: session_id.clone(),
            reason: ProtocolReasonCode::Conflict,
        },
    )
    .unwrap();
    core.handle(
        controller.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::SessionClose(close)),
        NOW + 15,
    )
    .unwrap();
    let post_close = offer(
        &mut controller,
        &target.device_id,
        2,
        "directory-3",
        "relay-3",
        &fingerprint,
    );
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(post_close)),
            NOW + 16,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::UnknownSession
    );
}

#[test]
fn replay_rate_limit_and_disconnect_cleanup_fail_closed() {
    let mut controller = TestDevice::new("controller-1", 1);
    let mut target = TestDevice::new("target-1", 2);
    let mut core = core_with(&[
        (&controller, BackendRole::Controller),
        (&target, BackendRole::Agent),
    ]);
    register(&mut core, &mut controller, BackendRole::Controller);
    register(&mut core, &mut target, BackendRole::Agent);
    let _intent = authorize_route(&mut core, &mut controller, &mut target);

    let heartbeat_claims = controller.claims(&core.config().server_device_id.clone());
    let heartbeat = PresenceHeartbeat::sign(
        &controller.identity,
        PresenceHeartbeatPayload {
            claims: heartbeat_claims,
            connection_id: *controller.connection_id.as_bytes(),
            observed_at_ms: NOW + 4,
        },
    )
    .unwrap();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::PresenceHeartbeat(heartbeat));
    core.handle(controller.connection_id, envelope.clone(), NOW + 4)
        .unwrap();
    assert_eq!(
        core.handle(controller.connection_id, envelope, NOW + 4)
            .unwrap_err()
            .reason_code(),
        ProtocolReasonCode::ReplayRejected
    );

    core.disconnect(target.connection_id);
    assert!(!core.is_present(&target.device_id));
    assert_eq!(core.route_count(), 0);
    core.prune(NOW + 31_100);
    assert!(!core.is_present(&controller.device_id));

    let mut limited_config = config();
    limited_config.max_messages_per_window = 1;
    let mut limited = RealtimeCore::new(limited_config, Arc::new(FakeTokens::default())).unwrap();
    let connection = ConnectionId::from_bytes([9; 16]).unwrap();
    limited.open_connection(connection, NOW).unwrap();
    let invalid = SignalEnvelope::new(AuthenticatedSignalMessage::ProtocolError(
        mrd_signal_proto::SignalErrorMessage {
            reason: ProtocolReasonCode::Malformed,
            correlation_id: None,
            detail: "invalid".into(),
        },
    ));
    let _ = limited.handle(connection, invalid.clone(), NOW);
    assert_eq!(
        limited
            .handle(connection, invalid, NOW)
            .unwrap_err()
            .reason_code(),
        ProtocolReasonCode::RateLimited
    );
}
