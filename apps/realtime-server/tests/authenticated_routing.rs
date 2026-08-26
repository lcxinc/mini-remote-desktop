use mrd_identity::DeviceIdentity;
use mrd_proto::{BackendRole, DeviceId, SessionId};
use mrd_signal_proto::{
    AuthClaims, AuthenticatedRegister, AuthenticatedSignalMessage, PresenceHeartbeat,
    PresenceHeartbeatPayload, ProtocolReasonCode, RegisterPayload, RelayMigrationAnswer,
    RelayMigrationAnswerPayload, RelayMigrationCandidate, RelayMigrationCandidatePayload,
    RelayMigrationOffer, RelayMigrationOfferPayload, SessionClose, SessionClosePayload,
    SessionGrant, SessionGrantPayload, SessionIntent, SessionIntentPayload, SignalEnvelope,
    WebRtcCandidate, WebRtcCandidatePayload, WebRtcOffer, WebRtcOfferPayload,
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
fn session_intent_routes_only_to_authenticated_target_and_is_idempotent() {
    let mut controller = TestDevice::new("controller-1", 1);
    let mut target = TestDevice::new("target-1", 2);
    let mut core = core_with(&[
        (&controller, BackendRole::Controller),
        (&target, BackendRole::Agent),
    ]);
    register(&mut core, &mut controller, BackendRole::Controller);
    register(&mut core, &mut target, BackendRole::Agent);

    let idempotency_key = [44; 16];
    for _ in 0..2 {
        let intent_claims = controller.claims(&target.device_id.clone());
        let intent = SessionIntent::sign(
            &controller.identity,
            SessionIntentPayload {
                claims: intent_claims,
                session_id: SessionId("session-1".into()),
                idempotency_key,
                target_device_id: target.device_id.clone(),
                requested_transport: "webrtc".into(),
            },
        )
        .unwrap();
        let deliveries = core
            .handle(
                controller.connection_id,
                SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntent(intent)),
                NOW + 2,
            )
            .unwrap();
        assert_eq!(
            deliveries[0].target,
            DeliveryTarget::Connection(target.connection_id)
        );
    }
    assert_eq!(core.route_count(), 1);
}

#[test]
fn random_peer_cannot_inject_offer_candidate_or_close() {
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
    authorize_route(&mut core, &mut controller, &mut target);

    let fingerprint = "a".repeat(64);
    let offer_claims = random.claims(&target.device_id.clone());
    let offer = WebRtcOffer::sign(
        &random.identity,
        WebRtcOfferPayload {
            claims: offer_claims,
            session_id: SessionId("session-1".into()),
            sdp: "v=0".into(),
            candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
        },
    )
    .unwrap();
    let candidate_claims = random.claims(&target.device_id.clone());
    let candidate = WebRtcCandidate::sign(
        &random.identity,
        WebRtcCandidatePayload {
            claims: candidate_claims,
            session_id: SessionId("session-1".into()),
            candidate: "candidate:1".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            candidate_fingerprint: fingerprint,
        },
    )
    .unwrap();
    let close_claims = random.claims(&target.device_id.clone());
    let close = SessionClose::sign(
        &random.identity,
        SessionClosePayload {
            claims: close_claims,
            session_id: SessionId("session-1".into()),
            reason: ProtocolReasonCode::Conflict,
        },
    )
    .unwrap();

    for message in [
        AuthenticatedSignalMessage::WebrtcOffer(offer),
        AuthenticatedSignalMessage::WebrtcCandidate(candidate),
        AuthenticatedSignalMessage::SessionClose(close),
    ] {
        assert_eq!(
            core.handle(random.connection_id, SignalEnvelope::new(message), NOW + 4)
                .unwrap_err()
                .reason_code(),
            ProtocolReasonCode::UnauthorizedRoute
        );
    }
}

fn authorize_route(core: &mut RealtimeCore, controller: &mut TestDevice, target: &mut TestDevice) {
    let fingerprint = "a".repeat(64);
    let intent_claims = controller.claims(&target.device_id.clone());
    let intent = SessionIntent::sign(
        &controller.identity,
        SessionIntentPayload {
            claims: intent_claims,
            session_id: SessionId("session-1".into()),
            idempotency_key: [45; 16],
            target_device_id: target.device_id.clone(),
            requested_transport: "webrtc".into(),
        },
    )
    .unwrap();
    core.handle(
        controller.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntent(intent)),
        NOW + 2,
    )
    .unwrap();
    let grant_claims = target.claims(&controller.device_id.clone());
    let grant = SessionGrant::sign(
        &target.identity,
        SessionGrantPayload {
            claims: grant_claims,
            session_id: SessionId("session-1".into()),
            controller_device_id: controller.device_id.clone(),
            accepted_transport: "webrtc".into(),
            accepted_candidate_fingerprints: BTreeSet::from([fingerprint]),
        },
    )
    .unwrap();
    core.handle(
        target.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::SessionGrant(grant)),
        NOW + 3,
    )
    .unwrap();
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
    authorize_route(&mut core, &mut controller, &mut target);

    let session_id = SessionId("session-1".into());
    let fingerprint = "a".repeat(64);
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
                sdp: "v=0".into(),
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
            sdp: "v=0".into(),
            candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
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
            candidate: "candidate:relay".into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            candidate_fingerprint: fingerprint.clone(),
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

    let ungranted = offer(
        &mut controller,
        &target.device_id,
        2,
        "directory-2",
        "relay-2",
        &"b".repeat(64),
    );
    assert_eq!(
        core.handle(
            controller.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(ungranted)),
            NOW + 8,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::UnauthorizedRoute
    );

    let second = offer(
        &mut controller,
        &target.device_id,
        2,
        "directory-2",
        "relay-2",
        &fingerprint,
    );
    core.handle(
        controller.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(second)),
        NOW + 9,
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
            sdp: "v=0".into(),
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

    let refreshed_grant_claims = target.claims(&controller.device_id);
    let refreshed_grant = SessionGrant::sign(
        &target.identity,
        SessionGrantPayload {
            claims: refreshed_grant_claims,
            session_id: session_id.clone(),
            controller_device_id: controller.device_id.clone(),
            accepted_transport: "webrtc".into(),
            accepted_candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
        },
    )
    .unwrap();
    core.handle(
        target.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::SessionGrant(refreshed_grant)),
        NOW + 11,
    )
    .unwrap();

    let stale_answer_claims = target.claims(&controller.device_id);
    let stale_answer = RelayMigrationAnswer::sign(
        &target.identity,
        RelayMigrationAnswerPayload {
            claims: stale_answer_claims,
            session_id: session_id.clone(),
            migration_generation: 2,
            directory_id: "directory-2".into(),
            node_id: "relay-2".into(),
            sdp: "v=0".into(),
            candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
        },
    )
    .unwrap();
    assert_eq!(
        core.handle(
            target.connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationAnswer(
                stale_answer,
            )),
            NOW + 12,
        )
        .unwrap_err()
        .reason_code(),
        ProtocolReasonCode::Conflict
    );
    let reset_offer = offer(
        &mut controller,
        &target.device_id,
        1,
        "directory-reset",
        "relay-reset",
        &fingerprint,
    );
    core.handle(
        controller.connection_id,
        SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(reset_offer)),
        NOW + 13,
    )
    .unwrap();

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
    authorize_route(&mut core, &mut controller, &mut target);

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
