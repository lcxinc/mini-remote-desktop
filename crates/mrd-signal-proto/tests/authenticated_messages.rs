use mrd_identity::DeviceIdentity;
use mrd_proto::{BackendRole, DeviceId, SessionId};
use mrd_signal_proto::{
    relay_candidate_fingerprint, AuthClaims, AuthenticatedRegister, AuthenticatedSignalMessage,
    RegisterPayload, RelayMigrationCandidate, RelayMigrationCandidatePayload, RelayMigrationOffer,
    RelayMigrationOfferPayload, SignalEnvelope, SignalProtocolError, SignalReplayGuard,
    SIGNAL_PROTOCOL_VERSION,
};
use ring::rand::SystemRandom;

fn identity() -> DeviceIdentity {
    DeviceIdentity::generate(&SystemRandom::new()).expect("device identity")
}

fn claims(identity: &DeviceIdentity, nonce: [u8; 16], counter: u64) -> AuthClaims {
    AuthClaims {
        issuer_device_id: DeviceId("controller-1".into()),
        issuer_key_id: identity.key_id().to_owned(),
        intended_peer_device_id: DeviceId("signal-server".into()),
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
        counter,
        nonce,
    }
}

fn signed_register(
    identity: &DeviceIdentity,
    nonce: [u8; 16],
    counter: u64,
) -> AuthenticatedRegister {
    AuthenticatedRegister::sign(
        identity,
        RegisterPayload {
            claims: claims(identity, nonce, counter),
            role: BackendRole::Controller,
            device_name: "Rdesk".into(),
            backend_device_token: "backend-token".into(),
            challenge_id: [7; 16],
            challenge_nonce: [8; 32],
        },
    )
    .expect("sign register")
}

#[test]
fn authenticated_envelope_requires_explicit_supported_version() {
    let identity = identity();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::Register(signed_register(
        &identity, [1; 16], 1,
    )));
    let encoded = serde_json::to_value(&envelope).unwrap();
    assert_eq!(encoded["version"], SIGNAL_PROTOCOL_VERSION);

    let mut missing = encoded.clone();
    missing.as_object_mut().unwrap().remove("version");
    assert!(serde_json::from_value::<SignalEnvelope>(missing).is_err());

    let mut wrong = encoded;
    wrong["version"] = serde_json::json!(SIGNAL_PROTOCOL_VERSION + 1);
    assert!(serde_json::from_value::<SignalEnvelope>(wrong).is_err());
}

#[test]
fn signed_message_rejects_wrong_peer_expiry_and_signature_tampering() {
    let identity = identity();
    let signed = signed_register(&identity, [2; 16], 1);
    let mut replay = SignalReplayGuard::new(8, 64);

    assert_eq!(
        signed.verify_for(&DeviceId("other-server".into()), 1_500, &mut replay),
        Err(SignalProtocolError::WrongIntendedPeer)
    );
    assert_eq!(
        signed.verify_for(&DeviceId("signal-server".into()), 2_000, &mut replay),
        Err(SignalProtocolError::Expired)
    );

    let mut tampered = signed;
    tampered.payload.device_name = "rewritten-by-server".into();
    assert_eq!(
        tampered.verify_for(&DeviceId("signal-server".into()), 1_500, &mut replay),
        Err(SignalProtocolError::InvalidSignature)
    );
}

#[test]
fn replay_guard_rejects_repeated_nonce_after_valid_signature() {
    let identity = identity();
    let first = signed_register(&identity, [3; 16], 1);
    let repeated = signed_register(&identity, [3; 16], 2);
    let peer = DeviceId("signal-server".into());
    let mut replay = SignalReplayGuard::new(8, 64);

    first.verify_for(&peer, 1_500, &mut replay).unwrap();
    assert_eq!(
        repeated.verify_for(&peer, 1_500, &mut replay),
        Err(SignalProtocolError::RepeatedNonce)
    );
}

#[test]
fn authenticated_message_keeps_session_and_peer_binding_inside_signature() {
    use mrd_signal_proto::{SessionIntent, SessionIntentPayload};

    let identity = identity();
    let mut intent_claims = claims(&identity, [4; 16], 1);
    intent_claims.intended_peer_device_id = DeviceId("target-1".into());
    let intent = SessionIntent::sign(
        &identity,
        SessionIntentPayload {
            claims: intent_claims,
            session_id: SessionId("session-1".into()),
            idempotency_key: [11; 16],
            target_device_id: DeviceId("target-1".into()),
            requested_transport: "webrtc".into(),
        },
    )
    .unwrap();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntent(intent));
    let decoded: SignalEnvelope =
        serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
    assert_eq!(decoded, envelope);
}

#[test]
fn session_grant_authorizes_only_committed_candidate_fingerprints() {
    use std::collections::BTreeSet;

    use mrd_signal_proto::{SessionGrant, SessionGrantPayload, WebRtcCandidatePayload};

    let identity = identity();
    let controller = DeviceId("controller-1".into());
    let mut grant_claims = claims(&identity, [5; 16], 1);
    grant_claims.issuer_device_id = DeviceId("target-1".into());
    grant_claims.intended_peer_device_id = controller.clone();
    let accepted = "a".repeat(64);
    let grant = SessionGrant::sign(
        &identity,
        SessionGrantPayload {
            claims: grant_claims,
            session_id: SessionId("session-1".into()),
            controller_device_id: controller,
            accepted_transport: "webrtc".into(),
            accepted_candidate_fingerprints: BTreeSet::from([accepted.clone()]),
        },
    )
    .unwrap();
    let candidate = WebRtcCandidatePayload {
        claims: claims(&identity, [6; 16], 2),
        session_id: SessionId("session-1".into()),
        candidate: "candidate:1 1 UDP 1 127.0.0.1 5000 typ host".into(),
        sdp_mid: Some("0".into()),
        sdp_mline_index: Some(0),
        candidate_fingerprint: accepted,
    };
    assert!(grant.payload.accepts_candidate(&candidate));

    let mut rewritten = candidate;
    rewritten.candidate_fingerprint = "b".repeat(64);
    assert!(!grant.payload.accepts_candidate(&rewritten));
}

#[test]
fn session_intent_rejects_target_that_disagrees_with_signed_peer_claim() {
    use mrd_signal_proto::{SessionIntent, SessionIntentPayload};

    let identity = identity();
    let error = SessionIntent::sign(
        &identity,
        SessionIntentPayload {
            claims: claims(&identity, [7; 16], 1),
            session_id: SessionId("session-1".into()),
            idempotency_key: [12; 16],
            target_device_id: DeviceId("different-target".into()),
            requested_transport: "webrtc".into(),
        },
    )
    .unwrap_err();
    assert_eq!(error, SignalProtocolError::WrongIntendedPeer);
}

#[test]
fn relay_migration_payload_binds_generation_directory_node_and_fingerprints() {
    use std::collections::BTreeSet;

    let identity = identity();
    let fingerprint = "a".repeat(64);
    let offer = RelayMigrationOffer::sign(
        &identity,
        RelayMigrationOfferPayload {
            claims: claims(&identity, [8; 16], 1),
            session_id: SessionId("session-1".into()),
            migration_generation: 1,
            directory_id: "directory-20260822-0001".into(),
            node_id: "relay-us-east-1a".into(),
            sdp: "v=0".into(),
            restart_route_token: "1".repeat(64),
            candidate_fingerprints: BTreeSet::from([fingerprint.clone()]),
        },
    )
    .unwrap();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(
        offer.clone(),
    ));
    let decoded: SignalEnvelope = serde_json::from_slice(&serde_json::to_vec(&envelope).unwrap())
        .expect("migration envelope roundtrip");
    assert_eq!(decoded, envelope);

    let mut tampered = offer;
    tampered.payload.node_id = "relay-attacker".into();
    assert_eq!(
        tampered.verify_for(
            &DeviceId("signal-server".into()),
            1_500,
            &mut SignalReplayGuard::new(8, 64),
        ),
        Err(SignalProtocolError::InvalidSignature)
    );

    let candidate_line = "candidate:1 1 UDP 1 192.0.2.10 5000 typ relay";
    let candidate_fingerprint = relay_candidate_fingerprint(
        &SessionId("session-1".into()),
        1,
        candidate_line,
        Some("0"),
        Some(0),
        Some("restart-ufrag"),
        &"1".repeat(64),
    );
    let candidate = RelayMigrationCandidate::sign(
        &identity,
        RelayMigrationCandidatePayload {
            claims: claims(&identity, [9; 16], 2),
            session_id: SessionId("session-1".into()),
            migration_generation: 1,
            directory_id: "directory-20260822-0001".into(),
            node_id: "relay-us-east-1a".into(),
            candidate: candidate_line.into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("restart-ufrag".into()),
            restart_route_token: "1".repeat(64),
            candidate_fingerprint,
        },
    )
    .unwrap();
    let mut replay = SignalReplayGuard::new(8, 64);
    candidate
        .verify_for(&DeviceId("signal-server".into()), 1_500, &mut replay)
        .unwrap();
    assert_eq!(
        candidate.verify_for(&DeviceId("signal-server".into()), 1_500, &mut replay),
        Err(SignalProtocolError::RepeatedNonce)
    );
}

#[test]
fn relay_migration_rejects_generation_zero_and_unbound_candidate_material() {
    use std::collections::BTreeSet;

    let identity = identity();
    let base = RelayMigrationOfferPayload {
        claims: claims(&identity, [10; 16], 1),
        session_id: SessionId("session-1".into()),
        migration_generation: 0,
        directory_id: "directory-1".into(),
        node_id: "relay-1".into(),
        sdp: "v=0".into(),
        restart_route_token: "1".repeat(64),
        candidate_fingerprints: BTreeSet::from(["a".repeat(64)]),
    };
    assert_eq!(
        RelayMigrationOffer::sign(&identity, base.clone()),
        Err(SignalProtocolError::Malformed)
    );
    for mut invalid in [
        RelayMigrationOfferPayload {
            migration_generation: 1,
            directory_id: String::new(),
            ..base.clone()
        },
        RelayMigrationOfferPayload {
            migration_generation: 1,
            node_id: String::new(),
            ..base.clone()
        },
        RelayMigrationOfferPayload {
            migration_generation: 1,
            restart_route_token: String::new(),
            ..base.clone()
        },
        RelayMigrationOfferPayload {
            migration_generation: 1,
            candidate_fingerprints: BTreeSet::new(),
            ..base
        },
    ] {
        invalid.claims.counter += 1;
        assert_eq!(
            RelayMigrationOffer::sign(&identity, invalid),
            Err(SignalProtocolError::Malformed)
        );
    }
}
