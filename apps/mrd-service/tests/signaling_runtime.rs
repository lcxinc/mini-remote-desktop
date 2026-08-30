use mrd_application::{
    AuthenticatedSessionSignal, AuthenticatedSessionSignalPort, SessionLifecycleState,
    SessionSnapshot, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_proto::{BackendRole, DeviceId, SessionId};
use mrd_service::{
    signaling::{
        relay_candidate_fingerprint, spawn, AuthenticatedSessionSignalingCommand,
        AuthenticatedSessionSignalingReceiveError, AuthenticatedSessionSignalingSendError,
        InboundDisposition, OutboundAuthenticatedSessionSignal, OutboundRelayMigrationSignal,
        RelaySignalingCommand, ServiceSignalingMapper, SignalingConfig, SignalingConnectionState,
        SignalingRuntimeCore, SignalingRuntimeError, SignalingStatus,
        AUTHENTICATED_SESSION_SIGNAL_QUEUE_CAPACITY,
    },
    AppState,
};
use mrd_signal_proto::{
    webrtc_candidate_fingerprint_v3, AuthClaims, AuthenticatedSignalMessage, ProtocolReasonCode,
    Registered, RegisteredPayload, RelayMigrationOffer, RelayMigrationOfferPayload,
    ServerChallenge, SessionGrant, SessionGrantPayload, SessionGrantV3, SessionGrantV3Payload,
    SessionIntent, SessionIntentPayload, SessionIntentV3, SessionIntentV3Payload, SignalEnvelope,
    WanAccessModeV3, WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
    WebRtcAnswer as LegacyWebRtcAnswer, WebRtcAnswerPayload as LegacyWebRtcAnswerPayload,
    WebRtcAnswerV3, WebRtcAnswerV3Payload, WebRtcCandidate as LegacyWebRtcCandidate,
    WebRtcCandidatePayload as LegacyWebRtcCandidatePayload, WebRtcCandidateV3,
    WebRtcCandidateV3Payload, WebRtcDescriptionRoleV3, WebRtcOffer as LegacyWebRtcOffer,
    WebRtcOfferPayload as LegacyWebRtcOfferPayload, WebRtcOfferV3, WebRtcOfferV3Payload,
};
use ring::rand::SystemRandom;
use std::{
    collections::BTreeSet,
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing_subscriber::fmt::MakeWriter;

const NOW: u64 = 1_000_000;
const TEST_ONLY_SIGNAL_SDP_SENTINEL: &str = "TEST_ONLY_SIGNAL_SDP_SENTINEL";
const TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL: &str = "TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL";
const TEST_ONLY_SIGNAL_UFRAG_SENTINEL: &str = "TEST_ONLY_SIGNAL_UFRAG_SENTINEL";
const TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL: &str = "TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL";
const TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL: &str =
    "turn:TEST_ONLY_USER:TEST_ONLY_PASS@relay.invalid:3478?transport=udp";
const TEST_ONLY_RESTART_ROUTE_TOKEN: &str = "TEST_ONLY_RESTART_ROUTE_TOKEN_SENTINEL";

#[derive(Clone, Default)]
struct TraceBuffer(Arc<Mutex<Vec<u8>>>);

struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for TraceBuffer {
    type Writer = TraceWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        TraceWriter(Arc::clone(&self.0))
    }
}

impl TraceBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }
}

fn identity() -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::generate(&SystemRandom::new()).unwrap())
}

fn claims(
    signer: &DeviceIdentity,
    issuer: &str,
    intended_peer: &str,
    counter: u64,
    nonce: u8,
) -> AuthClaims {
    AuthClaims {
        issuer_device_id: DeviceId(issuer.into()),
        issuer_key_id: signer.key_id().into(),
        intended_peer_device_id: DeviceId(intended_peer.into()),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 30_000,
        counter,
        nonce: [nonce; 16],
    }
}

fn config(server: &DeviceIdentity) -> SignalingConfig {
    config_with_role_at(server, BackendRole::Agent, "ws://127.0.0.1:9532/realtime")
}

fn config_with_role_at(
    server: &DeviceIdentity,
    role: BackendRole,
    endpoint: &str,
) -> SignalingConfig {
    SignalingConfig::new(
        endpoint,
        DeviceId("local-device".into()),
        "Local workstation",
        role,
        "backend-token-secret",
        DeviceId("signal-server".into()),
        Some(server.key_id().into()),
        Duration::from_secs(5),
        Duration::from_millis(250),
        Duration::from_secs(8),
    )
    .unwrap()
}

fn v3_request(session_id: &str, controller: &str, target: &str) -> WanSessionRequestV3 {
    WanSessionRequestV3 {
        session_id: SessionId(session_id.into()),
        idempotency_key: [8; 16],
        controller_device_id: DeviceId(controller.into()),
        target_device_id: DeviceId(target.into()),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![
            WanPermissionScopeV3::InputKeyboard,
            WanPermissionScopeV3::ScreenView,
        ],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    }
}

fn inbound_v3_intent(signer: &DeviceIdentity, session_id: &str) -> SessionIntentV3 {
    inbound_v3_intent_from(signer, session_id, "peer-device", "local-device", 1, 61)
}

fn inbound_v3_intent_from(
    signer: &DeviceIdentity,
    session_id: &str,
    controller_device_id: &str,
    target_device_id: &str,
    counter: u64,
    nonce: u8,
) -> SessionIntentV3 {
    let request = v3_request(session_id, controller_device_id, target_device_id);
    let request_commitment = request.commitment().unwrap();
    SessionIntentV3::sign(
        signer,
        SessionIntentV3Payload {
            claims: claims(
                signer,
                controller_device_id,
                target_device_id,
                counter,
                nonce,
            ),
            request,
            request_commitment,
        },
    )
    .unwrap()
}

fn inbound_v3_grant(signer: &DeviceIdentity, session_id: &str) -> SessionGrantV3 {
    SessionGrantV3::sign(
        signer,
        SessionGrantV3Payload {
            claims: claims(signer, "peer-device", "local-device", 1, 71),
            session_id: SessionId(session_id.into()),
            controller_device_id: DeviceId("local-device".into()),
            target_device_id: DeviceId("peer-device".into()),
            intent_commitment: "a".repeat(64),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: None,
            backend_policy_revision: 7,
            policy_expires_at_ms: NOW + 20_000,
            relay_generation: 0,
            relay_directory_id: "directory-0".into(),
            primary_relay_node_id: "relay-primary".into(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .unwrap()
}

fn inbound_v3_offer(signer: &DeviceIdentity, session_id: &str) -> WebRtcOfferV3 {
    WebRtcOfferV3::sign(
        signer,
        WebRtcOfferV3Payload {
            claims: claims(signer, "peer-device", "local-device", 2, 62),
            session_id: SessionId(session_id.into()),
            controller_device_id: DeviceId("peer-device".into()),
            target_device_id: DeviceId("local-device".into()),
            grant_commitment: "b".repeat(64),
            sdp: TEST_ONLY_SIGNAL_SDP_SENTINEL.into(),
            candidate_fingerprints: vec!["c".repeat(64)],
        },
    )
    .unwrap()
}

fn inbound_v3_answer(signer: &DeviceIdentity, session_id: &str) -> WebRtcAnswerV3 {
    WebRtcAnswerV3::sign(
        signer,
        WebRtcAnswerV3Payload {
            claims: claims(signer, "peer-device", "local-device", 2, 72),
            session_id: SessionId(session_id.into()),
            controller_device_id: DeviceId("local-device".into()),
            target_device_id: DeviceId("peer-device".into()),
            grant_commitment: "b".repeat(64),
            sdp: TEST_ONLY_SIGNAL_SDP_SENTINEL.into(),
            candidate_fingerprints: vec!["d".repeat(64)],
        },
    )
    .unwrap()
}

fn inbound_v3_candidate(
    signer: &DeviceIdentity,
    session_id: &str,
    role: WebRtcDescriptionRoleV3,
    counter: u64,
    nonce: u8,
) -> WebRtcCandidateV3 {
    let session_id = SessionId(session_id.into());
    let candidate = TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL.to_string();
    let grant_commitment = "b".repeat(64);
    let candidate_fingerprint = webrtc_candidate_fingerprint_v3(
        &session_id,
        &grant_commitment,
        role,
        &candidate,
        Some("0"),
        Some(0),
        Some(TEST_ONLY_SIGNAL_UFRAG_SENTINEL),
    );
    let (controller, target) = match role {
        WebRtcDescriptionRoleV3::Offer => ("peer-device", "local-device"),
        WebRtcDescriptionRoleV3::Answer => ("local-device", "peer-device"),
    };
    WebRtcCandidateV3::sign(
        signer,
        WebRtcCandidateV3Payload {
            claims: claims(signer, "peer-device", "local-device", counter, nonce),
            session_id,
            controller_device_id: DeviceId(controller.into()),
            target_device_id: DeviceId(target.into()),
            grant_commitment,
            description_role: role,
            candidate,
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some(TEST_ONLY_SIGNAL_UFRAG_SENTINEL.into()),
            candidate_fingerprint,
        },
    )
    .unwrap()
}

fn outbound_v3_grant(session_id: &str) -> AuthenticatedSessionSignalingCommand {
    AuthenticatedSessionSignalingCommand {
        peer_device_id: DeviceId("peer-device".into()),
        signal: OutboundAuthenticatedSessionSignal::SessionGrant {
            session_id: SessionId(session_id.into()),
            controller_device_id: DeviceId("peer-device".into()),
            target_device_id: DeviceId("local-device".into()),
            intent_commitment: "a".repeat(64),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: None,
            backend_policy_revision: 7,
            policy_expires_at_ms: NOW + 60_000,
            relay_generation: 0,
            relay_directory_id: "directory-0".into(),
            primary_relay_node_id: "relay-primary".into(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    }
}

fn outbound_v3_intent(session_id: &str) -> AuthenticatedSessionSignalingCommand {
    AuthenticatedSessionSignalingCommand {
        peer_device_id: DeviceId("peer-device".into()),
        signal: OutboundAuthenticatedSessionSignal::SessionIntent {
            request: v3_request(session_id, "local-device", "peer-device"),
        },
    }
}

fn outbound_v3_offer(session_id: &str) -> AuthenticatedSessionSignalingCommand {
    AuthenticatedSessionSignalingCommand {
        peer_device_id: DeviceId("peer-device".into()),
        signal: OutboundAuthenticatedSessionSignal::WebRtcOffer {
            session_id: SessionId(session_id.into()),
            controller_device_id: DeviceId("local-device".into()),
            target_device_id: DeviceId("peer-device".into()),
            grant_commitment: "b".repeat(64),
            sdp: TEST_ONLY_SIGNAL_SDP_SENTINEL.into(),
            candidate_fingerprints: vec!["c".repeat(64)],
        },
    }
}

fn outbound_v3_answer(session_id: &str) -> AuthenticatedSessionSignalingCommand {
    AuthenticatedSessionSignalingCommand {
        peer_device_id: DeviceId("peer-device".into()),
        signal: OutboundAuthenticatedSessionSignal::WebRtcAnswer {
            session_id: SessionId(session_id.into()),
            controller_device_id: DeviceId("peer-device".into()),
            target_device_id: DeviceId("local-device".into()),
            grant_commitment: "b".repeat(64),
            sdp: TEST_ONLY_SIGNAL_SDP_SENTINEL.into(),
            candidate_fingerprints: vec!["d".repeat(64)],
        },
    }
}

fn outbound_v3_candidate(
    session_id: &str,
    description_role: WebRtcDescriptionRoleV3,
) -> AuthenticatedSessionSignalingCommand {
    let session_id = SessionId(session_id.into());
    let grant_commitment = "b".repeat(64);
    let candidate = TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL.to_string();
    let candidate_fingerprint = webrtc_candidate_fingerprint_v3(
        &session_id,
        &grant_commitment,
        description_role,
        &candidate,
        Some("0"),
        Some(0),
        Some(TEST_ONLY_SIGNAL_UFRAG_SENTINEL),
    );
    let (controller, target) = match description_role {
        WebRtcDescriptionRoleV3::Offer => ("local-device", "peer-device"),
        WebRtcDescriptionRoleV3::Answer => ("peer-device", "local-device"),
    };
    AuthenticatedSessionSignalingCommand {
        peer_device_id: DeviceId("peer-device".into()),
        signal: OutboundAuthenticatedSessionSignal::WebRtcCandidate {
            session_id,
            controller_device_id: DeviceId(controller.into()),
            target_device_id: DeviceId(target.into()),
            grant_commitment,
            description_role,
            candidate,
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some(TEST_ONLY_SIGNAL_UFRAG_SENTINEL.into()),
            candidate_fingerprint,
        },
    }
}

fn envelope_counter(envelope: &SignalEnvelope) -> u64 {
    match &envelope.message {
        AuthenticatedSignalMessage::Register(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::PresenceHeartbeat(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::SessionIntentV3(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::SessionGrantV3(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::WebrtcOfferV3(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::WebrtcAnswerV3(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::WebrtcCandidateV3(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::RelayMigrationOffer(message) => message.payload.claims.counter,
        AuthenticatedSignalMessage::RelayMigrationAnswer(message) => message.payload.claims.counter,
        _ => panic!("message has no expected outbound claims counter"),
    }
}

fn unpinned_config() -> SignalingConfig {
    SignalingConfig::new(
        "ws://127.0.0.1:9532/realtime",
        DeviceId("local-device".into()),
        "Local workstation",
        BackendRole::Agent,
        "backend-token-secret",
        DeviceId("signal-server".into()),
        None,
        Duration::from_secs(5),
        Duration::from_millis(250),
        Duration::from_secs(8),
    )
    .unwrap()
}

fn registered(server: &DeviceIdentity, counter: u64) -> Registered {
    registered_with_nonce(server, counter, 31)
}

fn registered_with_nonce(server: &DeviceIdentity, counter: u64, nonce: u8) -> Registered {
    Registered::sign(
        server,
        RegisteredPayload {
            claims: claims(server, "signal-server", "local-device", counter, nonce),
            registered_device_id: DeviceId("local-device".into()),
            connection_id: [5; 16],
            heartbeat_interval_ms: 3_000,
        },
    )
    .unwrap()
}

#[test]
fn service_authenticates_with_persistent_device_key_and_backend_token_then_heartbeats() {
    let local = identity();
    let server = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), Arc::clone(&local));
    let challenge = ServerChallenge {
        challenge_id: [1; 16],
        challenge_nonce: [2; 32],
        issued_at_ms: NOW,
        expires_at_ms: NOW + 5_000,
    };

    let registration = runtime.build_registration(challenge.clone(), NOW).unwrap();
    let AuthenticatedSignalMessage::Register(register) = registration.message else {
        panic!("expected registration")
    };
    assert_eq!(
        register.payload.backend_device_token,
        "backend-token-secret"
    );
    assert_eq!(register.payload.challenge_id, challenge.challenge_id);
    assert_eq!(register.payload.challenge_nonce, challenge.challenge_nonce);
    assert_eq!(register.payload.claims.issuer_key_id, local.key_id());
    register
        .verify_for(
            &DeviceId("signal-server".into()),
            NOW,
            &mut mrd_signal_proto::SignalReplayGuard::new(4, 4),
        )
        .unwrap();

    runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    assert_eq!(
        runtime.snapshot().state,
        SignalingConnectionState::Authenticated
    );
    assert!(runtime.heartbeat_if_due(NOW + 2_999).unwrap().is_none());
    let heartbeat = runtime
        .heartbeat_if_due(NOW + 3_000)
        .unwrap()
        .expect("heartbeat due");
    let AuthenticatedSignalMessage::PresenceHeartbeat(heartbeat) = heartbeat.message else {
        panic!("expected heartbeat")
    };
    assert_eq!(heartbeat.payload.connection_id, [5; 16]);
    assert_eq!(heartbeat.payload.claims.issuer_key_id, local.key_id());
}

#[test]
fn reconnect_backoff_is_exponential_bounded_and_health_is_observable() {
    let server = identity();
    let local = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), local);

    assert_eq!(runtime.reconnect_delay(), Duration::from_millis(250));
    runtime.note_connection_failure(NOW, &SignalingRuntimeError::Disconnected);
    assert_eq!(runtime.reconnect_delay(), Duration::from_millis(250));
    runtime.note_connection_failure(NOW + 500, &SignalingRuntimeError::Disconnected);
    assert_eq!(runtime.reconnect_delay(), Duration::from_millis(500));
    for attempt in 0..16 {
        runtime
            .note_connection_failure(NOW + 1_000 + attempt, &SignalingRuntimeError::Disconnected);
    }
    assert_eq!(runtime.reconnect_delay(), Duration::from_secs(8));
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.state, SignalingConnectionState::Backoff);
    assert!(snapshot.reconnect_attempt >= 2);
    assert_eq!(
        snapshot.last_error.as_deref(),
        Some("signaling_disconnected")
    );
}

#[test]
fn v3_initial_runtime_errors_health_and_trace_use_closed_codes() {
    let server = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), identity());
    let trace = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(trace.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    let _trace_guard = tracing::subscriber::set_default(subscriber);
    let raw_transport = std::io::Error::other(format!(
        "{} {} {} {} {} {}",
        TEST_ONLY_SIGNAL_SDP_SENTINEL,
        TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
        TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
        TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
        TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
        TEST_ONLY_RESTART_ROUTE_TOKEN,
    ));
    let errors = [
        SignalingRuntimeError::from(tokio_tungstenite::tungstenite::Error::Io(raw_transport)),
        SignalingRuntimeError::Apply,
        SignalingRuntimeError::ServerProtocol,
    ];

    for (offset, error) in errors.iter().enumerate() {
        runtime.note_connection_failure(NOW + offset as u64, error);
        let rendered = format!("{error:?} {error}");
        for sentinel in [
            TEST_ONLY_SIGNAL_SDP_SENTINEL,
            TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
            TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
            TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
            TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
            TEST_ONLY_RESTART_ROUTE_TOKEN,
        ] {
            assert!(
                !rendered.contains(sentinel),
                "runtime error exposed a body sentinel"
            );
        }
    }

    assert_eq!(
        runtime.snapshot().last_error.as_deref(),
        Some("signaling_server_protocol")
    );
    let trace = trace.text();
    assert!(trace.contains("signaling_transport"));
    assert!(trace.contains("signaling_apply"));
    assert!(trace.contains("signaling_server_protocol"));
    for sentinel in [
        TEST_ONLY_SIGNAL_SDP_SENTINEL,
        TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
        TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
        TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
        TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
        TEST_ONLY_RESTART_ROUTE_TOKEN,
    ] {
        assert!(!trace.contains(sentinel), "trace exposed a body sentinel");
    }
}

#[test]
fn configuration_redacts_tokens_and_rejects_insecure_or_secret_bearing_urls() {
    let config = unpinned_config();
    let debug = format!("{config:?}");
    assert!(!debug.contains("backend-token-secret"));
    assert!(debug.contains("REDACTED"));
    assert!(SignalingConfig::new(
        "ws://remote.example/ws",
        DeviceId("local-device".into()),
        "Local workstation",
        BackendRole::Agent,
        "backend-token-secret",
        DeviceId("signal-server".into()),
        None,
        Duration::from_secs(1),
        Duration::from_millis(50),
        Duration::from_secs(1),
    )
    .is_err());
    assert!(SignalingConfig::new(
        "wss://signal.example/ws?token=leak",
        DeviceId("local-device".into()),
        "Local workstation",
        BackendRole::Agent,
        "backend-token-secret",
        DeviceId("signal-server".into()),
        None,
        Duration::from_secs(1),
        Duration::from_millis(50),
        Duration::from_secs(1),
    )
    .is_err());
}

#[test]
fn first_authenticated_server_key_is_pinned_for_reconnects() {
    let first_server = identity();
    let replacement_server = identity();
    let mut runtime = SignalingRuntimeCore::new(unpinned_config(), identity());
    runtime
        .accept_registered(registered(&first_server, 1), NOW)
        .unwrap();
    runtime.note_connection_failure(NOW + 1, &SignalingRuntimeError::Disconnected);
    assert!(runtime
        .accept_registered(registered(&replacement_server, 1), NOW + 2)
        .is_err());
}

#[test]
fn v3_initial_all_legacy_v2_messages_are_rejected() {
    let server = identity();
    let local = identity();
    let controller = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), local);
    runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let legacy_claims = || claims(&controller, "controller-1", "local-device", 1, 41);
    let public_key = controller.public_key().to_vec();
    let messages = [
        AuthenticatedSignalMessage::SessionIntent(SessionIntent {
            payload: SessionIntentPayload {
                claims: legacy_claims(),
                session_id: SessionId("legacy-intent".into()),
                idempotency_key: [8; 16],
                target_device_id: DeviceId("local-device".into()),
                requested_transport: "webrtc".into(),
            },
            signer_public_key: public_key.clone(),
            signature: vec![0; 64],
        }),
        AuthenticatedSignalMessage::SessionGrant(SessionGrant {
            payload: SessionGrantPayload {
                claims: legacy_claims(),
                session_id: SessionId("legacy-grant".into()),
                controller_device_id: DeviceId("controller-1".into()),
                accepted_transport: "webrtc".into(),
                accepted_candidate_fingerprints: BTreeSet::new(),
            },
            signer_public_key: public_key.clone(),
            signature: vec![0; 64],
        }),
        AuthenticatedSignalMessage::WebrtcOffer(LegacyWebRtcOffer {
            payload: LegacyWebRtcOfferPayload {
                claims: legacy_claims(),
                session_id: SessionId("legacy-offer".into()),
                sdp: TEST_ONLY_SIGNAL_SDP_SENTINEL.into(),
                candidate_fingerprints: BTreeSet::new(),
            },
            signer_public_key: public_key.clone(),
            signature: vec![0; 64],
        }),
        AuthenticatedSignalMessage::WebrtcAnswer(LegacyWebRtcAnswer {
            payload: LegacyWebRtcAnswerPayload {
                claims: legacy_claims(),
                session_id: SessionId("legacy-answer".into()),
                sdp: TEST_ONLY_SIGNAL_SDP_SENTINEL.into(),
                candidate_fingerprints: BTreeSet::new(),
            },
            signer_public_key: public_key.clone(),
            signature: vec![0; 64],
        }),
        AuthenticatedSignalMessage::WebrtcCandidate(LegacyWebRtcCandidate {
            payload: LegacyWebRtcCandidatePayload {
                claims: legacy_claims(),
                session_id: SessionId("legacy-candidate".into()),
                candidate: TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL.into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                candidate_fingerprint: "a".repeat(64),
            },
            signer_public_key: public_key,
            signature: vec![0; 64],
        }),
    ];

    for message in messages {
        let error = runtime
            .handle_inbound(SignalEnvelope::new(message), NOW + 1)
            .unwrap_err();
        assert!(matches!(
            error,
            SignalingRuntimeError::Protocol(
                mrd_signal_proto::SignalProtocolError::UnsupportedVersion
            )
        ));
    }
}

#[test]
fn signed_relay_migration_is_mapped_without_becoming_reconnect() {
    let server = identity();
    let local = identity();
    let controller = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), local);
    runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let offer = RelayMigrationOffer::sign(
        &controller,
        RelayMigrationOfferPayload {
            claims: claims(&controller, "controller-1", "local-device", 1, 42),
            session_id: SessionId("migration-session".into()),
            migration_generation: 1,
            directory_id: "directory-1".into(),
            node_id: "relay-1".into(),
            sdp: "v=0".into(),
            restart_route_token: "1".repeat(64),
            candidate_fingerprints: BTreeSet::from(["a".repeat(64)]),
        },
    )
    .unwrap();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::RelayMigrationOffer(offer));
    let InboundDisposition::Applied(applied) =
        runtime.handle_inbound(envelope.clone(), NOW + 1).unwrap()
    else {
        panic!("expected applied migration offer")
    };
    assert!(matches!(
        applied.signal,
        AuthenticatedSessionSignal::RelayMigrationOffer {
            migration_generation: 1,
            ref directory_id,
            ref node_id,
            ..
        } if directory_id == "directory-1" && node_id == "relay-1"
    ));
    assert_eq!(
        runtime.handle_inbound(envelope, NOW + 2).unwrap(),
        InboundDisposition::Duplicate
    );
}

#[test]
fn outbound_relay_migration_is_signed_with_restart_route_binding() {
    let server = identity();
    let local = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), Arc::clone(&local));
    let envelope = runtime
        .build_relay_migration_signal(
            RelaySignalingCommand {
                peer_device_id: DeviceId("peer-device".into()),
                signal: OutboundRelayMigrationSignal::Offer {
                    session_id: SessionId("outbound-session".into()),
                    migration_generation: 1,
                    directory_id: "directory-1".into(),
                    node_id: "relay-1".into(),
                    sdp: "v=0".into(),
                    restart_route_token: "1".repeat(64),
                    candidate_fingerprints: BTreeSet::from(["a".repeat(64)]),
                },
            },
            NOW,
        )
        .unwrap();
    let AuthenticatedSignalMessage::RelayMigrationOffer(offer) = envelope.message else {
        panic!("expected signed migration offer")
    };
    assert_eq!(offer.payload.claims.issuer_key_id, local.key_id());
    assert_eq!(offer.payload.restart_route_token, "1".repeat(64));
    assert_eq!(
        offer.payload.claims.intended_peer_device_id,
        DeviceId("peer-device".into())
    );
}

#[test]
fn v3_initial_inbound_preserves_typed_signed_payloads_and_redacts_bodies() {
    let server = identity();
    let peer = identity();
    let mut target_runtime = SignalingRuntimeCore::new(
        config_with_role_at(&server, BackendRole::Agent, "ws://127.0.0.1:9532/realtime"),
        identity(),
    );
    target_runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();

    let intent = inbound_v3_intent(&peer, "typed-target-session");
    let offer = inbound_v3_offer(&peer, "typed-target-session");
    let offer_candidate = inbound_v3_candidate(
        &peer,
        "typed-target-session",
        WebRtcDescriptionRoleV3::Offer,
        3,
        63,
    );
    for (message, expected) in [
        (
            AuthenticatedSignalMessage::SessionIntentV3(intent.clone()),
            "intent",
        ),
        (
            AuthenticatedSignalMessage::WebrtcOfferV3(offer.clone()),
            "offer",
        ),
        (
            AuthenticatedSignalMessage::WebrtcCandidateV3(offer_candidate.clone()),
            "offer_candidate",
        ),
    ] {
        let InboundDisposition::Applied(event) = target_runtime
            .handle_inbound(SignalEnvelope::new(message), NOW + 1)
            .unwrap()
        else {
            panic!("expected applied {expected}")
        };
        assert_eq!(event.signal.session_id().0.as_str(), "typed-target-session");
        match (expected, &event.signal) {
            ("intent", AuthenticatedSessionSignal::SessionIntentV3 { message }) => {
                assert_eq!(message, &intent)
            }
            ("offer", AuthenticatedSessionSignal::WebRtcOfferV3 { message }) => {
                assert_eq!(message, &offer)
            }
            ("offer_candidate", AuthenticatedSessionSignal::WebRtcCandidateV3 { message }) => {
                assert_eq!(message, &offer_candidate)
            }
            _ => panic!("unexpected typed v3 event"),
        }
        let debug = format!("{event:?}");
        assert!(!debug.contains(TEST_ONLY_SIGNAL_SDP_SENTINEL));
        assert!(!debug.contains(TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL));
        assert!(!debug.contains(TEST_ONLY_SIGNAL_UFRAG_SENTINEL));
    }

    let mut controller_runtime = SignalingRuntimeCore::new(
        config_with_role_at(
            &server,
            BackendRole::Controller,
            "ws://127.0.0.1:9532/realtime",
        ),
        identity(),
    );
    controller_runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let grant = inbound_v3_grant(&peer, "typed-controller-session");
    let answer = inbound_v3_answer(&peer, "typed-controller-session");
    let answer_candidate = inbound_v3_candidate(
        &peer,
        "typed-controller-session",
        WebRtcDescriptionRoleV3::Answer,
        3,
        73,
    );
    for (message, expected) in [
        (
            AuthenticatedSignalMessage::SessionGrantV3(grant.clone()),
            "grant",
        ),
        (
            AuthenticatedSignalMessage::WebrtcAnswerV3(answer.clone()),
            "answer",
        ),
        (
            AuthenticatedSignalMessage::WebrtcCandidateV3(answer_candidate.clone()),
            "answer_candidate",
        ),
    ] {
        let InboundDisposition::Applied(event) = controller_runtime
            .handle_inbound(SignalEnvelope::new(message), NOW + 1)
            .unwrap()
        else {
            panic!("expected applied {expected}")
        };
        assert_eq!(
            event.signal.session_id().0.as_str(),
            "typed-controller-session"
        );
        match (expected, &event.signal) {
            ("grant", AuthenticatedSessionSignal::SessionGrantV3 { message }) => {
                assert_eq!(message, &grant)
            }
            ("answer", AuthenticatedSessionSignal::WebRtcAnswerV3 { message }) => {
                assert_eq!(message, &answer)
            }
            ("answer_candidate", AuthenticatedSessionSignal::WebRtcCandidateV3 { message }) => {
                assert_eq!(message, &answer_candidate)
            }
            _ => panic!("unexpected typed v3 event"),
        }
        let debug = format!("{event:?}");
        assert!(!debug.contains(TEST_ONLY_SIGNAL_SDP_SENTINEL));
        assert!(!debug.contains(TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL));
        assert!(!debug.contains(TEST_ONLY_SIGNAL_UFRAG_SENTINEL));
    }
}

#[test]
fn v3_webrtc_messages_allow_signed_counter_reordering_per_session() {
    let server = identity();
    let peer = identity();
    let mut runtime = SignalingRuntimeCore::new(
        config_with_role_at(&server, BackendRole::Agent, "ws://127.0.0.1:9532/realtime"),
        identity(),
    );
    runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();

    let session_id = "reordered-webrtc-session";
    let mut offer_payload = inbound_v3_offer(&peer, session_id).payload;
    offer_payload.claims.counter = 1;
    offer_payload.claims.nonce = [91; 16];
    let offer = WebRtcOfferV3::sign(&peer, offer_payload).unwrap();
    let candidate = inbound_v3_candidate(&peer, session_id, WebRtcDescriptionRoleV3::Offer, 2, 92);

    // ICE candidates may be delivered before the SDP description.  Their
    // authenticated counters are consequently not a globally ordered stream.
    assert!(matches!(
        runtime
            .handle_inbound(
                SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcCandidateV3(
                    candidate.clone(),
                )),
                NOW + 1,
            )
            .unwrap(),
        InboundDisposition::Applied(_)
    ));
    assert!(matches!(
        runtime
            .handle_inbound(
                SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(offer)),
                NOW + 1,
            )
            .unwrap(),
        InboundDisposition::Applied(_)
    ));

    // The exact signed envelope remains idempotent even after an out-of-order
    // message has been accepted.
    assert_eq!(
        runtime
            .handle_inbound(
                SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcCandidateV3(candidate)),
                NOW + 1,
            )
            .unwrap(),
        InboundDisposition::Duplicate
    );

    // A fresh envelope with the same authenticated tuple is still a replay,
    // even if an attacker changes the signed description body.
    let mut altered_offer_payload = inbound_v3_offer(&peer, session_id).payload;
    altered_offer_payload.claims.counter = 1;
    altered_offer_payload.claims.nonce = [91; 16];
    altered_offer_payload.sdp = "v=0\r\n".into();
    let altered_offer = WebRtcOfferV3::sign(&peer, altered_offer_payload).unwrap();
    assert!(matches!(
        runtime.handle_inbound(
            SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(altered_offer)),
            NOW + 1,
        ),
        Err(SignalingRuntimeError::Protocol(
            mrd_signal_proto::SignalProtocolError::RepeatedNonce
        ))
    ));

    // The same issuer/counter/nonce can be used by a separate session without
    // poisoning that session's independently tracked replay window.
    let second_session = "reordered-webrtc-session-2";
    let mut second_offer_payload = inbound_v3_offer(&peer, second_session).payload;
    second_offer_payload.claims.counter = 1;
    second_offer_payload.claims.nonce = [91; 16];
    let second_offer = WebRtcOfferV3::sign(&peer, second_offer_payload).unwrap();
    assert!(matches!(
        runtime
            .handle_inbound(
                SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(second_offer)),
                NOW + 1,
            )
            .unwrap(),
        InboundDisposition::Applied(_)
    ));
}

#[tokio::test]
async fn v3_initial_invalid_runtime_messages_never_reach_scoped_bus() {
    struct InvalidCase {
        name: &'static str,
        role: BackendRole,
        envelope: SignalEnvelope,
        session_id: &'static str,
        expected_code: &'static str,
    }

    let peer = identity();
    let mut invalid_intent = inbound_v3_intent(&peer, "invalid-signature-intent");
    invalid_intent.signature[0] ^= 1;

    let mut tampered_grant = inbound_v3_grant(&peer, "tampered-grant");
    tampered_grant.payload.relay_directory_id = "directory-mutated-after-signing".into();

    let mut wrong_peer_offer_payload = inbound_v3_offer(&peer, "wrong-peer-offer").payload;
    wrong_peer_offer_payload.claims.intended_peer_device_id = DeviceId("other-device".into());
    wrong_peer_offer_payload.target_device_id = DeviceId("other-device".into());
    let wrong_peer_offer = WebRtcOfferV3::sign(&peer, wrong_peer_offer_payload).unwrap();

    let cases = [
        InvalidCase {
            name: "intent invalid signature",
            role: BackendRole::Agent,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntentV3(
                invalid_intent,
            )),
            session_id: "invalid-signature-intent",
            expected_code: "signaling_protocol_authentication_failed",
        },
        InvalidCase {
            name: "intent wrong local role",
            role: BackendRole::Controller,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntentV3(
                inbound_v3_intent(&peer, "wrong-role-intent"),
            )),
            session_id: "wrong-role-intent",
            expected_code: "signaling_role_mismatch",
        },
        InvalidCase {
            name: "grant tampered payload",
            role: BackendRole::Controller,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::SessionGrantV3(
                tampered_grant,
            )),
            session_id: "tampered-grant",
            expected_code: "signaling_protocol_authentication_failed",
        },
        InvalidCase {
            name: "grant wrong local role",
            role: BackendRole::Agent,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::SessionGrantV3(
                inbound_v3_grant(&peer, "wrong-role-grant"),
            )),
            session_id: "wrong-role-grant",
            expected_code: "signaling_role_mismatch",
        },
        InvalidCase {
            name: "offer wrong intended peer",
            role: BackendRole::Agent,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(
                wrong_peer_offer,
            )),
            session_id: "wrong-peer-offer",
            expected_code: "signaling_protocol_wrong_peer",
        },
        InvalidCase {
            name: "offer wrong local role",
            role: BackendRole::Controller,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(
                inbound_v3_offer(&peer, "wrong-role-offer"),
            )),
            session_id: "wrong-role-offer",
            expected_code: "signaling_role_mismatch",
        },
        InvalidCase {
            name: "answer wrong local role",
            role: BackendRole::Agent,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcAnswerV3(
                inbound_v3_answer(&peer, "wrong-role-answer"),
            )),
            session_id: "wrong-role-answer",
            expected_code: "signaling_role_mismatch",
        },
        InvalidCase {
            name: "offer candidate wrong local role",
            role: BackendRole::Controller,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcCandidateV3(
                inbound_v3_candidate(
                    &peer,
                    "wrong-role-offer-candidate",
                    WebRtcDescriptionRoleV3::Offer,
                    3,
                    83,
                ),
            )),
            session_id: "wrong-role-offer-candidate",
            expected_code: "signaling_role_mismatch",
        },
        InvalidCase {
            name: "answer candidate wrong local role",
            role: BackendRole::Agent,
            envelope: SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcCandidateV3(
                inbound_v3_candidate(
                    &peer,
                    "wrong-role-answer-candidate",
                    WebRtcDescriptionRoleV3::Answer,
                    3,
                    84,
                ),
            )),
            session_id: "wrong-role-answer-candidate",
            expected_code: "signaling_role_mismatch",
        },
    ];
    let trace = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(trace.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    let _trace_guard = tracing::subscriber::set_default(subscriber);

    for case in cases {
        let server = identity();
        let app_state = Arc::new(AppState::new());
        let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
        let mut subscription = app_state.relay_signaling.subscribe_authenticated_session(
            SessionId(case.session_id.into()),
            DeviceId("peer-device".into()),
        );
        let mut runtime = SignalingRuntimeCore::new(
            config_with_role_at(&server, case.role, "ws://127.0.0.1:9532/realtime"),
            identity(),
        );
        runtime
            .accept_registered(registered(&server, 1), NOW)
            .unwrap();

        let error = match runtime.handle_inbound(case.envelope, NOW + 1) {
            Err(error) => Some(error),
            Ok(InboundDisposition::Applied(event)) => {
                mapper.apply_authenticated_signal(*event).await.unwrap();
                None
            }
            Ok(InboundDisposition::Duplicate | InboundDisposition::Control) => None,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), subscription.recv())
                .await
                .is_err(),
            "{} reached the scoped signaling bus",
            case.name,
        );
        let error = error.unwrap_or_else(|| panic!("{} was not rejected", case.name));
        assert_eq!(error.code(), case.expected_code, "{}", case.name);
        let rendered = format!("{error:?} {error}");
        for sentinel in [
            TEST_ONLY_SIGNAL_SDP_SENTINEL,
            TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
            TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
            TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
            TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
            TEST_ONLY_RESTART_ROUTE_TOKEN,
        ] {
            assert!(
                !rendered.contains(sentinel),
                "{} exposed a body sentinel in its error",
                case.name,
            );
        }
        runtime.note_connection_failure(NOW + 2, &error);
        assert_eq!(
            runtime.snapshot().last_error.as_deref(),
            Some(case.expected_code),
            "{}",
            case.name,
        );
    }

    let trace = trace.text();
    for sentinel in [
        TEST_ONLY_SIGNAL_SDP_SENTINEL,
        TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
        TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
        TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
        TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
        TEST_ONLY_RESTART_ROUTE_TOKEN,
    ] {
        assert!(!trace.contains(sentinel), "trace exposed a body sentinel");
    }
}

#[test]
fn v3_initial_duplicate_remains_suppressed_across_reconnect() {
    let server = identity();
    let peer = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), identity());
    runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntentV3(
        inbound_v3_intent(&peer, "reconnect-session"),
    ));
    assert!(matches!(
        runtime.handle_inbound(envelope.clone(), NOW + 1).unwrap(),
        InboundDisposition::Applied(_)
    ));

    runtime.note_connection_failure(NOW + 2, &SignalingRuntimeError::Disconnected);
    runtime
        .accept_registered(registered_with_nonce(&server, 2, 32), NOW + 3)
        .unwrap();
    assert_eq!(
        runtime.handle_inbound(envelope, NOW + 4).unwrap(),
        InboundDisposition::Duplicate
    );
}

#[test]
fn v3_initial_outbound_shares_one_monotonic_claims_issuer() {
    let server = identity();
    let mut agent = SignalingRuntimeCore::new(
        config_with_role_at(&server, BackendRole::Agent, "ws://127.0.0.1:9532/realtime"),
        identity(),
    );
    let agent_registration = agent
        .build_registration(
            ServerChallenge {
                challenge_id: [1; 16],
                challenge_nonce: [2; 32],
                issued_at_ms: NOW,
                expires_at_ms: NOW + 5_000,
            },
            NOW,
        )
        .unwrap();
    agent
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let agent_heartbeat = agent
        .heartbeat_if_due(NOW + 3_000)
        .unwrap()
        .expect("heartbeat due");
    let mut agent_counters = vec![
        envelope_counter(&agent_registration),
        envelope_counter(&agent_heartbeat),
    ];
    for (offset, command) in [
        outbound_v3_grant("agent-counter-session"),
        outbound_v3_answer("agent-counter-session"),
        outbound_v3_candidate("agent-counter-session", WebRtcDescriptionRoleV3::Answer),
    ]
    .into_iter()
    .enumerate()
    {
        let envelope = agent
            .build_authenticated_session_signal(command, NOW + 3_001 + offset as u64)
            .unwrap();
        agent_counters.push(envelope_counter(&envelope));
    }
    let agent_migration = agent
        .build_relay_migration_signal(
            RelaySignalingCommand {
                peer_device_id: DeviceId("peer-device".into()),
                signal: OutboundRelayMigrationSignal::Answer {
                    session_id: SessionId("agent-counter-session".into()),
                    migration_generation: 1,
                    directory_id: "directory-1".into(),
                    node_id: "relay-1".into(),
                    sdp: "private-migration-body".into(),
                    restart_route_token: "1".repeat(64),
                    candidate_fingerprints: BTreeSet::from(["e".repeat(64)]),
                },
            },
            NOW + 3_004,
        )
        .unwrap();
    agent_counters.push(envelope_counter(&agent_migration));
    assert_eq!(agent_counters, [1, 2, 3, 4, 5, 6]);

    let mut controller = SignalingRuntimeCore::new(
        config_with_role_at(
            &server,
            BackendRole::Controller,
            "ws://127.0.0.1:9532/realtime",
        ),
        identity(),
    );
    let controller_registration = controller
        .build_registration(
            ServerChallenge {
                challenge_id: [3; 16],
                challenge_nonce: [4; 32],
                issued_at_ms: NOW,
                expires_at_ms: NOW + 5_000,
            },
            NOW,
        )
        .unwrap();
    controller
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let controller_heartbeat = controller
        .heartbeat_if_due(NOW + 3_000)
        .unwrap()
        .expect("heartbeat due");
    let mut controller_counters = vec![
        envelope_counter(&controller_registration),
        envelope_counter(&controller_heartbeat),
    ];
    for (offset, command) in [
        outbound_v3_intent("controller-counter-session"),
        outbound_v3_offer("controller-counter-session"),
        outbound_v3_candidate("controller-counter-session", WebRtcDescriptionRoleV3::Offer),
    ]
    .into_iter()
    .enumerate()
    {
        let envelope = controller
            .build_authenticated_session_signal(command, NOW + 3_001 + offset as u64)
            .unwrap();
        controller_counters.push(envelope_counter(&envelope));
    }
    let controller_migration = controller
        .build_relay_migration_signal(
            RelaySignalingCommand {
                peer_device_id: DeviceId("peer-device".into()),
                signal: OutboundRelayMigrationSignal::Offer {
                    session_id: SessionId("controller-counter-session".into()),
                    migration_generation: 1,
                    directory_id: "directory-1".into(),
                    node_id: "relay-1".into(),
                    sdp: "private-migration-body".into(),
                    restart_route_token: "1".repeat(64),
                    candidate_fingerprints: BTreeSet::from(["e".repeat(64)]),
                },
            },
            NOW + 3_004,
        )
        .unwrap();
    controller_counters.push(envelope_counter(&controller_migration));
    assert_eq!(controller_counters, [1, 2, 3, 4, 5, 6]);
}

#[test]
fn v3_initial_debug_surfaces_redact_all_signal_bodies_and_route_tokens() {
    let sensitive_body = format!(
        "{} {} {} {} {} {}",
        TEST_ONLY_SIGNAL_SDP_SENTINEL,
        TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
        TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
        TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
        TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
        TEST_ONLY_RESTART_ROUTE_TOKEN,
    );
    let server = identity();
    let mut controller = SignalingRuntimeCore::new(
        config_with_role_at(
            &server,
            BackendRole::Controller,
            "ws://127.0.0.1:9532/realtime",
        ),
        identity(),
    );
    let mut outbound = outbound_v3_offer("debug-session");
    let OutboundAuthenticatedSessionSignal::WebRtcOffer { sdp, .. } = &mut outbound.signal else {
        panic!("expected outbound offer")
    };
    *sdp = sensitive_body.clone();
    let outbound_debug = format!("{outbound:?}");
    let envelope = controller
        .build_authenticated_session_signal(outbound, NOW)
        .unwrap();
    let envelope_debug = format!("{envelope:?} {:?}", envelope.message);

    let peer = identity();
    let mut inbound_payload = inbound_v3_offer(&peer, "debug-session").payload;
    inbound_payload.sdp = sensitive_body;
    let inbound = WebRtcOfferV3::sign(&peer, inbound_payload).unwrap();
    let mut agent = SignalingRuntimeCore::new(config(&server), identity());
    agent
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let disposition = agent
        .handle_inbound(
            SignalEnvelope::new(AuthenticatedSignalMessage::WebrtcOfferV3(inbound)),
            NOW + 1,
        )
        .unwrap();
    let disposition_debug = format!("{disposition:?}");

    let relay_command = RelaySignalingCommand {
        peer_device_id: DeviceId("peer-device".into()),
        signal: OutboundRelayMigrationSignal::Candidate {
            session_id: SessionId("debug-session".into()),
            migration_generation: 1,
            directory_id: TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL.into(),
            node_id: TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL.into(),
            candidate: TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL.into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some(TEST_ONLY_SIGNAL_UFRAG_SENTINEL.into()),
            restart_route_token: TEST_ONLY_RESTART_ROUTE_TOKEN.into(),
            candidate_fingerprint: "a".repeat(64),
        },
    };
    let relay_debug = format!("{relay_command:?}");
    let rendered = format!("{outbound_debug} {envelope_debug} {disposition_debug} {relay_debug}");
    for sentinel in [
        TEST_ONLY_SIGNAL_SDP_SENTINEL,
        TEST_ONLY_SIGNAL_CANDIDATE_SENTINEL,
        TEST_ONLY_SIGNAL_UFRAG_SENTINEL,
        TEST_ONLY_SIGNAL_ICE_PWD_SENTINEL,
        TEST_ONLY_SIGNAL_TURN_USERINFO_SENTINEL,
        TEST_ONLY_RESTART_ROUTE_TOKEN,
    ] {
        assert!(
            !rendered.contains(sentinel),
            "Debug exposed a body sentinel"
        );
    }
}

#[tokio::test]
async fn v3_controller_grant_never_reaches_bus_without_pending_authorization() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let peer = identity();
    let session_id = SessionId("unsolicited-controller-grant".into());
    let mut subscription = app_state
        .relay_signaling
        .subscribe_authenticated_session(session_id.clone(), DeviceId("peer-device".into()));

    let result = mapper
        .apply_authenticated_signal(verified_event_for_device(
            &peer,
            "peer-device",
            AuthenticatedSessionSignal::SessionGrantV3 {
                message: inbound_v3_grant(&peer, &session_id.0),
            },
        ))
        .await;

    assert!(result.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), subscription.recv())
            .await
            .is_err(),
        "unsolicited grant reached the scoped signaling bus"
    );
}

#[tokio::test]
async fn v3_initial_bus_routes_exact_session_and_peer_and_clears_on_close() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let peer = identity();
    let other_peer = identity();
    let session_id = SessionId("routed-session".into());
    let mut subscription = app_state
        .relay_signaling
        .subscribe_authenticated_session(session_id.clone(), DeviceId("peer-device".into()));

    mapper
        .apply_authenticated_signal(verified_event_for_device(
            &peer,
            "peer-device",
            AuthenticatedSessionSignal::SessionIntentV3 {
                message: inbound_v3_intent(&peer, "other-session"),
            },
        ))
        .await
        .unwrap();
    mapper
        .apply_authenticated_signal(verified_event_for_device(
            &other_peer,
            "other-peer",
            AuthenticatedSessionSignal::SessionIntentV3 {
                message: inbound_v3_intent_from(
                    &other_peer,
                    "routed-session",
                    "other-peer",
                    "local-device",
                    1,
                    81,
                ),
            },
        ))
        .await
        .unwrap();
    mapper
        .apply_authenticated_signal(verified_event_for_device(
            &peer,
            "peer-device",
            AuthenticatedSessionSignal::SessionIntentV3 {
                message: inbound_v3_intent(&peer, "routed-session"),
            },
        ))
        .await
        .unwrap();

    let event = tokio::time::timeout(Duration::from_millis(100), subscription.recv())
        .await
        .expect("matching event routed")
        .unwrap();
    assert_eq!(event.sender.device_id, DeviceId("peer-device".into()));
    assert!(matches!(
        event.signal,
        AuthenticatedSessionSignal::SessionIntentV3 { ref message }
            if message.payload.request.session_id == session_id
    ));

    app_state
        .relay_signaling
        .close_authenticated_session(&session_id)
        .await
        .unwrap();
    let mut after_close = app_state
        .relay_signaling
        .subscribe_authenticated_session(session_id.clone(), DeviceId("peer-device".into()));
    assert_eq!(
        after_close.recv().await,
        Err(AuthenticatedSessionSignalingReceiveError::SessionClosed)
    );
    assert!(matches!(
        app_state
            .relay_signaling
            .try_send_authenticated(outbound_v3_grant(&session_id.0)),
        Err(AuthenticatedSessionSignalingSendError::SessionClosed)
    ));
}

#[tokio::test]
async fn v3_initial_bus_reports_backpressure_without_waiting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = identity();
    let app_state = Arc::new(AppState::new());
    let task = spawn(
        config_with_role_at(&server, BackendRole::Agent, &format!("ws://{address}/ws")),
        Arc::clone(&app_state),
    )
    .unwrap();
    let mut receipts = Vec::with_capacity(AUTHENTICATED_SESSION_SIGNAL_QUEUE_CAPACITY);
    for _ in 0..AUTHENTICATED_SESSION_SIGNAL_QUEUE_CAPACITY {
        receipts.push(
            app_state
                .relay_signaling
                .try_send_authenticated(outbound_v3_grant("backpressure-session"))
                .unwrap(),
        );
    }
    assert!(matches!(
        app_state
            .relay_signaling
            .try_send_authenticated(outbound_v3_grant("backpressure-session")),
        Err(AuthenticatedSessionSignalingSendError::Backpressure)
    ));
    drop(receipts);
    task.shutdown().await;
    drop(listener);
}

#[tokio::test]
async fn v3_initial_close_fences_commands_queued_during_reconnect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = identity();
    let app_state = Arc::new(AppState::new());
    let task = spawn(
        config_with_role_at(&server, BackendRole::Agent, &format!("ws://{address}/ws")),
        Arc::clone(&app_state),
    )
    .unwrap();
    let session_id = SessionId("closed-while-reconnecting".into());
    let first_receipt = app_state
        .relay_signaling
        .try_send_authenticated(outbound_v3_grant(&session_id.0))
        .unwrap();
    let second_receipt = app_state
        .relay_signaling
        .try_send_authenticated(outbound_v3_grant(&session_id.0))
        .unwrap();
    app_state
        .relay_signaling
        .close_authenticated_session(&session_id)
        .await
        .unwrap();
    for receipt in [first_receipt, second_receipt] {
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), receipt.wait())
                .await
                .expect("closed receipt completed"),
            Err(AuthenticatedSessionSignalingSendError::SessionClosed)
        );
    }
    assert!(matches!(
        app_state
            .relay_signaling
            .try_send_authenticated(outbound_v3_grant(&session_id.0)),
        Err(AuthenticatedSessionSignalingSendError::SessionClosed)
    ));
    task.shutdown().await;
    drop(listener);
}

#[tokio::test]
async fn v3_initial_close_purges_full_session_queue_for_another_session() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = identity();
    let app_state = Arc::new(AppState::new());
    let task = spawn(
        config_with_role_at(&server, BackendRole::Agent, &format!("ws://{address}/ws")),
        Arc::clone(&app_state),
    )
    .unwrap();
    let closed_session = SessionId("full-closed-session".into());
    let mut closed_receipts = Vec::new();
    for _ in 0..AUTHENTICATED_SESSION_SIGNAL_QUEUE_CAPACITY {
        closed_receipts.push(
            app_state
                .relay_signaling
                .try_send_authenticated(outbound_v3_grant(&closed_session.0))
                .unwrap(),
        );
    }
    app_state
        .relay_signaling
        .close_authenticated_session(&closed_session)
        .await
        .unwrap();
    for receipt in closed_receipts {
        assert_eq!(
            receipt.wait().await,
            Err(AuthenticatedSessionSignalingSendError::SessionClosed)
        );
    }

    let open_session = SessionId("open-after-purge".into());
    let open_receipt = app_state
        .relay_signaling
        .try_send_authenticated(outbound_v3_grant(&open_session.0))
        .expect("closed session must release physical queue capacity");
    task.shutdown().await;
    assert_eq!(
        open_receipt.wait().await,
        Err(AuthenticatedSessionSignalingSendError::Unavailable)
    );
    drop(listener);
}

#[tokio::test]
async fn v3_initial_blocked_subscription_is_woken_by_session_close() {
    let app_state = Arc::new(AppState::new());
    let session_id = SessionId("blocked-subscription-session".into());
    let mut subscription = app_state
        .relay_signaling
        .subscribe_authenticated_session(session_id.clone(), DeviceId("peer-device".into()));
    let mut pending_recv = tokio::spawn(async move { subscription.recv().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut pending_recv)
            .await
            .is_err(),
        "subscription must be waiting before close"
    );

    app_state
        .relay_signaling
        .close_authenticated_session(&session_id)
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), pending_recv)
            .await
            .expect("close woke blocked subscription")
            .unwrap(),
        Err(AuthenticatedSessionSignalingReceiveError::SessionClosed)
    );
}

#[tokio::test]
async fn v3_initial_queued_matching_broadcast_is_fenced_by_session_close() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let peer = identity();
    let session_id = SessionId("queued-before-close".into());
    let mut subscription = app_state
        .relay_signaling
        .subscribe_authenticated_session(session_id.clone(), DeviceId("peer-device".into()));
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::SessionIntentV3 {
                message: inbound_v3_intent(&peer, &session_id.0),
            },
        ))
        .await
        .unwrap();

    app_state
        .relay_signaling
        .close_authenticated_session(&session_id)
        .await
        .unwrap();
    assert_eq!(
        subscription.recv().await,
        Err(AuthenticatedSessionSignalingReceiveError::SessionClosed)
    );
}

#[tokio::test]
async fn v3_initial_closed_session_tombstones_are_not_evicted() {
    let app_state = Arc::new(AppState::new());
    let first = SessionId("closed-session-0".into());
    for index in 0..4_200 {
        app_state
            .relay_signaling
            .close_authenticated_session(&SessionId(format!("closed-session-{index}")))
            .await
            .unwrap();
    }

    assert!(matches!(
        app_state
            .relay_signaling
            .try_send_authenticated(outbound_v3_grant(&first.0)),
        Err(AuthenticatedSessionSignalingSendError::SessionClosed)
    ));
}

fn verified_event(
    sender: &DeviceIdentity,
    signal: AuthenticatedSessionSignal,
) -> VerifiedSignalingEvent {
    verified_event_for_device(sender, "peer-device", signal)
}

fn verified_event_for_device(
    sender: &DeviceIdentity,
    device_id: &str,
    signal: AuthenticatedSessionSignal,
) -> VerifiedSignalingEvent {
    VerifiedSignalingEvent {
        sender: VerifiedSignalingIdentity {
            device_id: DeviceId(device_id.into()),
            key_id: sender.key_id().into(),
            public_key: sender.public_key().to_vec(),
            counter: 1,
            nonce: [7; 16],
            issued_at_ms: NOW,
            expires_at_ms: NOW + 30_000,
        },
        signal,
    }
}

fn controller_snapshot(session_id: &SessionId) -> SessionSnapshot {
    SessionSnapshot {
        session_id: session_id.clone(),
        transport: "webrtc".into(),
        source_device_id: Some(DeviceId("local-device".into())),
        target_device_id: Some(DeviceId("peer-device".into())),
        local_listen_addr: None,
        local_server_name: None,
        local_cert_der_b64: None,
        remote_listen_addr: None,
        remote_server_name: None,
        remote_cert_der_b64: None,
        lifecycle_state: SessionLifecycleState::Created,
        last_error: None,
        sender_active: false,
        receiver_active: false,
    }
}

#[tokio::test]
async fn signed_intent_becomes_attended_authorization_request_and_session_record() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let controller = identity();
    let session_id = SessionId("incoming-session".into());

    mapper
        .apply_authenticated_signal(verified_event(
            &controller,
            AuthenticatedSessionSignal::AuthorizationRequested {
                session_id: session_id.clone(),
                idempotency_key: [4; 16],
                requested_transport: "webrtc".into(),
            },
        ))
        .await
        .unwrap();

    let authorization = app_state
        .session_authorizations
        .snapshot_at(&session_id, NOW + 1)
        .await
        .expect("authorization aggregate");
    assert_eq!(
        authorization.authorization_state,
        mrd_ipc::RemoteAuthorizationState::AwaitingLocalConsent
    );
    assert_eq!(authorization.peer_device_id.0, "peer-device");
    assert_eq!(
        authorization.requested_scopes,
        vec![
            mrd_ipc::RemotePermissionScope::ScreenView,
            mrd_ipc::RemotePermissionScope::InputPointer,
            mrd_ipc::RemotePermissionScope::InputKeyboard,
        ]
    );
    let session = app_state
        .sessions
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .unwrap();
    assert_eq!(session.source_device_id.as_ref().unwrap().0, "peer-device");
    assert_eq!(session.lifecycle_state, SessionLifecycleState::Created);
}

#[tokio::test]
async fn intent_cannot_reuse_a_legacy_session_without_an_authorization_aggregate() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let controller = identity();
    let session_id = SessionId("legacy-collision".into());
    let mut legacy = controller_snapshot(&session_id);
    legacy.source_device_id = Some(DeviceId("peer-device".into()));
    legacy.target_device_id = None;
    app_state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), legacy);

    assert!(mapper
        .apply_authenticated_signal(verified_event(
            &controller,
            AuthenticatedSessionSignal::AuthorizationRequested {
                session_id: session_id.clone(),
                idempotency_key: [4; 16],
                requested_transport: "webrtc".into(),
            },
        ))
        .await
        .is_err());
    assert!(app_state
        .session_authorizations
        .snapshot_at(&session_id, NOW)
        .await
        .is_none());
}

#[tokio::test]
async fn grant_deny_and_close_update_only_the_matching_session_aggregate() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let peer = identity();
    let grant_id = SessionId("grant-session".into());
    let deny_id = SessionId("deny-session".into());
    let close_id = SessionId("close-session".into());
    {
        let mut sessions = app_state.sessions.lock().await;
        sessions.insert(grant_id.clone(), controller_snapshot(&grant_id));
        sessions.insert(deny_id.clone(), controller_snapshot(&deny_id));
        let mut streaming = controller_snapshot(&close_id);
        streaming.lifecycle_state = SessionLifecycleState::Streaming;
        streaming.receiver_active = true;
        sessions.insert(close_id.clone(), streaming);
    }

    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Granted {
                session_id: grant_id.clone(),
                accepted_transport: "webrtc".into(),
                accepted_candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .unwrap();
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Denied {
                session_id: deny_id.clone(),
                reason: ProtocolReasonCode::UnauthorizedRoute,
            },
        ))
        .await
        .unwrap();
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Closed {
                session_id: close_id.clone(),
                reason: ProtocolReasonCode::UnknownSession,
            },
        ))
        .await
        .unwrap();

    let sessions = app_state.sessions.lock().await;
    assert_eq!(
        sessions.get(&grant_id).unwrap().lifecycle_state,
        SessionLifecycleState::Connecting
    );
    assert!(matches!(
        sessions.get(&deny_id).unwrap().lifecycle_state,
        SessionLifecycleState::Failed { .. }
    ));
    assert_eq!(
        sessions.get(&close_id).unwrap().lifecycle_state,
        SessionLifecycleState::Closed
    );
    assert!(!sessions.get(&close_id).unwrap().receiver_active);
}

#[tokio::test]
async fn relay_migration_mapper_requires_the_bound_peer_grant_and_live_session() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let peer = identity();
    let session_id = SessionId("migration-grant-session".into());
    app_state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), controller_snapshot(&session_id));

    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Granted {
                session_id: session_id.clone(),
                accepted_transport: "webrtc".into(),
                accepted_candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .unwrap();
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationOffer {
                session_id: session_id.clone(),
                migration_generation: 1,
                directory_id: "directory-1".into(),
                node_id: "relay-1".into(),
                sdp: "v=0".into(),
                restart_route_token: "1".repeat(64),
                candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .unwrap();
    assert!(mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationAnswer {
                session_id: session_id.clone(),
                migration_generation: 1,
                directory_id: "directory-1".into(),
                node_id: "relay-1".into(),
                sdp: "v=0".into(),
                restart_route_token: "1".repeat(64),
                candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .is_err());
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationOffer {
                session_id: session_id.clone(),
                migration_generation: 2,
                directory_id: "directory-2".into(),
                node_id: "relay-2".into(),
                sdp: "v=0".into(),
                restart_route_token: "2".repeat(64),
                candidate_fingerprints: vec!["b".repeat(64)],
            },
        ))
        .await
        .unwrap();

    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Closed {
                session_id: session_id.clone(),
                reason: ProtocolReasonCode::Conflict,
            },
        ))
        .await
        .unwrap();
    assert!(mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationOffer {
                session_id,
                migration_generation: 2,
                directory_id: "directory-2".into(),
                node_id: "relay-2".into(),
                sdp: "v=0".into(),
                restart_route_token: "2".repeat(64),
                candidate_fingerprints: vec!["b".repeat(64)],
            },
        ))
        .await
        .is_err());
}

#[tokio::test]
async fn outbound_relay_migration_binding_fences_answer_candidate_and_generation() {
    let app_state = Arc::new(AppState::new());
    let mapper = ServiceSignalingMapper::new(Arc::clone(&app_state));
    let peer = identity();
    let session_id = SessionId("outbound-migration-session".into());
    app_state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), controller_snapshot(&session_id));
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Granted {
                session_id: session_id.clone(),
                accepted_transport: "webrtc".into(),
                accepted_candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .unwrap();
    assert!(mapper
        .bind_outbound_relay_migration(
            session_id.clone(),
            "wrong-peer-key".into(),
            1,
            "directory-1".into(),
            "relay-1".into(),
            "1".repeat(64),
        )
        .await
        .is_err());
    mapper
        .bind_outbound_relay_migration(
            session_id.clone(),
            peer.key_id().into(),
            1,
            "directory-1".into(),
            "relay-1".into(),
            "1".repeat(64),
        )
        .await
        .unwrap();
    let committed_candidate_fingerprint = relay_candidate_fingerprint(
        &session_id,
        1,
        "candidate:relay",
        Some("0"),
        Some(0),
        Some("restart-ufrag"),
        &"1".repeat(64),
    );

    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationAnswer {
                session_id: session_id.clone(),
                migration_generation: 1,
                directory_id: "directory-1".into(),
                node_id: "relay-1".into(),
                sdp: "v=0".into(),
                restart_route_token: "1".repeat(64),
                candidate_fingerprints: vec![committed_candidate_fingerprint.clone()],
            },
        ))
        .await
        .unwrap();
    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationCandidate {
                session_id: session_id.clone(),
                migration_generation: 1,
                directory_id: "directory-1".into(),
                node_id: "relay-1".into(),
                candidate: "candidate:relay".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: Some("restart-ufrag".into()),
                restart_route_token: "1".repeat(64),
                candidate_fingerprint: committed_candidate_fingerprint.clone(),
            },
        ))
        .await
        .unwrap();
    assert!(mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationCandidate {
                session_id: session_id.clone(),
                migration_generation: 1,
                directory_id: "mismatched-directory".into(),
                node_id: "relay-1".into(),
                candidate: "candidate:relay".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: Some("restart-ufrag".into()),
                restart_route_token: "1".repeat(64),
                candidate_fingerprint: committed_candidate_fingerprint,
            },
        ))
        .await
        .is_err());
    assert!(mapper
        .bind_outbound_relay_migration(
            session_id.clone(),
            peer.key_id().into(),
            3,
            "directory-3".into(),
            "relay-3".into(),
            "3".repeat(64),
        )
        .await
        .is_err());
    mapper
        .bind_outbound_relay_migration(
            session_id.clone(),
            peer.key_id().into(),
            2,
            "directory-2".into(),
            "relay-2".into(),
            "2".repeat(64),
        )
        .await
        .unwrap();

    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::Granted {
                session_id: session_id.clone(),
                accepted_transport: "webrtc".into(),
                accepted_candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .unwrap();
    assert!(mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationAnswer {
                session_id: session_id.clone(),
                migration_generation: 2,
                directory_id: "directory-2".into(),
                node_id: "relay-2".into(),
                sdp: "v=0".into(),
                restart_route_token: "2".repeat(64),
                candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .is_err());
    mapper
        .bind_outbound_relay_migration(
            session_id,
            peer.key_id().into(),
            1,
            "directory-reset".into(),
            "relay-reset".into(),
            "1".repeat(64),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn signaling_disconnect_changes_health_without_authorizing_or_closing_local_route() {
    let app_state = Arc::new(AppState::new());
    let session_id = SessionId("valid-local-route".into());
    let mut session = controller_snapshot(&session_id);
    session.lifecycle_state = SessionLifecycleState::Streaming;
    session.receiver_active = true;
    app_state
        .sessions
        .lock()
        .await
        .insert(session_id.clone(), session.clone());
    let status = SignalingStatus::default();

    status.note_disconnected(
        NOW,
        1,
        Duration::from_secs(1),
        &SignalingRuntimeError::Disconnected,
    );

    assert_eq!(status.snapshot().state, SignalingConnectionState::Backoff);
    let sessions = app_state.sessions.lock().await;
    let preserved = sessions.get(&session_id).expect("local route preserved");
    assert_eq!(preserved.lifecycle_state, SessionLifecycleState::Streaming);
    assert!(preserved.receiver_active);
    assert_eq!(preserved.target_device_id, session.target_device_id);
    drop(sessions);
    assert!(app_state
        .session_authorizations
        .snapshot_at(&session_id, NOW)
        .await
        .is_none());
}

#[tokio::test]
async fn ipc_runtime_snapshot_exposes_sanitized_signaling_health() {
    let app_state = Arc::new(AppState::new());
    let raw_transport =
        tokio_tungstenite::tungstenite::Error::Io(std::io::Error::other("token=must-not-leak"));
    app_state.signaling_status.note_disconnected(
        NOW,
        3,
        Duration::from_secs(2),
        &SignalingRuntimeError::from(raw_transport),
    );

    let mrd_ipc::IpcResponse::RuntimeSnapshot { snapshot } =
        mrd_service::handlers::session::runtime_snapshot(&app_state).await
    else {
        panic!("expected runtime snapshot")
    };
    assert_eq!(snapshot.signaling.state, "backoff");
    assert_eq!(snapshot.signaling.reconnect_attempt, 3);
    assert_eq!(snapshot.signaling.next_retry_at_ms, Some(NOW + 2_000));
    assert_eq!(
        snapshot.signaling.last_error.as_deref(),
        Some("signaling_transport")
    );
}

#[derive(Debug)]
struct BoundTokenVerifier {
    device_id: DeviceId,
    key_id: String,
}

impl realtime_server::BackendTokenVerifier for BoundTokenVerifier {
    fn verify(
        &self,
        token: &str,
        now_ms: u64,
    ) -> Result<realtime_server::VerifiedBackendToken, realtime_server::BackendTokenError> {
        if token != "backend-token-secret" {
            return Err(realtime_server::BackendTokenError::Invalid);
        }
        Ok(realtime_server::VerifiedBackendToken {
            device_id: self.device_id.clone(),
            device_key_id: self.key_id.clone(),
            role: BackendRole::Agent,
            expires_at_ms: now_ms + 60_000,
        })
    }
}

#[tokio::test]
async fn async_driver_completes_real_websocket_challenge_registration_and_shutdown() {
    let app_state = Arc::new(AppState::new());
    app_state
        .devices
        .lock()
        .await
        .register_if_unregistered(DeviceId("local-device".into()), "Local workstation".into());
    let verifier = Arc::new(BoundTokenVerifier {
        device_id: DeviceId("local-device".into()),
        key_id: app_state
            .device_identities
            .machine_key_id()
            .unwrap()
            .to_owned(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_config = realtime_server::ws::ServerRuntimeConfig {
        bind_addr: address,
        secure_websocket_required: false,
        max_message_bytes: mrd_signal_client::MAX_SIGNAL_MESSAGE_BYTES,
        outbound_queue_capacity: 16,
        prune_interval: Duration::from_secs(10),
        core: realtime_server::CoreConfig {
            server_device_id: DeviceId("signal-server".into()),
            challenge_ttl_ms: 5_000,
            presence_ttl_ms: 3_000,
            route_ttl_ms: 30_000,
            max_connections: 8,
            max_messages_per_window: 64,
            rate_window_ms: 1_000,
        },
    };
    let core = realtime_server::RealtimeCore::new(server_config.core.clone(), verifier).unwrap();
    let router = realtime_server::ws::build_router(realtime_server::ws::RealtimeAppState::new(
        core,
        server_config,
    ));
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let runtime_config = SignalingConfig::new(
        &format!("ws://{address}/ws"),
        DeviceId("local-device".into()),
        "Local workstation",
        BackendRole::Agent,
        "backend-token-secret",
        DeviceId("signal-server".into()),
        None,
        Duration::from_secs(2),
        Duration::from_millis(50),
        Duration::from_millis(200),
    )
    .unwrap();

    let task = spawn(runtime_config, Arc::clone(&app_state)).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if app_state.signaling_status.snapshot().state
                == SignalingConnectionState::Authenticated
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("driver authenticated against real WebSocket server");
    task.shutdown().await;
    assert_eq!(
        app_state.signaling_status.snapshot().state,
        SignalingConnectionState::Stopped
    );
    server.abort();
}
