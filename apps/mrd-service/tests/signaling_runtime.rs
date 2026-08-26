use mrd_application::{
    AuthenticatedSessionSignal, AuthenticatedSessionSignalPort, SessionLifecycleState,
    SessionSnapshot, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_proto::{BackendRole, DeviceId, SessionId};
use mrd_service::{
    signaling::{
        spawn, InboundDisposition, ServiceSignalingMapper, SignalingConfig,
        SignalingConnectionState, SignalingRuntimeCore, SignalingStatus,
    },
    AppState,
};
use mrd_signal_proto::{
    AuthClaims, AuthenticatedSignalMessage, ProtocolReasonCode, Registered, RegisteredPayload,
    RelayMigrationOffer, RelayMigrationOfferPayload, ServerChallenge, SessionIntent,
    SessionIntentPayload, SignalEnvelope,
};
use ring::rand::SystemRandom;
use std::{collections::BTreeSet, sync::Arc, time::Duration};

const NOW: u64 = 1_000_000;

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
    SignalingConfig::new(
        "ws://127.0.0.1:9532/realtime",
        DeviceId("local-device".into()),
        "Local workstation",
        BackendRole::Agent,
        "backend-token-secret",
        DeviceId("signal-server".into()),
        Some(server.key_id().into()),
        Duration::from_secs(5),
        Duration::from_millis(250),
        Duration::from_secs(8),
    )
    .unwrap()
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
    Registered::sign(
        server,
        RegisteredPayload {
            claims: claims(server, "signal-server", "local-device", counter, 31),
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
    runtime.note_connection_failure(NOW, "connection refused");
    assert_eq!(runtime.reconnect_delay(), Duration::from_millis(250));
    runtime.note_connection_failure(NOW + 500, "connection refused");
    assert_eq!(runtime.reconnect_delay(), Duration::from_millis(500));
    for attempt in 0..16 {
        runtime.note_connection_failure(NOW + 1_000 + attempt, "offline");
    }
    assert_eq!(runtime.reconnect_delay(), Duration::from_secs(8));
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.state, SignalingConnectionState::Backoff);
    assert!(snapshot.reconnect_attempt >= 2);
    assert_eq!(snapshot.last_error.as_deref(), Some("offline"));
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
    runtime.note_connection_failure(NOW + 1, "restart");
    assert!(runtime
        .accept_registered(registered(&replacement_server, 1), NOW + 2)
        .is_err());
}

#[test]
fn duplicate_signed_intent_is_idempotent_but_tampering_is_rejected() {
    let server = identity();
    let local = identity();
    let controller = identity();
    let mut runtime = SignalingRuntimeCore::new(config(&server), local);
    runtime
        .accept_registered(registered(&server, 1), NOW)
        .unwrap();
    let intent = SessionIntent::sign(
        &controller,
        SessionIntentPayload {
            claims: claims(&controller, "controller-1", "local-device", 1, 41),
            session_id: SessionId("session-intent".into()),
            idempotency_key: [8; 16],
            target_device_id: DeviceId("local-device".into()),
            requested_transport: "webrtc".into(),
        },
    )
    .unwrap();
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::SessionIntent(intent));

    let InboundDisposition::Applied(applied) =
        runtime.handle_inbound(envelope.clone(), NOW + 1).unwrap()
    else {
        panic!("expected applied intent")
    };
    assert!(matches!(
        applied.signal,
        AuthenticatedSessionSignal::AuthorizationRequested { .. }
    ));
    assert_eq!(
        runtime.handle_inbound(envelope.clone(), NOW + 2).unwrap(),
        InboundDisposition::Duplicate
    );

    let mut tampered = envelope;
    let AuthenticatedSignalMessage::SessionIntent(intent) = &mut tampered.message else {
        unreachable!()
    };
    intent.payload.requested_transport = "quic_quinn".into();
    assert!(runtime.handle_inbound(tampered, NOW + 3).is_err());
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

fn verified_event(
    sender: &DeviceIdentity,
    signal: AuthenticatedSessionSignal,
) -> VerifiedSignalingEvent {
    VerifiedSignalingEvent {
        sender: VerifiedSignalingIdentity {
            device_id: DeviceId("peer-device".into()),
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
                candidate_fingerprints: vec!["a".repeat(64)],
            },
        ))
        .await
        .is_err());
    assert!(mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationOffer {
                session_id: session_id.clone(),
                migration_generation: 2,
                directory_id: "directory-2".into(),
                node_id: "relay-2".into(),
                sdp: "v=0".into(),
                candidate_fingerprints: vec!["b".repeat(64)],
            },
        ))
        .await
        .is_err());

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
                candidate_fingerprints: vec!["a".repeat(64)],
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
        )
        .await
        .unwrap();

    mapper
        .apply_authenticated_signal(verified_event(
            &peer,
            AuthenticatedSessionSignal::RelayMigrationAnswer {
                session_id: session_id.clone(),
                migration_generation: 1,
                directory_id: "directory-1".into(),
                node_id: "relay-1".into(),
                sdp: "v=0".into(),
                candidate_fingerprints: vec!["a".repeat(64)],
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
                candidate_fingerprint: "a".repeat(64),
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
                candidate_fingerprint: "a".repeat(64),
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

    status.note_disconnected(NOW, 1, Duration::from_secs(1), "network unavailable");

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
    app_state.signaling_status.note_disconnected(
        NOW,
        3,
        Duration::from_secs(2),
        "token=must-not-leak",
    );

    let mrd_ipc::IpcResponse::RuntimeSnapshot { snapshot } =
        mrd_service::handlers::session::runtime_snapshot(&app_state).await
    else {
        panic!("expected runtime snapshot")
    };
    assert_eq!(snapshot.signaling.state, "backoff");
    assert_eq!(snapshot.signaling.reconnect_attempt, 3);
    assert_eq!(snapshot.signaling.next_retry_at_ms, Some(NOW + 2_000));
    assert!(!snapshot
        .signaling
        .last_error
        .as_deref()
        .unwrap()
        .contains("must-not-leak"));
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

    let task = spawn(runtime_config, Arc::clone(&app_state));
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
