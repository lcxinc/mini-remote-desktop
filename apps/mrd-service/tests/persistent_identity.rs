use mrd_application::ports::{SessionLifecycleState, SessionSnapshot};
use mrd_identity::DeviceIdentity;
use mrd_ipc::{
    AuditEventsQueryV2, AuditLogQuery, ConsentDecision, ConsentResponse, DecimalU64, IpcRequest,
    IpcResponse, RemoteAccessMode, RemoteAuthorizationState, RemotePermissionScope,
    RemoteReasonCode, TrustedDeviceState,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::ipc_server::IpcServer;
use mrd_service::{
    app_state::AppState,
    session_authorization::{VerifiedIncomingAuthorizationRequest, VerifiedSessionGrant},
    wan_session::{
        coordinator::{
            NoopWanSessionCleanup, SystemWanSessionClock, WanSessionCoordinator,
            WanSessionCoordinatorConfig,
        },
        model::{
            WanSessionFailure, WanSessionIdentity, WanSessionPhase, WanSessionRole, WanSessionState,
        },
    },
};
use mrd_store_sqlite::{AuditDraft, SecretBytes, SecretProtector, TrustState};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

struct SensitiveBuffer(Vec<u8>);

impl Drop for SensitiveBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct TestSecretProtector {
    key: [u8; 32],
}

impl Drop for TestSecretProtector {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SecretProtector for TestSecretProtector {
    fn protect(&self, purpose: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
            .map_err(|_| "invalid test protector key".to_owned())?;
        let key = aead::LessSafeKey::new(unbound);
        let mut nonce_bytes = [0_u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| "test protector nonce generation failed".to_owned())?;
        let mut ciphertext = SensitiveBuffer(plaintext.to_vec());
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_bytes),
            aead::Aad::from(purpose),
            &mut ciphertext.0,
        )
        .map_err(|_| "test protector encryption failed".to_owned())?;
        let mut protected = nonce_bytes.to_vec();
        protected.extend_from_slice(&ciphertext.0);
        Ok(protected)
    }

    fn unprotect(&self, purpose: &[u8], protected: &[u8]) -> Result<SecretBytes, String> {
        if protected.len() < 12 + aead::AES_256_GCM.tag_len() {
            return Err("protected secret is truncated".to_owned());
        }
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes.copy_from_slice(&protected[..12]);
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
            .map_err(|_| "invalid test protector key".to_owned())?;
        let key = aead::LessSafeKey::new(unbound);
        let mut plaintext = SensitiveBuffer(protected[12..].to_vec());
        let plaintext_len = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce_bytes),
                aead::Aad::from(purpose),
                &mut plaintext.0,
            )
            .map_err(|_| "protected secret authentication failed".to_owned())?
            .len();
        plaintext.0.truncate(plaintext_len);
        Ok(SecretBytes::new(std::mem::take(&mut plaintext.0)))
    }
}

fn temp_db() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mrd-service-persistent-identity-{}-{unique}.sqlite",
        std::process::id()
    ))
}

fn audit(timestamp_ms: u64, action: &str, peer_key_id: &str) -> AuditDraft {
    AuditDraft {
        timestamp_ms,
        action: action.to_owned(),
        outcome: "allowed".to_owned(),
        session_id: None,
        actor_device_id: Some("local-service".to_owned()),
        peer_device_id: None,
        transport_kind: None,
        reason_code: None,
        details: BTreeMap::from([("peer_key_id".to_owned(), peer_key_id.to_owned())]),
    }
}

fn remove_sqlite_files(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.to_string_lossy())),
        PathBuf::from(format!("{}-shm", path.to_string_lossy())),
        PathBuf::from(format!("{}-journal", path.to_string_lossy())),
    ] {
        match std::fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove {}: {error}", candidate.display()),
        }
    }
    assert!(!path.exists(), "temporary SQLite database was not removed");
}

fn peer_authorization_request(
    session_id: &str,
    peer_key_id: &str,
) -> VerifiedIncomingAuthorizationRequest {
    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    VerifiedIncomingAuthorizationRequest {
        session_id: SessionId(session_id.to_owned()),
        peer_device_id: DeviceId("trusted-controller".to_owned()),
        peer_key_id: peer_key_id.to_owned(),
        peer_key_epoch: 1,
        access_mode: RemoteAccessMode::Attended,
        requested_scopes: vec![RemotePermissionScope::ScreenView],
        peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
        machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
        runtime_capabilities: vec![RemotePermissionScope::ScreenView],
        transport_kind: "quic".to_owned(),
        request_nonce: [23; 16],
        created_at_ms,
        expires_at_ms: created_at_ms + 30_000,
    }
}

async fn install_peer_grant(
    state: &AppState,
    request: VerifiedIncomingAuthorizationRequest,
) -> SessionId {
    let session_id = request.session_id.clone();
    let created_at_ms = request.created_at_ms;
    state
        .session_authorizations
        .begin_verified_incoming(request)
        .await
        .expect("pending trusted peer authorization");
    let approved = state
        .session_authorizations
        .respond_to_consent(
            ConsentResponse {
                session_id: session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
            created_at_ms + 1,
        )
        .await
        .expect("approved peer authorization");
    state
        .session_authorizations
        .install_verified_grant(
            VerifiedSessionGrant {
                grant_id: format!("grant-{}", session_id.0),
                session_id: session_id.clone(),
                granted_scopes: approved.granted_scopes,
                issued_at_ms: created_at_ms + 2,
                expires_at_ms: created_at_ms + 20_000,
                policy_revision: 1,
                route_constraint: "quic".to_owned(),
                transport_fingerprint_sha256: [31; 32],
            },
            created_at_ms + 2,
        )
        .await
        .expect("installed peer grant");
    session_id
}

#[test]
fn machine_identity_trust_and_audit_survive_service_restarts() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x31; 32] });
    let peer = DeviceIdentity::generate(&SystemRandom::new()).expect("peer identity");
    let peer_key_id = peer.key_id().to_owned();

    let first = AppState::open_persistent(&path, protector.clone()).expect("first service state");
    let machine_key_id = first
        .device_identities
        .machine_key_id()
        .expect("persistent machine identity")
        .to_owned();
    assert_eq!(first.device_identities.machine_key_epoch(), Some(1));
    assert!(matches!(
        first.device_identities.upsert(
            mrd_proto::DeviceId("unauthenticated-device".to_owned()),
            Some("unverified-fingerprint".to_owned()),
            "trusted",
        ),
        Err(mrd_service::app_state::DeviceIdentityRegistryError::AuthenticatedPeerRequired)
    ));
    let (approved, approval_audit) = first
        .device_identities
        .approve_authenticated_peer(
            &peer_key_id,
            peer.public_key(),
            1,
            audit(1, "trust.approved", &peer_key_id),
        )
        .expect("approve authenticated peer");
    assert_eq!(approved.state, TrustState::Trusted);
    assert_eq!(approval_audit.sequence, 1);
    first
        .audit_log
        .record(
            "service.restart_marker",
            "success",
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("append service audit");
    drop(first);

    let second = AppState::open_persistent(&path, protector.clone()).expect("reopened state");
    assert_eq!(
        second.device_identities.machine_key_id(),
        Some(machine_key_id.as_str())
    );
    assert_eq!(second.device_identities.machine_key_epoch(), Some(1));
    assert_eq!(
        second
            .device_identities
            .trusted_records(true)
            .expect("persisted trust"),
        vec![approved.clone()]
    );
    let events = second
        .audit_log
        .query(&AuditLogQuery {
            session_id: None,
            action: None,
            limit: Some(10),
        })
        .expect("persisted audit");
    assert_eq!(
        events
            .iter()
            .map(|event| (event.id, event.action.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "trust.approved"), (2, "service.restart_marker")]
    );

    let revoked = second
        .device_identities
        .transition_authenticated_peer(
            &peer_key_id,
            1,
            TrustState::Revoked,
            audit(3, "trust.revoked", &peer_key_id),
        )
        .expect("revoke authenticated peer")
        .into_applied()
        .expect("revocation should apply");
    assert_eq!(revoked.record.state, TrustState::Revoked);
    assert_eq!(revoked.record.revision, 2);
    assert_eq!(revoked.audit.sequence, 3);
    drop(second);

    let third = AppState::open_persistent(&path, protector).expect("second reopened state");
    let persisted = third
        .device_identities
        .trusted_records(true)
        .expect("revoked trust");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].state, TrustState::Revoked);
    assert_eq!(persisted[0].revision, 2);
    let events = third
        .audit_log
        .query(&AuditLogQuery {
            session_id: None,
            action: None,
            limit: Some(10),
        })
        .expect("audit after second restart");
    assert_eq!(events.last().map(|event| event.id), Some(3));
    assert_eq!(
        events.last().map(|event| event.action.as_str()),
        Some("trust.revoked")
    );

    drop(third);
    let wrong_protector: Arc<dyn SecretProtector> =
        Arc::new(TestSecretProtector { key: [0x32; 32] });
    assert!(AppState::open_persistent(&path, wrong_protector).is_err());
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn persistent_service_rejects_legacy_pairing_and_audits_the_denial() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x41; 32] });
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    let server = IpcServer::new(state.clone());

    let response = server
        .handle_request(IpcRequest::PairDevice {
            device_id: DeviceId("legacy-peer".to_owned()),
            certificate_fingerprint: Some("unverified-fingerprint".to_owned()),
        })
        .await;
    assert!(matches!(
        response,
        IpcResponse::Error { ref code, .. } if code == "E_AUTHENTICATED_PEER_REQUIRED"
    ));

    let events = state
        .audit_log
        .query(&AuditLogQuery {
            session_id: None,
            action: Some("device.pair".to_owned()),
            limit: Some(10),
        })
        .expect("denial audit");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(
        events[0].reason.as_deref(),
        Some("E_AUTHENTICATED_PEER_REQUIRED")
    );

    drop(server);
    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn persistent_trust_can_be_listed_and_revoked_through_secure_ipc() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x51; 32] });
    let peer = DeviceIdentity::generate(&SystemRandom::new()).expect("peer identity");
    let peer_key_id = peer.key_id().to_owned();
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    state
        .device_identities
        .approve_authenticated_peer(
            &peer_key_id,
            peer.public_key(),
            1,
            audit(1, "trust.approved", &peer_key_id),
        )
        .expect("seed authenticated trust");
    let server = IpcServer::new(state.clone());

    assert!(matches!(
        server
            .handle_request(IpcRequest::RegisterDevice {
                device_id: DeviceId("l".repeat(300)),
                device_name: "Long local identity".to_owned(),
            })
            .await,
        IpcResponse::DeviceRegistered { .. }
    ));

    let listed = server
        .handle_request(IpcRequest::ListTrustedDevices {
            include_revoked: false,
        })
        .await;
    let IpcResponse::TrustedDeviceList { devices } = listed else {
        panic!("expected durable trust list");
    };
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].peer_key_id, peer_key_id);
    assert_eq!(devices[0].state, TrustedDeviceState::Trusted);
    assert!(devices[0].permission_ceiling.is_empty());

    let revoked = server
        .handle_request(IpcRequest::RevokeTrustedDevice {
            peer_key_id: peer.key_id().to_owned(),
            expected_trust_revision: DecimalU64::new(1),
        })
        .await;
    let IpcResponse::TrustedDeviceUpdated { device } = revoked else {
        panic!("expected durable trust update");
    };
    assert_eq!(device.state, TrustedDeviceState::Revoked);
    assert_eq!(device.trust_revision, DecimalU64::new(2));
    let revoke_audit = state
        .audit_log
        .query(&AuditLogQuery {
            session_id: None,
            action: Some("trust.revoked".to_owned()),
            limit: Some(10),
        })
        .expect("revoke audit");
    assert_eq!(revoke_audit.len(), 1);
    assert!(revoke_audit[0]
        .actor_device_id
        .as_ref()
        .is_some_and(|value| value.0.starts_with("sha256:")));

    let active = server
        .handle_request(IpcRequest::ListTrustedDevices {
            include_revoked: false,
        })
        .await;
    assert!(matches!(
        active,
        IpcResponse::TrustedDeviceList { ref devices } if devices.is_empty()
    ));

    drop(server);
    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn invalid_audit_query_does_not_poison_health_and_long_ids_are_redacted() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x61; 32] });
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    let server = IpcServer::new(state.clone());
    let long_device_id = DeviceId("d".repeat(300));

    let registered = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: long_device_id,
            device_name: "Long identifier".to_owned(),
        })
        .await;
    assert!(matches!(registered, IpcResponse::DeviceRegistered { .. }));
    let events = state
        .audit_log
        .query(&AuditLogQuery {
            session_id: None,
            action: Some("device.register".to_owned()),
            limit: Some(10),
        })
        .expect("bounded durable audit");
    assert_eq!(events.len(), 1);
    assert!(events[0]
        .actor_device_id
        .as_ref()
        .is_some_and(|value| value.0.starts_with("sha256:")));

    state
        .audit_log
        .record(
            "session.start",
            "error",
            Some(SessionId("long-transport-session".to_owned())),
            None,
            Some(DeviceId("peer".to_owned())),
            Some("t".repeat(65)),
            Some("E_PREFLIGHT".to_owned()),
            Vec::new(),
        )
        .expect("long transport must not poison durable audit");
    let transport_events = state
        .audit_log
        .query(&AuditLogQuery {
            session_id: Some(SessionId("long-transport-session".to_owned())),
            action: Some("session.start".to_owned()),
            limit: Some(10),
        })
        .expect("bounded transport audit");
    assert_eq!(transport_events.len(), 1);
    assert!(transport_events[0]
        .transport_kind
        .as_ref()
        .is_some_and(|value| value.len() <= 64 && value.starts_with("sha256:")));
    let invalid = server
        .handle_request(IpcRequest::AuditLog {
            query: AuditLogQuery {
                session_id: None,
                action: Some("x".repeat(129)),
                limit: Some(10),
            },
        })
        .await;
    assert!(matches!(
        invalid,
        IpcResponse::Error { ref code, .. } if code == "E_INVALID_AUDIT_QUERY"
    ));
    assert!(state.security_is_healthy());

    drop(server);
    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn runtime_store_corruption_blocks_mutation_and_latches_unhealthy() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x71; 32] });
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    let server = IpcServer::new(state.clone());
    let original_device = DeviceId("original-device".to_owned());
    assert!(matches!(
        server
            .handle_request(IpcRequest::RegisterDevice {
                device_id: original_device.clone(),
                device_name: "Original".to_owned(),
            })
            .await,
        IpcResponse::DeviceRegistered { .. }
    ));
    let active_session = SessionId("must-stop-after-corruption".to_owned());
    state.sessions.lock().await.insert(
        active_session.clone(),
        SessionSnapshot {
            session_id: active_session.clone(),
            transport: "quic".to_owned(),
            source_device_id: Some(original_device.clone()),
            target_device_id: Some(DeviceId("peer-device".to_owned())),
            local_listen_addr: None,
            local_server_name: None,
            local_cert_der_b64: None,
            remote_listen_addr: None,
            remote_server_name: None,
            remote_cert_der_b64: None,
            lifecycle_state: SessionLifecycleState::Streaming,
            last_error: None,
            sender_active: true,
            receiver_active: true,
        },
    );

    let connection = rusqlite::Connection::open(&path).expect("tamper connection");
    connection
        .execute(
            "UPDATE audit_events SET outcome = 'tampered' WHERE sequence = 1",
            [],
        )
        .expect("tamper audit row");
    drop(connection);

    let stopped = server
        .handle_request(IpcRequest::StopSession {
            session_id: active_session.clone(),
        })
        .await;
    assert!(matches!(stopped, IpcResponse::SessionStopped { .. }));
    let sessions = state.sessions.lock().await;
    let stopped_snapshot = sessions
        .get(&active_session)
        .expect("closed session snapshot");
    assert!(!stopped_snapshot.sender_active);
    assert!(!stopped_snapshot.receiver_active);
    drop(sessions);
    let blocked = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: DeviceId("must-not-register".to_owned()),
            device_name: "Blocked".to_owned(),
        })
        .await;
    assert!(matches!(
        blocked,
        IpcResponse::Error { ref code, .. } if code == "E_SECURITY_STORE_UNAVAILABLE"
    ));
    assert_eq!(
        state
            .devices
            .lock()
            .await
            .get_local_device()
            .map(|value| &value.0),
        Some(&original_device)
    );
    let health = server.handle_request(IpcRequest::ServiceHealth).await;
    assert!(matches!(
        health,
        IpcResponse::ServiceHealth { ref status } if !status.healthy
    ));

    drop(server);
    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn audit_events_v2_never_reports_a_tampered_chain_as_verified() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x73; 32] });
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    state
        .audit_log
        .record(
            "session.authorization_grant",
            "allowed",
            Some(SessionId("tampered-audit-session".to_string())),
            None,
            Some(DeviceId("tampered-audit-peer".to_string())),
            Some("quic".to_string()),
            None,
            Vec::new(),
        )
        .expect("persist audit event");

    let connection = rusqlite::Connection::open(&path).expect("tamper connection");
    connection
        .execute(
            "UPDATE audit_events SET outcome = 'tampered' WHERE sequence = 1",
            [],
        )
        .expect("tamper audit row");
    drop(connection);

    let response = IpcServer::new(state.clone())
        .handle_request(IpcRequest::GetAuditEventsV2 {
            query: AuditEventsQueryV2 {
                after_sequence: Some(DecimalU64::new(0)),
                limit: 16,
                session_id: None,
                action: None,
                outcome: None,
                peer_device_id: None,
            },
        })
        .await;
    assert!(matches!(
        response,
        IpcResponse::Error { ref code, .. } if code == "E_SECURITY_STORE_UNAVAILABLE"
    ));
    assert!(!state.security_is_healthy());

    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn audit_events_v2_pages_persisted_events_after_reopen() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x74; 32] });
    let session_id = SessionId("persisted-audit-page".to_string());
    let peer_device_id = DeviceId("persisted-audit-peer".to_string());
    {
        let state = AppState::open_persistent(&path, protector.clone())
            .expect("initial persistent service security state");
        for outcome in ["pending", "allowed"] {
            state
                .audit_log
                .record(
                    "session.authorization_decision",
                    outcome,
                    Some(session_id.clone()),
                    Some(DeviceId("persisted-local-device".to_string())),
                    Some(peer_device_id.clone()),
                    Some("quic".to_string()),
                    None,
                    Vec::new(),
                )
                .expect("persist typed audit source event");
        }
    }

    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("reopened persistent service state"),
    );
    let response = IpcServer::new(state)
        .handle_request(IpcRequest::GetAuditEventsV2 {
            query: AuditEventsQueryV2 {
                after_sequence: Some(DecimalU64::new(0)),
                limit: 1,
                session_id: Some(session_id.clone()),
                action: Some("session.authorization_decision".to_string()),
                outcome: None,
                peer_device_id: Some(peer_device_id),
            },
        })
        .await;
    let IpcResponse::AuditEventsV2 { page } = response else {
        panic!("expected persisted audit page, got {response:?}");
    };
    assert!(page.chain_verified);
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].session_id.as_ref(), Some(&session_id));
    assert_eq!(page.events[0].outcome, "pending");
    assert_eq!(
        page.events[0].transport_kind,
        Some(mrd_ipc::RemoteRouteKind::LanQuic)
    );
    assert!(page.has_more);
    assert_eq!(page.next_after_sequence, Some(page.events[0].sequence));

    remove_sqlite_files(&path);
}

async fn assert_applied_trust_transition_revokes_authorizations(suspend: bool) {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x81; 32] });
    let peer = DeviceIdentity::generate(&SystemRandom::new()).expect("peer identity");
    let peer_key_id = peer.key_id().to_owned();
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    state
        .device_identities
        .approve_authenticated_peer(
            &peer_key_id,
            peer.public_key(),
            1,
            audit(1, "trust.approved", &peer_key_id),
        )
        .expect("trusted peer approval");

    let pending_id = state
        .session_authorizations
        .begin_verified_incoming(peer_authorization_request(
            "trust-transition-pending",
            &peer_key_id,
        ))
        .await
        .expect("pending peer authorization")
        .session_id;
    let active_id = install_peer_grant(
        state.as_ref(),
        peer_authorization_request("trust-transition-active", &peer_key_id),
    )
    .await;
    state.sessions.lock().await.insert(
        active_id.clone(),
        SessionSnapshot {
            session_id: active_id.clone(),
            transport: "quic".to_owned(),
            source_device_id: Some(DeviceId("trusted-controller".to_owned())),
            target_device_id: None,
            local_listen_addr: None,
            local_server_name: None,
            local_cert_der_b64: None,
            remote_listen_addr: None,
            remote_server_name: None,
            remote_cert_der_b64: None,
            lifecycle_state: SessionLifecycleState::Streaming,
            last_error: None,
            sender_active: true,
            receiver_active: false,
        },
    );
    let media_task = tokio::spawn(std::future::pending::<()>());
    state
        .media_tasks
        .lock()
        .await
        .register(active_id.clone(), media_task.abort_handle());

    let request = if suspend {
        IpcRequest::SuspendTrustedDevice {
            peer_key_id: peer_key_id.clone(),
            expected_trust_revision: DecimalU64::new(1),
        }
    } else {
        IpcRequest::RevokeTrustedDevice {
            peer_key_id: peer_key_id.clone(),
            expected_trust_revision: DecimalU64::new(1),
        }
    };
    let response = IpcServer::new(state.clone()).handle_request(request).await;
    let IpcResponse::TrustedDeviceUpdated { device } = response else {
        panic!("expected applied trust transition, got {response:?}");
    };
    assert_eq!(
        device.state,
        if suspend {
            TrustedDeviceState::Suspended
        } else {
            TrustedDeviceState::Revoked
        }
    );

    for session_id in [&pending_id, &active_id] {
        let snapshot = state
            .session_authorizations
            .snapshot(session_id)
            .await
            .expect("revoked authorization retained");
        assert_eq!(
            snapshot.authorization_state,
            RemoteAuthorizationState::Revoked
        );
        assert_eq!(
            snapshot.failure.as_ref().map(|failure| failure.code),
            Some(RemoteReasonCode::GrantRevoked)
        );
        assert!(state
            .session_authorizations
            .active_grant(session_id)
            .await
            .is_none());
    }
    tokio::task::yield_now().await;
    assert!(
        media_task.is_finished(),
        "revoked media task must be aborted"
    );
    let sessions = state.sessions.lock().await;
    let closed = sessions
        .get(&active_id)
        .expect("terminated session projection retained");
    assert_eq!(closed.lifecycle_state, SessionLifecycleState::Closed);
    assert!(!closed.sender_active);
    drop(sessions);

    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn suspending_trusted_peer_via_ipc_revokes_active_and_pending_authorizations() {
    assert_applied_trust_transition_revokes_authorizations(true).await;
}

#[tokio::test]
async fn revoking_trusted_peer_via_ipc_revokes_active_and_pending_authorizations() {
    assert_applied_trust_transition_revokes_authorizations(false).await;
}

#[tokio::test]
async fn revoking_trusted_peer_via_ipc_terminalizes_the_matching_wan_workflow() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x83; 32] });
    let peer = DeviceIdentity::generate(&SystemRandom::new()).expect("peer identity");
    let peer_key_id = peer.key_id().to_owned();
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    state
        .device_identities
        .approve_authenticated_peer(
            &peer_key_id,
            peer.public_key(),
            1,
            audit(1, "trust.approved", &peer_key_id),
        )
        .expect("trusted peer approval");
    let mut request = peer_authorization_request("trust-transition-wan", &peer_key_id);
    request.transport_kind = "webrtc_relay".to_owned();
    let session_id = request.session_id.clone();
    let deadline_unix_ms = request.expires_at_ms;
    state
        .session_authorizations
        .begin_verified_incoming(request)
        .await
        .expect("pending WAN peer authorization");
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            Arc::new(NoopWanSessionCleanup),
            Arc::new(SystemWanSessionClock),
        )
        .expect("WAN coordinator"),
    );
    coordinator
        .begin(WanSessionState::new(
            WanSessionRole::Target,
            WanSessionIdentity::new(
                session_id.clone(),
                DeviceId("trusted-controller".to_owned()),
                DeviceId("local-target".to_owned()),
                peer_key_id.clone(),
                "b".repeat(64),
                deadline_unix_ms,
            )
            .expect("WAN target identity"),
        ))
        .await
        .expect("begin WAN target workflow");
    state
        .bind_wan_session_coordinator(coordinator.clone())
        .expect("bind WAN coordinator");

    let response = IpcServer::new(state.clone())
        .handle_request(IpcRequest::RevokeTrustedDevice {
            peer_key_id,
            expected_trust_revision: DecimalU64::new(1),
        })
        .await;
    assert!(matches!(response, IpcResponse::TrustedDeviceUpdated { .. }));
    let workflow = coordinator
        .snapshot(&session_id)
        .await
        .expect("retained WAN terminal state");
    assert_eq!(workflow.phase(), WanSessionPhase::Failed);
    assert_eq!(workflow.failure(), Some(WanSessionFailure::Cancelled));

    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn trust_revoke_fences_pending_outgoing_wan_without_cleaning_a_colliding_lan_projection() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x84; 32] });
    let peer = DeviceIdentity::generate(&SystemRandom::new()).expect("peer identity");
    let peer_key_id = peer.key_id().to_owned();
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    state
        .device_identities
        .approve_authenticated_peer(
            &peer_key_id,
            peer.public_key(),
            1,
            audit(1, "trust.approved", &peer_key_id),
        )
        .expect("trusted peer approval");

    let mut proven_request =
        peer_authorization_request("trust-revoke-proven-wan-device", &peer_key_id);
    proven_request.peer_device_id = DeviceId("pending-wan-target".to_owned());
    proven_request.transport_kind = "webrtc_relay".to_owned();
    state
        .session_authorizations
        .begin_outgoing(proven_request)
        .await
        .expect("exact peer key proves the pending WAN device association");

    let mut request = peer_authorization_request("trust-revoke-pending-wan", &peer_key_id);
    request.peer_device_id = DeviceId("pending-wan-target".to_owned());
    request.peer_key_id = format!("pending_authenticated_peer:{}", request.peer_device_id.0);
    request.transport_kind = "webrtc_relay".to_owned();
    let session_id = request.session_id.clone();
    state
        .session_authorizations
        .begin_outgoing(request)
        .await
        .expect("pending outgoing WAN authorization");

    state.sessions.lock().await.insert(
        session_id.clone(),
        SessionSnapshot {
            session_id: session_id.clone(),
            transport: "quic".to_owned(),
            source_device_id: Some(DeviceId("unrelated-lan-controller".to_owned())),
            target_device_id: Some(DeviceId("unrelated-lan-target".to_owned())),
            local_listen_addr: None,
            local_server_name: None,
            local_cert_der_b64: None,
            remote_listen_addr: None,
            remote_server_name: None,
            remote_cert_der_b64: None,
            lifecycle_state: SessionLifecycleState::Streaming,
            last_error: None,
            sender_active: true,
            receiver_active: false,
        },
    );
    let media_task = tokio::spawn(std::future::pending::<()>());
    state
        .media_tasks
        .lock()
        .await
        .register(session_id.clone(), media_task.abort_handle());

    let response = IpcServer::new(Arc::clone(&state))
        .handle_request(IpcRequest::RevokeTrustedDevice {
            peer_key_id,
            expected_trust_revision: DecimalU64::new(1),
        })
        .await;
    assert!(matches!(response, IpcResponse::TrustedDeviceUpdated { .. }));
    let authorization = state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .expect("pending WAN authorization retained as terminal evidence");
    assert_eq!(
        authorization.authorization_state,
        RemoteAuthorizationState::Revoked
    );
    assert_eq!(
        authorization.failure.as_ref().map(|failure| failure.code),
        Some(RemoteReasonCode::GrantRevoked)
    );
    let sessions = state.sessions.lock().await;
    let unrelated_lan = sessions
        .get(&session_id)
        .expect("colliding LAN projection must remain present");
    assert_eq!(
        unrelated_lan.lifecycle_state,
        SessionLifecycleState::Streaming
    );
    assert!(unrelated_lan.sender_active);
    drop(sessions);
    assert_eq!(state.media_tasks.lock().await.active_count(&session_id), 1);

    media_task.abort();
    let _ = media_task.await;
    drop(state);
    remove_sqlite_files(&path);
}

#[tokio::test]
async fn rejected_trust_transition_leaves_existing_authorization_active() {
    let path = temp_db();
    let protector: Arc<dyn SecretProtector> = Arc::new(TestSecretProtector { key: [0x82; 32] });
    let peer = DeviceIdentity::generate(&SystemRandom::new()).expect("peer identity");
    let peer_key_id = peer.key_id().to_owned();
    let state = Arc::new(
        AppState::open_persistent(&path, protector).expect("persistent service security state"),
    );
    state
        .device_identities
        .approve_authenticated_peer(
            &peer_key_id,
            peer.public_key(),
            1,
            audit(1, "trust.approved", &peer_key_id),
        )
        .expect("trusted peer approval");
    let active_id = install_peer_grant(
        state.as_ref(),
        peer_authorization_request("rejected-trust-transition", &peer_key_id),
    )
    .await;

    let response = IpcServer::new(state.clone())
        .handle_request(IpcRequest::RevokeTrustedDevice {
            peer_key_id,
            expected_trust_revision: DecimalU64::new(99),
        })
        .await;
    assert!(matches!(
        response,
        IpcResponse::Error { ref code, .. } if code == "E_TRUST_REVISION_MISMATCH"
    ));
    let still_granted = state
        .session_authorizations
        .snapshot(&active_id)
        .await
        .expect("authorization retained");
    assert_eq!(
        still_granted.authorization_state,
        RemoteAuthorizationState::Granted
    );
    assert!(state
        .session_authorizations
        .active_grant(&active_id)
        .await
        .is_some());

    drop(state);
    remove_sqlite_files(&path);
}
