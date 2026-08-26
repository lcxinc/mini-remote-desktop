use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use mrd_application::ports::{
    TransportEnvelope, TransportLane, TransportMuxPort, VideoEnvelopeMetadata,
};
use mrd_application::{
    AuthenticatedSessionSignal, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_proto::SessionId;
use mrd_relay_control::{
    RelayDirectoryCandidate, RelayDirectoryEndpoint, RelayDirectoryPayload,
    RelayDirectoryTransport, RelayReservation, SignedRelayDirectory,
    RELAY_DIRECTORY_FORMAT_VERSION,
};
use mrd_service::{
    relay::{
        relay_peer_digest, RelayAccessBackend, RelayAccessContext, RelayBackendError,
        RelayClientConfig, RelayClock, RelayConnectionHealth, RelayDirectoryClient,
        RelayFailoverConfigError, RelayFailoverCoordinator, RelayInputBarrier,
        RelayMigrationAttempt, RelayMigrationCommit, RelayMigrationExecutor, RelayMigrationFailure,
        RelayMigrationFailureCode, RelayMigrationOffer, RelayMigrationPhase, RelayRecoveryOutcome,
        RelayTerminalSecurityReason, ServiceRelayMigrationExecutor,
    },
    transports::{memory::MemoryTransportMux, TransportMuxConfig},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_000_000;

#[test]
fn production_migration_executor_rejects_unbounded_negotiation_deadlines() {
    let app_state = Arc::new(mrd_service::AppState::new());
    assert!(
        ServiceRelayMigrationExecutor::new(Arc::clone(&app_state), Duration::from_millis(99),)
            .is_err()
    );
    assert!(ServiceRelayMigrationExecutor::new(app_state, Duration::from_secs(61)).is_err());
}

#[derive(Default)]
struct FakeBackend {
    responses: Mutex<VecDeque<Result<Vec<u8>, RelayBackendError>>>,
    gate: Mutex<Option<Arc<Semaphore>>>,
    fetches: AtomicU64,
}

impl FakeBackend {
    fn push(&self, response: Result<Vec<u8>, RelayBackendError>) {
        self.responses.lock().unwrap().push_back(response);
    }
}

#[async_trait]
impl RelayAccessBackend for FakeBackend {
    async fn fetch(
        &self,
        _context: &RelayAccessContext,
    ) -> Result<Zeroizing<Vec<u8>>, RelayBackendError> {
        self.fetches.fetch_add(1, Ordering::AcqRel);
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(RelayBackendError::Unavailable))
            .map(Zeroizing::new)
    }
}

struct FakeClock(AtomicU64);

impl FakeClock {
    fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    fn advance(&self, millis: u64) {
        self.0.fetch_add(millis, Ordering::AcqRel);
    }
}

impl RelayClock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

struct FakeInputBarrier {
    events: Arc<Mutex<Vec<String>>>,
    frozen: Mutex<HashSet<SessionId>>,
    gate: Mutex<Option<Arc<Semaphore>>>,
}

#[async_trait]
impl RelayInputBarrier for FakeInputBarrier {
    async fn freeze_after_release(&self, session_id: &SessionId) -> Result<(), ()> {
        {
            let mut events = self.events.lock().unwrap();
            events.push(format!("release_all:{}", session_id.0));
            events.push(format!("freeze:{}", session_id.0));
        }
        self.frozen.lock().unwrap().insert(session_id.clone());
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
        Ok(())
    }

    async fn thaw(&self, session_id: &SessionId) {
        self.events
            .lock()
            .unwrap()
            .push(format!("thaw:{}", session_id.0));
        self.frozen.lock().unwrap().remove(session_id);
    }

    async fn is_frozen(&self, session_id: &SessionId) -> bool {
        self.frozen.lock().unwrap().contains(session_id)
    }
}

struct FakeExecutor {
    events: Arc<Mutex<Vec<String>>>,
    mux: Arc<dyn TransportMuxPort>,
    gate: Option<Arc<Semaphore>>,
    failure: Mutex<Option<RelayMigrationFailure>>,
}

#[async_trait]
impl RelayMigrationExecutor for FakeExecutor {
    async fn migrate(
        &self,
        attempt: &RelayMigrationAttempt,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        self.events.lock().unwrap().push(format!(
            "migrate:{}:{}:{}",
            attempt.session_id().0,
            attempt.generation(),
            attempt.route_evidence().node_id()
        ));
        if let Some(gate) = &self.gate {
            gate.acquire().await.unwrap().forget();
        }
        if let Some(error) = self.failure.lock().unwrap().take() {
            return Err(error);
        }
        Ok(RelayMigrationCommit::for_attempt(
            attempt,
            Arc::clone(&self.mux),
        ))
    }

    async fn respond(
        &self,
        attempt: &RelayMigrationAttempt,
        _offer: RelayMigrationOffer,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        self.events.lock().unwrap().push(format!(
            "respond:{}:{}:{}",
            attempt.session_id().0,
            attempt.generation(),
            attempt.route_evidence().node_id()
        ));
        if let Some(gate) = &self.gate {
            gate.acquire().await.unwrap().forget();
        }
        if let Some(error) = self.failure.lock().unwrap().take() {
            return Err(error);
        }
        Ok(RelayMigrationCommit::for_attempt(
            attempt,
            Arc::clone(&self.mux),
        ))
    }

    async fn discard_loser(&self, session_id: &SessionId, generation: u64) {
        self.events
            .lock()
            .unwrap()
            .push(format!("discard:{}:{generation}", session_id.0));
    }

    async fn close_all(&self, session_id: &SessionId) {
        self.events
            .lock()
            .unwrap()
            .push(format!("close_all:{}", session_id.0));
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn relay_config() -> RelayClientConfig {
    RelayClientConfig::new(
        "https://control.example.test/api/v1/relays/access",
        "device-token",
        BTreeMap::from([(
            "relay-signing-key".into(),
            signing_key().verifying_key().to_bytes().to_vec(),
        )]),
        Duration::from_secs(2),
        4,
    )
    .unwrap()
}

fn access_response(expires_at_ms: u64) -> Vec<u8> {
    access_response_with_backup_domain(expires_at_ms, "domain-c")
}

fn access_response_with_backup_domain(expires_at_ms: u64, backup_domain: &str) -> Vec<u8> {
    let endpoints = [
        ("relay-a", "domain-a", "relay-a.example.test"),
        ("relay-b", "domain-a", "relay-b.example.test"),
        ("relay-c", backup_domain, "relay-c.example.test"),
    ];
    let payload = RelayDirectoryPayload {
        format_version: RELAY_DIRECTORY_FORMAT_VERSION,
        policy_revision: 7,
        directory_id: "directory-failover".into(),
        issued_at_ms: NOW - 1_000,
        expires_at_ms,
        session_id: "failover-session".into(),
        intended_peer_digest: relay_peer_digest("peer-device").unwrap(),
        candidates: endpoints
            .iter()
            .map(|(node_id, failure_domain, host)| RelayDirectoryCandidate {
                node_id: (*node_id).into(),
                region: if *node_id == "relay-c" {
                    "eu-west".into()
                } else {
                    "us-east".into()
                },
                failure_domain: (*failure_domain).into(),
                endpoints: vec![RelayDirectoryEndpoint {
                    transport: RelayDirectoryTransport::Udp,
                    host: (*host).into(),
                    port: 3478,
                }],
                capabilities: 1,
                load_class: 1,
                selection_reason: "eligible".into(),
                reservation: RelayReservation {
                    reservation_id: format!("reservation-{node_id}"),
                    expires_at_ms,
                },
            })
            .collect(),
    };
    let signature = signing_key().sign(&payload.canonical_signing_bytes().unwrap());
    let directory = SignedRelayDirectory {
        payload,
        signing_key_id: "relay-signing-key".into(),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    };
    let credentials = endpoints
        .iter()
        .map(|(node_id, _, host)| {
            json!({
                "node_id": node_id,
                "urls": [format!("turn:{host}:3478?transport=udp")],
                "username": format!("user-{node_id}"),
                "credential": format!("password-{node_id}"),
                "expires_at_unix_seconds": expires_at_ms / 1000 + 60
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({
        "directory": directory,
        "credentials": credentials
    }))
    .unwrap()
}

struct Fixture {
    backend: Arc<FakeBackend>,
    client: Arc<RelayDirectoryClient>,
    clock: Arc<FakeClock>,
    input: Arc<FakeInputBarrier>,
    executor: Arc<FakeExecutor>,
    coordinator: Arc<RelayFailoverCoordinator>,
    context: RelayAccessContext,
    access: Arc<mrd_service::relay::VerifiedRelayAccess>,
    session_id: SessionId,
    remote_mux: Arc<MemoryTransportMux>,
    _replacement_remote: Option<Arc<MemoryTransportMux>>,
}

async fn make_fixture(gate: Option<Arc<Semaphore>>, replacement_same_as_active: bool) -> Fixture {
    let backend = Arc::new(FakeBackend::default());
    backend.push(Ok(access_response(NOW + 30_000)));
    let clock = Arc::new(FakeClock::new(NOW));
    let client = Arc::new(RelayDirectoryClient::with_backend(
        relay_config(),
        backend.clone(),
        clock.clone(),
    ));
    let context = RelayAccessContext::new("failover-session", 7, "peer-device").unwrap();
    let access = client.access(context.clone()).await.unwrap();
    let session_id = SessionId("failover-session".into());
    let (active, remote) = MemoryTransportMux::pair(session_id.clone(), TransportMuxConfig::test());
    let active: Arc<dyn TransportMuxPort> = Arc::new(active);
    let remote_mux = Arc::new(remote);
    let (replacement, replacement_remote): (
        Arc<dyn TransportMuxPort>,
        Option<Arc<MemoryTransportMux>>,
    ) = if replacement_same_as_active {
        (Arc::clone(&active), None)
    } else {
        let (replacement, replacement_remote) =
            MemoryTransportMux::pair(session_id.clone(), TransportMuxConfig::test());
        (Arc::new(replacement), Some(Arc::new(replacement_remote)))
    };
    let events = Arc::new(Mutex::new(Vec::new()));
    let input = Arc::new(FakeInputBarrier {
        events: Arc::clone(&events),
        frozen: Mutex::new(HashSet::new()),
        gate: Mutex::new(None),
    });
    let executor = Arc::new(FakeExecutor {
        events,
        mux: replacement,
        gate,
        failure: Mutex::new(None),
    });
    let provider: Arc<dyn mrd_service::relay::RelayAccessProvider> = client.clone();
    let executor_port: Arc<dyn RelayMigrationExecutor> = executor.clone();
    let input_port: Arc<dyn RelayInputBarrier> = input.clone();
    let clock_port: Arc<dyn RelayClock> = clock.clone();
    let coordinator = Arc::new(
        RelayFailoverCoordinator::new(
            provider,
            executor_port,
            input_port,
            clock_port,
            Duration::from_secs(5),
        )
        .unwrap(),
    );
    coordinator
        .install_session(context.clone(), Arc::clone(&access), "relay-a", active)
        .await
        .unwrap();
    Fixture {
        backend,
        client,
        clock,
        input,
        executor,
        coordinator,
        context,
        access,
        session_id,
        remote_mux,
        _replacement_remote: replacement_remote,
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..1_000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("condition was not reached");
}

async fn wait_for_phase(
    coordinator: &RelayFailoverCoordinator,
    session_id: &SessionId,
    expected: RelayMigrationPhase,
) {
    for _ in 0..1_000 {
        if coordinator.snapshot(session_id).await.unwrap().phase == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("migration phase did not reach {expected:?}");
}

#[tokio::test]
async fn authenticated_remote_offer_refreshes_exact_node_and_commits_answer_side_generation() {
    let fixture = make_fixture(None, false).await;
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    let event = VerifiedSignalingEvent {
        sender: VerifiedSignalingIdentity {
            device_id: mrd_proto::DeviceId("peer-device".into()),
            key_id: "peer-key".into(),
            public_key: vec![7; 32],
            counter: 1,
            nonce: [9; 16],
            issued_at_ms: NOW,
            expires_at_ms: NOW + 30_000,
        },
        signal: AuthenticatedSessionSignal::RelayMigrationOffer {
            session_id: fixture.session_id.clone(),
            migration_generation: 1,
            directory_id: "directory-failover".into(),
            node_id: "relay-c".into(),
            sdp: "verified-offer".into(),
            restart_route_token: "1".repeat(64),
            candidate_fingerprints: vec!["a".repeat(64)],
        },
    };
    let offer = RelayMigrationOffer::from_verified_event(event).expect("migration offer");

    let outcome = fixture
        .coordinator
        .accept_remote_offer(offer)
        .await
        .expect("answer-side migration");

    assert!(matches!(outcome, RelayRecoveryOutcome::Migrated { .. }));
    let snapshot = fixture
        .coordinator
        .snapshot(&fixture.session_id)
        .await
        .unwrap();
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.active_node_id, "relay-c");
    let events = fixture.executor.events.lock().unwrap();
    assert!(events.contains(&"release_all:failover-session".into()));
    assert!(events.contains(&"freeze:failover-session".into()));
    assert!(events.contains(&"respond:failover-session:1:relay-c".into()));
    assert!(events.contains(&"thaw:failover-session".into()));
}

#[tokio::test]
async fn cancelling_terminalization_cannot_skip_transport_close() {
    let fixture = make_fixture(None, false).await;
    let input_gate = Arc::new(Semaphore::new(0));
    *fixture.input.gate.lock().unwrap() = Some(Arc::clone(&input_gate));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let terminalization = tokio::spawn(async move {
        coordinator
            .terminate_security(&session_id, RelayTerminalSecurityReason::RelayRevoked)
            .await
    });
    wait_until(|| {
        fixture
            .executor
            .events
            .lock()
            .unwrap()
            .contains(&"freeze:failover-session".into())
    })
    .await;

    terminalization.abort();
    input_gate.add_permits(1);
    assert!(terminalization.await.unwrap_err().is_cancelled());
    wait_until(|| {
        fixture
            .executor
            .events
            .lock()
            .unwrap()
            .contains(&"close_all:failover-session".into())
    })
    .await;
}

#[tokio::test]
async fn cancelling_directory_refresh_returns_planning_session_to_idle() {
    let fixture = make_fixture(None, false).await;
    let backend_gate = Arc::new(Semaphore::new(0));
    *fixture.backend.gate.lock().unwrap() = Some(Arc::clone(&backend_gate));
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let recovery = tokio::spawn(async move {
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
    });
    wait_until(|| fixture.backend.fetches.load(Ordering::Acquire) >= 2).await;

    recovery.abort();
    assert!(recovery.await.unwrap_err().is_cancelled());
    backend_gate.add_permits(1);
    wait_for_phase(
        &fixture.coordinator,
        &fixture.session_id,
        RelayMigrationPhase::Idle,
    )
    .await;
}

#[tokio::test]
async fn cancelling_frozen_migration_discards_attempt_and_thaws_input() {
    let executor_gate = Arc::new(Semaphore::new(0));
    let fixture = make_fixture(Some(Arc::clone(&executor_gate)), false).await;
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let recovery = tokio::spawn(async move {
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
    });
    wait_until(|| {
        fixture
            .executor
            .events
            .lock()
            .unwrap()
            .contains(&"migrate:failover-session:1:relay-c".into())
    })
    .await;

    recovery.abort();
    assert!(recovery.await.unwrap_err().is_cancelled());
    executor_gate.add_permits(1);
    wait_until(|| {
        let events = fixture.executor.events.lock().unwrap();
        events.contains(&"discard:failover-session:1".into())
            && events.contains(&"thaw:failover-session".into())
    })
    .await;
    assert!(!fixture.input.is_frozen(&fixture.session_id).await);
}

#[tokio::test]
async fn expired_access_cannot_be_installed_as_an_active_relay_session() {
    let fixture = make_fixture(None, false).await;
    fixture.clock.advance(31_000);
    let provider: Arc<dyn mrd_service::relay::RelayAccessProvider> = fixture.client.clone();
    let executor: Arc<dyn RelayMigrationExecutor> = fixture.executor.clone();
    let input: Arc<dyn RelayInputBarrier> = fixture.input.clone();
    let clock: Arc<dyn RelayClock> = fixture.clock.clone();
    let coordinator =
        RelayFailoverCoordinator::new(provider, executor, input, clock, Duration::from_secs(5))
            .unwrap();
    let (active, _remote) =
        MemoryTransportMux::pair(fixture.session_id.clone(), TransportMuxConfig::test());

    assert_eq!(
        coordinator
            .install_session(
                fixture.context.clone(),
                Arc::clone(&fixture.access),
                "relay-a",
                Arc::new(active),
            )
            .await
            .unwrap_err(),
        RelayFailoverConfigError::AccessExpired
    );
}

#[tokio::test]
async fn duplicate_install_is_rejected_without_replacing_the_active_session() {
    let fixture = make_fixture(None, false).await;
    let original_mux = fixture
        .coordinator
        .active_mux(&fixture.session_id)
        .await
        .unwrap();
    let (replacement, _remote) =
        MemoryTransportMux::pair(fixture.session_id.clone(), TransportMuxConfig::test());

    let error = fixture
        .coordinator
        .install_session(
            fixture.context.clone(),
            Arc::clone(&fixture.access),
            "relay-a",
            Arc::new(replacement),
        )
        .await
        .expect_err("duplicate install must fail closed");

    assert_eq!(
        error,
        mrd_service::relay::RelayFailoverConfigError::DuplicateSession
    );
    let still_active = fixture
        .coordinator
        .active_mux(&fixture.session_id)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&original_mux, &still_active));
}

#[tokio::test]
async fn retry_after_started_migration_uses_the_next_generation() {
    let fixture = make_fixture(None, false).await;
    *fixture.executor.failure.lock().unwrap() = Some(RelayMigrationFailure::retryable(
        RelayMigrationFailureCode::SignalingUnavailable,
    ));
    fixture.backend.push(Ok(access_response(NOW + 30_000)));

    assert_eq!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Retryable {
            code: RelayMigrationFailureCode::SignalingUnavailable
        }
    );

    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Migrated { .. }
    ));
    let migrations = fixture
        .executor
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.starts_with("migrate:"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        migrations,
        vec![
            "migrate:failover-session:1:relay-c",
            "migrate:failover-session:2:relay-c"
        ]
    );
}

#[tokio::test]
async fn disconnected_uses_grace_failed_is_immediate_and_backup_crosses_failure_domain() {
    let fixture = make_fixture(None, false).await;
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    assert_eq!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Disconnected)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Grace {
            retry_at_ms: NOW + 5_000
        }
    );
    fixture.clock.advance(4_999);
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Disconnected)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Grace { .. }
    ));
    fixture.clock.advance(1);
    let RelayRecoveryOutcome::Migrated { evidence } = fixture
        .coordinator
        .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Disconnected)
        .await
        .unwrap()
    else {
        panic!("expected migration after grace")
    };
    assert_eq!(evidence.node_id(), "relay-c");
    assert_eq!(evidence.failure_domain(), "domain-c");
    let events = fixture.executor.events.lock().unwrap().clone();
    assert_eq!(
        &events[..3],
        &[
            "release_all:failover-session",
            "freeze:failover-session",
            "migrate:failover-session:1:relay-c",
        ]
    );

    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 1, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Migrated { .. }
    ));
    assert_eq!(
        fixture
            .coordinator
            .snapshot(&fixture.session_id)
            .await
            .unwrap()
            .generation,
        2
    );
}

#[tokio::test]
async fn stale_health_from_the_replaced_generation_is_suppressed() {
    let fixture = make_fixture(None, false).await;
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Migrated { .. }
    ));
    let fetches_after_commit = fixture.backend.fetches.load(Ordering::Acquire);

    assert_eq!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::SuppressedStaleHealth {
            observed_generation: 0,
            active_generation: 1,
        }
    );
    assert_eq!(
        fixture.backend.fetches.load(Ordering::Acquire),
        fetches_after_commit
    );
}

#[tokio::test]
async fn replacement_is_atomic_and_terminal_event_suppresses_the_late_loser() {
    let gate = Arc::new(Semaphore::new(0));
    let fixture = make_fixture(Some(Arc::clone(&gate)), false).await;
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let recovery = tokio::spawn(async move {
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap()
    });
    for _ in 0..100 {
        if fixture
            .executor
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("migrate:"))
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    let in_flight = fixture
        .coordinator
        .snapshot(&fixture.session_id)
        .await
        .unwrap();
    assert_eq!(in_flight.active_node_id, "relay-a");
    assert_eq!(
        in_flight.phase,
        RelayMigrationPhase::InFlight { generation: 1 }
    );
    assert!(fixture.input.is_frozen(&fixture.session_id).await);
    assert_eq!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::InProgress { generation: 1 }
    );

    assert_eq!(
        fixture
            .coordinator
            .terminate_security(
                &fixture.session_id,
                RelayTerminalSecurityReason::IdentityMismatch,
            )
            .await
            .unwrap(),
        RelayRecoveryOutcome::Terminal {
            reason: RelayTerminalSecurityReason::IdentityMismatch
        }
    );
    assert_eq!(
        fixture
            .coordinator
            .terminate_security(
                &fixture.session_id,
                RelayTerminalSecurityReason::PolicyChanged,
            )
            .await
            .unwrap(),
        RelayRecoveryOutcome::Terminal {
            reason: RelayTerminalSecurityReason::IdentityMismatch
        }
    );
    assert_eq!(
        fixture
            .executor
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.starts_with("close_all:"))
            .count(),
        1
    );
    gate.add_permits(1);
    assert_eq!(
        recovery.await.unwrap(),
        RelayRecoveryOutcome::SuppressedLate { generation: 1 }
    );
    let terminal = fixture
        .coordinator
        .snapshot(&fixture.session_id)
        .await
        .unwrap();
    assert_eq!(terminal.active_node_id, "relay-a");
    assert_eq!(terminal.generation, 0);
    assert_eq!(terminal.phase, RelayMigrationPhase::Terminal);
    let events = fixture.executor.events.lock().unwrap().clone();
    assert!(events.contains(&"close_all:failover-session".into()));
    assert!(events.contains(&"discard:failover-session:1".into()));
}

#[tokio::test]
async fn terminal_event_during_input_freeze_prevents_migration_from_starting() {
    let fixture = make_fixture(None, false).await;
    let input_gate = Arc::new(Semaphore::new(0));
    *fixture.input.gate.lock().unwrap() = Some(Arc::clone(&input_gate));
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let recovery = tokio::spawn(async move {
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap()
    });
    for _ in 0..100 {
        if fixture
            .executor
            .events
            .lock()
            .unwrap()
            .contains(&"freeze:failover-session".into())
        {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(
        fixture
            .coordinator
            .terminate_security(
                &fixture.session_id,
                RelayTerminalSecurityReason::RelayRevoked,
            )
            .await
            .unwrap(),
        RelayRecoveryOutcome::Terminal {
            reason: RelayTerminalSecurityReason::RelayRevoked
        }
    );
    input_gate.add_permits(1);
    assert_eq!(
        recovery.await.unwrap(),
        RelayRecoveryOutcome::SuppressedLate { generation: 1 }
    );
    assert!(!fixture
        .executor
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.starts_with("migrate:")));
}

#[tokio::test]
async fn transport_error_after_terminal_close_is_suppressed_not_retried() {
    let gate = Arc::new(Semaphore::new(0));
    let fixture = make_fixture(Some(Arc::clone(&gate)), false).await;
    *fixture.executor.failure.lock().unwrap() = Some(RelayMigrationFailure::retryable(
        RelayMigrationFailureCode::TransportUnavailable,
    ));
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let recovery = tokio::spawn(async move {
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap()
    });
    for _ in 0..100 {
        if fixture
            .executor
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("migrate:"))
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    fixture
        .coordinator
        .terminate_security(
            &fixture.session_id,
            RelayTerminalSecurityReason::IdentityMismatch,
        )
        .await
        .unwrap();

    gate.add_permits(1);

    assert_eq!(
        recovery.await.unwrap(),
        RelayRecoveryOutcome::SuppressedLate { generation: 1 }
    );
    assert!(fixture.input.is_frozen(&fixture.session_id).await);
}

#[tokio::test]
async fn terminal_event_during_directory_refresh_suppresses_retryable_planning_result() {
    let fixture = make_fixture(None, false).await;
    let backend_gate = Arc::new(Semaphore::new(0));
    *fixture.backend.gate.lock().unwrap() = Some(Arc::clone(&backend_gate));
    fixture.backend.push(Ok(access_response_with_backup_domain(
        NOW + 30_000,
        "domain-a",
    )));
    let coordinator = Arc::clone(&fixture.coordinator);
    let session_id = fixture.session_id.clone();
    let recovery = tokio::spawn(async move {
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap()
    });
    for _ in 0..100 {
        if fixture.backend.fetches.load(Ordering::Acquire) >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    fixture
        .coordinator
        .terminate_security(
            &fixture.session_id,
            RelayTerminalSecurityReason::IdentityMismatch,
        )
        .await
        .unwrap();

    backend_gate.add_permits(1);

    assert_eq!(
        recovery.await.unwrap(),
        RelayRecoveryOutcome::SuppressedLate { generation: 1 }
    );
}

#[tokio::test]
async fn backend_outage_uses_fresh_cache_but_expiry_is_retryable_not_security_terminal() {
    let fixture = make_fixture(None, false).await;
    fixture.backend.push(Err(RelayBackendError::Unavailable));
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Migrated { .. }
    ));

    let expired = make_fixture(None, false).await;
    expired.clock.advance(31_000);
    expired.backend.push(Err(RelayBackendError::Unavailable));
    assert_eq!(
        expired
            .coordinator
            .observe_health(&expired.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Retryable {
            code: RelayMigrationFailureCode::BackendUnavailable
        }
    );
    let snapshot = expired
        .coordinator
        .snapshot(&expired.session_id)
        .await
        .unwrap();
    assert_eq!(snapshot.active_node_id, "relay-a");
    assert_eq!(snapshot.phase, RelayMigrationPhase::Idle);
    assert!(!expired
        .executor
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.starts_with("close_all:")));
}

#[tokio::test]
async fn backend_revocation_is_reported_as_grant_expiry_not_signature_failure() {
    let fixture = make_fixture(None, false).await;
    fixture.backend.push(Err(RelayBackendError::Unauthorized));

    assert_eq!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Terminal {
            reason: RelayTerminalSecurityReason::GrantExpired
        }
    );
}

#[tokio::test]
async fn invalid_signed_refresh_and_explicit_security_events_close_active_and_pending_paths() {
    let fixture = make_fixture(None, false).await;
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&access_response(NOW + 30_000)).unwrap();
    tampered["directory"]["payload"]["directory_id"] = json!("directory-attacker");
    fixture
        .backend
        .push(Ok(serde_json::to_vec(&tampered).unwrap()));
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Terminal {
            reason: RelayTerminalSecurityReason::SignatureInvalid
        }
    ));
    assert!(fixture.input.is_frozen(&fixture.session_id).await);

    for reason in [
        RelayTerminalSecurityReason::GrantExpired,
        RelayTerminalSecurityReason::PolicyChanged,
        RelayTerminalSecurityReason::RelayRevoked,
        RelayTerminalSecurityReason::IdentityMismatch,
    ] {
        let fixture = make_fixture(None, false).await;
        assert_eq!(
            fixture
                .coordinator
                .terminate_security(&fixture.session_id, reason)
                .await
                .unwrap(),
            RelayRecoveryOutcome::Terminal { reason }
        );
        assert!(fixture.input.is_frozen(&fixture.session_id).await);
        assert!(fixture
            .executor
            .events
            .lock()
            .unwrap()
            .contains(&"close_all:failover-session".into()));
    }
}

#[tokio::test]
async fn stable_mux_preserves_all_lane_continuity_across_atomic_relay_commit() {
    let fixture = make_fixture(None, true).await;
    for lane in TransportLane::ALL {
        fixture
            .coordinator
            .active_mux(&fixture.session_id)
            .await
            .unwrap()
            .send(envelope(&fixture.session_id, lane, 1))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), fixture.remote_mux.recv(lane))
            .await
            .unwrap()
            .unwrap()
            .expect("first envelope");
    }
    fixture.backend.push(Ok(access_response(NOW + 30_000)));
    assert!(matches!(
        fixture
            .coordinator
            .observe_health(&fixture.session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Migrated { .. }
    ));
    for lane in TransportLane::ALL {
        fixture
            .coordinator
            .active_mux(&fixture.session_id)
            .await
            .unwrap()
            .send(envelope(&fixture.session_id, lane, 2))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), fixture.remote_mux.recv(lane))
            .await
            .unwrap()
            .unwrap()
            .expect("post-migration envelope");
        assert_eq!(received.sequence, 2);
    }
    let snapshot = fixture
        .coordinator
        .active_mux(&fixture.session_id)
        .await
        .unwrap()
        .route_snapshot()
        .await;
    for lane in TransportLane::ALL {
        assert_eq!(snapshot.lane(lane).sent, 2);
    }
}

fn envelope(session_id: &SessionId, lane: TransportLane, sequence: u64) -> TransportEnvelope {
    TransportEnvelope {
        session_id: session_id.clone(),
        lane,
        sequence,
        payload: vec![sequence as u8],
        video: (lane == TransportLane::Video).then(|| VideoEnvelopeMetadata {
            codec: "h264".into(),
            timestamp_us: sequence,
            keyframe: true,
            width: 1,
            height: 1,
        }),
    }
}
