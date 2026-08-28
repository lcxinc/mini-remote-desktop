use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use mrd_application::ports::TransportMuxPort;
use mrd_proto::SessionId;
use mrd_relay_control::{
    lease_expires_at, select_relays, FailureDomainId, RegionId, RelayDirectoryCandidate,
    RelayDirectoryEndpoint, RelayDirectoryPayload, RelayDirectoryTransport, RelayEndpoint,
    RelayNodeId, RelayNodeSnapshot, RelayNodeState, RelayReservation, RelayScoreWeights,
    RelaySelectionPolicy, RelayTransport, SignedRelayDirectory, RELAY_DIRECTORY_FORMAT_VERSION,
};
use mrd_service::{
    relay::{
        relay_peer_digest, RelayAccessBackend, RelayAccessContext, RelayBackendError,
        RelayClientConfig, RelayClock, RelayConnectionHealth, RelayDirectoryClient,
        RelayFailoverCoordinator, RelayInputBarrier, RelayMigrationAttempt, RelayMigrationCommit,
        RelayMigrationExecutor, RelayMigrationFailure, RelayMigrationOffer, RelayRecoveryOutcome,
        RelayTerminalSecurityReason,
    },
    transports::{memory::MemoryTransportMux, TransportMuxConfig},
};
use ring::digest::{digest, SHA256};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

const NOW_MS: u64 = 1_800_000_000_000;

fn relay_node(node_id: &str, region: &str, failure_domain: &str, rtt_ms: u32) -> RelayNodeSnapshot {
    RelayNodeSnapshot {
        node_id: RelayNodeId::new(node_id).unwrap(),
        region: RegionId::new(region).unwrap(),
        failure_domain: FailureDomainId::new(failure_domain).unwrap(),
        state: RelayNodeState::Ready,
        lease_expires_at_ms: lease_expires_at(NOW_MS),
        endpoints: vec![RelayEndpoint::new(
            RelayTransport::Udp,
            format!("{node_id}.example.test"),
            3478,
        )
        .unwrap()],
        active_allocations: 0,
        max_allocations: 2,
        current_egress_bps: 0,
        max_egress_bps: 10_000_000,
        recent_failure_bps: 0,
        measured_rtt_ms: Some(rtt_ms),
    }
}

fn selection_policy() -> RelaySelectionPolicy {
    RelaySelectionPolicy {
        preferred_regions: vec![RegionId::new("ap-east").unwrap()],
        accepted_transports: vec![RelayTransport::Udp],
        max_backups: 2,
        soft_allocation_limit_bps: 8_000,
        weights: RelayScoreWeights {
            base_score: 1_000_000,
            region_preference: 100_000,
            rtt_penalty_per_ms: 100,
            allocation_utilization_penalty: 100_000,
            bandwidth_headroom_reward: 50_000,
            recent_failure_penalty: 50_000,
            soft_full_penalty: 200_000,
            degraded_penalty: 200_000,
        },
    }
}

struct ReservationPool {
    active: AtomicU32,
    maximum: u32,
}

impl ReservationPool {
    fn reserve(&self) -> bool {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then_some(active + 1)
            })
            .is_ok()
    }

    fn expire_all(&self) {
        self.active.store(0, Ordering::Release);
    }
}

#[test]
fn three_nodes_cover_selection_capacity_drain_and_lease_expiry() {
    let mut primary = relay_node("relay-a", "ap-east", "rack-a", 5);
    let mut same_region_backup = relay_node("relay-b", "ap-east", "rack-b", 20);
    same_region_backup.active_allocations = 1;
    let remote_backup = relay_node("relay-c", "eu-west", "rack-c", 30);

    let decision = select_relays(
        &selection_policy(),
        &[
            same_region_backup.clone(),
            remote_backup.clone(),
            primary.clone(),
        ],
        NOW_MS,
    )
    .unwrap();
    assert_eq!(decision.primary.node_id.as_str(), "relay-a");
    assert_eq!(decision.backups.len(), 2);
    assert!(decision
        .backups
        .iter()
        .any(|candidate| candidate.region.as_str() == "eu-west"));

    let capacity = Arc::new(ReservationPool {
        active: AtomicU32::new(0),
        maximum: 1,
    });
    let start = Arc::new(Barrier::new(3));
    let racers = (0..2)
        .map(|_| {
            let capacity = Arc::clone(&capacity);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                capacity.reserve()
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    assert_eq!(
        racers
            .into_iter()
            .map(|racer| racer.join().unwrap())
            .filter(|reserved| *reserved)
            .count(),
        1,
        "a reservation race must never admit beyond hard capacity"
    );

    primary.state = RelayNodeState::Draining;
    same_region_backup.lease_expires_at_ms = NOW_MS;
    let after_drain = select_relays(
        &selection_policy(),
        &[primary, same_region_backup, remote_backup],
        NOW_MS,
    )
    .unwrap();
    assert_eq!(after_drain.primary.node_id.as_str(), "relay-c");
    assert_eq!(after_drain.rejections.len(), 2);

    capacity.expire_all();
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
}

#[test]
fn initial_wan_generation_zero_is_explicit_and_peer_bound() {
    let context = RelayAccessContext::for_generation(
        "initial-wan-integration-session",
        7,
        "target-device",
        0,
    )
    .unwrap();
    assert_eq!(context.generation(), Some(0));
    assert!(!context.is_refresh());
    assert_eq!(
        context.intended_peer_digest(),
        relay_peer_digest("target-device").unwrap()
    );

    let request = serde_json::to_value(&context).unwrap();
    assert_eq!(request["generation"], json!(0));
    assert!(request.get("refresh").is_none());
    assert!(request.get("peer_digest").is_none());
}

#[derive(Default)]
struct FakeBackend {
    responses: Mutex<VecDeque<Vec<u8>>>,
}

#[async_trait]
impl RelayAccessBackend for FakeBackend {
    async fn fetch(
        &self,
        _context: &RelayAccessContext,
    ) -> Result<Zeroizing<Vec<u8>>, RelayBackendError> {
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(RelayBackendError::Unavailable)
    }
}

struct FakeClock(AtomicU64);

impl RelayClock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

struct InputBarrier {
    events: Arc<Mutex<Vec<String>>>,
    frozen: Mutex<HashSet<SessionId>>,
}

#[async_trait]
impl RelayInputBarrier for InputBarrier {
    async fn freeze_after_release(&self, session_id: &SessionId) -> Result<(), ()> {
        let mut events = self.events.lock().unwrap();
        events.push("release_all".into());
        events.push("freeze".into());
        drop(events);
        self.frozen.lock().unwrap().insert(session_id.clone());
        Ok(())
    }

    async fn thaw(&self, session_id: &SessionId) {
        self.events.lock().unwrap().push("thaw".into());
        self.frozen.lock().unwrap().remove(session_id);
    }

    async fn is_frozen(&self, session_id: &SessionId) -> bool {
        self.frozen.lock().unwrap().contains(session_id)
    }
}

struct MigrationExecutor {
    events: Arc<Mutex<Vec<String>>>,
    replacement: Arc<dyn TransportMuxPort>,
}

#[async_trait]
impl RelayMigrationExecutor for MigrationExecutor {
    async fn migrate(
        &self,
        attempt: &RelayMigrationAttempt,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        self.events.lock().unwrap().push(format!(
            "migrate:{}:{}",
            attempt.generation(),
            attempt.route_evidence().node_id()
        ));
        Ok(RelayMigrationCommit::for_attempt(
            attempt,
            Arc::clone(&self.replacement),
        ))
    }

    async fn respond(
        &self,
        _attempt: &RelayMigrationAttempt,
        _offer: RelayMigrationOffer,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        unreachable!("this controller-side integration does not answer an offer")
    }

    async fn discard_loser(&self, _session_id: &SessionId, generation: u64) {
        self.events
            .lock()
            .unwrap()
            .push(format!("discard:{generation}"));
    }

    async fn close_all(&self, _session_id: &SessionId) {
        self.events.lock().unwrap().push("close_all".into());
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn relay_access_response(generation: Option<u64>) -> Vec<u8> {
    let nodes = [
        ("relay-a", "ap-east", "rack-a"),
        ("relay-b", "ap-east", "rack-a"),
        ("relay-c", "eu-west", "rack-c"),
    ];
    let expires_at_ms = NOW_MS + 30_000;
    let payload = RelayDirectoryPayload {
        format_version: RELAY_DIRECTORY_FORMAT_VERSION,
        policy_revision: 7,
        directory_id: "directory-integration".into(),
        issued_at_ms: NOW_MS - 1_000,
        expires_at_ms,
        session_id: "relay-integration-session".into(),
        intended_peer_digest: relay_peer_digest("peer-device").unwrap(),
        candidates: nodes
            .iter()
            .map(
                |(node_id, region, failure_domain)| RelayDirectoryCandidate {
                    node_id: (*node_id).into(),
                    region: (*region).into(),
                    failure_domain: (*failure_domain).into(),
                    endpoints: vec![RelayDirectoryEndpoint {
                        transport: RelayDirectoryTransport::Udp,
                        host: format!("{node_id}.example.test"),
                        port: 3478,
                    }],
                    capabilities: 1,
                    load_class: 1,
                    selection_reason: if generation.is_some() && *node_id == "relay-a" {
                        "preferred-region"
                    } else {
                        "eligible"
                    }
                    .into(),
                    reservation: RelayReservation {
                        reservation_id: format!("reservation-{node_id}"),
                        expires_at_ms,
                    },
                },
            )
            .collect(),
    };
    let signature = signing_key().sign(&payload.canonical_signing_bytes().unwrap());
    let directory = SignedRelayDirectory {
        payload,
        signing_key_id: "integration-key".into(),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    };
    let credentials = nodes
        .iter()
        .map(|(node_id, _, _)| {
            json!({
                "node_id": node_id,
                "urls": [format!("turn:{node_id}.example.test:3478?transport=udp")],
                "username": format!("user-{node_id}"),
                "credential": format!("password-{node_id}"),
                "expires_at_unix_seconds": expires_at_ms / 1000 + 60
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({
        "generation": generation,
        "directory_id": "directory-integration",
        "relay_url_digest": generation.map(|_| relay_url_digest("turn:relay-a.example.test:3478?transport=udp")),
        "directory": directory,
        "credentials": credentials
    }))
    .unwrap()
}

fn relay_url_digest(url: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MRD_RELAY_URLS_V1\0");
    bytes.extend_from_slice(&(url.len() as u32).to_be_bytes());
    bytes.extend_from_slice(url.as_bytes());
    digest(&SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn relay_failure_migrates_then_security_dominates_and_closes_transports() {
    let backend = Arc::new(FakeBackend::default());
    {
        let mut responses = backend.responses.lock().unwrap();
        responses.push_back(relay_access_response(None));
        responses.push_back(relay_access_response(Some(1)));
    }
    let clock = Arc::new(FakeClock(AtomicU64::new(NOW_MS)));
    let config = RelayClientConfig::new(
        "https://relay-control.example.test/api/v1/relays/access",
        "test-device-token",
        BTreeMap::from([(
            "integration-key".into(),
            signing_key().verifying_key().to_bytes().to_vec(),
        )]),
        Duration::from_secs(2),
        4,
    )
    .unwrap();
    let client = Arc::new(RelayDirectoryClient::with_backend(
        config,
        backend,
        clock.clone(),
    ));
    let context = RelayAccessContext::new("relay-integration-session", 7, "peer-device").unwrap();
    let access = client.access(context.clone()).await.unwrap();
    let session_id = SessionId("relay-integration-session".into());
    let (active, _active_remote) =
        MemoryTransportMux::pair(session_id.clone(), TransportMuxConfig::test());
    let (replacement, _replacement_remote) =
        MemoryTransportMux::pair(session_id.clone(), TransportMuxConfig::test());
    let events = Arc::new(Mutex::new(Vec::new()));
    let input = Arc::new(InputBarrier {
        events: Arc::clone(&events),
        frozen: Mutex::new(HashSet::new()),
    });
    let executor = Arc::new(MigrationExecutor {
        events: Arc::clone(&events),
        replacement: Arc::new(replacement),
    });
    let coordinator = RelayFailoverCoordinator::new(
        client,
        executor,
        input.clone(),
        clock,
        Duration::from_secs(5),
    )
    .unwrap();
    coordinator
        .install_session(context, access, "relay-a", Arc::new(active))
        .await
        .unwrap();

    let outcome = coordinator
        .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
        .await
        .unwrap();
    let RelayRecoveryOutcome::Migrated { evidence } = outcome else {
        panic!("a hard relay failure must migrate immediately");
    };
    assert_eq!(evidence.node_id(), "relay-c");
    assert_eq!(evidence.failure_domain(), "rack-c");
    assert_eq!(evidence.generation(), 1);
    assert_eq!(
        coordinator
            .observe_health(&session_id, 0, RelayConnectionHealth::Failed)
            .await
            .unwrap(),
        RelayRecoveryOutcome::SuppressedStaleHealth {
            observed_generation: 0,
            active_generation: 1,
        }
    );

    assert_eq!(
        coordinator
            .terminate_security(&session_id, RelayTerminalSecurityReason::RelayRevoked)
            .await
            .unwrap(),
        RelayRecoveryOutcome::Terminal {
            reason: RelayTerminalSecurityReason::RelayRevoked,
        }
    );
    assert!(
        input.is_frozen(&session_id).await,
        "terminal security state must keep control input frozen"
    );
    let snapshot = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(snapshot.generation, 1);
    assert_eq!(
        snapshot.terminal_reason,
        Some(RelayTerminalSecurityReason::RelayRevoked)
    );
    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            "release_all",
            "freeze",
            "migrate:1:relay-c",
            "thaw",
            "release_all",
            "freeze",
            "close_all",
        ]
    );
}
