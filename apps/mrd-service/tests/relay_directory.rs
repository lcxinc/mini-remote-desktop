use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use mrd_relay_control::{
    RelayDirectoryCandidate, RelayDirectoryEndpoint, RelayDirectoryPayload,
    RelayDirectoryTransport, RelayReservation, SignedRelayDirectory,
    RELAY_DIRECTORY_FORMAT_VERSION,
};
use mrd_service::relay::{
    relay_peer_digest, RelayAccessBackend, RelayAccessContext, RelayBackendError,
    RelayClientConfig, RelayClientError, RelayClock, RelayDirectoryClient,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_000_000;

#[derive(Default)]
struct FakeBackend {
    responses: Mutex<VecDeque<Result<Vec<u8>, RelayBackendError>>>,
    calls: Mutex<Vec<RelayAccessContext>>,
    advance_clock_on_fetch_ms: AtomicU64,
    clock: Mutex<Option<Arc<FakeClock>>>,
}

impl FakeBackend {
    fn push(&self, response: Result<Vec<u8>, RelayBackendError>) {
        self.responses.lock().unwrap().push_back(response);
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait]
impl RelayAccessBackend for FakeBackend {
    async fn fetch(
        &self,
        context: &RelayAccessContext,
    ) -> Result<Zeroizing<Vec<u8>>, RelayBackendError> {
        self.calls.lock().unwrap().push(context.clone());
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(RelayBackendError::Unavailable));
        let advance = self.advance_clock_on_fetch_ms.swap(0, Ordering::AcqRel);
        if advance != 0 {
            self.clock
                .lock()
                .unwrap()
                .as_ref()
                .expect("fetch clock")
                .advance(advance);
        }
        response.map(Zeroizing::new)
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

fn make_client(
    capacity: usize,
    backend: Arc<FakeBackend>,
    clock: Arc<FakeClock>,
) -> RelayDirectoryClient {
    *backend.clock.lock().unwrap() = Some(Arc::clone(&clock));
    RelayDirectoryClient::with_backend(config(capacity), backend, clock)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x31; 32])
}

fn config(capacity: usize) -> RelayClientConfig {
    let signing_key = signing_key();
    RelayClientConfig::new(
        "https://control.example.test/api/v1/relays/access",
        "device-token-secret",
        BTreeMap::from([(
            "directory-key-1".to_owned(),
            signing_key.verifying_key().to_bytes().to_vec(),
        )]),
        Duration::from_secs(3),
        capacity,
    )
    .unwrap()
}

fn context(session_id: &str) -> RelayAccessContext {
    RelayAccessContext::new(session_id, 7, "peer-device-1").unwrap()
}

fn generation_context(session_id: &str, generation: u64) -> RelayAccessContext {
    RelayAccessContext::for_generation(session_id, 7, "peer-device-1", generation).unwrap()
}

fn signed_response(session_id: &str, expires_at_ms: u64) -> Vec<u8> {
    signed_response_at(session_id, NOW - 1_000, expires_at_ms)
}

fn signed_response_at(session_id: &str, issued_at_ms: u64, expires_at_ms: u64) -> Vec<u8> {
    let peer_digest = relay_peer_digest("peer-device-1").unwrap();
    let payload = RelayDirectoryPayload {
        format_version: RELAY_DIRECTORY_FORMAT_VERSION,
        policy_revision: 7,
        directory_id: format!("directory-{session_id}"),
        issued_at_ms,
        expires_at_ms,
        session_id: session_id.to_owned(),
        intended_peer_digest: peer_digest,
        candidates: vec![
            RelayDirectoryCandidate {
                node_id: "relay-a".into(),
                region: "us-east".into(),
                failure_domain: "host-a".into(),
                endpoints: vec![RelayDirectoryEndpoint {
                    transport: RelayDirectoryTransport::Udp,
                    host: "relay-a.example.test".into(),
                    port: 3478,
                }],
                capabilities: 1,
                load_class: 1,
                selection_reason: "preferred_region".into(),
                reservation: RelayReservation {
                    reservation_id: format!("reservation-a-{session_id}"),
                    expires_at_ms,
                },
            },
            RelayDirectoryCandidate {
                node_id: "relay-b".into(),
                region: "eu-west".into(),
                failure_domain: "host-b".into(),
                endpoints: vec![RelayDirectoryEndpoint {
                    transport: RelayDirectoryTransport::Tls,
                    host: "relay-b.example.test".into(),
                    port: 5349,
                }],
                capabilities: 1,
                load_class: 2,
                selection_reason: "failure_domain_backup".into(),
                reservation: RelayReservation {
                    reservation_id: format!("reservation-b-{session_id}"),
                    expires_at_ms,
                },
            },
        ],
    };
    let signature = signing_key().sign(&payload.canonical_signing_bytes().unwrap());
    let directory = SignedRelayDirectory {
        payload,
        signing_key_id: "directory-key-1".into(),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    };
    serde_json::to_vec(&json!({
        "directory": directory,
        "credentials": [
            {
                "node_id": "relay-a",
                "urls": ["turn:relay-a.example.test:3478?transport=udp"],
                "username": "turn-user-a",
                "credential": "turn-password-a",
                "expires_at_unix_seconds": (expires_at_ms / 1000) + 60
            },
            {
                "node_id": "relay-b",
                "urls": ["turns:relay-b.example.test:5349?transport=tcp"],
                "username": "turn-user-b",
                "credential": "turn-password-b",
                "expires_at_unix_seconds": (expires_at_ms / 1000) + 60
            }
        ]
    }))
    .unwrap()
}

#[test]
fn relay_client_configuration_requires_https_pinned_keys_and_credential_free_urls() {
    let keys = config(2).trusted_keys().clone();
    for endpoint in [
        "http://control.example.test/api/v1/relays/access",
        "https://user@control.example.test/api/v1/relays/access",
        "https://control.example.test/api/v1/relays/access?token=secret",
    ] {
        assert!(RelayClientConfig::new(
            endpoint,
            "device-token-secret",
            keys.clone(),
            Duration::from_secs(3),
            2,
        )
        .is_err());
    }
    assert!(RelayClientConfig::new(
        "https://control.example.test/api/v1/relays/access",
        "device-token-secret",
        BTreeMap::new(),
        Duration::from_secs(3),
        2,
    )
    .is_err());
    let debug = format!("{:?}", config(2));
    assert!(!debug.contains("device-token-secret"));
    assert!(!debug.contains("control.example.test"));
    assert!(!debug.contains("/api/v1/relays/access"));
}

#[test]
fn relay_access_context_preserves_v2_json_and_binds_v3_generation() {
    let legacy = serde_json::to_value(context("legacy-session")).unwrap();
    assert_eq!(
        legacy,
        json!({
            "session_id": "legacy-session",
            "policy_revision": 7,
            "intended_peer_id": "peer-device-1"
        })
    );

    let generation_zero = serde_json::to_value(generation_context("wan-session", 0)).unwrap();
    assert_eq!(
        generation_zero,
        json!({
            "session_id": "wan-session",
            "policy_revision": 7,
            "intended_peer_id": "peer-device-1",
            "generation": 0
        })
    );
    let refresh = RelayAccessContext::for_refresh("wan-session", 7, "peer-device-1", 0)
        .expect("valid refresh context");
    assert_eq!(
        serde_json::to_value(refresh).unwrap(),
        json!({
            "session_id": "wan-session",
            "policy_revision": 7,
            "intended_peer_id": "peer-device-1",
            "generation": 0,
            "refresh": true
        })
    );
}

#[tokio::test]
async fn relay_cache_keys_include_the_exact_wan_generation() {
    let backend = Arc::new(FakeBackend::default());
    backend.push(Ok(signed_response("wan-cache", NOW + 30_000)));
    backend.push(Ok(signed_response("wan-cache", NOW + 30_000)));
    let client = make_client(4, backend.clone(), Arc::new(FakeClock::new(NOW)));

    client
        .access(generation_context("wan-cache", 0))
        .await
        .unwrap();
    client
        .access(generation_context("wan-cache", 1))
        .await
        .unwrap();

    assert_eq!(backend.call_count(), 2);
    assert_eq!(client.cache_len().await, 2);
}

#[tokio::test]
async fn directory_is_verified_before_use_and_credentials_are_node_bound_and_redacted() {
    let backend = Arc::new(FakeBackend::default());
    backend.push(Ok(signed_response("session-1", NOW + 30_000)));
    let client = make_client(4, backend.clone(), Arc::new(FakeClock::new(NOW)));

    let access = client.access(context("session-1")).await.unwrap();
    assert_eq!(access.directory().payload().session_id, "session-1");
    assert_eq!(access.directory().payload().policy_revision, 7);
    let credential = access.credentials_for("relay-a").unwrap();
    assert_eq!(credential.urls.len(), 1);
    let evidence = access.route_evidence("relay-a", 1).unwrap();
    let initial_evidence = access
        .route_evidence("relay-a", 0)
        .expect("initial selected-pair evidence uses generation zero");
    assert_eq!(initial_evidence.generation(), 0);
    let debug = format!("{access:?} {credential:?} {evidence:?}");
    for secret in [
        "turn-user-a",
        "turn-password-a",
        "relay-a.example.test",
        "reservation-a-session-1",
    ] {
        assert!(!debug.contains(secret));
    }
    assert_eq!(backend.call_count(), 1);
    assert_eq!(client.cache_len().await, 1);
}

#[tokio::test]
async fn signature_or_credential_binding_failure_is_terminal_and_never_cached() {
    let backend = Arc::new(FakeBackend::default());
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&signed_response("tampered", NOW + 30_000)).unwrap();
    tampered["directory"]["payload"]["candidates"][0]["node_id"] = json!("relay-attacker");
    backend.push(Ok(serde_json::to_vec(&tampered).unwrap()));
    let client = make_client(2, backend, Arc::new(FakeClock::new(NOW)));
    let error = client.access(context("tampered")).await.unwrap_err();
    assert!(error.is_terminal_security());
    assert_eq!(client.cache_len().await, 0);

    let backend = Arc::new(FakeBackend::default());
    let mut credential_mismatch: serde_json::Value =
        serde_json::from_slice(&signed_response("mismatch", NOW + 30_000)).unwrap();
    credential_mismatch["credentials"][0]["urls"][0] =
        json!("turn:other.example.test:3478?transport=udp");
    backend.push(Ok(serde_json::to_vec(&credential_mismatch).unwrap()));
    let client = make_client(2, backend, Arc::new(FakeClock::new(NOW)));
    assert!(client
        .access(context("mismatch"))
        .await
        .unwrap_err()
        .is_terminal_security());
    assert_eq!(client.cache_len().await, 0);
}

#[tokio::test]
async fn cache_is_bounded_and_backend_outage_uses_only_unexpired_verified_entries() {
    let backend = Arc::new(FakeBackend::default());
    let clock = Arc::new(FakeClock::new(NOW));
    for session_id in ["session-1", "session-2", "session-3"] {
        backend.push(Ok(signed_response(session_id, NOW + 30_000)));
    }
    let client = make_client(2, backend.clone(), Arc::clone(&clock));
    for session_id in ["session-1", "session-2", "session-3"] {
        client.access(context(session_id)).await.unwrap();
    }
    assert_eq!(client.cache_len().await, 2);

    backend.push(Err(RelayBackendError::Unavailable));
    clock.advance(1_000);
    let cached = client.refresh(context("session-3")).await.unwrap();
    assert_eq!(cached.directory().payload().session_id, "session-3");

    backend.push(Err(RelayBackendError::Unavailable));
    clock.advance(30_000);
    assert_eq!(
        client.refresh(context("session-3")).await.unwrap_err(),
        RelayClientError::BackendUnavailable
    );
}

#[tokio::test]
async fn response_is_verified_with_time_sampled_after_the_network_fetch() {
    let backend = Arc::new(FakeBackend::default());
    let clock = Arc::new(FakeClock::new(NOW));
    backend.push(Ok(signed_response_at(
        "response-time",
        NOW + 1_000,
        NOW + 31_000,
    )));
    backend
        .advance_clock_on_fetch_ms
        .store(1_000, Ordering::Release);
    let client = make_client(2, backend, clock);

    let access = client
        .access(context("response-time"))
        .await
        .expect("server-issued response must be current when it arrives");

    assert_eq!(access.directory().payload().issued_at_ms, NOW + 1_000);
}
