use std::{
    collections::VecDeque,
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use mrd_relay_agent::{
    backend::{
        canonical_relay_request, decode_enrollment_response, decode_heartbeat_response,
        BackendError, EnrollmentRequest, EnrollmentStatus, HeartbeatPayload, NodeCertificate,
        NodeDirective, PickupRequest, RelayBackendPort, RenewalRequest, ReqwestRelayBackend,
        SignedHeartbeat,
    },
    config::{AgentConfig, ConfigError},
    identity::{load_or_create_identity, CertificateState, IdentityFsPort, StoredIdentity},
    metrics::{parse_coturn_metrics, MetricsError, MetricsLimits, ReqwestCoturnMetrics},
    process::{
        AllocationProbeEvidence, CoturnRuntimePort, CoturnSnapshot, ProcessError, ProcessHealth,
        SecretBytes,
    },
    runtime::{
        AgentRuntime, ClockPort, JitterPort, RandomJitter, RuntimeError, RuntimeStateSnapshot,
        RuntimeStateStorePort, SleeperPort, SystemClock,
    },
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, KeyPair, PKCS_ED25519,
};
use sha2::Digest as _;
use x509_parser::{
    certification_request::X509CertificationRequest, pem::parse_x509_pem, prelude::FromDer,
};

#[derive(Default)]
struct MemoryIdentityFs {
    identity: Mutex<Option<StoredIdentity>>,
    writes: Mutex<Vec<StoredIdentity>>,
    strict_permissions: Mutex<u32>,
    fail_next_writes: Mutex<u32>,
}

impl IdentityFsPort for MemoryIdentityFs {
    fn load(&self) -> Result<Option<StoredIdentity>, RuntimeError> {
        Ok(self.identity.lock().unwrap().clone())
    }

    fn atomic_replace(&self, identity: &StoredIdentity) -> Result<(), RuntimeError> {
        let mut failures = self.fail_next_writes.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            if *failures == 0 {
                return Err(RuntimeError::IdentityIo);
            }
        }
        drop(failures);
        self.writes.lock().unwrap().push(identity.clone());
        *self.identity.lock().unwrap() = Some(identity.clone());
        Ok(())
    }

    fn enforce_strict_permissions(&self) -> Result<(), RuntimeError> {
        *self.strict_permissions.lock().unwrap() += 1;
        Ok(())
    }
}

#[test]
fn identity_is_generated_atomically_and_reused_without_exposing_private_material() {
    let fs = MemoryIdentityFs::default();
    let first = load_or_create_identity(&fs, "relay-hkg-1").unwrap();
    let second = load_or_create_identity(&fs, "relay-hkg-1").unwrap();

    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(fs.writes.lock().unwrap().len(), 1);
    assert_eq!(*fs.strict_permissions.lock().unwrap(), 2);
    assert!(first.csr_pem().contains("BEGIN CERTIFICATE REQUEST"));
    let debug = format!("{first:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(first.csr_pem()));

    let (_, pem) = parse_x509_pem(first.csr_pem().as_bytes()).unwrap();
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
    csr.verify_signature().unwrap();
    let csr_public_key = csr
        .certification_request_info
        .subject_pki
        .subject_public_key
        .data;
    assert_eq!(csr_public_key.as_ref(), first.public_key());

    let body = br#"{"probe":"identity-roundtrip"}"#;
    let signature_b64 = second
        .sign_request(
            "POST",
            "/api/v1/relays/relay-hkg-1/heartbeat",
            1_725_000_000,
            1,
            body,
        )
        .unwrap();
    let canonical = canonical_relay_request(
        "POST",
        "/api/v1/relays/relay-hkg-1/heartbeat",
        "relay-hkg-1",
        1_725_000_000,
        1,
        body,
    )
    .unwrap();
    let signature =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64).unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, second.public_key())
        .verify(&canonical, &signature)
        .unwrap();

    let stored = fs.identity.lock().unwrap().clone().unwrap();
    let mut corrupted = serde_json::to_value(stored).unwrap();
    corrupted["csr_pem"] = serde_json::Value::String("not-a-csr".into());
    let corrupted_fs = MemoryIdentityFs::default();
    *corrupted_fs.identity.lock().unwrap() = Some(serde_json::from_value(corrupted).unwrap());
    assert!(matches!(
        load_or_create_identity(&corrupted_fs, "relay-hkg-1"),
        Err(RuntimeError::IdentityInvalid)
    ));
}

#[derive(Default)]
struct FakeBackend {
    enrollments: Mutex<Vec<EnrollmentRequest>>,
    pickups: Mutex<Vec<PickupRequest>>,
    renewals: Mutex<Vec<RenewalRequest>>,
    heartbeats: Mutex<Vec<SignedHeartbeat>>,
    enrollment_results: Mutex<VecDeque<Result<EnrollmentStatus, BackendError>>>,
    pickup_results: Mutex<VecDeque<Result<Option<NodeCertificate>, BackendError>>>,
    renewal_results: Mutex<VecDeque<Result<NodeCertificate, BackendError>>>,
    heartbeat_results: Mutex<VecDeque<Result<NodeDirective, BackendError>>>,
}

#[async_trait]
impl RelayBackendPort for FakeBackend {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentStatus, BackendError> {
        self.enrollments.lock().unwrap().push(request);
        self.enrollment_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(BackendError::Unavailable))
    }

    async fn pickup(
        &self,
        request: PickupRequest,
    ) -> Result<Option<NodeCertificate>, BackendError> {
        self.pickups.lock().unwrap().push(request);
        self.pickup_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(None))
    }

    async fn renew(&self, request: RenewalRequest) -> Result<NodeCertificate, BackendError> {
        let csr_pem = request.csr_pem.clone();
        self.renewals.lock().unwrap().push(request);
        if let Some(result) = self.renewal_results.lock().unwrap().pop_front() {
            return result;
        }
        Ok(issue_certificate_for_csr(&csr_pem, 2_000))
    }

    async fn heartbeat(&self, heartbeat: SignedHeartbeat) -> Result<NodeDirective, BackendError> {
        self.heartbeats.lock().unwrap().push(heartbeat);
        self.heartbeat_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(BackendError::Unavailable))
    }
}

#[derive(Default)]
struct FakeCoturn {
    snapshots: Mutex<VecDeque<Result<CoturnSnapshot, ProcessError>>>,
    restarts: Mutex<u32>,
    restart_results: Mutex<VecDeque<Result<(), ProcessError>>>,
    secret_versions: Mutex<Vec<u64>>,
    drains: Mutex<Vec<bool>>,
    probes: Mutex<VecDeque<Result<AllocationProbeEvidence, ProcessError>>>,
}

#[async_trait]
impl CoturnRuntimePort for FakeCoturn {
    async fn snapshot(&self) -> Result<CoturnSnapshot, ProcessError> {
        self.snapshots
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(CoturnSnapshot::healthy(0, 0)))
    }

    async fn restart(&self) -> Result<(), ProcessError> {
        *self.restarts.lock().unwrap() += 1;
        self.restart_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(()))
    }

    async fn apply_secret(&self, version: u64, _secret: SecretBytes) -> Result<(), ProcessError> {
        self.secret_versions.lock().unwrap().push(version);
        Ok(())
    }

    async fn set_draining(&self, draining: bool) -> Result<(), ProcessError> {
        self.drains.lock().unwrap().push(draining);
        Ok(())
    }

    async fn probe_local_allocation(&self) -> Result<AllocationProbeEvidence, ProcessError> {
        self.probes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(ProcessError::ProbeUnavailable))
    }
}

#[derive(Default)]
struct FakeClock {
    monotonic_ms: Mutex<u64>,
    unix_seconds: Mutex<i64>,
}

impl ClockPort for FakeClock {
    fn monotonic_ms(&self) -> u64 {
        *self.monotonic_ms.lock().unwrap()
    }

    fn unix_seconds(&self) -> i64 {
        *self.unix_seconds.lock().unwrap()
    }
}

#[derive(Default)]
struct FakeSleeper {
    sleeps: Mutex<Vec<Duration>>,
}

#[async_trait]
impl SleeperPort for FakeSleeper {
    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
    }
}

struct FixedJitter(u64);

impl JitterPort for FixedJitter {
    fn jitter_ms(&self, _upper_exclusive: u64) -> u64 {
        self.0
    }
}

#[derive(Default)]
struct FakeRuntimeStateStore {
    state: Mutex<RuntimeStateSnapshot>,
}

impl RuntimeStateStorePort for FakeRuntimeStateStore {
    fn load(&self) -> Result<RuntimeStateSnapshot, RuntimeError> {
        Ok(self.state.lock().unwrap().clone())
    }

    fn atomic_store(&self, state: &RuntimeStateSnapshot) -> Result<(), RuntimeError> {
        *self.state.lock().unwrap() = state.clone();
        Ok(())
    }
}

fn invalid_certificate(serial: &str, expires_at_unix_seconds: i64) -> NodeCertificate {
    NodeCertificate {
        certificate_pem: format!("certificate-{serial}"),
        ca_certificate_pem: "ca-certificate".into(),
        expires_at_unix_seconds,
    }
}

fn enrollment_request() -> EnrollmentRequest {
    EnrollmentRequest {
        token: secrecy::SecretString::from("enrollment-token"),
        node_id: "relay-hkg-1".into(),
        region: "hkg".into(),
        failure_domain: "hkg-a".into(),
        endpoints: vec!["turn:relay.example:3478?transport=udp".into()],
        max_allocations: 100,
        max_egress_bps: 1_000_000,
        csr_pem: String::new(),
        turn_rest_secret: secrecy::SecretString::from("test-only-redacted"),
    }
}

fn issue_certificate_for_csr(csr_pem: &str, expires_at_unix_seconds: i64) -> NodeCertificate {
    let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut ca_params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "MRD test relay CA");
    ca_params.distinguished_name = distinguished_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
    let leaf = csr.signed_by(&ca, &ca_key).unwrap();
    NodeCertificate {
        certificate_pem: leaf.pem(),
        ca_certificate_pem: ca.pem(),
        expires_at_unix_seconds,
    }
}

fn certificate_public_key(certificate: &NodeCertificate) -> Vec<u8> {
    let (_, pem) = parse_x509_pem(certificate.certificate_pem.as_bytes()).unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
    certificate.public_key().subject_public_key.data.to_vec()
}

#[tokio::test]
async fn enrollment_pickup_and_renewal_switch_identity_only_after_atomic_persist() {
    let fs = Arc::new(MemoryIdentityFs::default());
    let backend = Arc::new(FakeBackend::default());
    backend
        .enrollment_results
        .lock()
        .unwrap()
        .push_back(Ok(EnrollmentStatus::Pending {
            enrollment_id: "enrollment-1".into(),
            receipt: secrecy::SecretString::from("one-use-receipt"),
        }));
    backend
        .renewal_results
        .lock()
        .unwrap()
        .push_back(Err(BackendError::Unavailable));

    let mut state = CertificateState::new(fs.clone(), "relay-hkg-1").unwrap();
    state
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let enrollment_csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(issue_certificate_for_csr(&enrollment_csr, 1_000))));
    state.pickup(backend.as_ref()).await.unwrap();
    let old_certificate = state.active_certificate().unwrap();
    let old_public_key = state.public_key();
    assert_eq!(certificate_public_key(&old_certificate), old_public_key);

    assert!(state
        .renew(backend.as_ref(), "renewal-1", 500)
        .await
        .is_err());
    assert_eq!(state.public_key(), old_public_key);
    let first_renewal_csr = backend.renewals.lock().unwrap()[0].csr_pem.clone();
    drop(state);
    let mut state = CertificateState::new(fs, "relay-hkg-1").unwrap();
    state
        .renew(backend.as_ref(), "renewal-1", 500)
        .await
        .unwrap();
    assert_eq!(
        backend.renewals.lock().unwrap()[1].csr_pem,
        first_renewal_csr
    );
    let new_certificate = state.active_certificate().unwrap();
    assert_ne!(state.public_key(), old_public_key);
    assert_eq!(certificate_public_key(&new_certificate), state.public_key());
}

#[tokio::test]
async fn certificate_delivery_is_retained_for_retry_when_atomic_persist_fails() {
    let fs = Arc::new(MemoryIdentityFs::default());
    let backend = Arc::new(FakeBackend::default());
    backend
        .enrollment_results
        .lock()
        .unwrap()
        .push_back(Ok(EnrollmentStatus::Pending {
            enrollment_id: "enrollment-persist".into(),
            receipt: secrecy::SecretString::from("one-use-persist-receipt"),
        }));
    let mut state = CertificateState::new(fs.clone(), "relay-hkg-1").unwrap();
    state
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let enrollment_csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(issue_certificate_for_csr(&enrollment_csr, 1_000))));
    *fs.fail_next_writes.lock().unwrap() = 1;
    assert_eq!(
        state.pickup(backend.as_ref()).await,
        Err(RuntimeError::IdentityIo)
    );
    assert!(state.active_certificate().is_none());
    assert!(state.pickup(backend.as_ref()).await.unwrap());
    let delivered_certificate = state.active_certificate().unwrap();
    let delivered_public_key = state.public_key();
    assert_eq!(
        certificate_public_key(&delivered_certificate),
        delivered_public_key
    );
    assert_eq!(backend.pickups.lock().unwrap().len(), 1);

    *fs.fail_next_writes.lock().unwrap() = 3;
    assert_eq!(
        state.renew(backend.as_ref(), "renew-persist", 500).await,
        Err(RuntimeError::IdentityIo)
    );
    assert_eq!(state.public_key(), delivered_public_key);
    state
        .renew(backend.as_ref(), "renew-persist", 501)
        .await
        .unwrap();
    let renewed_certificate = state.active_certificate().unwrap();
    assert_ne!(state.public_key(), delivered_public_key);
    assert_eq!(
        certificate_public_key(&renewed_certificate),
        state.public_key()
    );
    assert_eq!(backend.renewals.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn enrollment_receipt_survives_restart_and_mismatched_certificate_is_rejected() {
    let fs = Arc::new(MemoryIdentityFs::default());
    let backend = Arc::new(FakeBackend::default());
    backend
        .enrollment_results
        .lock()
        .unwrap()
        .push_back(Ok(EnrollmentStatus::Pending {
            enrollment_id: "enrollment-restart".into(),
            receipt: secrecy::SecretString::from("one-use-restart-receipt"),
        }));
    let mut first = CertificateState::new(fs.clone(), "relay-hkg-1").unwrap();
    first
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    drop(first);

    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(invalid_certificate("wrong-key", 1_000))));
    let mut restarted = CertificateState::new(fs.clone(), "relay-hkg-1").unwrap();
    assert_eq!(
        restarted.pickup(backend.as_ref()).await,
        Err(RuntimeError::CertificateInvalid)
    );
    assert!(restarted.active_certificate().is_none());

    let csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    let good_certificate = issue_certificate_for_csr(&csr, 1_000);
    assert_eq!(
        certificate_public_key(&good_certificate),
        restarted.public_key()
    );
    let (_, leaf_pem) = parse_x509_pem(good_certificate.certificate_pem.as_bytes()).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_pem.contents).unwrap();
    let (_, ca_pem) = parse_x509_pem(good_certificate.ca_certificate_pem.as_bytes()).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_pem.contents).unwrap();
    assert_eq!(leaf.issuer(), ca.subject());
    leaf.verify_signature(Some(ca.public_key())).unwrap();
    assert!(ca.basic_constraints().unwrap().unwrap().value.ca);
    let san = leaf.subject_alternative_name().unwrap().unwrap();
    assert!(san.value.general_names.iter().any(|name| matches!(
        name,
        x509_parser::extensions::GeneralName::URI(uri)
            if *uri == "urn:mrd:relay:relay-hkg-1"
    )));
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(good_certificate)));
    restarted.pickup(backend.as_ref()).await.unwrap();
    assert_eq!(backend.pickups.lock().unwrap().len(), 2);
    let certificate = restarted.active_certificate().unwrap();
    assert_eq!(certificate_public_key(&certificate), restarted.public_key());
}

#[tokio::test]
async fn signed_heartbeat_counter_survives_restart_and_exact_body_verifies() {
    let fs = Arc::new(MemoryIdentityFs::default());
    let backend = Arc::new(FakeBackend::default());
    backend
        .enrollment_results
        .lock()
        .unwrap()
        .push_back(Ok(EnrollmentStatus::Pending {
            enrollment_id: "enrollment-counter".into(),
            receipt: secrecy::SecretString::from("one-use-counter-receipt"),
        }));
    let mut first = CertificateState::new(fs.clone(), "relay-hkg-1").unwrap();
    first
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let enrollment_csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(issue_certificate_for_csr(&enrollment_csr, 1_000))));
    first.pickup(backend.as_ref()).await.unwrap();
    let payload = HeartbeatPayload {
        active_allocations: 3,
        current_egress_bps: 9_000,
        measured_rtt_ms: Some(27),
        recent_failure_bps: 5,
        endpoints: vec!["turn:relay.example:3478?transport=udp".into()],
    };
    let first_public_key = first.public_key();
    let signed_one = first.sign_heartbeat(500, payload.clone()).unwrap();
    assert_eq!(signed_one.sequence, 1);
    drop(first);

    let mut second = CertificateState::new(fs, "relay-hkg-1").unwrap();
    let signed_two = second.sign_heartbeat(501, payload.clone()).unwrap();
    assert_eq!(signed_two.sequence, 2);
    assert_eq!(
        serde_json::from_slice::<HeartbeatPayload>(&signed_two.body).unwrap(),
        payload
    );
    let canonical = canonical_relay_request(
        "POST",
        "/api/v1/relays/relay-hkg-1/heartbeat",
        "relay-hkg-1",
        501,
        2,
        &signed_two.body,
    )
    .unwrap();
    let signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signed_two.signature_b64,
    )
    .unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, first_public_key)
        .verify(&canonical, &signature)
        .unwrap();
}

#[test]
fn heartbeat_signature_matches_task4_length_prefixed_wire_contract() {
    let body = br#"{"active_allocations":1,"current_egress_bps":2,"measured_rtt_ms":null,"recent_failure_bps":0,"endpoints":["turn:relay.example:3478?transport=udp"]}"#;
    let canonical = canonical_relay_request(
        "POST",
        "/api/v1/relays/relay-hkg-1/heartbeat",
        "relay-hkg-1",
        1_725_000_000,
        7,
        body,
    )
    .unwrap();
    assert!(canonical.starts_with(b"MRD_RELAY_REQUEST_V1\0"));
    assert_eq!(
        &canonical[canonical.len() - 32..],
        sha2::Sha256::digest(body).as_slice()
    );
}

#[test]
fn backend_response_wire_is_bounded_identity_bound_and_rejects_schema_drift() {
    let enrollment = br#"{"enrollment_id":"enroll-1","node_id":"relay-hkg-1","status":"pending","receipt":"receipt-that-is-long-enough-for-the-contract"}"#;
    assert!(decode_enrollment_response(enrollment, "relay-hkg-1").is_ok());
    assert_eq!(
        decode_enrollment_response(enrollment, "relay-other").unwrap_err(),
        BackendError::ProtocolInvalid
    );
    let drifted = br#"{"enrollment_id":"enroll-1","node_id":"relay-hkg-1","status":"pending","receipt":"receipt-that-is-long-enough-for-the-contract","unexpected":true}"#;
    assert_eq!(
        decode_enrollment_response(drifted, "relay-hkg-1").unwrap_err(),
        BackendError::ProtocolInvalid
    );

    let heartbeat = br#"{"node_id":"relay-hkg-1","state":"draining","sequence":7,"lease_expires_at":"2026-08-23T12:00:00Z"}"#;
    let directive = decode_heartbeat_response(heartbeat, "relay-hkg-1", 7).unwrap();
    assert!(directive.draining);
    assert_eq!(directive.sequence, 7);
    assert_eq!(
        decode_heartbeat_response(heartbeat, "relay-hkg-1", 8).unwrap_err(),
        BackendError::ProtocolInvalid
    );
    assert_eq!(
        decode_heartbeat_response(&vec![b'x'; 256 * 1024 + 1], "relay-hkg-1", 7).unwrap_err(),
        BackendError::ProtocolInvalid
    );
}

#[tokio::test]
async fn heartbeat_schedule_uses_monotonic_time_even_when_wall_clock_moves_back() {
    let clock = Arc::new(FakeClock::default());
    let sleeper = Arc::new(FakeSleeper::default());
    *clock.monotonic_ms.lock().unwrap() = 10_000;
    *clock.unix_seconds.lock().unwrap() = 500;
    let mut runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        Arc::new(FakeCoturn::default()),
        clock.clone(),
        sleeper.clone(),
        Arc::new(FixedJitter(0)),
    );

    assert_eq!(runtime.delay_until_next_heartbeat(), Duration::ZERO);
    runtime.note_heartbeat_attempt();
    *clock.monotonic_ms.lock().unwrap() = 12_000;
    *clock.unix_seconds.lock().unwrap() = 100;
    assert_eq!(runtime.delay_until_next_heartbeat(), Duration::from_secs(3));
    *clock.monotonic_ms.lock().unwrap() = 15_000;
    assert_eq!(runtime.delay_until_next_heartbeat(), Duration::ZERO);
}

#[tokio::test]
async fn heartbeat_once_uses_backend_directive_without_stalling_local_supervisor() {
    let backend = Arc::new(FakeBackend::default());
    backend
        .heartbeat_results
        .lock()
        .unwrap()
        .push_back(Ok(NodeDirective::state(1, true)));
    let coturn = Arc::new(FakeCoturn::default());
    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(4, 40)));
    let mut runtime = AgentRuntime::new_volatile(
        backend.clone(),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
    );
    runtime.supervise_coturn_once().await.unwrap();
    runtime
        .heartbeat_once(SignedHeartbeat {
            node_id: "relay-hkg-1".into(),
            timestamp: 500,
            sequence: 1,
            body: b"{}".to_vec(),
            signature_b64: "signature".into(),
        })
        .await
        .unwrap();
    assert_eq!(backend.heartbeats.lock().unwrap().len(), 1);
    assert_eq!(runtime.process_health(), ProcessHealth::Healthy);
    assert!(runtime.is_draining());
}

#[test]
fn metrics_parser_is_bounded_and_rejects_non_finite_overflow_and_duplicates() {
    let valid = "turn_active_allocations 12\nturn_current_ingress_bps 1000\nturn_current_egress_bps 2000\nturn_errors_total 3\n";
    let sample = parse_coturn_metrics(valid.as_bytes(), MetricsLimits::default()).unwrap();
    assert_eq!(sample.active_allocations, 12);
    assert_eq!(sample.current_egress_bps, 2_000);
    assert_eq!(sample.errors_total, 3);

    for invalid in [
        "turn_active_allocations NaN\n",
        "turn_active_allocations inf\n",
        "turn_active_allocations 18446744073709551616\n",
        "turn_active_allocations 1\nturn_active_allocations 2\n",
        "turn_active_allocations{peer=\"secret-label\"} 1\n",
    ] {
        assert!(matches!(
            parse_coturn_metrics(invalid.as_bytes(), MetricsLimits::default()),
            Err(MetricsError::Invalid)
        ));
    }
    let oversized = vec![b'x'; MetricsLimits::default().max_input_bytes + 1];
    assert_eq!(
        parse_coturn_metrics(&oversized, MetricsLimits::default()),
        Err(MetricsError::TooLarge)
    );
}

#[test]
fn production_metrics_source_is_restricted_to_loopback_and_clock_jitter_are_bounded() {
    assert!(ReqwestCoturnMetrics::new(
        "http://127.0.0.1:9641/metrics".parse().unwrap(),
        MetricsLimits::default(),
    )
    .is_ok());
    assert!(ReqwestCoturnMetrics::new(
        "http://[::1]:9641/metrics".parse().unwrap(),
        MetricsLimits::default(),
    )
    .is_ok());
    assert!(ReqwestCoturnMetrics::new(
        "http://metrics.example/metrics".parse().unwrap(),
        MetricsLimits::default(),
    )
    .is_err());

    let clock = SystemClock::new();
    let first = clock.monotonic_ms();
    let second = clock.monotonic_ms();
    assert!(second >= first);
    assert!(clock.unix_seconds() > 0);
    let jitter = RandomJitter;
    for _ in 0..100 {
        assert!(jitter.jitter_ms(17) < 17);
    }
    assert_eq!(jitter.jitter_ms(0), 0);
}

#[test]
fn reqwest_backend_can_enroll_before_mtls_and_only_installs_a_matching_identity_explicitly() {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let certificate = CertificateParams::default().self_signed(&key).unwrap();
    let backend = ReqwestRelayBackend::new(
        "https://relay-control.example/".parse().unwrap(),
        certificate.pem().as_bytes(),
    )
    .unwrap();
    backend
        .with_mtls_identity(certificate.pem().as_bytes(), key.serialize_pem().as_bytes())
        .unwrap();
}

#[tokio::test]
async fn local_probe_requires_allocation_permission_and_bidirectional_roundtrip_evidence() {
    let weak = AllocationProbeEvidence {
        allocated_relay_address: None,
        permission_installed: false,
        sent_nonce: [7; 16],
        received_nonce: None,
        bytes_sent: 0,
        bytes_received: 0,
    };
    assert!(!weak.is_real_roundtrip());
    let strong = AllocationProbeEvidence {
        allocated_relay_address: Some("127.0.0.1:55000".parse().unwrap()),
        permission_installed: true,
        sent_nonce: [7; 16],
        received_nonce: Some([7; 16]),
        bytes_sent: 16,
        bytes_received: 16,
    };
    assert!(strong.is_real_roundtrip());

    let coturn = Arc::new(FakeCoturn::default());
    coturn.probes.lock().unwrap().push_back(Ok(weak));
    coturn.probes.lock().unwrap().push_back(Ok(strong.clone()));
    let mut runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        coturn,
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
    );
    assert!(matches!(
        runtime.probe_coturn_once().await,
        Err(RuntimeError::Process(ProcessError::ProbeInvalid))
    ));
    assert_eq!(runtime.probe_coturn_once().await.unwrap(), strong);
}

#[tokio::test]
async fn coturn_restart_is_attempted_exactly_three_times_then_stays_failed() {
    let coturn = Arc::new(FakeCoturn::default());
    for _ in 0..5 {
        coturn
            .snapshots
            .lock()
            .unwrap()
            .push_back(Ok(CoturnSnapshot {
                health: ProcessHealth::Failed,
                active_allocations: 0,
                current_egress_bps: 0,
            }));
    }
    let mut runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
    );
    for _ in 0..5 {
        runtime.supervise_coturn_once().await.unwrap();
    }
    assert_eq!(*coturn.restarts.lock().unwrap(), 3);
    assert_eq!(runtime.process_health(), ProcessHealth::Failed);

    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(0, 0)));
    runtime.supervise_coturn_once().await.unwrap();
    assert_eq!(runtime.restart_attempts(), 0);
}

#[tokio::test]
async fn snapshot_and_restart_errors_still_stop_after_exactly_three_attempts() {
    let coturn = Arc::new(FakeCoturn::default());
    for _ in 0..5 {
        coturn
            .snapshots
            .lock()
            .unwrap()
            .push_back(Err(ProcessError::Unavailable));
        coturn
            .restart_results
            .lock()
            .unwrap()
            .push_back(Err(ProcessError::Unavailable));
    }
    let mut runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
    );
    for _ in 0..5 {
        runtime.supervise_coturn_once().await.unwrap();
    }
    assert_eq!(*coturn.restarts.lock().unwrap(), 3);
    assert_eq!(runtime.process_health(), ProcessHealth::Failed);
}

#[tokio::test]
async fn backend_backoff_is_bounded_and_does_not_stop_local_supervision() {
    let coturn = Arc::new(FakeCoturn::default());
    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(2, 30)));
    let mut runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(17)),
    );
    for attempt in 0..20 {
        assert!(runtime.backend_retry_delay(attempt) <= Duration::from_secs(30));
    }
    runtime.supervise_coturn_once().await.unwrap();
    assert_eq!(runtime.process_health(), ProcessHealth::Healthy);
}

#[tokio::test]
async fn directives_reject_replay_and_apply_drain_and_secret_monotonically() {
    let coturn = Arc::new(FakeCoturn::default());
    let mut runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
    );
    assert!(matches!(
        runtime
            .apply_directive(NodeDirective::update(
                1,
                false,
                1,
                SecretBytes::new(b"unsafe-secret".to_vec()),
            ))
            .await,
        Err(RuntimeError::SecretUpdateUnsafe)
    ));
    runtime
        .apply_directive(NodeDirective::update(
            10,
            true,
            4,
            SecretBytes::new(b"secret-v4".to_vec()),
        ))
        .await
        .unwrap();
    runtime
        .apply_directive(NodeDirective::update(
            11,
            true,
            4,
            SecretBytes::new(b"secret-v4".to_vec()),
        ))
        .await
        .unwrap();
    assert!(matches!(
        runtime
            .apply_directive(NodeDirective::update(
                9,
                false,
                3,
                SecretBytes::new(b"old-secret".to_vec())
            ))
            .await,
        Err(RuntimeError::DirectiveReplay)
    ));
    assert_eq!(coturn.secret_versions.lock().unwrap().as_slice(), &[4]);
    assert_eq!(coturn.drains.lock().unwrap().as_slice(), &[true]);
    assert!(runtime.is_draining());

    assert!(matches!(
        runtime
            .apply_directive(NodeDirective::update(
                12,
                true,
                4,
                SecretBytes::new(b"different-v4-secret".to_vec()),
            ))
            .await,
        Err(RuntimeError::SecretVersionReplay)
    ));
}

#[tokio::test]
async fn directive_sequence_secret_version_and_drain_survive_runtime_restart() {
    let state_store = Arc::new(FakeRuntimeStateStore::default());
    let coturn = Arc::new(FakeCoturn::default());
    let mut first = AgentRuntime::new_with_state_store(
        Arc::new(FakeBackend::default()),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        state_store.clone(),
    )
    .unwrap();
    first
        .apply_directive(NodeDirective::update(
            10,
            true,
            4,
            SecretBytes::new(b"secret-v4".to_vec()),
        ))
        .await
        .unwrap();
    drop(first);

    let mut restarted = AgentRuntime::new_with_state_store(
        Arc::new(FakeBackend::default()),
        coturn,
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        state_store,
    )
    .unwrap();
    assert!(restarted.is_draining());
    assert!(matches!(
        restarted
            .apply_directive(NodeDirective::update(
                9,
                false,
                3,
                SecretBytes::new(b"old-secret".to_vec()),
            ))
            .await,
        Err(RuntimeError::DirectiveReplay)
    ));
    assert!(matches!(
        restarted
            .apply_directive(NodeDirective::update(
                11,
                true,
                4,
                SecretBytes::new(b"different-v4-secret".to_vec()),
            ))
            .await,
        Err(RuntimeError::SecretVersionReplay)
    ));
}

#[test]
fn configuration_requires_https_bounded_values_safe_absolute_path_and_redacts_secrets() {
    let valid_turn_secret = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        (0u8..32).collect::<Vec<_>>(),
    );
    let mut config = AgentConfig {
        backend_url: "https://relay-control.example/".parse().unwrap(),
        node_id: "relay-hkg-1".into(),
        region: "hkg".into(),
        failure_domain: "hkg-a".into(),
        endpoints: vec!["turn:relay.example:3478?transport=udp".into()],
        max_allocations: 100,
        max_egress_bps: 1_000_000,
        identity_path: std::env::temp_dir().join("mrd-relay-agent-identity.json"),
        enrollment_token: Some(secrecy::SecretString::from(
            "private-enrollment-token-that-is-never-logged-1234",
        )),
        turn_rest_secret: Some(secrecy::SecretString::from(valid_turn_secret.clone())),
        heartbeat_interval: Duration::from_secs(5),
        backend_backoff_cap: Duration::from_secs(30),
    };
    assert_eq!(config.validate(), Ok(()));
    let debug = format!("{config:?}");
    assert!(!debug.contains("private-enrollment-token"));
    assert!(!debug.contains(&valid_turn_secret));

    config.backend_url = "http://relay-control.example/".parse().unwrap();
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
    config.backend_url = "https://user:password@relay-control.example/"
        .parse()
        .unwrap();
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
    config.backend_url = "https://relay-control.example/".parse().unwrap();
    config.identity_path = std::path::PathBuf::from("relative/identity.json");
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
    config.identity_path = std::env::temp_dir().join("mrd-relay-agent-identity.json");
    config.turn_rest_secret = Some(secrecy::SecretString::from(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ));
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
}

#[test]
fn secret_and_error_rendering_are_always_redacted_and_reason_codes_are_stable() {
    let secret = SecretBytes::new(b"ultra-sensitive-turn-secret".to_vec());
    let mut rendered = String::new();
    write!(&mut rendered, "{secret:?} {secret}").unwrap();
    assert!(!rendered.contains("ultra-sensitive"));
    assert!(rendered.contains("REDACTED"));
    assert_eq!(
        BackendError::Unavailable.reason_code(),
        "relay_backend_unavailable"
    );
    assert_eq!(
        ProcessError::ProbeUnavailable.reason_code(),
        "relay_probe_unavailable"
    );
}
