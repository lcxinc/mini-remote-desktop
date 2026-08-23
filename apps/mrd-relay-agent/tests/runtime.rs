use std::{
    collections::VecDeque,
    fmt::Write as _,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use mrd_relay_agent::{
    backend::{
        canonical_relay_request, decode_enrollment_response, decode_heartbeat_response,
        decode_pickup_response, rotation_proof_message, BackendError, DesiredNodeState,
        EnrollmentRequest, EnrollmentStatus, HeartbeatPayload, NodeCertificate, NodeDirective,
        PickupRequest, RelayBackendClientFactoryPort, RelayBackendPort, RelayHealth,
        RelayNodeState, RenewalRequest, ReqwestRelayBackend, SecretCommitRequest,
        SecretUploadRequest, SignedHeartbeat, SwappableRelayBackend,
    },
    config::{AgentConfig, ConfigError},
    identity::{load_or_create_identity, CertificateState, IdentityFsPort, StoredIdentity},
    metrics::{
        parse_coturn_metrics, CoturnMetrics, MetricsError, MetricsLimits, MetricsPort,
        ReqwestCoturnMetrics,
    },
    process::{
        AllocationProbeEvidence, CoturnRuntimePort, CoturnSnapshot, LocalAllocationProbePort,
        ProcessError, ProcessHealth, SecretBytes, WebRtcLocalAllocationProbe,
    },
    runtime::{
        backend_worker_once, run_agent, AgentRuntime, ClockPort, CoturnSupervisor,
        HeartbeatSampler, HostPressureSnapshot, IdentityLifecycle, IdentityMaintenance, JitterPort,
        PortableRelayAgentConfig, PortableRelayAgentDeps, RandomJitter, RuntimeError,
        RuntimeStateSnapshot, RuntimeStateStorePort, SecretRotationPhase, SharedRelayHealth,
        SleeperPort, StdRuntimeStateStore, SystemClock,
    },
};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams,
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use ring::signature::KeyPair as _;
use rustls_pki_types::PrivatePkcs8KeyDer;
use secrecy::ExposeSecret as _;
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

struct FakeBackend {
    issuer: TestCertificateAuthority,
    enrollments: Mutex<Vec<EnrollmentRequest>>,
    pickups: Mutex<Vec<PickupRequest>>,
    renewals: Mutex<Vec<RenewalRequest>>,
    heartbeats: Mutex<Vec<SignedHeartbeat>>,
    enrollment_results: Mutex<VecDeque<Result<EnrollmentStatus, BackendError>>>,
    pickup_results: Mutex<VecDeque<Result<Option<NodeCertificate>, BackendError>>>,
    renewal_results: Mutex<VecDeque<Result<NodeCertificate, BackendError>>>,
    heartbeat_results: Mutex<VecDeque<Result<NodeDirective, BackendError>>>,
    uploads: Mutex<Vec<SecretUploadRequest>>,
    commits: Mutex<Vec<SecretCommitRequest>>,
    upload_results: Mutex<VecDeque<Result<(), BackendError>>>,
    commit_results: Mutex<VecDeque<Result<(), BackendError>>>,
    auto_issue_pickup: Mutex<bool>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            issuer: TestCertificateAuthority::new(),
            enrollments: Mutex::default(),
            pickups: Mutex::default(),
            renewals: Mutex::default(),
            heartbeats: Mutex::default(),
            enrollment_results: Mutex::default(),
            pickup_results: Mutex::default(),
            renewal_results: Mutex::default(),
            heartbeat_results: Mutex::default(),
            uploads: Mutex::default(),
            commits: Mutex::default(),
            upload_results: Mutex::default(),
            commit_results: Mutex::default(),
            auto_issue_pickup: Mutex::new(false),
        }
    }
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
        let explicit = self.pickup_results.lock().unwrap().pop_front();
        if let Some(result) = explicit {
            return result;
        }
        if *self.auto_issue_pickup.lock().unwrap() {
            let csr = self
                .enrollments
                .lock()
                .unwrap()
                .last()
                .ok_or(BackendError::ProtocolInvalid)?
                .csr_pem
                .clone();
            return Ok(Some(self.issuer.issue(&csr, LeafProfile::Client)));
        }
        Ok(None)
    }

    async fn renew(&self, request: RenewalRequest) -> Result<NodeCertificate, BackendError> {
        let csr_pem = request.csr_pem.clone();
        self.renewals.lock().unwrap().push(request);
        if let Some(result) = self.renewal_results.lock().unwrap().pop_front() {
            return result;
        }
        Ok(self.issuer.issue(&csr_pem, LeafProfile::Client))
    }

    async fn heartbeat(&self, heartbeat: SignedHeartbeat) -> Result<NodeDirective, BackendError> {
        self.heartbeats.lock().unwrap().push(heartbeat);
        self.heartbeat_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(BackendError::Unavailable))
    }

    async fn upload_secret(&self, request: SecretUploadRequest) -> Result<(), BackendError> {
        self.uploads.lock().unwrap().push(request);
        self.upload_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(()))
    }

    async fn commit_secret(&self, request: SecretCommitRequest) -> Result<(), BackendError> {
        self.commits.lock().unwrap().push(request);
        self.commit_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(()))
    }
}

struct PendingHeartbeatBackend {
    entered: Arc<tokio::sync::Semaphore>,
}

#[async_trait]
impl RelayBackendPort for PendingHeartbeatBackend {
    async fn enroll(&self, _request: EnrollmentRequest) -> Result<EnrollmentStatus, BackendError> {
        Err(BackendError::Unavailable)
    }

    async fn pickup(
        &self,
        _request: PickupRequest,
    ) -> Result<Option<NodeCertificate>, BackendError> {
        Err(BackendError::Unavailable)
    }

    async fn renew(&self, _request: RenewalRequest) -> Result<NodeCertificate, BackendError> {
        Err(BackendError::Unavailable)
    }

    async fn heartbeat(&self, _heartbeat: SignedHeartbeat) -> Result<NodeDirective, BackendError> {
        self.entered.add_permits(1);
        std::future::pending().await
    }
}

struct FakeBackendFactory {
    failures: Mutex<u32>,
    builds: Mutex<Vec<Vec<u8>>>,
    replacement: Arc<FakeBackend>,
}

struct StaticBackendFactory(Arc<dyn RelayBackendPort>);

impl RelayBackendClientFactoryPort for StaticBackendFactory {
    fn build_mtls(
        &self,
        _certificate: &NodeCertificate,
        _private_pkcs8: &[u8],
    ) -> Result<Arc<dyn RelayBackendPort>, BackendError> {
        Ok(self.0.clone())
    }
}

impl FakeBackendFactory {
    fn new(failures: u32, replacement: Arc<FakeBackend>) -> Self {
        Self {
            failures: Mutex::new(failures),
            builds: Mutex::default(),
            replacement,
        }
    }
}

impl RelayBackendClientFactoryPort for FakeBackendFactory {
    fn build_mtls(
        &self,
        certificate: &NodeCertificate,
        private_pkcs8: &[u8],
    ) -> Result<Arc<dyn RelayBackendPort>, BackendError> {
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(private_pkcs8)
            .map_err(|_| BackendError::TlsInvalid)?;
        if certificate_public_key(certificate) != key.public_key().as_ref() {
            return Err(BackendError::TlsInvalid);
        }
        self.builds
            .lock()
            .unwrap()
            .push(certificate_public_key(certificate));
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Err(BackendError::TlsInvalid);
        }
        Ok(self.replacement.clone())
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

struct NotifyingCoturn {
    supervised: Arc<tokio::sync::Semaphore>,
}

#[async_trait]
impl CoturnRuntimePort for NotifyingCoturn {
    async fn snapshot(&self) -> Result<CoturnSnapshot, ProcessError> {
        self.supervised.add_permits(1);
        Ok(CoturnSnapshot::healthy(0, 0))
    }

    async fn restart(&self) -> Result<(), ProcessError> {
        Ok(())
    }

    async fn apply_secret(&self, _version: u64, _secret: SecretBytes) -> Result<(), ProcessError> {
        Ok(())
    }

    async fn set_draining(&self, _draining: bool) -> Result<(), ProcessError> {
        Ok(())
    }

    async fn probe_local_allocation(&self) -> Result<AllocationProbeEvidence, ProcessError> {
        Err(ProcessError::ProbeUnavailable)
    }
}

#[derive(Default)]
struct FakeClock {
    monotonic_ms: Mutex<u64>,
    unix_seconds: Mutex<i64>,
}

struct FakeMetrics(CoturnMetrics);

#[async_trait]
impl MetricsPort for FakeMetrics {
    async fn collect(&self) -> Result<CoturnMetrics, MetricsError> {
        Ok(self.0.clone())
    }
}

struct NonEvidenceProbe;

#[async_trait]
impl LocalAllocationProbePort for NonEvidenceProbe {
    async fn probe(&self) -> Result<AllocationProbeEvidence, ProcessError> {
        Ok(AllocationProbeEvidence::NonEvidence)
    }
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

struct AdvancingSleeper {
    clock: Arc<FakeClock>,
    sleeps: Mutex<Vec<Duration>>,
}

#[async_trait]
impl SleeperPort for AdvancingSleeper {
    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
        let delta = u64::try_from(duration.as_millis()).unwrap();
        let mut monotonic = self.clock.monotonic_ms.lock().unwrap();
        *monotonic = monotonic.saturating_add(delta);
    }
}

struct FixedJitter(u64);

impl JitterPort for FixedJitter {
    fn jitter_ms(&self, _upper_exclusive: u64) -> u64 {
        self.0
    }
}

async fn one_response_server(response: &'static [u8]) -> url::Url {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 2048];
        let _ = stream.read(&mut request).await;
        stream.write_all(response).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    format!("http://{address}/metrics").parse().unwrap()
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

const CERT_NOW_UNIX_SECONDS: i64 = 1_800_000_000;
const ROTATION_CHALLENGE: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

#[derive(Clone, Copy)]
enum LeafProfile {
    Client,
    MissingBasicConstraints,
    MissingDigitalSignature,
    MissingClientAuth,
    Ca,
    Expired,
    NotYetValid,
    WrongCommonName,
    DuplicateSan,
}

struct TestCertificateAuthority {
    key: KeyPair,
    certificate: Certificate,
}

impl TestCertificateAuthority {
    fn new() -> Self {
        Self::with_settings(
            date_time_ymd(2025, 1, 1),
            date_time_ymd(2035, 1, 1),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        )
    }

    fn with_settings(
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
        key_usages: Vec<KeyUsagePurpose>,
    ) -> Self {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "MRD test relay CA");
        params.distinguished_name = distinguished_name;
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = key_usages;
        let certificate = params.self_signed(&key).unwrap();
        Self { key, certificate }
    }

    fn pem(&self) -> String {
        self.certificate.pem()
    }

    fn issue(&self, csr_pem: &str, profile: LeafProfile) -> NodeCertificate {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        csr.params.not_before = date_time_ymd(2026, 1, 1);
        csr.params.not_after = date_time_ymd(2030, 1, 1);
        csr.params.is_ca = IsCa::ExplicitNoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        match profile {
            LeafProfile::Client => {}
            LeafProfile::MissingBasicConstraints => csr.params.is_ca = IsCa::NoCa,
            LeafProfile::MissingDigitalSignature => csr.params.key_usages.clear(),
            LeafProfile::MissingClientAuth => csr.params.extended_key_usages.clear(),
            LeafProfile::Ca => csr.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
            LeafProfile::Expired => csr.params.not_after = date_time_ymd(2026, 2, 1),
            LeafProfile::NotYetValid => csr.params.not_before = date_time_ymd(2031, 1, 1),
            LeafProfile::WrongCommonName => {
                let mut name = DistinguishedName::new();
                name.push(DnType::CommonName, "relay-hkg-other");
                csr.params.distinguished_name = name;
            }
            LeafProfile::DuplicateSan => {
                csr.params
                    .subject_alt_names
                    .push(csr.params.subject_alt_names[0].clone());
            }
        }
        let leaf = csr.signed_by(&self.certificate, &self.key).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf.der()).unwrap();
        NodeCertificate {
            certificate_pem: leaf.pem(),
            ca_certificate_pem: self.pem(),
            expires_at_unix_seconds: parsed.validity().not_after.timestamp(),
        }
    }
}

fn certificate_state(
    fs: Arc<MemoryIdentityFs>,
    backend: &Arc<FakeBackend>,
) -> CertificateState<MemoryIdentityFs> {
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    CertificateState::new(fs, "relay-hkg-1", &backend.issuer.pem(), clock).unwrap()
}

fn issue_certificate_for_csr(issuer: &TestCertificateAuthority, csr_pem: &str) -> NodeCertificate {
    issuer.issue(csr_pem, LeafProfile::Client)
}

async fn pending_certificate_state() -> (
    Arc<MemoryIdentityFs>,
    Arc<FakeBackend>,
    CertificateState<MemoryIdentityFs>,
    String,
) {
    let fs = Arc::new(MemoryIdentityFs::default());
    let backend = Arc::new(FakeBackend::default());
    backend
        .enrollment_results
        .lock()
        .unwrap()
        .push_back(Ok(EnrollmentStatus::Pending {
            enrollment_id: "enrollment-strict-cert".into(),
            receipt: secrecy::SecretString::from("one-use-strict-cert-receipt"),
        }));
    let mut state = certificate_state(fs.clone(), &backend);
    state
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    (fs, backend, state, csr)
}

async fn assert_leaf_profile_rejected(profile: LeafProfile) {
    let (_fs, backend, mut state, csr) = pending_certificate_state().await;
    let certificate = backend.issuer.issue(&csr, profile);
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(certificate)));
    assert_eq!(
        state.pickup(backend.as_ref()).await,
        Err(RuntimeError::CertificateInvalid)
    );
    assert!(state.active_certificate().is_none());
}

fn replace_stored_csr(fs: &MemoryIdentityFs, common_name: &str, san_count: usize) {
    let stored = fs.identity.lock().unwrap().clone().unwrap();
    let mut value = serde_json::to_value(stored).unwrap();
    let private_b64 = value["private_pkcs8_b64"].as_str().unwrap();
    let private =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, private_b64).unwrap();
    let private = PrivatePkcs8KeyDer::from(private);
    let key = KeyPair::from_pkcs8_der_and_sign_algo(&private, &PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name = distinguished_name;
    params.subject_alt_names = (0..san_count)
        .map(|_| rcgen::SanType::URI("urn:mrd:relay:relay-hkg-1".try_into().unwrap()))
        .collect();
    value["csr_pem"] =
        serde_json::Value::String(params.serialize_request(&key).unwrap().pem().unwrap());
    *fs.identity.lock().unwrap() = Some(serde_json::from_value(value).unwrap());
}

#[test]
fn identity_reload_rejects_wrong_csr_common_name_and_ambiguous_uri_san() {
    let wrong_cn = MemoryIdentityFs::default();
    load_or_create_identity(&wrong_cn, "relay-hkg-1").unwrap();
    replace_stored_csr(&wrong_cn, "relay-hkg-2", 1);
    assert!(matches!(
        load_or_create_identity(&wrong_cn, "relay-hkg-1"),
        Err(RuntimeError::IdentityInvalid)
    ));

    let duplicate_san = MemoryIdentityFs::default();
    load_or_create_identity(&duplicate_san, "relay-hkg-1").unwrap();
    replace_stored_csr(&duplicate_san, "relay-hkg-1", 2);
    assert!(matches!(
        load_or_create_identity(&duplicate_san, "relay-hkg-1"),
        Err(RuntimeError::IdentityInvalid)
    ));
}

#[tokio::test]
async fn certificate_rejects_missing_basic_constraints_ca_false() {
    assert_leaf_profile_rejected(LeafProfile::MissingBasicConstraints).await;
}

#[tokio::test]
async fn certificate_rejects_missing_digital_signature_key_usage() {
    assert_leaf_profile_rejected(LeafProfile::MissingDigitalSignature).await;
}

#[tokio::test]
async fn certificate_rejects_missing_client_auth_extended_key_usage() {
    assert_leaf_profile_rejected(LeafProfile::MissingClientAuth).await;
}

#[tokio::test]
async fn certificate_rejects_leaf_marked_as_ca() {
    assert_leaf_profile_rejected(LeafProfile::Ca).await;
}

#[tokio::test]
async fn certificate_rejects_wrong_common_name_and_ambiguous_san() {
    assert_leaf_profile_rejected(LeafProfile::WrongCommonName).await;
    assert_leaf_profile_rejected(LeafProfile::DuplicateSan).await;
}

#[tokio::test]
async fn certificate_rejects_expired_or_not_yet_valid_leaf() {
    assert_leaf_profile_rejected(LeafProfile::Expired).await;
    assert_leaf_profile_rejected(LeafProfile::NotYetValid).await;
}

#[tokio::test]
async fn certificate_rejects_wire_expiry_that_differs_from_x509_not_after() {
    let (_fs, backend, mut state, csr) = pending_certificate_state().await;
    let mut certificate = backend.issuer.issue(&csr, LeafProfile::Client);
    certificate.expires_at_unix_seconds -= 1;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(certificate)));
    assert_eq!(
        state.pickup(backend.as_ref()).await,
        Err(RuntimeError::CertificateInvalid)
    );
}

#[tokio::test]
async fn certificate_rejects_chain_not_anchored_to_configured_trust_root() {
    let (_fs, backend, mut state, csr) = pending_certificate_state().await;
    let untrusted_issuer = TestCertificateAuthority::new();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(untrusted_issuer.issue(&csr, LeafProfile::Client))));
    assert_eq!(
        state.pickup(backend.as_ref()).await,
        Err(RuntimeError::CertificateInvalid)
    );
}

#[test]
fn configured_ca_rejects_expired_future_and_missing_key_cert_sign() {
    for ca in [
        TestCertificateAuthority::with_settings(
            date_time_ymd(2020, 1, 1),
            date_time_ymd(2021, 1, 1),
            vec![KeyUsagePurpose::KeyCertSign],
        ),
        TestCertificateAuthority::with_settings(
            date_time_ymd(2031, 1, 1),
            date_time_ymd(2035, 1, 1),
            vec![KeyUsagePurpose::KeyCertSign],
        ),
        TestCertificateAuthority::with_settings(
            date_time_ymd(2025, 1, 1),
            date_time_ymd(2035, 1, 1),
            vec![KeyUsagePurpose::CrlSign],
        ),
    ] {
        let clock = Arc::new(FakeClock::default());
        *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
        assert!(matches!(
            CertificateState::new(
                Arc::new(MemoryIdentityFs::default()),
                "relay-hkg-1",
                &ca.pem(),
                clock,
            ),
            Err(RuntimeError::CertificateInvalid)
        ));
    }
}

#[tokio::test]
async fn certificate_reload_revalidates_active_and_pending_pairs() {
    let (fs, backend, mut state, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    state.pickup(backend.as_ref()).await.unwrap();

    let original = fs.identity.lock().unwrap().clone().unwrap();
    let mut corrupt_active = serde_json::to_value(original.clone()).unwrap();
    corrupt_active["certificate"]["expires_at_unix_seconds"] =
        serde_json::Value::from(CERT_NOW_UNIX_SECONDS);
    *fs.identity.lock().unwrap() = Some(serde_json::from_value(corrupt_active).unwrap());
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    assert!(matches!(
        CertificateState::new(fs.clone(), "relay-hkg-1", &backend.issuer.pem(), clock),
        Err(RuntimeError::CertificateInvalid)
    ));

    *fs.identity.lock().unwrap() = Some(original);
    backend
        .renewal_results
        .lock()
        .unwrap()
        .push_back(Err(BackendError::Unavailable));
    assert_eq!(
        state
            .renew(backend.as_ref(), "renew-reload", CERT_NOW_UNIX_SECONDS)
            .await,
        Err(RuntimeError::Backend(BackendError::Unavailable))
    );
    let pending_csr = backend.renewals.lock().unwrap()[0].csr_pem.clone();
    let expired = backend.issuer.issue(&pending_csr, LeafProfile::Expired);
    let mut pending = serde_json::to_value(fs.identity.lock().unwrap().clone().unwrap()).unwrap();
    pending["pending_renewal"]["certificate"] = serde_json::json!({
        "certificate_pem": expired.certificate_pem,
        "ca_certificate_pem": expired.ca_certificate_pem,
        "expires_at_unix_seconds": expired.expires_at_unix_seconds,
    });
    *fs.identity.lock().unwrap() = Some(serde_json::from_value(pending).unwrap());
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    assert!(matches!(
        CertificateState::new(fs, "relay-hkg-1", &backend.issuer.pem(), clock),
        Err(RuntimeError::CertificateInvalid)
    ));
}

fn dummy_heartbeat(sequence: u64) -> SignedHeartbeat {
    SignedHeartbeat {
        node_id: "relay-hkg-1".into(),
        identity_epoch: 1,
        timestamp: CERT_NOW_UNIX_SECONDS,
        sequence,
        body: b"{}".to_vec(),
        signature_b64: "REDACTED-test-signature".into(),
    }
}

#[tokio::test]
async fn renewal_factory_failure_keeps_old_pair_and_backend_until_retry_succeeds() {
    let (_fs, backend, mut state, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    state.pickup(backend.as_ref()).await.unwrap();
    let old_public_key = state.public_key();
    let replacement = Arc::new(FakeBackend::default());
    let factory = FakeBackendFactory::new(1, replacement.clone());
    let slot = SwappableRelayBackend::new(backend.clone());

    assert_eq!(
        state
            .renew_and_swap(
                backend.as_ref(),
                "renew-client-factory",
                CERT_NOW_UNIX_SECONDS,
                &factory,
                &slot,
            )
            .await,
        Err(RuntimeError::Backend(BackendError::TlsInvalid))
    );
    assert_eq!(state.public_key(), old_public_key);
    assert!(slot.heartbeat(dummy_heartbeat(1)).await.is_err());
    assert_eq!(backend.heartbeats.lock().unwrap().len(), 1);
    assert!(replacement.heartbeats.lock().unwrap().is_empty());

    state
        .renew_and_swap(
            backend.as_ref(),
            "renew-client-factory",
            CERT_NOW_UNIX_SECONDS + 1,
            &factory,
            &slot,
        )
        .await
        .unwrap();
    assert_ne!(state.public_key(), old_public_key);
    assert!(slot.heartbeat(dummy_heartbeat(2)).await.is_err());
    assert_eq!(replacement.heartbeats.lock().unwrap().len(), 1);
    assert_eq!(factory.builds.lock().unwrap().len(), 2);
    assert_eq!(state.identity_epoch(), 2);
}

#[tokio::test]
async fn renewal_atomic_promotion_failure_keeps_old_pair_and_backend() {
    let (fs, backend, mut state, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    state.pickup(backend.as_ref()).await.unwrap();
    let old_public_key = state.public_key();
    let replacement = Arc::new(FakeBackend::default());
    let factory = FakeBackendFactory::new(0, replacement.clone());
    let slot = SwappableRelayBackend::new(backend.clone());
    *fs.fail_next_writes.lock().unwrap() = 4;

    assert_eq!(
        state
            .renew_and_swap(
                backend.as_ref(),
                "renew-atomic-failure",
                CERT_NOW_UNIX_SECONDS,
                &factory,
                &slot,
            )
            .await,
        Err(RuntimeError::IdentityIo)
    );
    assert_eq!(state.public_key(), old_public_key);
    assert!(slot.heartbeat(dummy_heartbeat(1)).await.is_err());
    assert_eq!(backend.heartbeats.lock().unwrap().len(), 1);
    assert!(replacement.heartbeats.lock().unwrap().is_empty());

    state
        .renew_and_swap(
            backend.as_ref(),
            "renew-atomic-failure",
            CERT_NOW_UNIX_SECONDS + 1,
            &factory,
            &slot,
        )
        .await
        .unwrap();
    assert_ne!(state.public_key(), old_public_key);
    assert!(slot.heartbeat(dummy_heartbeat(2)).await.is_err());
    assert_eq!(replacement.heartbeats.lock().unwrap().len(), 1);
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

    let mut state = certificate_state(fs.clone(), &backend);
    state
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let enrollment_csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(issue_certificate_for_csr(
            &backend.issuer,
            &enrollment_csr,
        ))));
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
    let mut state = certificate_state(fs, &backend);
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
    let mut state = certificate_state(fs.clone(), &backend);
    state
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let enrollment_csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(issue_certificate_for_csr(
            &backend.issuer,
            &enrollment_csr,
        ))));
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
    let mut first = certificate_state(fs.clone(), &backend);
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
    let mut restarted = certificate_state(fs.clone(), &backend);
    assert_eq!(
        restarted.pickup(backend.as_ref()).await,
        Err(RuntimeError::CertificateInvalid)
    );
    assert!(restarted.active_certificate().is_none());

    let csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    let good_certificate = issue_certificate_for_csr(&backend.issuer, &csr);
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
    let mut first = certificate_state(fs.clone(), &backend);
    first
        .enroll(backend.as_ref(), enrollment_request())
        .await
        .unwrap();
    let enrollment_csr = backend.enrollments.lock().unwrap()[0].csr_pem.clone();
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(issue_certificate_for_csr(
            &backend.issuer,
            &enrollment_csr,
        ))));
    first.pickup(backend.as_ref()).await.unwrap();
    let payload = HeartbeatPayload {
        identity_epoch: 1,
        boot_id: "AgICAgICAgICAgICAgICAg".into(),
        nonce: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into(),
        process_health: RelayHealth::Healthy,
        listener_health: RelayHealth::Healthy,
        probe_health: RelayHealth::Healthy,
        active_allocations: 3,
        current_ingress_bps: 4_500,
        current_egress_bps: 9_000,
        max_allocations: 100,
        max_egress_bps: 100_000,
        packet_loss_bps: 1,
        cpu_usage_bps: 2_000,
        memory_usage_bps: 3_000,
        measured_rtt_ms: Some(27),
        recent_failure_bps: 5,
        endpoints: vec!["turn:relay.example:3478?transport=udp".into()],
        applied_secret_version: 1,
    };
    let first_public_key = first.public_key();
    let signed_one = first.sign_heartbeat(500, payload.clone()).unwrap();
    assert_eq!(signed_one.sequence, 1);
    drop(first);

    let mut second = certificate_state(fs, &backend);
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
fn shared_heartbeat_fixture_binds_extended_request_and_available_directive() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/relay_heartbeat_wire_v1.json"
    ))
    .unwrap();
    let request_body = fixture["request_body_json"].as_str().unwrap().as_bytes();
    let payload: HeartbeatPayload = serde_json::from_slice(request_body).unwrap();
    assert_eq!(payload.identity_epoch, 7);
    assert_eq!(payload.boot_id, "AgICAgICAgICAgICAgICAg");
    assert_eq!(payload.nonce, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
    assert_eq!(payload.current_ingress_bps, 400_000);
    assert_eq!(payload.applied_secret_version, 4);

    let canonical = canonical_relay_request(
        fixture["method"].as_str().unwrap(),
        fixture["path"].as_str().unwrap(),
        fixture["node_id"].as_str().unwrap(),
        fixture["timestamp"].as_i64().unwrap(),
        fixture["sequence"].as_u64().unwrap(),
        request_body,
    )
    .unwrap();
    let canonical_hex = canonical
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(canonical_hex, fixture["canonical_hex"]);

    let directive = decode_heartbeat_response(
        fixture["response_body_json"].as_str().unwrap().as_bytes(),
        "relay-hkg-1",
        7,
        42,
    )
    .unwrap();
    assert_eq!(directive.identity_epoch, 7);
    assert_eq!(directive.state.as_str(), "available");
    assert!(!directive.desired.draining);
    assert_eq!(directive.desired.secret_version, 4);
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
    let invalid_id = br#"{"enrollment_id":"../pickup","node_id":"relay-hkg-1","status":"pending","receipt":"receipt-that-is-long-enough-for-the-contract"}"#;
    assert_eq!(
        decode_enrollment_response(invalid_id, "relay-hkg-1").unwrap_err(),
        BackendError::ProtocolInvalid
    );
    let pending = br#"{"enrollment_id":"enroll-1","node_id":"relay-hkg-1","status":"pending","certificate_pem":null,"ca_certificate_pem":null,"expires_at":null}"#;
    assert!(decode_pickup_response(pending, "enroll-1", "relay-hkg-1")
        .unwrap()
        .is_none());
    let ambiguous = br#"{"enrollment_id":"enroll-1","node_id":"relay-hkg-1","status":"pending","certificate_pem":"secret-pem","ca_certificate_pem":null,"expires_at":null}"#;
    assert_eq!(
        decode_pickup_response(ambiguous, "enroll-1", "relay-hkg-1").unwrap_err(),
        BackendError::ProtocolInvalid
    );
    let unknown = br#"{"enrollment_id":"enroll-1","node_id":"relay-hkg-1","status":"issued","certificate_pem":null,"ca_certificate_pem":null,"expires_at":null}"#;
    assert_eq!(
        decode_pickup_response(unknown, "enroll-1", "relay-hkg-1").unwrap_err(),
        BackendError::ProtocolInvalid
    );

    let heartbeat = br#"{"node_id":"relay-hkg-1","identity_epoch":1,"state":"draining","sequence":7,"desired":{"draining":true,"secret_version":1,"not_before":null,"old_credential_deadline":null},"lease_expires_at":"2026-08-23T12:00:00Z"}"#;
    let directive = decode_heartbeat_response(heartbeat, "relay-hkg-1", 1, 7).unwrap();
    assert!(directive.desired.draining);
    assert_eq!(directive.sequence, 7);
    assert_eq!(
        decode_heartbeat_response(heartbeat, "relay-hkg-1", 1, 8).unwrap_err(),
        BackendError::ProtocolInvalid
    );
    assert_eq!(
        decode_heartbeat_response(&vec![b'x'; 256 * 1024 + 1], "relay-hkg-1", 1, 7).unwrap_err(),
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
async fn heartbeat_sampler_uses_process_boot_identity_unique_nonce_metrics_and_probe_truth() {
    let sampler = HeartbeatSampler::new(
        Arc::new(FakeMetrics(CoturnMetrics {
            active_allocations: 7,
            current_ingress_bps: 11_000,
            current_egress_bps: 22_000,
            errors_total: 3,
        })),
        vec!["turn:relay.example:3478?transport=udp".into()],
        100,
        1_000_000,
    )
    .unwrap();
    let pressure = HostPressureSnapshot {
        packet_loss_bps: 50,
        cpu_usage_bps: 2_000,
        memory_usage_bps: 3_000,
        measured_rtt_ms: Some(24),
        recent_failure_bps: 100,
    };
    let first = sampler
        .sample(
            7,
            ProcessHealth::Failed,
            ProcessHealth::Degraded,
            RelayHealth::NonEvidence,
            pressure,
            4,
        )
        .await
        .unwrap();
    let second = sampler
        .sample(
            7,
            ProcessHealth::Failed,
            ProcessHealth::Degraded,
            RelayHealth::NonEvidence,
            pressure,
            4,
        )
        .await
        .unwrap();
    assert_eq!(first.boot_id, second.boot_id);
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(first.process_health, RelayHealth::Failed);
    assert_eq!(first.listener_health, RelayHealth::Degraded);
    assert_eq!(first.probe_health, RelayHealth::NonEvidence);
    assert_eq!(first.active_allocations, 7);
    assert_eq!(first.current_ingress_bps, 11_000);
    assert_eq!(first.current_egress_bps, 22_000);
    assert_eq!(first.applied_secret_version, 4);
    first.validate().unwrap();

    let new_process = HeartbeatSampler::new(
        Arc::new(FakeMetrics(CoturnMetrics::default())),
        vec!["turn:relay.example:3478?transport=udp".into()],
        100,
        1_000_000,
    )
    .unwrap();
    let after_restart = new_process
        .sample(
            7,
            ProcessHealth::Healthy,
            ProcessHealth::Healthy,
            RelayHealth::NonEvidence,
            HostPressureSnapshot::default(),
            4,
        )
        .await
        .unwrap();
    assert_ne!(first.boot_id, after_restart.boot_id);
}

#[tokio::test]
async fn heartbeat_cycle_connects_identity_metrics_probe_and_backend_directive() {
    let (_fs, backend, mut identity, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    identity.pickup(backend.as_ref()).await.unwrap();
    backend
        .heartbeat_results
        .lock()
        .unwrap()
        .push_back(Ok(NodeDirective::state(1, false)));
    let store = Arc::new(FakeRuntimeStateStore::default());
    *store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        ..RuntimeStateSnapshot::default()
    };
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    let mut runtime = AgentRuntime::new_with_state_store(
        backend.clone(),
        Arc::new(FakeCoturn::default()),
        clock,
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        store,
    )
    .unwrap();
    let sampler = HeartbeatSampler::new(
        Arc::new(FakeMetrics(CoturnMetrics {
            active_allocations: 2,
            current_ingress_bps: 3_000,
            current_egress_bps: 4_000,
            errors_total: 5,
        })),
        vec!["turn:relay.example:3478?transport=udp".into()],
        100,
        1_000_000,
    )
    .unwrap();
    runtime
        .heartbeat_cycle(
            &mut identity,
            &sampler,
            ProcessHealth::Failed,
            ProcessHealth::Healthy,
            RelayHealth::NonEvidence,
            HostPressureSnapshot::default(),
        )
        .await
        .unwrap();
    let heartbeats = backend.heartbeats.lock().unwrap();
    assert_eq!(heartbeats.len(), 1);
    assert_eq!(heartbeats[0].identity_epoch, 1);
    assert_eq!(heartbeats[0].sequence, 1);
    let payload: HeartbeatPayload = serde_json::from_slice(&heartbeats[0].body).unwrap();
    assert_eq!(payload.process_health, RelayHealth::Failed);
    assert_eq!(payload.listener_health, RelayHealth::Healthy);
    assert_eq!(payload.probe_health, RelayHealth::NonEvidence);
    assert_eq!(payload.active_allocations, 2);
    assert_eq!(payload.current_ingress_bps, 3_000);
    assert_eq!(payload.current_egress_bps, 4_000);
    assert_eq!(payload.applied_secret_version, 1);
}

#[tokio::test]
async fn backend_worker_automatically_enrolls_picks_up_installs_and_renews_identity() {
    let fs = Arc::new(MemoryIdentityFs::default());
    let backend = Arc::new(FakeBackend::default());
    *backend.auto_issue_pickup.lock().unwrap() = true;
    backend
        .enrollment_results
        .lock()
        .unwrap()
        .push_back(Ok(EnrollmentStatus::Pending {
            enrollment_id: "enrollment-auto".into(),
            receipt: secrecy::SecretString::from("one-use-auto-enrollment-receipt"),
        }));
    backend
        .heartbeat_results
        .lock()
        .unwrap()
        .push_back(Ok(NodeDirective::state(1, false)));
    let mut identity = certificate_state(fs, &backend);
    let initial_backend = Arc::new(FakeBackend::default());
    let slot = Arc::new(SwappableRelayBackend::new(initial_backend.clone()));
    let factory = FakeBackendFactory::new(0, backend.clone());
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    let state_store = Arc::new(FakeRuntimeStateStore::default());
    *state_store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        ..RuntimeStateSnapshot::default()
    };
    let mut runtime = AgentRuntime::new_with_state_store(
        slot.clone(),
        Arc::new(FakeCoturn::default()),
        clock.clone(),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        state_store.clone(),
    )
    .unwrap();
    let sampler = HeartbeatSampler::new(
        Arc::new(FakeMetrics(CoturnMetrics::default())),
        vec!["turn:relay.example:3478?transport=udp".into()],
        100,
        1_000_000,
    )
    .unwrap();
    let mut lifecycle = IdentityLifecycle::new(Duration::from_secs(24 * 60 * 60)).unwrap();
    let activated = backend_worker_once(
        &mut lifecycle,
        &mut identity,
        backend.as_ref(),
        slot.as_ref(),
        &factory,
        Some(enrollment_request()),
        &mut runtime,
        &sampler,
        ProcessHealth::Healthy,
        ProcessHealth::Healthy,
        RelayHealth::Healthy,
        HostPressureSnapshot::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        activated,
        IdentityMaintenance::Activated { identity_epoch: 1 }
    );
    assert_eq!(backend.enrollments.lock().unwrap().len(), 1);
    assert_eq!(backend.pickups.lock().unwrap().len(), 1);
    assert_eq!(backend.heartbeats.lock().unwrap().len(), 1);
    assert!(initial_backend.heartbeats.lock().unwrap().is_empty());

    let expires_at = identity
        .active_certificate()
        .unwrap()
        .expires_at_unix_seconds;
    *clock.unix_seconds.lock().unwrap() = expires_at - 1;
    let mut epoch_two = NodeDirective::state(1, false);
    epoch_two.identity_epoch = 2;
    backend
        .heartbeat_results
        .lock()
        .unwrap()
        .push_back(Ok(epoch_two));
    let renewed = backend_worker_once(
        &mut lifecycle,
        &mut identity,
        backend.as_ref(),
        slot.as_ref(),
        &factory,
        None,
        &mut runtime,
        &sampler,
        ProcessHealth::Healthy,
        ProcessHealth::Healthy,
        RelayHealth::Healthy,
        HostPressureSnapshot::default(),
    )
    .await
    .unwrap();
    assert_eq!(renewed, IdentityMaintenance::Renewed { identity_epoch: 2 });
    assert_eq!(identity.identity_epoch(), 2);
    assert_eq!(state_store.state.lock().unwrap().identity_epoch, 2);
    assert_eq!(backend.renewals.lock().unwrap().len(), 1);
    assert_eq!(backend.heartbeats.lock().unwrap().len(), 2);
    assert_eq!(backend.heartbeats.lock().unwrap()[1].identity_epoch, 2);
    assert_eq!(backend.heartbeats.lock().unwrap()[1].sequence, 1);
}

#[tokio::test]
async fn backend_worker_automatically_advances_persisted_secret_transaction() {
    let (_fs, backend, mut identity, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    identity.pickup(backend.as_ref()).await.unwrap();
    backend
        .heartbeat_results
        .lock()
        .unwrap()
        .push_back(Ok(NodeDirective {
            identity_epoch: 1,
            sequence: 1,
            state: RelayNodeState::Draining,
            desired: DesiredNodeState {
                draining: true,
                secret_version: 2,
                not_before_unix_seconds: Some(CERT_NOW_UNIX_SECONDS + 10),
                old_credential_deadline_unix_seconds: Some(CERT_NOW_UNIX_SECONDS + 60),
                rotation_challenge: Some(ROTATION_CHALLENGE.into()),
            },
            secret_update: None,
        }));
    let initial_backend = Arc::new(FakeBackend::default());
    let slot = Arc::new(SwappableRelayBackend::new(initial_backend));
    let factory = FakeBackendFactory::new(0, backend.clone());
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    let state_store = Arc::new(FakeRuntimeStateStore::default());
    *state_store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        ..RuntimeStateSnapshot::default()
    };
    let mut runtime = AgentRuntime::new_with_state_store(
        slot.clone(),
        Arc::new(FakeCoturn::default()),
        clock,
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        state_store.clone(),
    )
    .unwrap();
    let sampler = HeartbeatSampler::new(
        Arc::new(FakeMetrics(CoturnMetrics::default())),
        vec!["turn:relay.example:3478?transport=udp".into()],
        100,
        1_000_000,
    )
    .unwrap();
    let mut lifecycle = IdentityLifecycle::new(Duration::from_secs(24 * 60 * 60)).unwrap();

    backend_worker_once(
        &mut lifecycle,
        &mut identity,
        backend.as_ref(),
        slot.as_ref(),
        &factory,
        None,
        &mut runtime,
        &sampler,
        ProcessHealth::Healthy,
        ProcessHealth::Healthy,
        RelayHealth::Healthy,
        HostPressureSnapshot::default(),
    )
    .await
    .unwrap();

    assert_eq!(backend.uploads.lock().unwrap().len(), 1);
    assert_eq!(
        state_store
            .state
            .lock()
            .unwrap()
            .pending_rotation
            .as_ref()
            .unwrap()
            .phase,
        SecretRotationPhase::Uploaded
    );
}

#[tokio::test]
async fn successful_backend_cycles_follow_exact_monotonic_five_second_deadlines() {
    let (_fs, backend, mut identity, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    identity.pickup(backend.as_ref()).await.unwrap();
    for sequence in 1..=3 {
        backend
            .heartbeat_results
            .lock()
            .unwrap()
            .push_back(Ok(NodeDirective::state(sequence, false)));
    }
    let slot = Arc::new(SwappableRelayBackend::new(backend.clone()));
    let factory = FakeBackendFactory::new(0, backend.clone());
    let clock = Arc::new(FakeClock::default());
    *clock.monotonic_ms.lock().unwrap() = 10_000;
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    let sleeper = Arc::new(AdvancingSleeper {
        clock: clock.clone(),
        sleeps: Mutex::default(),
    });
    let store = Arc::new(FakeRuntimeStateStore::default());
    *store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        ..RuntimeStateSnapshot::default()
    };
    let mut runtime = AgentRuntime::new_with_state_store(
        slot.clone(),
        Arc::new(FakeCoturn::default()),
        clock.clone(),
        sleeper.clone(),
        Arc::new(FixedJitter(0)),
        store,
    )
    .unwrap();
    let sampler = HeartbeatSampler::new(
        Arc::new(FakeMetrics(CoturnMetrics::default())),
        vec!["turn:relay.example:3478?transport=udp".into()],
        100,
        1_000_000,
    )
    .unwrap();
    let mut lifecycle = IdentityLifecycle::new(Duration::from_secs(24 * 60 * 60)).unwrap();
    for cycle in 0..3 {
        if cycle == 1 {
            *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS - 10_000;
        }
        backend_worker_once(
            &mut lifecycle,
            &mut identity,
            backend.as_ref(),
            slot.as_ref(),
            &factory,
            None,
            &mut runtime,
            &sampler,
            ProcessHealth::Healthy,
            ProcessHealth::Healthy,
            RelayHealth::Healthy,
            HostPressureSnapshot::default(),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        *sleeper.sleeps.lock().unwrap(),
        vec![
            Duration::ZERO,
            Duration::from_secs(5),
            Duration::from_secs(5)
        ]
    );
    assert_eq!(*clock.monotonic_ms.lock().unwrap(), 20_000);
}

#[tokio::test]
async fn heartbeat_once_applies_backend_directive() {
    let backend = Arc::new(FakeBackend::default());
    backend
        .heartbeat_results
        .lock()
        .unwrap()
        .push_back(Ok(NodeDirective::state(1, true)));
    let coturn = Arc::new(FakeCoturn::default());
    let mut runtime = AgentRuntime::new_volatile(
        backend.clone(),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
    );
    runtime
        .heartbeat_once(SignedHeartbeat {
            node_id: "relay-hkg-1".into(),
            identity_epoch: 1,
            timestamp: 500,
            sequence: 1,
            body: b"{}".to_vec(),
            signature_b64: "signature".into(),
        })
        .await
        .unwrap();
    assert_eq!(backend.heartbeats.lock().unwrap().len(), 1);
    assert!(runtime.is_draining());
}

#[tokio::test]
async fn run_agent_keeps_supervisor_live_while_backend_heartbeat_never_returns() {
    let (_fs, enrollment_backend, mut identity, csr) = pending_certificate_state().await;
    enrollment_backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(
            enrollment_backend.issuer.issue(&csr, LeafProfile::Client),
        )));
    identity.pickup(enrollment_backend.as_ref()).await.unwrap();
    let backend_entered = Arc::new(tokio::sync::Semaphore::new(0));
    let supervised = Arc::new(tokio::sync::Semaphore::new(0));
    let backend = Arc::new(PendingHeartbeatBackend {
        entered: backend_entered.clone(),
    });
    let coturn = Arc::new(NotifyingCoturn {
        supervised: supervised.clone(),
    });
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = CERT_NOW_UNIX_SECONDS;
    let state_store = Arc::new(FakeRuntimeStateStore::default());
    *state_store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        ..RuntimeStateSnapshot::default()
    };
    let dependencies = PortableRelayAgentDeps {
        identity,
        enrollment_backend,
        initial_backend: backend.clone(),
        factory: Arc::new(StaticBackendFactory(backend)),
        coturn,
        clock,
        sleeper: Arc::new(FakeSleeper::default()),
        jitter: Arc::new(FixedJitter(0)),
        state_store,
        metrics: Arc::new(FakeMetrics(CoturnMetrics::default())),
        probe: Arc::new(NonEvidenceProbe),
    };
    let config = PortableRelayAgentConfig {
        enrollment: None,
        endpoints: vec!["turn:relay.example:3478?transport=udp".into()],
        max_allocations: 100,
        max_egress_bps: 1_000_000,
        pressure: HostPressureSnapshot::default(),
        renewal_window: Duration::from_secs(24 * 60 * 60),
    };
    let task = tokio::spawn(run_agent(dependencies, config));
    tokio::time::timeout(Duration::from_secs(1), backend_entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    tokio::time::timeout(Duration::from_secs(1), supervised.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert!(!task.is_finished());
    task.abort();
}

#[test]
fn metrics_parser_is_bounded_and_rejects_non_finite_overflow_and_duplicates() {
    let valid = "turn_active_allocations 12\nturn_current_ingress_bps 1000\nturn_current_egress_bps 2000\nturn_errors_total 3\n";
    let sample = parse_coturn_metrics(valid.as_bytes(), MetricsLimits::default()).unwrap();
    assert_eq!(sample.active_allocations, 12);
    assert_eq!(sample.current_egress_bps, 2_000);
    assert_eq!(sample.errors_total, 3);
    let real_fixture = include_bytes!("../../../tests/fixtures/coturn_metrics.prom");
    let real = parse_coturn_metrics(real_fixture, MetricsLimits::default()).unwrap();
    assert_eq!(real.active_allocations, 12);
    assert_eq!(real.current_ingress_bps, 1_048_576);
    assert_eq!(real.current_egress_bps, 2_097_152);

    for invalid in [
        "turn_active_allocations NaN\n",
        "turn_active_allocations inf\n",
        "turn_active_allocations 18446744073709551616\n",
        "turn_active_allocations -1\n",
        "turn_active_allocations 1.0\n",
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
    assert_eq!(
        parse_coturn_metrics(&[0xff, 0xfe], MetricsLimits::default()),
        Err(MetricsError::Invalid)
    );
    let too_many_lines = "# comment\n".repeat(MetricsLimits::default().max_lines + 1);
    assert_eq!(
        parse_coturn_metrics(too_many_lines.as_bytes(), MetricsLimits::default()),
        Err(MetricsError::TooLarge)
    );
    let long_line = format!(
        "{} 1\n",
        "x".repeat(MetricsLimits::default().max_line_bytes)
    );
    assert_eq!(
        parse_coturn_metrics(long_line.as_bytes(), MetricsLimits::default()),
        Err(MetricsError::TooLarge)
    );
    let too_many_fields = (0..=MetricsLimits::default().max_fields)
        .map(|index| format!("field_{index} {index}\n"))
        .collect::<String>();
    assert_eq!(
        parse_coturn_metrics(too_many_fields.as_bytes(), MetricsLimits::default()),
        Err(MetricsError::Invalid)
    );
}

#[tokio::test]
async fn metrics_http_rejects_oversized_content_length_and_chunked_body_while_streaming() {
    let limits = MetricsLimits {
        max_input_bytes: 32,
        ..MetricsLimits::default()
    };
    let content_length =
        one_response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
            .await;
    assert_eq!(
        ReqwestCoturnMetrics::new(content_length, limits)
            .unwrap()
            .collect()
            .await,
        Err(MetricsError::TooLarge)
    );

    let chunked = one_response_server(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n1\r\ny\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(
        ReqwestCoturnMetrics::new(chunked, limits)
            .unwrap()
            .collect()
            .await,
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
    let weak = AllocationProbeEvidence::NonEvidence;
    assert!(!weak.is_real_roundtrip());

    let coturn = Arc::new(FakeCoturn::default());
    coturn.probes.lock().unwrap().push_back(Ok(weak));
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
    let username = "sensitive-local-probe-user";
    let credential = "sensitive-local-probe-credential";
    let production = WebRtcLocalAllocationProbe::new(
        vec!["turn:127.0.0.1:3478?transport=udp".into()],
        secrecy::SecretString::from(username),
        secrecy::SecretString::from(credential),
        Duration::from_secs(5),
    )
    .unwrap();
    let debug = format!("{production:?}");
    assert!(!debug.contains(username));
    assert!(!debug.contains(credential));
    assert!(WebRtcLocalAllocationProbe::new(
        vec!["turn:remote-relay.example:3478?transport=udp".into()],
        secrecy::SecretString::from(username),
        secrecy::SecretString::from(credential),
        Duration::from_secs(5),
    )
    .is_err());
}

#[tokio::test]
async fn coturn_restart_is_attempted_exactly_three_times_then_stays_failed() {
    let coturn = Arc::new(FakeCoturn::default());
    let sleeper = Arc::new(FakeSleeper::default());
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
    let shared = SharedRelayHealth::default();
    let mut supervisor = CoturnSupervisor::new(
        coturn.clone(),
        sleeper.clone(),
        Arc::new(NonEvidenceProbe),
        shared.clone(),
    );
    for _ in 0..5 {
        supervisor.supervise_once().await.unwrap();
    }
    assert_eq!(*coturn.restarts.lock().unwrap(), 3);
    assert_eq!(
        *sleeper.sleeps.lock().unwrap(),
        vec![
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
    assert_eq!(supervisor.restart_attempts(), 3);
    assert_eq!(shared.snapshot().process, ProcessHealth::Failed);
}

#[tokio::test]
async fn production_supervisor_does_not_reset_restart_budget_on_healthy_process_non_evidence() {
    let coturn = Arc::new(FakeCoturn::default());
    let sleeper = Arc::new(FakeSleeper::default());
    let shared = SharedRelayHealth::default();
    let mut supervisor = CoturnSupervisor::new(
        coturn.clone(),
        sleeper.clone(),
        Arc::new(NonEvidenceProbe),
        shared.clone(),
    );
    for _ in 0..5 {
        supervisor.supervise_once().await.unwrap();
    }
    assert_eq!(supervisor.restart_attempts(), 3);
    assert_eq!(*coturn.restarts.lock().unwrap(), 3);
    assert_eq!(
        *sleeper.sleeps.lock().unwrap(),
        vec![
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
        ]
    );
    let health = shared.snapshot();
    assert_eq!(health.process, ProcessHealth::Healthy);
    assert_eq!(health.probe, RelayHealth::NonEvidence);
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
    let shared = SharedRelayHealth::default();
    let mut supervisor = CoturnSupervisor::new(
        coturn.clone(),
        Arc::new(FakeSleeper::default()),
        Arc::new(NonEvidenceProbe),
        shared.clone(),
    );
    for _ in 0..5 {
        supervisor.supervise_once().await.unwrap();
    }
    assert_eq!(*coturn.restarts.lock().unwrap(), 3);
    assert_eq!(supervisor.restart_attempts(), 3);
    assert_eq!(shared.snapshot().process, ProcessHealth::Failed);
}

#[tokio::test]
async fn backend_backoff_is_bounded_and_does_not_stop_local_supervision() {
    let coturn = Arc::new(FakeCoturn::default());
    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(2, 30)));
    let runtime = AgentRuntime::new_volatile(
        Arc::new(FakeBackend::default()),
        coturn.clone(),
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(17)),
    );
    for attempt in 0..20 {
        let delay = runtime.backend_retry_delay(attempt);
        assert!(!delay.is_zero());
        assert!(delay <= Duration::from_secs(30));
    }
    let shared = SharedRelayHealth::default();
    let mut supervisor = CoturnSupervisor::new(
        coturn,
        Arc::new(FakeSleeper::default()),
        Arc::new(NonEvidenceProbe),
        shared.clone(),
    );
    supervisor.supervise_once().await.unwrap();
    assert_eq!(shared.snapshot().process, ProcessHealth::Healthy);
    assert_eq!(shared.snapshot().probe, RelayHealth::NonEvidence);
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
async fn generated_secret_rotation_persists_intent_uses_monotonic_window_and_requires_live_probe() {
    let (identity_fs, backend, mut identity, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    identity.pickup(backend.as_ref()).await.unwrap();
    let coturn = Arc::new(FakeCoturn::default());
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = 1_000;
    *clock.monotonic_ms.lock().unwrap() = 10_000;
    let store = Arc::new(FakeRuntimeStateStore::default());
    *store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        last_directive_sequence: 0,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        draining: false,
        pending_rotation: None,
    };
    let mut runtime = AgentRuntime::new_with_state_store(
        backend.clone(),
        coturn.clone(),
        clock.clone(),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        store.clone(),
    )
    .unwrap();
    runtime
        .apply_directive(NodeDirective {
            identity_epoch: 1,
            sequence: 1,
            state: RelayNodeState::Draining,
            desired: DesiredNodeState {
                draining: true,
                secret_version: 2,
                not_before_unix_seconds: Some(1_010),
                old_credential_deadline_unix_seconds: Some(1_060),
                rotation_challenge: Some(ROTATION_CHALLENGE.into()),
            },
            secret_update: None,
        })
        .await
        .unwrap();
    let intent = store.state.lock().unwrap().clone();
    let pending = intent.pending_rotation.as_ref().unwrap();
    assert_eq!(pending.phase, SecretRotationPhase::Intent);
    assert!(format!("{intent:?}").contains("REDACTED"));
    assert_eq!(*coturn.drains.lock().unwrap(), vec![true]);

    assert!(!runtime
        .advance_secret_rotation(&mut identity)
        .await
        .unwrap());
    assert_eq!(backend.uploads.lock().unwrap().len(), 1);
    assert!(coturn.secret_versions.lock().unwrap().is_empty());
    assert_eq!(
        store
            .state
            .lock()
            .unwrap()
            .pending_rotation
            .as_ref()
            .unwrap()
            .phase,
        SecretRotationPhase::Uploaded
    );

    // A wall-clock jump cannot shorten the safety window in this process.
    *clock.unix_seconds.lock().unwrap() = 5_000;
    *clock.monotonic_ms.lock().unwrap() = 69_999;
    assert!(!runtime
        .advance_secret_rotation(&mut identity)
        .await
        .unwrap());
    assert!(coturn.secret_versions.lock().unwrap().is_empty());

    *clock.monotonic_ms.lock().unwrap() = 70_000;
    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(1, 0)));
    assert!(!runtime
        .advance_secret_rotation(&mut identity)
        .await
        .unwrap());
    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(0, 0)));
    coturn
        .probes
        .lock()
        .unwrap()
        .push_back(Ok(AllocationProbeEvidence::NonEvidence));
    assert_eq!(
        runtime.advance_secret_rotation(&mut identity).await,
        Err(RuntimeError::Process(ProcessError::ProbeInvalid))
    );
    assert_eq!(*coturn.secret_versions.lock().unwrap(), vec![2]);
    assert!(backend.commits.lock().unwrap().is_empty());
    assert_eq!(
        store
            .state
            .lock()
            .unwrap()
            .pending_rotation
            .as_ref()
            .unwrap()
            .phase,
        SecretRotationPhase::Applied
    );

    drop(runtime);
    *clock.unix_seconds.lock().unwrap() = 1_061;
    *clock.monotonic_ms.lock().unwrap() = 5;
    let mut restarted = AgentRuntime::new_with_state_store(
        backend.clone(),
        coturn.clone(),
        clock,
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        store,
    )
    .unwrap();
    coturn
        .snapshots
        .lock()
        .unwrap()
        .push_back(Ok(CoturnSnapshot::healthy(0, 0)));
    coturn
        .probes
        .lock()
        .unwrap()
        .push_back(Ok(AllocationProbeEvidence::NonEvidence));
    assert_eq!(
        restarted.advance_secret_rotation(&mut identity).await,
        Err(RuntimeError::Process(ProcessError::ProbeInvalid))
    );
    assert_eq!(*coturn.secret_versions.lock().unwrap(), vec![2]);
    assert!(backend.commits.lock().unwrap().is_empty());
    drop(identity_fs);
}

#[tokio::test]
async fn pending_generated_secret_is_reused_after_upload_failure_and_restart() {
    let (_identity_fs, backend, mut identity, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    identity.pickup(backend.as_ref()).await.unwrap();
    backend
        .upload_results
        .lock()
        .unwrap()
        .push_back(Err(BackendError::Unavailable));
    let clock = Arc::new(FakeClock::default());
    *clock.unix_seconds.lock().unwrap() = 2_000;
    *clock.monotonic_ms.lock().unwrap() = 50;
    let store = Arc::new(FakeRuntimeStateStore::default());
    *store.state.lock().unwrap() = RuntimeStateSnapshot {
        identity_epoch: 1,
        secret_version: 1,
        secret_digest: Some([1; 32]),
        ..RuntimeStateSnapshot::default()
    };
    let coturn = Arc::new(FakeCoturn::default());
    let mut runtime = AgentRuntime::new_with_state_store(
        backend.clone(),
        coturn.clone(),
        clock.clone(),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        store.clone(),
    )
    .unwrap();
    runtime
        .apply_directive(NodeDirective {
            identity_epoch: 1,
            sequence: 1,
            state: RelayNodeState::Draining,
            desired: DesiredNodeState {
                draining: true,
                secret_version: 2,
                not_before_unix_seconds: Some(2_010),
                old_credential_deadline_unix_seconds: Some(2_060),
                rotation_challenge: Some(ROTATION_CHALLENGE.into()),
            },
            secret_update: None,
        })
        .await
        .unwrap();
    assert_eq!(
        runtime.advance_secret_rotation(&mut identity).await,
        Err(RuntimeError::Backend(BackendError::Unavailable))
    );
    let first = backend.uploads.lock().unwrap()[0].clone();
    let persisted_rotation = store
        .state
        .lock()
        .unwrap()
        .pending_rotation
        .as_ref()
        .unwrap()
        .rotation_id
        .clone();
    drop(runtime);

    *clock.unix_seconds.lock().unwrap() = 2_001;
    *clock.monotonic_ms.lock().unwrap() = 5;
    let mut restarted = AgentRuntime::new_with_state_store(
        backend.clone(),
        coturn,
        clock,
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        store,
    )
    .unwrap();
    assert!(!restarted
        .advance_secret_rotation(&mut identity)
        .await
        .unwrap());
    let uploads = backend.uploads.lock().unwrap();
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[1].rotation_id, persisted_rotation);
    assert_eq!(
        uploads[1].turn_rest_secret.expose_secret(),
        first.turn_rest_secret.expose_secret()
    );
}

#[tokio::test]
async fn secret_upload_and_commit_requests_match_signed_python_wire() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/relay_secret_rotation_wire_v1.json"
    ))
    .unwrap();
    let (_fs, backend, mut identity, csr) = pending_certificate_state().await;
    backend
        .pickup_results
        .lock()
        .unwrap()
        .push_back(Ok(Some(backend.issuer.issue(&csr, LeafProfile::Client))));
    identity.pickup(backend.as_ref()).await.unwrap();
    let public_key = identity.public_key();
    let secret = secrecy::SecretString::from("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
    let upload = identity
        .prepare_secret_upload(2_500, "rotation-0001".into(), 2, secret)
        .unwrap();
    let upload_body = fixture["upload"]["body_json"].as_str().unwrap();
    assert!(upload_body.contains(upload.turn_rest_secret.expose_secret()));
    assert_eq!(
        upload.authentication.sequence,
        fixture["upload"]["sequence"].as_u64().unwrap()
    );
    let upload_canonical = canonical_relay_request(
        fixture["upload"]["method"].as_str().unwrap(),
        fixture["upload"]["path"].as_str().unwrap(),
        fixture["node_id"].as_str().unwrap(),
        fixture["upload"]["timestamp"].as_i64().unwrap(),
        upload.authentication.sequence,
        upload_body.as_bytes(),
    )
    .unwrap();
    let upload_signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &upload.authentication.signature_b64,
    )
    .unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_key)
        .verify(&upload_canonical, &upload_signature)
        .unwrap();

    let commit = identity
        .prepare_secret_commit(
            2_501,
            "rotation-0001".into(),
            2,
            ROTATION_CHALLENGE.into(),
            [
                0x72, 0xcd, 0x6e, 0x84, 0x22, 0xc4, 0x07, 0xfb, 0x6d, 0x09, 0x86, 0x90, 0xf1, 0x13,
                0x0b, 0x7d, 0xed, 0x7e, 0xc2, 0xf7, 0xf5, 0xe1, 0xd3, 0x0b, 0xd9, 0xd5, 0x21, 0xf0,
                0x15, 0x36, 0x37, 0x93,
            ],
            [0xab; 32],
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        )
        .unwrap();
    let proof_message = rotation_proof_message(
        fixture["node_id"].as_str().unwrap(),
        1,
        "rotation-0001",
        2,
        ROTATION_CHALLENGE,
        &[
            0x72, 0xcd, 0x6e, 0x84, 0x22, 0xc4, 0x07, 0xfb, 0x6d, 0x09, 0x86, 0x90, 0xf1, 0x13,
            0x0b, 0x7d, 0xed, 0x7e, 0xc2, 0xf7, 0xf5, 0xe1, 0xd3, 0x0b, 0xd9, 0xd5, 0x21, 0xf0,
            0x15, 0x36, 0x37, 0x93,
        ],
        &[0xab; 32],
    )
    .unwrap();
    assert_eq!(
        proof_message
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        fixture["proof_message_hex"]
    );
    assert_eq!(commit.proof_mac, fixture["proof_mac"]);
    assert_eq!(
        commit.authentication.sequence,
        upload.authentication.sequence + 1
    );
    assert_eq!(
        commit.authentication.sequence,
        fixture["commit"]["sequence"].as_u64().unwrap()
    );
    let commit_body = fixture["commit"]["body_json"].as_str().unwrap();
    let commit_canonical = canonical_relay_request(
        fixture["commit"]["method"].as_str().unwrap(),
        fixture["commit"]["path"].as_str().unwrap(),
        fixture["node_id"].as_str().unwrap(),
        fixture["commit"]["timestamp"].as_i64().unwrap(),
        commit.authentication.sequence,
        commit_body.as_bytes(),
    )
    .unwrap();
    let commit_signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &commit.authentication.signature_b64,
    )
    .unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(&commit_canonical, &commit_signature)
        .unwrap();
    assert!(!format!("{upload:?}").contains(upload.turn_rest_secret.expose_secret()));
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

#[tokio::test]
async fn identity_epoch_rotation_resets_sequence_and_rejects_old_epoch_directives() {
    let store = Arc::new(FakeRuntimeStateStore::default());
    let coturn = Arc::new(FakeCoturn::default());
    let mut runtime = AgentRuntime::new_with_state_store(
        Arc::new(FakeBackend::default()),
        coturn,
        Arc::new(FakeClock::default()),
        Arc::new(FakeSleeper::default()),
        Arc::new(FixedJitter(0)),
        store.clone(),
    )
    .unwrap();
    runtime
        .apply_directive(NodeDirective::state(5, true))
        .await
        .unwrap();
    runtime.activate_identity_epoch(2).unwrap();
    assert_eq!(store.state.lock().unwrap().identity_epoch, 2);
    assert_eq!(store.state.lock().unwrap().last_directive_sequence, 0);
    assert!(store.state.lock().unwrap().draining);
    let mut old_epoch = NodeDirective::state(6, false);
    old_epoch.identity_epoch = 1;
    assert_eq!(
        runtime.apply_directive(old_epoch).await,
        Err(RuntimeError::DirectiveReplay)
    );
    let mut new_epoch = NodeDirective::state(1, false);
    new_epoch.identity_epoch = 2;
    runtime.apply_directive(new_epoch).await.unwrap();
    assert!(!runtime.is_draining());
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
        runtime_state_path: std::env::temp_dir().join("mrd-relay-agent-state.json"),
        trusted_ca_path: std::env::temp_dir().join("mrd-relay-agent-ca.pem"),
        metrics_url: "http://127.0.0.1:9641/metrics".parse().unwrap(),
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
    config.turn_rest_secret = None;
    config.region = "HKG".into();
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
    config.region = "hkg".into();
    config.node_id = ":relay-hkg-1".into();
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
    config.node_id = "relay-hkg-1".into();
    config.trusted_ca_path = config.runtime_state_path.clone();
    assert_eq!(config.validate(), Err(ConfigError::Invalid));
}

#[test]
fn configuration_loader_is_bounded_strict_and_does_not_require_cli_secrets() {
    let directory = std::env::temp_dir().join(format!(
        "mrd-agent-config-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("agent.json");
    let identity_path = directory.join("identity.json");
    let runtime_path = directory.join("runtime.json");
    let ca_path = directory.join("ca.pem");
    let value = serde_json::json!({
        "backend_url": "https://relay-control.example/",
        "node_id": "relay-hkg-1",
        "region": "hkg",
        "failure_domain": "hkg-a",
        "endpoints": ["turn:relay.example:3478?transport=udp"],
        "max_allocations": 100,
        "max_egress_bps": 1_000_000,
        "identity_path": identity_path,
        "runtime_state_path": runtime_path,
        "trusted_ca_path": ca_path,
        "metrics_url": "http://127.0.0.1:9641/metrics",
        "enrollment_token": "private-enrollment-token-that-is-never-logged-1234",
        "turn_rest_secret": null,
        "heartbeat_interval_seconds": 5,
        "backend_backoff_cap_seconds": 30
    });
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let loaded = AgentConfig::load(&path).unwrap();
    assert_eq!(loaded.node_id, "relay-hkg-1");
    assert!(!format!("{loaded:?}").contains("private-enrollment-token"));

    let mut unknown = value;
    unknown["unexpected"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(matches!(
        AgentConfig::load(&path),
        Err(ConfigError::Invalid)
    ));

    std::fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert!(matches!(
        AgentConfig::load(&path),
        Err(ConfigError::Invalid)
    ));
    assert!(matches!(
        AgentConfig::load(std::path::Path::new("relative-agent.json")),
        Err(ConfigError::Invalid)
    ));
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn production_runtime_state_store_is_atomic_bounded_and_requires_absolute_path() {
    assert!(matches!(
        StdRuntimeStateStore::new(std::path::PathBuf::from("relative-runtime.json")),
        Err(RuntimeError::StateInvalid)
    ));
    let directory = std::env::temp_dir().join(format!(
        "mrd-agent-runtime-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("runtime.json");
    let store = StdRuntimeStateStore::new(path.clone()).unwrap();
    let state = RuntimeStateSnapshot {
        identity_epoch: 2,
        last_directive_sequence: 9,
        secret_version: 4,
        secret_digest: Some([0x5a; 32]),
        draining: true,
        pending_rotation: None,
    };
    store.atomic_store(&state).unwrap();
    assert_eq!(store.load().unwrap(), state);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
    assert!(std::fs::metadata(&path).unwrap().len() < 64 * 1024);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn secret_and_error_rendering_are_always_redacted_and_reason_codes_are_stable() {
    let secret = SecretBytes::new(b"ultra-sensitive-turn-secret".to_vec());
    let mut rendered = String::new();
    write!(&mut rendered, "{secret:?} {secret}").unwrap();
    assert!(!rendered.contains("ultra-sensitive"));
    assert!(rendered.contains("REDACTED"));
    let certificate = NodeCertificate {
        certificate_pem: "sensitive-leaf-pem".into(),
        ca_certificate_pem: "sensitive-ca-pem".into(),
        expires_at_unix_seconds: 1_900_000_000,
    };
    let certificate_debug = format!("{certificate:?}");
    assert!(!certificate_debug.contains("sensitive"));
    assert!(certificate_debug.contains("REDACTED"));
    let renewal = RenewalRequest {
        node_id: "relay-hkg-1".into(),
        renewal_id: "renewal-redaction".into(),
        csr_pem: "sensitive-csr-pem".into(),
        authentication: mrd_relay_agent::backend::RequestAuthentication {
            timestamp: 1,
            sequence: 1,
            signature_b64: "sensitive-signature".into(),
        },
    };
    let renewal_debug = format!("{renewal:?}");
    assert!(!renewal_debug.contains("sensitive"));
    assert!(renewal_debug.contains("REDACTED"));
    assert_eq!(
        BackendError::Unavailable.reason_code(),
        "relay_backend_unavailable"
    );
    assert_eq!(
        ProcessError::ProbeUnavailable.reason_code(),
        "relay_probe_unavailable"
    );
}

#[test]
fn main_without_native_adapter_exits_nonzero_with_stable_reason() {
    let output = Command::new(env!("CARGO_BIN_EXE_mrd-relay-agent"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "relay_native_adapter_unavailable\n"
    );
    assert!(output.stdout.is_empty());
}
