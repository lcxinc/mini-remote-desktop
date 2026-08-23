use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Certificate, Client, Identity, StatusCode};
use ring::{digest, signature};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::process::SecretBytes;

const REQUEST_CONTEXT: &[u8] = b"MRD_RELAY_REQUEST_V1\0";
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct EnrollmentRequest {
    pub token: SecretString,
    pub node_id: String,
    pub region: String,
    pub failure_domain: String,
    pub endpoints: Vec<String>,
    pub max_allocations: u32,
    pub max_egress_bps: u64,
    pub csr_pem: String,
    pub turn_rest_secret: SecretString,
}

impl std::fmt::Debug for EnrollmentRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentRequest")
            .field("token", &"REDACTED")
            .field("node_id", &self.node_id)
            .field("region", &self.region)
            .field("failure_domain", &self.failure_domain)
            .field("endpoints", &self.endpoints)
            .field("max_allocations", &self.max_allocations)
            .field("max_egress_bps", &self.max_egress_bps)
            .field("csr_pem", &"REDACTED")
            .field("turn_rest_secret", &"REDACTED")
            .finish()
    }
}

#[derive(Debug)]
pub enum EnrollmentStatus {
    Pending {
        enrollment_id: String,
        receipt: SecretString,
    },
}

#[derive(Clone)]
pub struct PickupRequest {
    pub enrollment_id: String,
    pub node_id: String,
    pub receipt: SecretString,
}

impl std::fmt::Debug for PickupRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PickupRequest")
            .field("enrollment_id", &self.enrollment_id)
            .field("node_id", &self.node_id)
            .field("receipt", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct RenewalRequest {
    pub node_id: String,
    pub renewal_id: String,
    pub csr_pem: String,
    #[serde(skip)]
    pub authentication: RequestAuthentication,
}

impl std::fmt::Debug for RenewalRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RenewalRequest")
            .field("node_id", &self.node_id)
            .field("renewal_id", &self.renewal_id)
            .field("csr_pem", &"REDACTED")
            .field("authentication", &self.authentication)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeCertificate {
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub expires_at_unix_seconds: i64,
}

impl std::fmt::Debug for NodeCertificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeCertificate")
            .field("certificate_pem", &"REDACTED")
            .field("ca_certificate_pem", &"REDACTED")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

#[derive(Clone)]
pub struct RequestAuthentication {
    pub timestamp: i64,
    pub sequence: u64,
    pub signature_b64: String,
}

impl std::fmt::Debug for RequestAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestAuthentication")
            .field("timestamp", &self.timestamp)
            .field("sequence", &self.sequence)
            .field("signature_b64", &"REDACTED")
            .finish()
    }
}

#[derive(Clone)]
pub struct SignedHeartbeat {
    pub node_id: String,
    pub identity_epoch: u64,
    pub timestamp: i64,
    pub sequence: u64,
    pub body: Vec<u8>,
    pub signature_b64: String,
}

#[derive(Clone)]
pub struct SecretUploadRequest {
    pub node_id: String,
    pub identity_epoch: u64,
    pub rotation_id: String,
    pub secret_version: u64,
    pub turn_rest_secret: SecretString,
    pub authentication: RequestAuthentication,
}

impl std::fmt::Debug for SecretUploadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretUploadRequest")
            .field("node_id", &self.node_id)
            .field("identity_epoch", &self.identity_epoch)
            .field("rotation_id", &self.rotation_id)
            .field("secret_version", &self.secret_version)
            .field("turn_rest_secret", &"REDACTED")
            .field("authentication", &self.authentication)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct SecretCommitRequest {
    pub node_id: String,
    pub identity_epoch: u64,
    pub rotation_id: String,
    pub secret_version: u64,
    pub probe_evidence_sha256: String,
    pub authentication: RequestAuthentication,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayHealth {
    Healthy,
    Degraded,
    Failed,
    NonEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatPayload {
    pub identity_epoch: u64,
    pub boot_id: String,
    pub nonce: String,
    pub process_health: RelayHealth,
    pub listener_health: RelayHealth,
    pub probe_health: RelayHealth,
    pub active_allocations: u32,
    pub current_ingress_bps: u64,
    pub current_egress_bps: u64,
    pub max_allocations: u32,
    pub max_egress_bps: u64,
    pub packet_loss_bps: u16,
    pub cpu_usage_bps: u16,
    pub memory_usage_bps: u16,
    pub measured_rtt_ms: Option<u32>,
    pub recent_failure_bps: u16,
    pub endpoints: Vec<String>,
    pub applied_secret_version: u64,
}

impl HeartbeatPayload {
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.identity_epoch == 0
            || !is_canonical_base64url(&self.boot_id, 16)
            || !is_canonical_base64url(&self.nonce, 32)
            || self.process_health == RelayHealth::NonEvidence
            || self.listener_health == RelayHealth::NonEvidence
            || self.max_allocations == 0
            || self.active_allocations > self.max_allocations
            || self.max_egress_bps == 0
            || self.applied_secret_version == 0
            || self.packet_loss_bps > 10_000
            || self.cpu_usage_bps > 10_000
            || self.memory_usage_bps > 10_000
            || self.recent_failure_bps > 10_000
            || self.endpoints.is_empty()
            || self.endpoints.len() > 4
            || self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.is_empty() || endpoint.len() > 512)
        {
            return Err(BackendError::ProtocolInvalid);
        }
        Ok(())
    }
}

fn is_canonical_base64url(value: &str, decoded_len: usize) -> bool {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(value) else {
        return false;
    };
    decoded.len() == decoded_len && URL_SAFE_NO_PAD.encode(decoded) == value
}

impl std::fmt::Debug for SignedHeartbeat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedHeartbeat")
            .field("node_id", &self.node_id)
            .field("identity_epoch", &self.identity_epoch)
            .field("timestamp", &self.timestamp)
            .field("sequence", &self.sequence)
            .field("body_length", &self.body.len())
            .field("signature_b64", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayNodeState {
    Available,
    Degraded,
    Draining,
    Unavailable,
    Revoked,
}

impl RelayNodeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Unavailable => "unavailable",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredNodeState {
    pub draining: bool,
    pub secret_version: u64,
    pub not_before_unix_seconds: Option<i64>,
    pub old_credential_deadline_unix_seconds: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct NodeDirective {
    pub identity_epoch: u64,
    pub sequence: u64,
    pub state: RelayNodeState,
    pub desired: DesiredNodeState,
    pub secret_update: Option<SecretUpdate>,
}

impl NodeDirective {
    pub fn update(sequence: u64, draining: bool, version: u64, secret: SecretBytes) -> Self {
        Self {
            identity_epoch: 1,
            sequence,
            state: if draining {
                RelayNodeState::Draining
            } else {
                RelayNodeState::Available
            },
            desired: DesiredNodeState {
                draining,
                secret_version: version,
                not_before_unix_seconds: None,
                old_credential_deadline_unix_seconds: None,
            },
            secret_update: Some(SecretUpdate { version, secret }),
        }
    }

    pub fn state(sequence: u64, draining: bool) -> Self {
        Self {
            identity_epoch: 1,
            sequence,
            state: if draining {
                RelayNodeState::Draining
            } else {
                RelayNodeState::Available
            },
            desired: DesiredNodeState {
                draining,
                secret_version: 1,
                not_before_unix_seconds: None,
                old_credential_deadline_unix_seconds: None,
            },
            secret_update: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SecretUpdate {
    pub version: u64,
    pub secret: SecretBytes,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("relay_backend_unavailable")]
    Unavailable,
    #[error("relay_backend_rejected")]
    Rejected,
    #[error("relay_backend_protocol_invalid")]
    ProtocolInvalid,
    #[error("relay_tls_invalid")]
    TlsInvalid,
}

impl BackendError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unavailable => "relay_backend_unavailable",
            Self::Rejected => "relay_backend_rejected",
            Self::ProtocolInvalid => "relay_backend_protocol_invalid",
            Self::TlsInvalid => "relay_tls_invalid",
        }
    }
}

#[async_trait]
pub trait RelayBackendPort: Send + Sync {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentStatus, BackendError>;
    async fn pickup(&self, request: PickupRequest)
        -> Result<Option<NodeCertificate>, BackendError>;
    async fn renew(&self, request: RenewalRequest) -> Result<NodeCertificate, BackendError>;
    async fn heartbeat(&self, heartbeat: SignedHeartbeat) -> Result<NodeDirective, BackendError>;
    async fn upload_secret(&self, _request: SecretUploadRequest) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    async fn commit_secret(&self, _request: SecretCommitRequest) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
}

pub trait RelayBackendClientFactoryPort: Send + Sync {
    fn build_mtls(
        &self,
        certificate: &NodeCertificate,
        private_pkcs8: &[u8],
    ) -> Result<Arc<dyn RelayBackendPort>, BackendError>;
}

pub struct SwappableRelayBackend {
    current: RwLock<Arc<dyn RelayBackendPort>>,
}

impl SwappableRelayBackend {
    pub fn new(current: Arc<dyn RelayBackendPort>) -> Self {
        Self {
            current: RwLock::new(current),
        }
    }

    pub fn swap(&self, replacement: Arc<dyn RelayBackendPort>) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = replacement;
    }

    fn current(&self) -> Arc<dyn RelayBackendPort> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

#[async_trait]
impl RelayBackendPort for SwappableRelayBackend {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentStatus, BackendError> {
        self.current().enroll(request).await
    }

    async fn pickup(
        &self,
        request: PickupRequest,
    ) -> Result<Option<NodeCertificate>, BackendError> {
        self.current().pickup(request).await
    }

    async fn renew(&self, request: RenewalRequest) -> Result<NodeCertificate, BackendError> {
        self.current().renew(request).await
    }

    async fn heartbeat(&self, heartbeat: SignedHeartbeat) -> Result<NodeDirective, BackendError> {
        self.current().heartbeat(heartbeat).await
    }

    async fn upload_secret(&self, request: SecretUploadRequest) -> Result<(), BackendError> {
        self.current().upload_secret(request).await
    }

    async fn commit_secret(&self, request: SecretCommitRequest) -> Result<(), BackendError> {
        self.current().commit_secret(request).await
    }
}

pub fn canonical_relay_request(
    method: &str,
    path: &str,
    node_id: &str,
    timestamp: i64,
    sequence: u64,
    body: &[u8],
) -> Result<Vec<u8>, BackendError> {
    if body.len() > MAX_BODY_BYTES
        || method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !path.starts_with('/')
        || path.contains('?')
        || path.len() > 1024
        || node_id.is_empty()
        || node_id.len() > 128
        || !node_id.is_ascii()
        || timestamp < 0
    {
        return Err(BackendError::ProtocolInvalid);
    }
    let digest = digest::digest(&digest::SHA256, body);
    let timestamp = timestamp.to_string();
    let sequence = sequence.to_string();
    let fields: [&[u8]; 6] = [
        method.as_bytes(),
        path.as_bytes(),
        node_id.as_bytes(),
        timestamp.as_bytes(),
        sequence.as_bytes(),
        digest.as_ref(),
    ];
    let mut encoded = Vec::with_capacity(REQUEST_CONTEXT.len() + body.len().min(32) + 256);
    encoded.extend_from_slice(REQUEST_CONTEXT);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| BackendError::ProtocolInvalid)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field);
    }
    Ok(encoded)
}

pub fn sign_relay_request(
    private_pkcs8: &[u8],
    method: &str,
    path: &str,
    node_id: &str,
    timestamp: i64,
    sequence: u64,
    body: &[u8],
) -> Result<String, BackendError> {
    let canonical = canonical_relay_request(method, path, node_id, timestamp, sequence, body)?;
    let key = signature::Ed25519KeyPair::from_pkcs8(private_pkcs8)
        .map_err(|_| BackendError::ProtocolInvalid)?;
    Ok(STANDARD.encode(key.sign(&canonical).as_ref()))
}

pub(crate) fn serialize_renewal_body(
    renewal_id: &str,
    csr_pem: &str,
) -> Result<Vec<u8>, BackendError> {
    #[derive(Serialize)]
    struct RenewalWire<'a> {
        renewal_id: &'a str,
        csr_pem: &'a str,
    }
    if !is_urlsafe_identifier(renewal_id) || csr_pem.len() > 16_384 {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::to_vec(&RenewalWire {
        renewal_id,
        csr_pem,
    })
    .map_err(|_| BackendError::ProtocolInvalid)
}

pub(crate) fn serialize_secret_upload_body(
    request: &SecretUploadRequest,
) -> Result<Vec<u8>, BackendError> {
    #[derive(Serialize)]
    struct Wire<'a> {
        identity_epoch: u64,
        rotation_id: &'a str,
        secret_version: u64,
        turn_rest_secret: &'a str,
    }
    if request.identity_epoch == 0
        || request.secret_version < 2
        || !is_urlsafe_identifier(&request.rotation_id)
        || !is_canonical_base64url(request.turn_rest_secret.expose_secret(), 32)
    {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::to_vec(&Wire {
        identity_epoch: request.identity_epoch,
        rotation_id: &request.rotation_id,
        secret_version: request.secret_version,
        turn_rest_secret: request.turn_rest_secret.expose_secret(),
    })
    .map_err(|_| BackendError::ProtocolInvalid)
}

pub(crate) fn serialize_secret_commit_body(
    request: &SecretCommitRequest,
) -> Result<Vec<u8>, BackendError> {
    #[derive(Serialize)]
    struct Wire<'a> {
        identity_epoch: u64,
        rotation_id: &'a str,
        secret_version: u64,
        probe_evidence_sha256: &'a str,
    }
    if request.identity_epoch == 0
        || request.secret_version < 2
        || !is_urlsafe_identifier(&request.rotation_id)
        || request.probe_evidence_sha256.len() != 64
        || !request
            .probe_evidence_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::to_vec(&Wire {
        identity_epoch: request.identity_epoch,
        rotation_id: &request.rotation_id,
        secret_version: request.secret_version,
        probe_evidence_sha256: &request.probe_evidence_sha256,
    })
    .map_err(|_| BackendError::ProtocolInvalid)
}

pub struct ReqwestRelayBackend {
    base_url: Url,
    root_certificate: Certificate,
    enrollment_client: Client,
    mtls_client: Option<Client>,
}

pub struct ReqwestRelayBackendFactory {
    base_url: Url,
    ca_certificate_pem: Vec<u8>,
}

impl ReqwestRelayBackendFactory {
    pub fn new(base_url: Url, ca_certificate_pem: &[u8]) -> Result<Self, BackendError> {
        ReqwestRelayBackend::new(base_url.clone(), ca_certificate_pem)?;
        Ok(Self {
            base_url,
            ca_certificate_pem: ca_certificate_pem.to_vec(),
        })
    }
}

impl RelayBackendClientFactoryPort for ReqwestRelayBackendFactory {
    fn build_mtls(
        &self,
        certificate: &NodeCertificate,
        private_pkcs8: &[u8],
    ) -> Result<Arc<dyn RelayBackendPort>, BackendError> {
        let private = rustls_pki_types::PrivatePkcs8KeyDer::from(private_pkcs8.to_vec());
        let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&private, &rcgen::PKCS_ED25519)
            .map_err(|_| BackendError::TlsInvalid)?;
        let private_pem = Zeroizing::new(key.serialize_pem());
        let backend = ReqwestRelayBackend::new(self.base_url.clone(), &self.ca_certificate_pem)?
            .with_mtls_identity(
                certificate.certificate_pem.as_bytes(),
                private_pem.as_bytes(),
            )?;
        Ok(Arc::new(backend))
    }
}

impl ReqwestRelayBackend {
    pub fn new(base_url: Url, ca_certificate_pem: &[u8]) -> Result<Self, BackendError> {
        if base_url.scheme() != "https"
            || base_url.cannot_be_a_base()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(BackendError::TlsInvalid);
        }
        let root =
            Certificate::from_pem(ca_certificate_pem).map_err(|_| BackendError::TlsInvalid)?;
        let enrollment_client = secure_client(Some(root.clone()), None)?;
        Ok(Self {
            base_url,
            root_certificate: root,
            enrollment_client,
            mtls_client: None,
        })
    }

    pub fn with_mtls_identity(
        mut self,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<Self, BackendError> {
        let mut identity_pem = Zeroizing::new(Vec::with_capacity(
            certificate_pem.len() + private_key_pem.len(),
        ));
        identity_pem.extend_from_slice(certificate_pem);
        identity_pem.extend_from_slice(private_key_pem);
        let identity = Identity::from_pem(&identity_pem).map_err(|_| BackendError::TlsInvalid)?;
        self.mtls_client = Some(secure_client(
            Some(self.root_certificate.clone()),
            Some(identity),
        )?);
        Ok(self)
    }

    fn url(&self, path: &str) -> Result<Url, BackendError> {
        self.base_url
            .join(path)
            .map_err(|_| BackendError::ProtocolInvalid)
    }
}

fn secure_client(
    root: Option<Certificate>,
    identity: Option<Identity>,
) -> Result<Client, BackendError> {
    let mut builder = Client::builder()
        .https_only(true)
        .use_rustls_tls()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(root) = root {
        builder = builder.add_root_certificate(root);
    }
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    builder.build().map_err(|_| BackendError::TlsInvalid)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentResponse {
    enrollment_id: String,
    node_id: String,
    status: String,
    receipt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PickupResponse {
    enrollment_id: String,
    node_id: String,
    status: String,
    certificate_pem: Option<String>,
    ca_certificate_pem: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalResponse {
    renewal_id: String,
    node_id: String,
    certificate_pem: String,
    ca_certificate_pem: String,
    fingerprint: String,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatResponse {
    node_id: String,
    identity_epoch: u64,
    state: String,
    sequence: u64,
    desired: DesiredStateResponse,
    lease_expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredStateResponse {
    draining: bool,
    secret_version: u64,
    not_before: Option<String>,
    old_credential_deadline: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretUploadResponse {
    node_id: String,
    identity_epoch: u64,
    rotation_id: String,
    secret_version: u64,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretCommitResponse {
    node_id: String,
    identity_epoch: u64,
    rotation_id: String,
    active_secret_version: u64,
    status: String,
}

pub fn decode_enrollment_response(
    body: &[u8],
    expected_node_id: &str,
) -> Result<EnrollmentStatus, BackendError> {
    let body: EnrollmentResponse = decode_json(body)?;
    if body.node_id != expected_node_id
        || body.status != "pending"
        || !is_urlsafe_identifier(&body.enrollment_id)
        || !(20..=512).contains(&body.receipt.len())
    {
        return Err(BackendError::ProtocolInvalid);
    }
    Ok(EnrollmentStatus::Pending {
        enrollment_id: body.enrollment_id,
        receipt: SecretString::from(body.receipt),
    })
}

pub fn decode_pickup_response(
    body: &[u8],
    expected_enrollment_id: &str,
    expected_node_id: &str,
) -> Result<Option<NodeCertificate>, BackendError> {
    let body: PickupResponse = decode_json(body)?;
    if body.enrollment_id != expected_enrollment_id
        || body.node_id != expected_node_id
        || !is_urlsafe_identifier(&body.enrollment_id)
    {
        return Err(BackendError::ProtocolInvalid);
    }
    match body.status.as_str() {
        "pending"
            if body.certificate_pem.is_none()
                && body.ca_certificate_pem.is_none()
                && body.expires_at.is_none() =>
        {
            Ok(None)
        }
        "approved" => certificate_from_wire(
            body.certificate_pem,
            body.ca_certificate_pem,
            body.expires_at,
        )
        .map(Some),
        _ => Err(BackendError::ProtocolInvalid),
    }
}

pub fn decode_heartbeat_response(
    body: &[u8],
    expected_node_id: &str,
    expected_identity_epoch: u64,
    expected_sequence: u64,
) -> Result<NodeDirective, BackendError> {
    let body: HeartbeatResponse = decode_json(body)?;
    if body.node_id != expected_node_id
        || body.identity_epoch != expected_identity_epoch
        || body.sequence != expected_sequence
        || !matches!(
            body.state.as_str(),
            "available" | "degraded" | "draining" | "unavailable" | "revoked"
        )
        || body.desired.secret_version == 0
        || (body.desired.not_before.is_some() != body.desired.old_credential_deadline.is_some())
        || parse_rfc3339_unix_seconds(&body.lease_expires_at)? <= 0
    {
        return Err(BackendError::ProtocolInvalid);
    }
    let state = match body.state.as_str() {
        "available" => RelayNodeState::Available,
        "degraded" => RelayNodeState::Degraded,
        "draining" => RelayNodeState::Draining,
        "unavailable" => RelayNodeState::Unavailable,
        "revoked" => RelayNodeState::Revoked,
        _ => return Err(BackendError::ProtocolInvalid),
    };
    let not_before_unix_seconds = body
        .desired
        .not_before
        .as_deref()
        .map(parse_rfc3339_unix_seconds)
        .transpose()?;
    let old_credential_deadline_unix_seconds = body
        .desired
        .old_credential_deadline
        .as_deref()
        .map(parse_rfc3339_unix_seconds)
        .transpose()?;
    if not_before_unix_seconds
        .zip(old_credential_deadline_unix_seconds)
        .is_some_and(|(not_before, deadline)| deadline < not_before)
    {
        return Err(BackendError::ProtocolInvalid);
    }
    Ok(NodeDirective {
        identity_epoch: body.identity_epoch,
        sequence: body.sequence,
        state,
        desired: DesiredNodeState {
            draining: body.desired.draining,
            secret_version: body.desired.secret_version,
            not_before_unix_seconds,
            old_credential_deadline_unix_seconds,
        },
        secret_update: None,
    })
}

fn decode_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, BackendError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::from_slice(body).map_err(|_| BackendError::ProtocolInvalid)
}

fn is_urlsafe_identifier(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

async fn read_bounded_response(
    mut response: reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(BackendError::ProtocolInvalid);
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BackendError::Unavailable)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(BackendError::ProtocolInvalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[async_trait]
impl RelayBackendPort for ReqwestRelayBackend {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentStatus, BackendError> {
        let expected_node_id = request.node_id.clone();
        #[derive(Serialize)]
        struct EnrollmentWire<'a> {
            token: &'a str,
            node_id: &'a str,
            region: &'a str,
            failure_domain: &'a str,
            endpoints: &'a [String],
            max_allocations: u32,
            max_egress_bps: u64,
            csr_pem: &'a str,
            turn_rest_secret: &'a str,
        }
        let wire = EnrollmentWire {
            token: request.token.expose_secret(),
            node_id: &request.node_id,
            region: &request.region,
            failure_domain: &request.failure_domain,
            endpoints: &request.endpoints,
            max_allocations: request.max_allocations,
            max_egress_bps: request.max_egress_bps,
            csr_pem: &request.csr_pem,
            turn_rest_secret: request.turn_rest_secret.expose_secret(),
        };
        let response = self
            .enrollment_client
            .post(self.url("api/v1/relays/enroll")?)
            .json(&wire)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if response.status() != StatusCode::ACCEPTED {
            return Err(BackendError::Rejected);
        }
        let body = read_bounded_response(response).await?;
        decode_enrollment_response(&body, &expected_node_id)
    }

    async fn pickup(
        &self,
        request: PickupRequest,
    ) -> Result<Option<NodeCertificate>, BackendError> {
        let expected_enrollment_id = request.enrollment_id.clone();
        let expected_node_id = request.node_id.clone();
        let response = self
            .enrollment_client
            .post(self.url(&format!(
                "api/v1/relays/enrollments/{}/pickup",
                request.enrollment_id
            ))?)
            .header(
                "X-Relay-Enrollment-Receipt",
                request.receipt.expose_secret(),
            )
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if !response.status().is_success() {
            return Err(BackendError::Rejected);
        }
        let body = read_bounded_response(response).await?;
        decode_pickup_response(&body, &expected_enrollment_id, &expected_node_id)
    }

    async fn renew(&self, request: RenewalRequest) -> Result<NodeCertificate, BackendError> {
        let expected_node_id = request.node_id.clone();
        let expected_renewal_id = request.renewal_id.clone();
        let path = format!("/api/v1/relays/{}/renew", request.node_id);
        let body = serialize_renewal_body(&request.renewal_id, &request.csr_pem)?;
        let response = self
            .mtls_client
            .as_ref()
            .ok_or(BackendError::TlsInvalid)?
            .post(self.url(path.trim_start_matches('/'))?)
            .header("X-Relay-Node-Id", &request.node_id)
            .header("X-Relay-Timestamp", request.authentication.timestamp)
            .header("X-Relay-Sequence", request.authentication.sequence)
            .header("X-Relay-Signature", &request.authentication.signature_b64)
            .header("X-Relay-Renewal-Id", &request.renewal_id)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if !response.status().is_success() {
            return Err(BackendError::Rejected);
        }
        let body = read_bounded_response(response).await?;
        let body: RenewalResponse = decode_json(&body)?;
        if body.node_id != expected_node_id
            || body.renewal_id != expected_renewal_id
            || !is_urlsafe_identifier(&body.renewal_id)
            || body.fingerprint.len() != 71
            || !body.fingerprint.starts_with("sha256:")
            || !body.fingerprint.as_bytes()[7..]
                .iter()
                .copied()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(BackendError::ProtocolInvalid);
        }
        certificate_from_wire(
            Some(body.certificate_pem),
            Some(body.ca_certificate_pem),
            Some(body.expires_at),
        )
    }

    async fn heartbeat(&self, heartbeat: SignedHeartbeat) -> Result<NodeDirective, BackendError> {
        let expected_node_id = heartbeat.node_id.clone();
        let expected_identity_epoch = heartbeat.identity_epoch;
        let expected_sequence = heartbeat.sequence;
        let path = format!("api/v1/relays/{}/heartbeat", heartbeat.node_id);
        let response = self
            .mtls_client
            .as_ref()
            .ok_or(BackendError::TlsInvalid)?
            .post(self.url(&path)?)
            .header("Content-Type", "application/json")
            .header("X-Relay-Node-Id", &heartbeat.node_id)
            .header("X-Relay-Timestamp", heartbeat.timestamp)
            .header("X-Relay-Sequence", heartbeat.sequence)
            .header("X-Relay-Signature", &heartbeat.signature_b64)
            .body(heartbeat.body)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if !response.status().is_success() {
            return Err(BackendError::Rejected);
        }
        let body = read_bounded_response(response).await?;
        decode_heartbeat_response(
            &body,
            &expected_node_id,
            expected_identity_epoch,
            expected_sequence,
        )
    }

    async fn upload_secret(&self, request: SecretUploadRequest) -> Result<(), BackendError> {
        let path = format!("/api/v1/relays/{}/secret-rotation/upload", request.node_id);
        let body = serialize_secret_upload_body(&request)?;
        let response = self
            .mtls_client
            .as_ref()
            .ok_or(BackendError::TlsInvalid)?
            .post(self.url(path.trim_start_matches('/'))?)
            .header("X-Relay-Node-Id", &request.node_id)
            .header("X-Relay-Timestamp", request.authentication.timestamp)
            .header("X-Relay-Sequence", request.authentication.sequence)
            .header("X-Relay-Signature", &request.authentication.signature_b64)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if response.status() != StatusCode::ACCEPTED || !response_has_no_store(&response) {
            return Err(BackendError::Rejected);
        }
        let body = read_bounded_response(response).await?;
        let body: SecretUploadResponse = decode_json(&body)?;
        if body.node_id != request.node_id
            || body.identity_epoch != request.identity_epoch
            || body.rotation_id != request.rotation_id
            || body.secret_version != request.secret_version
            || body.status != "uploaded"
        {
            return Err(BackendError::ProtocolInvalid);
        }
        Ok(())
    }

    async fn commit_secret(&self, request: SecretCommitRequest) -> Result<(), BackendError> {
        let path = format!("/api/v1/relays/{}/secret-rotation/commit", request.node_id);
        let body = serialize_secret_commit_body(&request)?;
        let response = self
            .mtls_client
            .as_ref()
            .ok_or(BackendError::TlsInvalid)?
            .post(self.url(path.trim_start_matches('/'))?)
            .header("X-Relay-Node-Id", &request.node_id)
            .header("X-Relay-Timestamp", request.authentication.timestamp)
            .header("X-Relay-Sequence", request.authentication.sequence)
            .header("X-Relay-Signature", &request.authentication.signature_b64)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if !response.status().is_success() || !response_has_no_store(&response) {
            return Err(BackendError::Rejected);
        }
        let body = read_bounded_response(response).await?;
        let body: SecretCommitResponse = decode_json(&body)?;
        if body.node_id != request.node_id
            || body.identity_epoch != request.identity_epoch
            || body.rotation_id != request.rotation_id
            || body.active_secret_version != request.secret_version
            || body.status != "committed"
        {
            return Err(BackendError::ProtocolInvalid);
        }
        Ok(())
    }
}

fn response_has_no_store(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"))
        })
}

fn certificate_from_wire(
    certificate_pem: Option<String>,
    ca_certificate_pem: Option<String>,
    expires_at: Option<String>,
) -> Result<NodeCertificate, BackendError> {
    let certificate_pem = certificate_pem.ok_or(BackendError::ProtocolInvalid)?;
    let ca_certificate_pem = ca_certificate_pem.ok_or(BackendError::ProtocolInvalid)?;
    let expires_at = expires_at.ok_or(BackendError::ProtocolInvalid)?;
    let expires_at_unix_seconds = parse_rfc3339_unix_seconds(&expires_at)?;
    if certificate_pem.len() > 64 * 1024 || ca_certificate_pem.len() > 64 * 1024 {
        return Err(BackendError::ProtocolInvalid);
    }
    Ok(NodeCertificate {
        certificate_pem,
        ca_certificate_pem,
        expires_at_unix_seconds,
    })
}

fn parse_rfc3339_unix_seconds(value: &str) -> Result<i64, BackendError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|value| value.unix_timestamp())
        .map_err(|_| BackendError::ProtocolInvalid)
}
