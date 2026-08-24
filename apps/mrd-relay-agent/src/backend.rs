use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use reqwest::{Certificate, Client, Identity, StatusCode};
use ring::{digest, signature};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::process::SecretBytes;

const REQUEST_CONTEXT: &[u8] = b"MRD_RELAY_REQUEST_V1\0";
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

fn bytes_from_zeroizing_owner<T>(owner: T) -> Bytes
where
    T: AsRef<[u8]> + ZeroizeOnDrop + Send + 'static,
{
    Bytes::from_owner(owner)
}

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
            .field("endpoint_count", &self.endpoints.len())
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
    signed_body: Bytes,
}

impl SecretUploadRequest {
    pub fn signed_body(&self) -> &[u8] {
        &self.signed_body
    }
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

#[derive(Clone)]
pub struct SecretCommitRequest {
    pub node_id: String,
    pub identity_epoch: u64,
    pub rotation_id: String,
    pub secret_version: u64,
    pub rotation_challenge: String,
    pub probe_evidence_sha256: String,
    pub proof_mac: String,
    pub authentication: RequestAuthentication,
}

impl std::fmt::Debug for SecretCommitRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretCommitRequest")
            .field("node_id", &self.node_id)
            .field("identity_epoch", &self.identity_epoch)
            .field("rotation_id", &self.rotation_id)
            .field("secret_version", &self.secret_version)
            .field("rotation_challenge", &"REDACTED")
            .field("probe_evidence_sha256", &"REDACTED")
            .field("proof_mac", &"REDACTED")
            .field("authentication", &self.authentication)
            .finish()
    }
}

#[derive(Clone)]
pub struct SecretRotationStatusRequest {
    pub node_id: String,
    pub identity_epoch: u64,
    pub rotation_id: String,
    pub secret_version: u64,
    pub rotation_challenge: String,
    pub probe_evidence_sha256: String,
    pub proof_mac: String,
    pub authentication: RequestAuthentication,
}

impl std::fmt::Debug for SecretRotationStatusRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretRotationStatusRequest")
            .field("node_id", &self.node_id)
            .field("identity_epoch", &self.identity_epoch)
            .field("rotation_id", &self.rotation_id)
            .field("secret_version", &self.secret_version)
            .field("rotation_challenge", &"REDACTED")
            .field("probe_evidence_sha256", &"REDACTED")
            .field("proof_mac", &"REDACTED")
            .field("authentication", &self.authentication)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretRotationStatus {
    CommittedExact { active_secret_version: u64 },
    Pending { active_secret_version: u64 },
    Unknown { active_secret_version: u64 },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayHealth {
    Healthy,
    Degraded,
    Failed,
    NonEvidence,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
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
            || self.probe_health == RelayHealth::Degraded
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
                .any(|endpoint| !crate::config::is_public_turn_endpoint(endpoint))
        {
            return Err(BackendError::ProtocolInvalid);
        }
        Ok(())
    }
}

impl std::fmt::Debug for HeartbeatPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeartbeatPayload")
            .field("identity_epoch", &self.identity_epoch)
            .field("boot_id", &self.boot_id)
            .field("nonce", &"REDACTED")
            .field("process_health", &self.process_health)
            .field("listener_health", &self.listener_health)
            .field("probe_health", &self.probe_health)
            .field("active_allocations", &self.active_allocations)
            .field("current_ingress_bps", &self.current_ingress_bps)
            .field("current_egress_bps", &self.current_egress_bps)
            .field("max_allocations", &self.max_allocations)
            .field("max_egress_bps", &self.max_egress_bps)
            .field("packet_loss_bps", &self.packet_loss_bps)
            .field("cpu_usage_bps", &self.cpu_usage_bps)
            .field("memory_usage_bps", &self.memory_usage_bps)
            .field("measured_rtt_ms", &self.measured_rtt_ms)
            .field("recent_failure_bps", &self.recent_failure_bps)
            .field("endpoint_count", &self.endpoints.len())
            .field("applied_secret_version", &self.applied_secret_version)
            .finish()
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

#[derive(Clone, PartialEq, Eq)]
pub struct DesiredNodeState {
    pub draining: bool,
    pub secret_version: u64,
    pub not_before_unix_seconds: Option<i64>,
    pub old_credential_deadline_unix_seconds: Option<i64>,
    pub rotation_challenge: Option<String>,
}

impl std::fmt::Debug for DesiredNodeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesiredNodeState")
            .field("draining", &self.draining)
            .field("secret_version", &self.secret_version)
            .field("not_before_unix_seconds", &self.not_before_unix_seconds)
            .field(
                "old_credential_deadline_unix_seconds",
                &self.old_credential_deadline_unix_seconds,
            )
            .field(
                "rotation_challenge",
                &self.rotation_challenge.as_ref().map(|_| "REDACTED"),
            )
            .finish()
    }
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
                rotation_challenge: None,
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
                rotation_challenge: None,
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
    #[error("relay_backend_conflict")]
    Conflict,
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
            Self::Conflict => "relay_backend_conflict",
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
    async fn rotation_status(
        &self,
        _request: SecretRotationStatusRequest,
    ) -> Result<SecretRotationStatus, BackendError> {
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

    async fn rotation_status(
        &self,
        request: SecretRotationStatusRequest,
    ) -> Result<SecretRotationStatus, BackendError> {
        self.current().rotation_status(request).await
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

fn serialize_secret_upload_body(
    identity_epoch: u64,
    rotation_id: &str,
    secret_version: u64,
    turn_rest_secret: &str,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    #[derive(Serialize)]
    struct Wire<'a> {
        identity_epoch: u64,
        rotation_id: &'a str,
        secret_version: u64,
        turn_rest_secret: &'a str,
    }
    if identity_epoch == 0
        || secret_version < 2
        || !is_urlsafe_identifier(rotation_id)
        || !is_canonical_base64url(turn_rest_secret, 32)
    {
        return Err(BackendError::ProtocolInvalid);
    }
    let mut body = Zeroizing::new(Vec::new());
    serde_json::to_writer(
        &mut *body,
        &Wire {
            identity_epoch,
            rotation_id,
            secret_version,
            turn_rest_secret,
        },
    )
    .map_err(|_| BackendError::ProtocolInvalid)?;
    Ok(body)
}

pub(crate) fn build_secret_upload_request<E>(
    node_id: String,
    identity_epoch: u64,
    rotation_id: String,
    secret_version: u64,
    turn_rest_secret: SecretString,
    signer: impl FnOnce(&[u8]) -> Result<RequestAuthentication, E>,
) -> Result<SecretUploadRequest, E>
where
    E: From<BackendError>,
{
    if !is_node_identifier(&node_id) {
        return Err(E::from(BackendError::ProtocolInvalid));
    }
    let body = serialize_secret_upload_body(
        identity_epoch,
        &rotation_id,
        secret_version,
        turn_rest_secret.expose_secret(),
    )
    .map_err(E::from)?;
    let authentication = signer(body.as_ref())?;
    Ok(SecretUploadRequest {
        node_id,
        identity_epoch,
        rotation_id,
        secret_version,
        turn_rest_secret,
        authentication,
        signed_body: bytes_from_zeroizing_owner(body),
    })
}

fn serialize_enrollment_body(request: &EnrollmentRequest) -> Result<Bytes, BackendError> {
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
    let mut body = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *body, &wire).map_err(|_| BackendError::ProtocolInvalid)?;
    Ok(bytes_from_zeroizing_owner(body))
}

pub(crate) fn serialize_secret_commit_body(
    request: &SecretCommitRequest,
) -> Result<Vec<u8>, BackendError> {
    serialize_rotation_proof_body(
        request.identity_epoch,
        &request.rotation_id,
        request.secret_version,
        &request.rotation_challenge,
        &request.probe_evidence_sha256,
        &request.proof_mac,
    )
}

pub(crate) fn serialize_secret_rotation_status_body(
    request: &SecretRotationStatusRequest,
) -> Result<Vec<u8>, BackendError> {
    serialize_rotation_proof_body(
        request.identity_epoch,
        &request.rotation_id,
        request.secret_version,
        &request.rotation_challenge,
        &request.probe_evidence_sha256,
        &request.proof_mac,
    )
}

fn serialize_rotation_proof_body(
    identity_epoch: u64,
    rotation_id: &str,
    secret_version: u64,
    rotation_challenge: &str,
    probe_evidence_sha256: &str,
    proof_mac: &str,
) -> Result<Vec<u8>, BackendError> {
    #[derive(Serialize)]
    struct Wire<'a> {
        identity_epoch: u64,
        rotation_id: &'a str,
        secret_version: u64,
        rotation_challenge: &'a str,
        probe_evidence_sha256: &'a str,
        proof_mac: &'a str,
    }
    if identity_epoch == 0
        || secret_version < 2
        || !is_urlsafe_identifier(rotation_id)
        || !is_canonical_base64url(rotation_challenge, 32)
        || probe_evidence_sha256.len() != 64
        || !probe_evidence_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || proof_mac.len() != 64
        || !proof_mac
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::to_vec(&Wire {
        identity_epoch,
        rotation_id,
        secret_version,
        rotation_challenge,
        probe_evidence_sha256,
        proof_mac,
    })
    .map_err(|_| BackendError::ProtocolInvalid)
}

const ROTATION_PROOF_CONTEXT: &[u8] = b"MRD_RELAY_ROTATION_PROOF_V1\0";

pub fn rotation_proof_message(
    node_id: &str,
    identity_epoch: u64,
    rotation_id: &str,
    secret_version: u64,
    rotation_challenge: &str,
    pending_secret_digest: &[u8; 32],
    probe_evidence_sha256: &[u8; 32],
) -> Result<Vec<u8>, BackendError> {
    if identity_epoch == 0
        || secret_version < 2
        || !is_node_identifier(node_id)
        || !is_urlsafe_identifier(rotation_id)
        || !is_canonical_base64url(rotation_challenge, 32)
    {
        return Err(BackendError::ProtocolInvalid);
    }
    let identity_epoch = identity_epoch.to_string();
    let secret_version = secret_version.to_string();
    let fields: [&[u8]; 7] = [
        node_id.as_bytes(),
        identity_epoch.as_bytes(),
        rotation_id.as_bytes(),
        secret_version.as_bytes(),
        rotation_challenge.as_bytes(),
        pending_secret_digest,
        probe_evidence_sha256,
    ];
    let mut output = Vec::with_capacity(
        ROTATION_PROOF_CONTEXT.len() + fields.iter().map(|field| 4 + field.len()).sum::<usize>(),
    );
    output.extend_from_slice(ROTATION_PROOF_CONTEXT);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| BackendError::ProtocolInvalid)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
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
        let private_pem = encode_private_pkcs8_pem(private_pkcs8)?;
        let backend = ReqwestRelayBackend::new(self.base_url.clone(), &self.ca_certificate_pem)?
            .with_mtls_identity(
                certificate.certificate_pem.as_bytes(),
                private_pem.as_bytes(),
            )?;
        Ok(Arc::new(backend))
    }
}

fn encode_private_pkcs8_pem(private_pkcs8: &[u8]) -> Result<Zeroizing<String>, BackendError> {
    if private_pkcs8.is_empty() || private_pkcs8.len() > 64 * 1024 {
        return Err(BackendError::TlsInvalid);
    }
    let encoded = Zeroizing::new(STANDARD.encode(private_pkcs8));
    let mut pem = Zeroizing::new(String::with_capacity(encoded.len().saturating_add(64)));
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).map_err(|_| BackendError::TlsInvalid)?);
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    Ok(pem)
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
        .tls_built_in_root_certs(false)
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
    rotation_challenge: Option<String>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRotationStatusResponse {
    node_id: String,
    identity_epoch: u64,
    active_secret_version: u64,
    status: String,
}

pub fn decode_secret_rotation_status_response(
    body: &[u8],
    expected_node_id: &str,
    expected_identity_epoch: u64,
    target_secret_version: u64,
) -> Result<SecretRotationStatus, BackendError> {
    let body: SecretRotationStatusResponse = decode_json(body)?;
    if body.node_id != expected_node_id
        || body.identity_epoch != expected_identity_epoch
        || body.active_secret_version == 0
        || target_secret_version < 2
    {
        return Err(BackendError::ProtocolInvalid);
    }
    match body.status.as_str() {
        "committed_exact" if body.active_secret_version == target_secret_version => {
            Ok(SecretRotationStatus::CommittedExact {
                active_secret_version: body.active_secret_version,
            })
        }
        "pending" if body.active_secret_version < target_secret_version => {
            Ok(SecretRotationStatus::Pending {
                active_secret_version: body.active_secret_version,
            })
        }
        "unknown" => Ok(SecretRotationStatus::Unknown {
            active_secret_version: body.active_secret_version,
        }),
        _ => Err(BackendError::ProtocolInvalid),
    }
}

pub fn decode_enrollment_response(
    body: &[u8],
    expected_node_id: &str,
) -> Result<EnrollmentStatus, BackendError> {
    let body: EnrollmentResponse = decode_json(body)?;
    if body.node_id != expected_node_id
        || body.status != "pending"
        || !is_urlsafe_identifier(&body.enrollment_id)
        || !valid_enrollment_receipt(&body.receipt)
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
        || (body.desired.rotation_challenge.is_some() != body.desired.not_before.is_some())
        || body
            .desired
            .rotation_challenge
            .as_deref()
            .is_some_and(|value| !is_canonical_base64url(value, 32))
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
            rotation_challenge: body.desired.rotation_challenge,
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
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_node_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub(crate) fn valid_enrollment_receipt(value: &str) -> bool {
    (20..=512).contains(&value.len())
        && value
            .as_bytes()
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_graphic())
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

fn backend_status_error(status: StatusCode) -> Option<BackendError> {
    if status.is_success() {
        return None;
    }
    match status.as_u16() {
        408 | 425 | 429 | 500 | 502 | 503 | 504 => Some(BackendError::Unavailable),
        409 => Some(BackendError::Conflict),
        _ => Some(BackendError::Rejected),
    }
}

fn require_success_status(status: StatusCode) -> Result<(), BackendError> {
    backend_status_error(status).map_or(Ok(()), Err)
}

#[async_trait]
impl RelayBackendPort for ReqwestRelayBackend {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<EnrollmentStatus, BackendError> {
        let expected_node_id = request.node_id.clone();
        let body = serialize_enrollment_body(&request)?;
        // The serialized zeroizing owner is now authoritative; release the
        // source SecretString owners before the network await.
        drop(request);
        let response = self
            .enrollment_client
            .post(self.url("api/v1/relays/enroll")?)
            .header("Content-Type", "application/json")
            // The zeroizing Bytes owner covers every controllable plaintext
            // allocation. Copies below reqwest/hyper/rustls are an upstream
            // boundary with no accessible clearing API.
            .body(body)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if response.status() != StatusCode::ACCEPTED {
            return Err(
                backend_status_error(response.status()).unwrap_or(BackendError::ProtocolInvalid)
            );
        }
        require_private_no_store(&response)?;
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
        require_success_status(response.status())?;
        require_private_no_store(&response)?;
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
        require_success_status(response.status())?;
        require_private_no_store(&response)?;
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
        require_success_status(response.status())?;
        require_private_no_store(&response)?;
        let body = read_bounded_response(response).await?;
        decode_heartbeat_response(
            &body,
            &expected_node_id,
            expected_identity_epoch,
            expected_sequence,
        )
    }

    async fn upload_secret(&self, request: SecretUploadRequest) -> Result<(), BackendError> {
        let SecretUploadRequest {
            node_id,
            identity_epoch,
            rotation_id,
            secret_version,
            turn_rest_secret: _,
            authentication,
            signed_body,
        } = request;
        let path = format!("/api/v1/relays/{node_id}/secret-rotation/upload");
        let response = self
            .mtls_client
            .as_ref()
            .ok_or(BackendError::TlsInvalid)?
            .post(self.url(path.trim_start_matches('/'))?)
            .header("X-Relay-Node-Id", &node_id)
            .header("X-Relay-Timestamp", authentication.timestamp)
            .header("X-Relay-Sequence", authentication.sequence)
            .header("X-Relay-Signature", &authentication.signature_b64)
            .header("Content-Type", "application/json")
            // This is the exact Bytes owner that was signed. It remains alive
            // through reqwest's request-body lifetime and zeroizes on final
            // drop. Copies below reqwest/hyper/rustls are an upstream boundary
            // with no accessible clearing API.
            .body(signed_body)
            .send()
            .await
            .map_err(|_| BackendError::Unavailable)?;
        if response.status() != StatusCode::ACCEPTED {
            return Err(
                backend_status_error(response.status()).unwrap_or(BackendError::ProtocolInvalid)
            );
        }
        require_private_no_store(&response)?;
        let body = read_bounded_response(response).await?;
        let body: SecretUploadResponse = decode_json(&body)?;
        if body.node_id != node_id
            || body.identity_epoch != identity_epoch
            || body.rotation_id != rotation_id
            || body.secret_version != secret_version
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
        require_success_status(response.status())?;
        require_private_no_store(&response)?;
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

    async fn rotation_status(
        &self,
        request: SecretRotationStatusRequest,
    ) -> Result<SecretRotationStatus, BackendError> {
        let path = format!("/api/v1/relays/{}/secret-rotation/status", request.node_id);
        let body = serialize_secret_rotation_status_body(&request)?;
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
        require_success_status(response.status())?;
        require_private_no_store(&response)?;
        let body = read_bounded_response(response).await?;
        decode_secret_rotation_status_response(
            &body,
            &request.node_id,
            request.identity_epoch,
            request.secret_version,
        )
    }
}

fn require_private_no_store(response: &reqwest::Response) -> Result<(), BackendError> {
    if headers_are_private_no_store(response.headers()) {
        Ok(())
    } else {
        Err(BackendError::ProtocolInvalid)
    }
}

fn headers_are_private_no_store(headers: &reqwest::header::HeaderMap) -> bool {
    let cache_control = headers
        .get_all(reqwest::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','));
    let mut no_store = false;
    let mut private = false;
    for directive in cache_control {
        no_store |= directive.trim().eq_ignore_ascii_case("no-store");
        private |= directive.trim().eq_ignore_ascii_case("private");
    }
    let pragma_no_cache = headers
        .get_all(reqwest::header::PRAGMA)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-cache"));
    no_store && private && pragma_no_cache
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

#[cfg(test)]
mod response_security_tests {
    use std::{
        net::IpAddr,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    use super::{
        backend_status_error, build_secret_upload_request, bytes_from_zeroizing_owner,
        decode_enrollment_response, headers_are_private_no_store, secure_client,
        serialize_enrollment_body, BackendError, EnrollmentRequest, RequestAuthentication,
    };
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ED25519,
    };
    use reqwest::header::{HeaderMap, HeaderValue, CACHE_CONTROL, PRAGMA};
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use secrecy::{ExposeSecret, SecretString};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    struct ObservableZeroizingOwner {
        bytes: Vec<u8>,
        zeroized: Arc<AtomicBool>,
    }

    impl AsRef<[u8]> for ObservableZeroizingOwner {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Zeroize for ObservableZeroizingOwner {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.zeroized.store(true, Ordering::SeqCst);
        }
    }

    impl Drop for ObservableZeroizingOwner {
        fn drop(&mut self) {
            self.zeroize();
        }
    }

    impl ZeroizeOnDrop for ObservableZeroizingOwner {}

    struct TestTlsAuthority {
        certificate: Certificate,
        key: KeyPair,
    }

    impl TestTlsAuthority {
        fn new(common_name: &str) -> Self {
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let mut params = CertificateParams::default();
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, common_name);
            params.distinguished_name = name;
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let certificate = params.self_signed(&key).unwrap();
            Self { certificate, key }
        }

        fn server_config(&self, san: IpAddr) -> ServerConfig {
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.subject_alt_names = vec![SanType::IpAddress(san)];
            let certificate = params
                .signed_by(&key, &self.certificate, &self.key)
                .unwrap();
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap()
        }
    }

    async fn spawn_https_server(config: ServerConfig) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        address
    }

    #[test]
    fn sensitive_responses_require_private_no_store_and_pragma_no_cache() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        assert!(headers_are_private_no_store(&headers));

        for missing in [CACHE_CONTROL, PRAGMA] {
            let mut stripped = headers.clone();
            stripped.remove(missing);
            assert!(!headers_are_private_no_store(&stripped));
        }
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        assert!(!headers_are_private_no_store(&headers));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("private"));
        assert!(!headers_are_private_no_store(&headers));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("cache"));
        assert!(!headers_are_private_no_store(&headers));
    }

    #[test]
    fn transient_http_statuses_are_retryable_but_auth_and_protocol_fail_closed() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert_eq!(
                backend_status_error(reqwest::StatusCode::from_u16(status).unwrap()),
                Some(BackendError::Unavailable)
            );
        }
        assert_eq!(
            backend_status_error(reqwest::StatusCode::CONFLICT),
            Some(BackendError::Conflict)
        );
        for status in [400, 401, 403, 404, 422] {
            assert_eq!(
                backend_status_error(reqwest::StatusCode::from_u16(status).unwrap()),
                Some(BackendError::Rejected)
            );
        }
        assert_eq!(backend_status_error(reqwest::StatusCode::OK), None);
    }

    #[test]
    fn enrollment_receipt_is_always_safe_for_the_pickup_header() {
        fn response(receipt: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "enrollment_id": "enroll-0001",
                "node_id": "relay-hkg-1",
                "status": "pending",
                "receipt": receipt,
            }))
            .unwrap()
        }

        for receipt in ["r".repeat(20), "r".repeat(512)] {
            assert!(decode_enrollment_response(&response(&receipt), "relay-hkg-1").is_ok());
            assert!(reqwest::header::HeaderValue::from_str(&receipt).is_ok());
        }
        for byte in b'!'..=b'~' {
            let receipt = char::from(byte).to_string().repeat(20);
            assert!(decode_enrollment_response(&response(&receipt), "relay-hkg-1").is_ok());
            assert!(reqwest::header::HeaderValue::from_str(&receipt).is_ok());
        }

        for receipt in [
            "r".repeat(19),
            "r".repeat(513),
            format!("{} {}", "r".repeat(10), "r".repeat(10)),
            format!("{}\r{}", "r".repeat(10), "r".repeat(10)),
            format!("{}\n{}", "r".repeat(10), "r".repeat(10)),
            format!("{}\0{}", "r".repeat(10), "r".repeat(10)),
            format!("{}\u{7f}{}", "r".repeat(10), "r".repeat(10)),
            format!("{}é{}", "r".repeat(10), "r".repeat(10)),
        ] {
            assert!(
                matches!(
                    decode_enrollment_response(&response(&receipt), "relay-hkg-1"),
                    Err(BackendError::ProtocolInvalid)
                ),
                "receipt should be rejected: {receipt:?}"
            );
        }
    }

    #[test]
    fn bytes_owner_is_zeroized_only_after_the_last_body_clone_drops() {
        let zeroized = Arc::new(AtomicBool::new(false));
        let body = bytes_from_zeroizing_owner(ObservableZeroizingOwner {
            bytes: b"a controllable secret body".to_vec(),
            zeroized: zeroized.clone(),
        });
        let request_body = body.clone();
        drop(body);
        assert!(!zeroized.load(Ordering::SeqCst));
        drop(request_body);
        assert!(zeroized.load(Ordering::SeqCst));
    }

    #[test]
    fn secret_upload_signs_and_carries_one_exact_canonical_body() {
        let calls = AtomicUsize::new(0);
        let mut signed = Vec::new();
        let mut request = build_secret_upload_request(
            "relay-hkg-1".to_owned(),
            7,
            "rotation-0001".to_owned(),
            8,
            SecretString::from("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
            |body| {
                calls.fetch_add(1, Ordering::SeqCst);
                signed.extend_from_slice(body);
                Ok::<_, BackendError>(RequestAuthentication {
                    timestamp: 2_500,
                    sequence: 41,
                    signature_b64: "signature".to_owned(),
                })
            },
        )
        .unwrap();

        let expected = br#"{"identity_epoch":7,"rotation_id":"rotation-0001","secret_version":8,"turn_rest_secret":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(signed, expected);
        assert_eq!(request.signed_body(), expected);

        request.turn_rest_secret =
            SecretString::from("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI");
        assert_ne!(
            request.turn_rest_secret.expose_secret().as_bytes(),
            request.signed_body()
        );
        assert_eq!(request.signed_body(), expected);

        let source = include_str!("backend.rs");
        let builder_start = source
            .find("pub(crate) fn build_secret_upload_request")
            .unwrap();
        let builder_end = source[builder_start..]
            .find("fn serialize_enrollment_body")
            .map(|offset| builder_start + offset)
            .unwrap();
        assert_eq!(
            source[builder_start..builder_end]
                .matches("serialize_secret_upload_body(")
                .count(),
            1
        );
        let implementation = source
            .split_once("impl RelayBackendPort for ReqwestRelayBackend")
            .unwrap()
            .1;
        let upload_start = implementation.find("async fn upload_secret(&self").unwrap();
        let upload_end = implementation[upload_start..]
            .find("async fn commit_secret(&self")
            .map(|offset| upload_start + offset)
            .unwrap();
        let upload = &implementation[upload_start..upload_end];
        assert!(!upload.contains("serialize_secret_upload_body"));
        assert!(!upload.contains("mem::take"));
    }

    #[test]
    fn enrollment_secrets_are_serialized_into_the_zeroizing_body_owner() {
        let request = EnrollmentRequest {
            token: SecretString::from("private-enrollment-token"),
            node_id: "relay-hkg-1".to_owned(),
            region: "ap-east".to_owned(),
            failure_domain: "hkg-a".to_owned(),
            endpoints: vec!["turn:relay.example:3478?transport=udp".to_owned()],
            max_allocations: 100,
            max_egress_bps: 1_000_000,
            csr_pem: "csr".to_owned(),
            turn_rest_secret: SecretString::from("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
        };
        let body = serialize_enrollment_body(&request).unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"token":"private-enrollment-token","node_id":"relay-hkg-1","region":"ap-east","failure_domain":"hkg-a","endpoints":["turn:relay.example:3478?transport=udp"],"max_allocations":100,"max_egress_bps":1000000,"csr_pem":"csr","turn_rest_secret":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#
        );

        let source = include_str!("backend.rs");
        let implementation = source
            .split_once("impl RelayBackendPort for ReqwestRelayBackend")
            .unwrap()
            .1;
        let enroll_start = implementation.find("async fn enroll(&self").unwrap();
        let enroll_end = implementation[enroll_start..]
            .find("async fn pickup(&self")
            .map(|offset| enroll_start + offset)
            .unwrap();
        let enroll = &implementation[enroll_start..enroll_end];
        assert!(enroll.contains("serialize_enrollment_body(&request)"));
        assert!(enroll.contains("drop(request);"));
        assert!(enroll.contains(".body(body)"));
        assert!(!enroll.contains(".json("));
    }

    #[test]
    fn strict_clients_disable_builtin_roots_and_heartbeat_checks_sensitive_headers() {
        let source = include_str!("backend.rs");
        let disable_builtin = ["tls_built_", "in_root_certs(false)"].concat();
        assert!(source.contains(&disable_builtin));

        let implementation = source
            .split_once("impl RelayBackendPort for ReqwestRelayBackend")
            .unwrap()
            .1;
        let heartbeat_start = implementation.find("async fn heartbeat(&self").unwrap();
        let heartbeat_end = implementation[heartbeat_start..]
            .find("async fn upload_secret(&self")
            .map(|offset| heartbeat_start + offset)
            .unwrap();
        let heartbeat = &implementation[heartbeat_start..heartbeat_end];
        assert!(heartbeat.contains("require_private_no_store(&response)?"));
    }

    #[tokio::test]
    async fn configured_private_ca_is_exclusive_and_hostname_is_still_verified() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let configured = TestTlsAuthority::new("configured private root");
        let unrelated = TestTlsAuthority::new("unrelated root");
        let root = reqwest::Certificate::from_pem(configured.certificate.pem().as_bytes()).unwrap();
        let client = secure_client(Some(root), None).unwrap();

        let trusted_address =
            spawn_https_server(configured.server_config(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
                .await;
        let trusted = client
            .get(format!("https://{trusted_address}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(trusted.status(), reqwest::StatusCode::NO_CONTENT);

        let unrelated_address =
            spawn_https_server(unrelated.server_config(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)))
                .await;
        assert!(client
            .get(format!("https://{unrelated_address}/"))
            .send()
            .await
            .is_err());

        let wrong_san_address = spawn_https_server(
            configured.server_config(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))),
        )
        .await;
        assert!(client
            .get(format!("https://{wrong_san_address}/"))
            .send()
            .await
            .is_err());
    }
}
