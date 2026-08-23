use std::time::Duration;

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

#[derive(Clone, Debug, Serialize)]
pub struct RenewalRequest {
    pub node_id: String,
    pub renewal_id: String,
    pub csr_pem: String,
    #[serde(skip)]
    pub authentication: RequestAuthentication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeCertificate {
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub expires_at_unix_seconds: i64,
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
    pub timestamp: i64,
    pub sequence: u64,
    pub body: Vec<u8>,
    pub signature_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatPayload {
    pub active_allocations: u32,
    pub current_egress_bps: u64,
    pub measured_rtt_ms: Option<u32>,
    pub recent_failure_bps: u16,
    pub endpoints: Vec<String>,
}

impl HeartbeatPayload {
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.recent_failure_bps > 10_000
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

impl std::fmt::Debug for SignedHeartbeat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedHeartbeat")
            .field("node_id", &self.node_id)
            .field("timestamp", &self.timestamp)
            .field("sequence", &self.sequence)
            .field("body_length", &self.body.len())
            .field("signature_b64", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct NodeDirective {
    pub sequence: u64,
    pub draining: bool,
    pub secret_update: Option<SecretUpdate>,
}

impl NodeDirective {
    pub fn update(sequence: u64, draining: bool, version: u64, secret: SecretBytes) -> Self {
        Self {
            sequence,
            draining,
            secret_update: Some(SecretUpdate { version, secret }),
        }
    }

    pub fn state(sequence: u64, draining: bool) -> Self {
        Self {
            sequence,
            draining,
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
    if renewal_id.is_empty() || renewal_id.len() > 128 || csr_pem.len() > 16_384 {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::to_vec(&RenewalWire {
        renewal_id,
        csr_pem,
    })
    .map_err(|_| BackendError::ProtocolInvalid)
}

pub struct ReqwestRelayBackend {
    base_url: Url,
    root_certificate: Certificate,
    enrollment_client: Client,
    mtls_client: Option<Client>,
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
    state: String,
    sequence: u64,
    lease_expires_at: String,
}

pub fn decode_enrollment_response(
    body: &[u8],
    expected_node_id: &str,
) -> Result<EnrollmentStatus, BackendError> {
    let body: EnrollmentResponse = decode_json(body)?;
    if body.node_id != expected_node_id
        || body.status != "pending"
        || body.enrollment_id.is_empty()
        || body.enrollment_id.len() > 128
        || !(20..=512).contains(&body.receipt.len())
    {
        return Err(BackendError::ProtocolInvalid);
    }
    Ok(EnrollmentStatus::Pending {
        enrollment_id: body.enrollment_id,
        receipt: SecretString::from(body.receipt),
    })
}

pub fn decode_heartbeat_response(
    body: &[u8],
    expected_node_id: &str,
    expected_sequence: u64,
) -> Result<NodeDirective, BackendError> {
    let body: HeartbeatResponse = decode_json(body)?;
    if body.node_id != expected_node_id
        || body.sequence != expected_sequence
        || !matches!(
            body.state.as_str(),
            "ready" | "degraded" | "draining" | "unavailable" | "revoked"
        )
        || parse_rfc3339_unix_seconds(&body.lease_expires_at)? <= 0
    {
        return Err(BackendError::ProtocolInvalid);
    }
    Ok(NodeDirective::state(
        body.sequence,
        body.state == "draining",
    ))
}

fn decode_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, BackendError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(BackendError::ProtocolInvalid);
    }
    serde_json::from_slice(body).map_err(|_| BackendError::ProtocolInvalid)
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
        let body: PickupResponse = decode_json(&body)?;
        if body.enrollment_id != expected_enrollment_id || body.node_id != expected_node_id {
            return Err(BackendError::ProtocolInvalid);
        }
        if body.status == "pending" {
            return Ok(None);
        }
        certificate_from_wire(
            body.certificate_pem,
            body.ca_certificate_pem,
            body.expires_at,
        )
        .map(Some)
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
            || body.fingerprint.len() > 128
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
        decode_heartbeat_response(&body, &expected_node_id, expected_sequence)
    }
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
