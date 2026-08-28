//! Versioned, session-bound relay-directory contract.
//!
//! JSON is only a transport representation. Untrusted JSON must enter through
//! [`SignedRelayDirectory::from_json`], which enforces a total input limit
//! before parsing. Signatures always cover the canonical binary representation
//! produced by [`RelayDirectoryPayload::canonical_signing_bytes`].

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain-separation bytes prepended verbatim to every signed directory.
pub const RELAY_DIRECTORY_CONTEXT: &[u8] = b"MRD_RELAY_DIRECTORY_V1";
/// Only format version accepted by this implementation.
pub const RELAY_DIRECTORY_FORMAT_VERSION: u16 = 1;
/// Total transport limit, including JSON syntax and escaped string expansion.
///
/// This is eight times the 16 KiB canonical limit, leaving room for the
/// worst-case six-byte JSON escapes plus object syntax.
pub const MAX_RELAY_DIRECTORY_JSON_BYTES: usize = 128 * 1024;

const MAX_CANDIDATES: usize = 8;
const MAX_ENDPOINTS_PER_CANDIDATE: usize = 4;
const MAX_STRING_BYTES: usize = 256;
const MAX_CANONICAL_BYTES: usize = 16 * 1024;

/// TURN transport advertised by a signed relay directory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayDirectoryTransport {
    Udp,
    Tcp,
    Tls,
}

impl RelayDirectoryTransport {
    const fn wire_code(self) -> u8 {
        match self {
            Self::Udp => 1,
            Self::Tcp => 2,
            Self::Tls => 3,
        }
    }
}

/// One concrete TURN endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelayDirectoryEndpoint {
    pub transport: RelayDirectoryTransport,
    pub host: String,
    pub port: u16,
}

/// Capacity reservation attached to one relay candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelayReservation {
    pub reservation_id: String,
    pub expires_at_ms: u64,
}

/// A signed candidate, including selection explanation and reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelayDirectoryCandidate {
    pub node_id: String,
    pub region: String,
    pub failure_domain: String,
    pub endpoints: Vec<RelayDirectoryEndpoint>,
    pub capabilities: u32,
    pub load_class: u8,
    pub selection_reason: String,
    pub reservation: RelayReservation,
}

/// The complete session- and peer-bound signed payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelayDirectoryPayload {
    pub format_version: u16,
    pub policy_revision: u64,
    pub directory_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub session_id: String,
    pub intended_peer_digest: String,
    pub candidates: Vec<RelayDirectoryCandidate>,
}

/// JSON-transportable outer signature envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SignedRelayDirectory {
    pub payload: RelayDirectoryPayload,
    pub signing_key_id: String,
    pub signature_b64: String,
}

/// A directory whose signature, structure, session, time window, and reservations are valid.
///
/// This type does not establish that the policy revision or intended peer
/// matches the caller's authorization context. Candidate-consuming code should
/// require [`ContextVerifiedRelayDirectory`] instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRelayDirectory {
    payload: RelayDirectoryPayload,
    canonical_signing_bytes: Vec<u8>,
}

/// A directory additionally bound to the caller's exact policy and peer context.
///
/// This distinct type is produced only by
/// [`SignedRelayDirectory::verify_for_context`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextVerifiedRelayDirectory {
    verified: VerifiedRelayDirectory,
}

impl ContextVerifiedRelayDirectory {
    pub fn payload(&self) -> &RelayDirectoryPayload {
        self.verified.payload()
    }

    pub fn canonical_signing_bytes(&self) -> &[u8] {
        self.verified.canonical_signing_bytes()
    }

    pub fn into_payload(self) -> RelayDirectoryPayload {
        self.verified.into_payload()
    }
}

impl VerifiedRelayDirectory {
    pub fn payload(&self) -> &RelayDirectoryPayload {
        &self.payload
    }

    pub fn canonical_signing_bytes(&self) -> &[u8] {
        &self.canonical_signing_bytes
    }

    pub fn into_payload(self) -> RelayDirectoryPayload {
        self.payload
    }
}

/// Stable fail-closed rejection reasons for relay-directory consumers.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RelayDirectoryError {
    #[error("unsupported relay-directory format version {version}")]
    UnsupportedFormatVersion { version: u16 },
    #[error("relay-directory policy revision is invalid")]
    InvalidPolicyRevision,
    #[error("relay-directory policy revision does not match the expected revision")]
    PolicyRevisionMismatch { expected: u64, actual: u64 },
    #[error("relay-directory intended-peer binding does not match")]
    PeerBindingMismatch,
    #[error("relay-directory JSON exceeds the maximum of {max} bytes")]
    JsonTooLarge { max: usize },
    #[error("relay-directory JSON is invalid")]
    InvalidJson,
    #[error("relay directory has too many candidates (maximum {max})")]
    TooManyCandidates { max: usize },
    #[error("relay candidate has too many endpoints (maximum {max})")]
    TooManyEndpoints { max: usize },
    #[error("relay directory must contain at least one candidate")]
    EmptyCandidates,
    #[error("relay candidate must contain at least one endpoint")]
    EmptyEndpoints,
    #[error("relay directory contains a duplicate node")]
    DuplicateNode,
    #[error("relay candidate contains a duplicate endpoint")]
    DuplicateEndpoint,
    #[error("relay directory contains a duplicate reservation")]
    DuplicateReservation,
    #[error("relay candidates are not in canonical order")]
    NonCanonicalCandidateOrder,
    #[error("relay endpoints are not in canonical order")]
    NonCanonicalEndpointOrder,
    #[error("relay-directory field {field} is empty")]
    EmptyField { field: &'static str },
    #[error("relay-directory field {field} is too long (maximum {max} bytes)")]
    StringTooLong { field: &'static str, max: usize },
    #[error("relay-directory validity window is invalid")]
    InvalidValidityWindow,
    #[error("relay-directory reservation is invalid")]
    InvalidReservation,
    #[error("relay-directory load class is invalid")]
    InvalidLoadClass,
    #[error("relay directory is not yet valid")]
    NotYetValid,
    #[error("relay directory has expired")]
    Expired,
    #[error("relay reservation has expired")]
    ReservationExpired,
    #[error("relay directory is bound to a different session")]
    SessionMismatch,
    #[error("relay-directory signing key is not trusted")]
    UntrustedSigningKey,
    #[error("relay-directory signing key is invalid")]
    InvalidPublicKey,
    #[error("relay-directory signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("relay-directory signature is invalid")]
    InvalidSignature,
    #[error("relay-directory canonical representation is too large")]
    CanonicalEncodingTooLarge,
}

impl RelayDirectoryPayload {
    /// Build the only byte representation accepted for version 1 signatures.
    ///
    /// Field order is fixed: context, format version, policy revision,
    /// directory id, issued time, expiry, session id, intended-peer digest,
    /// candidate count, and then every canonical candidate. Candidate fields
    /// are node, region, failure domain, endpoint list, capability bits, load
    /// class, selection reason, reservation id, and reservation expiry.
    /// Integers are big-endian and strings are UTF-8 prefixed by a big-endian
    /// `u32` byte length. Candidates sort by the UTF-8 bytes of `node_id`.
    /// Endpoints sort by transport wire code, host UTF-8 bytes, and port.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, RelayDirectoryError> {
        self.validate_contract()?;

        let mut candidates: Vec<&RelayDirectoryCandidate> = self.candidates.iter().collect();
        candidates.sort_by(|left, right| left.node_id.as_bytes().cmp(right.node_id.as_bytes()));

        let mut encoded = Vec::with_capacity(1024);
        encoded.extend_from_slice(RELAY_DIRECTORY_CONTEXT);
        push_u16(&mut encoded, self.format_version);
        push_u64(&mut encoded, self.policy_revision);
        push_string(&mut encoded, "directory_id", &self.directory_id)?;
        push_u64(&mut encoded, self.issued_at_ms);
        push_u64(&mut encoded, self.expires_at_ms);
        push_string(&mut encoded, "session_id", &self.session_id)?;
        push_string(
            &mut encoded,
            "intended_peer_digest",
            &self.intended_peer_digest,
        )?;
        push_u32(&mut encoded, candidates.len() as u32);

        for candidate in candidates {
            push_string(&mut encoded, "node_id", &candidate.node_id)?;
            push_string(&mut encoded, "region", &candidate.region)?;
            push_string(&mut encoded, "failure_domain", &candidate.failure_domain)?;

            let mut endpoints: Vec<&RelayDirectoryEndpoint> = candidate.endpoints.iter().collect();
            endpoints.sort_by(|left, right| compare_endpoints(left, right));
            push_u32(&mut encoded, endpoints.len() as u32);
            for endpoint in endpoints {
                encoded.push(endpoint.transport.wire_code());
                push_string(&mut encoded, "endpoint_host", &endpoint.host)?;
                push_u16(&mut encoded, endpoint.port);
            }

            push_u32(&mut encoded, candidate.capabilities);
            encoded.push(candidate.load_class);
            push_string(
                &mut encoded,
                "selection_reason",
                &candidate.selection_reason,
            )?;
            push_string(
                &mut encoded,
                "reservation_id",
                &candidate.reservation.reservation_id,
            )?;
            push_u64(&mut encoded, candidate.reservation.expires_at_ms);
        }

        if encoded.len() > MAX_CANONICAL_BYTES {
            return Err(RelayDirectoryError::CanonicalEncodingTooLarge);
        }
        Ok(encoded)
    }

    fn validate_contract(&self) -> Result<(), RelayDirectoryError> {
        if self.format_version != RELAY_DIRECTORY_FORMAT_VERSION {
            return Err(RelayDirectoryError::UnsupportedFormatVersion {
                version: self.format_version,
            });
        }
        if self.policy_revision == 0 {
            return Err(RelayDirectoryError::InvalidPolicyRevision);
        }
        validate_string("directory_id", &self.directory_id)?;
        validate_string("session_id", &self.session_id)?;
        validate_string("intended_peer_digest", &self.intended_peer_digest)?;
        if self.issued_at_ms >= self.expires_at_ms {
            return Err(RelayDirectoryError::InvalidValidityWindow);
        }
        if self.candidates.is_empty() {
            return Err(RelayDirectoryError::EmptyCandidates);
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(RelayDirectoryError::TooManyCandidates {
                max: MAX_CANDIDATES,
            });
        }

        validate_candidate_order(&self.candidates)?;
        let mut reservation_ids = BTreeSet::new();
        for candidate in &self.candidates {
            validate_string("node_id", &candidate.node_id)?;
            validate_string("region", &candidate.region)?;
            validate_string("failure_domain", &candidate.failure_domain)?;
            validate_string("selection_reason", &candidate.selection_reason)?;
            validate_string("reservation_id", &candidate.reservation.reservation_id)?;
            if !reservation_ids.insert(candidate.reservation.reservation_id.as_bytes()) {
                return Err(RelayDirectoryError::DuplicateReservation);
            }
            if candidate.load_class > 3 {
                return Err(RelayDirectoryError::InvalidLoadClass);
            }
            if candidate.reservation.expires_at_ms <= self.issued_at_ms
                || candidate.reservation.expires_at_ms > self.expires_at_ms
            {
                return Err(RelayDirectoryError::InvalidReservation);
            }
            if candidate.endpoints.is_empty() {
                return Err(RelayDirectoryError::EmptyEndpoints);
            }
            if candidate.endpoints.len() > MAX_ENDPOINTS_PER_CANDIDATE {
                return Err(RelayDirectoryError::TooManyEndpoints {
                    max: MAX_ENDPOINTS_PER_CANDIDATE,
                });
            }
            validate_endpoint_order(&candidate.endpoints)?;
            for endpoint in &candidate.endpoints {
                validate_string("endpoint_host", &endpoint.host)?;
                if endpoint.port == 0 {
                    return Err(RelayDirectoryError::EmptyField {
                        field: "endpoint_port",
                    });
                }
            }
        }
        Ok(())
    }
}

impl SignedRelayDirectory {
    /// Parse untrusted JSON only after applying the total transport size cap.
    ///
    /// Public directory types intentionally do not implement `Deserialize`, so
    /// consumers cannot bypass this bounded entry point with `serde_json`.
    ///
    /// ```compile_fail
    /// use mrd_relay_control::SignedRelayDirectory;
    /// let _: SignedRelayDirectory = serde_json::from_str("{}").unwrap();
    /// ```
    pub fn from_json(input: &[u8]) -> Result<Self, RelayDirectoryError> {
        if input.len() > MAX_RELAY_DIRECTORY_JSON_BYTES {
            return Err(RelayDirectoryError::JsonTooLarge {
                max: MAX_RELAY_DIRECTORY_JSON_BYTES,
            });
        }
        let raw: RawSignedRelayDirectory =
            serde_json::from_slice(input).map_err(|_| RelayDirectoryError::InvalidJson)?;
        let signed = Self::from(raw);
        signed.payload.canonical_signing_bytes()?;
        validate_string("signing_key_id", &signed.signing_key_id)?;
        decode_signature(&signed.signature_b64)?;
        Ok(signed)
    }

    /// Verify signature, structural invariants, session binding, current time,
    /// and reservation validity.
    ///
    /// This required compatibility entry point deliberately does not compare
    /// policy revision or intended-peer digest against caller context. Use
    /// [`Self::verify_for_context`] before consuming relay candidates.
    pub fn verify(
        &self,
        trusted_keys: &BTreeMap<String, Vec<u8>>,
        expected_session_id: &str,
        now_ms: u64,
    ) -> Result<VerifiedRelayDirectory, RelayDirectoryError> {
        let canonical_signing_bytes = self.payload.canonical_signing_bytes()?;
        validate_string("signing_key_id", &self.signing_key_id)?;
        if self.payload.session_id != expected_session_id {
            return Err(RelayDirectoryError::SessionMismatch);
        }
        if now_ms < self.payload.issued_at_ms {
            return Err(RelayDirectoryError::NotYetValid);
        }
        if now_ms >= self.payload.expires_at_ms {
            return Err(RelayDirectoryError::Expired);
        }
        if self
            .payload
            .candidates
            .iter()
            .any(|candidate| now_ms >= candidate.reservation.expires_at_ms)
        {
            return Err(RelayDirectoryError::ReservationExpired);
        }

        let trusted_key = trusted_keys
            .get(&self.signing_key_id)
            .ok_or(RelayDirectoryError::UntrustedSigningKey)?;
        let key_bytes: [u8; 32] = trusted_key
            .as_slice()
            .try_into()
            .map_err(|_| RelayDirectoryError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| RelayDirectoryError::InvalidPublicKey)?;

        let signature = decode_signature(&self.signature_b64)?;
        verifying_key
            .verify_strict(&canonical_signing_bytes, &signature)
            .map_err(|_| RelayDirectoryError::InvalidSignature)?;

        Ok(VerifiedRelayDirectory {
            payload: self.payload.clone(),
            canonical_signing_bytes,
        })
    }

    /// Perform basic verification and bind the directory to the caller's exact
    /// selection-policy revision and intended-peer digest.
    pub fn verify_for_context(
        &self,
        trusted_keys: &BTreeMap<String, Vec<u8>>,
        expected_session_id: &str,
        expected_policy_revision: u64,
        expected_peer_digest: &str,
        now_ms: u64,
    ) -> Result<ContextVerifiedRelayDirectory, RelayDirectoryError> {
        let verified = self.verify(trusted_keys, expected_session_id, now_ms)?;
        if verified.payload.policy_revision != expected_policy_revision {
            return Err(RelayDirectoryError::PolicyRevisionMismatch {
                expected: expected_policy_revision,
                actual: verified.payload.policy_revision,
            });
        }
        if verified.payload.intended_peer_digest != expected_peer_digest {
            return Err(RelayDirectoryError::PeerBindingMismatch);
        }
        Ok(ContextVerifiedRelayDirectory { verified })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignedRelayDirectory {
    payload: RawRelayDirectoryPayload,
    signing_key_id: String,
    signature_b64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayDirectoryPayload {
    format_version: u16,
    policy_revision: u64,
    directory_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    session_id: String,
    intended_peer_digest: String,
    candidates: Vec<RawRelayDirectoryCandidate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayDirectoryCandidate {
    node_id: String,
    region: String,
    failure_domain: String,
    endpoints: Vec<RawRelayDirectoryEndpoint>,
    capabilities: u32,
    load_class: u8,
    selection_reason: String,
    reservation: RawRelayReservation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayDirectoryEndpoint {
    transport: RawRelayDirectoryTransport,
    host: String,
    port: u16,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawRelayDirectoryTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayReservation {
    reservation_id: String,
    expires_at_ms: u64,
}

impl From<RawSignedRelayDirectory> for SignedRelayDirectory {
    fn from(raw: RawSignedRelayDirectory) -> Self {
        Self {
            payload: raw.payload.into(),
            signing_key_id: raw.signing_key_id,
            signature_b64: raw.signature_b64,
        }
    }
}

impl From<RawRelayDirectoryPayload> for RelayDirectoryPayload {
    fn from(raw: RawRelayDirectoryPayload) -> Self {
        Self {
            format_version: raw.format_version,
            policy_revision: raw.policy_revision,
            directory_id: raw.directory_id,
            issued_at_ms: raw.issued_at_ms,
            expires_at_ms: raw.expires_at_ms,
            session_id: raw.session_id,
            intended_peer_digest: raw.intended_peer_digest,
            candidates: raw.candidates.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RawRelayDirectoryCandidate> for RelayDirectoryCandidate {
    fn from(raw: RawRelayDirectoryCandidate) -> Self {
        Self {
            node_id: raw.node_id,
            region: raw.region,
            failure_domain: raw.failure_domain,
            endpoints: raw.endpoints.into_iter().map(Into::into).collect(),
            capabilities: raw.capabilities,
            load_class: raw.load_class,
            selection_reason: raw.selection_reason,
            reservation: raw.reservation.into(),
        }
    }
}

impl From<RawRelayDirectoryEndpoint> for RelayDirectoryEndpoint {
    fn from(raw: RawRelayDirectoryEndpoint) -> Self {
        Self {
            transport: raw.transport.into(),
            host: raw.host,
            port: raw.port,
        }
    }
}

impl From<RawRelayDirectoryTransport> for RelayDirectoryTransport {
    fn from(raw: RawRelayDirectoryTransport) -> Self {
        match raw {
            RawRelayDirectoryTransport::Udp => Self::Udp,
            RawRelayDirectoryTransport::Tcp => Self::Tcp,
            RawRelayDirectoryTransport::Tls => Self::Tls,
        }
    }
}

impl From<RawRelayReservation> for RelayReservation {
    fn from(raw: RawRelayReservation) -> Self {
        Self {
            reservation_id: raw.reservation_id,
            expires_at_ms: raw.expires_at_ms,
        }
    }
}

fn validate_candidate_order(
    candidates: &[RelayDirectoryCandidate],
) -> Result<(), RelayDirectoryError> {
    let mut node_ids = BTreeSet::new();
    for candidate in candidates {
        if !node_ids.insert(candidate.node_id.as_bytes()) {
            return Err(RelayDirectoryError::DuplicateNode);
        }
    }
    for adjacent in candidates.windows(2) {
        match adjacent[0]
            .node_id
            .as_bytes()
            .cmp(adjacent[1].node_id.as_bytes())
        {
            Ordering::Less => {}
            Ordering::Equal => return Err(RelayDirectoryError::DuplicateNode),
            Ordering::Greater => return Err(RelayDirectoryError::NonCanonicalCandidateOrder),
        }
    }
    Ok(())
}

fn validate_endpoint_order(
    endpoints: &[RelayDirectoryEndpoint],
) -> Result<(), RelayDirectoryError> {
    let mut endpoint_keys = BTreeSet::new();
    for endpoint in endpoints {
        let key = (endpoint.transport, endpoint.host.as_bytes(), endpoint.port);
        if !endpoint_keys.insert(key) {
            return Err(RelayDirectoryError::DuplicateEndpoint);
        }
    }
    for adjacent in endpoints.windows(2) {
        match compare_endpoints(&adjacent[0], &adjacent[1]) {
            Ordering::Less => {}
            Ordering::Equal => return Err(RelayDirectoryError::DuplicateEndpoint),
            Ordering::Greater => return Err(RelayDirectoryError::NonCanonicalEndpointOrder),
        }
    }
    Ok(())
}

fn compare_endpoints(left: &RelayDirectoryEndpoint, right: &RelayDirectoryEndpoint) -> Ordering {
    left.transport
        .wire_code()
        .cmp(&right.transport.wire_code())
        .then_with(|| left.host.as_bytes().cmp(right.host.as_bytes()))
        .then_with(|| left.port.cmp(&right.port))
}

fn validate_string(field: &'static str, value: &str) -> Result<(), RelayDirectoryError> {
    if value.is_empty() {
        return Err(RelayDirectoryError::EmptyField { field });
    }
    if value.len() > MAX_STRING_BYTES {
        return Err(RelayDirectoryError::StringTooLong {
            field,
            max: MAX_STRING_BYTES,
        });
    }
    Ok(())
}

fn decode_signature(signature_b64: &str) -> Result<Signature, RelayDirectoryError> {
    if signature_b64.is_empty() || signature_b64.len() > 128 {
        return Err(RelayDirectoryError::InvalidSignatureEncoding);
    }
    let signature_bytes = STANDARD
        .decode(signature_b64.as_bytes())
        .map_err(|_| RelayDirectoryError::InvalidSignatureEncoding)?;
    if STANDARD.encode(&signature_bytes) != signature_b64 {
        return Err(RelayDirectoryError::InvalidSignatureEncoding);
    }
    Signature::from_slice(&signature_bytes)
        .map_err(|_| RelayDirectoryError::InvalidSignatureEncoding)
}

fn push_string(
    encoded: &mut Vec<u8>,
    field: &'static str,
    value: &str,
) -> Result<(), RelayDirectoryError> {
    validate_string(field, value)?;
    push_u32(encoded, value.len() as u32);
    encoded.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(encoded: &mut Vec<u8>, value: u16) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(encoded: &mut Vec<u8>, value: u32) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_be_bytes());
}
