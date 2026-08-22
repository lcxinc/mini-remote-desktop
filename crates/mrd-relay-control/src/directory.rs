//! Versioned, session-bound relay-directory contract.
//!
//! JSON is only a transport representation. Signatures always cover the
//! canonical binary representation produced by [`RelayDirectoryPayload::canonical_signing_bytes`].

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

const MAX_CANDIDATES: usize = 8;
const MAX_ENDPOINTS_PER_CANDIDATE: usize = 4;
const MAX_STRING_BYTES: usize = 256;
const MAX_CANONICAL_BYTES: usize = 16 * 1024;

/// TURN transport advertised by a signed relay directory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayDirectoryEndpoint {
    pub transport: RelayDirectoryTransport,
    pub host: String,
    pub port: u16,
}

/// Capacity reservation attached to one relay candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayReservation {
    pub reservation_id: String,
    pub expires_at_ms: u64,
}

/// A signed candidate, including selection explanation and reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayDirectory {
    pub payload: RelayDirectoryPayload,
    pub signing_key_id: String,
    pub signature_b64: String,
}

/// A directory whose signature, bindings, time window, and reservations passed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRelayDirectory {
    payload: RelayDirectoryPayload,
    canonical_signing_bytes: Vec<u8>,
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
        for candidate in &self.candidates {
            validate_string("node_id", &candidate.node_id)?;
            validate_string("region", &candidate.region)?;
            validate_string("failure_domain", &candidate.failure_domain)?;
            validate_string("selection_reason", &candidate.selection_reason)?;
            validate_string("reservation_id", &candidate.reservation.reservation_id)?;
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

        if self.signature_b64.len() > 128 {
            return Err(RelayDirectoryError::InvalidSignatureEncoding);
        }
        let signature_bytes = STANDARD
            .decode(self.signature_b64.as_bytes())
            .map_err(|_| RelayDirectoryError::InvalidSignatureEncoding)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| RelayDirectoryError::InvalidSignatureEncoding)?;
        verifying_key
            .verify_strict(&canonical_signing_bytes, &signature)
            .map_err(|_| RelayDirectoryError::InvalidSignature)?;

        Ok(VerifiedRelayDirectory {
            payload: self.payload.clone(),
            canonical_signing_bytes,
        })
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
