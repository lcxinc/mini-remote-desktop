//! Versioned, end-to-end authenticated signaling messages.

use crate::initial_v3::{
    SessionGrantV3, SessionIntentV3, WebRtcAnswerV3, WebRtcCandidateV3, WebRtcOfferV3,
};
use mrd_identity::{public_key_id, verify_context_bytes, DeviceIdentity};
use mrd_proto::{BackendRole, DeviceId, SessionId};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use thiserror::Error;

pub const SIGNAL_PROTOCOL_V2: u16 = 2;
pub const SIGNAL_PROTOCOL_V3: u16 = 3;
pub const SIGNAL_PROTOCOL_VERSION: u16 = SIGNAL_PROTOCOL_V2;
pub const SIGNAL_MAX_MESSAGE_LIFETIME_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalEnvelope {
    pub version: u16,
    pub message: AuthenticatedSignalMessage,
}

impl SignalEnvelope {
    pub fn new(message: AuthenticatedSignalMessage) -> Self {
        Self {
            version: message.required_version(),
            message,
        }
    }

    pub fn validate_version(&self) -> Result<(), SignalProtocolError> {
        if self.message.is_legacy_v2_initial() || self.version != self.message.required_version() {
            return Err(SignalProtocolError::UnsupportedVersion);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for SignalEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawEnvelope {
            version: u16,
            message: AuthenticatedSignalMessage,
        }

        let raw = RawEnvelope::deserialize(deserializer)?;
        let envelope = Self {
            version: raw.version,
            message: raw.message,
        };
        envelope
            .validate_version()
            .map_err(|error| D::Error::custom(error.to_string()))?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum AuthenticatedSignalMessage {
    ServerChallenge(ServerChallenge),
    Register(AuthenticatedRegister),
    Registered(Registered),
    PresenceHeartbeat(PresenceHeartbeat),
    SessionIntent(SessionIntent),
    SessionGrant(SessionGrant),
    SessionDeny(SessionDeny),
    WebrtcOffer(WebRtcOffer),
    WebrtcAnswer(WebRtcAnswer),
    WebrtcCandidate(WebRtcCandidate),
    SessionIntentV3(SessionIntentV3),
    SessionGrantV3(SessionGrantV3),
    WebrtcOfferV3(WebRtcOfferV3),
    WebrtcAnswerV3(WebRtcAnswerV3),
    WebrtcCandidateV3(WebRtcCandidateV3),
    RelayMigrationOffer(RelayMigrationOffer),
    RelayMigrationAnswer(RelayMigrationAnswer),
    RelayMigrationCandidate(RelayMigrationCandidate),
    SessionClose(SessionClose),
    ReconnectRequest(ReconnectRequest),
    ReconnectGrant(ReconnectGrant),
    ProtocolError(SignalErrorMessage),
}

impl AuthenticatedSignalMessage {
    pub fn required_version(&self) -> u16 {
        match self {
            Self::SessionIntentV3(_)
            | Self::SessionGrantV3(_)
            | Self::WebrtcOfferV3(_)
            | Self::WebrtcAnswerV3(_)
            | Self::WebrtcCandidateV3(_) => SIGNAL_PROTOCOL_V3,
            _ => SIGNAL_PROTOCOL_V2,
        }
    }

    fn is_legacy_v2_initial(&self) -> bool {
        matches!(
            self,
            Self::SessionIntent(_)
                | Self::SessionGrant(_)
                | Self::WebrtcOffer(_)
                | Self::WebrtcAnswer(_)
                | Self::WebrtcCandidate(_)
        )
    }

    pub fn verify_for(
        &self,
        expected_peer: &DeviceId,
        now_ms: u64,
        replay: &mut SignalReplayGuard,
    ) -> Result<VerifiedSignalMetadata, SignalProtocolError> {
        macro_rules! verify {
            ($message:expr) => {{
                $message.verify_for(expected_peer, now_ms, replay)?;
                Ok(VerifiedSignalMetadata::from_claims(
                    &$message.payload.claims,
                ))
            }};
        }
        match self {
            Self::Register(message) => verify!(message),
            Self::Registered(message) => verify!(message),
            Self::PresenceHeartbeat(message) => verify!(message),
            Self::SessionIntent(_)
            | Self::SessionGrant(_)
            | Self::WebrtcOffer(_)
            | Self::WebrtcAnswer(_)
            | Self::WebrtcCandidate(_) => Err(SignalProtocolError::UnsupportedVersion),
            Self::SessionIntentV3(message) => verify!(message),
            Self::SessionGrantV3(message) => verify!(message),
            Self::WebrtcOfferV3(message) => verify!(message),
            Self::WebrtcAnswerV3(message) => verify!(message),
            Self::WebrtcCandidateV3(message) => verify!(message),
            Self::SessionDeny(message) => verify!(message),
            Self::RelayMigrationOffer(message) => verify!(message),
            Self::RelayMigrationAnswer(message) => verify!(message),
            Self::RelayMigrationCandidate(message) => verify!(message),
            Self::SessionClose(message) => verify!(message),
            Self::ReconnectRequest(message) => verify!(message),
            Self::ReconnectGrant(message) => verify!(message),
            Self::ServerChallenge(_) | Self::ProtocolError(_) => {
                Err(SignalProtocolError::UnsignedMessage)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthClaims {
    pub issuer_device_id: DeviceId,
    pub issuer_key_id: String,
    pub intended_peer_device_id: DeviceId,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub counter: u64,
    pub nonce: [u8; 16],
}

impl AuthClaims {
    fn validate_structure(&self, signer_public_key: &[u8]) -> Result<(), SignalProtocolError> {
        validate_identifier(&self.issuer_device_id.0)?;
        validate_identifier(&self.intended_peer_device_id.0)?;
        if self.issuer_key_id != public_key_id(signer_public_key) {
            return Err(SignalProtocolError::SignerKeyMismatch);
        }
        if self.counter == 0 || self.nonce == [0; 16] || self.issued_at_ms >= self.expires_at_ms {
            return Err(SignalProtocolError::Malformed);
        }
        if self.expires_at_ms - self.issued_at_ms > SIGNAL_MAX_MESSAGE_LIFETIME_MS {
            return Err(SignalProtocolError::LifetimeTooLong);
        }
        Ok(())
    }

    fn validate(
        &self,
        signer_public_key: &[u8],
        expected_peer: &DeviceId,
        now_ms: u64,
    ) -> Result<(), SignalProtocolError> {
        self.validate_structure(signer_public_key)?;
        if &self.intended_peer_device_id != expected_peer {
            return Err(SignalProtocolError::WrongIntendedPeer);
        }
        if now_ms < self.issued_at_ms {
            return Err(SignalProtocolError::NotYetValid);
        }
        if now_ms >= self.expires_at_ms {
            return Err(SignalProtocolError::Expired);
        }
        Ok(())
    }
}

pub trait AuthenticatedPayload: Serialize {
    const SIGNATURE_CONTEXT: &'static str;
    fn claims(&self) -> &AuthClaims;
    fn validate_payload(&self) -> Result<(), SignalProtocolError>;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSignal<T> {
    pub payload: T,
    pub signer_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl<T> fmt::Debug for SignedSignal<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedSignal")
            .field("payload", &"REDACTED")
            .field("signer_public_key_len", &self.signer_public_key.len())
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

impl<T> SignedSignal<T>
where
    T: AuthenticatedPayload,
{
    pub fn sign(identity: &DeviceIdentity, payload: T) -> Result<Self, SignalProtocolError> {
        payload.claims().validate_structure(identity.public_key())?;
        payload.validate_payload()?;
        let canonical = serde_json::to_vec(&payload).map_err(|_| SignalProtocolError::Malformed)?;
        let signature = identity
            .sign_context_bytes(T::SIGNATURE_CONTEXT, &canonical)
            .map_err(|_| SignalProtocolError::InvalidSignature)?;
        Ok(Self {
            payload,
            signer_public_key: identity.public_key().to_vec(),
            signature,
        })
    }

    pub fn verify_for(
        &self,
        expected_peer: &DeviceId,
        now_ms: u64,
        replay: &mut SignalReplayGuard,
    ) -> Result<VerifiedSignalMetadata, SignalProtocolError> {
        if self.signer_public_key.len() != 32 || self.signature.len() != 64 {
            return Err(SignalProtocolError::InvalidSignature);
        }
        self.payload
            .claims()
            .validate(&self.signer_public_key, expected_peer, now_ms)?;
        self.payload.validate_payload()?;
        let canonical =
            serde_json::to_vec(&self.payload).map_err(|_| SignalProtocolError::Malformed)?;
        verify_context_bytes(
            &self.signer_public_key,
            T::SIGNATURE_CONTEXT,
            &canonical,
            &self.signature,
        )
        .map_err(|_| SignalProtocolError::InvalidSignature)?;
        replay.accept(
            &self.payload.claims().issuer_key_id,
            self.payload.claims().counter,
            self.payload.claims().nonce,
        )?;
        Ok(VerifiedSignalMetadata::from_claims(self.payload.claims()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignalMetadata {
    pub issuer_device_id: DeviceId,
    pub issuer_key_id: String,
    pub intended_peer_device_id: DeviceId,
    pub counter: u64,
    pub nonce: [u8; 16],
}

impl VerifiedSignalMetadata {
    fn from_claims(claims: &AuthClaims) -> Self {
        Self {
            issuer_device_id: claims.issuer_device_id.clone(),
            issuer_key_id: claims.issuer_key_id.clone(),
            intended_peer_device_id: claims.intended_peer_device_id.clone(),
            counter: claims.counter,
            nonce: claims.nonce,
        }
    }
}

#[derive(Debug)]
pub struct SignalReplayGuard {
    max_signers: usize,
    nonce_capacity: usize,
    signers: HashMap<String, SignerReplayState>,
}

#[derive(Debug, Default)]
struct SignerReplayState {
    highest_counter: Option<u64>,
    nonce_order: VecDeque<[u8; 16]>,
    nonces: HashSet<[u8; 16]>,
}

impl SignalReplayGuard {
    pub fn new(max_signers: usize, nonce_capacity: usize) -> Self {
        Self {
            max_signers: max_signers.max(1),
            nonce_capacity: nonce_capacity.max(1),
            signers: HashMap::new(),
        }
    }

    pub fn accept(
        &mut self,
        issuer_key_id: &str,
        counter: u64,
        nonce: [u8; 16],
    ) -> Result<(), SignalProtocolError> {
        if !self.signers.contains_key(issuer_key_id) && self.signers.len() >= self.max_signers {
            return Err(SignalProtocolError::ReplayCapacity);
        }
        let state = self.signers.entry(issuer_key_id.to_owned()).or_default();
        if state.nonces.contains(&nonce) {
            return Err(SignalProtocolError::RepeatedNonce);
        }
        if state
            .highest_counter
            .is_some_and(|highest| counter <= highest)
        {
            return Err(SignalProtocolError::CounterRollback);
        }
        state.highest_counter = Some(counter);
        state.nonces.insert(nonce);
        state.nonce_order.push_back(nonce);
        while state.nonce_order.len() > self.nonce_capacity {
            if let Some(expired) = state.nonce_order.pop_front() {
                state.nonces.remove(&expired);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SignalProtocolError {
    #[error("signaling protocol version is unsupported")]
    UnsupportedVersion,
    #[error("signaling message is malformed")]
    Malformed,
    #[error("signaling message targets another peer")]
    WrongIntendedPeer,
    #[error("signaling signer key does not match signed claims")]
    SignerKeyMismatch,
    #[error("signaling message signature is invalid")]
    InvalidSignature,
    #[error("signaling message is not yet valid")]
    NotYetValid,
    #[error("signaling message expired")]
    Expired,
    #[error("signaling message lifetime exceeds the protocol maximum")]
    LifetimeTooLong,
    #[error("signaling message nonce was already accepted")]
    RepeatedNonce,
    #[error("signaling message counter did not increase")]
    CounterRollback,
    #[error("signaling replay guard capacity is exhausted")]
    ReplayCapacity,
    #[error("signaling message type is not authenticated")]
    UnsignedMessage,
}

impl SignalProtocolError {
    pub fn reason_code(&self) -> ProtocolReasonCode {
        match self {
            Self::UnsupportedVersion => ProtocolReasonCode::UnsupportedVersion,
            Self::Malformed | Self::LifetimeTooLong => ProtocolReasonCode::Malformed,
            Self::WrongIntendedPeer => ProtocolReasonCode::WrongPeer,
            Self::SignerKeyMismatch | Self::InvalidSignature | Self::UnsignedMessage => {
                ProtocolReasonCode::AuthenticationFailed
            }
            Self::NotYetValid | Self::Expired => ProtocolReasonCode::Expired,
            Self::RepeatedNonce | Self::CounterRollback | Self::ReplayCapacity => {
                ProtocolReasonCode::ReplayRejected
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolReasonCode {
    UnsupportedVersion,
    Malformed,
    AuthenticationFailed,
    WrongPeer,
    Expired,
    ReplayRejected,
    UnauthorizedRoute,
    RateLimited,
    UnknownSession,
    Conflict,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalErrorMessage {
    pub reason: ProtocolReasonCode,
    pub correlation_id: Option<[u8; 16]>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerChallenge {
    pub challenge_id: [u8; 16],
    pub challenge_nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

macro_rules! signed_payload {
    ($type:ty, $context:literal, $this:ident, $validate:block) => {
        impl AuthenticatedPayload for $type {
            const SIGNATURE_CONTEXT: &'static str = $context;
            fn claims(&self) -> &AuthClaims {
                &self.claims
            }
            fn validate_payload(&self) -> Result<(), SignalProtocolError> {
                let $this = self;
                $validate
            }
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisterPayload {
    pub claims: AuthClaims,
    pub role: BackendRole,
    pub device_name: String,
    pub backend_device_token: String,
    pub challenge_id: [u8; 16],
    pub challenge_nonce: [u8; 32],
}
signed_payload!(RegisterPayload, "MRD_SIGNAL_REGISTER_V2", message, {
    {
        validate_text(&message.device_name, 1, 128)?;
        validate_text(&message.backend_device_token, 1, 4_096)?;
        if message.challenge_id == [0; 16] || message.challenge_nonce == [0; 32] {
            return Err(SignalProtocolError::Malformed);
        }
        Ok(())
    }
});
pub type AuthenticatedRegister = SignedSignal<RegisterPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredPayload {
    pub claims: AuthClaims,
    pub registered_device_id: DeviceId,
    pub connection_id: [u8; 16],
    pub heartbeat_interval_ms: u32,
}
signed_payload!(RegisteredPayload, "MRD_SIGNAL_REGISTERED_V2", message, {
    {
        validate_identifier(&message.registered_device_id.0)?;
        if message.registered_device_id != message.claims.intended_peer_device_id
            || message.connection_id == [0; 16]
            || message.heartbeat_interval_ms == 0
        {
            return Err(SignalProtocolError::Malformed);
        }
        Ok(())
    }
});
pub type Registered = SignedSignal<RegisteredPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PresenceHeartbeatPayload {
    pub claims: AuthClaims,
    pub connection_id: [u8; 16],
    pub observed_at_ms: u64,
}
signed_payload!(
    PresenceHeartbeatPayload,
    "MRD_SIGNAL_PRESENCE_V2",
    message,
    {
        {
            if message.connection_id == [0; 16] || message.observed_at_ms == 0 {
                return Err(SignalProtocolError::Malformed);
            }
            Ok(())
        }
    }
);
pub type PresenceHeartbeat = SignedSignal<PresenceHeartbeatPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionIntentPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub idempotency_key: [u8; 16],
    pub target_device_id: DeviceId,
    pub requested_transport: String,
}
pub type SessionIntent = SignedSignal<SessionIntentPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub controller_device_id: DeviceId,
    pub accepted_transport: String,
    pub accepted_candidate_fingerprints: BTreeSet<String>,
}
pub type SessionGrant = SignedSignal<SessionGrantPayload>;

impl SessionGrantPayload {
    /// Candidates are routed separately, but only fingerprints committed by the grant are valid.
    pub fn accepts_candidate(&self, candidate: &WebRtcCandidatePayload) -> bool {
        self.session_id == candidate.session_id
            && self
                .accepted_candidate_fingerprints
                .contains(&candidate.candidate_fingerprint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionDenyPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub controller_device_id: DeviceId,
    pub reason: ProtocolReasonCode,
}
signed_payload!(SessionDenyPayload, "MRD_SIGNAL_SESSION_DENY_V2", message, {
    {
        validate_identifier(&message.session_id.0)?;
        validate_identifier(&message.controller_device_id.0)?;
        if message.controller_device_id != message.claims.intended_peer_device_id {
            return Err(SignalProtocolError::WrongIntendedPeer);
        }
        Ok(())
    }
});
pub type SessionDeny = SignedSignal<SessionDenyPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebRtcOfferPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub sdp: String,
    pub candidate_fingerprints: BTreeSet<String>,
}
pub type WebRtcOffer = SignedSignal<WebRtcOfferPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebRtcAnswerPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub sdp: String,
    pub candidate_fingerprints: BTreeSet<String>,
}
pub type WebRtcAnswer = SignedSignal<WebRtcAnswerPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebRtcCandidatePayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub candidate_fingerprint: String,
}
pub type WebRtcCandidate = SignedSignal<WebRtcCandidatePayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMigrationOfferPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub migration_generation: u64,
    pub directory_id: String,
    pub node_id: String,
    pub sdp: String,
    pub restart_route_token: String,
    pub candidate_fingerprints: BTreeSet<String>,
}
signed_payload!(
    RelayMigrationOfferPayload,
    "MRD_SIGNAL_RELAY_MIGRATION_OFFER_V2",
    message,
    {
        {
            validate_migration_description(
                &message.session_id,
                message.migration_generation,
                &message.directory_id,
                &message.node_id,
                &message.sdp,
                &message.restart_route_token,
                &message.candidate_fingerprints,
            )
        }
    }
);
pub type RelayMigrationOffer = SignedSignal<RelayMigrationOfferPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMigrationAnswerPayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub migration_generation: u64,
    pub directory_id: String,
    pub node_id: String,
    pub sdp: String,
    pub restart_route_token: String,
    pub candidate_fingerprints: BTreeSet<String>,
}
signed_payload!(
    RelayMigrationAnswerPayload,
    "MRD_SIGNAL_RELAY_MIGRATION_ANSWER_V2",
    message,
    {
        {
            validate_migration_description(
                &message.session_id,
                message.migration_generation,
                &message.directory_id,
                &message.node_id,
                &message.sdp,
                &message.restart_route_token,
                &message.candidate_fingerprints,
            )
        }
    }
);
pub type RelayMigrationAnswer = SignedSignal<RelayMigrationAnswerPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayMigrationCandidatePayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub migration_generation: u64,
    pub directory_id: String,
    pub node_id: String,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
    pub restart_route_token: String,
    pub candidate_fingerprint: String,
}
signed_payload!(
    RelayMigrationCandidatePayload,
    "MRD_SIGNAL_RELAY_MIGRATION_CANDIDATE_V2",
    message,
    {
        {
            validate_migration_binding(
                &message.session_id,
                message.migration_generation,
                &message.directory_id,
                &message.node_id,
            )?;
            validate_text(&message.candidate, 1, 8_192)?;
            if let Some(mid) = &message.sdp_mid {
                validate_text(mid, 1, 128)?;
            }
            if let Some(username_fragment) = &message.username_fragment {
                validate_text(username_fragment, 1, 256)?;
            }
            validate_restart_route_token(&message.restart_route_token)?;
            validate_fingerprint(&message.candidate_fingerprint)?;
            if relay_candidate_fingerprint(
                &message.session_id,
                message.migration_generation,
                &message.candidate,
                message.sdp_mid.as_deref(),
                message.sdp_mline_index,
                message.username_fragment.as_deref(),
                &message.restart_route_token,
            ) != message.candidate_fingerprint
            {
                return Err(SignalProtocolError::Malformed);
            }
            Ok(())
        }
    }
);
pub type RelayMigrationCandidate = SignedSignal<RelayMigrationCandidatePayload>;

fn validate_migration_description(
    session_id: &SessionId,
    migration_generation: u64,
    directory_id: &str,
    node_id: &str,
    sdp: &str,
    restart_route_token: &str,
    candidate_fingerprints: &BTreeSet<String>,
) -> Result<(), SignalProtocolError> {
    validate_migration_binding(session_id, migration_generation, directory_id, node_id)?;
    validate_text(sdp, 1, 256 * 1_024)?;
    validate_restart_route_token(restart_route_token)?;
    if candidate_fingerprints.is_empty() || candidate_fingerprints.len() > 256 {
        return Err(SignalProtocolError::Malformed);
    }
    for fingerprint in candidate_fingerprints {
        validate_fingerprint(fingerprint)?;
    }
    Ok(())
}

fn validate_restart_route_token(value: &str) -> Result<(), SignalProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn relay_candidate_fingerprint(
    session_id: &SessionId,
    generation: u64,
    candidate: &str,
    sdp_mid: Option<&str>,
    sdp_mline_index: Option<u16>,
    username_fragment: Option<&str>,
    restart_route_token: &str,
) -> String {
    let generation = generation.to_be_bytes();
    let sdp_mline_index = sdp_mline_index.unwrap_or(u16::MAX).to_be_bytes();
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    for field in [
        b"MRD_RELAY_CANDIDATE_V1\0".as_slice(),
        session_id.0.as_bytes(),
        generation.as_slice(),
        candidate.as_bytes(),
        sdp_mid.unwrap_or_default().as_bytes(),
        sdp_mline_index.as_slice(),
        username_fragment.unwrap_or_default().as_bytes(),
        restart_route_token.as_bytes(),
    ] {
        context.update(&(field.len() as u64).to_be_bytes());
        context.update(field);
    }
    context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_migration_binding(
    session_id: &SessionId,
    migration_generation: u64,
    directory_id: &str,
    node_id: &str,
) -> Result<(), SignalProtocolError> {
    validate_identifier(&session_id.0)?;
    validate_identifier(directory_id)?;
    validate_identifier(node_id)?;
    if migration_generation == 0 {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionClosePayload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub reason: ProtocolReasonCode,
}
signed_payload!(
    SessionClosePayload,
    "MRD_SIGNAL_SESSION_CLOSE_V2",
    message,
    {
        {
            validate_identifier(&message.session_id.0)
        }
    }
);
pub type SessionClose = SignedSignal<SessionClosePayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconnectRequestPayload {
    pub claims: AuthClaims,
    pub previous_connection_id: [u8; 16],
}
signed_payload!(
    ReconnectRequestPayload,
    "MRD_SIGNAL_RECONNECT_REQUEST_V2",
    message,
    {
        {
            if message.previous_connection_id == [0; 16] {
                return Err(SignalProtocolError::Malformed);
            }
            Ok(())
        }
    }
);
pub type ReconnectRequest = SignedSignal<ReconnectRequestPayload>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconnectGrantPayload {
    pub claims: AuthClaims,
    pub new_connection_id: [u8; 16],
    pub resumable_sessions: Vec<SessionId>,
}
signed_payload!(
    ReconnectGrantPayload,
    "MRD_SIGNAL_RECONNECT_GRANT_V2",
    message,
    {
        {
            if message.new_connection_id == [0; 16] || message.resumable_sessions.len() > 128 {
                return Err(SignalProtocolError::Malformed);
            }
            let mut unique = HashSet::new();
            for session in &message.resumable_sessions {
                validate_identifier(&session.0)?;
                if !unique.insert(session.0.as_str()) {
                    return Err(SignalProtocolError::Malformed);
                }
            }
            Ok(())
        }
    }
);
pub type ReconnectGrant = SignedSignal<ReconnectGrantPayload>;

fn validate_identifier(value: &str) -> Result<(), SignalProtocolError> {
    validate_text(value, 1, 256)?;
    if value.chars().any(|character| character.is_control()) {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

fn validate_text(value: &str, minimum: usize, maximum: usize) -> Result<(), SignalProtocolError> {
    if value.len() < minimum || value.len() > maximum || value.contains('\0') {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), SignalProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}
