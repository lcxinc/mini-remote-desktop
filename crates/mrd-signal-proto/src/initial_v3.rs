//! Authenticated protocol-v3 messages for initial attended WAN relay sessions.

use crate::{
    AuthClaims, AuthenticatedPayload, AuthenticatedSignalMessage, SignalProtocolError, SignedSignal,
};
use mrd_proto::{DeviceId, SessionId};
use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_SCOPES: usize = 32;
const MAX_CANDIDATES: usize = 256;
const REQUEST_COMMITMENT_CONTEXT: &[u8] = b"MRD_WAN_SESSION_REQUEST_V3\0";
const INTENT_COMMITMENT_CONTEXT: &[u8] = b"MRD_SIGNAL_SESSION_INTENT_COMMITMENT_V3\0";
const GRANT_COMMITMENT_CONTEXT: &[u8] = b"MRD_SIGNAL_SESSION_GRANT_COMMITMENT_V3\0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WanAccessModeV3 {
    Attended,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WanRoutePolicyV3 {
    RelayOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcDescriptionRoleV3 {
    Offer,
    Answer,
}

impl WebRtcDescriptionRoleV3 {
    fn as_wire(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WanPermissionScopeV3 {
    #[serde(rename = "audio.listen")]
    AudioListen,
    #[serde(rename = "audio.talk")]
    AudioTalk,
    #[serde(rename = "clipboard.read")]
    ClipboardRead,
    #[serde(rename = "clipboard.write")]
    ClipboardWrite,
    #[serde(rename = "display.multi_view")]
    DisplayMultiView,
    #[serde(rename = "display.switch")]
    DisplaySwitch,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "input.keyboard")]
    InputKeyboard,
    #[serde(rename = "input.pointer")]
    InputPointer,
    #[serde(rename = "power.restart")]
    PowerRestart,
    #[serde(rename = "power.shutdown")]
    PowerShutdown,
    #[serde(rename = "privacy.blank_screen")]
    PrivacyBlankScreen,
    #[serde(rename = "privacy.block_local_input")]
    PrivacyBlockLocalInput,
    #[serde(rename = "screen.view")]
    ScreenView,
    #[serde(rename = "secure_desktop.control")]
    SecureDesktopControl,
    #[serde(rename = "secure_desktop.view")]
    SecureDesktopView,
    #[serde(rename = "terminal.open")]
    TerminalOpen,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WanMediaProfileV3 {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_mbps: u32,
    pub codec: String,
    pub codec_profile: Option<String>,
    pub bit_depth: Option<u8>,
    pub chroma_subsampling: Option<String>,
    pub pixel_format: Option<String>,
    pub hdr_enabled: Option<bool>,
    pub color_mode: Option<String>,
    pub color_pipeline: Option<String>,
}

impl WanMediaProfileV3 {
    fn validate(&self) -> Result<(), SignalProtocolError> {
        if self.width == 0
            || self.width > 16_384
            || self.height == 0
            || self.height > 16_384
            || self.fps == 0
            || self.fps > 240
            || self.bitrate_mbps == 0
            || self.bitrate_mbps > 1_000
        {
            return Err(SignalProtocolError::Malformed);
        }
        validate_normalized_token(&self.codec, 32)?;
        for value in [
            self.codec_profile.as_deref(),
            self.chroma_subsampling.as_deref(),
            self.pixel_format.as_deref(),
            self.color_mode.as_deref(),
            self.color_pipeline.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_normalized_token(value, 64)?;
        }
        if self
            .bit_depth
            .is_some_and(|value| value != 8 && value != 10)
        {
            return Err(SignalProtocolError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WanSessionRequestV3 {
    pub session_id: SessionId,
    pub idempotency_key: [u8; 16],
    pub controller_device_id: DeviceId,
    pub target_device_id: DeviceId,
    pub access_mode: WanAccessModeV3,
    pub requested_scopes: Vec<WanPermissionScopeV3>,
    pub requested_profile: Option<WanMediaProfileV3>,
    pub route_policy: WanRoutePolicyV3,
}

impl WanSessionRequestV3 {
    pub fn validate(&self) -> Result<(), SignalProtocolError> {
        validate_identifier(&self.session_id.0)?;
        validate_identifier(&self.controller_device_id.0)?;
        validate_identifier(&self.target_device_id.0)?;
        if self.idempotency_key == [0; 16]
            || self.controller_device_id == self.target_device_id
            || !is_strictly_sorted(&self.requested_scopes)
            || self.requested_scopes.is_empty()
            || self.requested_scopes.len() > MAX_SCOPES
        {
            return Err(SignalProtocolError::Malformed);
        }
        if let Some(profile) = &self.requested_profile {
            profile.validate()?;
        }
        Ok(())
    }

    /// Cross-language request commitment: context bytes followed by compact JSON bytes.
    pub fn commitment(&self) -> Result<String, SignalProtocolError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|_| SignalProtocolError::Malformed)?;
        Ok(digest_hex(&[REQUEST_COMMITMENT_CONTEXT, &canonical]))
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionIntentV3Payload {
    pub claims: AuthClaims,
    pub request: WanSessionRequestV3,
    pub request_commitment: String,
}

impl fmt::Debug for SessionIntentV3Payload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionIntentV3Payload")
            .field("session_id", &self.request.session_id)
            .field("controller_device_id", &self.request.controller_device_id)
            .field("target_device_id", &self.request.target_device_id)
            .field("body", &"REDACTED")
            .finish()
    }
}

impl AuthenticatedPayload for SessionIntentV3Payload {
    const SIGNATURE_CONTEXT: &'static str = "MRD_SIGNAL_SESSION_INTENT_V3";

    fn claims(&self) -> &AuthClaims {
        &self.claims
    }

    fn validate_payload(&self) -> Result<(), SignalProtocolError> {
        self.request.validate()?;
        validate_fingerprint(&self.request_commitment)?;
        if self.claims.issuer_device_id != self.request.controller_device_id
            || self.claims.intended_peer_device_id != self.request.target_device_id
            || self.request_commitment != self.request.commitment()?
        {
            return Err(SignalProtocolError::Malformed);
        }
        Ok(())
    }
}

pub type SessionIntentV3 = SignedSignal<SessionIntentV3Payload>;

impl SignedSignal<SessionIntentV3Payload> {
    pub fn commitment(&self) -> Result<String, SignalProtocolError> {
        signed_commitment(INTENT_COMMITMENT_CONTEXT, self)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantV3Payload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub controller_device_id: DeviceId,
    pub target_device_id: DeviceId,
    pub intent_commitment: String,
    pub approved_scopes: Vec<WanPermissionScopeV3>,
    pub approved_profile: Option<WanMediaProfileV3>,
    pub backend_policy_revision: u64,
    pub policy_expires_at_ms: u64,
    pub relay_generation: u64,
    pub relay_directory_id: String,
    pub primary_relay_node_id: String,
    pub route_policy: WanRoutePolicyV3,
}

impl fmt::Debug for SessionGrantV3Payload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionGrantV3Payload")
            .field("session_id", &self.session_id)
            .field("controller_device_id", &self.controller_device_id)
            .field("target_device_id", &self.target_device_id)
            .field("body", &"REDACTED")
            .finish()
    }
}

impl AuthenticatedPayload for SessionGrantV3Payload {
    const SIGNATURE_CONTEXT: &'static str = "MRD_SIGNAL_SESSION_GRANT_V3";

    fn claims(&self) -> &AuthClaims {
        &self.claims
    }

    fn validate_payload(&self) -> Result<(), SignalProtocolError> {
        validate_identifier(&self.session_id.0)?;
        validate_identifier(&self.controller_device_id.0)?;
        validate_identifier(&self.target_device_id.0)?;
        validate_identifier(&self.relay_directory_id)?;
        validate_identifier(&self.primary_relay_node_id)?;
        validate_fingerprint(&self.intent_commitment)?;
        if self.claims.issuer_device_id != self.target_device_id
            || self.claims.intended_peer_device_id != self.controller_device_id
            || self.controller_device_id == self.target_device_id
            || self.backend_policy_revision == 0
            || self.policy_expires_at_ms <= self.claims.issued_at_ms
            || self.relay_generation != 0
            || self.approved_scopes.is_empty()
            || self.approved_scopes.len() > MAX_SCOPES
            || !is_strictly_sorted(&self.approved_scopes)
        {
            return Err(SignalProtocolError::Malformed);
        }
        if let Some(profile) = &self.approved_profile {
            profile.validate()?;
        }
        Ok(())
    }
}

pub type SessionGrantV3 = SignedSignal<SessionGrantV3Payload>;

impl SignedSignal<SessionGrantV3Payload> {
    pub fn commitment(&self) -> Result<String, SignalProtocolError> {
        signed_commitment(GRANT_COMMITMENT_CONTEXT, self)
    }

    pub fn verify_intent(&self, intent: &SessionIntentV3) -> Result<(), SignalProtocolError> {
        self.payload.validate_payload()?;
        intent.payload.validate_payload()?;
        let request = &intent.payload.request;
        if self.payload.intent_commitment != intent.commitment()?
            || self.payload.session_id != request.session_id
            || self.payload.controller_device_id != request.controller_device_id
            || self.payload.target_device_id != request.target_device_id
            || self.payload.route_policy != request.route_policy
            || self
                .payload
                .approved_scopes
                .iter()
                .any(|scope| !request.requested_scopes.contains(scope))
            || !profile_within(
                self.payload.approved_profile.as_ref(),
                request.requested_profile.as_ref(),
            )
        {
            return Err(SignalProtocolError::Malformed);
        }
        Ok(())
    }
}

macro_rules! description_payload {
    ($name:ident, $signed:ident, $context:literal, $role:expr, $variant:ident) => {
        #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub claims: AuthClaims,
            pub session_id: SessionId,
            pub controller_device_id: DeviceId,
            pub target_device_id: DeviceId,
            pub grant_commitment: String,
            pub sdp: String,
            pub candidate_fingerprints: Vec<String>,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("session_id", &self.session_id)
                    .field("controller_device_id", &self.controller_device_id)
                    .field("target_device_id", &self.target_device_id)
                    .field("candidate_count", &self.candidate_fingerprints.len())
                    .field("body", &"REDACTED")
                    .finish()
            }
        }

        impl AuthenticatedPayload for $name {
            const SIGNATURE_CONTEXT: &'static str = $context;

            fn claims(&self) -> &AuthClaims {
                &self.claims
            }

            fn validate_payload(&self) -> Result<(), SignalProtocolError> {
                validate_description(
                    &self.claims,
                    &self.session_id,
                    &self.controller_device_id,
                    &self.target_device_id,
                    &self.grant_commitment,
                    &self.sdp,
                    &self.candidate_fingerprints,
                    $role,
                )
            }
        }

        pub type $signed = SignedSignal<$name>;

        impl SignedSignal<$name> {
            pub fn verify_grant(&self, grant: &SessionGrantV3) -> Result<(), SignalProtocolError> {
                verify_grant_binding(
                    &self.payload.session_id,
                    &self.payload.controller_device_id,
                    &self.payload.target_device_id,
                    &self.payload.grant_commitment,
                    grant,
                )
            }

            pub fn verify_candidate_manifest(
                &self,
                candidates: &[WebRtcCandidateV3Payload],
            ) -> Result<(), SignalProtocolError> {
                self.payload.validate_payload()?;
                verify_manifest(
                    &self.payload.session_id,
                    &self.payload.controller_device_id,
                    &self.payload.target_device_id,
                    &self.payload.grant_commitment,
                    $role,
                    &self.payload.candidate_fingerprints,
                    candidates,
                )
            }
        }

        impl From<$signed> for AuthenticatedSignalMessage {
            fn from(value: $signed) -> Self {
                AuthenticatedSignalMessage::$variant(value)
            }
        }
    };
}

description_payload!(
    WebRtcOfferV3Payload,
    WebRtcOfferV3,
    "MRD_SIGNAL_WEBRTC_OFFER_V3",
    WebRtcDescriptionRoleV3::Offer,
    WebrtcOfferV3
);
description_payload!(
    WebRtcAnswerV3Payload,
    WebRtcAnswerV3,
    "MRD_SIGNAL_WEBRTC_ANSWER_V3",
    WebRtcDescriptionRoleV3::Answer,
    WebrtcAnswerV3
);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebRtcCandidateV3Payload {
    pub claims: AuthClaims,
    pub session_id: SessionId,
    pub controller_device_id: DeviceId,
    pub target_device_id: DeviceId,
    pub grant_commitment: String,
    pub description_role: WebRtcDescriptionRoleV3,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
    pub candidate_fingerprint: String,
}

impl fmt::Debug for WebRtcCandidateV3Payload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebRtcCandidateV3Payload")
            .field("session_id", &self.session_id)
            .field("controller_device_id", &self.controller_device_id)
            .field("target_device_id", &self.target_device_id)
            .field("description_role", &self.description_role)
            .field("body", &"REDACTED")
            .finish()
    }
}

impl AuthenticatedPayload for WebRtcCandidateV3Payload {
    const SIGNATURE_CONTEXT: &'static str = "MRD_SIGNAL_WEBRTC_CANDIDATE_V3";

    fn claims(&self) -> &AuthClaims {
        &self.claims
    }

    fn validate_payload(&self) -> Result<(), SignalProtocolError> {
        validate_identifier(&self.session_id.0)?;
        validate_identifier(&self.controller_device_id.0)?;
        validate_identifier(&self.target_device_id.0)?;
        validate_fingerprint(&self.grant_commitment)?;
        validate_text(&self.candidate, 1, 8_192)?;
        if let Some(mid) = &self.sdp_mid {
            validate_text(mid, 1, 128)?;
        }
        if let Some(username_fragment) = &self.username_fragment {
            validate_text(username_fragment, 1, 256)?;
        }
        validate_fingerprint(&self.candidate_fingerprint)?;
        validate_role_claims(
            &self.claims,
            &self.controller_device_id,
            &self.target_device_id,
            self.description_role,
        )?;
        if self.candidate_fingerprint
            != webrtc_candidate_fingerprint_v3(
                &self.session_id,
                &self.grant_commitment,
                self.description_role,
                &self.candidate,
                self.sdp_mid.as_deref(),
                self.sdp_mline_index,
                self.username_fragment.as_deref(),
            )
        {
            return Err(SignalProtocolError::Malformed);
        }
        Ok(())
    }
}

pub type WebRtcCandidateV3 = SignedSignal<WebRtcCandidateV3Payload>;

impl SignedSignal<WebRtcCandidateV3Payload> {
    pub fn verify_grant(&self, grant: &SessionGrantV3) -> Result<(), SignalProtocolError> {
        verify_grant_binding(
            &self.payload.session_id,
            &self.payload.controller_device_id,
            &self.payload.target_device_id,
            &self.payload.grant_commitment,
            grant,
        )
    }
}

impl From<WebRtcCandidateV3> for AuthenticatedSignalMessage {
    fn from(value: WebRtcCandidateV3) -> Self {
        Self::WebrtcCandidateV3(value)
    }
}

impl From<SessionIntentV3> for AuthenticatedSignalMessage {
    fn from(value: SessionIntentV3) -> Self {
        Self::SessionIntentV3(value)
    }
}

impl From<SessionGrantV3> for AuthenticatedSignalMessage {
    fn from(value: SessionGrantV3) -> Self {
        Self::SessionGrantV3(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn webrtc_candidate_fingerprint_v3(
    session_id: &SessionId,
    grant_commitment: &str,
    description_role: WebRtcDescriptionRoleV3,
    candidate: &str,
    sdp_mid: Option<&str>,
    sdp_mline_index: Option<u16>,
    username_fragment: Option<&str>,
) -> String {
    let mid = encode_optional_bytes(sdp_mid.map(str::as_bytes));
    let index = encode_optional_bytes(sdp_mline_index.map(|value| value.to_be_bytes().to_vec()));
    let username_fragment = encode_optional_bytes(username_fragment.map(str::as_bytes));
    digest_framed(&[
        b"MRD_WEBRTC_CANDIDATE_V3\0",
        session_id.0.as_bytes(),
        grant_commitment.as_bytes(),
        description_role.as_wire().as_bytes(),
        candidate.as_bytes(),
        &mid,
        &index,
        &username_fragment,
    ])
}

#[allow(clippy::too_many_arguments)]
fn validate_description(
    claims: &AuthClaims,
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    sdp: &str,
    candidate_fingerprints: &[String],
    role: WebRtcDescriptionRoleV3,
) -> Result<(), SignalProtocolError> {
    validate_identifier(&session_id.0)?;
    validate_identifier(&controller_device_id.0)?;
    validate_identifier(&target_device_id.0)?;
    validate_fingerprint(grant_commitment)?;
    validate_text(sdp, 1, 256 * 1_024)?;
    validate_role_claims(claims, controller_device_id, target_device_id, role)?;
    if candidate_fingerprints.is_empty()
        || candidate_fingerprints.len() > MAX_CANDIDATES
        || !is_strictly_sorted(candidate_fingerprints)
    {
        return Err(SignalProtocolError::Malformed);
    }
    for fingerprint in candidate_fingerprints {
        validate_fingerprint(fingerprint)?;
    }
    Ok(())
}

fn validate_role_claims(
    claims: &AuthClaims,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    role: WebRtcDescriptionRoleV3,
) -> Result<(), SignalProtocolError> {
    let (issuer, intended_peer) = match role {
        WebRtcDescriptionRoleV3::Offer => (controller_device_id, target_device_id),
        WebRtcDescriptionRoleV3::Answer => (target_device_id, controller_device_id),
    };
    if controller_device_id == target_device_id
        || &claims.issuer_device_id != issuer
        || &claims.intended_peer_device_id != intended_peer
    {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

fn verify_grant_binding(
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    grant: &SessionGrantV3,
) -> Result<(), SignalProtocolError> {
    grant.payload.validate_payload()?;
    if grant_commitment != grant.commitment()?
        || session_id != &grant.payload.session_id
        || controller_device_id != &grant.payload.controller_device_id
        || target_device_id != &grant.payload.target_device_id
    {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_manifest(
    session_id: &SessionId,
    controller_device_id: &DeviceId,
    target_device_id: &DeviceId,
    grant_commitment: &str,
    role: WebRtcDescriptionRoleV3,
    manifest: &[String],
    candidates: &[WebRtcCandidateV3Payload],
) -> Result<(), SignalProtocolError> {
    if manifest.len() != candidates.len() {
        return Err(SignalProtocolError::Malformed);
    }
    let mut fingerprints = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        candidate.validate_payload()?;
        if &candidate.session_id != session_id
            || &candidate.controller_device_id != controller_device_id
            || &candidate.target_device_id != target_device_id
            || candidate.grant_commitment != grant_commitment
            || candidate.description_role != role
        {
            return Err(SignalProtocolError::Malformed);
        }
        fingerprints.push(candidate.candidate_fingerprint.clone());
    }
    fingerprints.sort();
    if !is_strictly_sorted(&fingerprints) || fingerprints != manifest {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

fn profile_within(
    approved: Option<&WanMediaProfileV3>,
    requested: Option<&WanMediaProfileV3>,
) -> bool {
    match (approved, requested) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(approved), Some(requested)) => {
            approved.codec == requested.codec
                && approved.codec_profile == requested.codec_profile
                && approved.width <= requested.width
                && approved.height <= requested.height
                && approved.fps <= requested.fps
                && approved.bitrate_mbps <= requested.bitrate_mbps
                && approved.bit_depth == requested.bit_depth
                && approved.chroma_subsampling == requested.chroma_subsampling
                && approved.pixel_format == requested.pixel_format
                && approved.hdr_enabled == requested.hdr_enabled
                && approved.color_mode == requested.color_mode
                && approved.color_pipeline == requested.color_pipeline
        }
    }
}

fn signed_commitment<T: Serialize>(
    context: &[u8],
    signed: &SignedSignal<T>,
) -> Result<String, SignalProtocolError> {
    let canonical = serde_json::to_vec(signed).map_err(|_| SignalProtocolError::Malformed)?;
    Ok(digest_framed(&[context, &canonical]))
}

fn digest_hex(fields: &[&[u8]]) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    for field in fields {
        context.update(field);
    }
    hex(context.finish().as_ref())
}

fn digest_framed(fields: &[&[u8]]) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    for field in fields {
        context.update(&(field.len() as u64).to_be_bytes());
        context.update(field);
    }
    hex(context.finish().as_ref())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode_optional_bytes<T>(value: Option<T>) -> Vec<u8>
where
    T: AsRef<[u8]>,
{
    match value {
        Some(value) => {
            let value = value.as_ref();
            let mut encoded = Vec::with_capacity(value.len() + 1);
            encoded.push(1);
            encoded.extend_from_slice(value);
            encoded
        }
        None => vec![0],
    }
}

fn is_strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_normalized_token(value: &str, maximum: usize) -> Result<(), SignalProtocolError> {
    validate_text(value, 1, maximum)?;
    if value.trim() != value
        || value.bytes().any(|byte| {
            byte.is_ascii_uppercase()
                || !(byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b':' | b'+'))
        })
    {
        return Err(SignalProtocolError::Malformed);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), SignalProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
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
