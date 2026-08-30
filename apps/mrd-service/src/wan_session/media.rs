//! Authorization-gated media activation for the initial WAN relay session.
//!
//! This module deliberately stops at a small service-owned port.  Concrete
//! capture, decode, render, and Agent command adapters belong to the service
//! runtime; none of them may be called until the coordinator has published a
//! `RelayVerified` state with the exact installed grant.

use super::{
    coordinator::WanSessionCoordinator,
    model::{WanSessionPhase, WanSessionRole, WanSessionState},
};
use async_trait::async_trait;
use mrd_ipc::{LanDiscoverySnapshot, MediaProfile, RemoteRoutePreference};
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{WanMediaProfileV3, WanPermissionScopeV3};
use std::{fmt, time::Duration};
use thiserror::Error;
use tokio::sync::oneshot;

const WAN_MEDIA_READINESS_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum age accepted for an already cached LAN discovery record when the
/// caller asks for `Auto`.  Auto never probes or waits for a new announcement.
pub const DEFAULT_LAN_DISCOVERY_MAX_AGE_MS: u64 = 5_000;

/// Redacted evidence used by the route selector.  `signed` and
/// `public_key_pinned` are intentionally separate: a signed diagnostic record
/// is not enough to authorize the secure LAN bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanDiscoveryEvidence {
    fresh: bool,
    signed: bool,
    public_key_pinned: bool,
    supports_quic: bool,
    /// Only authenticated LAN peer records may set this bit.  A public
    /// `LanDiscoverySnapshot` never contains enough information to set it.
    authenticated: bool,
    pub(crate) peer_key_id: Option<String>,
    pub(crate) peer_public_key: Option<Vec<u8>>,
    pub(crate) peer_key_epoch: Option<u64>,
}

impl LanDiscoveryEvidence {
    #[cfg(any(test, debug_assertions))]
    pub const fn for_test(
        fresh: bool,
        signed: bool,
        public_key_pinned: bool,
        supports_quic: bool,
    ) -> Self {
        Self {
            fresh,
            signed,
            public_key_pinned,
            supports_quic,
            authenticated: true,
            peer_key_id: None,
            peer_public_key: None,
            peer_key_epoch: None,
        }
    }

    /// Construct evidence from the private authenticated peer registry.  This
    /// is crate-visible so route dispatch cannot mint it from IPC DTOs.
    pub(crate) fn from_authenticated_peer(
        fresh: bool,
        supports_quic: bool,
        peer_key_id: String,
        peer_public_key: Vec<u8>,
        peer_key_epoch: u64,
    ) -> Self {
        Self {
            fresh,
            signed: true,
            public_key_pinned: true,
            supports_quic,
            authenticated: true,
            peer_key_id: Some(peer_key_id),
            peer_public_key: Some(peer_public_key),
            peer_key_epoch: Some(peer_key_epoch),
        }
    }

    /// Build diagnostic-only evidence from the public discovery projection.
    /// The projection intentionally omits the signing key, epoch, and trust
    /// revision, so it can never authorize the secure LAN route.
    pub fn from_snapshot(
        snapshot: &LanDiscoverySnapshot,
        target_device_id: &DeviceId,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Option<Self> {
        let peer = snapshot
            .peers
            .iter()
            .find(|peer| peer.device_id == *target_device_id)?;
        let observed_at_ms = now_ms.saturating_sub(peer.age_ms);
        let fresh = now_ms.saturating_sub(observed_at_ms) <= max_age_ms;
        let supports_quic = peer
            .transports
            .iter()
            .any(|transport| transport.eq_ignore_ascii_case("quic"));
        Some(Self {
            fresh,
            signed: false,
            public_key_pinned: false,
            supports_quic,
            authenticated: false,
            peer_key_id: None,
            peer_public_key: None,
            peer_key_epoch: None,
        })
    }

    pub const fn is_fresh(&self) -> bool {
        self.fresh
    }

    pub const fn is_signed(&self) -> bool {
        self.signed
    }

    pub const fn is_public_key_pinned(&self) -> bool {
        self.public_key_pinned
    }

    pub const fn supports_quic(&self) -> bool {
        self.supports_quic
    }

    pub const fn is_secure_lan_candidate(&self) -> bool {
        self.authenticated
            && self.fresh
            && self.signed
            && self.public_key_pinned
            && self.supports_quic
    }
}

/// The only two initial route choices.  There is no implicit fallback after a
/// route has been selected: a failed explicit LAN request remains a LAN
/// failure, and a WAN relay request remains a WAN relay request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanRouteSelection {
    Lan,
    WanRelay,
}

/// Select an initial route without performing any network I/O.
pub fn select_route(
    preference: RemoteRoutePreference,
    cached_lan: Option<LanDiscoveryEvidence>,
) -> WanRouteSelection {
    match preference {
        RemoteRoutePreference::Lan => WanRouteSelection::Lan,
        RemoteRoutePreference::WanRelay => WanRouteSelection::WanRelay,
        RemoteRoutePreference::Auto => cached_lan
            .filter(|evidence| evidence.is_secure_lan_candidate())
            .map(|_| WanRouteSelection::Lan)
            .unwrap_or(WanRouteSelection::WanRelay),
    }
}

/// Compatibility alias for callers that name the result as a selected route.
pub type SelectedRemoteRoute = WanRouteSelection;

/// Read only the already cached authenticated LAN record and re-check the
/// current key/epoch pin.  Callers should hold `authorization_security_gate`
/// while invoking this helper.  It never triggers discovery or waits.
pub async fn fresh_authenticated_lan_evidence(
    app_state: &crate::app_state::AppState,
    target_device_id: &DeviceId,
    now_ms: u64,
    max_age_ms: u64,
) -> Option<LanDiscoveryEvidence> {
    let evidence = app_state
        .lan_discovery
        .fresh_authenticated_peer_evidence(target_device_id, now_ms, max_age_ms)
        .await?;
    let key_id = evidence.peer_key_id.as_deref()?;
    let public_key = evidence.peer_public_key.as_deref()?;
    let epoch = evidence.peer_key_epoch?;
    let trust = app_state
        .device_identities
        .authenticated_peer_trust(key_id, public_key, epoch)
        .ok()?;
    trust.is_controllable().then_some(evidence)
}

/// Authority derived exclusively from a coordinator state at
/// `RelayVerified`.  The exact grant and route proof are copied into the
/// opaque value so media adapters cannot synthesize authority from an IPC
/// request or a backend-only record.
#[derive(Clone, PartialEq, Eq)]
pub struct WanMediaAuthority {
    session_id: SessionId,
    role: WanSessionRole,
    controller_device_id: DeviceId,
    target_device_id: DeviceId,
    controller_key_id: String,
    target_key_id: String,
    grant_id: [u8; 32],
    policy_revision: u64,
    expires_at_ms: u64,
    approved_scopes: Vec<WanPermissionScopeV3>,
    approved_profile: Option<WanMediaProfileV3>,
    generation: u64,
}

impl fmt::Debug for WanMediaAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanMediaAuthority")
            .field("session_id", &"OPAQUE")
            .field("role", &self.role)
            .field("approved_scopes", &self.approved_scopes)
            .field(
                "approved_profile",
                &self.approved_profile.as_ref().map(|_| "SET"),
            )
            .field("generation", &self.generation)
            .finish()
    }
}

impl WanMediaAuthority {
    pub fn from_relay_verified(state: &WanSessionState) -> Result<Self, WanMediaActivationError> {
        if state.phase() != WanSessionPhase::RelayVerified {
            return Err(WanMediaActivationError::NotRelayVerified);
        }
        Self::from_verified_route(state)
    }

    pub(crate) fn from_streaming(state: &WanSessionState) -> Result<Self, WanMediaActivationError> {
        if state.phase() != WanSessionPhase::Streaming {
            return Err(WanMediaActivationError::NotRelayVerified);
        }
        Self::from_verified_route(state)
    }

    fn from_verified_route(state: &WanSessionState) -> Result<Self, WanMediaActivationError> {
        let grant = state.grant().ok_or(WanMediaActivationError::MissingGrant)?;
        let grant_commitment = grant
            .grant_commitment()
            .ok_or(WanMediaActivationError::GrantCommitmentMissing)?;
        let grant_id = decode_hex_digest(grant_commitment)
            .ok_or(WanMediaActivationError::GrantCommitmentMissing)?;
        let proof = state
            .route_proof()
            .ok_or(WanMediaActivationError::MissingRouteProof)?;
        if !proof.is_relay_to_relay() || state.access() != Some(proof.access()) {
            return Err(WanMediaActivationError::InvalidRouteProof);
        }
        Ok(Self {
            session_id: state.identity().session_id().clone(),
            role: state.role(),
            controller_device_id: state.identity().controller_device_id().clone(),
            target_device_id: state.identity().target_device_id().clone(),
            controller_key_id: state.identity().controller_key_fingerprint().to_owned(),
            target_key_id: state
                .identity()
                .target_key_fingerprint()
                .ok_or(WanMediaActivationError::GrantCommitmentMissing)?
                .to_owned(),
            grant_id,
            policy_revision: grant.policy_revision(),
            expires_at_ms: grant.grant_expires_at_ms(),
            approved_scopes: grant.approved_scopes().to_vec(),
            approved_profile: grant.approved_profile().cloned(),
            generation: proof.access().generation(),
        })
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn role(&self) -> WanSessionRole {
        self.role
    }

    pub fn approved_scopes(&self) -> &[WanPermissionScopeV3] {
        &self.approved_scopes
    }

    pub fn approved_profile(&self) -> Option<&WanMediaProfileV3> {
        self.approved_profile.as_ref()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn controller_device_id(&self) -> &DeviceId {
        &self.controller_device_id
    }

    pub(crate) fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }

    pub(crate) fn controller_key_id(&self) -> &str {
        &self.controller_key_id
    }

    pub(crate) fn target_key_id(&self) -> &str {
        &self.target_key_id
    }

    pub(crate) const fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    pub(crate) const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub(crate) const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn allows_scope(&self, scope: WanPermissionScopeV3) -> bool {
        self.approved_scopes.contains(&scope)
    }

    /// Produce a role-specific plan.  Input intentionally does not appear in
    /// this plan; it needs a separate control-evidence barrier.
    pub fn media_plan(&self) -> Result<WanMediaPlan, WanMediaActivationError> {
        if !self.allows_scope(WanPermissionScopeV3::ScreenView) {
            return Err(WanMediaActivationError::ScreenScopeRequired);
        }
        Ok(WanMediaPlan {
            session_id: self.session_id.clone(),
            role: self.role,
            profile: self.approved_profile.clone(),
            action: match self.role {
                WanSessionRole::Target => WanMediaAction::CaptureAndSend,
                WanSessionRole::Controller => WanMediaAction::ReceiveAndRender,
            },
            input_frozen: true,
        })
    }
}

/// Role-specific media operation selected after relay verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanMediaAction {
    CaptureAndSend,
    ReceiveAndRender,
}

/// Approved profile and role operation passed to service adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanMediaPlan {
    session_id: SessionId,
    role: WanSessionRole,
    profile: Option<WanMediaProfileV3>,
    action: WanMediaAction,
    input_frozen: bool,
}

impl WanMediaPlan {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn role(&self) -> WanSessionRole {
        self.role
    }

    pub fn profile(&self) -> Option<&WanMediaProfileV3> {
        self.profile.as_ref()
    }

    pub const fn action(&self) -> WanMediaAction {
        self.action
    }

    pub const fn input_frozen(&self) -> bool {
        self.input_frozen
    }
}

fn decode_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

/// First real codec/transport boundary crossed by one exact WAN media runtime.
#[derive(Clone, PartialEq, Eq)]
pub struct WanMediaReadyEvidence {
    session_id: SessionId,
    generation: u64,
    role: WanSessionRole,
    sequence: u64,
}

impl fmt::Debug for WanMediaReadyEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanMediaReadyEvidence")
            .field("session_id", &"OPAQUE")
            .field("generation", &self.generation)
            .field("role", &self.role)
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl WanMediaReadyEvidence {
    pub(crate) fn from_authority(authority: &WanMediaAuthority, sequence: u64) -> Self {
        Self {
            session_id: authority.session_id().clone(),
            generation: authority.generation(),
            role: authority.role(),
            sequence,
        }
    }

    fn matches(&self, authority: &WanMediaAuthority) -> bool {
        self.session_id == *authority.session_id()
            && self.generation == authority.generation()
            && self.role == authority.role()
    }
}

pub(crate) type WanMediaReadySender =
    oneshot::Sender<Result<WanMediaReadyEvidence, WanMediaActivationError>>;

/// Single-use receipt proving that an owned media task crossed its first real
/// capture/send or receive/decode boundary.
pub struct WanMediaActivationReceipt {
    ready: oneshot::Receiver<Result<WanMediaReadyEvidence, WanMediaActivationError>>,
}

impl fmt::Debug for WanMediaActivationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanMediaActivationReceipt")
            .finish_non_exhaustive()
    }
}

impl WanMediaActivationReceipt {
    pub(crate) fn pending() -> (Self, WanMediaReadySender) {
        let (ready_tx, ready) = oneshot::channel();
        (Self { ready }, ready_tx)
    }

    #[cfg(any(test, debug_assertions))]
    pub fn ready_for_test(authority: &WanMediaAuthority, sequence: u64) -> Self {
        let (receipt, ready) = Self::pending();
        let _ = ready.send(Ok(WanMediaReadyEvidence::from_authority(
            authority, sequence,
        )));
        receipt
    }

    async fn wait(
        self,
        authority: &WanMediaAuthority,
    ) -> Result<WanMediaReadyEvidence, WanMediaActivationError> {
        let evidence = tokio::time::timeout(WAN_MEDIA_READINESS_TIMEOUT, self.ready)
            .await
            .map_err(|_| WanMediaActivationError::ReadinessTimeout)?
            .map_err(|_| WanMediaActivationError::StartupFailed)??;
        if !evidence.matches(authority) {
            return Err(WanMediaActivationError::ReadinessMismatch);
        }
        Ok(evidence)
    }
}

/// Minimum service-owned media API.  Implementations may bridge these calls
/// to local capture/decoder/render registries or to signed Agent commands.
#[async_trait]
pub trait WanMediaActivationPort: Send + Sync {
    async fn start_target_capture_send(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<WanMediaActivationReceipt, WanMediaActivationError>;

    async fn start_controller_receive_render(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<WanMediaActivationReceipt, WanMediaActivationError>;

    async fn stop_media(&self, _session_id: &SessionId) -> Result<(), WanMediaActivationError> {
        Ok(())
    }

    async fn remove_failover(
        &self,
        _session_id: &SessionId,
    ) -> Result<(), WanMediaActivationError> {
        Ok(())
    }
}

/// Separate input port so media activation cannot accidentally enable input.
#[async_trait]
pub trait WanInputActivationPort: Send + Sync {
    async fn enable_input(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError>;
}

/// Existing control/evidence implementations should report the exact session
/// grant's authenticated control evidence through this narrow port.
#[async_trait]
pub trait ControlEvidenceBarrier: Send + Sync {
    async fn is_verified(&self, session_id: &SessionId) -> bool;
}

/// Start the role-specific media operation only for a fresh RelayVerified
/// state, then publish Streaming through the same coordinator entry.
pub async fn start_verified_media(
    coordinator: &WanSessionCoordinator,
    state: &WanSessionState,
    media: &dyn WanMediaActivationPort,
) -> Result<WanMediaPlan, WanMediaActivationError> {
    let authority = WanMediaAuthority::from_relay_verified(state)?;
    let plan = authority.media_plan()?;
    let start_result = match plan.action() {
        WanMediaAction::CaptureAndSend => media.start_target_capture_send(&authority).await,
        WanMediaAction::ReceiveAndRender => media.start_controller_receive_render(&authority).await,
    };
    let receipt = match start_result {
        Ok(receipt) => receipt,
        Err(error) => {
            fail_media_session(coordinator, media, authority.session_id()).await;
            return Err(error);
        }
    };
    if let Err(error) = receipt.wait(&authority).await {
        fail_media_session(coordinator, media, authority.session_id()).await;
        return Err(error);
    }
    let current_state = match coordinator.snapshot(authority.session_id()).await {
        Ok(state) => state,
        Err(_) => {
            fail_media_session(coordinator, media, authority.session_id()).await;
            return Err(WanMediaActivationError::CoordinatorFailure);
        }
    };
    let current = WanMediaAuthority::from_relay_verified(&current_state);
    if current.as_ref() != Ok(&authority) {
        fail_media_session(coordinator, media, authority.session_id()).await;
        return Err(WanMediaActivationError::AuthorityChanged);
    }
    if let Err(_error) = coordinator.record_streaming(authority.session_id()).await {
        fail_media_session(coordinator, media, authority.session_id()).await;
        return Err(WanMediaActivationError::CoordinatorFailure);
    }
    Ok(plan)
}

async fn fail_media_session(
    coordinator: &WanSessionCoordinator,
    media: &dyn WanMediaActivationPort,
    session_id: &SessionId,
) {
    let coordinator_entry_missing = match coordinator
        .fail(session_id, super::model::WanSessionFailure::Transport)
        .await
    {
        Ok(_) => false,
        Err(super::coordinator::WanSessionCoordinatorError::SessionNotFound) => true,
        Err(_) => {
            tracing::warn!(session_id = %session_id.0, "WAN media failure could not be recorded by coordinator");
            false
        }
    };
    // The coordinator cleanup receipt is the sole owner while an entry exists.
    // Direct compensation is reserved for the explicit missing-entry race.
    if coordinator_entry_missing {
        if media.stop_media(session_id).await.is_err() {
            tracing::warn!(session_id = %session_id.0, "WAN media stop cleanup failed");
        }
        if media.remove_failover(session_id).await.is_err() {
            tracing::warn!(session_id = %session_id.0, "WAN media failover cleanup failed");
        }
    }
}

/// Enable input only after the existing authenticated control evidence barrier
/// has passed and the exact grant contains an input scope.
pub async fn enable_input_after_control_evidence(
    authority: &WanMediaAuthority,
    barrier: &dyn ControlEvidenceBarrier,
    input: &dyn WanInputActivationPort,
) -> Result<(), WanMediaActivationError> {
    if !authority.allows_scope(WanPermissionScopeV3::InputKeyboard)
        && !authority.allows_scope(WanPermissionScopeV3::InputPointer)
    {
        return Err(WanMediaActivationError::InputScopeRequired);
    }
    if !barrier.is_verified(authority.session_id()).await {
        return Err(WanMediaActivationError::ControlEvidenceRequired);
    }
    input.enable_input(authority).await
}

/// Convert the protocol-v3 profile into the existing IPC/profile registry
/// representation without introducing a second policy source.
pub fn ipc_media_profile(profile: &WanMediaProfileV3) -> MediaProfile {
    MediaProfile {
        width: profile.width,
        height: profile.height,
        fps: profile.fps,
        bitrate_mbps: profile.bitrate_mbps,
        codec: profile.codec.clone(),
        codec_profile: profile.codec_profile.clone(),
        bit_depth: profile.bit_depth,
        chroma_subsampling: profile.chroma_subsampling.clone(),
        pixel_format: profile.pixel_format.clone(),
        hdr_enabled: profile.hdr_enabled,
        color_mode: profile.color_mode.clone(),
        color_pipeline: profile.color_pipeline.clone(),
    }
}

/// Convert an IPC media profile into the signed protocol-v3 representation.
pub fn wan_media_profile(profile: &MediaProfile) -> WanMediaProfileV3 {
    WanMediaProfileV3 {
        width: profile.width,
        height: profile.height,
        fps: profile.fps,
        bitrate_mbps: profile.bitrate_mbps,
        codec: profile.codec.clone(),
        codec_profile: profile.codec_profile.clone(),
        bit_depth: profile.bit_depth,
        chroma_subsampling: profile.chroma_subsampling.clone(),
        pixel_format: profile.pixel_format.clone(),
        hdr_enabled: profile.hdr_enabled,
        color_mode: profile.color_mode.clone(),
        color_pipeline: profile.color_pipeline.clone(),
    }
}

/// Stable typed failures for callers that need to project media startup into
/// `RemoteFailure` without exposing backend/transport internals.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WanMediaActivationError {
    #[error("WAN media requires RelayVerified state")]
    NotRelayVerified,
    #[error("WAN media grant is missing")]
    MissingGrant,
    #[error("WAN media grant has no signed commitment")]
    GrantCommitmentMissing,
    #[error("WAN media route proof is missing")]
    MissingRouteProof,
    #[error("WAN media route proof is invalid")]
    InvalidRouteProof,
    #[error("WAN media requires an approved screen.view scope")]
    ScreenScopeRequired,
    #[error("WAN input requires an approved input scope")]
    InputScopeRequired,
    #[error("WAN input control evidence is not verified")]
    ControlEvidenceRequired,
    #[error("WAN media startup failed")]
    StartupFailed,
    #[error("WAN media readiness timed out")]
    ReadinessTimeout,
    #[error("WAN media readiness evidence did not match authority")]
    ReadinessMismatch,
    #[error("WAN media authority changed during startup")]
    AuthorityChanged,
    #[error("WAN media coordinator operation failed")]
    CoordinatorFailure,
}
