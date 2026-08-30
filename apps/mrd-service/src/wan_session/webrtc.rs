//! Generation-zero, relay-only WebRTC negotiation.
//!
//! Initial negotiation intentionally has its own state and host seam. Relay
//! migration (generation one and above) owns restart-token state in
//! `relay::executor`; this executor never creates or consumes that state.

use super::model::{
    GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionFailure, WanSessionIdentity,
    WanSessionPhase, WanSessionRole, WanSessionState,
};
use crate::{
    relay::{
        install_connected_relay_session, urls_digest, RelayAccessContext, RelayRouteEvidence,
        VerifiedRelayAccess,
    },
    signaling::{
        AuthenticatedSessionSignalingCommand, AuthenticatedSessionSignalingReceiveError,
        AuthenticatedSessionSignalingSendError, AuthenticatedSessionSignalingSubscription,
        OutboundAuthenticatedSessionSignal, RelaySignalingBus,
    },
    transports::webrtc::{ServiceWebRtcTransportError, ServiceWebRtcTransportHost},
};
use async_trait::async_trait;
use mrd_application::{
    AuthenticatedSessionSignal, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{
    webrtc_candidate_fingerprint_v3, AuthenticatedPayload, SignalReplayGuard, SignedSignal,
    WebRtcCandidateV3, WebRtcDescriptionRoleV3,
};
use mrd_transport_webrtc::{
    IceCandidate, IceTransportPolicy, PeerConnectionConfig, PeerConnectionRole, SessionDescription,
    SessionDescriptionType,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    fmt,
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::{watch, Mutex};

const SHA256_HEX_BYTES: usize = 64;
const MAX_GENERATION_ZERO_CANDIDATES: usize = 256;
const MIN_NEGOTIATION_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(60);
const GENERATION_ZERO_QUIESCENCE: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GenerationZeroSignalKey {
    issuer_key_id: String,
    counter: u64,
    nonce: [u8; 16],
}

/// The protocol replay guard deliberately enforces monotonic counters.  ICE
/// candidates are allowed to arrive before their description, so generation
/// zero uses a bounded seen-set while still asking `SignedSignal` to perform
/// the complete signature, freshness, and intended-peer validation for every
/// message.
#[derive(Debug)]
struct GenerationZeroReplayWindow {
    capacity: usize,
    order: VecDeque<GenerationZeroSignalKey>,
    seen: HashSet<GenerationZeroSignalKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerationZeroVerificationFailure {
    Invalid,
    Duplicate,
}

impl GenerationZeroReplayWindow {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::with_capacity(capacity.min(MAX_GENERATION_ZERO_CANDIDATES * 4)),
            seen: HashSet::with_capacity(capacity.min(MAX_GENERATION_ZERO_CANDIDATES * 4)),
        }
    }

    fn accept(&mut self, key: GenerationZeroSignalKey) -> bool {
        if !self.seen.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }
        true
    }
}

fn verify_generation_zero_signal<T>(
    message: &SignedSignal<T>,
    expected_peer: &DeviceId,
    now_unix_ms: u64,
    replay: &mut GenerationZeroReplayWindow,
) -> Result<(), GenerationZeroVerificationFailure>
where
    T: AuthenticatedPayload,
{
    // Use a fresh protocol guard for each message.  It retains all signature,
    // claims, lifetime, and intended-peer checks without imposing a transport
    // ordering requirement on independently delivered ICE messages.
    let mut message_guard = SignalReplayGuard::new(2, 1);
    message
        .verify_for(expected_peer, now_unix_ms, &mut message_guard)
        .map_err(|_| GenerationZeroVerificationFailure::Invalid)?;
    let claims = message.payload.claims();
    let key = GenerationZeroSignalKey {
        issuer_key_id: claims.issuer_key_id.clone(),
        counter: claims.counter,
        nonce: claims.nonce,
    };
    if replay.accept(key) {
        Ok(())
    } else {
        Err(GenerationZeroVerificationFailure::Duplicate)
    }
}

/// A host-produced route proof. SDP, ICE candidates, TURN credentials, and
/// candidate IDs are intentionally absent from this value.
#[derive(Clone, PartialEq, Eq)]
pub struct GenerationZeroRouteProof {
    session_id: SessionId,
    generation: u64,
    directory_id: String,
    primary_node_id: String,
    relay_url_digest: String,
    local_relay: bool,
    remote_relay: bool,
}

impl fmt::Debug for GenerationZeroRouteProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationZeroRouteProof")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("directory_id", &self.directory_id)
            .field("primary_node_id", &self.primary_node_id)
            .field("relay_url_digest", &"[REDACTED]")
            .field("local_relay", &self.local_relay)
            .field("remote_relay", &self.remote_relay)
            .finish()
    }
}

impl GenerationZeroRouteProof {
    /// Construct a proof for a host implementation after it has checked the
    /// selected pair and exact TURN URL digest.
    pub(crate) fn new(
        session_id: SessionId,
        directory_id: String,
        primary_node_id: String,
        relay_url_digest: String,
        local_relay: bool,
        remote_relay: bool,
    ) -> Result<Self, GenerationZeroNegotiationError> {
        if !is_sha256_hex(&relay_url_digest)
            || directory_id.is_empty()
            || primary_node_id.is_empty()
            || !local_relay
            || !remote_relay
        {
            return Err(GenerationZeroNegotiationError::RouteEvidenceMismatch);
        }
        Ok(Self {
            session_id,
            generation: 0,
            directory_id,
            primary_node_id,
            relay_url_digest,
            local_relay,
            remote_relay,
        })
    }

    /// Test-only construction hook for host seams. Production installers
    /// still re-verify this value through the service-owned relay runtime.
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    pub fn for_test(
        session_id: SessionId,
        directory_id: String,
        primary_node_id: String,
        relay_url_digest: String,
    ) -> Result<Self, GenerationZeroNegotiationError> {
        Self::new(
            session_id,
            directory_id,
            primary_node_id,
            relay_url_digest,
            true,
            true,
        )
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn directory_id(&self) -> &str {
        &self.directory_id
    }

    pub fn primary_node_id(&self) -> &str {
        &self.primary_node_id
    }

    pub fn relay_url_digest(&self) -> &str {
        &self.relay_url_digest
    }

    pub fn is_relay_to_relay(&self) -> bool {
        self.local_relay && self.remote_relay
    }

    fn from_verified_route(
        session_id: &SessionId,
        route: &RelayRouteEvidence,
    ) -> Result<Self, GenerationZeroNegotiationError> {
        if route.session_id() != session_id.0
            || route.generation() != 0
            || !is_sha256_hex(&hex_digest(route.urls_digest()))
        {
            return Err(GenerationZeroNegotiationError::RouteEvidenceMismatch);
        }
        Self::new(
            session_id.clone(),
            route.directory_id().to_owned(),
            route.node_id().to_owned(),
            hex_digest(route.urls_digest()),
            true,
            true,
        )
    }
}

/// Testable host boundary for generation-zero negotiation. The concrete
/// service host implementation below is the production adapter.
#[async_trait]
pub trait GenerationZeroWebRtcHost: Send + Sync {
    async fn open_generation_zero(
        &self,
        session_id: &SessionId,
        config: PeerConnectionConfig,
    ) -> Result<(), GenerationZeroWebRtcHostError>;

    async fn create_offer(
        &self,
        session_id: &SessionId,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError>;

    async fn accept_offer(
        &self,
        session_id: &SessionId,
        offer: SessionDescription,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError>;

    async fn accept_answer(
        &self,
        session_id: &SessionId,
        answer: SessionDescription,
    ) -> Result<(), GenerationZeroWebRtcHostError>;

    async fn next_local_candidate(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<IceCandidate>, GenerationZeroWebRtcHostError>;

    async fn add_remote_candidate(
        &self,
        session_id: &SessionId,
        candidate: IceCandidate,
    ) -> Result<(), GenerationZeroWebRtcHostError>;

    async fn wait_connected(
        &self,
        session_id: &SessionId,
    ) -> Result<(), GenerationZeroWebRtcHostError>;

    /// Return an opaque proof after observing a nominated relay/relay pair on
    /// this host's exact URL set.
    async fn prove_generation_zero_route(
        &self,
        expected: &RelayRouteEvidence,
        session_id: &SessionId,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroWebRtcHostError>;

    async fn close_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(), GenerationZeroWebRtcHostError>;
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GenerationZeroWebRtcHostError {
    #[error("generation-zero WebRTC host is unavailable")]
    Unavailable,
    #[error("generation-zero WebRTC host rejected the operation")]
    Rejected,
    #[error("generation-zero WebRTC host route evidence is invalid")]
    RouteEvidenceMismatch,
    #[error("generation-zero WebRTC host session is closed")]
    Closed,
}

/// Errors exposed by the generation-zero signaling seam.  Concrete websocket
/// errors are collapsed here so the negotiation executor never logs or returns
/// transport strings containing protocol bodies.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GenerationZeroSignalingError {
    #[error("generation-zero signaling is unavailable")]
    Unavailable,
    #[error("generation-zero signaling queue is full")]
    Backpressure,
    #[error("generation-zero signaling stream is closed")]
    Closed,
    #[error("generation-zero signaling stream overflowed")]
    Lagged,
}

/// Scoped inbound stream used by the generation-zero executor.
#[async_trait]
pub trait GenerationZeroSignalingSubscription: Send {
    async fn recv(&mut self) -> Result<VerifiedSignalingEvent, GenerationZeroSignalingError>;

    async fn try_recv(
        &mut self,
    ) -> Result<Option<VerifiedSignalingEvent>, GenerationZeroSignalingError>;
}

/// Authenticated signaling boundary for the generation-zero executor.
///
/// The receiver is created from an `Arc<Self>` so the production relay bus can
/// retain its lifecycle fence, while tests can provide an in-memory scoped
/// implementation without exposing any bus mutation or event injection API.
#[async_trait]
pub trait GenerationZeroSignaling: Send + Sync {
    fn subscribe(
        self: Arc<Self>,
        session_id: SessionId,
        peer_device_id: DeviceId,
    ) -> Box<dyn GenerationZeroSignalingSubscription>;

    async fn send(
        &self,
        command: AuthenticatedSessionSignalingCommand,
    ) -> Result<(), GenerationZeroSignalingError>;
}

struct RelayGenerationZeroSubscription {
    inner: AuthenticatedSessionSignalingSubscription,
}

#[async_trait]
impl GenerationZeroSignalingSubscription for RelayGenerationZeroSubscription {
    async fn recv(&mut self) -> Result<VerifiedSignalingEvent, GenerationZeroSignalingError> {
        self.inner.recv().await.map_err(map_relay_receive_error)
    }

    async fn try_recv(
        &mut self,
    ) -> Result<Option<VerifiedSignalingEvent>, GenerationZeroSignalingError> {
        self.inner.try_recv().await.map_err(map_relay_receive_error)
    }
}

#[async_trait]
impl GenerationZeroSignaling for RelaySignalingBus {
    fn subscribe(
        self: Arc<Self>,
        session_id: SessionId,
        peer_device_id: DeviceId,
    ) -> Box<dyn GenerationZeroSignalingSubscription> {
        Box::new(RelayGenerationZeroSubscription {
            inner: self.subscribe_authenticated_session(session_id, peer_device_id),
        })
    }

    async fn send(
        &self,
        command: AuthenticatedSessionSignalingCommand,
    ) -> Result<(), GenerationZeroSignalingError> {
        let receipt = self
            .try_send_authenticated(command)
            .map_err(map_relay_send_error)?;
        receipt.wait().await.map_err(map_relay_send_error)
    }
}

#[async_trait]
impl GenerationZeroWebRtcHost for ServiceWebRtcTransportHost {
    async fn open_generation_zero(
        &self,
        session_id: &SessionId,
        config: PeerConnectionConfig,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        if config.ice_transport_policy != IceTransportPolicy::Relay || config.ice_servers.len() != 1
        {
            return Err(GenerationZeroWebRtcHostError::Rejected);
        }
        self.open_session(session_id.clone(), config)
            .await
            .map_err(map_host_error)
    }

    async fn create_offer(
        &self,
        session_id: &SessionId,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        ServiceWebRtcTransportHost::create_offer(self, session_id)
            .await
            .map_err(map_host_error)
    }

    async fn accept_offer(
        &self,
        session_id: &SessionId,
        offer: SessionDescription,
    ) -> Result<SessionDescription, GenerationZeroWebRtcHostError> {
        ServiceWebRtcTransportHost::accept_offer(self, session_id, offer)
            .await
            .map_err(map_host_error)
    }

    async fn accept_answer(
        &self,
        session_id: &SessionId,
        answer: SessionDescription,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        ServiceWebRtcTransportHost::accept_answer(self, session_id, answer)
            .await
            .map_err(map_host_error)
    }

    async fn next_local_candidate(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<IceCandidate>, GenerationZeroWebRtcHostError> {
        ServiceWebRtcTransportHost::next_local_candidate(self, session_id)
            .await
            .map_err(map_host_error)
    }

    async fn add_remote_candidate(
        &self,
        session_id: &SessionId,
        candidate: IceCandidate,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        ServiceWebRtcTransportHost::add_ice_candidate(self, session_id, candidate)
            .await
            .map_err(map_host_error)
    }

    async fn wait_connected(
        &self,
        session_id: &SessionId,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        ServiceWebRtcTransportHost::wait_connected(self, session_id)
            .await
            .map_err(map_host_error)
    }

    async fn prove_generation_zero_route(
        &self,
        expected: &RelayRouteEvidence,
        session_id: &SessionId,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroWebRtcHostError> {
        let evidence = self
            .verify_active_relay(session_id, expected.clone())
            .await
            .map_err(map_host_error)?;
        GenerationZeroRouteProof::from_verified_route(session_id, evidence.route())
            .map_err(|_| GenerationZeroWebRtcHostError::RouteEvidenceMismatch)
    }

    async fn close_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(), GenerationZeroWebRtcHostError> {
        match ServiceWebRtcTransportHost::close_session(self, session_id).await {
            Ok(()) | Err(ServiceWebRtcTransportError::SessionNotFound(_)) => Ok(()),
            Err(error) => Err(map_host_error(error)),
        }
    }
}

fn map_host_error(error: ServiceWebRtcTransportError) -> GenerationZeroWebRtcHostError {
    match error {
        ServiceWebRtcTransportError::ReplacementEvidenceMismatch => {
            GenerationZeroWebRtcHostError::RouteEvidenceMismatch
        }
        ServiceWebRtcTransportError::DuplicateSession(_) => GenerationZeroWebRtcHostError::Rejected,
        ServiceWebRtcTransportError::SessionNotFound(_) => GenerationZeroWebRtcHostError::Closed,
        ServiceWebRtcTransportError::InvalidReplacement
        | ServiceWebRtcTransportError::Transport(_) => GenerationZeroWebRtcHostError::Unavailable,
    }
}

/// A completed installation that can be rolled back if the authority or
/// deadline fence changes before the negotiation is committed.
///
/// The receipt is deliberately explicit rather than relying on `Drop`: the
/// rollback is asynchronous and must be awaited by the negotiation executor.
#[async_trait]
pub trait GenerationZeroInstallReceipt: Send + Sync {
    async fn rollback(&self) -> Result<(), GenerationZeroNegotiationError>;
}

/// Post-proof installation boundary. Production uses this to register the
/// stable mux with relay failover; tests use it to count calls. Implementors
/// must make the operation cancellation-safe. If cancellation interrupts an
/// in-flight install before a receipt can be returned, the executor invokes
/// `rollback_generation_zero` as a compensating operation.
#[async_trait]
pub trait GenerationZeroSessionInstaller: Send + Sync {
    async fn install_generation_zero(
        &self,
        proof: &GenerationZeroRouteProof,
    ) -> Result<Box<dyn GenerationZeroInstallReceipt>, GenerationZeroNegotiationError>;

    async fn rollback_generation_zero(
        &self,
        _proof: &GenerationZeroRouteProof,
    ) -> Result<(), GenerationZeroNegotiationError> {
        Ok(())
    }
}

/// Production post-proof adapter. It delegates to the existing relay runtime
/// registration boundary, which re-verifies authorization and selected-pair
/// evidence before enabling generation-one failover.
pub struct ServiceGenerationZeroSessionInstaller {
    app_state: Arc<crate::AppState>,
    context: RelayAccessContext,
    access: Arc<VerifiedRelayAccess>,
    active_node_id: String,
}

impl fmt::Debug for ServiceGenerationZeroSessionInstaller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceGenerationZeroSessionInstaller")
            .field("context", &self.context)
            .field("active_node_id", &self.active_node_id)
            .finish_non_exhaustive()
    }
}

impl ServiceGenerationZeroSessionInstaller {
    pub fn new(
        app_state: Arc<crate::AppState>,
        context: RelayAccessContext,
        access: Arc<VerifiedRelayAccess>,
        active_node_id: impl Into<String>,
    ) -> Self {
        Self {
            app_state,
            context,
            access,
            active_node_id: active_node_id.into(),
        }
    }
}

struct ServiceGenerationZeroInstallReceipt {
    app_state: Arc<crate::AppState>,
    session_id: SessionId,
}

#[async_trait]
impl GenerationZeroInstallReceipt for ServiceGenerationZeroInstallReceipt {
    async fn rollback(&self) -> Result<(), GenerationZeroNegotiationError> {
        let coordinator = self
            .app_state
            .relay_failover_coordinator()
            .ok_or(GenerationZeroNegotiationError::InstallationFailed)?;
        coordinator
            .terminate_security(
                &self.session_id,
                crate::relay::RelayTerminalSecurityReason::RouteEvidenceMismatch,
            )
            .await
            .map_err(|_| GenerationZeroNegotiationError::InstallationFailed)?;
        Ok(())
    }
}

#[async_trait]
impl GenerationZeroSessionInstaller for ServiceGenerationZeroSessionInstaller {
    async fn install_generation_zero(
        &self,
        proof: &GenerationZeroRouteProof,
    ) -> Result<Box<dyn GenerationZeroInstallReceipt>, GenerationZeroNegotiationError> {
        let expected_session = SessionId(self.context.session_id.clone());
        let route = self
            .access
            .route_evidence(&self.active_node_id, 0)
            .map_err(|_| GenerationZeroNegotiationError::InstallationFailed)?;
        if proof.session_id() != &expected_session
            || proof.generation() != 0
            || proof.directory_id() != route.directory_id()
            || proof.primary_node_id() != route.node_id()
            || proof.relay_url_digest() != hex_digest(route.urls_digest())
            || !proof.is_relay_to_relay()
        {
            return Err(GenerationZeroNegotiationError::RouteEvidenceMismatch);
        }
        install_connected_relay_session(
            &self.app_state,
            self.context.clone(),
            Arc::clone(&self.access),
            &self.active_node_id,
        )
        .await
        .map_err(|_| GenerationZeroNegotiationError::InstallationFailed)?;
        Ok(Box::new(ServiceGenerationZeroInstallReceipt {
            app_state: Arc::clone(&self.app_state),
            session_id: expected_session,
        }))
    }

    async fn rollback_generation_zero(
        &self,
        _proof: &GenerationZeroRouteProof,
    ) -> Result<(), GenerationZeroNegotiationError> {
        ServiceGenerationZeroInstallReceipt {
            app_state: Arc::clone(&self.app_state),
            session_id: SessionId(self.context.session_id.clone()),
        }
        .rollback()
        .await
    }
}

/// Re-checkable authority boundary used immediately before registration. A
/// coordinator-backed implementation can reject revocation or terminal state
/// changes that occurred while ICE was gathering.
#[async_trait]
pub trait GenerationZeroNegotiationAuthority: Send + Sync {
    async fn revalidate_generation_zero(
        &self,
        context: &GenerationZeroNegotiationContext,
        now_unix_ms: u64,
    ) -> Result<(), GenerationZeroNegotiationError>;
}

#[derive(Debug, Default)]
pub struct ImmutableGenerationZeroAuthority;

#[async_trait]
impl GenerationZeroNegotiationAuthority for ImmutableGenerationZeroAuthority {
    async fn revalidate_generation_zero(
        &self,
        context: &GenerationZeroNegotiationContext,
        now_unix_ms: u64,
    ) -> Result<(), GenerationZeroNegotiationError> {
        if now_unix_ms >= context.identity().deadline_unix_ms()
            || context.grant().grant_expires_at_ms() <= now_unix_ms
            || context.grant().policy_expires_at_ms() <= now_unix_ms
            || context.access().generation() != 0
        {
            return Err(GenerationZeroNegotiationError::DeadlineExceeded);
        }
        Ok(())
    }
}

/// Coordinator-backed authority used by service wiring. It reads current
/// state after ICE connection and compares all immutable grant/access
/// bindings, so revoke/terminal transitions cannot race installation.
pub struct WanSessionCoordinatorGenerationZeroAuthority {
    coordinator: Arc<super::coordinator::WanSessionCoordinator>,
}

impl fmt::Debug for WanSessionCoordinatorGenerationZeroAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionCoordinatorGenerationZeroAuthority")
            .finish_non_exhaustive()
    }
}

impl WanSessionCoordinatorGenerationZeroAuthority {
    pub fn new(coordinator: Arc<super::coordinator::WanSessionCoordinator>) -> Self {
        Self { coordinator }
    }
}

#[async_trait]
impl GenerationZeroNegotiationAuthority for WanSessionCoordinatorGenerationZeroAuthority {
    async fn revalidate_generation_zero(
        &self,
        context: &GenerationZeroNegotiationContext,
        now_unix_ms: u64,
    ) -> Result<(), GenerationZeroNegotiationError> {
        let state = self
            .coordinator
            .snapshot(context.identity().session_id())
            .await
            .map_err(|_| GenerationZeroNegotiationError::NotReady)?;
        if state.role() != context.role()
            || state.identity() != context.identity()
            || !matches!(
                state.phase(),
                WanSessionPhase::AccessBound | WanSessionPhase::Negotiating
            )
            || state.grant() != Some(context.grant())
            || state.access() != Some(context.access())
        {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        ImmutableGenerationZeroAuthority
            .revalidate_generation_zero(context, now_unix_ms)
            .await
    }
}

/// Verified immutable inputs for one generation-zero exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct GenerationZeroNegotiationContext {
    role: WanSessionRole,
    identity: WanSessionIdentity,
    grant: GrantBinding,
    access: RelayAccessBinding,
    grant_commitment: String,
}

impl fmt::Debug for GenerationZeroNegotiationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationZeroNegotiationContext")
            .field("role", &self.role)
            .field("session_id", self.identity.session_id())
            .field("grant", &"REDACTED")
            .field("access", &self.access)
            .field("grant_commitment", &"[REDACTED]")
            .finish()
    }
}

impl GenerationZeroNegotiationContext {
    /// The supplied commitment must already be bound to the installed signed
    /// grant. It is not accepted merely because it has the right shape.
    pub fn from_state(
        state: &WanSessionState,
        grant_commitment: String,
        now_unix_ms: u64,
    ) -> Result<Self, GenerationZeroNegotiationError> {
        if state.phase() != WanSessionPhase::AccessBound {
            return Err(GenerationZeroNegotiationError::NotReady);
        }
        if now_unix_ms >= state.identity().deadline_unix_ms() {
            return Err(GenerationZeroNegotiationError::DeadlineExceeded);
        }
        if !is_sha256_hex(&grant_commitment) {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        let grant = state
            .grant()
            .cloned()
            .ok_or(GenerationZeroNegotiationError::NotReady)?;
        let access = state
            .access()
            .cloned()
            .ok_or(GenerationZeroNegotiationError::NotReady)?;
        if grant.grant_commitment() != Some(grant_commitment.as_str())
            || grant.policy_revision() != access.policy_revision()
            || access.generation() != 0
            || state.identity().target_key_fingerprint().is_none()
            || grant.grant_expires_at_ms() <= now_unix_ms
            || grant.policy_expires_at_ms() <= now_unix_ms
        {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        Ok(Self {
            role: state.role(),
            identity: state.identity().clone(),
            grant,
            access,
            grant_commitment,
        })
    }

    pub fn role(&self) -> WanSessionRole {
        self.role
    }

    pub fn identity(&self) -> &WanSessionIdentity {
        &self.identity
    }

    pub fn grant(&self) -> &GrantBinding {
        &self.grant
    }

    pub fn access(&self) -> &RelayAccessBinding {
        &self.access
    }

    pub fn grant_commitment(&self) -> &str {
        &self.grant_commitment
    }

    pub fn local_device_id(&self) -> &DeviceId {
        match self.role {
            WanSessionRole::Controller => self.identity.controller_device_id(),
            WanSessionRole::Target => self.identity.target_device_id(),
        }
    }

    pub fn peer_device_id(&self) -> &DeviceId {
        match self.role {
            WanSessionRole::Controller => self.identity.target_device_id(),
            WanSessionRole::Target => self.identity.controller_device_id(),
        }
    }

    /// Build a relay-only config from the verified primary node only.
    pub fn primary_peer_config(
        &self,
        access: &VerifiedRelayAccess,
    ) -> Result<PeerConnectionConfig, GenerationZeroNegotiationError> {
        let expected_peer_digest = crate::relay::relay_peer_digest(&self.peer_device_id().0)
            .map_err(|_| GenerationZeroNegotiationError::InvalidBinding)?;
        if access.generation() != Some(0)
            || access.directory().payload().session_id != self.identity.session_id().0
            || access.directory().payload().directory_id != self.access.directory_id()
            || access.directory().payload().intended_peer_digest != expected_peer_digest
        {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        let credential = access
            .credentials_for(self.access.primary_node_id())
            .ok_or(GenerationZeroNegotiationError::InvalidBinding)?;
        let actual_digest = hex_digest(&urls_digest(&credential.urls));
        if actual_digest != self.access.relay_url_digest() {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        let route = access
            .route_evidence(self.access.primary_node_id(), 0)
            .map_err(|_| GenerationZeroNegotiationError::InvalidBinding)?;
        if route.directory_id() != self.access.directory_id()
            || route.node_id() != self.access.primary_node_id()
            || hex_digest(route.urls_digest()) != self.access.relay_url_digest()
        {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        let role = match self.role {
            WanSessionRole::Controller => PeerConnectionRole::Offerer,
            WanSessionRole::Target => PeerConnectionRole::Answerer,
        };
        Ok(credential.apply_relay_only(PeerConnectionConfig {
            role,
            ..PeerConnectionConfig::default()
        }))
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum GenerationZeroNegotiationError {
    #[error("generation-zero negotiation is not authorized")]
    NotReady,
    #[error("generation-zero negotiation binding is invalid")]
    InvalidBinding,
    #[error("generation-zero negotiation deadline exceeded")]
    DeadlineExceeded,
    #[error("generation-zero negotiation was cancelled")]
    Cancelled,
    #[error("generation-zero negotiation timed out")]
    Timeout,
    #[error("generation-zero signaling is unavailable")]
    SignalingUnavailable,
    #[error("generation-zero signaling queue is full")]
    SignalingBackpressure,
    #[error("generation-zero candidate manifest is invalid")]
    CandidateManifestMismatch,
    #[error("generation-zero candidate was duplicated")]
    CandidateDuplicate,
    #[error("generation-zero candidate has the wrong role or peer")]
    CandidateWrongRole,
    #[error("generation-zero transport is unavailable")]
    TransportUnavailable,
    #[error("generation-zero relay route evidence is invalid")]
    RouteEvidenceMismatch,
    #[error("generation-zero session installation failed")]
    InstallationFailed,
    #[error("generation-zero negotiation is already owned by another task")]
    AlreadyOwned,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GenerationZeroNegotiationResult {
    proof: GenerationZeroRouteProof,
}

impl fmt::Debug for GenerationZeroNegotiationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationZeroNegotiationResult")
            .field("proof", &self.proof)
            .finish()
    }
}

impl GenerationZeroNegotiationResult {
    pub fn proof(&self) -> &GenerationZeroRouteProof {
        &self.proof
    }
}

/// Bounded, role-aware generation-zero executor.
pub struct GenerationZeroNegotiator {
    host: Arc<dyn GenerationZeroWebRtcHost>,
    signaling: Arc<dyn GenerationZeroSignaling>,
    installer: Arc<dyn GenerationZeroSessionInstaller>,
    authority: Arc<dyn GenerationZeroNegotiationAuthority>,
    coordinator: Option<Arc<super::coordinator::WanSessionCoordinator>>,
    authorization_gate: Option<Arc<tokio::sync::Mutex<()>>>,
    clock: Arc<dyn GenerationZeroClock>,
    timeout: Duration,
    ownership_scope: usize,
}

/// Clock used for signed-message freshness checks.  Production uses the
/// system clock; tests can inject a deterministic clock without weakening
/// expiry validation.
pub trait GenerationZeroClock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

/// The ownership fence is process-wide but scoped to one service host (or its
/// authoritative coordinator). This keeps duplicate IPC-created negotiators
/// mutually exclusive without making independent service instances collide.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GenerationZeroOwnershipKey {
    scope: usize,
    session_id: SessionId,
}

static GENERATION_ZERO_OWNERS: OnceLock<StdMutex<HashSet<GenerationZeroOwnershipKey>>> =
    OnceLock::new();

fn generation_zero_owners() -> &'static StdMutex<HashSet<GenerationZeroOwnershipKey>> {
    GENERATION_ZERO_OWNERS.get_or_init(|| StdMutex::new(HashSet::new()))
}

struct GenerationZeroOwnershipLease {
    key: GenerationZeroOwnershipKey,
}

impl Drop for GenerationZeroOwnershipLease {
    fn drop(&mut self) {
        let mut owners = generation_zero_owners()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners.remove(&self.key);
    }
}

fn claim_generation_zero_ownership(
    scope: usize,
    session_id: &SessionId,
) -> Result<GenerationZeroOwnershipLease, GenerationZeroNegotiationError> {
    let key = GenerationZeroOwnershipKey {
        scope,
        session_id: session_id.clone(),
    };
    let mut owners = generation_zero_owners()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !owners.insert(key.clone()) {
        return Err(GenerationZeroNegotiationError::AlreadyOwned);
    }
    Ok(GenerationZeroOwnershipLease { key })
}

#[derive(Debug, Default)]
pub struct SystemGenerationZeroClock;

impl GenerationZeroClock for SystemGenerationZeroClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }
}

impl fmt::Debug for GenerationZeroNegotiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenerationZeroNegotiator")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl GenerationZeroNegotiator {
    pub fn new(
        host: Arc<dyn GenerationZeroWebRtcHost>,
        signaling: Arc<dyn GenerationZeroSignaling>,
        installer: Arc<dyn GenerationZeroSessionInstaller>,
        timeout: Duration,
    ) -> Result<Self, GenerationZeroNegotiationError> {
        if !(MIN_NEGOTIATION_TIMEOUT..=MAX_NEGOTIATION_TIMEOUT).contains(&timeout) {
            return Err(GenerationZeroNegotiationError::InvalidBinding);
        }
        let ownership_scope = Arc::as_ptr(&host) as *const () as usize;
        Ok(Self {
            host,
            signaling,
            installer,
            authority: Arc::new(ImmutableGenerationZeroAuthority),
            coordinator: None,
            authorization_gate: None,
            clock: Arc::new(SystemGenerationZeroClock),
            timeout,
            ownership_scope,
        })
    }

    pub fn with_clock(mut self, clock: Arc<dyn GenerationZeroClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_authority(
        mut self,
        authority: Arc<dyn GenerationZeroNegotiationAuthority>,
    ) -> Self {
        self.authority = authority;
        self
    }

    pub fn with_coordinator(
        mut self,
        coordinator: Arc<super::coordinator::WanSessionCoordinator>,
    ) -> Self {
        self.ownership_scope = Arc::as_ptr(&coordinator) as usize;
        self.coordinator = Some(coordinator);
        self
    }

    pub fn with_authorization_gate(
        mut self,
        authorization_gate: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        self.authorization_gate = Some(authorization_gate);
        self
    }

    /// Build the service-owned executor with the concrete host, authenticated
    /// signaling bus, coordinator authority, and post-proof relay installer.
    /// Callers must supply the already verified access and its exact route
    /// context; this factory never selects a fallback node.
    pub fn for_service(
        app_state: Arc<crate::AppState>,
        coordinator: Arc<super::coordinator::WanSessionCoordinator>,
        access: Arc<VerifiedRelayAccess>,
        context: RelayAccessContext,
        active_node_id: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, GenerationZeroNegotiationError> {
        let installer = Arc::new(ServiceGenerationZeroSessionInstaller::new(
            Arc::clone(&app_state),
            context,
            access,
            active_node_id,
        ));
        let authority = Arc::new(WanSessionCoordinatorGenerationZeroAuthority::new(
            Arc::clone(&coordinator),
        ));
        Self::new(
            app_state.webrtc_host.clone(),
            app_state.relay_signaling.clone(),
            installer,
            timeout,
        )
        .map(|negotiator| {
            negotiator
                .with_authority(authority)
                .with_coordinator(coordinator)
                .with_authorization_gate(Arc::clone(&app_state.authorization_security_gate))
        })
    }

    pub async fn negotiate(
        &self,
        context: GenerationZeroNegotiationContext,
        relay_access: &VerifiedRelayAccess,
    ) -> Result<GenerationZeroNegotiationResult, GenerationZeroNegotiationError> {
        let (_, cancellation) = watch::channel(false);
        self.negotiate_with_cancellation(context, relay_access, cancellation)
            .await
    }

    pub async fn negotiate_with_cancellation(
        &self,
        context: GenerationZeroNegotiationContext,
        relay_access: &VerifiedRelayAccess,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<GenerationZeroNegotiationResult, GenerationZeroNegotiationError> {
        let session_id = context.identity.session_id().clone();
        let effective_timeout = self.effective_timeout(&context, relay_access)?;
        let mut opened = false;
        let mut owns_session = false;
        let mut ownership_lease = None;
        let install_proof = Arc::new(Mutex::new(None::<GenerationZeroRouteProof>));
        let install_receipt = Arc::new(Mutex::new(None::<Box<dyn GenerationZeroInstallReceipt>>));
        let timed = tokio::time::timeout(effective_timeout, async {
            let config = context.primary_peer_config(relay_access)?;
            self.authority
                .revalidate_generation_zero(&context, self.clock.now_unix_ms())
                .await?;
            ownership_lease = Some(claim_generation_zero_ownership(
                self.ownership_scope,
                &session_id,
            )?);
            owns_session = true;

            // Subscribe before opening/signaling so an immediate
            // answer/candidate cannot race the receiver.
            let mut inbound = Arc::clone(&self.signaling)
                .subscribe(session_id.clone(), context.peer_device_id().clone());
            let cancellation_fence = cancellation.clone();
            let operation = async {
                if let Some(coordinator) = &self.coordinator {
                    coordinator
                        .begin_negotiation(&session_id)
                        .await
                        .map_err(map_coordinator_error)?;
                }
                let proof = match context.role() {
                    WanSessionRole::Controller => {
                        self.host
                            .open_generation_zero(&session_id, config.clone())
                            .await
                            .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
                        opened = true;
                        self.negotiate_controller(&context, relay_access, inbound.as_mut())
                            .await
                    }
                    WanSessionRole::Target => {
                        self.negotiate_target(
                            &context,
                            relay_access,
                            config,
                            inbound.as_mut(),
                            &mut opened,
                        )
                        .await
                    }
                }?;
                if proof.session_id() != &session_id
                    || proof.generation() != 0
                    || proof.directory_id() != context.access.directory_id()
                    || proof.primary_node_id() != context.access.primary_node_id()
                    || proof.relay_url_digest() != context.access.relay_url_digest()
                    || !proof.is_relay_to_relay()
                {
                    return Err(GenerationZeroNegotiationError::RouteEvidenceMismatch);
                }
                let _authorization_guard = match &self.authorization_gate {
                    Some(gate) => Some(gate.lock().await),
                    None => None,
                };
                self.authority
                    .revalidate_generation_zero(&context, self.clock.now_unix_ms())
                    .await?;
                if let Some(coordinator) = &self.coordinator {
                    let model_proof =
                        RelayRouteProof::from_verified_access(context.access(), true, true)
                            .map_err(|_| GenerationZeroNegotiationError::RouteEvidenceMismatch)?;
                    let installer = Arc::clone(&self.installer);
                    let proof_for_install = proof.clone();
                    let install_proof = Arc::clone(&install_proof);
                    let install_receipt = Arc::clone(&install_receipt);
                    coordinator
                        .commit_generation_zero(
                            &session_id,
                            context.role(),
                            context.identity(),
                            context.grant(),
                            context.access(),
                            model_proof,
                            move || async move {
                                install_proof.lock().await.replace(proof_for_install.clone());
                                let receipt = installer
                                    .install_generation_zero(&proof_for_install)
                                    .await
                                    .map_err(|_| {
                                        super::coordinator::WanSessionCoordinatorError::CleanupFailed
                                    })?;
                                install_receipt.lock().await.replace(receipt);
                                Ok(())
                            },
                        )
                        .await
                        .map_err(map_coordinator_error)?;
                } else {
                    install_proof.lock().await.replace(proof.clone());
                    let receipt = self.installer.install_generation_zero(&proof).await?;
                    install_receipt.lock().await.replace(receipt);
                    self.authority
                        .revalidate_generation_zero(&context, self.clock.now_unix_ms())
                        .await?;
                }
                if *cancellation_fence.borrow() {
                    return Err(GenerationZeroNegotiationError::Cancelled);
                }
                Ok(GenerationZeroNegotiationResult { proof })
            };
            tokio::select! {
                biased;
                result = operation => result,
                _ = wait_for_cancellation(&mut cancellation) => {
                    Err(GenerationZeroNegotiationError::Cancelled)
                }
            }
        })
        .await;
        let result = match timed {
            Ok(result) => result,
            Err(_) => Err(GenerationZeroNegotiationError::Timeout),
        };
        if result.is_err() {
            let proof_for_rollback = install_proof.lock().await.take();
            let receipt_for_rollback = install_receipt.lock().await.take();
            let rollback_failed = if let Some(receipt) = receipt_for_rollback {
                receipt.rollback().await.is_err()
            } else {
                true
            };
            if rollback_failed {
                if let Some(proof) = proof_for_rollback.as_ref() {
                    let _ = self.installer.rollback_generation_zero(proof).await;
                }
            }
        }
        if result.is_err() && opened {
            let _ = self.host.close_session(&session_id).await;
        }
        // A service-built negotiator carries the shared authorization gate;
        // its wrapper must perform coordinator failure, cleanup, authorization,
        // and IPC projection as one terminalization operation. Standalone
        // coordinator-backed executors retain their self-terminalizing behavior.
        if result.is_err()
            && owns_session
            && self.coordinator.is_some()
            && self.authorization_gate.is_none()
        {
            if let Some(coordinator) = &self.coordinator {
                let still_live = coordinator
                    .snapshot(&session_id)
                    .await
                    .is_ok_and(|state| !state.phase().is_terminal());
                if still_live {
                    let failure = result
                        .as_ref()
                        .err()
                        .map_or(WanSessionFailure::Transport, negotiation_failure);
                    let _ = coordinator.fail(&session_id, failure).await;
                }
            }
        }
        drop(ownership_lease);
        result
    }

    fn effective_timeout(
        &self,
        context: &GenerationZeroNegotiationContext,
        relay_access: &VerifiedRelayAccess,
    ) -> Result<Duration, GenerationZeroNegotiationError> {
        let now = self.clock.now_unix_ms();
        let deadlines = [
            context.identity().deadline_unix_ms(),
            context.grant().grant_expires_at_ms(),
            context.grant().policy_expires_at_ms(),
            relay_access.directory().payload().expires_at_ms,
        ];
        let deadline = deadlines
            .into_iter()
            .min()
            .ok_or(GenerationZeroNegotiationError::DeadlineExceeded)?;
        if now >= deadline {
            return Err(GenerationZeroNegotiationError::DeadlineExceeded);
        }
        let remaining_ms = deadline - now;
        let configured_ms = self.timeout.as_millis().min(u64::MAX as u128) as u64;
        let effective_ms = configured_ms.min(remaining_ms);
        if effective_ms == 0 {
            return Err(GenerationZeroNegotiationError::DeadlineExceeded);
        }
        Ok(Duration::from_millis(effective_ms))
    }

    async fn negotiate_controller(
        &self,
        context: &GenerationZeroNegotiationContext,
        relay_access: &VerifiedRelayAccess,
        inbound: &mut dyn GenerationZeroSignalingSubscription,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroNegotiationError> {
        let session_id = context.identity.session_id();
        let offer = self
            .host
            .create_offer(session_id)
            .await
            .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
        if offer.kind != SessionDescriptionType::Offer || offer.generation() != 0 {
            return Err(GenerationZeroNegotiationError::TransportUnavailable);
        }
        let local_candidates = self.collect_local_candidates(context).await?;
        self.send_description(
            context,
            WebRtcDescriptionRoleV3::Offer,
            &offer,
            &local_candidates,
        )
        .await?;
        self.send_candidates(context, WebRtcDescriptionRoleV3::Offer, &local_candidates)
            .await?;

        let mut replay = GenerationZeroReplayWindow::new(MAX_GENERATION_ZERO_CANDIDATES * 4);
        let (answer, buffered) = self
            .receive_description_and_candidates(
                context,
                WebRtcDescriptionRoleV3::Answer,
                inbound,
                &mut replay,
            )
            .await?;
        let answer = SessionDescription::from_wire(SessionDescriptionType::Answer, answer, 0, None)
            .map_err(|_| GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        self.host
            .accept_answer(session_id, answer)
            .await
            .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
        self.apply_remote_candidates(context, buffered).await?;
        self.finish_route_proof(context, relay_access).await
    }

    async fn negotiate_target(
        &self,
        context: &GenerationZeroNegotiationContext,
        relay_access: &VerifiedRelayAccess,
        config: PeerConnectionConfig,
        inbound: &mut dyn GenerationZeroSignalingSubscription,
        opened: &mut bool,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroNegotiationError> {
        let mut replay = GenerationZeroReplayWindow::new(MAX_GENERATION_ZERO_CANDIDATES * 4);
        let (offer, buffered) = self
            .receive_description_and_candidates(
                context,
                WebRtcDescriptionRoleV3::Offer,
                inbound,
                &mut replay,
            )
            .await?;
        let offer = SessionDescription::from_wire(SessionDescriptionType::Offer, offer, 0, None)
            .map_err(|_| GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        self.host
            .open_generation_zero(context.identity().session_id(), config)
            .await
            .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
        *opened = true;
        let answer = self
            .host
            .accept_offer(context.identity().session_id(), offer)
            .await
            .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
        if answer.kind != SessionDescriptionType::Answer || answer.generation() != 0 {
            return Err(GenerationZeroNegotiationError::TransportUnavailable);
        }
        self.apply_remote_candidates(context, buffered).await?;
        let local_candidates = self.collect_local_candidates(context).await?;
        self.send_description(
            context,
            WebRtcDescriptionRoleV3::Answer,
            &answer,
            &local_candidates,
        )
        .await?;
        self.send_candidates(context, WebRtcDescriptionRoleV3::Answer, &local_candidates)
            .await?;
        self.finish_route_proof(context, relay_access).await
    }

    async fn collect_local_candidates(
        &self,
        context: &GenerationZeroNegotiationContext,
    ) -> Result<BTreeMap<String, IceCandidate>, GenerationZeroNegotiationError> {
        let mut candidates = BTreeMap::new();
        loop {
            let candidate = self
                .host
                .next_local_candidate(context.identity().session_id())
                .await
                .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
            let Some(candidate) = candidate else { break };
            if candidate.generation() != 0 || candidate.restart_route_token().is_some() {
                return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
            }
            if candidates.len() >= MAX_GENERATION_ZERO_CANDIDATES {
                return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
            }
            let role = match context.role() {
                WanSessionRole::Controller => WebRtcDescriptionRoleV3::Offer,
                WanSessionRole::Target => WebRtcDescriptionRoleV3::Answer,
            };
            let fingerprint = webrtc_candidate_fingerprint_v3(
                context.identity().session_id(),
                context.grant_commitment(),
                role,
                &candidate.candidate,
                candidate.sdp_mid.as_deref(),
                candidate.sdp_mline_index,
                candidate.username_fragment.as_deref(),
            );
            if candidates.insert(fingerprint, candidate).is_some() {
                return Err(GenerationZeroNegotiationError::CandidateDuplicate);
            }
        }
        if candidates.is_empty() {
            return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
        }
        Ok(candidates)
    }

    async fn send_description(
        &self,
        context: &GenerationZeroNegotiationContext,
        role: WebRtcDescriptionRoleV3,
        description: &SessionDescription,
        candidates: &BTreeMap<String, IceCandidate>,
    ) -> Result<(), GenerationZeroNegotiationError> {
        let fingerprints = candidates.keys().cloned().collect::<Vec<_>>();
        let signal = match role {
            WebRtcDescriptionRoleV3::Offer => OutboundAuthenticatedSessionSignal::WebRtcOffer {
                session_id: context.identity().session_id().clone(),
                controller_device_id: context.identity().controller_device_id().clone(),
                target_device_id: context.identity().target_device_id().clone(),
                grant_commitment: context.grant_commitment().to_owned(),
                sdp: description.sdp.clone(),
                candidate_fingerprints: fingerprints,
            },
            WebRtcDescriptionRoleV3::Answer => OutboundAuthenticatedSessionSignal::WebRtcAnswer {
                session_id: context.identity().session_id().clone(),
                controller_device_id: context.identity().controller_device_id().clone(),
                target_device_id: context.identity().target_device_id().clone(),
                grant_commitment: context.grant_commitment().to_owned(),
                sdp: description.sdp.clone(),
                candidate_fingerprints: fingerprints,
            },
        };
        self.send(context, signal).await
    }

    async fn send_candidates(
        &self,
        context: &GenerationZeroNegotiationContext,
        role: WebRtcDescriptionRoleV3,
        candidates: &BTreeMap<String, IceCandidate>,
    ) -> Result<(), GenerationZeroNegotiationError> {
        for (fingerprint, candidate) in candidates {
            self.send(
                context,
                OutboundAuthenticatedSessionSignal::WebRtcCandidate {
                    session_id: context.identity().session_id().clone(),
                    controller_device_id: context.identity().controller_device_id().clone(),
                    target_device_id: context.identity().target_device_id().clone(),
                    grant_commitment: context.grant_commitment().to_owned(),
                    description_role: role,
                    candidate: candidate.candidate.clone(),
                    sdp_mid: candidate.sdp_mid.clone(),
                    sdp_mline_index: candidate.sdp_mline_index,
                    username_fragment: candidate.username_fragment.clone(),
                    candidate_fingerprint: fingerprint.clone(),
                },
            )
            .await?;
        }
        Ok(())
    }

    async fn send(
        &self,
        context: &GenerationZeroNegotiationContext,
        signal: OutboundAuthenticatedSessionSignal,
    ) -> Result<(), GenerationZeroNegotiationError> {
        self.signaling
            .send(AuthenticatedSessionSignalingCommand {
                peer_device_id: context.peer_device_id().clone(),
                signal,
            })
            .await
            .map_err(map_signaling_error)
    }

    async fn receive_description_and_candidates(
        &self,
        context: &GenerationZeroNegotiationContext,
        expected_role: WebRtcDescriptionRoleV3,
        inbound: &mut dyn GenerationZeroSignalingSubscription,
        replay: &mut GenerationZeroReplayWindow,
    ) -> Result<(String, BTreeMap<String, WebRtcCandidateV3>), GenerationZeroNegotiationError> {
        let mut buffered = BTreeMap::new();
        loop {
            let event = inbound.recv().await.map_err(map_signaling_error)?;
            match event.signal {
                AuthenticatedSessionSignal::WebRtcOfferV3 { message }
                    if expected_role == WebRtcDescriptionRoleV3::Offer =>
                {
                    self.validate_description_event(
                        context,
                        expected_role,
                        &event.sender,
                        &message,
                        replay,
                    )?;
                    let expected = message
                        .payload
                        .candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>();
                    if expected.len() != message.payload.candidate_fingerprints.len() {
                        return Err(GenerationZeroNegotiationError::CandidateDuplicate);
                    }
                    return self
                        .receive_candidates(
                            context,
                            expected_role,
                            expected,
                            buffered,
                            inbound,
                            message.payload.sdp,
                            replay,
                        )
                        .await;
                }
                AuthenticatedSessionSignal::WebRtcAnswerV3 { message }
                    if expected_role == WebRtcDescriptionRoleV3::Answer =>
                {
                    self.validate_description_event(
                        context,
                        expected_role,
                        &event.sender,
                        &message,
                        replay,
                    )?;
                    let expected = message
                        .payload
                        .candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>();
                    if expected.len() != message.payload.candidate_fingerprints.len() {
                        return Err(GenerationZeroNegotiationError::CandidateDuplicate);
                    }
                    return self
                        .receive_candidates(
                            context,
                            expected_role,
                            expected,
                            buffered,
                            inbound,
                            message.payload.sdp,
                            replay,
                        )
                        .await;
                }
                AuthenticatedSessionSignal::WebRtcCandidateV3 { message } => {
                    self.validate_candidate_event(
                        context,
                        expected_role,
                        &event.sender,
                        &message,
                        replay,
                    )?;
                    let fingerprint = message.payload.candidate_fingerprint.clone();
                    if buffered.len() >= MAX_GENERATION_ZERO_CANDIDATES
                        || buffered.insert(fingerprint, message).is_some()
                    {
                        return Err(GenerationZeroNegotiationError::CandidateDuplicate);
                    }
                }
                AuthenticatedSessionSignal::SessionIntentV3 { .. }
                | AuthenticatedSessionSignal::SessionGrantV3 { .. } => continue,
                _ => return Err(GenerationZeroNegotiationError::CandidateWrongRole),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn receive_candidates(
        &self,
        context: &GenerationZeroNegotiationContext,
        expected_role: WebRtcDescriptionRoleV3,
        expected: BTreeSet<String>,
        mut buffered: BTreeMap<String, WebRtcCandidateV3>,
        inbound: &mut dyn GenerationZeroSignalingSubscription,
        sdp: String,
        replay: &mut GenerationZeroReplayWindow,
    ) -> Result<(String, BTreeMap<String, WebRtcCandidateV3>), GenerationZeroNegotiationError> {
        if expected.is_empty() || expected.len() > MAX_GENERATION_ZERO_CANDIDATES {
            return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
        }
        while buffered.len() < expected.len() {
            let event = inbound.recv().await.map_err(map_signaling_error)?;
            let message = match event.signal {
                AuthenticatedSessionSignal::WebRtcCandidateV3 { message } => message,
                AuthenticatedSessionSignal::SessionIntentV3 { .. }
                | AuthenticatedSessionSignal::SessionGrantV3 { .. } => continue,
                _ => return Err(GenerationZeroNegotiationError::CandidateWrongRole),
            };
            self.validate_candidate_event(context, expected_role, &event.sender, &message, replay)?;
            let fingerprint = message.payload.candidate_fingerprint.clone();
            if !expected.contains(&fingerprint) {
                return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
            }
            if buffered.insert(fingerprint, message).is_some() {
                return Err(GenerationZeroNegotiationError::CandidateDuplicate);
            }
        }
        if buffered.keys().collect::<BTreeSet<_>>() != expected.iter().collect::<BTreeSet<_>>() {
            return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
        }
        // A scoped receiver can contain history records or receive a late
        // candidate immediately after the final manifest item. Keep a small,
        // explicit quiescence window instead of treating one empty
        // `try_recv` result as end-of-stream. The window is bounded by the
        // caller's outer negotiation timeout.
        let quiescence_deadline = tokio::time::Instant::now() + GENERATION_ZERO_QUIESCENCE;
        loop {
            let remaining =
                quiescence_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok((sdp, buffered));
            }
            let event = match tokio::time::timeout(remaining, inbound.recv()).await {
                Ok(event) => event.map_err(map_signaling_error)?,
                Err(_) => return Ok((sdp, buffered)),
            };
            match event.signal {
                AuthenticatedSessionSignal::SessionIntentV3 { .. }
                | AuthenticatedSessionSignal::SessionGrantV3 { .. } => continue,
                AuthenticatedSessionSignal::WebRtcCandidateV3 { message } => {
                    self.validate_candidate_event(
                        context,
                        expected_role,
                        &event.sender,
                        &message,
                        replay,
                    )?;
                    if expected.contains(&message.payload.candidate_fingerprint) {
                        return Err(GenerationZeroNegotiationError::CandidateDuplicate);
                    }
                    return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
                }
                _ => return Err(GenerationZeroNegotiationError::CandidateWrongRole),
            }
        }
    }

    fn validate_description_event<T>(
        &self,
        context: &GenerationZeroNegotiationContext,
        expected_role: WebRtcDescriptionRoleV3,
        sender: &VerifiedSignalingIdentity,
        message: &SignedSignal<T>,
        replay: &mut GenerationZeroReplayWindow,
    ) -> Result<(), GenerationZeroNegotiationError>
    where
        T: AuthenticatedPayload,
    {
        message
            .payload
            .validate_payload()
            .map_err(|_| GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let claims = message.payload.claims();
        let local = context.local_device_id();
        let peer = context.peer_device_id();
        let expected_issuer = match expected_role {
            WebRtcDescriptionRoleV3::Offer => context.identity().controller_device_id(),
            WebRtcDescriptionRoleV3::Answer => context.identity().target_device_id(),
        };
        let expected_peer_key = match context.role() {
            WanSessionRole::Controller => context
                .identity()
                .target_key_fingerprint()
                .ok_or(GenerationZeroNegotiationError::InvalidBinding)?,
            WanSessionRole::Target => context.identity().controller_key_fingerprint(),
        };
        match verify_generation_zero_signal(message, local, self.clock.now_unix_ms(), replay) {
            Ok(()) => {}
            Err(GenerationZeroVerificationFailure::Duplicate) => {
                return Err(GenerationZeroNegotiationError::CandidateDuplicate)
            }
            Err(GenerationZeroVerificationFailure::Invalid) => {
                return Err(GenerationZeroNegotiationError::CandidateWrongRole)
            }
        }
        if sender.device_id != *peer
            || sender.key_id != expected_peer_key
            || sender.key_id != claims.issuer_key_id
            || claims.issuer_key_id != expected_peer_key
            || sender.public_key != message.signer_public_key
            || sender.counter != claims.counter
            || sender.nonce != claims.nonce
            || sender.issued_at_ms != claims.issued_at_ms
            || sender.expires_at_ms != claims.expires_at_ms
            || claims.issuer_device_id != *expected_issuer
            || claims.intended_peer_device_id != *local
        {
            return Err(GenerationZeroNegotiationError::CandidateWrongRole);
        }
        let payload = serde_json::to_value(&message.payload)
            .map_err(|_| GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let object = payload
            .as_object()
            .ok_or(GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let session = object
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let controller = object
            .get("controller_device_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let target = object
            .get("target_device_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let grant = object
            .get("grant_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or(GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        if session != context.identity().session_id().0
            || controller != context.identity().controller_device_id().0
            || target != context.identity().target_device_id().0
            || grant != context.grant_commitment()
        {
            return Err(GenerationZeroNegotiationError::CandidateManifestMismatch);
        }
        Ok(())
    }

    fn validate_candidate_event(
        &self,
        context: &GenerationZeroNegotiationContext,
        expected_role: WebRtcDescriptionRoleV3,
        sender: &VerifiedSignalingIdentity,
        message: &WebRtcCandidateV3,
        replay: &mut GenerationZeroReplayWindow,
    ) -> Result<(), GenerationZeroNegotiationError> {
        message
            .payload
            .validate_payload()
            .map_err(|_| GenerationZeroNegotiationError::CandidateManifestMismatch)?;
        let payload = &message.payload;
        let claims = &payload.claims;
        let expected_issuer = match expected_role {
            WebRtcDescriptionRoleV3::Offer => context.identity().controller_device_id(),
            WebRtcDescriptionRoleV3::Answer => context.identity().target_device_id(),
        };
        let expected_peer_key = match context.role() {
            WanSessionRole::Controller => context
                .identity()
                .target_key_fingerprint()
                .ok_or(GenerationZeroNegotiationError::InvalidBinding)?,
            WanSessionRole::Target => context.identity().controller_key_fingerprint(),
        };
        match verify_generation_zero_signal(
            message,
            context.local_device_id(),
            self.clock.now_unix_ms(),
            replay,
        ) {
            Ok(()) => {}
            Err(GenerationZeroVerificationFailure::Duplicate) => {
                return Err(GenerationZeroNegotiationError::CandidateDuplicate)
            }
            Err(GenerationZeroVerificationFailure::Invalid) => {
                return Err(GenerationZeroNegotiationError::CandidateWrongRole)
            }
        }
        if sender.device_id != *context.peer_device_id()
            || sender.key_id != claims.issuer_key_id
            || sender.key_id != expected_peer_key
            || claims.issuer_key_id != expected_peer_key
            || sender.public_key != message.signer_public_key
            || sender.counter != claims.counter
            || sender.nonce != claims.nonce
            || sender.issued_at_ms != claims.issued_at_ms
            || sender.expires_at_ms != claims.expires_at_ms
            || payload.session_id != *context.identity().session_id()
            || payload.controller_device_id != *context.identity().controller_device_id()
            || payload.target_device_id != *context.identity().target_device_id()
            || payload.grant_commitment != context.grant_commitment()
            || payload.description_role != expected_role
            || claims.issuer_device_id != *expected_issuer
            || claims.intended_peer_device_id != *context.local_device_id()
        {
            return Err(GenerationZeroNegotiationError::CandidateWrongRole);
        }
        Ok(())
    }

    async fn apply_remote_candidates(
        &self,
        context: &GenerationZeroNegotiationContext,
        candidates: BTreeMap<String, WebRtcCandidateV3>,
    ) -> Result<(), GenerationZeroNegotiationError> {
        for (_, message) in candidates {
            let candidate = &message.payload;
            let candidate = IceCandidate::from_wire(
                candidate.candidate.clone(),
                candidate.sdp_mid.clone(),
                candidate.sdp_mline_index,
                candidate.username_fragment.clone(),
                0,
                None,
            )
            .map_err(|_| GenerationZeroNegotiationError::CandidateManifestMismatch)?;
            self.host
                .add_remote_candidate(context.identity().session_id(), candidate)
                .await
                .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
        }
        Ok(())
    }

    async fn finish_route_proof(
        &self,
        context: &GenerationZeroNegotiationContext,
        relay_access: &VerifiedRelayAccess,
    ) -> Result<GenerationZeroRouteProof, GenerationZeroNegotiationError> {
        self.host
            .wait_connected(context.identity().session_id())
            .await
            .map_err(|_| GenerationZeroNegotiationError::TransportUnavailable)?;
        let route = relay_access
            .route_evidence(context.access().primary_node_id(), 0)
            .map_err(|_| GenerationZeroNegotiationError::RouteEvidenceMismatch)?;
        self.host
            .prove_generation_zero_route(&route, context.identity().session_id())
            .await
            .map_err(|_| GenerationZeroNegotiationError::RouteEvidenceMismatch)
    }
}

fn map_relay_send_error(
    error: AuthenticatedSessionSignalingSendError,
) -> GenerationZeroSignalingError {
    match error {
        AuthenticatedSessionSignalingSendError::Backpressure => {
            GenerationZeroSignalingError::Backpressure
        }
        AuthenticatedSessionSignalingSendError::Unavailable
        | AuthenticatedSessionSignalingSendError::SessionClosed
        | AuthenticatedSessionSignalingSendError::Invalid => {
            GenerationZeroSignalingError::Unavailable
        }
    }
}

fn map_relay_receive_error(
    error: AuthenticatedSessionSignalingReceiveError,
) -> GenerationZeroSignalingError {
    match error {
        AuthenticatedSessionSignalingReceiveError::SessionClosed
        | AuthenticatedSessionSignalingReceiveError::Closed => GenerationZeroSignalingError::Closed,
        AuthenticatedSessionSignalingReceiveError::Lagged => GenerationZeroSignalingError::Lagged,
    }
}

fn map_signaling_error(error: GenerationZeroSignalingError) -> GenerationZeroNegotiationError {
    match error {
        GenerationZeroSignalingError::Backpressure => {
            GenerationZeroNegotiationError::SignalingBackpressure
        }
        GenerationZeroSignalingError::Unavailable
        | GenerationZeroSignalingError::Closed
        | GenerationZeroSignalingError::Lagged => {
            GenerationZeroNegotiationError::SignalingUnavailable
        }
    }
}

fn map_coordinator_error(
    error: super::coordinator::WanSessionCoordinatorError,
) -> GenerationZeroNegotiationError {
    match error {
        super::coordinator::WanSessionCoordinatorError::DeadlineExceeded => {
            GenerationZeroNegotiationError::DeadlineExceeded
        }
        super::coordinator::WanSessionCoordinatorError::RoleOrPhaseMismatch
        | super::coordinator::WanSessionCoordinatorError::BackendBindingMismatch
        | super::coordinator::WanSessionCoordinatorError::SessionTerminal
        | super::coordinator::WanSessionCoordinatorError::SessionNotFound => {
            GenerationZeroNegotiationError::InvalidBinding
        }
        _ => GenerationZeroNegotiationError::InstallationFailed,
    }
}

fn negotiation_failure(error: &GenerationZeroNegotiationError) -> WanSessionFailure {
    match error {
        GenerationZeroNegotiationError::DeadlineExceeded
        | GenerationZeroNegotiationError::Timeout => WanSessionFailure::DeadlineExceeded,
        GenerationZeroNegotiationError::Cancelled => WanSessionFailure::Cancelled,
        GenerationZeroNegotiationError::CandidateManifestMismatch
        | GenerationZeroNegotiationError::CandidateDuplicate
        | GenerationZeroNegotiationError::CandidateWrongRole
        | GenerationZeroNegotiationError::RouteEvidenceMismatch => WanSessionFailure::RouteMismatch,
        GenerationZeroNegotiationError::InvalidBinding
        | GenerationZeroNegotiationError::NotReady
        | GenerationZeroNegotiationError::SignalingUnavailable
        | GenerationZeroNegotiationError::SignalingBackpressure
        | GenerationZeroNegotiationError::TransportUnavailable
        | GenerationZeroNegotiationError::InstallationFailed
        | GenerationZeroNegotiationError::AlreadyOwned => WanSessionFailure::Transport,
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn hex_digest(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn wait_for_cancellation(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() {
            return;
        }
        if receiver.changed().await.is_err() {
            // A dropped sender means the caller did not request cancellation
            // (the convenience `negotiate` API intentionally drops its
            // private sender).  Keep waiting; the enclosing operation timeout
            // remains responsible for cleanup.
            std::future::pending::<()>().await;
        }
    }
}
