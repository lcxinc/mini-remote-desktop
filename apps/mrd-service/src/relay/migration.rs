//! Session failover state machine and WebRTC replacement integration.

use super::client::{
    RelayAccessContext, RelayClientError, RelayClock, RelayDirectoryClient, RelayRouteEvidence,
    VerifiedRelayAccess,
};
use crate::{control_input::ControlInputRegistry, AppState};
use async_trait::async_trait;
use mrd_application::{
    ports::TransportMuxPort, AuthenticatedSessionSignal, VerifiedSignalingEvent,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_relay_control::RelayDirectoryError;
use mrd_transport_webrtc::{PeerConnectionConfig, PeerConnectionRole};
use std::{collections::HashMap, fmt, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::{watch, Mutex};
use zeroize::Zeroize;

#[async_trait]
pub trait RelayAccessProvider: Send + Sync {
    async fn refresh_access(
        &self,
        context: &RelayAccessContext,
    ) -> Result<Arc<VerifiedRelayAccess>, RelayClientError>;
}

#[async_trait]
impl RelayAccessProvider for RelayDirectoryClient {
    async fn refresh_access(
        &self,
        context: &RelayAccessContext,
    ) -> Result<Arc<VerifiedRelayAccess>, RelayClientError> {
        self.refresh(context.clone()).await
    }
}

#[async_trait]
pub trait RelayInputBarrier: Send + Sync {
    async fn freeze_after_release(&self, session_id: &SessionId) -> Result<(), ()>;
    async fn thaw(&self, session_id: &SessionId);
    async fn is_frozen(&self, session_id: &SessionId) -> bool;
}

pub struct ServiceRelayInputBarrier {
    registry: Arc<Mutex<ControlInputRegistry>>,
}

impl ServiceRelayInputBarrier {
    pub fn new(app_state: &AppState) -> Self {
        Self {
            registry: app_state.control_input(),
        }
    }
}

#[async_trait]
impl RelayInputBarrier for ServiceRelayInputBarrier {
    async fn freeze_after_release(&self, session_id: &SessionId) -> Result<(), ()> {
        self.registry
            .lock()
            .await
            .freeze_session_for_migration(session_id)
            .map(|_| ())
            .map_err(|_| ())
    }

    async fn thaw(&self, session_id: &SessionId) {
        self.registry
            .lock()
            .await
            .thaw_session_after_migration(session_id);
    }

    async fn is_frozen(&self, session_id: &SessionId) -> bool {
        self.registry
            .lock()
            .await
            .session_is_migration_frozen(session_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionHealth {
    Connected,
    Disconnected,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTerminalSecurityReason {
    GrantExpired,
    PolicyChanged,
    RelayRevoked,
    SignatureInvalid,
    IdentityMismatch,
    RouteEvidenceMismatch,
    InputSafetyFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMigrationFailureCode {
    BackendUnavailable,
    SignalingUnavailable,
    TransportUnavailable,
    NoDifferentFailureDomain,
    InputSafetyFailure,
    SecurityViolation,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("relay migration failed: {code:?}")]
pub struct RelayMigrationFailure {
    code: RelayMigrationFailureCode,
    terminal_security: bool,
}

impl RelayMigrationFailure {
    pub fn retryable(code: RelayMigrationFailureCode) -> Self {
        Self {
            code,
            terminal_security: false,
        }
    }

    pub fn terminal(code: RelayMigrationFailureCode) -> Self {
        Self {
            code,
            terminal_security: true,
        }
    }

    pub fn code(&self) -> RelayMigrationFailureCode {
        self.code
    }

    pub fn is_terminal_security(&self) -> bool {
        self.terminal_security
    }
}

pub struct RelayMigrationAttempt {
    session_id: SessionId,
    generation: u64,
    route_evidence: RelayRouteEvidence,
    peer_config: PeerConnectionConfig,
}

impl fmt::Debug for RelayMigrationAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayMigrationAttempt")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("route_evidence", &self.route_evidence)
            .field("peer_config", &"[REDACTED]")
            .finish()
    }
}

impl RelayMigrationAttempt {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn route_evidence(&self) -> &RelayRouteEvidence {
        &self.route_evidence
    }

    pub fn peer_config(&self) -> &PeerConnectionConfig {
        &self.peer_config
    }
}

/// One authenticated peer migration offer passed to the answer-side executor.
pub struct RelayMigrationOffer {
    pub(crate) peer_device_id: DeviceId,
    pub(crate) peer_key_id: String,
    pub(crate) session_id: SessionId,
    pub(crate) generation: u64,
    pub(crate) directory_id: String,
    pub(crate) node_id: String,
    pub(crate) sdp: String,
    pub(crate) restart_route_token: String,
    pub(crate) candidate_fingerprints: Vec<String>,
}

impl RelayMigrationOffer {
    /// Extract an answer-side offer only from an event already verified by signaling.
    pub fn from_verified_event(event: VerifiedSignalingEvent) -> Option<Self> {
        let AuthenticatedSessionSignal::RelayMigrationOffer {
            session_id,
            migration_generation,
            directory_id,
            node_id,
            sdp,
            restart_route_token,
            candidate_fingerprints,
        } = event.signal
        else {
            return None;
        };
        Some(Self {
            peer_device_id: event.sender.device_id,
            peer_key_id: event.sender.key_id,
            session_id,
            generation: migration_generation,
            directory_id,
            node_id,
            sdp,
            restart_route_token,
            candidate_fingerprints,
        })
    }
}

impl fmt::Debug for RelayMigrationOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayMigrationOffer")
            .field("peer_device_id", &self.peer_device_id)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("directory_id", &self.directory_id)
            .field("node_id", &self.node_id)
            .field("sdp", &"[REDACTED]")
            .field("restart_route_token", &"[REDACTED]")
            .field(
                "candidate_fingerprint_count",
                &self.candidate_fingerprints.len(),
            )
            .finish()
    }
}

impl Drop for RelayMigrationOffer {
    fn drop(&mut self) {
        self.peer_key_id.zeroize();
        self.sdp.zeroize();
        self.restart_route_token.zeroize();
        self.candidate_fingerprints.zeroize();
    }
}

pub struct RelayMigrationCommit {
    generation: u64,
    route_evidence: RelayRouteEvidence,
    mux: Arc<dyn TransportMuxPort>,
}

impl fmt::Debug for RelayMigrationCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayMigrationCommit")
            .field("generation", &self.generation)
            .field("route_evidence", &self.route_evidence)
            .finish_non_exhaustive()
    }
}

impl RelayMigrationCommit {
    /// Build the exact commit returned after infrastructure verified and published this attempt.
    pub fn for_attempt(attempt: &RelayMigrationAttempt, mux: Arc<dyn TransportMuxPort>) -> Self {
        Self {
            generation: attempt.generation,
            route_evidence: attempt.route_evidence.clone(),
            mux,
        }
    }
}

#[async_trait]
pub trait RelayMigrationExecutor: Send + Sync {
    /// Negotiate, validate, and atomically publish one pending replacement.
    async fn migrate(
        &self,
        attempt: &RelayMigrationAttempt,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure>;

    /// Answer one authenticated controller offer. Test executors that only exercise the
    /// controller path may keep the fail-closed default.
    async fn respond(
        &self,
        _attempt: &RelayMigrationAttempt,
        _offer: RelayMigrationOffer,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        Err(RelayMigrationFailure::retryable(
            RelayMigrationFailureCode::SignalingUnavailable,
        ))
    }

    /// Suppress and close an attempt that completed after its generation lost ownership.
    async fn discard_loser(&self, session_id: &SessionId, generation: u64);

    /// Close active and pending transport paths after a terminal security event.
    async fn close_all(&self, session_id: &SessionId);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRecoveryOutcome {
    Healthy,
    Grace {
        retry_at_ms: u64,
    },
    InProgress {
        generation: u64,
    },
    SuppressedStaleHealth {
        observed_generation: u64,
        active_generation: u64,
    },
    Migrated {
        evidence: RelayRouteEvidence,
    },
    Retryable {
        code: RelayMigrationFailureCode,
    },
    SuppressedLate {
        generation: u64,
    },
    Terminal {
        reason: RelayTerminalSecurityReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMigrationPhase {
    Idle,
    Planning { generation: u64 },
    InFlight { generation: u64 },
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionSnapshot {
    pub session_id: SessionId,
    pub active_directory_id: String,
    pub active_node_id: String,
    pub active_failure_domain: String,
    pub generation: u64,
    pub health: RelayConnectionHealth,
    pub phase: RelayMigrationPhase,
    pub terminal_reason: Option<RelayTerminalSecurityReason>,
}

struct RelaySessionState {
    context: RelayAccessContext,
    latest_access: Arc<VerifiedRelayAccess>,
    active_directory_id: String,
    active_node_id: String,
    active_failure_domain: String,
    generation: u64,
    highest_attempted_generation: u64,
    health: RelayConnectionHealth,
    disconnected_at_ms: Option<u64>,
    phase: RelayMigrationPhase,
    terminal_reason: Option<RelayTerminalSecurityReason>,
    terminal_cleanup: Option<watch::Receiver<bool>>,
    active_mux: Arc<dyn TransportMuxPort>,
}

struct RelayRecoveryCancellationGuard {
    sessions: Arc<Mutex<HashMap<SessionId, RelaySessionState>>>,
    executor: Arc<dyn RelayMigrationExecutor>,
    input: Arc<dyn RelayInputBarrier>,
    session_id: SessionId,
    generation: u64,
    runtime: tokio::runtime::Handle,
}

impl RelayRecoveryCancellationGuard {
    fn new(
        coordinator: &RelayFailoverCoordinator,
        session_id: &SessionId,
        generation: u64,
    ) -> Self {
        Self {
            sessions: Arc::clone(&coordinator.sessions),
            executor: Arc::clone(&coordinator.executor),
            input: Arc::clone(&coordinator.input),
            session_id: session_id.clone(),
            generation,
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl Drop for RelayRecoveryCancellationGuard {
    fn drop(&mut self) {
        let sessions = Arc::clone(&self.sessions);
        let executor = Arc::clone(&self.executor);
        let input = Arc::clone(&self.input);
        let session_id = self.session_id.clone();
        let generation = self.generation;
        self.runtime.spawn(async move {
            let was_in_flight = {
                let mut sessions = sessions.lock().await;
                let Some(state) = sessions.get_mut(&session_id) else {
                    return;
                };
                match state.phase {
                    RelayMigrationPhase::Planning {
                        generation: current,
                    } if current == generation && state.terminal_reason.is_none() => {
                        state.phase = RelayMigrationPhase::Idle;
                        return;
                    }
                    RelayMigrationPhase::InFlight {
                        generation: current,
                    } if current == generation && state.terminal_reason.is_none() => true,
                    _ => return,
                }
            };
            if was_in_flight {
                executor.discard_loser(&session_id, generation).await;
                let owns_freeze = {
                    let mut sessions = sessions.lock().await;
                    let Some(state) = sessions.get_mut(&session_id) else {
                        return;
                    };
                    if state.phase == (RelayMigrationPhase::InFlight { generation })
                        && state.terminal_reason.is_none()
                    {
                        state.phase = RelayMigrationPhase::Idle;
                        true
                    } else {
                        false
                    }
                };
                if owns_freeze {
                    input.thaw(&session_id).await;
                }
            }
        });
    }
}

pub struct RelayFailoverCoordinator {
    provider: Arc<dyn RelayAccessProvider>,
    executor: Arc<dyn RelayMigrationExecutor>,
    input: Arc<dyn RelayInputBarrier>,
    clock: Arc<dyn RelayClock>,
    disconnected_grace: Duration,
    sessions: Arc<Mutex<HashMap<SessionId, RelaySessionState>>>,
}

impl fmt::Debug for RelayFailoverCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayFailoverCoordinator")
            .field("disconnected_grace", &self.disconnected_grace)
            .finish_non_exhaustive()
    }
}

impl RelayFailoverCoordinator {
    pub fn new(
        provider: Arc<dyn RelayAccessProvider>,
        executor: Arc<dyn RelayMigrationExecutor>,
        input: Arc<dyn RelayInputBarrier>,
        clock: Arc<dyn RelayClock>,
        disconnected_grace: Duration,
    ) -> Result<Self, RelayFailoverConfigError> {
        if disconnected_grace < Duration::from_millis(100)
            || disconnected_grace > Duration::from_secs(60)
        {
            return Err(RelayFailoverConfigError::InvalidGrace);
        }
        Ok(Self {
            provider,
            executor,
            input,
            clock,
            disconnected_grace,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[cfg(any(test, debug_assertions))]
    pub async fn install_session(
        &self,
        context: RelayAccessContext,
        access: Arc<VerifiedRelayAccess>,
        active_node_id: &str,
        active_mux: Arc<dyn TransportMuxPort>,
    ) -> Result<(), RelayFailoverConfigError> {
        self.install_session_inner(context, access, active_node_id, active_mux)
            .await
    }

    pub(crate) async fn install_verified_session(
        &self,
        context: RelayAccessContext,
        access: Arc<VerifiedRelayAccess>,
        active_node_id: &str,
        evidence: crate::transports::webrtc::VerifiedActiveRelayEvidence,
        active_mux: Arc<dyn TransportMuxPort>,
    ) -> Result<(), RelayFailoverConfigError> {
        let expected = access
            .route_evidence(active_node_id, 0)
            .map_err(|_| RelayFailoverConfigError::ActiveRelayEvidenceMismatch)?;
        if evidence.route() != &expected {
            return Err(RelayFailoverConfigError::ActiveRelayEvidenceMismatch);
        }
        self.install_session_inner(context, access, active_node_id, active_mux)
            .await
    }

    async fn install_session_inner(
        &self,
        context: RelayAccessContext,
        access: Arc<VerifiedRelayAccess>,
        active_node_id: &str,
        active_mux: Arc<dyn TransportMuxPort>,
    ) -> Result<(), RelayFailoverConfigError> {
        let (active_directory_id, active_node_id, active_failure_domain) = {
            let payload = access.directory().payload();
            if payload.session_id != context.session_id
                || payload.policy_revision != context.policy_revision
                || payload.intended_peer_digest != context.intended_peer_digest()
            {
                return Err(RelayFailoverConfigError::ContextMismatch);
            }
            let active = payload
                .candidates
                .iter()
                .find(|candidate| candidate.node_id == active_node_id)
                .ok_or(RelayFailoverConfigError::ActiveNodeMissing)?;
            if access.credentials_for(active_node_id).is_none() {
                return Err(RelayFailoverConfigError::ActiveNodeMissing);
            }
            (
                payload.directory_id.clone(),
                active.node_id.clone(),
                active.failure_domain.clone(),
            )
        };
        let route = active_mux.route_snapshot().await;
        let session_id = SessionId(context.session_id.clone());
        if route.session_id != session_id || route.closed {
            return Err(RelayFailoverConfigError::MuxMismatch);
        }
        if !access.is_fresh(self.clock.now_ms()) {
            return Err(RelayFailoverConfigError::AccessExpired);
        }
        let state = RelaySessionState {
            context,
            latest_access: access,
            active_directory_id,
            active_node_id,
            active_failure_domain,
            generation: 0,
            highest_attempted_generation: 0,
            health: RelayConnectionHealth::Connected,
            disconnected_at_ms: None,
            phase: RelayMigrationPhase::Idle,
            terminal_reason: None,
            terminal_cleanup: None,
            active_mux,
        };
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(&session_id) {
            return Err(RelayFailoverConfigError::DuplicateSession);
        }
        sessions.insert(session_id, state);
        Ok(())
    }

    pub async fn observe_health(
        &self,
        session_id: &SessionId,
        observed_generation: u64,
        health: RelayConnectionHealth,
    ) -> Result<RelayRecoveryOutcome, RelayFailoverConfigError> {
        let now_ms = self.clock.now_ms();
        let (generation, context, cached_access, active_node_id, active_failure_domain) = {
            let mut sessions = self.sessions.lock().await;
            let state = sessions
                .get_mut(session_id)
                .ok_or(RelayFailoverConfigError::SessionMissing)?;
            if let Some(reason) = state.terminal_reason {
                return Ok(RelayRecoveryOutcome::Terminal { reason });
            }
            if observed_generation != state.generation {
                return Ok(RelayRecoveryOutcome::SuppressedStaleHealth {
                    observed_generation,
                    active_generation: state.generation,
                });
            }
            state.health = health;
            if health == RelayConnectionHealth::Connected {
                state.disconnected_at_ms = None;
                return Ok(RelayRecoveryOutcome::Healthy);
            }
            if let RelayMigrationPhase::Planning { generation }
            | RelayMigrationPhase::InFlight { generation } = state.phase
            {
                return Ok(RelayRecoveryOutcome::InProgress { generation });
            }
            if health == RelayConnectionHealth::Disconnected {
                let disconnected_at = *state.disconnected_at_ms.get_or_insert(now_ms);
                let retry_at_ms = disconnected_at.saturating_add(
                    self.disconnected_grace
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                );
                if now_ms < retry_at_ms {
                    return Ok(RelayRecoveryOutcome::Grace { retry_at_ms });
                }
            } else {
                state.disconnected_at_ms = None;
            }
            let generation = state
                .highest_attempted_generation
                .checked_add(1)
                .ok_or(RelayFailoverConfigError::GenerationExhausted)?;
            state.phase = RelayMigrationPhase::Planning { generation };
            (
                generation,
                state.context.clone(),
                Arc::clone(&state.latest_access),
                state.active_node_id.clone(),
                state.active_failure_domain.clone(),
            )
        };

        self.recover(
            session_id,
            generation,
            context,
            cached_access,
            active_node_id,
            active_failure_domain,
        )
        .await
    }

    /// Apply one authenticated controller offer on the agent side. The directory is refreshed
    /// locally and the exact node is re-authorized before TURN credentials reach WebRTC.
    pub async fn accept_remote_offer(
        &self,
        offer: RelayMigrationOffer,
    ) -> Result<RelayRecoveryOutcome, RelayFailoverConfigError> {
        let session_id = offer.session_id.clone();
        let generation = offer.generation;
        let (context, cached_access, active_failure_domain) = {
            let mut sessions = self.sessions.lock().await;
            let state = sessions
                .get_mut(&session_id)
                .ok_or(RelayFailoverConfigError::SessionMissing)?;
            if let Some(reason) = state.terminal_reason {
                return Ok(RelayRecoveryOutcome::Terminal { reason });
            }
            if state.phase != RelayMigrationPhase::Idle {
                return Ok(RelayRecoveryOutcome::InProgress {
                    generation: match state.phase {
                        RelayMigrationPhase::Planning { generation }
                        | RelayMigrationPhase::InFlight { generation } => generation,
                        RelayMigrationPhase::Idle | RelayMigrationPhase::Terminal => {
                            state.highest_attempted_generation
                        }
                    },
                });
            }
            let expected = state
                .highest_attempted_generation
                .checked_add(1)
                .ok_or(RelayFailoverConfigError::GenerationExhausted)?;
            if generation != expected {
                return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
            }
            state.phase = RelayMigrationPhase::Planning { generation };
            (
                state.context.clone(),
                Arc::clone(&state.latest_access),
                state.active_failure_domain.clone(),
            )
        };
        let _cancellation_guard =
            RelayRecoveryCancellationGuard::new(self, &session_id, generation);
        let refresh_context = RelayAccessContext::for_refresh(
            context.session_id.clone(),
            context.policy_revision,
            context.intended_peer_id.clone(),
            generation
                .checked_sub(1)
                .ok_or(RelayFailoverConfigError::ContextMismatch)?,
        )
        .map_err(|_| RelayFailoverConfigError::ContextMismatch)?;
        let access = match self.provider.refresh_access(&refresh_context).await {
            Ok(access) => access,
            Err(RelayClientError::BackendUnavailable)
                if cached_access.is_fresh(self.clock.now_ms()) =>
            {
                cached_access
            }
            Err(error) if error.is_terminal_security() => {
                return self
                    .terminalize(&session_id, terminal_reason_for_client_error(&error))
                    .await;
            }
            Err(_) => {
                return Ok(self
                    .retryable_or_suppressed(
                        &session_id,
                        generation,
                        RelayMigrationFailureCode::BackendUnavailable,
                    )
                    .await);
            }
        };
        if access.directory().payload().directory_id != offer.directory_id {
            return self
                .terminalize(
                    &session_id,
                    RelayTerminalSecurityReason::RouteEvidenceMismatch,
                )
                .await;
        }
        let candidate = access
            .directory()
            .payload()
            .candidates
            .iter()
            .find(|candidate| candidate.node_id == offer.node_id);
        let Some(candidate) = candidate else {
            return self
                .terminalize(
                    &session_id,
                    RelayTerminalSecurityReason::RouteEvidenceMismatch,
                )
                .await;
        };
        if candidate.failure_domain == active_failure_domain {
            return self
                .terminalize(
                    &session_id,
                    RelayTerminalSecurityReason::RouteEvidenceMismatch,
                )
                .await;
        }
        let Some(credentials) = access.credentials_for(&offer.node_id) else {
            return self
                .terminalize(
                    &session_id,
                    RelayTerminalSecurityReason::RouteEvidenceMismatch,
                )
                .await;
        };
        let route_evidence = match access.route_evidence(&offer.node_id, generation) {
            Ok(evidence) => evidence,
            Err(_) => {
                return self
                    .terminalize(
                        &session_id,
                        RelayTerminalSecurityReason::RouteEvidenceMismatch,
                    )
                    .await;
            }
        };
        let peer_config = PeerConnectionConfig {
            role: PeerConnectionRole::Answerer,
            ..PeerConnectionConfig::default()
        };
        let attempt = RelayMigrationAttempt {
            session_id: session_id.clone(),
            generation,
            route_evidence,
            peer_config: credentials.apply_relay_only(peer_config),
        };
        {
            let mut sessions = self.sessions.lock().await;
            let Some(state) = sessions.get_mut(&session_id) else {
                return Err(RelayFailoverConfigError::SessionMissing);
            };
            if state.terminal_reason.is_some()
                || state.phase != (RelayMigrationPhase::Planning { generation })
            {
                return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
            }
            state.phase = RelayMigrationPhase::InFlight { generation };
            state.highest_attempted_generation = generation;
        }
        if self.input.freeze_after_release(&session_id).await.is_err() {
            return self
                .terminalize(&session_id, RelayTerminalSecurityReason::InputSafetyFailure)
                .await;
        }
        let commit = match self.executor.respond(&attempt, offer).await {
            Ok(commit) => commit,
            Err(error) if error.is_terminal_security() => {
                return self
                    .terminalize(
                        &session_id,
                        RelayTerminalSecurityReason::RouteEvidenceMismatch,
                    )
                    .await;
            }
            Err(error) => {
                if !self.clear_phase(&session_id, generation).await {
                    return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
                }
                self.thaw_cancellation_safe(&session_id).await;
                return Ok(RelayRecoveryOutcome::Retryable { code: error.code() });
            }
        };
        let commit_route = commit.mux.route_snapshot().await;
        if commit.generation != generation
            || commit.route_evidence != attempt.route_evidence
            || commit_route.session_id != session_id
            || commit_route.closed
        {
            self.executor.discard_loser(&session_id, generation).await;
            return self
                .terminalize(
                    &session_id,
                    RelayTerminalSecurityReason::RouteEvidenceMismatch,
                )
                .await;
        }
        let evidence = commit.route_evidence.clone();
        let committed = {
            let mut sessions = self.sessions.lock().await;
            let state = sessions
                .get_mut(&session_id)
                .ok_or(RelayFailoverConfigError::SessionMissing)?;
            if state.terminal_reason.is_some()
                || state.phase != (RelayMigrationPhase::InFlight { generation })
            {
                false
            } else {
                state.latest_access = access;
                state.active_directory_id = evidence.directory_id().to_owned();
                state.active_node_id = evidence.node_id().to_owned();
                state.active_failure_domain = evidence.failure_domain().to_owned();
                state.generation = generation;
                state.health = RelayConnectionHealth::Connected;
                state.disconnected_at_ms = None;
                state.phase = RelayMigrationPhase::Idle;
                state.active_mux = commit.mux;
                true
            }
        };
        if !committed {
            self.executor.discard_loser(&session_id, generation).await;
            return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
        }
        self.thaw_cancellation_safe(&session_id).await;
        Ok(RelayRecoveryOutcome::Migrated { evidence })
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover(
        &self,
        session_id: &SessionId,
        generation: u64,
        context: RelayAccessContext,
        cached_access: Arc<VerifiedRelayAccess>,
        active_node_id: String,
        active_failure_domain: String,
    ) -> Result<RelayRecoveryOutcome, RelayFailoverConfigError> {
        let _cancellation_guard = RelayRecoveryCancellationGuard::new(self, session_id, generation);
        let refresh_context = RelayAccessContext::for_refresh(
            context.session_id.clone(),
            context.policy_revision,
            context.intended_peer_id.clone(),
            generation
                .checked_sub(1)
                .ok_or(RelayFailoverConfigError::ContextMismatch)?,
        )
        .map_err(|_| RelayFailoverConfigError::ContextMismatch)?;
        let access = match self.provider.refresh_access(&refresh_context).await {
            Ok(access) => access,
            Err(RelayClientError::BackendUnavailable) => {
                if cached_access.is_fresh(self.clock.now_ms()) {
                    cached_access
                } else {
                    return Ok(self
                        .retryable_or_suppressed(
                            session_id,
                            generation,
                            RelayMigrationFailureCode::BackendUnavailable,
                        )
                        .await);
                }
            }
            Err(error) if error.is_terminal_security() => {
                let reason = terminal_reason_for_client_error(&error);
                return self.terminalize(session_id, reason).await;
            }
            Err(_) => {
                return Ok(self
                    .retryable_or_suppressed(
                        session_id,
                        generation,
                        RelayMigrationFailureCode::BackendUnavailable,
                    )
                    .await);
            }
        };

        let Some(candidate) = access
            .directory()
            .payload()
            .candidates
            .iter()
            .find(|candidate| {
                candidate.node_id != active_node_id
                    && candidate.failure_domain != active_failure_domain
                    && access.credentials_for(&candidate.node_id).is_some()
            })
        else {
            return Ok(self
                .retryable_or_suppressed(
                    session_id,
                    generation,
                    RelayMigrationFailureCode::NoDifferentFailureDomain,
                )
                .await);
        };
        let credential = access
            .credentials_for(&candidate.node_id)
            .ok_or(RelayFailoverConfigError::ActiveNodeMissing)?;
        let route_evidence = access
            .route_evidence(&candidate.node_id, generation)
            .map_err(|_| RelayFailoverConfigError::ContextMismatch)?;
        let attempt = RelayMigrationAttempt {
            session_id: session_id.clone(),
            generation,
            route_evidence,
            peer_config: credential.apply_relay_only(PeerConnectionConfig::default()),
        };
        {
            let mut sessions = self.sessions.lock().await;
            let Some(state) = sessions.get_mut(session_id) else {
                return Err(RelayFailoverConfigError::SessionMissing);
            };
            if state.terminal_reason.is_some()
                || state.phase != (RelayMigrationPhase::Planning { generation })
            {
                return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
            }
            state.phase = RelayMigrationPhase::InFlight { generation };
            state.highest_attempted_generation = generation;
        }

        if self.input.freeze_after_release(session_id).await.is_err() {
            return self
                .terminalize(session_id, RelayTerminalSecurityReason::InputSafetyFailure)
                .await;
        }
        {
            let sessions = self.sessions.lock().await;
            let state = sessions
                .get(session_id)
                .ok_or(RelayFailoverConfigError::SessionMissing)?;
            if state.terminal_reason.is_some()
                || state.phase != (RelayMigrationPhase::InFlight { generation })
            {
                return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
            }
        }
        let commit = match self.executor.migrate(&attempt).await {
            Ok(commit) => commit,
            Err(error) if error.is_terminal_security() => {
                return self
                    .terminalize(
                        session_id,
                        RelayTerminalSecurityReason::RouteEvidenceMismatch,
                    )
                    .await;
            }
            Err(error) => {
                let owns_freeze = self.clear_phase(session_id, generation).await;
                if !owns_freeze {
                    return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
                }
                self.thaw_cancellation_safe(session_id).await;
                return Ok(RelayRecoveryOutcome::Retryable { code: error.code() });
            }
        };

        let commit_route = commit.mux.route_snapshot().await;
        if commit.generation != generation
            || commit.route_evidence != attempt.route_evidence
            || commit_route.session_id != *session_id
            || commit_route.closed
        {
            self.executor.discard_loser(session_id, generation).await;
            return self
                .terminalize(
                    session_id,
                    RelayTerminalSecurityReason::RouteEvidenceMismatch,
                )
                .await;
        }

        let evidence = commit.route_evidence.clone();
        let committed = {
            let mut sessions = self.sessions.lock().await;
            let state = sessions
                .get_mut(session_id)
                .ok_or(RelayFailoverConfigError::SessionMissing)?;
            if state.terminal_reason.is_some()
                || state.phase != (RelayMigrationPhase::InFlight { generation })
            {
                false
            } else {
                state.latest_access = access;
                state.active_directory_id = evidence.directory_id().to_owned();
                state.active_node_id = evidence.node_id().to_owned();
                state.active_failure_domain = evidence.failure_domain().to_owned();
                state.generation = generation;
                state.health = RelayConnectionHealth::Connected;
                state.disconnected_at_ms = None;
                state.phase = RelayMigrationPhase::Idle;
                state.active_mux = commit.mux;
                true
            }
        };
        if !committed {
            self.executor.discard_loser(session_id, generation).await;
            return Ok(RelayRecoveryOutcome::SuppressedLate { generation });
        }
        self.thaw_cancellation_safe(session_id).await;
        Ok(RelayRecoveryOutcome::Migrated { evidence })
    }

    pub async fn terminate_security(
        &self,
        session_id: &SessionId,
        reason: RelayTerminalSecurityReason,
    ) -> Result<RelayRecoveryOutcome, RelayFailoverConfigError> {
        self.terminalize(session_id, reason).await
    }

    pub async fn snapshot(
        &self,
        session_id: &SessionId,
    ) -> Result<RelaySessionSnapshot, RelayFailoverConfigError> {
        let sessions = self.sessions.lock().await;
        let state = sessions
            .get(session_id)
            .ok_or(RelayFailoverConfigError::SessionMissing)?;
        Ok(RelaySessionSnapshot {
            session_id: session_id.clone(),
            active_directory_id: state.active_directory_id.clone(),
            active_node_id: state.active_node_id.clone(),
            active_failure_domain: state.active_failure_domain.clone(),
            generation: state.generation,
            health: state.health,
            phase: state.phase,
            terminal_reason: state.terminal_reason,
        })
    }

    pub async fn active_mux(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<dyn TransportMuxPort>, RelayFailoverConfigError> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .map(|state| Arc::clone(&state.active_mux))
            .ok_or(RelayFailoverConfigError::SessionMissing)
    }

    async fn terminalize(
        &self,
        session_id: &SessionId,
        reason: RelayTerminalSecurityReason,
    ) -> Result<RelayRecoveryOutcome, RelayFailoverConfigError> {
        let (reason, cleanup_sender, mut completion) = {
            let mut sessions = self.sessions.lock().await;
            let state = sessions
                .get_mut(session_id)
                .ok_or(RelayFailoverConfigError::SessionMissing)?;
            if let Some(existing) = state.terminal_reason {
                (existing, None, state.terminal_cleanup.clone())
            } else {
                let (cleanup_sender, completion) = watch::channel(false);
                state.phase = RelayMigrationPhase::Terminal;
                state.terminal_reason = Some(reason);
                state.terminal_cleanup = Some(completion.clone());
                (reason, Some(cleanup_sender), Some(completion))
            }
        };
        if let Some(cleanup_sender) = cleanup_sender {
            let input = Arc::clone(&self.input);
            let executor = Arc::clone(&self.executor);
            let session_id = session_id.clone();
            tokio::spawn(async move {
                let _ = input.freeze_after_release(&session_id).await;
                executor.close_all(&session_id).await;
                let _ = cleanup_sender.send(true);
            });
        }
        if let Some(completion) = completion.as_mut() {
            completion
                .wait_for(|complete| *complete)
                .await
                .map_err(|_| RelayFailoverConfigError::TerminalCleanupFailed)?;
        }
        Ok(RelayRecoveryOutcome::Terminal { reason })
    }

    async fn thaw_cancellation_safe(&self, session_id: &SessionId) {
        let input = Arc::clone(&self.input);
        let session_id = session_id.clone();
        let _ = tokio::spawn(async move { input.thaw(&session_id).await }).await;
    }

    async fn clear_phase(&self, session_id: &SessionId, generation: u64) -> bool {
        let mut sessions = self.sessions.lock().await;
        let Some(state) = sessions.get_mut(session_id) else {
            return false;
        };
        if matches!(
            state.phase,
            RelayMigrationPhase::Planning { generation: current }
                | RelayMigrationPhase::InFlight { generation: current }
                if current == generation
        ) && state.terminal_reason.is_none()
        {
            state.phase = RelayMigrationPhase::Idle;
            true
        } else {
            false
        }
    }

    async fn retryable_or_suppressed(
        &self,
        session_id: &SessionId,
        generation: u64,
        code: RelayMigrationFailureCode,
    ) -> RelayRecoveryOutcome {
        if self.clear_phase(session_id, generation).await {
            RelayRecoveryOutcome::Retryable { code }
        } else {
            RelayRecoveryOutcome::SuppressedLate { generation }
        }
    }
}

fn terminal_reason_for_client_error(error: &RelayClientError) -> RelayTerminalSecurityReason {
    match error {
        RelayClientError::Unauthorized => RelayTerminalSecurityReason::GrantExpired,
        RelayClientError::InvalidContext => RelayTerminalSecurityReason::IdentityMismatch,
        RelayClientError::InvalidResponse | RelayClientError::CredentialBinding => {
            RelayTerminalSecurityReason::RouteEvidenceMismatch
        }
        RelayClientError::Directory(directory_error) => match directory_error {
            RelayDirectoryError::InvalidPolicyRevision
            | RelayDirectoryError::PolicyRevisionMismatch { .. } => {
                RelayTerminalSecurityReason::PolicyChanged
            }
            RelayDirectoryError::PeerBindingMismatch | RelayDirectoryError::SessionMismatch => {
                RelayTerminalSecurityReason::IdentityMismatch
            }
            RelayDirectoryError::Expired | RelayDirectoryError::ReservationExpired => {
                RelayTerminalSecurityReason::GrantExpired
            }
            RelayDirectoryError::UntrustedSigningKey
            | RelayDirectoryError::InvalidPublicKey
            | RelayDirectoryError::InvalidSignatureEncoding
            | RelayDirectoryError::InvalidSignature => {
                RelayTerminalSecurityReason::SignatureInvalid
            }
            _ => RelayTerminalSecurityReason::RouteEvidenceMismatch,
        },
        RelayClientError::BackendUnavailable => RelayTerminalSecurityReason::RouteEvidenceMismatch,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayFailoverConfigError {
    #[error("relay disconnected grace is invalid")]
    InvalidGrace,
    #[error("relay session context does not match the verified directory")]
    ContextMismatch,
    #[error("active relay node is absent from the verified directory")]
    ActiveNodeMissing,
    #[error("relay session transport mux does not match")]
    MuxMismatch,
    #[error("initial WebRTC relay evidence does not match the signed directory route")]
    ActiveRelayEvidenceMismatch,
    #[error("relay access expired before session installation")]
    AccessExpired,
    #[error("relay session is already installed")]
    DuplicateSession,
    #[error("relay session is not installed")]
    SessionMissing,
    #[error("relay migration generation is exhausted")]
    GenerationExhausted,
    #[error("terminal relay cleanup task failed")]
    TerminalCleanupFailed,
}
