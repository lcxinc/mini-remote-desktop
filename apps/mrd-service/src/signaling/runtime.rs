use super::{ServiceSignalingMapper, SignalingConfig, SignalingConfigError};
use crate::AppState;
use mrd_application::{
    apply_authenticated_realtime_events, AuthenticatedSessionSignal, AuthenticatedSignalingPort,
    VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_proto::BackendRole;
use mrd_signal_proto::{
    AuthClaims, AuthenticatedSignalMessage, PresenceHeartbeat, PresenceHeartbeatPayload,
    RegisterPayload, Registered, ServerChallenge, SignalEnvelope, SignalProtocolError,
    SignalReplayGuard,
};
use ring::{digest, rand::SecureRandom, rand::SystemRandom};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use thiserror::Error;

const ACCEPTED_MESSAGE_LIMIT: usize = 4_096;
const PEER_KEY_LIMIT: usize = 4_096;
const MAX_CHALLENGE_LIFETIME_MS: u64 = 60_000;
const MIN_HEARTBEAT_INTERVAL_MS: u64 = 250;
const MAX_HEARTBEAT_INTERVAL_MS: u64 = 300_000;

/// Observable connection phase for service health projections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignalingConnectionState {
    /// No signaling configuration was provided.
    #[default]
    Disabled,
    /// A network connection or authentication handshake is in progress.
    Connecting,
    /// Challenge authentication completed and presence heartbeats are active.
    Authenticated,
    /// The runtime is waiting before a reconnect attempt.
    Backoff,
    /// The runtime was intentionally stopped.
    Stopped,
}

/// Point-in-time, secret-free signaling health snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignalingRuntimeSnapshot {
    pub state: SignalingConnectionState,
    pub reconnect_attempt: u32,
    pub next_retry_at_ms: Option<u64>,
    pub last_connected_at_ms: Option<u64>,
    pub last_message_at_ms: Option<u64>,
    pub last_error: Option<String>,
}

/// Concurrent signaling status shared with IPC health projections.
#[derive(Debug, Default)]
pub struct SignalingStatus(RwLock<SignalingRuntimeSnapshot>);

impl SignalingStatus {
    /// Return a consistent point-in-time snapshot.
    pub fn snapshot(&self) -> SignalingRuntimeSnapshot {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn note_connecting(&self) {
        let mut status = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.state = SignalingConnectionState::Connecting;
        status.next_retry_at_ms = None;
    }

    pub(crate) fn note_authenticated(&self, now_ms: u64) {
        let mut status = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.state = SignalingConnectionState::Authenticated;
        status.reconnect_attempt = 0;
        status.next_retry_at_ms = None;
        status.last_connected_at_ms = Some(now_ms);
        status.last_message_at_ms = Some(now_ms);
        status.last_error = None;
    }

    pub(crate) fn note_message(&self, now_ms: u64) {
        self.0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_message_at_ms = Some(now_ms);
    }

    /// Record a transient disconnect without mutating any session aggregate.
    pub fn note_disconnected(
        &self,
        now_ms: u64,
        reconnect_attempt: u32,
        retry_after: Duration,
        error: &str,
    ) {
        let mut status = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.state = SignalingConnectionState::Backoff;
        status.reconnect_attempt = reconnect_attempt;
        status.next_retry_at_ms =
            Some(now_ms.saturating_add(retry_after.as_millis().min(u128::from(u64::MAX)) as u64));
        status.last_error = Some(sanitize_error(error));
    }

    pub(crate) fn note_stopped(&self) {
        let mut status = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.state = SignalingConnectionState::Stopped;
        status.next_retry_at_ms = None;
    }
}

/// Result of processing one authenticated inbound envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundDisposition {
    /// The signed session event was verified and should be applied once.
    Applied(Box<VerifiedSignalingEvent>),
    /// The exact signed envelope was already accepted.
    Duplicate,
    /// A valid server control message required no session mutation.
    Control,
}

/// Deterministic authenticated signaling state machine used by the async driver.
pub struct SignalingRuntimeCore {
    config: SignalingConfig,
    identity: Arc<DeviceIdentity>,
    status: Arc<SignalingStatus>,
    outbound_counter: u64,
    connection_id: Option<[u8; 16]>,
    heartbeat_interval: Option<Duration>,
    next_heartbeat_at_ms: Option<u64>,
    reconnect_attempt: u32,
    observed_server_key_id: Option<String>,
    replay: SignalReplayGuard,
    accepted_order: VecDeque<[u8; 32]>,
    accepted: HashSet<[u8; 32]>,
    peer_keys: HashMap<mrd_proto::DeviceId, String>,
}

impl SignalingRuntimeCore {
    /// Construct a runtime around the service's persistent machine identity.
    pub fn new(config: SignalingConfig, identity: Arc<DeviceIdentity>) -> Self {
        let status = Arc::new(SignalingStatus::default());
        status.note_connecting();
        Self::with_status(config, identity, status)
    }

    pub(crate) fn with_status(
        config: SignalingConfig,
        identity: Arc<DeviceIdentity>,
        status: Arc<SignalingStatus>,
    ) -> Self {
        Self {
            config,
            identity,
            status,
            outbound_counter: 1,
            connection_id: None,
            heartbeat_interval: None,
            next_heartbeat_at_ms: None,
            reconnect_attempt: 0,
            observed_server_key_id: None,
            replay: SignalReplayGuard::new(4_096, 2_048),
            accepted_order: VecDeque::new(),
            accepted: HashSet::new(),
            peer_keys: HashMap::new(),
        }
    }

    /// Build the signed challenge response containing the configured backend token.
    pub fn build_registration(
        &mut self,
        challenge: ServerChallenge,
        now_ms: u64,
    ) -> Result<SignalEnvelope, SignalingRuntimeError> {
        if now_ms < challenge.issued_at_ms
            || now_ms >= challenge.expires_at_ms
            || challenge
                .expires_at_ms
                .saturating_sub(challenge.issued_at_ms)
                > MAX_CHALLENGE_LIFETIME_MS
            || challenge.challenge_id == [0; 16]
            || challenge.challenge_nonce == [0; 32]
        {
            return Err(SignalingRuntimeError::InvalidChallenge);
        }
        let payload = RegisterPayload {
            claims: self.next_claims(self.config.server_device_id().clone(), now_ms)?,
            role: self.config.role(),
            device_name: self.config.device_name().to_owned(),
            backend_device_token: self.config.backend_device_token().to_owned(),
            challenge_id: challenge.challenge_id,
            challenge_nonce: challenge.challenge_nonce,
        };
        let signed = mrd_signal_proto::AuthenticatedRegister::sign(&self.identity, payload)?;
        Ok(SignalEnvelope::new(AuthenticatedSignalMessage::Register(
            signed,
        )))
    }

    /// Verify the server registration acknowledgement and arm heartbeats.
    pub fn accept_registered(
        &mut self,
        registered: Registered,
        now_ms: u64,
    ) -> Result<(), SignalingRuntimeError> {
        let metadata = registered.verify_for(self.config.device_id(), now_ms, &mut self.replay)?;
        if metadata.issuer_device_id != *self.config.server_device_id()
            || registered.payload.registered_device_id != *self.config.device_id()
            || self
                .config
                .trusted_server_key_id()
                .is_some_and(|expected| expected != metadata.issuer_key_id)
        {
            return Err(SignalingRuntimeError::ServerIdentityMismatch);
        }
        if self
            .observed_server_key_id
            .as_ref()
            .is_some_and(|observed| observed != &metadata.issuer_key_id)
        {
            return Err(SignalingRuntimeError::ServerIdentityMismatch);
        }
        let heartbeat_interval_ms = u64::from(registered.payload.heartbeat_interval_ms);
        if !(MIN_HEARTBEAT_INTERVAL_MS..=MAX_HEARTBEAT_INTERVAL_MS).contains(&heartbeat_interval_ms)
        {
            return Err(SignalingRuntimeError::InvalidHeartbeatInterval);
        }
        let interval = Duration::from_millis(heartbeat_interval_ms);
        self.observed_server_key_id = Some(metadata.issuer_key_id);
        self.connection_id = Some(registered.payload.connection_id);
        self.heartbeat_interval = Some(interval);
        self.next_heartbeat_at_ms = Some(now_ms.saturating_add(interval.as_millis() as u64));
        self.reconnect_attempt = 0;
        self.status.note_authenticated(now_ms);
        Ok(())
    }

    /// Produce one signed heartbeat when the server-advertised interval elapses.
    pub fn heartbeat_if_due(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<SignalEnvelope>, SignalingRuntimeError> {
        let Some(next) = self.next_heartbeat_at_ms else {
            return Ok(None);
        };
        if now_ms < next {
            return Ok(None);
        }
        let connection_id = self
            .connection_id
            .ok_or(SignalingRuntimeError::NotAuthenticated)?;
        let claims = self.next_claims(self.config.server_device_id().clone(), now_ms)?;
        let heartbeat = PresenceHeartbeat::sign(
            &self.identity,
            PresenceHeartbeatPayload {
                claims,
                connection_id,
                observed_at_ms: now_ms.max(1),
            },
        )?;
        let interval = self
            .heartbeat_interval
            .ok_or(SignalingRuntimeError::NotAuthenticated)?;
        self.next_heartbeat_at_ms = Some(now_ms.saturating_add(interval.as_millis() as u64));
        Ok(Some(SignalEnvelope::new(
            AuthenticatedSignalMessage::PresenceHeartbeat(heartbeat),
        )))
    }

    /// Verify, bind and map one inbound session envelope.
    pub fn handle_inbound(
        &mut self,
        envelope: SignalEnvelope,
        now_ms: u64,
    ) -> Result<InboundDisposition, SignalingRuntimeError> {
        envelope.validate_version()?;
        let digest = envelope_digest(&envelope)?;
        if self.accepted.contains(&digest) {
            return Ok(InboundDisposition::Duplicate);
        }
        let (metadata, public_key, signal) = match &envelope.message {
            AuthenticatedSignalMessage::SessionIntent(message) => (
                {
                    self.require_role(BackendRole::Agent)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::AuthorizationRequested {
                    session_id: message.payload.session_id.clone(),
                    idempotency_key: message.payload.idempotency_key,
                    requested_transport: message.payload.requested_transport.clone(),
                },
            ),
            AuthenticatedSignalMessage::SessionGrant(message) => (
                {
                    self.require_role(BackendRole::Controller)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::Granted {
                    session_id: message.payload.session_id.clone(),
                    accepted_transport: message.payload.accepted_transport.clone(),
                    accepted_candidate_fingerprints: message
                        .payload
                        .accepted_candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect(),
                },
            ),
            AuthenticatedSignalMessage::SessionDeny(message) => (
                {
                    self.require_role(BackendRole::Controller)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::Denied {
                    session_id: message.payload.session_id.clone(),
                    reason: message.payload.reason,
                },
            ),
            AuthenticatedSignalMessage::WebrtcOffer(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::WebRtcOffer {
                    session_id: message.payload.session_id.clone(),
                    sdp: message.payload.sdp.clone(),
                    candidate_fingerprints: message
                        .payload
                        .candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect(),
                },
            ),
            AuthenticatedSignalMessage::WebrtcAnswer(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::WebRtcAnswer {
                    session_id: message.payload.session_id.clone(),
                    sdp: message.payload.sdp.clone(),
                    candidate_fingerprints: message
                        .payload
                        .candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect(),
                },
            ),
            AuthenticatedSignalMessage::WebrtcCandidate(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::WebRtcCandidate {
                    session_id: message.payload.session_id.clone(),
                    candidate: message.payload.candidate.clone(),
                    sdp_mid: message.payload.sdp_mid.clone(),
                    sdp_mline_index: message.payload.sdp_mline_index,
                    candidate_fingerprint: message.payload.candidate_fingerprint.clone(),
                },
            ),
            AuthenticatedSignalMessage::RelayMigrationOffer(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::RelayMigrationOffer {
                    session_id: message.payload.session_id.clone(),
                    migration_generation: message.payload.migration_generation,
                    directory_id: message.payload.directory_id.clone(),
                    node_id: message.payload.node_id.clone(),
                    sdp: message.payload.sdp.clone(),
                    candidate_fingerprints: message
                        .payload
                        .candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect(),
                },
            ),
            AuthenticatedSignalMessage::RelayMigrationAnswer(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::RelayMigrationAnswer {
                    session_id: message.payload.session_id.clone(),
                    migration_generation: message.payload.migration_generation,
                    directory_id: message.payload.directory_id.clone(),
                    node_id: message.payload.node_id.clone(),
                    sdp: message.payload.sdp.clone(),
                    candidate_fingerprints: message
                        .payload
                        .candidate_fingerprints
                        .iter()
                        .cloned()
                        .collect(),
                },
            ),
            AuthenticatedSignalMessage::RelayMigrationCandidate(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::RelayMigrationCandidate {
                    session_id: message.payload.session_id.clone(),
                    migration_generation: message.payload.migration_generation,
                    directory_id: message.payload.directory_id.clone(),
                    node_id: message.payload.node_id.clone(),
                    candidate: message.payload.candidate.clone(),
                    sdp_mid: message.payload.sdp_mid.clone(),
                    sdp_mline_index: message.payload.sdp_mline_index,
                    candidate_fingerprint: message.payload.candidate_fingerprint.clone(),
                },
            ),
            AuthenticatedSignalMessage::SessionClose(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::Closed {
                    session_id: message.payload.session_id.clone(),
                    reason: message.payload.reason,
                },
            ),
            AuthenticatedSignalMessage::ProtocolError(error) => {
                return Err(SignalingRuntimeError::ServerProtocol(format!(
                    "{:?}",
                    error.reason
                )))
            }
            AuthenticatedSignalMessage::ReconnectGrant(_)
            | AuthenticatedSignalMessage::PresenceHeartbeat(_) => {
                return Err(SignalingRuntimeError::UnexpectedMessage)
            }
            AuthenticatedSignalMessage::ServerChallenge(_)
            | AuthenticatedSignalMessage::Register(_)
            | AuthenticatedSignalMessage::Registered(_)
            | AuthenticatedSignalMessage::ReconnectRequest(_) => {
                return Err(SignalingRuntimeError::UnexpectedMessage)
            }
        };
        match self.peer_keys.get(&metadata.issuer_device_id) {
            Some(existing) if existing != &metadata.issuer_key_id => {
                return Err(SignalingRuntimeError::PeerIdentityChanged)
            }
            None => {
                if self.peer_keys.len() >= PEER_KEY_LIMIT {
                    return Err(SignalingRuntimeError::PeerCapacity);
                }
                self.peer_keys.insert(
                    metadata.issuer_device_id.clone(),
                    metadata.issuer_key_id.clone(),
                );
            }
            _ => {}
        }
        self.remember_digest(digest);
        self.status.note_message(now_ms);
        Ok(InboundDisposition::Applied(Box::new(
            VerifiedSignalingEvent {
                sender: VerifiedSignalingIdentity {
                    device_id: metadata.issuer_device_id,
                    key_id: metadata.issuer_key_id,
                    public_key,
                    counter: metadata.counter,
                    nonce: metadata.nonce,
                    issued_at_ms: signed_claims(&envelope.message)
                        .ok_or(SignalingRuntimeError::UnexpectedMessage)?
                        .issued_at_ms,
                    expires_at_ms: signed_claims(&envelope.message)
                        .ok_or(SignalingRuntimeError::UnexpectedMessage)?
                        .expires_at_ms,
                },
                signal,
            },
        )))
    }

    /// Current secret-free health state.
    pub fn snapshot(&self) -> SignalingRuntimeSnapshot {
        self.status.snapshot()
    }

    /// Current bounded exponential reconnect delay.
    pub fn reconnect_delay(&self) -> Duration {
        exponential_delay(
            self.config.initial_reconnect(),
            self.config.max_reconnect(),
            self.reconnect_attempt.saturating_sub(1),
        )
    }

    /// Record one failed connection attempt and advance the reconnect schedule.
    pub fn note_connection_failure(&mut self, now_ms: u64, error: &str) {
        self.reconnect_attempt = self.reconnect_attempt.saturating_add(1);
        let delay = self.reconnect_delay();
        self.connection_id = None;
        self.heartbeat_interval = None;
        self.next_heartbeat_at_ms = None;
        self.status
            .note_disconnected(now_ms, self.reconnect_attempt, delay, error);
    }

    pub(crate) fn config(&self) -> &SignalingConfig {
        &self.config
    }

    fn next_claims(
        &mut self,
        intended_peer_device_id: mrd_proto::DeviceId,
        now_ms: u64,
    ) -> Result<AuthClaims, SignalingRuntimeError> {
        let counter = self.outbound_counter;
        self.outbound_counter = self
            .outbound_counter
            .checked_add(1)
            .ok_or(SignalingRuntimeError::CounterExhausted)?;
        let mut nonce = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SignalingRuntimeError::EntropyUnavailable)?;
        Ok(AuthClaims {
            issuer_device_id: self.config.device_id().clone(),
            issuer_key_id: self.identity.key_id().into(),
            intended_peer_device_id,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(30_000),
            counter,
            nonce,
        })
    }

    fn require_role(&self, required: BackendRole) -> Result<(), SignalingRuntimeError> {
        if self.config.role() != required {
            return Err(SignalingRuntimeError::RoleMismatch);
        }
        Ok(())
    }

    fn remember_digest(&mut self, digest: [u8; 32]) {
        self.accepted.insert(digest);
        self.accepted_order.push_back(digest);
        while self.accepted_order.len() > ACCEPTED_MESSAGE_LIMIT {
            if let Some(expired) = self.accepted_order.pop_front() {
                self.accepted.remove(&expired);
            }
        }
    }
}

fn signed_claims(message: &AuthenticatedSignalMessage) -> Option<&AuthClaims> {
    match message {
        AuthenticatedSignalMessage::Register(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::Registered(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::PresenceHeartbeat(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::SessionIntent(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::SessionGrant(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::SessionDeny(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::WebrtcOffer(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::WebrtcAnswer(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::WebrtcCandidate(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::RelayMigrationOffer(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::RelayMigrationAnswer(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::RelayMigrationCandidate(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::SessionClose(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::ReconnectRequest(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::ReconnectGrant(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::ServerChallenge(_)
        | AuthenticatedSignalMessage::ProtocolError(_) => None,
    }
}

fn envelope_digest(envelope: &SignalEnvelope) -> Result<[u8; 32], SignalingRuntimeError> {
    let bytes = serde_json::to_vec(envelope).map_err(SignalingRuntimeError::Serialize)?;
    digest::digest(&digest::SHA256, &bytes)
        .as_ref()
        .try_into()
        .map_err(|_| SignalingRuntimeError::EntropyUnavailable)
}

fn exponential_delay(initial: Duration, maximum: Duration, attempt: u32) -> Duration {
    let factor = 1_u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
    initial.saturating_mul(factor).min(maximum)
}

fn sanitize_error(error: &str) -> String {
    let mut value: String = error
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect();
    for marker in ["token=", "authorization:", "bearer "] {
        if value.to_ascii_lowercase().contains(marker) {
            value = "signaling connection failed (secret-bearing detail redacted)".into();
            break;
        }
    }
    value
}

#[derive(Default)]
struct SignalingInbox(Mutex<Vec<VerifiedSignalingEvent>>);

impl SignalingInbox {
    fn push(&self, event: VerifiedSignalingEvent) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }
}

#[async_trait::async_trait]
impl AuthenticatedSignalingPort for SignalingInbox {
    async fn drain_authenticated_events(&self) -> anyhow::Result<Vec<VerifiedSignalingEvent>> {
        let mut events = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(std::mem::take(&mut *events))
    }
}

/// Handle for stopping and joining the service-owned signaling task.
pub struct SignalingTask {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl SignalingTask {
    /// Stop the reconnect loop and wait for its connection to close.
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.join.await;
    }
}

/// Start optional signaling from environment configuration.
pub async fn spawn_from_env(
    app_state: Arc<AppState>,
) -> Result<Option<SignalingTask>, SignalingRuntimeError> {
    let (device_id, device_name) = {
        let devices = app_state.devices.lock().await;
        devices
            .get_local_device()
            .cloned()
            .ok_or(SignalingRuntimeError::LocalDeviceMissing)?
    };
    let Some(config) = SignalingConfig::from_env(device_id, &device_name)? else {
        return Ok(None);
    };
    Ok(Some(spawn(config, app_state)))
}

/// Spawn one explicitly configured service-owned signaling connection.
pub fn spawn(config: SignalingConfig, app_state: Arc<AppState>) -> SignalingTask {
    let identity = app_state.device_identities.machine_identity();
    let status = Arc::clone(&app_state.signaling_status);
    let mapper = Arc::new(ServiceSignalingMapper::new(app_state));
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        run_reconnect_loop(config, identity, status, mapper, shutdown_rx).await;
    });
    SignalingTask {
        shutdown: Some(shutdown),
        join,
    }
}

async fn run_reconnect_loop(
    config: SignalingConfig,
    identity: Arc<DeviceIdentity>,
    status: Arc<SignalingStatus>,
    mapper: Arc<ServiceSignalingMapper>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let mut core = SignalingRuntimeCore::with_status(config, identity, Arc::clone(&status));
    loop {
        status.note_connecting();
        let connection = run_connection(&mut core, &mapper, &mut shutdown).await;
        match connection {
            ConnectionExit::Shutdown => break,
            ConnectionExit::Failed(error) => {
                let now_ms = unix_time_ms();
                core.note_connection_failure(now_ms, &error.to_string());
                tracing::warn!(
                    reconnect_attempt = core.snapshot().reconnect_attempt,
                    error = %error,
                    "authenticated signaling connection unavailable"
                );
                let delay = core.reconnect_delay();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = &mut shutdown => break,
                }
            }
        }
    }
    status.note_stopped();
}

enum ConnectionExit {
    Shutdown,
    Failed(SignalingRuntimeError),
}

async fn run_connection(
    core: &mut SignalingRuntimeCore,
    mapper: &Arc<ServiceSignalingMapper>,
    shutdown: &mut tokio::sync::oneshot::Receiver<()>,
) -> ConnectionExit {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let endpoint = core.config().endpoint().as_str().to_owned();
    let connected = tokio::select! {
        _ = &mut *shutdown => return ConnectionExit::Shutdown,
        result = tokio::time::timeout(core.config().connect_timeout(), tokio_tungstenite::connect_async(endpoint)) => result,
    };
    let (socket, _) = match connected {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return ConnectionExit::Failed(error.into()),
        Err(_) => return ConnectionExit::Failed(SignalingRuntimeError::ConnectTimeout),
    };
    let (mut writer, mut reader) = socket.split();
    let challenge =
        match read_envelope(&mut reader, core.config().connect_timeout(), shutdown).await {
            Ok(Some(SignalEnvelope {
                message: AuthenticatedSignalMessage::ServerChallenge(challenge),
                ..
            })) => challenge,
            Ok(None) => return ConnectionExit::Shutdown,
            Ok(Some(_)) => return ConnectionExit::Failed(SignalingRuntimeError::UnexpectedMessage),
            Err(error) => return ConnectionExit::Failed(error),
        };
    let now_ms = unix_time_ms();
    let registration = match core.build_registration(challenge, now_ms) {
        Ok(value) => value,
        Err(error) => return ConnectionExit::Failed(error),
    };
    if let Err(error) = send_envelope(&mut writer, registration).await {
        return ConnectionExit::Failed(error);
    }
    let acknowledgement =
        match read_envelope(&mut reader, core.config().connect_timeout(), shutdown).await {
            Ok(Some(SignalEnvelope {
                message: AuthenticatedSignalMessage::Registered(value),
                ..
            })) => value,
            Ok(None) => return ConnectionExit::Shutdown,
            Ok(Some(_)) => return ConnectionExit::Failed(SignalingRuntimeError::UnexpectedMessage),
            Err(error) => return ConnectionExit::Failed(error),
        };
    if let Err(error) = core.accept_registered(acknowledgement, unix_time_ms()) {
        return ConnectionExit::Failed(error);
    }

    let inbox = SignalingInbox::default();
    let mut heartbeat_tick = tokio::time::interval(Duration::from_millis(100));
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = &mut *shutdown => {
                let _ = writer.send(Message::Close(None)).await;
                return ConnectionExit::Shutdown;
            }
            _ = heartbeat_tick.tick() => {
                match core.heartbeat_if_due(unix_time_ms()) {
                    Ok(Some(heartbeat)) => if let Err(error) = send_envelope(&mut writer, heartbeat).await {
                        return ConnectionExit::Failed(error);
                    },
                    Ok(None) => {}
                    Err(error) => return ConnectionExit::Failed(error),
                }
            }
            message = reader.next() => {
                let envelope = match decode_socket_message(message) {
                    Ok(Some(value)) => value,
                    Ok(None) => continue,
                    Err(error) => return ConnectionExit::Failed(error),
                };
                match core.handle_inbound(envelope, unix_time_ms()) {
                    Ok(InboundDisposition::Applied(event)) => {
                        inbox.push(*event);
                        if let Err(error) = apply_authenticated_realtime_events(&inbox, mapper.as_ref()).await {
                            return ConnectionExit::Failed(SignalingRuntimeError::Apply(error));
                        }
                    }
                    Ok(InboundDisposition::Duplicate | InboundDisposition::Control) => {}
                    Err(error) => return ConnectionExit::Failed(error),
                }
            }
        }
    }
}

async fn read_envelope<S>(
    reader: &mut S,
    timeout: Duration,
    shutdown: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<Option<SignalEnvelope>, SignalingRuntimeError>
where
    S: futures_util::Stream<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
{
    loop {
        let message = tokio::select! {
            _ = &mut *shutdown => return Ok(None),
            result = tokio::time::timeout(timeout, futures_util::StreamExt::next(reader)) => result,
        };
        let message = message.map_err(|_| SignalingRuntimeError::HandshakeTimeout)?;
        match decode_socket_message(message)? {
            Some(envelope) => return Ok(Some(envelope)),
            None => continue,
        }
    }
}

fn decode_socket_message(
    message: Option<
        Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
    >,
) -> Result<Option<SignalEnvelope>, SignalingRuntimeError> {
    use tokio_tungstenite::tungstenite::Message;
    match message {
        Some(Ok(Message::Text(raw))) => mrd_signal_client::decode_authenticated_message(&raw)
            .map(Some)
            .map_err(Into::into),
        Some(Ok(Message::Binary(raw))) => {
            let raw = std::str::from_utf8(&raw).map_err(|_| SignalingRuntimeError::InvalidUtf8)?;
            mrd_signal_client::decode_authenticated_message(raw)
                .map(Some)
                .map_err(Into::into)
        }
        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => Ok(None),
        Some(Ok(Message::Close(_))) | None => Err(SignalingRuntimeError::Disconnected),
        Some(Err(error)) => Err(error.into()),
    }
}

async fn send_envelope<S>(
    writer: &mut S,
    envelope: SignalEnvelope,
) -> Result<(), SignalingRuntimeError>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    use futures_util::SinkExt;
    let raw = mrd_signal_client::encode_authenticated_message(&envelope)?;
    writer
        .send(tokio_tungstenite::tungstenite::Message::Text(raw))
        .await
        .map_err(Into::into)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Authenticated signaling runtime failure.
#[derive(Debug, Error)]
pub enum SignalingRuntimeError {
    #[error(transparent)]
    Config(#[from] SignalingConfigError),
    #[error(transparent)]
    Protocol(#[from] SignalProtocolError),
    #[error(transparent)]
    Client(#[from] mrd_signal_client::SignalClientError),
    #[error("signaling transport failed: {0}")]
    Transport(String),
    #[error("signaling payload serialization failed: {0}")]
    Serialize(serde_json::Error),
    #[error("signaling challenge is invalid or expired")]
    InvalidChallenge,
    #[error("signaling server identity does not match configuration")]
    ServerIdentityMismatch,
    #[error("signaling peer changed its authenticated key")]
    PeerIdentityChanged,
    #[error("signaling peer identity capacity is exhausted")]
    PeerCapacity,
    #[error("signaling message is not valid for this connection role")]
    RoleMismatch,
    #[error("signaling message arrived in an invalid protocol phase")]
    UnexpectedMessage,
    #[error("signaling runtime is not authenticated")]
    NotAuthenticated,
    #[error("signaling heartbeat interval is outside the supported bounds")]
    InvalidHeartbeatInterval,
    #[error("signaling counter is exhausted")]
    CounterExhausted,
    #[error("signaling entropy is unavailable")]
    EntropyUnavailable,
    #[error("signaling server rejected the protocol message: {0}")]
    ServerProtocol(String),
    #[error("signaling connect timed out")]
    ConnectTimeout,
    #[error("signaling authentication handshake timed out")]
    HandshakeTimeout,
    #[error("signaling connection closed")]
    Disconnected,
    #[error("signaling binary message is not UTF-8")]
    InvalidUtf8,
    #[error("local device registration is unavailable")]
    LocalDeviceMissing,
    #[error("applying an authenticated signaling event failed: {0}")]
    Apply(#[source] anyhow::Error),
}

impl From<tokio_tungstenite::tungstenite::Error> for SignalingRuntimeError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Transport(error.to_string())
    }
}
