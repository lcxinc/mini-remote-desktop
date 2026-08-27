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
    RegisterPayload, Registered, RelayMigrationAnswer, RelayMigrationAnswerPayload,
    RelayMigrationCandidate, RelayMigrationCandidatePayload, RelayMigrationOffer,
    RelayMigrationOfferPayload, ServerChallenge, SessionGrantV3, SessionGrantV3Payload,
    SessionIntentV3, SessionIntentV3Payload, SignalEnvelope, SignalProtocolError,
    SignalReplayGuard, WanMediaProfileV3, WanPermissionScopeV3, WanRoutePolicyV3,
    WanSessionRequestV3, WebRtcAnswerV3, WebRtcAnswerV3Payload, WebRtcCandidateV3,
    WebRtcCandidateV3Payload, WebRtcDescriptionRoleV3, WebRtcOfferV3, WebRtcOfferV3Payload,
};
use ring::{digest, rand::SecureRandom, rand::SystemRandom};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use thiserror::Error;

const ACCEPTED_MESSAGE_LIMIT: usize = 4_096;
const PEER_KEY_LIMIT: usize = 4_096;
const MAX_CHALLENGE_LIFETIME_MS: u64 = 60_000;
const MIN_HEARTBEAT_INTERVAL_MS: u64 = 250;
const MAX_HEARTBEAT_INTERVAL_MS: u64 = 300_000;
const RELAY_SIGNAL_QUEUE_CAPACITY: usize = 128;
const RELAY_EVENT_QUEUE_CAPACITY: usize = 256;

pub const AUTHENTICATED_SESSION_SIGNAL_QUEUE_CAPACITY: usize = RELAY_SIGNAL_QUEUE_CAPACITY;

#[derive(Clone, PartialEq, Eq)]
pub enum OutboundAuthenticatedSessionSignal {
    SessionIntent {
        request: WanSessionRequestV3,
    },
    SessionGrant {
        session_id: mrd_proto::SessionId,
        controller_device_id: mrd_proto::DeviceId,
        target_device_id: mrd_proto::DeviceId,
        intent_commitment: String,
        approved_scopes: Vec<WanPermissionScopeV3>,
        approved_profile: Option<WanMediaProfileV3>,
        backend_policy_revision: u64,
        policy_expires_at_ms: u64,
        relay_generation: u64,
        relay_directory_id: String,
        primary_relay_node_id: String,
        route_policy: WanRoutePolicyV3,
    },
    WebRtcOffer {
        session_id: mrd_proto::SessionId,
        controller_device_id: mrd_proto::DeviceId,
        target_device_id: mrd_proto::DeviceId,
        grant_commitment: String,
        sdp: String,
        candidate_fingerprints: Vec<String>,
    },
    WebRtcAnswer {
        session_id: mrd_proto::SessionId,
        controller_device_id: mrd_proto::DeviceId,
        target_device_id: mrd_proto::DeviceId,
        grant_commitment: String,
        sdp: String,
        candidate_fingerprints: Vec<String>,
    },
    WebRtcCandidate {
        session_id: mrd_proto::SessionId,
        controller_device_id: mrd_proto::DeviceId,
        target_device_id: mrd_proto::DeviceId,
        grant_commitment: String,
        description_role: WebRtcDescriptionRoleV3,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
        username_fragment: Option<String>,
        candidate_fingerprint: String,
    },
}

impl OutboundAuthenticatedSessionSignal {
    pub fn session_id(&self) -> &mrd_proto::SessionId {
        match self {
            Self::SessionIntent { request } => &request.session_id,
            Self::SessionGrant { session_id, .. }
            | Self::WebRtcOffer { session_id, .. }
            | Self::WebRtcAnswer { session_id, .. }
            | Self::WebRtcCandidate { session_id, .. } => session_id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::SessionIntent { .. } => "session_intent_v3",
            Self::SessionGrant { .. } => "session_grant_v3",
            Self::WebRtcOffer { .. } => "webrtc_offer_v3",
            Self::WebRtcAnswer { .. } => "webrtc_answer_v3",
            Self::WebRtcCandidate { .. } => "webrtc_candidate_v3",
        }
    }
}

impl std::fmt::Debug for OutboundAuthenticatedSessionSignal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundAuthenticatedSessionSignal")
            .field("kind", &self.kind())
            .field("session_id", self.session_id())
            .field("body", &"REDACTED")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionSignalingCommand {
    pub peer_device_id: mrd_proto::DeviceId,
    pub signal: OutboundAuthenticatedSessionSignal,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AuthenticatedSessionSignalingSendError {
    #[error("authenticated signaling is unavailable")]
    Unavailable,
    #[error("authenticated signaling queue is full")]
    Backpressure,
    #[error("authenticated session signaling command is invalid")]
    Invalid,
    #[error("authenticated session signaling is closed")]
    SessionClosed,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AuthenticatedSessionSignalingReceiveError {
    #[error("authenticated session signaling is closed")]
    SessionClosed,
    #[error("authenticated session signaling stream closed")]
    Closed,
    #[error("authenticated session signaling stream overflowed")]
    Lagged,
}

pub struct AuthenticatedSessionSignalingReceipt {
    completed: tokio::sync::oneshot::Receiver<Result<(), AuthenticatedSessionSignalingSendError>>,
}

impl std::fmt::Debug for AuthenticatedSessionSignalingReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedSessionSignalingReceipt")
            .finish_non_exhaustive()
    }
}

impl AuthenticatedSessionSignalingReceipt {
    pub async fn wait(self) -> Result<(), AuthenticatedSessionSignalingSendError> {
        self.completed
            .await
            .map_err(|_| AuthenticatedSessionSignalingSendError::Unavailable)?
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum OutboundRelayMigrationSignal {
    Offer {
        session_id: mrd_proto::SessionId,
        migration_generation: u64,
        directory_id: String,
        node_id: String,
        sdp: String,
        restart_route_token: String,
        candidate_fingerprints: BTreeSet<String>,
    },
    Answer {
        session_id: mrd_proto::SessionId,
        migration_generation: u64,
        directory_id: String,
        node_id: String,
        sdp: String,
        restart_route_token: String,
        candidate_fingerprints: BTreeSet<String>,
    },
    Candidate {
        session_id: mrd_proto::SessionId,
        migration_generation: u64,
        directory_id: String,
        node_id: String,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
        username_fragment: Option<String>,
        restart_route_token: String,
        candidate_fingerprint: String,
    },
}

impl std::fmt::Debug for OutboundRelayMigrationSignal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, generation) = match self {
            Self::Offer {
                migration_generation,
                ..
            } => ("offer", migration_generation),
            Self::Answer {
                migration_generation,
                ..
            } => ("answer", migration_generation),
            Self::Candidate {
                migration_generation,
                ..
            } => ("candidate", migration_generation),
        };
        formatter
            .debug_struct("OutboundRelayMigrationSignal")
            .field("kind", &kind)
            .field("migration_generation", generation)
            .field("body", &"REDACTED")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySignalingCommand {
    pub peer_device_id: mrd_proto::DeviceId,
    pub signal: OutboundRelayMigrationSignal,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum RelaySignalingSendError {
    #[error("authenticated signaling is unavailable")]
    Unavailable,
    #[error("relay signaling command is invalid")]
    Invalid,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum RelaySignalingReceiveError {
    #[error("authenticated relay signaling stream closed")]
    Closed,
    #[error("authenticated relay signaling stream overflowed")]
    Lagged,
}

struct OutboundRelaySignalingRequest {
    command: RelaySignalingCommand,
    completion: tokio::sync::oneshot::Sender<Result<(), RelaySignalingSendError>>,
}

struct OutboundAuthenticatedSessionSignalingRequest {
    request_id: u64,
    command: AuthenticatedSessionSignalingCommand,
}

struct PendingAuthenticatedSessionSignalingRequest {
    session_id: mrd_proto::SessionId,
    completion: tokio::sync::oneshot::Sender<Result<(), AuthenticatedSessionSignalingSendError>>,
}

#[derive(Default)]
struct AuthenticatedSessionBusState {
    closed: HashSet<mrd_proto::SessionId>,
    pending: HashMap<u64, PendingAuthenticatedSessionSignalingRequest>,
    queued: VecDeque<OutboundAuthenticatedSessionSignalingRequest>,
}

pub struct RelaySignalingBus {
    outbound: tokio::sync::mpsc::Sender<OutboundRelaySignalingRequest>,
    receiver: Mutex<Option<tokio::sync::mpsc::Receiver<OutboundRelaySignalingRequest>>>,
    inbound: tokio::sync::broadcast::Sender<VerifiedSignalingEvent>,
    closed_signal: tokio::sync::watch::Sender<u64>,
    history: Mutex<VecDeque<VerifiedSignalingEvent>>,
    authenticated: Mutex<AuthenticatedSessionBusState>,
    authenticated_lifecycle: tokio::sync::RwLock<()>,
    authenticated_ready: tokio::sync::Notify,
    next_authenticated_request_id: std::sync::atomic::AtomicU64,
    active: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for RelaySignalingBus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelaySignalingBus")
            .field(
                "active",
                &self.active.load(std::sync::atomic::Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl Default for RelaySignalingBus {
    fn default() -> Self {
        let (outbound, receiver) = tokio::sync::mpsc::channel(RELAY_SIGNAL_QUEUE_CAPACITY);
        let (inbound, _) = tokio::sync::broadcast::channel(RELAY_EVENT_QUEUE_CAPACITY);
        let (closed_signal, _) = tokio::sync::watch::channel(0);
        Self {
            outbound,
            receiver: Mutex::new(Some(receiver)),
            inbound,
            closed_signal,
            history: Mutex::new(VecDeque::with_capacity(RELAY_EVENT_QUEUE_CAPACITY)),
            authenticated: Mutex::new(AuthenticatedSessionBusState::default()),
            authenticated_lifecycle: tokio::sync::RwLock::new(()),
            authenticated_ready: tokio::sync::Notify::new(),
            next_authenticated_request_id: std::sync::atomic::AtomicU64::new(1),
            active: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl RelaySignalingBus {
    pub async fn send(
        &self,
        command: RelaySignalingCommand,
    ) -> Result<(), RelaySignalingSendError> {
        if !self.active.load(std::sync::atomic::Ordering::Acquire) {
            return Err(RelaySignalingSendError::Unavailable);
        }
        let (completion, completed) = tokio::sync::oneshot::channel();
        self.outbound
            .send(OutboundRelaySignalingRequest {
                command,
                completion,
            })
            .await
            .map_err(|_| RelaySignalingSendError::Unavailable)?;
        completed
            .await
            .map_err(|_| RelaySignalingSendError::Unavailable)?
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<VerifiedSignalingEvent> {
        self.inbound.subscribe()
    }

    pub fn subscribe_migration(
        &self,
        session_id: mrd_proto::SessionId,
        generation: u64,
    ) -> RelaySignalingSubscription {
        let history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let live = self.inbound.subscribe();
        let replay = history
            .iter()
            .filter(|event| relay_event_matches(event, &session_id, generation))
            .cloned()
            .collect();
        RelaySignalingSubscription {
            session_id,
            generation,
            replay,
            live,
        }
    }

    pub fn try_send_authenticated(
        &self,
        command: AuthenticatedSessionSignalingCommand,
    ) -> Result<AuthenticatedSessionSignalingReceipt, AuthenticatedSessionSignalingSendError> {
        let session_id = command.signal.session_id().clone();
        let request_id = self
            .next_authenticated_request_id
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |current| current.checked_add(1),
            )
            .map_err(|_| AuthenticatedSessionSignalingSendError::Invalid)?;
        let (completion, completed) = tokio::sync::oneshot::channel();
        {
            let mut authenticated = self
                .authenticated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if authenticated.closed.contains(&session_id) {
                return Err(AuthenticatedSessionSignalingSendError::SessionClosed);
            }
            if !self.active.load(std::sync::atomic::Ordering::Acquire) {
                return Err(AuthenticatedSessionSignalingSendError::Unavailable);
            }
            if authenticated.pending.len() >= AUTHENTICATED_SESSION_SIGNAL_QUEUE_CAPACITY {
                return Err(AuthenticatedSessionSignalingSendError::Backpressure);
            }
            authenticated.pending.insert(
                request_id,
                PendingAuthenticatedSessionSignalingRequest {
                    session_id,
                    completion,
                },
            );
            authenticated
                .queued
                .push_back(OutboundAuthenticatedSessionSignalingRequest {
                    request_id,
                    command,
                });
        }
        self.authenticated_ready.notify_one();
        Ok(AuthenticatedSessionSignalingReceipt { completed })
    }

    pub fn subscribe_authenticated_session(
        self: &Arc<Self>,
        session_id: mrd_proto::SessionId,
        peer_device_id: mrd_proto::DeviceId,
    ) -> AuthenticatedSessionSignalingSubscription {
        let history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let live = self.inbound.subscribe();
        let replay = history
            .iter()
            .filter(|event| {
                authenticated_session_event_matches(event, &session_id, &peer_device_id)
            })
            .cloned()
            .collect();
        AuthenticatedSessionSignalingSubscription {
            bus: Arc::clone(self),
            session_id,
            peer_device_id,
            replay,
            live,
            closed_signal: self.closed_signal.subscribe(),
        }
    }

    pub async fn close_authenticated_session(
        &self,
        session_id: &mrd_proto::SessionId,
    ) -> Result<(), AuthenticatedSessionSignalingSendError> {
        let _lifecycle = self.authenticated_lifecycle.write().await;
        let completions = {
            let mut authenticated = self
                .authenticated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            authenticated.closed.insert(session_id.clone());
            authenticated
                .queued
                .retain(|request| request.command.signal.session_id() != session_id);
            let request_ids = authenticated
                .pending
                .iter()
                .filter_map(|(request_id, pending)| {
                    (pending.session_id == *session_id).then_some(*request_id)
                })
                .collect::<Vec<_>>();
            request_ids
                .into_iter()
                .filter_map(|request_id| {
                    authenticated
                        .pending
                        .remove(&request_id)
                        .map(|pending| pending.completion)
                })
                .collect::<Vec<_>>()
        };
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|event| event.signal.session_id() != session_id);
        for completion in completions {
            let _ = completion.send(Err(AuthenticatedSessionSignalingSendError::SessionClosed));
        }
        self.closed_signal
            .send_modify(|version| *version = version.wrapping_add(1));
        Ok(())
    }

    pub(crate) async fn publish(&self, event: VerifiedSignalingEvent) {
        let _lifecycle = self.authenticated_lifecycle.read().await;
        let authenticated = self
            .authenticated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if authenticated.closed.contains(event.signal.session_id()) {
            return;
        }
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if history.len() == RELAY_EVENT_QUEUE_CAPACITY {
            history.pop_front();
        }
        history.push_back(event.clone());
        let _ = self.inbound.send(event);
    }

    fn take_receiver(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<OutboundRelaySignalingRequest>, SignalingRuntimeError>
    {
        self.receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or(SignalingRuntimeError::AlreadyStarted)
    }

    async fn recv_authenticated(&self) -> Option<OutboundAuthenticatedSessionSignalingRequest> {
        loop {
            let notified = self.authenticated_ready.notified();
            if let Some(request) = self
                .authenticated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .queued
                .pop_front()
            {
                return Some(request);
            }
            if !self.active.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            notified.await;
        }
    }

    fn set_active(&self, active: bool) {
        self.active
            .store(active, std::sync::atomic::Ordering::Release);
        if !active {
            self.authenticated_ready.notify_waiters();
        }
    }

    fn is_authenticated_session_closed(&self, session_id: &mrd_proto::SessionId) -> bool {
        self.authenticated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
            .contains(session_id)
    }

    fn authenticated_request_is_live(&self, request_id: u64) -> bool {
        let mut authenticated = self
            .authenticated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stale = authenticated
            .pending
            .get(&request_id)
            .map(|pending| {
                pending.completion.is_closed() || authenticated.closed.contains(&pending.session_id)
            })
            .unwrap_or(true);
        if stale {
            authenticated.pending.remove(&request_id);
            false
        } else {
            true
        }
    }

    async fn admit_authenticated_request(
        &self,
        request_id: u64,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        let lifecycle = self.authenticated_lifecycle.read().await;
        if self.authenticated_request_is_live(request_id) {
            Some(lifecycle)
        } else {
            None
        }
    }

    fn complete_authenticated(
        &self,
        request_id: u64,
        result: Result<(), AuthenticatedSessionSignalingSendError>,
    ) {
        let completion = self
            .authenticated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(&request_id)
            .map(|pending| pending.completion);
        if let Some(completion) = completion {
            let _ = completion.send(result);
        }
    }

    fn fail_all_authenticated(&self) {
        let completions = {
            let mut authenticated = self
                .authenticated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            authenticated.queued.clear();
            authenticated
                .pending
                .drain()
                .map(|(_, pending)| pending.completion)
                .collect::<Vec<_>>()
        };
        for completion in completions {
            let _ = completion.send(Err(AuthenticatedSessionSignalingSendError::Unavailable));
        }
    }
}

pub struct RelaySignalingSubscription {
    session_id: mrd_proto::SessionId,
    generation: u64,
    replay: VecDeque<VerifiedSignalingEvent>,
    live: tokio::sync::broadcast::Receiver<VerifiedSignalingEvent>,
}

impl RelaySignalingSubscription {
    pub async fn recv(&mut self) -> Result<VerifiedSignalingEvent, RelaySignalingReceiveError> {
        if let Some(event) = self.replay.pop_front() {
            return Ok(event);
        }
        loop {
            match self.live.recv().await {
                Ok(event) if relay_event_matches(&event, &self.session_id, self.generation) => {
                    return Ok(event);
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err(RelaySignalingReceiveError::Closed);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    return Err(RelaySignalingReceiveError::Lagged);
                }
            }
        }
    }
}

pub struct AuthenticatedSessionSignalingSubscription {
    bus: Arc<RelaySignalingBus>,
    session_id: mrd_proto::SessionId,
    peer_device_id: mrd_proto::DeviceId,
    replay: VecDeque<VerifiedSignalingEvent>,
    live: tokio::sync::broadcast::Receiver<VerifiedSignalingEvent>,
    closed_signal: tokio::sync::watch::Receiver<u64>,
}

impl std::fmt::Debug for AuthenticatedSessionSignalingSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedSessionSignalingSubscription")
            .field("session_id", &self.session_id)
            .field("peer_device_id", &self.peer_device_id)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedSessionSignalingSubscription {
    pub async fn recv(
        &mut self,
    ) -> Result<VerifiedSignalingEvent, AuthenticatedSessionSignalingReceiveError> {
        loop {
            let lifecycle = self.bus.authenticated_lifecycle.read().await;
            if self.bus.is_authenticated_session_closed(&self.session_id) {
                self.replay.clear();
                return Err(AuthenticatedSessionSignalingReceiveError::SessionClosed);
            }
            if let Some(event) = self.replay.pop_front() {
                return Ok(event);
            }
            drop(lifecycle);
            tokio::select! {
                event = self.live.recv() => match event {
                    Ok(event)
                        if authenticated_session_event_matches(
                            &event,
                            &self.session_id,
                            &self.peer_device_id,
                        ) =>
                    {
                        let _lifecycle = self.bus.authenticated_lifecycle.read().await;
                        if self.bus.is_authenticated_session_closed(&self.session_id) {
                            self.replay.clear();
                            return Err(AuthenticatedSessionSignalingReceiveError::SessionClosed);
                        }
                        return Ok(event);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(AuthenticatedSessionSignalingReceiveError::Closed);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        return Err(AuthenticatedSessionSignalingReceiveError::Lagged);
                    }
                },
                changed = self.closed_signal.changed() => {
                    if changed.is_err() {
                        return Err(AuthenticatedSessionSignalingReceiveError::Closed);
                    }
                }
            }
        }
    }
}

fn relay_event_matches(
    event: &VerifiedSignalingEvent,
    session_id: &mrd_proto::SessionId,
    generation: u64,
) -> bool {
    match &event.signal {
        AuthenticatedSessionSignal::RelayMigrationOffer {
            session_id: current,
            migration_generation,
            ..
        }
        | AuthenticatedSessionSignal::RelayMigrationAnswer {
            session_id: current,
            migration_generation,
            ..
        }
        | AuthenticatedSessionSignal::RelayMigrationCandidate {
            session_id: current,
            migration_generation,
            ..
        } => current == session_id && *migration_generation == generation,
        _ => false,
    }
}

fn authenticated_session_event_matches(
    event: &VerifiedSignalingEvent,
    session_id: &mrd_proto::SessionId,
    peer_device_id: &mrd_proto::DeviceId,
) -> bool {
    event.sender.device_id == *peer_device_id
        && event.signal.session_id() == session_id
        && matches!(
            &event.signal,
            AuthenticatedSessionSignal::SessionIntentV3 { .. }
                | AuthenticatedSessionSignal::SessionGrantV3 { .. }
                | AuthenticatedSessionSignal::WebRtcOfferV3 { .. }
                | AuthenticatedSessionSignal::WebRtcAnswerV3 { .. }
                | AuthenticatedSessionSignal::WebRtcCandidateV3 { .. }
                | AuthenticatedSessionSignal::Denied { .. }
                | AuthenticatedSessionSignal::Closed { .. }
        )
}

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
        error: &SignalingRuntimeError,
    ) {
        let mut status = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        status.state = SignalingConnectionState::Backoff;
        status.reconnect_attempt = reconnect_attempt;
        status.next_retry_at_ms =
            Some(now_ms.saturating_add(retry_after.as_millis().min(u128::from(u64::MAX)) as u64));
        status.last_error = Some(error.code().into());
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

    pub fn build_authenticated_session_signal(
        &mut self,
        command: AuthenticatedSessionSignalingCommand,
        now_ms: u64,
    ) -> Result<SignalEnvelope, SignalingRuntimeError> {
        let peer_device_id = command.peer_device_id;
        let message = match command.signal {
            OutboundAuthenticatedSessionSignal::SessionIntent { request } => {
                self.require_role(BackendRole::Controller)?;
                if request.controller_device_id != *self.config.device_id()
                    || request.target_device_id != peer_device_id
                {
                    return Err(SignalingRuntimeError::RoleMismatch);
                }
                let request_commitment = request.commitment()?;
                let claims = self.next_claims(peer_device_id, now_ms)?;
                AuthenticatedSignalMessage::SessionIntentV3(SessionIntentV3::sign(
                    &self.identity,
                    SessionIntentV3Payload {
                        claims,
                        request,
                        request_commitment,
                    },
                )?)
            }
            OutboundAuthenticatedSessionSignal::SessionGrant {
                session_id,
                controller_device_id,
                target_device_id,
                intent_commitment,
                approved_scopes,
                approved_profile,
                backend_policy_revision,
                policy_expires_at_ms,
                relay_generation,
                relay_directory_id,
                primary_relay_node_id,
                route_policy,
            } => {
                self.require_role(BackendRole::Agent)?;
                if controller_device_id != peer_device_id
                    || target_device_id != *self.config.device_id()
                {
                    return Err(SignalingRuntimeError::RoleMismatch);
                }
                let claims = self.next_claims(peer_device_id, now_ms)?;
                AuthenticatedSignalMessage::SessionGrantV3(SessionGrantV3::sign(
                    &self.identity,
                    SessionGrantV3Payload {
                        claims,
                        session_id,
                        controller_device_id,
                        target_device_id,
                        intent_commitment,
                        approved_scopes,
                        approved_profile,
                        backend_policy_revision,
                        policy_expires_at_ms,
                        relay_generation,
                        relay_directory_id,
                        primary_relay_node_id,
                        route_policy,
                    },
                )?)
            }
            OutboundAuthenticatedSessionSignal::WebRtcOffer {
                session_id,
                controller_device_id,
                target_device_id,
                grant_commitment,
                sdp,
                candidate_fingerprints,
            } => {
                self.require_role(BackendRole::Controller)?;
                if controller_device_id != *self.config.device_id()
                    || target_device_id != peer_device_id
                {
                    return Err(SignalingRuntimeError::RoleMismatch);
                }
                let claims = self.next_claims(peer_device_id, now_ms)?;
                AuthenticatedSignalMessage::WebrtcOfferV3(WebRtcOfferV3::sign(
                    &self.identity,
                    WebRtcOfferV3Payload {
                        claims,
                        session_id,
                        controller_device_id,
                        target_device_id,
                        grant_commitment,
                        sdp,
                        candidate_fingerprints,
                    },
                )?)
            }
            OutboundAuthenticatedSessionSignal::WebRtcAnswer {
                session_id,
                controller_device_id,
                target_device_id,
                grant_commitment,
                sdp,
                candidate_fingerprints,
            } => {
                self.require_role(BackendRole::Agent)?;
                if controller_device_id != peer_device_id
                    || target_device_id != *self.config.device_id()
                {
                    return Err(SignalingRuntimeError::RoleMismatch);
                }
                let claims = self.next_claims(peer_device_id, now_ms)?;
                AuthenticatedSignalMessage::WebrtcAnswerV3(WebRtcAnswerV3::sign(
                    &self.identity,
                    WebRtcAnswerV3Payload {
                        claims,
                        session_id,
                        controller_device_id,
                        target_device_id,
                        grant_commitment,
                        sdp,
                        candidate_fingerprints,
                    },
                )?)
            }
            OutboundAuthenticatedSessionSignal::WebRtcCandidate {
                session_id,
                controller_device_id,
                target_device_id,
                grant_commitment,
                description_role,
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
                candidate_fingerprint,
            } => {
                let (required_role, expected_local, expected_peer) = match description_role {
                    WebRtcDescriptionRoleV3::Offer => (
                        BackendRole::Controller,
                        &controller_device_id,
                        &target_device_id,
                    ),
                    WebRtcDescriptionRoleV3::Answer => {
                        (BackendRole::Agent, &target_device_id, &controller_device_id)
                    }
                };
                self.require_role(required_role)?;
                if expected_local != self.config.device_id() || expected_peer != &peer_device_id {
                    return Err(SignalingRuntimeError::RoleMismatch);
                }
                let claims = self.next_claims(peer_device_id, now_ms)?;
                AuthenticatedSignalMessage::WebrtcCandidateV3(WebRtcCandidateV3::sign(
                    &self.identity,
                    WebRtcCandidateV3Payload {
                        claims,
                        session_id,
                        controller_device_id,
                        target_device_id,
                        grant_commitment,
                        description_role,
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                        username_fragment,
                        candidate_fingerprint,
                    },
                )?)
            }
        };
        Ok(SignalEnvelope::new(message))
    }

    pub fn build_relay_migration_signal(
        &mut self,
        command: RelaySignalingCommand,
        now_ms: u64,
    ) -> Result<SignalEnvelope, SignalingRuntimeError> {
        let claims = self.next_claims(command.peer_device_id, now_ms)?;
        let message = match command.signal {
            OutboundRelayMigrationSignal::Offer {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                sdp,
                restart_route_token,
                candidate_fingerprints,
            } => AuthenticatedSignalMessage::RelayMigrationOffer(RelayMigrationOffer::sign(
                &self.identity,
                RelayMigrationOfferPayload {
                    claims,
                    session_id,
                    migration_generation,
                    directory_id,
                    node_id,
                    sdp,
                    restart_route_token,
                    candidate_fingerprints,
                },
            )?),
            OutboundRelayMigrationSignal::Answer {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                sdp,
                restart_route_token,
                candidate_fingerprints,
            } => AuthenticatedSignalMessage::RelayMigrationAnswer(RelayMigrationAnswer::sign(
                &self.identity,
                RelayMigrationAnswerPayload {
                    claims,
                    session_id,
                    migration_generation,
                    directory_id,
                    node_id,
                    sdp,
                    restart_route_token,
                    candidate_fingerprints,
                },
            )?),
            OutboundRelayMigrationSignal::Candidate {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
                restart_route_token,
                candidate_fingerprint,
            } => {
                AuthenticatedSignalMessage::RelayMigrationCandidate(RelayMigrationCandidate::sign(
                    &self.identity,
                    RelayMigrationCandidatePayload {
                        claims,
                        session_id,
                        migration_generation,
                        directory_id,
                        node_id,
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                        username_fragment,
                        restart_route_token,
                        candidate_fingerprint,
                    },
                )?)
            }
        };
        Ok(SignalEnvelope::new(message))
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
            AuthenticatedSignalMessage::SessionIntent(_)
            | AuthenticatedSignalMessage::SessionGrant(_)
            | AuthenticatedSignalMessage::WebrtcOffer(_)
            | AuthenticatedSignalMessage::WebrtcAnswer(_)
            | AuthenticatedSignalMessage::WebrtcCandidate(_) => {
                return Err(SignalProtocolError::UnsupportedVersion.into());
            }
            AuthenticatedSignalMessage::SessionIntentV3(message) => (
                {
                    self.require_role(BackendRole::Agent)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::SessionIntentV3 {
                    message: message.clone(),
                },
            ),
            AuthenticatedSignalMessage::SessionGrantV3(message) => (
                {
                    self.require_role(BackendRole::Controller)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::SessionGrantV3 {
                    message: message.clone(),
                },
            ),
            AuthenticatedSignalMessage::WebrtcOfferV3(message) => (
                {
                    self.require_role(BackendRole::Agent)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::WebRtcOfferV3 {
                    message: message.clone(),
                },
            ),
            AuthenticatedSignalMessage::WebrtcAnswerV3(message) => (
                {
                    self.require_role(BackendRole::Controller)?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::WebRtcAnswerV3 {
                    message: message.clone(),
                },
            ),
            AuthenticatedSignalMessage::WebrtcCandidateV3(message) => (
                {
                    self.require_role(match message.payload.description_role {
                        WebRtcDescriptionRoleV3::Offer => BackendRole::Agent,
                        WebRtcDescriptionRoleV3::Answer => BackendRole::Controller,
                    })?;
                    message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?
                },
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::WebRtcCandidateV3 {
                    message: message.clone(),
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
            AuthenticatedSignalMessage::RelayMigrationOffer(message) => (
                message.verify_for(self.config.device_id(), now_ms, &mut self.replay)?,
                message.signer_public_key.clone(),
                AuthenticatedSessionSignal::RelayMigrationOffer {
                    session_id: message.payload.session_id.clone(),
                    migration_generation: message.payload.migration_generation,
                    directory_id: message.payload.directory_id.clone(),
                    node_id: message.payload.node_id.clone(),
                    sdp: message.payload.sdp.clone(),
                    restart_route_token: message.payload.restart_route_token.clone(),
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
                    restart_route_token: message.payload.restart_route_token.clone(),
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
                    username_fragment: message.payload.username_fragment.clone(),
                    restart_route_token: message.payload.restart_route_token.clone(),
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
                let _ = error;
                return Err(SignalingRuntimeError::ServerProtocol);
            }
            AuthenticatedSignalMessage::ReconnectGrant(_)
            | AuthenticatedSignalMessage::PresenceHeartbeat(_) => {
                return Err(SignalingRuntimeError::UnexpectedMessage);
            }
            AuthenticatedSignalMessage::ServerChallenge(_)
            | AuthenticatedSignalMessage::Register(_)
            | AuthenticatedSignalMessage::Registered(_)
            | AuthenticatedSignalMessage::ReconnectRequest(_) => {
                return Err(SignalingRuntimeError::UnexpectedMessage);
            }
        };
        match self.peer_keys.get(&metadata.issuer_device_id) {
            Some(existing) if existing != &metadata.issuer_key_id => {
                return Err(SignalingRuntimeError::PeerIdentityChanged);
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
    pub fn note_connection_failure(&mut self, now_ms: u64, error: &SignalingRuntimeError) {
        self.reconnect_attempt = self.reconnect_attempt.saturating_add(1);
        let delay = self.reconnect_delay();
        self.connection_id = None;
        self.heartbeat_interval = None;
        self.next_heartbeat_at_ms = None;
        self.status
            .note_disconnected(now_ms, self.reconnect_attempt, delay, error);
        tracing::warn!(
            reconnect_attempt = self.reconnect_attempt,
            error_code = error.code(),
            "authenticated signaling connection unavailable"
        );
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
        AuthenticatedSignalMessage::SessionIntentV3(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::SessionGrantV3(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::WebrtcOfferV3(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::WebrtcAnswerV3(value) => Some(&value.payload.claims),
        AuthenticatedSignalMessage::WebrtcCandidateV3(value) => Some(&value.payload.claims),
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
    let bytes = serde_json::to_vec(envelope).map_err(|_| SignalingRuntimeError::Serialize)?;
    digest::digest(&digest::SHA256, &bytes)
        .as_ref()
        .try_into()
        .map_err(|_| SignalingRuntimeError::EntropyUnavailable)
}

fn exponential_delay(initial: Duration, maximum: Duration, attempt: u32) -> Duration {
    let factor = 1_u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
    initial.saturating_mul(factor).min(maximum)
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
    Ok(Some(spawn(config, app_state)?))
}

/// Spawn one explicitly configured service-owned signaling connection.
pub fn spawn(
    config: SignalingConfig,
    app_state: Arc<AppState>,
) -> Result<SignalingTask, SignalingRuntimeError> {
    let identity = app_state.device_identities.machine_identity();
    let status = Arc::clone(&app_state.signaling_status);
    let relay_signaling = Arc::clone(&app_state.relay_signaling);
    let outbound = relay_signaling.take_receiver()?;
    relay_signaling.set_active(true);
    let mapper = Arc::new(ServiceSignalingMapper::new(Arc::clone(&app_state)));
    app_state
        .bind_signaling_mapper(Arc::clone(&mapper))
        .map_err(|_| SignalingRuntimeError::AlreadyStarted)?;
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        run_reconnect_loop(
            config,
            identity,
            status,
            mapper,
            relay_signaling,
            outbound,
            shutdown_rx,
        )
        .await;
    });
    Ok(SignalingTask {
        shutdown: Some(shutdown),
        join,
    })
}

async fn run_reconnect_loop(
    config: SignalingConfig,
    identity: Arc<DeviceIdentity>,
    status: Arc<SignalingStatus>,
    mapper: Arc<ServiceSignalingMapper>,
    relay_signaling: Arc<RelaySignalingBus>,
    mut outbound: tokio::sync::mpsc::Receiver<OutboundRelaySignalingRequest>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let mut core = SignalingRuntimeCore::with_status(config, identity, Arc::clone(&status));
    loop {
        status.note_connecting();
        let connection = run_connection(
            &mut core,
            &mapper,
            &relay_signaling,
            &mut outbound,
            &mut shutdown,
        )
        .await;
        match connection {
            ConnectionExit::Shutdown => break,
            ConnectionExit::Failed(error) => {
                let now_ms = unix_time_ms();
                core.note_connection_failure(now_ms, &error);
                let delay = core.reconnect_delay();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = &mut shutdown => break,
                }
            }
        }
    }
    relay_signaling.set_active(false);
    while let Ok(request) = outbound.try_recv() {
        let _ = request
            .completion
            .send(Err(RelaySignalingSendError::Unavailable));
    }
    relay_signaling.fail_all_authenticated();
    status.note_stopped();
}

enum ConnectionExit {
    Shutdown,
    Failed(SignalingRuntimeError),
}

async fn run_connection(
    core: &mut SignalingRuntimeCore,
    mapper: &Arc<ServiceSignalingMapper>,
    relay_signaling: &Arc<RelaySignalingBus>,
    outbound: &mut tokio::sync::mpsc::Receiver<OutboundRelaySignalingRequest>,
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
            request = outbound.recv() => {
                let Some(request) = request else {
                    return ConnectionExit::Failed(SignalingRuntimeError::OutboundClosed);
                };
                // A migration deadline may expire while signaling is reconnecting. Never emit
                // that now-ownerless command after its caller has stopped waiting.
                if request.completion.is_closed() {
                    continue;
                }
                let envelope = match core.build_relay_migration_signal(request.command, unix_time_ms()) {
                    Ok(envelope) => envelope,
                    Err(_) => {
                        let _ = request.completion.send(Err(RelaySignalingSendError::Invalid));
                        continue;
                    }
                };
                if request.completion.is_closed() {
                    continue;
                }
                if let Err(error) = send_envelope(&mut writer, envelope).await {
                    let _ = request.completion.send(Err(RelaySignalingSendError::Unavailable));
                    return ConnectionExit::Failed(error);
                }
                let _ = request.completion.send(Ok(()));
            }
            request = relay_signaling.recv_authenticated() => {
                let Some(request) = request else {
                    return ConnectionExit::Failed(SignalingRuntimeError::OutboundClosed);
                };
                let Some(_send_admission) = relay_signaling
                    .admit_authenticated_request(request.request_id)
                    .await
                else {
                    continue;
                };
                let envelope = match core.build_authenticated_session_signal(
                    request.command,
                    unix_time_ms(),
                ) {
                    Ok(envelope) => envelope,
                    Err(_) => {
                        relay_signaling.complete_authenticated(
                            request.request_id,
                            Err(AuthenticatedSessionSignalingSendError::Invalid),
                        );
                        continue;
                    }
                };
                if !relay_signaling.authenticated_request_is_live(request.request_id) {
                    continue;
                }
                if let Err(error) = send_envelope(&mut writer, envelope).await {
                    relay_signaling.complete_authenticated(
                        request.request_id,
                        Err(AuthenticatedSessionSignalingSendError::Unavailable),
                    );
                    return ConnectionExit::Failed(error);
                }
                relay_signaling.complete_authenticated(request.request_id, Ok(()));
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
                            let _ = error;
                            return ConnectionExit::Failed(SignalingRuntimeError::Apply);
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
    #[error("authenticated signaling runtime is already started")]
    AlreadyStarted,
    #[error("authenticated signaling outbound channel closed")]
    OutboundClosed,
    #[error(transparent)]
    Config(#[from] SignalingConfigError),
    #[error(transparent)]
    Protocol(#[from] SignalProtocolError),
    #[error("signaling codec failed")]
    Client,
    #[error("signaling transport failed")]
    Transport,
    #[error("signaling payload serialization failed")]
    Serialize,
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
    #[error("signaling server rejected the protocol message")]
    ServerProtocol,
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
    #[error("applying an authenticated signaling event failed")]
    Apply,
}

impl From<tokio_tungstenite::tungstenite::Error> for SignalingRuntimeError {
    fn from(_: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Transport
    }
}

impl From<mrd_signal_client::SignalClientError> for SignalingRuntimeError {
    fn from(_: mrd_signal_client::SignalClientError) -> Self {
        Self::Client
    }
}

impl SignalingRuntimeError {
    /// Return the closed, body-free code used by traces and health projections.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AlreadyStarted => "signaling_already_started",
            Self::OutboundClosed => "signaling_outbound_closed",
            Self::Config(_) => "signaling_config",
            Self::Protocol(error) => match error.reason_code() {
                mrd_signal_proto::ProtocolReasonCode::UnsupportedVersion => {
                    "signaling_protocol_unsupported_version"
                }
                mrd_signal_proto::ProtocolReasonCode::Malformed => "signaling_protocol_malformed",
                mrd_signal_proto::ProtocolReasonCode::AuthenticationFailed => {
                    "signaling_protocol_authentication_failed"
                }
                mrd_signal_proto::ProtocolReasonCode::WrongPeer => "signaling_protocol_wrong_peer",
                mrd_signal_proto::ProtocolReasonCode::Expired => "signaling_protocol_expired",
                mrd_signal_proto::ProtocolReasonCode::ReplayRejected => {
                    "signaling_protocol_replay_rejected"
                }
                _ => "signaling_protocol_rejected",
            },
            Self::Client => "signaling_codec",
            Self::Transport => "signaling_transport",
            Self::Serialize => "signaling_serialize",
            Self::InvalidChallenge => "signaling_invalid_challenge",
            Self::ServerIdentityMismatch => "signaling_server_identity_mismatch",
            Self::PeerIdentityChanged => "signaling_peer_identity_changed",
            Self::PeerCapacity => "signaling_peer_capacity",
            Self::RoleMismatch => "signaling_role_mismatch",
            Self::UnexpectedMessage => "signaling_unexpected_message",
            Self::NotAuthenticated => "signaling_not_authenticated",
            Self::InvalidHeartbeatInterval => "signaling_invalid_heartbeat_interval",
            Self::CounterExhausted => "signaling_counter_exhausted",
            Self::EntropyUnavailable => "signaling_entropy_unavailable",
            Self::ServerProtocol => "signaling_server_protocol",
            Self::ConnectTimeout => "signaling_connect_timeout",
            Self::HandshakeTimeout => "signaling_handshake_timeout",
            Self::Disconnected => "signaling_disconnected",
            Self::InvalidUtf8 => "signaling_invalid_utf8",
            Self::LocalDeviceMissing => "signaling_local_device_missing",
            Self::Apply => "signaling_apply",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated_command(session_id: &str) -> AuthenticatedSessionSignalingCommand {
        AuthenticatedSessionSignalingCommand {
            peer_device_id: mrd_proto::DeviceId("peer-device".into()),
            signal: OutboundAuthenticatedSessionSignal::SessionIntent {
                request: WanSessionRequestV3 {
                    session_id: mrd_proto::SessionId(session_id.into()),
                    idempotency_key: [1; 16],
                    controller_device_id: mrd_proto::DeviceId("local-device".into()),
                    target_device_id: mrd_proto::DeviceId("peer-device".into()),
                    access_mode: mrd_signal_proto::WanAccessModeV3::Attended,
                    requested_scopes: vec![WanPermissionScopeV3::ScreenView],
                    requested_profile: None,
                    route_policy: WanRoutePolicyV3::RelayOnly,
                },
            },
        }
    }

    #[tokio::test]
    async fn authenticated_send_admission_linearizes_session_close() {
        let bus = Arc::new(RelaySignalingBus::default());
        bus.set_active(true);
        let session_id = mrd_proto::SessionId("send-fence-session".into());
        let receipt = bus
            .try_send_authenticated(authenticated_command(&session_id.0))
            .unwrap();
        let request = bus.recv_authenticated().await.unwrap();
        let admission = bus
            .admit_authenticated_request(request.request_id)
            .await
            .expect("live request admitted");

        let closing_bus = Arc::clone(&bus);
        let closing_session = session_id.clone();
        let closing = tokio::spawn(async move {
            closing_bus
                .close_authenticated_session(&closing_session)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if bus.authenticated_lifecycle.try_read().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("close acquired write-fence priority");
        assert!(!closing.is_finished(), "close bypassed an admitted send");

        drop(admission);
        closing.await.unwrap().unwrap();
        assert!(bus
            .admit_authenticated_request(request.request_id)
            .await
            .is_none());
        assert_eq!(
            receipt.wait().await,
            Err(AuthenticatedSessionSignalingSendError::SessionClosed)
        );
    }
}
