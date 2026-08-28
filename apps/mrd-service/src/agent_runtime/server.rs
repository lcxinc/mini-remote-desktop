//! Bounded per-connection registration and lifecycle server.

use super::{
    AgentBinding, AgentConnectionId, AgentMediaIngress, AgentRegistry, AgentRegistryError,
    AgentRouteError, ObservedAgentIdentity,
};
use mrd_agent_ipc::{
    decode_frame, validate_consent_result, write_frame, AgentCapability, AgentHeartbeat,
    AgentStopping, AgentToService, CancelConsent, CommandResult, ConsentCancelReason,
    ConsentDecision, ConsentRequest, ConsentResult, ConsentValidationError, ExecuteCommand,
    FrameError, InputAck, InputEventEnvelope, InputRejection, MediaAccessUnit,
    RegisteredAgentIdentity, RenderAccessUnit, RenderBoundaryMetrics, ServiceToAgent, StopAgent,
    StopReason, ValidatedConsent, AGENT_IPC_CONSENT_CANCEL_PROTOCOL_MINOR,
    AGENT_IPC_CORRELATED_REQUESTS_PROTOCOL_MINOR, AGENT_IPC_FRAME_HEADER_BYTES,
    AGENT_IPC_MAX_FRAME_BYTES, AGENT_IPC_PROTOCOL_MAJOR,
    AGENT_IPC_RENDER_ACCESS_UNIT_PROTOCOL_MINOR, AGENT_IPC_RENDER_METRICS_PROTOCOL_MINOR,
    AGENT_IPC_RENDER_SURFACE_PROTOCOL_MINOR,
};
use mrd_proto::SessionId;
use std::{
    collections::{hash_map::Entry, HashMap},
    future::Future,
    io::ErrorKind,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

const INBOUND_QUEUE_CAPACITY: usize = 32;
const OUTBOUND_QUEUE_CAPACITY: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const REPLACED_STOP_GRACE_MS: u64 = 5_000;
const PENDING_REQUEST_CAPACITY: usize = 32;

/// Service clock boundary used by deterministic protocol tests.
pub trait AgentServerClock: Send + Sync {
    /// Current service time in Unix milliseconds.
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Default)]
struct SystemAgentServerClock;

impl AgentServerClock for SystemAgentServerClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }
}

/// Normal terminal state for one private agent connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentConnectionExit {
    /// Peer closed the private stream without a graceful stopping event.
    Disconnected,
    /// A bound `AgentStopping` event completed graceful shutdown.
    Stopped,
}

/// Validated attended-consent decision plus the exact agent generation that
/// displayed it. Callers persist this binding for later desktop-bound work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedConsent {
    binding: AgentBinding,
    consent: ValidatedConsent,
}

impl CorrelatedConsent {
    /// Exact generation and desktop capability that produced the decision.
    pub fn binding(&self) -> &AgentBinding {
        &self.binding
    }

    /// Consent result validated against the original request.
    pub fn consent(&self) -> &ValidatedConsent {
        &self.consent
    }

    /// Consume the correlation while preserving both security-relevant parts.
    pub fn into_parts(self) -> (AgentBinding, ValidatedConsent) {
        (self.binding, self.consent)
    }
}

/// Registration server failures. Any failure closes and revokes the connection.
#[derive(Debug, Error)]
pub enum AgentServerError {
    /// Registry rejected identity, proof, capability, or lifecycle state.
    #[error(transparent)]
    Registry(#[from] AgentRegistryError),
    /// Bounded control framing failed.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The peer did not complete the registration sequence in time.
    #[error("agent registration handshake timed out")]
    HandshakeTimeout,
    /// The stream ended during registration.
    #[error("agent disconnected during registration")]
    DisconnectedDuringHandshake,
    /// Registration messages arrived out of order.
    #[error("agent registration message sequence is invalid")]
    UnexpectedHandshakeMessage,
    /// A post-registration message is not yet supported by the service shell.
    #[error("agent sent an unsupported registered message")]
    UnsupportedRegisteredMessage,
    /// The connection id is already installed in the live server directory.
    #[error("agent connection id is already served")]
    DuplicateConnection,
    /// No live connection owns the requested outbound queue.
    #[error("agent connection is unavailable")]
    ConnectionUnavailable,
    /// The bounded outbound queue is full or closed.
    #[error("agent outbound queue is unavailable")]
    OutboundUnavailable,
    /// Peer stopped reading before a bounded control write completed.
    #[error("agent control write timed out")]
    WriteTimeout,
    /// A response-bearing message was sent through the one-way compatibility API.
    #[error("agent request requires correlated request/response routing")]
    ResponseRequired,
}

/// Failures for one exact, response-bearing request to a session agent.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AgentRequestError {
    /// The persisted agent binding is no longer routable.
    #[error(transparent)]
    Route(#[from] AgentRouteError),
    /// Input request fields violate the bounded IPC contract.
    #[error("agent input request is invalid: {0:?}")]
    InvalidInput(InputRejection),
    /// Consent request or result violates its correlation contract.
    #[error("agent consent request is invalid: {0}")]
    InvalidConsent(ConsentValidationError),
    /// A render unit violates the bounded service-to-agent media contract.
    #[error("agent render access unit is invalid")]
    InvalidRenderAccessUnit,
    /// No live server connection owns the exact bound connection.
    #[error("agent connection is unavailable")]
    ConnectionUnavailable,
    /// The exact connection's bounded outbound queue is full or closed.
    #[error("agent request queue is unavailable")]
    OutboundUnavailable,
    /// The same correlation identity already has an outstanding request.
    #[error("agent request correlation is already pending")]
    DuplicateRequest,
    /// The bounded pending-request directory or token space is exhausted.
    #[error("agent request capacity is exhausted")]
    CapacityExhausted,
    /// The exact agent generation was revoked while the request was pending.
    #[error("agent request was revoked")]
    Revoked,
    /// The authenticated agent disconnected while the request was pending.
    #[error("agent disconnected before responding")]
    Disconnected,
    /// No correlated response arrived within the configured deadline.
    #[error("agent request timed out")]
    Timeout,
    /// Correlation state could not be inspected safely.
    #[error("agent response correlation state is unavailable")]
    StateUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InputCorrelationKey {
    session_id: SessionId,
    resource_id: [u8; 16],
    start_grant_id: [u8; 32],
    sequence: u64,
}

impl InputCorrelationKey {
    fn from_event(event: &InputEventEnvelope) -> Self {
        Self {
            session_id: event.session_id.clone(),
            resource_id: event.resource_id,
            start_grant_id: event.start_grant_id,
            sequence: event.sequence,
        }
    }

    fn from_ack(ack: &InputAck) -> Self {
        Self {
            session_id: ack.session_id.clone(),
            resource_id: ack.resource_id,
            start_grant_id: ack.start_grant_id,
            sequence: ack.sequence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RequestCorrelationKey {
    Input(u64),
    Consent(u64),
    Execute(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RequestSemanticKey {
    Input(InputCorrelationKey),
    Consent([u8; 16]),
    Execute([u8; 16]),
}

enum PendingReply {
    Input {
        registration_id: [u8; 16],
        registration_epoch: u64,
        event_commitment: [u8; 32],
        reply: oneshot::Sender<Result<InputAck, AgentRequestError>>,
    },
    Consent {
        request: ConsentRequest,
        reply: oneshot::Sender<Result<ValidatedConsent, AgentRequestError>>,
    },
    Execute {
        registration_id: [u8; 16],
        command_id: [u8; 16],
        reply: oneshot::Sender<Result<CommandResult, AgentRequestError>>,
    },
}

impl PendingReply {
    fn fail(self, error: AgentRequestError) {
        match self {
            Self::Input { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Consent { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Execute { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

struct PendingRequest {
    semantic: RequestSemanticKey,
    sent: bool,
    cancellation: watch::Sender<Option<RequestCancellation>>,
    reply: PendingReply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestCancellation {
    CallerAborted,
    TimedOut,
    SessionClosed,
    PolicyChanged,
}

impl RequestCancellation {
    fn consent_reason(self) -> ConsentCancelReason {
        match self {
            Self::CallerAborted => ConsentCancelReason::CallerAborted,
            Self::TimedOut => ConsentCancelReason::TimedOut,
            Self::SessionClosed => ConsentCancelReason::SessionClosed,
            Self::PolicyChanged => ConsentCancelReason::PolicyChanged,
        }
    }
}

#[derive(Default)]
struct RequestCorrelationState {
    pending: HashMap<RequestCorrelationKey, PendingRequest>,
    pending_semantics: HashMap<RequestSemanticKey, RequestCorrelationKey>,
}

#[derive(Clone)]
struct ConnectionControl {
    outbound: mpsc::Sender<OutboundMessage>,
    requests: Arc<Mutex<RequestCorrelationState>>,
}

impl ConnectionControl {
    fn new(outbound: mpsc::Sender<OutboundMessage>) -> Self {
        Self {
            outbound,
            requests: Arc::new(Mutex::new(RequestCorrelationState::default())),
        }
    }

    fn register_request(
        &self,
        key: RequestCorrelationKey,
        pending: PendingRequest,
    ) -> Result<(), AgentRequestError> {
        let mut requests = self
            .requests
            .lock()
            .map_err(|_| AgentRequestError::StateUnavailable)?;
        if requests.pending.contains_key(&key)
            || requests.pending_semantics.contains_key(&pending.semantic)
        {
            return Err(AgentRequestError::DuplicateRequest);
        }
        if requests.pending.len() >= PENDING_REQUEST_CAPACITY {
            return Err(AgentRequestError::CapacityExhausted);
        }
        requests
            .pending_semantics
            .insert(pending.semantic.clone(), key.clone());
        requests.pending.insert(key, pending);
        Ok(())
    }

    fn mark_request_sent(&self, key: &RequestCorrelationKey) -> bool {
        let Ok(mut requests) = self.requests.lock() else {
            return false;
        };
        let Some(pending) = requests.pending.get_mut(key) else {
            return false;
        };
        pending.sent = true;
        true
    }

    fn cancel_request(&self, key: &RequestCorrelationKey, reason: RequestCancellation) {
        self.cancel_request_with_publication_hook(key, reason, || {});
    }

    fn cancel_request_with_publication_hook<F>(
        &self,
        key: &RequestCorrelationKey,
        reason: RequestCancellation,
        after_publication: F,
    ) where
        F: FnOnce(),
    {
        let pending = self.requests.lock().ok().and_then(|mut requests| {
            let pending = requests.pending.get(key)?;
            let _ = pending.cancellation.send(Some(reason));
            after_publication();
            remove_pending_request(&mut requests, key)
        });
        if let Some(pending) = pending {
            if pending.sent {
                self.queue_consent_cancel(&pending.reply, reason);
            }
        }
    }

    fn queue_consent_cancel(&self, reply: &PendingReply, reason: RequestCancellation) {
        let PendingReply::Consent { request, .. } = reply else {
            return;
        };
        let _ = self
            .outbound
            .try_send(OutboundMessage::ConsentCancel(CancelConsent {
                request_token: request.request_token,
                request_id: request.request_id,
                session_id: request.session_id.clone(),
                reason: reason.consent_reason(),
            }));
    }

    fn queue_cancel_for_written_message(
        &self,
        message: &ServiceToAgent,
        reason: RequestCancellation,
    ) {
        let ServiceToAgent::ConsentRequest(request) = message else {
            return;
        };
        let _ = self
            .outbound
            .try_send(OutboundMessage::ConsentCancel(CancelConsent {
                request_token: request.request_token,
                request_id: request.request_id,
                session_id: request.session_id.clone(),
                reason: reason.consent_reason(),
            }));
    }

    fn is_request_pending(&self, key: &RequestCorrelationKey) -> bool {
        self.requests
            .lock()
            .is_ok_and(|requests| requests.pending.contains_key(key))
    }

    fn fail_request(&self, key: &RequestCorrelationKey, error: AgentRequestError) {
        let pending = self.requests.lock().ok().and_then(|mut requests| {
            remove_pending_request_with_cancellation(
                &mut requests,
                key,
                RequestCancellation::SessionClosed,
            )
        });
        if let Some(pending) = pending {
            pending.reply.fail(error);
        }
    }

    fn resolve_input_ack(&self, ack: InputAck) {
        let key = RequestCorrelationKey::Input(ack.request_token);
        let semantic = RequestSemanticKey::Input(InputCorrelationKey::from_ack(&ack));
        let pending = {
            let Ok(mut requests) = self.requests.lock() else {
                return;
            };
            let matches = requests.pending.get(&key).is_some_and(|pending| {
                pending.sent
                    && pending.semantic == semantic
                    && matches!(
                        &pending.reply,
                        PendingReply::Input {
                            registration_id,
                            registration_epoch,
                            event_commitment,
                            ..
                        } if *registration_id == ack.registration_id
                            && *registration_epoch == ack.registration_epoch
                            && *event_commitment == ack.event_commitment
                    )
            });
            matches
                .then(|| remove_pending_request(&mut requests, &key))
                .flatten()
        };
        if let Some(pending) = pending {
            if let PendingReply::Input { reply, .. } = pending.reply {
                let _ = reply.send(Ok(ack));
            }
        }
    }

    fn resolve_consent_result(&self, result: ConsentResult, now_ms: u64) {
        let key = RequestCorrelationKey::Consent(result.request_token);
        let resolved = {
            let Ok(mut requests) = self.requests.lock() else {
                return;
            };
            let validated = requests.pending.get(&key).and_then(|pending| {
                if !pending.sent {
                    return None;
                }
                let PendingReply::Consent { request, .. } = &pending.reply else {
                    return None;
                };
                validate_consent_result(request, &result, now_ms).ok()
            });
            let pending = validated
                .is_some()
                .then(|| remove_pending_request(&mut requests, &key))
                .flatten();
            pending.zip(validated)
        };
        if let Some((pending, validated)) = resolved {
            if let PendingReply::Consent { reply, .. } = pending.reply {
                let _ = reply.send(Ok(validated));
            }
        }
    }

    fn resolve_command_result(&self, result: CommandResult) {
        let key = RequestCorrelationKey::Execute(result.request_token);
        let pending = {
            let Ok(mut requests) = self.requests.lock() else {
                return;
            };
            let matches = requests.pending.get(&key).is_some_and(|pending| {
                pending.sent
                    && matches!(
                        &pending.reply,
                        PendingReply::Execute {
                            registration_id,
                            command_id,
                            ..
                        } if *registration_id == result.registration_id
                            && *command_id == result.command_id
                    )
            });
            matches
                .then(|| remove_pending_request(&mut requests, &key))
                .flatten()
        };
        if let Some(pending) = pending {
            if let PendingReply::Execute { reply, .. } = pending.reply {
                let _ = reply.send(Ok(result));
            }
        }
    }

    fn fail_all(&self, error: AgentRequestError) {
        let reason = if error == AgentRequestError::Revoked {
            RequestCancellation::PolicyChanged
        } else {
            RequestCancellation::SessionClosed
        };
        let pending = self
            .requests
            .lock()
            .map(|mut requests| {
                for pending in requests.pending.values() {
                    let _ = pending.cancellation.send(Some(reason));
                }
                requests.pending_semantics.clear();
                requests
                    .pending
                    .drain()
                    .map(|(_, pending)| pending)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for pending in pending {
            pending.reply.fail(error.clone());
        }
    }
}

fn remove_pending_request(
    requests: &mut RequestCorrelationState,
    key: &RequestCorrelationKey,
) -> Option<PendingRequest> {
    let pending = requests.pending.remove(key)?;
    requests.pending_semantics.remove(&pending.semantic);
    Some(pending)
}

fn remove_pending_request_with_cancellation(
    requests: &mut RequestCorrelationState,
    key: &RequestCorrelationKey,
    reason: RequestCancellation,
) -> Option<PendingRequest> {
    let pending = requests.pending.get(key)?;
    let _ = pending.cancellation.send(Some(reason));
    remove_pending_request(requests, key)
}

struct PendingRequestGuard {
    control: ConnectionControl,
    key: RequestCorrelationKey,
    armed: bool,
}

impl PendingRequestGuard {
    fn cancel(&mut self, reason: RequestCancellation) {
        if self.armed {
            self.armed = false;
            self.control.cancel_request(&self.key, reason);
        }
    }
}

impl Drop for PendingRequestGuard {
    fn drop(&mut self) {
        self.cancel(RequestCancellation::CallerAborted);
    }
}

enum OutboundMessage {
    OneWay(ServiceToAgent),
    ConsentCancel(CancelConsent),
    Request {
        message: ServiceToAgent,
        key: RequestCorrelationKey,
        binding: AgentBinding,
        required_capability: AgentCapability,
        minimum_protocol_minor: u16,
        cancellation: watch::Receiver<Option<RequestCancellation>>,
    },
}

enum InboundEvent {
    Message(AgentToService),
    Failed(FrameError),
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevocableWriteOutcome {
    Written,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestWriteOutcome {
    Written,
    Revoked,
    Cancelled(RequestCancellation),
}

type MediaSink = Arc<dyn Fn(MediaAccessUnit) + Send + Sync>;

/// Shared server for authenticated agent connections.
pub struct AgentServer {
    registry: Arc<AgentRegistry>,
    clock: Arc<dyn AgentServerClock>,
    request_timeout: Duration,
    next_request_token: AtomicU64,
    controls: Arc<Mutex<HashMap<AgentConnectionId, ConnectionControl>>>,
    media_sink: Arc<Mutex<Option<MediaSink>>>,
    render_metrics: Arc<Mutex<HashMap<SessionId, RenderBoundaryMetrics>>>,
}

impl AgentServer {
    /// Construct a server using the production wall clock.
    pub fn new(registry: Arc<AgentRegistry>) -> Self {
        Self::with_clock(registry, Arc::new(SystemAgentServerClock))
    }

    /// Construct a server with an injected trusted clock.
    pub fn with_clock(registry: Arc<AgentRegistry>, clock: Arc<dyn AgentServerClock>) -> Self {
        Self::with_clock_and_request_timeout(registry, clock, REQUEST_TIMEOUT)
    }

    /// Construct a server with injected clock and request deadline.
    ///
    /// The explicit deadline keeps request/response timeout behavior deterministic
    /// in integration tests while production constructors use the safe default.
    pub fn with_clock_and_request_timeout(
        registry: Arc<AgentRegistry>,
        clock: Arc<dyn AgentServerClock>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            registry,
            clock,
            request_timeout,
            next_request_token: AtomicU64::new(1),
            controls: Arc::new(Mutex::new(HashMap::new())),
            media_sink: Arc::new(Mutex::new(None)),
            render_metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Installs the service-owned sink for validated agent media units.
    pub fn set_media_sink(&self, sink: Arc<dyn Fn(MediaAccessUnit) + Send + Sync>) {
        if let Ok(mut slot) = self.media_sink.lock() {
            *slot = Some(sink);
        }
    }

    /// Binds the authenticated agent stream to a bounded service ingress queue.
    pub fn set_media_ingress(&self, ingress: Arc<tokio::sync::Mutex<AgentMediaIngress>>) {
        self.set_media_sink(Arc::new(move |unit| {
            if let Ok(mut queue) = ingress.try_lock() {
                let _ = queue.push(unit);
            }
        }));
    }

    /// Return the latest authenticated cumulative metrics for one logical session.
    pub fn render_boundary_metrics(&self, session_id: &SessionId) -> Option<RenderBoundaryMetrics> {
        self.render_metrics.lock().ok()?.get(session_id).cloned()
    }

    /// Remove stale metrics when the exact logical render route is revoked.
    pub fn clear_render_boundary_metrics(&self, session_id: &SessionId) {
        if let Ok(mut metrics) = self.render_metrics.lock() {
            metrics.remove(session_id);
        }
    }

    /// Route one bounded encoded unit to the exact persisted render binding.
    pub fn send_render_access_unit(
        &self,
        binding: &AgentBinding,
        unit: RenderAccessUnit,
    ) -> Result<(), AgentRequestError> {
        if !unit.is_valid() {
            return Err(AgentRequestError::InvalidRenderAccessUnit);
        }
        if binding.required_capability() != AgentCapability::Render {
            return Err(AgentRouteError::CapabilityBindingMismatch.into());
        }
        let route = self.registry.resolve_exact_with_minimum_minor(
            binding,
            AgentCapability::Render,
            AGENT_IPC_RENDER_ACCESS_UNIT_PROTOCOL_MINOR,
            self.clock.now_ms(),
        )?;
        let control = self
            .controls
            .lock()
            .map_err(|_| AgentRequestError::ConnectionUnavailable)?
            .get(&route.connection_id())
            .cloned()
            .ok_or(AgentRequestError::ConnectionUnavailable)?;
        control
            .outbound
            .try_send(OutboundMessage::OneWay(ServiceToAgent::RenderAccessUnit(
                unit,
            )))
            .map_err(|_| AgentRequestError::OutboundUnavailable)
    }

    /// Queue a bounded service command for one exact private connection.
    pub fn send_to_connection(
        &self,
        connection_id: AgentConnectionId,
        message: ServiceToAgent,
    ) -> Result<(), AgentServerError> {
        if !matches!(message, ServiceToAgent::StopAgent(_)) {
            return Err(AgentServerError::ResponseRequired);
        }
        if !self.registry.is_connection_active(connection_id) {
            return Err(AgentServerError::ConnectionUnavailable);
        }
        let control = self
            .controls
            .lock()
            .map_err(|_| AgentServerError::ConnectionUnavailable)?
            .get(&connection_id)
            .cloned()
            .ok_or(AgentServerError::ConnectionUnavailable)?;
        control
            .outbound
            .try_send(OutboundMessage::OneWay(message))
            .map_err(|_| AgentServerError::OutboundUnavailable)
    }

    /// Route one attended-consent prompt to the named Windows session and await
    /// a result validated against the exact request.
    pub async fn request_consent(
        &self,
        mut request: ConsentRequest,
    ) -> Result<CorrelatedConsent, AgentRequestError> {
        let token = self.next_request_token()?;
        request.request_token = token;
        let now_ms = self.clock.now_ms();
        validate_consent_request(&request, now_ms).map_err(AgentRequestError::InvalidConsent)?;
        let binding = self.registry.bind_active_session(
            request.windows_session_id,
            AgentCapability::Consent,
            now_ms,
        )?;
        let route = self.registry.resolve_exact_with_minimum_minor(
            &binding,
            AgentCapability::Consent,
            AGENT_IPC_CONSENT_CANCEL_PROTOCOL_MINOR,
            now_ms,
        )?;
        let control = self
            .controls
            .lock()
            .map_err(|_| AgentRequestError::ConnectionUnavailable)?
            .get(&route.connection_id())
            .cloned()
            .ok_or(AgentRequestError::ConnectionUnavailable)?;
        let key = RequestCorrelationKey::Consent(token);
        let semantic = RequestSemanticKey::Consent(request.request_id);
        let (reply, response) = oneshot::channel();
        let (cancellation, cancelled) = watch::channel(None);
        control.register_request(
            key.clone(),
            PendingRequest {
                semantic,
                sent: false,
                cancellation,
                reply: PendingReply::Consent {
                    request: request.clone(),
                    reply,
                },
            },
        )?;
        let mut pending_guard = PendingRequestGuard {
            control: control.clone(),
            key: key.clone(),
            armed: true,
        };

        let mut lease = route.into_lease();
        if lease.is_revoked() {
            return Err(AgentRequestError::Revoked);
        }
        let result_binding = binding.clone();
        control
            .outbound
            .try_send(OutboundMessage::Request {
                message: ServiceToAgent::ConsentRequest(request.clone()),
                key,
                binding,
                required_capability: AgentCapability::Consent,
                minimum_protocol_minor: AGENT_IPC_CONSENT_CANCEL_PROTOCOL_MINOR,
                cancellation: cancelled,
            })
            .map_err(|_| AgentRequestError::OutboundUnavailable)?;

        let request_lifetime = Duration::from_millis(request.expires_at_ms.saturating_sub(now_ms));
        let response_lease = lease.clone();
        let consent = tokio::select! {
            biased;
            response = response => match response {
                Ok(Ok(_)) if response_lease.is_revoked() => Err(AgentRequestError::Revoked),
                Ok(result) => result,
                Err(_) => Err(AgentRequestError::Disconnected),
            },
            _ = lease.wait_revoked() => Err(AgentRequestError::Revoked),
            _ = tokio::time::sleep(self.request_timeout.min(request_lifetime)) => {
                Err(AgentRequestError::Timeout)
            },
        };
        match &consent {
            Err(AgentRequestError::Timeout) => {
                pending_guard.cancel(RequestCancellation::TimedOut);
            }
            Err(AgentRequestError::Revoked) => {
                pending_guard.cancel(RequestCancellation::PolicyChanged);
            }
            Err(AgentRequestError::Disconnected) => {
                pending_guard.cancel(RequestCancellation::SessionClosed);
            }
            _ => {}
        }
        let consent = consent?;
        Ok(CorrelatedConsent {
            binding: result_binding,
            consent,
        })
    }

    /// Route one input event to the exact persisted agent generation and await its bound ack.
    pub async fn request_input(
        &self,
        binding: &AgentBinding,
        mut event: InputEventEnvelope,
    ) -> Result<InputAck, AgentRequestError> {
        let token = self.next_request_token()?;
        event.request_token = token;
        event
            .validate_shape()
            .map_err(AgentRequestError::InvalidInput)?;
        let event_commitment = event
            .commitment()
            .map_err(AgentRequestError::InvalidInput)?;
        let route = self.registry.resolve_exact_with_minimum_minor(
            binding,
            AgentCapability::Input,
            AGENT_IPC_CORRELATED_REQUESTS_PROTOCOL_MINOR,
            self.clock.now_ms(),
        )?;
        let control = self
            .controls
            .lock()
            .map_err(|_| AgentRequestError::ConnectionUnavailable)?
            .get(&route.connection_id())
            .cloned()
            .ok_or(AgentRequestError::ConnectionUnavailable)?;
        let key = RequestCorrelationKey::Input(token);
        let semantic = RequestSemanticKey::Input(InputCorrelationKey::from_event(&event));
        let (reply, response) = oneshot::channel();
        let (cancellation, cancelled) = watch::channel(None);
        control.register_request(
            key.clone(),
            PendingRequest {
                semantic,
                sent: false,
                cancellation,
                reply: PendingReply::Input {
                    registration_id: *binding.registration_id(),
                    registration_epoch: binding.registration_epoch(),
                    event_commitment,
                    reply,
                },
            },
        )?;
        let _pending_guard = PendingRequestGuard {
            control: control.clone(),
            key: key.clone(),
            armed: true,
        };

        let mut lease = route.into_lease();
        if lease.is_revoked() {
            return Err(AgentRequestError::Revoked);
        }
        if control
            .outbound
            .try_send(OutboundMessage::Request {
                message: ServiceToAgent::InputEvent(event),
                key,
                binding: binding.clone(),
                required_capability: AgentCapability::Input,
                minimum_protocol_minor: AGENT_IPC_CORRELATED_REQUESTS_PROTOCOL_MINOR,
                cancellation: cancelled,
            })
            .is_err()
        {
            return Err(AgentRequestError::OutboundUnavailable);
        }

        let response_lease = lease.clone();
        let result = tokio::select! {
            biased;
            response = response => match response {
                Ok(Ok(_)) if response_lease.is_revoked() => Err(AgentRequestError::Revoked),
                Ok(result) => result,
                Err(_) => Err(AgentRequestError::Disconnected),
            },
            _ = lease.wait_revoked() => Err(AgentRequestError::Revoked),
            _ = tokio::time::sleep(self.request_timeout) => Err(AgentRequestError::Timeout),
        };
        result
    }

    /// Route one grant-bearing command to an already persisted exact agent
    /// binding and await the result from that registration and command id.
    pub async fn request_execute(
        &self,
        binding: &AgentBinding,
        mut execute: ExecuteCommand,
    ) -> Result<CommandResult, AgentRequestError> {
        let required_capability = execute.required_capability();
        if binding.required_capability() != required_capability {
            return Err(AgentRouteError::CapabilityBindingMismatch.into());
        }
        let minimum_protocol_minor = if matches!(
            &execute.command,
            mrd_agent_ipc::AgentCommand::StartRender { .. }
                | mrd_agent_ipc::AgentCommand::StopRender { .. }
        ) {
            AGENT_IPC_RENDER_SURFACE_PROTOCOL_MINOR
        } else {
            AGENT_IPC_CORRELATED_REQUESTS_PROTOCOL_MINOR
        };
        let route = self.registry.resolve_exact_with_minimum_minor(
            binding,
            required_capability,
            minimum_protocol_minor,
            self.clock.now_ms(),
        )?;
        let control = self
            .controls
            .lock()
            .map_err(|_| AgentRequestError::ConnectionUnavailable)?
            .get(&route.connection_id())
            .cloned()
            .ok_or(AgentRequestError::ConnectionUnavailable)?;
        let token = self.next_request_token()?;
        execute.request_token = token;
        let key = RequestCorrelationKey::Execute(token);
        let semantic = RequestSemanticKey::Execute(execute.command_id);
        let (reply, response) = oneshot::channel();
        let (cancellation, cancelled) = watch::channel(None);
        control.register_request(
            key.clone(),
            PendingRequest {
                semantic,
                sent: false,
                cancellation,
                reply: PendingReply::Execute {
                    registration_id: *binding.registration_id(),
                    command_id: execute.command_id,
                    reply,
                },
            },
        )?;
        let _pending_guard = PendingRequestGuard {
            control: control.clone(),
            key: key.clone(),
            armed: true,
        };

        let mut lease = route.into_lease();
        if lease.is_revoked() {
            return Err(AgentRequestError::Revoked);
        }
        control
            .outbound
            .try_send(OutboundMessage::Request {
                message: ServiceToAgent::Execute(Box::new(execute)),
                key,
                binding: binding.clone(),
                required_capability,
                minimum_protocol_minor,
                cancellation: cancelled,
            })
            .map_err(|_| AgentRequestError::OutboundUnavailable)?;

        let response_lease = lease.clone();
        tokio::select! {
            biased;
            response = response => match response {
                Ok(Ok(_)) if response_lease.is_revoked() => Err(AgentRequestError::Revoked),
                Ok(result) => result,
                Err(_) => Err(AgentRequestError::Disconnected),
            },
            _ = lease.wait_revoked() => Err(AgentRequestError::Revoked),
            _ = tokio::time::sleep(self.request_timeout) => Err(AgentRequestError::Timeout),
        }
    }

    fn next_request_token(&self) -> Result<u64, AgentRequestError> {
        self.next_request_token
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token.checked_add(1)
            })
            .map_err(|_| AgentRequestError::CapacityExhausted)
    }

    /// Serve one stream whose OS identity was independently verified.
    pub async fn serve_connection<S>(
        &self,
        stream: S,
        connection_id: AgentConnectionId,
        observed: ObservedAgentIdentity,
    ) -> Result<AgentConnectionExit, AgentServerError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let control = ConnectionControl::new(outbound_tx);
        {
            let mut controls = self
                .controls
                .lock()
                .map_err(|_| AgentServerError::ConnectionUnavailable)?;
            match controls.entry(connection_id) {
                Entry::Occupied(_) => return Err(AgentServerError::DuplicateConnection),
                Entry::Vacant(entry) => {
                    entry.insert(control.clone());
                }
            }
        }
        let cleanup = ConnectionCleanup {
            registry: Arc::clone(&self.registry),
            controls: Arc::clone(&self.controls),
            connection_id,
        };
        let (reader, mut writer) = tokio::io::split(stream);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let reader_task = tokio::spawn(read_loop(reader, inbound_tx));

        let result = self
            .run_connection(
                &mut writer,
                &mut inbound_rx,
                outbound_rx,
                control,
                connection_id,
                observed,
            )
            .await;
        stop_reader(reader_task).await;
        drop(cleanup);
        result
    }

    async fn run_connection<W>(
        &self,
        writer: &mut W,
        inbound: &mut mpsc::Receiver<InboundEvent>,
        mut outbound: mpsc::Receiver<OutboundMessage>,
        control: ConnectionControl,
        connection_id: AgentConnectionId,
        observed: ObservedAgentIdentity,
    ) -> Result<AgentConnectionExit, AgentServerError>
    where
        W: AsyncWrite + Unpin,
    {
        let register = match next_handshake_message(inbound).await? {
            AgentToService::AgentRegister(register) => register,
            _ => return Err(AgentServerError::UnexpectedHandshakeMessage),
        };
        let challenge = self.registry.begin_registration(
            connection_id,
            register,
            observed,
            self.clock.now_ms(),
        )?;
        write_service_frame(writer, &ServiceToAgent::AgentChallenge(challenge)).await?;

        let proof = match next_handshake_message(inbound).await? {
            AgentToService::AgentRegistered(proof) => proof,
            _ => return Err(AgentServerError::UnexpectedHandshakeMessage),
        };
        let identity =
            self.registry
                .complete_registration(connection_id, proof, self.clock.now_ms())?;

        let capabilities = match next_handshake_message(inbound).await? {
            AgentToService::AgentCapabilitySnapshot(snapshot) => snapshot,
            _ => return Err(AgentServerError::UnexpectedHandshakeMessage),
        };
        self.registry
            .activate_registration(connection_id, capabilities, self.clock.now_ms())?;
        let mut lease = self
            .registry
            .lease_for_session(identity.windows_session_id)
            .filter(|lease| {
                lease.registration_id() == &identity.registration_id
                    && lease.registration_epoch() == identity.registration_epoch
            })
            .ok_or(AgentRegistryError::NotActive)?;

        loop {
            tokio::select! {
                biased;
                _ = lease.wait_revoked() => {
                    control.fail_all(AgentRequestError::Revoked);
                    return self
                        .stop_revoked_connection(writer, inbound, &identity)
                        .await;
                }
                inbound_event = inbound.recv() => {
                    match inbound_event {
                        Some(InboundEvent::Message(AgentToService::AgentHeartbeat(heartbeat))) => {
                            self.registry.record_heartbeat(
                                connection_id,
                                heartbeat,
                                self.clock.now_ms(),
                            )?;
                        }
                        Some(InboundEvent::Message(AgentToService::AgentCapabilitySnapshot(snapshot))) => {
                            self.registry.record_capabilities(
                                connection_id,
                                snapshot,
                                self.clock.now_ms(),
                            )?;
                        }
                        Some(InboundEvent::Message(AgentToService::InputAck(ack))) => {
                            control.resolve_input_ack(ack);
                        }
                        Some(InboundEvent::Message(AgentToService::MediaAccessUnit(unit))) => {
                            // Media delivery is consumed by the LAN transport layer. Keep the
                            // authenticated agent connection alive while that hand-off is wired.
                            if crate::lan_discovery::media_sender::validate_agent_access_unit(unit.clone()).is_none() {
                                return Err(AgentServerError::UnsupportedRegisteredMessage);
                            }
                            if let Ok(slot) = self.media_sink.lock() {
                                if let Some(sink) = slot.as_ref() {
                                    sink(unit);
                                }
                            }
                        }
                        Some(InboundEvent::Message(AgentToService::RenderBoundaryMetrics(metrics))) => {
                            if identity.protocol_minor < AGENT_IPC_RENDER_METRICS_PROTOCOL_MINOR
                                || !metrics.is_valid()
                            {
                                return Err(AgentServerError::UnsupportedRegisteredMessage);
                            }
                            self.registry.record_heartbeat(
                                connection_id,
                                AgentHeartbeat { context: metrics.context.clone() },
                                self.clock.now_ms(),
                            )?;
                            let session_id = SessionId(metrics.session_id.clone());
                            let Ok(mut snapshots) = self.render_metrics.lock() else {
                                return Err(AgentServerError::UnsupportedRegisteredMessage);
                            };
                            if let Some(previous) = snapshots.get(&session_id) {
                                let same_resource = previous.resource_id == metrics.resource_id;
                                let regressed = metrics.enqueued_units < previous.enqueued_units
                                    || metrics.queue_replacements < previous.queue_replacements
                                    || metrics.decoded_frames < previous.decoded_frames
                                    || metrics.presented_frames < previous.presented_frames;
                                if same_resource && regressed {
                                    return Err(AgentServerError::UnsupportedRegisteredMessage);
                                }
                            }
                            snapshots.insert(session_id, metrics);
                        }
                        Some(InboundEvent::Message(AgentToService::ConsentResult(result))) => {
                            control.resolve_consent_result(result, self.clock.now_ms());
                        }
                        Some(InboundEvent::Message(AgentToService::CommandResult(result))) => {
                            control.resolve_command_result(result);
                        }
                        Some(InboundEvent::Message(AgentToService::AgentStopping(stopping))) => {
                            let heartbeat = AgentHeartbeat { context: stopping.context };
                            match self.registry.record_heartbeat(
                                connection_id,
                                heartbeat,
                                self.clock.now_ms(),
                            ) {
                                Ok(()) | Err(AgentRegistryError::NotActive) => {
                                    return Ok(AgentConnectionExit::Stopped);
                                }
                                Err(error) => return Err(error.into()),
                            }
                        }
                        Some(InboundEvent::Message(_)) => {
                            return Err(AgentServerError::UnsupportedRegisteredMessage);
                        }
                        Some(InboundEvent::Failed(error)) => return Err(error.into()),
                        Some(InboundEvent::Disconnected) | None => {
                            control.fail_all(AgentRequestError::Disconnected);
                            return Ok(AgentConnectionExit::Disconnected);
                        }
                    }
                }
                outbound_message = outbound.recv() => {
                    match outbound_message {
                        Some(OutboundMessage::OneWay(message)) => {
                            if lease.is_revoked() {
                                control.fail_all(AgentRequestError::Revoked);
                                return self
                                    .stop_revoked_connection(writer, inbound, &identity)
                                    .await;
                            }
                            let revoked = lease.wait_revoked();
                            if write_service_frame_until_revoked(writer, &message, revoked).await?
                                == RevocableWriteOutcome::Revoked
                            {
                                // A frame may now be partial, so hard-close instead of
                                // appending a StopAgent frame to a corrupt stream.
                                control.fail_all(AgentRequestError::Revoked);
                                return Ok(AgentConnectionExit::Disconnected);
                            }
                        }
                        Some(OutboundMessage::ConsentCancel(cancel)) => {
                            if lease.is_revoked() {
                                control.fail_all(AgentRequestError::Revoked);
                                return self
                                    .stop_revoked_connection(writer, inbound, &identity)
                                    .await;
                            }
                            let message = ServiceToAgent::CancelConsent(cancel);
                            let revoked = lease.wait_revoked();
                            if write_service_frame_until_revoked(writer, &message, revoked).await?
                                == RevocableWriteOutcome::Revoked
                            {
                                // Cleanup is already bound to this connection. If replacement
                                // interrupts a partial frame, hard-close the old stream.
                                control.fail_all(AgentRequestError::Revoked);
                                return Ok(AgentConnectionExit::Disconnected);
                            }
                        }
                        Some(OutboundMessage::Request {
                            message,
                            key,
                            binding,
                            required_capability,
                            minimum_protocol_minor,
                            cancellation,
                        }) => {
                            if !control.is_request_pending(&key)
                                || request_cancellation(&cancellation).is_some()
                            {
                                continue;
                            }
                            let exact_route = match self.registry.resolve_exact_with_minimum_minor(
                                &binding,
                                required_capability,
                                minimum_protocol_minor,
                                self.clock.now_ms(),
                            ) {
                                Ok(route) => route,
                                Err(error) => {
                                    control.fail_request(&key, AgentRequestError::Route(error));
                                    continue;
                                }
                            };
                            if !control.is_request_pending(&key)
                                || request_cancellation(&cancellation).is_some()
                            {
                                continue;
                            }
                            let mut exact_lease = exact_route.into_lease();
                            let cancellation_after_write = cancellation.clone();
                            match write_request_frame_until_interrupted(
                                writer,
                                &message,
                                exact_lease.wait_revoked(),
                                wait_for_request_cancellation(cancellation),
                            )
                            .await?
                            {
                                RequestWriteOutcome::Written => {
                                    if !control.mark_request_sent(&key) {
                                        // A concurrent caller cancellation can remove the
                                        // request immediately after the complete frame write.
                                        // Queue cleanup on this same connection without routing.
                                        if let Some(reason) =
                                            request_cancellation(&cancellation_after_write)
                                        {
                                            control.queue_cancel_for_written_message(
                                                &message, reason,
                                            );
                                        }
                                    }
                                }
                                RequestWriteOutcome::Revoked => {
                                    control.fail_all(AgentRequestError::Revoked);
                                    return Ok(AgentConnectionExit::Disconnected);
                                }
                                RequestWriteOutcome::Cancelled(_) => {
                                    // Cancellation may have interrupted a partial frame.
                                    // Hard-close so no later frame can be parsed across it.
                                    return Ok(AgentConnectionExit::Disconnected);
                                }
                            }
                        }
                        None => {
                            control.fail_all(AgentRequestError::Disconnected);
                            return Err(AgentServerError::OutboundUnavailable);
                        }
                    }
                }
            }
        }
    }

    async fn stop_revoked_connection<W>(
        &self,
        writer: &mut W,
        inbound: &mut mpsc::Receiver<InboundEvent>,
        identity: &RegisteredAgentIdentity,
    ) -> Result<AgentConnectionExit, AgentServerError>
    where
        W: AsyncWrite + Unpin,
    {
        let budget = Duration::from_millis(REPLACED_STOP_GRACE_MS);
        let stop = ServiceToAgent::StopAgent(StopAgent {
            request_id: identity.registration_id,
            deadline_ms: self.clock.now_ms().saturating_add(REPLACED_STOP_GRACE_MS),
            reason: StopReason::PolicyChange,
        });
        match tokio::time::timeout(budget, async {
            write_service_frame(writer, &stop).await?;
            wait_for_revoked_stop(inbound, identity).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(AgentConnectionExit::Disconnected),
        }
    }
}

struct ConnectionCleanup {
    registry: Arc<AgentRegistry>,
    controls: Arc<Mutex<HashMap<AgentConnectionId, ConnectionControl>>>,
    connection_id: AgentConnectionId,
}

impl Drop for ConnectionCleanup {
    fn drop(&mut self) {
        if let Ok(mut controls) = self.controls.lock() {
            if let Some(control) = controls.remove(&self.connection_id) {
                control.fail_all(AgentRequestError::Disconnected);
            }
        }
        self.registry.disconnect(self.connection_id);
    }
}

fn validate_consent_request(
    request: &ConsentRequest,
    now_ms: u64,
) -> Result<(), ConsentValidationError> {
    let shape_probe = ConsentResult {
        request_token: request.request_token,
        request_id: request.request_id,
        session_id: request.session_id.clone(),
        peer: request.peer.clone(),
        policy_revision: request.policy_revision,
        windows_session_id: request.windows_session_id,
        decision: ConsentDecision::Denied,
        approved_scopes: Default::default(),
        decided_at_ms: now_ms,
    };
    validate_consent_result(request, &shape_probe, now_ms).map(|_| ())
}

async fn next_handshake_message(
    inbound: &mut mpsc::Receiver<InboundEvent>,
) -> Result<AgentToService, AgentServerError> {
    let event = tokio::time::timeout(HANDSHAKE_TIMEOUT, inbound.recv())
        .await
        .map_err(|_| AgentServerError::HandshakeTimeout)?
        .ok_or(AgentServerError::DisconnectedDuringHandshake)?;
    match event {
        InboundEvent::Message(message) => Ok(message),
        InboundEvent::Failed(error) => Err(error.into()),
        InboundEvent::Disconnected => Err(AgentServerError::DisconnectedDuringHandshake),
    }
}

async fn write_service_frame<W>(
    writer: &mut W,
    message: &ServiceToAgent,
) -> Result<(), AgentServerError>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, write_frame(writer, message))
        .await
        .map_err(|_| AgentServerError::WriteTimeout)??;
    Ok(())
}

async fn write_service_frame_until_revoked<W, F>(
    writer: &mut W,
    message: &ServiceToAgent,
    revocation: F,
) -> Result<RevocableWriteOutcome, AgentServerError>
where
    W: AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    tokio::pin!(revocation);
    tokio::select! {
        biased;
        _ = &mut revocation => Ok(RevocableWriteOutcome::Revoked),
        result = write_service_frame(writer, message) => {
            result?;
            Ok(RevocableWriteOutcome::Written)
        }
    }
}

fn request_cancellation(
    cancellation: &watch::Receiver<Option<RequestCancellation>>,
) -> Option<RequestCancellation> {
    *cancellation.borrow()
}

async fn wait_for_request_cancellation(
    mut cancellation: watch::Receiver<Option<RequestCancellation>>,
) -> RequestCancellation {
    loop {
        if let Some(reason) = request_cancellation(&cancellation) {
            return reason;
        }
        if cancellation.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

async fn write_request_frame_until_interrupted<W, F, G>(
    writer: &mut W,
    message: &ServiceToAgent,
    revocation: F,
    cancellation: G,
) -> Result<RequestWriteOutcome, AgentServerError>
where
    W: AsyncWrite + Unpin,
    F: Future<Output = ()>,
    G: Future<Output = RequestCancellation>,
{
    tokio::pin!(revocation);
    tokio::pin!(cancellation);
    tokio::select! {
        biased;
        _ = &mut revocation => Ok(RequestWriteOutcome::Revoked),
        reason = &mut cancellation => Ok(RequestWriteOutcome::Cancelled(reason)),
        result = write_service_frame(writer, message) => {
            result?;
            Ok(RequestWriteOutcome::Written)
        },
    }
}

async fn wait_for_revoked_stop(
    inbound: &mut mpsc::Receiver<InboundEvent>,
    identity: &RegisteredAgentIdentity,
) -> Result<AgentConnectionExit, AgentServerError> {
    loop {
        match inbound.recv().await {
            Some(InboundEvent::Message(AgentToService::AgentStopping(stopping))) => {
                validate_stopping_binding(&stopping, identity)?;
                return Ok(AgentConnectionExit::Stopped);
            }
            Some(InboundEvent::Message(_)) => {}
            Some(InboundEvent::Failed(error)) => return Err(error.into()),
            Some(InboundEvent::Disconnected) | None => {
                return Ok(AgentConnectionExit::Disconnected);
            }
        }
    }
}

fn validate_stopping_binding(
    stopping: &AgentStopping,
    identity: &RegisteredAgentIdentity,
) -> Result<(), AgentServerError> {
    let context = &stopping.context;
    if context.registration_id != identity.registration_id
        || context.registration_epoch != identity.registration_epoch
        || context.windows_session_id != identity.windows_session_id
        || context.desktop_epoch == 0
        || context.sequence == 0
        || context.observed_at_ms == 0
    {
        return Err(AgentRegistryError::MessageBindingMismatch.into());
    }
    Ok(())
}

async fn read_loop<R>(mut reader: R, sender: mpsc::Sender<InboundEvent>)
where
    R: AsyncRead + Unpin,
{
    loop {
        match read_agent_frame(&mut reader, PARTIAL_FRAME_TIMEOUT).await {
            Ok(message) => {
                if sender.send(InboundEvent::Message(message)).await.is_err() {
                    return;
                }
            }
            Err(FrameError::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                ) =>
            {
                let _ = sender.send(InboundEvent::Disconnected).await;
                return;
            }
            Err(error) => {
                let _ = sender.send(InboundEvent::Failed(error)).await;
                return;
            }
        }
    }
}

async fn read_agent_frame<R>(
    reader: &mut R,
    partial_timeout: Duration,
) -> Result<AgentToService, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; AGENT_IPC_FRAME_HEADER_BYTES];
    reader.read_exact(&mut header[..1]).await?;
    tokio::time::timeout(partial_timeout, reader.read_exact(&mut header[1..]))
        .await
        .map_err(|_| partial_frame_timeout_error())??;

    let payload_len =
        u32::from_le_bytes(header[0..4].try_into().expect("fixed frame header")) as usize;
    let protocol_major = u16::from_le_bytes(header[4..6].try_into().expect("fixed frame header"));
    if protocol_major != AGENT_IPC_PROTOCOL_MAJOR {
        return Err(FrameError::UnsupportedMajor {
            received: protocol_major,
            supported: AGENT_IPC_PROTOCOL_MAJOR,
        });
    }
    if payload_len == 0 {
        return Err(FrameError::EmptyPayload);
    }
    if payload_len > AGENT_IPC_MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            declared: payload_len,
            max: AGENT_IPC_MAX_FRAME_BYTES,
        });
    }

    let mut frame = Vec::with_capacity(AGENT_IPC_FRAME_HEADER_BYTES + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(AGENT_IPC_FRAME_HEADER_BYTES + payload_len, 0);
    tokio::time::timeout(
        partial_timeout,
        reader.read_exact(&mut frame[AGENT_IPC_FRAME_HEADER_BYTES..]),
    )
    .await
    .map_err(|_| partial_frame_timeout_error())??;
    decode_frame::<AgentToService>(&frame).map(|decoded| decoded.message)
}

fn partial_frame_timeout_error() -> FrameError {
    FrameError::Io(std::io::Error::new(
        ErrorKind::TimedOut,
        "partial agent IPC frame timed out",
    ))
}

async fn stop_reader(reader_task: JoinHandle<()>) {
    reader_task.abort();
    let _ = reader_task.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_agent_ipc::encode_frame;
    use tokio::{
        io::{duplex, AsyncReadExt},
        sync::oneshot,
    };

    #[tokio::test]
    async fn revocation_cancels_a_stalled_outbound_frame() {
        let message = ServiceToAgent::StopAgent(StopAgent {
            request_id: [7; 16],
            deadline_ms: 5_000,
            reason: StopReason::ServiceShutdown,
        });
        let complete_frame_len = encode_frame(&message).unwrap().len();
        let (mut writer, mut reader) = duplex(1);
        let (revoke_tx, revoke_rx) = oneshot::channel();
        let writing = tokio::spawn(async move {
            write_service_frame_until_revoked(&mut writer, &message, async {
                let _ = revoke_rx.await;
            })
            .await
        });

        tokio::task::yield_now().await;
        revoke_tx.send(()).unwrap();
        assert_eq!(
            writing.await.unwrap().unwrap(),
            RevocableWriteOutcome::Revoked
        );
        let mut delivered = Vec::new();
        reader.read_to_end(&mut delivered).await.unwrap();
        assert!(
            delivered.len() < complete_frame_len,
            "a revoked peer must not receive a complete stalled frame"
        );
    }

    #[tokio::test]
    async fn an_already_cancelled_request_is_never_polled_for_write() {
        let message = ServiceToAgent::StopAgent(StopAgent {
            request_id: [8; 16],
            deadline_ms: 5_000,
            reason: StopReason::ServiceShutdown,
        });
        let (mut writer, mut reader) = duplex(1_024);

        let outcome = write_request_frame_until_interrupted(
            &mut writer,
            &message,
            std::future::pending(),
            std::future::ready(RequestCancellation::CallerAborted),
        )
        .await
        .unwrap();
        drop(writer);

        assert_eq!(
            outcome,
            RequestWriteOutcome::Cancelled(RequestCancellation::CallerAborted)
        );
        let mut delivered = Vec::new();
        reader.read_to_end(&mut delivered).await.unwrap();
        assert!(
            delivered.is_empty(),
            "a cancellation already visible at the write boundary must win over a ready sink"
        );
    }

    #[test]
    fn a_completed_request_channel_is_not_reclassified_as_session_cancellation() {
        let (completed, receiver) = watch::channel(None);
        drop(completed);

        assert_eq!(request_cancellation(&receiver), None);
    }

    #[test]
    fn cancellation_is_published_before_pending_removal_becomes_visible() {
        use std::sync::{atomic::AtomicBool, Barrier};

        let (outbound, _outbound_rx) = mpsc::channel(1);
        let control = ConnectionControl::new(outbound);
        let key = RequestCorrelationKey::Execute(9);
        let command_id = [9; 16];
        let (reply, _response) = oneshot::channel();
        let (cancellation, receiver) = watch::channel(None);
        control
            .register_request(
                key.clone(),
                PendingRequest {
                    semantic: RequestSemanticKey::Execute(command_id),
                    sent: false,
                    cancellation,
                    reply: PendingReply::Execute {
                        registration_id: [8; 16],
                        command_id,
                        reply,
                    },
                },
            )
            .unwrap();

        let published = Arc::new(Barrier::new(2));
        let observer_started = Arc::new(AtomicBool::new(false));
        let cancelling = {
            let control = control.clone();
            let key = key.clone();
            let receiver = receiver.clone();
            let published = Arc::clone(&published);
            let observer_started = Arc::clone(&observer_started);
            std::thread::spawn(move || {
                control.cancel_request_with_publication_hook(
                    &key,
                    RequestCancellation::TimedOut,
                    || {
                        assert_eq!(
                            request_cancellation(&receiver),
                            Some(RequestCancellation::TimedOut)
                        );
                        published.wait();
                        while !observer_started.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                    },
                );
            })
        };
        let observing = {
            let control = control.clone();
            let key = key.clone();
            let receiver = receiver.clone();
            let published = Arc::clone(&published);
            let observer_started = Arc::clone(&observer_started);
            std::thread::spawn(move || {
                published.wait();
                observer_started.store(true, Ordering::Release);
                (
                    control.is_request_pending(&key),
                    control.mark_request_sent(&key),
                    request_cancellation(&receiver),
                )
            })
        };

        cancelling.join().unwrap();
        assert_eq!(
            observing.join().unwrap(),
            (false, false, Some(RequestCancellation::TimedOut))
        );
    }
}
