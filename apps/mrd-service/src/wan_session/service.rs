//! Production adapters and background ownership for attended WAN sessions.

use super::{
    backend::{ServiceWanSessionWorkflowBackend, WanSessionApproval, WanSessionBackend},
    control_input::{
        bind_verified_mux, ServiceWanControlEvidenceBarrier, ServiceWanControlInputPort,
    },
    coordinator::{
        SystemWanSessionClock, VerifiedWanSessionGrant, VerifiedWanSessionIntent,
        WanSessionConsentPublisher, WanSessionCoordinator, WanSessionCoordinatorConfig,
        WanSessionCoordinatorError, WanSessionPortError, WanSessionWorkflowPorts,
    },
    media::{
        enable_input_after_control_evidence, start_verified_media, WanMediaActivationError,
        WanMediaActivationPort, WanMediaActivationReceipt, WanMediaAuthority,
    },
    media_runtime::{start_controller_runtime, start_target_runtime},
    model::{WanSessionFailure, WanSessionPhase, WanSessionRole, WanSessionState},
    signaling::ServiceWanSessionWorkflowSignaling,
    webrtc::{
        GenerationZeroNegotiationContext, GenerationZeroNegotiationError, GenerationZeroNegotiator,
    },
};
use async_trait::async_trait;
#[cfg(any(test, debug_assertions))]
use mrd_application::ports::TransportRouteKind;
use mrd_application::{
    ports::{SessionLifecycleState, SessionSnapshot, TransportMuxPort},
    AuthenticatedSessionSignal, VerifiedSignalingEvent,
};
use mrd_ipc::{
    RemoteAuthorizationState, RemoteFailure, RemotePermissionScope, RemoteReasonCode, SessionInfo,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{WanMediaProfileV3, WanPermissionScopeV3, WanSessionRequestV3};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Weak},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{oneshot, Mutex},
    task::{JoinHandle, JoinSet},
};

const WAN_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_INITIAL_EVENT_TASKS: usize = 32;

/// Service-owned terminal request for an already registered WAN session.
/// Callers must hold `AppState::authorization_security_gate` so authorization,
/// workflow cleanup, and the public projection cannot race trust changes.
#[derive(Debug, Clone)]
pub(crate) enum ServiceWanTerminalRequest {
    Close,
    Fail {
        failure: WanSessionFailure,
        remote_failure: RemoteFailure,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceSessionKind {
    Wan,
    Lan,
    Unknown,
}

/// Resolve the session authority while the authorization security gate is
/// held. Coordinator ownership wins, followed by the original authorization
/// transport, then the runtime projection. A missing WAN coordinator never
/// turns an explicit WAN authorization into a LAN session.
pub(crate) async fn resolve_session_kind_under_security_gate(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
) -> ServiceSessionKind {
    if let Some(coordinator) = app_state.wan_session_coordinator() {
        if coordinator.snapshot(session_id).await.is_ok() {
            return ServiceSessionKind::Wan;
        }
    }
    if let Some(transport) = app_state
        .session_authorizations
        .transport_kind(session_id)
        .await
    {
        return if transport == "webrtc_relay" {
            ServiceSessionKind::Wan
        } else {
            ServiceSessionKind::Lan
        };
    }
    match app_state
        .sessions
        .lock()
        .await
        .get(session_id)
        .map(|snapshot| snapshot.transport.as_str() == "webrtc_relay")
    {
        Some(true) => ServiceSessionKind::Wan,
        Some(false) => ServiceSessionKind::Lan,
        None => ServiceSessionKind::Unknown,
    }
}

/// Resolve and terminalize one WAN session while the authorization security
/// gate is held. `Ok(None)` means the id is not owned by the WAN coordinator.
/// A terminal coordinator state is projected even when its stored cleanup
/// receipt is an error, but the same error is returned on every retry.
pub(crate) async fn terminalize_wan_session_under_security_gate(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
    request: ServiceWanTerminalRequest,
) -> Result<Option<WanSessionState>, WanSessionCoordinatorError> {
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return Ok(None);
    };
    let current = match coordinator.snapshot(session_id).await {
        Ok(state) => state,
        Err(WanSessionCoordinatorError::SessionNotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let operation = match current.phase() {
        WanSessionPhase::Closed => coordinator.close(session_id).await,
        WanSessionPhase::Failed => {
            coordinator
                .fail(
                    session_id,
                    current.failure().unwrap_or(WanSessionFailure::Internal),
                )
                .await
        }
        _ => match &request {
            ServiceWanTerminalRequest::Close => coordinator.close(session_id).await,
            ServiceWanTerminalRequest::Fail { failure, .. } => {
                coordinator.fail(session_id, *failure).await
            }
        },
    };
    let terminal = coordinator.snapshot(session_id).await?;
    if terminal.phase().is_terminal() {
        let requested_remote_failure = match &request {
            ServiceWanTerminalRequest::Fail {
                failure,
                remote_failure,
            } if terminal.failure() == Some(*failure) => Some(remote_failure.clone()),
            ServiceWanTerminalRequest::Close | ServiceWanTerminalRequest::Fail { .. } => None,
        };
        publish_terminal_wan_state(app_state, &terminal, requested_remote_failure).await;
    }
    match operation {
        Ok(_) => Ok(Some(terminal)),
        Err(
            WanSessionCoordinatorError::SessionTerminal | WanSessionCoordinatorError::Transition(_),
        ) if terminal.phase().is_terminal() => Ok(Some(terminal)),
        Err(error) => Err(error),
    }
}

/// Re-publish a coordinator terminal state without replaying cleanup. This is
/// used by query/list paths and by future deadline/shutdown reconciliation.
pub(crate) async fn reconcile_wan_session_under_security_gate(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
) -> Result<Option<WanSessionState>, WanSessionCoordinatorError> {
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return Ok(None);
    };
    let state = match coordinator.snapshot(session_id).await {
        Ok(state) => state,
        Err(WanSessionCoordinatorError::SessionNotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !state.phase().is_terminal() {
        if let Some(authorization) = app_state.session_authorizations.snapshot(session_id).await {
            if is_terminal_authorization_state(authorization.authorization_state) {
                let failure = authorization
                    .failure
                    .clone()
                    .unwrap_or_else(|| RemoteFailure {
                        code: RemoteReasonCode::GrantRevoked,
                        message: "secure WAN authorization ended".to_owned(),
                        suggested_action: Some("start a new secure WAN session".to_owned()),
                    });
                return terminalize_wan_session_under_security_gate(
                    app_state,
                    session_id,
                    ServiceWanTerminalRequest::Fail {
                        failure: wan_failure_from_remote_reason(failure.code),
                        remote_failure: failure,
                    },
                )
                .await;
            }
        }
    }
    if state.phase().is_terminal() {
        publish_terminal_wan_state(app_state, &state, None).await;
    } else {
        if state.phase() == WanSessionPhase::Streaming {
            let _ = app_state
                .session_authorizations
                .mark_streaming(session_id, now_unix_ms())
                .await;
        }
        project_wan_session_state(app_state, &state).await;
    }
    Ok(Some(state))
}

/// Reconcile every coordinator-owned WAN workflow before reading the shared
/// runtime projection. Callers must hold `authorization_security_gate` so
/// terminal authorization changes and visible session state remain atomic.
pub(crate) async fn reconcile_all_wan_sessions_under_security_gate(
    app_state: &Arc<crate::AppState>,
) -> Result<(), WanSessionCoordinatorError> {
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return Ok(());
    };
    let session_ids = coordinator
        .snapshots()
        .await
        .into_iter()
        .map(|state| state.identity().session_id().clone())
        .collect::<Vec<_>>();
    for session_id in session_ids {
        reconcile_wan_session_under_security_gate(app_state, &session_id).await?;
    }
    Ok(())
}

/// Build deterministic IPC list projections from the workflow authority.
/// Existing media flags are used only after the coordinator reached Streaming.
pub(crate) async fn wan_session_infos_under_security_gate(
    app_state: &Arc<crate::AppState>,
) -> Vec<SessionInfo> {
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return Vec::new();
    };
    let states = coordinator.snapshots().await;
    for state in &states {
        if state.phase().is_terminal() {
            publish_terminal_wan_state(app_state, state, None).await;
        }
    }
    let projected = app_state
        .sessions
        .lock()
        .await
        .list_all()
        .into_iter()
        .map(|snapshot| (snapshot.session_id.clone(), snapshot))
        .collect::<HashMap<_, _>>();
    let mut sessions = states
        .iter()
        .map(|state| {
            let lifecycle = wan_lifecycle(state);
            let active = projected.get(state.identity().session_id());
            let media_is_streaming = lifecycle == SessionLifecycleState::Streaming;
            SessionInfo {
                session_id: state.identity().session_id().clone(),
                role: wan_role_name(state.role()).to_owned(),
                state: lifecycle.as_str().to_owned(),
                transport_kind: "webrtc_relay".to_owned(),
                last_error: wan_last_error(state),
                sender_active: media_is_streaming
                    && active.is_some_and(|snapshot| snapshot.sender_active),
                receiver_active: media_is_streaming
                    && active.is_some_and(|snapshot| snapshot.receiver_active),
                peer_device_id: Some(wan_peer_device_id(state).clone()),
            }
        })
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| left.session_id.0.cmp(&right.session_id.0));
    sessions
}

/// Service heartbeat entrypoint for deadline expiry. The authorization gate
/// makes the workflow transition and its public security projection atomic
/// with trust and policy changes.
pub async fn expire_due_wan_sessions(app_state: &Arc<crate::AppState>) -> usize {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return 0;
    };
    let expired = coordinator.expire_due_sessions().await;
    for state in coordinator.snapshots().await {
        if state.phase().is_terminal() {
            publish_terminal_wan_state(app_state, &state, None).await;
        }
    }
    expired
}

/// Service shutdown entrypoint. Every live workflow is cancelled and cleaned
/// before its authorization and IPC projection become terminal.
pub async fn shutdown_active_wan_sessions(app_state: &Arc<crate::AppState>) -> usize {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return 0;
    };
    let shutdown = coordinator.shutdown_active_sessions().await;
    for state in coordinator.snapshots().await {
        if state.phase().is_terminal() {
            publish_terminal_wan_state(app_state, &state, None).await;
        }
    }
    shutdown
}

pub(crate) async fn fail_wan_session(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
    failure: WanSessionFailure,
) -> Result<Option<WanSessionState>, WanSessionCoordinatorError> {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    terminalize_wan_session_under_security_gate(
        app_state,
        session_id,
        ServiceWanTerminalRequest::Fail {
            failure,
            remote_failure: wan_remote_failure(failure),
        },
    )
    .await
}

pub(crate) async fn reconcile_wan_session(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
) -> Result<Option<WanSessionState>, WanSessionCoordinatorError> {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    reconcile_wan_session_under_security_gate(app_state, session_id).await
}

async fn publish_terminal_wan_state(
    app_state: &Arc<crate::AppState>,
    state: &WanSessionState,
    requested_remote_failure: Option<RemoteFailure>,
) {
    if !state.phase().is_terminal() {
        return;
    }
    let (authorization_state, remote_failure) = match state.phase() {
        WanSessionPhase::Closed => (
            RemoteAuthorizationState::Revoked,
            RemoteFailure {
                code: RemoteReasonCode::GrantRevoked,
                message: "secure WAN session was closed".to_owned(),
                suggested_action: None,
            },
        ),
        WanSessionPhase::Failed => {
            let failure = state.failure().unwrap_or(WanSessionFailure::Internal);
            let authorization_state = wan_failure_authorization_state(failure);
            (
                authorization_state,
                requested_remote_failure.unwrap_or_else(|| wan_remote_failure(failure)),
            )
        }
        _ => return,
    };
    let _ = app_state
        .session_authorizations
        .record_failure(
            state.identity().session_id(),
            authorization_state,
            remote_failure,
            now_unix_ms(),
        )
        .await;
    project_wan_session_state(app_state, state).await;
}

async fn project_wan_session_state(app_state: &Arc<crate::AppState>, state: &WanSessionState) {
    let session_id = state.identity().session_id().clone();
    let mut sessions = app_state.sessions.lock().await;
    let previous = sessions.get(&session_id).cloned();
    let (source_device_id, target_device_id) = match state.role() {
        WanSessionRole::Controller => (
            Some(state.identity().controller_device_id().clone()),
            Some(state.identity().target_device_id().clone()),
        ),
        WanSessionRole::Target => (Some(state.identity().controller_device_id().clone()), None),
    };
    let lifecycle_state = wan_lifecycle(state);
    let media_is_streaming = lifecycle_state == SessionLifecycleState::Streaming;
    sessions.insert(
        session_id.clone(),
        SessionSnapshot {
            session_id,
            transport: "webrtc_relay".to_owned(),
            source_device_id,
            target_device_id,
            local_listen_addr: previous
                .as_ref()
                .and_then(|snapshot| snapshot.local_listen_addr.clone()),
            local_server_name: previous
                .as_ref()
                .and_then(|snapshot| snapshot.local_server_name.clone()),
            local_cert_der_b64: previous
                .as_ref()
                .and_then(|snapshot| snapshot.local_cert_der_b64.clone()),
            remote_listen_addr: previous
                .as_ref()
                .and_then(|snapshot| snapshot.remote_listen_addr.clone()),
            remote_server_name: previous
                .as_ref()
                .and_then(|snapshot| snapshot.remote_server_name.clone()),
            remote_cert_der_b64: previous
                .as_ref()
                .and_then(|snapshot| snapshot.remote_cert_der_b64.clone()),
            lifecycle_state,
            last_error: wan_last_error(state),
            sender_active: media_is_streaming
                && previous
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.sender_active),
            receiver_active: media_is_streaming
                && previous
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.receiver_active),
        },
    );
}

fn wan_lifecycle(state: &WanSessionState) -> SessionLifecycleState {
    match state.phase() {
        WanSessionPhase::Created
        | WanSessionPhase::BackendBound
        | WanSessionPhase::AwaitingConsent
            if state.role() == WanSessionRole::Target =>
        {
            SessionLifecycleState::Listening
        }
        WanSessionPhase::Created
        | WanSessionPhase::BackendBound
        | WanSessionPhase::AwaitingConsent
        | WanSessionPhase::Granted
        | WanSessionPhase::AccessBound
        | WanSessionPhase::Negotiating => SessionLifecycleState::Connecting,
        WanSessionPhase::RelayVerified => SessionLifecycleState::Connected,
        WanSessionPhase::Streaming => SessionLifecycleState::Streaming,
        WanSessionPhase::Closed => SessionLifecycleState::Closed,
        WanSessionPhase::Failed => SessionLifecycleState::Failed {
            message: wan_last_error(state).unwrap_or_else(|| "WAN session failed".to_owned()),
        },
    }
}

fn wan_role_name(role: WanSessionRole) -> &'static str {
    match role {
        WanSessionRole::Controller => "controller",
        WanSessionRole::Target => "agent",
    }
}

fn wan_peer_device_id(state: &WanSessionState) -> &DeviceId {
    match state.role() {
        WanSessionRole::Controller => state.identity().target_device_id(),
        WanSessionRole::Target => state.identity().controller_device_id(),
    }
}

fn wan_last_error(state: &WanSessionState) -> Option<String> {
    state.failure().map(|failure| {
        match failure {
            WanSessionFailure::DeadlineExceeded => "WAN session deadline exceeded",
            WanSessionFailure::IdentityMismatch => "WAN session identity verification failed",
            WanSessionFailure::PolicyMismatch => "WAN session policy changed",
            WanSessionFailure::RouteMismatch => "WAN relay route verification failed",
            WanSessionFailure::CapacityExceeded => "WAN session capacity exceeded",
            WanSessionFailure::RetryBudgetExceeded => "WAN session retry budget exceeded",
            WanSessionFailure::BufferCapacityExceeded => "WAN session buffer capacity exceeded",
            WanSessionFailure::Transport => "WAN transport failed",
            WanSessionFailure::Cancelled => "WAN session was cancelled",
            WanSessionFailure::InvalidTransition
            | WanSessionFailure::ConflictingDuplicate
            | WanSessionFailure::Internal => "WAN session failed",
        }
        .to_owned()
    })
}

fn wan_failure_authorization_state(failure: WanSessionFailure) -> RemoteAuthorizationState {
    match failure {
        WanSessionFailure::DeadlineExceeded => RemoteAuthorizationState::Expired,
        WanSessionFailure::IdentityMismatch => RemoteAuthorizationState::Denied,
        WanSessionFailure::PolicyMismatch => RemoteAuthorizationState::PolicyChanged,
        _ => RemoteAuthorizationState::Revoked,
    }
}

fn is_terminal_authorization_state(state: RemoteAuthorizationState) -> bool {
    matches!(
        state,
        RemoteAuthorizationState::Denied
            | RemoteAuthorizationState::Expired
            | RemoteAuthorizationState::Revoked
            | RemoteAuthorizationState::LockedOut
            | RemoteAuthorizationState::PolicyChanged
    )
}

fn wan_failure_from_remote_reason(reason: RemoteReasonCode) -> WanSessionFailure {
    match reason {
        RemoteReasonCode::IdentityMismatch | RemoteReasonCode::CertificateBindingMismatch => {
            WanSessionFailure::IdentityMismatch
        }
        RemoteReasonCode::AuthorizationTimeout | RemoteReasonCode::GrantExpired => {
            WanSessionFailure::DeadlineExceeded
        }
        RemoteReasonCode::PolicyChanged | RemoteReasonCode::ScopeDenied => {
            WanSessionFailure::PolicyMismatch
        }
        RemoteReasonCode::LanUnreachable
        | RemoteReasonCode::IceDirectFailed
        | RemoteReasonCode::TurnAllocationFailed
        | RemoteReasonCode::RouteLost
        | RemoteReasonCode::RouteMigrationTimeout => WanSessionFailure::Transport,
        RemoteReasonCode::TrustRequired
        | RemoteReasonCode::ConsentDenied
        | RemoteReasonCode::CredentialInvalid
        | RemoteReasonCode::CredentialLocked
        | RemoteReasonCode::GrantRevoked
        | RemoteReasonCode::ReplayDetected
        | RemoteReasonCode::ProtocolDowngradeBlocked
        | RemoteReasonCode::EncoderUnavailable
        | RemoteReasonCode::DecoderUnavailable
        | RemoteReasonCode::CaptureSourceLost
        | RemoteReasonCode::ProfileDowngraded
        | RemoteReasonCode::CongestionDownshift
        | RemoteReasonCode::RenderBudgetExceeded => WanSessionFailure::Cancelled,
    }
}

fn wan_remote_failure(failure: WanSessionFailure) -> RemoteFailure {
    let code = match failure {
        WanSessionFailure::DeadlineExceeded => RemoteReasonCode::AuthorizationTimeout,
        WanSessionFailure::IdentityMismatch => RemoteReasonCode::IdentityMismatch,
        WanSessionFailure::PolicyMismatch => RemoteReasonCode::PolicyChanged,
        WanSessionFailure::RouteMismatch | WanSessionFailure::Transport => {
            RemoteReasonCode::RouteLost
        }
        WanSessionFailure::CapacityExceeded => RemoteReasonCode::TurnAllocationFailed,
        WanSessionFailure::Cancelled => RemoteReasonCode::GrantRevoked,
        WanSessionFailure::RetryBudgetExceeded
        | WanSessionFailure::BufferCapacityExceeded
        | WanSessionFailure::InvalidTransition
        | WanSessionFailure::ConflictingDuplicate
        | WanSessionFailure::Internal => RemoteReasonCode::PolicyChanged,
    };
    RemoteFailure {
        code,
        message: wan_last_error_for_failure(failure).to_owned(),
        suggested_action: Some("start a new secure WAN session".to_owned()),
    }
}

fn wan_last_error_for_failure(failure: WanSessionFailure) -> &'static str {
    match failure {
        WanSessionFailure::DeadlineExceeded => "WAN session deadline exceeded",
        WanSessionFailure::IdentityMismatch => "WAN session identity verification failed",
        WanSessionFailure::PolicyMismatch => "WAN session policy changed",
        WanSessionFailure::RouteMismatch => "WAN relay route verification failed",
        WanSessionFailure::CapacityExceeded => "WAN session capacity exceeded",
        WanSessionFailure::RetryBudgetExceeded => "WAN session retry budget exceeded",
        WanSessionFailure::BufferCapacityExceeded => "WAN session buffer capacity exceeded",
        WanSessionFailure::Transport => "WAN transport failed",
        WanSessionFailure::Cancelled => "WAN session was cancelled",
        WanSessionFailure::InvalidTransition
        | WanSessionFailure::ConflictingDuplicate
        | WanSessionFailure::Internal => "WAN session failed",
    }
}

/// Idempotent production cleanup used by every terminal coordinator path.
/// A weak AppState reference avoids an AppState -> coordinator -> cleanup cycle.
pub struct ServiceWanSessionCleanup {
    app_state: Weak<crate::AppState>,
    backend: Arc<ServiceWanSessionWorkflowBackend>,
    consent: Arc<ServiceWanSessionConsentPublisher>,
}

impl ServiceWanSessionCleanup {
    pub fn new(
        app_state: &Arc<crate::AppState>,
        backend: Arc<ServiceWanSessionWorkflowBackend>,
        consent: Arc<ServiceWanSessionConsentPublisher>,
    ) -> Self {
        Self {
            app_state: Arc::downgrade(app_state),
            backend,
            consent,
        }
    }

    fn app_state(
        &self,
    ) -> Result<Arc<crate::AppState>, super::coordinator::WanSessionCoordinatorError> {
        self.app_state
            .upgrade()
            .ok_or(super::coordinator::WanSessionCoordinatorError::CleanupFailed)
    }
}

#[async_trait]
impl super::coordinator::WanSessionCleanup for ServiceWanSessionCleanup {
    async fn freeze_input(
        &self,
        session_id: &SessionId,
    ) -> Result<(), super::coordinator::WanSessionCoordinatorError> {
        let app_state = self.app_state()?;
        // The registry inserts the freeze fence even when releasing a platform
        // key/button fails, so cleanup remains fail-closed.
        let _ = app_state
            .control_input
            .lock()
            .await
            .freeze_session_for_migration(session_id);
        Ok(())
    }

    async fn stop_media(
        &self,
        session_id: &SessionId,
    ) -> Result<(), super::coordinator::WanSessionCoordinatorError> {
        let app_state = self.app_state()?;
        super::control_input::clear_wan_control_input(&app_state, session_id).await;
        app_state.media_tasks.lock().await.abort_session(session_id);
        app_state.media_profiles.lock().await.remove(session_id);
        app_state.capture_sources.lock().await.remove(session_id);
        app_state
            .peer_media_capabilities
            .lock()
            .await
            .remove(session_id);
        app_state.media_pipelines.lock().await.remove(session_id);
        app_state.remove_agent_render_route(session_id).await;
        Ok(())
    }

    async fn close_transport(
        &self,
        session_id: &SessionId,
    ) -> Result<(), super::coordinator::WanSessionCoordinatorError> {
        let app_state = self.app_state()?;
        match app_state.webrtc_host.close_session(session_id).await {
            Ok(())
            | Err(crate::transports::webrtc::ServiceWebRtcTransportError::SessionNotFound(_)) => {
                Ok(())
            }
            Err(_) => Err(super::coordinator::WanSessionCoordinatorError::CleanupFailed),
        }
    }

    async fn remove_failover(
        &self,
        session_id: &SessionId,
    ) -> Result<(), super::coordinator::WanSessionCoordinatorError> {
        let app_state = self.app_state()?;
        if let Some(failover) = app_state.relay_failover_coordinator() {
            if failover.snapshot(session_id).await.is_ok() {
                failover
                    .terminate_security(
                        session_id,
                        crate::relay::RelayTerminalSecurityReason::RelayRevoked,
                    )
                    .await
                    .map_err(|_| super::coordinator::WanSessionCoordinatorError::CleanupFailed)?;
            }
        }
        Ok(())
    }

    async fn clear_signaling(
        &self,
        session_id: &SessionId,
    ) -> Result<(), super::coordinator::WanSessionCoordinatorError> {
        let app_state = self.app_state()?;
        self.consent.discard(session_id).await;
        app_state
            .relay_signaling
            .close_authenticated_session(session_id)
            .await
            .map_err(|_| super::coordinator::WanSessionCoordinatorError::CleanupFailed)
    }

    async fn close_backend(
        &self,
        session_id: &SessionId,
        failed: bool,
    ) -> Result<(), super::coordinator::WanSessionCoordinatorError> {
        self.backend
            .close_session(session_id, failed)
            .await
            .map_err(|_| super::coordinator::WanSessionCoordinatorError::CleanupFailed)
    }
}

/// Bridges the target-side coordinator consent port to the existing exact
/// session authorization registry. Requested profiles are retained only until
/// the matching local decision is consumed.
pub struct ServiceWanSessionConsentPublisher {
    authorizations: Arc<crate::session_authorization::SessionAuthorizationRegistry>,
    requested_profiles: Mutex<HashMap<SessionId, Option<WanMediaProfileV3>>>,
}

impl std::fmt::Debug for ServiceWanSessionConsentPublisher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceWanSessionConsentPublisher")
            .finish_non_exhaustive()
    }
}

impl ServiceWanSessionConsentPublisher {
    pub fn new(
        authorizations: Arc<crate::session_authorization::SessionAuthorizationRegistry>,
    ) -> Self {
        Self {
            authorizations,
            requested_profiles: Mutex::new(HashMap::new()),
        }
    }

    async fn discard(&self, session_id: &SessionId) {
        self.requested_profiles.lock().await.remove(session_id);
    }
}

#[async_trait]
impl WanSessionConsentPublisher for ServiceWanSessionConsentPublisher {
    async fn publish_attended_request(
        &self,
        identity: &super::model::WanSessionIdentity,
        request: &WanSessionRequestV3,
        absolute_deadline_unix_ms: u64,
    ) -> Result<(), WanSessionPortError> {
        let now = now_unix_ms();
        if now >= absolute_deadline_unix_ms
            || request.session_id != *identity.session_id()
            || request.controller_device_id != *identity.controller_device_id()
            || request.target_device_id != *identity.target_device_id()
        {
            return Err(WanSessionPortError::Rejected);
        }
        let scopes = request
            .requested_scopes
            .iter()
            .copied()
            .map(ipc_scope)
            .collect::<Vec<_>>();
        let authorization = crate::session_authorization::VerifiedIncomingAuthorizationRequest {
            session_id: request.session_id.clone(),
            peer_device_id: request.controller_device_id.clone(),
            peer_key_id: identity.controller_key_fingerprint().to_owned(),
            peer_key_epoch: 1,
            access_mode: mrd_ipc::RemoteAccessMode::Attended,
            requested_scopes: scopes.clone(),
            peer_permission_ceiling: scopes.clone(),
            machine_permission_ceiling: scopes.clone(),
            runtime_capabilities: scopes,
            transport_kind: "webrtc_relay".to_owned(),
            request_nonce: request.idempotency_key,
            created_at_ms: now,
            expires_at_ms: absolute_deadline_unix_ms,
        };
        self.authorizations
            .begin_verified_incoming(authorization)
            .await
            .map_err(|_| WanSessionPortError::Rejected)?;
        self.requested_profiles.lock().await.insert(
            request.session_id.clone(),
            request.requested_profile.clone(),
        );
        Ok(())
    }

    async fn load_attended_approval(
        &self,
        identity: &super::model::WanSessionIdentity,
        absolute_deadline_unix_ms: u64,
    ) -> Result<WanSessionApproval, WanSessionPortError> {
        if now_unix_ms() >= absolute_deadline_unix_ms {
            return Err(WanSessionPortError::DeadlineExceeded);
        }
        let snapshot = self
            .authorizations
            .wait_for_authorization_decision(identity.session_id())
            .await;
        let profile = self
            .requested_profiles
            .lock()
            .await
            .remove(identity.session_id())
            .flatten();
        let snapshot = snapshot.map_err(|_| WanSessionPortError::Rejected)?;
        if snapshot.authorization_state != RemoteAuthorizationState::Authorizing
            || snapshot.peer_device_id != *identity.controller_device_id()
            || snapshot.peer_key_id != identity.controller_key_fingerprint()
        {
            return Err(WanSessionPortError::Rejected);
        }
        WanSessionApproval::new(
            snapshot.granted_scopes.into_iter().map(wan_scope).collect(),
            profile,
        )
        .map_err(|_| WanSessionPortError::Rejected)
    }
}

/// Minimal service-owned activation adapter. It updates the existing media
/// registries only after `WanMediaAuthority` has proven RelayVerified.
pub struct ServiceWanMediaActivationPort {
    app_state: Weak<crate::AppState>,
    #[cfg(any(test, debug_assertions))]
    test_mux: Option<(SessionId, Arc<dyn TransportMuxPort>)>,
}

impl ServiceWanMediaActivationPort {
    pub fn new(app_state: &Arc<crate::AppState>) -> Self {
        Self {
            app_state: Arc::downgrade(app_state),
            #[cfg(any(test, debug_assertions))]
            test_mux: None,
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub fn with_test_mux(
        app_state: &Arc<crate::AppState>,
        session_id: SessionId,
        mux: Arc<dyn TransportMuxPort>,
    ) -> Self {
        Self {
            app_state: Arc::downgrade(app_state),
            test_mux: Some((session_id, mux)),
        }
    }

    async fn resolve_mux(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<Arc<dyn TransportMuxPort>, WanMediaActivationError> {
        #[cfg(any(test, debug_assertions))]
        if let Some((session_id, mux)) = &self.test_mux {
            let route = mux.route_snapshot().await;
            if *session_id != *authority.session_id()
                || route.session_id != *authority.session_id()
                || route.kind != TransportRouteKind::TestMemory
                || route.closed
            {
                return Err(WanMediaActivationError::StartupFailed);
            }
            return Ok(Arc::clone(mux));
        }

        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        app_state
            .webrtc_host
            .verified_media_mux(authority.session_id(), authority.generation())
            .await
            .map_err(|_| WanMediaActivationError::StartupFailed)
    }

    #[cfg(any(test, debug_assertions))]
    pub async fn stop_media_for_test(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanMediaActivationError> {
        WanMediaActivationPort::stop_media(self, session_id).await
    }
}

#[async_trait]
impl WanMediaActivationPort for ServiceWanMediaActivationPort {
    async fn start_target_capture_send(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<WanMediaActivationReceipt, WanMediaActivationError> {
        if authority.role() != WanSessionRole::Target {
            return Err(WanMediaActivationError::StartupFailed);
        }
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        let mux = self.resolve_mux(authority).await?;
        bind_verified_mux(&app_state, authority.clone(), Arc::clone(&mux)).await?;
        #[cfg(any(test, debug_assertions))]
        let test_synthetic_capture = self.test_mux.is_some();
        #[cfg(not(any(test, debug_assertions)))]
        let test_synthetic_capture = false;
        start_target_runtime(app_state, authority.clone(), mux, test_synthetic_capture).await
    }

    async fn start_controller_receive_render(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<WanMediaActivationReceipt, WanMediaActivationError> {
        if authority.role() != WanSessionRole::Controller {
            return Err(WanMediaActivationError::StartupFailed);
        }
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        let mux = self.resolve_mux(authority).await?;
        bind_verified_mux(&app_state, authority.clone(), Arc::clone(&mux)).await?;
        start_controller_runtime(app_state, authority.clone(), mux).await
    }

    async fn stop_media(&self, session_id: &SessionId) -> Result<(), WanMediaActivationError> {
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        super::control_input::clear_wan_control_input(&app_state, session_id).await;
        app_state.media_tasks.lock().await.abort_session(session_id);
        app_state.media_profiles.lock().await.remove(session_id);
        app_state.capture_sources.lock().await.remove(session_id);
        app_state
            .peer_media_capabilities
            .lock()
            .await
            .remove(session_id);
        app_state.media_pipelines.lock().await.remove(session_id);
        app_state.remove_agent_render_route(session_id).await;
        Ok(())
    }

    async fn remove_failover(&self, session_id: &SessionId) -> Result<(), WanMediaActivationError> {
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        if let Some(failover) = app_state.relay_failover_coordinator() {
            if failover.snapshot(session_id).await.is_ok() {
                failover
                    .terminate_security(
                        session_id,
                        crate::relay::RelayTerminalSecurityReason::RelayRevoked,
                    )
                    .await
                    .map_err(|_| WanMediaActivationError::StartupFailed)?;
            }
        }
        Ok(())
    }
}

fn ipc_scope(scope: WanPermissionScopeV3) -> RemotePermissionScope {
    match scope {
        WanPermissionScopeV3::ScreenView => RemotePermissionScope::ScreenView,
        WanPermissionScopeV3::InputPointer => RemotePermissionScope::InputPointer,
        WanPermissionScopeV3::InputKeyboard => RemotePermissionScope::InputKeyboard,
        WanPermissionScopeV3::ClipboardRead => RemotePermissionScope::ClipboardRead,
        WanPermissionScopeV3::ClipboardWrite => RemotePermissionScope::ClipboardWrite,
        WanPermissionScopeV3::FileRead => RemotePermissionScope::FileRead,
        WanPermissionScopeV3::FileWrite => RemotePermissionScope::FileWrite,
        WanPermissionScopeV3::AudioListen => RemotePermissionScope::AudioListen,
        WanPermissionScopeV3::AudioTalk => RemotePermissionScope::AudioTalk,
        WanPermissionScopeV3::DisplaySwitch => RemotePermissionScope::DisplaySwitch,
        WanPermissionScopeV3::DisplayMultiView => RemotePermissionScope::DisplayMultiView,
        WanPermissionScopeV3::PowerRestart => RemotePermissionScope::PowerRestart,
        WanPermissionScopeV3::PowerShutdown => RemotePermissionScope::PowerShutdown,
        WanPermissionScopeV3::TerminalOpen => RemotePermissionScope::TerminalOpen,
        WanPermissionScopeV3::PrivacyBlockLocalInput => {
            RemotePermissionScope::PrivacyBlockLocalInput
        }
        WanPermissionScopeV3::PrivacyBlankScreen => RemotePermissionScope::PrivacyBlankScreen,
        WanPermissionScopeV3::SecureDesktopView => RemotePermissionScope::SecureDesktopView,
        WanPermissionScopeV3::SecureDesktopControl => RemotePermissionScope::SecureDesktopControl,
    }
}

fn wan_scope(scope: RemotePermissionScope) -> WanPermissionScopeV3 {
    match scope {
        RemotePermissionScope::ScreenView => WanPermissionScopeV3::ScreenView,
        RemotePermissionScope::InputPointer => WanPermissionScopeV3::InputPointer,
        RemotePermissionScope::InputKeyboard => WanPermissionScopeV3::InputKeyboard,
        RemotePermissionScope::ClipboardRead => WanPermissionScopeV3::ClipboardRead,
        RemotePermissionScope::ClipboardWrite => WanPermissionScopeV3::ClipboardWrite,
        RemotePermissionScope::FileRead => WanPermissionScopeV3::FileRead,
        RemotePermissionScope::FileWrite => WanPermissionScopeV3::FileWrite,
        RemotePermissionScope::AudioListen => WanPermissionScopeV3::AudioListen,
        RemotePermissionScope::AudioTalk => WanPermissionScopeV3::AudioTalk,
        RemotePermissionScope::DisplaySwitch => WanPermissionScopeV3::DisplaySwitch,
        RemotePermissionScope::DisplayMultiView => WanPermissionScopeV3::DisplayMultiView,
        RemotePermissionScope::PowerRestart => WanPermissionScopeV3::PowerRestart,
        RemotePermissionScope::PowerShutdown => WanPermissionScopeV3::PowerShutdown,
        RemotePermissionScope::TerminalOpen => WanPermissionScopeV3::TerminalOpen,
        RemotePermissionScope::PrivacyBlockLocalInput => {
            WanPermissionScopeV3::PrivacyBlockLocalInput
        }
        RemotePermissionScope::PrivacyBlankScreen => WanPermissionScopeV3::PrivacyBlankScreen,
        RemotePermissionScope::SecureDesktopView => WanPermissionScopeV3::SecureDesktopView,
        RemotePermissionScope::SecureDesktopControl => WanPermissionScopeV3::SecureDesktopControl,
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ServiceWanSessionStartError {
    #[error("local device identity is unavailable")]
    LocalIdentityUnavailable,
    #[error("WAN session coordinator could not be configured")]
    CoordinatorUnavailable,
    #[error("WAN session coordinator is already bound")]
    CoordinatorAlreadyBound,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ServiceWanControllerGrantError {
    #[error("authenticated WAN grant verification failed")]
    Verification,
    #[error("WAN coordinator rejected the authenticated grant")]
    Coordinator,
    #[error("WAN authorization rejected the authenticated grant")]
    Authorization,
}

/// Owns the background V3 intent/grant dispatcher. Dropping the handle does
/// not silently detach the task; callers should use `shutdown` so live
/// coordinator entries receive their cancellation fence and full cleanup.
pub struct ServiceWanSessionTask {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl ServiceWanSessionTask {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.join.await;
    }
}

/// Bind the single production coordinator and start consuming only the two
/// V3 messages that establish an initial WAN session. WebRTC descriptions and
/// candidates remain on the scoped generation-zero subscription.
pub async fn bind_and_spawn_wan_session_service(
    app_state: Arc<crate::AppState>,
    backend: Arc<dyn WanSessionBackend>,
) -> Result<ServiceWanSessionTask, ServiceWanSessionStartError> {
    let local_device_id = app_state
        .devices
        .lock()
        .await
        .get_local_device()
        .map(|(device_id, _)| device_id.clone())
        .ok_or(ServiceWanSessionStartError::LocalIdentityUnavailable)?;
    let local_identity = app_state.device_identities.machine_identity();
    let workflow_backend = Arc::new(ServiceWanSessionWorkflowBackend::new(backend));
    let signaling = Arc::new(ServiceWanSessionWorkflowSignaling::new(Arc::clone(
        &app_state.relay_signaling,
    )));
    let consent = Arc::new(ServiceWanSessionConsentPublisher::new(Arc::clone(
        &app_state.session_authorizations,
    )));
    let cleanup = Arc::new(ServiceWanSessionCleanup::new(
        &app_state,
        Arc::clone(&workflow_backend),
        Arc::clone(&consent),
    ));
    let clock = Arc::new(SystemWanSessionClock);
    let workflow =
        WanSessionWorkflowPorts::new(workflow_backend.clone(), signaling, consent, clock);
    let coordinator = Arc::new(
        WanSessionCoordinator::with_workflow_ports(
            WanSessionCoordinatorConfig::default(),
            cleanup,
            workflow,
        )
        .map_err(|_| ServiceWanSessionStartError::CoordinatorUnavailable)?,
    );
    app_state
        .bind_wan_session_coordinator(Arc::clone(&coordinator))
        .map_err(|_| ServiceWanSessionStartError::CoordinatorAlreadyBound)?;

    let (shutdown, shutdown_rx) = oneshot::channel();
    let join = tokio::spawn(run_wan_session_service(
        app_state,
        coordinator,
        workflow_backend,
        local_device_id,
        local_identity,
        shutdown_rx,
    ));
    Ok(ServiceWanSessionTask {
        shutdown: Some(shutdown),
        join,
    })
}

async fn run_wan_session_service(
    app_state: Arc<crate::AppState>,
    coordinator: Arc<WanSessionCoordinator>,
    backend: Arc<ServiceWanSessionWorkflowBackend>,
    local_device_id: DeviceId,
    local_identity: Arc<mrd_identity::DeviceIdentity>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut inbound = app_state.relay_signaling.subscribe();
    let mut tasks = JoinSet::<SessionId>::new();
    let mut active = HashSet::<SessionId>::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(session_id)) = completed {
                    active.remove(&session_id);
                }
            }
            event = inbound.recv() => {
                let Ok(event) = event else {
                    if matches!(event, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                        break;
                    }
                    continue;
                };
                if !matches!(
                    &event.signal,
                    AuthenticatedSessionSignal::SessionIntentV3 { .. }
                        | AuthenticatedSessionSignal::SessionGrantV3 { .. }
                ) {
                    continue;
                }
                let session_id = event.signal.session_id().clone();
                if active.contains(&session_id) || active.len() >= MAX_INITIAL_EVENT_TASKS {
                    continue;
                }
                active.insert(session_id.clone());
                let task_app_state = Arc::clone(&app_state);
                let task_coordinator = Arc::clone(&coordinator);
                let task_backend = Arc::clone(&backend);
                let task_local_device_id = local_device_id.clone();
                let task_local_identity = Arc::clone(&local_identity);
                tasks.spawn(async move {
                    handle_initial_event(
                        task_app_state,
                        task_coordinator,
                        task_backend,
                        task_local_device_id,
                        task_local_identity,
                        event,
                    )
                    .await;
                    session_id
                });
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let _ = shutdown_active_wan_sessions(&app_state).await;
}

async fn handle_initial_event(
    app_state: Arc<crate::AppState>,
    coordinator: Arc<WanSessionCoordinator>,
    backend: Arc<ServiceWanSessionWorkflowBackend>,
    local_device_id: DeviceId,
    local_identity: Arc<mrd_identity::DeviceIdentity>,
    event: VerifiedSignalingEvent,
) {
    let session_id = event.signal.session_id().clone();
    let result = if matches!(
        &event.signal,
        AuthenticatedSessionSignal::SessionIntentV3 { .. }
    ) {
        handle_target_intent(
            &coordinator,
            event,
            &local_device_id,
            local_identity.as_ref(),
        )
        .await
    } else {
        apply_verified_controller_grant(&app_state, &coordinator, event)
            .await
            .map_err(|_| ())
    };
    if result.is_err() {
        // Verification failures are ignored rather than terminalizing a valid
        // session: an attacker cannot turn a malformed frame into a close.
        let _ = reconcile_wan_session(&app_state, &session_id).await;
        return;
    }
    let _ = reconcile_wan_session(&app_state, &session_id).await;
    if spawn_generation_zero(
        Arc::clone(&app_state),
        Arc::clone(&coordinator),
        backend,
        &session_id,
    )
    .await
    .is_err()
    {
        let _ = fail_wan_session(&app_state, &session_id, WanSessionFailure::RouteMismatch).await;
    }
}

async fn handle_target_intent(
    coordinator: &WanSessionCoordinator,
    event: VerifiedSignalingEvent,
    local_device_id: &DeviceId,
    local_identity: &mrd_identity::DeviceIdentity,
) -> Result<(), ()> {
    let verified = VerifiedWanSessionIntent::verify_event(
        event,
        local_device_id,
        local_identity,
        now_unix_ms(),
    )
    .map_err(|_| ())?;
    let session_id = verified.identity().session_id().clone();
    coordinator
        .accept_verified_target_intent(verified)
        .await
        .map_err(|_| ())?;
    coordinator
        .approve_target(&session_id)
        .await
        .map_err(|_| ())?;
    Ok(())
}

async fn apply_verified_controller_grant(
    app_state: &Arc<crate::AppState>,
    coordinator: &WanSessionCoordinator,
    event: VerifiedSignalingEvent,
) -> Result<(), ServiceWanControllerGrantError> {
    apply_verified_controller_grant_inner(app_state, coordinator, event).await
}

/// Test-only integration seam for the production controller grant boundary.
/// The local device and signing identity are always derived from `AppState`.
#[doc(hidden)]
#[cfg(any(test, debug_assertions))]
pub async fn apply_verified_controller_grant_for_service(
    app_state: &Arc<crate::AppState>,
    coordinator: &WanSessionCoordinator,
    event: VerifiedSignalingEvent,
) -> Result<(), ServiceWanControllerGrantError> {
    apply_verified_controller_grant_inner(app_state, coordinator, event).await
}

async fn apply_verified_controller_grant_inner(
    app_state: &Arc<crate::AppState>,
    coordinator: &WanSessionCoordinator,
    event: VerifiedSignalingEvent,
) -> Result<(), ServiceWanControllerGrantError> {
    let local_device_id = app_state
        .devices
        .lock()
        .await
        .get_local_device()
        .map(|(device_id, _)| device_id.clone())
        .ok_or(ServiceWanControllerGrantError::Verification)?;
    let local_identity = app_state.device_identities.machine_identity();
    let verified = VerifiedWanSessionGrant::verify_event(
        event,
        &local_device_id,
        local_identity.as_ref(),
        now_unix_ms(),
    )
    .map_err(|_| ServiceWanControllerGrantError::Verification)?;
    let session_id = verified.session_id().clone();
    if coordinator
        .install_controller_grant(&session_id, verified.clone())
        .await
        .is_err()
    {
        deny_pending_controller_authorization(
            app_state,
            &session_id,
            controller_grant_mismatch(),
            now_unix_ms(),
        )
        .await;
        return Err(ServiceWanControllerGrantError::Coordinator);
    }
    let state = match coordinator.snapshot(&session_id).await {
        Ok(state) => state,
        Err(_) => {
            deny_pending_controller_authorization(
                app_state,
                &session_id,
                controller_grant_mismatch(),
                now_unix_ms(),
            )
            .await;
            return Err(ServiceWanControllerGrantError::Coordinator);
        }
    };
    if install_controller_authorization(app_state, &state, &verified)
        .await
        .is_err()
    {
        let _ = fail_wan_session(app_state, &session_id, WanSessionFailure::Internal).await;
        return Err(ServiceWanControllerGrantError::Authorization);
    }
    Ok(())
}

async fn install_controller_authorization(
    app_state: &Arc<crate::AppState>,
    state: &super::model::WanSessionState,
    verified: &VerifiedWanSessionGrant,
) -> Result<(), RemoteFailure> {
    let installed_at_ms = now_unix_ms();
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    let result = async {
        let trust = app_state
            .device_identities
            .authenticated_peer_trust_current_key(
                verified.target_key_fingerprint(),
                verified.target_public_key(),
            )
            .map_err(|_| controller_grant_trust_invalid())?;
        if matches!(
            trust,
            crate::app_state::AuthenticatedPeerTrust::Suspended
                | crate::app_state::AuthenticatedPeerTrust::Revoked
                | crate::app_state::AuthenticatedPeerTrust::EpochMismatch
        ) {
            return Err(controller_grant_trust_invalid());
        }
        let identity = state.identity();
        let grant = state.grant().ok_or_else(controller_grant_mismatch)?;
        let access = state.access().ok_or_else(controller_grant_mismatch)?;
        if state.role() != WanSessionRole::Controller
            || state.phase() != WanSessionPhase::AccessBound
            || identity.session_id() != verified.session_id()
            || identity.target_device_id() != verified.target_device_id()
            || identity.target_key_fingerprint() != Some(verified.target_key_fingerprint())
            || grant.grant_commitment() != Some(verified.grant_commitment())
            || grant.policy_expires_at_ms() > verified.expires_at_ms()
            || verified.expires_at_ms() > identity.deadline_unix_ms()
        {
            return Err(controller_grant_mismatch());
        }
        let transport_fingerprint_sha256 =
            decode_sha256(access.relay_url_digest()).ok_or_else(controller_grant_mismatch)?;
        let authorization_grant = crate::session_authorization::VerifiedSessionGrant {
            grant_id: format!("sha256:{}", verified.grant_commitment()),
            session_id: identity.session_id().clone(),
            granted_scopes: grant
                .approved_scopes()
                .iter()
                .copied()
                .map(ipc_scope)
                .collect(),
            issued_at_ms: verified.issued_at_ms(),
            expires_at_ms: grant.grant_expires_at_ms(),
            policy_revision: grant.policy_revision(),
            route_constraint: "webrtc_relay".to_owned(),
            transport_fingerprint_sha256,
        };
        let existing = app_state
            .session_authorizations
            .snapshot_at(identity.session_id(), installed_at_ms)
            .await
            .ok_or_else(controller_grant_mismatch)?;
        if existing.authorization_state == RemoteAuthorizationState::Granted {
            let existing_grant = app_state
                .session_authorizations
                .active_grant(identity.session_id())
                .await;
            return if existing.peer_device_id == *verified.target_device_id()
                && existing.peer_key_id == verified.target_key_fingerprint()
                && existing_grant.as_ref() == Some(&authorization_grant)
            {
                Ok(())
            } else {
                Err(controller_grant_mismatch())
            };
        }
        app_state
            .session_authorizations
            .bind_outgoing_authenticated_peer(
                identity.session_id(),
                verified.target_device_id(),
                verified.target_key_fingerprint(),
                verified.target_public_key(),
                installed_at_ms,
            )
            .await?;
        let snapshot = app_state
            .session_authorizations
            .install_verified_grant(authorization_grant, installed_at_ms)
            .await?;
        if snapshot.authorization_state == RemoteAuthorizationState::Granted
            && snapshot.peer_key_id == verified.target_key_fingerprint()
        {
            Ok(())
        } else {
            Err(controller_grant_mismatch())
        }
    }
    .await;
    if let Err(failure) = result.as_ref() {
        record_pending_controller_authorization_denial(
            app_state,
            verified.session_id(),
            failure.clone(),
            installed_at_ms,
        )
        .await;
    }
    result
}

async fn deny_pending_controller_authorization(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
    failure: RemoteFailure,
    failed_at_ms: u64,
) {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    record_pending_controller_authorization_denial(app_state, session_id, failure, failed_at_ms)
        .await;
}

async fn record_pending_controller_authorization_denial(
    app_state: &Arc<crate::AppState>,
    session_id: &SessionId,
    failure: RemoteFailure,
    failed_at_ms: u64,
) {
    let is_pending = app_state
        .session_authorizations
        .snapshot_at(session_id, failed_at_ms)
        .await
        .is_some_and(|snapshot| {
            snapshot.authorization_state == RemoteAuthorizationState::Authorizing
        });
    if is_pending {
        let _ = app_state
            .session_authorizations
            .record_failure(
                session_id,
                RemoteAuthorizationState::Denied,
                failure,
                failed_at_ms,
            )
            .await;
    }
}

fn controller_grant_mismatch() -> RemoteFailure {
    RemoteFailure {
        code: RemoteReasonCode::PolicyChanged,
        message: "verified WAN grant does not match the pending authorization".to_owned(),
        suggested_action: Some("start a new secure WAN session request".to_owned()),
    }
}

fn controller_grant_trust_invalid() -> RemoteFailure {
    RemoteFailure {
        code: RemoteReasonCode::TrustRequired,
        message: "authenticated WAN peer trust is no longer active".to_owned(),
        suggested_action: Some("restore peer trust before starting a new session".to_owned()),
    }
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut decoded = [0u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

async fn spawn_generation_zero(
    app_state: Arc<crate::AppState>,
    coordinator: Arc<WanSessionCoordinator>,
    backend: Arc<ServiceWanSessionWorkflowBackend>,
    session_id: &SessionId,
) -> Result<(), ()> {
    let state = coordinator.snapshot(session_id).await.map_err(|_| ())?;
    if state.phase() != WanSessionPhase::AccessBound {
        return Ok(());
    }
    let grant_commitment = state
        .grant()
        .and_then(|grant| grant.grant_commitment())
        .ok_or(())?
        .to_owned();
    let context =
        GenerationZeroNegotiationContext::from_state(&state, grant_commitment, now_unix_ms())
            .map_err(|_| ())?;
    let raw_access = backend.relay_access(session_id).ok_or(())?;
    if raw_access.generation() != 0
        || raw_access.binding().session_id() != session_id
        || raw_access.binding().controller_device_id() != state.identity().controller_device_id()
        || raw_access.binding().target_device_id() != state.identity().target_device_id()
    {
        return Err(());
    }
    let peer_device_id = match state.role() {
        WanSessionRole::Controller => state.identity().target_device_id(),
        WanSessionRole::Target => state.identity().controller_device_id(),
    };
    let access_binding = state.access().ok_or(())?;
    let relay_context = crate::relay::RelayAccessContext::for_generation(
        session_id.0.clone(),
        access_binding.policy_revision(),
        peer_device_id.0.clone(),
        0,
    )
    .map_err(|_| ())?;
    let verified_access = Arc::clone(raw_access.verified());
    let negotiator = GenerationZeroNegotiator::for_service(
        Arc::clone(&app_state),
        Arc::clone(&coordinator),
        Arc::clone(&verified_access),
        relay_context,
        access_binding.primary_node_id().to_owned(),
        WAN_NEGOTIATION_TIMEOUT,
    )
    .map_err(|_| ())?;
    let media = Arc::new(ServiceWanMediaActivationPort::new(&app_state));
    let failure_app_state = Arc::clone(&app_state);
    let owned_session_id = session_id.clone();
    let task_coordinator = Arc::clone(&coordinator);
    coordinator
        .spawn_owned_task(session_id, move |cancellation| async move {
            let outcome = negotiator
                .negotiate_with_cancellation(
                    context,
                    verified_access.as_ref(),
                    cancellation.into_receiver(),
                )
                .await;
            if let Err(error) = outcome {
                // Always reconcile through the service terminalizer. Some
                // coordinator commit errors are already terminal, while host
                // errors remain live for this wrapper to fail; both require the
                // same authorization-gated public projection.
                let _ = fail_wan_session(
                    &failure_app_state,
                    &owned_session_id,
                    negotiation_failure(error),
                )
                .await;
                return;
            }
            if let Ok(state) = task_coordinator.snapshot(&owned_session_id).await {
                let authority = WanMediaAuthority::from_relay_verified(&state);
                let activation = async {
                    let authority = authority?;
                    start_verified_media(task_coordinator.as_ref(), &state, media.as_ref()).await?;
                    reconcile_wan_session(&failure_app_state, &owned_session_id)
                        .await
                        .map_err(|_| WanMediaActivationError::CoordinatorFailure)?;
                    if authority.role() == WanSessionRole::Target
                        && (authority.allows_scope(WanPermissionScopeV3::InputPointer)
                            || authority.allows_scope(WanPermissionScopeV3::InputKeyboard))
                    {
                        let input = ServiceWanControlInputPort::new(&failure_app_state);
                        let barrier = ServiceWanControlEvidenceBarrier::new(&failure_app_state);
                        enable_input_after_control_evidence(&authority, &barrier, &input).await?;
                    }
                    Ok::<(), WanMediaActivationError>(())
                }
                .await;
                if activation.is_err() {
                    let _ = fail_wan_session(
                        &failure_app_state,
                        &owned_session_id,
                        WanSessionFailure::Transport,
                    )
                    .await;
                } else {
                    let _ = reconcile_wan_session(&failure_app_state, &owned_session_id).await;
                }
            }
        })
        .await
        .map_err(|_| ())
}

fn negotiation_failure(error: GenerationZeroNegotiationError) -> WanSessionFailure {
    match error {
        GenerationZeroNegotiationError::DeadlineExceeded
        | GenerationZeroNegotiationError::Timeout => WanSessionFailure::DeadlineExceeded,
        GenerationZeroNegotiationError::Cancelled => WanSessionFailure::Cancelled,
        GenerationZeroNegotiationError::InvalidBinding
        | GenerationZeroNegotiationError::CandidateManifestMismatch
        | GenerationZeroNegotiationError::CandidateDuplicate
        | GenerationZeroNegotiationError::CandidateWrongRole
        | GenerationZeroNegotiationError::RouteEvidenceMismatch => WanSessionFailure::RouteMismatch,
        GenerationZeroNegotiationError::NotReady
        | GenerationZeroNegotiationError::SignalingUnavailable
        | GenerationZeroNegotiationError::SignalingBackpressure
        | GenerationZeroNegotiationError::TransportUnavailable
        | GenerationZeroNegotiationError::InstallationFailed
        | GenerationZeroNegotiationError::AlreadyOwned => WanSessionFailure::Transport,
    }
}
