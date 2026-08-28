//! Production adapters and background ownership for attended WAN sessions.

use super::{
    backend::{ServiceWanSessionWorkflowBackend, WanSessionApproval, WanSessionBackend},
    coordinator::{
        SystemWanSessionClock, VerifiedWanSessionGrant, VerifiedWanSessionIntent,
        WanSessionConsentPublisher, WanSessionCoordinator, WanSessionCoordinatorConfig,
        WanSessionPortError, WanSessionWorkflowPorts,
    },
    media::{
        ipc_media_profile, start_verified_media, WanMediaActivationError, WanMediaActivationPort,
        WanMediaAuthority,
    },
    model::{WanSessionFailure, WanSessionPhase, WanSessionRole},
    signaling::ServiceWanSessionWorkflowSignaling,
    webrtc::{
        GenerationZeroNegotiationContext, GenerationZeroNegotiationError, GenerationZeroNegotiator,
    },
};
use async_trait::async_trait;
use mrd_application::{
    ports::{SessionLifecycleState, SessionSnapshot},
    AuthenticatedSessionSignal, VerifiedSignalingEvent,
};
use mrd_ipc::{MediaProfileNegotiation, RemoteAuthorizationState, RemotePermissionScope};
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
}

impl ServiceWanMediaActivationPort {
    pub fn new(app_state: &Arc<crate::AppState>) -> Self {
        Self {
            app_state: Arc::downgrade(app_state),
        }
    }

    async fn activate(
        &self,
        authority: &WanMediaAuthority,
        sender: bool,
    ) -> Result<(), WanMediaActivationError> {
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        if let Some(profile) = authority.approved_profile() {
            let profile = ipc_media_profile(profile);
            app_state.media_profiles.lock().await.set(
                authority.session_id().clone(),
                MediaProfileNegotiation {
                    requested: profile.clone(),
                    selected: profile.clone(),
                    status: "accepted".to_owned(),
                    reason: None,
                    selected_source_id: None,
                    selected_width: Some(profile.width),
                    selected_height: Some(profile.height),
                    downgrade_reason: None,
                },
            );
            app_state
                .media_pipelines
                .lock()
                .await
                .set_active_media_profile(authority.session_id().clone(), &profile);
        }
        let mut sessions = app_state.sessions.lock().await;
        let previous = sessions.get(authority.session_id()).cloned();
        sessions.insert(
            authority.session_id().clone(),
            SessionSnapshot {
                session_id: authority.session_id().clone(),
                transport: "webrtc_relay".to_owned(),
                source_device_id: previous
                    .as_ref()
                    .and_then(|value| value.source_device_id.clone()),
                target_device_id: previous
                    .as_ref()
                    .and_then(|value| value.target_device_id.clone()),
                local_listen_addr: None,
                local_server_name: None,
                local_cert_der_b64: None,
                remote_listen_addr: None,
                remote_server_name: None,
                remote_cert_der_b64: None,
                lifecycle_state: SessionLifecycleState::Streaming,
                last_error: None,
                sender_active: sender,
                receiver_active: !sender,
            },
        );
        Ok(())
    }
}

#[async_trait]
impl WanMediaActivationPort for ServiceWanMediaActivationPort {
    async fn start_target_capture_send(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError> {
        if authority.role() != WanSessionRole::Target {
            return Err(WanMediaActivationError::StartupFailed);
        }
        self.activate(authority, true).await
    }

    async fn start_controller_receive_render(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError> {
        if authority.role() != WanSessionRole::Controller {
            return Err(WanMediaActivationError::StartupFailed);
        }
        self.activate(authority, false).await
    }

    async fn stop_media(&self, session_id: &SessionId) -> Result<(), WanMediaActivationError> {
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
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
    let _ = coordinator.shutdown_active_sessions().await;
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
        handle_controller_grant(
            &coordinator,
            event,
            &local_device_id,
            local_identity.as_ref(),
        )
        .await
    };
    if result.is_err() {
        // Verification failures are ignored rather than terminalizing a valid
        // session: an attacker cannot turn a malformed frame into a close.
        return;
    }
    if spawn_generation_zero(app_state, Arc::clone(&coordinator), backend, &session_id)
        .await
        .is_err()
    {
        let _ = coordinator
            .fail(&session_id, WanSessionFailure::RouteMismatch)
            .await;
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

async fn handle_controller_grant(
    coordinator: &WanSessionCoordinator,
    event: VerifiedSignalingEvent,
    local_device_id: &DeviceId,
    local_identity: &mrd_identity::DeviceIdentity,
) -> Result<(), ()> {
    let verified = VerifiedWanSessionGrant::verify_event(
        event,
        local_device_id,
        local_identity,
        now_unix_ms(),
    )
    .map_err(|_| ())?;
    let session_id = verified.session_id().clone();
    coordinator
        .install_controller_grant(&session_id, verified)
        .await
        .map_err(|_| ())?;
    Ok(())
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
                let still_live = task_coordinator
                    .snapshot(&owned_session_id)
                    .await
                    .is_ok_and(|state| !state.phase().is_terminal());
                if still_live {
                    let _ = task_coordinator
                        .fail(&owned_session_id, negotiation_failure(error))
                        .await;
                }
                return;
            }
            if let Ok(state) = task_coordinator.snapshot(&owned_session_id).await {
                let _ =
                    start_verified_media(task_coordinator.as_ref(), &state, media.as_ref()).await;
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
