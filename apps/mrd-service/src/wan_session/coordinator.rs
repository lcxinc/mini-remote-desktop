use super::{
    backend::{WanSessionApproval, WanSessionBinding, WanSessionStatus},
    model::{
        GrantBinding, RelayAccessBinding, RelayRouteProof, TransitionResult, WanSessionEvent,
        WanSessionFailure, WanSessionIdentity, WanSessionPhase, WanSessionRole, WanSessionState,
        WanSessionTransitionError,
    },
};
use async_trait::async_trait;
use mrd_application::{AuthenticatedSessionSignal, VerifiedSignalingEvent};
use mrd_identity::DeviceIdentity;
use mrd_proto::SessionId;
use mrd_signal_proto::{SignalReplayGuard, WanAccessModeV3, WanRoutePolicyV3, WanSessionRequestV3};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{watch, Mutex},
    task::JoinHandle,
};

const CLEANUP_STEP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WanSessionCoordinatorConfig {
    pub max_sessions: usize,
    pub max_terminal_sessions: usize,
    pub max_tasks_per_session: usize,
    pub max_buffered_events_per_session: usize,
    pub max_retries_per_session: usize,
}

impl WanSessionCoordinatorConfig {
    pub fn validate(self) -> Result<Self, WanSessionCoordinatorError> {
        if self.max_sessions == 0
            || self.max_tasks_per_session == 0
            || self.max_buffered_events_per_session == 0
            || self.max_terminal_sessions == 0
        {
            return Err(WanSessionCoordinatorError::InvalidConfiguration);
        }
        Ok(self)
    }
}

impl Default for WanSessionCoordinatorConfig {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            max_terminal_sessions: 1_024,
            max_tasks_per_session: 8,
            max_buffered_events_per_session: 64,
            max_retries_per_session: 2,
        }
    }
}

#[async_trait]
pub trait WanSessionCleanup: Send + Sync {
    async fn freeze_input(&self, session_id: &SessionId) -> Result<(), WanSessionCoordinatorError>;
    async fn stop_media(&self, session_id: &SessionId) -> Result<(), WanSessionCoordinatorError>;
    async fn close_transport(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError>;
    async fn remove_failover(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError>;
    async fn clear_signaling(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError>;
    async fn close_backend(
        &self,
        session_id: &SessionId,
        failed: bool,
    ) -> Result<(), WanSessionCoordinatorError>;
}

#[derive(Debug, Default)]
pub struct NoopWanSessionCleanup;

#[async_trait]
impl WanSessionCleanup for NoopWanSessionCleanup {
    async fn freeze_input(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn stop_media(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn close_transport(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn remove_failover(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn clear_signaling(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }

    async fn close_backend(
        &self,
        _: &SessionId,
        _: bool,
    ) -> Result<(), WanSessionCoordinatorError> {
        Ok(())
    }
}

pub struct WanSessionCoordinator {
    config: WanSessionCoordinatorConfig,
    cleanup: Arc<dyn WanSessionCleanup>,
    clock: Arc<dyn WanSessionClock>,
    workflow: Option<WanSessionWorkflowPorts>,
    registry: Mutex<Registry>,
}

impl std::fmt::Debug for WanSessionCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WanSessionCoordinator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Registry {
    sessions: HashMap<SessionId, Arc<SessionEntry>>,
    active_sessions: usize,
    terminal_order: VecDeque<SessionId>,
}

struct SessionEntry {
    state: Mutex<WanSessionState>,
    operation: Mutex<()>,
    cancellation: watch::Sender<bool>,
    task_group: Mutex<SessionTaskGroup>,
    budgets: Mutex<SessionBudgets>,
    finalized: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct SessionTaskGroup {
    closed: bool,
    handles: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct SessionBudgets {
    retries: usize,
    buffered_events: usize,
}

impl WanSessionCoordinator {
    pub fn new(
        config: WanSessionCoordinatorConfig,
        cleanup: Arc<dyn WanSessionCleanup>,
        clock: Arc<dyn WanSessionClock>,
    ) -> Result<Self, WanSessionCoordinatorError> {
        Ok(Self {
            config: config.validate()?,
            cleanup,
            clock,
            workflow: None,
            registry: Mutex::new(Registry::default()),
        })
    }

    pub fn with_workflow_ports(
        config: WanSessionCoordinatorConfig,
        cleanup: Arc<dyn WanSessionCleanup>,
        workflow: WanSessionWorkflowPorts,
    ) -> Result<Self, WanSessionCoordinatorError> {
        let clock = workflow.clock.clone();
        Ok(Self {
            config: config.validate()?,
            cleanup,
            clock,
            workflow: Some(workflow),
            registry: Mutex::new(Registry::default()),
        })
    }

    /// Controller-side initial workflow: create the authoritative backend request,
    /// bind its commitment, then enqueue the authenticated V3 intent.
    pub async fn start_controller(
        &self,
        identity: WanSessionIdentity,
        request: WanSessionRequestV3,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        validate_request_identity(&identity, &request)?;
        let workflow = self.workflow()?;
        let session_id = identity.session_id().clone();
        let deadline = identity.deadline_unix_ms();
        let begin = self
            .begin(WanSessionState::new(
                WanSessionRole::Controller,
                identity.clone(),
            ))
            .await?;
        let entry = self.entry(&session_id).await?;
        let _operation = entry.operation.lock().await;
        if begin == TransitionResult::Duplicate {
            let calculated = request
                .commitment()
                .map_err(|_| WanSessionCoordinatorError::BackendBindingMismatch)?;
            let matches =
                entry.state.lock().await.request_commitment() == Some(calculated.as_str());
            if matches {
                return Ok(begin);
            }
            let _ = self
                .apply(
                    &session_id,
                    WanSessionEvent::BackendBound {
                        request_commitment: calculated,
                    },
                    workflow.clock.now_unix_ms(),
                )
                .await;
            return Err(WanSessionCoordinatorError::SessionConflict);
        }

        let result = async {
            let snapshot = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.backend.create(&request, deadline),
            )
            .await
            .map_err(WanSessionCoordinatorError::Backend)?;
            snapshot.verify_requested(&identity, &request)?;
            self.apply(
                &session_id,
                WanSessionEvent::BackendBound {
                    request_commitment: snapshot.request_commitment().to_owned(),
                },
                workflow.clock.now_unix_ms(),
            )
            .await?;
            let intent_commitment = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.signaling.send_intent(
                    &identity,
                    &request,
                    snapshot.request_commitment(),
                    deadline,
                ),
            )
            .await
            .map_err(WanSessionCoordinatorError::Signaling)?;
            self.apply(
                &session_id,
                WanSessionEvent::AwaitingConsent { intent_commitment },
                workflow.clock.now_unix_ms(),
            )
            .await
        }
        .await;
        self.fail_workflow_if_needed(&session_id, result, workflow.clock.now_unix_ms())
            .await
    }

    /// Target-side initial workflow. The signed intent is checked against a fresh,
    /// independently fetched backend request before IPC consent is published.
    pub async fn accept_verified_target_intent(
        &self,
        verified: VerifiedWanSessionIntent,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        let VerifiedWanSessionIntent {
            identity,
            request,
            request_commitment,
            intent_commitment,
        } = verified;
        validate_request_identity(&identity, &request)?;
        let calculated = request
            .commitment()
            .map_err(|_| WanSessionCoordinatorError::BackendBindingMismatch)?;
        if calculated != request_commitment {
            return Err(WanSessionCoordinatorError::BackendBindingMismatch);
        }
        let workflow = self.workflow()?;
        let session_id = identity.session_id().clone();
        let deadline = identity.deadline_unix_ms();
        let begin = self
            .begin(WanSessionState::new(
                WanSessionRole::Target,
                identity.clone(),
            ))
            .await?;
        let entry = self.entry(&session_id).await?;
        let _operation = entry.operation.lock().await;
        if begin == TransitionResult::Duplicate {
            let matches =
                entry.state.lock().await.request_commitment() == Some(request_commitment.as_str());
            if matches {
                return Ok(begin);
            }
            let _ = self
                .apply(
                    &session_id,
                    WanSessionEvent::BackendBound {
                        request_commitment: request_commitment.clone(),
                    },
                    workflow.clock.now_unix_ms(),
                )
                .await;
            return Err(WanSessionCoordinatorError::SessionConflict);
        }

        let result = async {
            let snapshot = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.backend.inspect(identity.binding(), deadline),
            )
            .await
            .map_err(WanSessionCoordinatorError::Backend)?;
            snapshot.verify_requested(&identity, &request)?;
            if snapshot.request_commitment() != request_commitment {
                return Err(WanSessionCoordinatorError::BackendBindingMismatch);
            }
            self.apply(
                &session_id,
                WanSessionEvent::BackendBound {
                    request_commitment: snapshot.request_commitment().to_owned(),
                },
                workflow.clock.now_unix_ms(),
            )
            .await?;
            run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow
                    .consent
                    .publish_attended_request(&identity, &request, deadline),
            )
            .await
            .map_err(WanSessionCoordinatorError::Consent)?;
            self.apply(
                &session_id,
                WanSessionEvent::AwaitingConsent { intent_commitment },
                workflow.clock.now_unix_ms(),
            )
            .await
        }
        .await;
        self.fail_workflow_if_needed(&session_id, result, workflow.clock.now_unix_ms())
            .await
    }

    /// Target approval binds the backend's exact policy, acquires generation zero,
    /// and only then emits a grant. No transport or media is opened here.
    pub async fn approve_target(
        &self,
        session_id: &SessionId,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        let workflow = self.workflow()?;
        let entry = self.entry(session_id).await?;
        let _operation = entry.operation.lock().await;
        let state = self.snapshot(session_id).await?;
        if state.role() == WanSessionRole::Target && state.phase() == WanSessionPhase::AccessBound {
            return Ok(TransitionResult::Duplicate);
        }
        if state.role() != WanSessionRole::Target
            || state.phase() != WanSessionPhase::AwaitingConsent
        {
            return Err(WanSessionCoordinatorError::RoleOrPhaseMismatch);
        }
        let identity = state.identity().clone();
        let intent_commitment = state
            .intent_commitment()
            .ok_or(WanSessionCoordinatorError::BackendBindingMismatch)?
            .to_owned();
        let deadline = identity.deadline_unix_ms();
        let result = async {
            let approval = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.consent.load_attended_approval(&identity, deadline),
            )
            .await
            .map_err(WanSessionCoordinatorError::Consent)?;
            let snapshot = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow
                    .backend
                    .approve(identity.binding(), &approval, deadline),
            )
            .await
            .map_err(WanSessionCoordinatorError::Backend)?;
            let grant = snapshot.verify_approved(&identity)?.clone();
            if grant.approved_scopes() != approval.approved_scopes()
                || grant.approved_profile() != approval.approved_profile()
            {
                return Err(WanSessionCoordinatorError::BackendBindingMismatch);
            }
            let access = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.backend.access_generation_zero(
                    identity.binding(),
                    grant.policy_revision(),
                    deadline,
                ),
            )
            .await
            .map_err(WanSessionCoordinatorError::Backend)?;
            // The signaling adapter must sign and publish the grant before
            // this state becomes authoritative.  The returned commitment is
            // the exact bytes that peers will bind their WebRTC messages to;
            // a backend-only grant remains deliberately unbound.
            let signed_grant_commitment = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.signaling.send_grant_with_commitment(
                    &identity,
                    &intent_commitment,
                    &grant,
                    &access,
                    deadline,
                ),
            )
            .await
            .map_err(WanSessionCoordinatorError::Signaling)?;
            let grant = grant
                .with_grant_commitment(signed_grant_commitment)
                .map_err(|_| WanSessionCoordinatorError::BackendBindingMismatch)?;
            self.apply(
                session_id,
                WanSessionEvent::Granted(grant.clone()),
                workflow.clock.now_unix_ms(),
            )
            .await?;
            self.apply(
                session_id,
                WanSessionEvent::AccessBound(access.clone()),
                workflow.clock.now_unix_ms(),
            )
            .await?;
            Ok(TransitionResult::Applied)
        }
        .await;
        self.fail_workflow_if_needed(session_id, result, workflow.clock.now_unix_ms())
            .await
    }

    /// Controller installs a verified V3 grant only after independently inspecting
    /// the matching approved backend record, then obtains the same generation zero.
    pub async fn install_controller_grant(
        &self,
        session_id: &SessionId,
        verified: VerifiedWanSessionGrant,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        let workflow = self.workflow()?;
        let entry = self.entry(session_id).await?;
        let _operation = entry.operation.lock().await;
        let initial_state = self.snapshot(session_id).await?;
        let base_identity_matches = verified.session_id == *initial_state.identity().session_id()
            && verified.controller_device_id == *initial_state.identity().controller_device_id()
            && verified.target_device_id == *initial_state.identity().target_device_id()
            && verified.controller_key_fingerprint
                == initial_state.identity().controller_key_fingerprint()
            && verified.expires_at_ms <= initial_state.identity().deadline_unix_ms()
            && initial_state
                .identity()
                .target_key_fingerprint()
                .is_none_or(|fingerprint| fingerprint == verified.target_key_fingerprint);
        if !base_identity_matches {
            return Err(WanSessionCoordinatorError::VerifiedGrantRequired);
        }
        if initial_state.identity().target_key_fingerprint().is_none() {
            entry
                .state
                .lock()
                .await
                .bind_controller_target_key(&verified.target_key_fingerprint)
                .map_err(|_| WanSessionCoordinatorError::VerifiedGrantRequired)?;
        }
        let state = self.snapshot(session_id).await?;
        if state.identity().target_key_fingerprint()
            != Some(verified.target_key_fingerprint.as_str())
        {
            return Err(WanSessionCoordinatorError::VerifiedGrantRequired);
        }
        if state.role() == WanSessionRole::Controller
            && state.phase() == WanSessionPhase::AccessBound
            && state.intent_commitment() == Some(verified.intent_commitment.as_str())
            && state.grant().is_some_and(|grant| {
                grant.approved_scopes() == verified.approved_scopes
                    && grant.approved_profile() == verified.approved_profile.as_ref()
                    && grant.grant_commitment() == Some(verified.grant_commitment.as_str())
                    && grant.policy_revision() == verified.policy_revision
                    && grant.policy_expires_at_ms() == verified.policy_expires_at_ms
                    && grant.route_policy() == verified.route_policy
            })
            && state.access().is_some_and(|access| {
                access.generation() == verified.generation
                    && access.directory_id() == verified.directory_id
                    && access.primary_node_id() == verified.primary_node_id
            })
        {
            return Ok(TransitionResult::Duplicate);
        }
        if state.role() != WanSessionRole::Controller
            || state.phase() != WanSessionPhase::AwaitingConsent
        {
            return Err(WanSessionCoordinatorError::RoleOrPhaseMismatch);
        }
        if state.intent_commitment() != Some(verified.intent_commitment.as_str()) {
            let _ = self
                .apply(
                    session_id,
                    WanSessionEvent::AwaitingConsent {
                        intent_commitment: verified.intent_commitment,
                    },
                    workflow.clock.now_unix_ms(),
                )
                .await;
            return Err(WanSessionCoordinatorError::BackendBindingMismatch);
        }
        let identity = state.identity().clone();
        let deadline = identity.deadline_unix_ms();
        let result = async {
            let snapshot = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.backend.inspect(identity.binding(), deadline),
            )
            .await
            .map_err(WanSessionCoordinatorError::Backend)?;
            let backend_grant = snapshot.verify_approved(&identity)?;
            if backend_grant.approved_scopes() != verified.approved_scopes
                || backend_grant.approved_profile() != verified.approved_profile.as_ref()
                || backend_grant.policy_revision() != verified.policy_revision
                || backend_grant.policy_expires_at_ms() != verified.policy_expires_at_ms
                || backend_grant.route_policy() != verified.route_policy
                || verified.generation != 0
            {
                return Err(WanSessionCoordinatorError::BackendBindingMismatch);
            }
            let access = run_port_before_deadline(
                workflow.clock.as_ref(),
                deadline,
                workflow.backend.access_generation_zero(
                    identity.binding(),
                    backend_grant.policy_revision(),
                    deadline,
                ),
            )
            .await
            .map_err(WanSessionCoordinatorError::Backend)?;
            if access.generation() != verified.generation
                || access.directory_id() != verified.directory_id
                || access.primary_node_id() != verified.primary_node_id
            {
                return Err(WanSessionCoordinatorError::BackendBindingMismatch);
            }
            let backend_grant = backend_grant
                .clone()
                .with_grant_commitment(verified.grant_commitment.clone())
                .map_err(|_| WanSessionCoordinatorError::BackendBindingMismatch)?;
            self.apply(
                session_id,
                WanSessionEvent::Granted(backend_grant.clone()),
                workflow.clock.now_unix_ms(),
            )
            .await?;
            self.apply(
                session_id,
                WanSessionEvent::AccessBound(access),
                workflow.clock.now_unix_ms(),
            )
            .await
        }
        .await;
        self.fail_workflow_if_needed(session_id, result, workflow.clock.now_unix_ms())
            .await
    }

    pub async fn begin(
        &self,
        state: WanSessionState,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        if self.clock.now_unix_ms() >= state.identity().deadline_unix_ms() {
            return Err(WanSessionCoordinatorError::DeadlineExceeded);
        }
        let session_id = state.identity().session_id().clone();
        let mut registry = self.registry.lock().await;
        if let Some(existing) = registry.sessions.get(&session_id) {
            let existing = existing.state.lock().await;
            if existing.role() == state.role() && existing.identity() == state.identity() {
                return Ok(TransitionResult::Duplicate);
            }
            return Err(WanSessionCoordinatorError::SessionConflict);
        }
        if registry.active_sessions >= self.config.max_sessions {
            return Err(WanSessionCoordinatorError::CapacityExceeded);
        }
        let (cancellation, _) = watch::channel(false);
        registry.sessions.insert(
            session_id,
            Arc::new(SessionEntry {
                state: Mutex::new(state),
                operation: Mutex::new(()),
                cancellation,
                task_group: Mutex::new(SessionTaskGroup::default()),
                budgets: Mutex::new(SessionBudgets::default()),
                finalized: std::sync::atomic::AtomicBool::new(false),
            }),
        );
        registry.active_sessions += 1;
        Ok(TransitionResult::Applied)
    }

    pub async fn begin_negotiation(
        &self,
        session_id: &SessionId,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        self.apply_with_operation(session_id, WanSessionEvent::Negotiating)
            .await
    }

    /// Atomically install a verified generation-zero transport and advance
    /// the authoritative state.  The per-session operation lock remains held
    /// across the revalidation, installer call, and state transition so a
    /// concurrent close/fail cannot publish a stale media route.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_generation_zero<F, Fut>(
        &self,
        session_id: &SessionId,
        role: WanSessionRole,
        identity: &WanSessionIdentity,
        grant: &GrantBinding,
        access: &RelayAccessBinding,
        proof: RelayRouteProof,
        install: F,
    ) -> Result<TransitionResult, WanSessionCoordinatorError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<(), WanSessionCoordinatorError>> + Send,
    {
        let entry = self.entry(session_id).await?;
        let _operation = entry.operation.lock().await;
        let now = self.clock.now_unix_ms();
        {
            let state = entry.state.lock().await;
            if state.phase() != WanSessionPhase::Negotiating || state.role() != role {
                return Err(WanSessionCoordinatorError::RoleOrPhaseMismatch);
            }
            if now >= identity.deadline_unix_ms()
                || now >= grant.grant_expires_at_ms()
                || now >= grant.policy_expires_at_ms()
            {
                return Err(WanSessionCoordinatorError::DeadlineExceeded);
            }
            if grant.grant_commitment().is_none()
                || state.identity() != identity
                || state.grant() != Some(grant)
                || state.access() != Some(access)
                || !proof.is_relay_to_relay()
                || proof.access() != access
            {
                return Err(WanSessionCoordinatorError::BackendBindingMismatch);
            }
        }

        if install().await.is_err() {
            let failure = {
                let mut state = entry.state.lock().await;
                let transition = state.apply(
                    WanSessionEvent::Failed(WanSessionFailure::Transport),
                    self.clock.now_unix_ms(),
                );
                (transition, state.phase().is_terminal())
            };
            if failure.1 {
                self.finalize(
                    session_id,
                    &entry,
                    matches!(
                        failure.0,
                        Ok(TransitionResult::Applied | TransitionResult::Duplicate)
                    ),
                )
                .await?;
            }
            return Err(WanSessionCoordinatorError::CleanupFailed);
        }

        let (transition, terminal, failed, invalidated_error) = {
            let mut state = entry.state.lock().await;
            let now = self.clock.now_unix_ms();
            let deadline_invalidated = now >= identity.deadline_unix_ms()
                || now >= grant.grant_expires_at_ms()
                || now >= grant.policy_expires_at_ms();
            let binding_invalidated = state.phase() != WanSessionPhase::Negotiating
                || state.role() != role
                || grant.grant_commitment().is_none()
                || state.identity() != identity
                || state.grant() != Some(grant)
                || state.access() != Some(access);
            let invalidated = deadline_invalidated || binding_invalidated;
            let transition = if invalidated {
                state.apply(
                    WanSessionEvent::Failed(if deadline_invalidated {
                        WanSessionFailure::DeadlineExceeded
                    } else {
                        WanSessionFailure::RouteMismatch
                    }),
                    now,
                )
            } else {
                state.apply(WanSessionEvent::RelayVerified(proof), now)
            };
            (
                transition,
                state.phase().is_terminal(),
                state.phase() == WanSessionPhase::Failed,
                if deadline_invalidated {
                    Some(WanSessionCoordinatorError::DeadlineExceeded)
                } else if binding_invalidated {
                    Some(WanSessionCoordinatorError::BackendBindingMismatch)
                } else {
                    None
                },
            )
        };
        if terminal {
            self.finalize(session_id, &entry, failed).await?;
        }
        if let Some(error) = invalidated_error {
            // `WanSessionState::apply` deliberately rejects every event at
            // the exact deadline, while still recording the terminal failure.
            // Do not let that internal transition result turn an
            // invalidated install into a false successful commit.
            return Err(error);
        }
        transition.map_err(WanSessionCoordinatorError::Transition)
    }

    pub async fn record_streaming(
        &self,
        session_id: &SessionId,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        self.apply_with_operation(session_id, WanSessionEvent::Streaming)
            .await
    }

    pub async fn close(
        &self,
        session_id: &SessionId,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        self.apply_with_operation(session_id, WanSessionEvent::Closed)
            .await
    }

    pub async fn fail(
        &self,
        session_id: &SessionId,
        failure: WanSessionFailure,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        self.apply_with_operation(session_id, WanSessionEvent::Failed(failure))
            .await
    }

    /// Expire all sessions whose single absolute deadline has elapsed. The
    /// service heartbeat should call this even when no signaling arrives.
    pub async fn expire_due_sessions(&self) -> usize {
        let now = self.clock.now_unix_ms();
        let entries = self
            .registry
            .lock()
            .await
            .sessions
            .iter()
            .map(|(session_id, entry)| (session_id.clone(), Arc::clone(entry)))
            .collect::<Vec<_>>();
        let mut expired = 0;
        for (session_id, entry) in entries {
            let due = {
                let state = entry.state.lock().await;
                !state.phase().is_terminal() && now >= state.identity().deadline_unix_ms()
            };
            if due {
                let _ = self
                    .fail(&session_id, WanSessionFailure::DeadlineExceeded)
                    .await;
                expired += 1;
            }
        }
        expired
    }

    /// Fail and finalize every live session during service shutdown. Terminal
    /// entries remain immutable and are skipped.
    pub async fn shutdown_active_sessions(&self) -> usize {
        let entries = self
            .registry
            .lock()
            .await
            .sessions
            .iter()
            .map(|(session_id, entry)| (session_id.clone(), Arc::clone(entry)))
            .collect::<Vec<_>>();
        let mut closed = 0;
        for (session_id, entry) in entries {
            let live = !entry.state.lock().await.phase().is_terminal();
            if live {
                let _ = self.fail(&session_id, WanSessionFailure::Cancelled).await;
                closed += 1;
            }
        }
        closed
    }

    async fn apply_with_operation(
        &self,
        session_id: &SessionId,
        event: WanSessionEvent,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        let entry = self.entry(session_id).await?;
        let _operation = entry.operation.lock().await;
        self.apply(session_id, event, self.clock.now_unix_ms())
            .await
    }

    async fn apply(
        &self,
        session_id: &SessionId,
        event: WanSessionEvent,
        now_unix_ms: u64,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        let entry = self.entry(session_id).await?;
        let (transition, terminal, failed) = {
            let mut state = entry.state.lock().await;
            let transition = state.apply(event, now_unix_ms);
            (
                transition,
                state.phase().is_terminal(),
                state.phase() == WanSessionPhase::Failed,
            )
        };

        let cleanup_result = if terminal {
            self.finalize(session_id, &entry, failed).await
        } else {
            Ok(())
        };
        let transition = transition.map_err(WanSessionCoordinatorError::Transition)?;
        cleanup_result?;
        Ok(transition)
    }

    pub async fn snapshot(
        &self,
        session_id: &SessionId,
    ) -> Result<WanSessionState, WanSessionCoordinatorError> {
        let entry = self.entry(session_id).await?;
        let state = entry.state.lock().await.clone();
        Ok(state)
    }

    pub async fn spawn_owned_task<F, Fut>(
        &self,
        session_id: &SessionId,
        task: F,
    ) -> Result<(), WanSessionCoordinatorError>
    where
        F: FnOnce(WanSessionCancellation) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let entry = self.entry(session_id).await?;
        {
            let state = entry.state.lock().await;
            if state.phase().is_terminal()
                || self.clock.now_unix_ms() >= state.identity().deadline_unix_ms()
            {
                return Err(WanSessionCoordinatorError::SessionTerminal);
            }
        }
        let mut group = entry.task_group.lock().await;
        if group.closed {
            return Err(WanSessionCoordinatorError::SessionTerminal);
        }
        group.handles.retain(|handle| !handle.is_finished());
        if group.handles.len() >= self.config.max_tasks_per_session {
            return Err(WanSessionCoordinatorError::TaskCapacityExceeded);
        }
        let cancellation = WanSessionCancellation {
            receiver: entry.cancellation.subscribe(),
        };
        group.handles.push(tokio::spawn(task(cancellation)));
        Ok(())
    }

    pub async fn consume_retry(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        let entry = self
            .live_entry_before(session_id, self.clock.now_unix_ms())
            .await?;
        let mut budgets = entry.budgets.lock().await;
        if budgets.retries >= self.config.max_retries_per_session {
            return Err(WanSessionCoordinatorError::RetryBudgetExceeded);
        }
        budgets.retries += 1;
        Ok(())
    }

    pub async fn reserve_buffered_event(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        let entry = self
            .live_entry_before(session_id, self.clock.now_unix_ms())
            .await?;
        let mut budgets = entry.budgets.lock().await;
        if budgets.buffered_events >= self.config.max_buffered_events_per_session {
            return Err(WanSessionCoordinatorError::BufferCapacityExceeded);
        }
        budgets.buffered_events += 1;
        Ok(())
    }

    pub async fn release_buffered_event(
        &self,
        session_id: &SessionId,
    ) -> Result<(), WanSessionCoordinatorError> {
        let entry = self.entry(session_id).await?;
        let mut budgets = entry.budgets.lock().await;
        budgets.buffered_events = budgets.buffered_events.saturating_sub(1);
        Ok(())
    }

    fn workflow(&self) -> Result<&WanSessionWorkflowPorts, WanSessionCoordinatorError> {
        self.workflow
            .as_ref()
            .ok_or(WanSessionCoordinatorError::WorkflowUnavailable)
    }

    async fn fail_workflow_if_needed(
        &self,
        session_id: &SessionId,
        result: Result<TransitionResult, WanSessionCoordinatorError>,
        now_unix_ms: u64,
    ) -> Result<TransitionResult, WanSessionCoordinatorError> {
        if result.is_ok() {
            return result;
        }
        let failure = match result.as_ref().err() {
            Some(WanSessionCoordinatorError::DeadlineExceeded)
            | Some(WanSessionCoordinatorError::Backend(WanSessionPortError::DeadlineExceeded))
            | Some(WanSessionCoordinatorError::Signaling(WanSessionPortError::DeadlineExceeded))
            | Some(WanSessionCoordinatorError::Consent(WanSessionPortError::DeadlineExceeded)) => {
                WanSessionFailure::DeadlineExceeded
            }
            Some(WanSessionCoordinatorError::Consent(WanSessionPortError::Rejected)) => {
                WanSessionFailure::Cancelled
            }
            _ => WanSessionFailure::Internal,
        };
        if self
            .snapshot(session_id)
            .await
            .is_ok_and(|state| !state.phase().is_terminal())
        {
            let _ = self
                .apply(session_id, WanSessionEvent::Failed(failure), now_unix_ms)
                .await;
        }
        result
    }

    async fn live_entry_before(
        &self,
        session_id: &SessionId,
        now_unix_ms: u64,
    ) -> Result<Arc<SessionEntry>, WanSessionCoordinatorError> {
        let entry = self.entry(session_id).await?;
        let state = entry.state.lock().await;
        if state.phase().is_terminal() {
            return Err(WanSessionCoordinatorError::SessionTerminal);
        }
        if now_unix_ms >= state.identity().deadline_unix_ms() {
            return Err(WanSessionCoordinatorError::DeadlineExceeded);
        }
        drop(state);
        Ok(entry)
    }

    async fn entry(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<SessionEntry>, WanSessionCoordinatorError> {
        self.registry
            .lock()
            .await
            .sessions
            .get(session_id)
            .cloned()
            .ok_or(WanSessionCoordinatorError::SessionNotFound)
    }

    async fn finalize(
        &self,
        session_id: &SessionId,
        entry: &Arc<SessionEntry>,
        failed: bool,
    ) -> Result<(), WanSessionCoordinatorError> {
        use std::sync::atomic::Ordering;
        if entry.finalized.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let handles = {
            let mut group = entry.task_group.lock().await;
            group.closed = true;
            let _ = entry.cancellation.send(true);
            std::mem::take(&mut group.handles)
        };

        let mut first_error = None;
        for result in [
            bounded_cleanup(self.cleanup.freeze_input(session_id)).await,
            bounded_cleanup(self.cleanup.stop_media(session_id)).await,
            bounded_cleanup(self.cleanup.close_transport(session_id)).await,
            bounded_cleanup(self.cleanup.remove_failover(session_id)).await,
            bounded_cleanup(self.cleanup.clear_signaling(session_id)).await,
            bounded_cleanup(self.cleanup.close_backend(session_id, failed)).await,
        ] {
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        let current_task_id = tokio::task::try_id();
        for mut handle in handles {
            // A task is allowed to report its own terminal failure. Joining
            // its JoinHandle here would wait for the current future to return
            // from this very finalize call. Dropping that one handle detaches
            // it for the few instructions needed to return; all sibling tasks
            // remain cancellation-owned and joined below.
            if current_task_id.is_some_and(|task_id| task_id == handle.id()) {
                continue;
            }
            match tokio::time::timeout(CLEANUP_STEP_TIMEOUT, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) if first_error.is_none() => {
                    first_error = Some(WanSessionCoordinatorError::TaskJoinFailed);
                }
                Err(_) if first_error.is_none() => {
                    handle.abort();
                    let _ = handle.await;
                    first_error = Some(WanSessionCoordinatorError::CleanupTimeout);
                }
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                }
                _ => {}
            }
        }

        let mut registry = self.registry.lock().await;
        registry.active_sessions = registry.active_sessions.saturating_sub(1);
        registry.terminal_order.push_back(session_id.clone());
        while registry.terminal_order.len() > self.config.max_terminal_sessions {
            if let Some(expired) = registry.terminal_order.pop_front() {
                registry.sessions.remove(&expired);
            }
        }
        drop(registry);
        first_error.map_or(Ok(()), Err)
    }
}

async fn bounded_cleanup<F>(future: F) -> Result<(), WanSessionCoordinatorError>
where
    F: Future<Output = Result<(), WanSessionCoordinatorError>>,
{
    tokio::time::timeout(CLEANUP_STEP_TIMEOUT, future)
        .await
        .map_err(|_| WanSessionCoordinatorError::CleanupTimeout)?
}

async fn run_port_before_deadline<T, F>(
    clock: &dyn WanSessionClock,
    absolute_deadline_unix_ms: u64,
    future: F,
) -> Result<T, WanSessionPortError>
where
    F: Future<Output = Result<T, WanSessionPortError>>,
{
    let remaining_ms = absolute_deadline_unix_ms.saturating_sub(clock.now_unix_ms());
    if remaining_ms == 0 {
        return Err(WanSessionPortError::DeadlineExceeded);
    }
    tokio::time::timeout(Duration::from_millis(remaining_ms), future)
        .await
        .map_err(|_| WanSessionPortError::DeadlineExceeded)?
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedWanSessionIntent {
    identity: WanSessionIdentity,
    request: WanSessionRequestV3,
    request_commitment: String,
    intent_commitment: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedWanSessionGrant {
    session_id: SessionId,
    controller_device_id: mrd_proto::DeviceId,
    target_device_id: mrd_proto::DeviceId,
    target_key_fingerprint: String,
    target_public_key: [u8; 32],
    controller_key_fingerprint: String,
    intent_commitment: String,
    grant_commitment: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    approved_scopes: Vec<mrd_signal_proto::WanPermissionScopeV3>,
    approved_profile: Option<mrd_signal_proto::WanMediaProfileV3>,
    policy_revision: u64,
    policy_expires_at_ms: u64,
    generation: u64,
    directory_id: String,
    primary_node_id: String,
    route_policy: WanRoutePolicyV3,
}

impl std::fmt::Debug for VerifiedWanSessionGrant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedWanSessionGrant")
            .field("session_id", &self.session_id)
            .field("controller_device_id", &self.controller_device_id)
            .field("target_device_id", &self.target_device_id)
            .field("body", &"REDACTED")
            .finish()
    }
}

impl VerifiedWanSessionGrant {
    pub fn verify_event(
        event: VerifiedSignalingEvent,
        local_controller_device_id: &mrd_proto::DeviceId,
        local_controller_identity: &DeviceIdentity,
        now_unix_ms: u64,
    ) -> Result<Self, WanSessionCoordinatorError> {
        let AuthenticatedSessionSignal::SessionGrantV3 { message } = event.signal else {
            return Err(WanSessionCoordinatorError::VerifiedGrantRequired);
        };
        let claims = &message.payload.claims;
        let mut replay = SignalReplayGuard::new(1, 1);
        message
            .verify_for(local_controller_device_id, now_unix_ms, &mut replay)
            .map_err(|_| WanSessionCoordinatorError::VerifiedGrantRequired)?;
        if event.sender.device_id != message.payload.target_device_id
            || event.sender.device_id != claims.issuer_device_id
            || event.sender.key_id != claims.issuer_key_id
            || event.sender.public_key != message.signer_public_key
            || event.sender.counter != claims.counter
            || event.sender.nonce != claims.nonce
            || event.sender.issued_at_ms != claims.issued_at_ms
            || event.sender.expires_at_ms != claims.expires_at_ms
            || &message.payload.controller_device_id != local_controller_device_id
            || claims.intended_peer_device_id != message.payload.controller_device_id
        {
            return Err(WanSessionCoordinatorError::VerifiedGrantRequired);
        }
        let target_public_key: [u8; 32] = event
            .sender
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| WanSessionCoordinatorError::VerifiedGrantRequired)?;
        let grant_commitment = message
            .commitment()
            .map_err(|_| WanSessionCoordinatorError::VerifiedGrantRequired)?;
        let issued_at_ms = claims.issued_at_ms;
        let expires_at_ms = claims.expires_at_ms;
        let payload = message.payload;
        if payload.policy_expires_at_ms > expires_at_ms {
            return Err(WanSessionCoordinatorError::VerifiedGrantRequired);
        }
        Ok(Self {
            session_id: payload.session_id,
            controller_device_id: payload.controller_device_id,
            target_device_id: payload.target_device_id,
            target_key_fingerprint: event.sender.key_id,
            target_public_key,
            controller_key_fingerprint: local_controller_identity.key_id().to_owned(),
            intent_commitment: payload.intent_commitment,
            grant_commitment,
            issued_at_ms,
            expires_at_ms,
            approved_scopes: payload.approved_scopes,
            approved_profile: payload.approved_profile,
            policy_revision: payload.backend_policy_revision,
            policy_expires_at_ms: payload.policy_expires_at_ms,
            generation: payload.relay_generation,
            directory_id: payload.relay_directory_id,
            primary_node_id: payload.primary_relay_node_id,
            route_policy: payload.route_policy,
        })
    }
}

impl std::fmt::Debug for VerifiedWanSessionIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedWanSessionIntent")
            .field("identity", &self.identity)
            .field("request", &"REDACTED")
            .field("request_commitment", &self.request_commitment)
            .field("intent_commitment", &self.intent_commitment)
            .finish()
    }
}

impl VerifiedWanSessionGrant {
    pub fn grant_commitment(&self) -> &str {
        &self.grant_commitment
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn target_device_id(&self) -> &mrd_proto::DeviceId {
        &self.target_device_id
    }

    pub fn target_key_fingerprint(&self) -> &str {
        &self.target_key_fingerprint
    }

    pub fn target_public_key(&self) -> &[u8; 32] {
        &self.target_public_key
    }

    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl VerifiedWanSessionIntent {
    /// Narrow a runtime-verified V3 event into the only value accepted by the
    /// target workflow. Metadata and signed claims must agree exactly.
    pub fn verify_event(
        event: VerifiedSignalingEvent,
        local_target_device_id: &mrd_proto::DeviceId,
        local_target_identity: &DeviceIdentity,
        now_unix_ms: u64,
    ) -> Result<Self, WanSessionCoordinatorError> {
        let AuthenticatedSessionSignal::SessionIntentV3 { message } = event.signal else {
            return Err(WanSessionCoordinatorError::VerifiedIntentRequired);
        };
        let claims = &message.payload.claims;
        let request = &message.payload.request;
        let mut replay = SignalReplayGuard::new(1, 1);
        message
            .verify_for(local_target_device_id, now_unix_ms, &mut replay)
            .map_err(|_| WanSessionCoordinatorError::VerifiedIntentRequired)?;
        if event.sender.device_id != request.controller_device_id
            || event.sender.device_id != claims.issuer_device_id
            || event.sender.key_id != claims.issuer_key_id
            || event.sender.public_key != message.signer_public_key
            || event.sender.counter != claims.counter
            || event.sender.nonce != claims.nonce
            || event.sender.issued_at_ms != claims.issued_at_ms
            || event.sender.expires_at_ms != claims.expires_at_ms
            || claims.intended_peer_device_id != request.target_device_id
            || &request.target_device_id != local_target_device_id
        {
            return Err(WanSessionCoordinatorError::VerifiedIntentRequired);
        }
        let identity = WanSessionIdentity::new(
            request.session_id.clone(),
            request.controller_device_id.clone(),
            request.target_device_id.clone(),
            event.sender.key_id,
            local_target_identity.key_id().to_owned(),
            claims.expires_at_ms,
        )
        .map_err(|_| WanSessionCoordinatorError::VerifiedIntentRequired)?;
        let intent_commitment = message
            .commitment()
            .map_err(|_| WanSessionCoordinatorError::VerifiedIntentRequired)?;
        let request_commitment = message.payload.request_commitment.clone();
        let request = message.payload.request;
        if request
            .commitment()
            .map_err(|_| WanSessionCoordinatorError::VerifiedIntentRequired)?
            != request_commitment
        {
            return Err(WanSessionCoordinatorError::VerifiedIntentRequired);
        }
        Ok(Self {
            identity,
            request,
            request_commitment,
            intent_commitment,
        })
    }

    pub fn identity(&self) -> &WanSessionIdentity {
        &self.identity
    }

    pub fn request(&self) -> &WanSessionRequestV3 {
        &self.request
    }

    pub fn request_commitment(&self) -> &str {
        &self.request_commitment
    }

    pub fn intent_commitment(&self) -> &str {
        &self.intent_commitment
    }
}

#[derive(Clone)]
pub struct WanSessionWorkflowPorts {
    backend: Arc<dyn WanSessionWorkflowBackend>,
    signaling: Arc<dyn WanSessionWorkflowSignaling>,
    consent: Arc<dyn WanSessionConsentPublisher>,
    clock: Arc<dyn WanSessionClock>,
}

impl std::fmt::Debug for WanSessionWorkflowPorts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WanSessionWorkflowPorts")
            .finish_non_exhaustive()
    }
}

impl WanSessionWorkflowPorts {
    pub fn new(
        backend: Arc<dyn WanSessionWorkflowBackend>,
        signaling: Arc<dyn WanSessionWorkflowSignaling>,
        consent: Arc<dyn WanSessionConsentPublisher>,
        clock: Arc<dyn WanSessionClock>,
    ) -> Self {
        Self {
            backend,
            signaling,
            consent,
            clock,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WanBackendSessionSnapshot {
    request: WanSessionRequestV3,
    request_commitment: String,
    status: WanSessionStatus,
    grant: Option<GrantBinding>,
}

impl std::fmt::Debug for WanBackendSessionSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WanBackendSessionSnapshot")
            .field("session_id", &self.request.session_id)
            .field("controller_device_id", &self.request.controller_device_id)
            .field("target_device_id", &self.request.target_device_id)
            .field("request", &"REDACTED")
            .field("request_commitment", &self.request_commitment)
            .field("status", &self.status)
            .field("grant", &self.grant.as_ref().map(|_| "SET"))
            .finish()
    }
}

impl WanBackendSessionSnapshot {
    pub fn requested(
        request: WanSessionRequestV3,
        request_commitment: String,
    ) -> Result<Self, WanSessionCoordinatorError> {
        Self::new(
            request,
            request_commitment,
            WanSessionStatus::Requested,
            None,
        )
    }

    pub fn approved(
        request: WanSessionRequestV3,
        request_commitment: String,
        grant: GrantBinding,
    ) -> Result<Self, WanSessionCoordinatorError> {
        Self::new(
            request,
            request_commitment,
            WanSessionStatus::Approved,
            Some(grant),
        )
    }

    fn new(
        request: WanSessionRequestV3,
        request_commitment: String,
        status: WanSessionStatus,
        grant: Option<GrantBinding>,
    ) -> Result<Self, WanSessionCoordinatorError> {
        let calculated = request
            .commitment()
            .map_err(|_| WanSessionCoordinatorError::BackendBindingMismatch)?;
        if calculated != request_commitment
            || matches!(status, WanSessionStatus::Requested) && grant.is_some()
            || matches!(status, WanSessionStatus::Approved) && grant.is_none()
            || grant
                .as_ref()
                .is_some_and(|grant| grant.request_commitment() != request_commitment)
            || grant.as_ref().is_some_and(|grant| {
                grant
                    .approved_scopes()
                    .iter()
                    .any(|scope| !request.requested_scopes.contains(scope))
                    || !approved_profile_within(
                        grant.approved_profile(),
                        request.requested_profile.as_ref(),
                    )
            })
        {
            return Err(WanSessionCoordinatorError::BackendBindingMismatch);
        }
        Ok(Self {
            request,
            request_commitment,
            status,
            grant,
        })
    }

    pub fn request(&self) -> &WanSessionRequestV3 {
        &self.request
    }

    pub fn request_commitment(&self) -> &str {
        &self.request_commitment
    }

    pub fn status(&self) -> WanSessionStatus {
        self.status
    }

    pub fn grant(&self) -> Option<&GrantBinding> {
        self.grant.as_ref()
    }

    fn verify_requested(
        &self,
        identity: &WanSessionIdentity,
        request: &WanSessionRequestV3,
    ) -> Result<(), WanSessionCoordinatorError> {
        if self.status != WanSessionStatus::Requested
            || &self.request != request
            || !request_matches_identity(identity, request)
        {
            return Err(WanSessionCoordinatorError::BackendBindingMismatch);
        }
        Ok(())
    }

    fn verify_approved(
        &self,
        identity: &WanSessionIdentity,
    ) -> Result<&GrantBinding, WanSessionCoordinatorError> {
        if self.status != WanSessionStatus::Approved
            || !request_matches_identity(identity, &self.request)
        {
            return Err(WanSessionCoordinatorError::BackendBindingMismatch);
        }
        self.grant
            .as_ref()
            .ok_or(WanSessionCoordinatorError::BackendBindingMismatch)
    }
}

#[async_trait]
pub trait WanSessionWorkflowBackend: Send + Sync {
    async fn create(
        &self,
        request: &WanSessionRequestV3,
        absolute_deadline_unix_ms: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError>;
    async fn inspect(
        &self,
        binding: &WanSessionBinding,
        absolute_deadline_unix_ms: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError>;
    async fn approve(
        &self,
        binding: &WanSessionBinding,
        approval: &WanSessionApproval,
        absolute_deadline_unix_ms: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError>;
    async fn access_generation_zero(
        &self,
        binding: &WanSessionBinding,
        policy_revision: u64,
        absolute_deadline_unix_ms: u64,
    ) -> Result<RelayAccessBinding, WanSessionPortError>;
}

#[async_trait]
pub trait WanSessionWorkflowSignaling: Send + Sync {
    async fn send_intent(
        &self,
        identity: &WanSessionIdentity,
        request: &WanSessionRequestV3,
        request_commitment: &str,
        absolute_deadline_unix_ms: u64,
    ) -> Result<String, WanSessionPortError>;
    /// Sign and publish a grant, returning the exact commitment of the
    /// signed message. Implementations must not report success without it.
    async fn send_grant_with_commitment(
        &self,
        identity: &WanSessionIdentity,
        intent_commitment: &str,
        grant: &GrantBinding,
        access: &RelayAccessBinding,
        absolute_deadline_unix_ms: u64,
    ) -> Result<String, WanSessionPortError>;
}

#[async_trait]
pub trait WanSessionConsentPublisher: Send + Sync {
    async fn publish_attended_request(
        &self,
        identity: &WanSessionIdentity,
        request: &WanSessionRequestV3,
        absolute_deadline_unix_ms: u64,
    ) -> Result<(), WanSessionPortError>;
    async fn load_attended_approval(
        &self,
        identity: &WanSessionIdentity,
        absolute_deadline_unix_ms: u64,
    ) -> Result<WanSessionApproval, WanSessionPortError>;
}

pub trait WanSessionClock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemWanSessionClock;

impl WanSessionClock for SystemWanSessionClock {
    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WanSessionPortError {
    #[error("WAN session port is unavailable")]
    Unavailable,
    #[error("WAN session port rejected the operation")]
    Rejected,
    #[error("WAN session port deadline exceeded")]
    DeadlineExceeded,
}

fn validate_request_identity(
    identity: &WanSessionIdentity,
    request: &WanSessionRequestV3,
) -> Result<(), WanSessionCoordinatorError> {
    request
        .validate()
        .map_err(|_| WanSessionCoordinatorError::BackendBindingMismatch)?;
    if request.access_mode != WanAccessModeV3::Attended
        || request.route_policy != WanRoutePolicyV3::RelayOnly
        || !request_matches_identity(identity, request)
    {
        return Err(WanSessionCoordinatorError::BackendBindingMismatch);
    }
    Ok(())
}

fn request_matches_identity(identity: &WanSessionIdentity, request: &WanSessionRequestV3) -> bool {
    request.session_id == *identity.session_id()
        && request.controller_device_id == *identity.controller_device_id()
        && request.target_device_id == *identity.target_device_id()
}

fn approved_profile_within(
    approved: Option<&mrd_signal_proto::WanMediaProfileV3>,
    requested: Option<&mrd_signal_proto::WanMediaProfileV3>,
) -> bool {
    match (approved, requested) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(approved), Some(requested)) => {
            approved.width <= requested.width
                && approved.height <= requested.height
                && approved.fps <= requested.fps
                && approved.bitrate_mbps <= requested.bitrate_mbps
                && approved.codec == requested.codec
                && approved.codec_profile == requested.codec_profile
                && approved.bit_depth == requested.bit_depth
                && approved.chroma_subsampling == requested.chroma_subsampling
                && approved.pixel_format == requested.pixel_format
                && approved.hdr_enabled == requested.hdr_enabled
                && approved.color_mode == requested.color_mode
                && approved.color_pipeline == requested.color_pipeline
        }
    }
}

pub struct WanSessionCancellation {
    receiver: watch::Receiver<bool>,
}

impl WanSessionCancellation {
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    pub async fn cancelled(&mut self) {
        while !*self.receiver.borrow() {
            if self.receiver.changed().await.is_err() {
                break;
            }
        }
    }

    pub(crate) fn into_receiver(self) -> watch::Receiver<bool> {
        self.receiver
    }
}

#[derive(Debug, Error)]
pub enum WanSessionCoordinatorError {
    #[error("invalid WAN session coordinator configuration")]
    InvalidConfiguration,
    #[error("WAN session was not found")]
    SessionNotFound,
    #[error("WAN session identity conflicts with an existing session")]
    SessionConflict,
    #[error("WAN session capacity exceeded")]
    CapacityExceeded,
    #[error("WAN session task capacity exceeded")]
    TaskCapacityExceeded,
    #[error("WAN session event buffer capacity exceeded")]
    BufferCapacityExceeded,
    #[error("WAN session retry budget exceeded")]
    RetryBudgetExceeded,
    #[error("WAN session deadline exceeded")]
    DeadlineExceeded,
    #[error("WAN session is terminal")]
    SessionTerminal,
    #[error("WAN session workflow ports are not configured")]
    WorkflowUnavailable,
    #[error("WAN session role or phase does not permit this operation")]
    RoleOrPhaseMismatch,
    #[error("WAN session backend binding mismatch")]
    BackendBindingMismatch,
    #[error("WAN session backend operation failed")]
    Backend(#[source] WanSessionPortError),
    #[error("WAN session signaling operation failed")]
    Signaling(#[source] WanSessionPortError),
    #[error("WAN session consent publication failed")]
    Consent(#[source] WanSessionPortError),
    #[error("runtime-verified WAN session intent required")]
    VerifiedIntentRequired,
    #[error("runtime-verified WAN session grant required")]
    VerifiedGrantRequired,
    #[error("WAN session transition failed")]
    Transition(#[source] WanSessionTransitionError),
    #[error("WAN session owned task failed to join")]
    TaskJoinFailed,
    #[error("WAN session cleanup failed")]
    CleanupFailed,
    #[error("WAN session cleanup deadline exceeded")]
    CleanupTimeout,
}

impl From<WanSessionFailure> for WanSessionCoordinatorError {
    fn from(failure: WanSessionFailure) -> Self {
        match failure {
            WanSessionFailure::CapacityExceeded => Self::CapacityExceeded,
            WanSessionFailure::RetryBudgetExceeded => Self::RetryBudgetExceeded,
            WanSessionFailure::BufferCapacityExceeded => Self::BufferCapacityExceeded,
            WanSessionFailure::DeadlineExceeded => Self::DeadlineExceeded,
            _ => Self::CleanupFailed,
        }
    }
}
