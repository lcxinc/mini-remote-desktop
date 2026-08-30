//! Agent-local consent authority state.
//!
//! Binding and registry types are deliberately crate-private. External callers
//! can supply only the display-safe [`ConsentBackend`] boundary:
//!
//! ```compile_fail
//! use mrd_session_agent::consent::TrustedSessionBinding;
//! ```
//!
//! ```compile_fail
//! use mrd_session_agent::consent::TrustedSessionBindingSource;
//! ```
//!
//! ```compile_fail
//! use mrd_session_agent::consent::ConsentAuthorityRegistry;
//! ```
use mrd_agent_ipc::{
    CancelConsent, ConsentDecision, ConsentRequest, ConsentResult, DesktopKind, PeerBinding,
    AGENT_CONSENT_MAX_LIFETIME_MS, AGENT_IPC_MAX_IDENTIFIER_BYTES,
};
use mrd_proto::SessionId;
use mrd_session::PermissionScopes;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::Instant,
};

/// Maximum simultaneously live consent-derived session bindings.
pub const MAX_ACTIVE_BINDINGS: usize = 64;
/// Maximum prompts that may be awaiting a local decision.
pub const MAX_PENDING_CONSENTS: usize = 32;
/// Maximum completed/cancelled consent identities retained against replay.
pub const MAX_CONSENT_TOMBSTONES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedSessionBinding {
    pub(crate) authority_generation: u64,
    pub(crate) consent_request_id: [u8; 16],
    pub(crate) registration_id: [u8; 16],
    pub(crate) registration_epoch: u64,
    pub(crate) session_id: SessionId,
    pub(crate) peer: PeerBinding,
    pub(crate) approved_scopes: PermissionScopes,
    pub(crate) policy_revision: u64,
    pub(crate) windows_session_id: u32,
    pub(crate) desktop_epoch: u64,
    pub(crate) desktop_kind: DesktopKind,
    pub(crate) authorization_expires_at_ms: u64,
    pub(crate) authorization_deadline: Instant,
    pub(crate) expected_issuer_key_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorityInvalidation {
    pub(crate) session_id: SessionId,
    pub(crate) authority_generation: u64,
    pub(crate) consent_request_id: [u8; 16],
}

impl From<&TrustedSessionBinding> for AuthorityInvalidation {
    fn from(binding: &TrustedSessionBinding) -> Self {
        Self {
            session_id: binding.session_id.clone(),
            authority_generation: binding.authority_generation,
            consent_request_id: binding.consent_request_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedConsentContext {
    pub(crate) registration_id: [u8; 16],
    pub(crate) registration_epoch: u64,
    pub(crate) windows_session_id: u32,
    pub(crate) desktop_epoch: u64,
    pub(crate) desktop_kind: DesktopKind,
    pub(crate) expected_issuer_key_id: [u8; 32],
    pub(crate) now_ms: u64,
}

impl TrustedConsentContext {
    fn is_valid_for(&self, request: &ConsentRequest) -> bool {
        self.registration_id.iter().any(|byte| *byte != 0)
            && self.registration_epoch != 0
            && self.windows_session_id == request.windows_session_id
            && self.desktop_epoch != 0
            && self.desktop_kind == DesktopKind::Default
            && self.expected_issuer_key_id.iter().any(|byte| *byte != 0)
    }

    fn same_authority(&self, other: &Self) -> bool {
        self.registration_id == other.registration_id
            && self.registration_epoch == other.registration_epoch
            && self.windows_session_id == other.windows_session_id
            && self.desktop_epoch == other.desktop_epoch
            && self.desktop_kind == other.desktop_kind
            && self.expected_issuer_key_id == other.expected_issuer_key_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConsentFingerprint {
    session_id: SessionId,
    peer: PeerBinding,
    requested_scopes: PermissionScopes,
    policy_revision: u64,
    windows_session_id: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
    authorization_expires_at_ms: u64,
}

impl From<&ConsentRequest> for ConsentFingerprint {
    fn from(request: &ConsentRequest) -> Self {
        Self {
            session_id: request.session_id.clone(),
            peer: request.peer.clone(),
            requested_scopes: request.requested_scopes.clone(),
            policy_revision: request.policy_revision,
            windows_session_id: request.windows_session_id,
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            authorization_expires_at_ms: request.authorization_expires_at_ms,
        }
    }
}

/// Read-only display data passed to the local consent surface.
///
/// Registration, desktop, issuer, policy, and timestamp authority deliberately
/// remain inside the runtime and are not representable through this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPrompt {
    session_id: SessionId,
    peer: PeerBinding,
    requested_scopes: PermissionScopes,
}

impl ConsentPrompt {
    #[cfg(all(test, windows))]
    pub(crate) fn for_native_test(
        session_id: SessionId,
        peer: PeerBinding,
        requested_scopes: PermissionScopes,
    ) -> Self {
        Self {
            session_id,
            peer,
            requested_scopes,
        }
    }

    pub(crate) fn into_display_parts(self) -> (SessionId, PeerBinding, PermissionScopes) {
        (self.session_id, self.peer, self.requested_scopes)
    }

    /// Product session requesting attended consent.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Authenticated remote peer rendered by the consent surface.
    pub fn peer(&self) -> &PeerBinding {
        &self.peer
    }

    /// Requested scopes from which an approval may select a subset.
    pub fn requested_scopes(&self) -> &PermissionScopes {
        &self.requested_scopes
    }
}

/// Terminal decision returned only after the local consent surface has closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentBackendDecision {
    /// The user approved the returned non-empty subset of requested scopes.
    Approved(PermissionScopes),
    /// The user explicitly denied the request.
    Denied,
    /// The surface closed without an explicit approval or denial.
    Dismissed,
    /// The surface observed a runtime abort and has finished closing.
    Cancelled,
}

/// Trusted runtime reason delivered to an already-visible consent surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentAbortReason {
    /// The service withdrew this exact delivered request.
    Service(mrd_agent_ipc::ConsentCancelReason),
    /// The trusted interactive desktop no longer matches this prompt.
    DesktopChanged,
    /// The monotonic prompt deadline elapsed.
    PromptExpired,
    /// The agent is stopping and will not wait for the surface to close.
    RuntimeStopping,
    /// The authenticated service connection disappeared.
    ServiceDisconnected,
}

/// Heap-owned asynchronous consent operation returned by a backend.
pub type ConsentBackendFuture =
    Pin<Box<dyn Future<Output = ConsentBackendDecision> + Send + 'static>>;

/// Native attended-consent boundary.
///
/// The backend receives display-only prompt data and an abort watch. It cannot
/// provide or override any trusted authorization context.
pub trait ConsentBackend: Send + Sync {
    /// Return an O(1), wait-free, panic-free availability snapshot.
    ///
    /// Implementations must not perform I/O, acquire contended locks, or wait
    /// for a UI thread. The runtime still catches a contract-violating panic
    /// and treats the backend as unavailable when publishing capabilities.
    fn is_available(&self) -> bool;

    /// Immediately construct a cancellation-safe asynchronous prompt handle.
    ///
    /// This method must not display UI, perform I/O, or block. All UI work must
    /// begin when the returned future is polled. Dropping that future must
    /// cancel any work and close its surface without leaving helper threads.
    /// The future resolves only after its surface has closed.
    fn prompt(
        &self,
        prompt: ConsentPrompt,
        abort: watch::Receiver<Option<ConsentAbortReason>>,
    ) -> ConsentBackendFuture;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingConsentPrompt {
    pub(crate) attempt_id: u64,
    pub(crate) request: ConsentRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConsentBeginOutcome {
    Prompt(PendingConsentPrompt),
    Cached(ConsentResult),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentCompletionRejection {
    InvalidLocalContext,
    PromptExpired,
    ScopeEscalation,
    UnexpectedApprovedScopes,
    BindingCapacityExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentCompletionDisposition {
    Approved,
    NonApproved,
    Rejected(ConsentCompletionRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsentCompletion {
    pub(crate) result: ConsentResult,
    pub(crate) binding_changed: bool,
    pub(crate) disposition: ConsentCompletionDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreshAuthorityChange {
    pub(crate) session_id: SessionId,
    pub(crate) consent_request_id: [u8; 16],
    authority_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsentManagerCompletion {
    pub(crate) results: Vec<ConsentResult>,
    pub(crate) fresh_authority_change: Option<FreshAuthorityChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConsentManagerBeginOutcome {
    PromptAdmitted,
    Cached(ConsentResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConsentCompletionOutcome {
    Completed(ConsentCompletion),
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConsentCancelOutcome {
    Cancelled(ConsentResult),
    Ignored,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ConsentRegistryError {
    #[error("consent request shape is invalid")]
    InvalidRequest,
    #[error("consent request is outside its prompt window")]
    InactiveRequest,
    #[error("trusted local consent context does not match the request")]
    InvalidLocalContext,
    #[error("consent request id was reused for different semantics")]
    ConsentReplayConflict,
    #[error("an equivalent consent request is already pending")]
    ConsentAlreadyPending,
    #[error("the pending consent capacity is full")]
    PendingCapacityExceeded,
    #[error("the consent replay capacity is full")]
    TombstoneCapacityExceeded,
    #[error("consent attempt identities are exhausted")]
    AttemptIdExhausted,
    #[error("consent authority deadline is outside the monotonic clock range")]
    DeadlineOverflow,
    #[error("the consent authority registry lock is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone)]
struct PendingConsent {
    attempt_id: u64,
    request: ConsentRequest,
    fingerprint: ConsentFingerprint,
    context: TrustedConsentContext,
    authorization_deadline: Instant,
}

#[derive(Debug, Clone)]
struct ConsentTombstone {
    fingerprint: ConsentFingerprint,
    result: ConsentResult,
    retain_until_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct RegistryLimits {
    active_bindings: usize,
    pending_consents: usize,
    consent_tombstones: usize,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            active_bindings: MAX_ACTIVE_BINDINGS,
            pending_consents: MAX_PENDING_CONSENTS,
            consent_tombstones: MAX_CONSENT_TOMBSTONES,
        }
    }
}

#[derive(Default)]
struct ConsentAuthorityState {
    bindings: HashMap<SessionId, TrustedSessionBinding>,
    pending: HashMap<[u8; 16], PendingConsent>,
    pending_attempts: HashMap<u64, [u8; 16]>,
    tombstones: HashMap<[u8; 16], ConsentTombstone>,
    next_attempt_id: u64,
}

impl ConsentAuthorityState {
    fn prune_for_capacity(&mut self, now_ms: u64) {
        self.tombstones
            .retain(|_, tombstone| now_ms < tombstone.retain_until_ms);
        let expired_request_ids = self
            .pending
            .iter()
            .filter_map(|(request_id, pending)| {
                (now_ms >= pending.request.expires_at_ms).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in expired_request_ids {
            let Some(pending) = self.pending.remove(&request_id) else {
                continue;
            };
            self.pending_attempts.remove(&pending.attempt_id);
            if now_ms < pending.request.authorization_expires_at_ms {
                self.tombstones.insert(
                    request_id,
                    ConsentTombstone {
                        fingerprint: pending.fingerprint,
                        result: terminal_result(
                            &pending.request,
                            ConsentDecision::Expired,
                            pending.request.expires_at_ms.saturating_sub(1),
                        ),
                        retain_until_ms: pending.request.authorization_expires_at_ms,
                    },
                );
            }
        }
    }

    fn allocate_attempt_id(&mut self) -> Result<u64, ConsentRegistryError> {
        let next = self
            .next_attempt_id
            .checked_add(1)
            .ok_or(ConsentRegistryError::AttemptIdExhausted)?;
        self.next_attempt_id = next;
        Ok(next)
    }
}

/// Bounded in-memory source of consent-derived authority.
pub(crate) struct ConsentAuthorityRegistry {
    state: Mutex<ConsentAuthorityState>,
    limits: RegistryLimits,
}

impl Default for ConsentAuthorityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsentAuthorityRegistry {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ConsentAuthorityState::default()),
            limits: RegistryLimits::default(),
        }
    }

    #[cfg(test)]
    fn with_limits(active_bindings: usize, pending_consents: usize, tombstones: usize) -> Self {
        Self {
            state: Mutex::new(ConsentAuthorityState::default()),
            limits: RegistryLimits {
                active_bindings,
                pending_consents,
                consent_tombstones: tombstones,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn begin(
        &self,
        request: ConsentRequest,
        context: TrustedConsentContext,
    ) -> Result<ConsentBeginOutcome, ConsentRegistryError> {
        let anchor = Instant::now();
        self.begin_at(request, context, anchor)
    }

    fn begin_at(
        &self,
        request: ConsentRequest,
        context: TrustedConsentContext,
        anchor: Instant,
    ) -> Result<ConsentBeginOutcome, ConsentRegistryError> {
        if !valid_request_shape(&request) {
            return Err(ConsentRegistryError::InvalidRequest);
        }
        let fingerprint = ConsentFingerprint::from(&request);
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        state.prune_for_capacity(context.now_ms);

        if let Some(tombstone) = state.tombstones.get(&request.request_id) {
            if tombstone.fingerprint != fingerprint {
                return Err(ConsentRegistryError::ConsentReplayConflict);
            }
            let mut cached = tombstone.result.clone();
            cached.request_token = request.request_token;
            return Ok(ConsentBeginOutcome::Cached(cached));
        }
        if let Some(pending) = state.pending.get(&request.request_id) {
            return if pending.fingerprint == fingerprint {
                Err(ConsentRegistryError::ConsentAlreadyPending)
            } else {
                Err(ConsentRegistryError::ConsentReplayConflict)
            };
        }
        if context.now_ms < request.issued_at_ms || context.now_ms >= request.expires_at_ms {
            return Err(ConsentRegistryError::InactiveRequest);
        }
        if !context.is_valid_for(&request) {
            return Err(ConsentRegistryError::InvalidLocalContext);
        }
        if state.pending.len() >= self.limits.pending_consents {
            return Err(ConsentRegistryError::PendingCapacityExceeded);
        }
        if state.tombstones.len().saturating_add(state.pending.len())
            >= self.limits.consent_tombstones
        {
            return Err(ConsentRegistryError::TombstoneCapacityExceeded);
        }

        let authorization_deadline = checked_authority_deadline(
            anchor,
            request
                .authorization_expires_at_ms
                .saturating_sub(context.now_ms),
        )?;
        let attempt_id = state.allocate_attempt_id()?;
        state.pending.insert(
            request.request_id,
            PendingConsent {
                attempt_id,
                request: request.clone(),
                fingerprint,
                context,
                authorization_deadline,
            },
        );
        state
            .pending_attempts
            .insert(attempt_id, request.request_id);
        Ok(ConsentBeginOutcome::Prompt(PendingConsentPrompt {
            attempt_id,
            request,
        }))
    }

    pub(crate) fn resolve(
        &self,
        session_id: &SessionId,
        now_ms: u64,
    ) -> Result<Option<TrustedSessionBinding>, ConsentRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        Ok(state.bindings.get(session_id).and_then(|binding| {
            (now_ms < binding.authorization_expires_at_ms
                && Instant::now() < binding.authorization_deadline)
                .then(|| binding.clone())
        }))
    }

    pub(crate) fn take_due(
        &self,
        now: Instant,
        now_ms: u64,
    ) -> Result<Vec<AuthorityInvalidation>, ConsentRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        let due = state
            .bindings
            .iter()
            .filter_map(|(session_id, binding)| {
                (now >= binding.authorization_deadline
                    || now_ms >= binding.authorization_expires_at_ms)
                    .then_some(session_id.clone())
            })
            .collect::<Vec<_>>();
        let mut invalidations = Vec::with_capacity(due.len());
        for session_id in due {
            if let Some(binding) = state.bindings.remove(&session_id) {
                invalidations.push(AuthorityInvalidation::from(&binding));
            }
        }
        Ok(invalidations)
    }

    pub(crate) fn next_authority_deadline(&self) -> Result<Option<Instant>, ConsentRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        Ok(state
            .bindings
            .values()
            .map(|binding| binding.authorization_deadline)
            .min())
    }

    pub(crate) fn take_desktop_mismatch(
        &self,
        desktop_epoch: u64,
        desktop_kind: DesktopKind,
    ) -> Result<Vec<AuthorityInvalidation>, ConsentRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        let mismatching = state
            .bindings
            .iter()
            .filter_map(|(session_id, binding)| {
                (binding.desktop_epoch != desktop_epoch || binding.desktop_kind != desktop_kind)
                    .then_some(session_id.clone())
            })
            .collect::<Vec<_>>();
        let mut invalidations = Vec::with_capacity(mismatching.len());
        for session_id in mismatching {
            if let Some(binding) = state.bindings.remove(&session_id) {
                invalidations.push(AuthorityInvalidation::from(&binding));
            }
        }
        Ok(invalidations)
    }

    pub(crate) fn drain(&self) -> Result<Vec<AuthorityInvalidation>, ConsentRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        Ok(state
            .bindings
            .drain()
            .map(|(_, binding)| AuthorityInvalidation::from(&binding))
            .collect())
    }

    pub(crate) fn complete(
        &self,
        attempt_id: u64,
        decision: ConsentDecision,
        approved_scopes: PermissionScopes,
        context: TrustedConsentContext,
    ) -> Result<ConsentCompletionOutcome, ConsentRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        let Some(request_id) = state.pending_attempts.remove(&attempt_id) else {
            return Ok(ConsentCompletionOutcome::Ignored);
        };
        let Some(pending) = state.pending.remove(&request_id) else {
            return Ok(ConsentCompletionOutcome::Ignored);
        };

        let (mut final_decision, mut final_scopes, mut disposition) =
            normalize_decision(&pending, decision, approved_scopes, &context);
        if final_decision == ConsentDecision::Approved
            && !state.bindings.contains_key(&pending.request.session_id)
            && state.bindings.len() >= self.limits.active_bindings
        {
            final_decision = ConsentDecision::Dismissed;
            final_scopes.clear();
            disposition = ConsentCompletionDisposition::Rejected(
                ConsentCompletionRejection::BindingCapacityExceeded,
            );
        }

        let result = ConsentResult {
            request_token: pending.request.request_token,
            request_id: pending.request.request_id,
            session_id: pending.request.session_id.clone(),
            peer: pending.request.peer.clone(),
            policy_revision: pending.request.policy_revision,
            windows_session_id: pending.request.windows_session_id,
            decision: final_decision,
            approved_scopes: final_scopes.clone(),
            decided_at_ms: clamped_decided_at(&pending.request, context.now_ms),
        };
        let binding_changed = if final_decision == ConsentDecision::Approved {
            state.bindings.insert(
                pending.request.session_id.clone(),
                TrustedSessionBinding {
                    authority_generation: pending.attempt_id,
                    consent_request_id: pending.request.request_id,
                    registration_id: pending.context.registration_id,
                    registration_epoch: pending.context.registration_epoch,
                    session_id: pending.request.session_id.clone(),
                    peer: pending.request.peer.clone(),
                    approved_scopes: final_scopes,
                    policy_revision: pending.request.policy_revision,
                    windows_session_id: pending.context.windows_session_id,
                    desktop_epoch: pending.context.desktop_epoch,
                    desktop_kind: pending.context.desktop_kind,
                    authorization_expires_at_ms: pending.request.authorization_expires_at_ms,
                    authorization_deadline: pending.authorization_deadline,
                    expected_issuer_key_id: pending.context.expected_issuer_key_id,
                },
            );
            true
        } else {
            false
        };
        state.tombstones.insert(
            request_id,
            ConsentTombstone {
                fingerprint: pending.fingerprint,
                result: result.clone(),
                retain_until_ms: pending.request.authorization_expires_at_ms,
            },
        );
        Ok(ConsentCompletionOutcome::Completed(ConsentCompletion {
            result,
            binding_changed,
            disposition,
        }))
    }

    pub(crate) fn cancel(
        &self,
        cancel: &CancelConsent,
        now_ms: u64,
    ) -> Result<ConsentCancelOutcome, ConsentRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        let Some(pending) = state.pending.get(&cancel.request_id) else {
            return Ok(ConsentCancelOutcome::Ignored);
        };
        if pending.request.request_token != cancel.request_token
            || pending.request.session_id != cancel.session_id
        {
            return Ok(ConsentCancelOutcome::Ignored);
        }
        let Some(pending) = state.pending.remove(&cancel.request_id) else {
            return Ok(ConsentCancelOutcome::Ignored);
        };
        state.pending_attempts.remove(&pending.attempt_id);
        let decision = if now_ms >= pending.request.expires_at_ms {
            ConsentDecision::Expired
        } else {
            ConsentDecision::Dismissed
        };
        let result = terminal_result(
            &pending.request,
            decision,
            clamped_decided_at(&pending.request, now_ms),
        );
        if now_ms < pending.request.authorization_expires_at_ms {
            state.tombstones.insert(
                cancel.request_id,
                ConsentTombstone {
                    fingerprint: pending.fingerprint,
                    result: result.clone(),
                    retain_until_ms: pending.request.authorization_expires_at_ms,
                },
            );
        }
        Ok(ConsentCancelOutcome::Cancelled(result))
    }

    pub(crate) fn invalidate_fresh_authority(
        &self,
        change: &FreshAuthorityChange,
    ) -> Result<bool, ConsentRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConsentRegistryError::Unavailable)?;
        let matches = state
            .bindings
            .get(&change.session_id)
            .is_some_and(|binding| {
                binding.consent_request_id == change.consent_request_id
                    && binding.authority_generation == change.authority_generation
            });
        if matches {
            state.bindings.remove(&change.session_id);
        }
        Ok(matches)
    }
}

const CONSENT_COMPLETION_CHANNEL_CAPACITY: usize = 1;

#[derive(Debug)]
pub(crate) struct BackendCompletion {
    attempt_id: u64,
    outcome: BackendCompletionOutcome,
}

#[derive(Debug)]
enum BackendCompletionOutcome {
    Decision(ConsentBackendDecision),
    Unavailable,
    BackendFailed,
}

struct ManagedPrompt {
    pending: PendingConsentPrompt,
    context: TrustedConsentContext,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivePromptPhase {
    Prompting,
    Closing,
}

struct ActivePrompt {
    prompt: ManagedPrompt,
    phase: ActivePromptPhase,
    abort: watch::Sender<Option<ConsentAbortReason>>,
    backend_abort: Option<tokio::task::AbortHandle>,
    task: Option<JoinHandle<()>>,
}

/// Single-owner, bounded coordinator for local consent prompt futures.
pub(crate) struct ConsentManager {
    registry: Arc<ConsentAuthorityRegistry>,
    backend: Arc<dyn ConsentBackend>,
    queued: VecDeque<ManagedPrompt>,
    active: Option<ActivePrompt>,
    completion_tx: mpsc::Sender<BackendCompletion>,
    completion_rx: mpsc::Receiver<BackendCompletion>,
}

impl ConsentManager {
    pub(crate) fn new(backend: Arc<dyn ConsentBackend>) -> Self {
        let (completion_tx, completion_rx) = mpsc::channel(CONSENT_COMPLETION_CHANNEL_CAPACITY);
        Self {
            registry: Arc::new(ConsentAuthorityRegistry::new()),
            backend,
            queued: VecDeque::with_capacity(MAX_PENDING_CONSENTS),
            active: None,
            completion_tx,
            completion_rx,
        }
    }

    pub(crate) fn is_available(&self) -> bool {
        catch_unwind(AssertUnwindSafe(|| self.backend.is_available())).unwrap_or(false)
    }

    #[cfg(test)]
    pub(crate) fn registry(&self) -> Arc<ConsentAuthorityRegistry> {
        Arc::clone(&self.registry)
    }

    pub(crate) fn resolve_binding(
        &self,
        session_id: &SessionId,
        now_ms: u64,
    ) -> Result<Option<TrustedSessionBinding>, ConsentRegistryError> {
        self.registry.resolve(session_id, now_ms)
    }

    pub(crate) fn admit(
        &mut self,
        request: ConsentRequest,
        context: TrustedConsentContext,
    ) -> Result<ConsentManagerBeginOutcome, ConsentRegistryError> {
        let now = Instant::now();
        match self.registry.begin_at(request, context.clone(), now)? {
            ConsentBeginOutcome::Cached(result) => {
                return Ok(ConsentManagerBeginOutcome::Cached(result));
            }
            ConsentBeginOutcome::Prompt(pending) => {
                let prompt_lifetime_ms =
                    pending.request.expires_at_ms.saturating_sub(context.now_ms);
                self.queued.push_back(ManagedPrompt {
                    pending,
                    context: context.clone(),
                    deadline: now + std::time::Duration::from_millis(prompt_lifetime_ms),
                });
            }
        }
        Ok(ConsentManagerBeginOutcome::PromptAdmitted)
    }

    #[cfg(test)]
    pub(crate) fn begin(
        &mut self,
        request: ConsentRequest,
        context: TrustedConsentContext,
    ) -> Result<Vec<ConsentResult>, ConsentRegistryError> {
        let mut results = Vec::new();
        if let ConsentManagerBeginOutcome::Cached(result) = self.admit(request, context.clone())? {
            results.push(result);
        }
        results.append(&mut self.activate(context)?);
        Ok(results)
    }

    pub(crate) fn activate(
        &mut self,
        context: TrustedConsentContext,
    ) -> Result<Vec<ConsentResult>, ConsentRegistryError> {
        let now = Instant::now();
        let mut results = Vec::new();
        self.expire_queued_due(now, context.now_ms, &mut results)?;
        self.start_next(Instant::now(), &context, &mut results)?;
        Ok(results)
    }

    pub(crate) fn has_active_prompt(&self) -> bool {
        self.active.is_some()
    }

    pub(crate) fn needs_activation(&self) -> bool {
        self.active.is_none() && !self.queued.is_empty()
    }

    pub(crate) fn next_deadline(&self) -> Result<Option<Instant>, ConsentRegistryError> {
        let prompt_deadline = self
            .active
            .as_ref()
            .filter(|active| active.phase == ActivePromptPhase::Prompting)
            .map(|active| active.prompt.deadline)
            .into_iter()
            .chain(self.queued.iter().map(|prompt| prompt.deadline))
            .min();
        Ok(prompt_deadline
            .into_iter()
            .chain(self.registry.next_authority_deadline()?)
            .min())
    }

    pub(crate) async fn next_completion(&mut self) -> Option<BackendCompletion> {
        self.completion_rx.recv().await
    }

    pub(crate) fn complete(
        &mut self,
        completion: BackendCompletion,
        context: TrustedConsentContext,
    ) -> Result<ConsentManagerCompletion, ConsentRegistryError> {
        let Some(active) = self.active.as_ref() else {
            return Ok(ConsentManagerCompletion {
                results: Vec::new(),
                fresh_authority_change: None,
            });
        };
        if active.prompt.pending.attempt_id != completion.attempt_id {
            return Ok(ConsentManagerCompletion {
                results: Vec::new(),
                fresh_authority_change: None,
            });
        }
        let now = Instant::now();
        let now_ms = context.now_ms;
        let deadline_won = active.phase == ActivePromptPhase::Prompting
            && (now >= active.prompt.deadline
                || context.now_ms >= active.prompt.pending.request.expires_at_ms);
        let mut results = Vec::new();
        if deadline_won {
            self.expire_active(now_ms, &mut results)?;
            // This completion is proof that the backend surface has closed. The
            // just-consumed attempt may now transition Closing -> Idle, but its
            // decision (including Approved) is deliberately ignored.
            self.active.take();
            self.expire_queued_due(now, now_ms, &mut results)?;
            self.start_next(Instant::now(), &context, &mut results)?;
            return Ok(ConsentManagerCompletion {
                results,
                fresh_authority_change: None,
            });
        }
        let Some(active) = self.active.take() else {
            return Err(ConsentRegistryError::Unavailable);
        };
        let mut fresh_authority_change = None;
        if active.phase != ActivePromptPhase::Closing {
            let (decision, scopes) = match completion.outcome {
                BackendCompletionOutcome::Decision(ConsentBackendDecision::Approved(scopes)) => {
                    (ConsentDecision::Approved, scopes)
                }
                BackendCompletionOutcome::Decision(ConsentBackendDecision::Denied) => {
                    (ConsentDecision::Denied, PermissionScopes::new())
                }
                BackendCompletionOutcome::Decision(
                    ConsentBackendDecision::Dismissed | ConsentBackendDecision::Cancelled,
                )
                | BackendCompletionOutcome::Unavailable
                | BackendCompletionOutcome::BackendFailed => {
                    (ConsentDecision::Dismissed, PermissionScopes::new())
                }
            };
            match self.registry.complete(
                active.prompt.pending.attempt_id,
                decision,
                scopes,
                context.clone(),
            )? {
                ConsentCompletionOutcome::Completed(completed) => {
                    if completed.binding_changed {
                        fresh_authority_change = Some(FreshAuthorityChange {
                            session_id: completed.result.session_id.clone(),
                            consent_request_id: completed.result.request_id,
                            authority_generation: active.prompt.pending.attempt_id,
                        });
                    }
                    results.push(completed.result);
                }
                ConsentCompletionOutcome::Ignored => {}
            }
        }
        self.expire_queued_due(now, now_ms, &mut results)?;
        if fresh_authority_change.is_none() {
            self.start_next(Instant::now(), &context, &mut results)?;
        }
        Ok(ConsentManagerCompletion {
            results,
            fresh_authority_change,
        })
    }

    pub(crate) fn resume_after_fresh_authority(
        &mut self,
        context: TrustedConsentContext,
    ) -> Result<Vec<ConsentResult>, ConsentRegistryError> {
        let mut results = Vec::new();
        let now = Instant::now();
        self.expire_queued_due(now, context.now_ms, &mut results)?;
        self.start_next(Instant::now(), &context, &mut results)?;
        Ok(results)
    }

    pub(crate) fn invalidate_fresh_authority(
        &self,
        change: &FreshAuthorityChange,
    ) -> Result<bool, ConsentRegistryError> {
        self.registry.invalidate_fresh_authority(change)
    }

    pub(crate) fn take_due_authority(
        &self,
        now: Instant,
        now_ms: u64,
    ) -> Result<Vec<AuthorityInvalidation>, ConsentRegistryError> {
        self.registry.take_due(now, now_ms)
    }

    pub(crate) fn take_desktop_mismatch(
        &self,
        desktop_epoch: u64,
        desktop_kind: DesktopKind,
    ) -> Result<Vec<AuthorityInvalidation>, ConsentRegistryError> {
        self.registry
            .take_desktop_mismatch(desktop_epoch, desktop_kind)
    }

    pub(crate) fn invalidate_desktop_prompts(
        &mut self,
        desktop_epoch: u64,
        desktop_kind: DesktopKind,
        now_ms: u64,
    ) -> Result<Vec<ConsentResult>, ConsentRegistryError> {
        let mut results = self.expire_due(Instant::now(), now_ms)?;
        let active_mismatch = self.active.as_ref().is_some_and(|active| {
            active.prompt.context.desktop_epoch != desktop_epoch
                || active.prompt.context.desktop_kind != desktop_kind
        });
        if active_mismatch {
            let active_prompting = self
                .active
                .as_ref()
                .is_some_and(|active| active.phase == ActivePromptPhase::Prompting);
            if active_prompting {
                let outcome = {
                    let active = self
                        .active
                        .as_ref()
                        .ok_or(ConsentRegistryError::Unavailable)?;
                    cancel_managed_prompt(&self.registry, &active.prompt, now_ms)?
                };
                let ConsentCancelOutcome::Cancelled(result) = outcome else {
                    return Err(ConsentRegistryError::Unavailable);
                };
                let active = self
                    .active
                    .as_mut()
                    .ok_or(ConsentRegistryError::Unavailable)?;
                active.phase = ActivePromptPhase::Closing;
                active
                    .abort
                    .send_replace(Some(ConsentAbortReason::DesktopChanged));
                results.push(result);
            }
        }

        let mut index = 0;
        while index < self.queued.len() {
            let mismatch = self.queued.get(index).is_some_and(|prompt| {
                prompt.context.desktop_epoch != desktop_epoch
                    || prompt.context.desktop_kind != desktop_kind
            });
            if !mismatch {
                index += 1;
                continue;
            }
            let outcome = {
                let prompt = self
                    .queued
                    .get(index)
                    .ok_or(ConsentRegistryError::Unavailable)?;
                cancel_managed_prompt(&self.registry, prompt, now_ms)?
            };
            let ConsentCancelOutcome::Cancelled(result) = outcome else {
                return Err(ConsentRegistryError::Unavailable);
            };
            self.queued
                .remove(index)
                .ok_or(ConsentRegistryError::Unavailable)?;
            results.push(result);
        }
        Ok(results)
    }

    pub(crate) fn drain_authority(
        &self,
    ) -> Result<Vec<AuthorityInvalidation>, ConsentRegistryError> {
        self.registry.drain()
    }

    pub(crate) fn expire_due(
        &mut self,
        now: Instant,
        now_ms: u64,
    ) -> Result<Vec<ConsentResult>, ConsentRegistryError> {
        let mut results = Vec::new();
        let active_due = self.active.as_ref().is_some_and(|active| {
            active.phase == ActivePromptPhase::Prompting
                && (now >= active.prompt.deadline
                    || now_ms >= active.prompt.pending.request.expires_at_ms)
        });
        if active_due {
            self.expire_active(now_ms, &mut results)?;
        }
        self.expire_queued_due(now, now_ms, &mut results)?;
        Ok(results)
    }

    pub(crate) fn cancel(
        &mut self,
        cancel: &CancelConsent,
        now: Instant,
        now_ms: u64,
    ) -> Result<Vec<ConsentResult>, ConsentRegistryError> {
        let mut results = self.expire_due(now, now_ms)?;
        let active_matches = self
            .active
            .as_ref()
            .is_some_and(|active| exact_cancel_matches(&active.prompt.pending.request, cancel));
        if active_matches {
            let outcome = self.registry.cancel(cancel, now_ms)?;
            let ConsentCancelOutcome::Cancelled(result) = outcome else {
                return Ok(results);
            };
            let Some(active) = self.active.as_mut() else {
                return Err(ConsentRegistryError::Unavailable);
            };
            active.phase = ActivePromptPhase::Closing;
            active
                .abort
                .send_replace(Some(ConsentAbortReason::Service(cancel.reason)));
            results.push(result);
            return Ok(results);
        }

        let queued_index = self
            .queued
            .iter()
            .position(|prompt| exact_cancel_matches(&prompt.pending.request, cancel));
        let Some(queued_index) = queued_index else {
            return Ok(results);
        };
        let outcome = self.registry.cancel(cancel, now_ms)?;
        let ConsentCancelOutcome::Cancelled(result) = outcome else {
            return Ok(results);
        };
        self.queued.remove(queued_index);
        results.push(result);
        Ok(results)
    }

    pub(crate) async fn shutdown(
        &mut self,
        reason: ConsentAbortReason,
        now_ms: u64,
    ) -> Result<(), ConsentRegistryError> {
        let active = self.active.take();
        let queued = self.queued.drain(..).collect::<Vec<_>>();
        let mut first_error = None;

        if let Some(active) = active.as_ref() {
            if let Err(error) = cancel_managed_prompt(&self.registry, &active.prompt, now_ms) {
                first_error = Some(error);
            }
        }
        for prompt in &queued {
            if let Err(error) = cancel_managed_prompt(&self.registry, prompt, now_ms) {
                first_error.get_or_insert(error);
            }
        }

        if let Some(mut active) = active {
            active.abort.send_replace(Some(reason));
            if let Some(backend_abort) = active.backend_abort.take() {
                backend_abort.abort();
            }
            if let Some(task) = active.task.take() {
                task.abort();
                let _ = task.await;
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn start_next(
        &mut self,
        mut now: Instant,
        current_context: &TrustedConsentContext,
        results: &mut Vec<ConsentResult>,
    ) -> Result<(), ConsentRegistryError> {
        if self.active.is_some() {
            return Ok(());
        }
        let prompt = loop {
            let Some(prompt) = self.queued.pop_front() else {
                return Ok(());
            };
            if now >= prompt.deadline
                || current_context.now_ms >= prompt.pending.request.expires_at_ms
            {
                complete_expired_prompt(&self.registry, &prompt, current_context.now_ms, results)?;
                now = Instant::now();
                continue;
            }
            if !prompt.context.same_authority(current_context) {
                let outcome =
                    cancel_managed_prompt(&self.registry, &prompt, current_context.now_ms)?;
                let ConsentCancelOutcome::Cancelled(result) = outcome else {
                    return Err(ConsentRegistryError::Unavailable);
                };
                results.push(result);
                now = Instant::now();
                continue;
            }
            break prompt;
        };
        let display_prompt = ConsentPrompt {
            session_id: prompt.pending.request.session_id.clone(),
            peer: prompt.pending.request.peer.clone(),
            requested_scopes: prompt.pending.request.requested_scopes.clone(),
        };
        let (abort, abort_receiver) = watch::channel(None);
        let attempt_id = prompt.pending.attempt_id;
        self.active = Some(ActivePrompt {
            prompt,
            phase: ActivePromptPhase::Prompting,
            abort,
            backend_abort: None,
            task: None,
        });

        let backend = Arc::clone(&self.backend);
        let backend_task = tokio::spawn(async move {
            if !backend.is_available() {
                return BackendCompletionOutcome::Unavailable;
            }
            let future = backend.prompt(display_prompt, abort_receiver);
            BackendCompletionOutcome::Decision(future.await)
        });
        let backend_abort = backend_task.abort_handle();
        let Some(active) = self.active.as_mut() else {
            backend_abort.abort();
            return Err(ConsentRegistryError::Unavailable);
        };
        active.backend_abort = Some(backend_abort);
        let completion = self.completion_tx.clone();
        let task = tokio::spawn(async move {
            let outcome = match backend_task.await {
                Ok(outcome) => outcome,
                Err(error) if error.is_cancelled() => return,
                Err(_) => BackendCompletionOutcome::BackendFailed,
            };
            let _ = completion
                .send(BackendCompletion {
                    attempt_id,
                    outcome,
                })
                .await;
        });
        let Some(active) = self.active.as_mut() else {
            task.abort();
            return Err(ConsentRegistryError::Unavailable);
        };
        active.task = Some(task);
        Ok(())
    }

    fn expire_active(
        &mut self,
        now_ms: u64,
        results: &mut Vec<ConsentResult>,
    ) -> Result<(), ConsentRegistryError> {
        let Some(active) = self.active.as_mut() else {
            return Err(ConsentRegistryError::Unavailable);
        };
        complete_expired_prompt(&self.registry, &active.prompt, now_ms, results)?;
        active.phase = ActivePromptPhase::Closing;
        active
            .abort
            .send_replace(Some(ConsentAbortReason::PromptExpired));
        Ok(())
    }

    fn expire_queued_due(
        &mut self,
        now: Instant,
        now_ms: u64,
        results: &mut Vec<ConsentResult>,
    ) -> Result<(), ConsentRegistryError> {
        let mut index = 0;
        while index < self.queued.len() {
            let due = self.queued.get(index).is_some_and(|prompt| {
                now >= prompt.deadline || now_ms >= prompt.pending.request.expires_at_ms
            });
            if !due {
                index += 1;
                continue;
            }
            let Some(prompt) = self.queued.remove(index) else {
                return Err(ConsentRegistryError::Unavailable);
            };
            complete_expired_prompt(&self.registry, &prompt, now_ms, results)?;
        }
        Ok(())
    }
}

impl Drop for ConsentManager {
    fn drop(&mut self) {
        let Some(mut active) = self.active.take() else {
            return;
        };
        active
            .abort
            .send_replace(Some(ConsentAbortReason::RuntimeStopping));
        if let Some(backend_abort) = active.backend_abort.take() {
            backend_abort.abort();
        }
        if let Some(task) = active.task.take() {
            task.abort();
        }
    }
}

fn cancel_managed_prompt(
    registry: &ConsentAuthorityRegistry,
    prompt: &ManagedPrompt,
    now_ms: u64,
) -> Result<ConsentCancelOutcome, ConsentRegistryError> {
    registry.cancel(
        &CancelConsent {
            request_token: prompt.pending.request.request_token,
            request_id: prompt.pending.request.request_id,
            session_id: prompt.pending.request.session_id.clone(),
            reason: mrd_agent_ipc::ConsentCancelReason::SessionClosed,
        },
        now_ms,
    )
}

fn exact_cancel_matches(request: &ConsentRequest, cancel: &CancelConsent) -> bool {
    request.request_token == cancel.request_token
        && request.request_id == cancel.request_id
        && request.session_id == cancel.session_id
}

fn complete_expired_prompt(
    registry: &ConsentAuthorityRegistry,
    prompt: &ManagedPrompt,
    now_ms: u64,
    results: &mut Vec<ConsentResult>,
) -> Result<(), ConsentRegistryError> {
    let mut context = prompt.context.clone();
    context.now_ms = now_ms.max(prompt.pending.request.expires_at_ms);
    match registry.complete(
        prompt.pending.attempt_id,
        ConsentDecision::Expired,
        PermissionScopes::new(),
        context,
    )? {
        ConsentCompletionOutcome::Completed(completed) => results.push(completed.result),
        ConsentCompletionOutcome::Ignored => {}
    }
    Ok(())
}

fn normalize_decision(
    pending: &PendingConsent,
    decision: ConsentDecision,
    approved_scopes: PermissionScopes,
    context: &TrustedConsentContext,
) -> (
    ConsentDecision,
    PermissionScopes,
    ConsentCompletionDisposition,
) {
    if context.now_ms < pending.context.now_ms {
        return (
            ConsentDecision::Dismissed,
            PermissionScopes::new(),
            ConsentCompletionDisposition::Rejected(ConsentCompletionRejection::InvalidLocalContext),
        );
    }
    if context.now_ms < pending.request.issued_at_ms
        || context.now_ms >= pending.request.expires_at_ms
    {
        return (
            ConsentDecision::Expired,
            PermissionScopes::new(),
            ConsentCompletionDisposition::Rejected(ConsentCompletionRejection::PromptExpired),
        );
    }
    if !context.is_valid_for(&pending.request) || !context.same_authority(&pending.context) {
        return (
            ConsentDecision::Dismissed,
            PermissionScopes::new(),
            ConsentCompletionDisposition::Rejected(ConsentCompletionRejection::InvalidLocalContext),
        );
    }
    match decision {
        ConsentDecision::Approved if approved_scopes.is_empty() => (
            ConsentDecision::Dismissed,
            PermissionScopes::new(),
            ConsentCompletionDisposition::Rejected(ConsentCompletionRejection::ScopeEscalation),
        ),
        ConsentDecision::Approved
            if !pending
                .request
                .requested_scopes
                .is_superset(&approved_scopes) =>
        {
            (
                ConsentDecision::Dismissed,
                PermissionScopes::new(),
                ConsentCompletionDisposition::Rejected(ConsentCompletionRejection::ScopeEscalation),
            )
        }
        ConsentDecision::Approved => (
            ConsentDecision::Approved,
            approved_scopes,
            ConsentCompletionDisposition::Approved,
        ),
        _non_approved if !approved_scopes.is_empty() => (
            ConsentDecision::Dismissed,
            PermissionScopes::new(),
            ConsentCompletionDisposition::Rejected(
                ConsentCompletionRejection::UnexpectedApprovedScopes,
            ),
        ),
        non_approved => (
            non_approved,
            PermissionScopes::new(),
            ConsentCompletionDisposition::NonApproved,
        ),
    }
}

fn clamped_decided_at(request: &ConsentRequest, now_ms: u64) -> u64 {
    now_ms
        .max(request.issued_at_ms)
        .min(request.expires_at_ms.saturating_sub(1))
}

fn terminal_result(
    request: &ConsentRequest,
    decision: ConsentDecision,
    decided_at_ms: u64,
) -> ConsentResult {
    ConsentResult {
        request_token: request.request_token,
        request_id: request.request_id,
        session_id: request.session_id.clone(),
        peer: request.peer.clone(),
        policy_revision: request.policy_revision,
        windows_session_id: request.windows_session_id,
        decision,
        approved_scopes: PermissionScopes::new(),
        decided_at_ms,
    }
}

fn valid_request_shape(request: &ConsentRequest) -> bool {
    request.request_token != 0
        && request.request_id.iter().any(|byte| *byte != 0)
        && !request.session_id.0.is_empty()
        && request.session_id.0.len() <= AGENT_IPC_MAX_IDENTIFIER_BYTES
        && !request.peer.device_id.0.is_empty()
        && request.peer.device_id.0.len() <= AGENT_IPC_MAX_IDENTIFIER_BYTES
        && request.peer.key_id.iter().any(|byte| *byte != 0)
        && !request.requested_scopes.is_empty()
        && request.policy_revision != 0
        && request.windows_session_id != 0
        && request.issued_at_ms != 0
        && request.expires_at_ms > request.issued_at_ms
        && request.authorization_expires_at_ms >= request.expires_at_ms
        && request
            .authorization_expires_at_ms
            .saturating_sub(request.issued_at_ms)
            <= AGENT_CONSENT_MAX_LIFETIME_MS
}

fn checked_authority_deadline(
    now: Instant,
    lifetime_ms: u64,
) -> Result<Instant, ConsentRegistryError> {
    if lifetime_ms > AGENT_CONSENT_MAX_LIFETIME_MS {
        return Err(ConsentRegistryError::DeadlineOverflow);
    }
    now.checked_add(std::time::Duration::from_millis(lifetime_ms))
        .ok_or(ConsentRegistryError::DeadlineOverflow)
}

#[cfg(test)]
mod tests;
