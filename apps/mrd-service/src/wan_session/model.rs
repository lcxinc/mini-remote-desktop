use super::backend::WanSessionBinding;
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{WanMediaProfileV3, WanPermissionScopeV3, WanRoutePolicyV3};
use std::fmt;
use thiserror::Error;

const DIGEST_HEX_BYTES: usize = 64;
const MAX_ROUTE_IDENTIFIER_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanSessionRole {
    Controller,
    Target,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WanSessionPhase {
    Created,
    BackendBound,
    AwaitingConsent,
    Granted,
    AccessBound,
    Negotiating,
    RelayVerified,
    Streaming,
    Closed,
    Failed,
}

impl WanSessionPhase {
    fn next(self) -> Option<Self> {
        match self {
            Self::Created => Some(Self::BackendBound),
            Self::BackendBound => Some(Self::AwaitingConsent),
            Self::AwaitingConsent => Some(Self::Granted),
            Self::Granted => Some(Self::AccessBound),
            Self::AccessBound => Some(Self::Negotiating),
            Self::Negotiating => Some(Self::RelayVerified),
            Self::RelayVerified => Some(Self::Streaming),
            Self::Streaming | Self::Closed | Self::Failed => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanSessionFailure {
    InvalidTransition,
    ConflictingDuplicate,
    DeadlineExceeded,
    IdentityMismatch,
    PolicyMismatch,
    RouteMismatch,
    CapacityExceeded,
    RetryBudgetExceeded,
    BufferCapacityExceeded,
    Transport,
    Cancelled,
    Internal,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WanSessionIdentity {
    binding: WanSessionBinding,
    controller_key_fingerprint: String,
    target_key_fingerprint: String,
    deadline_unix_ms: u64,
}

impl fmt::Debug for WanSessionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionIdentity")
            .field("binding", &self.binding)
            .field(
                "controller_key_fingerprint",
                &self.controller_key_fingerprint,
            )
            .field("target_key_fingerprint", &self.target_key_fingerprint)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .finish()
    }
}

impl WanSessionIdentity {
    pub fn new(
        session_id: SessionId,
        controller_device_id: DeviceId,
        target_device_id: DeviceId,
        controller_key_fingerprint: String,
        target_key_fingerprint: String,
        deadline_unix_ms: u64,
    ) -> Result<Self, WanSessionModelError> {
        let binding = WanSessionBinding::new(session_id, controller_device_id, target_device_id)
            .map_err(|_| WanSessionModelError::InvalidIdentity)?;
        if !is_digest(&controller_key_fingerprint)
            || !is_digest(&target_key_fingerprint)
            || controller_key_fingerprint == target_key_fingerprint
            || deadline_unix_ms == 0
        {
            return Err(WanSessionModelError::InvalidIdentity);
        }
        Ok(Self {
            binding,
            controller_key_fingerprint,
            target_key_fingerprint,
            deadline_unix_ms,
        })
    }

    pub fn binding(&self) -> &WanSessionBinding {
        &self.binding
    }

    pub fn session_id(&self) -> &SessionId {
        self.binding.session_id()
    }

    pub fn controller_device_id(&self) -> &DeviceId {
        self.binding.controller_device_id()
    }

    pub fn target_device_id(&self) -> &DeviceId {
        self.binding.target_device_id()
    }

    pub fn controller_key_fingerprint(&self) -> &str {
        &self.controller_key_fingerprint
    }

    pub fn target_key_fingerprint(&self) -> &str {
        &self.target_key_fingerprint
    }

    pub fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }

    pub fn verify_actor(
        &self,
        role: WanSessionRole,
        device_id: &DeviceId,
        key_fingerprint: &str,
    ) -> bool {
        match role {
            WanSessionRole::Controller => {
                device_id == self.controller_device_id()
                    && key_fingerprint == self.controller_key_fingerprint
            }
            WanSessionRole::Target => {
                device_id == self.target_device_id()
                    && key_fingerprint == self.target_key_fingerprint
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantBinding {
    request_commitment: String,
    approved_scopes: Vec<WanPermissionScopeV3>,
    approved_profile: Option<WanMediaProfileV3>,
    policy_revision: u64,
    policy_expires_at_ms: u64,
    grant_expires_at_ms: u64,
    route_policy: WanRoutePolicyV3,
}

impl GrantBinding {
    pub fn new(
        request_commitment: String,
        approved_scopes: Vec<WanPermissionScopeV3>,
        policy_revision: u64,
        policy_expires_at_ms: u64,
        grant_expires_at_ms: u64,
        route_policy: WanRoutePolicyV3,
    ) -> Result<Self, WanSessionModelError> {
        Self::with_profile(
            request_commitment,
            approved_scopes,
            None,
            policy_revision,
            policy_expires_at_ms,
            grant_expires_at_ms,
            route_policy,
        )
    }

    pub fn with_profile(
        request_commitment: String,
        approved_scopes: Vec<WanPermissionScopeV3>,
        approved_profile: Option<WanMediaProfileV3>,
        policy_revision: u64,
        policy_expires_at_ms: u64,
        grant_expires_at_ms: u64,
        route_policy: WanRoutePolicyV3,
    ) -> Result<Self, WanSessionModelError> {
        if !is_digest(&request_commitment)
            || approved_scopes.is_empty()
            || approved_scopes.windows(2).any(|pair| pair[0] >= pair[1])
            || policy_revision == 0
            || grant_expires_at_ms == 0
            || policy_expires_at_ms < grant_expires_at_ms
            || route_policy != WanRoutePolicyV3::RelayOnly
        {
            return Err(WanSessionModelError::InvalidPolicy);
        }
        Ok(Self {
            request_commitment,
            approved_scopes,
            approved_profile,
            policy_revision,
            policy_expires_at_ms,
            grant_expires_at_ms,
            route_policy,
        })
    }

    pub fn request_commitment(&self) -> &str {
        &self.request_commitment
    }

    pub fn approved_scopes(&self) -> &[WanPermissionScopeV3] {
        &self.approved_scopes
    }

    pub fn approved_profile(&self) -> Option<&WanMediaProfileV3> {
        self.approved_profile.as_ref()
    }

    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub fn policy_expires_at_ms(&self) -> u64 {
        self.policy_expires_at_ms
    }

    pub fn grant_expires_at_ms(&self) -> u64 {
        self.grant_expires_at_ms
    }

    pub fn route_policy(&self) -> WanRoutePolicyV3 {
        self.route_policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAccessBinding {
    policy_revision: u64,
    generation: u64,
    directory_id: String,
    primary_node_id: String,
    relay_url_digest: String,
}

impl RelayAccessBinding {
    pub fn generation_zero(
        policy_revision: u64,
        directory_id: String,
        primary_node_id: String,
        relay_url_digest: String,
    ) -> Result<Self, WanSessionModelError> {
        Self::exact_generation(
            policy_revision,
            0,
            directory_id,
            primary_node_id,
            relay_url_digest,
        )
    }

    pub fn exact_generation(
        policy_revision: u64,
        generation: u64,
        directory_id: String,
        primary_node_id: String,
        relay_url_digest: String,
    ) -> Result<Self, WanSessionModelError> {
        if policy_revision == 0
            || generation != 0
            || !is_safe_route_identifier(&directory_id)
            || !is_safe_route_identifier(&primary_node_id)
            || !is_digest(&relay_url_digest)
        {
            return Err(WanSessionModelError::InvalidRoute);
        }
        Ok(Self {
            policy_revision,
            generation,
            directory_id,
            primary_node_id,
            relay_url_digest,
        })
    }

    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRouteProof {
    access: RelayAccessBinding,
    local_candidate_relayed: bool,
    remote_candidate_relayed: bool,
}

impl RelayRouteProof {
    pub fn from_access(
        access: &RelayAccessBinding,
        local_candidate_relayed: bool,
        remote_candidate_relayed: bool,
    ) -> Result<Self, WanSessionModelError> {
        if !local_candidate_relayed || !remote_candidate_relayed {
            return Err(WanSessionModelError::InvalidRoute);
        }
        Ok(Self {
            access: access.clone(),
            local_candidate_relayed,
            remote_candidate_relayed,
        })
    }

    pub fn access(&self) -> &RelayAccessBinding {
        &self.access
    }

    pub fn is_relay_to_relay(&self) -> bool {
        self.local_candidate_relayed && self.remote_candidate_relayed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WanSessionEvent {
    BackendBound { request_commitment: String },
    AwaitingConsent { intent_commitment: String },
    Granted(GrantBinding),
    AccessBound(RelayAccessBinding),
    Negotiating,
    RelayVerified(RelayRouteProof),
    Streaming,
    Closed,
    Failed(WanSessionFailure),
}

impl WanSessionEvent {
    fn target_phase(&self) -> WanSessionPhase {
        match self {
            Self::BackendBound { .. } => WanSessionPhase::BackendBound,
            Self::AwaitingConsent { .. } => WanSessionPhase::AwaitingConsent,
            Self::Granted(_) => WanSessionPhase::Granted,
            Self::AccessBound(_) => WanSessionPhase::AccessBound,
            Self::Negotiating => WanSessionPhase::Negotiating,
            Self::RelayVerified(_) => WanSessionPhase::RelayVerified,
            Self::Streaming => WanSessionPhase::Streaming,
            Self::Closed => WanSessionPhase::Closed,
            Self::Failed(_) => WanSessionPhase::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionResult {
    Applied,
    Duplicate,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WanSessionState {
    role: WanSessionRole,
    identity: WanSessionIdentity,
    phase: WanSessionPhase,
    accepted_events: Vec<WanSessionEvent>,
    request_commitment: Option<String>,
    intent_commitment: Option<String>,
    grant: Option<GrantBinding>,
    access: Option<RelayAccessBinding>,
    route_proof: Option<RelayRouteProof>,
    failure: Option<WanSessionFailure>,
}

impl fmt::Debug for WanSessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WanSessionState")
            .field("role", &self.role)
            .field("identity", &self.identity)
            .field("phase", &self.phase)
            .field("request_commitment", &self.request_commitment)
            .field("grant", &self.grant)
            .field("access", &self.access)
            .field("route_proof", &self.route_proof)
            .field("failure", &self.failure)
            .finish()
    }
}

impl WanSessionState {
    pub fn new(role: WanSessionRole, identity: WanSessionIdentity) -> Self {
        Self {
            role,
            identity,
            phase: WanSessionPhase::Created,
            accepted_events: Vec::with_capacity(8),
            request_commitment: None,
            intent_commitment: None,
            grant: None,
            access: None,
            route_proof: None,
            failure: None,
        }
    }

    pub fn role(&self) -> WanSessionRole {
        self.role
    }

    pub fn identity(&self) -> &WanSessionIdentity {
        &self.identity
    }

    pub fn phase(&self) -> WanSessionPhase {
        self.phase
    }

    pub fn grant(&self) -> Option<&GrantBinding> {
        self.grant.as_ref()
    }

    pub fn request_commitment(&self) -> Option<&str> {
        self.request_commitment.as_deref()
    }

    pub fn intent_commitment(&self) -> Option<&str> {
        self.intent_commitment.as_deref()
    }

    pub fn access(&self) -> Option<&RelayAccessBinding> {
        self.access.as_ref()
    }

    pub fn route_proof(&self) -> Option<&RelayRouteProof> {
        self.route_proof.as_ref()
    }

    pub fn failure(&self) -> Option<WanSessionFailure> {
        self.failure
    }

    pub fn apply(
        &mut self,
        event: WanSessionEvent,
        now_unix_ms: u64,
    ) -> Result<TransitionResult, WanSessionTransitionError> {
        let target = event.target_phase();
        if self.accepted_events.contains(&event) {
            return Ok(TransitionResult::Duplicate);
        }
        if self.phase.is_terminal() {
            return Err(WanSessionTransitionError::Terminal);
        }
        if now_unix_ms >= self.identity.deadline_unix_ms {
            return self.fail(WanSessionFailure::DeadlineExceeded);
        }
        if target <= self.phase {
            return self.fail(WanSessionFailure::ConflictingDuplicate);
        }
        if let WanSessionEvent::Failed(failure) = event {
            self.set_terminal_failure(failure);
            return Ok(TransitionResult::Applied);
        }
        if matches!(event, WanSessionEvent::Closed) {
            self.phase = WanSessionPhase::Closed;
            self.accepted_events.push(event);
            return Ok(TransitionResult::Applied);
        }
        if self.phase.next() != Some(target) {
            return self.fail(WanSessionFailure::InvalidTransition);
        }

        let semantic_result = match &event {
            WanSessionEvent::BackendBound { request_commitment } => {
                if is_digest(request_commitment) {
                    self.request_commitment = Some(request_commitment.clone());
                    Ok(())
                } else {
                    Err(WanSessionFailure::IdentityMismatch)
                }
            }
            WanSessionEvent::AwaitingConsent { intent_commitment } => {
                if is_digest(intent_commitment) {
                    self.intent_commitment = Some(intent_commitment.clone());
                    Ok(())
                } else {
                    Err(WanSessionFailure::IdentityMismatch)
                }
            }
            WanSessionEvent::Granted(grant) => {
                if self.request_commitment.as_deref() == Some(grant.request_commitment())
                    && now_unix_ms < grant.grant_expires_at_ms()
                    && now_unix_ms < grant.policy_expires_at_ms()
                    && grant.grant_expires_at_ms() <= self.identity.deadline_unix_ms
                {
                    self.grant = Some(grant.clone());
                    Ok(())
                } else {
                    Err(WanSessionFailure::PolicyMismatch)
                }
            }
            WanSessionEvent::AccessBound(access) => {
                if self
                    .grant
                    .as_ref()
                    .is_some_and(|grant| grant.policy_revision() == access.policy_revision())
                    && access.generation() == 0
                {
                    self.access = Some(access.clone());
                    Ok(())
                } else {
                    Err(WanSessionFailure::RouteMismatch)
                }
            }
            WanSessionEvent::Negotiating => Ok(()),
            WanSessionEvent::RelayVerified(proof) => {
                if proof.is_relay_to_relay() && self.access.as_ref() == Some(proof.access()) {
                    self.route_proof = Some(proof.clone());
                    Ok(())
                } else {
                    Err(WanSessionFailure::RouteMismatch)
                }
            }
            WanSessionEvent::Streaming => {
                if self.route_proof.is_some() {
                    Ok(())
                } else {
                    Err(WanSessionFailure::RouteMismatch)
                }
            }
            WanSessionEvent::Closed | WanSessionEvent::Failed(_) => unreachable!(),
        };
        if let Err(failure) = semantic_result {
            return self.fail(failure);
        }

        self.phase = target;
        self.accepted_events.push(event);
        Ok(TransitionResult::Applied)
    }

    fn fail(
        &mut self,
        failure: WanSessionFailure,
    ) -> Result<TransitionResult, WanSessionTransitionError> {
        self.set_terminal_failure(failure);
        Err(WanSessionTransitionError::Rejected(failure))
    }

    fn set_terminal_failure(&mut self, failure: WanSessionFailure) {
        self.phase = WanSessionPhase::Failed;
        self.failure = Some(failure);
        self.accepted_events.push(WanSessionEvent::Failed(failure));
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WanSessionTransitionError {
    #[error("WAN session transition rejected")]
    Rejected(WanSessionFailure),
    #[error("WAN session is terminal")]
    Terminal,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WanSessionModelError {
    #[error("invalid WAN session identity")]
    InvalidIdentity,
    #[error("invalid WAN session policy")]
    InvalidPolicy,
    #[error("invalid WAN relay route")]
    InvalidRoute,
}

fn is_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_BYTES
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_safe_route_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ROUTE_IDENTIFIER_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
