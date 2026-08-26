use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

const ROUTE_WILDCARD: &str = "*";
const SUPPORTED_EXACT_ROUTES: &[&str] = &["direct", "relay", "quic", "none"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GatePolicy {
    pub id: String,
    #[serde(default)]
    pub required_scenarios: Vec<String>,
    #[serde(default)]
    pub allow_skips: Vec<AllowedSkip>,
    #[serde(default)]
    pub thresholds: Vec<ThresholdRule>,
    #[serde(default)]
    pub secure_lan_requirements: Option<SecureLanRequirements>,
    #[serde(default)]
    pub security_negative_requirements: Option<SecurityNegativeRequirements>,
    #[serde(default)]
    pub multi_region_relay_requirements: Option<MultiRegionRelayRequirements>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AllowedSkip {
    pub scenario: String,
    pub capability: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRule {
    pub metric: String,
    pub route: String,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecureLanRequirements {
    pub identity_state: String,
    pub authorization_outcome: String,
    pub allowed_authorization_bases: Vec<String>,
    pub scope_authorized: bool,
    pub route_selected: String,
    pub quic_peer_authenticated: bool,
    pub min_real_frames_presented: u64,
    pub control_input_authenticated: bool,
    pub min_control_events_injected: u64,
    pub cleanup_completed: bool,
    pub min_audit_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityNegativeRequirements {
    pub attempts: Vec<SecurityNegativeAttemptRule>,
    pub require_rejected: bool,
    pub max_sender_tasks_started: u64,
    pub max_receiver_tasks_started: u64,
    pub max_media_packets_sent: u64,
    pub max_media_frames_presented: u64,
    pub max_control_events_injected: u64,
    pub require_cleanup_completed: bool,
    pub min_audit_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityNegativeAttemptRule {
    pub scenario: String,
    pub attempt_kind: String,
    pub rejection_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MultiRegionRelayRequirements {
    pub route_selected: String,
    pub max_node_removal_ms: u64,
    pub max_media_recovery_ms: u64,
    pub min_video_frames_after_recovery: u64,
    pub min_audio_packets_after_recovery: u64,
    pub min_control_events_after_recovery: u64,
    pub require_signed_directory: bool,
    pub require_distinct_regions: bool,
    pub require_distinct_failure_domains: bool,
    pub require_relay_candidate_pair: bool,
    pub require_permissions_unchanged: bool,
    pub require_release_all: bool,
    pub require_cleanup: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("policy id is empty")]
    EmptyPolicyId,
    #[error("policy contains an empty required scenario")]
    EmptyRequiredScenario,
    #[error("policy has no effective threshold, allowed-skip, or security rule")]
    NoEffectiveRule,
    #[error("policy cannot combine specialized validation profiles")]
    AmbiguousSecurityProfile,
    #[error("invalid threshold rule: {0}")]
    InvalidThreshold(String),
    #[error("invalid allowed-skip rule: {0}")]
    InvalidAllowedSkip(String),
    #[error("invalid secure-LAN requirement: {0}")]
    InvalidSecureLanRequirement(String),
    #[error("invalid security-negative requirement: {0}")]
    InvalidSecurityNegativeRequirement(String),
    #[error("invalid multi-region relay requirement: {0}")]
    InvalidMultiRegionRelayRequirement(String),
}

pub fn validate_policy(policy: &GatePolicy) -> Result<(), PolicyError> {
    if policy.id.trim().is_empty() {
        return Err(PolicyError::EmptyPolicyId);
    }
    if policy
        .required_scenarios
        .iter()
        .any(|scenario| scenario.trim().is_empty())
    {
        return Err(PolicyError::EmptyRequiredScenario);
    }
    let validation_profiles = usize::from(policy.secure_lan_requirements.is_some())
        + usize::from(policy.security_negative_requirements.is_some())
        + usize::from(policy.multi_region_relay_requirements.is_some());
    if validation_profiles > 1 {
        return Err(PolicyError::AmbiguousSecurityProfile);
    }

    for rule in &policy.thresholds {
        if rule.metric.trim().is_empty() || rule.route.trim().is_empty() {
            return Err(PolicyError::InvalidThreshold(
                "metric and route must be non-empty".to_owned(),
            ));
        }
        if !is_supported_route_selector(&rule.route) {
            return Err(PolicyError::InvalidThreshold(format!(
                "unsupported route selector: {}; expected one of direct, relay, quic, none, or *",
                rule.route
            )));
        }
        if rule.min.is_none() && rule.max.is_none() {
            return Err(PolicyError::InvalidThreshold(
                "at least one bound is required".to_owned(),
            ));
        }
        if rule.min.is_some_and(|value| !value.is_finite())
            || rule.max.is_some_and(|value| !value.is_finite())
        {
            return Err(PolicyError::InvalidThreshold(
                "bounds must be finite".to_owned(),
            ));
        }
        if matches!((rule.min, rule.max), (Some(min), Some(max)) if min > max) {
            return Err(PolicyError::InvalidThreshold(
                "minimum exceeds maximum".to_owned(),
            ));
        }
    }

    for rule in &policy.allow_skips {
        if rule.scenario.trim().is_empty()
            || rule.capability.trim().is_empty()
            || rule.reason.trim().is_empty()
        {
            return Err(PolicyError::InvalidAllowedSkip(
                "scenario, capability, and reason must be non-empty".to_owned(),
            ));
        }
    }

    if let Some(requirements) = &policy.secure_lan_requirements {
        if requirements.identity_state.trim().is_empty()
            || requirements.authorization_outcome.trim().is_empty()
            || requirements.route_selected.trim().is_empty()
            || requirements.allowed_authorization_bases.is_empty()
            || requirements
                .allowed_authorization_bases
                .iter()
                .any(|basis| basis.trim().is_empty())
        {
            return Err(PolicyError::InvalidSecureLanRequirement(
                "identity, authorization, route, and allowed bases must be non-empty".to_owned(),
            ));
        }
        if !is_supported_exact_route(&requirements.route_selected) {
            return Err(PolicyError::InvalidSecureLanRequirement(format!(
                "unsupported exact route: {}; expected one of direct, relay, quic, or none",
                requirements.route_selected
            )));
        }
    }

    if let Some(requirements) = &policy.security_negative_requirements {
        validate_negative_attempt_rules(policy, requirements)?;
    }

    if let Some(requirements) = &policy.multi_region_relay_requirements {
        if requirements.route_selected != "relay" {
            return Err(PolicyError::InvalidMultiRegionRelayRequirement(
                "route_selected must be relay".to_owned(),
            ));
        }
        if requirements.max_node_removal_ms == 0
            || requirements.max_media_recovery_ms == 0
            || requirements.min_video_frames_after_recovery == 0
            || requirements.min_audio_packets_after_recovery == 0
            || requirements.min_control_events_after_recovery == 0
        {
            return Err(PolicyError::InvalidMultiRegionRelayRequirement(
                "timing bounds and restored media minima must be positive".to_owned(),
            ));
        }
    }

    if policy.thresholds.is_empty()
        && policy.allow_skips.is_empty()
        && policy.secure_lan_requirements.is_none()
        && policy.security_negative_requirements.is_none()
        && policy.multi_region_relay_requirements.is_none()
    {
        return Err(PolicyError::NoEffectiveRule);
    }

    Ok(())
}

fn is_supported_exact_route(route: &str) -> bool {
    SUPPORTED_EXACT_ROUTES.contains(&route)
}

fn is_supported_route_selector(route: &str) -> bool {
    route == ROUTE_WILDCARD || is_supported_exact_route(route)
}

pub(crate) fn route_selector_matches(selector: &str, selected_route: &str) -> bool {
    selector == ROUTE_WILDCARD || selector == selected_route
}

fn validate_negative_attempt_rules(
    policy: &GatePolicy,
    requirements: &SecurityNegativeRequirements,
) -> Result<(), PolicyError> {
    if requirements.attempts.is_empty() {
        return Err(PolicyError::InvalidSecurityNegativeRequirement(
            "at least one attempt mapping is required".to_owned(),
        ));
    }

    let mut scenarios = HashSet::new();
    let mut attempt_kinds = HashSet::new();
    for attempt in &requirements.attempts {
        if attempt.scenario.trim().is_empty()
            || attempt.attempt_kind.trim().is_empty()
            || attempt.rejection_reason.trim().is_empty()
        {
            return Err(PolicyError::InvalidSecurityNegativeRequirement(
                "scenario, attempt kind, and rejection reason must be non-empty".to_owned(),
            ));
        }
        if !scenarios.insert(attempt.scenario.as_str()) {
            return Err(PolicyError::InvalidSecurityNegativeRequirement(format!(
                "duplicate scenario mapping: {}",
                attempt.scenario
            )));
        }
        if !attempt_kinds.insert(attempt.attempt_kind.as_str()) {
            return Err(PolicyError::InvalidSecurityNegativeRequirement(format!(
                "duplicate attempt-kind mapping: {}",
                attempt.attempt_kind
            )));
        }
    }

    let required_scenarios: HashSet<&str> = policy
        .required_scenarios
        .iter()
        .map(String::as_str)
        .collect();
    if required_scenarios != scenarios {
        return Err(PolicyError::InvalidSecurityNegativeRequirement(
            "attempt mappings must exactly cover required scenarios".to_owned(),
        ));
    }

    Ok(())
}
