use std::collections::HashSet;

use crate::{
    lease_is_fresh, FailureDomainId, RegionId, RelayEndpoint, RelayNodeId, RelayNodeSnapshot,
    RelayNodeState, RelayTransport,
};

const BASIS_POINTS: u64 = 10_000;
const UNKNOWN_RTT_MS: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayScoreWeights {
    pub base_score: u64,
    pub region_preference: u64,
    pub rtt_penalty_per_ms: u64,
    pub allocation_utilization_penalty: u64,
    pub bandwidth_headroom_reward: u64,
    pub recent_failure_penalty: u64,
    pub soft_full_penalty: u64,
    pub degraded_penalty: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelaySelectionPolicy {
    pub preferred_regions: Vec<RegionId>,
    /// Transports clients are permitted to use. An empty list accepts no relay endpoints.
    pub accepted_transports: Vec<RelayTransport>,
    pub max_backups: usize,
    pub soft_allocation_limit_bps: u16,
    pub weights: RelayScoreWeights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayRejectionCode {
    StaleLease,
    Enrolling,
    Draining,
    Unavailable,
    Revoked,
    TransportIncompatible,
    HardCapacityReached,
}

impl RelayRejectionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleLease => "stale_lease",
            Self::Enrolling => "enrolling",
            Self::Draining => "draining",
            Self::Unavailable => "unavailable",
            Self::Revoked => "revoked",
            Self::TransportIncompatible => "transport_incompatible",
            Self::HardCapacityReached => "hard_capacity_reached",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRejection {
    pub node_id: RelayNodeId,
    pub reason: RelayRejectionCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelaySelectedCandidate {
    pub node_id: RelayNodeId,
    pub region: RegionId,
    pub failure_domain: FailureDomainId,
    pub endpoints: Vec<RelayEndpoint>,
    pub score: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelaySelectionDecision {
    pub primary: RelaySelectedCandidate,
    pub backups: Vec<RelaySelectedCandidate>,
    pub rejections: Vec<RelayRejection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelaySelectionError {
    pub rejections: Vec<RelayRejection>,
}

pub fn select_relays(
    policy: &RelaySelectionPolicy,
    nodes: &[RelayNodeSnapshot],
    now_ms: u64,
) -> Result<RelaySelectionDecision, RelaySelectionError> {
    let mut candidates = Vec::with_capacity(nodes.len());
    let mut rejections = Vec::new();

    for node in nodes {
        if let Some(reason) = rejection_reason(policy, node, now_ms) {
            rejections.push(RelayRejection {
                node_id: node.node_id.clone(),
                reason,
            });
        } else {
            candidates.push(candidate(policy, node));
        }
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    rejections.sort_by(|left, right| {
        left.node_id
            .cmp(&right.node_id)
            .then_with(|| left.reason.as_str().cmp(right.reason.as_str()))
    });

    if candidates.is_empty() {
        return Err(RelaySelectionError { rejections });
    }

    let primary = candidates.remove(0);
    let selected_domain_capacity = policy.max_backups.min(candidates.len()).saturating_add(1);
    let mut selected_domains = HashSet::with_capacity(selected_domain_capacity);
    selected_domains.insert(primary.failure_domain.clone());
    let backups = candidates
        .into_iter()
        .filter(|candidate| selected_domains.insert(candidate.failure_domain.clone()))
        .take(policy.max_backups)
        .collect();

    Ok(RelaySelectionDecision {
        primary,
        backups,
        rejections,
    })
}

fn rejection_reason(
    policy: &RelaySelectionPolicy,
    node: &RelayNodeSnapshot,
    now_ms: u64,
) -> Option<RelayRejectionCode> {
    if !lease_is_fresh(node.lease_expires_at_ms, now_ms) {
        return Some(RelayRejectionCode::StaleLease);
    }
    match node.state {
        RelayNodeState::Ready | RelayNodeState::Degraded => {}
        RelayNodeState::Enrolling => return Some(RelayRejectionCode::Enrolling),
        RelayNodeState::Draining => return Some(RelayRejectionCode::Draining),
        RelayNodeState::Unavailable => return Some(RelayRejectionCode::Unavailable),
        RelayNodeState::Revoked => return Some(RelayRejectionCode::Revoked),
    }
    if !has_compatible_transport(policy, node) {
        return Some(RelayRejectionCode::TransportIncompatible);
    }
    if node.active_allocations >= node.max_allocations
        || node.current_egress_bps >= node.max_egress_bps
    {
        return Some(RelayRejectionCode::HardCapacityReached);
    }
    None
}

fn has_compatible_transport(policy: &RelaySelectionPolicy, node: &RelayNodeSnapshot) -> bool {
    node.endpoints
        .iter()
        .any(|endpoint| transport_is_accepted(policy, endpoint.transport))
}

fn transport_is_accepted(policy: &RelaySelectionPolicy, transport: RelayTransport) -> bool {
    policy.accepted_transports.contains(&transport)
}

fn candidate(policy: &RelaySelectionPolicy, node: &RelayNodeSnapshot) -> RelaySelectedCandidate {
    RelaySelectedCandidate {
        node_id: node.node_id.clone(),
        region: node.region.clone(),
        failure_domain: node.failure_domain.clone(),
        endpoints: node
            .endpoints
            .iter()
            .filter(|endpoint| transport_is_accepted(policy, endpoint.transport))
            .cloned()
            .collect(),
        score: score(policy, node),
    }
}

fn score(policy: &RelaySelectionPolicy, node: &RelayNodeSnapshot) -> u64 {
    let allocation_utilization_bps = ratio_bps(
        u64::from(node.active_allocations),
        u64::from(node.max_allocations),
    );
    let bandwidth_utilization_bps = ratio_bps(node.current_egress_bps, node.max_egress_bps);
    let bandwidth_headroom_bps = BASIS_POINTS.saturating_sub(bandwidth_utilization_bps);

    let region_reward = policy
        .preferred_regions
        .iter()
        .position(|region| region == &node.region)
        .map(|index| {
            let preference_rank = policy.preferred_regions.len().saturating_sub(index);
            u64::try_from(preference_rank)
                .unwrap_or(u64::MAX)
                .saturating_mul(policy.weights.region_preference)
        })
        .unwrap_or(0);
    let rewards = policy
        .weights
        .base_score
        .saturating_add(region_reward)
        .saturating_add(weighted_bps(
            bandwidth_headroom_bps,
            policy.weights.bandwidth_headroom_reward,
        ));

    let mut penalties = u64::from(node.measured_rtt_ms.unwrap_or(UNKNOWN_RTT_MS))
        .saturating_mul(policy.weights.rtt_penalty_per_ms)
        .saturating_add(weighted_bps(
            allocation_utilization_bps,
            policy.weights.allocation_utilization_penalty,
        ))
        .saturating_add(weighted_bps(
            u64::from(node.recent_failure_bps).min(BASIS_POINTS),
            policy.weights.recent_failure_penalty,
        ));
    if allocation_utilization_bps >= u64::from(policy.soft_allocation_limit_bps) {
        penalties = penalties.saturating_add(policy.weights.soft_full_penalty);
    }
    if node.state == RelayNodeState::Degraded {
        penalties = penalties.saturating_add(policy.weights.degraded_penalty);
    }

    rewards.saturating_sub(penalties)
}

fn ratio_bps(current: u64, maximum: u64) -> u64 {
    if maximum == 0 {
        return BASIS_POINTS;
    }
    let scaled = u128::from(current.min(maximum)) * u128::from(BASIS_POINTS);
    clamp_u128_to_u64(scaled / u128::from(maximum))
}

fn weighted_bps(value_bps: u64, weight: u64) -> u64 {
    let weighted = u128::from(value_bps) * u128::from(weight) / u128::from(BASIS_POINTS);
    clamp_u128_to_u64(weighted)
}

fn clamp_u128_to_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{ratio_bps, weighted_bps};

    #[test]
    fn ratio_preserves_precision_near_u64_max() {
        assert_eq!(ratio_bps(u64::MAX - 1, u64::MAX), 9_999);
        assert_eq!(ratio_bps(u64::MAX, u64::MAX), 10_000);
    }

    #[test]
    fn full_basis_point_weight_preserves_u64_max() {
        assert_eq!(weighted_bps(10_000, u64::MAX), u64::MAX);
    }
}
