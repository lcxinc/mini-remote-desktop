use mrd_relay_control::{
    lease_expires_at, lease_is_fresh, select_relays, FailureDomainId, IdentifierError, RegionId,
    RelayEndpoint, RelayHealthTracker, RelayNodeId, RelayNodeSnapshot, RelayNodeState,
    RelayRejectionCode, RelayScoreWeights, RelaySelectionPolicy, RelayTransport,
    RELAY_LEASE_DURATION_MS,
};

const NOW_MS: u64 = 1_000_000;

fn id(value: &str) -> RelayNodeId {
    RelayNodeId::new(value).expect("valid relay node id")
}

fn region(value: &str) -> RegionId {
    RegionId::new(value).expect("valid region id")
}

fn failure_domain(value: &str) -> FailureDomainId {
    FailureDomainId::new(value).expect("valid failure domain id")
}

fn endpoint(transport: RelayTransport) -> RelayEndpoint {
    RelayEndpoint::new(transport, "relay.example.test", 3478).expect("valid endpoint")
}

fn node(node_id: &str) -> RelayNodeSnapshot {
    RelayNodeSnapshot {
        node_id: id(node_id),
        region: region("ap-east"),
        failure_domain: failure_domain(node_id),
        state: RelayNodeState::Ready,
        lease_expires_at_ms: NOW_MS + RELAY_LEASE_DURATION_MS,
        endpoints: vec![endpoint(RelayTransport::Udp), endpoint(RelayTransport::Tls)],
        active_allocations: 20,
        max_allocations: 100,
        current_egress_bps: 200,
        max_egress_bps: 1_000,
        recent_failure_bps: 100,
        measured_rtt_ms: Some(30),
    }
}

fn policy() -> RelaySelectionPolicy {
    RelaySelectionPolicy {
        preferred_regions: vec![region("ap-east"), region("ap-southeast")],
        accepted_transports: vec![RelayTransport::Udp],
        max_backups: 2,
        soft_allocation_limit_bps: 8_000,
        weights: RelayScoreWeights {
            base_score: 1_000_000,
            region_preference: 100_000,
            rtt_penalty_per_ms: 100,
            allocation_utilization_penalty: 200_000,
            bandwidth_headroom_reward: 100_000,
            recent_failure_penalty: 50_000,
            soft_full_penalty: 120_000,
            degraded_penalty: 80_000,
        },
    }
}

#[test]
fn bounded_identifiers_reject_empty_oversized_and_unsafe_values() {
    assert_eq!(RelayNodeId::new(""), Err(IdentifierError::Empty));
    assert_eq!(
        RelayNodeId::new("x".repeat(65)),
        Err(IdentifierError::TooLong { max: 64 })
    );
    assert_eq!(
        RelayNodeId::new("relay/hkg"),
        Err(IdentifierError::InvalidCharacter { index: 5 })
    );
    assert_eq!(id("relay-hkg_1.example").as_str(), "relay-hkg_1.example");
}

#[test]
fn hard_filters_emit_stable_reason_codes() {
    let mut stale = node("stale");
    stale.lease_expires_at_ms = NOW_MS;

    let mut draining = node("draining");
    draining.state = RelayNodeState::Draining;

    let mut unavailable = node("unavailable");
    unavailable.state = RelayNodeState::Unavailable;

    let mut revoked = node("revoked");
    revoked.state = RelayNodeState::Revoked;

    let mut incompatible = node("incompatible");
    incompatible.endpoints = vec![endpoint(RelayTransport::Tcp)];

    let mut hard_full = node("hard-full");
    hard_full.active_allocations = hard_full.max_allocations;

    let eligible = node("eligible");
    let decision = select_relays(
        &policy(),
        &[
            stale,
            draining,
            unavailable,
            revoked,
            incompatible,
            hard_full,
            eligible,
        ],
        NOW_MS,
    )
    .expect("one node remains eligible");

    assert_eq!(decision.primary.node_id.as_str(), "eligible");
    let reasons: Vec<(&str, RelayRejectionCode, &str)> = decision
        .rejections
        .iter()
        .map(|rejection| {
            (
                rejection.node_id.as_str(),
                rejection.reason,
                rejection.reason.as_str(),
            )
        })
        .collect();
    assert_eq!(
        reasons,
        vec![
            ("draining", RelayRejectionCode::Draining, "draining"),
            (
                "hard-full",
                RelayRejectionCode::HardCapacityReached,
                "hard_capacity_reached"
            ),
            (
                "incompatible",
                RelayRejectionCode::TransportIncompatible,
                "transport_incompatible"
            ),
            ("revoked", RelayRejectionCode::Revoked, "revoked"),
            ("stale", RelayRejectionCode::StaleLease, "stale_lease"),
            (
                "unavailable",
                RelayRejectionCode::Unavailable,
                "unavailable"
            ),
        ]
    );
}

#[test]
fn rejections_are_sorted_by_node_id_and_stable_reason_code() {
    let mut stale_alpha = node("relay-alpha");
    stale_alpha.lease_expires_at_ms = NOW_MS;

    let mut draining_alpha = node("relay-alpha");
    draining_alpha.state = RelayNodeState::Draining;

    let mut unavailable_zulu = node("relay-zulu");
    unavailable_zulu.state = RelayNodeState::Unavailable;

    let eligible = node("eligible");
    let first = select_relays(
        &policy(),
        &[
            unavailable_zulu.clone(),
            stale_alpha.clone(),
            eligible.clone(),
            draining_alpha.clone(),
        ],
        NOW_MS,
    )
    .expect("eligible node remains");
    let second = select_relays(
        &policy(),
        &[draining_alpha, eligible, stale_alpha, unavailable_zulu],
        NOW_MS,
    )
    .expect("eligible node remains");

    let signature = |decision: &mrd_relay_control::RelaySelectionDecision| {
        decision
            .rejections
            .iter()
            .map(|rejection| {
                (
                    rejection.node_id.as_str().to_owned(),
                    rejection.reason.as_str(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(signature(&first), signature(&second));
    assert_eq!(
        signature(&first),
        vec![
            ("relay-alpha".to_owned(), "draining"),
            ("relay-alpha".to_owned(), "stale_lease"),
            ("relay-zulu".to_owned(), "unavailable"),
        ]
    );
}

#[test]
fn selected_candidates_only_expose_accepted_transports() {
    let decision = select_relays(&policy(), &[node("mixed-transports")], NOW_MS)
        .expect("UDP endpoint is compatible");

    assert_eq!(decision.primary.endpoints.len(), 1);
    assert_eq!(decision.primary.endpoints[0].transport, RelayTransport::Udp);
}

#[test]
fn empty_accepted_transports_rejects_nodes() {
    let mut no_transports = policy();
    no_transports.accepted_transports.clear();

    let error = select_relays(&no_transports, &[node("relay-hkg-1")], NOW_MS)
        .expect_err("an empty policy accepts no transports");

    assert_eq!(error.rejections.len(), 1);
    assert_eq!(
        error.rejections[0].reason,
        RelayRejectionCode::TransportIncompatible
    );
}

#[test]
fn soft_full_and_degraded_nodes_remain_eligible_with_penalties() {
    let mut healthy = node("healthy");
    healthy.failure_domain = failure_domain("fd-healthy");

    let mut soft_full = node("soft-full");
    soft_full.failure_domain = failure_domain("fd-soft");
    soft_full.active_allocations = 80;

    let mut degraded = node("degraded");
    degraded.failure_domain = failure_domain("fd-degraded");
    degraded.state = RelayNodeState::Degraded;

    let decision = select_relays(&policy(), &[soft_full, degraded, healthy], NOW_MS)
        .expect("penalized nodes are still eligible");

    assert_eq!(decision.primary.node_id.as_str(), "healthy");
    assert_eq!(decision.backups.len(), 2);
    let soft_score = decision
        .backups
        .iter()
        .find(|candidate| candidate.node_id.as_str() == "soft-full")
        .expect("soft-full node selected as a backup")
        .score;
    let degraded_score = decision
        .backups
        .iter()
        .find(|candidate| candidate.node_id.as_str() == "degraded")
        .expect("degraded node selected as a backup")
        .score;
    assert_eq!(decision.primary.score - soft_score, 240_000);
    assert_eq!(decision.primary.score - degraded_score, 80_000);
}

#[test]
fn scoring_combines_region_rtt_allocations_bandwidth_and_failures_as_integers() {
    let candidate = node("relay-hkg-1");
    let decision = select_relays(&policy(), &[candidate], NOW_MS).expect("eligible relay");

    // 1_000_000 base + 200_000 first-region bonus + 80_000 bandwidth headroom
    // - 3_000 RTT - 40_000 allocation utilization - 500 recent failures.
    assert_eq!(decision.primary.score, 1_236_500);
}

#[test]
fn unknown_rtt_is_scored_conservatively_and_deterministically() {
    let mut low_rtt = node("low-rtt");
    low_rtt.failure_domain = failure_domain("fd-low");
    low_rtt.measured_rtt_ms = Some(5);

    let mut unknown_rtt = node("unknown-rtt");
    unknown_rtt.failure_domain = failure_domain("fd-unknown");
    unknown_rtt.measured_rtt_ms = None;

    let first = select_relays(&policy(), &[unknown_rtt.clone(), low_rtt.clone()], NOW_MS)
        .expect("both relays remain eligible");
    let second = select_relays(&policy(), &[low_rtt, unknown_rtt], NOW_MS)
        .expect("input order does not change the result");

    assert_eq!(first, second);
    assert_eq!(first.primary.node_id.as_str(), "low-rtt");
    assert!(first.backups[0].score <= first.primary.score);
}

#[test]
fn backups_are_selected_from_distinct_failure_domains() {
    let mut primary = node("relay-hkg-1");
    primary.measured_rtt_ms = Some(5);
    primary.failure_domain = failure_domain("az-a");

    let mut same_domain = node("relay-hkg-2");
    same_domain.measured_rtt_ms = Some(10);
    same_domain.failure_domain = failure_domain("az-a");

    let mut backup_one = node("relay-sin-1");
    backup_one.measured_rtt_ms = Some(20);
    backup_one.failure_domain = failure_domain("az-b");

    let mut backup_two = node("relay-nrt-1");
    backup_two.measured_rtt_ms = Some(30);
    backup_two.failure_domain = failure_domain("az-c");

    let decision = select_relays(
        &policy(),
        &[same_domain, backup_two, primary, backup_one],
        NOW_MS,
    )
    .expect("eligible relays");

    assert_eq!(decision.primary.node_id.as_str(), "relay-hkg-1");
    assert_eq!(decision.backups[0].node_id.as_str(), "relay-sin-1");
    assert_eq!(decision.backups[1].node_id.as_str(), "relay-nrt-1");
    assert!(decision
        .backups
        .iter()
        .all(|backup| backup.failure_domain != decision.primary.failure_domain));
    assert_ne!(
        decision.backups[0].failure_domain,
        decision.backups[1].failure_domain
    );
}

#[test]
fn extreme_max_backups_is_bounded_by_available_candidates() {
    let mut primary = node("relay-primary");
    primary.measured_rtt_ms = Some(5);
    primary.failure_domain = failure_domain("fd-primary");

    let mut backup = node("relay-backup");
    backup.measured_rtt_ms = Some(10);
    backup.failure_domain = failure_domain("fd-backup");

    let mut unbounded_policy = policy();
    unbounded_policy.max_backups = usize::MAX;

    let decision = select_relays(&unbounded_policy, &[backup, primary], NOW_MS)
        .expect("the policy limit must not become an allocation request");
    assert_eq!(decision.backups.len(), 1);
    assert_eq!(decision.backups[0].node_id.as_str(), "relay-backup");
}

#[test]
fn equal_scores_use_node_id_as_the_final_stable_tie_breaker() {
    let mut zulu = node("relay-zulu");
    zulu.failure_domain = failure_domain("fd-zulu");
    let mut alpha = node("relay-alpha");
    alpha.failure_domain = failure_domain("fd-alpha");

    let first =
        select_relays(&policy(), &[zulu.clone(), alpha.clone()], NOW_MS).expect("eligible relays");
    let second = select_relays(&policy(), &[alpha, zulu], NOW_MS).expect("eligible relays");

    assert_eq!(first.primary.node_id.as_str(), "relay-alpha");
    assert_eq!(second.primary.node_id.as_str(), "relay-alpha");
}

#[test]
fn recovery_requires_three_consecutive_healthy_heartbeats() {
    let mut health = RelayHealthTracker::new(RelayNodeState::Unavailable);

    assert_eq!(health.record_heartbeat(true), RelayNodeState::Unavailable);
    assert_eq!(health.record_heartbeat(true), RelayNodeState::Unavailable);
    assert_eq!(health.record_heartbeat(false), RelayNodeState::Unavailable);
    assert_eq!(health.healthy_heartbeat_streak(), 0);
    assert_eq!(health.record_heartbeat(true), RelayNodeState::Unavailable);
    assert_eq!(health.record_heartbeat(true), RelayNodeState::Unavailable);
    assert_eq!(health.record_heartbeat(true), RelayNodeState::Ready);
}

#[test]
fn lease_expiry_has_an_exact_fifteen_second_boundary() {
    let heartbeat_at_ms = 42_000;
    let expires_at_ms = lease_expires_at(heartbeat_at_ms);

    assert_eq!(RELAY_LEASE_DURATION_MS, 15_000);
    assert_eq!(expires_at_ms, 57_000);
    assert!(lease_is_fresh(expires_at_ms, 56_999));
    assert!(!lease_is_fresh(expires_at_ms, 57_000));
    assert!(!lease_is_fresh(expires_at_ms, 57_001));
    assert_eq!(lease_expires_at(u64::MAX - 1), u64::MAX);
}

#[test]
fn scoring_saturates_instead_of_overflowing() {
    let mut extreme = node("extreme");
    extreme.measured_rtt_ms = Some(u32::MAX);
    extreme.recent_failure_bps = 10_000;
    let mut extreme_policy = policy();
    extreme_policy.weights = RelayScoreWeights {
        base_score: u64::MAX,
        region_preference: u64::MAX,
        rtt_penalty_per_ms: u64::MAX,
        allocation_utilization_penalty: u64::MAX,
        bandwidth_headroom_reward: u64::MAX,
        recent_failure_penalty: u64::MAX,
        soft_full_penalty: u64::MAX,
        degraded_penalty: u64::MAX,
    };

    let decision = select_relays(&extreme_policy, &[extreme], NOW_MS)
        .expect("saturating score remains selectable");
    assert_eq!(decision.primary.score, 0);
}
