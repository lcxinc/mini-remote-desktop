use crate::policy::route_selector_matches;
use crate::{
    validate_artifact_for_policy, validate_policy, ArtifactError, GatePolicy, RemoteExperienceRun,
    Verdict,
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    pub failures: Vec<String>,
}

impl Evaluation {
    fn invalid(error: ArtifactError) -> Self {
        Self {
            verdict: Verdict::InvalidArtifact,
            failures: vec![error.to_string()],
        }
    }

    fn infra(message: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::InfraFail,
            failures: vec![message.into()],
        }
    }
}

pub fn evaluate(run: &RemoteExperienceRun, policy: &GatePolicy) -> Evaluation {
    if let Err(error) = validate_policy(policy) {
        return Evaluation::infra(format!("policy is invalid: {error}"));
    }
    if let Err(error) = validate_artifact_for_policy(run, policy) {
        return Evaluation::invalid(error);
    }
    if policy.multi_region_relay_requirements.is_some()
        && (run.gate_status == Verdict::InfraFail || run.producer_status == "infra_failed")
    {
        return Evaluation::infra("multi-region relay infrastructure did not produce evidence");
    }

    let mut failures = Vec::new();
    let required = policy
        .required_scenarios
        .iter()
        .any(|scenario| scenario == &run.scenario.id);
    if !required && (run.scenario.required || !policy.required_scenarios.is_empty()) {
        failures.push(format!(
            "scenario is not declared by policy: {}",
            run.scenario.id
        ));
    }
    if required && !run.scenario.required {
        failures.push(format!(
            "policy-required scenario is marked optional by artifact: {}",
            run.scenario.id
        ));
    }
    evaluate_secure_lan_requirements(run, policy, &mut failures);
    evaluate_security_negative_requirements(run, policy, &mut failures);
    evaluate_multi_region_relay_requirements(run, policy, &mut failures);
    if !failures.is_empty() {
        return Evaluation {
            verdict: Verdict::ProductFail,
            failures,
        };
    }

    if required && run.media.profile_downgraded {
        failures.push("required media profile was downgraded".to_owned());
    }
    if run.producer_status != "completed" {
        failures.push(format!("producer status is {}", run.producer_status));
    }

    let mut applicable_thresholds = 0usize;
    for rule in &policy.thresholds {
        if !route_selector_matches(&rule.route, &run.route.selected) {
            continue;
        }
        applicable_thresholds += 1;
        let value = match rule.metric.as_str() {
            "visible_first_frame_ms" => run.present.visible_first_frame_ms,
            _ => None,
        };
        let Some(value) = value else {
            failures.push(format!("threshold metric is unavailable: {}", rule.metric));
            continue;
        };
        if rule.min.is_some_and(|min| value < min) {
            failures.push(format!("{}={} is below minimum", rule.metric, value));
        }
        if rule.max.is_some_and(|max| value > max) {
            failures.push(format!("{}={} exceeds maximum", rule.metric, value));
        }
    }
    if !policy.thresholds.is_empty() && applicable_thresholds == 0 {
        failures.push(format!(
            "no threshold applies to selected route: {}",
            run.route.selected
        ));
    }

    if failures.is_empty() {
        Evaluation {
            verdict: Verdict::Pass,
            failures,
        }
    } else {
        Evaluation {
            verdict: Verdict::ProductFail,
            failures,
        }
    }
}

fn evaluate_multi_region_relay_requirements(
    run: &RemoteExperienceRun,
    policy: &GatePolicy,
    failures: &mut Vec<String>,
) {
    let Some(requirements) = &policy.multi_region_relay_requirements else {
        return;
    };
    let Some(relay) = &run.relay else {
        failures.push("multi-region relay runtime evidence is missing".to_owned());
        return;
    };

    if run.route.selected != requirements.route_selected {
        failures.push(format!(
            "selected route is {}, expected {}",
            run.route.selected, requirements.route_selected
        ));
    }
    if run.route.candidate_pair != "relay/relay" {
        failures.push("route candidate_pair is not relay/relay".to_owned());
    }
    if requirements.require_signed_directory && !relay.directory.signature_verified {
        failures.push("relay directory signature was not verified".to_owned());
    }
    if relay.directory.policy_revision == 0 {
        failures.push("relay directory policy revision is zero".to_owned());
    }
    if relay.directory.expires_at_ms < relay.reservation.expires_at_ms {
        failures.push("relay reservation outlives its signed directory".to_owned());
    }
    if relay.primary.node_id == relay.backup.node_id {
        failures.push("primary and backup relay nodes are identical".to_owned());
    }
    if requirements.require_distinct_regions && relay.primary.region == relay.backup.region {
        failures.push("primary and backup relay regions are identical".to_owned());
    }
    if requirements.require_distinct_failure_domains
        && relay.primary.failure_domain == relay.backup.failure_domain
    {
        failures.push("primary and backup relay failure domains are identical".to_owned());
    }
    if !relay.reservation.committed {
        failures.push("relay capacity reservations were not committed".to_owned());
    }
    if relay.reservation.primary_node_id != relay.primary.node_id
        || relay.reservation.backup_node_id != relay.backup.node_id
    {
        failures.push("relay reservations are not bound to the selected nodes".to_owned());
    }
    if relay.reservation.primary_reservation_id == relay.reservation.backup_reservation_id {
        failures.push("primary and backup relay reservations are identical".to_owned());
    }
    if requirements.require_relay_candidate_pair
        && (relay.selected_pair.local_candidate_type != "relay"
            || relay.selected_pair.remote_candidate_type != "relay"
            || !relay.selected_pair.nominated
            || !relay.selected_pair.runtime_verified)
    {
        failures.push("runtime-selected ICE pair is not a nominated relay/relay pair".to_owned());
    }
    if relay.selected_pair.relay_node_id != relay.backup.node_id {
        failures.push("runtime-selected relay does not name the backup node".to_owned());
    }
    if !matches!(
        relay.selected_pair.transport.as_str(),
        "udp" | "tcp" | "tls"
    ) {
        failures.push(format!(
            "unsupported selected relay transport: {}",
            relay.selected_pair.transport
        ));
    }
    if !relay.allocation.primary_established || !relay.allocation.backup_established {
        failures.push("TURN allocations were not established on both relay nodes".to_owned());
    }
    if relay.allocation.primary_node_id != relay.primary.node_id
        || relay.allocation.backup_node_id != relay.backup.node_id
    {
        failures.push("TURN allocations are not bound to the selected nodes".to_owned());
    }
    if relay.allocation.primary_allocation_id == relay.allocation.backup_allocation_id {
        failures.push("primary and backup TURN allocations are identical".to_owned());
    }
    if relay.allocation.relayed_bytes_before_failure == 0 {
        failures.push("primary TURN allocation relayed no data before failure".to_owned());
    }
    if relay.injected_failure.target_node_id != relay.primary.node_id {
        failures.push("injected failure did not target the primary relay".to_owned());
    }
    if relay.detection.detected_at_ms < relay.injected_failure.injected_at_ms
        || relay.detection.removed_at_ms < relay.detection.detected_at_ms
    {
        failures.push("relay failure detection timestamps are out of order".to_owned());
    } else if relay.detection.removed_at_ms - relay.injected_failure.injected_at_ms
        > requirements.max_node_removal_ms
    {
        failures.push(format!(
            "failed relay removal exceeded {}ms",
            requirements.max_node_removal_ms
        ));
    }
    if relay.generation.before.checked_add(1) != Some(relay.generation.after) {
        failures.push("relay migration generation did not advance exactly once".to_owned());
    }
    if relay.restored_media.backup_node_id != relay.backup.node_id {
        failures.push("restored media does not name the backup relay".to_owned());
    }
    if !relay.restored_media.media_resumed {
        failures.push("media did not resume after relay migration".to_owned());
    }
    if relay.restored_media.resumed_at_ms < relay.injected_failure.injected_at_ms {
        failures.push("media recovery timestamp precedes failure injection".to_owned());
    } else if relay.restored_media.resumed_at_ms - relay.injected_failure.injected_at_ms
        > requirements.max_media_recovery_ms
    {
        failures.push(format!(
            "media recovery exceeded {}ms",
            requirements.max_media_recovery_ms
        ));
    }
    if relay.restored_media.video_frames_after_recovery
        < requirements.min_video_frames_after_recovery
    {
        failures.push("restored video frame evidence is below minimum".to_owned());
    }
    if relay.restored_media.audio_packets_after_recovery
        < requirements.min_audio_packets_after_recovery
    {
        failures.push("restored audio packet evidence is below minimum".to_owned());
    }
    if relay.restored_media.control_events_after_recovery
        < requirements.min_control_events_after_recovery
    {
        failures.push("restored control evidence is below minimum".to_owned());
    }
    if requirements.require_permissions_unchanged && !relay.restored_media.permissions_unchanged {
        failures.push("session permissions changed during relay migration".to_owned());
    }
    if requirements.require_release_all && !relay.restored_media.release_all_recorded {
        failures.push("ReleaseAll was not recorded before migration".to_owned());
    }
    if requirements.require_cleanup
        && !(relay.cleanup.reservation_released
            && relay.cleanup.old_allocation_closed
            && relay.cleanup.replacement_allocation_closed
            && relay.cleanup.input_thawed
            && relay.cleanup.lab_reset)
    {
        failures.push("multi-region relay cleanup is incomplete".to_owned());
    }
}

fn evaluate_secure_lan_requirements(
    run: &RemoteExperienceRun,
    policy: &GatePolicy,
    failures: &mut Vec<String>,
) {
    let Some(requirements) = &policy.secure_lan_requirements else {
        return;
    };
    let Some(security) = &run.security else {
        failures.push("secure LAN security evidence is missing".to_owned());
        return;
    };
    let Some(side_effects) = &run.side_effects else {
        failures.push("secure LAN side-effect evidence is missing".to_owned());
        return;
    };

    if security.identity_state != requirements.identity_state {
        failures.push(format!(
            "identity state is {}, expected {}",
            security.identity_state, requirements.identity_state
        ));
    }
    if security.authorization_outcome != requirements.authorization_outcome {
        failures.push(format!(
            "authorization outcome is {}, expected {}",
            security.authorization_outcome, requirements.authorization_outcome
        ));
    }
    if !requirements
        .allowed_authorization_bases
        .contains(&security.authorization_basis)
    {
        failures.push(format!(
            "authorization basis is not allowed: {}",
            security.authorization_basis
        ));
    }
    if security.scope_authorized != requirements.scope_authorized {
        failures.push(format!(
            "scope authorization is {}, expected {}",
            security.scope_authorized, requirements.scope_authorized
        ));
    }
    if run.route.selected != requirements.route_selected {
        failures.push(format!(
            "selected route is {}, expected {}",
            run.route.selected, requirements.route_selected
        ));
    }
    if security.quic_peer_authenticated != requirements.quic_peer_authenticated {
        failures.push(format!(
            "QUIC peer authentication is {}, expected {}",
            security.quic_peer_authenticated, requirements.quic_peer_authenticated
        ));
    }
    if security.rejected {
        failures.push("authorized secure LAN session was rejected".to_owned());
    }
    if side_effects.media_frames_presented < requirements.min_real_frames_presented {
        failures.push(format!(
            "media_frames_presented={} is below minimum {}",
            side_effects.media_frames_presented, requirements.min_real_frames_presented
        ));
    }
    if security.control_input_authenticated != requirements.control_input_authenticated {
        failures.push(format!(
            "control input authentication is {}, expected {}",
            security.control_input_authenticated, requirements.control_input_authenticated
        ));
    }
    if side_effects.control_events_injected < requirements.min_control_events_injected {
        failures.push(format!(
            "control_events_injected={} is below minimum {}",
            side_effects.control_events_injected, requirements.min_control_events_injected
        ));
    }
    if security.cleanup_completed != requirements.cleanup_completed {
        failures.push(format!(
            "cleanup completion is {}, expected {}",
            security.cleanup_completed, requirements.cleanup_completed
        ));
    }
    if run.audit_event_ids.len() < requirements.min_audit_events {
        failures.push(format!(
            "audit_event_ids count {} is below minimum {}",
            run.audit_event_ids.len(),
            requirements.min_audit_events
        ));
    }
}

fn evaluate_security_negative_requirements(
    run: &RemoteExperienceRun,
    policy: &GatePolicy,
    failures: &mut Vec<String>,
) {
    let Some(requirements) = &policy.security_negative_requirements else {
        return;
    };
    let Some(security) = &run.security else {
        failures.push("security-negative evidence is missing".to_owned());
        return;
    };
    let Some(side_effects) = &run.side_effects else {
        failures.push("security-negative side-effect evidence is missing".to_owned());
        return;
    };

    let Some(attempt) = requirements
        .attempts
        .iter()
        .find(|attempt| attempt.scenario == run.scenario.id)
    else {
        failures.push(format!(
            "security-negative scenario is not mapped by policy: {}",
            run.scenario.id
        ));
        return;
    };
    if security.attempt_kind != attempt.attempt_kind {
        failures.push(format!(
            "security attempt kind is {}, expected {} for {}",
            security.attempt_kind, attempt.attempt_kind, run.scenario.id
        ));
    }
    if security.rejection_reason != attempt.rejection_reason {
        failures.push(format!(
            "security rejection reason is {}, expected {} for {}",
            security.rejection_reason, attempt.rejection_reason, run.scenario.id
        ));
    }
    if requirements.require_rejected && !security.rejected {
        failures.push("security attempt was not rejected".to_owned());
    }
    for (name, actual, maximum) in [
        (
            "sender_tasks_started",
            side_effects.sender_tasks_started,
            requirements.max_sender_tasks_started,
        ),
        (
            "receiver_tasks_started",
            side_effects.receiver_tasks_started,
            requirements.max_receiver_tasks_started,
        ),
        (
            "media_packets_sent",
            side_effects.media_packets_sent,
            requirements.max_media_packets_sent,
        ),
        (
            "media_frames_presented",
            side_effects.media_frames_presented,
            requirements.max_media_frames_presented,
        ),
        (
            "control_events_injected",
            side_effects.control_events_injected,
            requirements.max_control_events_injected,
        ),
    ] {
        if actual > maximum {
            failures.push(format!("{name}={actual} exceeds maximum {maximum}"));
        }
    }
    if requirements.require_cleanup_completed && !security.cleanup_completed {
        failures.push("security-negative cleanup did not complete".to_owned());
    }
    if run.audit_event_ids.len() < requirements.min_audit_events {
        failures.push(format!(
            "audit_event_ids count {} is below minimum {}",
            run.audit_event_ids.len(),
            requirements.min_audit_events
        ));
    }
}

pub fn evaluate_allowed_skip(
    policy: &GatePolicy,
    scenario: &str,
    capability: &str,
    reason: &str,
) -> Evaluation {
    if let Err(error) = validate_policy(policy) {
        return Evaluation::infra(format!("policy is invalid: {error}"));
    }
    let allowed = policy.allow_skips.iter().any(|rule| {
        rule.scenario == scenario && rule.capability == capability && rule.reason == reason
    });
    if allowed {
        Evaluation {
            verdict: Verdict::AllowedSkip,
            failures: Vec::new(),
        }
    } else {
        Evaluation {
            verdict: Verdict::ProductFail,
            failures: vec![format!(
                "skip is not allowlisted: scenario={scenario}, capability={capability}, reason={reason}"
            )],
        }
    }
}
