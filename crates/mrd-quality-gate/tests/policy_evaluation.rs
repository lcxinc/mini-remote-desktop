use mrd_quality_gate::{
    evaluate, evaluate_allowed_skip, validate_policy, Evaluation, GatePolicy, Verdict,
};

fn policy(name: &str) -> GatePolicy {
    let raw = match name {
        "strict-required-metrics.v1.json" => {
            include_str!("../../../tests/quality-gates/policies/strict-required-metrics.v1.json")
        }
        "diagnostic-allowed-skip.v1.json" => {
            include_str!("../../../tests/quality-gates/policies/diagnostic-allowed-skip.v1.json")
        }
        "windows-secure-lan.v1.json" => {
            include_str!("../../../tests/quality-gates/policies/windows-secure-lan.v1.json")
        }
        "windows-security-negative.v1.json" => {
            include_str!("../../../tests/quality-gates/policies/windows-security-negative.v1.json")
        }
        "windows-multi-region-relay.v1.json" => {
            include_str!("../../../tests/quality-gates/policies/windows-multi-region-relay.v1.json")
        }
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str(raw).unwrap()
}

fn fixture(name: &str) -> mrd_quality_gate::RemoteExperienceRun {
    let raw = match name {
        "missing-present.json" => {
            include_str!("../../../tests/quality-gates/fixtures/missing-present.json")
        }
        "valid-direct.json" => {
            include_str!("../../../tests/quality-gates/fixtures/valid-direct.json")
        }
        "security-untrusted.json" => {
            include_str!("../../../tests/quality-gates/fixtures/security-untrusted.json")
        }
        "security-replay.json" => {
            include_str!("../../../tests/quality-gates/fixtures/security-replay.json")
        }
        "security-revoked.json" => {
            include_str!("../../../tests/quality-gates/fixtures/security-revoked.json")
        }
        "security-wrong-scope.json" => {
            include_str!("../../../tests/quality-gates/fixtures/security-wrong-scope.json")
        }
        "security-certificate-substitution.json" => include_str!(
            "../../../tests/quality-gates/fixtures/security-certificate-substitution.json"
        ),
        "multi-region-relay-valid.json" => {
            include_str!("../../../tests/quality-gates/fixtures/multi-region-relay-valid.json")
        }
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str(raw).unwrap()
}

#[test]
fn missing_required_metric_is_invalid_not_skipped() {
    let result = evaluate(
        &fixture("missing-present.json"),
        &policy("strict-required-metrics.v1.json"),
    );
    assert_eq!(result.verdict, Verdict::InvalidArtifact);
}

#[test]
fn release_profile_downgrade_is_product_failure() {
    let mut run = fixture("valid-direct.json");
    run.media.profile_downgraded = true;
    let result = evaluate(&run, &policy("strict-required-metrics.v1.json"));
    assert_eq!(result.verdict, Verdict::ProductFail);
}

#[test]
fn explicitly_allowlisted_capability_skip_is_allowed() {
    let result: Evaluation = evaluate_allowed_skip(
        &policy("diagnostic-allowed-skip.v1.json"),
        "diagnostic.local",
        "gpu_probe",
        "hardware_unavailable",
    );
    assert_eq!(result.verdict, Verdict::AllowedSkip);
}

#[test]
fn every_security_negative_fixture_passes_only_as_a_clean_rejection() {
    let policy = policy("windows-security-negative.v1.json");
    for name in [
        "security-untrusted.json",
        "security-replay.json",
        "security-revoked.json",
        "security-wrong-scope.json",
        "security-certificate-substitution.json",
    ] {
        let result = evaluate(&fixture(name), &policy);
        assert_eq!(
            result.verdict,
            Verdict::Pass,
            "{name}: {:?}",
            result.failures
        );
    }
}

#[test]
fn security_negative_gate_rejects_missing_rejection_or_any_side_effect() {
    let policy = policy("windows-security-negative.v1.json");
    let raw = include_str!("../../../tests/quality-gates/fixtures/security-replay.json");
    let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
    value["security"]["rejected"] = serde_json::json!(false);
    let run = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);

    value["security"]["rejected"] = serde_json::json!(true);
    value["side_effects"]["control_events_injected"] = serde_json::json!(1);
    let run = serde_json::from_value(value).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);
}

fn secure_positive_run() -> mrd_quality_gate::RemoteExperienceRun {
    let raw = include_str!("../../../tests/quality-gates/fixtures/valid-direct.json");
    let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
    value["run_id"] = serde_json::json!("secure-positive-001");
    value["scenario"] = serde_json::json!({
        "id": "cross.e2e.secure_remote_display",
        "required": true
    });
    value["route"] = serde_json::json!({
        "requested": "quic",
        "selected": "quic",
        "candidate_pair": "controller:target"
    });
    value["security"] = serde_json::json!({
        "attempt_kind": "authorized_session",
        "identity_state": "trusted",
        "authorization_outcome": "granted",
        "authorization_basis": "consent",
        "scope_authorized": true,
        "quic_peer_authenticated": true,
        "control_input_authenticated": true,
        "rejected": false,
        "rejection_reason": "none",
        "cleanup_completed": true
    });
    value["side_effects"] = serde_json::json!({
        "sender_tasks_started": 1,
        "receiver_tasks_started": 1,
        "media_packets_sent": 20,
        "media_frames_presented": 10,
        "control_events_injected": 1
    });
    serde_json::from_value(value).unwrap()
}

#[test]
fn secure_lan_positive_gate_enforces_authenticated_quic_input_and_real_frames() {
    let policy = policy("windows-secure-lan.v1.json");
    let run = secure_positive_run();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::Pass);

    let mut value = serde_json::to_value(&run).unwrap();
    value["security"]["quic_peer_authenticated"] = serde_json::json!(false);
    let unauthenticated = serde_json::from_value(value).unwrap();
    assert_eq!(
        evaluate(&unauthenticated, &policy).verdict,
        Verdict::ProductFail
    );

    let mut value = serde_json::to_value(&run).unwrap();
    value["side_effects"]["media_frames_presented"] = serde_json::json!(0);
    let no_frames = serde_json::from_value(value).unwrap();
    assert_eq!(evaluate(&no_frames, &policy).verdict, Verdict::ProductFail);
}

#[test]
fn ordinary_policy_cannot_be_relaxed_by_security_evidence() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/valid-direct.json");
    let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
    value["security"] = serde_json::json!({
        "attempt_kind": "authorized_session",
        "identity_state": "trusted",
        "authorization_outcome": "granted",
        "authorization_basis": "consent",
        "scope_authorized": true,
        "quic_peer_authenticated": true,
        "control_input_authenticated": true,
        "rejected": false,
        "rejection_reason": "none",
        "cleanup_completed": true
    });
    value["side_effects"] = serde_json::json!({
        "sender_tasks_started": 1,
        "receiver_tasks_started": 1,
        "media_packets_sent": 1,
        "media_frames_presented": 1,
        "control_events_injected": 1
    });
    value["present"]["input_to_photon_ms"] = serde_json::json!([]);
    value["resources"] = serde_json::json!({
        "cpu_percent": [],
        "gpu_percent": [],
        "rss_bytes": [],
        "vram_bytes": []
    });

    let run = serde_json::from_value(value).unwrap();
    assert_eq!(
        evaluate(&run, &policy("strict-required-metrics.v1.json")).verdict,
        Verdict::InvalidArtifact
    );
}

#[test]
fn unknown_policy_fields_are_rejected_including_nested_rules() {
    let top_level_typo = r#"{
        "id": "secure-policy-with-typo",
        "required_scenarios": ["cross.e2e.secure_remote_display"],
        "secure_lna_requirements": {}
    }"#;
    assert!(serde_json::from_str::<GatePolicy>(top_level_typo).is_err());

    let nested_typo =
        include_str!("../../../tests/quality-gates/policies/windows-secure-lan.v1.json").replace(
            "\"min_audit_events\": 1",
            "\"min_audit_events\": 1, \"unexpected\": true",
        );
    assert!(serde_json::from_str::<GatePolicy>(&nested_typo).is_err());
}

#[test]
fn policy_without_an_effective_rule_is_infrastructure_failure() {
    let policy: GatePolicy = serde_json::from_str(
        r#"{
            "id": "empty-policy",
            "required_scenarios": ["windows.1080p60.direct"],
            "allow_skips": [],
            "thresholds": []
        }"#,
    )
    .unwrap();

    assert_eq!(
        evaluate(&fixture("valid-direct.json"), &policy).verdict,
        Verdict::InfraFail
    );
}

#[test]
fn security_negative_rule_binds_scenario_attempt_and_rejection_reason() {
    let policy = policy("windows-security-negative.v1.json");
    let raw = include_str!("../../../tests/quality-gates/fixtures/security-replay.json");
    let original: serde_json::Value = serde_json::from_str(raw).unwrap();

    let mut wrong_attempt = original.clone();
    wrong_attempt["security"]["attempt_kind"] = serde_json::json!("untrusted");
    let run = serde_json::from_value(wrong_attempt).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);

    let mut wrong_reason = original;
    wrong_reason["security"]["rejection_reason"] = serde_json::json!("trust_required");
    let run = serde_json::from_value(wrong_reason).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);
}

#[test]
fn structurally_invalid_secure_artifact_is_invalid_before_policy_evaluation() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/missing-present.json");
    let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
    value["scenario"]["id"] = serde_json::json!("cross.e2e.secure_remote_display");
    value["route"]["requested"] = serde_json::json!("quic");
    value["route"]["selected"] = serde_json::json!("quic");
    value["audit_event_ids"] = serde_json::json!([]);
    let run = serde_json::from_value(value).unwrap();

    assert_eq!(
        evaluate(&run, &policy("windows-secure-lan.v1.json")).verdict,
        Verdict::InvalidArtifact
    );
}

#[test]
fn policy_required_scenario_cannot_be_marked_optional_by_artifact() {
    let mut run = fixture("valid-direct.json");
    run.scenario.required = false;

    let result = evaluate(&run, &policy("strict-required-metrics.v1.json"));

    assert_eq!(result.verdict, Verdict::ProductFail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.contains("marked optional")));
}

#[test]
fn artifact_cannot_replace_a_policy_required_scenario_with_an_arbitrary_id() {
    let mut run = fixture("valid-direct.json");
    run.scenario.id = "artifact.chosen.scenario".to_owned();
    run.scenario.required = false;

    let result = evaluate(&run, &policy("strict-required-metrics.v1.json"));

    assert_eq!(result.verdict, Verdict::ProductFail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.contains("scenario is not declared by policy")));
}

#[test]
fn unsupported_threshold_route_is_an_invalid_policy_instead_of_a_noop() {
    let mut policy = policy("strict-required-metrics.v1.json");
    policy.thresholds[0].route = "diretc".to_owned();

    assert!(validate_policy(&policy).is_err());
    assert_eq!(
        evaluate(&fixture("valid-direct.json"), &policy).verdict,
        Verdict::InfraFail
    );
}

#[test]
fn supported_exact_route_without_an_applicable_threshold_fails_closed() {
    let mut policy = policy("strict-required-metrics.v1.json");
    policy.thresholds[0].route = "relay".to_owned();

    let result = evaluate(&fixture("valid-direct.json"), &policy);

    assert_eq!(result.verdict, Verdict::ProductFail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.contains("no threshold applies to selected route")));
}

#[test]
fn explicit_route_wildcard_applies_threshold_to_any_selected_route() {
    let mut policy = policy("strict-required-metrics.v1.json");
    policy.thresholds[0].route = "*".to_owned();
    let mut run = fixture("valid-direct.json");
    run.route.selected = "quic".to_owned();
    run.present.visible_first_frame_ms = Some(5_000.0);

    let result = evaluate(&run, &policy);

    assert_eq!(result.verdict, Verdict::ProductFail);
    assert!(result
        .failures
        .iter()
        .any(|failure| failure.contains("visible_first_frame_ms=5000 exceeds maximum")));
}

#[test]
fn unsupported_secure_lan_route_is_an_invalid_policy() {
    let mut policy = policy("windows-secure-lan.v1.json");
    policy
        .secure_lan_requirements
        .as_mut()
        .unwrap()
        .route_selected = "quiic".to_owned();

    assert!(validate_policy(&policy).is_err());
    assert_eq!(
        evaluate(&secure_positive_run(), &policy).verdict,
        Verdict::InfraFail
    );
}

#[test]
fn complete_multi_region_runtime_evidence_passes() {
    let result = evaluate(
        &fixture("multi-region-relay-valid.json"),
        &policy("windows-multi-region-relay.v1.json"),
    );
    assert_eq!(result.verdict, Verdict::Pass, "{:?}", result.failures);
}

#[test]
fn metadata_only_or_non_relay_selected_pair_cannot_pass() {
    let policy = policy("windows-multi-region-relay.v1.json");
    let run = fixture("multi-region-relay-valid.json");
    let mut value = serde_json::to_value(run).unwrap();
    value["relay"]["selected_pair"]["runtime_verified"] = serde_json::json!(false);
    let run = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);

    value["relay"]["selected_pair"]["runtime_verified"] = serde_json::json!(true);
    value["relay"]["selected_pair"]["remote_candidate_type"] = serde_json::json!("host");
    let run = serde_json::from_value(value).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);
}

#[test]
fn relay_gate_enforces_failure_domain_generation_recovery_and_cleanup() {
    let policy = policy("windows-multi-region-relay.v1.json");
    let run = fixture("multi-region-relay-valid.json");
    let original = serde_json::to_value(run).unwrap();
    for mutation in [
        ("backup", "failure_domain", serde_json::json!("rack-a")),
        ("generation", "after", serde_json::json!(0)),
        ("restored_media", "media_resumed", serde_json::json!(false)),
        ("cleanup", "lab_reset", serde_json::json!(false)),
    ] {
        let mut value = original.clone();
        value["relay"][mutation.0][mutation.1] = mutation.2;
        let run = serde_json::from_value(value).unwrap();
        assert_eq!(
            evaluate(&run, &policy).verdict,
            Verdict::ProductFail,
            "relay.{}.{} must be enforced",
            mutation.0,
            mutation.1
        );
    }
}

#[test]
fn relay_gate_binds_reservations_and_allocations_to_selected_nodes() {
    let policy = policy("windows-multi-region-relay.v1.json");
    let run = fixture("multi-region-relay-valid.json");
    let original = serde_json::to_value(run).unwrap();
    for (section, field) in [
        ("reservation", "primary_node_id"),
        ("reservation", "backup_node_id"),
        ("allocation", "primary_node_id"),
        ("allocation", "backup_node_id"),
    ] {
        let mut value = original.clone();
        value["relay"][section][field] = serde_json::json!("relay-unrelated");
        let run = serde_json::from_value(value).unwrap();
        assert_eq!(
            evaluate(&run, &policy).verdict,
            Verdict::ProductFail,
            "relay.{section}.{field} must be bound"
        );
    }
}

#[test]
fn relay_gate_enforces_ten_second_removal_and_twenty_second_recovery() {
    let policy = policy("windows-multi-region-relay.v1.json");
    let run = fixture("multi-region-relay-valid.json");
    let original = serde_json::to_value(run).unwrap();

    let mut slow_removal = original.clone();
    slow_removal["relay"]["detection"]["removed_at_ms"] = serde_json::json!(20_001);
    let run = serde_json::from_value(slow_removal).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);

    let mut slow_recovery = original;
    slow_recovery["relay"]["restored_media"]["resumed_at_ms"] = serde_json::json!(30_001);
    let run = serde_json::from_value(slow_recovery).unwrap();
    assert_eq!(evaluate(&run, &policy).verdict, Verdict::ProductFail);
}

#[test]
fn missing_live_infrastructure_is_infra_fail_never_product_pass() {
    let mut run = fixture("multi-region-relay-valid.json");
    run.producer_status = "infra_failed".to_owned();
    run.gate_status = Verdict::InfraFail;
    let result = evaluate(&run, &policy("windows-multi-region-relay.v1.json"));
    assert_eq!(result.verdict, Verdict::InfraFail);
}
