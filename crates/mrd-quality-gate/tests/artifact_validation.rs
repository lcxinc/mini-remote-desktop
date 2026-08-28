use mrd_quality_gate::{validate_artifact, ArtifactError, RemoteExperienceRun};

#[test]
fn required_present_metric_cannot_be_missing() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/missing-present.json");
    let run: RemoteExperienceRun = serde_json::from_str(raw).unwrap();
    assert_eq!(
        validate_artifact(&run),
        Err(ArtifactError::MissingRequiredMetric(
            "visible_first_frame_ms"
        ))
    );
}

#[test]
fn finite_complete_direct_fixture_is_valid() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/valid-direct.json");
    let run: RemoteExperienceRun = serde_json::from_str(raw).unwrap();
    assert!(validate_artifact(&run).is_ok());
}

#[test]
fn clean_security_rejection_does_not_require_fabricated_media_samples() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/security-untrusted.json");
    let run: RemoteExperienceRun = serde_json::from_str(raw).unwrap();
    assert!(validate_artifact(&run).is_ok());
}

#[test]
fn secure_positive_run_requires_real_first_frame_and_fps_but_not_unavailable_samples() {
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
    let run: RemoteExperienceRun = serde_json::from_value(value).unwrap();
    assert!(validate_artifact(&run).is_ok());
}

#[test]
fn artifact_identity_and_schema_fields_must_be_valid() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/valid-direct.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();

    for (field, invalid_value) in [
        (
            "schema_version",
            serde_json::json!("remote-experience-run.v1"),
        ),
        ("run_id", serde_json::json!("   ")),
    ] {
        let mut candidate = value.clone();
        candidate[field] = invalid_value;
        let run: RemoteExperienceRun = serde_json::from_value(candidate).unwrap();
        assert!(validate_artifact(&run).is_err(), "{field} must be rejected");
    }

    let mut candidate = value;
    candidate["scenario"]["id"] = serde_json::json!("\t");
    let run: RemoteExperienceRun = serde_json::from_value(candidate).unwrap();
    assert!(
        validate_artifact(&run).is_err(),
        "empty scenario id must be rejected"
    );
}

#[test]
fn audit_event_ids_must_be_non_empty_and_unique() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/valid-direct.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();

    for audit_ids in [
        serde_json::json!([""]),
        serde_json::json!(["audit-1", "audit-1"]),
    ] {
        let mut candidate = value.clone();
        candidate["audit_event_ids"] = audit_ids;
        let run: RemoteExperienceRun = serde_json::from_value(candidate).unwrap();
        assert!(validate_artifact(&run).is_err());
    }
}

#[test]
fn security_and_side_effect_evidence_must_be_paired() {
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

    let run: RemoteExperienceRun = serde_json::from_value(value).unwrap();
    assert!(validate_artifact(&run).is_err());
}

#[test]
fn unknown_artifact_and_nested_evidence_fields_are_rejected_by_serde() {
    let direct_raw = include_str!("../../../tests/quality-gates/fixtures/valid-direct.json");
    let mut direct: serde_json::Value = serde_json::from_str(direct_raw).unwrap();
    direct["schema_verzion"] = serde_json::json!("remote-experience-run.v2");
    assert!(serde_json::from_value::<RemoteExperienceRun>(direct).is_err());

    let security_raw = include_str!("../../../tests/quality-gates/fixtures/security-replay.json");
    let security: serde_json::Value = serde_json::from_str(security_raw).unwrap();
    for path in ["security", "side_effects"] {
        let mut candidate = security.clone();
        candidate[path]["unexpected_evidence"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<RemoteExperienceRun>(candidate).is_err(),
            "unknown {path} field must be rejected"
        );
    }
}

#[test]
fn security_evidence_strings_cannot_be_blank() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/security-replay.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();

    for field in [
        "attempt_kind",
        "identity_state",
        "authorization_outcome",
        "authorization_basis",
        "rejection_reason",
    ] {
        let mut candidate = value.clone();
        candidate["security"][field] = serde_json::json!("   ");
        let run: RemoteExperienceRun = serde_json::from_value(candidate).unwrap();
        assert!(
            validate_artifact(&run).is_err(),
            "blank security.{field} must be rejected"
        );
    }
}

#[test]
fn complete_runtime_multi_region_relay_fixture_is_valid() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/multi-region-relay-valid.json");
    let run: RemoteExperienceRun = serde_json::from_str(raw).unwrap();
    assert!(validate_artifact(&run).is_ok());
}

#[test]
fn relay_evidence_contract_contains_runtime_generation_traffic_and_cleanup() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/multi-region-relay-valid.json");
    let run: RemoteExperienceRun = serde_json::from_str(raw).unwrap();
    let relay = run.relay.expect("relay runtime evidence");

    assert!(relay.directory.signature_verified);
    assert!(relay.reservation.committed);
    assert_eq!(relay.reservation.primary_node_id, relay.primary.node_id);
    assert_eq!(relay.reservation.backup_node_id, relay.backup.node_id);
    assert_eq!(relay.selected_pair.local_candidate_type, "relay");
    assert_eq!(relay.selected_pair.remote_candidate_type, "relay");
    assert!(relay.selected_pair.runtime_verified);
    assert_eq!(
        relay.generation.before.checked_add(1),
        Some(relay.generation.after)
    );
    assert!(relay.allocation.relayed_bytes_before_failure > 0);
    assert!(relay.restored_media.video_frames_after_recovery > 0);
    assert!(relay.restored_media.audio_packets_after_recovery > 0);
    assert!(relay.restored_media.control_events_after_recovery > 0);
    assert!(relay.restored_media.release_all_recorded);
    assert!(relay.cleanup.reservation_released);
    assert!(relay.cleanup.old_allocation_closed);
    assert!(relay.cleanup.replacement_allocation_closed);
    assert!(relay.cleanup.input_thawed);
    assert!(relay.cleanup.lab_reset);
}

#[test]
fn relay_route_cannot_be_claimed_with_metadata_only() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/multi-region-relay-valid.json");
    let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
    value.as_object_mut().unwrap().remove("relay");
    let run: RemoteExperienceRun = serde_json::from_value(value).unwrap();

    assert_eq!(
        validate_artifact(&run),
        Err(ArtifactError::MissingRequiredMetric("relay"))
    );
}

#[test]
fn relay_evidence_rejects_blank_runtime_identifiers() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/multi-region-relay-valid.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    for path in [
        ["directory", "directory_id"],
        ["directory", "session_id"],
        ["primary", "failure_domain"],
        ["backup", "failure_domain"],
        ["reservation", "primary_reservation_id"],
        ["reservation", "primary_node_id"],
        ["selected_pair", "relay_node_id"],
        ["allocation", "primary_allocation_id"],
        ["allocation", "primary_node_id"],
        ["injected_failure", "kind"],
        ["detection", "source"],
    ] {
        let mut candidate = value.clone();
        candidate["relay"][path[0]][path[1]] = serde_json::json!("   ");
        let run: RemoteExperienceRun = serde_json::from_value(candidate).unwrap();
        assert!(
            validate_artifact(&run).is_err(),
            "blank relay.{}.{} must be rejected",
            path[0],
            path[1]
        );
    }
}

#[test]
fn relay_runtime_evidence_cannot_be_attached_to_a_non_relay_route() {
    let raw = include_str!("../../../tests/quality-gates/fixtures/multi-region-relay-valid.json");
    let mut value: serde_json::Value = serde_json::from_str(raw).unwrap();
    value["route"]["selected"] = serde_json::json!("direct");
    let run: RemoteExperienceRun = serde_json::from_value(value).unwrap();
    assert_eq!(
        validate_artifact(&run),
        Err(ArtifactError::RelayRouteMismatch)
    );
}
