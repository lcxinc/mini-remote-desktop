use crate::{GatePolicy, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

const REMOTE_EXPERIENCE_SCHEMA_VERSION: &str = "remote-experience-run.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RemoteExperienceRun {
    pub schema_version: String,
    pub run_id: String,
    pub scenario: ScenarioIdentity,
    pub route: RouteEvidence,
    pub media: MediaEvidence,
    pub present: PresentMetrics,
    pub resources: ResourceEvidence,
    pub producer_status: String,
    pub gate_status: Verdict,
    pub audit_event_ids: Vec<String>,
    #[serde(default)]
    pub security: Option<SecurityEvidence>,
    #[serde(default)]
    pub side_effects: Option<SideEffectEvidence>,
    #[serde(default)]
    pub relay: Option<RelayEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScenarioIdentity {
    pub id: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteEvidence {
    pub requested: String,
    pub selected: String,
    pub candidate_pair: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MediaEvidence {
    pub requested_profile: String,
    pub selected_profile: String,
    pub profile_downgraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PresentMetrics {
    pub visible_first_frame_ms: Option<f64>,
    pub input_to_photon_ms: Vec<f64>,
    pub fps_windows: Vec<f64>,
    pub freeze_count: u64,
    pub stall_ms: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceEvidence {
    pub cpu_percent: Vec<f64>,
    pub gpu_percent: Vec<f64>,
    pub rss_bytes: Vec<f64>,
    pub vram_bytes: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvidence {
    pub attempt_kind: String,
    pub identity_state: String,
    pub authorization_outcome: String,
    pub authorization_basis: String,
    pub scope_authorized: bool,
    pub quic_peer_authenticated: bool,
    pub control_input_authenticated: bool,
    pub rejected: bool,
    pub rejection_reason: String,
    pub cleanup_completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SideEffectEvidence {
    pub sender_tasks_started: u64,
    pub receiver_tasks_started: u64,
    pub media_packets_sent: u64,
    pub media_frames_presented: u64,
    pub control_events_injected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayEvidence {
    pub directory: RelayDirectoryEvidence,
    pub primary: RelayNodeEvidence,
    pub backup: RelayNodeEvidence,
    pub reservation: RelayReservationEvidence,
    pub selected_pair: RelaySelectedPairEvidence,
    pub allocation: RelayAllocationEvidence,
    pub injected_failure: RelayInjectedFailureEvidence,
    pub detection: RelayFailureDetectionEvidence,
    pub generation: RelayGenerationEvidence,
    pub restored_media: RelayRestoredMediaEvidence,
    pub cleanup: RelayCleanupEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayDirectoryEvidence {
    pub directory_id: String,
    pub session_id: String,
    pub signing_key_id: String,
    pub signature_verified: bool,
    pub policy_revision: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayNodeEvidence {
    pub node_id: String,
    pub region: String,
    pub failure_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayReservationEvidence {
    pub primary_reservation_id: String,
    pub primary_node_id: String,
    pub backup_reservation_id: String,
    pub backup_node_id: String,
    pub committed: bool,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelaySelectedPairEvidence {
    pub relay_node_id: String,
    pub local_candidate_type: String,
    pub remote_candidate_type: String,
    pub transport: String,
    pub nominated: bool,
    pub runtime_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayAllocationEvidence {
    pub primary_allocation_id: String,
    pub primary_node_id: String,
    pub backup_allocation_id: String,
    pub backup_node_id: String,
    pub primary_established: bool,
    pub backup_established: bool,
    pub relayed_bytes_before_failure: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayInjectedFailureEvidence {
    pub kind: String,
    pub target_node_id: String,
    pub injected_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayFailureDetectionEvidence {
    pub source: String,
    pub detected_at_ms: u64,
    pub removed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayGenerationEvidence {
    pub before: u64,
    pub after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayRestoredMediaEvidence {
    pub backup_node_id: String,
    pub media_resumed: bool,
    pub resumed_at_ms: u64,
    pub video_frames_after_recovery: u64,
    pub audio_packets_after_recovery: u64,
    pub control_events_after_recovery: u64,
    pub permissions_unchanged: bool,
    pub release_all_recorded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayCleanupEvidence {
    pub reservation_released: bool,
    pub old_allocation_closed: bool,
    pub replacement_allocation_closed: bool,
    pub input_thawed: bool,
    pub lab_reset: bool,
}

#[derive(Debug, Error, PartialEq)]
pub enum ArtifactError {
    #[error("unsupported schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("required string is empty: {0}")]
    EmptyRequiredString(&'static str),
    #[error("missing required metric: {0}")]
    MissingRequiredMetric(&'static str),
    #[error("required sample set is empty: {0}")]
    EmptyRequiredSamples(&'static str),
    #[error("numeric field is not finite: {0}")]
    NonFiniteMetric(&'static str),
    #[error("duplicate audit event id: {0}")]
    DuplicateAuditEventId(String),
    #[error("relay runtime evidence requires route.selected=relay")]
    RelayRouteMismatch,
}

pub fn validate_artifact(run: &RemoteExperienceRun) -> Result<(), ArtifactError> {
    let profile = match (run.security.as_ref(), run.relay.as_ref()) {
        (_, Some(_)) => ArtifactValidationProfile::MultiRegionRelay,
        (Some(security), None) if security.rejected => ArtifactValidationProfile::SecurityNegative,
        (Some(_), None) => ArtifactValidationProfile::SecureLanPositive,
        (None, None) if run.route.selected == "relay" => {
            ArtifactValidationProfile::MultiRegionRelay
        }
        (None, None) => ArtifactValidationProfile::Standard,
    };
    validate_artifact_with_profile(run, profile)
}

pub fn validate_artifact_for_policy(
    run: &RemoteExperienceRun,
    policy: &GatePolicy,
) -> Result<(), ArtifactError> {
    let profile = if policy.multi_region_relay_requirements.is_some() {
        ArtifactValidationProfile::MultiRegionRelay
    } else if policy.security_negative_requirements.is_some() {
        ArtifactValidationProfile::SecurityNegative
    } else if policy.secure_lan_requirements.is_some() {
        ArtifactValidationProfile::SecureLanPositive
    } else {
        ArtifactValidationProfile::Standard
    };
    validate_artifact_with_profile(run, profile)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactValidationProfile {
    Standard,
    SecureLanPositive,
    SecurityNegative,
    MultiRegionRelay,
}

fn validate_artifact_with_profile(
    run: &RemoteExperienceRun,
    profile: ArtifactValidationProfile,
) -> Result<(), ArtifactError> {
    validate_artifact_identity(run)?;
    validate_security_evidence_pair(run, profile)?;
    validate_relay_evidence(run, profile)?;

    if profile != ArtifactValidationProfile::SecurityNegative
        && run.present.visible_first_frame_ms.is_none()
    {
        return Err(ArtifactError::MissingRequiredMetric(
            "visible_first_frame_ms",
        ));
    }

    let all_samples = [
        (
            "input_to_photon_ms",
            run.present.input_to_photon_ms.as_slice(),
        ),
        ("fps_windows", run.present.fps_windows.as_slice()),
        ("stall_ms", run.present.stall_ms.as_slice()),
        ("cpu_percent", run.resources.cpu_percent.as_slice()),
        ("gpu_percent", run.resources.gpu_percent.as_slice()),
        ("rss_bytes", run.resources.rss_bytes.as_slice()),
        ("vram_bytes", run.resources.vram_bytes.as_slice()),
    ];
    for (name, values) in all_samples {
        if values.iter().any(|value| !value.is_finite()) {
            return Err(ArtifactError::NonFiniteMetric(name));
        }
    }

    let required_samples: &[(&'static str, &[f64])] = match profile {
        ArtifactValidationProfile::Standard => &[
            (
                "input_to_photon_ms",
                run.present.input_to_photon_ms.as_slice(),
            ),
            ("fps_windows", run.present.fps_windows.as_slice()),
            ("cpu_percent", run.resources.cpu_percent.as_slice()),
            ("gpu_percent", run.resources.gpu_percent.as_slice()),
            ("rss_bytes", run.resources.rss_bytes.as_slice()),
            ("vram_bytes", run.resources.vram_bytes.as_slice()),
        ],
        ArtifactValidationProfile::SecureLanPositive
        | ArtifactValidationProfile::MultiRegionRelay => {
            &[("fps_windows", run.present.fps_windows.as_slice())]
        }
        ArtifactValidationProfile::SecurityNegative => &[],
    };
    for (name, values) in required_samples {
        if values.is_empty() {
            return Err(ArtifactError::EmptyRequiredSamples(name));
        }
    }

    if run
        .present
        .visible_first_frame_ms
        .is_some_and(|value| !value.is_finite())
    {
        return Err(ArtifactError::NonFiniteMetric("visible_first_frame_ms"));
    }
    Ok(())
}

fn validate_artifact_identity(run: &RemoteExperienceRun) -> Result<(), ArtifactError> {
    if run.schema_version != REMOTE_EXPERIENCE_SCHEMA_VERSION {
        return Err(ArtifactError::UnsupportedSchemaVersion(
            run.schema_version.clone(),
        ));
    }
    if run.run_id.trim().is_empty() {
        return Err(ArtifactError::EmptyRequiredString("run_id"));
    }
    if run.scenario.id.trim().is_empty() {
        return Err(ArtifactError::EmptyRequiredString("scenario.id"));
    }
    for (name, value) in [
        ("route.requested", run.route.requested.as_str()),
        ("route.selected", run.route.selected.as_str()),
        ("route.candidate_pair", run.route.candidate_pair.as_str()),
        ("producer_status", run.producer_status.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ArtifactError::EmptyRequiredString(name));
        }
    }
    if run.audit_event_ids.is_empty() {
        return Err(ArtifactError::EmptyRequiredSamples("audit_event_ids"));
    }

    let mut audit_ids = HashSet::new();
    for audit_id in &run.audit_event_ids {
        let audit_id = audit_id.trim();
        if audit_id.is_empty() {
            return Err(ArtifactError::EmptyRequiredString("audit_event_ids[]"));
        }
        if !audit_ids.insert(audit_id) {
            return Err(ArtifactError::DuplicateAuditEventId(audit_id.to_owned()));
        }
    }
    Ok(())
}

fn validate_security_evidence_pair(
    run: &RemoteExperienceRun,
    profile: ArtifactValidationProfile,
) -> Result<(), ArtifactError> {
    match (run.security.is_some(), run.side_effects.is_some()) {
        (true, false) => return Err(ArtifactError::MissingRequiredMetric("side_effects")),
        (false, true) => return Err(ArtifactError::MissingRequiredMetric("security")),
        _ => {}
    }

    if matches!(
        profile,
        ArtifactValidationProfile::SecureLanPositive | ArtifactValidationProfile::SecurityNegative
    ) && run.security.is_none()
    {
        return Err(ArtifactError::MissingRequiredMetric("security"));
    }
    if let Some(security) = &run.security {
        for (name, value) in [
            ("security.attempt_kind", security.attempt_kind.as_str()),
            ("security.identity_state", security.identity_state.as_str()),
            (
                "security.authorization_outcome",
                security.authorization_outcome.as_str(),
            ),
            (
                "security.authorization_basis",
                security.authorization_basis.as_str(),
            ),
            (
                "security.rejection_reason",
                security.rejection_reason.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(ArtifactError::EmptyRequiredString(name));
            }
        }
    }
    Ok(())
}

fn validate_relay_evidence(
    run: &RemoteExperienceRun,
    profile: ArtifactValidationProfile,
) -> Result<(), ArtifactError> {
    let relay_required =
        profile == ArtifactValidationProfile::MultiRegionRelay || run.route.selected == "relay";
    if run.relay.is_some() && run.route.selected != "relay" {
        return Err(ArtifactError::RelayRouteMismatch);
    }
    let Some(relay) = &run.relay else {
        return if relay_required {
            Err(ArtifactError::MissingRequiredMetric("relay"))
        } else {
            Ok(())
        };
    };

    for (name, value) in [
        (
            "relay.directory.directory_id",
            relay.directory.directory_id.as_str(),
        ),
        (
            "relay.directory.signing_key_id",
            relay.directory.signing_key_id.as_str(),
        ),
        (
            "relay.directory.session_id",
            relay.directory.session_id.as_str(),
        ),
        ("relay.primary.node_id", relay.primary.node_id.as_str()),
        ("relay.primary.region", relay.primary.region.as_str()),
        (
            "relay.primary.failure_domain",
            relay.primary.failure_domain.as_str(),
        ),
        ("relay.backup.node_id", relay.backup.node_id.as_str()),
        ("relay.backup.region", relay.backup.region.as_str()),
        (
            "relay.backup.failure_domain",
            relay.backup.failure_domain.as_str(),
        ),
        (
            "relay.reservation.primary_reservation_id",
            relay.reservation.primary_reservation_id.as_str(),
        ),
        (
            "relay.reservation.primary_node_id",
            relay.reservation.primary_node_id.as_str(),
        ),
        (
            "relay.reservation.backup_reservation_id",
            relay.reservation.backup_reservation_id.as_str(),
        ),
        (
            "relay.reservation.backup_node_id",
            relay.reservation.backup_node_id.as_str(),
        ),
        (
            "relay.selected_pair.relay_node_id",
            relay.selected_pair.relay_node_id.as_str(),
        ),
        (
            "relay.selected_pair.local_candidate_type",
            relay.selected_pair.local_candidate_type.as_str(),
        ),
        (
            "relay.selected_pair.remote_candidate_type",
            relay.selected_pair.remote_candidate_type.as_str(),
        ),
        (
            "relay.selected_pair.transport",
            relay.selected_pair.transport.as_str(),
        ),
        (
            "relay.allocation.primary_allocation_id",
            relay.allocation.primary_allocation_id.as_str(),
        ),
        (
            "relay.allocation.primary_node_id",
            relay.allocation.primary_node_id.as_str(),
        ),
        (
            "relay.allocation.backup_allocation_id",
            relay.allocation.backup_allocation_id.as_str(),
        ),
        (
            "relay.allocation.backup_node_id",
            relay.allocation.backup_node_id.as_str(),
        ),
        (
            "relay.injected_failure.kind",
            relay.injected_failure.kind.as_str(),
        ),
        (
            "relay.injected_failure.target_node_id",
            relay.injected_failure.target_node_id.as_str(),
        ),
        ("relay.detection.source", relay.detection.source.as_str()),
        (
            "relay.restored_media.backup_node_id",
            relay.restored_media.backup_node_id.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(ArtifactError::EmptyRequiredString(name));
        }
    }
    Ok(())
}
