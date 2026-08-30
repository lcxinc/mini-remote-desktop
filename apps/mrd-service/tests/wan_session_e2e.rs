use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{Read, Write},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const EVIDENCE_SCHEMA: &str = "mrd-initial-wan-session-evidence.v1";
const MAX_CONTROL_OUTPUT_BYTES: usize = 1_048_576;
const PINNED_COTURN_IMAGE: &str =
    "coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e";
const TEST_ATTESTATION_KEY_ID: &str = "test-only-initial-wan-attestation";
const ATTESTATION_DOMAIN: &[u8] = b"MRD_INITIAL_WAN_EVIDENCE_V1\0";

static INVOCATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitialWanRow {
    UdpGenerationZero,
    TcpGenerationZero,
    TlsGenerationZero,
    TargetRejection,
    CapacityExhaustion,
    BackendLossBeforeApproval,
    SignalingDisconnect,
    ExpiredGeneration,
    ServiceRestart,
    #[serde(rename = "primary_failure_cross_failure_domain_migration")]
    PrimaryFailureCrossDomainMigration,
    DeterministicReleaseAll,
}

impl InitialWanRow {
    const ALL: [Self; 11] = [
        Self::UdpGenerationZero,
        Self::TcpGenerationZero,
        Self::TlsGenerationZero,
        Self::TargetRejection,
        Self::CapacityExhaustion,
        Self::BackendLossBeforeApproval,
        Self::SignalingDisconnect,
        Self::ExpiredGeneration,
        Self::ServiceRestart,
        Self::PrimaryFailureCrossDomainMigration,
        Self::DeterministicReleaseAll,
    ];

    fn id(self) -> &'static str {
        match self {
            Self::UdpGenerationZero => "udp_generation_zero",
            Self::TcpGenerationZero => "tcp_generation_zero",
            Self::TlsGenerationZero => "tls_generation_zero",
            Self::TargetRejection => "target_rejection",
            Self::CapacityExhaustion => "capacity_exhaustion",
            Self::BackendLossBeforeApproval => "backend_loss_before_approval",
            Self::SignalingDisconnect => "signaling_disconnect",
            Self::ExpiredGeneration => "expired_generation",
            Self::ServiceRestart => "service_restart",
            Self::PrimaryFailureCrossDomainMigration => {
                "primary_failure_cross_failure_domain_migration"
            }
            Self::DeterministicReleaseAll => "deterministic_release_all",
        }
    }

    fn rejection_reason(self) -> Option<&'static str> {
        match self {
            Self::TargetRejection => Some("target_rejected"),
            Self::CapacityExhaustion => Some("capacity_exhausted"),
            Self::BackendLossBeforeApproval => Some("backend_unavailable_before_approval"),
            Self::ExpiredGeneration => Some("generation_expired"),
            _ => None,
        }
    }

    fn transport(self) -> &'static str {
        match self {
            Self::TcpGenerationZero => "tcp",
            Self::TlsGenerationZero => "tls",
            _ => "udp",
        }
    }

    fn grant_observed(self) -> bool {
        self.rejection_reason().is_none() || self == Self::ExpiredGeneration
    }

    fn target_approved(self) -> bool {
        self.rejection_reason().is_none()
            || matches!(self, Self::CapacityExhaustion | Self::ExpiredGeneration)
    }

    fn relay_access_observed(self) -> bool {
        self.rejection_reason().is_none() || self == Self::ExpiredGeneration
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanEvidence {
    schema_version: String,
    invocation_id: String,
    evidence_id: String,
    row: InitialWanRow,
    verdict: String,
    topology: InitialWanTopologyEvidence,
    authorization: InitialWanAuthorizationEvidence,
    generation: InitialWanGenerationEvidence,
    reservation: InitialWanReservationEvidence,
    selected_pair: InitialWanSelectedPairEvidence,
    traffic: InitialWanTrafficEvidence,
    fault: InitialWanFaultEvidence,
    cleanup: InitialWanCleanupEvidence,
    attestation: InitialWanAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanAttestation {
    key_id: String,
    signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanEvidenceMatrix {
    schema_version: String,
    invocation_id: String,
    scenario: InitialWanScenarioEvidence,
    rows: Vec<InitialWanEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanScenarioEvidence {
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanTopologyEvidence {
    controller_service_runtime: bool,
    target_service_runtime: bool,
    realtime_server: bool,
    fastapi_backend: bool,
    controller_runtime_id: String,
    target_runtime_id: String,
    realtime_runtime_id: String,
    backend_runtime_id: String,
    coturn_image: String,
    coturn_node_count: u64,
    regions: Vec<String>,
    failure_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanAuthorizationEvidence {
    attended: bool,
    intent_signature_verified: bool,
    grant_signature_verified: bool,
    target_approved: bool,
    policy_revision: u64,
    scope_digest_equal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanGenerationEvidence {
    controller: u64,
    target: u64,
    before_migration: u64,
    after_migration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanReservationEvidence {
    session_id: String,
    controller_session_id: String,
    target_session_id: String,
    controller_directory_id: Option<String>,
    target_directory_id: Option<String>,
    controller_relay_url_digest: Option<String>,
    target_relay_url_digest: Option<String>,
    primary_reservation_id: Option<String>,
    backup_reservation_id: Option<String>,
    owner_verified: bool,
    committed: bool,
    primary_node_id: String,
    backup_node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanSelectedPairEvidence {
    local_candidate_type: String,
    remote_candidate_type: String,
    transport: String,
    runtime_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanTrafficEvidence {
    media_frames: u64,
    control_events: u64,
    realtime_control_events: u64,
    media_probe_id: String,
    control_probe_id: String,
    realtime_control_probe_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanFaultEvidence {
    expected_rejection: Option<String>,
    transport_opened: bool,
    primary_failed: bool,
    cross_failure_domain: bool,
    service_restart_count: u64,
    service_runtime_before_id: Option<String>,
    service_runtime_after_id: Option<String>,
    signaling_disconnect_count: u64,
    signaling_connection_before_id: Option<String>,
    signaling_connection_after_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialWanCleanupEvidence {
    release_all_recorded: bool,
    release_all_sequence: Vec<String>,
    reservation_released: bool,
    allocations_closed: bool,
    signaling_closed: bool,
    service_tasks_joined: bool,
    containers_removed: bool,
    created_container_names: Vec<String>,
    removed_container_names: Vec<String>,
}

fn complete_evidence(invocation_id: &str, row: InitialWanRow) -> Value {
    let rejected = row.rejection_reason();
    let connected = rejected.is_none();
    let grant_observed = row.grant_observed();
    let target_approved = row.target_approved();
    let relay_access_observed = row.relay_access_observed();
    let migration = row == InitialWanRow::PrimaryFailureCrossDomainMigration;
    let container_a = format!("mrd-wan-e2e-{invocation_id}-coturn-a");
    let container_b = format!("mrd-wan-e2e-{invocation_id}-coturn-b");
    let mut evidence = json!({
        "schema_version": EVIDENCE_SCHEMA,
        "invocation_id": invocation_id,
        "evidence_id": format!("{invocation_id}:{}", row.id()),
        "row": row.id(),
        "verdict": "PASS",
        "topology": {
            "controller_service_runtime": true,
            "target_service_runtime": true,
            "realtime_server": true,
            "fastapi_backend": true,
            "controller_runtime_id": format!("{invocation_id}:controller"),
            "target_runtime_id": format!("{invocation_id}:target"),
            "realtime_runtime_id": format!("{invocation_id}:realtime"),
            "backend_runtime_id": format!("{invocation_id}:backend"),
            "coturn_image": PINNED_COTURN_IMAGE,
            "coturn_node_count": 2,
            "regions": ["local-a", "local-b"],
            "failure_domains": ["process-a", "process-b"]
        },
        "authorization": {
            "attended": true,
            "intent_signature_verified": true,
            "grant_signature_verified": grant_observed,
            "target_approved": target_approved,
            "policy_revision": 7,
            "scope_digest_equal": grant_observed
        },
        "generation": {
            "controller": if migration { 1 } else { 0 },
            "target": if migration { 1 } else { 0 },
            "before_migration": 0,
            "after_migration": if migration { 1 } else { 0 }
        },
        "reservation": {
            "session_id": "session-evidence-only",
            "controller_session_id": "session-evidence-only",
            "target_session_id": "session-evidence-only",
            "controller_directory_id": relay_access_observed.then_some("directory-evidence-only"),
            "target_directory_id": relay_access_observed.then_some("directory-evidence-only"),
            "controller_relay_url_digest": relay_access_observed.then_some("digest-evidence-only"),
            "target_relay_url_digest": relay_access_observed.then_some("digest-evidence-only"),
            "primary_reservation_id": relay_access_observed.then_some("reservation-evidence-primary"),
            "backup_reservation_id": relay_access_observed.then_some("reservation-evidence-backup"),
            "owner_verified": relay_access_observed,
            "committed": connected,
            "primary_node_id": "relay-local-a",
            "backup_node_id": "relay-local-b"
        },
        "selected_pair": {
            "local_candidate_type": if connected { "relay" } else { "none" },
            "remote_candidate_type": if connected { "relay" } else { "none" },
            "transport": row.transport(),
            "runtime_verified": connected
        },
        "traffic": {
            "media_frames": if connected { 2 } else { 0 },
            "control_events": if connected { 2 } else { 0 },
            "realtime_control_events": if connected { 2 } else { 0 },
            "media_probe_id": format!("{invocation_id}:{}:media", row.id()),
            "control_probe_id": format!("{invocation_id}:{}:control", row.id()),
            "realtime_control_probe_id": format!("{invocation_id}:{}:realtime-control", row.id())
        },
        "fault": {
            "expected_rejection": rejected,
            "transport_opened": connected,
            "primary_failed": migration,
            "cross_failure_domain": migration,
            "service_restart_count": if row == InitialWanRow::ServiceRestart { 1 } else { 0 },
            "service_runtime_before_id": (row == InitialWanRow::ServiceRestart).then(|| format!("{invocation_id}:target:before-restart")),
            "service_runtime_after_id": (row == InitialWanRow::ServiceRestart).then(|| format!("{invocation_id}:target:after-restart")),
            "signaling_disconnect_count": if row == InitialWanRow::SignalingDisconnect { 1 } else { 0 },
            "signaling_connection_before_id": (row == InitialWanRow::SignalingDisconnect).then(|| format!("{invocation_id}:signal:before-disconnect")),
            "signaling_connection_after_id": (row == InitialWanRow::SignalingDisconnect).then(|| format!("{invocation_id}:signal:after-disconnect"))
        },
        "cleanup": {
            "release_all_recorded": true,
            "release_all_sequence": ["input_down", "release_all", "input_frozen"],
            "reservation_released": true,
            "allocations_closed": true,
            "signaling_closed": true,
            "service_tasks_joined": true,
            "containers_removed": true,
            "created_container_names": [container_a.clone(), container_b.clone()],
            "removed_container_names": [container_a, container_b]
        },
        "attestation": {
            "key_id": TEST_ATTESTATION_KEY_ID,
            "signature_b64": "PENDING"
        }
    });
    attest_test_evidence(&mut evidence);
    evidence
}

fn test_attestation_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x7a; 32])
}

fn attest_test_evidence(evidence: &mut Value) {
    let signing_key = test_attestation_signing_key();
    let signature = signing_key.sign(&evidence_signing_bytes(evidence).unwrap());
    evidence["attestation"]["signature_b64"] = json!(STANDARD.encode(signature.to_bytes()));
}

fn evidence_signing_bytes(evidence: &Value) -> Result<Vec<u8>, String> {
    let mut unsigned = evidence.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| "initial WAN evidence is not an object".to_owned())?
        .remove("attestation");
    let mut canonical = String::new();
    write_canonical_json(&unsigned, &mut canonical)?;
    let mut bytes = Vec::with_capacity(ATTESTATION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ATTESTATION_DOMAIN);
    bytes.extend_from_slice(canonical.as_bytes());
    Ok(bytes)
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|_| "initial WAN evidence string is invalid".to_owned())?,
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(fields) => {
            output.push('{');
            let mut names = fields.keys().collect::<Vec<_>>();
            names.sort_unstable();
            for (index, name) in names.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(name)
                        .map_err(|_| "initial WAN evidence field is invalid".to_owned())?,
                );
                output.push(':');
                write_canonical_json(&fields[name], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn required_bool(value: &Value, pointer: &str) -> Result<bool, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean evidence: {pointer}"))
}

fn required_u64(value: &Value, pointer: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing numeric evidence: {pointer}"))
}

fn required_str<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing string evidence: {pointer}"))
}

fn contains_secret_field(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            let name = name.to_ascii_lowercase();
            name.contains("password")
                || name.contains("secret")
                || name.contains("token")
                || name.contains("credential")
                || name.contains("private_key")
                || name == "sdp"
                || name == "candidate"
                || name == "ice_pwd"
                || contains_secret_field(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_field),
        Value::String(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("a=ice-pwd:")
                || value.contains("a=ice-ufrag:")
                || value.contains("candidate:")
                || ((value.starts_with("turn:") || value.starts_with("turns:"))
                    && value.contains('@'))
                || value.starts_with("authorization:")
                || value.starts_with("bearer ")
        }
        _ => false,
    }
}

fn validate_evidence(
    evidence: &Value,
    invocation_id: &str,
    row: InitialWanRow,
) -> Result<(), String> {
    let key = test_attestation_signing_key().verifying_key();
    validate_evidence_with_key(evidence, invocation_id, row, TEST_ATTESTATION_KEY_ID, &key)
}

fn validate_evidence_with_key(
    evidence: &Value,
    invocation_id: &str,
    row: InitialWanRow,
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let parsed = serde_json::from_value::<InitialWanEvidence>(evidence.clone())
        .map_err(|_| "initial WAN evidence does not match the closed schema".to_owned())?;
    if contains_secret_field(evidence) {
        return Err("evidence contains a forbidden secret-bearing field".to_owned());
    }
    if required_str(evidence, "/schema_version")? != EVIDENCE_SCHEMA
        || required_str(evidence, "/invocation_id")? != invocation_id
        || required_str(evidence, "/evidence_id")? != format!("{invocation_id}:{}", row.id())
        || required_str(evidence, "/row")? != row.id()
        || required_str(evidence, "/verdict")? != "PASS"
    {
        return Err(
            "evidence identity is not bound to the requested invocation and row".to_owned(),
        );
    }
    if parsed.attestation.key_id != expected_key_id {
        return Err("initial WAN evidence attestation key is untrusted".to_owned());
    }
    let signature_bytes = STANDARD
        .decode(parsed.attestation.signature_b64.as_bytes())
        .map_err(|_| "initial WAN evidence attestation is malformed".to_owned())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "initial WAN evidence attestation is malformed".to_owned())?;
    verifying_key
        .verify(&evidence_signing_bytes(evidence)?, &signature)
        .map_err(|_| "initial WAN evidence attestation is invalid".to_owned())?;

    for pointer in [
        "/topology/controller_service_runtime",
        "/topology/target_service_runtime",
        "/topology/realtime_server",
        "/topology/fastapi_backend",
        "/authorization/attended",
        "/authorization/intent_signature_verified",
        "/cleanup/release_all_recorded",
        "/cleanup/reservation_released",
        "/cleanup/allocations_closed",
        "/cleanup/signaling_closed",
        "/cleanup/service_tasks_joined",
        "/cleanup/containers_removed",
    ] {
        if !required_bool(evidence, pointer)? {
            return Err(format!("runtime proof is false: {pointer}"));
        }
    }
    let regions = evidence
        .pointer("/topology/regions")
        .and_then(Value::as_array)
        .ok_or_else(|| "region evidence is missing".to_owned())?;
    let failure_domains = evidence
        .pointer("/topology/failure_domains")
        .and_then(Value::as_array)
        .ok_or_else(|| "failure-domain evidence is missing".to_owned())?;
    if required_str(evidence, "/topology/coturn_image")? != PINNED_COTURN_IMAGE
        || required_u64(evidence, "/topology/coturn_node_count")? < 2
        || regions.len() < 2
        || regions[0] == regions[1]
        || failure_domains.len() < 2
        || failure_domains[0] == failure_domains[1]
    {
        return Err("the pinned multi-region coturn data plane was not observed".to_owned());
    }
    for (pointer, component) in [
        ("/topology/controller_runtime_id", "controller"),
        ("/topology/target_runtime_id", "target"),
        ("/topology/realtime_runtime_id", "realtime"),
        ("/topology/backend_runtime_id", "backend"),
    ] {
        if required_str(evidence, pointer)? != format!("{invocation_id}:{component}") {
            return Err(format!(
                "runtime identity is not invocation-bound: {component}"
            ));
        }
    }
    if required_str(evidence, "/reservation/session_id")?
        != required_str(evidence, "/reservation/controller_session_id")?
        || required_str(evidence, "/reservation/session_id")?
            != required_str(evidence, "/reservation/target_session_id")?
        || required_u64(evidence, "/generation/controller")?
            != required_u64(evidence, "/generation/target")?
    {
        return Err("session ownership or generation differs between peers".to_owned());
    }

    if row.relay_access_observed() {
        if !required_bool(evidence, "/reservation/owner_verified")?
            || required_str(evidence, "/reservation/controller_directory_id")?
                != required_str(evidence, "/reservation/target_directory_id")?
            || required_str(evidence, "/reservation/controller_relay_url_digest")?
                != required_str(evidence, "/reservation/target_relay_url_digest")?
            || required_str(evidence, "/reservation/primary_reservation_id")?
                == required_str(evidence, "/reservation/backup_reservation_id")?
        {
            return Err("relay access is not identically bound to both peers".to_owned());
        }
    } else if required_bool(evidence, "/reservation/owner_verified")?
        || [
            "/reservation/controller_directory_id",
            "/reservation/target_directory_id",
            "/reservation/controller_relay_url_digest",
            "/reservation/target_relay_url_digest",
            "/reservation/primary_reservation_id",
            "/reservation/backup_reservation_id",
        ]
        .iter()
        .any(|pointer| {
            evidence
                .pointer(pointer)
                .is_some_and(|value| !value.is_null())
        })
    {
        return Err("row claims reservation ownership before relay access".to_owned());
    }

    let created = evidence
        .pointer("/cleanup/created_container_names")
        .and_then(Value::as_array)
        .ok_or_else(|| "created container names are missing".to_owned())?;
    let removed = evidence
        .pointer("/cleanup/removed_container_names")
        .and_then(Value::as_array)
        .ok_or_else(|| "removed container names are missing".to_owned())?;
    if created.is_empty() || created != removed {
        return Err(
            "cleanup is not bound to the exact containers created by the invocation".to_owned(),
        );
    }
    let expected_container_prefix = format!("mrd-wan-e2e-{invocation_id}-");
    if created.iter().any(|name| {
        !name
            .as_str()
            .is_some_and(|name| name.starts_with(&expected_container_prefix))
    }) {
        return Err("container evidence is not bound to the invocation".to_owned());
    }
    let release_sequence = evidence
        .pointer("/cleanup/release_all_sequence")
        .and_then(Value::as_array)
        .ok_or_else(|| "ReleaseAll sequence is missing".to_owned())?;
    if release_sequence
        != &vec![
            json!("input_down"),
            json!("release_all"),
            json!("input_frozen"),
        ]
    {
        return Err("ReleaseAll did not precede input freeze".to_owned());
    }

    if let Some(reason) = row.rejection_reason() {
        if required_str(evidence, "/fault/expected_rejection")? != reason
            || required_bool(evidence, "/authorization/grant_signature_verified")?
                != row.grant_observed()
            || required_bool(evidence, "/authorization/target_approved")? != row.target_approved()
            || required_bool(evidence, "/authorization/scope_digest_equal")? != row.grant_observed()
            || required_bool(evidence, "/fault/transport_opened")?
            || required_bool(evidence, "/reservation/committed")?
        {
            return Err("negative row did not fail closed at the expected boundary".to_owned());
        }
    } else if !required_bool(evidence, "/authorization/target_approved")?
        || !required_bool(evidence, "/authorization/grant_signature_verified")?
        || !required_bool(evidence, "/authorization/scope_digest_equal")?
        || !required_bool(evidence, "/reservation/committed")?
        || !required_bool(evidence, "/fault/transport_opened")?
        || !required_bool(evidence, "/selected_pair/runtime_verified")?
        || required_str(evidence, "/selected_pair/local_candidate_type")? != "relay"
        || required_str(evidence, "/selected_pair/remote_candidate_type")? != "relay"
        || required_str(evidence, "/selected_pair/transport")? != row.transport()
        || required_u64(evidence, "/traffic/media_frames")? == 0
        || required_u64(evidence, "/traffic/control_events")? == 0
        || required_u64(evidence, "/traffic/realtime_control_events")? == 0
        || required_str(evidence, "/traffic/media_probe_id")?
            != format!("{invocation_id}:{}:media", row.id())
        || required_str(evidence, "/traffic/control_probe_id")?
            != format!("{invocation_id}:{}:control", row.id())
        || required_str(evidence, "/traffic/realtime_control_probe_id")?
            != format!("{invocation_id}:{}:realtime-control", row.id())
    {
        return Err("connected row lacks relay/relay traffic proof".to_owned());
    }

    if row != InitialWanRow::PrimaryFailureCrossDomainMigration
        && (required_u64(evidence, "/generation/controller")? != 0
            || required_u64(evidence, "/generation/before_migration")? != 0
            || required_u64(evidence, "/generation/after_migration")? != 0)
    {
        return Err("initial WAN row did not remain on shared generation zero".to_owned());
    }
    if row == InitialWanRow::ServiceRestart {
        let before = required_str(evidence, "/fault/service_runtime_before_id")?;
        let after = required_str(evidence, "/fault/service_runtime_after_id")?;
        if required_u64(evidence, "/fault/service_restart_count")? == 0
            || before == after
            || !before.starts_with(&format!("{invocation_id}:target:"))
            || !after.starts_with(&format!("{invocation_id}:target:"))
        {
            return Err("service restart row lacks before/after runtime proof".to_owned());
        }
    } else if required_u64(evidence, "/fault/service_restart_count")? != 0
        || evidence
            .pointer("/fault/service_runtime_before_id")
            .is_some_and(|value| !value.is_null())
        || evidence
            .pointer("/fault/service_runtime_after_id")
            .is_some_and(|value| !value.is_null())
    {
        return Err("non-restart row claims a service restart".to_owned());
    }
    if row == InitialWanRow::SignalingDisconnect {
        let before = required_str(evidence, "/fault/signaling_connection_before_id")?;
        let after = required_str(evidence, "/fault/signaling_connection_after_id")?;
        if required_u64(evidence, "/fault/signaling_disconnect_count")? == 0
            || before == after
            || !before.starts_with(&format!("{invocation_id}:signal:"))
            || !after.starts_with(&format!("{invocation_id}:signal:"))
        {
            return Err("signaling disconnect row lacks before/after connection proof".to_owned());
        }
    } else if required_u64(evidence, "/fault/signaling_disconnect_count")? != 0
        || evidence
            .pointer("/fault/signaling_connection_before_id")
            .is_some_and(|value| !value.is_null())
        || evidence
            .pointer("/fault/signaling_connection_after_id")
            .is_some_and(|value| !value.is_null())
    {
        return Err("non-disconnect row claims a signaling disconnect".to_owned());
    }

    if row == InitialWanRow::PrimaryFailureCrossDomainMigration
        && (!required_bool(evidence, "/fault/primary_failed")?
            || !required_bool(evidence, "/fault/cross_failure_domain")?
            || required_u64(evidence, "/topology/coturn_node_count")? < 2
            || required_u64(evidence, "/generation/after_migration")?
                != required_u64(evidence, "/generation/before_migration")?
                    .checked_add(1)
                    .ok_or_else(|| "migration generation overflowed".to_owned())?
            || required_u64(evidence, "/generation/controller")?
                != required_u64(evidence, "/generation/after_migration")?)
    {
        return Err("migration did not advance once across a failure-domain boundary".to_owned());
    }
    if row != InitialWanRow::PrimaryFailureCrossDomainMigration
        && (required_bool(evidence, "/fault/primary_failed")?
            || required_bool(evidence, "/fault/cross_failure_domain")?)
    {
        return Err("non-migration row claims a relay failure or domain crossing".to_owned());
    }
    Ok(())
}

fn validate_matrix(artifact: &Value, expected_invocation_id: &str) -> Result<(), String> {
    let key = test_attestation_signing_key().verifying_key();
    validate_matrix_with_key(
        artifact,
        expected_invocation_id,
        TEST_ATTESTATION_KEY_ID,
        &key,
    )
}

fn validate_matrix_with_key(
    artifact: &Value,
    expected_invocation_id: &str,
    expected_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let matrix: InitialWanEvidenceMatrix = serde_json::from_value(artifact.clone())
        .map_err(|_| "initial WAN matrix does not match the closed schema".to_owned())?;
    if matrix.schema_version != "mrd-initial-wan-session-matrix.v1"
        || matrix.invocation_id != expected_invocation_id
        || matrix.scenario.id != "initial_wan_local"
        || matrix.rows.len() != InitialWanRow::ALL.len()
    {
        return Err("initial WAN matrix identity or row count is invalid".to_owned());
    }
    for expected_row in InitialWanRow::ALL {
        let matching = matrix
            .rows
            .iter()
            .filter(|evidence| evidence.row == expected_row)
            .count();
        if matching != 1 {
            return Err(format!(
                "initial WAN row is missing or duplicated: {}",
                expected_row.id()
            ));
        }
    }
    for evidence in &matrix.rows {
        let value = serde_json::to_value(evidence)
            .map_err(|_| "initial WAN row could not be validated".to_owned())?;
        validate_evidence_with_key(
            &value,
            expected_invocation_id,
            evidence.row,
            expected_key_id,
            verifying_key,
        )?;
    }
    Ok(())
}

fn load_live_attestation_key() -> (String, VerifyingKey) {
    let key_id = env::var("MRD_INITIAL_WAN_ATTESTATION_KEY_ID")
        .unwrap_or_else(|_| panic!("INFRA_FAIL: MRD_INITIAL_WAN_ATTESTATION_KEY_ID is required"));
    let path = env::var_os("MRD_INITIAL_WAN_ATTESTATION_PUBLIC_KEY").unwrap_or_else(|| {
        panic!("INFRA_FAIL: MRD_INITIAL_WAN_ATTESTATION_PUBLIC_KEY is required")
    });
    let bytes = fs::read(path)
        .unwrap_or_else(|_| panic!("INFRA_FAIL: initial WAN attestation key is unavailable"));
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .unwrap_or_else(|_| panic!("INFRA_FAIL: initial WAN attestation key is invalid"));
    let key = VerifyingKey::from_bytes(&key_bytes)
        .unwrap_or_else(|_| panic!("INFRA_FAIL: initial WAN attestation key is invalid"));
    (key_id, key)
}

#[test]
#[ignore = "runner supplies an invocation-bound MRD_INITIAL_WAN_EVIDENCE_PATH"]
fn evidence_file_contract() {
    let path = env::var_os("MRD_INITIAL_WAN_EVIDENCE_PATH")
        .unwrap_or_else(|| panic!("INFRA_FAIL: MRD_INITIAL_WAN_EVIDENCE_PATH is required"));
    let invocation_id = env::var("MRD_INITIAL_WAN_INVOCATION_ID")
        .unwrap_or_else(|_| panic!("INFRA_FAIL: MRD_INITIAL_WAN_INVOCATION_ID is required"));
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|_| panic!("INFRA_FAIL: initial WAN evidence file is unavailable"));
    if metadata.len() > MAX_CONTROL_OUTPUT_BYTES as u64 {
        panic!("PRODUCT_FAIL: initial WAN evidence file exceeds its size bound");
    }
    let artifact = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or_else(|| panic!("PRODUCT_FAIL: initial WAN evidence file is invalid"));
    let (key_id, key) = load_live_attestation_key();
    validate_matrix_with_key(&artifact, &invocation_id, &key_id, &key)
        .unwrap_or_else(|error| panic!("PRODUCT_FAIL: {error}"));
}

fn invoke_live_control(control: &std::ffi::OsStr, request: &Value) -> Result<Value, &'static str> {
    let mut child = Command::new(control)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "initial WAN lab control did not start")?;
    child
        .stdin
        .take()
        .ok_or("initial WAN lab control stdin is unavailable")?
        .write_all(request.to_string().as_bytes())
        .map_err(|_| "initial WAN lab request could not be written")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("initial WAN lab stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("initial WAN lab stderr is unavailable")?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_CONTROL_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(MAX_CONTROL_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < Duration::from_secs(180) => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("initial WAN lab control timed out");
            }
            Err(_) => return Err("initial WAN lab control status is unavailable"),
        }
    };
    let stdout = stdout_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or("initial WAN lab stdout could not be read")?;
    let stderr = stderr_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or("initial WAN lab stderr could not be read")?;
    if stdout.len() > MAX_CONTROL_OUTPUT_BYTES || stderr.len() > MAX_CONTROL_OUTPUT_BYTES {
        return Err("initial WAN lab control output exceeded its bound");
    }
    if !status.success() {
        return Err("initial WAN lab control process failed");
    }
    let response: Value = serde_json::from_slice(&stdout)
        .map_err(|_| "initial WAN lab control returned invalid JSON")?;
    if contains_secret_field(&response)
        || response.as_object().is_none_or(|fields| {
            fields
                .keys()
                .any(|key| key != "verdict" && key != "evidence" && key != "failure")
        })
    {
        return Err("initial WAN lab control returned unsafe fields");
    }
    Ok(response)
}

fn pass_response(response: &Value) -> bool {
    response.get("verdict").and_then(Value::as_str) == Some("PASS")
}

fn run_live_row(row: InitialWanRow) {
    let control = env::var_os("MRD_INITIAL_WAN_LAB_CONTROL")
        .unwrap_or_else(|| panic!("INFRA_FAIL: MRD_INITIAL_WAN_LAB_CONTROL is required"));
    let invocation_id = format!(
        "mrd-wan-e2e-{}-{}",
        std::process::id(),
        INVOCATION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let base_request = |action: &str, target: &str| {
        json!({
            "schema_version": 1,
            "invocation_id": invocation_id,
            "scenario": "initial_wan_local",
            "action": action,
            "target": target
        })
    };
    let preflight = invoke_live_control(control.as_os_str(), &base_request("preflight", "lab"))
        .unwrap_or_else(|error| panic!("INFRA_FAIL: {error}"));
    if !pass_response(&preflight) {
        panic!("INFRA_FAIL: initial WAN live preflight did not pass");
    }

    let row_result = invoke_live_control(
        control.as_os_str(),
        &base_request("run_initial_wan_row", row.id()),
    );
    let reset_result = invoke_live_control(control.as_os_str(), &base_request("reset", "lab"));
    let reset = reset_result.unwrap_or_else(|error| panic!("INFRA_FAIL: {error}"));
    if !pass_response(&reset) {
        panic!("PRODUCT_FAIL: initial WAN live reset did not pass");
    }
    let response = row_result.unwrap_or_else(|error| panic!("INFRA_FAIL: {error}"));
    if !pass_response(&response) {
        panic!("PRODUCT_FAIL: initial WAN lab control did not pass the requested row");
    }
    let evidence = response
        .get("evidence")
        .unwrap_or_else(|| panic!("INFRA_FAIL: initial WAN lab control returned no evidence"));
    let (key_id, key) = load_live_attestation_key();
    validate_evidence_with_key(evidence, &invocation_id, row, &key_id, &key)
        .unwrap_or_else(|error| panic!("PRODUCT_FAIL: {error}"));
}

macro_rules! live_row {
    ($name:ident, $row:expr) => {
        #[test]
        #[ignore = "live initial WAN evidence requires MRD_INITIAL_WAN_LAB_CONTROL"]
        fn $name() {
            run_live_row($row);
        }
    };
}

live_row!(live_udp_generation_zero, InitialWanRow::UdpGenerationZero);
live_row!(live_tcp_generation_zero, InitialWanRow::TcpGenerationZero);
live_row!(live_tls_generation_zero, InitialWanRow::TlsGenerationZero);
live_row!(live_target_rejection, InitialWanRow::TargetRejection);
live_row!(live_capacity_exhaustion, InitialWanRow::CapacityExhaustion);
live_row!(
    live_backend_loss_before_approval,
    InitialWanRow::BackendLossBeforeApproval
);
live_row!(
    live_signaling_disconnect,
    InitialWanRow::SignalingDisconnect
);
live_row!(live_expired_generation, InitialWanRow::ExpiredGeneration);
live_row!(live_service_restart, InitialWanRow::ServiceRestart);
live_row!(
    live_primary_failure_cross_failure_domain_migration,
    InitialWanRow::PrimaryFailureCrossDomainMigration
);
live_row!(
    live_deterministic_release_all,
    InitialWanRow::DeterministicReleaseAll
);

#[test]
fn evidence_contract_accepts_only_invocation_bound_runtime_proof() {
    let evidence = complete_evidence("invocation-001", InitialWanRow::UdpGenerationZero);
    assert!(validate_evidence(
        &evidence,
        "invocation-001",
        InitialWanRow::UdpGenerationZero,
    )
    .is_ok());

    let mut replayed = evidence.clone();
    replayed["invocation_id"] = json!("another-invocation");
    attest_test_evidence(&mut replayed);
    assert!(validate_evidence(
        &replayed,
        "invocation-001",
        InitialWanRow::UdpGenerationZero,
    )
    .is_err());

    let mut metadata_only = evidence;
    metadata_only["traffic"]["media_frames"] = json!(0);
    attest_test_evidence(&mut metadata_only);
    assert!(validate_evidence(
        &metadata_only,
        "invocation-001",
        InitialWanRow::UdpGenerationZero,
    )
    .is_err());

    let mut tampered = complete_evidence("invocation-001", InitialWanRow::UdpGenerationZero);
    tampered["traffic"]["media_frames"] = json!(99);
    assert!(validate_evidence(
        &tampered,
        "invocation-001",
        InitialWanRow::UdpGenerationZero,
    )
    .is_err());

    let wrong_key = SigningKey::from_bytes(&[0x29; 32]).verifying_key();
    let signed = complete_evidence("invocation-001", InitialWanRow::UdpGenerationZero);
    assert!(validate_evidence_with_key(
        &signed,
        "invocation-001",
        InitialWanRow::UdpGenerationZero,
        TEST_ATTESTATION_KEY_ID,
        &wrong_key,
    )
    .is_err());
}

#[test]
fn evidence_contract_covers_every_initial_wan_row() {
    assert_eq!(InitialWanRow::ALL.len(), 11);
    let rows = InitialWanRow::ALL
        .into_iter()
        .map(|row| complete_evidence("matrix-invocation", row))
        .collect::<Vec<_>>();
    let matrix = json!({
        "schema_version": "mrd-initial-wan-session-matrix.v1",
        "invocation_id": "matrix-invocation",
        "scenario": {"id": "initial_wan_local"},
        "rows": rows
    });
    assert!(validate_matrix(&matrix, "matrix-invocation").is_ok());
    for row in InitialWanRow::ALL {
        let evidence = complete_evidence("matrix-invocation", row);
        assert!(
            validate_evidence(&evidence, "matrix-invocation", row).is_ok(),
            "contract fixture must represent {row:?}"
        );
    }
}

#[test]
fn evidence_contract_rejects_secret_fields_and_incomplete_cleanup() {
    let mut secret = complete_evidence("invocation-002", InitialWanRow::TcpGenerationZero);
    secret["credential"] = json!("forbidden");
    assert!(
        validate_evidence(&secret, "invocation-002", InitialWanRow::TcpGenerationZero,).is_err()
    );

    let mut leaked = complete_evidence("invocation-003", InitialWanRow::DeterministicReleaseAll);
    leaked["cleanup"]["containers_removed"] = json!(false);
    attest_test_evidence(&mut leaked);
    assert!(validate_evidence(
        &leaked,
        "invocation-003",
        InitialWanRow::DeterministicReleaseAll,
    )
    .is_err());

    let mut false_transport = complete_evidence("invocation-004", InitialWanRow::UdpGenerationZero);
    false_transport["fault"]["transport_opened"] = json!(false);
    attest_test_evidence(&mut false_transport);
    assert!(validate_evidence(
        &false_transport,
        "invocation-004",
        InitialWanRow::UdpGenerationZero,
    )
    .is_err());

    let mut stale_generation = complete_evidence(
        "invocation-005",
        InitialWanRow::PrimaryFailureCrossDomainMigration,
    );
    stale_generation["generation"]["controller"] = json!(0);
    stale_generation["generation"]["target"] = json!(0);
    attest_test_evidence(&mut stale_generation);
    assert!(validate_evidence(
        &stale_generation,
        "invocation-005",
        InitialWanRow::PrimaryFailureCrossDomainMigration,
    )
    .is_err());
}
