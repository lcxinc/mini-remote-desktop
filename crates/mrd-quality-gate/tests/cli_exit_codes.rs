use std::{fs, path::PathBuf, process::Command};

fn gate_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_mrd-quality-gate")
        .or(option_env!("CARGO_BIN_EXE_mrd_quality_gate"))
        .map(PathBuf::from)
        .expect("Cargo must expose the quality-gate binary to integration tests")
}

fn run_gate(artifact: &str, policy: &str) -> (std::process::Output, PathBuf) {
    let output_path = std::env::temp_dir().join(format!(
        "mrd-quality-gate-{}-{artifact}",
        std::process::id()
    ));
    let artifact_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/quality-gates/fixtures")
        .join(artifact);
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/quality-gates/policies")
        .join(policy);
    Command::new(gate_binary())
        .args([
            "--artifact",
            artifact_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .map(|output| (output, output_path))
        .unwrap()
}

fn run_gate_without_output(artifact: &str, policy: &str) -> std::process::Output {
    let artifact_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/quality-gates/fixtures")
        .join(artifact);
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/quality-gates/policies")
        .join(policy);
    Command::new(gate_binary())
        .args([
            "--artifact",
            artifact_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

#[test]
fn invalid_artifact_exits_four() {
    let (output, _) = run_gate("missing-present.json", "windows-1080p60-direct.v1.json");
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn valid_direct_fixture_exits_zero() {
    let (output, output_path) = run_gate("valid-direct.json", "windows-1080p60-direct.v1.json");

    assert_eq!(output.status.code(), Some(0));
    let verdict: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output_path).unwrap()).unwrap();
    assert_eq!(verdict["verdict"], "PASS");
    assert_eq!(verdict["failures"], serde_json::json!([]));
}

#[test]
fn omitted_output_writes_verdict_json_to_stdout() {
    let output = run_gate_without_output("valid-direct.json", "windows-1080p60-direct.v1.json");

    assert_eq!(output.status.code(), Some(0));
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verdict["verdict"], "PASS");
    assert_eq!(verdict["failures"], serde_json::json!([]));
}

#[test]
fn unknown_artifact_field_exits_four_instead_of_being_ignored() {
    let fixture_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/quality-gates/fixtures");
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/quality-gates/policies/windows-1080p60-direct.v1.json");
    let raw = fs::read_to_string(fixture_root.join("valid-direct.json")).unwrap();
    let mut artifact: serde_json::Value = serde_json::from_str(&raw).unwrap();
    artifact["schema_verzion"] = serde_json::json!("remote-experience-run.v2");
    let artifact_path = std::env::temp_dir().join(format!(
        "mrd-quality-gate-unknown-artifact-field-{}.json",
        std::process::id()
    ));
    fs::write(&artifact_path, serde_json::to_vec(&artifact).unwrap()).unwrap();

    let output = Command::new(gate_binary())
        .args([
            "--artifact",
            artifact_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let _ = fs::remove_file(artifact_path);

    assert_eq!(output.status.code(), Some(4));
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verdict["verdict"], "INVALID_ARTIFACT");
}
