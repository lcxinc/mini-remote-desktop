use std::fs;

fn workflow() -> String {
    fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/mainline-e2e.yml"
    ))
    .unwrap()
}

#[test]
fn mainline_workflow_enforces_gate_after_upload_on_pull_requests() {
    let yaml = workflow();
    assert!(
        yaml.contains("quality-gate:"),
        "workflow must define a quality-gate job"
    );
    assert!(
        yaml.contains("cargo test -p mrd-quality-gate"),
        "quality-gate tests must run"
    );
    assert!(
        yaml.contains("if: always()"),
        "gate artifacts must upload on failure"
    );
    assert!(
        yaml.contains("name: Enforce quality gate"),
        "workflow must have an explicit enforcement step"
    );
    assert!(
        !yaml.contains("continue-on-error: true"),
        "enforcement must not be optional"
    );
}

#[test]
fn windows_required_row_invokes_release_policy() {
    let yaml = workflow();
    assert!(yaml.contains("windows-1080p60-direct.v1.json"));
    assert!(yaml.contains("cargo run -p mrd-quality-gate"));
    assert!(yaml.contains("--artifact tests/quality-gates/fixtures/valid-direct.json"));
}

#[test]
fn gate_zero_runs_and_archives_security_negative_evidence() {
    let yaml = workflow();
    assert!(yaml.contains("tests/benchmarks/scripts/run_secure_lan_negative.ps1"));
    assert!(yaml.contains("secure-lan-negative.log"));
    assert!(yaml.contains("artifacts/e2e/security-negative/"));
    assert!(
        !yaml.contains("run_secure_lan_negative.ps1 2>&1 | tee secure-lan-negative.log || true"),
        "security-negative failures must propagate through the gate"
    );
}

#[test]
fn secure_lan_positive_gate_is_explicit_and_device_lab_only() {
    let yaml = workflow();
    assert!(yaml.contains("secure-lan-device-lab:"));
    assert!(yaml.contains("needs: [l0-l1-generic, quality-gate]"));
    assert!(yaml.contains("vars.MRD_DEVICE_LAB_SECURE_LAN_ENABLED == 'true'"));
    assert!(yaml.contains("runs-on: [self-hosted, Windows, X64, device-lab]"));
    assert!(yaml.contains("-ScenarioId\", \"cross.e2e.secure_remote_display\""));
    assert!(yaml.contains("-ProfileId\", \"1080p60\""));
    assert!(yaml.contains("artifacts/e2e/device-lab/secure-lan/"));
}

fn relay_control_workflow() -> String {
    fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/relay-control.yml"
    ))
    .unwrap()
}

fn cross_platform_workflow() -> String {
    fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/rust.yml"
    ))
    .unwrap()
}

fn repository_attributes() -> String {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.gitattributes")).unwrap()
}

fn multi_region_lab_workflow() -> String {
    fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/multi-region-relay-device-lab.yml"
    ))
    .unwrap()
}

#[test]
fn relay_control_ci_runs_postgres_linux_windows_and_deterministic_contracts() {
    let yaml = relay_control_workflow();
    for required in [
        "services:",
        "postgres:",
        "MRD_TEST_DATABASE_URL",
        "test_relay_repository.py",
        "test_relay_repository_postgres.py",
        "test_relay_directory_postgres.py",
        "cargo test --locked -p mrd-relay-control",
        "cargo build --locked -p mrd-relay-agent",
        "runs-on: ubuntu-latest",
        "runs-on: windows-latest",
        "test_multi_region_relay.ps1",
        "cargo test --locked -p mrd-quality-gate",
        "if: always()",
        "name: Enforce relay control gate",
    ] {
        assert!(
            yaml.contains(required),
            "missing relay CI contract: {required}"
        );
    }
    assert!(!yaml.contains("continue-on-error: true"));
}

#[test]
fn cross_platform_ci_runs_real_backend_tests_and_workspace_lints() {
    let yaml = cross_platform_workflow();
    for required in [
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "python -m pytest",
    ] {
        assert!(
            yaml.contains(required),
            "missing core CI command: {required}"
        );
    }
    assert!(
        !yaml.contains("python -m unittest discover"),
        "unittest discovery silently misses the pytest suite"
    );
}

#[test]
fn relay_control_ci_covers_runtime_and_deployment_paths_and_preserves_exit_codes() {
    let yaml = relay_control_workflow();
    for required in [
        "apps/mrd-service/src/relay/**",
        "deploy/turn/**",
        "tests/benchmarks/scripts/**",
        "HOME=/root",
        "$contractExitCode = $LASTEXITCODE",
        "$qualityGateExitCode = $LASTEXITCODE",
        "shell: pwsh",
        "$PSNativeCommandUseErrorActionPreference = $false",
    ] {
        assert!(
            yaml.contains(required),
            "missing deterministic relay CI contract: {required}"
        );
    }
    assert!(
        !yaml.contains("| Tee-Object"),
        "native commands must be captured before log rendering"
    );
}

#[test]
fn cross_platform_scripts_have_deterministic_line_endings() {
    let attributes = repository_attributes();
    for required in ["*.ps1 text eol=lf", "*.sh text eol=lf"] {
        assert!(
            attributes.contains(required),
            "missing line-ending contract: {required}"
        );
    }
}

#[test]
fn live_multi_region_workflow_is_separate_enforced_and_never_skips_missing_infra() {
    let yaml = multi_region_lab_workflow();
    for required in [
        "multi-region-relay-device-lab:",
        "runs-on: [self-hosted, Windows, X64, multi-region-relay]",
        "MRD_RELAY_LAB_CONTROL",
        "run_multi_region_relay.ps1",
        "-Scenario all",
        "if: always()",
        "name: Enforce multi-region relay verdict",
        "multi-region-relay-summary.json",
    ] {
        assert!(
            yaml.contains(required),
            "missing lab workflow contract: {required}"
        );
    }
    assert!(!yaml.contains("continue-on-error: true"));
    assert!(!yaml.contains("if-no-files-found: ignore"));
    assert!(!yaml.contains("missing infrastructure; skipping"));
    assert!(!yaml.contains("exit 0 # infra"));
}
