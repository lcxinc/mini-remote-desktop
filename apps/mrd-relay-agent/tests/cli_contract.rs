use std::{fs, path::PathBuf, process::Command, time::SystemTime};

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mrd-relay-agent"))
}

fn broker() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mrd-relay-coturn-control"))
}

#[test]
fn agent_cli_rejects_ambiguous_or_relative_invocations_without_output_or_exit_78() {
    for arguments in [
        vec![],
        vec!["unknown"],
        vec!["validate", "--config"],
        vec!["validate", "--config", "relative.json"],
        vec![
            "preflight",
            "--config",
            "relative.json",
            "--challenge",
            "SECRET_SHOULD_NOT_BE_ECHOED",
        ],
    ] {
        let output = agent().args(&arguments).output().unwrap();
        assert!(!output.status.success());
        assert_ne!(output.status.code(), Some(78));
        assert!(output.stdout.is_empty());
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        assert!(matches!(
            stderr,
            "relay_cli_invalid\n" | "relay_agent_config_invalid\n"
        ));
        assert!(!stderr.contains("SECRET_SHOULD_NOT_BE_ECHOED"));
    }
}

#[test]
fn validate_is_static_and_accepts_an_inline_secret_free_production_config() {
    let config_path = temporary_config_path();
    fs::write(&config_path, VALID_CONFIG).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = agent()
        .args(["validate", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    let _ = fs::remove_file(&config_path);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn broker_cli_fails_closed_without_the_frozen_activation_contract() {
    let output = broker().output().unwrap();
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"relay_broker_cli_invalid\n");

    let output = broker().arg("--socket-activated").output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(matches!(
        stderr,
        "relay_broker_activation_invalid\n"
            | "relay_broker_platform_unavailable\n"
            | "relay_broker_cli_invalid\n"
    ));
}

#[test]
fn windows_provisioning_never_accepts_a_secret_in_argv_or_echoes_stdin() {
    let secret = "ENROLLMENT_SECRET_SHOULD_NEVER_BE_ECHOED_123456";
    let output = agent()
        .args([
            "provision-windows",
            "--config",
            "relative.json",
            "--purpose",
            "enrollment",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.as_mut().unwrap().write_all(secret.as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));

    let output = agent()
        .args([
            "provision-windows",
            "--config",
            "relative.json",
            "--purpose",
            secret,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"relay_cli_invalid\n");
}

#[cfg(target_os = "linux")]
#[test]
fn drain_proof_cli_recognizes_the_frozen_challenge_bound_invocation() {
    let config_path = temporary_config_path();
    fs::write(&config_path, VALID_CONFIG).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = agent()
        .args(["drain-proof", "--config"])
        .arg(&config_path)
        .args(["--challenge", &"5a".repeat(32)])
        .output()
        .unwrap();
    let _ = fs::remove_file(&config_path);

    assert_eq!(output.status.code(), Some(69));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"relay_platform_unavailable\n");
}

#[cfg(windows)]
#[test]
fn windows_run_enters_the_scm_dispatcher_instead_of_running_as_a_console_process() {
    let config_path = temporary_config_path();
    fs::write(&config_path, WINDOWS_SERVICE_CONFIG).unwrap();
    let output = agent()
        .args(["run", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    let _ = fs::remove_file(&config_path);

    // A console invocation is not connected to the SCM and must fail at the
    // dispatcher boundary before opening identity, runtime, or secret stores.
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"relay_agent_service_failed\n");
}

fn temporary_config_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    #[cfg(target_os = "linux")]
    let root = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .expect("Linux CLI contract tests require an absolute HOME");
    #[cfg(not(target_os = "linux"))]
    let root = std::env::temp_dir();
    root.join(format!("mrd-relay-agent-cli-{unique}.json"))
}

const VALID_CONFIG: &[u8] = br#"{
  "backend_url":"https://relay-control.example.test/",
  "node_id":"relay-hkg-1",
  "region":"hkg",
  "failure_domain":"hkg-a",
  "endpoints":[
    "turn:relay.example.test:3478?transport=udp",
    "turn:relay.example.test:3478?transport=tcp",
    "turns:relay.example.test:5349?transport=tcp"
  ],
  "max_allocations":128,
  "max_egress_bps":80000000,
  "identity_path":"/var/lib/mrd-relay-agent/identity.envelope",
  "runtime_state_path":"/var/lib/mrd-relay-agent/runtime.envelope",
  "trusted_ca_path":"/etc/mrd-relay-agent/backend-ca.pem",
  "metrics_url":"http://127.0.0.1:9641/metrics",
  "heartbeat_interval_seconds":5,
  "backend_backoff_cap_seconds":30,
  "target":"linux-systemd",
  "relay_min_port":49152,
  "relay_max_port":65535,
  "transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],
  "tls_listener_port":5349,
  "enrollment_token_path":"/run/credentials/mrd-relay-agent.service/enrollment-token",
  "turn_rest_secret_path":"/run/credentials/mrd-relay-agent.service/turn-rest-secret"
}"#;

#[cfg(windows)]
const WINDOWS_SERVICE_CONFIG: &[u8] = br#"{
  "backend_url":"https://relay-control.example.test/",
  "node_id":"relay-hkg-1",
  "region":"hkg",
  "failure_domain":"hkg-a",
  "endpoints":[
    "turn:relay.example.test:3478?transport=udp",
    "turn:relay.example.test:3478?transport=tcp",
    "turns:relay.example.test:5349?transport=tcp"
  ],
  "max_allocations":128,
  "max_egress_bps":80000000,
  "identity_path":"C:\\ProgramData\\MRD\\RelayAgent\\identity.envelope",
  "runtime_state_path":"C:\\ProgramData\\MRD\\RelayAgent\\runtime.envelope",
  "trusted_ca_path":"C:\\ProgramData\\MRD\\RelayAgent\\backend-ca.pem",
  "metrics_url":"http://127.0.0.1:9641/metrics",
  "heartbeat_interval_seconds":5,
  "backend_backoff_cap_seconds":30,
  "target":"windows-service",
  "relay_min_port":49152,
  "relay_max_port":65535,
  "transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],
  "tls_listener_port":5349,
  "enrollment_token_path":"C:\\ProgramData\\MRD\\RelayAgent\\secrets\\enrollment-token.dpapi",
  "turn_rest_secret_path":"C:\\ProgramData\\MRD\\RelayAgent\\secrets\\turn-rest-secret.dpapi",
  "target_config":{
    "kind":"windows-service",
    "agent_service_sid":"S-1-5-80-1-2-3-4-5",
    "broker_executable":"C:\\Program Files\\MRD\\mrd-relay-coturn-control.exe",
    "broker_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
    "native_wrapper":"C:\\Program Files\\MRD\\mrd-coturn-native-control.exe",
    "native_wrapper_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
    "native_wrapper_signer":"MRD Release Signing"
  }
}"#;
