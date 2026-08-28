use std::{
    collections::VecDeque,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use mrd_relay_agent::{
    config::{ProductionAgentConfig, WindowsDataLayout},
    platform::{
        drain_proof_sha256,
        linux::{
            linux_probe_loopback_host, select_linux_drain_recovery,
            validate_linux_broker_peer_claim, validate_unique_wsl_interop_registration,
            LinuxBrokerPeerClaim, LinuxDrainJournalClaim, LinuxDrainJournalPhase,
            LinuxDrainRecoveryAction, LinuxDrainStateClaim, LinuxDrainTargetClaim,
            LinuxPendingDrainJournal, LinuxPendingDrainOperation, LinuxPendingOperation,
            LinuxPendingSecretJournal, LINUX_CONTROL_SOCKET,
        },
        probe_proof_sha256,
        windows::{
            parse_windows_agent_service_command, target_command_plan,
            validate_windows_agent_peer_claim, validate_windows_agent_service_sid,
            validate_windows_authenticode_claim, validate_windows_broker_peer_claim,
            validate_windows_counter_epoch, validate_windows_delegated_generation,
            validate_windows_generation_transition, validate_windows_maintenance_peer_claim,
            windows_maintenance_action_allowed, WindowsAgentPeerClaim, WindowsAuthenticodeClaim,
            WindowsBrokerClient, WindowsBrokerConfig, WindowsBrokerPeerClaim,
            WindowsGenerationTransition, WindowsMaintenancePeerClaim, WindowsTargetConfig,
        },
        BrokerAction, BrokerControlPort, BrokerRequest, CommandOutput, CommandPlan, CoturnTarget,
        PlatformCoturnRuntime, PlatformExpectation, TransportCapability,
    },
    process::{CoturnRuntimePort, ProcessError, SecretBytes},
};
use sha2::{Digest as _, Sha256};

const HELPER: &str = "/usr/local/libexec/mrd-relay-coturn-control";
const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone, Debug, PartialEq, Eq)]
struct BrokerObservation {
    target: CoturnTarget,
    action: BrokerAction,
    version: Option<u64>,
    draining: Option<bool>,
    snapshot_challenge: Option<[u8; 32]>,
    has_secret_payload: bool,
    debug: String,
}

#[derive(Default)]
struct FakeBroker {
    outputs: Mutex<VecDeque<Result<CommandOutput, ProcessError>>>,
    observations: Mutex<Vec<BrokerObservation>>,
}

impl FakeBroker {
    fn with_outputs(outputs: impl IntoIterator<Item = CommandOutput>) -> Self {
        Self {
            outputs: Mutex::new(outputs.into_iter().map(Ok).collect()),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<BrokerObservation> {
        self.observations.lock().unwrap().clone()
    }
}

#[async_trait]
impl BrokerControlPort for FakeBroker {
    async fn exchange(&self, request: BrokerRequest) -> Result<CommandOutput, ProcessError> {
        self.observations.lock().unwrap().push(BrokerObservation {
            target: request.target(),
            action: request.action(),
            version: request.secret_version(),
            draining: request.draining(),
            snapshot_challenge: request.snapshot_challenge().copied(),
            has_secret_payload: request.has_secret_payload(),
            debug: format!("{request:?}"),
        });
        let queued = self.outputs.lock().unwrap().pop_front();
        match queued {
            Some(result) => result,
            None if request.action() == BrokerAction::Probe => Ok(live_probe(&request)),
            None => Err(ProcessError::Unavailable),
        }
    }
}

fn snapshot(target: CoturnTarget, generation: u64, version: u64, draining: bool) -> CommandOutput {
    CommandOutput::new(
        0,
        format!(
            r#"{{"target":"{}","generation":{generation},"applied_secret_version":{version},"health":"healthy","active_allocations":0,"counter_source":"{}","counter_epoch":"invocation-{generation}","total_ingress_bytes":{},"total_egress_bytes":{},"measurement_monotonic_ns":{},"configured_max_allocations":128,"configured_max_egress_bps":80000000,"relay_min_port":49152,"relay_max_port":65535,"transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],"configured_endpoints":["turn:relay.example.test:3478?transport=udp","turn:relay.example.test:3478?transport=tcp","turns:relay.example.test:5349?transport=tcp"],"draining":{draining},"drain_completed":{draining}}}"#,
            target.as_str(),
            counter_source(target),
            generation * 1_000,
            generation * 2_000,
            generation * 1_000_000_000,
        )
        .into_bytes(),
    )
}

fn counter_source(target: CoturnTarget) -> &'static str {
    match target {
        CoturnTarget::LinuxSystemd => "systemd_ip_accounting",
        CoturnTarget::WindowsService => "windows_verified_wrapper",
        CoturnTarget::Docker => "docker_engine_stats",
        CoturnTarget::Wsl2 => "wsl_systemd_ip_accounting",
    }
}

fn drain_proof_response(
    target: CoturnTarget,
    generation: u64,
    version: u64,
    challenge: &[u8; 32],
) -> CommandOutput {
    let challenge_sha256: [u8; 32] = Sha256::digest(challenge).into();
    let proof = drain_proof_sha256(target, generation, version, challenge).unwrap();
    CommandOutput::new(
        0,
        format!(
            r#"{{"schema_version":1,"scope":"local","target":"{}","generation":{generation},"applied_secret_version":{version},"draining":true,"active_allocations":0,"drain_completed":true,"challenge_sha256":"{}","proof_sha256":"{}"}}"#,
            target.as_str(),
            lower_hex(&challenge_sha256),
            lower_hex(&proof),
        )
        .into_bytes(),
    )
}

fn platform_expectation() -> PlatformExpectation {
    PlatformExpectation::new(
        128,
        80_000_000,
        49_152,
        65_535,
        vec![
            TransportCapability::TurnUdp,
            TransportCapability::TurnTcp,
            TransportCapability::TurnsTcp,
        ],
        vec![
            "turn:relay.example.test:3478?transport=udp".into(),
            "turn:relay.example.test:3478?transport=tcp".into(),
            "turns:relay.example.test:5349?transport=tcp".into(),
        ],
    )
    .unwrap()
}

fn live_probe(request: &BrokerRequest) -> CommandOutput {
    let target = request.target();
    let generation = request.probe_generation().unwrap();
    let version = request.probe_secret_version().unwrap();
    let challenge = request.probe_challenge().unwrap();
    let proof = probe_proof_sha256(
        target,
        generation,
        version,
        challenge,
        "local-relay-candidate",
        "remote-relay-candidate",
        2,
        2,
        64,
        64,
    )
    .unwrap();
    CommandOutput::new(
        0,
        format!(
            r#"{{"target":"{}","generation":{generation},"applied_secret_version":{version},"challenge":"{}","listener_reachable":true,"credential_authenticated":true,"allocation_created":true,"permission_created":true,"packets_sent":2,"packets_received":2,"bytes_sent":64,"bytes_received":64,"local_candidate_kind":"relay","remote_candidate_kind":"relay","local_candidate_id":"local-relay-candidate","remote_candidate_id":"remote-relay-candidate","proof_sha256":"{}"}}"#,
            target.as_str(),
            lower_hex(challenge),
            lower_hex(&proof),
        )
        .into_bytes(),
    )
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[test]
fn command_plans_require_absolute_non_shell_executables_and_literal_arguments() {
    assert!(CommandPlan::new("relative/tool", ["snapshot"]).is_err());
    assert!(CommandPlan::new("/bin/sh", ["-c", "systemctl restart coturn"]).is_err());
    assert!(CommandPlan::new(
        r"C:\Windows\System32\cmd.exe",
        ["/c", "sc.exe stop mrd-coturn"]
    )
    .is_err());
    assert!(CommandPlan::new("/usr/bin/tool", ["*.conf"]).is_err());
    assert!(CommandPlan::new(r"\\server\share\helper.exe", ["snapshot"]).is_err());
    assert!(CommandPlan::new(r"\\?\C:\Program Files\MRD\helper.exe", ["snapshot"]).is_err());
    assert!(CommandPlan::new(r"C:\Program Files\MRD\helper.exe:stream", ["snapshot"]).is_err());

    let secret = "test-only-secret-that-must-never-appear";
    let plan = CommandPlan::new("/usr/bin/tool", ["apply-secret", "2"])
        .unwrap()
        .with_secret_stdin(SecretBytes::new(secret.as_bytes().to_vec()))
        .unwrap();
    assert!(plan.has_secret_stdin());
    assert!(!format!("{plan:?}").contains(secret));
    assert!(plan
        .arguments()
        .iter()
        .all(|argument| argument.to_string_lossy() != secret));
}

#[test]
fn windows_maintenance_cli_is_scm_installed_agent_binary_even_when_service_is_stopped() {
    let claim = WindowsMaintenancePeerClaim {
        client_is_elevated_administrator: true,
        client_process_id: 4100,
        agent_service_process_id: None,
        client_executable: PathBuf::from(r"C:\Program Files\MRD\mrd-relay-agent.exe"),
        agent_service_executable: PathBuf::from(r"C:\Program Files\MRD\mrd-relay-agent.exe"),
        client_executable_sha256: [0x11; 32],
        agent_service_executable_sha256: [0x11; 32],
    };
    assert!(validate_windows_maintenance_peer_claim(&claim).is_ok());
    assert!(
        validate_windows_maintenance_peer_claim(&WindowsMaintenancePeerClaim {
            agent_service_process_id: Some(4200),
            ..claim.clone()
        })
        .is_ok()
    );
    for changed in [
        WindowsMaintenancePeerClaim {
            client_is_elevated_administrator: false,
            ..claim.clone()
        },
        WindowsMaintenancePeerClaim {
            agent_service_process_id: Some(claim.client_process_id),
            ..claim.clone()
        },
        WindowsMaintenancePeerClaim {
            client_executable: PathBuf::from(r"C:\Temp\mrd-relay-agent.exe"),
            ..claim.clone()
        },
        WindowsMaintenancePeerClaim {
            client_executable_sha256: [0x22; 32],
            ..claim.clone()
        },
    ] {
        assert!(validate_windows_maintenance_peer_claim(&changed).is_err());
    }
    assert!(windows_maintenance_action_allowed(BrokerAction::Snapshot));
    assert!(windows_maintenance_action_allowed(BrokerAction::Probe));
    assert!(!windows_maintenance_action_allowed(BrokerAction::Restart));
    assert!(!windows_maintenance_action_allowed(
        BrokerAction::ApplySecret
    ));
    assert!(!windows_maintenance_action_allowed(
        BrokerAction::SetDraining
    ));
}

#[test]
fn windows_agent_scm_command_has_one_exact_installed_binary_and_run_config_shape() {
    let command = r#""D:\MRD\mrd-relay-agent.exe" run --config "E:\MRDData\config\agent.json""#;
    assert_eq!(
        parse_windows_agent_service_command(command).unwrap(),
        PathBuf::from(r"D:\MRD\mrd-relay-agent.exe")
    );
    let unicode = r#""D:\远程桌面\mrd-relay-agent.exe" run --config "E:\中继数据\配置\agent.json""#;
    assert_eq!(
        parse_windows_agent_service_command(unicode).unwrap(),
        PathBuf::from(r"D:\远程桌面\mrd-relay-agent.exe")
    );
    for invalid in [
        r#"D:\MRD\mrd-relay-agent.exe run --config "E:\MRDData\config\agent.json""#,
        r#""D:\MRD\other.exe" run --config "E:\MRDData\config\agent.json""#,
        r#""D:\MRD\mrd-relay-agent.exe" validate --config "E:\MRDData\config\agent.json""#,
        r#""D:\MRD\mrd-relay-agent.exe" run --config "relative.json""#,
        r#""D:\MRD\mrd-relay-agent.exe" run --config "E:\MRDData\config\agent.json" extra"#,
        "\"D:\\MRD\\mrd-relay-agent.exe\" run --config \"E:\\MRDData\\config\\agent.json\"\n",
        "\"D:\\MRD\\mrd-relay-agent.exe\" run --config \"E:\\MRDData\\config\\agent.json\u{0000}\"",
        "\"D:\\MRD\\mrd-relay-agent.exe\" run --config \"E:\\MRDData\\config\\agent\u{0007}.json\"",
    ] {
        assert!(
            parse_windows_agent_service_command(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn broker_peer_identity_must_be_verified_before_any_secret_write() {
    let linux = LinuxBrokerPeerClaim {
        peer_uid: 0,
        peer_pid: 4242,
        peer_executable: PathBuf::from("/usr/local/libexec/mrd-relay-coturn-control"),
        socket_uid: 0,
        socket_gid: 991,
        expected_agent_gid: 991,
        socket_mode: 0o660,
        parent_uid: 0,
        parent_gid: 991,
        parent_mode: 0o750,
        helper_uid: 0,
        helper_mode: 0o755,
        socket_is_socket: true,
        socket_or_parent_is_symlink: false,
    };
    assert!(validate_linux_broker_peer_claim(&linux).is_ok());
    let mut socket_activated_by_pid1 = linux.clone();
    socket_activated_by_pid1.peer_pid = 1;
    socket_activated_by_pid1.peer_executable = PathBuf::from("/usr/lib/systemd/systemd");
    assert!(
        validate_linux_broker_peer_claim(&socket_activated_by_pid1).is_ok(),
        "systemd Accept=yes may expose PID 1 as the connected root peer before the helper starts"
    );
    let mut wrong_uid = linux.clone();
    wrong_uid.peer_uid = 1000;
    assert!(validate_linux_broker_peer_claim(&wrong_uid).is_err());
    let mut permissive_socket = linux;
    permissive_socket.socket_mode = 0o666;
    assert!(validate_linux_broker_peer_claim(&permissive_socket).is_err());

    let mut wrong_group = permissive_socket;
    wrong_group.socket_mode = 0o660;
    wrong_group.socket_gid = 992;
    wrong_group.parent_gid = 992;
    assert!(validate_linux_broker_peer_claim(&wrong_group).is_err());

    let expected_hash = [0x33; 32];
    let windows = WindowsBrokerPeerClaim {
        server_is_local_system: true,
        server_has_expected_restricted_service_sid: true,
        server_process_id: 4242,
        scm_service_process_id: 4242,
        server_executable: PathBuf::from(r"C:\Program Files\MRD\mrd-relay-coturn-control.exe"),
        server_executable_sha256: expected_hash,
        expected_executable: PathBuf::from(r"C:\Program Files\MRD\mrd-relay-coturn-control.exe"),
        expected_executable_sha256: expected_hash,
    };
    assert!(validate_windows_broker_peer_claim(&windows).is_ok());
    let mut wrong_token = windows.clone();
    wrong_token.server_is_local_system = false;
    assert!(validate_windows_broker_peer_claim(&wrong_token).is_err());
    let mut wrong_binary = windows;
    wrong_binary.server_executable_sha256[0] ^= 1;
    assert!(validate_windows_broker_peer_claim(&wrong_binary).is_err());
    let mut missing_service_sid = wrong_binary.clone();
    missing_service_sid.server_executable_sha256 = expected_hash;
    missing_service_sid.server_has_expected_restricted_service_sid = false;
    assert!(validate_windows_broker_peer_claim(&missing_service_sid).is_err());
    let mut stale_scm_pid = wrong_binary;
    stale_scm_pid.server_executable_sha256 = expected_hash;
    stale_scm_pid.scm_service_process_id += 1;
    assert!(validate_windows_broker_peer_claim(&stale_scm_pid).is_err());

    assert!(WindowsBrokerClient::new(
        PathBuf::from(r"C:\Program Files\MRD\mrd-relay-coturn-control.exe"),
        expected_hash,
    )
    .is_ok());
    assert!(
        WindowsBrokerClient::new(PathBuf::from(r"\\server\helper.exe"), expected_hash).is_err()
    );
    assert!(WindowsBrokerClient::new(
        PathBuf::from(r"C:\Program Files\MRD\mrd-relay-coturn-control.exe"),
        [0; 32],
    )
    .is_err());

    let agent = WindowsAgentPeerClaim {
        client_is_local_service: true,
        client_has_expected_restricted_service_sid: true,
        client_process_id: 900,
        scm_service_process_id: 900,
    };
    assert!(validate_windows_agent_peer_claim(&agent).is_ok());
    assert!(validate_windows_agent_peer_claim(&WindowsAgentPeerClaim {
        client_is_local_service: false,
        ..agent
    })
    .is_err());
    assert!(validate_windows_agent_peer_claim(&WindowsAgentPeerClaim {
        scm_service_process_id: 901,
        ..agent
    })
    .is_err());
}

#[test]
fn linux_preflight_loopback_is_bound_to_one_rendered_listener_family() {
    assert_eq!(
        linux_probe_loopback_host(
            b"listening-port=3478\nlistening-ip=0.0.0.0\nexternal-ip=198.20.0.10\n"
        )
        .unwrap(),
        "127.0.0.1"
    );
    assert_eq!(
        linux_probe_loopback_host(
            b"listening-port=3478\nlistening-ip=::\nexternal-ip=2606:4700:4700::1111\n"
        )
        .unwrap(),
        "[::1]"
    );
    assert_eq!(
        linux_probe_loopback_host(b"listening-ip=0.0.0.0\n# listening-ip=::\n").unwrap(),
        "127.0.0.1"
    );

    for invalid in [
        b"listening-port=3478\n".as_slice(),
        b"listening-ip=127.0.0.1\n".as_slice(),
        b"listening-ip=0.0.0.0\nlistening-ip=::\n".as_slice(),
        b"listening-ip=::\nlistening-ip=::\n".as_slice(),
        b"listening-ip = ::\n".as_slice(),
        b"listening-ip=0.0.0.0\n\xff\n".as_slice(),
    ] {
        assert!(linux_probe_loopback_host(invalid).is_err());
    }
}

#[test]
fn wsl_interop_evidence_requires_one_known_registration_with_p_or_pf_flags() {
    const PREFIX: &str = "enabled\ninterpreter /init\nflags: ";
    const SUFFIX: &str = "\noffset 0\nmagic 4d5a\n";
    let p = format!("{PREFIX}P{SUFFIX}");
    let pf = format!("{PREFIX}PF{SUFFIX}");
    assert!(validate_unique_wsl_interop_registration(&[("WSLInterop", &p)]).is_ok());
    assert!(validate_unique_wsl_interop_registration(&[("WSLInterop-late", &pf)]).is_ok());

    for invalid in [
        Vec::<(&str, &str)>::new(),
        vec![("WSLInterop", p.as_str()), ("WSLInterop-late", pf.as_str())],
        vec![("WSLInterop-other", p.as_str())],
        vec![(
            "WSLInterop",
            "enabled\ninterpreter /init\nflags: F\noffset 0\nmagic 4d5a\n",
        )],
        vec![(
            "WSLInterop",
            "enabled\ninterpreter /init\nflags: PPF\noffset 0\nmagic 4d5a\n",
        )],
        vec![(
            "WSLInterop",
            "enabled\ninterpreter /init\nflags: PX\noffset 0\nmagic 4d5a\n",
        )],
        vec![(
            "WSLInterop",
            "enabled\nenabled\ninterpreter /init\nflags: P\noffset 0\nmagic 4d5a\n",
        )],
        vec![(
            "WSLInterop",
            "enabled\ninterpreter /init\nflags: P\noffset 0\nmagic 4d5a\nunknown\n",
        )],
    ] {
        assert!(validate_unique_wsl_interop_registration(&invalid).is_err());
    }
}

#[test]
fn linux_drain_recovery_never_publishes_undrained_without_trusted_zero_and_new_epoch() {
    let invocation = "0123456789abcdef0123456789abcdef";
    let next_invocation = "fedcba9876543210fedcba9876543210";
    let running = |invocation_id: &str, active_allocations| LinuxDrainTargetClaim {
        invocation_id: Some(invocation_id.to_owned()),
        target_active: true,
        clean_exit: false,
        active_allocations,
    };
    let clean_exit = LinuxDrainTargetClaim {
        invocation_id: Some(invocation.to_owned()),
        target_active: false,
        clean_exit: true,
        active_allocations: None,
    };
    let active = LinuxDrainStateClaim {
        generation: 7,
        invocation_id: invocation.to_owned(),
        draining: false,
        drain_completed: false,
        external_restart_detected: false,
    };
    let begin_drain = LinuxDrainJournalClaim {
        desired_draining: true,
        phase: LinuxDrainJournalPhase::IntentPersisted,
        previous_state: active.clone(),
    };
    assert_eq!(
        select_linux_drain_recovery(&begin_drain, &active, &running(invocation, None)).unwrap(),
        LinuxDrainRecoveryAction::ApplyDrainSignal
    );
    assert_eq!(
        select_linux_drain_recovery(&begin_drain, &active, &clean_exit).unwrap(),
        LinuxDrainRecoveryAction::CommitDrained
    );

    let drained = LinuxDrainStateClaim {
        draining: true,
        drain_completed: true,
        ..active.clone()
    };
    let finish_drain = LinuxDrainJournalClaim {
        phase: LinuxDrainJournalPhase::TargetMutationIssued,
        ..begin_drain
    };
    assert_eq!(
        select_linux_drain_recovery(&finish_drain, &drained, &clean_exit).unwrap(),
        LinuxDrainRecoveryAction::ClearJournal
    );

    let undrain = LinuxDrainJournalClaim {
        desired_draining: false,
        phase: LinuxDrainJournalPhase::IntentPersisted,
        previous_state: drained.clone(),
    };
    assert_eq!(
        select_linux_drain_recovery(&undrain, &drained, &running(invocation, Some(0))).unwrap(),
        LinuxDrainRecoveryAction::RestartUndrained
    );
    for untrusted in [None, Some(1)] {
        assert!(
            select_linux_drain_recovery(&undrain, &drained, &running(invocation, untrusted))
                .is_err()
        );
    }
    assert_eq!(
        select_linux_drain_recovery(&undrain, &drained, &running(next_invocation, Some(3)),)
            .unwrap(),
        LinuxDrainRecoveryAction::CommitUndrained
    );

    let restarted = LinuxDrainStateClaim {
        generation: 8,
        invocation_id: next_invocation.to_owned(),
        draining: false,
        drain_completed: false,
        external_restart_detected: false,
    };
    assert_eq!(
        select_linux_drain_recovery(
            &LinuxDrainJournalClaim {
                phase: LinuxDrainJournalPhase::TargetMutationIssued,
                ..undrain
            },
            &restarted,
            &running(next_invocation, None),
        )
        .unwrap(),
        LinuxDrainRecoveryAction::ClearJournal
    );
}

#[test]
fn linux_pending_journal_is_backward_compatible_and_rejects_mixed_operations() {
    let previous_state = serde_json::json!({
        "schema_version": 1,
        "target": "linux-systemd",
        "generation": 7,
        "applied_secret_version": 11,
        "invocation_id": "0123456789abcdef0123456789abcdef",
        "secret_sha256": "a".repeat(64),
        "config_sha256": "b".repeat(64),
        "draining": false,
        "drain_completed": false,
        "external_restart_detected": false
    });
    let legacy_secret = serde_json::json!({
        "schema_version": 1,
        "target": "linux-systemd",
        "desired_version": 12,
        "desired_secret_sha256": "c".repeat(64),
        "desired_config_sha256": "d".repeat(64),
        "previous_state": previous_state,
        "had_previous_secret": true,
        "had_previous_config": true
    });
    let parsed: LinuxPendingOperation = serde_json::from_value(legacy_secret.clone()).unwrap();
    assert!(matches!(parsed, LinuxPendingOperation::Secret(_)));

    let drain = serde_json::json!({
        "schema_version": 1,
        "target": "linux-systemd",
        "operation": "set_draining",
        "desired_draining": true,
        "phase": "intent_persisted",
        "previous_state": previous_state
    });
    let parsed: LinuxPendingOperation = serde_json::from_value(drain.clone()).unwrap();
    assert!(matches!(
        parsed,
        LinuxPendingOperation::Drain(LinuxPendingDrainJournal {
            operation: LinuxPendingDrainOperation::SetDraining,
            phase: LinuxDrainJournalPhase::IntentPersisted,
            ..
        })
    ));

    let mut mixed = legacy_secret.as_object().unwrap().clone();
    mixed.insert("operation".to_owned(), serde_json::json!("set_draining"));
    mixed.insert("desired_draining".to_owned(), serde_json::json!(true));
    mixed.insert("phase".to_owned(), serde_json::json!("intent_persisted"));
    for invalid in [
        serde_json::Value::Object(mixed),
        drain
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    if key == "phase" {
                        serde_json::json!("unknown")
                    } else {
                        value.clone()
                    },
                )
            })
            .collect(),
    ] {
        assert!(serde_json::from_value::<LinuxPendingOperation>(invalid).is_err());
    }

    let _type_contract: Option<(LinuxPendingSecretJournal, LinuxPendingDrainJournal)> = None;
}

#[test]
fn native_wrapper_authenticode_policy_requires_trust_and_the_exact_configured_signer() {
    let valid = WindowsAuthenticodeClaim {
        signature_trusted: true,
        signer_subject: "MRD Release Signing".to_owned(),
        expected_signer_subject: "MRD Release Signing".to_owned(),
    };
    assert!(validate_windows_authenticode_claim(&valid).is_ok());

    let mut untrusted = valid.clone();
    untrusted.signature_trusted = false;
    assert!(validate_windows_authenticode_claim(&untrusted).is_err());

    let mut wrong_signer = valid;
    wrong_signer.signer_subject = "Different Release Signing".to_owned();
    assert!(validate_windows_authenticode_claim(&wrong_signer).is_err());
}

#[test]
fn windows_agent_store_acl_is_bound_to_the_resolved_agent_service_sid() {
    let resolved = "S-1-5-80-1-2-3-4-5";
    assert!(validate_windows_agent_service_sid(resolved, resolved).is_ok());
    assert!(validate_windows_agent_service_sid("S-1-5-80-1-2-3-4-6", resolved).is_err());
    assert!(validate_windows_agent_service_sid("LocalService", resolved).is_err());
}

#[test]
fn windows_delegated_generation_is_exactly_bound_to_the_outer_transition() {
    assert!(validate_windows_delegated_generation(9, 9).is_ok());
    assert!(validate_windows_delegated_generation(8, 9).is_err());
    assert!(validate_windows_delegated_generation(10, 9).is_err());
    assert!(validate_windows_delegated_generation(0, 9).is_err());
    assert!(validate_windows_delegated_generation(9, 0).is_err());
}

#[test]
fn windows_counter_epoch_uses_the_common_128_byte_bound() {
    assert!(validate_windows_counter_epoch(&"a".repeat(128)).is_ok());
    assert!(validate_windows_counter_epoch(&"a".repeat(129)).is_err());
    assert!(validate_windows_counter_epoch("").is_err());
    assert!(validate_windows_counter_epoch("epoch\nreplacement").is_err());
}

#[test]
fn windows_external_restart_generation_transition_is_strict_and_recoverable() {
    assert_eq!(
        validate_windows_generation_transition(CoturnTarget::WindowsService, 7, false, 8).unwrap(),
        WindowsGenerationTransition::AdvanceState
    );
    assert!(
        validate_windows_generation_transition(CoturnTarget::WindowsService, 7, false, 7).is_err()
    );

    assert_eq!(
        validate_windows_generation_transition(CoturnTarget::Docker, 7, false, 7).unwrap(),
        WindowsGenerationTransition::AdvanceDockerIdentityAndState
    );
    assert_eq!(
        validate_windows_generation_transition(CoturnTarget::Docker, 7, false, 8).unwrap(),
        WindowsGenerationTransition::AdvanceState
    );
    assert_eq!(
        validate_windows_generation_transition(CoturnTarget::Docker, 8, true, 8).unwrap(),
        WindowsGenerationTransition::Stable
    );
    assert!(validate_windows_generation_transition(CoturnTarget::Docker, 8, true, 7).is_err());
}

#[test]
fn broker_frames_are_bounded_target_bound_and_keep_secret_out_of_metadata() {
    assert_eq!(
        LINUX_CONTROL_SOCKET,
        "/run/mrd-relay-coturn-control/control.sock"
    );
    let secret = [0x41_u8; 32];
    let request = BrokerRequest::apply_secret(
        CoturnTarget::LinuxSystemd,
        7,
        SecretBytes::new(secret.to_vec()),
    )
    .unwrap();
    let header = request.frame_header();

    assert_eq!(&header[..4], b"MRDC");
    assert_eq!(header[4], 1);
    assert_eq!(header[5], BrokerAction::ApplySecret as u8);
    assert_eq!(header[6], CoturnTarget::LinuxSystemd as u8);
    assert_eq!(u32::from_be_bytes(header[8..12].try_into().unwrap()), 8);
    assert_eq!(
        u32::from_be_bytes(header[12..16].try_into().unwrap()),
        secret.len() as u32
    );
    assert_eq!(request.metadata(), 7_u64.to_be_bytes());
    assert!(!format!("{request:?}").contains("41414141"));
    assert!(BrokerRequest::validate_header(header).is_ok());

    let challenge = [0x7c; 32];
    let drain_snapshot =
        BrokerRequest::snapshot_with_drain_challenge(CoturnTarget::LinuxSystemd, challenge)
            .unwrap();
    let drain_header = drain_snapshot.frame_header();
    assert_eq!(drain_snapshot.action(), BrokerAction::Snapshot);
    assert_eq!(drain_snapshot.snapshot_challenge(), Some(&challenge));
    assert_eq!(
        u32::from_be_bytes(drain_header[8..12].try_into().unwrap()),
        32
    );
    assert!(BrokerRequest::validate_header(drain_header).is_ok());
    assert!(
        BrokerRequest::snapshot_with_drain_challenge(CoturnTarget::LinuxSystemd, [0; 32]).is_err()
    );

    let mut unknown_opcode = header;
    unknown_opcode[5] = 99;
    assert!(BrokerRequest::validate_header(unknown_opcode).is_err());
    let mut unknown_target = header;
    unknown_target[6] = 99;
    assert!(BrokerRequest::validate_header(unknown_target).is_err());

    for invalid_length in [31, 33, 43] {
        assert!(BrokerRequest::apply_secret(
            CoturnTarget::LinuxSystemd,
            7,
            SecretBytes::new(vec![0x41; invalid_length]),
        )
        .is_err());
    }
}

#[tokio::test]
async fn all_targets_use_the_broker_for_all_five_runtime_operations() {
    for target in CoturnTarget::ALL {
        let broker = Arc::new(FakeBroker::with_outputs([
            snapshot(target, 1, 1, false),
            snapshot(target, 2, 1, false),
            snapshot(target, 3, 2, false),
            snapshot(target, 3, 2, true),
        ]));
        let runtime =
            PlatformCoturnRuntime::new(target, broker.clone(), platform_expectation()).unwrap();

        assert_eq!(runtime.target(), target);
        assert_eq!(runtime.snapshot().await.unwrap().generation, 1);
        runtime.restart().await.unwrap();
        runtime
            .apply_secret(2, SecretBytes::new(vec![0x42; 32]))
            .await
            .unwrap();
        runtime.set_draining(true).await.unwrap();
        assert!(runtime
            .probe_local_allocation()
            .await
            .unwrap()
            .is_real_roundtrip());

        let observations = broker.observations();
        assert_eq!(observations.len(), 5);
        assert!(observations.iter().all(|item| item.target == target));
        assert_eq!(
            observations
                .iter()
                .map(|item| item.action)
                .collect::<Vec<_>>(),
            [
                BrokerAction::Snapshot,
                BrokerAction::Restart,
                BrokerAction::ApplySecret,
                BrokerAction::SetDraining,
                BrokerAction::Probe,
            ]
        );
        assert_eq!(observations[2].version, Some(2));
        assert!(observations[2].has_secret_payload);
        assert_eq!(observations[3].draining, Some(true));
        assert!(observations
            .iter()
            .all(|item| !item.debug.contains("42424242")));
    }
}

#[test]
fn windows_broker_inner_plans_bind_verified_targets_without_shells_or_secrets() {
    let configurations = [
        (
            CoturnTarget::WindowsService,
            WindowsBrokerConfig::native(Some(PathBuf::from(
                r"C:\Program Files\MRD\mrd-coturn-native-wrapper.exe",
            ))),
        ),
        (
            CoturnTarget::Docker,
            WindowsBrokerConfig::docker_bound(
                PathBuf::from(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
                CONTAINER_ID.to_owned(),
            ),
        ),
        (
            CoturnTarget::Wsl2,
            WindowsBrokerConfig::wsl2(PathBuf::from(r"C:\Windows\System32\wsl.exe")),
        ),
    ];

    for (target, config) in configurations {
        let plan = target_command_plan(&config, BrokerRequest::snapshot(target)).unwrap();
        assert!(plan.executable().to_string_lossy().starts_with("C:\\"));
        assert!(!plan.has_secret_stdin());
        assert_literal_plan(&plan);
        let arguments: Vec<_> = plan
            .arguments()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        match target {
            CoturnTarget::WindowsService => {
                assert!(plan
                    .executable()
                    .to_string_lossy()
                    .ends_with("mrd-coturn-native-wrapper.exe"));
            }
            CoturnTarget::Docker => {
                assert_eq!(arguments, ["inspect", "--type", "container", CONTAINER_ID]);
                assert!(arguments.iter().all(|arg| arg != HELPER));
            }
            CoturnTarget::Wsl2 => {
                assert!(arguments
                    .windows(2)
                    .any(|pair| pair == ["--distribution", "MRDRelay"]));
                assert!(arguments.windows(2).any(|pair| pair == ["--user", "root"]));
                assert!(arguments.iter().any(|argument| argument == "--wsl-broker"));
                assert!(arguments.windows(2).any(|pair| pair == ["--exec", HELPER]));
            }
            CoturnTarget::LinuxSystemd => unreachable!(),
        }
    }

    let unverified = WindowsBrokerConfig::native(None);
    assert!(target_command_plan(
        &unverified,
        BrokerRequest::set_draining(CoturnTarget::WindowsService, true),
    )
    .is_err());

    for (target, config) in [
        (
            CoturnTarget::WindowsService,
            WindowsBrokerConfig::native(Some(PathBuf::from(
                r"C:\Program Files\MRD\mrd-coturn-native-wrapper.exe",
            ))),
        ),
        (
            CoturnTarget::Docker,
            WindowsBrokerConfig::docker_bound(
                PathBuf::from(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
                CONTAINER_ID.to_owned(),
            ),
        ),
        (
            CoturnTarget::Wsl2,
            WindowsBrokerConfig::wsl2(PathBuf::from(r"C:\Windows\System32\wsl.exe")),
        ),
    ] {
        let apply = target_command_plan(
            &config,
            BrokerRequest::apply_secret(target, 9, SecretBytes::new(vec![0x55; 32])).unwrap(),
        );
        if target == CoturnTarget::Docker {
            assert!(apply.is_err());
        } else {
            let apply = apply.unwrap();
            let apply_args: Vec<_> = apply
                .arguments()
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert!(apply.has_secret_stdin());
            assert_eq!(&apply_args[apply_args.len() - 2..], ["apply-secret", "9"]);
            assert!(apply_args.iter().all(|arg| !arg.contains("55555555")));
        }

        let drain =
            target_command_plan(&config, BrokerRequest::set_draining(target, false)).unwrap();
        let drain_args: Vec<_> = drain
            .arguments()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        if target == CoturnTarget::Docker {
            assert_eq!(drain_args, ["restart", "--time", "30", CONTAINER_ID]);
        } else {
            assert_eq!(
                &drain_args[drain_args.len() - 2..],
                ["set-draining", "false"]
            );
        }
        assert!(!drain.has_secret_stdin());
    }

    assert!(target_command_plan(
        &WindowsBrokerConfig::docker(PathBuf::from(
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        )),
        BrokerRequest::snapshot(CoturnTarget::Docker),
    )
    .is_err());
}

#[test]
fn windows_docker_target_contract_builds_a_fresh_exact_identity_bound_create_plan() {
    let document = br#"{
      "schema_version":1,
      "target":"Docker",
      "control_pipe":"\\\\.\\pipe\\mrd-relay-coturn-control",
      "minimum_coturn_version":"4.17.2",
      "tls_port":5349,
      "relay_port_min":49160,
      "relay_port_max":49260,
      "max_allocations":100,
      "max_egress_bps":1000000000,
      "coturn_bps_capacity_bytes_per_second":125000000,
      "metrics_bind":"127.0.0.1:9641",
      "local_acceptance_command":["preflight","--config","ABSOLUTE_CONFIG","--challenge","HEX64"],
      "turnserver_baseline_path":"C:\\ProgramData\\MRD Relay\\broker\\turnserver.conf.base",
      "configured_endpoints":[
        "turn:relay.example.test:3478?transport=udp",
        "turn:relay.example.test:3478?transport=tcp",
        "turns:relay.example.test:5349?transport=tcp"
      ],
      "transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],
      "docker_executable":"C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
      "container_name":"mrd-coturn",
      "expected_container_id_state_path":"C:\\ProgramData\\MRD Relay\\broker\\docker-identity.json",
      "image":"coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e",
      "RestartPolicy":"restart=no",
      "labels":{"io.mrd.relay.managed":"true"},
      "read_only_rootfs":true,
      "bind_mounts":[
        {"source":"C:\\ProgramData\\MRD Relay\\broker\\docker-envelope","destination":"/run/mrd/turnserver.conf","read_only":true},
        {"source":"C:\\ProgramData\\MRD Relay\\tls","destination":"/run/mrd/tls","read_only":true}
      ],
      "published_ports":[
        "3478:3478/udp","3478:3478/tcp","5349:5349/tcp",
        "49160-49260:49160-49260/udp","49160-49260:49160-49260/tcp",
        "127.0.0.1:9641:9641/tcp"
      ]
    }"#;
    let target = WindowsTargetConfig::parse(document).unwrap();
    assert_eq!(target.target(), CoturnTarget::Docker);
    let plan = target.docker_fresh_create_plan().unwrap();
    assert_literal_plan(&plan);
    assert!(!plan.has_secret_stdin());
    let arguments: Vec<_> = plan
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    assert_eq!(&arguments[..3], ["create", "--name", "mrd-coturn"]);
    assert!(arguments
        .windows(2)
        .any(|pair| { pair == ["--label", "io.mrd.relay.managed=true"] }));
    assert!(arguments.windows(2).any(|pair| pair == ["--restart", "no"]));
    assert!(arguments.iter().any(|argument| argument == "--read-only"));
    assert!(arguments
        .windows(2)
        .any(|pair| pair == ["--entrypoint", "/usr/bin/turnserver"]));
    assert!(arguments
        .windows(2)
        .any(|pair| pair == ["--user", "65534:65534"]));
    assert!(arguments
        .windows(2)
        .any(|pair| pair == ["--network", "bridge"]));
    assert!(arguments
        .windows(2)
        .any(|pair| pair == ["--ipc", "private"]));
    assert!(arguments
        .windows(2)
        .any(|pair| pair == ["--cap-drop", "ALL"]));
    assert!(arguments
        .windows(2)
        .any(|pair| { pair == ["--security-opt", "no-new-privileges:true"] }));
    assert!(!arguments.iter().any(|argument| argument == "--privileged"));
    assert!(!arguments.iter().any(|argument| argument == "--cap-add"));
    assert!(arguments.iter().any(|argument| {
        argument == "coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e"
    }));
    assert_eq!(
        &arguments[arguments.len() - 2..],
        ["--config", "/run/mrd/turnserver.conf"]
    );

    for invalid in [
        String::from_utf8(document.to_vec())
            .unwrap()
            .replace("io.mrd.relay.managed", "com.mrd.relay.managed"),
        String::from_utf8(document.to_vec())
            .unwrap()
            .replace("restart=no", "always"),
        String::from_utf8(document.to_vec())
            .unwrap()
            .replace("125000000", "125000001"),
        String::from_utf8(document.to_vec())
            .unwrap()
            .replace("@sha256:aa68", ":latest@sha256:aa68"),
    ] {
        assert!(WindowsTargetConfig::parse(invalid.as_bytes()).is_err());
    }
}

#[tokio::test]
async fn target_mismatch_and_incomplete_probe_evidence_fail_closed() {
    let target = CoturnTarget::Wsl2;
    let wrong_target = Arc::new(FakeBroker::with_outputs([snapshot(
        CoturnTarget::Docker,
        1,
        1,
        false,
    )]));
    let runtime = PlatformCoturnRuntime::new(target, wrong_target, platform_expectation()).unwrap();
    assert_eq!(runtime.snapshot().await, Err(ProcessError::ProbeInvalid));

    let incomplete = CommandOutput::new(
        0,
        format!(
            r#"{{"target":"{}","listener_reachable":true,"credential_authenticated":true,"allocation_created":true,"permission_created":false,"packets_sent":2,"packets_received":2,"bytes_sent":64,"bytes_received":64,"local_candidate_kind":"relay","remote_candidate_kind":"relay","proof_sha256":"{}"}}"#,
            target.as_str(),
            "11".repeat(32),
        )
        .into_bytes(),
    );
    let broker = Arc::new(FakeBroker::with_outputs([incomplete]));
    let runtime =
        PlatformCoturnRuntime::new(target, broker.clone(), platform_expectation()).unwrap();
    assert_eq!(
        runtime.probe_local_allocation().await,
        Err(ProcessError::ProbeInvalid)
    );
}

struct ReplayProbeBroker {
    target: CoturnTarget,
    replay: Mutex<Option<CommandOutput>>,
}

#[async_trait]
impl BrokerControlPort for ReplayProbeBroker {
    async fn exchange(&self, request: BrokerRequest) -> Result<CommandOutput, ProcessError> {
        if request.action() == BrokerAction::Snapshot {
            return Ok(snapshot(self.target, 4, 3, false));
        }
        if request.action() != BrokerAction::Probe {
            return Err(ProcessError::Unavailable);
        }
        let mut replay = self.replay.lock().unwrap();
        if let Some(output) = replay.take() {
            return Ok(output);
        }
        let first = live_probe(&request);
        *replay = Some(CommandOutput::new(
            first.exit_code(),
            first.stdout().to_vec(),
        ));
        Ok(first)
    }
}

#[tokio::test]
async fn probe_response_is_single_use_and_bound_to_current_generation_version_and_challenge() {
    let target = CoturnTarget::LinuxSystemd;
    let broker = Arc::new(ReplayProbeBroker {
        target,
        replay: Mutex::new(None),
    });
    let runtime = PlatformCoturnRuntime::new(target, broker, platform_expectation()).unwrap();
    runtime.snapshot().await.unwrap();
    assert!(runtime.probe_local_allocation().await.is_ok());
    assert_eq!(
        runtime.probe_local_allocation().await,
        Err(ProcessError::ProbeInvalid),
        "the second request has a fresh challenge and must reject the captured response"
    );
}

#[tokio::test]
async fn snapshot_capacity_counter_source_ports_transports_and_endpoints_are_strictly_bound() {
    let target = CoturnTarget::Docker;
    let valid = String::from_utf8(snapshot(target, 1, 1, false).stdout().to_vec()).unwrap();
    for (old, new) in [
        ("\"docker_engine_stats\"", "\"systemd_ip_accounting\""),
        (
            "\"configured_max_allocations\":128",
            "\"configured_max_allocations\":127",
        ),
        (
            "\"configured_max_egress_bps\":80000000",
            "\"configured_max_egress_bps\":10000000",
        ),
        ("\"relay_min_port\":49152", "\"relay_min_port\":49153"),
        ("\"turn_udp\"", "\"dtls\""),
        (
            "turn:relay.example.test:3478?transport=udp",
            "turn:other.example.test:3478?transport=udp",
        ),
    ] {
        let broker = Arc::new(FakeBroker::with_outputs([CommandOutput::new(
            0,
            valid.replacen(old, new, 1).into_bytes(),
        )]));
        let runtime = PlatformCoturnRuntime::new(target, broker, platform_expectation()).unwrap();
        assert_eq!(
            runtime.snapshot().await,
            Err(ProcessError::ProbeInvalid),
            "mismatch at {old} must fail closed"
        );
    }
}

#[tokio::test]
async fn verified_platform_traffic_requires_two_same_generation_counter_samples() {
    let target = CoturnTarget::LinuxSystemd;
    let first = snapshot(target, 7, 3, false);
    let second = String::from_utf8(snapshot(target, 7, 3, false).stdout().to_vec())
        .unwrap()
        .replace(
            "\"total_ingress_bytes\":7000",
            "\"total_ingress_bytes\":8000",
        )
        .replace(
            "\"total_egress_bytes\":14000",
            "\"total_egress_bytes\":16000",
        )
        .replace(
            "\"measurement_monotonic_ns\":7000000000",
            "\"measurement_monotonic_ns\":8000000000",
        );
    let broker = Arc::new(FakeBroker::with_outputs([
        first,
        CommandOutput::new(0, second.into_bytes()),
    ]));
    let runtime = PlatformCoturnRuntime::new(target, broker, platform_expectation()).unwrap();

    assert_eq!(
        runtime.collect_metrics_sample().await,
        Err(ProcessError::ProbeInvalid)
    );
    let sample = runtime.collect_metrics_sample().await.unwrap();
    assert_eq!(sample.generation, 7);
    assert_eq!(sample.active_allocations, 0);
    assert_eq!(sample.current_ingress_bps, 8_000);
    assert_eq!(sample.current_egress_bps, 16_000);
}

#[tokio::test]
async fn read_only_preflight_uses_supplied_challenge_and_emits_exact_success_schema() {
    let target = CoturnTarget::LinuxSystemd;
    let broker = Arc::new(FakeBroker::with_outputs([snapshot(target, 11, 6, false)]));
    let runtime =
        PlatformCoturnRuntime::new(target, broker.clone(), platform_expectation()).unwrap();
    let evidence = runtime.preflight([0xa5; 32]).await.unwrap();
    let value = serde_json::to_value(&evidence).unwrap();
    let keys: std::collections::BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "schema_version",
            "scope",
            "target",
            "generation",
            "applied_secret_version",
            "challenge_sha256",
            "listener_reachable",
            "credential_authenticated",
            "allocation_created",
            "permission_created",
            "packets_sent",
            "packets_received",
            "bytes_sent",
            "bytes_received",
            "local_candidate_kind",
            "remote_candidate_kind",
            "proof_sha256",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["scope"], "local");
    assert_eq!(value["target"], target.as_str());
    assert_eq!(value["generation"], 11);
    assert_eq!(value["applied_secret_version"], 6);
    assert_eq!(value["local_candidate_kind"], "relay");
    assert_eq!(value["remote_candidate_kind"], "relay");
    assert_ne!(value["challenge_sha256"], "a5".repeat(32));

    let observations = broker.observations();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].action, BrokerAction::Snapshot);
    assert_eq!(observations[1].action, BrokerAction::Probe);
}

#[tokio::test]
async fn drain_proof_requires_a_broker_committed_zero_allocation_drain_and_binds_challenge() {
    let target = CoturnTarget::LinuxSystemd;
    let challenge = [0x5a; 32];
    let broker = Arc::new(FakeBroker::with_outputs([drain_proof_response(
        target, 12, 7, &challenge,
    )]));
    let runtime =
        PlatformCoturnRuntime::new(target, broker.clone(), platform_expectation()).unwrap();
    let evidence = runtime.drain_proof(challenge).await.unwrap();
    let value = serde_json::to_value(&evidence).unwrap();
    let keys: std::collections::BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "schema_version",
            "scope",
            "target",
            "generation",
            "applied_secret_version",
            "draining",
            "active_allocations",
            "drain_completed",
            "challenge_sha256",
            "proof_sha256",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["scope"], "local");
    assert_eq!(value["target"], target.as_str());
    assert_eq!(value["generation"], 12);
    assert_eq!(value["applied_secret_version"], 7);
    assert_eq!(value["draining"], true);
    assert_eq!(value["active_allocations"], 0);
    assert_eq!(value["drain_completed"], true);
    assert_eq!(
        value["proof_sha256"],
        lower_hex(&drain_proof_sha256(target, 12, 7, &challenge).unwrap())
    );
    let observations = broker.observations();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].action, BrokerAction::Snapshot);
    assert_eq!(observations[0].snapshot_challenge, Some(challenge));

    for (old, new) in [
        ("\"draining\":true", "\"draining\":false"),
        ("\"active_allocations\":0", "\"active_allocations\":1"),
        ("\"drain_completed\":true", "\"drain_completed\":false"),
    ] {
        let invalid = String::from_utf8(
            drain_proof_response(target, 12, 7, &challenge)
                .stdout()
                .to_vec(),
        )
        .unwrap()
        .replacen(old, new, 1);
        let broker = Arc::new(FakeBroker::with_outputs([CommandOutput::new(
            0,
            invalid.into_bytes(),
        )]));
        let runtime = PlatformCoturnRuntime::new(target, broker, platform_expectation()).unwrap();
        assert_eq!(
            runtime.drain_proof(challenge).await,
            Err(ProcessError::ProbeInvalid)
        );
    }

    let ordinary_snapshot = Arc::new(FakeBroker::with_outputs([snapshot(target, 12, 7, true)]));
    let runtime =
        PlatformCoturnRuntime::new(target, ordinary_snapshot, platform_expectation()).unwrap();
    assert_eq!(
        runtime.drain_proof(challenge).await,
        Err(ProcessError::ProbeInvalid)
    );
}

#[test]
fn production_config_is_closed_target_bound_and_contains_only_secret_paths() {
    let valid = r#"{
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
    let config = ProductionAgentConfig::from_slice(valid.as_bytes()).unwrap();
    assert_eq!(config.target(), CoturnTarget::LinuxSystemd);
    assert_eq!(config.platform_expectation().max_allocations(), 128);
    assert_eq!(config.platform_expectation().max_egress_bps(), 80_000_000);

    for invalid in [
        valid.replace(
            "\"turn_rest_secret_path\"",
            "\"turn_rest_secret\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"turn_rest_secret_path\"",
        ),
        valid.replace("80000000", "80000001"),
        valid.replace(
            "/run/credentials/mrd-relay-agent.service/enrollment-token",
            "/tmp/enrollment-token",
        ),
        valid.replace("\"linux-systemd\"", "\"docker\""),
        valid.replace("\"turns_tcp\"", "\"dtls\""),
    ] {
        assert!(ProductionAgentConfig::from_slice(invalid.as_bytes()).is_err());
    }
}

#[test]
fn windows_data_layout_is_unicode_custom_root_bound_by_exact_components() {
    let layout = WindowsDataLayout::from_config_path(Path::new(
        r"D:\中继数据\MRD\RelayAgent\config\agent.json",
    ))
    .unwrap();
    assert!(layout.matches_relative(
        Path::new(r"d:\中继数据\mrd\relayagent\state\identity.json"),
        &["state", "identity.json"],
    ));
    assert!(layout.matches_relative(
        Path::new(r"D:\中继数据\MRD\RelayAgent\broker\docker-envelope"),
        &["broker", "docker-envelope"],
    ));
    for escaped in [
        r"D:\prefix\中继数据\MRD\RelayAgent\state\identity.json",
        r"D:\中继数据\MRD\RelayAgent-old\state\identity.json",
        r"D:\中继数据\MRD\RelayAgent\state\..\identity.json",
        r"\\server\share\中继数据\MRD\RelayAgent\state\identity.json",
        r"D:\中继数据\MRD\RelayAgent\state\identity.json:stream",
    ] {
        assert!(!layout.matches_relative(Path::new(escaped), &["state", "identity.json"]));
    }
    assert!(WindowsDataLayout::from_config_path(Path::new(
        r"D:\中继数据\MRD\RelayAgent\agent.json",
    ))
    .is_err());
}

#[test]
fn windows_production_config_binds_every_mutable_and_static_path_to_the_config_data_root() {
    let valid = r#"{
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
        "identity_path":"D:\\中继数据\\MRD\\RelayAgent\\state\\identity.json",
        "runtime_state_path":"D:\\中继数据\\MRD\\RelayAgent\\state\\runtime.json",
        "trusted_ca_path":"D:\\中继数据\\MRD\\RelayAgent\\config\\trusted-ca.pem",
        "metrics_url":"http://127.0.0.1:9641/metrics",
        "heartbeat_interval_seconds":5,
        "backend_backoff_cap_seconds":30,
        "target":"windows-service",
        "relay_min_port":49152,
        "relay_max_port":65535,
        "transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],
        "tls_listener_port":5349,
        "enrollment_token_path":"D:\\中继数据\\MRD\\RelayAgent\\secrets\\enrollment-token.dpapi",
        "turn_rest_secret_path":"D:\\中继数据\\MRD\\RelayAgent\\secrets\\turn-rest-secret.dpapi",
        "target_config":{
            "kind":"windows-service",
            "agent_service_sid":"S-1-5-80-1-2-3-4-5",
            "broker_executable":"D:\\Program Files\\MRD\\mrd-relay-coturn-control.exe",
            "broker_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "native_wrapper":"D:\\Program Files\\MRD\\mrd-coturn-native-control.exe",
            "native_wrapper_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "native_wrapper_signer":"MRD Release Signing"
        }
    }"#;
    let config_path = Path::new(r"D:\中继数据\MRD\RelayAgent\config\agent.json");
    let config = ProductionAgentConfig::from_slice_at_path(valid.as_bytes(), config_path).unwrap();
    assert_eq!(
        config.windows_data_root(),
        Some(Path::new(r"D:\中继数据\MRD\RelayAgent"))
    );

    for invalid in [
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\state\\identity.json"#,
            r#"D:\\中继数据\\MRD\\RelayAgent-old\\state\\identity.json"#,
        ),
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\state\\runtime.json"#,
            r#"D:\\中继数据\\MRD\\RelayAgent\\state\\nested\\runtime.json"#,
        ),
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\secrets\\enrollment-token.dpapi"#,
            r#"D:\\prefix\\中继数据\\MRD\\RelayAgent\\secrets\\enrollment-token.dpapi"#,
        ),
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\config\\trusted-ca.pem"#,
            r#"E:\\中继数据\\MRD\\RelayAgent\\config\\trusted-ca.pem"#,
        ),
    ] {
        assert!(
            ProductionAgentConfig::from_slice_at_path(invalid.as_bytes(), config_path).is_err()
        );
    }
    assert!(ProductionAgentConfig::from_slice_at_path(
        valid.as_bytes(),
        Path::new(r"D:\prefix\中继数据\MRD\RelayAgent\config\agent.json"),
    )
    .is_err());
}

#[test]
fn windows_docker_production_config_requires_the_exact_two_read_only_data_root_mounts() {
    let valid = r#"{
        "backend_url":"https://relay-control.example.test/","node_id":"relay-hkg-1",
        "region":"hkg","failure_domain":"hkg-a",
        "endpoints":["turn:relay.example.test:3478?transport=udp","turn:relay.example.test:3478?transport=tcp","turns:relay.example.test:5349?transport=tcp"],
        "max_allocations":128,"max_egress_bps":80000000,
        "identity_path":"D:\\中继数据\\MRD\\RelayAgent\\state\\identity.json",
        "runtime_state_path":"D:\\中继数据\\MRD\\RelayAgent\\state\\runtime.json",
        "trusted_ca_path":"D:\\中继数据\\MRD\\RelayAgent\\config\\trusted-ca.pem",
        "metrics_url":"http://127.0.0.1:9641/metrics","heartbeat_interval_seconds":5,
        "backend_backoff_cap_seconds":30,"target":"docker","relay_min_port":49152,
        "relay_max_port":65535,"transport_capabilities":["turn_udp","turn_tcp","turns_tcp"],
        "tls_listener_port":5349,
        "enrollment_token_path":"D:\\中继数据\\MRD\\RelayAgent\\secrets\\enrollment-token.dpapi",
        "turn_rest_secret_path":"D:\\中继数据\\MRD\\RelayAgent\\secrets\\turn-rest-secret.dpapi",
        "target_config":{
            "kind":"docker","agent_service_sid":"S-1-5-80-1-2-3-4-5",
            "broker_executable":"D:\\Program Files\\MRD\\mrd-relay-coturn-control.exe",
            "broker_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "docker_executable":"D:\\Program Files\\Docker\\docker.exe",
            "canonical_image":"coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e",
            "expected_container_id_state_path":"D:\\中继数据\\MRD\\RelayAgent\\broker\\docker-identity.json",
            "managed_label":"io.mrd.relay.managed=true","container_read_only":true,
            "restart_policy":"no","relay_udp_range_published":true,
            "published_ports":[
                {"host_port":3478,"container_port":3478,"protocol":"udp"},
                {"host_port":3478,"container_port":3478,"protocol":"tcp"},
                {"host_port":5349,"container_port":5349,"protocol":"tcp"}
            ],
            "read_only_mounts":[
                {"source":"D:\\中继数据\\MRD\\RelayAgent\\broker\\docker-envelope","destination":"/run/mrd/turnserver.conf","read_only":true},
                {"source":"D:\\中继数据\\MRD\\RelayAgent\\tls","destination":"/run/mrd/tls","read_only":true}
            ]
        }
    }"#;
    let config_path = Path::new(r"D:\中继数据\MRD\RelayAgent\config\agent.json");
    assert!(ProductionAgentConfig::from_slice_at_path(valid.as_bytes(), config_path).is_ok());
    for (case, invalid) in [
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\broker\\docker-envelope"#,
            r#"D:\\中继数据\\MRD\\RelayAgent-old\\broker\\docker-envelope"#,
        ),
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\tls"#,
            r#"D:\\中继数据\\MRD\\RelayAgent\\tls-old"#,
        ),
        valid.replace(
            r#"D:\\中继数据\\MRD\\RelayAgent\\broker\\docker-identity.json"#,
            r#"D:\\prefix\\中继数据\\MRD\\RelayAgent\\broker\\docker-identity.json"#,
        ),
        valid.replace(
            r#""read_only_mounts":["#,
            r#""read_only_mounts":[{"source":"D:\\中继数据\\MRD\\RelayAgent\\broker\\extra","destination":"/run/mrd/extra","read_only":true},"#,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            ProductionAgentConfig::from_slice_at_path(invalid.as_bytes(), config_path).is_err(),
            "accepted invalid Docker layout case {case}"
        );
    }
}

fn assert_literal_plan(plan: &CommandPlan) {
    let executable = plan.executable().to_string_lossy();
    assert!(!matches!(
        executable
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "sh" | "bash" | "cmd" | "cmd.exe" | "powershell" | "powershell.exe" | "pwsh.exe"
    ));
    let arguments: Vec<OsString> = plan.arguments().to_vec();
    assert!(!arguments.iter().any(|argument| {
        let argument = argument.to_string_lossy();
        matches!(argument.as_ref(), "-c" | "/c" | "/k" | "--command")
            || argument.contains(['*', '?', '[', ']'])
    }));
}
