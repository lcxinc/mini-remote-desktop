#![cfg(target_os = "linux")]

use std::{
    io::Write as _,
    process::{Command, Stdio},
};

fn broker() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mrd-relay-coturn-control"))
}

#[test]
fn valid_wsl_snapshot_reaches_the_root_and_kernel_evidence_gate() {
    let output = broker()
        .args(["--wsl-broker", "snapshot"])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"relay_broker_activation_invalid\n");
}

#[test]
fn every_typed_wsl_action_reaches_the_kernel_evidence_gate() {
    for arguments in [
        vec!["--wsl-broker", "restart"],
        vec!["--wsl-broker", "set-draining", "true"],
        vec!["--wsl-broker", "set-draining", "false"],
    ] {
        let output = broker()
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(70));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"relay_broker_activation_invalid\n");
    }

    let secret = b"0123456789abcdef0123456789abcdef";
    let mut child = broker()
        .args(["--wsl-broker", "apply-secret", "17"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(secret).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"relay_broker_activation_invalid\n");
    assert!(!output
        .stderr
        .windows(secret.len())
        .any(|value| value == secret));
}

#[test]
fn wsl_probe_and_untyped_actions_are_cli_errors_without_reading_stdin() {
    for arguments in [
        vec!["--wsl-broker", "probe"],
        vec!["--wsl-broker", "apply-secret"],
        vec!["--wsl-broker", "apply-secret", "0"],
        vec!["--wsl-broker", "set-draining", "1"],
        vec!["--wsl-broker", "snapshot", "extra"],
    ] {
        let output = broker()
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"relay_broker_cli_invalid\n");
    }
}
