use std::path::Path;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use mrd_relay_agent::{
    broker::{
        decode_request_frame, derive_coturn_rest_credentials, encode_response_frame,
        parse_docker_engine_stats_http, render_linux_coturn_config, select_pending_recovery,
        select_windows_pending_recovery, validate_linux_client_peer, validate_probe_stability,
        validate_socket_activation, CoturnRestCredentials, LinuxClientPeerClaim,
        PendingRecoveryAction, PendingRecoveryObservation, ProbeStabilityObservation,
        SocketActivationClaim, WindowsPendingRecoveryAction, WindowsPendingRecoveryObservation,
    },
    platform::{linux, BrokerAction, BrokerRequest, CoturnTarget},
    process::SecretBytes,
};
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicIpVectors {
    schema_version: u8,
    accepted: Vec<String>,
    rejected: Vec<String>,
    accepted_mappings: Vec<ExternalIpMapping>,
    rejected_mappings: Vec<ExternalIpMapping>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalIpMapping {
    external_ip: String,
    relay_ip: String,
}

trait AmbiguousIfDebug<A> {
    fn assert_not_debug() {}
}

impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<u8> for T {}

fn encoded_request(request: &BrokerRequest, secret: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(&request.frame_header());
    encoded.extend_from_slice(request.metadata());
    if let Some(secret) = secret {
        encoded.extend_from_slice(secret);
    }
    encoded
}

fn hardened_coturn_template() -> Vec<u8> {
    String::from_utf8(include_bytes!("../../../deploy/turn/turnserver.conf.example").to_vec())
        .unwrap()
        .replace("CHANGE_ME_RELAY_REALM", "relay.example.net")
        .replace("CHANGE_ME_RELAY_FQDN", "relay.example.net")
        .replace(
            "CHANGE_ME_WITH_43_CHAR_BASE64URL_SECRET",
            "__MRD_BROKER_SECRET_V1__",
        )
        .into_bytes()
}

fn replace_config_line(template: &[u8], needle: &str, replacement: Option<&str>) -> Vec<u8> {
    let text = std::str::from_utf8(template).unwrap();
    let mut matched = 0;
    let mut output = String::new();
    for line in text.lines() {
        if line == needle {
            matched += 1;
            if let Some(replacement) = replacement {
                output.push_str(replacement);
                output.push('\n');
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    assert_eq!(matched, 1, "fixture line must occur exactly once: {needle}");
    output.into_bytes()
}

fn append_config_line(template: &[u8], line: &str) -> Vec<u8> {
    let mut output = template.to_vec();
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(line.as_bytes());
    output.push(b'\n');
    output
}

fn append_external_mapping(template: &[u8], mapping: &ExternalIpMapping) -> Vec<u8> {
    let template = append_config_line(template, &format!("external-ip={}", mapping.external_ip));
    if mapping.relay_ip.is_empty() {
        template
    } else {
        append_config_line(&template, &format!("relay-ip={}", mapping.relay_ip))
    }
}

fn bind_listener_to_public_address(template: &[u8], external_ip: &str) -> Vec<u8> {
    let public = external_ip.split('/').next().unwrap();
    let listener = if public.parse::<std::net::IpAddr>().unwrap().is_ipv6() {
        "listening-ip=::"
    } else {
        "listening-ip=0.0.0.0"
    };
    replace_config_line(template, "listening-ip=0.0.0.0", Some(listener))
}

#[test]
fn broker_decoder_accepts_only_one_exact_bounded_request() {
    let snapshot = BrokerRequest::snapshot(CoturnTarget::LinuxSystemd);
    let decoded = decode_request_frame(encoded_request(&snapshot, None)).unwrap();
    assert_eq!(decoded.target(), CoturnTarget::LinuxSystemd);
    assert_eq!(decoded.action(), BrokerAction::Snapshot);
    assert!(!decoded.has_secret_payload());

    let apply = BrokerRequest::apply_secret(
        CoturnTarget::LinuxSystemd,
        17,
        SecretBytes::new(vec![0x5a; 32]),
    )
    .unwrap();
    let decoded = decode_request_frame(encoded_request(&apply, Some(&[0x5a; 32]))).unwrap();
    assert_eq!(decoded.secret_version(), Some(17));
    assert!(decoded.has_secret_payload());
    assert!(!format!("{decoded:?}").contains("5a5a"));

    let mut trailing = encoded_request(&snapshot, None);
    trailing.push(0);
    assert!(decode_request_frame(trailing).is_err());

    let mut wrong_reserved = encoded_request(&snapshot, None);
    wrong_reserved[7] = 1;
    assert!(decode_request_frame(wrong_reserved).is_err());

    for wrong_secret_len in [31_u32, 33, 43] {
        let mut frame = encoded_request(&apply, None);
        frame[12..16].copy_from_slice(&wrong_secret_len.to_be_bytes());
        frame.resize(16 + 8 + wrong_secret_len as usize, 0x5a);
        assert!(decode_request_frame(frame).is_err());
    }
}

#[test]
fn broker_response_is_one_bounded_length_prefixed_json_value() {
    let payload = br#"{"health":"failed","reason":"relay_test"}"#;
    let encoded = encode_response_frame(payload).unwrap();
    assert_eq!(
        u32::from_be_bytes(encoded[..4].try_into().unwrap()),
        payload.len() as u32
    );
    assert_eq!(&encoded[4..], payload);

    assert!(encode_response_frame(b"").is_err());
    assert!(encode_response_frame(&vec![b'x'; 8193]).is_err());
    assert!(encode_response_frame(b"not-json").is_err());
    assert!(encode_response_frame(br#"{}{}"#).is_err());
}

#[test]
fn socket_activation_and_linux_peer_policy_are_exact() {
    let activation = SocketActivationClaim {
        current_pid: 500,
        listen_pid: 500,
        listen_fds: 1,
        first_fd: 3,
        fd_is_connected_unix_stream: true,
    };
    assert!(validate_socket_activation(&activation).is_ok());
    for invalid in [
        SocketActivationClaim {
            listen_pid: 1,
            ..activation
        },
        SocketActivationClaim {
            listen_fds: 2,
            ..activation
        },
        SocketActivationClaim {
            first_fd: 4,
            ..activation
        },
        SocketActivationClaim {
            fd_is_connected_unix_stream: false,
            ..activation
        },
    ] {
        assert!(validate_socket_activation(&invalid).is_err());
    }

    let peer = LinuxClientPeerClaim {
        peer_uid: 991,
        expected_agent_uid: 991,
        peer_pid: 101,
    };
    assert!(validate_linux_client_peer(&peer).is_ok());
    assert!(validate_linux_client_peer(&LinuxClientPeerClaim {
        peer_uid: 0,
        ..peer
    })
    .is_err());
    assert!(validate_linux_client_peer(&LinuxClientPeerClaim {
        peer_pid: 0,
        ..peer
    })
    .is_err());
}

#[test]
fn renderer_binds_raw_secret_capacity_ports_transports_and_tls_credentials() {
    let base = hardened_coturn_template();
    assert!(!std::str::from_utf8(&base)
        .unwrap()
        .contains("CHANGE_ME_WITH_43_CHAR_BASE64URL_SECRET"));
    let rendered = render_linux_coturn_config(&base, &[0x42; 32]).unwrap();
    let text = std::str::from_utf8(rendered.bytes()).unwrap();
    assert!(text.contains("static-auth-secret=QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"));
    assert!(text.contains(&format!("cert={}", linux::COTURN_CERT_CREDENTIAL_PATH)));
    assert!(text.contains(&format!("pkey={}", linux::COTURN_KEY_CREDENTIAL_PATH)));
    assert!(!text.contains("/etc/mrd-relay-agent/tls/"));
    assert_eq!(rendered.configured_max_allocations(), 100);
    assert_eq!(rendered.configured_max_egress_bps(), 1_000_000_000);
    assert_eq!(rendered.relay_ports(), (49160, 49260));
    assert_eq!(
        rendered.configured_endpoints(),
        [
            "turn:relay.example.net:3478?transport=udp",
            "turn:relay.example.net:3478?transport=tcp",
            "turns:relay.example.net:5349?transport=tcp",
        ]
    );
    assert!(!format!("{rendered:?}").contains("QkJCQk"));

    assert!(render_linux_coturn_config(&base, &[0x42; 31]).is_err());
    let duplicate = [
        base.as_slice(),
        b"static-auth-secret=__MRD_BROKER_SECRET_V1__\n",
    ]
    .concat();
    assert!(render_linux_coturn_config(&duplicate, &[0x42; 32]).is_err());
    assert_eq!(
        Path::new(linux::ROOT_CONTROL_HELPER),
        Path::new("/usr/local/libexec/mrd-relay-coturn-control")
    );
}

#[test]
fn renderer_accepts_windows_crlf_but_rejects_lone_carriage_returns() {
    let base = String::from_utf8(hardened_coturn_template()).unwrap();
    let mut canonical_lf = base.lines().collect::<Vec<_>>().join("\n");
    canonical_lf.push('\n');
    let crlf = canonical_lf.replace('\n', "\r\n");
    let rendered = render_linux_coturn_config(crlf.as_bytes(), &[0x42; 32]).unwrap();
    assert!(!rendered.bytes().contains(&b'\r'));

    let lone_carriage_return = canonical_lf.replacen('\n', "\r", 1);
    assert!(render_linux_coturn_config(lone_carriage_return.as_bytes(), &[0x42; 32]).is_err());
}

#[test]
fn renderer_secret_material_never_enters_an_unzeroized_string() {
    let broker_source = include_str!("../src/broker.rs");
    let renderer = broker_source
        .split_once("pub fn render_coturn_config(")
        .unwrap()
        .1
        .split_once("fn validate_coturn_template_semantics(")
        .unwrap()
        .0;
    assert!(renderer.contains("canonical_turn_secret_bytes(raw_secret)?"));
    assert!(renderer.contains("append_zeroizing_config_line("));
    assert!(renderer.contains("Zeroizing::new(Vec::with_capacity(MAX_CONFIG_BYTES))"));
    assert!(!renderer.contains("URL_SAFE_NO_PAD.encode(raw_secret)"));
    assert!(!renderer.contains("format!(\"static-auth-secret="));
    let appender = broker_source
        .split_once("fn append_zeroizing_config_line(")
        .unwrap()
        .1
        .split_once("fn validate_coturn_template_semantics(")
        .unwrap()
        .0;
    assert!(!appender.contains(".reserve("));

    let linux_source = include_str!("../src/broker/linux_runtime.rs");
    let material_loader = linux_source
        .split_once("fn load_verified_material()")
        .unwrap()
        .1
        .split_once("async fn apply_secret_transaction(")
        .unwrap()
        .0;
    assert!(material_loader.contains("canonical_turn_secret_bytes("));
    assert!(material_loader.contains("decode_slice("));
    assert!(!material_loader.contains("URL_SAFE_NO_PAD.encode("));
    assert!(!material_loader.contains("URL_SAFE_NO_PAD.decode("));
}

#[test]
fn renderer_rejects_missing_duplicate_forbidden_and_comment_disguised_hardening() {
    let baseline = hardened_coturn_template();
    let cases = [
        (
            "missing use-auth-secret",
            replace_config_line(&baseline, "use-auth-secret", None),
        ),
        (
            "commented use-auth-secret",
            replace_config_line(&baseline, "use-auth-secret", Some("# use-auth-secret")),
        ),
        (
            "missing no-cli",
            replace_config_line(&baseline, "no-cli", None),
        ),
        ("duplicate no-cli", append_config_line(&baseline, "no-cli")),
        (
            "forbidden no-auth",
            append_config_line(&baseline, "no-auth"),
        ),
        (
            "comment-disguised no-auth",
            append_config_line(&baseline, "no-auth # supposedly disabled"),
        ),
        (
            "forbidden allow-loopback-peers",
            append_config_line(&baseline, "allow-loopback-peers"),
        ),
        (
            "unknown dangerous directive",
            append_config_line(&baseline, "cli-password=attacker-controlled"),
        ),
        (
            "public prometheus",
            replace_config_line(
                &baseline,
                "prometheus-address=127.0.0.1",
                Some("prometheus-address=0.0.0.0"),
            ),
        ),
        (
            "wrong prometheus port",
            replace_config_line(
                &baseline,
                "prometheus-port=9641",
                Some("prometheus-port=9642"),
            ),
        ),
        (
            "missing 401 limiter",
            replace_config_line(&baseline, "unauthorized-ratelimit", None),
        ),
        (
            "wrong 401 limit",
            replace_config_line(
                &baseline,
                "unauthorized-ratelimit-rps=10",
                Some("unauthorized-ratelimit-rps=11"),
            ),
        ),
        (
            "missing private deny",
            replace_config_line(&baseline, "denied-peer-ip=10.0.0.0-10.255.255.255", None),
        ),
        (
            "missing IPv6 loopback deny",
            replace_config_line(&baseline, "denied-peer-ip=::1", None),
        ),
        (
            "missing IPv6 unique-local deny",
            replace_config_line(
                &baseline,
                "denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                None,
            ),
        ),
        (
            "duplicate deny",
            append_config_line(&baseline, "denied-peer-ip=127.0.0.0-127.255.255.255"),
        ),
        (
            "missing TLS certificate",
            replace_config_line(
                &baseline,
                "cert=/etc/mrd-relay-agent/tls/fullchain.pem",
                None,
            ),
        ),
        (
            "missing TLS private key",
            replace_config_line(&baseline, "pkey=/etc/mrd-relay-agent/tls/privkey.pem", None),
        ),
        (
            "unfrozen TLS certificate source",
            replace_config_line(
                &baseline,
                "cert=/etc/mrd-relay-agent/tls/fullchain.pem",
                Some("cert=/tmp/attacker-cert.pem"),
            ),
        ),
        (
            "unfrozen TLS private-key source",
            replace_config_line(
                &baseline,
                "pkey=/etc/mrd-relay-agent/tls/privkey.pem",
                Some("pkey=/tmp/attacker-key.pem"),
            ),
        ),
        (
            "non-canonical IPv6 wildcard listener",
            replace_config_line(
                &baseline,
                "listening-ip=0.0.0.0",
                Some("listening-ip=0:0:0:0:0:0:0:0"),
            ),
        ),
    ];

    for (name, template) in cases {
        assert!(
            render_linux_coturn_config(&template, &[0x42; 32]).is_err(),
            "renderer accepted {name}"
        );
    }
}

#[test]
fn renderer_external_ip_policy_matches_the_shared_deploy_vectors_and_cross_field_binding() {
    let vectors: PublicIpVectors = serde_json::from_str(include_str!(
        "../../../deploy/turn/public-ip-test-vectors.json"
    ))
    .unwrap();
    assert_eq!(vectors.schema_version, 1);
    let baseline = hardened_coturn_template();

    for address in vectors.accepted {
        let template = bind_listener_to_public_address(&baseline, &address);
        let template = append_config_line(&template, &format!("external-ip={address}"));
        assert!(
            render_linux_coturn_config(&template, &[0x42; 32]).is_ok(),
            "renderer rejected shared public address {address}"
        );
    }
    for address in vectors.rejected {
        let template = append_config_line(&baseline, &format!("external-ip={address}"));
        assert!(
            render_linux_coturn_config(&template, &[0x42; 32]).is_err(),
            "renderer accepted shared non-public address {address}"
        );
    }
    for mapping in vectors.accepted_mappings {
        let template = bind_listener_to_public_address(&baseline, &mapping.external_ip);
        let template = append_external_mapping(&template, &mapping);
        assert!(
            render_linux_coturn_config(&template, &[0x42; 32]).is_ok(),
            "renderer rejected shared mapping {} / {}",
            mapping.external_ip,
            mapping.relay_ip
        );
    }
    for mapping in vectors.rejected_mappings {
        let template = append_external_mapping(&baseline, &mapping);
        assert!(
            render_linux_coturn_config(&template, &[0x42; 32]).is_err(),
            "renderer accepted invalid mapping {} / {}",
            mapping.external_ip,
            mapping.relay_ip
        );
    }

    let ipv6_listener_with_ipv4_public =
        replace_config_line(&baseline, "listening-ip=0.0.0.0", Some("listening-ip=::"));
    let ipv6_listener_with_ipv4_public =
        append_config_line(&ipv6_listener_with_ipv4_public, "external-ip=192.0.0.9");
    assert!(render_linux_coturn_config(&ipv6_listener_with_ipv4_public, &[0x42; 32]).is_err());

    let ipv4_listener_with_ipv6_public =
        append_config_line(&baseline, "external-ip=2606:4700:4700::1111");
    assert!(render_linux_coturn_config(&ipv4_listener_with_ipv6_public, &[0x42; 32]).is_err());
}

#[test]
fn coturn_rest_credentials_use_the_canonical_configured_secret_and_exact_four_part_username() {
    let _ = <CoturnRestCredentials as AmbiguousIfDebug<_>>::assert_not_debug;
    let raw_secret = [0x42; 32];
    let username = "2000000000:mrd-local-preflight:0123456789abcdef:linux-systemd";
    let credentials = derive_coturn_rest_credentials(&raw_secret, username).unwrap();
    let canonical_secret = URL_SAFE_NO_PAD.encode(raw_secret);
    assert_eq!(canonical_secret.len(), 43);
    let expected = STANDARD.encode(
        ring::hmac::sign(
            &ring::hmac::Key::new(
                ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                canonical_secret.as_bytes(),
            ),
            username.as_bytes(),
        )
        .as_ref(),
    );
    let wrong_raw_key = STANDARD.encode(
        ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &raw_secret),
            username.as_bytes(),
        )
        .as_ref(),
    );

    assert_eq!(credentials.username(), username);
    assert_eq!(credentials.credential(), expected);
    assert_ne!(credentials.credential(), wrong_raw_key);

    for invalid in [
        "2000000000:scope:nonce",
        "2000000000:scope:nonce:target:extra",
        "02000000000:scope:nonce:target",
        "0:scope:nonce:target",
        "+2000000000:scope:nonce:target",
        "2000000000::nonce:target",
        "2000000000:scope:bad/nonce:target",
        "2000000000:scope:nonce:targét",
        "2000000000:scope:nonce:target\n",
    ] {
        assert!(derive_coturn_rest_credentials(&raw_secret, invalid).is_err());
    }
    let oversized = format!("2000000000:{}:nonce:target", "a".repeat(129));
    assert!(derive_coturn_rest_credentials(&raw_secret, &oversized).is_err());
    assert!(derive_coturn_rest_credentials(&raw_secret[..31], username).is_err());
}

#[test]
fn pending_transaction_recovery_never_guesses_which_secret_the_process_loaded() {
    let old_invocation = Some("old-invocation".to_owned());
    let source_changed_process_old = PendingRecoveryObservation {
        committed_marker_matches_desired: false,
        desired_secret_and_config_match: true,
        previous_invocation: old_invocation.clone(),
        current_invocation: old_invocation.clone(),
        target_active: true,
    };
    assert_eq!(
        select_pending_recovery(&source_changed_process_old),
        PendingRecoveryAction::RestartAndVerify
    );

    let lost_response_after_restart = PendingRecoveryObservation {
        current_invocation: Some("new-invocation".to_owned()),
        ..source_changed_process_old.clone()
    };
    assert_eq!(
        select_pending_recovery(&lost_response_after_restart),
        PendingRecoveryAction::Commit
    );

    let first_start = PendingRecoveryObservation {
        committed_marker_matches_desired: false,
        desired_secret_and_config_match: true,
        previous_invocation: None,
        current_invocation: Some("first-invocation".to_owned()),
        target_active: true,
    };
    assert_eq!(
        select_pending_recovery(&first_start),
        PendingRecoveryAction::Commit
    );

    let partial_write = PendingRecoveryObservation {
        desired_secret_and_config_match: false,
        ..lost_response_after_restart
    };
    assert_eq!(
        select_pending_recovery(&partial_write),
        PendingRecoveryAction::Rollback
    );

    let marker_committed_but_journal_remained = PendingRecoveryObservation {
        committed_marker_matches_desired: true,
        desired_secret_and_config_match: true,
        previous_invocation: old_invocation,
        current_invocation: Some("new-invocation".to_owned()),
        target_active: true,
    };
    assert_eq!(
        select_pending_recovery(&marker_committed_but_journal_remained),
        PendingRecoveryAction::RemoveJournal
    );
}

#[test]
fn windows_pending_transaction_recovery_commits_only_verified_target_evidence() {
    let old_epoch = Some("old-target-epoch".to_owned());
    let process_old = WindowsPendingRecoveryObservation {
        committed_marker_matches_desired: false,
        active_secret_matches_desired: false,
        target_config_matches_desired: true,
        target_reports_desired_version: false,
        previous_epoch: old_epoch.clone(),
        current_epoch: old_epoch.clone(),
        target_active: true,
    };
    assert_eq!(
        select_windows_pending_recovery(&process_old),
        WindowsPendingRecoveryAction::RetryDesired
    );

    let lost_response = WindowsPendingRecoveryObservation {
        target_reports_desired_version: true,
        current_epoch: Some("new-target-epoch".to_owned()),
        ..process_old.clone()
    };
    assert_eq!(
        select_windows_pending_recovery(&lost_response),
        WindowsPendingRecoveryAction::CommitDesired
    );

    let active_written_before_marker = WindowsPendingRecoveryObservation {
        active_secret_matches_desired: true,
        ..lost_response.clone()
    };
    assert_eq!(
        select_windows_pending_recovery(&active_written_before_marker),
        WindowsPendingRecoveryAction::CommitDesired
    );

    let committed_but_journal_remained = WindowsPendingRecoveryObservation {
        committed_marker_matches_desired: true,
        active_secret_matches_desired: true,
        ..active_written_before_marker
    };
    assert_eq!(
        select_windows_pending_recovery(&committed_but_journal_remained),
        WindowsPendingRecoveryAction::RemoveJournal
    );

    let ambiguous = WindowsPendingRecoveryObservation {
        target_reports_desired_version: false,
        target_config_matches_desired: false,
        current_epoch: Some("unexpected-epoch".to_owned()),
        ..process_old
    };
    assert_eq!(
        select_windows_pending_recovery(&ambiguous),
        WindowsPendingRecoveryAction::FailClosed
    );
}

#[test]
fn docker_engine_stats_parser_uses_exact_raw_network_counters() {
    let body = br#"{"networks":{"eth0":{"rx_bytes":123456789,"tx_bytes":987654321,"rx_packets":4,"tx_packets":5},"eth1":{"rx_bytes":11,"tx_bytes":22,"rx_packets":1,"tx_packets":1}}}"#;
    let response = [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes(),
        body.to_vec(),
    ]
    .concat();
    let counters = parse_docker_engine_stats_http(&response).unwrap();
    assert_eq!(counters.total_ingress_bytes, 123_456_800);
    assert_eq!(counters.total_egress_bytes, 987_654_343);

    let mut trailing = response.clone();
    trailing.push(0);
    assert!(parse_docker_engine_stats_http(&trailing).is_err());
    let duplicate_length = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| {
            let mut value = response.clone();
            value.splice(
                index + 2..index + 2,
                format!("Content-Length: {}\r\n", body.len()).bytes(),
            );
            value
        })
        .unwrap();
    assert!(parse_docker_engine_stats_http(&duplicate_length).is_err());
    assert!(parse_docker_engine_stats_http(
        b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"networks\":{}}"
    )
    .is_err());

    let chunked_body = br#"{"networks":{"nat":{"rx_bytes":41,"tx_bytes":43}}}"#;
    let chunked = [
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".as_slice(),
        format!("{:X}\r\n", chunked_body.len()).as_bytes(),
        chunked_body,
        b"\r\n0\r\n\r\n".as_slice(),
    ]
    .concat();
    let counters = parse_docker_engine_stats_http(&chunked).unwrap();
    assert_eq!(counters.total_ingress_bytes, 41);
    assert_eq!(counters.total_egress_bytes, 43);
}

#[test]
fn probe_proof_requires_the_same_live_target_generation_before_and_after_roundtrip() {
    let before = ProbeStabilityObservation {
        target: CoturnTarget::Docker,
        generation: 7,
        applied_secret_version: 3,
        epoch: "container-epoch-7".to_owned(),
        active: true,
        draining: false,
        external_restart_detected: false,
    };
    assert!(validate_probe_stability(&before, &before).is_ok());

    for changed in [
        ProbeStabilityObservation {
            generation: 8,
            epoch: "container-epoch-8".to_owned(),
            ..before.clone()
        },
        ProbeStabilityObservation {
            applied_secret_version: 4,
            ..before.clone()
        },
        ProbeStabilityObservation {
            active: false,
            ..before.clone()
        },
        ProbeStabilityObservation {
            draining: true,
            ..before.clone()
        },
        ProbeStabilityObservation {
            external_restart_detected: true,
            ..before.clone()
        },
    ] {
        assert!(validate_probe_stability(&before, &changed).is_err());
    }
}
