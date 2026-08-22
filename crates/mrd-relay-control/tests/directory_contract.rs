use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use mrd_relay_control::{
    RelayDirectoryCandidate, RelayDirectoryEndpoint, RelayDirectoryError, RelayDirectoryPayload,
    RelayDirectoryTransport, RelayReservation, SignedRelayDirectory,
    MAX_RELAY_DIRECTORY_JSON_BYTES, RELAY_DIRECTORY_MIN_POLICY_REVISION,
};
use serde::Deserialize;

const TEST_KEY_ID: &str = "directory-test-key-v1";
const TEST_SEED: [u8; 32] = [0x42; 32];

fn payload() -> RelayDirectoryPayload {
    RelayDirectoryPayload {
        format_version: 1,
        policy_revision: 17,
        directory_id: "directory-20260822-0001".to_owned(),
        issued_at_ms: 1_777_000_000_000,
        expires_at_ms: 1_777_000_030_000,
        session_id: "session-alpha".to_owned(),
        intended_peer_digest: "peer-sha256-0123456789abcdef".to_owned(),
        candidates: vec![
            RelayDirectoryCandidate {
                node_id: "relay-ap-sg-a".to_owned(),
                region: "ap-southeast-1".to_owned(),
                failure_domain: "ap-southeast-1a".to_owned(),
                endpoints: vec![
                    RelayDirectoryEndpoint {
                        transport: RelayDirectoryTransport::Udp,
                        host: "turn-a.example.test".to_owned(),
                        port: 3478,
                    },
                    RelayDirectoryEndpoint {
                        transport: RelayDirectoryTransport::Tls,
                        host: "turn-a.example.test".to_owned(),
                        port: 5349,
                    },
                ],
                capabilities: 0x0000_0007,
                load_class: 1,
                selection_reason: "preferred-region".to_owned(),
                reservation: RelayReservation {
                    reservation_id: "reservation-a".to_owned(),
                    expires_at_ms: 1_777_000_020_000,
                },
            },
            RelayDirectoryCandidate {
                node_id: "relay-eu-de-b".to_owned(),
                region: "eu-central-1".to_owned(),
                failure_domain: "eu-central-1b".to_owned(),
                endpoints: vec![RelayDirectoryEndpoint {
                    transport: RelayDirectoryTransport::Tcp,
                    host: "turn-b.example.test".to_owned(),
                    port: 3478,
                }],
                capabilities: 0x0000_0003,
                load_class: 2,
                selection_reason: "failure-domain-backup".to_owned(),
                reservation: RelayReservation {
                    reservation_id: "reservation-b".to_owned(),
                    expires_at_ms: 1_777_000_025_000,
                },
            },
        ],
    }
}

fn signed(payload: RelayDirectoryPayload) -> SignedRelayDirectory {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let signature = signing_key.sign(&payload.canonical_signing_bytes().unwrap());
    SignedRelayDirectory {
        payload,
        signing_key_id: TEST_KEY_ID.to_owned(),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    }
}

fn trusted_keys() -> BTreeMap<String, Vec<u8>> {
    let public_key = SigningKey::from_bytes(&TEST_SEED)
        .verifying_key()
        .to_bytes()
        .to_vec();
    BTreeMap::from([(TEST_KEY_ID.to_owned(), public_key)])
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenFixture {
    test_only_public_key_b64: String,
    directory: serde_json::Value,
}

#[test]
fn canonical_bytes_and_ed25519_golden_vector_are_stable() {
    let payload = payload();
    let bytes = payload.canonical_signing_bytes().unwrap();
    assert_eq!(
        to_hex(&bytes),
        "4d52445f52454c41595f4449524543544f52595f563100010000000000000011000000176469726563746f72792d32303236303832322d303030310000019dbd742a000000019dbd749f300000000d73657373696f6e2d616c7068610000001c706565722d7368613235362d30313233343536373839616263646566000000020000000d72656c61792d61702d73672d610000000e61702d736f757468656173742d310000000f61702d736f757468656173742d31610000000201000000137475726e2d612e6578616d706c652e746573740d9603000000137475726e2d612e6578616d706c652e7465737414e50000000701000000107072656665727265642d726567696f6e0000000d7265736572766174696f6e2d610000019dbd7478200000000d72656c61792d65752d64652d620000000c65752d63656e7472616c2d310000000d65752d63656e7472616c2d31620000000102000000137475726e2d622e6578616d706c652e746573740d960000000302000000156661696c7572652d646f6d61696e2d6261636b75700000000d7265736572766174696f6e2d620000019dbd748ba8"
    );

    let signed = signed(payload.clone());
    let verified = signed
        .verify(&trusted_keys(), "session-alpha", 1_777_000_010_000)
        .unwrap();
    assert_eq!(verified.payload(), &payload);
    assert_eq!(verified.canonical_signing_bytes(), bytes.as_slice());
}

#[test]
fn signed_fields_and_canonical_order_are_bound() {
    let valid = signed(payload());

    let mut changed = valid.clone();
    changed.payload.candidates.swap(0, 1);
    assert_eq!(
        changed.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::NonCanonicalCandidateOrder)
    );

    let mut changed = valid.clone();
    changed.payload.candidates[0].endpoints[0].host = "attacker.example".to_owned();
    assert_eq!(
        changed.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::InvalidSignature)
    );

    let mut changed = valid.clone();
    changed.payload.candidates[0].endpoints.swap(0, 1);
    assert_eq!(
        changed.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::NonCanonicalEndpointOrder)
    );

    assert_eq!(
        valid.verify(&trusted_keys(), "session-other", 1_777_000_010_000),
        Err(RelayDirectoryError::SessionMismatch)
    );

    let mut changed = valid.clone();
    changed.payload.session_id = "session-other".to_owned();
    assert_eq!(
        changed.verify(&trusted_keys(), "session-other", 1_777_000_010_000),
        Err(RelayDirectoryError::InvalidSignature)
    );

    let mut changed = valid.clone();
    changed.payload.policy_revision += 1;
    assert_eq!(
        changed.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::InvalidSignature)
    );

    let mut changed = valid.clone();
    changed.payload.expires_at_ms += 1;
    assert_eq!(
        changed.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::InvalidSignature)
    );

    let mut changed = valid;
    changed.signature_b64.replace_range(0..1, "A");
    assert_eq!(
        changed.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::InvalidSignature)
    );
}

#[test]
fn malformed_untrusted_and_expired_directories_fail_closed() {
    let valid_payload = payload();

    let mut invalid = valid_payload.clone();
    invalid.candidates.push(invalid.candidates[0].clone());
    assert_eq!(
        invalid.canonical_signing_bytes(),
        Err(RelayDirectoryError::DuplicateNode)
    );

    let mut invalid = valid_payload.clone();
    let duplicate_endpoint = invalid.candidates[0].endpoints[0].clone();
    invalid.candidates[0].endpoints.push(duplicate_endpoint);
    assert_eq!(
        invalid.canonical_signing_bytes(),
        Err(RelayDirectoryError::DuplicateEndpoint)
    );

    let mut invalid = valid_payload.clone();
    invalid.format_version = 2;
    assert_eq!(
        invalid.canonical_signing_bytes(),
        Err(RelayDirectoryError::UnsupportedFormatVersion { version: 2 })
    );

    let valid = signed(valid_payload.clone());
    assert_eq!(
        valid.verify(
            &trusted_keys(),
            "session-alpha",
            valid_payload.expires_at_ms
        ),
        Err(RelayDirectoryError::Expired)
    );

    let mut invalid = valid_payload.clone();
    invalid.candidates[0].reservation.expires_at_ms = invalid.expires_at_ms + 1;
    assert_eq!(
        invalid.canonical_signing_bytes(),
        Err(RelayDirectoryError::InvalidReservation)
    );

    let mut stale_policy = valid_payload;
    stale_policy.policy_revision = 0;
    assert_eq!(
        stale_policy.canonical_signing_bytes(),
        Err(RelayDirectoryError::InvalidPolicyRevision)
    );

    assert_eq!(
        valid.verify(&BTreeMap::new(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::UntrustedSigningKey)
    );
}

#[test]
fn correctly_resigned_nonzero_stale_policy_is_rejected() {
    let mut stale_payload = payload();
    stale_payload.policy_revision = RELAY_DIRECTORY_MIN_POLICY_REVISION - 1;
    let stale = signed(stale_payload);
    let signature_bytes = STANDARD.decode(&stale.signature_b64).unwrap();
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    SigningKey::from_bytes(&TEST_SEED)
        .verifying_key()
        .verify_strict(
            &stale.payload.canonical_signing_bytes().unwrap(),
            &signature,
        )
        .unwrap();

    assert_eq!(
        stale.verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::StalePolicy {
            minimum: RELAY_DIRECTORY_MIN_POLICY_REVISION,
            actual: RELAY_DIRECTORY_MIN_POLICY_REVISION - 1,
        })
    );
}

#[test]
fn oversized_escaped_json_is_rejected_before_deserialization() {
    let oversized = format!(
        "{{\"payload\":{{\"directory_id\":\"{}\"}}}}",
        "\\u0061".repeat(MAX_RELAY_DIRECTORY_JSON_BYTES)
    );
    assert!(oversized.len() > MAX_RELAY_DIRECTORY_JSON_BYTES);
    assert_eq!(
        SignedRelayDirectory::from_json(oversized.as_bytes()),
        Err(RelayDirectoryError::JsonTooLarge {
            max: MAX_RELAY_DIRECTORY_JSON_BYTES,
        })
    );
}

#[test]
fn candidate_and_endpoint_caps_are_enforced() {
    let mut invalid = payload();
    for index in 2..9 {
        let mut candidate = invalid.candidates[1].clone();
        candidate.node_id = format!("relay-{index:02}");
        candidate.reservation.reservation_id = format!("reservation-{index:02}");
        invalid.candidates.push(candidate);
    }
    invalid
        .candidates
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    assert_eq!(
        invalid.canonical_signing_bytes(),
        Err(RelayDirectoryError::TooManyCandidates { max: 8 })
    );

    let mut invalid = payload();
    invalid.candidates[0].endpoints = (1..=5)
        .map(|index| RelayDirectoryEndpoint {
            transport: RelayDirectoryTransport::Udp,
            host: format!("turn-{index}.example.test"),
            port: 3478,
        })
        .collect();
    assert_eq!(
        invalid.canonical_signing_bytes(),
        Err(RelayDirectoryError::TooManyEndpoints { max: 4 })
    );
}

#[test]
fn fixture_is_valid_tamper_vector_is_invalid_and_unknown_fields_are_rejected() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/relay/fixtures");
    let valid_json = fs::read_to_string(fixtures.join("directory-v1.json")).unwrap();
    let fixture: GoldenFixture = serde_json::from_str(&valid_json).unwrap();
    assert_eq!(
        STANDARD.decode(&fixture.test_only_public_key_b64).unwrap(),
        trusted_keys()[TEST_KEY_ID]
    );
    let directory_json = serde_json::to_vec(&fixture.directory).unwrap();
    SignedRelayDirectory::from_json(&directory_json)
        .unwrap()
        .verify(&trusted_keys(), "session-alpha", 1_777_000_010_000)
        .unwrap();

    let tampered_json = fs::read_to_string(fixtures.join("directory-v1-tampered.json")).unwrap();
    let tampered: GoldenFixture = serde_json::from_str(&tampered_json).unwrap();
    let tampered_json = serde_json::to_vec(&tampered.directory).unwrap();
    assert_eq!(
        SignedRelayDirectory::from_json(&tampered_json)
            .unwrap()
            .verify(&trusted_keys(), "session-alpha", 1_777_000_010_000),
        Err(RelayDirectoryError::InvalidSignature)
    );

    let mut unknown: serde_json::Value = serde_json::from_str(&valid_json).unwrap();
    unknown["directory"]["payload"]["unknown_critical_field"] = serde_json::json!(true);
    let unknown_directory = serde_json::to_vec(&unknown["directory"]).unwrap();
    assert_eq!(
        SignedRelayDirectory::from_json(&unknown_directory),
        Err(RelayDirectoryError::InvalidJson)
    );
}
