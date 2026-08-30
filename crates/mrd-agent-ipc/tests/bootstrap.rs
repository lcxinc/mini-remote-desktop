use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    edwards::CompressedEdwardsY,
};
use mrd_agent_ipc::{
    derive_execute_grant_issuer_key_id, derive_registration_public_key, read_agent_bootstrap,
    windows_agent_bootstrap_pipe_name, write_agent_bootstrap, AgentBootstrap,
    BoundEd25519ExecuteGrantVerifier, BoundEd25519RegistrationVerifier, DesktopKind, ExecuteGrant,
    ExecuteGrantClaims, ExecuteGrantVerifier, GrantAudience, PeerBinding,
    RegistrationProofVerifier,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_session::{PermissionScope, PermissionScopes};
use ring::signature::KeyPair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

fn execute_issuer(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
    (derive_execute_grant_issuer_key_id(&public_key), public_key)
}

fn noncanonical_nonweak_ed25519_encoding() -> [u8; 32] {
    // p = 2^255 - 19 in little-endian form. ZIP-215 decoding reduces y modulo p,
    // so some y = p + k encodings decompress even though RFC 8032 encoding is
    // required to use the canonical representative k.
    let mut field_modulus = [0xff_u8; 32];
    field_modulus[0] = 0xed;
    field_modulus[31] = 0x7f;

    for k in 0_u8..19 {
        for x_sign in [0_u8, 0x80] {
            let mut candidate = field_modulus;
            let (low, carry) = candidate[0].overflowing_add(k);
            candidate[0] = low;
            debug_assert!(!carry);
            candidate[31] |= x_sign;
            let compressed = CompressedEdwardsY(candidate);
            if let Some(point) = compressed.decompress() {
                if point.compress().to_bytes() != candidate && !point.is_small_order() {
                    return candidate;
                }
            }
        }
    }
    panic!("test must find a decompressible noncanonical nonweak Ed25519 encoding");
}

async fn encoded_bootstrap(execute_issuer_seed: [u8; 32]) -> Vec<u8> {
    let registration_seed = [7_u8; 32];
    let registration_key =
        derive_registration_public_key(&registration_seed).expect("derive registration key");
    let (execute_grant_issuer_key_id, execute_grant_public_key) =
        execute_issuer(execute_issuer_seed);
    let (mut writer, mut reader) = tokio::io::duplex(2_048);
    let writing = tokio::spawn(async move {
        write_agent_bootstrap(
            &mut writer,
            AgentBootstrap {
                control_endpoint: r"\\.\pipe\mrd-agent-control-test",
                service_process_id: 44,
                service_process_creation_time: 55,
                heartbeat_interval_ms: 1_000,
                handshake_timeout_ms: 5_000,
                registration_seed: Zeroizing::new(registration_seed),
                expected_agent_key_id: registration_key.key_id,
                execute_grant_issuer_key_id,
                execute_grant_public_key,
            },
        )
        .await
        .unwrap();
        writer.shutdown().await.unwrap();
    });
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    writing.await.unwrap();
    bytes
}

#[tokio::test]
async fn bootstrap_codec_round_trips_secret_without_serde_or_environment_state() {
    let seed = [7_u8; 32];
    let key = derive_registration_public_key(&seed).expect("derive registration key");
    let (execute_grant_issuer_key_id, execute_grant_public_key) = execute_issuer([17; 32]);
    let endpoint = r"\\.\pipe\mrd-agent-control-test";
    let (mut writer, mut reader) = tokio::io::duplex(2_048);
    let writing = tokio::spawn(async move {
        write_agent_bootstrap(
            &mut writer,
            AgentBootstrap {
                control_endpoint: endpoint,
                service_process_id: 44,
                service_process_creation_time: 55,
                heartbeat_interval_ms: 1_000,
                handshake_timeout_ms: 5_000,
                registration_seed: Zeroizing::new(seed),
                expected_agent_key_id: key.key_id,
                execute_grant_issuer_key_id,
                execute_grant_public_key,
            },
        )
        .await
    });
    let received = read_agent_bootstrap(&mut reader).await.unwrap();
    writing.await.unwrap().unwrap();

    assert_eq!(received.control_endpoint(), endpoint);
    assert_eq!(received.service_process_id(), 44);
    assert_eq!(received.service_process_creation_time(), 55);
    assert_eq!(received.heartbeat_interval_ms(), 1_000);
    assert_eq!(received.handshake_timeout_ms(), 5_000);
    assert_eq!(received.expected_agent_key_id(), &key.key_id);
    assert_eq!(
        received.execute_grant_issuer_key_id(),
        &execute_grant_issuer_key_id
    );
    assert_eq!(
        received.execute_grant_public_key(),
        &execute_grant_public_key
    );
    assert_eq!(&*received.into_registration_seed(), &seed);
}

#[test]
fn derived_verifier_is_bound_to_the_bootstrap_key_id() {
    let seed = [8_u8; 32];
    let key = derive_registration_public_key(&seed).unwrap();
    let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let signature = signer.sign(b"bound transcript");
    let verifier = BoundEd25519RegistrationVerifier::new(key.key_id, key.public_key).unwrap();

    assert!(verifier.verify(
        &key.key_id,
        b"bound transcript",
        signature.as_ref().try_into().unwrap()
    ));
    assert!(!verifier.verify(
        &[99; 32],
        b"bound transcript",
        signature.as_ref().try_into().unwrap()
    ));
    assert!(!verifier.verify(
        &key.key_id,
        b"different transcript",
        signature.as_ref().try_into().unwrap()
    ));
}

#[test]
fn raw_execute_issuer_key_id_round_trips_the_mrd_identity_hex_form() {
    let (_, public_key) = execute_issuer([9; 32]);
    let raw = derive_execute_grant_issuer_key_id(&public_key);
    let hex = raw
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(hex, mrd_identity::public_key_id(&public_key));

    let parsed = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|digits| u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(parsed.as_slice(), raw);
}

#[test]
fn bootstrap_pipe_name_is_derived_only_from_os_process_identity() {
    assert_eq!(
        windows_agent_bootstrap_pipe_name(7, 42, 0x1234),
        r"\\.\pipe\mrd-agent-bootstrap-v2-s7-p42-c0000000000001234"
    );
}

#[tokio::test]
async fn bootstrap_v2_rejects_zero_mismatched_and_invalid_execute_issuer_keys() {
    let registration_seed = [27_u8; 32];
    let registration_key = derive_registration_public_key(&registration_seed).unwrap();
    let (valid_key_id, valid_public_key) = execute_issuer([28; 32]);
    let invalid_public_key = (1_u8..=u8::MAX)
        .map(|value| [value; 32])
        .find(|candidate| ed25519_dalek::VerifyingKey::from_bytes(candidate).is_err())
        .expect("test must find a non-decompressible Ed25519 encoding");
    let mut weak_public_key = [0_u8; 32];
    weak_public_key[0] = 1;
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&weak_public_key)
        .expect("identity point has a canonical encoding")
        .is_weak());

    for (case, (key_id, public_key)) in [
        ([0; 32], valid_public_key),
        (valid_key_id, [0; 32]),
        ([29; 32], valid_public_key),
        (
            derive_execute_grant_issuer_key_id(&invalid_public_key),
            invalid_public_key,
        ),
        (
            derive_execute_grant_issuer_key_id(&weak_public_key),
            weak_public_key,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let result = write_agent_bootstrap(
            &mut tokio::io::sink(),
            AgentBootstrap {
                control_endpoint: r"\\.\pipe\mrd-agent-control-test",
                service_process_id: 44,
                service_process_creation_time: 55,
                heartbeat_interval_ms: 1_000,
                handshake_timeout_ms: 5_000,
                registration_seed: Zeroizing::new(registration_seed),
                expected_agent_key_id: registration_key.key_id,
                execute_grant_issuer_key_id: key_id,
                execute_grant_public_key: public_key,
            },
        )
        .await;
        assert!(
            result.is_err(),
            "invalid issuer key case {case} was accepted"
        );
    }
}

#[tokio::test]
async fn execute_issuer_rejects_zip215_aliases_and_points_outside_the_prime_order_subgroup() {
    let noncanonical = noncanonical_nonweak_ed25519_encoding();
    let noncanonical_point = CompressedEdwardsY(noncanonical)
        .decompress()
        .expect("ZIP-215 alias must decompress");
    assert_ne!(noncanonical_point.compress().to_bytes(), noncanonical);
    assert!(!noncanonical_point.is_small_order());

    let mixed_order = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    let mixed_order_point = CompressedEdwardsY(mixed_order)
        .decompress()
        .expect("canonical mixed-order point must decompress");
    assert_eq!(mixed_order_point.compress().to_bytes(), mixed_order);
    assert!(!mixed_order_point.is_small_order());
    assert!(!mixed_order_point.is_torsion_free());

    for public_key in [noncanonical, mixed_order] {
        let key_id = derive_execute_grant_issuer_key_id(&public_key);
        assert!(BoundEd25519ExecuteGrantVerifier::new(key_id, public_key).is_err());

        let registration_seed = [30_u8; 32];
        let registration_key = derive_registration_public_key(&registration_seed).unwrap();
        assert!(write_agent_bootstrap(
            &mut tokio::io::sink(),
            AgentBootstrap {
                control_endpoint: r"\\.\pipe\mrd-agent-control-test",
                service_process_id: 44,
                service_process_creation_time: 55,
                heartbeat_interval_ms: 1_000,
                handshake_timeout_ms: 5_000,
                registration_seed: Zeroizing::new(registration_seed),
                expected_agent_key_id: registration_key.key_id,
                execute_grant_issuer_key_id: key_id,
                execute_grant_public_key: public_key,
            },
        )
        .await
        .is_err());

        let mut encoded = encoded_bootstrap([31; 32]).await;
        encoded[104..136].copy_from_slice(&key_id);
        encoded[136..168].copy_from_slice(&public_key);
        assert!(read_agent_bootstrap(&mut std::io::Cursor::new(encoded))
            .await
            .is_err());
    }
}

#[tokio::test]
async fn bootstrap_v2_rejects_truncation_and_v1_downgrade() {
    let bytes = encoded_bootstrap([31; 32]).await;
    for length in [0, 8, 104, bytes.len() - 1] {
        let mut truncated = std::io::Cursor::new(bytes[..length].to_vec());
        assert!(read_agent_bootstrap(&mut truncated).await.is_err());
    }

    let mut legacy_magic = bytes.clone();
    legacy_magic[0..8].copy_from_slice(b"MRDABT1\0");
    legacy_magic[8..10].copy_from_slice(&1_u16.to_le_bytes());
    let mut downgraded = std::io::Cursor::new(legacy_magic);
    assert!(read_agent_bootstrap(&mut downgraded).await.is_err());
}

#[tokio::test]
async fn bootstrap_never_serializes_the_execute_grant_private_seed() {
    let issuer_seed = [37; 32];
    let bytes = encoded_bootstrap(issuer_seed).await;
    assert!(
        !bytes
            .windows(issuer_seed.len())
            .any(|window| window == issuer_seed),
        "execute-grant signing seed leaked into bootstrap"
    );
}

fn execute_grant(issuer_key_id: [u8; 32]) -> ExecuteGrant {
    ExecuteGrant {
        claims: ExecuteGrantClaims {
            grant_id: [41; 32],
            registration_id: [42; 16],
            registration_epoch: 1,
            session_id: SessionId("bootstrap-verifier-session".into()),
            peer: PeerBinding {
                device_id: DeviceId("bootstrap-verifier-peer".into()),
                key_id: [43; 32],
            },
            scopes: PermissionScopes::from([PermissionScope::ScreenView]),
            policy_revision: 1,
            windows_session_id: 7,
            desktop_epoch: 1,
            desktop_kind: DesktopKind::Default,
            issued_at_ms: 1_000,
            not_before_ms: 1_000,
            expires_at_ms: 2_000,
            command_digest: [44; 32],
            audience: GrantAudience::SessionAgent,
        },
        issuer_key_id,
        signature: [0; 64],
    }
}

#[test]
fn execute_grant_verifier_accepts_only_the_bootstrap_pinned_key_and_message() {
    let seed = [47; 32];
    let signer = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
    let key_id = derive_execute_grant_issuer_key_id(&public_key);
    let verifier = BoundEd25519ExecuteGrantVerifier::new(key_id, public_key).unwrap();
    let mut grant = execute_grant(key_id);
    grant.signature = signer
        .sign(&grant.signing_bytes())
        .as_ref()
        .try_into()
        .unwrap();

    assert!(verifier.verify(
        &grant.issuer_key_id,
        &grant.signing_bytes(),
        &grant.signature
    ));
    assert!(!verifier.verify(&[48; 32], &grant.signing_bytes(), &grant.signature));

    let (_, wrong_public_key) = execute_issuer([49; 32]);
    let wrong_verifier = BoundEd25519ExecuteGrantVerifier::new(
        derive_execute_grant_issuer_key_id(&wrong_public_key),
        wrong_public_key,
    )
    .unwrap();
    assert!(!wrong_verifier.verify(
        &grant.issuer_key_id,
        &grant.signing_bytes(),
        &grant.signature
    ));

    let mut wrong_signature = grant.signature;
    wrong_signature[0] ^= 1;
    assert!(!verifier.verify(
        &grant.issuer_key_id,
        &grant.signing_bytes(),
        &wrong_signature
    ));

    grant.claims.session_id = SessionId("mutated-session".into());
    assert!(!verifier.verify(
        &grant.issuer_key_id,
        &grant.signing_bytes(),
        &grant.signature
    ));
}
