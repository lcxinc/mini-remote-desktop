use mrd_transport_webrtc::{
    IceCandidate, IceServerConfig, PeerConnectionConfig, PeerConnectionRole, RestartRouteToken,
    SessionDescription, SessionDescriptionType, WebRtcPeerConnection,
};

fn loopback_config(role: PeerConnectionRole) -> PeerConnectionConfig {
    PeerConnectionConfig {
        role,
        include_loopback_candidates: true,
        ..PeerConnectionConfig::default()
    }
}

fn fake_turn_servers() -> Vec<IceServerConfig> {
    vec![IceServerConfig::new(
        vec!["turn:relay.example.test:3478?transport=udp".to_owned()],
        "temporary-user".to_owned(),
        "temporary-credential".to_owned(),
    )]
}

fn token(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

#[tokio::test]
async fn restart_requires_authenticated_turn_servers() {
    let peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("peer");

    let missing = peer
        .create_restart_offer(1, Vec::new())
        .await
        .expect_err("empty ICE server list must not permit a host restart");
    assert!(missing.to_string().to_ascii_uppercase().contains("TURN"));
    let untrusted = peer
        .create_restart_offer(
            1,
            vec![IceServerConfig::new(
                vec!["stun:relay.example.test:3478".to_owned()],
                "temporary-user".to_owned(),
                "temporary-credential".to_owned(),
            )],
        )
        .await
        .expect_err("STUN-only server must not permit restart");
    assert!(untrusted.to_string().to_ascii_uppercase().contains("TURN"));
    let unauthenticated = peer
        .create_restart_offer(
            1,
            vec![IceServerConfig::new(
                vec!["turn:relay.example.test:3478".to_owned()],
                String::new(),
                String::new(),
            )],
        )
        .await
        .expect_err("unauthenticated TURN server must not permit restart");
    assert!(unauthenticated
        .to_string()
        .to_ascii_uppercase()
        .contains("TURN"));
    let mixed = peer
        .create_restart_offer(
            1,
            vec![IceServerConfig::new(
                vec![
                    "turn:relay.example.test:3478".to_owned(),
                    "stun:relay.example.test:3478".to_owned(),
                ],
                "temporary-user".to_owned(),
                "temporary-credential".to_owned(),
            )],
        )
        .await
        .expect_err("every restart URL must be a TURN URL");
    assert!(mixed.to_string().to_ascii_uppercase().contains("TURN"));

    peer.close().await.expect("close peer");
}

#[tokio::test]
async fn same_generation_answers_and_candidates_are_bound_to_an_opaque_route_token() {
    let first_peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("first peer");
    let second_peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("second peer");
    let first_offer = first_peer
        .create_restart_offer(1, fake_turn_servers())
        .await
        .expect("first restart offer");
    let second_offer = second_peer
        .create_restart_offer(1, fake_turn_servers())
        .await
        .expect("second restart offer");
    let first_token = first_offer
        .restart_route_token()
        .expect("first route token")
        .to_wire();
    let second_token = second_offer
        .restart_route_token()
        .expect("second route token")
        .to_wire();
    assert_ne!(first_token, second_token);
    assert_eq!(first_token.len(), 64);
    assert_eq!(
        RestartRouteToken::from_wire(&first_token)
            .unwrap()
            .to_wire(),
        first_token
    );
    assert!(!format!("{:?}", first_offer.restart_route_token()).contains(&first_token));

    let wrong_answer = SessionDescription::from_wire(
        SessionDescriptionType::Answer,
        "v=0\r\na=ice-pwd:must-not-parse\r\n".to_owned(),
        1,
        Some(&second_token),
    )
    .expect("well-formed wire answer");
    let error = first_peer
        .accept_restart_answer(1, wrong_answer)
        .await
        .expect_err("same generation answer from another route must fail");
    assert!(error.to_string().contains("route"));
    assert!(!error.to_string().contains("must-not-parse"));

    let wrong_candidate = IceCandidate::from_wire(
        "candidate:1 1 udp 1 127.0.0.1 9 typ relay ufrag candidate-secret".to_owned(),
        Some("0".to_owned()),
        Some(0),
        Some("candidate-secret".to_owned()),
        1,
        Some(&second_token),
    )
    .expect("well-formed wire candidate");
    let error = first_peer
        .add_restart_candidate(1, wrong_candidate)
        .await
        .expect_err("same generation candidate from another route must fail");
    assert!(error.to_string().contains("route"));
    assert!(!error.to_string().contains("candidate-secret"));

    first_peer.close().await.expect("close first peer");
    second_peer.close().await.expect("close second peer");
}

#[tokio::test]
async fn same_generation_is_idempotent_only_for_the_existing_route() {
    let offerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("offerer");
    let answerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Answerer))
        .await
        .expect("answerer");
    let offer = offerer
        .create_restart_offer(1, fake_turn_servers())
        .await
        .expect("restart offer");
    let answer = answerer
        .accept_restart_offer(1, fake_turn_servers(), offer.clone())
        .await
        .expect("first acceptance");

    let duplicate = answerer
        .accept_restart_offer(1, fake_turn_servers(), offer)
        .await
        .expect("same route retry returns the existing answer");

    assert_eq!(duplicate, answer);
    let wrong_route_offer = SessionDescription::from_wire(
        SessionDescriptionType::Offer,
        "v=0\r\na=ice-pwd:must-not-parse\r\n".into(),
        1,
        Some(&token('b')),
    )
    .unwrap();
    let error = answerer
        .accept_restart_offer(1, fake_turn_servers(), wrong_route_offer)
        .await
        .expect_err("same generation with another route token is not idempotent");
    assert!(error.to_string().contains("route"));
    assert!(!error.to_string().contains("must-not-parse"));
    assert_eq!(answerer.pending_restart_generation().await, Some(1));
    offerer.close().await.expect("close offerer");
    answerer.close().await.expect("close answerer");
}

#[tokio::test]
async fn candidate_parse_errors_redact_raw_candidate_and_ufrag_extensions() {
    let peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("peer");
    let offer = peer
        .create_restart_offer(1, fake_turn_servers())
        .await
        .expect("restart offer");
    let route_token = offer.restart_route_token().unwrap().to_wire();
    let candidate_secret = "raw-candidate-secret";
    let extension_secret = "extension-ufrag-secret";
    let candidate = IceCandidate::from_wire(
        format!("{candidate_secret} ufrag {extension_secret}"),
        Some("0".into()),
        Some(0),
        None,
        1,
        Some(&route_token),
    )
    .unwrap();

    let error = peer
        .add_restart_candidate(1, candidate)
        .await
        .expect_err("malformed candidate must fail");

    let output = error.to_string();
    assert!(!output.contains(candidate_secret));
    assert!(!output.contains(extension_secret));
    peer.close().await.expect("close peer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_generations_are_monotonic_and_stale_signaling_is_rejected() {
    let peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("peer");

    let first = peer
        .create_restart_offer(1, fake_turn_servers())
        .await
        .expect("generation one offer");
    assert_eq!(first.generation(), 1);
    let first_token = first.restart_route_token().unwrap().to_wire();
    assert_eq!(peer.pending_restart_generation().await, Some(1));

    let duplicate = peer
        .create_restart_offer(1, fake_turn_servers())
        .await
        .expect_err("same generation must fail");
    assert!(duplicate.to_string().contains("generation"));

    let second = peer
        .create_restart_offer(2, fake_turn_servers())
        .await
        .expect("newer generation supersedes the loser");
    assert_eq!(second.generation(), 2);
    assert_eq!(peer.pending_restart_generation().await, Some(2));

    let stale_answer = SessionDescription::from_wire(
        SessionDescriptionType::Answer,
        "v=0\r\na=ice-pwd:must-not-appear\r\n".to_owned(),
        1,
        Some(&first_token),
    )
    .unwrap();
    let error = peer
        .accept_restart_answer(1, stale_answer)
        .await
        .expect_err("stale answer must fail before SDP parsing");
    assert!(error.to_string().contains("generation"));
    assert!(!error.to_string().contains("must-not-appear"));

    let stale_candidate = IceCandidate::from_wire(
        "candidate:1 1 udp 1 127.0.0.1 9 typ host".to_owned(),
        Some("0".to_owned()),
        Some(0),
        None,
        1,
        Some(&first_token),
    )
    .unwrap();
    let error = peer
        .add_restart_candidate(1, stale_candidate)
        .await
        .expect_err("stale candidate must fail");
    assert!(error.to_string().contains("generation"));

    peer.close().await.expect("close peer");
}

#[tokio::test]
async fn failed_generation_remains_consumed_and_cannot_flow_back() {
    let answerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Answerer))
        .await
        .expect("answerer");
    let first_token = token('1');
    let invalid = SessionDescription::from_wire(
        SessionDescriptionType::Offer,
        "not-an-sdp\r\na=ice-pwd:failed-generation-secret\r\n".to_owned(),
        1,
        Some(&first_token),
    )
    .unwrap();
    let failed = answerer
        .accept_restart_offer(1, fake_turn_servers(), invalid.clone())
        .await
        .expect_err("invalid SDP must fail the pending build");
    assert!(!failed.to_string().contains("failed-generation-secret"));
    assert_eq!(answerer.pending_restart_generation().await, None);

    for (generation, route_token) in [(1, token('1')), (1, token('2'))] {
        let retry = SessionDescription::from_wire(
            SessionDescriptionType::Offer,
            invalid.sdp.clone(),
            generation,
            Some(&route_token),
        )
        .unwrap();
        let error = answerer
            .accept_restart_offer(generation, fake_turn_servers(), retry)
            .await
            .expect_err("consumed generation must never create another route");
        assert!(error.to_string().contains("generation"));
    }
    let lower = answerer
        .accept_restart_offer(0, fake_turn_servers(), invalid)
        .await
        .expect_err("lower generation must not flow back");
    assert!(lower.to_string().contains("generation"));

    let second = SessionDescription::from_wire(
        SessionDescriptionType::Offer,
        "also-not-an-sdp".to_owned(),
        2,
        Some(&token('3')),
    )
    .unwrap();
    let error = answerer
        .accept_restart_offer(2, fake_turn_servers(), second)
        .await
        .expect_err("generation two reaches SDP parsing");
    assert!(!error.to_string().contains("stale or losing"));
    let consumed_second = SessionDescription::from_wire(
        SessionDescriptionType::Offer,
        "must-not-be-parsed".to_owned(),
        2,
        Some(&token('3')),
    )
    .unwrap();
    let error = answerer
        .accept_restart_offer(2, fake_turn_servers(), consumed_second)
        .await
        .expect_err("failed generation two remains consumed");
    assert!(error.to_string().contains("generation"));

    answerer.close().await.expect("close answerer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_restart_builds_keep_only_the_highest_generation() {
    let peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("peer");

    let (loser, winner) = tokio::join!(
        peer.create_restart_offer(1, fake_turn_servers()),
        peer.create_restart_offer(2, fake_turn_servers())
    );

    if let Ok(losing_offer) = loser {
        assert_eq!(losing_offer.generation(), 1);
    }
    assert_eq!(winner.expect("highest generation offer").generation(), 2);
    assert_eq!(peer.pending_restart_generation().await, Some(2));
    let stale = peer
        .next_restart_candidate(1)
        .await
        .expect_err("losing generation candidate stream must be detached");
    assert!(stale.to_string().contains("generation"));
    peer.close().await.expect("close peer");
}

#[test]
fn temporary_credentials_route_tokens_candidates_and_urls_are_redacted() {
    let server = IceServerConfig::new(
        vec!["turn:embedded-user:embedded-pass@relay.example.test/private-path?api_key=query-secret#fragment-secret".to_owned()],
        "temporary-user".to_owned(),
        "temporary-password".to_owned(),
    );
    for output in [format!("{server:?}"), format!("{server}")] {
        for secret in [
            "temporary-user",
            "temporary-password",
            "embedded-user",
            "embedded-pass",
            "private-path",
            "query-secret",
            "fragment-secret",
        ] {
            assert!(!output.contains(secret), "leaked {secret}: {output}");
        }
        assert!(output.contains("REDACTED"));
    }

    let route_token = token('a');
    let parsed_token = RestartRouteToken::from_wire(&route_token).unwrap();
    for output in [format!("{parsed_token:?}"), format!("{parsed_token}")] {
        assert!(!output.contains(&route_token));
        assert!(output.contains("REDACTED"));
    }
    let description = SessionDescription::from_wire(
        SessionDescriptionType::Offer,
        "v=0\r\na=ice-ufrag:temporary-user\r\na=ice-pwd:temporary-password\r\n".to_owned(),
        7,
        Some(&route_token),
    )
    .unwrap();
    let debug = format!("{description:?}");
    assert!(!debug.contains("temporary-user"));
    assert!(!debug.contains("temporary-password"));
    assert!(!debug.contains(&route_token));

    let candidate = IceCandidate::from_wire(
        "candidate:1 1 udp 1 127.0.0.1 9 typ relay ufrag extension-secret".to_owned(),
        Some("0".to_owned()),
        Some(0),
        Some("username-fragment-secret".to_owned()),
        7,
        Some(&route_token),
    )
    .unwrap();
    let debug = format!("{candidate:?}");
    assert!(!debug.contains("extension-secret"));
    assert!(!debug.contains("username-fragment-secret"));
    assert!(!debug.contains(&route_token));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn route_token_wire_encoding_rejects_noncanonical_values() {
    for invalid in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "z".repeat(64),
    ] {
        let error = RestartRouteToken::from_wire(&invalid).expect_err("noncanonical token");
        assert!(!error.to_string().contains(&invalid));
    }
    assert!(
        SessionDescription::from_wire(SessionDescriptionType::Offer, "v=0".into(), 1, None)
            .is_err()
    );
    assert!(SessionDescription::from_wire(
        SessionDescriptionType::Offer,
        "v=0".into(),
        0,
        Some(&token('a'))
    )
    .is_err());
}
