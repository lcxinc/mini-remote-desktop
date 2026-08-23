use std::time::Duration;

use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};
use mrd_transport_webrtc::{
    ControlLane, IceCandidate, IceServerConfig, PeerConnectionConfig, PeerConnectionRole,
    SessionDescription, SessionDescriptionType, WebRtcPeerConnection,
};

const WAIT: Duration = Duration::from_secs(10);

fn loopback_config(role: PeerConnectionRole) -> PeerConnectionConfig {
    PeerConnectionConfig {
        role,
        include_loopback_candidates: true,
        ..PeerConnectionConfig::default()
    }
}

async fn exchange_candidate(
    from: &WebRtcPeerConnection,
    to: &WebRtcPeerConnection,
) -> IceCandidate {
    let candidate = tokio::time::timeout(WAIT, from.next_local_candidate())
        .await
        .expect("candidate gathering timed out")
        .expect("candidate stream closed");
    to.add_ice_candidate(candidate.clone())
        .await
        .expect("candidate should be accepted");
    candidate
}

async fn connect_loopback() -> (WebRtcPeerConnection, WebRtcPeerConnection) {
    let offerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("offerer");
    let answerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Answerer))
        .await
        .expect("answerer");
    let offer = offerer.create_offer().await.expect("offer");
    let answer = answerer.accept_offer(offer).await.expect("answer");
    offerer.accept_answer(answer).await.expect("accept answer");
    tokio::join!(
        exchange_candidate(&offerer, &answerer),
        exchange_candidate(&answerer, &offerer)
    );
    tokio::time::timeout(WAIT, offerer.wait_connected())
        .await
        .expect("offerer timeout")
        .expect("offerer connected");
    tokio::time::timeout(WAIT, answerer.wait_connected())
        .await
        .expect("answerer timeout")
        .expect("answerer connected");
    (offerer, answerer)
}

async fn exchange_restart_candidate(
    generation: u64,
    from: &WebRtcPeerConnection,
    to: &WebRtcPeerConnection,
) {
    let candidate = tokio::time::timeout(WAIT, from.next_restart_candidate(generation))
        .await
        .expect("restart candidate gathering timed out")
        .expect("restart candidate");
    assert_eq!(candidate.generation, generation);
    to.add_restart_candidate(generation, candidate)
        .await
        .expect("restart candidate should be accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_generations_are_monotonic_and_stale_signaling_is_rejected() {
    let peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("peer");

    let first = peer
        .create_restart_offer(1, Vec::new())
        .await
        .expect("generation one offer");
    assert_eq!(first.generation, 1);
    assert_eq!(peer.pending_restart_generation().await, Some(1));

    let duplicate = peer
        .create_restart_offer(1, Vec::new())
        .await
        .expect_err("same generation must fail");
    assert!(duplicate.to_string().contains("generation"));

    let second = peer
        .create_restart_offer(2, Vec::new())
        .await
        .expect("newer generation supersedes the loser");
    assert_eq!(second.generation, 2);
    assert_eq!(peer.pending_restart_generation().await, Some(2));

    let stale_answer = SessionDescription {
        kind: SessionDescriptionType::Answer,
        sdp: "v=0\r\na=ice-pwd:must-not-appear\r\n".to_owned(),
        generation: 1,
    };
    let error = peer
        .accept_restart_answer(1, stale_answer)
        .await
        .expect_err("stale answer must fail before SDP parsing");
    assert!(error.to_string().contains("generation"));
    assert!(!error.to_string().contains("must-not-appear"));

    let stale_candidate = IceCandidate {
        candidate: "candidate:1 1 udp 1 127.0.0.1 9 typ host".to_owned(),
        sdp_mid: Some("0".to_owned()),
        sdp_mline_index: Some(0),
        username_fragment: None,
        generation: 1,
    };
    let error = peer
        .add_restart_candidate(1, stale_candidate)
        .await
        .expect_err("stale candidate must fail");
    assert!(error.to_string().contains("generation"));

    peer.close().await.expect("close peer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_restart_builds_keep_only_the_highest_generation() {
    let peer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("peer");

    let (loser, winner) = tokio::join!(
        peer.create_restart_offer(1, Vec::new()),
        peer.create_restart_offer(2, Vec::new())
    );

    if let Ok(losing_offer) = loser {
        assert_eq!(losing_offer.generation, 1);
    }
    assert_eq!(winner.expect("highest generation offer").generation, 2);
    assert_eq!(peer.pending_restart_generation().await, Some(2));
    let stale = peer
        .next_restart_candidate(1)
        .await
        .expect_err("losing generation candidate stream must be detached");
    assert!(stale.to_string().contains("generation"));
    peer.close().await.expect("close peer");
}

#[test]
fn temporary_credentials_and_sdp_secrets_are_redacted_from_formatting() {
    let server = IceServerConfig::new(
        vec!["turn:embedded-user:embedded-pass@relay.example.test:3478?transport=udp".to_owned()],
        "temporary-user".to_owned(),
        "temporary-password".to_owned(),
    );
    for output in [format!("{server:?}"), format!("{server}")] {
        assert!(!output.contains("temporary-user"));
        assert!(!output.contains("temporary-password"));
        assert!(!output.contains("embedded-user"));
        assert!(!output.contains("embedded-pass"));
        assert!(output.contains("REDACTED"));
    }

    let description = SessionDescription {
        kind: SessionDescriptionType::Offer,
        sdp: "v=0\r\na=ice-ufrag:temporary-user\r\na=ice-pwd:temporary-password\r\n".to_owned(),
        generation: 7,
    };
    let debug = format!("{description:?}");
    assert!(!debug.contains("temporary-user"));
    assert!(!debug.contains("temporary-password"));
    assert!(debug.contains("REDACTED"));

    let candidate = IceCandidate {
        candidate: "candidate:1 1 udp 1 127.0.0.1 9 typ host".to_owned(),
        sdp_mid: Some("0".to_owned()),
        sdp_mline_index: Some(0),
        username_fragment: Some("temporary-user".to_owned()),
        generation: 7,
    };
    let debug = format!("{candidate:?}");
    assert!(!debug.contains("temporary-user"));
    assert!(debug.contains("REDACTED"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_replacement_preserves_old_route_then_atomically_resumes_media_and_control() {
    let (offerer, answerer) = connect_loopback().await;

    let invalid_offer = SessionDescription {
        kind: SessionDescriptionType::Offer,
        sdp: "not-an-sdp\r\na=ice-pwd:must-not-leak\r\n".to_owned(),
        generation: 1,
    };
    let invalid = answerer
        .accept_restart_offer(1, Vec::new(), invalid_offer)
        .await
        .expect_err("invalid pending peer must fail independently");
    assert!(!invalid.to_string().contains("must-not-leak"));
    assert_eq!(answerer.pending_restart_generation().await, None);
    offerer
        .send_control(ControlLane::Reliable, b"old-route-after-pending-failure")
        .await
        .expect("failed pending route must not affect active route");
    let after_failure = tokio::time::timeout(WAIT, answerer.next_control(ControlLane::Reliable))
        .await
        .expect("old route after pending failure timeout")
        .expect("old route after pending failure message");
    assert_eq!(after_failure.as_ref(), b"old-route-after-pending-failure");

    let offer = offerer
        .create_restart_offer(1, Vec::new())
        .await
        .expect("restart offer");
    let answer = answerer
        .accept_restart_offer(1, Vec::new(), offer)
        .await
        .expect("restart answer");
    offerer
        .accept_restart_answer(1, answer)
        .await
        .expect("accept restart answer");
    tokio::join!(
        exchange_restart_candidate(1, &offerer, &answerer),
        exchange_restart_candidate(1, &answerer, &offerer)
    );

    offerer
        .send_control(ControlLane::Reliable, b"old-route-still-live")
        .await
        .expect("old route remains usable while replacement is pending");
    let old_message = tokio::time::timeout(WAIT, answerer.next_control(ControlLane::Reliable))
        .await
        .expect("old route control timeout")
        .expect("old route control message");
    assert_eq!(old_message.as_ref(), b"old-route-still-live");

    let (offer_evidence, answer_evidence) = tokio::join!(
        offerer.validate_pending_restart(1),
        answerer.validate_pending_restart(1)
    );
    let offer_evidence = offer_evidence.expect("offerer replacement evidence");
    let answer_evidence = answer_evidence.expect("answerer replacement evidence");
    let stale_evidence = offer_evidence.clone();
    let stale_commit = offerer
        .commit_restart(2, stale_evidence)
        .await
        .expect_err("evidence cannot authorize another generation");
    assert!(stale_commit.to_string().contains("generation"));
    assert_eq!(offerer.current_generation().await, 0);
    assert_eq!(offerer.pending_restart_generation().await, Some(1));
    offerer
        .commit_restart(1, offer_evidence)
        .await
        .expect("commit offerer replacement");
    answerer
        .commit_restart(1, answer_evidence)
        .await
        .expect("commit answerer replacement");
    assert_eq!(offerer.current_generation().await, 1);
    assert_eq!(answerer.current_generation().await, 1);

    offerer
        .send_control(ControlLane::Reliable, b"control-resumed")
        .await
        .expect("control after route switch");
    let control = tokio::time::timeout(WAIT, answerer.next_control(ControlLane::Reliable))
        .await
        .expect("new route control timeout")
        .expect("new route control message");
    assert_eq!(control.as_ref(), b"control-resumed");

    let access_unit = EncodedAccessUnit {
        codec: VideoCodec::H264,
        timestamp_us: 99_000,
        is_keyframe: true,
        bytes: vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21],
    };
    offerer
        .send_h264_access_unit(&access_unit)
        .await
        .expect("media after route switch");
    let media = tokio::time::timeout(WAIT, answerer.next_h264_access_unit())
        .await
        .expect("new route media timeout")
        .expect("new route media");
    assert_eq!(media.bytes, access_unit.bytes);

    offerer.close().await.expect("close offerer");
    answerer.close().await.expect("close answerer");
}
