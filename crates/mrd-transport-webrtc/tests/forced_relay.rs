use std::{env, time::Duration};

use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};
use mrd_transport_webrtc::{
    probe_turn_relay, CandidateKind, ControlLane, IceCandidate, IceServerConfig,
    PeerConnectionConfig, PeerConnectionRole, TurnRelayProbeConfig, WebRtcPeerConnection,
};

const WAIT: Duration = Duration::from_secs(15);

#[test]
fn ice_server_debug_output_redacts_temporary_credentials() {
    let server = IceServerConfig::new(
        vec!["turn:relay.example.test:3478?transport=udp".to_owned()],
        "temporary-user".to_owned(),
        "temporary-password".to_owned(),
    );
    let debug = format!("{server:?}");
    assert!(!debug.contains("temporary-user"));
    assert!(!debug.contains("temporary-password"));
    assert!(debug.contains("[REDACTED]"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live evidence requires configured MRD_TEST_TURN_* infrastructure"]
async fn selected_candidate_pair_is_relay_when_forced() {
    let url = env::var("MRD_TEST_TURN_URL")
        .expect("INFRA_FAIL: MRD_TEST_TURN_URL is required for live TURN evidence");
    let username = env::var("MRD_TEST_TURN_USERNAME")
        .expect("INFRA_FAIL: MRD_TEST_TURN_USERNAME is required for live TURN evidence");
    let credential = env::var("MRD_TEST_TURN_CREDENTIAL")
        .expect("INFRA_FAIL: MRD_TEST_TURN_CREDENTIAL is required for live TURN evidence");
    let evidence = probe_turn_relay(TurnRelayProbeConfig {
        ice_servers: vec![IceServerConfig::new(vec![url], username, credential)],
        timeout: WAIT,
    })
    .await
    .expect("configured TURN server must produce real relay/relay traffic evidence");
    assert!(evidence.has_relay_pair());
    assert!(evidence.control_round_trip());
    assert!(evidence.media_round_trip());
}

fn live_turn_servers() -> Vec<IceServerConfig> {
    let url = env::var("MRD_TEST_TURN_URL")
        .expect("INFRA_FAIL: MRD_TEST_TURN_URL is required for live TURN evidence");
    let username = env::var("MRD_TEST_TURN_USERNAME")
        .expect("INFRA_FAIL: MRD_TEST_TURN_USERNAME is required for live TURN evidence");
    let credential = env::var("MRD_TEST_TURN_CREDENTIAL")
        .expect("INFRA_FAIL: MRD_TEST_TURN_CREDENTIAL is required for live TURN evidence");
    vec![IceServerConfig::new(vec![url], username, credential)]
}

fn loopback_config(role: PeerConnectionRole) -> PeerConnectionConfig {
    PeerConnectionConfig {
        role,
        include_loopback_candidates: true,
        ..PeerConnectionConfig::default()
    }
}

async fn exchange_initial_candidate(
    from: &WebRtcPeerConnection,
    to: &WebRtcPeerConnection,
) -> IceCandidate {
    let candidate = tokio::time::timeout(WAIT, from.next_local_candidate())
        .await
        .expect("INFRA_FAIL: initial candidate gathering timed out")
        .expect("INFRA_FAIL: initial candidate stream closed");
    to.add_ice_candidate(candidate.clone())
        .await
        .expect("initial candidate");
    candidate
}

async fn connect_initial_loopback() -> (WebRtcPeerConnection, WebRtcPeerConnection) {
    let offerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Offerer))
        .await
        .expect("initial offerer");
    let answerer = WebRtcPeerConnection::new(loopback_config(PeerConnectionRole::Answerer))
        .await
        .expect("initial answerer");
    let offer = offerer.create_offer().await.expect("initial offer");
    let answer = answerer.accept_offer(offer).await.expect("initial answer");
    offerer
        .accept_answer(answer)
        .await
        .expect("initial answer acceptance");
    tokio::join!(
        exchange_initial_candidate(&offerer, &answerer),
        exchange_initial_candidate(&answerer, &offerer)
    );
    tokio::time::timeout(WAIT, offerer.wait_connected())
        .await
        .expect("INFRA_FAIL: initial offerer timeout")
        .expect("initial offerer connected");
    tokio::time::timeout(WAIT, answerer.wait_connected())
        .await
        .expect("INFRA_FAIL: initial answerer timeout")
        .expect("initial answerer connected");
    (offerer, answerer)
}

async fn exchange_restart_candidate(from: &WebRtcPeerConnection, to: &WebRtcPeerConnection) {
    let candidate = tokio::time::timeout(WAIT, from.next_restart_candidate(1))
        .await
        .expect("INFRA_FAIL: relay candidate gathering timed out")
        .expect("INFRA_FAIL: relay candidate stream closed");
    assert_eq!(candidate.generation(), 1);
    to.add_restart_candidate(1, candidate)
        .await
        .expect("relay candidate");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live restart evidence requires configured MRD_TEST_TURN_* infrastructure"]
async fn relay_restart_commits_only_after_live_media_and_control_evidence() {
    let turn_servers = live_turn_servers();
    let (offerer, answerer) = connect_initial_loopback().await;
    let offer = offerer
        .create_restart_offer(1, turn_servers.clone())
        .await
        .expect("live restart offer");
    let answer = answerer
        .accept_restart_offer(1, turn_servers, offer)
        .await
        .expect("live restart answer");
    offerer
        .accept_restart_answer(1, answer)
        .await
        .expect("live restart answer acceptance");
    tokio::join!(
        exchange_restart_candidate(&offerer, &answerer),
        exchange_restart_candidate(&answerer, &offerer)
    );

    let (offer_evidence, answer_evidence) = tokio::join!(
        offerer.validate_pending_restart(1),
        answerer.validate_pending_restart(1)
    );
    let offer_evidence = offer_evidence.expect("live offerer relay evidence");
    let answer_evidence = answer_evidence.expect("live answerer relay evidence");
    assert_eq!(
        offer_evidence.selected_pair().local_candidate_kind,
        CandidateKind::Relay
    );
    assert_eq!(
        offer_evidence.selected_pair().remote_candidate_kind,
        CandidateKind::Relay
    );
    assert_eq!(
        answer_evidence.selected_pair().local_candidate_kind,
        CandidateKind::Relay
    );
    assert_eq!(
        answer_evidence.selected_pair().remote_candidate_kind,
        CandidateKind::Relay
    );
    offerer
        .commit_restart(1, offer_evidence)
        .await
        .expect("commit live offerer route");
    answerer
        .commit_restart(1, answer_evidence)
        .await
        .expect("commit live answerer route");

    offerer
        .send_control(ControlLane::Reliable, b"control-after-live-turn-switch")
        .await
        .expect("control after live switch");
    let control = tokio::time::timeout(WAIT, answerer.next_control(ControlLane::Reliable))
        .await
        .expect("INFRA_FAIL: control after live switch timed out")
        .expect("control after live switch");
    assert_eq!(control.as_ref(), b"control-after-live-turn-switch");
    let media = EncodedAccessUnit {
        codec: VideoCodec::H264,
        timestamp_us: 99_000,
        is_keyframe: true,
        bytes: vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21],
    };
    offerer
        .send_h264_access_unit(&media)
        .await
        .expect("media after live switch");
    let received = tokio::time::timeout(WAIT, answerer.next_h264_access_unit())
        .await
        .expect("INFRA_FAIL: media after live switch timed out")
        .expect("media after live switch");
    assert_eq!(received.bytes, media.bytes);

    offerer.close().await.expect("close offerer");
    answerer.close().await.expect("close answerer");
}
