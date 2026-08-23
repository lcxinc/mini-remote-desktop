use std::{env, time::Duration};

use mrd_transport_webrtc::{probe_turn_relay, IceServerConfig, TurnRelayProbeConfig};

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
