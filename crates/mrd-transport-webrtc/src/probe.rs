use std::{future::Future, time::Duration};

use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};

use crate::{
    config::{ice_server_secret_values, normalize_secret_values},
    CandidateKind, ControlLane, IceServerConfig, IceTransportPolicy, PeerConnectionConfig,
    PeerConnectionRole, SelectedCandidatePairStats, TransportError, WebRtcPeerConnection,
};

const PROBE_PAYLOAD: &[u8] = b"mrd-turn-relay-probe-v1";

#[derive(Debug, Clone)]
pub struct TurnRelayProbeConfig {
    pub ice_servers: Vec<IceServerConfig>,
    pub timeout: Duration,
}

impl Default for TurnRelayProbeConfig {
    fn default() -> Self {
        Self {
            ice_servers: Vec::new(),
            timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TurnRelayProbeEvidence {
    selected_pair: SelectedCandidatePairStats,
    control_round_trip: bool,
    media_round_trip: bool,
}

impl TurnRelayProbeEvidence {
    pub fn selected_pair(&self) -> &SelectedCandidatePairStats {
        &self.selected_pair
    }

    pub fn has_relay_pair(&self) -> bool {
        self.selected_pair.local_candidate_kind == CandidateKind::Relay
            && self.selected_pair.remote_candidate_kind == CandidateKind::Relay
    }

    pub fn control_round_trip(&self) -> bool {
        self.control_round_trip
    }

    pub fn media_round_trip(&self) -> bool {
        self.media_round_trip
    }

    fn from_observation(
        selected_pair: SelectedCandidatePairStats,
        control_round_trip: bool,
        media_round_trip: bool,
    ) -> Result<Self, TransportError> {
        if !selected_pair.nominated
            || selected_pair.local_candidate_kind != CandidateKind::Relay
            || selected_pair.remote_candidate_kind != CandidateKind::Relay
        {
            return Err(TransportError::Message(
                "TURN probe did not select a nominated relay/relay candidate pair".into(),
            ));
        }
        if !control_round_trip || !media_round_trip {
            return Err(TransportError::Message(
                "TURN probe requires actual control and media traffic".into(),
            ));
        }
        Ok(Self {
            selected_pair,
            control_round_trip,
            media_round_trip,
        })
    }
}

/// Produce live TURN evidence. Gathering a relay candidate alone is never success: the
/// selected pair must be relay/relay and real DTLS/SCTP and SRTP traffic must cross it.
pub async fn probe_turn_relay(
    config: TurnRelayProbeConfig,
) -> Result<TurnRelayProbeEvidence, TransportError> {
    if config.ice_servers.is_empty() {
        return Err(TransportError::Message(
            "TURN probe requires at least one ICE server".into(),
        ));
    }
    if config.timeout.is_zero() {
        return Err(TransportError::Message(
            "TURN probe timeout must be non-zero".into(),
        ));
    }
    let secrets = secret_values(&config.ice_servers);
    let deadline = tokio::time::Instant::now() + config.timeout;
    run_before_probe_deadline(deadline, async move {
        let offerer_config =
            probe_peer_config(PeerConnectionRole::Offerer, config.ice_servers.clone());
        let answerer_config = probe_peer_config(PeerConnectionRole::Answerer, config.ice_servers);
        // Separate tasks prevent either peer's CPU-heavy synchronous setup from serializing the
        // pair or starving the deadline driver. Detached task outputs are dropped on completion,
        // which invokes the peer's cancellation-safe shutdown when a deadline wins.
        let offerer_task =
            tokio::spawn(async move { WebRtcPeerConnection::new(offerer_config).await });
        let answerer_task =
            tokio::spawn(async move { WebRtcPeerConnection::new(answerer_config).await });
        let (offerer, answerer) = tokio::join!(offerer_task, answerer_task);
        let offerer = offerer
            .map_err(|_| TransportError::Message("TURN offerer creation task failed".into()))?;
        let answerer = answerer
            .map_err(|_| TransportError::Message("TURN answerer creation task failed".into()))?;
        let offerer = offerer.map_err(|error| redact(error, &secrets))?;
        let answerer = answerer.map_err(|error| redact(error, &secrets))?;
        let result = run_live_probe(&offerer, &answerer)
            .await
            .map_err(|error| redact(error, &secrets));

        // Shutdown is deliberately started, not awaited. Each peer's physical shutdown owns its
        // resources and keeps running if this deadline or its caller cancels this future.
        offerer.terminate_now();
        answerer.terminate_now();
        result
    })
    .await
}

async fn run_before_probe_deadline<T, F>(
    deadline: tokio::time::Instant,
    operation: F,
) -> Result<T, TransportError>
where
    F: Future<Output = Result<T, TransportError>>,
{
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| TransportError::Message("TURN probe timed out".into()))?
}

fn probe_peer_config(
    role: PeerConnectionRole,
    ice_servers: Vec<IceServerConfig>,
) -> PeerConnectionConfig {
    PeerConnectionConfig {
        role,
        ice_servers,
        ice_transport_policy: IceTransportPolicy::Relay,
        ..PeerConnectionConfig::default()
    }
}

async fn run_live_probe(
    offerer: &WebRtcPeerConnection,
    answerer: &WebRtcPeerConnection,
) -> Result<TurnRelayProbeEvidence, TransportError> {
    let offer = offerer.create_offer().await?;
    let answer = answerer.accept_offer(offer).await?;
    offerer.accept_answer(answer).await?;

    let offer_candidate = offerer
        .next_local_candidate()
        .await
        .ok_or_else(|| TransportError::Message("TURN offerer produced no candidate".into()))?;
    let answer_candidate = answerer
        .next_local_candidate()
        .await
        .ok_or_else(|| TransportError::Message("TURN answerer produced no candidate".into()))?;
    answerer.add_ice_candidate(offer_candidate).await?;
    offerer.add_ice_candidate(answer_candidate).await?;
    let (offer_connected, answer_connected) =
        tokio::join!(offerer.wait_connected(), answerer.wait_connected());
    offer_connected?;
    answer_connected?;

    let (offer_send, answer_send) = tokio::join!(
        offerer.send_control(ControlLane::Reliable, PROBE_PAYLOAD),
        answerer.send_control(ControlLane::Reliable, PROBE_PAYLOAD)
    );
    offer_send?;
    answer_send?;
    let (offer_control, answer_control) = tokio::join!(
        offerer.next_control(ControlLane::Reliable),
        answerer.next_control(ControlLane::Reliable)
    );
    let control_round_trip = offer_control.as_deref() == Some(PROBE_PAYLOAD)
        && answer_control.as_deref() == Some(PROBE_PAYLOAD);

    let media_probe = EncodedAccessUnit {
        codec: VideoCodec::H264,
        timestamp_us: 1_000,
        is_keyframe: true,
        bytes: vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21],
    };
    let (offer_media_send, answer_media_send) = tokio::join!(
        offerer.send_h264_access_unit(&media_probe),
        answerer.send_h264_access_unit(&media_probe)
    );
    offer_media_send?;
    answer_media_send?;
    let (offer_media, answer_media) = tokio::join!(
        offerer.next_h264_access_unit(),
        answerer.next_h264_access_unit()
    );
    let media_round_trip = offer_media.as_ref().map(|unit| &unit.bytes) == Some(&media_probe.bytes)
        && answer_media.as_ref().map(|unit| &unit.bytes) == Some(&media_probe.bytes);

    let selected_pair = offerer
        .selected_candidate_pair_stats()
        .await
        .ok_or_else(|| TransportError::Message("TURN probe selected pair is missing".into()))?;
    let answer_pair = answerer
        .selected_candidate_pair_stats()
        .await
        .ok_or_else(|| TransportError::Message("TURN probe answer pair is missing".into()))?;
    TurnRelayProbeEvidence::from_observation(answer_pair, control_round_trip, media_round_trip)?;
    TurnRelayProbeEvidence::from_observation(selected_pair, control_round_trip, media_round_trip)
}

fn secret_values(servers: &[IceServerConfig]) -> Vec<String> {
    ice_server_secret_values(servers)
}

fn redact(error: TransportError, secrets: &[String]) -> TransportError {
    let mut message = error.to_string();
    for secret in normalize_secret_values(secrets.to_vec()) {
        message = message.replace(&secret, "[REDACTED]");
    }
    TransportError::Message(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    fn pair(local: CandidateKind, remote: CandidateKind) -> SelectedCandidatePairStats {
        SelectedCandidatePairStats {
            local_candidate_id: "local".into(),
            remote_candidate_id: "remote".into(),
            local_candidate_kind: local,
            remote_candidate_kind: remote,
            nominated: true,
            packets_sent: 1,
            packets_received: 1,
            bytes_sent: 8,
            bytes_received: 8,
            current_round_trip_time: 0.01,
        }
    }

    #[test]
    fn host_srflx_and_prflx_pairs_are_never_turn_evidence() {
        for kind in [
            CandidateKind::Host,
            CandidateKind::ServerReflexive,
            CandidateKind::PeerReflexive,
        ] {
            assert!(TurnRelayProbeEvidence::from_observation(
                pair(CandidateKind::Relay, kind),
                true,
                true
            )
            .is_err());
            assert!(TurnRelayProbeEvidence::from_observation(
                pair(kind, CandidateKind::Relay),
                true,
                true
            )
            .is_err());
        }
    }

    #[test]
    fn relay_gathering_without_real_traffic_is_not_evidence() {
        let selected = pair(CandidateKind::Relay, CandidateKind::Relay);
        assert!(TurnRelayProbeEvidence::from_observation(selected.clone(), false, true).is_err());
        assert!(TurnRelayProbeEvidence::from_observation(selected, true, false).is_err());
    }

    #[tokio::test]
    async fn one_deadline_cancels_the_whole_probe_and_hands_off_owned_resources() {
        struct OwnedResource(Arc<AtomicBool>);

        impl Drop for OwnedResource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let timeout = Duration::from_millis(5);
        let started = tokio::time::Instant::now();
        let dropped = Arc::new(AtomicBool::new(false));
        let owned = OwnedResource(Arc::clone(&dropped));
        let result = run_before_probe_deadline(started + timeout, async move {
            let _owned = owned;
            std::future::pending::<Result<(), TransportError>>().await
        })
        .await;

        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(dropped.load(Ordering::Acquire));
        assert!(
            started.elapsed() <= timeout + Duration::from_millis(100),
            "probe exceeded the single deadline by more than scheduling tolerance"
        );
    }
}
