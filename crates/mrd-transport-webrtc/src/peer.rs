use std::{
    fmt,
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};

use bytes::Bytes;
use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};
use tokio::{
    sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
use webrtc::{
    api::{
        interceptor_registry::register_default_interceptors, media_engine::MediaEngine,
        setting_engine::SettingEngine, APIBuilder,
    },
    data_channel::{data_channel_state::RTCDataChannelState, RTCDataChannel},
    ice_transport::{ice_candidate::RTCIceCandidateInit, ice_server::RTCIceServer},
    interceptor::registry::Registry,
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        policy::ice_transport_policy::RTCIceTransportPolicy,
        sdp::session_description::RTCSessionDescription, RTCPeerConnection,
    },
    track::track_local::TrackLocal,
};

use crate::{
    config::{IceServerConfig, IceTransportPolicy, PeerConnectionConfig, PeerConnectionRole},
    control::{
        channel_info, realtime_channel_init, reliable_channel_init, weak_callback_owner,
        ControlChannels, ControlLane, ControlState, QueuedBytes, BULK_LABEL, CTRL_REL_LABEL,
        CTRL_RT_LABEL,
    },
    stats::selected_candidate_pair,
    H264RtpIngress, H264RtpSender, SelectedCandidatePairStats, TransportError,
};

const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const DISCONNECTED_GRACE_PERIOD: Duration = Duration::from_secs(2);
const BULK_BUFFER_HIGH_WATERMARK: usize = 64 * 1024;
const BULK_SEND_PACING_INTERVAL: Duration = Duration::from_millis(1);
const RESTART_VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);
const RESTART_PROBE_PREFIX: &[u8] = b"mrd-webrtc-restart-probe-v1:";
static NEXT_RESTART_ROUTE_ID: AtomicU64 = AtomicU64::new(1);
const RESTART_ROUTE_TOKEN_BYTES: usize = 32;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RestartRouteToken([u8; RESTART_ROUTE_TOKEN_BYTES]);

impl RestartRouteToken {
    fn generate() -> Result<Self, TransportError> {
        let mut bytes = [0_u8; RESTART_ROUTE_TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| {
            TransportError::Message("secure restart route token generation failed".into())
        })?;
        Ok(Self(bytes))
    }

    pub fn from_wire(value: &str) -> Result<Self, TransportError> {
        if value.len() != RESTART_ROUTE_TOKEN_BYTES * 2 || !value.is_ascii() {
            return Err(TransportError::Message(
                "invalid restart route token encoding".into(),
            ));
        }
        let mut bytes = [0_u8; RESTART_ROUTE_TOKEN_BYTES];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or_else(invalid_route_token)?;
            let low = decode_hex(pair[1]).ok_or_else(invalid_route_token)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub fn to_wire(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(RESTART_ROUTE_TOKEN_BYTES * 2);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for RestartRouteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestartRouteToken([REDACTED])")
    }
}

impl fmt::Display for RestartRouteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDescriptionType {
    Offer,
    Answer,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionDescription {
    pub kind: SessionDescriptionType,
    pub sdp: String,
    /// Authenticated signaling generation. Initial negotiation is generation zero.
    generation: u64,
    restart_route_token: Option<RestartRouteToken>,
}

impl SessionDescription {
    pub fn from_wire(
        kind: SessionDescriptionType,
        sdp: String,
        generation: u64,
        restart_route_token: Option<&str>,
    ) -> Result<Self, TransportError> {
        let restart_route_token = parse_wire_route(generation, restart_route_token)?;
        Ok(Self {
            kind,
            sdp,
            generation,
            restart_route_token,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn restart_route_token(&self) -> Option<&RestartRouteToken> {
        self.restart_route_token.as_ref()
    }

    fn initial(kind: SessionDescriptionType, sdp: String) -> Self {
        Self {
            kind,
            sdp,
            generation: 0,
            restart_route_token: None,
        }
    }

    fn bind_restart(&mut self, generation: u64, token: RestartRouteToken) {
        self.generation = generation;
        self.restart_route_token = Some(token);
    }

    fn clear_restart_binding(&mut self) {
        self.generation = 0;
        self.restart_route_token = None;
    }
}

impl fmt::Debug for SessionDescription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionDescription")
            .field("kind", &self.kind)
            .field("sdp", &"[REDACTED]")
            .field("generation", &self.generation)
            .field(
                "restart_route_token",
                &self.restart_route_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
    /// Authenticated signaling generation. Initial negotiation is generation zero.
    generation: u64,
    restart_route_token: Option<RestartRouteToken>,
}

impl IceCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn from_wire(
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
        username_fragment: Option<String>,
        generation: u64,
        restart_route_token: Option<&str>,
    ) -> Result<Self, TransportError> {
        let restart_route_token = parse_wire_route(generation, restart_route_token)?;
        Ok(Self {
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment,
            generation,
            restart_route_token,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn restart_route_token(&self) -> Option<&RestartRouteToken> {
        self.restart_route_token.as_ref()
    }

    fn bind_restart(&mut self, generation: u64, token: RestartRouteToken) {
        self.generation = generation;
        self.restart_route_token = Some(token);
    }

    fn clear_restart_binding(&mut self) {
        self.generation = 0;
        self.restart_route_token = None;
    }
}

impl fmt::Debug for IceCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IceCandidate")
            .field("candidate", &"[REDACTED]")
            .field("sdp_mid", &self.sdp_mid)
            .field("sdp_mline_index", &self.sdp_mline_index)
            .field("username_fragment", &"[REDACTED]")
            .field("generation", &self.generation)
            .field(
                "restart_route_token",
                &self.restart_route_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl From<RTCIceCandidateInit> for IceCandidate {
    fn from(value: RTCIceCandidateInit) -> Self {
        Self {
            candidate: value.candidate,
            sdp_mid: value.sdp_mid,
            sdp_mline_index: value.sdp_mline_index,
            username_fragment: value.username_fragment,
            generation: 0,
            restart_route_token: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RestartRouteEvidence {
    generation: u64,
    route_id: u64,
    selected_pair: SelectedCandidatePairStats,
    control_round_trip: bool,
    media_round_trip: bool,
}

impl RestartRouteEvidence {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn selected_pair(&self) -> &SelectedCandidatePairStats {
        &self.selected_pair
    }

    pub fn control_round_trip(&self) -> bool {
        self.control_round_trip
    }

    pub fn media_round_trip(&self) -> bool {
        self.media_round_trip
    }
}

enum PendingRestart {
    Building {
        generation: u64,
        route_token: RestartRouteToken,
    },
    Ready {
        generation: u64,
        route_token: RestartRouteToken,
        route_id: u64,
        peer: Arc<WebRtcPeerConnection>,
        local_description: SessionDescription,
        validated: bool,
    },
}

impl PendingRestart {
    fn generation(&self) -> u64 {
        match self {
            Self::Building { generation, .. } | Self::Ready { generation, .. } => *generation,
        }
    }

    fn route_token(&self) -> &RestartRouteToken {
        match self {
            Self::Building { route_token, .. } | Self::Ready { route_token, .. } => route_token,
        }
    }

    fn ready_peer(&self) -> Option<(u64, RestartRouteToken, Arc<WebRtcPeerConnection>)> {
        match self {
            Self::Ready {
                route_id,
                route_token,
                peer,
                ..
            } => Some((*route_id, route_token.clone(), Arc::clone(peer))),
            Self::Building { .. } => None,
        }
    }
}

#[derive(Default)]
struct RestartState {
    active_generation: u64,
    highest_seen_generation: u64,
    active_route_token: Option<RestartRouteToken>,
    active_replacement: Option<Arc<WebRtcPeerConnection>>,
    pending: Option<PendingRestart>,
}

impl RestartState {
    fn active_snapshot(
        &self,
    ) -> (
        u64,
        Option<RestartRouteToken>,
        Option<Arc<WebRtcPeerConnection>>,
    ) {
        (
            self.active_generation,
            self.active_route_token.clone(),
            self.active_replacement.as_ref().map(Arc::clone),
        )
    }
}

impl From<IceCandidate> for RTCIceCandidateInit {
    fn from(value: IceCandidate) -> Self {
        Self {
            candidate: value.candidate,
            sdp_mid: value.sdp_mid,
            sdp_mline_index: value.sdp_mline_index,
            username_fragment: value.username_fragment,
        }
    }
}

pub struct WebRtcPeerConnection {
    pc: Arc<RTCPeerConnection>,
    config: PeerConnectionConfig,
    h264_sender: Mutex<H264RtpSender>,
    local_candidates: Mutex<mpsc::Receiver<IceCandidate>>,
    h264_rx: Mutex<mpsc::Receiver<QueuedAccessUnit>>,
    reliable_rx: Mutex<mpsc::Receiver<QueuedBytes>>,
    realtime_rx: Mutex<mpsc::Receiver<QueuedBytes>>,
    bulk_rx: Mutex<mpsc::Receiver<QueuedBytes>>,
    control: Arc<ControlState>,
    connection_state_rx: watch::Receiver<RTCPeerConnectionState>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    active_tasks: Arc<AtomicUsize>,
    completed_video_drops: Arc<VideoDropCounter>,
    closed: Arc<AtomicBool>,
    restart: StdMutex<RestartState>,
    restart_cleanup_failures: AtomicU64,
    #[cfg(test)]
    fail_close_for_test: AtomicBool,
}

#[derive(Debug)]
struct QueuedAccessUnit {
    access_unit: EncodedAccessUnit,
    _byte_permit: OwnedSemaphorePermit,
}

#[derive(Debug, Default)]
struct VideoDropCounter {
    state: StdMutex<VideoDropState>,
}

#[derive(Debug, Default)]
struct VideoDropState {
    count: u64,
    sealed: bool,
}

impl VideoDropCounter {
    fn record(&self) {
        let mut state = self.state.lock().expect("video drop counter lock poisoned");
        if !state.sealed {
            state.count = state.count.saturating_add(1);
        }
    }

    fn take(&self) -> u64 {
        let mut state = self.state.lock().expect("video drop counter lock poisoned");
        std::mem::take(&mut state.count)
    }

    fn seal(&self) {
        self.state
            .lock()
            .expect("video drop counter lock poisoned")
            .sealed = true;
    }
}

impl QueuedAccessUnit {
    fn into_access_unit(self) -> EncodedAccessUnit {
        self.access_unit
    }
}

impl fmt::Debug for WebRtcPeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebRtcPeerConnection")
            .field("role", &self.config.role)
            .field("active_tasks", &self.active_task_count())
            .field("closed", &self.closed.load(Ordering::Acquire))
            .field("generation", &self.current_generation_now())
            .finish_non_exhaustive()
    }
}

impl Drop for WebRtcPeerConnection {
    fn drop(&mut self) {
        self.terminate_now();
    }
}

impl WebRtcPeerConnection {
    pub async fn new(config: PeerConnectionConfig) -> Result<Self, TransportError> {
        let codec = config.preflight()?.clone();
        let config_secrets = secret_values(&config.ice_servers);
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|error| TransportError::Message(format!("register codecs failed: {error}")))?;
        let registry =
            register_default_interceptors(Registry::new(), &mut media_engine).map_err(|error| {
                TransportError::Message(format!("register interceptors failed: {error}"))
            })?;
        let mut settings = SettingEngine::default();
        settings.set_include_loopback_candidate(config.include_loopback_candidates);
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(settings)
            .build();
        let ice_servers = config
            .ice_servers
            .iter()
            .map(|server| RTCIceServer {
                urls: server.urls.clone(),
                username: server.username.clone(),
                credential: server.credential.clone(),
            })
            .collect();
        let ice_transport_policy = match config.ice_transport_policy {
            IceTransportPolicy::All => RTCIceTransportPolicy::All,
            IceTransportPolicy::Relay => RTCIceTransportPolicy::Relay,
        };
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers,
                ice_transport_policy,
                ..Default::default()
            })
            .await
            .map_err(peer_error_redacted(
                "create peer connection",
                &config_secrets,
            ))?,
        );

        let capacity = config.event_queue_capacity;
        let (candidate_tx, candidate_rx) = mpsc::channel(capacity);
        pc.on_ice_candidate(Box::new(move |candidate| {
            let candidate_tx = candidate_tx.clone();
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    if let Ok(candidate) = candidate.to_json() {
                        let _ = candidate_tx.try_send(candidate.into());
                    }
                }
            })
        }));

        let (connection_state_tx, connection_state_rx) =
            watch::channel(RTCPeerConnectionState::New);
        pc.on_peer_connection_state_change(Box::new(move |state| {
            let connection_state_tx = connection_state_tx.clone();
            Box::pin(async move {
                let _ = connection_state_tx.send(state);
            })
        }));

        let (control, reliable_rx, realtime_rx, bulk_rx) = ControlState::new(
            capacity,
            config.reliable_queue_bytes,
            config.realtime_queue_bytes,
            config.bulk_queue_bytes,
        );
        let remote_control = Arc::clone(&control);
        let remote_pc = weak_callback_owner(&pc);
        pc.on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
            let remote_control = Arc::clone(&remote_control);
            let remote_pc = remote_pc.clone();
            Box::pin(async move {
                if remote_control
                    .install(channel, remote_pc.clone())
                    .await
                    .is_err()
                {
                    if let Some(remote_pc) = remote_pc.upgrade() {
                        let _ = remote_pc.close().await;
                    }
                }
            })
        }));

        let tasks = Arc::new(Mutex::new(Vec::new()));
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let completed_video_drops = Arc::new(VideoDropCounter::default());
        let closed = Arc::new(AtomicBool::new(false));
        let (h264_tx, h264_rx) = mpsc::channel(capacity);
        let h264_queue_budget = Arc::new(Semaphore::new(config.video_queue_bytes));
        let remote_tasks = Arc::clone(&tasks);
        let remote_active_tasks = Arc::clone(&active_tasks);
        let remote_completed_video_drops = Arc::clone(&completed_video_drops);
        let remote_closed = Arc::clone(&closed);
        let max_h264_access_unit_bytes = config.max_h264_access_unit_bytes;
        pc.on_track(Box::new(move |track, _receiver, _transceiver| {
            let h264_tx = h264_tx.clone();
            let h264_queue_budget = Arc::clone(&h264_queue_budget);
            let tasks = Arc::clone(&remote_tasks);
            let active_tasks = Arc::clone(&remote_active_tasks);
            let completed_video_drops = Arc::clone(&remote_completed_video_drops);
            let closed = Arc::clone(&remote_closed);
            Box::pin(async move {
                let mut tasks = tasks.lock().await;
                if closed.load(Ordering::Acquire) {
                    return;
                }
                let task_counter = Arc::clone(&active_tasks);
                let handle = spawn_tracked(&task_counter, async move {
                    let mut ingress =
                        H264RtpIngress::with_max_access_unit_bytes(max_h264_access_unit_bytes);
                    while let Ok((packet, _attributes)) = track.read_rtp().await {
                        let timestamp_us = u64::from(packet.header.timestamp) * 1_000_000 / 90_000;
                        if let Some(access_unit) = ingress.push_packet(
                            &packet.payload,
                            packet.header.marker,
                            packet.header.sequence_number,
                            timestamp_us,
                        ) {
                            let Some(byte_permit) = try_reserve_video_bytes(
                                Arc::clone(&h264_queue_budget),
                                access_unit.bytes.len(),
                            ) else {
                                completed_video_drops.record();
                                continue;
                            };
                            match h264_tx.try_send(QueuedAccessUnit {
                                access_unit,
                                _byte_permit: byte_permit,
                            }) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    completed_video_drops.record();
                                    continue;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        }
                    }
                });
                tasks.push(handle);
            })
        }));

        if config.role == PeerConnectionRole::Offerer {
            let reliable = pc
                .create_data_channel(CTRL_REL_LABEL, Some(reliable_channel_init()))
                .await
                .map_err(|error| {
                    TransportError::Message(format!("create ctrl_rel failed: {error}"))
                })?;
            control.install(reliable, weak_callback_owner(&pc)).await?;
            let realtime = pc
                .create_data_channel(CTRL_RT_LABEL, Some(realtime_channel_init()))
                .await
                .map_err(|error| {
                    TransportError::Message(format!("create ctrl_rt failed: {error}"))
                })?;
            control.install(realtime, weak_callback_owner(&pc)).await?;
            let bulk = pc
                .create_data_channel(BULK_LABEL, Some(reliable_channel_init()))
                .await
                .map_err(|error| TransportError::Message(format!("create bulk failed: {error}")))?;
            control.install(bulk, weak_callback_owner(&pc)).await?;
        }

        let h264_sender = H264RtpSender::new_with_profile_level_id(
            "screen",
            "desktop",
            config.fps,
            config.mtu,
            codec.profile.into(),
            codec.profile_level_id,
        );
        let rtp_sender = pc
            .add_track(h264_sender.track() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|error| TransportError::Message(format!("add H.264 track failed: {error}")))?;
        let rtcp_task = spawn_tracked(&active_tasks, async move {
            while rtp_sender.read_rtcp().await.is_ok() {}
        });
        tasks.lock().await.push(rtcp_task);

        Ok(Self {
            pc,
            config,
            h264_sender: Mutex::new(h264_sender),
            local_candidates: Mutex::new(candidate_rx),
            h264_rx: Mutex::new(h264_rx),
            reliable_rx: Mutex::new(reliable_rx),
            realtime_rx: Mutex::new(realtime_rx),
            bulk_rx: Mutex::new(bulk_rx),
            control,
            connection_state_rx,
            tasks,
            active_tasks,
            completed_video_drops,
            closed,
            restart: StdMutex::new(RestartState::default()),
            restart_cleanup_failures: AtomicU64::new(0),
            #[cfg(test)]
            fail_close_for_test: AtomicBool::new(false),
        })
    }

    pub async fn create_offer(&self) -> Result<SessionDescription, TransportError> {
        let (generation, route_token, route) = self.active_snapshot();
        if let Some(route) = route {
            let mut offer = route.create_offer_physical().await?;
            offer.bind_restart(
                generation,
                route_token.expect("published restart route has a token"),
            );
            return Ok(offer);
        }
        self.create_offer_physical().await
    }

    async fn create_offer_physical(&self) -> Result<SessionDescription, TransportError> {
        self.require_role(PeerConnectionRole::Offerer)?;
        let offer = self
            .pc
            .create_offer(None)
            .await
            .map_err(peer_error("create offer"))?;
        let description =
            SessionDescription::initial(SessionDescriptionType::Offer, offer.sdp.clone());
        let sdp = offer.sdp.clone();
        self.pc
            .set_local_description(offer)
            .await
            .map_err(|error| redact_sdp_error(peer_error("set local offer")(error), &sdp))?;
        Ok(description)
    }

    pub async fn accept_offer(
        &self,
        mut offer: SessionDescription,
    ) -> Result<SessionDescription, TransportError> {
        let (generation, route_token, route) = self.active_snapshot();
        require_generation(generation, offer.generation, "offer")?;
        if let Some(route) = route {
            let route_token = route_token.expect("published restart route has a token");
            require_matching_route_token(&offer.restart_route_token, &route_token, "offer")?;
            offer.clear_restart_binding();
            let mut answer = route.accept_offer_physical(offer).await?;
            answer.bind_restart(generation, route_token);
            return Ok(answer);
        }
        self.accept_offer_physical(offer).await
    }

    async fn accept_offer_physical(
        &self,
        offer: SessionDescription,
    ) -> Result<SessionDescription, TransportError> {
        self.require_role(PeerConnectionRole::Answerer)?;
        if offer.kind != SessionDescriptionType::Offer {
            return Err(TransportError::Message("expected an SDP offer".into()));
        }
        let remote_sdp = offer.sdp;
        let offer = RTCSessionDescription::offer(remote_sdp.clone())
            .map_err(|error| redact_sdp_error(peer_error("parse offer")(error), &remote_sdp))?;
        self.pc
            .set_remote_description(offer)
            .await
            .map_err(|error| {
                redact_sdp_error(peer_error("set remote offer")(error), &remote_sdp)
            })?;
        let answer = self
            .pc
            .create_answer(None)
            .await
            .map_err(peer_error("create answer"))?;
        let description =
            SessionDescription::initial(SessionDescriptionType::Answer, answer.sdp.clone());
        let local_sdp = answer.sdp.clone();
        self.pc
            .set_local_description(answer)
            .await
            .map_err(|error| redact_sdp_error(peer_error("set local answer")(error), &local_sdp))?;
        Ok(description)
    }

    pub async fn accept_answer(
        &self,
        mut answer: SessionDescription,
    ) -> Result<(), TransportError> {
        let (generation, route_token, route) = self.active_snapshot();
        require_generation(generation, answer.generation, "answer")?;
        if let Some(route) = route {
            require_matching_route_token(
                &answer.restart_route_token,
                &route_token.expect("published restart route has a token"),
                "answer",
            )?;
            answer.clear_restart_binding();
            return route.accept_answer_physical(answer).await;
        }
        self.accept_answer_physical(answer).await
    }

    async fn accept_answer_physical(
        &self,
        answer: SessionDescription,
    ) -> Result<(), TransportError> {
        self.require_role(PeerConnectionRole::Offerer)?;
        if answer.kind != SessionDescriptionType::Answer {
            return Err(TransportError::Message("expected an SDP answer".into()));
        }
        let remote_sdp = answer.sdp;
        let answer = RTCSessionDescription::answer(remote_sdp.clone())
            .map_err(|error| redact_sdp_error(peer_error("parse answer")(error), &remote_sdp))?;
        self.pc
            .set_remote_description(answer)
            .await
            .map_err(|error| redact_sdp_error(peer_error("set remote answer")(error), &remote_sdp))
    }

    pub async fn next_local_candidate(&self) -> Option<IceCandidate> {
        let (generation, route_token, route) = self.active_snapshot();
        let mut candidate = if let Some(route) = route {
            route.next_local_candidate_physical().await?
        } else {
            self.next_local_candidate_physical().await?
        };
        if let Some(route_token) = route_token {
            candidate.bind_restart(generation, route_token);
        }
        Some(candidate)
    }

    async fn next_local_candidate_physical(&self) -> Option<IceCandidate> {
        self.local_candidates.lock().await.recv().await
    }

    pub async fn add_ice_candidate(
        &self,
        mut candidate: IceCandidate,
    ) -> Result<(), TransportError> {
        let (generation, route_token, route) = self.active_snapshot();
        require_generation(generation, candidate.generation, "ICE candidate")?;
        if let Some(route) = route {
            require_matching_route_token(
                &candidate.restart_route_token,
                &route_token.expect("published restart route has a token"),
                "ICE candidate",
            )?;
            candidate.clear_restart_binding();
            return route.add_ice_candidate_physical(candidate).await;
        }
        self.add_ice_candidate_physical(candidate).await
    }

    async fn add_ice_candidate_physical(
        &self,
        candidate: IceCandidate,
    ) -> Result<(), TransportError> {
        let secrets = candidate_secret_values(&candidate);
        self.pc
            .add_ice_candidate(candidate.into())
            .await
            .map_err(peer_error_redacted("add ICE candidate", &secrets))
    }

    pub async fn wait_connected(&self) -> Result<(), TransportError> {
        if let Some(route) = self.active_route() {
            return route.wait_connected_physical().await;
        }
        self.wait_connected_physical().await
    }

    async fn wait_connected_physical(&self) -> Result<(), TransportError> {
        let mut states = self.connection_state_rx.clone();
        loop {
            let state = *states.borrow_and_update();
            match state {
                RTCPeerConnectionState::Connected => return Ok(()),
                RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Disconnected
                | RTCPeerConnectionState::Closed => {
                    return Err(TransportError::Message(format!(
                        "peer connection entered {state}"
                    )));
                }
                _ => {}
            }
            states.changed().await.map_err(|_| {
                TransportError::Message("peer connection state stream closed".into())
            })?;
        }
    }

    /// Wait until the peer connection leaves the usable connected state.
    pub async fn wait_terminated(&self) -> Result<(), TransportError> {
        if let Some(route) = self.active_route() {
            return route.wait_terminated_physical().await;
        }
        self.wait_terminated_physical().await
    }

    async fn wait_terminated_physical(&self) -> Result<(), TransportError> {
        let mut states = self.connection_state_rx.clone();
        loop {
            let state = *states.borrow_and_update();
            match state {
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => return Ok(()),
                RTCPeerConnectionState::Disconnected => {
                    tokio::select! {
                        _ = tokio::time::sleep(DISCONNECTED_GRACE_PERIOD) => return Ok(()),
                        changed = states.changed() => changed.map_err(|_| {
                            TransportError::Message("peer connection state stream closed".into())
                        })?,
                    }
                }
                _ => states.changed().await.map_err(|_| {
                    TransportError::Message("peer connection state stream closed".into())
                })?,
            }
        }
    }

    pub async fn send_h264_access_unit(
        &self,
        access_unit: &EncodedAccessUnit,
    ) -> Result<usize, TransportError> {
        if let Some(route) = self.active_route() {
            return route.send_h264_access_unit_physical(access_unit).await;
        }
        self.send_h264_access_unit_physical(access_unit).await
    }

    async fn send_h264_access_unit_physical(
        &self,
        access_unit: &EncodedAccessUnit,
    ) -> Result<usize, TransportError> {
        self.h264_sender
            .lock()
            .await
            .send_access_unit(access_unit)
            .await
    }

    pub async fn next_h264_access_unit(&self) -> Option<EncodedAccessUnit> {
        if let Some(route) = self.active_route() {
            return route.next_h264_access_unit_physical().await;
        }
        self.next_h264_access_unit_physical().await
    }

    async fn next_h264_access_unit_physical(&self) -> Option<EncodedAccessUnit> {
        self.h264_rx
            .lock()
            .await
            .recv()
            .await
            .map(QueuedAccessUnit::into_access_unit)
    }

    pub fn take_completed_video_drops(&self) -> u64 {
        if let Some(route) = self.active_route() {
            return route.completed_video_drops.take();
        }
        self.completed_video_drops.take()
    }

    pub async fn send_control(
        &self,
        lane: ControlLane,
        payload: &[u8],
    ) -> Result<usize, TransportError> {
        if let Some(route) = self.active_route() {
            return route.send_control_physical(lane, payload).await;
        }
        self.send_control_physical(lane, payload).await
    }

    async fn send_control_physical(
        &self,
        lane: ControlLane,
        payload: &[u8],
    ) -> Result<usize, TransportError> {
        let channel = self.wait_for_channel(lane).await?;
        if lane == ControlLane::Bulk {
            // Keep bulk from continuously winning the SCTP association's send loop. This tiny
            // pacing point lets the mux queue expose pressure and preserves an opportunity for
            // interactive control streams to run between large messages.
            tokio::time::sleep(BULK_SEND_PACING_INTERVAL).await;
            while channel.buffered_amount().await >= BULK_BUFFER_HIGH_WATERMARK {
                if self.closed.load(Ordering::Acquire) {
                    return Err(TransportError::Message(
                        "peer connection closed while waiting for bulk capacity".into(),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        channel
            .send(&Bytes::copy_from_slice(payload))
            .await
            .map_err(peer_error("send control message"))
    }

    pub async fn next_control(&self, lane: ControlLane) -> Option<Bytes> {
        if let Some(route) = self.active_route() {
            return route.next_control_physical(lane).await;
        }
        self.next_control_physical(lane).await
    }

    async fn next_control_physical(&self, lane: ControlLane) -> Option<Bytes> {
        match lane {
            ControlLane::Reliable => self.reliable_rx.lock().await.recv().await,
            ControlLane::Realtime => self.realtime_rx.lock().await.recv().await,
            ControlLane::Bulk => self.bulk_rx.lock().await.recv().await,
        }
        .map(QueuedBytes::into_bytes)
    }

    pub async fn control_channels(&self) -> ControlChannels {
        if let Some(route) = self.active_route() {
            return route.control_channels_physical().await;
        }
        self.control_channels_physical().await
    }

    async fn control_channels_physical(&self) -> ControlChannels {
        let reliable = self.control.channel(ControlLane::Reliable).await;
        let realtime = self.control.channel(ControlLane::Realtime).await;
        let bulk = self.control.channel(ControlLane::Bulk).await;
        ControlChannels {
            reliable: reliable.as_deref().map(channel_info).unwrap_or_else(|| {
                crate::ControlChannelInfo {
                    label: CTRL_REL_LABEL.to_owned(),
                    ordered: true,
                    max_retransmits: None,
                }
            }),
            realtime: realtime.as_deref().map(channel_info).unwrap_or_else(|| {
                crate::ControlChannelInfo {
                    label: CTRL_RT_LABEL.to_owned(),
                    ordered: false,
                    max_retransmits: Some(0),
                }
            }),
            bulk: bulk
                .as_deref()
                .map(channel_info)
                .unwrap_or_else(|| crate::ControlChannelInfo {
                    label: BULK_LABEL.to_owned(),
                    ordered: true,
                    max_retransmits: None,
                }),
        }
    }

    pub async fn selected_candidate_pair_stats(&self) -> Option<SelectedCandidatePairStats> {
        if let Some(route) = self.active_route() {
            return route.selected_candidate_pair_stats_physical().await;
        }
        self.selected_candidate_pair_stats_physical().await
    }

    async fn selected_candidate_pair_stats_physical(&self) -> Option<SelectedCandidatePairStats> {
        selected_candidate_pair(self.pc.get_stats().await)
    }

    pub fn active_task_count(&self) -> usize {
        if let Some(route) = self.active_route() {
            return route.active_tasks.load(Ordering::Acquire);
        }
        self.active_tasks.load(Ordering::Acquire)
    }

    /// Create a replacement offer with a strictly newer authenticated generation.
    ///
    /// webrtc-rs 0.12 cannot safely replace ICE servers in-place, so this constructs an
    /// independent peer and leaves the active route untouched until [`Self::commit_restart`].
    pub async fn create_restart_offer(
        &self,
        generation: u64,
        ice_servers: Vec<IceServerConfig>,
    ) -> Result<SessionDescription, TransportError> {
        self.require_active_role(PeerConnectionRole::Offerer)?;
        validate_turn_servers(&ice_servers)?;
        let secrets = secret_values(&ice_servers);
        let route_token = RestartRouteToken::generate()?;
        let (config, loser) = self.begin_restart(generation, route_token.clone())?;
        let config = restart_peer_config(config, ice_servers);
        close_loser(loser).await;

        let pending = match Self::new(config).await {
            Ok(peer) => Arc::new(peer),
            Err(error) => {
                self.abort_build(generation, &route_token);
                return Err(redact_transport_error(error, &secrets));
            }
        };
        let mut offer = match pending.create_offer_physical().await {
            Ok(offer) => offer,
            Err(error) => {
                self.abort_build(generation, &route_token);
                close_route_best_effort(&pending).await;
                return Err(redact_transport_error(error, &secrets));
            }
        };
        offer.bind_restart(generation, route_token.clone());
        if !self.finish_build(
            generation,
            &route_token,
            Arc::clone(&pending),
            offer.clone(),
        ) {
            close_route_best_effort(&pending).await;
            return Err(stale_generation_error(generation, "restart offer"));
        }
        Ok(offer)
    }

    /// Accept a replacement offer on a separate answerer peer.
    pub async fn accept_restart_offer(
        &self,
        generation: u64,
        ice_servers: Vec<IceServerConfig>,
        mut offer: SessionDescription,
    ) -> Result<SessionDescription, TransportError> {
        self.require_active_role(PeerConnectionRole::Answerer)?;
        require_generation(generation, offer.generation, "restart offer")?;
        let route_token = require_route_token(&offer.restart_route_token, "restart offer")?.clone();
        validate_turn_servers(&ice_servers)?;
        if let Some(answer) = self.existing_restart_description(generation, &route_token)? {
            return Ok(answer);
        }
        let secrets = secret_values(&ice_servers);
        let (config, loser) = self.begin_restart(generation, route_token.clone())?;
        let config = restart_peer_config(config, ice_servers);
        close_loser(loser).await;

        let pending = match Self::new(config).await {
            Ok(peer) => Arc::new(peer),
            Err(error) => {
                self.abort_build(generation, &route_token);
                return Err(redact_transport_error(error, &secrets));
            }
        };
        offer.clear_restart_binding();
        let mut answer = match pending.accept_offer_physical(offer).await {
            Ok(answer) => answer,
            Err(error) => {
                self.abort_build(generation, &route_token);
                close_route_best_effort(&pending).await;
                return Err(redact_transport_error(error, &secrets));
            }
        };
        answer.bind_restart(generation, route_token.clone());
        if !self.finish_build(
            generation,
            &route_token,
            Arc::clone(&pending),
            answer.clone(),
        ) {
            close_route_best_effort(&pending).await;
            return Err(stale_generation_error(generation, "restart offer"));
        }
        Ok(answer)
    }

    pub async fn accept_restart_answer(
        &self,
        generation: u64,
        mut answer: SessionDescription,
    ) -> Result<(), TransportError> {
        require_generation(generation, answer.generation, "restart answer")?;
        let route_token = require_route_token(&answer.restart_route_token, "restart answer")?;
        let (_, _, peer) = self.ready_restart_for_route(generation, route_token)?;
        answer.clear_restart_binding();
        peer.accept_answer_physical(answer).await
    }

    pub async fn next_restart_candidate(
        &self,
        generation: u64,
    ) -> Result<IceCandidate, TransportError> {
        let (route_id, route_token, peer) = self.ready_restart(generation)?;
        let Some(mut candidate) = peer.next_local_candidate_physical().await else {
            return Err(TransportError::Message(format!(
                "restart candidate stream closed for generation {generation}"
            )));
        };
        self.require_ready_route(generation, route_id)?;
        candidate.bind_restart(generation, route_token);
        Ok(candidate)
    }

    pub async fn add_restart_candidate(
        &self,
        generation: u64,
        mut candidate: IceCandidate,
    ) -> Result<(), TransportError> {
        require_generation(generation, candidate.generation, "restart ICE candidate")?;
        let route_token =
            require_route_token(&candidate.restart_route_token, "restart ICE candidate")?;
        let (_, _, peer) = self.ready_restart_for_route(generation, route_token)?;
        let secrets = candidate_secret_values(&candidate);
        candidate.clear_restart_binding();
        peer.add_ice_candidate_physical(candidate)
            .await
            .map_err(|error| redact_transport_error(error, &secrets))
    }

    /// Exercise real control and H.264 traffic on the pending route before publication.
    /// Both peers must call this concurrently after exchanging candidates.
    pub async fn validate_pending_restart(
        &self,
        generation: u64,
    ) -> Result<RestartRouteEvidence, TransportError> {
        let (route_id, _, peer) = self.ready_restart(generation)?;
        tokio::time::timeout(RESTART_VALIDATION_TIMEOUT, peer.wait_connected_physical())
            .await
            .map_err(|_| {
                TransportError::Message(format!(
                    "restart route connection timed out for generation {generation}"
                ))
            })??;

        let pair = peer
            .selected_candidate_pair_stats_physical()
            .await
            .ok_or_else(|| {
                TransportError::Message(format!(
                    "restart route has no selected candidate pair for generation {generation}"
                ))
            })?;
        validate_selected_pair(&pair, peer.config.ice_transport_policy)?;

        let mut control_probe = RESTART_PROBE_PREFIX.to_vec();
        control_probe.extend_from_slice(generation.to_string().as_bytes());
        peer.send_control_physical(ControlLane::Reliable, &control_probe)
            .await?;
        let media_probe = restart_media_probe(generation);
        peer.send_h264_access_unit_physical(&media_probe).await?;

        let received_control = tokio::time::timeout(
            RESTART_VALIDATION_TIMEOUT,
            peer.next_control_physical(ControlLane::Reliable),
        )
        .await
        .map_err(|_| {
            TransportError::Message(format!(
                "restart control probe timed out for generation {generation}"
            ))
        })?
        .ok_or_else(|| TransportError::Message("restart control channel closed".into()))?;
        if received_control.as_ref() != control_probe {
            return Err(TransportError::Message(
                "restart control probe payload mismatch".into(),
            ));
        }

        let received_media = tokio::time::timeout(
            RESTART_VALIDATION_TIMEOUT,
            peer.next_h264_access_unit_physical(),
        )
        .await
        .map_err(|_| {
            TransportError::Message(format!(
                "restart media probe timed out for generation {generation}"
            ))
        })?
        .ok_or_else(|| TransportError::Message("restart media stream closed".into()))?;
        if received_media.bytes != media_probe.bytes {
            return Err(TransportError::Message(
                "restart media probe payload mismatch".into(),
            ));
        }

        self.mark_restart_validated(generation, route_id)?;
        Ok(RestartRouteEvidence {
            generation,
            route_id,
            selected_pair: pair,
            control_round_trip: true,
            media_round_trip: true,
        })
    }

    /// Atomically publish a validated pending peer and then close the losing active route.
    pub async fn commit_restart(
        &self,
        generation: u64,
        evidence: RestartRouteEvidence,
    ) -> Result<(), TransportError> {
        let (replacement, previous) = {
            let mut state = self.restart_state();
            let pending = state
                .pending
                .take()
                .ok_or_else(|| stale_generation_error(generation, "restart commit"))?;
            let PendingRestart::Ready {
                generation: pending_generation,
                route_token,
                route_id,
                peer,
                local_description,
                validated,
            } = pending
            else {
                state.pending = Some(pending);
                return Err(TransportError::Message(format!(
                    "restart generation {generation} is still being built"
                )));
            };
            if pending_generation != generation
                || evidence.generation != generation
                || evidence.route_id != route_id
                || !validated
                || !evidence.control_round_trip
                || !evidence.media_round_trip
            {
                state.pending = Some(PendingRestart::Ready {
                    generation: pending_generation,
                    route_token,
                    route_id,
                    peer,
                    local_description,
                    validated,
                });
                return Err(stale_generation_error(generation, "restart evidence"));
            }
            let previous = state.active_replacement.replace(Arc::clone(&peer));
            state.active_generation = generation;
            state.active_route_token = Some(route_token);
            (peer, previous)
        };

        let cleanup_result = if let Some(previous) = previous {
            let result = previous.close_physical().await;
            if result.is_err() {
                previous.force_terminate_physical_now();
            }
            result
        } else {
            let result = self.close_physical().await;
            if result.is_err() {
                self.force_terminate_physical_now();
            }
            result
        };
        if cleanup_result.is_err() {
            self.restart_cleanup_failures.fetch_add(1, Ordering::AcqRel);
        }
        debug_assert_eq!(replacement.config.role, self.config.role);
        Ok(())
    }

    pub async fn current_generation(&self) -> u64 {
        self.current_generation_now()
    }

    pub async fn pending_restart_generation(&self) -> Option<u64> {
        self.restart_state()
            .pending
            .as_ref()
            .map(PendingRestart::generation)
    }

    /// Number of old-route close failures recovered after a replacement was published.
    pub fn restart_cleanup_failure_count(&self) -> u64 {
        self.restart_cleanup_failures.load(Ordering::Acquire)
    }

    /// Begin idempotent transport termination without requiring an async caller.
    pub fn terminate_now(&self) {
        if let Ok(state) = self.restart.lock() {
            if let Some(active) = &state.active_replacement {
                active.terminate_physical_now();
            }
            if let Some(PendingRestart::Ready { peer, .. }) = &state.pending {
                peer.terminate_physical_now();
            }
        }
        self.terminate_physical_now();
    }

    fn terminate_physical_now(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.force_terminate_physical_now();
    }

    fn force_terminate_physical_now(&self) {
        self.completed_video_drops.seal();
        if let Ok(mut tasks) = self.tasks.try_lock() {
            for task in tasks.iter() {
                task.abort();
            }
            tasks.clear();
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let tasks = Arc::clone(&self.tasks);
            runtime.spawn(async move {
                let mut tasks = tasks.lock().await;
                for task in tasks.iter() {
                    task.abort();
                }
                tasks.clear();
            });
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let pc = Arc::clone(&self.pc);
            runtime.spawn(async move {
                let _ = pc.close().await;
            });
        }
    }

    pub async fn close(&self) -> Result<(), TransportError> {
        let (active, pending) = {
            let mut state = self.restart_state();
            let active = state.active_replacement.take();
            let pending = match state.pending.take() {
                Some(PendingRestart::Ready { peer, .. }) => Some(peer),
                _ => None,
            };
            (active, pending)
        };
        if let Some(pending) = pending {
            pending.close_physical().await?;
        }
        if let Some(active) = active {
            active.close_physical().await?;
        }
        self.close_physical().await
    }

    async fn close_physical(&self) -> Result<(), TransportError> {
        self.completed_video_drops.seal();
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut tasks = self.tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        for task in tasks.drain(..) {
            let _ = task.await;
        }
        drop(tasks);
        if let Some(channel) = self.control.channel(ControlLane::Reliable).await {
            let _ = channel.close().await;
        }
        if let Some(channel) = self.control.channel(ControlLane::Realtime).await {
            let _ = channel.close().await;
        }
        if let Some(channel) = self.control.channel(ControlLane::Bulk).await {
            let _ = channel.close().await;
        }
        #[cfg(test)]
        if self.fail_close_for_test.load(Ordering::Acquire) {
            return Err(TransportError::Message(
                "injected old-route close failure".into(),
            ));
        }
        self.pc
            .close()
            .await
            .map_err(peer_error("close peer connection"))
    }

    fn require_role(&self, expected: PeerConnectionRole) -> Result<(), TransportError> {
        if self.config.role == expected {
            Ok(())
        } else {
            Err(TransportError::Message(format!(
                "operation requires {expected:?} role"
            )))
        }
    }

    fn require_active_role(&self, expected: PeerConnectionRole) -> Result<(), TransportError> {
        if let Some(route) = self.active_route() {
            route.require_role(expected)
        } else {
            self.require_role(expected)
        }
    }

    fn current_generation_now(&self) -> u64 {
        self.active_snapshot().0
    }

    fn active_route(&self) -> Option<Arc<WebRtcPeerConnection>> {
        self.active_snapshot().2
    }

    fn active_snapshot(
        &self,
    ) -> (
        u64,
        Option<RestartRouteToken>,
        Option<Arc<WebRtcPeerConnection>>,
    ) {
        self.restart_state().active_snapshot()
    }

    fn restart_state(&self) -> std::sync::MutexGuard<'_, RestartState> {
        self.restart.lock().expect("restart state lock poisoned")
    }

    fn begin_restart(
        &self,
        generation: u64,
        route_token: RestartRouteToken,
    ) -> Result<(PeerConnectionConfig, Option<Arc<WebRtcPeerConnection>>), TransportError> {
        if generation == 0 {
            return Err(TransportError::Message(
                "restart generation must be greater than zero".into(),
            ));
        }
        let mut state = self.restart_state();
        if generation <= state.highest_seen_generation {
            return Err(stale_generation_error(generation, "restart request"));
        }
        state.highest_seen_generation = generation;
        let config = state
            .active_replacement
            .as_ref()
            .map(|peer| peer.config.clone())
            .unwrap_or_else(|| self.config.clone());
        let loser = match state.pending.take() {
            Some(PendingRestart::Ready { peer, .. }) => Some(peer),
            _ => None,
        };
        state.pending = Some(PendingRestart::Building {
            generation,
            route_token,
        });
        Ok((config, loser))
    }

    fn finish_build(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
        peer: Arc<WebRtcPeerConnection>,
        local_description: SessionDescription,
    ) -> bool {
        let mut state = self.restart_state();
        let matches_pending = matches!(
            state.pending.as_ref(),
            Some(PendingRestart::Building {
                generation: pending,
                route_token: pending_token,
            }) if *pending == generation && pending_token == route_token
        );
        if matches_pending && generation > state.active_generation {
            state.pending = Some(PendingRestart::Ready {
                generation,
                route_token: route_token.clone(),
                route_id: NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed),
                peer,
                local_description,
                validated: false,
            });
            true
        } else {
            false
        }
    }

    fn abort_build(&self, generation: u64, route_token: &RestartRouteToken) {
        let mut state = self.restart_state();
        if matches!(
            state.pending.as_ref(),
            Some(PendingRestart::Building {
                generation: pending,
                route_token: pending_token,
            }) if *pending == generation && pending_token == route_token
        ) {
            state.pending = None;
        }
    }

    fn existing_restart_description(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
    ) -> Result<Option<SessionDescription>, TransportError> {
        let state = self.restart_state();
        if generation < state.highest_seen_generation {
            return Err(stale_generation_error(generation, "restart offer"));
        }
        if generation > state.highest_seen_generation {
            return Ok(None);
        }
        match state.pending.as_ref() {
            Some(PendingRestart::Ready {
                generation: pending_generation,
                route_token: pending_token,
                local_description,
                ..
            }) if *pending_generation == generation && pending_token == route_token => {
                Ok(Some(local_description.clone()))
            }
            Some(PendingRestart::Building {
                generation: pending_generation,
                route_token: pending_token,
            }) if *pending_generation == generation && pending_token == route_token => {
                Err(TransportError::Message(format!(
                    "restart generation {generation} is still being built"
                )))
            }
            _ => Err(stale_generation_error(generation, "restart route")),
        }
    }

    fn ready_restart(
        &self,
        generation: u64,
    ) -> Result<(u64, RestartRouteToken, Arc<WebRtcPeerConnection>), TransportError> {
        let state = self.restart_state();
        match state.pending.as_ref() {
            Some(pending) if pending.generation() == generation => {
                pending.ready_peer().ok_or_else(|| {
                    TransportError::Message(format!(
                        "restart generation {generation} is still being built"
                    ))
                })
            }
            _ => Err(stale_generation_error(generation, "restart signaling")),
        }
    }

    fn ready_restart_for_route(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
    ) -> Result<(u64, RestartRouteToken, Arc<WebRtcPeerConnection>), TransportError> {
        let state = self.restart_state();
        match state.pending.as_ref() {
            Some(pending)
                if pending.generation() == generation && pending.route_token() == route_token =>
            {
                pending.ready_peer().ok_or_else(|| {
                    TransportError::Message(format!(
                        "restart generation {generation} is still being built"
                    ))
                })
            }
            _ => Err(stale_generation_error(generation, "restart route")),
        }
    }

    fn require_ready_route(&self, generation: u64, route_id: u64) -> Result<(), TransportError> {
        let state = self.restart_state();
        match state.pending.as_ref() {
            Some(PendingRestart::Ready {
                generation: pending_generation,
                route_id: pending_route_id,
                ..
            }) if *pending_generation == generation && *pending_route_id == route_id => Ok(()),
            _ => Err(stale_generation_error(generation, "restart route")),
        }
    }

    fn mark_restart_validated(&self, generation: u64, route_id: u64) -> Result<(), TransportError> {
        let mut state = self.restart_state();
        match state.pending.as_mut() {
            Some(PendingRestart::Ready {
                generation: pending_generation,
                route_id: pending_route_id,
                validated,
                ..
            }) if *pending_generation == generation && *pending_route_id == route_id => {
                *validated = true;
                Ok(())
            }
            _ => Err(stale_generation_error(generation, "restart validation")),
        }
    }

    async fn wait_for_channel(
        &self,
        lane: ControlLane,
    ) -> Result<Arc<RTCDataChannel>, TransportError> {
        let deadline = tokio::time::Instant::now() + CHANNEL_OPEN_TIMEOUT;
        loop {
            if let Some(channel) = self.control.channel(lane).await {
                if channel.ready_state() == RTCDataChannelState::Open {
                    return Ok(channel);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(TransportError::Message(format!(
                    "control channel {lane:?} did not open"
                )));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn close_loser(loser: Option<Arc<WebRtcPeerConnection>>) {
    if let Some(loser) = loser {
        close_route_best_effort(&loser).await;
    }
}

async fn close_route_best_effort(peer: &WebRtcPeerConnection) {
    if peer.close_physical().await.is_err() {
        peer.force_terminate_physical_now();
    }
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn invalid_route_token() -> TransportError {
    TransportError::Message("invalid restart route token encoding".into())
}

fn parse_wire_route(
    generation: u64,
    token: Option<&str>,
) -> Result<Option<RestartRouteToken>, TransportError> {
    match (generation, token) {
        (0, None) => Ok(None),
        (0, Some(_)) => Err(TransportError::Message(
            "initial signaling must not carry a restart route token".into(),
        )),
        (_, Some(token)) => RestartRouteToken::from_wire(token).map(Some),
        (_, None) => Err(TransportError::Message(
            "restart signaling requires an opaque route token".into(),
        )),
    }
}

fn require_generation(
    expected: u64,
    actual: u64,
    context: &'static str,
) -> Result<(), TransportError> {
    if expected == actual {
        Ok(())
    } else {
        Err(TransportError::Message(format!(
            "stale {context} generation {actual}; expected {expected}"
        )))
    }
}

fn require_route_token<'a>(
    token: &'a Option<RestartRouteToken>,
    context: &'static str,
) -> Result<&'a RestartRouteToken, TransportError> {
    token.as_ref().ok_or_else(|| {
        TransportError::Message(format!(
            "{context} requires an authenticated restart route token"
        ))
    })
}

fn require_matching_route_token(
    actual: &Option<RestartRouteToken>,
    expected: &RestartRouteToken,
    context: &'static str,
) -> Result<(), TransportError> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(TransportError::Message(format!(
            "stale or losing {context} restart route"
        ))),
    }
}

fn stale_generation_error(generation: u64, context: &'static str) -> TransportError {
    TransportError::Message(format!("stale or losing {context} generation {generation}"))
}

fn restart_peer_config(
    mut config: PeerConnectionConfig,
    ice_servers: Vec<IceServerConfig>,
) -> PeerConnectionConfig {
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers = ice_servers;
    config
}

fn validate_turn_servers(ice_servers: &[IceServerConfig]) -> Result<(), TransportError> {
    if ice_servers.is_empty() {
        return Err(TransportError::Message(
            "relay restart requires at least one authenticated TURN server".into(),
        ));
    }
    for server in ice_servers {
        if server.urls.is_empty()
            || server.username.trim().is_empty()
            || server.credential.trim().is_empty()
        {
            return Err(TransportError::Message(
                "relay restart requires authenticated TURN server URLs".into(),
            ));
        }
        if server.urls.iter().any(|url| {
            let normalized = url.trim().to_ascii_lowercase();
            let endpoint = normalized
                .strip_prefix("turn:")
                .or_else(|| normalized.strip_prefix("turns:"));
            endpoint.is_none_or(|endpoint| {
                endpoint.is_empty()
                    || endpoint.starts_with('?')
                    || endpoint.chars().any(char::is_whitespace)
            })
        }) {
            return Err(TransportError::Message(
                "relay restart accepts only trusted turn: or turns: URLs".into(),
            ));
        }
    }
    Ok(())
}

fn secret_values(ice_servers: &[IceServerConfig]) -> Vec<String> {
    ice_servers
        .iter()
        .flat_map(|server| {
            std::iter::once(server.username.clone())
                .chain(std::iter::once(server.credential.clone()))
                .chain(server.urls.iter().flat_map(|url| {
                    std::iter::once(url.clone()).chain(
                        url.split(['/', '?', '#', '&', '=', '@', ':'])
                            .filter(|part| !part.is_empty())
                            .map(str::to_owned),
                    )
                }))
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn candidate_secret_values(candidate: &IceCandidate) -> Vec<String> {
    let mut secrets = vec![candidate.candidate.clone()];
    if let Some(username_fragment) = &candidate.username_fragment {
        secrets.push(username_fragment.clone());
    }
    let fields = candidate
        .candidate
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    for pair in fields.windows(2) {
        if pair[0].eq_ignore_ascii_case("ufrag") && !pair[1].is_empty() {
            secrets.push(pair[1].to_owned());
        }
    }
    secrets
}

fn redact_transport_error(error: TransportError, secrets: &[String]) -> TransportError {
    let mut message = error.to_string();
    for secret in secrets {
        message = message.replace(secret, "[REDACTED]");
    }
    TransportError::Message(message)
}

fn redact_sdp_error(error: TransportError, sdp: &str) -> TransportError {
    let secrets = sdp
        .lines()
        .filter_map(|line| {
            line.strip_prefix("a=ice-ufrag:")
                .or_else(|| line.strip_prefix("a=ice-pwd:"))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    redact_transport_error(error, &secrets)
}

fn validate_selected_pair(
    pair: &SelectedCandidatePairStats,
    _policy: IceTransportPolicy,
) -> Result<(), TransportError> {
    if !pair.nominated
        || pair.local_candidate_kind == crate::CandidateKind::Unknown
        || pair.remote_candidate_kind == crate::CandidateKind::Unknown
    {
        return Err(TransportError::Message(
            "restart route lacks a nominated candidate pair with known candidate kinds".into(),
        ));
    }
    if pair.local_candidate_kind != crate::CandidateKind::Relay
        || pair.remote_candidate_kind != crate::CandidateKind::Relay
    {
        return Err(TransportError::Message(
            "relay-only restart did not select a relay/relay candidate pair".into(),
        ));
    }
    Ok(())
}

fn restart_media_probe(generation: u64) -> EncodedAccessUnit {
    EncodedAccessUnit {
        codec: VideoCodec::H264,
        timestamp_us: generation.saturating_mul(1_000),
        is_keyframe: true,
        bytes: vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x21],
    }
}

fn try_reserve_video_bytes(budget: Arc<Semaphore>, bytes: usize) -> Option<OwnedSemaphorePermit> {
    u32::try_from(bytes)
        .ok()
        .and_then(|bytes| budget.try_acquire_many_owned(bytes).ok())
}

fn spawn_tracked<F>(counter: &Arc<AtomicUsize>, future: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    counter.fetch_add(1, Ordering::AcqRel);
    let counter = Arc::clone(counter);
    tokio::spawn(async move {
        struct TaskGuard(Arc<AtomicUsize>);
        impl Drop for TaskGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _guard = TaskGuard(counter);
        future.await;
    })
}

fn peer_error(context: &'static str) -> impl FnOnce(webrtc::Error) -> TransportError {
    move |error| TransportError::Message(format!("{context} failed: {error}"))
}

fn peer_error_redacted<'a>(
    context: &'static str,
    secrets: &'a [String],
) -> impl FnOnce(webrtc::Error) -> TransportError + 'a {
    move |error| redact_transport_error(peer_error(context)(error), secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    #[test]
    fn completed_video_budget_is_bounded_by_retained_bytes() {
        let budget = Arc::new(Semaphore::new(8));
        let retained = try_reserve_video_bytes(Arc::clone(&budget), 6)
            .expect("reserve bytes for a completed access unit");

        assert!(try_reserve_video_bytes(Arc::clone(&budget), 3).is_none());
        drop(retained);
        assert!(try_reserve_video_bytes(budget, 8).is_some());
    }

    #[test]
    fn completed_video_drop_counter_drains_atomically() {
        let drops = VideoDropCounter::default();
        drops.record();
        drops.record();

        assert_eq!(drops.take(), 2);
        assert_eq!(drops.take(), 0);
    }

    #[test]
    fn completed_video_drop_counter_rejects_increments_after_seal() {
        let drops = VideoDropCounter::default();
        drops.record();
        drops.seal();
        drops.record();

        assert_eq!(drops.take(), 1);
    }

    #[test]
    fn transport_error_redaction_removes_all_credential_values() {
        let error = TransportError::Message(
            "TURN setup failed for temporary-user using temporary-password".into(),
        );
        let redacted = redact_transport_error(
            error,
            &["temporary-user".into(), "temporary-password".into()],
        );
        let output = redacted.to_string();
        assert!(!output.contains("temporary-user"));
        assert!(!output.contains("temporary-password"));
        assert_eq!(output.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn sdp_error_redaction_removes_ice_credentials() {
        let sdp = "v=0\r\na=ice-ufrag:temporary-user\r\na=ice-pwd:temporary-password\r\n";
        let error =
            TransportError::Message("invalid temporary-user credential temporary-password".into());

        let output = redact_sdp_error(error, sdp).to_string();

        assert!(!output.contains("temporary-user"));
        assert!(!output.contains("temporary-password"));
        assert_eq!(output.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn candidate_error_redaction_removes_raw_candidate_and_ufrag_extension() {
        let candidate = IceCandidate::from_wire(
            "candidate:1 1 udp 1 127.0.0.1 9 typ relay ufrag extension-secret".into(),
            Some("0".into()),
            Some(0),
            Some("username-secret".into()),
            1,
            Some(&"a".repeat(64)),
        )
        .expect("candidate");
        let error = TransportError::Message(format!(
            "bad {} / extension-secret / username-secret",
            candidate.candidate
        ));

        let output =
            redact_transport_error(error, &candidate_secret_values(&candidate)).to_string();

        assert!(!output.contains("candidate:1"));
        assert!(!output.contains("extension-secret"));
        assert!(!output.contains("username-secret"));
    }

    #[test]
    fn turn_url_error_redaction_removes_path_query_and_fragment_values() {
        let server = IceServerConfig::new(
            vec!["turn:relay.example.test/private-secret?key=query-secret#fragment-secret".into()],
            "temporary-user".into(),
            "temporary-password".into(),
        );
        let secrets = secret_values(&[server]);
        let error = TransportError::Message(
            "failed private-secret query-secret fragment-secret temporary-password".into(),
        );

        let output = redact_transport_error(error, &secrets).to_string();

        assert!(!output.contains("private-secret"));
        assert!(!output.contains("query-secret"));
        assert!(!output.contains("fragment-secret"));
        assert!(!output.contains("temporary-password"));
    }

    #[test]
    fn restart_with_turn_servers_forces_relay_only_policy() {
        let active = PeerConnectionConfig::default();
        let servers = vec![IceServerConfig::new(
            vec!["turn:relay.example.test:3478".into()],
            "user".into(),
            "credential".into(),
        )];

        let restart = restart_peer_config(active, servers.clone());

        assert_eq!(restart.ice_servers, servers);
        assert_eq!(restart.ice_transport_policy, IceTransportPolicy::Relay);
    }

    #[test]
    fn host_srflx_and_prflx_pairs_cannot_validate_a_restart() {
        for kind in [
            crate::CandidateKind::Host,
            crate::CandidateKind::ServerReflexive,
            crate::CandidateKind::PeerReflexive,
        ] {
            let pair = SelectedCandidatePairStats {
                local_candidate_id: "local".into(),
                remote_candidate_id: "remote".into(),
                local_candidate_kind: crate::CandidateKind::Relay,
                remote_candidate_kind: kind,
                nominated: true,
                packets_sent: 1,
                packets_received: 1,
                bytes_sent: 1,
                bytes_received: 1,
                current_round_trip_time: 0.01,
            };
            assert!(validate_selected_pair(&pair, IceTransportPolicy::All).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_host_loopback_pair_is_rejected_as_restart_evidence() {
        fn config(role: PeerConnectionRole) -> PeerConnectionConfig {
            PeerConnectionConfig {
                role,
                include_loopback_candidates: true,
                ice_transport_policy: IceTransportPolicy::All,
                ..PeerConnectionConfig::default()
            }
        }

        let root_offerer = WebRtcPeerConnection::new(config(PeerConnectionRole::Offerer))
            .await
            .expect("root offerer");
        let root_answerer = WebRtcPeerConnection::new(config(PeerConnectionRole::Answerer))
            .await
            .expect("root answerer");
        let pending_offerer = Arc::new(
            WebRtcPeerConnection::new(config(PeerConnectionRole::Offerer))
                .await
                .expect("pending offerer"),
        );
        let pending_answerer = Arc::new(
            WebRtcPeerConnection::new(config(PeerConnectionRole::Answerer))
                .await
                .expect("pending answerer"),
        );
        let offer = pending_offerer
            .create_offer_physical()
            .await
            .expect("host offer");
        let answer = pending_answerer
            .accept_offer_physical(offer.clone())
            .await
            .expect("host answer");
        pending_offerer
            .accept_answer_physical(answer.clone())
            .await
            .expect("host answer acceptance");
        let exchange_offer = async {
            let candidate = pending_offerer
                .next_local_candidate_physical()
                .await
                .expect("offerer host candidate");
            pending_answerer
                .add_ice_candidate_physical(candidate)
                .await
                .expect("offerer host candidate acceptance");
        };
        let exchange_answer = async {
            let candidate = pending_answerer
                .next_local_candidate_physical()
                .await
                .expect("answerer host candidate");
            pending_offerer
                .add_ice_candidate_physical(candidate)
                .await
                .expect("answerer host candidate acceptance");
        };
        tokio::join!(exchange_offer, exchange_answer);
        let (offerer_connected, answerer_connected) = tokio::join!(
            pending_offerer.wait_connected_physical(),
            pending_answerer.wait_connected_physical()
        );
        offerer_connected.expect("offerer host connected");
        answerer_connected.expect("answerer host connected");

        let route_token = RestartRouteToken::generate().expect("route token");
        let mut bound_offer = offer;
        bound_offer.bind_restart(1, route_token.clone());
        let mut bound_answer = answer;
        bound_answer.bind_restart(1, route_token.clone());
        let offer_route_id = NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed);
        let answer_route_id = NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed);
        root_offerer.restart_state().pending = Some(PendingRestart::Ready {
            generation: 1,
            route_token: route_token.clone(),
            route_id: offer_route_id,
            peer: Arc::clone(&pending_offerer),
            local_description: bound_offer,
            validated: false,
        });
        root_answerer.restart_state().pending = Some(PendingRestart::Ready {
            generation: 1,
            route_token,
            route_id: answer_route_id,
            peer: Arc::clone(&pending_answerer),
            local_description: bound_answer,
            validated: false,
        });

        for error in [
            root_offerer
                .validate_pending_restart(1)
                .await
                .expect_err("offerer host pair is not relay evidence"),
            root_answerer
                .validate_pending_restart(1)
                .await
                .expect_err("answerer host pair is not relay evidence"),
        ] {
            assert!(error.to_string().contains("relay/relay"));
        }

        // The remaining assertions exercise only the private publication harness. Production
        // callers cannot construct evidence or mark a route validated, and the checks above
        // prove this host pair cannot produce evidence through validate_pending_restart.
        for root in [&root_offerer, &root_answerer] {
            let mut state = root.restart_state();
            let Some(PendingRestart::Ready { validated, .. }) = state.pending.as_mut() else {
                panic!("private pending route")
            };
            *validated = true;
        }
        let state_evidence = |route_id| RestartRouteEvidence {
            generation: 1,
            route_id,
            selected_pair: SelectedCandidatePairStats {
                local_candidate_id: "private-state-harness-local".into(),
                remote_candidate_id: "private-state-harness-remote".into(),
                local_candidate_kind: crate::CandidateKind::Relay,
                remote_candidate_kind: crate::CandidateKind::Relay,
                nominated: true,
                packets_sent: 1,
                packets_received: 1,
                bytes_sent: 1,
                bytes_received: 1,
                current_round_trip_time: 0.01,
            },
            control_round_trip: true,
            media_round_trip: true,
        };
        root_offerer
            .commit_restart(1, state_evidence(offer_route_id))
            .await
            .expect("private offerer publication");
        root_answerer
            .commit_restart(1, state_evidence(answer_route_id))
            .await
            .expect("private answerer publication");
        root_offerer
            .send_control(ControlLane::Reliable, b"private-state-harness-control")
            .await
            .expect("control through published peer");
        let control = tokio::time::timeout(
            Duration::from_secs(5),
            root_answerer.next_control(ControlLane::Reliable),
        )
        .await
        .expect("control receive timeout")
        .expect("control through published peer");
        assert_eq!(control.as_ref(), b"private-state-harness-control");
        let media = restart_media_probe(1);
        root_offerer
            .send_h264_access_unit(&media)
            .await
            .expect("media through published peer");
        let received = tokio::time::timeout(
            Duration::from_secs(5),
            root_answerer.next_h264_access_unit(),
        )
        .await
        .expect("media receive timeout")
        .expect("media through published peer");
        assert_eq!(received.bytes, media.bytes);
        root_offerer.close().await.expect("close root offerer");
        root_answerer.close().await.expect("close root answerer");
    }

    #[tokio::test]
    async fn active_snapshot_keeps_generation_and_peer_from_one_state_read() {
        let peer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("peer"),
        );
        let state = RestartState {
            active_generation: 9,
            highest_seen_generation: 9,
            active_route_token: Some(RestartRouteToken::generate().expect("route token")),
            active_replacement: Some(Arc::clone(&peer)),
            pending: None,
        };

        let (generation, route_token, route) = state.active_snapshot();

        assert_eq!(generation, 9);
        assert!(route_token.is_some());
        assert!(Arc::ptr_eq(&route.expect("active route"), &peer));
        peer.close().await.expect("close peer");
    }

    #[tokio::test]
    async fn published_restart_stays_committed_when_old_route_close_fails() {
        let active = WebRtcPeerConnection::new(PeerConnectionConfig::default())
            .await
            .expect("active peer");
        let replacement = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("replacement peer"),
        );
        let route_token = RestartRouteToken::generate().expect("route token");
        let route_id = NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed);
        let mut description =
            SessionDescription::initial(SessionDescriptionType::Offer, "state-harness-only".into());
        description.bind_restart(1, route_token.clone());
        active.restart_state().pending = Some(PendingRestart::Ready {
            generation: 1,
            route_token,
            route_id,
            peer: Arc::clone(&replacement),
            local_description: description,
            validated: true,
        });
        active.fail_close_for_test.store(true, Ordering::Release);
        let evidence = RestartRouteEvidence {
            generation: 1,
            route_id,
            selected_pair: SelectedCandidatePairStats {
                local_candidate_id: "state-harness-local".into(),
                remote_candidate_id: "state-harness-remote".into(),
                local_candidate_kind: crate::CandidateKind::Relay,
                remote_candidate_kind: crate::CandidateKind::Relay,
                nominated: true,
                packets_sent: 1,
                packets_received: 1,
                bytes_sent: 1,
                bytes_received: 1,
                current_round_trip_time: 0.01,
            },
            control_round_trip: true,
            media_round_trip: true,
        };

        active
            .commit_restart(1, evidence)
            .await
            .expect("publication is successful even when cleanup needs fallback");

        assert_eq!(active.current_generation().await, 1);
        assert_eq!(active.restart_cleanup_failure_count(), 1);
        assert!(Arc::ptr_eq(
            &active.active_route().expect("published replacement"),
            &replacement
        ));
        active.close().await.expect("close state harness");
    }
}
