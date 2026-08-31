#[cfg(test)]
use crate::cleanup::{reserve_cleanup_slot_from, CleanupSupervisor};
#[cfg(test)]
use std::sync::{Barrier, Weak};
use std::{
    fmt,
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{mpsc, watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore},
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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    cleanup::{
        reserve_cleanup_slot, submit_cleanup, CleanupJobMeta, CleanupPayload, CleanupPermit,
        CleanupPhase,
    },
    config::{
        ice_server_secret_values, is_public_turn_endpoint, normalize_secret_values,
        redact_error_with_secrets, IceServerConfig, IceTransportPolicy, PeerConnectionConfig,
        PeerConnectionRole, SecretValues,
    },
    control::{
        channel_info, realtime_channel_init, reliable_channel_init, weak_callback_owner,
        ControlChannels, ControlLane, ControlState, QueuedBytes, BULK_LABEL, CTRL_REL_LABEL,
        CTRL_RT_LABEL,
    },
    stats::selected_candidate_pair,
    turn_stream::TurnStreamBridgeOwner,
    H264RtpIngress, H264RtpSender, SelectedCandidatePairStats, TransportError,
};

const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const DISCONNECTED_GRACE_PERIOD: Duration = Duration::from_secs(2);
const BULK_BUFFER_HIGH_WATERMARK: usize = 64 * 1024;
const BULK_SEND_PACING_INTERVAL: Duration = Duration::from_millis(1);
const PHYSICAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const PHYSICAL_CLEANUP_RETRY: &str = "physical cleanup admission rolled back; retry required";
const RESTART_VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);
const RESTART_PROBE_PREFIX: &[u8] = b"mrd-webrtc-restart-probe-v1:";
static NEXT_RESTART_ROUTE_ID: AtomicU64 = AtomicU64::new(1);
const RESTART_ROUTE_TOKEN_BYTES: usize = 32;
const SCRUBBED_ICE_SERVER_URL: &str = "stun:0.0.0.0:9";

struct UpstreamIceServers(Vec<RTCIceServer>);

impl UpstreamIceServers {
    fn from_configs(servers: &[IceServerConfig]) -> Self {
        let mut owner = Self(Vec::with_capacity(servers.len()));
        for server in servers {
            owner.0.push(RTCIceServer {
                urls: server.urls.clone(),
                username: server.username.clone(),
                credential: server.credential.clone(),
            });
        }
        owner
    }

    fn take(&mut self) -> Vec<RTCIceServer> {
        std::mem::take(&mut self.0)
    }
}

impl Zeroize for UpstreamIceServers {
    fn zeroize(&mut self) {
        for server in &mut self.0 {
            server.urls.zeroize();
            server.username.zeroize();
            server.credential.zeroize();
        }
        self.0.clear();
    }
}

impl ZeroizeOnDrop for UpstreamIceServers {}

impl Drop for UpstreamIceServers {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct RestartRouteToken([u8; RESTART_ROUTE_TOKEN_BYTES]);

impl RestartRouteToken {
    fn generate() -> Result<Self, TransportError> {
        let mut bytes = Zeroizing::new([0_u8; RESTART_ROUTE_TOKEN_BYTES]);
        getrandom::fill(&mut *bytes).map_err(|_| {
            TransportError::Message("secure restart route token generation failed".into())
        })?;
        Ok(Self(*bytes))
    }

    pub fn from_wire(value: &str) -> Result<Self, TransportError> {
        if value.len() != RESTART_ROUTE_TOKEN_BYTES * 2 || !value.is_ascii() {
            return Err(TransportError::Message(
                "invalid restart route token encoding".into(),
            ));
        }
        let mut bytes = Zeroizing::new([0_u8; RESTART_ROUTE_TOKEN_BYTES]);
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = decode_hex(pair[0]).ok_or_else(invalid_route_token)?;
            let low = decode_hex(pair[1]).ok_or_else(invalid_route_token)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(*bytes))
    }

    pub fn to_wire(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = Zeroizing::new(String::with_capacity(RESTART_ROUTE_TOKEN_BYTES * 2));
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

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionDescription {
    #[zeroize(skip)]
    pub kind: SessionDescriptionType,
    pub sdp: String,
    /// Authenticated signaling generation. Initial negotiation is generation zero.
    #[zeroize(skip)]
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

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct IceCandidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    #[zeroize(skip)]
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
    /// Authenticated signaling generation. Initial negotiation is generation zero.
    #[zeroize(skip)]
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
        request_fingerprint: Option<[u8; 32]>,
    },
    Ready {
        generation: u64,
        route_token: RestartRouteToken,
        route_id: u64,
        peer: Arc<WebRtcPeerConnection>,
        local_description: SessionDescription,
        request_fingerprint: Option<[u8; 32]>,
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
    terminated: bool,
    active_generation: u64,
    highest_seen_generation: u64,
    active_route_token: Option<RestartRouteToken>,
    active_route_id: Option<u64>,
    active_replacement: Option<Arc<WebRtcPeerConnection>>,
    pending: Option<PendingRestart>,
    last_aborted_route: Option<(u64, RestartRouteToken)>,
}

struct CleanupTarget {
    peer: Arc<WebRtcPeerConnection>,
    meta: CleanupJobMeta,
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

struct RestartBuildGuard<'a> {
    owner: &'a WebRtcPeerConnection,
    generation: u64,
    route_token: RestartRouteToken,
    armed: bool,
}

impl<'a> RestartBuildGuard<'a> {
    fn new(
        owner: &'a WebRtcPeerConnection,
        generation: u64,
        route_token: RestartRouteToken,
    ) -> Self {
        Self {
            owner,
            generation,
            route_token,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RestartBuildGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.abort_build(self.generation, &self.route_token);
        }
    }
}

struct RestartValidationGuard<'a> {
    owner: &'a WebRtcPeerConnection,
    generation: u64,
    route_token: RestartRouteToken,
    route_id: u64,
    armed: bool,
}

impl<'a> RestartValidationGuard<'a> {
    fn new(
        owner: &'a WebRtcPeerConnection,
        generation: u64,
        route_token: RestartRouteToken,
        route_id: u64,
    ) -> Self {
        Self {
            owner,
            generation,
            route_token,
            route_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RestartValidationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.detach_pending_restart(
                self.generation,
                &self.route_token,
                Some(self.route_id),
            );
        }
    }
}

#[derive(Debug)]
enum PhysicalShutdownState {
    Open,
    Enqueuing { deadline: Instant },
    Closing { deadline: Instant },
    Closed { error: Option<String> },
    Quarantined { error: String },
}

struct PhysicalLifecycle {
    state: PhysicalShutdownState,
    physical: Option<PhysicalPeer>,
}

struct PhysicalShutdown {
    lifecycle: StdMutex<PhysicalLifecycle>,
    completed: Notify,
}

impl fmt::Debug for PhysicalShutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        f.debug_struct("PhysicalShutdown")
            .field("state", &lifecycle.state)
            .field("has_physical", &lifecycle.physical.is_some())
            .finish()
    }
}

impl Default for PhysicalShutdown {
    fn default() -> Self {
        Self {
            lifecycle: StdMutex::new(PhysicalLifecycle {
                state: PhysicalShutdownState::Open,
                physical: None,
            }),
            completed: Notify::new(),
        }
    }
}

impl PhysicalShutdown {
    fn install(&self, physical: PhysicalPeer) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        debug_assert!(matches!(lifecycle.state, PhysicalShutdownState::Open));
        debug_assert!(lifecycle.physical.is_none());
        lifecycle.physical = Some(physical);
    }

    fn begin(&self, timeout: Duration) -> Result<Option<PhysicalPeer>, TransportError> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match lifecycle.state {
            PhysicalShutdownState::Open => {
                let physical = lifecycle.physical.take().ok_or_else(|| {
                    TransportError::Message("physical cleanup ownership is unavailable".into())
                })?;
                lifecycle.state = PhysicalShutdownState::Enqueuing {
                    deadline: cleanup_deadline(timeout),
                };
                Ok(Some(physical))
            }
            PhysicalShutdownState::Enqueuing { .. }
            | PhysicalShutdownState::Closing { .. }
            | PhysicalShutdownState::Closed { .. }
            | PhysicalShutdownState::Quarantined { .. } => Ok(None),
        }
    }

    fn accepted(&self, timeout: Duration) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        lifecycle.state = match lifecycle.state {
            PhysicalShutdownState::Enqueuing { deadline } => {
                PhysicalShutdownState::Closing { deadline }
            }
            PhysicalShutdownState::Open if lifecycle.physical.is_none() => {
                PhysicalShutdownState::Closing {
                    deadline: cleanup_deadline(timeout),
                }
            }
            _ => return,
        };
        drop(lifecycle);
        self.completed.notify_waiters();
    }

    fn rollback(&self, physical: PhysicalPeer) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        debug_assert!(matches!(
            lifecycle.state,
            PhysicalShutdownState::Enqueuing { .. }
        ));
        debug_assert!(lifecycle.physical.is_none());
        lifecycle.physical = Some(physical);
        lifecycle.state = PhysicalShutdownState::Open;
        drop(lifecycle);
        self.completed.notify_waiters();
    }

    fn physical_snapshot(&self) -> Result<PhysicalSnapshot, TransportError> {
        let lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let physical = lifecycle
            .physical
            .as_ref()
            .ok_or_else(|| TransportError::Message("peer connection is closing".into()))?;
        Ok(PhysicalSnapshot {
            pc: Arc::clone(&physical.pc),
            control: Arc::clone(&physical.control),
            active_tasks: Arc::clone(&physical.active_tasks),
            h264_sender: Arc::clone(&physical.h264_sender),
        })
    }

    fn is_started(&self) -> bool {
        !matches!(
            self.lifecycle
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .state,
            PhysicalShutdownState::Open
        )
    }

    fn is_finished(&self) -> bool {
        matches!(
            self.lifecycle
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .state,
            PhysicalShutdownState::Closed { .. }
        )
    }

    #[cfg(test)]
    async fn wait_until_finished(&self) {
        loop {
            let notified = self.completed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_finished() {
                return;
            }
            notified.await;
        }
    }

    fn complete(&self, error: Option<String>) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        debug_assert!(matches!(
            lifecycle.state,
            PhysicalShutdownState::Closing { .. }
        ));
        lifecycle.state = PhysicalShutdownState::Closed { error };
        drop(lifecycle);
        self.completed.notify_waiters();
    }

    fn quarantine(&self, error: String) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        debug_assert!(matches!(
            lifecycle.state,
            PhysicalShutdownState::Closing { .. }
        ));
        lifecycle.state = PhysicalShutdownState::Quarantined { error };
        drop(lifecycle);
        self.completed.notify_waiters();
    }

    async fn wait(&self) -> Result<(), TransportError> {
        loop {
            let notified = self.completed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let outcome = {
                let lifecycle = self
                    .lifecycle
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                match &lifecycle.state {
                    PhysicalShutdownState::Closed { error } => {
                        Some(PhysicalShutdownWait::Closed(error.clone()))
                    }
                    PhysicalShutdownState::Quarantined { error } => {
                        Some(PhysicalShutdownWait::Quarantined(error.clone()))
                    }
                    PhysicalShutdownState::Enqueuing { deadline }
                    | PhysicalShutdownState::Closing { deadline } => {
                        Some(PhysicalShutdownWait::Closing(*deadline))
                    }
                    PhysicalShutdownState::Open => Some(PhysicalShutdownWait::Retry),
                }
            };
            match outcome {
                Some(PhysicalShutdownWait::Closed(error)) => {
                    return error.map_or(Ok(()), |error| Err(TransportError::Message(error)));
                }
                Some(PhysicalShutdownWait::Quarantined(error)) => {
                    return Err(TransportError::Message(error));
                }
                Some(PhysicalShutdownWait::Closing(deadline)) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(TransportError::Message(
                            "physical cleanup is still in progress after its deadline".into(),
                        ));
                    }
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                            return Err(TransportError::Message(
                                "physical cleanup is still in progress after its deadline".into(),
                            ));
                        }
                    }
                }
                Some(PhysicalShutdownWait::Retry) => {
                    return Err(TransportError::Message(PHYSICAL_CLEANUP_RETRY.into()));
                }
                None => notified.await,
            }
        }
    }
}

enum PhysicalShutdownWait {
    Closing(Instant),
    Closed(Option<String>),
    Quarantined(String),
    Retry,
}

fn cleanup_deadline(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

struct PhysicalPeer {
    pc: Arc<RTCPeerConnection>,
    control: Arc<ControlState>,
    tasks: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    active_tasks: Arc<AtomicUsize>,
    h264_sender: Arc<Mutex<H264RtpSender>>,
    turn_stream_bridges: Box<TurnStreamBridgeOwner>,
    cleanup_permit: CleanupPermit,
}

struct PhysicalAdmissionGuard<'a> {
    shutdown: &'a PhysicalShutdown,
    physical: Option<PhysicalPeer>,
}

impl<'a> PhysicalAdmissionGuard<'a> {
    fn new(shutdown: &'a PhysicalShutdown, physical: PhysicalPeer) -> Self {
        Self {
            shutdown,
            physical: Some(physical),
        }
    }

    fn take(&mut self) -> PhysicalPeer {
        self.physical
            .take()
            .expect("armed shutdown admission owns the physical peer")
    }
}

impl Drop for PhysicalAdmissionGuard<'_> {
    fn drop(&mut self) {
        if let Some(physical) = self.physical.take() {
            self.shutdown.rollback(physical);
        }
    }
}

struct PhysicalSnapshot {
    pc: Arc<RTCPeerConnection>,
    control: Arc<ControlState>,
    active_tasks: Arc<AtomicUsize>,
    h264_sender: Arc<Mutex<H264RtpSender>>,
}

struct PartialPhysicalPeer {
    pc: Arc<RTCPeerConnection>,
    control: Arc<ControlState>,
    tasks: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    active_tasks: Arc<AtomicUsize>,
    h264_sender: Option<Arc<Mutex<H264RtpSender>>>,
    turn_stream_bridges: Box<TurnStreamBridgeOwner>,
    cleanup_permit: CleanupPermit,
}

impl PartialPhysicalPeer {
    fn finish(mut self) -> PhysicalPeer {
        PhysicalPeer {
            pc: self.pc,
            control: self.control,
            tasks: self.tasks,
            active_tasks: self.active_tasks,
            h264_sender: self
                .h264_sender
                .take()
                .expect("completed peer has an H.264 sender"),
            turn_stream_bridges: self.turn_stream_bridges,
            cleanup_permit: self.cleanup_permit,
        }
    }
}

struct PhysicalCleanupPayload {
    owners: Option<PhysicalCleanupOwners>,
    close_gate: Option<Arc<Semaphore>>,
    injected_failure: bool,
    injected_panic: bool,
    pc_close_started: bool,
    physical_closed: bool,
}

struct PhysicalCleanupOwners {
    pc: Arc<RTCPeerConnection>,
    control: Arc<ControlState>,
    tasks: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    active_tasks: Arc<AtomicUsize>,
    h264_sender: Option<Arc<Mutex<H264RtpSender>>>,
    turn_stream_bridges: Box<TurnStreamBridgeOwner>,
}

impl PhysicalCleanupPayload {
    fn from_partial(physical: PartialPhysicalPeer) -> (CleanupPermit, Self) {
        (
            physical.cleanup_permit,
            Self {
                owners: Some(PhysicalCleanupOwners {
                    pc: physical.pc,
                    control: physical.control,
                    tasks: physical.tasks,
                    active_tasks: physical.active_tasks,
                    h264_sender: physical.h264_sender,
                    turn_stream_bridges: physical.turn_stream_bridges,
                }),
                close_gate: None,
                injected_failure: false,
                injected_panic: false,
                pc_close_started: false,
                physical_closed: false,
            },
        )
    }

    fn from_physical(
        physical: PhysicalPeer,
        close_gate: Option<Arc<Semaphore>>,
        injected_failure: bool,
        injected_panic: bool,
    ) -> (CleanupPermit, Self) {
        (
            physical.cleanup_permit,
            Self {
                owners: Some(PhysicalCleanupOwners {
                    pc: physical.pc,
                    control: physical.control,
                    tasks: physical.tasks,
                    active_tasks: physical.active_tasks,
                    h264_sender: Some(physical.h264_sender),
                    turn_stream_bridges: physical.turn_stream_bridges,
                }),
                close_gate,
                injected_failure,
                injected_panic,
                pc_close_started: false,
                physical_closed: false,
            },
        )
    }

    fn into_physical(mut self, cleanup_permit: CleanupPermit) -> PhysicalPeer {
        let mut owners = self
            .owners
            .take()
            .expect("rejected cleanup retains physical owners");
        PhysicalPeer {
            pc: owners.pc,
            control: owners.control,
            tasks: owners.tasks,
            active_tasks: owners.active_tasks,
            h264_sender: owners
                .h264_sender
                .take()
                .expect("completed peer cleanup payload retains its sender"),
            turn_stream_bridges: owners.turn_stream_bridges,
            cleanup_permit,
        }
    }
}

impl Drop for PhysicalCleanupPayload {
    fn drop(&mut self) {
        let Some(owners) = &self.owners else {
            return;
        };
        let tasks = owners
            .tasks
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        for task in tasks.iter() {
            task.abort();
        }
    }
}

struct PeerConstructionGuard {
    physical: Option<PartialPhysicalPeer>,
    completed_video_drops: Arc<VideoDropCounter>,
    shutdown: Arc<PhysicalShutdown>,
}

impl PeerConstructionGuard {
    fn set_h264_sender(&mut self, sender: Arc<Mutex<H264RtpSender>>) {
        self.physical
            .as_mut()
            .expect("armed construction guard")
            .h264_sender = Some(sender);
    }

    fn finish(mut self) -> PhysicalPeer {
        self.physical
            .take()
            .expect("armed construction guard")
            .finish()
    }
}

impl Drop for PeerConstructionGuard {
    fn drop(&mut self) {
        if let Some(physical) = self.physical.take() {
            self.completed_video_drops.seal();
            let (permit, payload) = PhysicalCleanupPayload::from_partial(physical);
            let _ = enqueue_physical_cleanup(
                Arc::clone(&self.shutdown),
                permit,
                payload,
                CleanupJobMeta {
                    kind: "partial-construction",
                    generation: None,
                    route_id: None,
                },
                PHYSICAL_CLEANUP_TIMEOUT,
                None,
            );
        }
    }
}

impl From<IceCandidate> for RTCIceCandidateInit {
    fn from(mut value: IceCandidate) -> Self {
        Self {
            candidate: std::mem::take(&mut value.candidate),
            sdp_mid: std::mem::take(&mut value.sdp_mid),
            sdp_mline_index: value.sdp_mline_index,
            username_fragment: std::mem::take(&mut value.username_fragment),
        }
    }
}

pub struct WebRtcPeerConnection {
    config: PeerConnectionConfig,
    local_candidates: Mutex<mpsc::Receiver<IceCandidate>>,
    h264_rx: Mutex<mpsc::Receiver<QueuedAccessUnit>>,
    reliable_rx: Mutex<mpsc::Receiver<QueuedBytes>>,
    realtime_rx: Mutex<mpsc::Receiver<QueuedBytes>>,
    bulk_rx: Mutex<mpsc::Receiver<QueuedBytes>>,
    connection_state_rx: watch::Receiver<RTCPeerConnectionState>,
    completed_video_drops: Arc<VideoDropCounter>,
    shutdown: Arc<PhysicalShutdown>,
    restart: StdMutex<RestartState>,
    restart_cleanup_failures: Arc<AtomicU64>,
    #[cfg(test)]
    fail_close_for_test: AtomicBool,
    #[cfg(test)]
    panic_cleanup_for_test: AtomicBool,
    #[cfg(test)]
    physical_cleanup_timeout_ms_for_test: AtomicU64,
    #[cfg(test)]
    restart_build_gate_for_test: StdMutex<Option<Arc<Semaphore>>>,
    #[cfg(test)]
    last_built_peer_for_test: StdMutex<Option<Weak<WebRtcPeerConnection>>>,
    #[cfg(test)]
    physical_close_gate_for_test: StdMutex<Option<Arc<Semaphore>>>,
    #[cfg(test)]
    shutdown_admission_hook_for_test: StdMutex<Option<ShutdownAdmissionHook>>,
    #[cfg(test)]
    concurrent_shutdown_observed_for_test: AtomicBool,
    #[cfg(test)]
    restart_validation_gate_for_test: StdMutex<Option<Arc<Semaphore>>>,
    #[cfg(test)]
    restart_validation_entered_for_test: AtomicBool,
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

#[cfg(test)]
struct BlockingCloseInterceptorHook {
    entered: Arc<AtomicBool>,
    gate: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
}

#[cfg(test)]
static BLOCKING_CLOSE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

#[cfg(test)]
#[derive(Clone)]
struct ShutdownAdmissionHook {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    action: ShutdownAdmissionAction,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum ShutdownAdmissionAction {
    Accept,
    Reject,
    Panic,
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
            .field("closed", &self.shutdown.is_finished())
            .field("generation", &self.current_generation_now())
            .finish_non_exhaustive()
    }
}

impl Drop for WebRtcPeerConnection {
    fn drop(&mut self) {
        self.terminate_with_kind("peer-drop");
    }
}

impl WebRtcPeerConnection {
    pub async fn new(config: PeerConnectionConfig) -> Result<Self, TransportError> {
        Self::new_inner(
            config,
            None,
            #[cfg(test)]
            None,
            #[cfg(test)]
            None,
        )
        .await
    }

    #[cfg(test)]
    async fn new_blocked_after_pc_for_test(
        config: PeerConnectionConfig,
        entered: Arc<AtomicBool>,
        gate: Arc<Semaphore>,
    ) -> Result<Self, TransportError> {
        Self::new_inner(config, Some((entered, gate)), None, None).await
    }

    #[cfg(test)]
    async fn new_with_cleanup_supervisor_for_test(
        config: PeerConnectionConfig,
        supervisor: Arc<CleanupSupervisor>,
    ) -> Result<Self, TransportError> {
        Self::new_inner(config, None, Some(supervisor), None).await
    }

    #[cfg(test)]
    async fn new_with_blocking_close_interceptor_for_test(
        config: PeerConnectionConfig,
        supervisor: Arc<CleanupSupervisor>,
        hook: BlockingCloseInterceptorHook,
    ) -> Result<Self, TransportError> {
        Self::new_inner(config, None, Some(supervisor), Some(hook)).await
    }

    async fn new_inner(
        mut config: PeerConnectionConfig,
        construction_hook: Option<(Arc<AtomicBool>, Arc<Semaphore>)>,
        #[cfg(test)] cleanup_supervisor: Option<Arc<CleanupSupervisor>>,
        #[cfg(test)] blocking_close_interceptor: Option<BlockingCloseInterceptorHook>,
    ) -> Result<Self, TransportError> {
        // Workspace-wide builds can unify transitive Rustls features from
        // unrelated applications, leaving both crypto providers enabled. Pick
        // the repository's configured provider before WebRTC constructs DTLS.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let codec = config.preflight()?.clone();
        #[cfg(test)]
        let cleanup_permit = if let Some(supervisor) = cleanup_supervisor {
            reserve_cleanup_slot_from(&supervisor).await
        } else {
            reserve_cleanup_slot().await
        };
        #[cfg(not(test))]
        let cleanup_permit = reserve_cleanup_slot().await;
        let cleanup_permit = cleanup_permit.map_err(|error| {
            TransportError::Message(format!("WebRTC cleanup capacity unavailable: {error}"))
        })?;
        let mut config_secrets = secret_values(&config.ice_servers);
        let turn_stream_bridges = TurnStreamBridgeOwner::prepare(&mut config.ice_servers)
            .await
            .map_err(|error| redact_error_with_secrets(error, &config_secrets))?;
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|error| TransportError::Message(format!("register codecs failed: {error}")))?;
        let registry =
            register_default_interceptors(Registry::new(), &mut media_engine).map_err(|error| {
                TransportError::Message(format!("register interceptors failed: {error}"))
            })?;
        #[cfg(test)]
        let mut registry = registry;
        #[cfg(test)]
        if let Some(hook) = blocking_close_interceptor {
            use webrtc::interceptor::{
                mock::{mock_builder::MockBuilder, mock_interceptor::MockInterceptor},
                Interceptor,
            };

            registry.add(Box::new(MockBuilder::new(move |_| {
                let entered = Arc::clone(&hook.entered);
                let gate = Arc::clone(&hook.gate);
                let calls = Arc::clone(&hook.calls);
                Ok(Arc::new(MockInterceptor {
                    close_fn: Some(Box::new(move || {
                        let entered = Arc::clone(&entered);
                        let gate = Arc::clone(&gate);
                        let calls = Arc::clone(&calls);
                        Box::pin(async move {
                            calls.fetch_add(1, Ordering::AcqRel);
                            entered.store(true, Ordering::Release);
                            let _ = gate.acquire_owned().await;
                            Ok(())
                        })
                    })),
                    ..Default::default()
                }) as Arc<dyn Interceptor + Send + Sync>)
            })));
        }
        let mut settings = SettingEngine::default();
        settings.set_include_loopback_candidate(config.include_loopback_candidates);
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(settings)
            .build();
        let mut upstream_ice_servers = UpstreamIceServers::from_configs(&config.ice_servers);
        let ice_transport_policy = match config.ice_transport_policy {
            IceTransportPolicy::All => RTCIceTransportPolicy::All,
            IceTransportPolicy::Relay => RTCIceTransportPolicy::Relay,
        };
        let pc = api
            .new_peer_connection(RTCConfiguration {
                ice_servers: upstream_ice_servers.take(),
                ice_transport_policy,
                ..Default::default()
            })
            .await
            .map_err(peer_error_redacted(
                "create peer connection",
                &config_secrets,
            ))?;
        scrub_accessible_upstream_ice_servers(&pc, ice_transport_policy)
            .await
            .map_err(peer_error("scrub peer ICE server configuration"))?;
        config.ice_servers.zeroize();
        config_secrets.zeroize();
        drop(config_secrets);
        let pc = Arc::new(pc);

        let capacity = config.event_queue_capacity;
        let (control, reliable_rx, realtime_rx, bulk_rx) = ControlState::new(
            capacity,
            config.reliable_queue_bytes,
            config.realtime_queue_bytes,
            config.bulk_queue_bytes,
        );
        let tasks = Arc::new(StdMutex::new(Vec::new()));
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let completed_video_drops = Arc::new(VideoDropCounter::default());
        let shutdown = Arc::new(PhysicalShutdown::default());
        let (h264_tx, h264_rx) = mpsc::channel(capacity);
        let h264_queue_budget = Arc::new(Semaphore::new(config.video_queue_bytes));
        let mut construction_guard = PeerConstructionGuard {
            physical: Some(PartialPhysicalPeer {
                pc: Arc::clone(&pc),
                control: Arc::clone(&control),
                tasks: Arc::clone(&tasks),
                active_tasks: Arc::clone(&active_tasks),
                h264_sender: None,
                turn_stream_bridges: Box::new(turn_stream_bridges),
                cleanup_permit,
            }),
            completed_video_drops: Arc::clone(&completed_video_drops),
            shutdown: Arc::clone(&shutdown),
        };
        if let Some((entered, gate)) = construction_hook {
            entered.store(true, Ordering::Release);
            let _ = gate.acquire().await;
        }

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

        let remote_tasks = Arc::clone(&tasks);
        let remote_active_tasks = Arc::clone(&active_tasks);
        let remote_completed_video_drops = Arc::clone(&completed_video_drops);
        let remote_shutdown = Arc::clone(&shutdown);
        let max_h264_access_unit_bytes = config.max_h264_access_unit_bytes;
        pc.on_track(Box::new(move |track, _receiver, _transceiver| {
            let h264_tx = h264_tx.clone();
            let h264_queue_budget = Arc::clone(&h264_queue_budget);
            let tasks = Arc::clone(&remote_tasks);
            let active_tasks = Arc::clone(&remote_active_tasks);
            let completed_video_drops = Arc::clone(&remote_completed_video_drops);
            let shutdown = Arc::clone(&remote_shutdown);
            Box::pin(async move {
                let mut tasks = tasks.lock().unwrap_or_else(|poison| poison.into_inner());
                if shutdown.is_started() {
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

        let h264_sender = Arc::new(Mutex::new(H264RtpSender::new_with_profile_level_id(
            "screen",
            "desktop",
            config.fps,
            config.mtu,
            codec.profile.into(),
            codec.profile_level_id,
        )));
        let rtp_sender = pc
            .add_track(h264_sender.lock().await.track() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|error| TransportError::Message(format!("add H.264 track failed: {error}")))?;
        let rtcp_task = spawn_tracked(&active_tasks, async move {
            while rtp_sender.read_rtcp().await.is_ok() {}
        });
        tasks
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(rtcp_task);

        construction_guard.set_h264_sender(Arc::clone(&h264_sender));
        let physical = construction_guard.finish();
        shutdown.install(physical);

        Ok(Self {
            config,
            local_candidates: Mutex::new(candidate_rx),
            h264_rx: Mutex::new(h264_rx),
            reliable_rx: Mutex::new(reliable_rx),
            realtime_rx: Mutex::new(realtime_rx),
            bulk_rx: Mutex::new(bulk_rx),
            connection_state_rx,
            completed_video_drops,
            shutdown,
            restart: StdMutex::new(RestartState::default()),
            restart_cleanup_failures: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            fail_close_for_test: AtomicBool::new(false),
            #[cfg(test)]
            panic_cleanup_for_test: AtomicBool::new(false),
            #[cfg(test)]
            physical_cleanup_timeout_ms_for_test: AtomicU64::new(
                PHYSICAL_CLEANUP_TIMEOUT.as_millis() as u64,
            ),
            #[cfg(test)]
            restart_build_gate_for_test: StdMutex::new(None),
            #[cfg(test)]
            last_built_peer_for_test: StdMutex::new(None),
            #[cfg(test)]
            physical_close_gate_for_test: StdMutex::new(None),
            #[cfg(test)]
            shutdown_admission_hook_for_test: StdMutex::new(None),
            #[cfg(test)]
            concurrent_shutdown_observed_for_test: AtomicBool::new(false),
            #[cfg(test)]
            restart_validation_gate_for_test: StdMutex::new(None),
            #[cfg(test)]
            restart_validation_entered_for_test: AtomicBool::new(false),
        })
    }

    fn physical_snapshot(&self) -> Result<PhysicalSnapshot, TransportError> {
        self.shutdown.physical_snapshot()
    }

    #[cfg(test)]
    fn physical_pc_for_test(&self) -> Option<Arc<RTCPeerConnection>> {
        self.physical_snapshot().ok().map(|physical| physical.pc)
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
        let pc = self.physical_snapshot()?.pc;
        let offer = pc
            .create_offer(None)
            .await
            .map_err(peer_error("create offer"))?;
        let description =
            SessionDescription::initial(SessionDescriptionType::Offer, offer.sdp.clone());
        pc.set_local_description(offer).await.map_err(|error| {
            redact_sdp_error(peer_error("set local offer")(error), &description.sdp)
        })?;
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
        mut offer: SessionDescription,
    ) -> Result<SessionDescription, TransportError> {
        self.require_role(PeerConnectionRole::Answerer)?;
        if offer.kind != SessionDescriptionType::Offer {
            return Err(TransportError::Message("expected an SDP offer".into()));
        }
        let remote_secrets = sdp_secret_values(&offer.sdp);
        let offer =
            RTCSessionDescription::offer(std::mem::take(&mut offer.sdp)).map_err(|error| {
                redact_transport_error(peer_error("parse offer")(error), &remote_secrets)
            })?;
        let pc = self.physical_snapshot()?.pc;
        pc.set_remote_description(offer).await.map_err(|error| {
            redact_transport_error(peer_error("set remote offer")(error), &remote_secrets)
        })?;
        let answer = pc
            .create_answer(None)
            .await
            .map_err(peer_error("create answer"))?;
        let description =
            SessionDescription::initial(SessionDescriptionType::Answer, answer.sdp.clone());
        pc.set_local_description(answer).await.map_err(|error| {
            redact_sdp_error(peer_error("set local answer")(error), &description.sdp)
        })?;
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
        mut answer: SessionDescription,
    ) -> Result<(), TransportError> {
        self.require_role(PeerConnectionRole::Offerer)?;
        if answer.kind != SessionDescriptionType::Answer {
            return Err(TransportError::Message("expected an SDP answer".into()));
        }
        let remote_secrets = sdp_secret_values(&answer.sdp);
        let answer =
            RTCSessionDescription::answer(std::mem::take(&mut answer.sdp)).map_err(|error| {
                redact_transport_error(peer_error("parse answer")(error), &remote_secrets)
            })?;
        self.physical_snapshot()?
            .pc
            .set_remote_description(answer)
            .await
            .map_err(|error| {
                redact_transport_error(peer_error("set remote answer")(error), &remote_secrets)
            })
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
        self.physical_snapshot()?
            .pc
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
        self.physical_snapshot()?
            .h264_sender
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
                if self.shutdown.is_started() {
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
        let control = self
            .physical_snapshot()
            .ok()
            .map(|physical| physical.control);
        let reliable = if let Some(control) = &control {
            control.channel(ControlLane::Reliable).await
        } else {
            None
        };
        let realtime = if let Some(control) = &control {
            control.channel(ControlLane::Realtime).await
        } else {
            None
        };
        let bulk = if let Some(control) = &control {
            control.channel(ControlLane::Bulk).await
        } else {
            None
        };
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
        let pc = self.physical_snapshot().ok()?.pc;
        selected_candidate_pair(pc.get_stats().await)
    }

    pub fn active_task_count(&self) -> usize {
        if let Some(route) = self.active_route() {
            return route.active_task_count();
        }
        self.physical_snapshot()
            .map(|physical| physical.active_tasks.load(Ordering::Acquire))
            .unwrap_or(0)
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
        let (config, loser) = self.begin_restart(generation, route_token.clone(), None)?;
        let mut build_guard = RestartBuildGuard::new(self, generation, route_token.clone());
        let config = restart_peer_config(config, ice_servers);
        close_loser(loser);

        let pending = match Self::new(config).await {
            Ok(peer) => Arc::new(peer),
            Err(error) => return Err(redact_transport_error(error, &secrets)),
        };
        self.wait_restart_build_gate_for_test(&pending).await;
        let mut offer = match pending.create_offer_physical().await {
            Ok(offer) => offer,
            Err(error) => {
                close_route_best_effort(
                    &pending,
                    CleanupJobMeta {
                        kind: "restart-build-failed",
                        generation: Some(generation),
                        route_id: None,
                    },
                );
                return Err(redact_transport_error(error, &secrets));
            }
        };
        offer.bind_restart(generation, route_token.clone());
        if !self.finish_build(
            generation,
            &route_token,
            Arc::clone(&pending),
            offer.clone(),
            None,
        ) {
            close_route_best_effort(
                &pending,
                CleanupJobMeta {
                    kind: "restart-build-lost",
                    generation: Some(generation),
                    route_id: None,
                },
            );
            return Err(self.restart_build_rejection(generation, "restart offer"));
        }
        build_guard.disarm();
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
        let request_fingerprint =
            restart_offer_fingerprint(generation, &route_token, &offer, &ice_servers);
        if let Some(answer) =
            self.existing_restart_description(generation, &route_token, &request_fingerprint)?
        {
            return Ok(answer);
        }
        let secrets = secret_values(&ice_servers);
        let (config, loser) =
            self.begin_restart(generation, route_token.clone(), Some(request_fingerprint))?;
        let mut build_guard = RestartBuildGuard::new(self, generation, route_token.clone());
        let config = restart_peer_config(config, ice_servers);
        close_loser(loser);

        let pending = match Self::new(config).await {
            Ok(peer) => Arc::new(peer),
            Err(error) => return Err(redact_transport_error(error, &secrets)),
        };
        self.wait_restart_build_gate_for_test(&pending).await;
        offer.clear_restart_binding();
        let mut answer = match pending.accept_offer_physical(offer).await {
            Ok(answer) => answer,
            Err(error) => {
                close_route_best_effort(
                    &pending,
                    CleanupJobMeta {
                        kind: "restart-build-failed",
                        generation: Some(generation),
                        route_id: None,
                    },
                );
                return Err(redact_transport_error(error, &secrets));
            }
        };
        answer.bind_restart(generation, route_token.clone());
        if !self.finish_build(
            generation,
            &route_token,
            Arc::clone(&pending),
            answer.clone(),
            Some(request_fingerprint),
        ) {
            close_route_best_effort(
                &pending,
                CleanupJobMeta {
                    kind: "restart-build-lost",
                    generation: Some(generation),
                    route_id: None,
                },
            );
            return Err(self.restart_build_rejection(generation, "restart offer"));
        }
        build_guard.disarm();
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
        self.next_restart_candidate_optional(generation)
            .await?
            .ok_or_else(|| {
                TransportError::Message(format!(
                    "restart candidate stream closed for generation {generation}"
                ))
            })
    }

    /// Return the next candidate for one pending restart, or `None` after ICE gathering
    /// completed normally. Generation and opaque-route fencing are checked before and after
    /// the await so a superseded route cannot leak candidates into a newer migration.
    pub async fn next_restart_candidate_optional(
        &self,
        generation: u64,
    ) -> Result<Option<IceCandidate>, TransportError> {
        let (route_id, route_token, peer) = self.ready_restart(generation)?;
        let Some(mut candidate) = peer.next_local_candidate_physical().await else {
            self.require_ready_route(generation, route_id)?;
            return Ok(None);
        };
        self.require_ready_route(generation, route_id)?;
        candidate.bind_restart(generation, route_token);
        Ok(Some(candidate))
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
        let (route_id, route_token, peer) = self.ready_restart(generation)?;
        let mut validation_guard =
            RestartValidationGuard::new(self, generation, route_token, route_id);
        self.wait_restart_validation_gate_for_test().await;
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
        let evidence = RestartRouteEvidence {
            generation,
            route_id,
            selected_pair: pair,
            control_round_trip: true,
            media_round_trip: true,
        };
        validation_guard.disarm();
        Ok(evidence)
    }

    /// Atomically publish a validated pending peer and then close the losing active route.
    pub async fn commit_restart(
        &self,
        generation: u64,
        evidence: RestartRouteEvidence,
    ) -> Result<(), TransportError> {
        let (replacement, previous) = {
            let mut state = self.restart_state();
            if state.terminated {
                return Err(terminated_error());
            }
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
                request_fingerprint,
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
                    request_fingerprint,
                    validated,
                });
                return Err(stale_generation_error(generation, "restart evidence"));
            }
            let previous_generation = state.active_generation;
            let previous_route_id = state.active_route_id;
            let previous = state
                .active_replacement
                .replace(Arc::clone(&peer))
                .map(|peer| CleanupTarget {
                    peer,
                    meta: CleanupJobMeta {
                        kind: "commit-old-route",
                        generation: Some(previous_generation),
                        route_id: previous_route_id,
                    },
                });
            state.active_generation = generation;
            state.active_route_token = Some(route_token);
            state.active_route_id = Some(route_id);
            (peer, previous)
        };

        let (cleanup, cleanup_started) = if let Some(previous) = previous {
            let cleanup_started = previous.peer.start_physical_shutdown_with_meta(
                previous.meta,
                Some(Arc::clone(&self.restart_cleanup_failures)),
            );
            (Arc::clone(&previous.peer.shutdown), cleanup_started)
        } else {
            let cleanup_started = self.start_physical_shutdown_with_meta(
                CleanupJobMeta {
                    kind: "commit-old-route",
                    generation: Some(0),
                    route_id: None,
                },
                Some(Arc::clone(&self.restart_cleanup_failures)),
            );
            (Arc::clone(&self.shutdown), cleanup_started)
        };
        if cleanup_started.is_ok() {
            let _ = cleanup.wait().await;
        } else {
            // Publication above is the commit point. A cleanup admission invariant failure must
            // remain observable, but cannot turn a committed replacement into a caller-visible
            // failure.
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

    /// Abort one pending route without allowing stale signaling to affect a newer route.
    /// Returns `false` when the same route was already aborted.
    pub fn abort_restart(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
    ) -> Result<bool, TransportError> {
        self.abort_restart_bound(generation, route_token, None, "restart-abort")
    }

    /// Number of old-route close failures recovered after a replacement was published.
    pub fn restart_cleanup_failure_count(&self) -> u64 {
        self.restart_cleanup_failures.load(Ordering::Acquire)
    }

    /// Begin idempotent transport termination without requiring an async caller.
    pub fn terminate_now(&self) {
        self.terminate_with_kind("terminate");
    }

    pub(crate) fn terminate_probe_now(&self) {
        self.terminate_with_kind("probe");
    }

    fn terminate_with_kind(&self, root_kind: &'static str) {
        let (active, pending) = if let Ok(mut state) = self.restart.lock() {
            state.terminated = true;
            let active = state.active_replacement.take().map(|peer| CleanupTarget {
                peer,
                meta: CleanupJobMeta {
                    kind: "terminate-active-restart",
                    generation: Some(state.active_generation),
                    route_id: state.active_route_id,
                },
            });
            let pending = match state.pending.take() {
                Some(PendingRestart::Ready {
                    generation,
                    route_id,
                    peer,
                    ..
                }) => Some(CleanupTarget {
                    peer,
                    meta: CleanupJobMeta {
                        kind: "terminate-pending-restart",
                        generation: Some(generation),
                        route_id: Some(route_id),
                    },
                }),
                _ => None,
            };
            state.active_route_token = None;
            state.last_aborted_route = None;
            (active, pending)
        } else {
            (None, None)
        };
        if let Some(active) = active {
            if active
                .peer
                .start_physical_shutdown_with_meta(active.meta, None)
                .is_err()
            {
                self.restart_cleanup_failures.fetch_add(1, Ordering::AcqRel);
            }
        }
        if let Some(pending) = pending {
            if pending
                .peer
                .start_physical_shutdown_with_meta(pending.meta, None)
                .is_err()
            {
                self.restart_cleanup_failures.fetch_add(1, Ordering::AcqRel);
            }
        }
        if self
            .start_physical_shutdown_with_meta(
                CleanupJobMeta {
                    kind: root_kind,
                    generation: Some(0),
                    route_id: None,
                },
                None,
            )
            .is_err()
        {
            self.restart_cleanup_failures.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn start_physical_shutdown_with_meta(
        &self,
        meta: CleanupJobMeta,
        failure_counter: Option<Arc<AtomicU64>>,
    ) -> Result<(), TransportError> {
        #[cfg(test)]
        let cleanup_timeout = Duration::from_millis(
            self.physical_cleanup_timeout_ms_for_test
                .load(Ordering::Acquire),
        );
        #[cfg(not(test))]
        let cleanup_timeout = PHYSICAL_CLEANUP_TIMEOUT;
        let Some(physical) = self.shutdown.begin(cleanup_timeout)? else {
            #[cfg(test)]
            self.concurrent_shutdown_observed_for_test
                .store(true, Ordering::Release);
            return Ok(());
        };
        let mut admission = PhysicalAdmissionGuard::new(&self.shutdown, physical);
        #[cfg(test)]
        let admission_action = self
            .shutdown_admission_hook_for_test
            .lock()
            .expect("shutdown admission hook lock poisoned")
            .take()
            .map(|hook| {
                hook.entered.wait();
                hook.release.wait();
                hook.action
            });
        self.completed_video_drops.seal();
        let shutdown = Arc::clone(&self.shutdown);
        #[cfg(test)]
        let close_gate = self
            .physical_close_gate_for_test
            .lock()
            .expect("physical close gate lock poisoned")
            .clone();
        #[cfg(not(test))]
        let close_gate = None;
        #[cfg(test)]
        let injected_failure = self.fail_close_for_test.load(Ordering::Acquire);
        #[cfg(not(test))]
        let injected_failure = false;
        #[cfg(test)]
        let injected_panic = self.panic_cleanup_for_test.load(Ordering::Acquire);
        #[cfg(not(test))]
        let injected_panic = false;
        #[cfg(test)]
        match admission_action {
            Some(ShutdownAdmissionAction::Reject) => {
                return Err(TransportError::Message(
                    "injected cleanup admission rejection".into(),
                ));
            }
            Some(ShutdownAdmissionAction::Panic) => {
                panic!("injected cleanup admission panic");
            }
            Some(ShutdownAdmissionAction::Accept) | None => {}
        }
        let physical = admission.take();
        let (permit, payload) = PhysicalCleanupPayload::from_physical(
            physical,
            close_gate,
            injected_failure,
            injected_panic,
        );
        match enqueue_physical_cleanup(
            shutdown,
            permit,
            payload,
            meta,
            cleanup_timeout,
            failure_counter,
        ) {
            Ok(()) => Ok(()),
            Err((permit, payload, reason)) => {
                self.shutdown.rollback(payload.into_physical(permit));
                Err(TransportError::Message(reason))
            }
        }
    }

    async fn wait_physical_shutdown_with_retry(
        &self,
        meta: CleanupJobMeta,
    ) -> Result<(), TransportError> {
        loop {
            match self.shutdown.wait().await {
                Err(TransportError::Message(message)) if message == PHYSICAL_CLEANUP_RETRY => {
                    self.start_physical_shutdown_with_meta(meta, None)?;
                }
                result => return result,
            }
        }
    }

    pub async fn close(&self) -> Result<(), TransportError> {
        let (active, pending) = {
            let mut state = self.restart_state();
            state.terminated = true;
            let active = state.active_replacement.take().map(|peer| CleanupTarget {
                peer,
                meta: CleanupJobMeta {
                    kind: "close-active-restart",
                    generation: Some(state.active_generation),
                    route_id: state.active_route_id,
                },
            });
            let pending = match state.pending.take() {
                Some(PendingRestart::Ready {
                    generation,
                    route_id,
                    peer,
                    ..
                }) => Some(CleanupTarget {
                    peer,
                    meta: CleanupJobMeta {
                        kind: "close-pending-restart",
                        generation: Some(generation),
                        route_id: Some(route_id),
                    },
                }),
                _ => None,
            };
            state.active_route_token = None;
            state.last_aborted_route = None;
            (active, pending)
        };
        let mut errors = Vec::new();
        let pending_started = if let Some(pending) = &pending {
            match pending
                .peer
                .start_physical_shutdown_with_meta(pending.meta, None)
            {
                Ok(()) => true,
                Err(error) => {
                    errors.push(error.to_string());
                    false
                }
            }
        } else {
            false
        };
        let active_started = if let Some(active) = &active {
            match active
                .peer
                .start_physical_shutdown_with_meta(active.meta, None)
            {
                Ok(()) => true,
                Err(error) => {
                    errors.push(error.to_string());
                    false
                }
            }
        } else {
            false
        };
        let root_meta = CleanupJobMeta {
            kind: "close-root",
            generation: Some(0),
            route_id: None,
        };
        let root_started = match self.start_physical_shutdown_with_meta(root_meta, None) {
            Ok(()) => true,
            Err(error) => {
                errors.push(error.to_string());
                false
            }
        };
        if pending_started {
            let pending = pending.expect("started pending cleanup has a peer");
            if let Err(error) = pending
                .peer
                .wait_physical_shutdown_with_retry(pending.meta)
                .await
            {
                errors.push(error.to_string());
            }
        }
        if active_started {
            let active = active.expect("started active cleanup has a peer");
            if let Err(error) = active
                .peer
                .wait_physical_shutdown_with_retry(active.meta)
                .await
            {
                errors.push(error.to_string());
            }
        }
        if root_started {
            if let Err(error) = self.wait_physical_shutdown_with_retry(root_meta).await {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(TransportError::Message(format!(
                "WebRTC shutdown failures: {}",
                errors.join("; ")
            )))
        }
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
        request_fingerprint: Option<[u8; 32]>,
    ) -> Result<(PeerConnectionConfig, Option<CleanupTarget>), TransportError> {
        let mut state = self.restart_state();
        if state.terminated {
            return Err(terminated_error());
        }
        let Some(expected_generation) = state.highest_seen_generation.checked_add(1) else {
            return Err(TransportError::Message(
                "restart generation exhausted; create a new session".into(),
            ));
        };
        if generation != expected_generation {
            if generation < expected_generation {
                return Err(stale_generation_error(generation, "restart request"));
            }
            return Err(TransportError::Message(format!(
                "invalid restart generation {generation}; expected generation {expected_generation}"
            )));
        }
        if generation <= state.active_generation {
            return Err(stale_generation_error(generation, "restart request"));
        }
        state.highest_seen_generation = generation;
        let config = state
            .active_replacement
            .as_ref()
            .map(|peer| peer.config.clone())
            .unwrap_or_else(|| self.config.clone());
        let loser = match state.pending.take() {
            Some(PendingRestart::Ready {
                generation,
                route_id,
                peer,
                ..
            }) => Some(CleanupTarget {
                peer,
                meta: CleanupJobMeta {
                    kind: "losing-restart",
                    generation: Some(generation),
                    route_id: Some(route_id),
                },
            }),
            _ => None,
        };
        state.pending = Some(PendingRestart::Building {
            generation,
            route_token,
            request_fingerprint,
        });
        Ok((config, loser))
    }

    fn finish_build(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
        peer: Arc<WebRtcPeerConnection>,
        local_description: SessionDescription,
        request_fingerprint: Option<[u8; 32]>,
    ) -> bool {
        let mut state = self.restart_state();
        let matches_pending = matches!(
            state.pending.as_ref(),
            Some(PendingRestart::Building {
                generation: pending,
                route_token: pending_token,
                ..
            }) if *pending == generation && pending_token == route_token
        );
        if matches_pending && generation > state.active_generation && !state.terminated {
            state.pending = Some(PendingRestart::Ready {
                generation,
                route_token: route_token.clone(),
                route_id: NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed),
                peer,
                local_description,
                request_fingerprint,
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
                ..
            }) if *pending == generation && pending_token == route_token
        ) {
            state.pending = None;
        }
    }

    fn detach_pending_restart(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
        route_id: Option<u64>,
    ) {
        let _ = self.abort_restart_bound(
            generation,
            route_token,
            route_id,
            "restart-validation-failed",
        );
    }

    fn abort_restart_bound(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
        route_id: Option<u64>,
        cleanup_kind: &'static str,
    ) -> Result<bool, TransportError> {
        let peer = {
            let mut state = self.restart_state();
            if state.terminated {
                return Err(terminated_error());
            }
            let matches = match state.pending.as_ref() {
                Some(PendingRestart::Building {
                    generation: pending_generation,
                    route_token: pending_token,
                    ..
                }) => {
                    route_id.is_none()
                        && *pending_generation == generation
                        && pending_token == route_token
                }
                Some(PendingRestart::Ready {
                    generation: pending_generation,
                    route_token: pending_token,
                    route_id: pending_route_id,
                    ..
                }) => {
                    *pending_generation == generation
                        && pending_token == route_token
                        && route_id.is_none_or(|route_id| route_id == *pending_route_id)
                }
                None => false,
            };
            if matches {
                let pending = state.pending.take().expect("matching pending route");
                state.last_aborted_route = Some((generation, route_token.clone()));
                match pending {
                    PendingRestart::Ready { route_id, peer, .. } => Some(CleanupTarget {
                        peer,
                        meta: CleanupJobMeta {
                            kind: cleanup_kind,
                            generation: Some(generation),
                            route_id: Some(route_id),
                        },
                    }),
                    PendingRestart::Building { .. } => None,
                }
            } else if state.last_aborted_route.as_ref().is_some_and(
                |(aborted_generation, aborted_token)| {
                    *aborted_generation == generation && aborted_token == route_token
                },
            ) && state.pending.is_none()
            {
                return Ok(false);
            } else {
                return Err(TransportError::Message(
                    "stale or losing restart route abort".into(),
                ));
            }
        };
        if let Some(peer) = peer {
            peer.peer
                .start_physical_shutdown_with_meta(peer.meta, None)?;
        }
        Ok(true)
    }

    fn restart_build_rejection(&self, generation: u64, context: &'static str) -> TransportError {
        if self.restart_state().terminated {
            terminated_error()
        } else {
            stale_generation_error(generation, context)
        }
    }

    #[cfg(not(test))]
    async fn wait_restart_build_gate_for_test(&self, _peer: &Arc<WebRtcPeerConnection>) {}

    #[cfg(test)]
    async fn wait_restart_build_gate_for_test(&self, peer: &Arc<WebRtcPeerConnection>) {
        *self
            .last_built_peer_for_test
            .lock()
            .expect("last built peer lock poisoned") = Some(Arc::downgrade(peer));
        let gate = self
            .restart_build_gate_for_test
            .lock()
            .expect("restart build gate lock poisoned")
            .clone();
        if let Some(gate) = gate {
            let _ = gate.acquire().await;
        }
    }

    #[cfg(test)]
    fn install_restart_build_gate_for_test(&self, gate: Arc<Semaphore>) {
        *self
            .restart_build_gate_for_test
            .lock()
            .expect("restart build gate lock poisoned") = Some(gate);
        *self
            .last_built_peer_for_test
            .lock()
            .expect("last built peer lock poisoned") = None;
    }

    #[cfg(test)]
    fn clear_restart_build_gate_for_test(&self) {
        *self
            .restart_build_gate_for_test
            .lock()
            .expect("restart build gate lock poisoned") = None;
    }

    #[cfg(test)]
    fn last_built_peer_for_test(&self) -> Option<Weak<WebRtcPeerConnection>> {
        self.last_built_peer_for_test
            .lock()
            .expect("last built peer lock poisoned")
            .clone()
    }

    #[cfg(test)]
    fn install_physical_close_gate_for_test(&self, gate: Arc<Semaphore>) {
        *self
            .physical_close_gate_for_test
            .lock()
            .expect("physical close gate lock poisoned") = Some(gate);
    }

    #[cfg(test)]
    fn install_shutdown_admission_hook_for_test(&self, hook: ShutdownAdmissionHook) {
        *self
            .shutdown_admission_hook_for_test
            .lock()
            .expect("shutdown admission hook lock poisoned") = Some(hook);
        self.concurrent_shutdown_observed_for_test
            .store(false, Ordering::Release);
    }

    #[cfg(test)]
    async fn wait_for_concurrent_shutdown_observer_for_test(&self) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !self
                .concurrent_shutdown_observed_for_test
                .load(Ordering::Acquire)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("concurrent shutdown caller observes admission window");
    }

    #[cfg(test)]
    fn set_physical_cleanup_timeout_for_test(&self, timeout: Duration) {
        self.physical_cleanup_timeout_ms_for_test.store(
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
    }

    #[cfg(test)]
    fn inject_physical_cleanup_panic_for_test(&self) {
        self.panic_cleanup_for_test.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn physical_shutdown_started_for_test(&self) -> bool {
        self.shutdown.is_started()
    }

    #[cfg(test)]
    fn physical_shutdown_finished_for_test(&self) -> bool {
        self.shutdown.is_finished()
    }

    #[cfg(test)]
    async fn wait_for_physical_shutdown_for_test(&self) {
        self.shutdown.wait_until_finished().await;
    }

    #[cfg(not(test))]
    async fn wait_restart_validation_gate_for_test(&self) {}

    #[cfg(test)]
    async fn wait_restart_validation_gate_for_test(&self) {
        self.restart_validation_entered_for_test
            .store(true, Ordering::Release);
        let gate = self
            .restart_validation_gate_for_test
            .lock()
            .expect("restart validation gate lock poisoned")
            .clone();
        if let Some(gate) = gate {
            let _ = gate.acquire().await;
        }
    }

    #[cfg(test)]
    fn install_restart_validation_gate_for_test(&self, gate: Arc<Semaphore>) {
        *self
            .restart_validation_gate_for_test
            .lock()
            .expect("restart validation gate lock poisoned") = Some(gate);
        self.restart_validation_entered_for_test
            .store(false, Ordering::Release);
    }

    #[cfg(test)]
    fn restart_validation_entered_for_test(&self) -> bool {
        self.restart_validation_entered_for_test
            .load(Ordering::Acquire)
    }

    fn existing_restart_description(
        &self,
        generation: u64,
        route_token: &RestartRouteToken,
        request_fingerprint: &[u8; 32],
    ) -> Result<Option<SessionDescription>, TransportError> {
        let state = self.restart_state();
        if state.terminated {
            return Err(terminated_error());
        }
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
                request_fingerprint: pending_fingerprint,
                ..
            }) if *pending_generation == generation
                && pending_token == route_token
                && pending_fingerprint.as_ref() == Some(request_fingerprint) =>
            {
                Ok(Some(local_description.clone()))
            }
            Some(PendingRestart::Ready {
                generation: pending_generation,
                route_token: pending_token,
                ..
            }) if *pending_generation == generation && pending_token == route_token => Err(
                TransportError::Message("restart route payload conflict".into()),
            ),
            Some(PendingRestart::Building {
                generation: pending_generation,
                route_token: pending_token,
                request_fingerprint: pending_fingerprint,
            }) if *pending_generation == generation
                && pending_token == route_token
                && pending_fingerprint.as_ref() == Some(request_fingerprint) =>
            {
                Err(TransportError::Message(format!(
                    "restart generation {generation} is still being built"
                )))
            }
            Some(PendingRestart::Building {
                generation: pending_generation,
                route_token: pending_token,
                ..
            }) if *pending_generation == generation && pending_token == route_token => Err(
                TransportError::Message("restart route payload conflict".into()),
            ),
            _ => Err(stale_generation_error(generation, "restart route")),
        }
    }

    fn ready_restart(
        &self,
        generation: u64,
    ) -> Result<(u64, RestartRouteToken, Arc<WebRtcPeerConnection>), TransportError> {
        let state = self.restart_state();
        if state.terminated {
            return Err(terminated_error());
        }
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
        if state.terminated {
            return Err(terminated_error());
        }
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
        if state.terminated {
            return Err(terminated_error());
        }
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
        if state.terminated {
            return Err(terminated_error());
        }
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
            let control = self.physical_snapshot()?.control;
            if let Some(channel) = control.channel(lane).await {
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

fn close_loser(loser: Option<CleanupTarget>) {
    if let Some(loser) = loser {
        close_route_best_effort(&loser.peer, loser.meta);
    }
}

fn enqueue_physical_cleanup(
    shutdown: Arc<PhysicalShutdown>,
    permit: CleanupPermit,
    payload: PhysicalCleanupPayload,
    meta: CleanupJobMeta,
    timeout: Duration,
    failure_counter: Option<Arc<AtomicU64>>,
) -> Result<(), (CleanupPermit, PhysicalCleanupPayload, String)> {
    let accepted_shutdown = Arc::clone(&shutdown);
    submit_cleanup(
        permit,
        meta,
        timeout,
        payload,
        move || accepted_shutdown.accepted(timeout),
        move |outcome| {
            let error = outcome.error_message();
            if error.is_some() {
                if let Some(counter) = failure_counter {
                    counter.fetch_add(1, Ordering::AcqRel);
                }
            }
            if outcome.is_quarantined() {
                shutdown.quarantine(
                    error.unwrap_or_else(|| "physical cleanup ownership quarantined".into()),
                );
            } else {
                shutdown.complete(error);
            }
        },
    )
    .map_err(|rejected| (rejected.permit, rejected.payload, rejected.reason))
}

impl CleanupPayload for PhysicalCleanupPayload {
    fn normal_cleanup(&mut self) -> CleanupPhase<'_> {
        Box::pin(async move {
            assert!(!self.injected_panic, "injected physical cleanup panic");
            if let Some(close_gate) = &self.close_gate {
                let _ = close_gate.acquire().await;
            }
            close_physical_payload(self).await?;
            if self.injected_failure {
                Err("physical cleanup reported a failure".into())
            } else {
                Ok(())
            }
        })
    }

    fn force_cleanup(&mut self) -> CleanupPhase<'_> {
        Box::pin(async move { close_physical_payload(self).await })
    }

    fn force_retry_safe(&self) -> bool {
        !self.pc_close_started
    }

    fn preserve_on_error(&self) -> bool {
        self.pc_close_started && !self.physical_closed
    }
}

async fn close_physical_payload(payload: &mut PhysicalCleanupPayload) -> Result<(), String> {
    let owners = payload
        .owners
        .as_mut()
        .ok_or_else(|| "physical cleanup owners missing".to_string())?;
    let tasks = {
        let mut tasks = owners
            .tasks
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        for task in tasks.iter() {
            task.abort();
        }
        std::mem::take(&mut *tasks)
    };
    for task in tasks {
        let _ = task.await;
    }
    owners.turn_stream_bridges.shutdown().await;
    // webrtc-rs retains private parsed ICE/agent copies which this crate cannot access. Replace
    // the public configuration copy again before close; the construction path already did this
    // immediately after the gatherer consumed its configuration.
    let _ = scrub_accessible_upstream_ice_servers(&owners.pc, RTCIceTransportPolicy::All).await;
    let close_channels = async {
        if let Some(channel) = owners.control.channel(ControlLane::Reliable).await {
            let _ = channel.close().await;
        }
        if let Some(channel) = owners.control.channel(ControlLane::Realtime).await {
            let _ = channel.close().await;
        }
        if let Some(channel) = owners.control.channel(ControlLane::Bulk).await {
            let _ = channel.close().await;
        }
    };
    payload.pc_close_started = true;
    let ((), close_result) = tokio::join!(close_channels, owners.pc.close());
    if owners.active_tasks.load(Ordering::Acquire) != 0 {
        return Err("tracked WebRTC tasks did not drain".into());
    }
    let _ = &owners.h264_sender;
    match close_result {
        Ok(()) => {
            payload.physical_closed = true;
            Ok(())
        }
        Err(_) if owners.pc.connection_state() == RTCPeerConnectionState::Closed => {
            payload.physical_closed = true;
            Ok(())
        }
        Err(_) => Err("close peer connection failed".to_string()),
    }
}

fn close_route_best_effort(peer: &WebRtcPeerConnection, meta: CleanupJobMeta) {
    let _ = peer.start_physical_shutdown_with_meta(meta, None);
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

fn terminated_error() -> TransportError {
    TransportError::Message("WebRTC session is terminated".into())
}

fn restart_offer_fingerprint(
    generation: u64,
    route_token: &RestartRouteToken,
    offer: &SessionDescription,
    ice_servers: &[IceServerConfig],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    fingerprint_field(&mut digest, b"mrd-restart-offer-v1");
    fingerprint_field(&mut digest, &generation.to_be_bytes());
    fingerprint_field(&mut digest, &route_token.0);
    fingerprint_field(
        &mut digest,
        &[match offer.kind {
            SessionDescriptionType::Offer => 1,
            SessionDescriptionType::Answer => 2,
        }],
    );
    fingerprint_field(&mut digest, offer.sdp.as_bytes());
    fingerprint_field(&mut digest, b"relay-only");
    fingerprint_field(&mut digest, &(ice_servers.len() as u64).to_be_bytes());
    for server in ice_servers {
        fingerprint_field(&mut digest, &(server.urls.len() as u64).to_be_bytes());
        for url in &server.urls {
            fingerprint_field(&mut digest, url.as_bytes());
        }
        fingerprint_field(&mut digest, server.username.as_bytes());
        fingerprint_field(&mut digest, server.credential.as_bytes());
    }
    digest.finalize().into()
}

fn fingerprint_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
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
        if server.urls.iter().any(|url| !is_public_turn_endpoint(url)) {
            return Err(TransportError::Message(
                "relay restart accepts only trusted turn: or turns: URLs".into(),
            ));
        }
    }
    Ok(())
}

fn secret_values(ice_servers: &[IceServerConfig]) -> SecretValues {
    ice_server_secret_values(ice_servers)
}

fn candidate_secret_values(candidate: &IceCandidate) -> SecretValues {
    let mut secrets = Zeroizing::new(vec![Zeroizing::new(candidate.candidate.clone())]);
    if let Some(username_fragment) = &candidate.username_fragment {
        secrets.push(Zeroizing::new(username_fragment.clone()));
    }
    let fields = candidate
        .candidate
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    for pair in fields.windows(2) {
        if pair[0].eq_ignore_ascii_case("ufrag") && !pair[1].is_empty() {
            secrets.push(Zeroizing::new(pair[1].to_owned()));
        }
    }
    normalize_secret_values(secrets)
}

fn redact_transport_error(error: TransportError, secrets: &SecretValues) -> TransportError {
    redact_error_with_secrets(error, secrets)
}

fn redact_sdp_error(error: TransportError, sdp: &str) -> TransportError {
    redact_transport_error(error, &sdp_secret_values(sdp))
}

fn sdp_secret_values(sdp: &str) -> SecretValues {
    Zeroizing::new(
        sdp.lines()
            .filter_map(|line| {
                line.strip_prefix("a=ice-ufrag:")
                    .or_else(|| line.strip_prefix("a=ice-pwd:"))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| Zeroizing::new(value.to_owned()))
            })
            .collect::<Vec<_>>(),
    )
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
    struct TaskGuard(Arc<AtomicUsize>);
    impl Drop for TaskGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    counter.fetch_add(1, Ordering::AcqRel);
    let guard = TaskGuard(Arc::clone(counter));
    tokio::spawn(async move {
        // Construct the guard before spawning so aborting a never-polled task still decrements the
        // physical task count when Tokio drops its captured future.
        let _guard = guard;
        future.await;
    })
}

fn peer_error(context: &'static str) -> impl FnOnce(webrtc::Error) -> TransportError {
    move |error| TransportError::Message(format!("{context} failed: {error}"))
}

async fn scrub_accessible_upstream_ice_servers(
    pc: &RTCPeerConnection,
    ice_transport_policy: RTCIceTransportPolicy,
) -> Result<(), webrtc::Error> {
    pc.set_configuration(RTCConfiguration {
        ice_servers: vec![RTCIceServer {
            urls: vec![SCRUBBED_ICE_SERVER_URL.into()],
            username: String::new(),
            credential: String::new(),
        }],
        ice_transport_policy,
        ..Default::default()
    })
    .await
}

fn peer_error_redacted<'a>(
    context: &'static str,
    secrets: &'a SecretValues,
) -> impl FnOnce(webrtc::Error) -> TransportError + 'a {
    move |error| redact_transport_error(peer_error(context)(error), secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn assert_zeroizing_owner<T: Zeroize + ZeroizeOnDrop>() {}

    fn assert_zeroizing_value<T: Zeroize + ZeroizeOnDrop>(_: &mut T) {}

    #[test]
    fn signaling_secret_owners_and_clones_zeroize_observably() {
        assert_zeroizing_owner::<RestartRouteToken>();
        assert_zeroizing_owner::<SessionDescription>();
        assert_zeroizing_owner::<IceCandidate>();

        let token_wire = "ab".repeat(RESTART_ROUTE_TOKEN_BYTES);
        let mut token = RestartRouteToken::from_wire(&token_wire).expect("route token");
        let mut description = SessionDescription::from_wire(
            SessionDescriptionType::Offer,
            "v=0\r\na=ice-ufrag:temporary-user\r\na=ice-pwd:temporary-password\r\n".into(),
            1,
            Some(&token_wire),
        )
        .expect("description");
        let mut description_clone = description.clone();
        let mut candidate = IceCandidate::from_wire(
            "candidate:1 1 udp 1 127.0.0.1 9 typ relay ufrag candidate-secret".into(),
            Some("data".into()),
            Some(0),
            Some("username-fragment-secret".into()),
            1,
            Some(&token_wire),
        )
        .expect("candidate");
        let mut candidate_clone = candidate.clone();
        let mut emitted_token = token.to_wire();
        assert_zeroizing_value(&mut emitted_token);

        token.zeroize();
        description.zeroize();
        description_clone.zeroize();
        candidate.zeroize();
        candidate_clone.zeroize();
        emitted_token.zeroize();

        assert_eq!(token.0, [0; RESTART_ROUTE_TOKEN_BYTES]);
        assert!(emitted_token.is_empty());
        for owner in [&description, &description_clone] {
            assert!(owner.sdp.is_empty());
            assert!(owner.restart_route_token.is_none());
        }
        for owner in [&candidate, &candidate_clone] {
            assert!(owner.candidate.is_empty());
            assert!(owner.sdp_mid.is_none());
            assert!(owner.username_fragment.is_none());
            assert!(owner.restart_route_token.is_none());
        }
    }

    #[test]
    fn temporary_upstream_ice_server_owner_zeroizes_observably() {
        assert_zeroizing_owner::<UpstreamIceServers>();
        let server = IceServerConfig::new(
            vec!["turn:relay.example.test:3478?transport=udp".into()],
            "temporary-upstream-user".into(),
            "temporary-upstream-credential".into(),
        );
        let mut owner = UpstreamIceServers::from_configs(&[server]);

        owner.zeroize();

        assert!(owner.0.is_empty());
    }

    #[test]
    fn relay_restart_rejects_every_credential_bearing_turn_url_component() {
        for malicious in [
            "turn:user:password@relay.example.test:3478?transport=udp",
            "turn:relay.example.test:3478/private-secret",
            "turn:relay.example.test:3478?api_key=query-secret",
            "turn:relay.example.test:3478?transport=udp&api_key=query-secret",
            "turn:relay.example.test:3478?transport=udp#fragment-secret",
        ] {
            let servers = [IceServerConfig::new(
                vec![malicious.into()],
                "ephemeral-user".into(),
                "ephemeral-credential".into(),
            )];
            assert!(
                validate_turn_servers(&servers).is_err(),
                "accepted credential-bearing TURN URL: {malicious}"
            );
        }
        assert!(validate_turn_servers(&[IceServerConfig::new(
            vec!["turn:relay.example.test:3478?transport=udp".into()],
            "ephemeral-user".into(),
            "ephemeral-credential".into(),
        )])
        .is_ok());
    }

    #[tokio::test]
    async fn peer_replaces_its_accessible_upstream_ice_server_configuration_copy() {
        let credential = "upstream-configuration-secret";
        let peer = WebRtcPeerConnection::new(PeerConnectionConfig {
            ice_servers: vec![IceServerConfig::new(
                vec!["turn:relay.example.test:3478?transport=udp".into()],
                "upstream-user-secret".into(),
                credential.into(),
            )],
            ..PeerConnectionConfig::default()
        })
        .await
        .expect("peer");
        let physical = peer.physical_pc_for_test().expect("physical PC");
        let upstream = physical.get_configuration().await;

        assert!(peer.config.ice_servers.is_empty());
        assert!(upstream.ice_servers.iter().all(|server| {
            server.username.is_empty()
                && server.credential.is_empty()
                && server.urls.iter().all(|url| !url.contains(credential))
        }));
        peer.close().await.expect("close peer");
    }

    #[tokio::test]
    async fn close_clears_owned_restart_tokens_before_the_peer_owner_drops() {
        let peer = WebRtcPeerConnection::new(PeerConnectionConfig::default())
            .await
            .expect("peer");
        {
            let mut state = peer.restart_state();
            state.active_route_token =
                Some(RestartRouteToken::from_wire(&"ab".repeat(32)).expect("active token"));
            state.last_aborted_route = Some((
                1,
                RestartRouteToken::from_wire(&"cd".repeat(32)).expect("aborted token"),
            ));
        }

        peer.close().await.expect("close peer");

        let state = peer.restart_state();
        assert!(state.active_route_token.is_none());
        assert!(state.last_aborted_route.is_none());
    }

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
        let secrets = normalize_secret_values(Zeroizing::new(vec![
            Zeroizing::new("temporary-user".into()),
            Zeroizing::new("temporary-password".into()),
        ]));
        let redacted = redact_transport_error(error, &secrets);
        let output = redacted.to_string();
        assert!(!output.contains("temporary-user"));
        assert!(!output.contains("temporary-password"));
        assert_eq!(output.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn transport_error_redaction_handles_overlapping_secrets_and_the_error_chain() {
        let server = IceServerConfig::new(
            vec!["turn:relay.example.test:3478?transport=udp".into()],
            "prefix".into(),
            "prefix-long-secret".into(),
        );
        let error = TransportError::Message(
            "TURN setup failed for prefix-long-secret owned by prefix".into(),
        );

        let redacted = redact_transport_error(error, &secret_values(&[server]));
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&redacted);
        while let Some(error) = source {
            let display = error.to_string();
            let debug = format!("{error:?}");
            for leaked in ["prefix", "long-secret"] {
                assert!(
                    !display.contains(leaked),
                    "Display leaked {leaked}: {display}"
                );
                assert!(!debug.contains(leaked), "Debug leaked {leaked}: {debug}");
            }
            source = error.source();
        }
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
            request_fingerprint: None,
            validated: false,
        });
        root_answerer.restart_state().pending = Some(PendingRestart::Ready {
            generation: 1,
            route_token,
            route_id: answer_route_id,
            peer: Arc::clone(&pending_answerer),
            local_description: bound_answer,
            request_fingerprint: None,
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

        assert_eq!(root_offerer.pending_restart_generation().await, None);
        assert_eq!(root_answerer.pending_restart_generation().await, None);
        assert!(pending_offerer.physical_shutdown_started_for_test());
        assert!(pending_answerer.physical_shutdown_started_for_test());
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
            terminated: false,
            active_generation: 9,
            highest_seen_generation: 9,
            active_route_token: Some(RestartRouteToken::generate().expect("route token")),
            active_route_id: Some(99),
            active_replacement: Some(Arc::clone(&peer)),
            pending: None,
            last_aborted_route: None,
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
        let route_secret = route_token.to_wire();
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
            request_fingerprint: None,
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
        let cleanup_snapshot = crate::cleanup_supervisor_snapshot();
        let cleanup_failure = cleanup_snapshot
            .recent_failures
            .iter()
            .rev()
            .find(|failure| failure.job_kind == "commit-old-route")
            .expect("global cleanup failure is observable");
        assert_eq!(cleanup_failure.job_kind, "commit-old-route");
        assert_eq!(cleanup_failure.generation, Some(0));
        assert_eq!(cleanup_failure.route_id_summary, None);
        assert!(!cleanup_failure.reason.contains(route_secret.as_str()));
        assert!(Arc::ptr_eq(
            &active.active_route().expect("published replacement"),
            &replacement
        ));
        let cleanup = active
            .close()
            .await
            .expect_err("later close still reports the recorded physical cleanup failure");
        assert!(cleanup.to_string().contains("cleanup job failed"));
    }

    #[tokio::test]
    async fn cancelled_commit_caller_cannot_cancel_old_route_cleanup_after_publication() {
        let active = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("active peer"),
        );
        let replacement = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("replacement peer"),
        );
        let route_token = RestartRouteToken::generate().expect("route token");
        let route_id = NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed);
        let mut description =
            SessionDescription::initial(SessionDescriptionType::Offer, "state-only".into());
        description.bind_restart(1, route_token.clone());
        active.restart_state().pending = Some(PendingRestart::Ready {
            generation: 1,
            route_token,
            route_id,
            peer: Arc::clone(&replacement),
            local_description: description,
            request_fingerprint: None,
            validated: true,
        });
        let gate = Arc::new(Semaphore::new(0));
        active.install_physical_close_gate_for_test(Arc::clone(&gate));
        active.fail_close_for_test.store(true, Ordering::Release);
        let evidence = RestartRouteEvidence {
            generation: 1,
            route_id,
            selected_pair: SelectedCandidatePairStats {
                local_candidate_id: "state-local".into(),
                remote_candidate_id: "state-remote".into(),
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
        let committing_peer = Arc::clone(&active);
        let commit = tokio::spawn(async move { committing_peer.commit_restart(1, evidence).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while active.current_generation().await != 1
                || !active.physical_shutdown_started_for_test()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("route published and cleanup transferred");

        commit.abort();
        assert!(commit.await.unwrap_err().is_cancelled());
        gate.add_permits(1);
        tokio::time::timeout(
            Duration::from_secs(5),
            active.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("old root cleanup finishes");

        assert_eq!(active.current_generation().await, 1);
        assert!(Arc::ptr_eq(
            &active.active_route().expect("published replacement"),
            &replacement
        ));
        assert_eq!(active.restart_cleanup_failure_count(), 1);
        let cleanup = active
            .close()
            .await
            .expect_err("recorded root cleanup failure remains observable");
        assert!(cleanup.to_string().contains("cleanup job failed"));
    }

    #[tokio::test]
    async fn cancelled_restart_build_removes_building_but_keeps_generation_consumed() {
        let peer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("peer"),
        );
        let gate = Arc::new(Semaphore::new(0));
        peer.install_restart_build_gate_for_test(Arc::clone(&gate));
        let building_peer = Arc::clone(&peer);
        let build = tokio::spawn(async move {
            building_peer
                .create_restart_offer(
                    1,
                    vec![IceServerConfig::new(
                        vec!["turn:relay.example.test:3478".into()],
                        "user".into(),
                        "credential".into(),
                    )],
                )
                .await
        });
        let built = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(built) = peer.last_built_peer_for_test() {
                    break built;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending physical peer built");

        build.abort();
        assert!(build.await.unwrap_err().is_cancelled());

        assert_eq!(peer.pending_restart_generation().await, None);
        assert_eq!(built.strong_count(), 0);
        let stale = peer
            .create_restart_offer(
                1,
                vec![IceServerConfig::new(
                    vec!["turn:relay.example.test:3478".into()],
                    "user".into(),
                    "credential".into(),
                )],
            )
            .await
            .expect_err("cancelled generation remains consumed");
        assert!(stale.to_string().contains("generation"));
        peer.clear_restart_build_gate_for_test();
        peer.create_restart_offer(
            2,
            vec![IceServerConfig::new(
                vec!["turn:relay.example.test:3478".into()],
                "user".into(),
                "credential".into(),
            )],
        )
        .await
        .expect("next generation can proceed");
        peer.close().await.expect("close peer");
    }

    #[tokio::test]
    async fn maximum_generation_exhausts_the_session_without_wrapping() {
        let peer = WebRtcPeerConnection::new(PeerConnectionConfig::default())
            .await
            .expect("peer");
        peer.restart_state().highest_seen_generation = u64::MAX;

        let error = peer
            .create_restart_offer(
                u64::MAX,
                vec![IceServerConfig::new(
                    vec!["turn:relay.example.test:3478".into()],
                    "user".into(),
                    "credential".into(),
                )],
            )
            .await
            .expect_err("generation counter cannot wrap");

        assert!(error.to_string().contains("exhausted"));
        assert_eq!(peer.pending_restart_generation().await, None);
        peer.close().await.expect("close peer");
    }

    #[tokio::test]
    async fn close_racing_a_blocked_build_cannot_leave_a_pending_peer() {
        let peer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("peer"),
        );
        let gate = Arc::new(Semaphore::new(0));
        peer.install_restart_build_gate_for_test(Arc::clone(&gate));
        let building_peer = Arc::clone(&peer);
        let build = tokio::spawn(async move {
            building_peer
                .create_restart_offer(
                    1,
                    vec![IceServerConfig::new(
                        vec!["turn:relay.example.test:3478".into()],
                        "user".into(),
                        "credential".into(),
                    )],
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while peer.last_built_peer_for_test().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending physical peer built");

        peer.close().await.expect("close wins termination race");
        gate.add_permits(1);
        let error = build
            .await
            .expect("build task joins")
            .expect_err("terminated build cannot publish");

        assert!(error.to_string().contains("terminated"));
        assert_eq!(peer.pending_restart_generation().await, None);
    }

    #[tokio::test]
    async fn cancelled_close_caller_does_not_cancel_physical_shutdown() {
        let peer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("peer"),
        );
        let pc = peer.physical_pc_for_test().expect("physical PC");
        let gate = Arc::new(Semaphore::new(0));
        peer.install_physical_close_gate_for_test(Arc::clone(&gate));
        let closing_peer = Arc::clone(&peer);
        let caller = tokio::spawn(async move { closing_peer.close().await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !peer.physical_shutdown_started_for_test() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown task starts");

        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(!peer.physical_shutdown_finished_for_test());
        gate.add_permits(1);
        tokio::time::timeout(
            Duration::from_secs(5),
            peer.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("detached shutdown finishes after caller cancellation");
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
    }

    #[tokio::test]
    async fn pc_close_future_survives_cleanup_deadline_without_reentry() {
        let _serial = BLOCKING_CLOSE_TEST_LOCK.lock().await;
        let supervisor = CleanupSupervisor::start_for_test(1, 2).expect("cleanup supervisor");
        let entered = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Semaphore::new(0));
        let close_calls = Arc::new(AtomicUsize::new(0));
        let peer = WebRtcPeerConnection::new_with_blocking_close_interceptor_for_test(
            PeerConnectionConfig::default(),
            Arc::clone(&supervisor),
            BlockingCloseInterceptorHook {
                entered: Arc::clone(&entered),
                gate: Arc::clone(&gate),
                calls: Arc::clone(&close_calls),
            },
        )
        .await
        .expect("peer with blocking close interceptor");
        let physical = peer.physical_snapshot().expect("physical owners");
        let pc = physical.pc;
        let active_tasks = physical.active_tasks;
        peer.set_physical_cleanup_timeout_for_test(Duration::from_millis(20));

        let error = tokio::time::timeout(Duration::from_secs(1), peer.close())
            .await
            .expect("caller cleanup deadline is bounded")
            .expect_err("physical close remains in progress at the caller deadline");
        assert!(error.to_string().contains("in progress"));
        assert!(entered.load(Ordering::Acquire));
        assert!(matches!(
            &peer
                .shutdown
                .lifecycle
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .state,
            PhysicalShutdownState::Closing { .. }
        ));
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::New);
        assert_eq!(supervisor.snapshot().available_admission_slots, 1);
        assert_eq!(close_calls.load(Ordering::Acquire), 1);

        let other = WebRtcPeerConnection::new_with_cleanup_supervisor_for_test(
            PeerConnectionConfig::default(),
            Arc::clone(&supervisor),
        )
        .await
        .expect("second peer is admitted while the first close remains pending");
        let other_pc = other.physical_pc_for_test().expect("second physical PC");
        tokio::time::timeout(Duration::from_secs(1), other.close())
            .await
            .expect("one pending close does not block the fixed worker event loop")
            .expect("second physical close");
        assert_eq!(other_pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(supervisor.snapshot().available_admission_slots, 1);

        gate.add_permits(1);
        tokio::time::timeout(
            Duration::from_secs(5),
            peer.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("the original close future resumes after the interceptor barrier");
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(active_tasks.load(Ordering::Acquire), 0);
        assert_eq!(supervisor.snapshot().available_admission_slots, 2);
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        peer.close().await.expect("completed close is idempotent");
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        supervisor.shutdown_for_test();
    }

    #[tokio::test]
    async fn capacity_one_releases_each_permit_only_after_the_same_close_future_finishes() {
        let _serial = BLOCKING_CLOSE_TEST_LOCK.lock().await;
        const ROUNDS: usize = 16;
        let supervisor = CleanupSupervisor::start_for_test(1, 1).expect("cleanup supervisor");

        for round in 0..ROUNDS {
            let entered = Arc::new(AtomicBool::new(false));
            let gate = Arc::new(Semaphore::new(0));
            let close_calls = Arc::new(AtomicUsize::new(0));
            let peer = WebRtcPeerConnection::new_with_blocking_close_interceptor_for_test(
                PeerConnectionConfig::default(),
                Arc::clone(&supervisor),
                BlockingCloseInterceptorHook {
                    entered: Arc::clone(&entered),
                    gate: Arc::clone(&gate),
                    calls: Arc::clone(&close_calls),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("round {round} peer admission failed: {error}"));
            let physical = peer.physical_snapshot().expect("physical owners");
            peer.set_physical_cleanup_timeout_for_test(Duration::from_millis(10));

            let error = tokio::time::timeout(Duration::from_secs(1), peer.close())
                .await
                .unwrap_or_else(|error| panic!("round {round} caller was unbounded: {error}"))
                .expect_err("blocked physical close remains in progress");
            assert!(error.to_string().contains("in progress"));
            assert!(entered.load(Ordering::Acquire));
            assert_eq!(close_calls.load(Ordering::Acquire), 1);
            assert_eq!(supervisor.snapshot().available_admission_slots, 0);
            assert_eq!(physical.pc.connection_state(), RTCPeerConnectionState::New);

            gate.add_permits(1);
            tokio::time::timeout(
                Duration::from_secs(5),
                peer.wait_for_physical_shutdown_for_test(),
            )
            .await
            .unwrap_or_else(|error| panic!("round {round} physical close stalled: {error}"));
            assert_eq!(
                physical.pc.connection_state(),
                RTCPeerConnectionState::Closed
            );
            assert_eq!(physical.active_tasks.load(Ordering::Acquire), 0);
            assert_eq!(close_calls.load(Ordering::Acquire), 1);
            assert_eq!(supervisor.snapshot().available_admission_slots, 1);
            peer.close().await.expect("completed close is idempotent");
            assert_eq!(close_calls.load(Ordering::Acquire), 1);
        }

        assert_eq!(supervisor.snapshot().completed_jobs, ROUNDS as u64);
        supervisor.shutdown_for_test();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_close_waits_through_the_take_to_acceptance_window() {
        let _serial = BLOCKING_CLOSE_TEST_LOCK.lock().await;
        let supervisor = CleanupSupervisor::start_for_test(1, 1).expect("cleanup supervisor");
        let close_entered = Arc::new(AtomicBool::new(false));
        let close_gate = Arc::new(Semaphore::new(0));
        let close_calls = Arc::new(AtomicUsize::new(0));
        let peer = Arc::new(
            WebRtcPeerConnection::new_with_blocking_close_interceptor_for_test(
                PeerConnectionConfig::default(),
                Arc::clone(&supervisor),
                BlockingCloseInterceptorHook {
                    entered: Arc::clone(&close_entered),
                    gate: Arc::clone(&close_gate),
                    calls: Arc::clone(&close_calls),
                },
            )
            .await
            .expect("peer"),
        );
        let physical = peer.physical_snapshot().expect("physical owners");
        let pc = physical.pc;
        let active_tasks = physical.active_tasks;
        peer.set_physical_cleanup_timeout_for_test(Duration::from_millis(30));
        let admission_entered = Arc::new(Barrier::new(2));
        let admission_release = Arc::new(Barrier::new(2));
        peer.install_shutdown_admission_hook_for_test(ShutdownAdmissionHook {
            entered: Arc::clone(&admission_entered),
            release: Arc::clone(&admission_release),
            action: ShutdownAdmissionAction::Accept,
        });

        let first_peer = Arc::clone(&peer);
        let first = tokio::spawn(async move { first_peer.close().await });
        tokio::task::spawn_blocking(move || admission_entered.wait())
            .await
            .expect("first caller reaches the admission window");
        let second_peer = Arc::clone(&peer);
        let mut second = tokio::spawn(async move { second_peer.close().await });
        peer.wait_for_concurrent_shutdown_observer_for_test().await;
        tokio::task::spawn_blocking(move || admission_release.wait())
            .await
            .expect("release cleanup admission");

        let first_error = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("first close is bounded")
            .expect("first close task")
            .expect_err("blocked physical cleanup remains in progress");
        assert!(first_error.to_string().contains("in progress"));
        let second_before_physical_release =
            tokio::time::timeout(Duration::from_millis(150), &mut second).await;

        close_gate.add_permits(1);
        if second_before_physical_release.is_err() {
            second
                .await
                .expect("second close task after physical release")
                .expect("physical release completes the old waiting caller");
        }
        tokio::time::timeout(
            Duration::from_secs(5),
            peer.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("same physical close eventually completes");
        assert!(close_entered.load(Ordering::Acquire));
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(active_tasks.load(Ordering::Acquire), 0);
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert_eq!(supervisor.snapshot().available_admission_slots, 1);
        supervisor.shutdown_for_test();

        let second_result = second_before_physical_release
            .expect("concurrent close must not wait for physical completion")
            .expect("second close task");
        let second_error = second_result.expect_err("concurrent close reports in progress");
        assert!(second_error.to_string().contains("in progress"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rejected_shutdown_admission_restores_ownership_and_wakes_a_retrying_caller() {
        let _serial = BLOCKING_CLOSE_TEST_LOCK.lock().await;
        let supervisor = CleanupSupervisor::start_for_test(1, 1).expect("cleanup supervisor");
        let close_entered = Arc::new(AtomicBool::new(false));
        let close_gate = Arc::new(Semaphore::new(0));
        let close_calls = Arc::new(AtomicUsize::new(0));
        let peer = Arc::new(
            WebRtcPeerConnection::new_with_blocking_close_interceptor_for_test(
                PeerConnectionConfig::default(),
                Arc::clone(&supervisor),
                BlockingCloseInterceptorHook {
                    entered: Arc::clone(&close_entered),
                    gate: Arc::clone(&close_gate),
                    calls: Arc::clone(&close_calls),
                },
            )
            .await
            .expect("peer"),
        );
        let physical = peer.physical_snapshot().expect("physical owners");
        let pc = physical.pc;
        let active_tasks = physical.active_tasks;
        peer.set_physical_cleanup_timeout_for_test(Duration::from_millis(30));
        let admission_entered = Arc::new(Barrier::new(2));
        let admission_release = Arc::new(Barrier::new(2));
        peer.install_shutdown_admission_hook_for_test(ShutdownAdmissionHook {
            entered: Arc::clone(&admission_entered),
            release: Arc::clone(&admission_release),
            action: ShutdownAdmissionAction::Reject,
        });

        let first_peer = Arc::clone(&peer);
        let first = tokio::spawn(async move { first_peer.close().await });
        tokio::task::spawn_blocking(move || admission_entered.wait())
            .await
            .expect("first caller reaches the admission window");
        let second_peer = Arc::clone(&peer);
        let mut second = tokio::spawn(async move { second_peer.close().await });
        peer.wait_for_concurrent_shutdown_observer_for_test().await;
        tokio::task::spawn_blocking(move || admission_release.wait())
            .await
            .expect("reject first cleanup admission");

        let first_error = first
            .await
            .expect("first close task")
            .expect_err("injected admission is rejected");
        assert!(first_error.to_string().contains("admission rejection"));
        let second_before_physical_release =
            tokio::time::timeout(Duration::from_millis(150), &mut second).await;

        close_gate.add_permits(1);
        if second_before_physical_release.is_err() {
            second.abort();
            let _ = second.await;
            peer.close()
                .await
                .expect("fallback cleanup after RED timeout");
        }
        tokio::time::timeout(
            Duration::from_secs(5),
            peer.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("retried physical cleanup completes");
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(active_tasks.load(Ordering::Acquire), 0);
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert_eq!(supervisor.snapshot().available_admission_slots, 1);
        supervisor.shutdown_for_test();

        let second_result = second_before_physical_release
            .expect("waiting caller is notified and retries admission")
            .expect("second close task");
        let second_error = second_result.expect_err("retried cleanup remains in progress");
        assert!(second_error.to_string().contains("in progress"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn panicked_shutdown_admission_rolls_back_and_wakes_a_retrying_caller() {
        let _serial = BLOCKING_CLOSE_TEST_LOCK.lock().await;
        let supervisor = CleanupSupervisor::start_for_test(1, 1).expect("cleanup supervisor");
        let close_entered = Arc::new(AtomicBool::new(false));
        let close_gate = Arc::new(Semaphore::new(0));
        let close_calls = Arc::new(AtomicUsize::new(0));
        let peer = Arc::new(
            WebRtcPeerConnection::new_with_blocking_close_interceptor_for_test(
                PeerConnectionConfig::default(),
                Arc::clone(&supervisor),
                BlockingCloseInterceptorHook {
                    entered: Arc::clone(&close_entered),
                    gate: Arc::clone(&close_gate),
                    calls: Arc::clone(&close_calls),
                },
            )
            .await
            .expect("peer"),
        );
        let physical = peer.physical_snapshot().expect("physical owners");
        let pc = physical.pc;
        let active_tasks = physical.active_tasks;
        peer.set_physical_cleanup_timeout_for_test(Duration::from_millis(30));
        let admission_entered = Arc::new(Barrier::new(2));
        let admission_release = Arc::new(Barrier::new(2));
        peer.install_shutdown_admission_hook_for_test(ShutdownAdmissionHook {
            entered: Arc::clone(&admission_entered),
            release: Arc::clone(&admission_release),
            action: ShutdownAdmissionAction::Panic,
        });

        let first_peer = Arc::clone(&peer);
        let first = tokio::spawn(async move { first_peer.close().await });
        tokio::task::spawn_blocking(move || admission_entered.wait())
            .await
            .expect("first caller reaches the admission window");
        let second_peer = Arc::clone(&peer);
        let second = tokio::spawn(async move { second_peer.close().await });
        peer.wait_for_concurrent_shutdown_observer_for_test().await;
        tokio::task::spawn_blocking(move || admission_release.wait())
            .await
            .expect("panic first cleanup admission");

        assert!(first.await.expect_err("first close panics").is_panic());
        let second_error = tokio::time::timeout(Duration::from_millis(150), second)
            .await
            .expect("waiting caller is notified and retries after unwind")
            .expect("second close task")
            .expect_err("retried cleanup remains in progress");
        assert!(second_error.to_string().contains("in progress"));

        close_gate.add_permits(1);
        tokio::time::timeout(
            Duration::from_secs(5),
            peer.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("physical cleanup completes after admission panic rollback");
        assert!(close_entered.load(Ordering::Acquire));
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(active_tasks.load(Ordering::Acquire), 0);
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert_eq!(supervisor.snapshot().available_admission_slots, 1);
        supervisor.shutdown_for_test();
    }

    #[tokio::test]
    async fn physical_cleanup_deadline_reports_in_progress_and_panic_quarantines() {
        let timed_out = WebRtcPeerConnection::new(PeerConnectionConfig::default())
            .await
            .expect("timeout peer");
        let timed_out_physical = timed_out
            .physical_snapshot()
            .expect("timeout physical owners");
        let timed_out_pc = timed_out_physical.pc;
        let timed_out_active_tasks = timed_out_physical.active_tasks;
        let timeout_gate = Arc::new(Semaphore::new(0));
        timed_out.install_physical_close_gate_for_test(Arc::clone(&timeout_gate));
        timed_out.set_physical_cleanup_timeout_for_test(Duration::from_millis(20));
        let error = tokio::time::timeout(Duration::from_secs(2), timed_out.close())
            .await
            .expect("caller wait remains bounded")
            .expect_err("pending physical cleanup is reported");
        assert!(error.to_string().contains("in progress"));
        assert!(!timed_out.physical_shutdown_finished_for_test());
        assert_eq!(timed_out_pc.connection_state(), RTCPeerConnectionState::New);
        timeout_gate.add_permits(1);
        tokio::time::timeout(
            Duration::from_secs(5),
            timed_out.wait_for_physical_shutdown_for_test(),
        )
        .await
        .expect("pre-close deadline does not cancel eventual physical teardown");
        assert_eq!(
            timed_out_pc.connection_state(),
            RTCPeerConnectionState::Closed,
            "timeout completion must follow a force phase that physically closes the PC"
        );
        assert_eq!(
            timed_out_active_tasks.load(Ordering::Acquire),
            0,
            "timeout force phase must abort and drain every tracked task"
        );
        let second = tokio::time::timeout(Duration::from_secs(1), timed_out.close())
            .await
            .expect("second close is bounded and idempotent");
        assert!(second.is_ok(), "completed physical close is successful");

        let supervisor = CleanupSupervisor::start_for_test(1, 1).expect("panic supervisor");
        let panicked = WebRtcPeerConnection::new_with_cleanup_supervisor_for_test(
            PeerConnectionConfig::default(),
            Arc::clone(&supervisor),
        )
        .await
        .expect("panic peer");
        let panicked_physical = panicked.physical_snapshot().expect("panic physical owners");
        let panicked_pc = panicked_physical.pc;
        let panicked_active_tasks = panicked_physical.active_tasks;
        panicked.inject_physical_cleanup_panic_for_test();
        let error = tokio::time::timeout(Duration::from_secs(2), panicked.close())
            .await
            .expect("quarantine completes the caller wait")
            .expect_err("panicked cleanup is reported");
        assert!(error.to_string().contains("panicked"));
        assert!(error.to_string().contains("quarantined"));
        assert!(!panicked.physical_shutdown_finished_for_test());
        assert!(matches!(
            &panicked
                .shutdown
                .lifecycle
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .state,
            PhysicalShutdownState::Quarantined { .. }
        ));
        assert_eq!(panicked_pc.connection_state(), RTCPeerConnectionState::New);
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.quarantined_jobs, 1);
        assert_eq!(snapshot.ownership_registry_depth, 1);
        assert_eq!(snapshot.available_admission_slots, 0);
        supervisor.release_quarantined_for_test();
        tokio::time::timeout(Duration::from_secs(1), async {
            while panicked_active_tasks.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test quarantine release drains captured tasks");
        supervisor.shutdown_for_test();
    }

    #[test]
    fn terminate_without_an_ambient_runtime_uses_owned_fallback_cleanup() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("setup runtime");
        let peer = runtime
            .block_on(WebRtcPeerConnection::new(PeerConnectionConfig::default()))
            .expect("peer");
        let physical = peer.physical_snapshot().expect("physical owners");
        let pc = physical.pc;
        let active_tasks = physical.active_tasks;
        drop(runtime);

        peer.terminate_now();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !peer.physical_shutdown_finished_for_test() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(peer.physical_shutdown_finished_for_test());
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(active_tasks.load(Ordering::Acquire), 0);
    }

    #[test]
    fn shutdown_started_inside_a_dropped_runtime_still_reaches_closed() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("setup runtime");
        let peer = Arc::new(
            runtime
                .block_on(WebRtcPeerConnection::new(PeerConnectionConfig::default()))
                .expect("peer"),
        );
        let physical = peer.physical_snapshot().expect("physical owners");
        let pc = physical.pc;
        let active_tasks = physical.active_tasks;
        let gate = Arc::new(Semaphore::new(0));
        peer.install_physical_close_gate_for_test(Arc::clone(&gate));
        let closing_peer = Arc::clone(&peer);
        runtime.block_on(async move {
            tokio::spawn(async move {
                let _ = closing_peer.close().await;
            });
            tokio::task::yield_now().await;
        });
        assert!(peer.physical_shutdown_started_for_test());

        drop(runtime);
        gate.add_permits(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !peer.physical_shutdown_finished_for_test() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }

        assert!(peer.physical_shutdown_finished_for_test());
        assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(active_tasks.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn blocked_losing_route_cleanup_does_not_block_the_next_build() {
        let peer = WebRtcPeerConnection::new(PeerConnectionConfig::default())
            .await
            .expect("peer");
        peer.create_restart_offer(
            1,
            vec![IceServerConfig::new(
                vec!["turn:relay.example.test:3478".into()],
                "user".into(),
                "credential".into(),
            )],
        )
        .await
        .expect("first pending route");
        let loser = peer
            .last_built_peer_for_test()
            .and_then(|peer| peer.upgrade())
            .expect("losing peer");
        let gate = Arc::new(Semaphore::new(0));
        loser.install_physical_close_gate_for_test(Arc::clone(&gate));

        let second = tokio::time::timeout(
            Duration::from_millis(250),
            peer.create_restart_offer(
                2,
                vec![IceServerConfig::new(
                    vec!["turn:relay.example.test:3478".into()],
                    "user".into(),
                    "credential".into(),
                )],
            ),
        )
        .await
        .expect("loser cleanup must be handed off before building generation two")
        .expect("generation two offer");

        assert_eq!(second.generation(), 2);
        assert!(loser.physical_shutdown_started_for_test());
        gate.add_permits(1);
        peer.close().await.expect("close peer");
    }

    #[tokio::test]
    async fn cleanup_pressure_uses_fixed_workers_and_eventually_converges() {
        let supervisor = CleanupSupervisor::start_for_test(1, 2).expect("cleanup supervisor");
        let first = WebRtcPeerConnection::new_with_cleanup_supervisor_for_test(
            PeerConnectionConfig::default(),
            Arc::clone(&supervisor),
        )
        .await
        .expect("first admitted peer");
        let second = WebRtcPeerConnection::new_with_cleanup_supervisor_for_test(
            PeerConnectionConfig::default(),
            Arc::clone(&supervisor),
        )
        .await
        .expect("second admitted peer");
        let first_snapshot = first.physical_snapshot().expect("first physical owners");
        let second_snapshot = second.physical_snapshot().expect("second physical owners");

        let third = tokio::time::timeout(
            Duration::from_secs(3),
            WebRtcPeerConnection::new_with_cleanup_supervisor_for_test(
                PeerConnectionConfig::default(),
                Arc::clone(&supervisor),
            ),
        )
        .await
        .expect("capacity refusal is bounded")
        .expect_err("the third peer must be rejected before constructing a physical PC");
        assert!(third.to_string().contains("capacity admission timed out"));
        assert_eq!(supervisor.snapshot().available_admission_slots, 0);

        first.terminate_now();
        second.terminate_now();
        tokio::time::timeout(Duration::from_secs(5), async {
            let (first_result, second_result) =
                tokio::join!(first.shutdown.wait(), second.shutdown.wait());
            first_result.expect("first physical cleanup");
            second_result.expect("second physical cleanup");
        })
        .await
        .expect("reserved cleanup jobs converge");

        assert_eq!(
            first_snapshot.pc.connection_state(),
            RTCPeerConnectionState::Closed
        );
        assert_eq!(
            second_snapshot.pc.connection_state(),
            RTCPeerConnectionState::Closed
        );
        assert_eq!(first_snapshot.active_tasks.load(Ordering::Acquire), 0);
        assert_eq!(second_snapshot.active_tasks.load(Ordering::Acquire), 0);
        let after = supervisor.snapshot();
        assert_eq!(after.available_admission_slots, 2);
        assert_eq!(after.worker_count, 1);
        assert_eq!(after.queue_capacity, 2);
        assert_eq!(after.admission_capacity, 2);
        assert_eq!(after.queue_depth, 0);
        assert_eq!(after.active_jobs, 0);
        assert_eq!(after.saturated_jobs, 0);
        assert_eq!(after.completed_jobs, 2);
        supervisor.shutdown_for_test();
    }

    #[tokio::test]
    async fn cancelled_partial_construction_is_handed_to_the_supervisor() {
        let before = crate::cleanup_supervisor_snapshot();
        let entered = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Semaphore::new(0));
        let build = tokio::spawn(WebRtcPeerConnection::new_blocked_after_pc_for_test(
            PeerConnectionConfig::default(),
            Arc::clone(&entered),
            Arc::clone(&gate),
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("constructor reached the guarded partial peer");

        build.abort();
        assert!(build.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), async {
            while crate::cleanup_supervisor_snapshot().completed_jobs <= before.completed_jobs {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("partial peer cleanup completes independently");

        let after = crate::cleanup_supervisor_snapshot();
        assert!(after.submitted_jobs > before.submitted_jobs);
        assert_eq!(after.worker_count, 2);
    }

    #[tokio::test]
    async fn cancelled_validation_detaches_and_cleans_only_its_bound_route() {
        let peer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("peer"),
        );
        peer.create_restart_offer(
            1,
            vec![IceServerConfig::new(
                vec!["turn:relay.example.test:3478".into()],
                "user".into(),
                "credential".into(),
            )],
        )
        .await
        .expect("pending route");
        let pending = peer
            .last_built_peer_for_test()
            .and_then(|pending| pending.upgrade())
            .expect("pending physical peer");
        let gate = Arc::new(Semaphore::new(0));
        peer.install_restart_validation_gate_for_test(Arc::clone(&gate));
        let validating_peer = Arc::clone(&peer);
        let validation =
            tokio::spawn(async move { validating_peer.validate_pending_restart(1).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !peer.restart_validation_entered_for_test() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("validation entered route-bound section");

        validation.abort();
        assert!(validation.await.unwrap_err().is_cancelled());

        assert_eq!(peer.pending_restart_generation().await, None);
        assert!(pending.physical_shutdown_started_for_test());
        peer.create_restart_offer(
            2,
            vec![IceServerConfig::new(
                vec!["turn:relay.example.test:3478".into()],
                "user".into(),
                "credential".into(),
            )],
        )
        .await
        .expect("new generation survives stale validation cleanup");
        gate.add_permits(1);
        peer.close().await.expect("close peer");
    }

    #[tokio::test]
    async fn close_starts_all_resource_cleanup_before_reporting_aggregate_error() {
        let root = WebRtcPeerConnection::new(PeerConnectionConfig::default())
            .await
            .expect("root");
        let active = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("active"),
        );
        let pending = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig::default())
                .await
                .expect("pending"),
        );
        let root_pc = root.physical_pc_for_test().expect("root PC");
        let pending_pc = pending.physical_pc_for_test().expect("pending PC");
        active.fail_close_for_test.store(true, Ordering::Release);
        let route_token = RestartRouteToken::generate().expect("route token");
        let mut description =
            SessionDescription::initial(SessionDescriptionType::Offer, "state-only".into());
        description.bind_restart(2, route_token.clone());
        {
            let mut state = root.restart_state();
            state.active_generation = 1;
            state.highest_seen_generation = 2;
            state.active_route_token = Some(RestartRouteToken::generate().expect("active token"));
            state.active_route_id = Some(1);
            state.active_replacement = Some(Arc::clone(&active));
            state.pending = Some(PendingRestart::Ready {
                generation: 2,
                route_token,
                route_id: NEXT_RESTART_ROUTE_ID.fetch_add(1, Ordering::Relaxed),
                peer: Arc::clone(&pending),
                local_description: description,
                request_fingerprint: None,
                validated: false,
            });
        }

        let error = root.close().await.expect_err("one cleanup reports failure");

        assert!(error.to_string().contains("cleanup job failed"));
        assert!(root.physical_shutdown_finished_for_test());
        assert!(active.physical_shutdown_finished_for_test());
        assert!(pending.physical_shutdown_finished_for_test());
        assert_eq!(root_pc.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(
            pending_pc.connection_state(),
            RTCPeerConnectionState::Closed
        );
    }
}
