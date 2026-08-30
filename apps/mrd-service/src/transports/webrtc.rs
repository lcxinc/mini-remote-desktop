use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use crate::relay::{urls_digest, RelayRouteEvidence};
use anyhow::{bail, Result};
use bytes::Bytes;
use mrd_application::ports::{
    TransportEnvelope, TransportLane, TransportMuxPort, TransportRouteKind, TransportRouteSnapshot,
    TransportSendOutcome, VideoEnvelopeMetadata,
};
use mrd_pipeline_core::{EncodedAccessUnit, VideoCodec};
use mrd_proto::SessionId;
use mrd_transport_webrtc::{
    CandidateKind, ControlLane, IceCandidate, IceServerConfig, IceTransportPolicy,
    PeerConnectionConfig, RestartRouteEvidence, SelectedCandidatePairStats, SessionDescription,
    WebRtcPeerConnection,
};
use thiserror::Error;
use tokio::sync::{watch, Mutex, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{quic, SessionMuxCore, TransportMuxConfig};

const DATA_FRAGMENT_MAGIC: &[u8; 4] = b"MRDF";
const DATA_FRAGMENT_VERSION: u8 = 1;
const DATA_FRAGMENT_HEADER_LEN: usize = 4 + 1 + 8 + 2 + 2 + 4;
const DATA_FRAGMENT_PAYLOAD_LEN: usize = 60 * 1024;
const MAX_ENVELOPE_WIRE_OVERHEAD: usize = 38 + u16::MAX as usize + u8::MAX as usize;
const DATA_CHANNEL_WIRE_BUDGET_OVERHEAD: usize = 128 * 1024;

#[derive(Debug, Error)]
pub enum ServiceWebRtcTransportError {
    #[error("WebRTC session {0:?} already exists")]
    DuplicateSession(SessionId),
    #[error("WebRTC session {0:?} was not found")]
    SessionNotFound(SessionId),
    #[error("WebRTC transport failed: {0}")]
    Transport(String),
    #[error("WebRTC replacement plan is invalid")]
    InvalidReplacement,
    #[error("WebRTC replacement evidence does not match the planned relay")]
    ReplacementEvidenceMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayUrlClass {
    TurnUdp,
    TurnTcp,
    TurnsTcp,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ServiceTurnRelayCredentials {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
    pub expires_at_unix_seconds: u64,
}

impl fmt::Debug for ServiceTurnRelayCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceTurnRelayCredentials")
            .field("url_classes", &self.url_classes())
            .field("username", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

impl ServiceTurnRelayCredentials {
    pub fn apply_relay_only(&self, mut config: PeerConnectionConfig) -> PeerConnectionConfig {
        config.ice_servers = vec![IceServerConfig::new(
            self.urls.clone(),
            self.username.clone(),
            self.credential.clone(),
        )];
        config.ice_transport_policy = IceTransportPolicy::Relay;
        config
    }

    pub fn url_classes(&self) -> Vec<RelayUrlClass> {
        self.urls
            .iter()
            .map(|url| {
                if url.starts_with("turns:") {
                    RelayUrlClass::TurnsTcp
                } else if url.starts_with("turn:") && url.contains("transport=tcp") {
                    RelayUrlClass::TurnTcp
                } else if url.starts_with("turn:") && url.contains("transport=udp") {
                    RelayUrlClass::TurnUdp
                } else {
                    RelayUrlClass::Unknown
                }
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct ServiceWebRtcTransportHost {
    sessions: RwLock<HashMap<SessionId, ServiceWebRtcSession>>,
}

#[derive(Debug, Clone)]
struct ServiceWebRtcSession {
    peer: Arc<WebRtcPeerConnection>,
    mux: Arc<WebRtcTransportMux>,
    replacement_gate: Arc<Mutex<()>>,
    initial_relay_urls_digest: Option<[u8; 32]>,
    relay_failure: Arc<RelayFailureGate>,
}

#[derive(Debug)]
struct RelayFailureGate {
    enabled: AtomicBool,
    generation: watch::Sender<Option<u64>>,
}

impl RelayFailureGate {
    fn disabled() -> Arc<Self> {
        let (generation, _) = watch::channel(None);
        Arc::new(Self {
            enabled: AtomicBool::new(false),
            generation,
        })
    }
}

/// One unpublished WebRTC replacement generation.
pub struct PendingWebRtcReplacement {
    session_id: SessionId,
    generation: u64,
    local_description: SessionDescription,
    planned_urls_digest: [u8; 32],
    peer: Arc<WebRtcPeerConnection>,
}

impl fmt::Debug for PendingWebRtcReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingWebRtcReplacement")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("local_description", &"[REDACTED]")
            .field("planned_urls_digest", &"[REDACTED]")
            .finish()
    }
}

impl PendingWebRtcReplacement {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn local_description(&self) -> SessionDescription {
        self.local_description.clone()
    }
}

impl Drop for PendingWebRtcReplacement {
    fn drop(&mut self) {
        if let Some(route_token) = self.local_description.restart_route_token() {
            let _ = self.peer.abort_restart(self.generation, route_token);
        }
    }
}

/// Real selected-pair and lane-probe evidence bound to one verified directory candidate.
pub struct VerifiedRelayEvidence {
    session_id: SessionId,
    generation: u64,
    planned_urls_digest: [u8; 32],
    route: RelayRouteEvidence,
    transport: RestartRouteEvidence,
}

impl fmt::Debug for VerifiedRelayEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRelayEvidence")
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("route", &self.route)
            .field("planned_urls_digest", &"[REDACTED]")
            .finish()
    }
}

impl VerifiedRelayEvidence {
    pub fn route(&self) -> &RelayRouteEvidence {
        &self.route
    }

    pub fn selected_pair(&self) -> &SelectedCandidatePairStats {
        self.transport.selected_pair()
    }
}

/// Opaque proof that generation zero is a nominated relay/relay route matching the signed
/// directory node and the exact TURN URL set used to create the peer.
pub(crate) struct VerifiedActiveRelayEvidence {
    route: RelayRouteEvidence,
}

impl VerifiedActiveRelayEvidence {
    pub(crate) fn route(&self) -> &RelayRouteEvidence {
        &self.route
    }
}

impl fmt::Debug for VerifiedActiveRelayEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedActiveRelayEvidence")
            .field("route", &self.route)
            .finish()
    }
}

impl ServiceWebRtcTransportHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn open_session(
        &self,
        session_id: SessionId,
        mut config: PeerConnectionConfig,
    ) -> Result<(), ServiceWebRtcTransportError> {
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&session_id) {
                return Err(ServiceWebRtcTransportError::DuplicateSession(session_id));
            }
        }
        let initial_relay_urls_digest = match config.ice_transport_policy {
            IceTransportPolicy::Relay => Some(replacement_urls_digest(&config)?),
            IceTransportPolicy::All => None,
        };
        let mux_config = TransportMuxConfig::default();
        config.max_h264_access_unit_bytes = config
            .max_h264_access_unit_bytes
            .min(mux_config.video_byte_capacity);
        config.video_queue_bytes = config.video_queue_bytes.min(mux_config.video_byte_capacity);
        config.reliable_queue_bytes = config.reliable_queue_bytes.min(
            mux_config
                .control_reliable_byte_capacity
                .saturating_add(DATA_CHANNEL_WIRE_BUDGET_OVERHEAD),
        );
        config.realtime_queue_bytes = config
            .realtime_queue_bytes
            .min(mux_config.control_realtime_byte_capacity);
        config.bulk_queue_bytes = config.bulk_queue_bytes.min(
            mux_config
                .bulk_byte_capacity
                .saturating_add(DATA_CHANNEL_WIRE_BUDGET_OVERHEAD),
        );
        let peer = Arc::new(
            WebRtcPeerConnection::new(config)
                .await
                .map_err(transport_error)?,
        );
        let replacement_gate = Arc::new(Mutex::new(()));
        let relay_failure = RelayFailureGate::disabled();
        let mux = Arc::new(
            WebRtcTransportMux::new_with_replacement_gate(
                session_id.clone(),
                mux_config,
                Arc::clone(&peer),
                Arc::clone(&replacement_gate),
                Arc::clone(&relay_failure),
            )
            .await
            .map_err(|error| ServiceWebRtcTransportError::Transport(error.to_string()))?,
        );
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(&session_id) {
            drop(sessions);
            let _ = mux.close().await;
            return Err(ServiceWebRtcTransportError::DuplicateSession(session_id));
        }
        sessions.insert(
            session_id,
            ServiceWebRtcSession {
                peer,
                mux,
                replacement_gate,
                initial_relay_urls_digest,
                relay_failure,
            },
        );
        Ok(())
    }

    /// Verify the already connected generation-zero path before registering it for failover.
    pub(crate) async fn verify_active_relay(
        &self,
        session_id: &SessionId,
        route: RelayRouteEvidence,
    ) -> Result<VerifiedActiveRelayEvidence, ServiceWebRtcTransportError> {
        let session = self.session_entry(session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        if route.session_id() != session_id.0
            || route.generation() != 0
            || session.initial_relay_urls_digest.as_ref() != Some(route.urls_digest())
            || session.peer.current_generation().await != 0
        {
            return Err(ServiceWebRtcTransportError::ReplacementEvidenceMismatch);
        }
        let pair = session
            .peer
            .selected_candidate_pair_stats()
            .await
            .ok_or(ServiceWebRtcTransportError::ReplacementEvidenceMismatch)?;
        let mux_route = session.mux.route_snapshot().await;
        if !pair.nominated
            || pair.local_candidate_kind != CandidateKind::Relay
            || pair.remote_candidate_kind != CandidateKind::Relay
            || mux_route.session_id != *session_id
            || mux_route.closed
        {
            return Err(ServiceWebRtcTransportError::ReplacementEvidenceMismatch);
        }
        Ok(VerifiedActiveRelayEvidence { route })
    }

    pub(crate) async fn enable_relay_failover(
        &self,
        session_id: &SessionId,
    ) -> Result<(), ServiceWebRtcTransportError> {
        let session = self.session_entry(session_id).await?;
        session.relay_failure.enabled.store(true, Ordering::Release);
        let _ = session.relay_failure.generation.send(None);
        Ok(())
    }

    pub async fn create_offer(
        &self,
        session_id: &SessionId,
    ) -> Result<SessionDescription, ServiceWebRtcTransportError> {
        self.session(session_id)
            .await?
            .create_offer()
            .await
            .map_err(transport_error)
    }

    pub async fn accept_offer(
        &self,
        session_id: &SessionId,
        offer: SessionDescription,
    ) -> Result<SessionDescription, ServiceWebRtcTransportError> {
        self.session(session_id)
            .await?
            .accept_offer(offer)
            .await
            .map_err(transport_error)
    }

    pub async fn accept_answer(
        &self,
        session_id: &SessionId,
        answer: SessionDescription,
    ) -> Result<(), ServiceWebRtcTransportError> {
        self.session(session_id)
            .await?
            .accept_answer(answer)
            .await
            .map_err(transport_error)
    }

    pub async fn next_local_candidate(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<IceCandidate>, ServiceWebRtcTransportError> {
        Ok(self.session(session_id).await?.next_local_candidate().await)
    }

    pub async fn add_ice_candidate(
        &self,
        session_id: &SessionId,
        candidate: IceCandidate,
    ) -> Result<(), ServiceWebRtcTransportError> {
        self.session(session_id)
            .await?
            .add_ice_candidate(candidate)
            .await
            .map_err(transport_error)
    }

    pub async fn wait_connected(
        &self,
        session_id: &SessionId,
    ) -> Result<(), ServiceWebRtcTransportError> {
        self.session(session_id)
            .await?
            .wait_connected()
            .await
            .map_err(transport_error)
    }

    pub async fn selected_candidate_pair_stats(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SelectedCandidatePairStats>, ServiceWebRtcTransportError> {
        Ok(self
            .session(session_id)
            .await?
            .selected_candidate_pair_stats()
            .await)
    }

    /// Build an offerer replacement on an independent relay-only peer.
    pub async fn begin_replacement(
        &self,
        session_id: &SessionId,
        generation: u64,
        config: PeerConnectionConfig,
    ) -> Result<PendingWebRtcReplacement, ServiceWebRtcTransportError> {
        let planned_urls_digest = replacement_urls_digest(&config)?;
        let session = self.session_entry(session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        let local_description = session
            .peer
            .create_restart_offer(generation, config.ice_servers)
            .await
            .map_err(transport_error)?;
        Ok(PendingWebRtcReplacement {
            session_id: session_id.clone(),
            generation,
            local_description,
            planned_urls_digest,
            peer: Arc::clone(&session.peer),
        })
    }

    /// Build an answerer replacement without disturbing the active route.
    pub async fn begin_replacement_from_offer(
        &self,
        session_id: &SessionId,
        generation: u64,
        config: PeerConnectionConfig,
        offer: SessionDescription,
    ) -> Result<PendingWebRtcReplacement, ServiceWebRtcTransportError> {
        let planned_urls_digest = replacement_urls_digest(&config)?;
        let session = self.session_entry(session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        let local_description = session
            .peer
            .accept_restart_offer(generation, config.ice_servers, offer)
            .await
            .map_err(transport_error)?;
        Ok(PendingWebRtcReplacement {
            session_id: session_id.clone(),
            generation,
            local_description,
            planned_urls_digest,
            peer: Arc::clone(&session.peer),
        })
    }

    pub async fn accept_replacement_answer(
        &self,
        pending: &PendingWebRtcReplacement,
        answer: SessionDescription,
    ) -> Result<(), ServiceWebRtcTransportError> {
        let session = self.session_entry(&pending.session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        session
            .peer
            .accept_restart_answer(pending.generation, answer)
            .await
            .map_err(transport_error)
    }

    pub async fn next_replacement_candidate(
        &self,
        pending: &PendingWebRtcReplacement,
    ) -> Result<IceCandidate, ServiceWebRtcTransportError> {
        self.next_replacement_candidate_optional(pending)
            .await?
            .ok_or_else(|| {
                ServiceWebRtcTransportError::Transport(format!(
                    "replacement candidate stream closed for generation {}",
                    pending.generation
                ))
            })
    }

    pub async fn next_replacement_candidate_optional(
        &self,
        pending: &PendingWebRtcReplacement,
    ) -> Result<Option<IceCandidate>, ServiceWebRtcTransportError> {
        let session = self.session_entry(&pending.session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        session
            .peer
            .next_restart_candidate_optional(pending.generation)
            .await
            .map_err(transport_error)
    }

    pub async fn add_replacement_candidate(
        &self,
        pending: &PendingWebRtcReplacement,
        candidate: IceCandidate,
    ) -> Result<(), ServiceWebRtcTransportError> {
        let session = self.session_entry(&pending.session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        session
            .peer
            .add_restart_candidate(pending.generation, candidate)
            .await
            .map_err(transport_error)
    }

    /// Validate the selected relay pair and both reliable-control and media lanes.
    pub async fn validate_replacement(
        &self,
        pending: &PendingWebRtcReplacement,
        planned_route: RelayRouteEvidence,
    ) -> Result<VerifiedRelayEvidence, ServiceWebRtcTransportError> {
        if pending.generation == 0
            || planned_route.session_id() != pending.session_id.0
            || planned_route.generation() != pending.generation
            || planned_route.urls_digest() != &pending.planned_urls_digest
        {
            return Err(ServiceWebRtcTransportError::ReplacementEvidenceMismatch);
        }
        let session = self.session_entry(&pending.session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        let transport = session
            .peer
            .validate_pending_restart(pending.generation)
            .await
            .map_err(transport_error)?;
        let pair = transport.selected_pair();
        if !pair.nominated
            || pair.local_candidate_kind != CandidateKind::Relay
            || pair.remote_candidate_kind != CandidateKind::Relay
            || !transport.control_round_trip()
            || !transport.media_round_trip()
        {
            return Err(ServiceWebRtcTransportError::ReplacementEvidenceMismatch);
        }
        Ok(VerifiedRelayEvidence {
            session_id: pending.session_id.clone(),
            generation: pending.generation,
            planned_urls_digest: pending.planned_urls_digest,
            route: planned_route,
            transport,
        })
    }

    /// Atomically publish a validated replacement and preserve the stable logical mux.
    pub async fn commit_replacement(
        &self,
        pending: PendingWebRtcReplacement,
        expected: VerifiedRelayEvidence,
    ) -> Result<Arc<dyn TransportMuxPort>, ServiceWebRtcTransportError> {
        if expected.session_id != pending.session_id
            || expected.generation != pending.generation
            || expected.planned_urls_digest != pending.planned_urls_digest
            || expected.route.session_id() != pending.session_id.0
            || expected.route.generation() != pending.generation
            || expected.route.urls_digest() != &pending.planned_urls_digest
        {
            return Err(ServiceWebRtcTransportError::ReplacementEvidenceMismatch);
        }
        let session = self.session_entry(&pending.session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        session
            .peer
            .commit_restart(pending.generation, expected.transport)
            .await
            .map_err(transport_error)?;
        let _ = session.relay_failure.generation.send(None);
        refresh_webrtc_route(&session.mux.core, &session.peer).await;
        let mux: Arc<dyn TransportMuxPort> = session.mux;
        Ok(mux)
    }

    /// Abort exactly one unpublished generation; stale handles cannot touch a newer route.
    pub async fn abort_replacement(
        &self,
        pending: PendingWebRtcReplacement,
    ) -> Result<bool, ServiceWebRtcTransportError> {
        let route_token = pending
            .local_description
            .restart_route_token()
            .ok_or(ServiceWebRtcTransportError::InvalidReplacement)?
            .clone();
        let session = self.session_entry(&pending.session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        session
            .peer
            .abort_restart(pending.generation, &route_token)
            .map_err(transport_error)
    }

    /// Wait until the active route has failed or remained disconnected past transport grace.
    pub async fn wait_failover_needed(
        &self,
        session_id: &SessionId,
    ) -> Result<u64, ServiceWebRtcTransportError> {
        let session = self.session_entry(session_id).await?;
        let mut failures = session.relay_failure.generation.subscribe();
        drop(session);
        loop {
            if let Some(generation) = *failures.borrow_and_update() {
                return Ok(generation);
            }
            failures.changed().await.map_err(|_| {
                ServiceWebRtcTransportError::Transport(
                    "relay failure notification stream closed".into(),
                )
            })?;
        }
    }

    pub async fn close_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(), ServiceWebRtcTransportError> {
        let session = self
            .sessions
            .write()
            .await
            .remove(session_id)
            .ok_or_else(|| ServiceWebRtcTransportError::SessionNotFound(session_id.clone()))?;
        let _replacement_guard = session.replacement_gate.lock().await;
        session
            .mux
            .close()
            .await
            .map_err(|error| ServiceWebRtcTransportError::Transport(error.to_string()))
    }

    /// Close a published losing generation without allowing a stale completion to affect a
    /// newer committed route.
    pub async fn close_session_if_generation(
        &self,
        session_id: &SessionId,
        generation: u64,
    ) -> Result<bool, ServiceWebRtcTransportError> {
        let session = self.session_entry(session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        if session.peer.current_generation().await != generation {
            return Ok(false);
        }
        let removed = {
            let mut sessions = self.sessions.write().await;
            let is_same_session = sessions
                .get(session_id)
                .is_some_and(|current| Arc::ptr_eq(&current.peer, &session.peer));
            if is_same_session {
                sessions.remove(session_id)
            } else {
                None
            }
        };
        let Some(removed) = removed else {
            return Ok(false);
        };
        removed
            .mux
            .close()
            .await
            .map_err(|error| ServiceWebRtcTransportError::Transport(error.to_string()))?;
        Ok(true)
    }

    pub async fn shutdown(&self) -> Result<(), ServiceWebRtcTransportError> {
        let sessions = std::mem::take(&mut *self.sessions.write().await);
        let mut first_error = None;
        for session in sessions.into_values() {
            let _replacement_guard = session.replacement_gate.lock().await;
            if let Err(error) = session.mux.close().await {
                first_error.get_or_insert_with(|| {
                    ServiceWebRtcTransportError::Transport(error.to_string())
                });
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub async fn transport_mux(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<WebRtcTransportMux>, ServiceWebRtcTransportError> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .map(|session| Arc::clone(&session.mux))
            .ok_or_else(|| ServiceWebRtcTransportError::SessionNotFound(session_id.clone()))
    }

    /// Return the stable media mux only while it still represents the exact
    /// relay generation authorized by the WAN coordinator.
    pub(crate) async fn verified_media_mux(
        &self,
        session_id: &SessionId,
        generation: u64,
    ) -> Result<Arc<dyn TransportMuxPort>, ServiceWebRtcTransportError> {
        let session = self.session_entry(session_id).await?;
        let _replacement_guard = session.replacement_gate.lock().await;
        let route = session.mux.route_snapshot().await;
        if session.peer.current_generation().await != generation
            || route.session_id != *session_id
            || route.kind != TransportRouteKind::WebRtcRelay
            || route.closed
        {
            return Err(ServiceWebRtcTransportError::ReplacementEvidenceMismatch);
        }
        Ok(session.mux)
    }

    async fn session(
        &self,
        session_id: &SessionId,
    ) -> Result<Arc<WebRtcPeerConnection>, ServiceWebRtcTransportError> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .map(|session| Arc::clone(&session.peer))
            .ok_or_else(|| ServiceWebRtcTransportError::SessionNotFound(session_id.clone()))
    }

    async fn session_entry(
        &self,
        session_id: &SessionId,
    ) -> Result<ServiceWebRtcSession, ServiceWebRtcTransportError> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| ServiceWebRtcTransportError::SessionNotFound(session_id.clone()))
    }
}

fn replacement_urls_digest(
    config: &PeerConnectionConfig,
) -> Result<[u8; 32], ServiceWebRtcTransportError> {
    if config.ice_transport_policy != IceTransportPolicy::Relay || config.ice_servers.is_empty() {
        return Err(ServiceWebRtcTransportError::InvalidReplacement);
    }
    let urls = config
        .ice_servers
        .iter()
        .flat_map(|server| server.urls.iter().cloned())
        .collect::<Vec<_>>();
    if urls.is_empty() {
        return Err(ServiceWebRtcTransportError::InvalidReplacement);
    }
    Ok(urls_digest(&urls))
}

fn transport_error(error: mrd_transport_webrtc::TransportError) -> ServiceWebRtcTransportError {
    ServiceWebRtcTransportError::Transport(error.to_string())
}

/// Session transport mux backed by a service-owned WebRTC peer connection.
#[derive(Debug)]
pub struct WebRtcTransportMux {
    core: Arc<SessionMuxCore>,
    peer: Arc<WebRtcPeerConnection>,
}

impl WebRtcTransportMux {
    pub async fn loopback(
        session_id: SessionId,
        config: TransportMuxConfig,
    ) -> Result<(Self, Self)> {
        use mrd_transport_webrtc::PeerConnectionRole;

        let offerer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig {
                role: PeerConnectionRole::Offerer,
                include_loopback_candidates: true,
                max_h264_access_unit_bytes: config.video_byte_capacity,
                video_queue_bytes: config.video_byte_capacity,
                reliable_queue_bytes: config
                    .control_reliable_byte_capacity
                    .saturating_add(DATA_CHANNEL_WIRE_BUDGET_OVERHEAD),
                realtime_queue_bytes: config.control_realtime_byte_capacity,
                bulk_queue_bytes: config
                    .bulk_byte_capacity
                    .saturating_add(DATA_CHANNEL_WIRE_BUDGET_OVERHEAD),
                ..PeerConnectionConfig::default()
            })
            .await?,
        );
        let answerer = Arc::new(
            WebRtcPeerConnection::new(PeerConnectionConfig {
                role: PeerConnectionRole::Answerer,
                include_loopback_candidates: true,
                max_h264_access_unit_bytes: config.video_byte_capacity,
                video_queue_bytes: config.video_byte_capacity,
                reliable_queue_bytes: config
                    .control_reliable_byte_capacity
                    .saturating_add(DATA_CHANNEL_WIRE_BUDGET_OVERHEAD),
                realtime_queue_bytes: config.control_realtime_byte_capacity,
                bulk_queue_bytes: config
                    .bulk_byte_capacity
                    .saturating_add(DATA_CHANNEL_WIRE_BUDGET_OVERHEAD),
                ..PeerConnectionConfig::default()
            })
            .await?,
        );
        let offer = offerer.create_offer().await?;
        let answer = answerer.accept_offer(offer).await?;
        offerer.accept_answer(answer).await?;
        let offer_candidate = offerer
            .next_local_candidate()
            .await
            .ok_or_else(|| anyhow::anyhow!("offerer produced no loopback ICE candidate"))?;
        let answer_candidate = answerer
            .next_local_candidate()
            .await
            .ok_or_else(|| anyhow::anyhow!("answerer produced no loopback ICE candidate"))?;
        answerer.add_ice_candidate(offer_candidate).await?;
        offerer.add_ice_candidate(answer_candidate).await?;
        tokio::try_join!(offerer.wait_connected(), answerer.wait_connected())?;

        let left = Self::new(session_id.clone(), config, offerer).await?;
        let right = Self::new(session_id, config, answerer).await?;
        Ok((left, right))
    }

    pub async fn new(
        session_id: SessionId,
        config: TransportMuxConfig,
        peer: Arc<WebRtcPeerConnection>,
    ) -> Result<Self> {
        Self::new_with_replacement_gate(
            session_id,
            config,
            peer,
            Arc::new(Mutex::new(())),
            RelayFailureGate::disabled(),
        )
        .await
    }

    async fn new_with_replacement_gate(
        session_id: SessionId,
        config: TransportMuxConfig,
        peer: Arc<WebRtcPeerConnection>,
        replacement_gate: Arc<Mutex<()>>,
        relay_failure: Arc<RelayFailureGate>,
    ) -> Result<Self> {
        let core = SessionMuxCore::new(
            session_id,
            config,
            TransportRouteKind::WebRtcPending,
            "webrtc:pending-local-candidate",
            "webrtc:pending-remote-candidate",
        );
        refresh_webrtc_route(&core, &peer).await;
        spawn_webrtc_senders(
            Arc::clone(&core),
            Arc::clone(&peer),
            Arc::clone(&replacement_gate),
            Arc::clone(&relay_failure),
        );
        spawn_webrtc_receivers(
            Arc::clone(&core),
            Arc::clone(&peer),
            Arc::clone(&replacement_gate),
            Arc::clone(&relay_failure),
            config,
        );
        spawn_webrtc_connection_watcher(
            Arc::clone(&core),
            Arc::clone(&peer),
            Arc::clone(&replacement_gate),
            relay_failure,
        );
        Ok(Self { core, peer })
    }
}

impl Drop for WebRtcTransportMux {
    fn drop(&mut self) {
        flush_webrtc_video_drops(&self.core, &self.peer);
        self.core.terminate_now(None);
        self.peer.terminate_now();
        flush_webrtc_video_drops(&self.core, &self.peer);
    }
}

async fn fail_webrtc(core: &SessionMuxCore, peer: &WebRtcPeerConnection, reason: String) {
    let _ = peer.close().await;
    flush_webrtc_video_drops(core, peer);
    core.fail(reason).await;
}

fn route_failure_belongs_to_active(
    observed_generation: u64,
    current_generation: u64,
    pending_generation: Option<u64>,
) -> bool {
    observed_generation == current_generation && pending_generation.is_none()
}

async fn fail_webrtc_if_active(
    core: &SessionMuxCore,
    peer: &WebRtcPeerConnection,
    replacement_gate: &Mutex<()>,
    relay_failure: &RelayFailureGate,
    observed_generation: u64,
    reason: String,
) -> bool {
    let replacement_guard = replacement_gate.lock().await;
    if !route_failure_belongs_to_active(
        observed_generation,
        peer.current_generation().await,
        peer.pending_restart_generation().await,
    ) {
        return false;
    }
    if relay_failure.enabled.load(Ordering::Acquire) {
        let _ = relay_failure.generation.send(Some(observed_generation));
        drop(replacement_guard);
        loop {
            if peer.current_generation().await != observed_generation
                || peer.pending_restart_generation().await.is_some()
            {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    fail_webrtc(core, peer, reason).await;
    true
}

fn flush_webrtc_video_drops(core: &SessionMuxCore, peer: &WebRtcPeerConnection) {
    core.record_adapter_drops(TransportLane::Video, peer.take_completed_video_drops());
}

fn spawn_webrtc_connection_watcher(
    core: Arc<SessionMuxCore>,
    peer: Arc<WebRtcPeerConnection>,
    replacement_gate: Arc<Mutex<()>>,
    relay_failure: Arc<RelayFailureGate>,
) {
    let owner = Arc::clone(&core);
    let task = tokio::spawn(async move {
        loop {
            let observed_generation = peer.current_generation().await;
            let termination = peer.wait_terminated().await;
            let reason = match termination {
                Ok(()) => "WebRTC peer connection terminated".to_owned(),
                Err(error) => format!("WebRTC connection watcher failed: {error}"),
            };
            if !fail_webrtc_if_active(
                &core,
                &peer,
                &replacement_gate,
                &relay_failure,
                observed_generation,
                reason,
            )
            .await
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            break;
        }
    });
    owner.register_task(task);
}

async fn refresh_webrtc_route(core: &SessionMuxCore, peer: &WebRtcPeerConnection) {
    let Some(stats) = peer.selected_candidate_pair_stats().await else {
        return;
    };
    if stats.local_candidate_kind == mrd_transport_webrtc::CandidateKind::Unknown
        || stats.remote_candidate_kind == mrd_transport_webrtc::CandidateKind::Unknown
    {
        return;
    }
    let kind = if stats.local_candidate_kind == mrd_transport_webrtc::CandidateKind::Relay
        || stats.remote_candidate_kind == mrd_transport_webrtc::CandidateKind::Relay
    {
        TransportRouteKind::WebRtcRelay
    } else {
        TransportRouteKind::WebRtcDirect
    };
    core.update_route(
        kind,
        stats.local_candidate_id,
        stats.remote_candidate_id,
        Some(format!("{:?}", stats.local_candidate_kind).to_ascii_lowercase()),
        Some(format!("{:?}", stats.remote_candidate_kind).to_ascii_lowercase()),
    )
    .await;
}

fn spawn_webrtc_senders(
    core: Arc<SessionMuxCore>,
    peer: Arc<WebRtcPeerConnection>,
    replacement_gate: Arc<Mutex<()>>,
    relay_failure: Arc<RelayFailureGate>,
) {
    for lane in TransportLane::ALL {
        let source = Arc::clone(&core);
        let peer = Arc::clone(&peer);
        let replacement_gate = Arc::clone(&replacement_gate);
        let relay_failure = Arc::clone(&relay_failure);
        let task = tokio::spawn(async move {
            while let Some(envelope) = source.next_outbound(lane).await {
                loop {
                    let observed_generation = peer.current_generation().await;
                    let result = match lane {
                        TransportLane::Video => {
                            let Some(metadata) = envelope.video.as_ref() else {
                                return;
                            };
                            if metadata.codec != "h264" {
                                return;
                            }
                            peer.send_h264_access_unit(&EncodedAccessUnit {
                                codec: VideoCodec::H264,
                                timestamp_us: metadata.timestamp_us,
                                is_keyframe: metadata.keyframe,
                                bytes: envelope.payload.clone(),
                            })
                            .await
                        }
                        TransportLane::ControlReliable => {
                            send_data_envelope(&peer, ControlLane::Reliable, &envelope).await
                        }
                        TransportLane::ControlRealtime => {
                            send_data_envelope(&peer, ControlLane::Realtime, &envelope).await
                        }
                        TransportLane::Bulk => {
                            send_data_envelope(&peer, ControlLane::Bulk, &envelope).await
                        }
                    };
                    let Err(error) = result else {
                        break;
                    };
                    if fail_webrtc_if_active(
                        &source,
                        &peer,
                        &replacement_gate,
                        &relay_failure,
                        observed_generation,
                        format!("WebRTC {lane:?} sender failed: {error}"),
                    )
                    .await
                    {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        });
        core.register_task(task);
    }
}

async fn send_data_envelope(
    peer: &WebRtcPeerConnection,
    lane: ControlLane,
    envelope: &TransportEnvelope,
) -> Result<usize, mrd_transport_webrtc::TransportError> {
    let payload = quic::encode_envelope(envelope)
        .map_err(|error| mrd_transport_webrtc::TransportError::Message(error.to_string()))?;
    let fragments = fragment_data_envelope(envelope.sequence, &payload)
        .map_err(mrd_transport_webrtc::TransportError::Message)?;
    if lane == ControlLane::Realtime && fragments.len() != 1 {
        return Err(mrd_transport_webrtc::TransportError::Message(
            "realtime WebRTC envelope exceeds one data-channel message".into(),
        ));
    }
    let mut bytes_sent = 0_usize;
    for fragment in fragments {
        bytes_sent = bytes_sent.saturating_add(peer.send_control(lane, &fragment).await?);
    }
    Ok(bytes_sent)
}

fn fragment_data_envelope(message_id: u64, payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let fragment_count = payload.len().max(1).div_ceil(DATA_FRAGMENT_PAYLOAD_LEN);
    let fragment_count = u16::try_from(fragment_count)
        .map_err(|_| "WebRTC data envelope requires too many fragments".to_owned())?;
    let total_len = u32::try_from(payload.len())
        .map_err(|_| "WebRTC data envelope exceeds wire length".to_owned())?;
    let mut fragments = Vec::with_capacity(fragment_count as usize);
    for (index, chunk) in payload.chunks(DATA_FRAGMENT_PAYLOAD_LEN).enumerate() {
        let mut encoded = Vec::with_capacity(DATA_FRAGMENT_HEADER_LEN + chunk.len());
        encoded.extend_from_slice(DATA_FRAGMENT_MAGIC);
        encoded.push(DATA_FRAGMENT_VERSION);
        encoded.extend_from_slice(&message_id.to_le_bytes());
        encoded.extend_from_slice(&(index as u16).to_le_bytes());
        encoded.extend_from_slice(&fragment_count.to_le_bytes());
        encoded.extend_from_slice(&total_len.to_le_bytes());
        encoded.extend_from_slice(chunk);
        fragments.push(encoded);
    }
    Ok(fragments)
}

#[derive(Debug)]
struct DataEnvelopeReassembler {
    max_total_len: usize,
    current: Option<PartialDataEnvelope>,
}

#[derive(Debug)]
struct PartialDataEnvelope {
    message_id: u64,
    fragment_count: u16,
    next_index: u16,
    total_len: usize,
    payload: Vec<u8>,
}

impl DataEnvelopeReassembler {
    fn new(max_total_len: usize) -> Self {
        Self {
            max_total_len: max_total_len.max(1),
            current: None,
        }
    }

    fn push(&mut self, fragment: &[u8]) -> Result<Option<Bytes>> {
        if fragment.len() < DATA_FRAGMENT_HEADER_LEN
            || &fragment[..4] != DATA_FRAGMENT_MAGIC
            || fragment[4] != DATA_FRAGMENT_VERSION
        {
            bail!("invalid WebRTC data fragment header");
        }
        let message_id = u64::from_le_bytes(fragment[5..13].try_into()?);
        let fragment_index = u16::from_le_bytes(fragment[13..15].try_into()?);
        let fragment_count = u16::from_le_bytes(fragment[15..17].try_into()?);
        let total_len = u32::from_le_bytes(fragment[17..21].try_into()?) as usize;
        if fragment_count == 0
            || fragment_index >= fragment_count
            || total_len > self.max_total_len
            || total_len.max(1).div_ceil(DATA_FRAGMENT_PAYLOAD_LEN) != fragment_count as usize
        {
            bail!("invalid WebRTC data fragment bounds");
        }
        let chunk = &fragment[DATA_FRAGMENT_HEADER_LEN..];
        let expected_chunk_len = if fragment_index + 1 == fragment_count {
            total_len.saturating_sub(
                DATA_FRAGMENT_PAYLOAD_LEN.saturating_mul(fragment_count.saturating_sub(1) as usize),
            )
        } else {
            DATA_FRAGMENT_PAYLOAD_LEN
        };
        if chunk.len() != expected_chunk_len {
            bail!("WebRTC data fragment payload length mismatch");
        }
        if self.current.is_none() {
            if fragment_index != 0 {
                bail!("WebRTC data envelope does not start at fragment zero");
            }
            self.current = Some(PartialDataEnvelope {
                message_id,
                fragment_count,
                next_index: 0,
                total_len,
                payload: Vec::with_capacity(total_len),
            });
        }
        let current = self.current.as_mut().expect("partial envelope initialized");
        if current.message_id != message_id
            || current.fragment_count != fragment_count
            || current.total_len != total_len
            || current.next_index != fragment_index
            || current.payload.len().saturating_add(chunk.len()) > current.total_len
        {
            self.current = None;
            bail!("inconsistent or reordered WebRTC data fragments");
        }
        current.payload.extend_from_slice(chunk);
        current.next_index = current.next_index.saturating_add(1);
        if current.next_index != current.fragment_count {
            return Ok(None);
        }
        let complete = self.current.take().expect("completed partial envelope");
        if complete.payload.len() != complete.total_len {
            bail!("WebRTC data envelope length mismatch");
        }
        Ok(Some(Bytes::from(complete.payload)))
    }
}

fn spawn_webrtc_receivers(
    core: Arc<SessionMuxCore>,
    peer: Arc<WebRtcPeerConnection>,
    replacement_gate: Arc<Mutex<()>>,
    relay_failure: Arc<RelayFailureGate>,
    config: TransportMuxConfig,
) {
    let max_payload_len = config.max_payload_len;
    let video_core = Arc::clone(&core);
    let video_peer = Arc::clone(&peer);
    let video_replacement_gate = Arc::clone(&replacement_gate);
    let video_relay_failure = Arc::clone(&relay_failure);
    let video_sequence = Arc::new(AtomicU64::new(0));
    let video_task = tokio::spawn(async move {
        loop {
            let observed_generation = video_peer.current_generation().await;
            let Some(access_unit) = video_peer.next_h264_access_unit().await else {
                flush_webrtc_video_drops(&video_core, &video_peer);
                if fail_webrtc_if_active(
                    &video_core,
                    &video_peer,
                    &video_replacement_gate,
                    &video_relay_failure,
                    observed_generation,
                    "WebRTC video receiver closed by peer".into(),
                )
                .await
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            };
            if video_peer.current_generation().await != observed_generation {
                continue;
            }
            flush_webrtc_video_drops(&video_core, &video_peer);
            let envelope = TransportEnvelope {
                session_id: video_core.session_id().clone(),
                lane: TransportLane::Video,
                sequence: video_sequence.fetch_add(1, Ordering::Relaxed),
                payload: access_unit.bytes,
                video: Some(VideoEnvelopeMetadata {
                    codec: "h264".into(),
                    timestamp_us: access_unit.timestamp_us,
                    keyframe: access_unit.is_keyframe,
                    width: 0,
                    height: 0,
                }),
            };
            if let Err(error) = video_core.deliver(envelope).await {
                if fail_webrtc_if_active(
                    &video_core,
                    &video_peer,
                    &video_replacement_gate,
                    &video_relay_failure,
                    observed_generation,
                    format!("WebRTC video delivery failed: {error}"),
                )
                .await
                {
                    return;
                }
            }
        }
    });
    core.register_task(video_task);

    for (lane, control_lane) in [
        (TransportLane::ControlReliable, ControlLane::Reliable),
        (TransportLane::ControlRealtime, ControlLane::Realtime),
        (TransportLane::Bulk, ControlLane::Bulk),
    ] {
        let target = Arc::clone(&core);
        let peer = Arc::clone(&peer);
        let replacement_gate = Arc::clone(&replacement_gate);
        let relay_failure = Arc::clone(&relay_failure);
        let task = tokio::spawn(async move {
            let mut reassembler = DataEnvelopeReassembler::new(
                max_payload_len
                    .min(config.byte_capacity(lane))
                    .saturating_add(MAX_ENVELOPE_WIRE_OVERHEAD),
            );
            let mut reassembler_generation = peer.current_generation().await;
            loop {
                let observed_generation = peer.current_generation().await;
                if reassembler_generation != observed_generation {
                    reassembler = DataEnvelopeReassembler::new(
                        max_payload_len
                            .min(config.byte_capacity(lane))
                            .saturating_add(MAX_ENVELOPE_WIRE_OVERHEAD),
                    );
                    reassembler_generation = observed_generation;
                }
                let Some(payload) = peer.next_control(control_lane).await else {
                    if fail_webrtc_if_active(
                        &target,
                        &peer,
                        &replacement_gate,
                        &relay_failure,
                        observed_generation,
                        format!("WebRTC {lane:?} receiver closed by peer"),
                    )
                    .await
                    {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                };
                if peer.current_generation().await != observed_generation {
                    continue;
                }
                let payload = match reassembler.push(&payload) {
                    Ok(Some(payload)) => payload,
                    Ok(None) => continue,
                    Err(error) => {
                        if fail_webrtc_if_active(
                            &target,
                            &peer,
                            &replacement_gate,
                            &relay_failure,
                            observed_generation,
                            format!("WebRTC {lane:?} fragment invalid: {error}"),
                        )
                        .await
                        {
                            return;
                        }
                        continue;
                    }
                };
                let Ok(envelope) = quic::decode_envelope(&payload, max_payload_len) else {
                    continue;
                };
                if envelope.lane != lane {
                    continue;
                }
                if let Err(error) = target.deliver(envelope).await {
                    if fail_webrtc_if_active(
                        &target,
                        &peer,
                        &replacement_gate,
                        &relay_failure,
                        observed_generation,
                        format!("WebRTC {lane:?} delivery failed: {error}"),
                    )
                    .await
                    {
                        return;
                    }
                }
            }
        });
        core.register_task(task);
    }
}

#[async_trait::async_trait]
impl TransportMuxPort for WebRtcTransportMux {
    async fn send(&self, envelope: TransportEnvelope) -> Result<TransportSendOutcome> {
        if let Some(metadata) = &envelope.video {
            if metadata.codec != "h264" {
                bail!("WebRTC mux does not support video codec {}", metadata.codec);
            }
        }
        if envelope.lane == TransportLane::ControlRealtime
            && quic::encode_envelope(&envelope)?.len() > DATA_FRAGMENT_PAYLOAD_LEN
        {
            bail!("WebRTC realtime envelope exceeds one data-channel message");
        }
        self.core.submit(envelope).await
    }

    async fn recv(&self, lane: TransportLane) -> Result<Option<TransportEnvelope>> {
        self.core.recv(lane).await
    }

    async fn route_snapshot(&self) -> TransportRouteSnapshot {
        refresh_webrtc_route(&self.core, &self.peer).await;
        flush_webrtc_video_drops(&self.core, &self.peer);
        self.core.snapshot().await
    }

    async fn close(&self) -> Result<()> {
        flush_webrtc_video_drops(&self.core, &self.peer);
        self.core.close().await;
        let close_result = self.peer.close().await;
        flush_webrtc_video_drops(&self.core, &self.peer);
        close_result?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_transport_webrtc::PeerConnectionRole;

    fn credentials() -> ServiceTurnRelayCredentials {
        ServiceTurnRelayCredentials {
            urls: vec!["turn:relay.example.test:3478?transport=udp".into()],
            username: "temporary-user".into(),
            credential: "temporary-password".into(),
            expires_at_unix_seconds: 1_800_000_000,
        }
    }

    #[test]
    fn relay_credentials_force_relay_policy_without_debug_secret_leakage() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ServiceTurnRelayCredentials>();

        let credentials = credentials();
        let config = credentials.apply_relay_only(PeerConnectionConfig {
            role: PeerConnectionRole::Offerer,
            ..PeerConnectionConfig::default()
        });
        assert_eq!(config.ice_transport_policy, IceTransportPolicy::Relay);
        assert_eq!(config.ice_servers.len(), 1);
        assert_eq!(credentials.url_classes(), vec![RelayUrlClass::TurnUdp]);

        let debug = format!("{credentials:?}");
        assert!(!debug.contains("temporary-user"));
        assert!(!debug.contains("temporary-password"));
        assert!(debug.contains("TurnUdp"));
    }

    #[test]
    fn data_fragmentation_round_trips_payload_larger_than_sctp_message() {
        let payload = vec![0x5a; 160 * 1024];
        let fragments = fragment_data_envelope(7, &payload).expect("fragment data envelope");
        assert!(fragments.len() > 1);
        assert!(fragments.iter().all(|fragment| fragment.len() <= 65_535));

        let mut reassembler = DataEnvelopeReassembler::new(payload.len());
        let mut completed = None;
        for fragment in fragments {
            completed = reassembler
                .push(&fragment)
                .expect("reassemble ordered data fragment")
                .or(completed);
        }
        assert_eq!(completed.expect("completed payload").as_ref(), payload);
    }

    #[test]
    fn data_reassembler_rejects_nonzero_first_fragment() {
        let payload = vec![0x33; 128 * 1024];
        let fragments = fragment_data_envelope(8, &payload).expect("fragment data envelope");
        let mut reassembler = DataEnvelopeReassembler::new(payload.len());

        let error = reassembler
            .push(&fragments[1])
            .expect_err("out-of-order first fragment must fail closed");
        assert!(error.to_string().contains("fragment zero"));
    }

    #[test]
    fn stale_or_replacing_route_failure_cannot_fail_the_stable_mux() {
        assert!(route_failure_belongs_to_active(1, 1, None));
        assert!(!route_failure_belongs_to_active(0, 1, None));
        assert!(!route_failure_belongs_to_active(1, 1, Some(2)));
    }

    #[tokio::test]
    async fn service_host_owns_exactly_one_mux_and_closes_it_with_the_session() {
        let host = ServiceWebRtcTransportHost::new();
        let session_id = SessionId("host-owned-mux".into());
        host.open_session(
            session_id.clone(),
            PeerConnectionConfig {
                role: PeerConnectionRole::Offerer,
                ..PeerConnectionConfig::default()
            },
        )
        .await
        .expect("open WebRTC session");

        let first = host
            .transport_mux(&session_id)
            .await
            .expect("first mux handle");
        let second = host
            .transport_mux(&session_id)
            .await
            .expect("second mux handle");
        assert!(Arc::ptr_eq(&first, &second));

        host.close_session(&session_id)
            .await
            .expect("host closes session mux");
        assert_eq!(
            first
                .send(TransportEnvelope {
                    session_id,
                    lane: TransportLane::ControlReliable,
                    sequence: 1,
                    payload: vec![1],
                    video: None,
                })
                .await
                .expect("closed send outcome"),
            TransportSendOutcome::Closed
        );
    }

    #[tokio::test]
    async fn dropping_uncommitted_replacement_aborts_its_pending_generation() {
        let host = ServiceWebRtcTransportHost::new();
        let session_id = SessionId("dropped-replacement".into());
        host.open_session(
            session_id.clone(),
            PeerConnectionConfig {
                role: PeerConnectionRole::Offerer,
                ..PeerConnectionConfig::default()
            },
        )
        .await
        .expect("open WebRTC session");
        let pending = host
            .begin_replacement(
                &session_id,
                1,
                credentials().apply_relay_only(PeerConnectionConfig {
                    role: PeerConnectionRole::Offerer,
                    ..PeerConnectionConfig::default()
                }),
            )
            .await
            .expect("begin pending replacement");
        let peer = host.session(&session_id).await.expect("session peer");
        assert_eq!(peer.pending_restart_generation().await, Some(1));

        drop(pending);

        assert_eq!(peer.pending_restart_generation().await, None);
        host.close_session(&session_id)
            .await
            .expect("close WebRTC session");
    }

    #[tokio::test]
    async fn old_route_closure_is_ignored_while_a_real_replacement_is_pending() {
        let host = ServiceWebRtcTransportHost::new();
        let session_id = SessionId("pending-replacement-failure-gate".into());
        host.open_session(
            session_id.clone(),
            PeerConnectionConfig {
                role: PeerConnectionRole::Offerer,
                ..PeerConnectionConfig::default()
            },
        )
        .await
        .expect("open WebRTC session");
        let pending = host
            .begin_replacement(
                &session_id,
                1,
                credentials().apply_relay_only(PeerConnectionConfig {
                    role: PeerConnectionRole::Offerer,
                    ..PeerConnectionConfig::default()
                }),
            )
            .await
            .expect("begin pending replacement");
        let session = host
            .session_entry(&session_id)
            .await
            .expect("session entry");

        assert!(
            !fail_webrtc_if_active(
                &session.mux.core,
                &session.peer,
                &session.replacement_gate,
                &session.relay_failure,
                0,
                "simulated old-route closure".into(),
            )
            .await
        );
        assert!(!session.mux.route_snapshot().await.closed);

        drop(pending);
        host.close_session(&session_id)
            .await
            .expect("close WebRTC session");
    }

    #[tokio::test]
    async fn relay_managed_failure_reports_generation_without_closing_stable_mux() {
        let host = Arc::new(ServiceWebRtcTransportHost::new());
        let session_id = SessionId("relay-managed-health-report".into());
        host.open_session(
            session_id.clone(),
            PeerConnectionConfig {
                role: PeerConnectionRole::Offerer,
                ..PeerConnectionConfig::default()
            },
        )
        .await
        .expect("open WebRTC session");
        let session = host
            .session_entry(&session_id)
            .await
            .expect("session entry");
        session.relay_failure.enabled.store(true, Ordering::Release);
        let failure = tokio::spawn({
            let core = Arc::clone(&session.mux.core);
            let peer = Arc::clone(&session.peer);
            let replacement_gate = Arc::clone(&session.replacement_gate);
            let relay_failure = Arc::clone(&session.relay_failure);
            async move {
                fail_webrtc_if_active(
                    &core,
                    &peer,
                    &replacement_gate,
                    &relay_failure,
                    0,
                    "simulated managed relay failure".into(),
                )
                .await
            }
        });

        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                host.wait_failover_needed(&session_id),
            )
            .await
            .expect("health report timeout")
            .expect("health generation"),
            0
        );
        assert!(!session.mux.route_snapshot().await.closed);

        failure.abort();
        let _ = failure.await;
        host.close_session(&session_id)
            .await
            .expect("close WebRTC session");
    }
}
