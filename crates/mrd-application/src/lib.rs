//! Application use-case layer.
//!
//! This crate orchestrates session lifecycle, signaling, transport and media
//! through abstract ports. It should contain policy and workflow logic, while
//! concrete adapters stay in service or infrastructure crates.

#![warn(missing_docs)]

use anyhow::Result;
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{IceCandidate, ProtocolReasonCode, SignalMessage};

/// Identity metadata proven by an end-to-end signed signaling message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignalingIdentity {
    /// Device identifier bound to the signing connection by the realtime server.
    pub device_id: DeviceId,
    /// Stable identifier derived from the signing public key.
    pub key_id: String,
    /// Ed25519 public key that verified the message.
    pub public_key: Vec<u8>,
    /// Monotonic counter carried by the signed claims.
    pub counter: u64,
    /// Replay-resistant nonce carried by the signed claims.
    pub nonce: [u8; 16],
    /// Time at which the signed command was issued.
    pub issued_at_ms: u64,
    /// Time after which the signed command must not be applied.
    pub expires_at_ms: u64,
}

/// Authenticated session semantics emitted by a signaling adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedSessionSignal {
    /// A controller requests attended authorization from this device.
    AuthorizationRequested {
        /// Globally stable session identifier.
        session_id: SessionId,
        /// Retry-stable key used to make request application idempotent.
        idempotency_key: [u8; 16],
        /// Requested transport identifier.
        requested_transport: String,
    },
    /// The target granted a previously requested session route.
    Granted {
        /// Session whose route was granted.
        session_id: SessionId,
        /// Transport accepted by the target.
        accepted_transport: String,
        /// WebRTC candidates committed by the grant.
        accepted_candidate_fingerprints: Vec<String>,
    },
    /// The target denied a previously requested session.
    Denied {
        /// Denied session identifier.
        session_id: SessionId,
        /// Stable protocol reason supplied by the target.
        reason: ProtocolReasonCode,
    },
    /// Apply a remote WebRTC offer.
    WebRtcOffer {
        /// Session identifier.
        session_id: SessionId,
        /// Remote SDP offer.
        sdp: String,
        /// Candidate fingerprints committed by the offer.
        candidate_fingerprints: Vec<String>,
    },
    /// Apply a remote WebRTC answer.
    WebRtcAnswer {
        /// Session identifier.
        session_id: SessionId,
        /// Remote SDP answer.
        sdp: String,
        /// Candidate fingerprints committed by the answer.
        candidate_fingerprints: Vec<String>,
    },
    /// Apply a remote WebRTC ICE candidate.
    WebRtcCandidate {
        /// Session identifier.
        session_id: SessionId,
        /// ICE candidate line.
        candidate: String,
        /// Optional SDP media identifier.
        sdp_mid: Option<String>,
        /// Optional SDP media-line index.
        sdp_mline_index: Option<u16>,
        /// SHA-256 candidate fingerprint committed by a grant.
        candidate_fingerprint: String,
    },
    /// Apply a relay-bound ICE migration offer.
    RelayMigrationOffer {
        /// Session identifier.
        session_id: SessionId,
        /// Strictly increasing migration generation.
        migration_generation: u64,
        /// Signed relay directory identifier used for selection.
        directory_id: String,
        /// Selected relay node identifier.
        node_id: String,
        /// Remote SDP migration offer.
        sdp: String,
        /// Candidate fingerprints committed by the migration offer.
        candidate_fingerprints: Vec<String>,
    },
    /// Apply a relay-bound ICE migration answer.
    RelayMigrationAnswer {
        /// Session identifier.
        session_id: SessionId,
        /// Migration generation being answered.
        migration_generation: u64,
        /// Signed relay directory identifier used for selection.
        directory_id: String,
        /// Selected relay node identifier.
        node_id: String,
        /// Remote SDP migration answer.
        sdp: String,
        /// Candidate fingerprints committed by the migration answer.
        candidate_fingerprints: Vec<String>,
    },
    /// Apply a relay-bound ICE migration candidate.
    RelayMigrationCandidate {
        /// Session identifier.
        session_id: SessionId,
        /// Migration generation receiving the candidate.
        migration_generation: u64,
        /// Signed relay directory identifier used for selection.
        directory_id: String,
        /// Selected relay node identifier.
        node_id: String,
        /// ICE candidate line.
        candidate: String,
        /// Optional SDP media identifier.
        sdp_mid: Option<String>,
        /// Optional SDP media-line index.
        sdp_mline_index: Option<u16>,
        /// SHA-256 candidate fingerprint committed by the grant.
        candidate_fingerprint: String,
    },
    /// The authenticated peer closed a session.
    Closed {
        /// Closed session identifier.
        session_id: SessionId,
        /// Stable protocol reason supplied by the peer.
        reason: ProtocolReasonCode,
    },
}

/// One verified signaling event ready for application policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignalingEvent {
    /// Proven sender identity and replay metadata.
    pub sender: VerifiedSignalingIdentity,
    /// Session command carried by the signed message.
    pub signal: AuthenticatedSessionSignal,
}

/// Abstract ports for external dependencies
///
/// These traits define the boundaries between the application layer
/// and infrastructure adapters. This allows the application logic to
/// be tested independently and swapped between implementations.
pub mod ports {
    use super::*;
    pub use mrd_session::SessionLifecycleState;

    pub mod transport_mux;
    pub use transport_mux::*;

    /// Signaling client port - handles communication with signaling server
    #[async_trait::async_trait]
    pub trait SignalingPort: Send + Sync {
        /// Drain pending signaling events
        async fn drain_events(&self, handle: u64) -> Result<Vec<SignalMessage>>;

        /// Get device ID for a registration handle
        async fn device_id(&self, handle: u64) -> Result<DeviceId>;
    }

    /// Authenticated signaling inbox owned by the local service.
    #[async_trait::async_trait]
    pub trait AuthenticatedSignalingPort: Send + Sync {
        /// Drain verified, de-duplicated signaling events without blocking.
        async fn drain_authenticated_events(&self) -> Result<Vec<VerifiedSignalingEvent>>;
    }

    /// Application boundary that applies verified signaling to session aggregates.
    #[async_trait::async_trait]
    pub trait AuthenticatedSessionSignalPort: Send + Sync {
        /// Apply exactly one verified event using local authorization policy.
        async fn apply_authenticated_signal(&self, event: VerifiedSignalingEvent) -> Result<()>;
    }

    /// Session coordinator port - manages session state and signaling metadata
    pub trait SessionCoordinatorPort: Send + Sync {
        /// Request a new session as controller
        #[allow(clippy::too_many_arguments)]
        fn request_session(
            &mut self,
            session_id: SessionId,
            source_device_id: DeviceId,
            target_device_id: DeviceId,
            transport: String,
            listen_addr: Option<String>,
            server_name: Option<String>,
            cert_der_b64: Option<String>,
        ) -> Result<()>;

        /// Accept an incoming session as agent
        fn accept_session(
            &mut self,
            session_id: SessionId,
            transport: String,
            listen_addr: Option<String>,
            server_name: Option<String>,
            cert_der_b64: Option<String>,
        ) -> Result<()>;

        /// Apply a remote WebRTC offer
        fn apply_remote_offer(&mut self, session_id: SessionId, sdp: String) -> Result<()>;

        /// Apply a remote WebRTC answer
        fn apply_remote_answer(&mut self, session_id: SessionId, sdp: String) -> Result<()>;

        /// Apply a remote ICE candidate
        fn apply_remote_ice_candidate(
            &mut self,
            session_id: SessionId,
            candidate: IceCandidate,
        ) -> Result<()>;

        /// Get a snapshot of session state
        fn snapshot(&self, session_id: &SessionId) -> Option<SessionSnapshot>;
    }

    /// Session snapshot DTO
    #[derive(Debug, Clone)]
    pub struct SessionSnapshot {
        /// Stable session identifier.
        pub session_id: SessionId,
        /// Selected transport identifier.
        pub transport: String,
        /// Local controller/source device.
        pub source_device_id: Option<DeviceId>,
        /// Remote target/agent device.
        pub target_device_id: Option<DeviceId>,
        /// Local QUIC/WebRTC listen address when available.
        pub local_listen_addr: Option<String>,
        /// Local TLS/SNI server name.
        pub local_server_name: Option<String>,
        /// Local certificate DER, base64 encoded.
        pub local_cert_der_b64: Option<String>,
        /// Remote transport listen address.
        pub remote_listen_addr: Option<String>,
        /// Remote TLS/SNI server name.
        pub remote_server_name: Option<String>,
        /// Remote certificate DER, base64 encoded.
        pub remote_cert_der_b64: Option<String>,
        /// Explicit lifecycle state from domain model
        pub lifecycle_state: SessionLifecycleState,
        /// Last error if any
        pub last_error: Option<String>,
        /// Whether sender-side media is active.
        pub sender_active: bool,
        /// Whether receiver-side media is active.
        pub receiver_active: bool,
    }

    /// QUIC host port - manages QUIC transport connection
    #[async_trait::async_trait]
    pub trait QuicHostPort: Send + Sync {
        /// Sync host state from session snapshot
        async fn sync_from_session_snapshot(
            &self,
            local_device_id: &DeviceId,
            session_id: &SessionId,
            snapshot: &SessionSnapshot,
        ) -> Result<()>;
    }
}

/// Application use cases
pub mod usecases {
    use super::*;

    /// Apply signaling events to session coordinators
    ///
    /// This use case drains events from the signaling client and applies
    /// them to the appropriate session coordinators (QUIC or WebRTC).
    pub async fn apply_realtime_events(
        signaling: &dyn ports::SignalingPort,
        webrtc_sessions: &mut dyn ports::SessionCoordinatorPort,
        quic_sessions: &mut dyn ports::SessionCoordinatorPort,
        handle: u64,
    ) -> Result<Option<SessionId>> {
        let events = signaling.drain_events(handle).await?;
        let mut last_session_id: Option<SessionId> = None;

        for event in events {
            match event {
                SignalMessage::SessionRequest(request) => {
                    last_session_id = Some(request.session_id.clone());
                    if request.transport == "quic_quinn" {
                        quic_sessions.request_session(
                            request.session_id,
                            request.source_device_id,
                            request.target_device_id,
                            request.transport,
                            request.quic_listen_addr,
                            request.quic_server_name,
                            request.quic_cert_der_b64,
                        )?;
                    }
                }
                SignalMessage::SessionAccept(accept) => {
                    last_session_id = Some(accept.session_id.clone());
                    if accept.transport == "quic_quinn" {
                        quic_sessions.accept_session(
                            accept.session_id,
                            accept.transport,
                            accept.quic_listen_addr,
                            accept.quic_server_name,
                            accept.quic_cert_der_b64,
                        )?;
                    }
                }
                SignalMessage::WebrtcOffer(description) => {
                    last_session_id = Some(description.session_id.clone());
                    webrtc_sessions.apply_remote_offer(description.session_id, description.sdp)?;
                }
                SignalMessage::WebrtcAnswer(description) => {
                    last_session_id = Some(description.session_id.clone());
                    webrtc_sessions.apply_remote_answer(description.session_id, description.sdp)?;
                }
                SignalMessage::IceCandidate(candidate) => {
                    last_session_id = Some(candidate.session_id.clone());
                    webrtc_sessions
                        .apply_remote_ice_candidate(candidate.session_id.clone(), candidate)?;
                }
                _ => {}
            }
        }

        Ok(last_session_id)
    }

    /// Drain and apply all currently queued authenticated signaling events.
    ///
    /// Network adapters verify signatures and replay properties before exposing
    /// events through the port. This use case keeps transport ownership out of
    /// UI shells and applies each event through the service session boundary.
    pub async fn apply_authenticated_realtime_events(
        signaling: &dyn ports::AuthenticatedSignalingPort,
        sessions: &dyn ports::AuthenticatedSessionSignalPort,
    ) -> Result<usize> {
        let events = signaling.drain_authenticated_events().await?;
        let count = events.len();
        for event in events {
            sessions.apply_authenticated_signal(event).await?;
        }
        Ok(count)
    }

    /// Sync QUIC host from session snapshot
    ///
    /// This use case synchronizes the QUIC transport host with the
    /// current session state from the session coordinator.
    pub async fn sync_quic_host_from_session_snapshot(
        quic_host: &dyn ports::QuicHostPort,
        quic_sessions: &dyn ports::SessionCoordinatorPort,
        local_device_id: &DeviceId,
        session_id: &SessionId,
    ) -> Result<()> {
        let snapshot = quic_sessions.snapshot(session_id);
        if let Some(snapshot) = snapshot {
            quic_host
                .sync_from_session_snapshot(local_device_id, session_id, &snapshot)
                .await?;
        }
        Ok(())
    }

    /// Start a new controller session
    pub fn start_session() -> Result<()> {
        Ok(())
    }

    /// Accept an incoming agent session
    pub fn accept_session() -> Result<()> {
        Ok(())
    }

    /// Synchronize runtime state
    pub fn sync_runtime() -> Result<()> {
        Ok(())
    }
}

/// Re-exports
pub use ports::*;
pub use usecases::*;
