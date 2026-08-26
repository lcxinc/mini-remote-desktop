pub mod auth;
pub mod presence;
pub mod routes;
pub mod ws;

use auth::{AuthError, Authenticator, SystemChallengeSource};
use mrd_identity::DeviceIdentity;
use mrd_proto::{BackendRole, DeviceId};
use mrd_signal_proto::{
    AuthClaims, AuthenticatedSignalMessage, ProtocolReasonCode, Registered, RegisteredPayload,
    SignalEnvelope, SignalProtocolError, SignalReplayGuard, VerifiedSignalMetadata,
    WebRtcDescriptionRoleV3,
};
use presence::{PresenceEntry, PresenceError, PresenceRegistry};
use ring::rand::{SecureRandom, SystemRandom};
use routes::{AuthorizedRoutes, IntentDisposition, RouteError};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

pub use auth::{
    BackendTokenError, BackendTokenVerifier, RejectAllBackendTokens, VerifiedBackendToken,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId([u8; 16]);

impl ConnectionId {
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, RealtimeError> {
        if bytes == [0; 16] {
            return Err(RealtimeError::InvalidConnection);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub server_device_id: DeviceId,
    pub challenge_ttl_ms: u64,
    pub presence_ttl_ms: u64,
    pub route_ttl_ms: u64,
    pub max_connections: usize,
    pub max_messages_per_window: u32,
    pub rate_window_ms: u64,
}

impl CoreConfig {
    fn validate(&self) -> Result<(), RealtimeError> {
        if self.server_device_id.0.is_empty()
            || self.challenge_ttl_ms == 0
            || self.presence_ttl_ms == 0
            || self.route_ttl_ms == 0
            || self.max_connections == 0
            || self.max_messages_per_window == 0
            || self.rate_window_ms == 0
        {
            return Err(RealtimeError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTarget {
    Connection(ConnectionId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub target: DeliveryTarget,
    pub envelope: SignalEnvelope,
}

#[derive(Debug, Clone, Copy)]
struct RateState {
    window_started_ms: u64,
    count: u32,
}

pub struct RealtimeCore {
    config: CoreConfig,
    authenticator: Authenticator,
    server_identity: DeviceIdentity,
    server_counter: u64,
    replay: SignalReplayGuard,
    presence: PresenceRegistry,
    routes: AuthorizedRoutes,
    rates: HashMap<ConnectionId, RateState>,
}

impl std::fmt::Debug for RealtimeCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealtimeCore")
            .field("config", &self.config)
            .field("presence_count", &self.presence.len())
            .field("route_count", &self.routes.len())
            .finish_non_exhaustive()
    }
}

impl RealtimeCore {
    pub fn new(
        config: CoreConfig,
        token_verifier: Arc<dyn BackendTokenVerifier>,
    ) -> Result<Self, RealtimeError> {
        config.validate()?;
        let server_identity = DeviceIdentity::generate(&SystemRandom::new())
            .map_err(|_| RealtimeError::EntropyUnavailable)?;
        Ok(Self {
            authenticator: Authenticator::new(
                config.server_device_id.clone(),
                config.challenge_ttl_ms,
                token_verifier,
                Arc::new(SystemChallengeSource),
            ),
            config,
            server_identity,
            server_counter: 1,
            replay: SignalReplayGuard::new(4_096, 2_048),
            presence: PresenceRegistry::default(),
            routes: AuthorizedRoutes::default(),
            rates: HashMap::new(),
        })
    }

    pub fn config(&self) -> &CoreConfig {
        &self.config
    }

    pub fn open_connection(
        &mut self,
        connection_id: ConnectionId,
        now_ms: u64,
    ) -> Result<mrd_signal_proto::ServerChallenge, RealtimeError> {
        if self.rates.len() >= self.config.max_connections
            || self.rates.contains_key(&connection_id)
        {
            return Err(RealtimeError::ConnectionCapacity);
        }
        self.rates.insert(
            connection_id,
            RateState {
                window_started_ms: now_ms,
                count: 0,
            },
        );
        match self.authenticator.issue(connection_id, now_ms) {
            Ok(challenge) => Ok(challenge),
            Err(error) => {
                self.rates.remove(&connection_id);
                Err(error.into())
            }
        }
    }

    pub fn handle(
        &mut self,
        connection_id: ConnectionId,
        envelope: SignalEnvelope,
        now_ms: u64,
    ) -> Result<Vec<Delivery>, RealtimeError> {
        self.check_rate(connection_id, now_ms)?;
        envelope.validate_version()?;
        match &envelope.message {
            AuthenticatedSignalMessage::Register(register) => {
                return self.handle_register(connection_id, register, now_ms)
            }
            AuthenticatedSignalMessage::ServerChallenge(_)
            | AuthenticatedSignalMessage::Registered(_)
            | AuthenticatedSignalMessage::ProtocolError(_)
            | AuthenticatedSignalMessage::ReconnectRequest(_)
            | AuthenticatedSignalMessage::ReconnectGrant(_) => {
                return Err(RealtimeError::UnsupportedMessage)
            }
            _ => {}
        }

        let presence = self.registered_presence(connection_id, now_ms)?.clone();
        match &envelope.message {
            AuthenticatedSignalMessage::PresenceHeartbeat(heartbeat) => {
                let metadata = heartbeat.verify_for(
                    &self.config.server_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                if heartbeat.payload.connection_id != *connection_id.as_bytes() {
                    return Err(RealtimeError::SenderBinding);
                }
                self.presence.heartbeat(connection_id, now_ms)?;
                Ok(Vec::new())
            }
            AuthenticatedSignalMessage::SessionIntent(_)
            | AuthenticatedSignalMessage::SessionGrant(_)
            | AuthenticatedSignalMessage::WebrtcOffer(_)
            | AuthenticatedSignalMessage::WebrtcAnswer(_)
            | AuthenticatedSignalMessage::WebrtcCandidate(_) => {
                Err(SignalProtocolError::UnsupportedVersion.into())
            }
            AuthenticatedSignalMessage::SessionIntentV3(intent) => {
                let request = &intent.payload.request;
                let metadata =
                    intent.verify_for(&request.target_device_id, now_ms, &mut self.replay)?;
                self.bind_sender(&presence, &metadata)?;
                if presence.role != BackendRole::Controller {
                    return Err(RealtimeError::UnauthorizedRoute);
                }
                let target = self
                    .presence
                    .by_device(&request.target_device_id)
                    .ok_or(RealtimeError::TargetUnavailable)?
                    .clone();
                if target.role != BackendRole::Agent {
                    return Err(RealtimeError::UnauthorizedRoute);
                }
                let disposition =
                    self.routes
                        .apply_intent(&presence.device_id, &intent.payload, now_ms)?;
                tracing::info!(
                    session_id = %request.session_id.0,
                    controller_device_id = %presence.device_id.0,
                    target_device_id = %target.device_id.0,
                    duplicate = disposition == IntentDisposition::Duplicate,
                    "authenticated v3 session intent routed"
                );
                Ok(vec![delivery(target.connection_id, envelope)])
            }
            AuthenticatedSignalMessage::SessionGrantV3(grant) => {
                let metadata = grant.verify_for(
                    &grant.payload.controller_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                if presence.role != BackendRole::Agent {
                    return Err(RealtimeError::UnauthorizedRoute);
                }
                let peer = self
                    .routes
                    .apply_grant(&presence.device_id, &grant.payload, now_ms)?;
                tracing::info!(
                    session_id = %grant.payload.session_id.0,
                    target_device_id = %presence.device_id.0,
                    controller_device_id = %peer.0,
                    "authenticated v3 session route granted"
                );
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::WebrtcOfferV3(offer) => {
                let metadata =
                    offer.verify_for(&offer.payload.target_device_id, now_ms, &mut self.replay)?;
                self.bind_sender(&presence, &metadata)?;
                if presence.role != BackendRole::Controller {
                    return Err(RealtimeError::UnauthorizedRoute);
                }
                let peer = self.routes.resolve_granted(
                    &offer.payload.session_id,
                    &presence.device_id,
                    now_ms,
                )?;
                self.require_intended_peer(&metadata, &peer)?;
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::WebrtcAnswerV3(answer) => {
                let metadata = answer.verify_for(
                    &answer.payload.controller_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                if presence.role != BackendRole::Agent {
                    return Err(RealtimeError::UnauthorizedRoute);
                }
                let peer = self.routes.resolve_granted(
                    &answer.payload.session_id,
                    &presence.device_id,
                    now_ms,
                )?;
                self.require_intended_peer(&metadata, &peer)?;
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::WebrtcCandidateV3(candidate) => {
                let (expected_peer, required_role) = match candidate.payload.description_role {
                    WebRtcDescriptionRoleV3::Offer => {
                        (&candidate.payload.target_device_id, BackendRole::Controller)
                    }
                    WebRtcDescriptionRoleV3::Answer => {
                        (&candidate.payload.controller_device_id, BackendRole::Agent)
                    }
                };
                let metadata = candidate.verify_for(expected_peer, now_ms, &mut self.replay)?;
                self.bind_sender(&presence, &metadata)?;
                if presence.role != required_role {
                    return Err(RealtimeError::UnauthorizedRoute);
                }
                let peer = self.routes.resolve_granted(
                    &candidate.payload.session_id,
                    &presence.device_id,
                    now_ms,
                )?;
                self.require_intended_peer(&metadata, &peer)?;
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::SessionDeny(deny) => {
                let metadata =
                    deny.verify_for(&deny.payload.controller_device_id, now_ms, &mut self.replay)?;
                self.bind_sender(&presence, &metadata)?;
                let peer = self
                    .routes
                    .deny(&deny.payload.session_id, &presence.device_id)?;
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::RelayMigrationOffer(offer) => {
                let metadata = offer.verify_for(
                    &offer.payload.claims.intended_peer_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                let peer = self.routes.resolve_migration_offer(
                    &presence.device_id,
                    &offer.payload,
                    now_ms,
                )?;
                self.require_intended_peer(&metadata, &peer)?;
                tracing::info!(
                    session_id = %offer.payload.session_id.0,
                    migration_generation = offer.payload.migration_generation,
                    directory_id = %offer.payload.directory_id,
                    node_id = %offer.payload.node_id,
                    "authenticated relay migration offer routed"
                );
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::RelayMigrationAnswer(answer) => {
                let metadata = answer.verify_for(
                    &answer.payload.claims.intended_peer_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                let peer = self.routes.resolve_migration_answer(
                    &presence.device_id,
                    &answer.payload,
                    now_ms,
                )?;
                self.require_intended_peer(&metadata, &peer)?;
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::RelayMigrationCandidate(candidate) => {
                let metadata = candidate.verify_for(
                    &candidate.payload.claims.intended_peer_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                let peer = self.routes.resolve_migration_candidate(
                    &presence.device_id,
                    &candidate.payload,
                    now_ms,
                )?;
                self.require_intended_peer(&metadata, &peer)?;
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            AuthenticatedSignalMessage::SessionClose(close) => {
                let metadata = close.verify_for(
                    &close.payload.claims.intended_peer_device_id,
                    now_ms,
                    &mut self.replay,
                )?;
                self.bind_sender(&presence, &metadata)?;
                let peer = self
                    .routes
                    .close(&close.payload.session_id, &presence.device_id)?;
                self.require_intended_peer(&metadata, &peer)?;
                tracing::info!(
                    session_id = %close.payload.session_id.0,
                    closing_device_id = %presence.device_id.0,
                    peer_device_id = %peer.0,
                    "authenticated session route closed"
                );
                Ok(vec![delivery(self.connection_for(&peer)?, envelope)])
            }
            _ => Err(RealtimeError::UnsupportedMessage),
        }
    }

    fn handle_register(
        &mut self,
        connection_id: ConnectionId,
        register: &mrd_signal_proto::AuthenticatedRegister,
        now_ms: u64,
    ) -> Result<Vec<Delivery>, RealtimeError> {
        if self.presence.by_connection(connection_id).is_some() {
            return Err(RealtimeError::AlreadyRegistered);
        }
        let registration =
            self.authenticator
                .authenticate(connection_id, register, now_ms, &mut self.replay)?;
        self.presence.register(PresenceEntry {
            connection_id,
            device_id: registration.token.device_id.clone(),
            device_key_id: registration.token.device_key_id,
            role: registration.token.role,
            last_seen_ms: now_ms,
            token_expires_at_ms: registration.token.expires_at_ms,
        })?;
        let registered =
            self.sign_registered(registration.token.device_id, connection_id, now_ms)?;
        tracing::info!(
            connection_id = ?connection_id,
            device_id = %registered.payload.registered_device_id.0,
            "authenticated realtime presence registered"
        );
        Ok(vec![delivery(
            connection_id,
            SignalEnvelope::new(AuthenticatedSignalMessage::Registered(registered)),
        )])
    }

    fn sign_registered(
        &mut self,
        device_id: DeviceId,
        connection_id: ConnectionId,
        now_ms: u64,
    ) -> Result<Registered, RealtimeError> {
        let counter = self.server_counter;
        self.server_counter = self
            .server_counter
            .checked_add(1)
            .ok_or(RealtimeError::CounterExhausted)?;
        let mut nonce = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| RealtimeError::EntropyUnavailable)?;
        Registered::sign(
            &self.server_identity,
            RegisteredPayload {
                claims: AuthClaims {
                    issuer_device_id: self.config.server_device_id.clone(),
                    issuer_key_id: self.server_identity.key_id().into(),
                    intended_peer_device_id: device_id.clone(),
                    issued_at_ms: now_ms,
                    expires_at_ms: now_ms.saturating_add(self.config.presence_ttl_ms),
                    counter,
                    nonce,
                },
                registered_device_id: device_id,
                connection_id: *connection_id.as_bytes(),
                heartbeat_interval_ms: u32::try_from(self.config.presence_ttl_ms / 3)
                    .unwrap_or(u32::MAX)
                    .max(1),
            },
        )
        .map_err(Into::into)
    }

    fn registered_presence(
        &mut self,
        connection_id: ConnectionId,
        now_ms: u64,
    ) -> Result<&PresenceEntry, RealtimeError> {
        let entry = self
            .presence
            .by_connection(connection_id)
            .ok_or(RealtimeError::NotRegistered)?;
        if now_ms >= entry.token_expires_at_ms {
            self.disconnect(connection_id);
            return Err(RealtimeError::TokenExpired);
        }
        self.presence
            .by_connection(connection_id)
            .ok_or(RealtimeError::NotRegistered)
    }

    fn bind_sender(
        &self,
        presence: &PresenceEntry,
        metadata: &VerifiedSignalMetadata,
    ) -> Result<(), RealtimeError> {
        if presence.device_id != metadata.issuer_device_id
            || presence.device_key_id != metadata.issuer_key_id
        {
            return Err(RealtimeError::SenderBinding);
        }
        Ok(())
    }

    fn require_intended_peer(
        &self,
        metadata: &VerifiedSignalMetadata,
        peer: &DeviceId,
    ) -> Result<(), RealtimeError> {
        if &metadata.intended_peer_device_id != peer {
            return Err(RealtimeError::UnauthorizedRoute);
        }
        Ok(())
    }

    fn connection_for(&self, device: &DeviceId) -> Result<ConnectionId, RealtimeError> {
        self.presence
            .by_device(device)
            .map(|entry| entry.connection_id)
            .ok_or(RealtimeError::TargetUnavailable)
    }

    fn check_rate(
        &mut self,
        connection_id: ConnectionId,
        now_ms: u64,
    ) -> Result<(), RealtimeError> {
        let state = self
            .rates
            .get_mut(&connection_id)
            .ok_or(RealtimeError::InvalidConnection)?;
        if now_ms
            >= state
                .window_started_ms
                .saturating_add(self.config.rate_window_ms)
        {
            state.window_started_ms = now_ms;
            state.count = 0;
        }
        if state.count >= self.config.max_messages_per_window {
            return Err(RealtimeError::RateLimited);
        }
        state.count += 1;
        Ok(())
    }

    pub fn disconnect(&mut self, connection_id: ConnectionId) {
        self.authenticator.remove_connection(connection_id);
        self.rates.remove(&connection_id);
        if let Some(presence) = self.presence.remove_connection(connection_id) {
            self.routes.remove_device(&presence.device_id);
            tracing::info!(
                connection_id = ?connection_id,
                device_id = %presence.device_id.0,
                "realtime presence disconnected"
            );
        }
    }

    pub fn prune(&mut self, now_ms: u64) -> Vec<ConnectionId> {
        let expired = self.presence.prune(now_ms, self.config.presence_ttl_ms);
        let expired_connections = expired
            .iter()
            .map(|presence| presence.connection_id)
            .collect();
        for presence in expired {
            self.rates.remove(&presence.connection_id);
            self.routes.remove_device(&presence.device_id);
        }
        self.routes.prune(now_ms, self.config.route_ttl_ms);
        expired_connections
    }

    pub fn is_present(&self, device: &DeviceId) -> bool {
        self.presence.by_device(device).is_some()
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn presence_count(&self) -> usize {
        self.presence.len()
    }
}

fn delivery(connection_id: ConnectionId, envelope: SignalEnvelope) -> Delivery {
    Delivery {
        target: DeliveryTarget::Connection(connection_id),
        envelope,
    }
}

#[derive(Debug, Error)]
pub enum RealtimeError {
    #[error("realtime server configuration is invalid")]
    InvalidConfig,
    #[error("connection id is invalid")]
    InvalidConnection,
    #[error("connection capacity is exhausted")]
    ConnectionCapacity,
    #[error("connection message rate exceeded")]
    RateLimited,
    #[error("connection is not authenticated")]
    NotRegistered,
    #[error("connection is already authenticated")]
    AlreadyRegistered,
    #[error("signed sender does not match authenticated presence")]
    SenderBinding,
    #[error("target device is unavailable")]
    TargetUnavailable,
    #[error("session route is unauthorized")]
    UnauthorizedRoute,
    #[error("backend token expired")]
    TokenExpired,
    #[error("message type is unsupported on this endpoint")]
    UnsupportedMessage,
    #[error("server counter is exhausted")]
    CounterExhausted,
    #[error("server entropy is unavailable")]
    EntropyUnavailable,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Presence(#[from] PresenceError),
    #[error(transparent)]
    Route(#[from] RouteError),
    #[error(transparent)]
    Protocol(#[from] SignalProtocolError),
}

impl RealtimeError {
    pub fn reason_code(&self) -> ProtocolReasonCode {
        match self {
            Self::InvalidConfig | Self::CounterExhausted | Self::EntropyUnavailable => {
                ProtocolReasonCode::Internal
            }
            Self::InvalidConnection | Self::UnsupportedMessage => ProtocolReasonCode::Malformed,
            Self::ConnectionCapacity | Self::RateLimited => ProtocolReasonCode::RateLimited,
            Self::NotRegistered
            | Self::AlreadyRegistered
            | Self::SenderBinding
            | Self::UnauthorizedRoute => ProtocolReasonCode::UnauthorizedRoute,
            Self::TargetUnavailable => ProtocolReasonCode::UnknownSession,
            Self::TokenExpired => ProtocolReasonCode::Expired,
            Self::Protocol(error) => error.reason_code(),
            Self::Auth(error) => match error {
                AuthError::ChallengeExpired | AuthError::TokenExpired => {
                    ProtocolReasonCode::Expired
                }
                AuthError::Protocol(protocol) => protocol.reason_code(),
                _ => ProtocolReasonCode::AuthenticationFailed,
            },
            Self::Presence(_) => ProtocolReasonCode::Conflict,
            Self::Route(error) => match error {
                RouteError::UnknownSession => ProtocolReasonCode::UnknownSession,
                RouteError::Conflict | RouteError::MigrationConflict => {
                    ProtocolReasonCode::Conflict
                }
                _ => ProtocolReasonCode::UnauthorizedRoute,
            },
        }
    }
}
