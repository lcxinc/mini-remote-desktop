use super::protocol::LanDiscoveryPacket;
use crate::app_state::AppState;
use anyhow::{Context, Result};
use common_control_proto::{
    authenticated_input_scope, decode_authenticated_input_event, encode_authenticated_input_event,
    AuthenticatedInputScope, ControlEvent,
};
use mrd_identity::{public_key_id, verify_context_bytes};
use mrd_ipc::{
    ControlInputButton, ControlInputEvent, ControlInputKey, ControlInputLane, RemoteFailure,
    RemotePermissionScope, RemoteReasonCode,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_session::{
    ControlEnvelopeError, ControlSequenceDecision, ControlSequenceError, ControlSequenceWindow,
    PermissionScope, SignedControlEnvelopeV2, CONTROL_ENVELOPE_MAX_LIFETIME_MS,
    CONTROL_ENVELOPE_MAX_WIRE_BYTES, CONTROL_ENVELOPE_SIGNATURE_CONTEXT, CONTROL_ENVELOPE_VERSION,
};
use ring::digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub const AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX: &[u8] = b"MRD_CTRL_INPUT_V2\0";
const AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX: &[u8] = b"MRD_CTRL_ACK_V2\0";
const CONTROL_INPUT_ACK_SIGNATURE_CONTEXT: &str = "MRD_LAN_CONTROL_ACK_V2";
const CONTROL_INPUT_REPLAY_WINDOW_WIDTH: usize = 128;
pub(crate) const CONTROL_INPUT_REPLAY_SESSION_LIMIT: usize = 2_048;
const CONTROL_INPUT_ACK_MAX_WIRE_BYTES: usize = 4_096;
const CONTROL_INPUT_ACK_LIFETIME_MS: u64 = 5_000;
const CONTROL_INPUT_AUDIT_ACTION: &str = "session.control_input_decision";

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct AuthenticatedControlReplayKey {
    pub(crate) session_id: String,
    pub(crate) grant_id: [u8; 32],
    pub(crate) source_key_id: String,
}

impl std::fmt::Debug for AuthenticatedControlReplayKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedControlReplayKey")
            .field("session_id", &"OPAQUE")
            .field("grant_id", &"SET")
            .field("source_key_id", &"SET")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct AuthenticatedControlSenderKey {
    pub(super) session_id: String,
    pub(super) grant_id: [u8; 32],
    pub(super) target_key_id: String,
}

#[derive(Debug)]
pub(super) struct AuthenticatedControlSenderState {
    reliable_sequence: Arc<tokio::sync::Mutex<u64>>,
    realtime_sequence: Arc<tokio::sync::Mutex<u64>>,
    next_event_id: AtomicU64,
    route: tokio::sync::Mutex<Option<AuthenticatedControlRoute>>,
    pub(super) expires_at_ms: u64,
}

#[derive(Debug, Clone)]
struct AuthenticatedControlRoute {
    target: SocketAddr,
    peer_device_id: DeviceId,
    peer_key_id: String,
    peer_public_key: [u8; 32],
}

impl AuthenticatedControlSenderState {
    fn new(expires_at_ms: u64) -> Self {
        Self {
            reliable_sequence: Arc::new(tokio::sync::Mutex::new(1)),
            realtime_sequence: Arc::new(tokio::sync::Mutex::new(1)),
            next_event_id: AtomicU64::new(1),
            route: tokio::sync::Mutex::new(None),
            expires_at_ms,
        }
    }

    fn sequence_for_lane(&self, lane: ControlInputLane) -> Arc<tokio::sync::Mutex<u64>> {
        match lane {
            ControlInputLane::Reliable | ControlInputLane::Cleanup => {
                Arc::clone(&self.reliable_sequence)
            }
            ControlInputLane::Realtime => Arc::clone(&self.realtime_sequence),
        }
    }

    fn next_event_id(&self) -> u64 {
        self.next_event_id.fetch_add(1, Ordering::Relaxed).max(1)
    }
}

pub(crate) struct AuthenticatedControlReplayState {
    realtime_window: ControlSequenceWindow,
    realtime_highest_sequence: u64,
    reliable_next_sequence: u64,
    reliable_observations: HashMap<u64, (u64, [u8; 32])>,
    reliable_sequence_by_event: HashMap<u64, u64>,
    acknowledgements: HashMap<(AuthenticatedControlReplayLane, u64), Vec<u8>>,
    expires_at_ms: u64,
}

impl std::fmt::Debug for AuthenticatedControlReplayState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedControlReplayState")
            .field("realtime_highest_sequence", &self.realtime_highest_sequence)
            .field("reliable_next_sequence", &self.reliable_next_sequence)
            .field("realtime_observations", &self.realtime_window.len())
            .field("reliable_observations", &self.reliable_observations.len())
            .field("acknowledgement_count", &self.acknowledgements.len())
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AuthenticatedControlReplayLane {
    Reliable,
    Cleanup,
    Realtime,
}

impl AuthenticatedControlReplayLane {
    pub(crate) fn from_input_lane(lane: ControlInputLane) -> Self {
        match lane {
            ControlInputLane::Reliable => Self::Reliable,
            ControlInputLane::Cleanup => Self::Cleanup,
            ControlInputLane::Realtime => Self::Realtime,
        }
    }
}

impl AuthenticatedControlReplayState {
    pub(crate) fn new(expires_at_ms: u64) -> Self {
        Self {
            realtime_window: ControlSequenceWindow::new(CONTROL_INPUT_REPLAY_WINDOW_WIDTH),
            realtime_highest_sequence: 0,
            reliable_next_sequence: 1,
            reliable_observations: HashMap::new(),
            reliable_sequence_by_event: HashMap::new(),
            acknowledgements: HashMap::new(),
            expires_at_ms,
        }
    }

    pub(crate) fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at_ms
    }

    pub(crate) fn observe(
        &mut self,
        lane: AuthenticatedControlReplayLane,
        sequence: u64,
        event_id: u64,
        commitment: [u8; 32],
    ) -> std::result::Result<ControlSequenceDecision, ControlSequenceError> {
        if lane == AuthenticatedControlReplayLane::Realtime {
            if sequence < self.realtime_highest_sequence {
                return Err(ControlSequenceError::OutOfWindow);
            }
            let decision = self
                .realtime_window
                .observe(sequence, event_id, commitment)?;
            if decision == ControlSequenceDecision::FirstSeen {
                self.realtime_highest_sequence = sequence;
            }
            return Ok(decision);
        }
        if sequence == 0 || sequence == u64::MAX || event_id == 0 {
            return Err(ControlSequenceError::Invalid);
        }
        if lane == AuthenticatedControlReplayLane::Cleanup {
            if sequence > self.reliable_next_sequence.saturating_add(1) {
                return Err(ControlSequenceError::OutOfWindow);
            }
            if sequence < self.reliable_next_sequence {
                return match self.reliable_observations.get(&sequence) {
                    Some((observed_event_id, observed_commitment))
                        if *observed_event_id == event_id && *observed_commitment == commitment =>
                    {
                        Ok(ControlSequenceDecision::ExactRetry)
                    }
                    Some(_) => Err(ControlSequenceError::Duplicate),
                    None => Err(ControlSequenceError::OutOfWindow),
                };
            }
            if self.reliable_sequence_by_event.contains_key(&event_id) {
                return Err(ControlSequenceError::Duplicate);
            }
            self.reliable_observations
                .insert(sequence, (event_id, commitment));
            self.reliable_sequence_by_event.insert(event_id, sequence);
            self.reliable_next_sequence = sequence.saturating_add(1);
            self.prune_reliable_observations();
            return Ok(ControlSequenceDecision::FirstSeen);
        }
        if sequence > self.reliable_next_sequence {
            return Err(ControlSequenceError::OutOfWindow);
        }
        if sequence < self.reliable_next_sequence {
            return match self.reliable_observations.get(&sequence) {
                Some((observed_event_id, observed_commitment))
                    if *observed_event_id == event_id && *observed_commitment == commitment =>
                {
                    Ok(ControlSequenceDecision::ExactRetry)
                }
                Some(_) => Err(ControlSequenceError::Duplicate),
                None => Err(ControlSequenceError::OutOfWindow),
            };
        }
        if self.reliable_sequence_by_event.contains_key(&event_id) {
            return Err(ControlSequenceError::Duplicate);
        }
        self.reliable_observations
            .insert(sequence, (event_id, commitment));
        self.reliable_sequence_by_event.insert(event_id, sequence);
        self.reliable_next_sequence = self.reliable_next_sequence.saturating_add(1);
        self.prune_reliable_observations();
        Ok(ControlSequenceDecision::FirstSeen)
    }

    fn prune_reliable_observations(&mut self) {
        while self.reliable_observations.len() > CONTROL_INPUT_REPLAY_WINDOW_WIDTH {
            let Some(oldest) = self.reliable_observations.keys().copied().min() else {
                break;
            };
            if let Some((old_event_id, _)) = self.reliable_observations.remove(&oldest) {
                self.reliable_sequence_by_event.remove(&old_event_id);
            }
            self.acknowledgements
                .remove(&(AuthenticatedControlReplayLane::Reliable, oldest));
            self.acknowledgements
                .remove(&(AuthenticatedControlReplayLane::Cleanup, oldest));
        }
    }

    pub(crate) fn cached_ack(
        &self,
        lane: AuthenticatedControlReplayLane,
        sequence: u64,
    ) -> Option<Vec<u8>> {
        self.acknowledgements.get(&(lane, sequence)).cloned()
    }

    pub(crate) fn cache_ack(
        &mut self,
        lane: AuthenticatedControlReplayLane,
        sequence: u64,
        datagram: Vec<u8>,
    ) {
        self.acknowledgements.insert((lane, sequence), datagram);
        if lane == AuthenticatedControlReplayLane::Realtime {
            while self
                .acknowledgements
                .keys()
                .filter(|(ack_lane, _)| *ack_lane == lane)
                .count()
                > CONTROL_INPUT_REPLAY_WINDOW_WIDTH
            {
                let Some(oldest) = self
                    .acknowledgements
                    .keys()
                    .filter_map(|(ack_lane, sequence)| (*ack_lane == lane).then_some(*sequence))
                    .min()
                else {
                    break;
                };
                self.acknowledgements.remove(&(lane, oldest));
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ControlInputAckV2 {
    protocol_version: u16,
    session_id: SessionId,
    grant_id: [u8; 32],
    source_key_id: String,
    target_key_id: String,
    sequence: u64,
    event_id: u64,
    request_commitment: [u8; 32],
    accepted: bool,
    reason: Option<RemoteReasonCode>,
    lane: Option<ControlInputLane>,
    event_count: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl ControlInputAckV2 {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u16,
            kind: &'static str,
            payload: &'a ControlInputAckV2,
        }

        Ok(serde_json::to_vec(&Commitment {
            schema_version: CONTROL_ENVELOPE_VERSION,
            kind: "control_input_ack",
            payload: self,
        })?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedControlInputAckV2 {
    payload: ControlInputAckV2,
    public_key: [u8; 32],
    signature: Vec<u8>,
}

pub(super) async fn process_authenticated_control_input_datagram(
    socket: &UdpSocket,
    app_state: &Arc<AppState>,
    envelope_bytes: &[u8],
    addr: SocketAddr,
) -> Result<()> {
    let received_at_ms = super::now_ms();
    // This is the only decoder for the independent V2 datagram prefix. The
    // raw-size check runs before serde allocates any envelope-owned buffers.
    let envelope =
        match SignedControlEnvelopeV2::decode_bounded_json(envelope_bytes, received_at_ms) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::debug!(%error, %addr, "rejected malformed authenticated control datagram");
                return Ok(());
            }
        };
    let signing_bytes = envelope
        .payload
        .signing_bytes()
        .context("failed to canonicalize authenticated control input")?;
    let request_commitment = control_request_commitment(&envelope, &signing_bytes);

    let authorization_guard = app_state.authorization_security_gate.lock().await;
    let decision_at_ms = super::now_ms();
    let local_device_id = DeviceId(super::local_device_id(app_state).await?);
    let local_identity = app_state.device_identities.machine_identity();

    let transport_kind = app_state
        .session_authorizations
        .transport_kind(&envelope.payload.session_id)
        .await;
    let validation = if matches!(transport_kind.as_deref(), Some("quic" | "lan_quic")) {
        validate_authenticated_control_input(
            app_state,
            &envelope,
            &signing_bytes,
            &local_device_id,
            local_identity.key_id(),
            decision_at_ms,
        )
        .await
    } else {
        Err(control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "authenticated LAN control input requires a verified LAN authorization",
        ))
    };
    let (authorization, event, lane) = match validation {
        Ok(validated) => validated,
        Err(failure) => {
            let ack = signed_control_ack_datagram(
                local_identity.as_ref(),
                &envelope,
                request_commitment,
                Err(failure.clone()),
                decision_at_ms,
            )?;
            terminate_terminal_control_authorization_if_present(
                app_state,
                &envelope.payload.session_id,
            )
            .await;
            audit_control_input_denial(app_state, &envelope, &failure, addr).await?;
            drop(authorization_guard);
            socket.send_to(&ack, addr).await?;
            return Ok(());
        }
    };

    let replay_key = AuthenticatedControlReplayKey {
        session_id: envelope.payload.session_id.0.clone(),
        grant_id: envelope.payload.grant_id,
        source_key_id: envelope.payload.source_key_id.clone(),
    };
    let mut replay_cache = app_state
        .lan_discovery
        .authenticated_control_inputs
        .lock()
        .await;
    prune_authenticated_control_replays(&mut replay_cache, decision_at_ms);
    if !replay_cache.contains_key(&replay_key)
        && replay_cache.len() >= CONTROL_INPUT_REPLAY_SESSION_LIMIT
    {
        let failure = control_failure(
            RemoteReasonCode::ReplayDetected,
            "authenticated control replay capacity is exhausted",
        );
        let ack = signed_control_ack_datagram(
            local_identity.as_ref(),
            &envelope,
            request_commitment,
            Err(failure.clone()),
            decision_at_ms,
        )?;
        drop(replay_cache);
        audit_control_input_denial(app_state, &envelope, &failure, addr).await?;
        drop(authorization_guard);
        socket.send_to(&ack, addr).await?;
        return Ok(());
    }
    let replay = replay_cache
        .entry(replay_key)
        .or_insert_with(|| AuthenticatedControlReplayState::new(authorization.expires_at_ms));
    let replay_lane = AuthenticatedControlReplayLane::from_input_lane(lane);
    match replay.observe(
        replay_lane,
        envelope.payload.sequence,
        envelope.payload.event_id,
        request_commitment,
    ) {
        Ok(ControlSequenceDecision::ExactRetry) => {
            let cached = replay
                .cached_ack(replay_lane, envelope.payload.sequence)
                .context("authenticated control retry has no cached acknowledgement")?;
            drop(replay_cache);
            drop(authorization_guard);
            socket.send_to(&cached, addr).await?;
            return Ok(());
        }
        Err(error) => {
            let failure = replay_failure(error);
            let ack = signed_control_ack_datagram(
                local_identity.as_ref(),
                &envelope,
                request_commitment,
                Err(failure.clone()),
                decision_at_ms,
            )?;
            drop(replay_cache);
            audit_control_input_denial(app_state, &envelope, &failure, addr).await?;
            drop(authorization_guard);
            socket.send_to(&ack, addr).await?;
            return Ok(());
        }
        Ok(ControlSequenceDecision::FirstSeen) => {}
    }

    // Keep the authorization gate held through the final injection call. Trust,
    // policy, revocation, and terminal-route transitions use the same gate.
    let control_input_registry = app_state.control_input();
    let mut control_input = control_input_registry.lock().await;
    let injection_at_ms = super::now_ms();
    let expired = injection_at_ms > authorization.expires_at_ms
        || injection_at_ms > envelope.payload.expires_at_ms;
    let security_unhealthy =
        !app_state.security_is_healthy() && !matches!(&event, ControlInputEvent::ReleaseAll);
    if expired || security_unhealthy {
        let failure = if expired {
            control_failure(
                RemoteReasonCode::GrantExpired,
                "authenticated control input expired before injection",
            )
        } else {
            control_failure(
                RemoteReasonCode::PolicyChanged,
                "authoritative security state became unavailable before injection",
            )
        };
        let ack = signed_control_ack_datagram(
            local_identity.as_ref(),
            &envelope,
            request_commitment,
            Err(failure.clone()),
            injection_at_ms,
        )?;
        replay.cache_ack(replay_lane, envelope.payload.sequence, ack.clone());
        if let Err(error) = control_input.release_session_all(&authorization.session_id) {
            tracing::warn!(
                session_id = %authorization.session_id.0,
                %error,
                "failed to release session input after control grant expiry"
            );
        }
        drop(control_input);
        drop(replay_cache);
        audit_control_input_denial(app_state, &envelope, &failure, addr).await?;
        if expired {
            let _ = app_state
                .session_authorizations
                .snapshot_at(&authorization.session_id, injection_at_ms)
                .await;
        } else {
            let _ = app_state
                .session_authorizations
                .record_failure(
                    &authorization.session_id,
                    mrd_ipc::RemoteAuthorizationState::PolicyChanged,
                    failure.clone(),
                    injection_at_ms,
                )
                .await;
        }
        super::terminate_authorized_remote_sessions_under_security_gate(
            app_state,
            std::slice::from_ref(&authorization.session_id),
        )
        .await;
        drop(authorization_guard);
        socket.send_to(&ack, addr).await?;
        return Ok(());
    }
    let injection = control_input.handle_authenticated_session_event(
        &authorization.session_id,
        service_control_scope(envelope.payload.scope),
        &event,
    );
    drop(control_input);
    let (ack_result, failure) = match injection {
        Ok(result) => (Ok((lane, result.event_count)), None),
        Err(error) => {
            let failure = RemoteFailure {
                code: RemoteReasonCode::PolicyChanged,
                message: format!("authorized control input could not be injected: {error}"),
                suggested_action: None,
            };
            (Err(failure.clone()), Some(failure))
        }
    };
    let ack = signed_control_ack_datagram(
        local_identity.as_ref(),
        &envelope,
        request_commitment,
        ack_result,
        decision_at_ms,
    )?;
    replay.cache_ack(replay_lane, envelope.payload.sequence, ack.clone());
    drop(replay_cache);

    if let Some(failure) = failure {
        if let Err(release_error) = control_input_registry
            .lock()
            .await
            .release_session_all(&authorization.session_id)
        {
            tracing::warn!(
                session_id = %authorization.session_id.0,
                %release_error,
                "failed to release session input after injector failure"
            );
        }
        let _ = app_state
            .session_authorizations
            .record_failure(
                &authorization.session_id,
                mrd_ipc::RemoteAuthorizationState::PolicyChanged,
                failure.clone(),
                super::now_ms(),
            )
            .await;
        super::terminate_authorized_remote_sessions_under_security_gate(
            app_state,
            std::slice::from_ref(&authorization.session_id),
        )
        .await;
        audit_control_input_denial(app_state, &envelope, &failure, addr).await?;
    }
    drop(authorization_guard);
    socket.send_to(&ack, addr).await?;
    Ok(())
}

async fn terminate_terminal_control_authorization_if_present(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) {
    let terminal = app_state
        .session_authorizations
        .snapshot(session_id)
        .await
        .is_some_and(|snapshot| {
            matches!(
                snapshot.authorization_state,
                mrd_ipc::RemoteAuthorizationState::Denied
                    | mrd_ipc::RemoteAuthorizationState::Expired
                    | mrd_ipc::RemoteAuthorizationState::Revoked
                    | mrd_ipc::RemoteAuthorizationState::LockedOut
                    | mrd_ipc::RemoteAuthorizationState::PolicyChanged
            )
        });
    if terminal {
        super::terminate_authorized_remote_sessions_under_security_gate(
            app_state,
            std::slice::from_ref(session_id),
        )
        .await;
    }
}

pub(crate) async fn validate_authenticated_control_input(
    app_state: &Arc<AppState>,
    envelope: &SignedControlEnvelopeV2,
    signing_bytes: &[u8],
    local_device_id: &DeviceId,
    local_key_id: &str,
    now_ms: u64,
) -> Result<
    (
        crate::session_authorization::ActiveControlAuthorization,
        ControlInputEvent,
        ControlInputLane,
    ),
    RemoteFailure,
> {
    let payload = &envelope.payload;
    if payload.target_device_id != *local_device_id || payload.target_key_id != local_key_id {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "authenticated control input targets a different device identity",
        ));
    }
    if public_key_id(&envelope.public_key) != payload.source_key_id
        || verify_context_bytes(
            &envelope.public_key,
            CONTROL_ENVELOPE_SIGNATURE_CONTEXT,
            signing_bytes,
            &envelope.signature,
        )
        .is_err()
    {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "authenticated control input signature is invalid",
        ));
    }
    envelope
        .validate_shape(now_ms)
        .map_err(|error| match error {
            ControlEnvelopeError::Expired => control_failure(
                RemoteReasonCode::GrantExpired,
                "authenticated control input expired while awaiting authorization",
            ),
            _ => control_failure(
                RemoteReasonCode::ProtocolDowngradeBlocked,
                "authenticated control input shape changed after bounded decoding",
            ),
        })?;

    let authorization = app_state
        .session_authorizations
        .active_control_authorization(&payload.session_id, now_ms)
        .await?;
    if authorization.role != mrd_ipc::RemoteSessionRole::Agent {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "authenticated incoming control input requires the local agent role",
        ));
    }
    if payload.source_device_id != authorization.peer_device_id
        || payload.source_key_id != authorization.peer_key_id
        || envelope.public_key != authorization.peer_public_key
    {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "authenticated control input source does not match the authorized peer",
        ));
    }
    if payload.grant_id != authorization.grant_id {
        return Err(control_failure(
            RemoteReasonCode::GrantRevoked,
            "authenticated control input grant does not match the active grant",
        ));
    }
    if payload.policy_revision != authorization.policy_revision
        || payload.issued_at_ms > authorization.expires_at_ms
        || payload.expires_at_ms > authorization.expires_at_ms
    {
        return Err(control_failure(
            RemoteReasonCode::PolicyChanged,
            "authenticated control input uses a stale authorization policy",
        ));
    }
    let required_scope = remote_scope(payload.scope);
    if !authorization.granted_scopes.contains(&required_scope) {
        return Err(control_failure(
            RemoteReasonCode::ScopeDenied,
            "authenticated control input scope is not granted",
        ));
    }

    let control_event = decode_authenticated_input_event(&payload.authenticated_event_bytes)
        .map_err(|_| {
            control_failure(
                RemoteReasonCode::ProtocolDowngradeBlocked,
                "authenticated control input event encoding is invalid",
            )
        })?;
    let event_scope = authenticated_input_scope(&control_event).map_err(|_| {
        control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "authenticated control input event has no valid input scope",
        )
    })?;
    if permission_scope(event_scope) != payload.scope {
        return Err(control_failure(
            RemoteReasonCode::ScopeDenied,
            "authenticated control input event does not match its bound scope",
        ));
    }
    let event = ipc_event_from_authenticated(control_event)?;
    let lane = authenticated_event_lane(&event);
    Ok((authorization, event, lane))
}

fn signed_control_ack_datagram(
    identity: &mrd_identity::DeviceIdentity,
    request: &SignedControlEnvelopeV2,
    request_commitment: [u8; 32],
    result: std::result::Result<(ControlInputLane, u32), RemoteFailure>,
    issued_at_ms: u64,
) -> Result<Vec<u8>> {
    let (accepted, reason, lane, event_count) = match result {
        Ok((lane, event_count)) => (true, None, Some(lane), event_count),
        Err(failure) => (false, Some(failure.code), None, 0),
    };
    let payload = ControlInputAckV2 {
        protocol_version: CONTROL_ENVELOPE_VERSION,
        session_id: request.payload.session_id.clone(),
        grant_id: request.payload.grant_id,
        source_key_id: request.payload.source_key_id.clone(),
        target_key_id: request.payload.target_key_id.clone(),
        sequence: request.payload.sequence,
        event_id: request.payload.event_id,
        request_commitment,
        accepted,
        reason,
        lane,
        event_count,
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(CONTROL_INPUT_ACK_LIFETIME_MS),
    };
    let signature = identity
        .sign_context_bytes(
            CONTROL_INPUT_ACK_SIGNATURE_CONTEXT,
            &payload.signing_bytes()?,
        )
        .context("failed to sign authenticated control acknowledgement")?;
    let public_key = identity
        .public_key()
        .try_into()
        .map_err(|_| anyhow::anyhow!("local Ed25519 public key has an invalid length"))?;
    let signed = SignedControlInputAckV2 {
        payload,
        public_key,
        signature,
    };
    let encoded = serde_json::to_vec(&signed)?;
    if encoded.len() > CONTROL_INPUT_ACK_MAX_WIRE_BYTES {
        anyhow::bail!("authenticated control acknowledgement exceeds its wire bound");
    }
    let mut datagram =
        Vec::with_capacity(AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX.len() + encoded.len());
    datagram.extend_from_slice(AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX);
    datagram.extend_from_slice(&encoded);
    Ok(datagram)
}

async fn audit_control_input_denial(
    app_state: &Arc<AppState>,
    envelope: &SignedControlEnvelopeV2,
    failure: &RemoteFailure,
    _addr: SocketAddr,
) -> Result<()> {
    let payload = &envelope.payload;
    let reason = reason_code_wire_name(failure.code);
    let audit_admission = app_state
        .lan_discovery
        .admit_control_input_denial_audit(super::now_ms())
        .await;
    let result = match audit_admission {
        super::LanPreAuthorizationAuditAdmission::Detailed {
            previous_window_suppressed,
        } => {
            let mut details = vec![
                ("sequence".to_string(), payload.sequence.to_string()),
                ("event_id".to_string(), payload.event_id.to_string()),
                (
                    "scope".to_string(),
                    permission_scope_name(payload.scope).to_string(),
                ),
            ];
            if previous_window_suppressed > 0 {
                details.push((
                    "previous_window_suppressed_denials".to_string(),
                    previous_window_suppressed.to_string(),
                ));
            }
            Some(app_state.audit_log.record(
                CONTROL_INPUT_AUDIT_ACTION,
                "denied",
                Some(payload.session_id.clone()),
                None,
                Some(payload.source_device_id.clone()),
                Some("lan_control_v2".to_string()),
                Some(reason.clone()),
                details,
            ))
        }
        super::LanPreAuthorizationAuditAdmission::OverflowMarker => {
            Some(app_state.audit_log.record(
                CONTROL_INPUT_AUDIT_ACTION,
                "denied_aggregate",
                None,
                None,
                None,
                Some("lan_control_v2".to_string()),
                Some(reason),
                vec![
                    ("aggregate".to_string(), "control_input_denials".to_string()),
                    (
                        "window_ms".to_string(),
                        super::LAN_CONTROL_DENIAL_AUDIT_WINDOW_MS.to_string(),
                    ),
                ],
            ))
        }
        super::LanPreAuthorizationAuditAdmission::Suppressed => None,
    };
    result
        .map(|result| result.map(|_| ()))
        .transpose()
        .map(|_| ())
        .map_err(|error| {
            app_state.mark_security_unhealthy();
            anyhow::Error::new(error).context("failed to durably audit control-input denial")
        })
}

pub(crate) fn control_request_commitment(
    envelope: &SignedControlEnvelopeV2,
    signing_bytes: &[u8],
) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(signing_bytes);
    context.update(&envelope.public_key);
    context.update(&envelope.signature);
    context
        .finish()
        .as_ref()
        .try_into()
        .expect("SHA-256 digest length")
}

fn prune_authenticated_control_replays(
    cache: &mut HashMap<AuthenticatedControlReplayKey, AuthenticatedControlReplayState>,
    now_ms: u64,
) {
    cache.retain(|_, replay| now_ms <= replay.expires_at_ms);
}

pub(crate) fn replay_failure(error: ControlSequenceError) -> RemoteFailure {
    let message = match error {
        ControlSequenceError::OutOfWindow => {
            "authenticated control input sequence is outside the replay window"
        }
        ControlSequenceError::Invalid | ControlSequenceError::Duplicate => {
            "authenticated control input sequence or event identifier was already used"
        }
    };
    control_failure(RemoteReasonCode::ReplayDetected, message)
}

pub(crate) fn control_failure(code: RemoteReasonCode, message: &str) -> RemoteFailure {
    RemoteFailure {
        code,
        message: message.to_string(),
        suggested_action: None,
    }
}

pub(crate) fn remote_scope(scope: PermissionScope) -> RemotePermissionScope {
    match scope {
        PermissionScope::InputPointer => RemotePermissionScope::InputPointer,
        PermissionScope::InputKeyboard => RemotePermissionScope::InputKeyboard,
        _ => unreachable!("ControlEnvelopeV2 shape validation only permits input scopes"),
    }
}

pub(crate) fn permission_scope(scope: AuthenticatedInputScope) -> PermissionScope {
    match scope {
        AuthenticatedInputScope::Pointer => PermissionScope::InputPointer,
        AuthenticatedInputScope::Keyboard => PermissionScope::InputKeyboard,
    }
}

pub(crate) fn service_control_scope(
    scope: PermissionScope,
) -> crate::control_input::ControlInputScope {
    match scope {
        PermissionScope::InputPointer => crate::control_input::ControlInputScope::Pointer,
        PermissionScope::InputKeyboard => crate::control_input::ControlInputScope::Keyboard,
        _ => unreachable!("ControlEnvelopeV2 shape validation only permits input scopes"),
    }
}

fn permission_scope_name(scope: PermissionScope) -> &'static str {
    match scope {
        PermissionScope::InputPointer => "input.pointer",
        PermissionScope::InputKeyboard => "input.keyboard",
        _ => "invalid",
    }
}

pub(crate) fn ipc_event_from_authenticated(
    event: ControlEvent,
) -> std::result::Result<ControlInputEvent, RemoteFailure> {
    match event {
        ControlEvent::MouseMove { x, y } => Ok(ControlInputEvent::MouseMove { x, y }),
        ControlEvent::MouseButton { button, pressed } => Ok(ControlInputEvent::MouseButton {
            button: match button {
                0 => ControlInputButton::Left,
                1 => ControlInputButton::Right,
                2 => ControlInputButton::Middle,
                3 => ControlInputButton::X1,
                4 => ControlInputButton::X2,
                _ => {
                    return Err(control_failure(
                        RemoteReasonCode::ProtocolDowngradeBlocked,
                        "authenticated control input contains an unsupported mouse button",
                    ))
                }
            },
            pressed,
        }),
        ControlEvent::MouseWheel { delta } => Ok(ControlInputEvent::MouseWheel { delta }),
        ControlEvent::MouseHorizontalWheel { delta } => {
            Ok(ControlInputEvent::MouseHorizontalWheel { delta })
        }
        ControlEvent::Key { key, pressed } => Ok(ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey {
                code: u16::try_from(key).map_err(|_| {
                    control_failure(
                        RemoteReasonCode::ProtocolDowngradeBlocked,
                        "authenticated control input contains an unsupported key code",
                    )
                })?,
            },
            pressed,
        }),
        ControlEvent::ReleaseAll { .. } => Ok(ControlInputEvent::ReleaseAll),
        _ => Err(control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "authenticated control input contains a non-input event",
        )),
    }
}

pub(crate) fn authenticated_event_lane(event: &ControlInputEvent) -> ControlInputLane {
    match event {
        ControlInputEvent::MouseMove { .. }
        | ControlInputEvent::MouseWheel { .. }
        | ControlInputEvent::MouseHorizontalWheel { .. } => ControlInputLane::Realtime,
        ControlInputEvent::MouseButton { .. } | ControlInputEvent::Key { .. } => {
            ControlInputLane::Reliable
        }
        ControlInputEvent::ReleaseAll => ControlInputLane::Cleanup,
    }
}

fn reason_code_wire_name(code: RemoteReasonCode) -> String {
    serde_json::to_string(&code)
        .unwrap_or_else(|_| "\"policy_changed\"".to_string())
        .trim_matches('"')
        .to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct LanControlInputDedupeKey {
    source_device_id: String,
    session_id: String,
    event_id: u64,
}

#[derive(Debug, Clone)]
pub(super) struct LanControlInputAckState {
    pub accepted: bool,
    pub message: Option<String>,
    pub lane: Option<ControlInputLane>,
    pub event_count: u32,
    timestamp_ms: u64,
}

pub async fn request_authenticated_lan_control_input(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    event: ControlInputEvent,
) -> std::result::Result<crate::control_input::ControlInputResult, RemoteFailure> {
    let lane = authenticated_event_lane(&event);
    if lane == ControlInputLane::Realtime {
        let result = request_authenticated_lan_control_input_impl(
            app_state,
            session_id,
            event.clone(),
            false,
        )
        .await;
        if let Err(failure) = &result {
            if outgoing_control_failure_is_terminal(failure, lane) {
                let authorization_guard = app_state.authorization_security_gate.lock().await;
                finalize_outgoing_control_failure_under_security_gate(
                    app_state, session_id, &event, failure,
                )
                .await;
                drop(authorization_guard);
            }
        }
        return result;
    }
    let authorization_guard = app_state.authorization_security_gate.lock().await;
    let result =
        request_authenticated_lan_control_input_impl(app_state, session_id, event.clone(), true)
            .await;
    if let Err(failure) = &result {
        if outgoing_control_failure_is_terminal(failure, lane) {
            finalize_outgoing_control_failure_under_security_gate(
                app_state, session_id, &event, failure,
            )
            .await;
        }
    }
    drop(authorization_guard);
    result
}

fn outgoing_control_failure_is_terminal(failure: &RemoteFailure, lane: ControlInputLane) -> bool {
    if lane != ControlInputLane::Realtime {
        return true;
    }
    matches!(
        failure.code,
        RemoteReasonCode::GrantExpired
            | RemoteReasonCode::GrantRevoked
            | RemoteReasonCode::IdentityMismatch
            | RemoteReasonCode::PolicyChanged
            | RemoteReasonCode::ProtocolDowngradeBlocked
    )
}

async fn finalize_outgoing_control_failure_under_security_gate(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    failed_event: &ControlInputEvent,
    failure: &RemoteFailure,
) {
    if !matches!(failed_event, ControlInputEvent::ReleaseAll) {
        let _ = request_authenticated_lan_control_input_impl(
            app_state,
            session_id,
            ControlInputEvent::ReleaseAll,
            true,
        )
        .await;
    }
    let authorization_state = match failure.code {
        RemoteReasonCode::GrantExpired => mrd_ipc::RemoteAuthorizationState::Expired,
        RemoteReasonCode::GrantRevoked => mrd_ipc::RemoteAuthorizationState::Revoked,
        _ => mrd_ipc::RemoteAuthorizationState::PolicyChanged,
    };
    let _ = app_state
        .session_authorizations
        .record_failure(
            session_id,
            authorization_state,
            failure.clone(),
            super::now_ms(),
        )
        .await;
    super::terminate_authorized_remote_sessions_under_security_gate(
        app_state,
        std::slice::from_ref(session_id),
    )
    .await;
}

async fn authenticated_control_sender_state(
    app_state: &Arc<AppState>,
    authorization: &crate::session_authorization::ActiveControlAuthorization,
) -> std::result::Result<Arc<AuthenticatedControlSenderState>, RemoteFailure> {
    let now_ms = super::now_ms();
    let key = AuthenticatedControlSenderKey {
        session_id: authorization.session_id.0.clone(),
        grant_id: authorization.grant_id,
        target_key_id: authorization.peer_key_id.clone(),
    };
    let mut senders = app_state
        .lan_discovery
        .authenticated_control_senders
        .lock()
        .await;
    senders.retain(|_, sender| now_ms <= sender.expires_at_ms);
    if let Some(sender) = senders.get(&key) {
        return Ok(Arc::clone(sender));
    }
    if senders.len() >= CONTROL_INPUT_REPLAY_SESSION_LIMIT {
        return Err(control_failure(
            RemoteReasonCode::ReplayDetected,
            "authenticated control sender capacity is exhausted",
        ));
    }
    let sender = Arc::new(AuthenticatedControlSenderState::new(
        authorization.expires_at_ms,
    ));
    senders.insert(key, Arc::clone(&sender));
    Ok(sender)
}

async fn authenticated_control_route(
    app_state: &Arc<AppState>,
    authorization: &crate::session_authorization::ActiveControlAuthorization,
    sender: &AuthenticatedControlSenderState,
    cleanup: bool,
) -> std::result::Result<AuthenticatedControlRoute, RemoteFailure> {
    let mut cached_route = sender.route.lock().await;
    let matching_cached_route = cached_route.as_ref().filter(|route| {
        route.peer_device_id == authorization.peer_device_id
            && route.peer_key_id == authorization.peer_key_id
            && route.peer_public_key == authorization.peer_public_key
    });
    if cleanup {
        if let Some(route) = matching_cached_route {
            return Ok(route.clone());
        }
    }

    let discovered_peer = app_state
        .lan_discovery
        .controllable_peer(&authorization.peer_device_id)
        .await;
    let Some(peer) = discovered_peer else {
        if let Some(route) = matching_cached_route {
            return Ok(route.clone());
        }
        return Err(lan_control_failure(
            "authenticated LAN peer is no longer controllable".to_string(),
        ));
    };
    if peer.peer_key_id.as_deref() != Some(authorization.peer_key_id.as_str())
        || peer.public_key.as_deref() != Some(authorization.peer_public_key.as_slice())
        || !peer.transports.iter().any(|transport| {
            transport.eq_ignore_ascii_case(super::protocol::LAN_INPUT_CONTROL_TRANSPORT)
        })
        || !peer.media_capabilities.iter().any(|capability| {
            capability.eq_ignore_ascii_case(super::protocol::LAN_INPUT_CONTROL_CAPABILITY)
        })
    {
        return Err(control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "authenticated LAN peer does not advertise input_control_v2 and control.keyboard_mouse under the bound identity",
        ));
    }
    let route = AuthenticatedControlRoute {
        target: peer.control_addr(),
        peer_device_id: authorization.peer_device_id.clone(),
        peer_key_id: authorization.peer_key_id.clone(),
        peer_public_key: authorization.peer_public_key,
    };
    *cached_route = Some(route.clone());
    Ok(route)
}

pub(crate) async fn request_authenticated_lan_control_input_under_security_gate(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    event: ControlInputEvent,
) -> std::result::Result<crate::control_input::ControlInputResult, RemoteFailure> {
    request_authenticated_lan_control_input_impl(app_state, session_id, event, true).await
}

async fn request_authenticated_lan_control_input_impl(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    event: ControlInputEvent,
    security_gate_held: bool,
) -> std::result::Result<crate::control_input::ControlInputResult, RemoteFailure> {
    let is_cleanup = matches!(&event, ControlInputEvent::ReleaseAll);
    if !app_state.security_is_healthy() && !is_cleanup {
        return Err(control_failure(
            RemoteReasonCode::PolicyChanged,
            "authoritative security state is unavailable",
        ));
    }
    let now_ms = super::now_ms();
    let authorization = app_state
        .session_authorizations
        .active_control_authorization(session_id, now_ms)
        .await?;
    if authorization.role != mrd_ipc::RemoteSessionRole::Controller {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "outgoing authenticated control input requires the local controller role",
        ));
    }

    let events = authenticated_events_from_ipc(&event, &authorization.granted_scopes)?;
    let mut event_count = 0_u32;
    let mut result_lane = authenticated_event_lane(&event);
    for control_event in events {
        let result = request_authenticated_control_event(
            app_state,
            &authorization,
            control_event,
            control_input_request_attempts(&event),
            security_gate_held,
        )
        .await?;
        result_lane = if matches!(event, ControlInputEvent::ReleaseAll) {
            ControlInputLane::Cleanup
        } else {
            result.lane
        };
        event_count = event_count.saturating_add(result.event_count);
    }
    Ok(crate::control_input::ControlInputResult {
        lane: result_lane,
        event_count,
    })
}

async fn request_authenticated_control_event(
    app_state: &Arc<AppState>,
    authorization: &crate::session_authorization::ActiveControlAuthorization,
    event: ControlEvent,
    attempts: usize,
    security_gate_held: bool,
) -> std::result::Result<crate::control_input::ControlInputResult, RemoteFailure> {
    let sender = authenticated_control_sender_state(app_state, authorization).await?;
    let cleanup = matches!(&event, ControlEvent::ReleaseAll { .. });
    let route = authenticated_control_route(app_state, authorization, &sender, cleanup).await?;
    let source_device_id = DeviceId(super::local_device_id(app_state).await.map_err(|error| {
        control_failure(RemoteReasonCode::IdentityMismatch, &error.to_string())
    })?);
    let local_identity = app_state.device_identities.machine_identity();
    let scope = permission_scope(authenticated_input_scope(&event).map_err(|_| {
        control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "control input event has no authenticated scope",
        )
    })?);
    let required_scope = remote_scope(scope);
    if !authorization.granted_scopes.contains(&required_scope) {
        return Err(control_failure(
            RemoteReasonCode::ScopeDenied,
            "control input scope is not present in the active grant",
        ));
    }
    let authenticated_event_bytes = encode_authenticated_input_event(&event).map_err(|_| {
        control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "control input event cannot be encoded for authenticated transport",
        )
    })?;
    let event_lane = authenticated_event_lane(&ipc_event_from_authenticated(event.clone())?);

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|error| lan_control_failure(format!("failed to bind control socket: {error}")))?;
    socket.connect(route.target).await.map_err(|error| {
        lan_control_failure(format!("failed to connect control socket: {error}"))
    })?;

    let sequence_state = sender.sequence_for_lane(event_lane);
    let mut sequence_guard = sequence_state.lock_owned().await;
    let sequence = *sequence_guard;
    let event_id = sender.next_event_id();
    let issued_at_ms = super::now_ms();
    let expires_at_ms = issued_at_ms
        .saturating_add(CONTROL_ENVELOPE_MAX_LIFETIME_MS)
        .min(authorization.expires_at_ms);
    if expires_at_ms <= issued_at_ms {
        return Err(control_failure(
            RemoteReasonCode::GrantExpired,
            "control input grant expired before the event could be signed",
        ));
    }
    let payload = mrd_session::ControlEnvelopeV2 {
        protocol_version: CONTROL_ENVELOPE_VERSION,
        session_id: authorization.session_id.clone(),
        grant_id: authorization.grant_id,
        source_device_id,
        target_device_id: authorization.peer_device_id.clone(),
        source_key_id: local_identity.key_id().to_string(),
        target_key_id: authorization.peer_key_id.clone(),
        scope,
        sequence,
        event_id,
        issued_at_ms,
        expires_at_ms,
        policy_revision: authorization.policy_revision,
        authenticated_event_bytes,
    };
    let signing_bytes = payload.signing_bytes().map_err(|_| {
        control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "control input envelope cannot be canonicalized",
        )
    })?;
    let signature: [u8; 64] = local_identity
        .sign_context_bytes(CONTROL_ENVELOPE_SIGNATURE_CONTEXT, &signing_bytes)
        .map_err(|_| {
            control_failure(
                RemoteReasonCode::IdentityMismatch,
                "control input envelope could not be signed",
            )
        })?
        .try_into()
        .map_err(|_| {
            control_failure(
                RemoteReasonCode::IdentityMismatch,
                "control input signature has an invalid length",
            )
        })?;
    let envelope = SignedControlEnvelopeV2 {
        payload,
        public_key: local_identity.public_key().try_into().map_err(|_| {
            control_failure(
                RemoteReasonCode::IdentityMismatch,
                "local control-input public key has an invalid length",
            )
        })?,
        signature,
    };
    let request_commitment = control_request_commitment(&envelope, &signing_bytes);
    let encoded = serde_json::to_vec(&envelope).map_err(|_| {
        control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "control input envelope cannot be serialized",
        )
    })?;
    if encoded.len() > CONTROL_ENVELOPE_MAX_WIRE_BYTES {
        return Err(control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "control input envelope exceeds its wire bound",
        ));
    }
    let mut datagram =
        Vec::with_capacity(AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX.len() + encoded.len());
    datagram.extend_from_slice(AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX);
    datagram.extend_from_slice(&encoded);
    *sequence_guard = sequence.saturating_add(1);
    let mut buffer = vec![
        0_u8;
        AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX.len()
            + CONTROL_INPUT_ACK_MAX_WIRE_BYTES
    ];
    for attempt in 0..attempts.max(1) {
        // Retries intentionally reuse the exact same signed datagram.
        send_authenticated_control_datagram(
            app_state,
            &socket,
            &datagram,
            authorization,
            security_gate_held,
            matches!(&event, ControlEvent::ReleaseAll { .. }),
        )
        .await?;
        let received = timeout(super::LAN_CONTROL_INPUT_ACK_TIMEOUT, async {
            loop {
                let len = socket.recv(&mut buffer).await.map_err(|error| {
                    lan_control_failure(format!(
                        "failed to receive authenticated control acknowledgement: {error}"
                    ))
                })?;
                let Some(ack_bytes) =
                    buffer[..len].strip_prefix(AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX)
                else {
                    continue;
                };
                if let Ok(result) = verify_control_ack(
                    ack_bytes,
                    &envelope,
                    authorization,
                    request_commitment,
                    super::now_ms(),
                ) {
                    return result;
                }
            }
        })
        .await;
        match received {
            Ok(result) => return result,
            Err(_) if attempt + 1 < attempts.max(1) => continue,
            Err(_) => {
                return Err(lan_control_failure(format!(
                    "authenticated LAN control input timed out after {} attempt(s)",
                    attempts.max(1)
                )))
            }
        }
    }
    Err(lan_control_failure(
        "authenticated LAN control input exhausted its retry budget".to_string(),
    ))
}

async fn send_authenticated_control_datagram(
    app_state: &Arc<AppState>,
    socket: &UdpSocket,
    datagram: &[u8],
    expected_authorization: &crate::session_authorization::ActiveControlAuthorization,
    security_gate_held: bool,
    allow_unhealthy_cleanup: bool,
) -> std::result::Result<(), RemoteFailure> {
    if security_gate_held {
        return revalidate_and_send_control_datagram(
            app_state,
            socket,
            datagram,
            expected_authorization,
            allow_unhealthy_cleanup,
        )
        .await;
    }

    let authorization_guard = app_state.authorization_security_gate.lock().await;
    let result = revalidate_and_send_control_datagram(
        app_state,
        socket,
        datagram,
        expected_authorization,
        allow_unhealthy_cleanup,
    )
    .await;
    drop(authorization_guard);
    result
}

async fn revalidate_and_send_control_datagram(
    app_state: &Arc<AppState>,
    socket: &UdpSocket,
    datagram: &[u8],
    expected_authorization: &crate::session_authorization::ActiveControlAuthorization,
    allow_unhealthy_cleanup: bool,
) -> std::result::Result<(), RemoteFailure> {
    if !app_state.security_is_healthy() && !allow_unhealthy_cleanup {
        return Err(control_failure(
            RemoteReasonCode::PolicyChanged,
            "authoritative security state became unavailable before input send",
        ));
    }
    let current = app_state
        .session_authorizations
        .active_control_authorization(&expected_authorization.session_id, super::now_ms())
        .await?;
    if &current != expected_authorization {
        return Err(control_failure(
            RemoteReasonCode::PolicyChanged,
            "control authorization changed before the signed input could be sent",
        ));
    }
    socket.send(datagram).await.map(|_| ()).map_err(|error| {
        lan_control_failure(format!(
            "failed to send authenticated control input: {error}"
        ))
    })
}

fn verify_control_ack(
    bytes: &[u8],
    request: &SignedControlEnvelopeV2,
    authorization: &crate::session_authorization::ActiveControlAuthorization,
    request_commitment: [u8; 32],
    now_ms: u64,
) -> std::result::Result<
    std::result::Result<crate::control_input::ControlInputResult, RemoteFailure>,
    (),
> {
    if bytes.is_empty() || bytes.len() > CONTROL_INPUT_ACK_MAX_WIRE_BYTES {
        return Err(());
    }
    let ack: SignedControlInputAckV2 = serde_json::from_slice(bytes).map_err(|_| ())?;
    let payload = &ack.payload;
    if ack.signature.len() != 64
        || payload.protocol_version != CONTROL_ENVELOPE_VERSION
        || payload.session_id != request.payload.session_id
        || payload.grant_id != request.payload.grant_id
        || payload.source_key_id != request.payload.source_key_id
        || payload.target_key_id != request.payload.target_key_id
        || payload.sequence != request.payload.sequence
        || payload.event_id != request.payload.event_id
        || payload.request_commitment != request_commitment
        || payload.issued_at_ms > now_ms.saturating_add(2_000)
        || payload.issued_at_ms > payload.expires_at_ms
        || now_ms > payload.expires_at_ms
        || payload.expires_at_ms.saturating_sub(payload.issued_at_ms)
            > CONTROL_INPUT_ACK_LIFETIME_MS
        || ack.public_key != authorization.peer_public_key
        || public_key_id(&ack.public_key) != authorization.peer_key_id
        || verify_context_bytes(
            &ack.public_key,
            CONTROL_INPUT_ACK_SIGNATURE_CONTEXT,
            &payload.signing_bytes().map_err(|_| ())?,
            &ack.signature,
        )
        .is_err()
    {
        return Err(());
    }
    if payload.accepted {
        let lane = payload.lane.ok_or(())?;
        let expected_lane = authenticated_event_lane(
            &ipc_event_from_authenticated(
                decode_authenticated_input_event(&request.payload.authenticated_event_bytes)
                    .map_err(|_| ())?,
            )
            .map_err(|_| ())?,
        );
        if payload.reason.is_some() || lane != expected_lane {
            return Err(());
        }
        Ok(Ok(crate::control_input::ControlInputResult {
            lane,
            event_count: payload.event_count,
        }))
    } else {
        if payload.lane.is_some() || payload.event_count != 0 {
            return Err(());
        }
        let code = payload.reason.ok_or(())?;
        Ok(Err(RemoteFailure {
            code,
            message: format!(
                "authenticated LAN peer rejected control input ({})",
                reason_code_wire_name(code)
            ),
            suggested_action: None,
        }))
    }
}

pub(crate) fn authenticated_events_from_ipc(
    event: &ControlInputEvent,
    granted_scopes: &[RemotePermissionScope],
) -> std::result::Result<Vec<ControlEvent>, RemoteFailure> {
    let events = match *event {
        ControlInputEvent::MouseMove { x, y } => vec![ControlEvent::MouseMove { x, y }],
        ControlInputEvent::MouseButton { button, pressed } => vec![ControlEvent::MouseButton {
            button: match button {
                ControlInputButton::Left => 0,
                ControlInputButton::Right => 1,
                ControlInputButton::Middle => 2,
                ControlInputButton::X1 => 3,
                ControlInputButton::X2 => 4,
            },
            pressed,
        }],
        ControlInputEvent::MouseWheel { delta } => vec![ControlEvent::MouseWheel { delta }],
        ControlInputEvent::MouseHorizontalWheel { delta } => {
            vec![ControlEvent::MouseHorizontalWheel { delta }]
        }
        ControlInputEvent::Key { key, pressed } => vec![ControlEvent::Key {
            key: match key {
                ControlInputKey::VirtualKey { code } => u32::from(code),
            },
            pressed,
        }],
        ControlInputEvent::ReleaseAll => {
            let mut events = Vec::with_capacity(2);
            if granted_scopes.contains(&RemotePermissionScope::InputPointer) {
                events.push(ControlEvent::ReleaseAll {
                    scope: AuthenticatedInputScope::Pointer,
                });
            }
            if granted_scopes.contains(&RemotePermissionScope::InputKeyboard) {
                events.push(ControlEvent::ReleaseAll {
                    scope: AuthenticatedInputScope::Keyboard,
                });
            }
            events
        }
    };
    if events.is_empty() {
        return Err(control_failure(
            RemoteReasonCode::ScopeDenied,
            "active grant contains no control-input scope",
        ));
    }
    for event in &events {
        let scope = authenticated_input_scope(event).map_err(|_| {
            control_failure(
                RemoteReasonCode::ProtocolDowngradeBlocked,
                "control input event has no authenticated scope",
            )
        })?;
        if !granted_scopes.contains(&remote_scope(permission_scope(scope))) {
            return Err(control_failure(
                RemoteReasonCode::ScopeDenied,
                "control input event exceeds the active grant",
            ));
        }
    }
    Ok(events)
}

fn lan_control_failure(message: String) -> RemoteFailure {
    RemoteFailure {
        code: RemoteReasonCode::LanUnreachable,
        message,
        suggested_action: Some("verify that the authenticated LAN peer is reachable".to_string()),
    }
}

pub async fn request_lan_control_input(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    event: ControlInputEvent,
) -> Result<crate::control_input::ControlInputResult> {
    if app_state
        .session_authorizations
        .snapshot(session_id)
        .await
        .is_some()
    {
        return request_authenticated_lan_control_input(app_state, session_id, event)
            .await
            .map_err(|failure| anyhow::anyhow!(failure.message));
    }
    let peer_device_id = super::session_remote_peer(app_state, session_id).await?;
    let target =
        super::peer_control_addr_with_input_control_capability(app_state, &peer_device_id).await?;
    let source_device_id = super::local_device_id(app_state).await?;
    let event_id = next_control_input_event_id();

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("failed to bind LAN control input UDP socket")?;
    let packet = LanDiscoveryPacket::ControlInput {
        magic: super::DISCOVERY_MAGIC.to_string(),
        app_id: super::DISCOVERY_APP_ID.to_string(),
        instance_id: app_state.lan_discovery.instance_id.clone(),
        session_id: session_id.0.clone(),
        source_device_id,
        event_id,
        event: event.clone(),
        timestamp_ms: super::now_ms(),
    };

    let mut buffer = vec![0_u8; super::DISCOVERY_PACKET_BUFFER_BYTES];
    let attempts = control_input_request_attempts(&event);
    for attempt in 0..attempts {
        super::send_packet(&socket, &packet, target).await?;

        let received = timeout(
            super::LAN_CONTROL_INPUT_ACK_TIMEOUT,
            socket.recv_from(&mut buffer),
        )
        .await;
        let (len, _) = match received {
            Ok(received) => received?,
            Err(_) if attempt + 1 < attempts => continue,
            Err(_) => {
                anyhow::bail!(
                    "LAN control input request timed out after {} attempt(s)",
                    attempts
                );
            }
        };

        let ack: LanDiscoveryPacket = serde_json::from_slice(&buffer[..len])?;
        match ack {
            LanDiscoveryPacket::ControlInputAck {
                magic,
                app_id,
                session_id: ack_session_id,
                event_id: ack_event_id,
                accepted,
                message,
                lane,
                event_count,
                ..
            } if super::is_valid_discovery_packet(&magic, &app_id)
                && ack_session_id == session_id.0
                && ack_event_id == event_id =>
            {
                if accepted {
                    return Ok(crate::control_input::ControlInputResult {
                        lane: lane.context("LAN peer accepted control input without lane")?,
                        event_count,
                    });
                } else {
                    anyhow::bail!(
                        "LAN peer rejected control input: {}",
                        message.unwrap_or_else(|| "unknown reason".to_string())
                    );
                }
            }
            _ => anyhow::bail!("unexpected LAN control input response"),
        };
    }

    anyhow::bail!(
        "LAN control input request timed out after {} attempt(s)",
        attempts
    )
}

fn next_control_input_event_id() -> u64 {
    super::LAN_CONTROL_INPUT_EVENT_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
        .max(1)
}

fn control_input_request_attempts(event: &ControlInputEvent) -> usize {
    match event {
        ControlInputEvent::MouseMove { .. }
        | ControlInputEvent::MouseWheel { .. }
        | ControlInputEvent::MouseHorizontalWheel { .. } => {
            super::LAN_CONTROL_INPUT_REALTIME_ATTEMPTS
        }
        ControlInputEvent::MouseButton { .. }
        | ControlInputEvent::Key { .. }
        | ControlInputEvent::ReleaseAll => super::LAN_CONTROL_INPUT_RELIABLE_ATTEMPTS,
    }
}

pub(super) async fn accept_or_replay_lan_control_input(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    source_device_id: &str,
    event_id: u64,
    event: &ControlInputEvent,
) -> LanControlInputAckState {
    let now = super::now_ms();
    let key = (event_id != 0).then(|| LanControlInputDedupeKey {
        source_device_id: source_device_id.to_string(),
        session_id: session_id.0.clone(),
        event_id,
    });
    if let Some(key) = key.as_ref() {
        let mut cache = app_state.lan_discovery.recent_control_inputs.lock().await;
        prune_recent_control_inputs(&mut cache, now);
        if let Some(cached) = cache.get(key).cloned() {
            return cached;
        }
    }

    let ack_state = match accept_lan_control_input(app_state, session_id, event).await {
        Ok(result) => LanControlInputAckState {
            accepted: true,
            message: Some("injected".to_string()),
            lane: Some(result.lane),
            event_count: result.event_count,
            timestamp_ms: now,
        },
        Err(error) => LanControlInputAckState {
            accepted: false,
            message: Some(error.to_string()),
            lane: None,
            event_count: 0,
            timestamp_ms: now,
        },
    };

    if let Some(key) = key {
        let mut cache = app_state.lan_discovery.recent_control_inputs.lock().await;
        cache.insert(key, ack_state.clone());
        prune_recent_control_inputs(&mut cache, now);
    }

    ack_state
}

async fn accept_lan_control_input(
    _app_state: &Arc<AppState>,
    _session_id: &SessionId,
    _event: &ControlInputEvent,
) -> Result<crate::control_input::ControlInputResult> {
    anyhow::bail!(
        "legacy unsigned LAN control input is disabled until ControlEnvelopeV2 is authenticated"
    )
}

fn prune_recent_control_inputs(
    cache: &mut HashMap<LanControlInputDedupeKey, LanControlInputAckState>,
    now: u64,
) {
    let cutoff = now.saturating_sub(super::LAN_CONTROL_INPUT_DEDUPE_WINDOW_MS);
    cache.retain(|_, ack| ack.timestamp_ms >= cutoff);
    if cache.len() <= super::LAN_CONTROL_INPUT_DEDUPE_CACHE_LIMIT {
        return;
    }

    let remove_count = cache.len() - super::LAN_CONTROL_INPUT_DEDUPE_CACHE_LIMIT;
    let mut oldest = cache
        .iter()
        .map(|(key, ack)| (key.clone(), ack.timestamp_ms))
        .collect::<Vec<_>>();
    oldest.sort_by_key(|(_, timestamp_ms)| *timestamp_ms);
    for (key, _) in oldest.into_iter().take(remove_count) {
        cache.remove(&key);
    }
}

#[cfg(test)]
mod authenticated_tests {
    use super::*;
    use mrd_identity::DeviceIdentity;
    use mrd_ipc::{
        ConsentDecision, ConsentResponse, DecimalU64, RemoteAccessMode, RemoteSessionRole,
    };
    use ring::rand::SystemRandom;

    const CONTROL_SCOPES: [RemotePermissionScope; 3] = [
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputPointer,
        RemotePermissionScope::InputKeyboard,
    ];

    struct ControlAuthorizationFixture<'a> {
        peer_device_id: DeviceId,
        peer_identity: &'a DeviceIdentity,
        role: RemoteSessionRole,
        grant_id: [u8; 32],
        created_at_ms: u64,
        expires_at_ms: u64,
    }

    async fn install_control_authorization(
        state: &Arc<AppState>,
        session_id: &SessionId,
        fixture: ControlAuthorizationFixture<'_>,
    ) {
        let ControlAuthorizationFixture {
            peer_device_id,
            peer_identity,
            role,
            grant_id,
            created_at_ms,
            expires_at_ms,
        } = fixture;
        let request = crate::session_authorization::VerifiedIncomingAuthorizationRequest {
            session_id: session_id.clone(),
            peer_device_id,
            peer_key_id: peer_identity.key_id().to_string(),
            peer_key_epoch: 1,
            access_mode: RemoteAccessMode::Attended,
            requested_scopes: CONTROL_SCOPES.to_vec(),
            peer_permission_ceiling: CONTROL_SCOPES.to_vec(),
            machine_permission_ceiling: CONTROL_SCOPES.to_vec(),
            runtime_capabilities: CONTROL_SCOPES.to_vec(),
            transport_kind: "quic".to_string(),
            request_nonce: [0x83; 16],
            created_at_ms,
            expires_at_ms,
        };
        let policy_revision = match role {
            RemoteSessionRole::Controller => state
                .session_authorizations
                .begin_outgoing(request)
                .await
                .expect("begin outgoing control authorization")
                .policy_revision
                .get(),
            RemoteSessionRole::Agent => {
                state
                    .session_authorizations
                    .begin_verified_incoming(request)
                    .await
                    .expect("begin incoming control authorization");
                state
                    .session_authorizations
                    .respond_to_consent(
                        ConsentResponse {
                            session_id: session_id.clone(),
                            decision: ConsentDecision::Approve,
                            approved_scopes: CONTROL_SCOPES.to_vec(),
                            expected_policy_revision: DecimalU64::new(1),
                        },
                        created_at_ms.saturating_add(1),
                    )
                    .await
                    .expect("approve incoming control authorization")
                    .policy_revision
                    .get()
            }
        };
        state
            .session_authorizations
            .bind_authenticated_peer_key(
                session_id,
                peer_identity.public_key(),
                created_at_ms.saturating_add(2),
            )
            .await
            .expect("bind control peer key");
        state
            .session_authorizations
            .install_verified_grant(
                crate::session_authorization::VerifiedSessionGrant {
                    grant_id: format!("sha256:{}", hex_bytes(&grant_id)),
                    session_id: session_id.clone(),
                    granted_scopes: CONTROL_SCOPES.to_vec(),
                    issued_at_ms: created_at_ms.saturating_add(3),
                    expires_at_ms,
                    policy_revision,
                    route_constraint: "quic".to_string(),
                    transport_fingerprint_sha256: [0x57; 32],
                },
                created_at_ms.saturating_add(3),
            )
            .await
            .expect("install control grant");
        state
            .session_authorizations
            .mark_streaming(session_id, created_at_ms.saturating_add(4))
            .await
            .expect("mark control authorization streaming");
    }

    fn signed_request(
        controller: &DeviceIdentity,
        target: &DeviceIdentity,
        session_id: SessionId,
        grant_id: [u8; 32],
        now_ms: u64,
    ) -> SignedControlEnvelopeV2 {
        let payload = mrd_session::ControlEnvelopeV2 {
            protocol_version: CONTROL_ENVELOPE_VERSION,
            session_id,
            grant_id,
            source_device_id: DeviceId("controller-device".to_string()),
            target_device_id: DeviceId("target-device".to_string()),
            source_key_id: controller.key_id().to_string(),
            target_key_id: target.key_id().to_string(),
            scope: PermissionScope::InputKeyboard,
            sequence: 1,
            event_id: 9,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(CONTROL_ENVELOPE_MAX_LIFETIME_MS),
            policy_revision: 1,
            authenticated_event_bytes: encode_authenticated_input_event(&ControlEvent::Key {
                key: 0x41,
                pressed: true,
            })
            .expect("encode key"),
        };
        let signature = controller
            .sign_context_bytes(
                CONTROL_ENVELOPE_SIGNATURE_CONTEXT,
                &payload.signing_bytes().expect("request signing bytes"),
            )
            .expect("sign request")
            .try_into()
            .expect("Ed25519 signature length");
        SignedControlEnvelopeV2 {
            payload,
            public_key: controller
                .public_key()
                .try_into()
                .expect("Ed25519 public key length"),
            signature,
        }
    }

    #[test]
    fn control_ack_requires_the_bound_target_signature_and_exact_request() {
        let controller = DeviceIdentity::generate(&SystemRandom::new()).expect("controller key");
        let target = DeviceIdentity::generate(&SystemRandom::new()).expect("target key");
        let attacker = DeviceIdentity::generate(&SystemRandom::new()).expect("attacker key");
        let now_ms = 10_000;
        let grant_id = [0x6a; 32];
        let request = signed_request(
            &controller,
            &target,
            SessionId("ack-verification".to_string()),
            grant_id,
            now_ms,
        );
        let commitment = control_request_commitment(
            &request,
            &request
                .payload
                .signing_bytes()
                .expect("request signing bytes"),
        );
        let authorization = crate::session_authorization::ActiveControlAuthorization {
            session_id: request.payload.session_id.clone(),
            role: RemoteSessionRole::Controller,
            peer_device_id: request.payload.target_device_id.clone(),
            peer_key_id: target.key_id().to_string(),
            peer_public_key: target
                .public_key()
                .try_into()
                .expect("target public key length"),
            grant_id,
            granted_scopes: CONTROL_SCOPES.to_vec(),
            expires_at_ms: request.payload.expires_at_ms,
            policy_revision: 1,
        };

        let valid = signed_control_ack_datagram(
            &target,
            &request,
            commitment,
            Ok((ControlInputLane::Reliable, 1)),
            now_ms,
        )
        .expect("sign valid ack");
        let valid = valid
            .strip_prefix(AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX)
            .expect("ack prefix");
        assert_eq!(
            verify_control_ack(valid, &request, &authorization, commitment, now_ms),
            Ok(Ok(crate::control_input::ControlInputResult {
                lane: ControlInputLane::Reliable,
                event_count: 1,
            }))
        );

        let forged = signed_control_ack_datagram(
            &attacker,
            &request,
            commitment,
            Ok((ControlInputLane::Reliable, 1)),
            now_ms,
        )
        .expect("sign forged ack");
        let forged = forged
            .strip_prefix(AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX)
            .expect("forged ack prefix");
        assert!(verify_control_ack(forged, &request, &authorization, commitment, now_ms).is_err());

        let wrong_lane = signed_control_ack_datagram(
            &target,
            &request,
            commitment,
            Ok((ControlInputLane::Realtime, 1)),
            now_ms,
        )
        .expect("sign wrong-lane ack");
        let wrong_lane = wrong_lane
            .strip_prefix(AUTHENTICATED_CONTROL_ACK_DATAGRAM_PREFIX)
            .expect("wrong-lane ack prefix");
        assert!(
            verify_control_ack(wrong_lane, &request, &authorization, commitment, now_ms).is_err()
        );
    }

    #[tokio::test]
    async fn reliable_sender_ignores_wrong_source_ack_and_reuses_exact_datagram() {
        let controller_state = Arc::new(AppState::new());
        let target_state = Arc::new(AppState::new());
        controller_state.devices.lock().await.register(
            DeviceId("controller-device".to_string()),
            "Controller".to_string(),
        );
        target_state
            .devices
            .lock()
            .await
            .register(DeviceId("target-device".to_string()), "Target".to_string());
        target_state
            .replace_control_input_for_test(mrd_input::RecordingInputInjector::available())
            .await;
        let controller_identity = controller_state.device_identities.machine_identity();
        let target_identity = target_state.device_identities.machine_identity();
        let session_id = SessionId("signed-control-retry".to_string());
        let grant_id = [0x72; 32];
        // Keep the synthetic authorization timeline safely in the past. On a
        // fast CI runner, the grant's `created_at + 3ms` issue time could
        // otherwise still be in the future when the first input is sent,
        // making the test depend on scheduler and platform timing.
        let created_at_ms = super::super::now_ms().saturating_sub(1_000);
        let expires_at_ms = created_at_ms.saturating_add(60_000);
        install_control_authorization(
            &controller_state,
            &session_id,
            ControlAuthorizationFixture {
                peer_device_id: DeviceId("target-device".to_string()),
                peer_identity: target_identity.as_ref(),
                role: RemoteSessionRole::Controller,
                grant_id,
                created_at_ms,
                expires_at_ms,
            },
        )
        .await;
        install_control_authorization(
            &target_state,
            &session_id,
            ControlAuthorizationFixture {
                peer_device_id: DeviceId("controller-device".to_string()),
                peer_identity: controller_identity.as_ref(),
                role: RemoteSessionRole::Agent,
                grant_id,
                created_at_ms,
                expires_at_ms,
            },
        )
        .await;

        let target_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("target socket"));
        let target_addr = target_socket.local_addr().expect("target address");
        let announcement = super::super::SignedLanAnnouncement::sign(
            target_identity.as_ref(),
            1,
            super::super::LanAnnouncement {
                magic: super::super::DISCOVERY_MAGIC.to_string(),
                app_id: super::super::DISCOVERY_APP_ID.to_string(),
                instance_id: "target-instance".to_string(),
                device_id: "target-device".to_string(),
                device_name: "Target".to_string(),
                device_type: "rdesk".to_string(),
                protocol_version: super::super::SIGNED_LAN_PROTOCOL_VERSION,
                discovery_port: target_addr.port(),
                transports: vec![
                    "quic".to_string(),
                    super::super::protocol::LAN_INPUT_CONTROL_TRANSPORT.to_string(),
                ],
                service_build_id: None,
                media_protocol_version: Some(super::super::protocol::LAN_MEDIA_PROTOCOL_VERSION),
                media_capabilities: vec![
                    super::super::protocol::LAN_INPUT_CONTROL_CAPABILITY.to_string()
                ],
                mac_address: None,
                timestamp_ms: created_at_ms,
            },
            target_addr,
            created_at_ms.saturating_add(15_000),
            [0x44; 16],
        )
        .expect("signed target announcement");
        let mut missing_input_capability = announcement.clone();
        missing_input_capability
            .payload
            .announcement
            .media_capabilities
            .clear();
        controller_state
            .lan_discovery
            .upsert_signed_peer(
                &missing_input_capability,
                crate::app_state::AuthenticatedPeerTrust::Trusted,
            )
            .await;
        let missing_capability = request_authenticated_lan_control_input_impl(
            &controller_state,
            &session_id,
            ControlInputEvent::Key {
                key: ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            },
            false,
        )
        .await
        .expect_err("transport without signed keyboard/mouse capability must fail closed");
        assert_eq!(
            missing_capability.code,
            RemoteReasonCode::ProtocolDowngradeBlocked
        );
        controller_state
            .lan_discovery
            .upsert_signed_peer(
                &announcement,
                crate::app_state::AuthenticatedPeerTrust::Trusted,
            )
            .await;

        let handler_socket = target_socket.clone();
        let handler_state = target_state.clone();
        let handler = tokio::spawn(async move {
            let rogue_socket = UdpSocket::bind("127.0.0.1:0").await.expect("rogue socket");
            let mut buffer = vec![0_u8; super::super::DISCOVERY_PACKET_BUFFER_BYTES];
            let (first_len, controller_addr) = handler_socket
                .recv_from(&mut buffer)
                .await
                .expect("first request");
            let first = buffer[..first_len].to_vec();
            super::super::process_lan_discovery_packet(
                &rogue_socket,
                &handler_state,
                &first,
                controller_addr,
            )
            .await
            .expect("process first request with wrong-source ack");

            let (retry_len, retry_addr) = handler_socket
                .recv_from(&mut buffer)
                .await
                .expect("retry request");
            let retry = buffer[..retry_len].to_vec();
            assert_eq!(retry, first, "reliable retry must reuse exact signed bytes");
            super::super::process_lan_discovery_packet(
                handler_socket.as_ref(),
                &handler_state,
                &retry,
                retry_addr,
            )
            .await
            .expect("process exact retry with bound-source ack");

            let (release_len, release_addr) = handler_socket
                .recv_from(&mut buffer)
                .await
                .expect("ordered key-up request");
            super::super::process_lan_discovery_packet(
                handler_socket.as_ref(),
                &handler_state,
                &buffer[..release_len],
                release_addr,
            )
            .await
            .expect("process key-up through the pinned control route");
        });

        let result = request_authenticated_lan_control_input(
            &controller_state,
            &session_id,
            ControlInputEvent::Key {
                key: ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            },
        )
        .await
        .expect("authenticated reliable input");
        controller_state
            .lan_discovery
            .upsert_signed_peer(
                &missing_input_capability,
                crate::app_state::AuthenticatedPeerTrust::Trusted,
            )
            .await;
        let revoked_capability = request_authenticated_lan_control_input_impl(
            &controller_state,
            &session_id,
            ControlInputEvent::MouseMove { x: 10, y: 20 },
            false,
        )
        .await
        .expect_err("a fresh signed capability revocation must override the cached route");
        assert_eq!(
            revoked_capability.code,
            RemoteReasonCode::ProtocolDowngradeBlocked
        );
        controller_state
            .lan_discovery
            .peers
            .lock()
            .await
            .prune_stale(u64::MAX, 0);
        let release = request_authenticated_lan_control_input(
            &controller_state,
            &session_id,
            ControlInputEvent::Key {
                key: ControlInputKey::VirtualKey { code: 0x41 },
                pressed: false,
            },
        )
        .await
        .expect("key-up uses the session-pinned signed route after discovery expiry");
        handler.await.expect("target handler");

        assert_eq!(result.lane, ControlInputLane::Reliable);
        assert_eq!(result.event_count, 1);
        assert_eq!(release.lane, ControlInputLane::Reliable);
        assert_eq!(release.event_count, 1);
        let target_snapshot = target_state
            .control_input()
            .lock()
            .await
            .snapshot(session_id);
        assert_eq!(target_snapshot.reliable.accepted_messages, 2);
        assert_eq!(target_snapshot.reliable.injected_messages, 2);
    }

    #[tokio::test]
    async fn exhausted_reliable_delivery_terminalizes_the_grant_instead_of_skipping_sequence() {
        let state = Arc::new(AppState::new());
        state.devices.lock().await.register(
            DeviceId("controller-device".to_string()),
            "Controller".to_string(),
        );
        let target_identity =
            DeviceIdentity::generate(&SystemRandom::new()).expect("target identity");
        let session_id = SessionId("reliable-delivery-exhausted".to_string());
        let created_at_ms = super::super::now_ms();
        install_control_authorization(
            &state,
            &session_id,
            ControlAuthorizationFixture {
                peer_device_id: DeviceId("missing-target".to_string()),
                peer_identity: &target_identity,
                role: RemoteSessionRole::Controller,
                grant_id: [0x73; 32],
                created_at_ms,
                expires_at_ms: created_at_ms.saturating_add(60_000),
            },
        )
        .await;
        let failure = lan_control_failure(
            "authenticated LAN control input timed out after 3 attempt(s)".to_string(),
        );
        assert!(outgoing_control_failure_is_terminal(
            &failure,
            ControlInputLane::Reliable
        ));

        let authorization_guard = state.authorization_security_gate.lock().await;
        finalize_outgoing_control_failure_under_security_gate(
            &state,
            &session_id,
            &ControlInputEvent::Key {
                key: ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            },
            &failure,
        )
        .await;
        drop(authorization_guard);

        let snapshot = state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("terminal authorization snapshot");
        assert_eq!(
            snapshot.authorization_state,
            mrd_ipc::RemoteAuthorizationState::PolicyChanged
        );
        assert_eq!(snapshot.failure, Some(failure));
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
