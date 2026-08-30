//! Authorization-gated WAN keyboard and pointer transport over the verified WebRTC mux.

use super::{
    media::{
        ControlEvidenceBarrier, WanInputActivationPort, WanMediaActivationError, WanMediaAuthority,
    },
    model::WanSessionRole,
};
use crate::{
    app_state::AppState,
    lan_discovery::lan_control_input::{
        authenticated_event_lane, authenticated_events_from_ipc, control_failure,
        control_request_commitment, replay_failure, service_control_scope,
        validate_authenticated_control_input, AuthenticatedControlReplayKey,
        AuthenticatedControlReplayLane, AuthenticatedControlReplayState,
        CONTROL_INPUT_REPLAY_SESSION_LIMIT,
    },
};
use async_trait::async_trait;
use common_control_proto::{
    authenticated_input_scope, decode_authenticated_input_event, encode_authenticated_input_event,
    ControlEvent,
};
use mrd_application::ports::{
    TransportEnvelope, TransportLane, TransportMuxPort, TransportRouteKind, TransportSendOutcome,
};
use mrd_identity::{public_key_id, verify_context_bytes};
use mrd_ipc::{
    ControlInputEvent, ControlInputLane, RemoteAuthorizationState, RemoteFailure,
    RemotePermissionScope, RemoteReasonCode, RemoteSessionRole,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_session::{
    ControlSequenceDecision, PermissionScope, SignedControlEnvelopeV2,
    CONTROL_ENVELOPE_MAX_LIFETIME_MS, CONTROL_ENVELOPE_MAX_WIRE_BYTES,
    CONTROL_ENVELOPE_SIGNATURE_CONTEXT, CONTROL_ENVELOPE_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Weak,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex, task::AbortHandle};

const WAN_CONTROL_ACK_SIGNATURE_CONTEXT: &str = "MRD_WAN_CONTROL_ACK_V1";
const WAN_CONTROL_ACK_MAX_WIRE_BYTES: usize = 4_096;
const WAN_CONTROL_ACK_LIFETIME_MS: u64 = 2_000;
const WAN_CONTROL_ACK_TIMEOUT: Duration = Duration::from_millis(750);
const WAN_CONTROL_MAX_ACK_FRAMES: usize = 16;

#[derive(Clone, PartialEq, Eq, Hash)]
struct WanControlSenderKey {
    session_id: SessionId,
    grant_id: [u8; 32],
    target_key_id: String,
}

struct WanControlSenderState {
    reliable_sequence: Arc<Mutex<u64>>,
    realtime_sequence: Arc<Mutex<u64>>,
    next_event_id: AtomicU64,
    expires_at_ms: u64,
}

impl WanControlSenderState {
    fn new(expires_at_ms: u64) -> Self {
        Self {
            reliable_sequence: Arc::new(Mutex::new(1)),
            realtime_sequence: Arc::new(Mutex::new(1)),
            next_event_id: AtomicU64::new(1),
            expires_at_ms,
        }
    }

    fn sequence_for(&self, lane: ControlInputLane) -> Arc<Mutex<u64>> {
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

#[derive(Clone)]
struct WanControlMuxBinding {
    authority: WanMediaAuthority,
    mux: Arc<dyn TransportMuxPort>,
}

/// Process-owned bounded state for WAN control send, replay, and receiver ownership.
pub(crate) struct WanControlInputRegistry {
    senders: HashMap<WanControlSenderKey, Arc<WanControlSenderState>>,
    replays: HashMap<AuthenticatedControlReplayKey, AuthenticatedControlReplayState>,
    receivers: HashMap<SessionId, (u64, AbortHandle)>,
    reserved_receivers: HashSet<(SessionId, u64)>,
    next_receiver_token: u64,
    bindings: HashMap<SessionId, WanControlMuxBinding>,
}

impl Default for WanControlInputRegistry {
    fn default() -> Self {
        Self {
            senders: HashMap::new(),
            replays: HashMap::new(),
            receivers: HashMap::new(),
            reserved_receivers: HashSet::new(),
            next_receiver_token: 1,
            bindings: HashMap::new(),
        }
    }
}

impl WanControlInputRegistry {
    fn reserve_receiver(&mut self, session_id: &SessionId) -> Result<Option<u64>, ()> {
        if self.receivers.contains_key(session_id)
            || self
                .reserved_receivers
                .iter()
                .any(|(reserved, _)| reserved == session_id)
        {
            return Ok(None);
        }
        if self
            .receivers
            .len()
            .saturating_add(self.reserved_receivers.len())
            >= CONTROL_INPUT_REPLAY_SESSION_LIMIT
        {
            return Err(());
        }
        let token = self.next_receiver_token.max(1);
        self.next_receiver_token = token.saturating_add(1).max(1);
        self.reserved_receivers.insert((session_id.clone(), token));
        Ok(Some(token))
    }

    fn install_receiver(&mut self, session_id: &SessionId, token: u64, abort: AbortHandle) -> bool {
        if !self.reserved_receivers.remove(&(session_id.clone(), token)) {
            abort.abort();
            return false;
        }
        self.receivers.insert(session_id.clone(), (token, abort));
        true
    }

    fn finish_receiver(&mut self, session_id: &SessionId, token: u64) {
        self.reserved_receivers.remove(&(session_id.clone(), token));
        if self
            .receivers
            .get(session_id)
            .is_some_and(|(active, _)| *active == token)
        {
            self.receivers.remove(session_id);
        }
    }

    fn clear_session(&mut self, session_id: &SessionId) {
        if let Some((_, abort)) = self.receivers.remove(session_id) {
            abort.abort();
        }
        self.reserved_receivers
            .retain(|(reserved, _)| reserved != session_id);
        self.senders.retain(|key, _| &key.session_id != session_id);
        self.replays.retain(|key, _| key.session_id != session_id.0);
        self.bindings.remove(session_id);
    }
}

/// Service adapter used both by IPC controller requests and target receiver activation.
pub struct ServiceWanControlInputPort {
    app_state: Weak<AppState>,
}

impl ServiceWanControlInputPort {
    pub fn new(app_state: &Arc<AppState>) -> Self {
        Self {
            app_state: Arc::downgrade(app_state),
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub async fn with_test_mux(
        app_state: &Arc<AppState>,
        authority: WanMediaAuthority,
        mux: Arc<dyn TransportMuxPort>,
    ) -> Result<Self, WanMediaActivationError> {
        let route = mux.route_snapshot().await;
        if route.session_id != *authority.session_id()
            || route.kind != TransportRouteKind::TestMemory
            || route.closed
        {
            return Err(WanMediaActivationError::StartupFailed);
        }
        bind_verified_mux(app_state, authority, mux).await?;
        Ok(Self::new(app_state))
    }

    async fn resolve_binding(
        &self,
        session_id: &SessionId,
    ) -> Result<(WanMediaAuthority, Arc<dyn TransportMuxPort>), RemoteFailure> {
        let app_state = self.app_state.upgrade().ok_or_else(route_lost)?;
        let installed_binding = {
            app_state
                .wan_control_inputs
                .lock()
                .await
                .bindings
                .get(session_id)
                .cloned()
        };
        if let Some(binding) = installed_binding {
            let route = binding.mux.route_snapshot().await;
            if route.session_id == *session_id
                && !route.closed
                && (route.kind == TransportRouteKind::WebRtcRelay
                    || cfg!(any(test, debug_assertions))
                        && route.kind == TransportRouteKind::TestMemory)
            {
                return Ok((binding.authority, binding.mux));
            }
            return Err(route_lost());
        }

        let coordinator = app_state.wan_session_coordinator().ok_or_else(route_lost)?;
        let state = coordinator
            .snapshot(session_id)
            .await
            .map_err(|_| route_lost())?;
        let authority = WanMediaAuthority::from_streaming(&state).map_err(|_| route_lost())?;
        let mux = app_state
            .webrtc_host
            .verified_media_mux(session_id, authority.generation())
            .await
            .map_err(|_| route_lost())?;
        bind_verified_mux(&app_state, authority.clone(), Arc::clone(&mux))
            .await
            .map_err(|_| route_lost())?;
        Ok((authority, mux))
    }

    async fn clear_session(&self, session_id: &SessionId) {
        if let Some(app_state) = self.app_state.upgrade() {
            app_state
                .wan_control_inputs
                .lock()
                .await
                .clear_session(session_id);
            let _ = app_state
                .control_input()
                .lock()
                .await
                .release_session_all(session_id);
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub async fn stop_for_test(&self, session_id: &SessionId) {
        self.clear_session(session_id).await;
    }

    #[cfg(any(test, debug_assertions))]
    #[allow(clippy::too_many_arguments)]
    pub async fn signed_event_for_test(
        &self,
        session_id: &SessionId,
        source_device_id: DeviceId,
        target_device_id: DeviceId,
        scope: PermissionScope,
        sequence: u64,
        event_id: u64,
        event: ControlEvent,
    ) -> Result<SignedControlEnvelopeV2, RemoteFailure> {
        let app_state = self.app_state.upgrade().ok_or_else(route_lost)?;
        let authorization = app_state
            .session_authorizations
            .active_control_authorization(session_id, now_ms())
            .await?;
        build_signed_envelope(
            &app_state,
            &authorization,
            source_device_id,
            target_device_id,
            scope,
            sequence,
            event_id,
            event,
        )
    }
}

/// Retain the stable mux only after the media adapter verified the exact relay generation.
/// The mux survives atomic relay replacement, while every use still requires a live relay route.
pub(crate) async fn bind_verified_mux(
    app_state: &Arc<AppState>,
    authority: WanMediaAuthority,
    mux: Arc<dyn TransportMuxPort>,
) -> Result<(), WanMediaActivationError> {
    let route = mux.route_snapshot().await;
    let allowed_route = route.kind == TransportRouteKind::WebRtcRelay
        || cfg!(any(test, debug_assertions)) && route.kind == TransportRouteKind::TestMemory;
    if route.session_id != *authority.session_id() || route.closed || !allowed_route {
        return Err(WanMediaActivationError::StartupFailed);
    }
    let mut registry = app_state.wan_control_inputs.lock().await;
    if let Some(existing) = registry.bindings.get(authority.session_id()) {
        return if existing.authority == authority && Arc::ptr_eq(&existing.mux, &mux) {
            Ok(())
        } else {
            Err(WanMediaActivationError::AuthorityChanged)
        };
    }
    if registry.bindings.len() >= CONTROL_INPUT_REPLAY_SESSION_LIMIT {
        return Err(WanMediaActivationError::StartupFailed);
    }
    registry.bindings.insert(
        authority.session_id().clone(),
        WanControlMuxBinding { authority, mux },
    );
    Ok(())
}

#[async_trait]
impl WanInputActivationPort for ServiceWanControlInputPort {
    async fn enable_input(
        &self,
        authority: &WanMediaAuthority,
    ) -> Result<(), WanMediaActivationError> {
        if authority.role() != WanSessionRole::Target {
            return Err(WanMediaActivationError::StartupFailed);
        }
        if !authority.allows_scope(mrd_signal_proto::WanPermissionScopeV3::InputPointer)
            && !authority.allows_scope(mrd_signal_proto::WanPermissionScopeV3::InputKeyboard)
        {
            return Err(WanMediaActivationError::InputScopeRequired);
        }
        let app_state = self
            .app_state
            .upgrade()
            .ok_or(WanMediaActivationError::StartupFailed)?;
        let (resolved, mux) = self
            .resolve_binding(authority.session_id())
            .await
            .map_err(|_| WanMediaActivationError::StartupFailed)?;
        if &resolved != authority {
            return Err(WanMediaActivationError::AuthorityChanged);
        }
        let now = now_ms();
        if app_state
            .session_authorizations
            .transport_kind(authority.session_id())
            .await
            .as_deref()
            != Some("webrtc_relay")
        {
            return Err(WanMediaActivationError::ControlEvidenceRequired);
        }
        let authorization = app_state
            .session_authorizations
            .active_control_authorization(authority.session_id(), now)
            .await
            .map_err(|_| WanMediaActivationError::ControlEvidenceRequired)?;
        if !authority_matches(
            &app_state,
            authority,
            &authorization,
            WanSessionRole::Target,
        ) {
            return Err(WanMediaActivationError::ControlEvidenceRequired);
        }

        let token = {
            let mut registry = app_state.wan_control_inputs.lock().await;
            match registry.reserve_receiver(authority.session_id()) {
                Ok(Some(token)) => token,
                Ok(None) => return Ok(()),
                Err(()) => return Err(WanMediaActivationError::StartupFailed),
            }
        };
        let session_id = authority.session_id().clone();
        let task_app_state = Arc::clone(&app_state);
        let task_authority = authority.clone();
        let task_session_id = session_id.clone();
        let task = tokio::spawn(async move {
            run_target_receiver(Arc::clone(&task_app_state), task_authority, mux).await;
            let _ = task_app_state
                .control_input()
                .lock()
                .await
                .release_session_all(&task_session_id);
            task_app_state
                .wan_control_inputs
                .lock()
                .await
                .finish_receiver(&task_session_id, token);
        });
        let installed = app_state.wan_control_inputs.lock().await.install_receiver(
            &session_id,
            token,
            task.abort_handle(),
        );
        if !installed {
            return Err(WanMediaActivationError::StartupFailed);
        }
        Ok(())
    }
}

/// Production control-evidence barrier used immediately after the WAN media authority is published.
pub struct ServiceWanControlEvidenceBarrier {
    app_state: Weak<AppState>,
}

impl ServiceWanControlEvidenceBarrier {
    pub fn new(app_state: &Arc<AppState>) -> Self {
        Self {
            app_state: Arc::downgrade(app_state),
        }
    }
}

#[async_trait]
impl ControlEvidenceBarrier for ServiceWanControlEvidenceBarrier {
    async fn is_verified(&self, session_id: &SessionId) -> bool {
        let Some(app_state) = self.app_state.upgrade() else {
            return false;
        };
        app_state
            .session_authorizations
            .transport_kind(session_id)
            .await
            .as_deref()
            == Some("webrtc_relay")
            && app_state
                .session_authorizations
                .active_control_authorization(session_id, now_ms())
                .await
                .is_ok()
    }
}

/// Send one IPC control request over the exact verified WAN mux. There is no LAN fallback.
pub async fn request_authenticated_wan_control_input(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    event: ControlInputEvent,
) -> Result<crate::control_input::ControlInputResult, RemoteFailure> {
    let port = ServiceWanControlInputPort::new(app_state);
    let (authority, mux) = port.resolve_binding(session_id).await?;
    if authority.role() != WanSessionRole::Controller {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "outgoing WAN control input requires the controller role",
        ));
    }
    let authorization = app_state
        .session_authorizations
        .active_control_authorization(session_id, now_ms())
        .await?;
    if app_state
        .session_authorizations
        .transport_kind(session_id)
        .await
        .as_deref()
        != Some("webrtc_relay")
        || !authority_matches(
            app_state,
            &authority,
            &authorization,
            WanSessionRole::Controller,
        )
    {
        return Err(control_failure(
            RemoteReasonCode::IdentityMismatch,
            "WAN control authority no longer matches the verified session",
        ));
    }
    let events = authenticated_events_from_ipc(&event, &authorization.granted_scopes)?;
    let mut event_count = 0_u32;
    let mut result_lane = authenticated_event_lane(&event);
    for control_event in events {
        let result =
            send_control_event(app_state, &authority, Arc::clone(&mux), control_event).await?;
        event_count = event_count.saturating_add(result.event_count);
        result_lane = if matches!(event, ControlInputEvent::ReleaseAll) {
            ControlInputLane::Cleanup
        } else {
            result.lane
        };
    }
    Ok(crate::control_input::ControlInputResult {
        lane: result_lane,
        event_count,
    })
}

pub(crate) async fn clear_wan_control_input(app_state: &Arc<AppState>, session_id: &SessionId) {
    ServiceWanControlInputPort::new(app_state)
        .clear_session(session_id)
        .await;
}

async fn send_control_event(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    mux: Arc<dyn TransportMuxPort>,
    event: ControlEvent,
) -> Result<crate::control_input::ControlInputResult, RemoteFailure> {
    let lane = authenticated_event_lane(&ipc_event(&event)?);
    let sender = sender_state(app_state, authority).await?;
    let sequence_state = sender.sequence_for(lane);
    let mut sequence = sequence_state.lock_owned().await;
    let event_id = sender.next_event_id();
    let envelope = {
        let _security_guard = app_state.authorization_security_gate.lock().await;
        let authorization = app_state
            .session_authorizations
            .active_control_authorization(authority.session_id(), now_ms())
            .await?;
        if app_state
            .session_authorizations
            .transport_kind(authority.session_id())
            .await
            .as_deref()
            != Some("webrtc_relay")
            || !authority_matches(
                app_state,
                authority,
                &authorization,
                WanSessionRole::Controller,
            )
        {
            return Err(control_failure(
                RemoteReasonCode::GrantRevoked,
                "WAN control authorization changed before send",
            ));
        }
        let scope = permission_scope_for_event(&event)?;
        build_signed_envelope(
            app_state,
            &authorization,
            authority.controller_device_id().clone(),
            authority.target_device_id().clone(),
            scope,
            *sequence,
            event_id,
            event,
        )?
    };
    let transport_lane = transport_lane(lane);
    let encoded = serde_json::to_vec(&envelope).map_err(|_| protocol_failure())?;
    if encoded.len() > CONTROL_ENVELOPE_MAX_WIRE_BYTES {
        return Err(protocol_failure());
    }
    let attempts = if lane == ControlInputLane::Realtime {
        1
    } else {
        3
    };
    let request_commitment = control_request_commitment(
        &envelope,
        &envelope
            .payload
            .signing_bytes()
            .map_err(|_| protocol_failure())?,
    );
    for attempt in 0..attempts {
        let outcome = mux
            .send(TransportEnvelope {
                session_id: authority.session_id().clone(),
                lane: transport_lane,
                sequence: envelope.payload.sequence,
                payload: encoded.clone(),
                video: None,
            })
            .await
            .map_err(|_| route_lost())?;
        match outcome {
            TransportSendOutcome::Enqueued | TransportSendOutcome::ReplacedStale => {}
            TransportSendOutcome::Backpressured if attempt + 1 < attempts => continue,
            TransportSendOutcome::Backpressured => {
                return Err(control_failure(
                    RemoteReasonCode::RouteLost,
                    "WAN control lane is backpressured",
                ));
            }
            TransportSendOutcome::Closed => return Err(route_lost()),
        }
        match wait_for_ack(
            app_state,
            authority,
            mux.as_ref(),
            transport_lane,
            &envelope,
            request_commitment,
        )
        .await
        {
            Ok(result) => {
                *sequence = sequence.saturating_add(1);
                return Ok(result);
            }
            Err(failure)
                if failure.code == RemoteReasonCode::RouteLost && attempt + 1 < attempts =>
            {
                continue;
            }
            Err(failure) => return Err(failure),
        }
    }
    Err(route_lost())
}

async fn sender_state(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
) -> Result<Arc<WanControlSenderState>, RemoteFailure> {
    let key = WanControlSenderKey {
        session_id: authority.session_id().clone(),
        grant_id: authority.grant_id(),
        target_key_id: authority.target_key_id().to_owned(),
    };
    let now = now_ms();
    let mut registry = app_state.wan_control_inputs.lock().await;
    registry
        .senders
        .retain(|_, sender| now <= sender.expires_at_ms);
    if let Some(sender) = registry.senders.get(&key) {
        return Ok(Arc::clone(sender));
    }
    if registry.senders.len() >= CONTROL_INPUT_REPLAY_SESSION_LIMIT {
        return Err(control_failure(
            RemoteReasonCode::ReplayDetected,
            "WAN control sender capacity is exhausted",
        ));
    }
    let sender = Arc::new(WanControlSenderState::new(authority.expires_at_ms()));
    registry.senders.insert(key, Arc::clone(&sender));
    Ok(sender)
}

async fn run_target_receiver(
    app_state: Arc<AppState>,
    authority: WanMediaAuthority,
    mux: Arc<dyn TransportMuxPort>,
) {
    loop {
        let received = tokio::select! {
            reliable = mux.recv(TransportLane::ControlReliable) => {
                reliable.map(|value| value.map(|envelope| (TransportLane::ControlReliable, envelope)))
            }
            realtime = mux.recv(TransportLane::ControlRealtime) => {
                realtime.map(|value| value.map(|envelope| (TransportLane::ControlRealtime, envelope)))
            }
        };
        let Ok(Some((lane, envelope))) = received else {
            break;
        };
        if let Some(ack) = process_target_envelope(&app_state, &authority, lane, envelope).await {
            let _ = mux.send(ack).await;
        }
    }
}

async fn process_target_envelope(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    transport_lane_value: TransportLane,
    transport: TransportEnvelope,
) -> Option<TransportEnvelope> {
    if transport.session_id != *authority.session_id()
        || transport.lane != transport_lane_value
        || transport.video.is_some()
        || transport.payload.is_empty()
        || transport.payload.len() > CONTROL_ENVELOPE_MAX_WIRE_BYTES
    {
        return None;
    }
    let received_at = now_ms();
    let envelope =
        SignedControlEnvelopeV2::decode_bounded_json(&transport.payload, received_at).ok()?;
    if envelope.payload.session_id != transport.session_id
        || envelope.payload.sequence != transport.sequence
    {
        return None;
    }
    let signing_bytes = envelope.payload.signing_bytes().ok()?;
    let commitment = control_request_commitment(&envelope, &signing_bytes);
    let _security_guard = app_state.authorization_security_gate.lock().await;
    let validation = if app_state
        .session_authorizations
        .transport_kind(authority.session_id())
        .await
        .as_deref()
        != Some("webrtc_relay")
    {
        Err(control_failure(
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "WAN control input cannot use a non-WAN authorization",
        ))
    } else {
        validate_authenticated_control_input(
            app_state,
            &envelope,
            &signing_bytes,
            authority.target_device_id(),
            authority.target_key_id(),
            received_at,
        )
        .await
    };
    let (authorization, event, input_lane) = match validation {
        Ok(validated)
            if authority_matches(app_state, authority, &validated.0, WanSessionRole::Target) =>
        {
            validated
        }
        Ok(_) => {
            return denial_ack(
                app_state,
                authority,
                &envelope,
                commitment,
                transport_lane_value,
                control_failure(
                    RemoteReasonCode::IdentityMismatch,
                    "WAN control input does not match the verified route authority",
                ),
            )
        }
        Err(failure) => {
            return denial_ack(
                app_state,
                authority,
                &envelope,
                commitment,
                transport_lane_value,
                failure,
            )
        }
    };
    if transport_lane(input_lane) != transport_lane_value {
        return denial_ack(
            app_state,
            authority,
            &envelope,
            commitment,
            transport_lane_value,
            protocol_failure(),
        );
    }

    let replay_key = AuthenticatedControlReplayKey {
        session_id: authority.session_id().0.clone(),
        grant_id: envelope.payload.grant_id,
        source_key_id: envelope.payload.source_key_id.clone(),
    };
    let replay_lane = AuthenticatedControlReplayLane::from_input_lane(input_lane);
    let mut registry = app_state.wan_control_inputs.lock().await;
    registry
        .replays
        .retain(|_, replay| !replay.is_expired(received_at));
    if !registry.replays.contains_key(&replay_key)
        && registry.replays.len() >= CONTROL_INPUT_REPLAY_SESSION_LIMIT
    {
        drop(registry);
        return denial_ack(
            app_state,
            authority,
            &envelope,
            commitment,
            transport_lane_value,
            control_failure(
                RemoteReasonCode::ReplayDetected,
                "WAN control replay capacity is exhausted",
            ),
        );
    }
    let replay = registry
        .replays
        .entry(replay_key)
        .or_insert_with(|| AuthenticatedControlReplayState::new(authorization.expires_at_ms));
    match replay.observe(
        replay_lane,
        envelope.payload.sequence,
        envelope.payload.event_id,
        commitment,
    ) {
        Ok(ControlSequenceDecision::ExactRetry) => {
            let ack = replay.cached_ack(replay_lane, envelope.payload.sequence)?;
            return Some(transport_ack(
                authority.session_id(),
                transport_lane_value,
                envelope.payload.sequence,
                ack,
            ));
        }
        Err(error) => {
            drop(registry);
            return denial_ack(
                app_state,
                authority,
                &envelope,
                commitment,
                transport_lane_value,
                replay_failure(error),
            );
        }
        Ok(ControlSequenceDecision::FirstSeen) => {}
    }

    let injection_at = now_ms();
    let mut authorization_failure = None;
    let result = if injection_at > authorization.expires_at_ms
        || injection_at > envelope.payload.expires_at_ms
    {
        Err(control_failure(
            RemoteReasonCode::GrantExpired,
            "WAN control input expired before injection",
        ))
    } else if !app_state.security_is_healthy() && !matches!(event, ControlInputEvent::ReleaseAll) {
        let failure = control_failure(
            RemoteReasonCode::PolicyChanged,
            "authoritative security state is unavailable",
        );
        authorization_failure = Some(failure.clone());
        Err(failure)
    } else {
        match app_state
            .control_input()
            .lock()
            .await
            .handle_authenticated_session_event(
                authority.session_id(),
                service_control_scope(envelope.payload.scope),
                &event,
            ) {
            Ok(result) => Ok((input_lane, result.event_count)),
            Err(_) => {
                let failure = control_failure(
                    RemoteReasonCode::PolicyChanged,
                    "authorized WAN control input could not be injected",
                );
                authorization_failure = Some(failure.clone());
                Err(failure)
            }
        }
    };
    let ack = signed_ack(
        app_state,
        &envelope,
        commitment,
        result.clone(),
        injection_at,
    )
    .ok()?;
    replay.cache_ack(replay_lane, envelope.payload.sequence, ack.clone());
    drop(registry);
    if let Some(failure) = authorization_failure {
        let _ = app_state
            .session_authorizations
            .record_failure(
                authority.session_id(),
                RemoteAuthorizationState::PolicyChanged,
                failure,
                injection_at,
            )
            .await;
    }
    Some(transport_ack(
        authority.session_id(),
        transport_lane_value,
        envelope.payload.sequence,
        ack,
    ))
}

fn denial_ack(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    envelope: &SignedControlEnvelopeV2,
    commitment: [u8; 32],
    transport_lane_value: TransportLane,
    failure: RemoteFailure,
) -> Option<TransportEnvelope> {
    let ack = signed_ack(app_state, envelope, commitment, Err(failure), now_ms()).ok()?;
    Some(transport_ack(
        authority.session_id(),
        transport_lane_value,
        envelope.payload.sequence,
        ack,
    ))
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WanControlAckPayload {
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

impl WanControlAckPayload {
    fn signing_bytes(&self) -> Result<Vec<u8>, RemoteFailure> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u16,
            kind: &'static str,
            payload: &'a WanControlAckPayload,
        }
        serde_json::to_vec(&Commitment {
            schema_version: CONTROL_ENVELOPE_VERSION,
            kind: "wan_control_ack",
            payload: self,
        })
        .map_err(|_| protocol_failure())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedWanControlAck {
    payload: WanControlAckPayload,
    public_key: [u8; 32],
    signature: Vec<u8>,
}

fn signed_ack(
    app_state: &Arc<AppState>,
    request: &SignedControlEnvelopeV2,
    request_commitment: [u8; 32],
    result: Result<(ControlInputLane, u32), RemoteFailure>,
    issued_at_ms: u64,
) -> Result<Vec<u8>, RemoteFailure> {
    let (accepted, reason, lane, event_count) = match result {
        Ok((lane, event_count)) => (true, None, Some(lane), event_count),
        Err(failure) => (false, Some(failure.code), None, 0),
    };
    let payload = WanControlAckPayload {
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
        expires_at_ms: issued_at_ms.saturating_add(WAN_CONTROL_ACK_LIFETIME_MS),
    };
    let identity = app_state.device_identities.machine_identity();
    let signature = identity
        .sign_context_bytes(WAN_CONTROL_ACK_SIGNATURE_CONTEXT, &payload.signing_bytes()?)
        .map_err(|_| identity_failure())?;
    let ack = SignedWanControlAck {
        payload,
        public_key: identity
            .public_key()
            .try_into()
            .map_err(|_| identity_failure())?,
        signature,
    };
    let encoded = serde_json::to_vec(&ack).map_err(|_| protocol_failure())?;
    if encoded.len() > WAN_CONTROL_ACK_MAX_WIRE_BYTES {
        return Err(protocol_failure());
    }
    Ok(encoded)
}

async fn wait_for_ack(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    mux: &dyn TransportMuxPort,
    transport_lane_value: TransportLane,
    request: &SignedControlEnvelopeV2,
    request_commitment: [u8; 32],
) -> Result<crate::control_input::ControlInputResult, RemoteFailure> {
    let deadline = tokio::time::Instant::now() + WAN_CONTROL_ACK_TIMEOUT;
    for _ in 0..WAN_CONTROL_MAX_ACK_FRAMES {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(route_lost());
        }
        let received = tokio::time::timeout(remaining, mux.recv(transport_lane_value))
            .await
            .map_err(|_| route_lost())?
            .map_err(|_| route_lost())?
            .ok_or_else(route_lost)?;
        if received.session_id != *authority.session_id()
            || received.lane != transport_lane_value
            || received.sequence != request.payload.sequence
            || received.video.is_some()
        {
            continue;
        }
        return validate_ack(
            app_state,
            authority,
            request,
            request_commitment,
            &received.payload,
        )
        .await;
    }
    Err(protocol_failure())
}

async fn validate_ack(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    request: &SignedControlEnvelopeV2,
    request_commitment: [u8; 32],
    bytes: &[u8],
) -> Result<crate::control_input::ControlInputResult, RemoteFailure> {
    if bytes.is_empty() || bytes.len() > WAN_CONTROL_ACK_MAX_WIRE_BYTES {
        return Err(protocol_failure());
    }
    let ack: SignedWanControlAck = serde_json::from_slice(bytes).map_err(|_| protocol_failure())?;
    let payload = &ack.payload;
    let now = now_ms();
    let _security_guard = app_state.authorization_security_gate.lock().await;
    let authorization = app_state
        .session_authorizations
        .active_control_authorization(authority.session_id(), now)
        .await?;
    if !authority_matches(
        app_state,
        authority,
        &authorization,
        WanSessionRole::Controller,
    ) || ack.signature.len() != 64
        || payload.protocol_version != CONTROL_ENVELOPE_VERSION
        || payload.session_id != request.payload.session_id
        || payload.grant_id != request.payload.grant_id
        || payload.source_key_id != request.payload.source_key_id
        || payload.target_key_id != request.payload.target_key_id
        || payload.sequence != request.payload.sequence
        || payload.event_id != request.payload.event_id
        || payload.request_commitment != request_commitment
        || payload.issued_at_ms > now.saturating_add(2_000)
        || payload.issued_at_ms > payload.expires_at_ms
        || now > payload.expires_at_ms
        || payload.expires_at_ms.saturating_sub(payload.issued_at_ms) > WAN_CONTROL_ACK_LIFETIME_MS
        || ack.public_key != authorization.peer_public_key
        || public_key_id(&ack.public_key) != authorization.peer_key_id
        || verify_context_bytes(
            &ack.public_key,
            WAN_CONTROL_ACK_SIGNATURE_CONTEXT,
            &payload.signing_bytes()?,
            &ack.signature,
        )
        .is_err()
    {
        return Err(protocol_failure());
    }
    if payload.accepted {
        if payload.reason.is_some() {
            return Err(protocol_failure());
        }
        let lane = payload.lane.ok_or_else(protocol_failure)?;
        let expected_lane = authenticated_event_lane(&ipc_event(
            &decode_authenticated_input_event(&request.payload.authenticated_event_bytes)
                .map_err(|_| protocol_failure())?,
        )?);
        if lane != expected_lane {
            return Err(protocol_failure());
        }
        Ok(crate::control_input::ControlInputResult {
            lane,
            event_count: payload.event_count,
        })
    } else {
        if payload.lane.is_some() || payload.event_count != 0 {
            return Err(protocol_failure());
        }
        Err(control_failure(
            payload.reason.ok_or_else(protocol_failure)?,
            "authenticated WAN peer rejected control input",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_signed_envelope(
    app_state: &Arc<AppState>,
    authorization: &crate::session_authorization::ActiveControlAuthorization,
    source_device_id: DeviceId,
    target_device_id: DeviceId,
    scope: PermissionScope,
    sequence: u64,
    event_id: u64,
    event: ControlEvent,
) -> Result<SignedControlEnvelopeV2, RemoteFailure> {
    let issued_at_ms = now_ms();
    let expires_at_ms = issued_at_ms
        .saturating_add(CONTROL_ENVELOPE_MAX_LIFETIME_MS)
        .min(authorization.expires_at_ms);
    if expires_at_ms <= issued_at_ms {
        return Err(control_failure(
            RemoteReasonCode::GrantExpired,
            "WAN control grant expired before signing",
        ));
    }
    let identity = app_state.device_identities.machine_identity();
    let payload = mrd_session::ControlEnvelopeV2 {
        protocol_version: CONTROL_ENVELOPE_VERSION,
        session_id: authorization.session_id.clone(),
        grant_id: authorization.grant_id,
        source_device_id,
        target_device_id,
        source_key_id: identity.key_id().to_owned(),
        target_key_id: authorization.peer_key_id.clone(),
        scope,
        sequence,
        event_id,
        issued_at_ms,
        expires_at_ms,
        policy_revision: authorization.policy_revision,
        authenticated_event_bytes: encode_authenticated_input_event(&event)
            .map_err(|_| protocol_failure())?,
    };
    let signature = identity
        .sign_context_bytes(
            CONTROL_ENVELOPE_SIGNATURE_CONTEXT,
            &payload.signing_bytes().map_err(|_| protocol_failure())?,
        )
        .map_err(|_| identity_failure())?
        .try_into()
        .map_err(|_| identity_failure())?;
    Ok(SignedControlEnvelopeV2 {
        payload,
        public_key: identity
            .public_key()
            .try_into()
            .map_err(|_| identity_failure())?,
        signature,
    })
}

fn authority_matches(
    app_state: &Arc<AppState>,
    authority: &WanMediaAuthority,
    authorization: &crate::session_authorization::ActiveControlAuthorization,
    expected_role: WanSessionRole,
) -> bool {
    if authority.role() != expected_role
        || authorization.session_id != *authority.session_id()
        || authorization.grant_id != authority.grant_id()
        || authorization.policy_revision != authority.policy_revision()
        || authorization.expires_at_ms != authority.expires_at_ms()
    {
        return false;
    }
    let (local_device_id, local_key_id, peer_device_id, peer_key_id, ipc_role) = match expected_role
    {
        WanSessionRole::Controller => (
            authority.controller_device_id(),
            authority.controller_key_id(),
            authority.target_device_id(),
            authority.target_key_id(),
            RemoteSessionRole::Controller,
        ),
        WanSessionRole::Target => (
            authority.target_device_id(),
            authority.target_key_id(),
            authority.controller_device_id(),
            authority.controller_key_id(),
            RemoteSessionRole::Agent,
        ),
    };
    if local_device_id == peer_device_id
        || app_state.device_identities.machine_key_id() != Some(local_key_id)
        || authorization.role != ipc_role
        || authorization.peer_device_id != *peer_device_id
        || authorization.peer_key_id != peer_key_id
    {
        return false;
    }
    let mut expected_scopes = authority
        .approved_scopes()
        .iter()
        .copied()
        .map(ipc_scope)
        .collect::<Vec<_>>();
    expected_scopes.sort_unstable();
    let mut actual_scopes = authorization.granted_scopes.clone();
    actual_scopes.sort_unstable();
    expected_scopes == actual_scopes
}

fn ipc_scope(scope: mrd_signal_proto::WanPermissionScopeV3) -> RemotePermissionScope {
    match scope {
        mrd_signal_proto::WanPermissionScopeV3::ScreenView => RemotePermissionScope::ScreenView,
        mrd_signal_proto::WanPermissionScopeV3::InputPointer => RemotePermissionScope::InputPointer,
        mrd_signal_proto::WanPermissionScopeV3::InputKeyboard => {
            RemotePermissionScope::InputKeyboard
        }
        mrd_signal_proto::WanPermissionScopeV3::ClipboardRead => {
            RemotePermissionScope::ClipboardRead
        }
        mrd_signal_proto::WanPermissionScopeV3::ClipboardWrite => {
            RemotePermissionScope::ClipboardWrite
        }
        mrd_signal_proto::WanPermissionScopeV3::FileRead => RemotePermissionScope::FileRead,
        mrd_signal_proto::WanPermissionScopeV3::FileWrite => RemotePermissionScope::FileWrite,
        mrd_signal_proto::WanPermissionScopeV3::AudioListen => RemotePermissionScope::AudioListen,
        mrd_signal_proto::WanPermissionScopeV3::AudioTalk => RemotePermissionScope::AudioTalk,
        mrd_signal_proto::WanPermissionScopeV3::DisplaySwitch => {
            RemotePermissionScope::DisplaySwitch
        }
        mrd_signal_proto::WanPermissionScopeV3::DisplayMultiView => {
            RemotePermissionScope::DisplayMultiView
        }
        mrd_signal_proto::WanPermissionScopeV3::PowerRestart => RemotePermissionScope::PowerRestart,
        mrd_signal_proto::WanPermissionScopeV3::PowerShutdown => {
            RemotePermissionScope::PowerShutdown
        }
        mrd_signal_proto::WanPermissionScopeV3::TerminalOpen => RemotePermissionScope::TerminalOpen,
        mrd_signal_proto::WanPermissionScopeV3::PrivacyBlockLocalInput => {
            RemotePermissionScope::PrivacyBlockLocalInput
        }
        mrd_signal_proto::WanPermissionScopeV3::PrivacyBlankScreen => {
            RemotePermissionScope::PrivacyBlankScreen
        }
        mrd_signal_proto::WanPermissionScopeV3::SecureDesktopView => {
            RemotePermissionScope::SecureDesktopView
        }
        mrd_signal_proto::WanPermissionScopeV3::SecureDesktopControl => {
            RemotePermissionScope::SecureDesktopControl
        }
    }
}

fn permission_scope_for_event(event: &ControlEvent) -> Result<PermissionScope, RemoteFailure> {
    match authenticated_input_scope(event).map_err(|_| protocol_failure())? {
        common_control_proto::AuthenticatedInputScope::Pointer => Ok(PermissionScope::InputPointer),
        common_control_proto::AuthenticatedInputScope::Keyboard => {
            Ok(PermissionScope::InputKeyboard)
        }
    }
}

fn ipc_event(event: &ControlEvent) -> Result<ControlInputEvent, RemoteFailure> {
    crate::lan_discovery::lan_control_input::ipc_event_from_authenticated(event.clone())
}

fn transport_lane(lane: ControlInputLane) -> TransportLane {
    match lane {
        ControlInputLane::Reliable | ControlInputLane::Cleanup => TransportLane::ControlReliable,
        ControlInputLane::Realtime => TransportLane::ControlRealtime,
    }
}

fn transport_ack(
    session_id: &SessionId,
    lane: TransportLane,
    sequence: u64,
    payload: Vec<u8>,
) -> TransportEnvelope {
    TransportEnvelope {
        session_id: session_id.clone(),
        lane,
        sequence,
        payload,
        video: None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn identity_failure() -> RemoteFailure {
    control_failure(
        RemoteReasonCode::IdentityMismatch,
        "WAN control identity operation failed",
    )
}

fn protocol_failure() -> RemoteFailure {
    control_failure(
        RemoteReasonCode::ProtocolDowngradeBlocked,
        "WAN control protocol validation failed",
    )
}

fn route_lost() -> RemoteFailure {
    control_failure(
        RemoteReasonCode::RouteLost,
        "verified WAN control route is unavailable",
    )
}
