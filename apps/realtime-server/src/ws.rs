use crate::{ConnectionId, CoreConfig, Delivery, DeliveryTarget, RealtimeCore, RealtimeError};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use mrd_proto::DeviceId;
use mrd_signal_client::{
    decode_authenticated_message, encode_authenticated_message, SignalClientError,
    MAX_SIGNAL_MESSAGE_BYTES,
};
use mrd_signal_proto::{
    AuthenticatedSignalMessage, ProtocolReasonCode, SignalEnvelope, SignalErrorMessage,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone)]
pub struct ServerRuntimeConfig {
    pub bind_addr: SocketAddr,
    pub secure_websocket_required: bool,
    pub max_message_bytes: usize,
    pub outbound_queue_capacity: usize,
    pub prune_interval: Duration,
    pub core: CoreConfig,
}

impl ServerRuntimeConfig {
    pub fn from_env() -> Result<Self, ServerConfigError> {
        let deployed = env_bool("MRD_REALTIME_DEPLOYED", false)?;
        let bind_addr: SocketAddr = std::env::var("MRD_REALTIME_BIND")
            .unwrap_or_else(|_| "127.0.0.1:9532".into())
            .parse()
            .map_err(|_| ServerConfigError::Invalid("MRD_REALTIME_BIND"))?;
        let tls_terminated = env_bool("MRD_REALTIME_TLS_TERMINATED", false)?;
        validate_deployment(deployed, tls_terminated, bind_addr)?;
        let max_message_bytes = env_usize(
            "MRD_REALTIME_MAX_MESSAGE_BYTES",
            MAX_SIGNAL_MESSAGE_BYTES,
            1_024,
            MAX_SIGNAL_MESSAGE_BYTES,
        )?;
        let outbound_queue_capacity = env_usize("MRD_REALTIME_OUTBOUND_QUEUE", 64, 1, 4_096)?;
        let presence_ttl_ms = env_u64("MRD_REALTIME_PRESENCE_TTL_MS", 30_000, 5_000, 300_000)?;
        Ok(Self {
            bind_addr,
            secure_websocket_required: deployed,
            max_message_bytes,
            outbound_queue_capacity,
            prune_interval: Duration::from_millis((presence_ttl_ms / 3).max(1_000)),
            core: CoreConfig {
                server_device_id: DeviceId(
                    std::env::var("MRD_REALTIME_SERVER_DEVICE_ID")
                        .unwrap_or_else(|_| "signal-server".into()),
                ),
                challenge_ttl_ms: env_u64("MRD_REALTIME_CHALLENGE_TTL_MS", 10_000, 1_000, 60_000)?,
                presence_ttl_ms,
                route_ttl_ms: env_u64("MRD_REALTIME_ROUTE_TTL_MS", 120_000, 5_000, 600_000)?,
                max_connections: env_usize("MRD_REALTIME_MAX_CONNECTIONS", 10_000, 1, 100_000)?,
                max_messages_per_window: u32::try_from(env_u64(
                    "MRD_REALTIME_RATE_MESSAGES",
                    256,
                    1,
                    100_000,
                )?)
                .map_err(|_| ServerConfigError::Invalid("MRD_REALTIME_RATE_MESSAGES"))?,
                rate_window_ms: env_u64("MRD_REALTIME_RATE_WINDOW_MS", 1_000, 100, 60_000)?,
            },
        })
    }
}

fn validate_deployment(
    deployed: bool,
    tls_terminated: bool,
    bind_addr: SocketAddr,
) -> Result<(), ServerConfigError> {
    if deployed && (!tls_terminated || !bind_addr.ip().is_loopback()) {
        Err(ServerConfigError::InsecureDeployment)
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ServerConfigError {
    #[error("invalid realtime-server environment variable: {0}")]
    Invalid(&'static str),
    #[error("deployed realtime-server requires loopback binding behind declared TLS termination")]
    InsecureDeployment,
}

fn env_bool(name: &'static str, default: bool) -> Result<bool, ServerConfigError> {
    let Ok(value) = std::env::var(name) else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ServerConfigError::Invalid(name)),
    }
}

fn env_u64(
    name: &'static str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ServerConfigError> {
    let value = std::env::var(name)
        .ok()
        .map(|raw| u64::from_str(raw.trim()).map_err(|_| ServerConfigError::Invalid(name)))
        .transpose()?
        .unwrap_or(default);
    if !(minimum..=maximum).contains(&value) {
        return Err(ServerConfigError::Invalid(name));
    }
    Ok(value)
}

fn env_usize(
    name: &'static str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ServerConfigError> {
    let value = std::env::var(name)
        .ok()
        .map(|raw| usize::from_str(raw.trim()).map_err(|_| ServerConfigError::Invalid(name)))
        .transpose()?
        .unwrap_or(default);
    if !(minimum..=maximum).contains(&value) {
        return Err(ServerConfigError::Invalid(name));
    }
    Ok(value)
}

#[derive(Clone)]
pub struct RealtimeAppState {
    core: Arc<Mutex<RealtimeCore>>,
    peers: Arc<Mutex<HashMap<ConnectionId, mpsc::Sender<String>>>>,
    config: ServerRuntimeConfig,
}

impl RealtimeAppState {
    pub fn new(core: RealtimeCore, config: ServerRuntimeConfig) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    pub fn spawn_pruner(&self) -> tokio::task::JoinHandle<()> {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(state.config.prune_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let expired = state.core.lock().await.prune(now_ms());
                if !expired.is_empty() {
                    let mut peers = state.peers.lock().await;
                    for connection in expired {
                        peers.remove(&connection);
                    }
                }
            }
        })
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    authenticated_presence: usize,
    authorized_routes: usize,
}

pub fn build_router(state: RealtimeAppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn health(State(state): State<RealtimeAppState>) -> Json<HealthResponse> {
    let core = state.core.lock().await;
    Json(HealthResponse {
        status: "ok",
        service: "realtime-server",
        authenticated_presence: core.presence_count(),
        authorized_routes: core.route_count(),
    })
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RealtimeAppState>,
    headers: HeaderMap,
) -> Response {
    if state.config.secure_websocket_required && !forwarded_as_https(&headers) {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "secure WebSocket transport is required",
        )
            .into_response();
    }
    let maximum = state.config.max_message_bytes;
    ws.max_frame_size(maximum)
        .max_message_size(maximum)
        .on_upgrade(move |socket| handle_socket(socket, state))
        .into_response()
}

fn forwarded_as_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("https"))
}

async fn handle_socket(socket: WebSocket, state: RealtimeAppState) {
    let Ok(connection_id) = random_connection_id() else {
        return;
    };
    let challenge = {
        let mut core = state.core.lock().await;
        match core.open_connection(connection_id, now_ms()) {
            Ok(challenge) => challenge,
            Err(error) => {
                tracing::warn!(reason = ?error.reason_code(), "realtime connection rejected");
                return;
            }
        }
    };
    let (mut socket_sender, mut socket_receiver) = socket.split();
    let (outbound, mut outbound_receiver) =
        mpsc::channel::<String>(state.config.outbound_queue_capacity);
    state
        .peers
        .lock()
        .await
        .insert(connection_id, outbound.clone());
    let writer = tokio::spawn(async move {
        while let Some(message) = outbound_receiver.recv().await {
            if socket_sender
                .send(Message::Text(message.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let challenge = SignalEnvelope::new(AuthenticatedSignalMessage::ServerChallenge(challenge));
    if let Ok(encoded) = encode_authenticated_message(&challenge) {
        let _ = outbound.try_send(encoded);
    }

    while let Some(result) = socket_receiver.next().await {
        let Ok(message) = result else { break };
        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                break;
            }
            continue;
        };
        if text.len() > state.config.max_message_bytes {
            send_error(&outbound, ProtocolReasonCode::Malformed);
            break;
        }
        let envelope = match decode_inbound(&text) {
            Ok(envelope) => envelope,
            Err(reason) => {
                send_error(&outbound, reason);
                continue;
            }
        };
        let deliveries = {
            let mut core = state.core.lock().await;
            core.handle(connection_id, envelope, now_ms())
        };
        match deliveries {
            Ok(deliveries) => deliver_all(&state, deliveries).await,
            Err(error) => {
                tracing::warn!(
                    connection_id = ?connection_id,
                    reason = ?error.reason_code(),
                    "authenticated realtime message rejected"
                );
                send_error(&outbound, error.reason_code());
            }
        }
    }

    state.peers.lock().await.remove(&connection_id);
    state.core.lock().await.disconnect(connection_id);
    writer.abort();
}

async fn deliver_all(state: &RealtimeAppState, deliveries: Vec<Delivery>) {
    let mut failed = Vec::new();
    for delivery in deliveries {
        let DeliveryTarget::Connection(connection_id) = delivery.target;
        let Ok(encoded) = encode_authenticated_message(&delivery.envelope) else {
            continue;
        };
        let sender = state.peers.lock().await.get(&connection_id).cloned();
        if let Some(sender) = sender {
            if sender.try_send(encoded).is_err() {
                tracing::warn!(
                    connection_id = ?connection_id,
                    "realtime outbound queue unavailable"
                );
                failed.push(connection_id);
            }
        }
    }
    for connection_id in failed {
        state.peers.lock().await.remove(&connection_id);
        state.core.lock().await.disconnect(connection_id);
    }
}

fn send_error(sender: &mpsc::Sender<String>, reason: ProtocolReasonCode) {
    let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::ProtocolError(
        SignalErrorMessage {
            reason,
            correlation_id: None,
            detail: "request rejected".into(),
        },
    ));
    if let Ok(encoded) = encode_authenticated_message(&envelope) {
        let _ = sender.try_send(encoded);
    }
}

fn decode_inbound(raw: &str) -> Result<SignalEnvelope, ProtocolReasonCode> {
    decode_authenticated_message(raw).map_err(|error| match error {
        SignalClientError::Protocol(protocol) => protocol.reason_code(),
        SignalClientError::Serialize(_) | SignalClientError::MessageTooLarge => {
            ProtocolReasonCode::Malformed
        }
    })
}

fn random_connection_id() -> Result<ConnectionId, RealtimeError> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| RealtimeError::EntropyUnavailable)?;
        if let Ok(connection) = ConnectionId::from_bytes(bytes) {
            return Ok(connection);
        }
    }
    Err(RealtimeError::EntropyUnavailable)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployed_config_requires_tls_termination_and_loopback() {
        let mut headers = HeaderMap::new();
        assert!(!forwarded_as_https(&headers));
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(forwarded_as_https(&headers));
        assert!(validate_deployment(true, false, "127.0.0.1:9532".parse().unwrap()).is_err());
        assert!(validate_deployment(true, true, "0.0.0.0:9532".parse().unwrap()).is_err());
        assert!(validate_deployment(true, true, "127.0.0.1:9532".parse().unwrap()).is_ok());
    }

    #[test]
    fn websocket_wire_decode_preserves_unsupported_version_reason() {
        for raw in [
            r#"{"version":2,"message":{"type":"session_intent","payload":{}}}"#,
            r#"{"version":3,"message":{"type":"protocol_error","payload":{"reason":"malformed","correlation_id":null,"detail":"request rejected"}}}"#,
        ] {
            assert_eq!(
                decode_inbound(raw).unwrap_err(),
                ProtocolReasonCode::UnsupportedVersion
            );
        }
    }
}
