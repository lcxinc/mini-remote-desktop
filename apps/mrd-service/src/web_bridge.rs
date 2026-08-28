#[cfg(feature = "browser-webrtc-preview")]
use crate::browser_webrtc_preview::{
    BrowserWebrtcPreviewHost, BrowserWebrtcPreviewStartRequest, BrowserWebrtcPreviewStopRequest,
};
use crate::{
    browser_webcodecs_preview::{
        spawn_browser_webcodecs_capture_sender, BrowserWebcodecsPreviewControlMessage,
        BrowserWebcodecsPreviewOutbound,
    },
    ipc_server::IpcServer,
    resource_monitor::{ResourceMonitor, ResourceSnapshotRequest},
};
use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mrd_ipc::{IpcRequest, IpcResponse};
use serde::{Deserialize, Serialize};
use std::{
    env,
    future::pending,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{mpsc, Mutex};
use tokio::{net::TcpListener, task::JoinHandle};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};

const DEFAULT_BIND: &str = "127.0.0.1:9532";
const TOKEN_HEADER: &str = "x-mrd-bridge-token";

#[derive(Debug, Clone)]
pub struct WebBridgeConfig {
    enabled: bool,
    bind: SocketAddr,
    token: Option<String>,
}

impl WebBridgeConfig {
    pub fn from_env() -> Result<Option<Self>> {
        let enabled = env::var("MRD_WEB_BRIDGE_ENABLED")
            .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "off" | "OFF"))
            .unwrap_or(true);
        if !enabled {
            return Ok(None);
        }

        let bind = env::var("MRD_WEB_BRIDGE_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
        let token = env::var("MRD_WEB_BRIDGE_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Self::new(bind.parse().context("parse MRD_WEB_BRIDGE_BIND")?, token).map(Some)
    }

    pub fn new(bind: SocketAddr, token: Option<String>) -> Result<Self> {
        if !is_loopback_addr(&bind) && token.is_none() {
            return Err(anyhow!(
                "MRD_WEB_BRIDGE_TOKEN is required when MRD_WEB_BRIDGE_BIND is not loopback"
            ));
        }

        Ok(Self {
            enabled: true,
            bind,
            token,
        })
    }

    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    #[allow(dead_code)]
    pub fn requires_token(&self) -> bool {
        self.token.is_some()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[allow(dead_code)]
    pub fn new_for_test(bind: SocketAddr, token: Option<String>) -> Result<Self> {
        Self::new(bind, token)
    }
}

#[derive(Clone)]
struct WebBridgeState {
    config: WebBridgeConfig,
    ipc_server: IpcServer,
    #[cfg(feature = "browser-webrtc-preview")]
    browser_webrtc_preview: Arc<Mutex<BrowserWebrtcPreviewHost>>,
    resource_monitor: Arc<Mutex<ResourceMonitor>>,
}

#[derive(Debug, Deserialize)]
struct IpcEnvelope {
    request: IpcRequest,
}

#[derive(Debug, Serialize)]
struct IpcResponseEnvelope {
    response: IpcResponse,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    bridge_enabled: bool,
    bind: String,
}

#[derive(Debug, Serialize)]
struct BridgeErrorPayload {
    code: String,
    message: String,
}

#[cfg(feature = "browser-webrtc-preview")]
#[derive(Debug, Serialize)]
struct BrowserWebrtcPreviewStopResponse {
    stopped: bool,
}

#[derive(Debug, Default, Deserialize)]
struct WebSocketAuthQuery {
    token: Option<String>,
}

pub async fn spawn_from_env(ipc_server: IpcServer) -> Result<Option<JoinHandle<Result<()>>>> {
    let Some(config) = WebBridgeConfig::from_env()? else {
        info!("mrd-service web bridge disabled");
        return Ok(None);
    };

    let listener = TcpListener::bind(config.bind())
        .await
        .with_context(|| format!("bind web bridge {}", config.bind()))?;
    let bind = listener.local_addr().unwrap_or_else(|_| config.bind());
    let app = build_router(ipc_server, config);

    info!("mrd-service web bridge listening on {}", bind);
    Ok(Some(tokio::spawn(async move {
        axum::serve(listener, app).await?;
        Ok(())
    })))
}

pub async fn wait_for_task(task: Option<JoinHandle<Result<()>>>) -> Result<()> {
    match task {
        Some(task) => task.await.context("web bridge task join failed")?,
        None => pending().await,
    }
}

pub fn build_router(ipc_server: IpcServer, config: WebBridgeConfig) -> Router {
    let cors_config = config.clone();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            is_allowed_browser_origin(&cors_config, origin)
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static(TOKEN_HEADER),
        ]);

    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/resource", post(resource_snapshot))
        .route("/ipc", post(ipc_handler))
        .route("/ws", get(ws_handler))
        .route(
            "/browser/webcodecs-preview/ws",
            get(browser_webcodecs_preview_ws_handler),
        )
        .route(
            "/browser/webrtc-preview/start",
            post(browser_webrtc_preview_start),
        )
        .route(
            "/browser/webrtc-preview/stop",
            post(browser_webrtc_preview_stop),
        )
        .with_state(WebBridgeState {
            config,
            ipc_server,
            #[cfg(feature = "browser-webrtc-preview")]
            browser_webrtc_preview: Arc::new(Mutex::new(BrowserWebrtcPreviewHost::default())),
            resource_monitor: Arc::new(Mutex::new(ResourceMonitor::new())),
        })
        .layer(cors)
}

async fn index(State(state): State<WebBridgeState>) -> Html<String> {
    Html(index_document(&state.config))
}

async fn health(State(state): State<WebBridgeState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "mrd-service",
        bridge_enabled: state.config.enabled,
        bind: state.config.bind().to_string(),
    })
}

async fn resource_snapshot(
    State(state): State<WebBridgeState>,
    headers: HeaderMap,
    Json(request): Json<ResourceSnapshotRequest>,
) -> Response {
    if let Err(response) = authorize_headers(&state.config, &headers) {
        return bridge_error_from_ipc_response(response).into_response();
    }

    let snapshot = state.resource_monitor.lock().await.snapshot(request.target);
    Json(snapshot).into_response()
}

async fn ipc_handler(
    State(state): State<WebBridgeState>,
    headers: HeaderMap,
    Json(envelope): Json<IpcEnvelope>,
) -> Json<IpcResponseEnvelope> {
    let response = if let Err(response) = authorize_headers(&state.config, &headers) {
        response
    } else {
        dispatch_ipc(state.ipc_server, envelope.request).await
    };

    Json(IpcResponseEnvelope { response })
}

async fn ws_handler(
    State(state): State<WebBridgeState>,
    Query(query): Query<WebSocketAuthQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let auth_error = authorize_ws_token(&state.config, &headers, query.token.as_deref()).err();
    ws.on_upgrade(move |socket| handle_ws(socket, state, auth_error))
}

async fn browser_webcodecs_preview_ws_handler(
    State(state): State<WebBridgeState>,
    Query(query): Query<WebSocketAuthQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let auth_error = authorize_ws_token(&state.config, &headers, query.token.as_deref()).err();
    ws.on_upgrade(move |socket| handle_browser_webcodecs_ws(socket, auth_error))
}

#[cfg(feature = "browser-webrtc-preview")]
async fn browser_webrtc_preview_start(
    State(state): State<WebBridgeState>,
    headers: HeaderMap,
    Json(request): Json<BrowserWebrtcPreviewStartRequest>,
) -> Response {
    if let Err(response) = authorize_headers(&state.config, &headers) {
        return bridge_error_from_ipc_response(response).into_response();
    }

    match state
        .browser_webrtc_preview
        .lock()
        .await
        .start(request)
        .await
    {
        Ok(answer) => Json(answer).into_response(),
        Err(message) => (
            StatusCode::BAD_REQUEST,
            Json(BridgeErrorPayload {
                code: "E_BROWSER_WEBRTC_PREVIEW".to_string(),
                message,
            }),
        )
            .into_response(),
    }
}

#[cfg(not(feature = "browser-webrtc-preview"))]
async fn browser_webrtc_preview_start(
    State(state): State<WebBridgeState>,
    headers: HeaderMap,
    Json(_request): Json<serde_json::Value>,
) -> Response {
    if let Err(response) = authorize_headers(&state.config, &headers) {
        return bridge_error_from_ipc_response(response).into_response();
    }

    (
        StatusCode::NOT_IMPLEMENTED,
        Json(BridgeErrorPayload {
            code: "E_BROWSER_WEBRTC_PREVIEW_DISABLED".to_string(),
            message: "browser WebRTC preview is not compiled into this mrd-service build; rebuild with --features browser-webrtc-preview".to_string(),
        }),
    )
        .into_response()
}

#[cfg(feature = "browser-webrtc-preview")]
async fn browser_webrtc_preview_stop(
    State(state): State<WebBridgeState>,
    headers: HeaderMap,
    Json(request): Json<BrowserWebrtcPreviewStopRequest>,
) -> Response {
    if let Err(response) = authorize_headers(&state.config, &headers) {
        return bridge_error_from_ipc_response(response).into_response();
    }

    match state
        .browser_webrtc_preview
        .lock()
        .await
        .stop(&request.session_id)
        .await
    {
        Ok(()) => Json(BrowserWebrtcPreviewStopResponse { stopped: true }).into_response(),
        Err(message) => (
            StatusCode::BAD_REQUEST,
            Json(BridgeErrorPayload {
                code: "E_BROWSER_WEBRTC_PREVIEW_STOP".to_string(),
                message,
            }),
        )
            .into_response(),
    }
}

#[cfg(not(feature = "browser-webrtc-preview"))]
async fn browser_webrtc_preview_stop(
    State(state): State<WebBridgeState>,
    headers: HeaderMap,
    Json(_request): Json<serde_json::Value>,
) -> Response {
    if let Err(response) = authorize_headers(&state.config, &headers) {
        return bridge_error_from_ipc_response(response).into_response();
    }

    (
        StatusCode::NOT_IMPLEMENTED,
        Json(BridgeErrorPayload {
            code: "E_BROWSER_WEBRTC_PREVIEW_DISABLED".to_string(),
            message: "browser WebRTC preview is not compiled into this mrd-service build; rebuild with --features browser-webrtc-preview".to_string(),
        }),
    )
        .into_response()
}

fn bridge_error_from_ipc_response(response: IpcResponse) -> (StatusCode, Json<BridgeErrorPayload>) {
    match response {
        IpcResponse::Error { code, message } => (
            StatusCode::UNAUTHORIZED,
            Json(BridgeErrorPayload { code, message }),
        ),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(BridgeErrorPayload {
                code: "E_WEB_BRIDGE_AUTH".to_string(),
                message: format!("unexpected bridge auth response: {other:?}"),
            }),
        ),
    }
}

async fn handle_ws(mut socket: WebSocket, state: WebBridgeState, auth_error: Option<IpcResponse>) {
    if let Some(response) = auth_error {
        let _ = send_ws_response(&mut socket, response).await;
        return;
    }

    while let Some(Ok(message)) = socket.recv().await {
        let Message::Text(text) = message else {
            continue;
        };
        let response = match serde_json::from_str::<IpcEnvelope>(&text) {
            Ok(envelope) => dispatch_ipc(state.ipc_server.clone(), envelope.request).await,
            Err(error) => IpcResponse::Error {
                code: "E_WEB_BRIDGE_BAD_REQUEST".to_string(),
                message: format!("Invalid web bridge request: {error}"),
            },
        };
        if send_ws_response(&mut socket, response).await.is_err() {
            break;
        }
    }
}

async fn handle_browser_webcodecs_ws(mut socket: WebSocket, auth_error: Option<IpcResponse>) {
    if let Some(response) = auth_error {
        let _ = send_webcodecs_error_from_ipc_response(&mut socket, response).await;
        return;
    }

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<BrowserWebcodecsPreviewOutbound>(4);
    let mut running: Option<Arc<AtomicBool>> = None;
    let mut request_keyframe: Option<Arc<AtomicBool>> = None;
    let mut capture_task: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                let Some(Ok(message)) = inbound else {
                    break;
                };
                let Message::Text(text) = message else {
                    continue;
                };
                match serde_json::from_str::<BrowserWebcodecsPreviewControlMessage>(&text) {
                    Ok(BrowserWebcodecsPreviewControlMessage::Start(request)) => {
                        if let Some(flag) = running.take() {
                            flag.store(false, Ordering::Relaxed);
                        }
                        if let Some(task) = capture_task.take() {
                            task.abort();
                        }
                        let flag = Arc::new(AtomicBool::new(true));
                        let keyframe_flag = Arc::new(AtomicBool::new(false));
                        capture_task = Some(spawn_browser_webcodecs_capture_sender(
                            request,
                            outbound_tx.clone(),
                            flag.clone(),
                            keyframe_flag.clone(),
                        ));
                        running = Some(flag);
                        request_keyframe = Some(keyframe_flag);
                    }
                    Ok(BrowserWebcodecsPreviewControlMessage::RequestKeyframe) => {
                        if let Some(flag) = &request_keyframe {
                            flag.store(true, Ordering::Relaxed);
                        }
                    }
                    Ok(BrowserWebcodecsPreviewControlMessage::Stop) => {
                        break;
                    }
                    Err(error) => {
                        let payload = BridgeErrorPayload {
                            code: "E_BROWSER_WEBCODECS_BAD_REQUEST".to_string(),
                            message: format!("Invalid WebCodecs preview request: {error}"),
                        };
                        let _ = socket
                            .send(Message::Text(
                                serde_json::to_string(&payload)
                                    .unwrap_or_else(|_| "{\"code\":\"E_BROWSER_WEBCODECS_BAD_REQUEST\"}".to_string())
                                    .into(),
                            ))
                            .await;
                    }
                }
            }
            outbound = outbound_rx.recv() => {
                let Some(outbound) = outbound else {
                    break;
                };
                let send_result = match outbound {
                    BrowserWebcodecsPreviewOutbound::Text(text) => {
                        socket.send(Message::Text(text.into())).await
                    }
                    BrowserWebcodecsPreviewOutbound::Binary(bytes) => {
                        socket.send(Message::Binary(bytes)).await
                    }
                };
                if send_result.is_err() {
                    break;
                }
            }
        }
    }

    if let Some(flag) = running {
        flag.store(false, Ordering::Relaxed);
    }
    if let Some(flag) = request_keyframe {
        flag.store(false, Ordering::Relaxed);
    }
    if let Some(task) = capture_task {
        task.abort();
    }
}

async fn send_webcodecs_error_from_ipc_response(
    socket: &mut WebSocket,
    response: IpcResponse,
) -> Result<(), axum::Error> {
    let (code, message) = match response {
        IpcResponse::Error { code, message } => (code, message),
        other => (
            "E_WEB_BRIDGE_AUTH".to_string(),
            format!("unexpected bridge auth response: {other:?}"),
        ),
    };
    socket
        .send(Message::Text(
            serde_json::to_string(&BridgeErrorPayload { code, message })
                .unwrap_or_else(|_| "{\"code\":\"E_WEB_BRIDGE_AUTH\"}".to_string())
                .into(),
        ))
        .await
}

async fn send_ws_response(
    socket: &mut WebSocket,
    response: IpcResponse,
) -> Result<(), axum::Error> {
    let envelope = IpcResponseEnvelope { response };
    socket
        .send(Message::Text(
            serde_json::to_string(&envelope)
                .unwrap_or_else(|error| {
                    format!(
                        r#"{{"response":{{"type":"Error","code":"E_WEB_BRIDGE_SERIALIZE","message":"{}"}}}}"#,
                        error
                    )
                })
                .into(),
        ))
        .await
}

async fn dispatch_ipc(ipc_server: IpcServer, request: IpcRequest) -> IpcResponse {
    if !is_ipc_request_allowed(&request) {
        warn!("Blocked web bridge IPC request: {:?}", request);
        return forbidden_response(&request);
    }

    ipc_server.handle_request(request).await
}

#[allow(dead_code)]
pub async fn dispatch_ipc_for_test(ipc_server: IpcServer, request: IpcRequest) -> IpcResponse {
    dispatch_ipc(ipc_server, request).await
}

pub fn is_ipc_request_allowed(request: &IpcRequest) -> bool {
    matches!(
        request,
        IpcRequest::LanDiscoverySnapshot
            | IpcRequest::RefreshLanDiscovery
            | IpcRequest::GetDevicePreferences
            | IpcRequest::UpdateDevicePreference { .. }
            | IpcRequest::ListDirectory { .. }
            | IpcRequest::StartFileTransfer { .. }
            | IpcRequest::ListFileTransfers
            | IpcRequest::ListFileTransferProviders
            | IpcRequest::CancelFileTransfer { .. }
            | IpcRequest::WakeOnLan { .. }
            | IpcRequest::RequestRemoteDevicePowerAction { .. }
            | IpcRequest::ListSessions
            | IpcRequest::StartLanRemoteSession { .. }
            | IpcRequest::ListLocalCaptureSources { .. }
            | IpcRequest::ListRemoteCaptureSources { .. }
            | IpcRequest::SelectRemoteCaptureSource { .. }
            | IpcRequest::ListRemoteDisplayModes { .. }
            | IpcRequest::SetRemoteDisplayMode { .. }
            | IpcRequest::RestoreRemoteDisplayMode { .. }
            | IpcRequest::CrossE2EInjectFault { .. }
            | IpcRequest::StartReceiver { .. }
            | IpcRequest::SessionRuntimeSnapshot { .. }
            | IpcRequest::RuntimeSnapshot
            | IpcRequest::CapabilitySnapshot
            | IpcRequest::EvaluateScenarioProfile { .. }
            | IpcRequest::GetPeerCapabilitySnapshot { .. }
            | IpcRequest::GetTelemetryBundle { .. }
            | IpcRequest::ProbeSnapshot { .. }
            | IpcRequest::MediaPipelineSnapshot { .. }
            | IpcRequest::ServiceHealth
            | IpcRequest::GetShellStatus
    )
}

fn index_document(config: &WebBridgeConfig) -> String {
    let bind = config.bind();
    let token_status = if config.requires_token() {
        "required"
    } else {
        "not required for localhost"
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>mrd-service Web Bridge</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #151515; color: #e5e7eb; }}
    main {{ width: min(760px, calc(100vw - 40px)); border: 1px solid rgba(16,185,129,.22); background: #202020; border-radius: 10px; padding: 28px; box-shadow: 0 24px 70px rgba(0,0,0,.35); }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ color: #a7f3d0; line-height: 1.6; }}
    code, a {{ color: #67e8f9; }}
    .grid {{ display: grid; gap: 10px; margin-top: 20px; }}
    .row {{ display: flex; justify-content: space-between; gap: 16px; padding: 10px 12px; border: 1px solid rgba(255,255,255,.08); border-radius: 8px; background: #2a2a2a; }}
    .key {{ color: #9ca3af; }}
  </style>
</head>
<body>
  <main>
    <h1>mrd-service Web Bridge</h1>
    <p>This endpoint is the local browser bridge for Rdesk Web. Open the Web UI at <a href="http://127.0.0.1:9531/">http://127.0.0.1:9531/</a>; the page will connect here for real local capabilities, LAN discovery, sessions, and telemetry.</p>
    <div class="grid">
      <div class="row"><span class="key">Status</span><strong>ok</strong></div>
      <div class="row"><span class="key">Bind</span><code>{bind}</code></div>
      <div class="row"><span class="key">Token</span><code>{token_status}</code></div>
      <div class="row"><span class="key">Health</span><code>GET /health</code></div>
      <div class="row"><span class="key">IPC bridge</span><code>POST /ipc</code></div>
      <div class="row"><span class="key">WebSocket</span><code>GET /ws</code></div>
      <div class="row"><span class="key">WebCodecs preview</span><code>GET /browser/webcodecs-preview/ws</code></div>
    </div>
  </main>
</body>
</html>"#
    )
}

#[allow(clippy::result_large_err)]
fn authorize_headers(config: &WebBridgeConfig, headers: &HeaderMap) -> Result<(), IpcResponse> {
    authorize_token(
        config,
        headers
            .get(TOKEN_HEADER)
            .and_then(|value| value.to_str().ok()),
    )
}

#[allow(clippy::result_large_err)]
fn authorize_ws_token(
    config: &WebBridgeConfig,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<(), IpcResponse> {
    let header_token = headers
        .get(TOKEN_HEADER)
        .and_then(|value| value.to_str().ok());
    authorize_token(config, header_token.or(query_token))
}

#[allow(clippy::result_large_err)]
fn authorize_token(config: &WebBridgeConfig, actual: Option<&str>) -> Result<(), IpcResponse> {
    let Some(expected) = config.token.as_deref() else {
        return Ok(());
    };

    let Some(actual) = actual else {
        return Err(IpcResponse::Error {
            code: "E_WEB_BRIDGE_UNAUTHORIZED".to_string(),
            message: "Missing X-MRD-Bridge-Token header or WebSocket token query.".to_string(),
        });
    };

    if actual == expected {
        Ok(())
    } else {
        Err(IpcResponse::Error {
            code: "E_WEB_BRIDGE_UNAUTHORIZED".to_string(),
            message: "Invalid X-MRD-Bridge-Token header.".to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
fn authorize_ws_token_for_test(
    config: &WebBridgeConfig,
    header_token: Option<&str>,
    query_token: Option<&str>,
) -> Result<(), IpcResponse> {
    authorize_token(config, header_token.or(query_token))
}

fn forbidden_response(request: &IpcRequest) -> IpcResponse {
    let debug = format!("{request:?}");
    let request_name = debug.split([' ', '{', '(']).next().unwrap_or("request");
    IpcResponse::Error {
        code: "E_WEB_BRIDGE_FORBIDDEN".to_string(),
        message: format!("{request_name} is not available through the web bridge."),
    }
}

fn is_loopback_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn is_localhost_origin(origin: &HeaderValue) -> bool {
    let Some(host) = origin_host(origin) else {
        return false;
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn is_allowed_browser_origin(config: &WebBridgeConfig, origin: &HeaderValue) -> bool {
    is_localhost_origin(origin) || (config.requires_token() && is_private_lan_origin(origin))
}

fn is_private_lan_origin(origin: &HeaderValue) -> bool {
    origin_host(origin)
        .and_then(|host| host.parse::<Ipv4Addr>().ok())
        .is_some_and(|ip| ip.is_private())
}

fn origin_host(origin: &HeaderValue) -> Option<&str> {
    let Ok(origin) = origin.to_str() else {
        return None;
    };
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    let host = rest.split('/').next().unwrap_or(rest);
    Some(host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_origin_predicate_accepts_dev_hosts() {
        assert!(is_localhost_origin(&HeaderValue::from_static(
            "http://127.0.0.1:9531"
        )));
        assert!(is_localhost_origin(&HeaderValue::from_static(
            "http://localhost:9531"
        )));
        assert!(!is_localhost_origin(&HeaderValue::from_static(
            "http://192.168.1.20:9531"
        )));
    }

    #[test]
    fn private_lan_origins_require_tokenized_bridge() {
        let loopback_config =
            WebBridgeConfig::new("127.0.0.1:9532".parse::<SocketAddr>().unwrap(), None).unwrap();
        let lan_config = WebBridgeConfig::new(
            "0.0.0.0:9533".parse::<SocketAddr>().unwrap(),
            Some("secret".to_string()),
        )
        .expect("LAN bridge config with token");

        let lan_origin = HeaderValue::from_static("http://192.168.1.52:9531");
        let public_origin = HeaderValue::from_static("http://203.0.113.10:9531");

        assert!(!is_allowed_browser_origin(&loopback_config, &lan_origin));
        assert!(is_allowed_browser_origin(&lan_config, &lan_origin));
        assert!(!is_allowed_browser_origin(&lan_config, &public_origin));
    }

    #[test]
    fn websocket_query_token_authorizes_without_header() {
        let config = WebBridgeConfig::new(
            "0.0.0.0:9532".parse::<SocketAddr>().unwrap(),
            Some("secret".to_string()),
        )
        .expect("LAN bridge config with token");

        assert!(authorize_ws_token_for_test(&config, None, Some("secret")).is_ok());
        assert!(authorize_ws_token_for_test(&config, None, Some("wrong")).is_err());
    }

    #[test]
    fn index_document_explains_bridge_and_web_ui_target() {
        let config =
            WebBridgeConfig::new("127.0.0.1:9532".parse::<SocketAddr>().unwrap(), None).unwrap();

        let html = index_document(&config);

        assert!(html.contains("mrd-service Web Bridge"));
        assert!(html.contains("http://127.0.0.1:9531/"));
        assert!(html.contains("/health"));
        assert!(html.contains("/ipc"));
        assert!(html.contains("/ws"));
    }

    #[cfg(not(feature = "browser-webrtc-preview"))]
    #[tokio::test]
    async fn browser_webrtc_preview_reports_disabled_without_feature() {
        let config =
            WebBridgeConfig::new("127.0.0.1:9532".parse::<SocketAddr>().unwrap(), None).unwrap();
        let state = WebBridgeState {
            config,
            ipc_server: IpcServer::new(Arc::new(crate::app_state::AppState::new())),
            resource_monitor: Arc::new(Mutex::new(ResourceMonitor::new())),
        };

        let response = browser_webrtc_preview_start(
            State(state),
            HeaderMap::new(),
            Json(serde_json::json!({
                "session_id": "preview-session",
                "offer_sdp": "v=0"
            })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn web_bridge_allows_local_capture_source_listing() {
        assert!(is_ipc_request_allowed(
            &IpcRequest::ListLocalCaptureSources {
                include_previews: false,
                limit: Some(24),
            }
        ));
    }

    #[test]
    fn web_bridge_allows_directory_listing() {
        assert!(is_ipc_request_allowed(&IpcRequest::ListDirectory {
            path: Some(".".to_string()),
        }));
    }

    #[test]
    fn web_bridge_allows_local_file_transfer_requests() {
        assert!(is_ipc_request_allowed(&IpcRequest::StartFileTransfer {
            request: mrd_ipc::FileTransferStartRequest {
                source_device_id: None,
                target_device_id: None,
                entries: vec![mrd_ipc::FileTransferEntry {
                    source_path: "source.txt".to_string(),
                    file_name: Some("source.txt".to_string()),
                    kind: mrd_ipc::FileEntryKind::File,
                }],
                target_path: ".".to_string(),
                conflict_policy: mrd_ipc::FileTransferConflictPolicy::Rename,
                transport_hint: Some("local".to_string()),
                provider_hint: None,
            },
        }));
        assert!(is_ipc_request_allowed(&IpcRequest::ListFileTransfers));
        assert!(is_ipc_request_allowed(
            &IpcRequest::ListFileTransferProviders
        ));
        assert!(is_ipc_request_allowed(&IpcRequest::CancelFileTransfer {
            transfer_id: "file-transfer-1".to_string(),
        }));
    }

    #[test]
    fn web_bridge_blocks_control_input_requests() {
        assert!(!is_ipc_request_allowed(&IpcRequest::SendControlInput {
            session_id: mrd_proto::SessionId("control-session".to_string()),
            event: mrd_ipc::ControlInputEvent::MouseMove { x: 10, y: 20 },
        }));
    }

    #[test]
    fn web_bridge_allows_cross_e2e_fault_requests() {
        assert!(is_ipc_request_allowed(&IpcRequest::CrossE2EInjectFault {
            session_id: mrd_proto::SessionId("fault-session".to_string()),
            fault_type: "network.pause_peer".to_string(),
            duration_ms: Some(500),
        }));
    }
}
