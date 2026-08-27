use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    routing::any,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use mrd_proto::{DeviceId, SessionId};
use mrd_relay_control::{
    RelayDirectoryCandidate, RelayDirectoryEndpoint, RelayDirectoryPayload,
    RelayDirectoryTransport, RelayReservation, SignedRelayDirectory,
    RELAY_DIRECTORY_FORMAT_VERSION,
};
use mrd_service::{
    relay::relay_peer_digest,
    wan_session::{
        backend::{
            HttpWanSessionBackend, WanRelayAccessRequest, WanSessionApproval, WanSessionBackend,
            WanSessionBackendError, WanSessionBinding, WanSessionStatus,
        },
        config::WanSessionBackendConfig,
    },
    AppState,
};
use mrd_signal_proto::{
    WanAccessModeV3, WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing_subscriber::fmt::MakeWriter;

static PRIVATE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x53; 32])
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after epoch")
        .as_millis()
        .try_into()
        .expect("wall clock fits u64")
}

fn private_material(domain: &str) -> String {
    format!(
        "opaque-{domain}-{}-{}",
        std::process::id(),
        PRIVATE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn request() -> WanSessionRequestV3 {
    WanSessionRequestV3 {
        session_id: SessionId("wan-session-1".into()),
        idempotency_key: [7; 16],
        controller_device_id: DeviceId("controller-1".into()),
        target_device_id: DeviceId("target-1".into()),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![
            WanPermissionScopeV3::InputKeyboard,
            WanPermissionScopeV3::ScreenView,
        ],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    }
}

fn binding(request: &WanSessionRequestV3) -> WanSessionBinding {
    WanSessionBinding::new(
        request.session_id.clone(),
        request.controller_device_id.clone(),
        request.target_device_id.clone(),
    )
    .expect("valid WAN session binding")
}

#[derive(Clone)]
struct CapturedRequest {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
enum FakeMode {
    Normal,
    Delay(Duration),
    FailFirst(StatusCode),
    AlwaysStatus(StatusCode, String),
    Oversized(usize),
    MismatchedSession,
}

#[derive(Clone)]
struct FakeState {
    canonical_request: WanSessionRequestV3,
    commitment: String,
    turn_username: String,
    turn_credential: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    mode: FakeMode,
}

struct FakeBackend {
    base_url: String,
    state: FakeState,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Default)]
struct TraceBuffer(Arc<Mutex<Vec<u8>>>);

struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("trace lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for TraceBuffer {
    type Writer = TraceWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        TraceWriter(Arc::clone(&self.0))
    }
}

impl TraceBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("trace lock")).into_owned()
    }
}

impl Drop for FakeBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeBackend {
    async fn spawn(request: WanSessionRequestV3) -> Self {
        Self::spawn_with_mode(request, FakeMode::Normal).await
    }

    async fn spawn_with_mode(request: WanSessionRequestV3, mode: FakeMode) -> Self {
        let state = FakeState {
            commitment: request.commitment().expect("request commitment"),
            canonical_request: request,
            turn_username: private_material("turn-user"),
            turn_credential: private_material("turn-credential"),
            captured: Arc::new(Mutex::new(Vec::new())),
            mode,
        };
        let app = Router::new()
            .fallback(any(fake_backend))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake WAN backend");
        let address = listener.local_addr().expect("fake backend address");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{address}/api/v1/"),
            state,
            task,
        }
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.state.captured.lock().expect("capture lock").clone()
    }
}

async fn fake_backend(State(state): State<FakeState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 64 * 1024)
        .await
        .map(|value| value.to_vec())
        .unwrap_or_default();
    let request_number = {
        let mut captured = state.captured.lock().expect("capture lock");
        captured.push(CapturedRequest {
            method: parts.method.clone(),
            path: parts.uri.path().to_owned(),
            headers: parts.headers,
            body,
        });
        captured.len()
    };

    match &state.mode {
        FakeMode::Delay(duration) => tokio::time::sleep(*duration).await,
        FakeMode::FailFirst(status) if request_number == 1 => {
            return Response::builder()
                .status(*status)
                .body(Body::empty())
                .expect("transient fake response");
        }
        FakeMode::AlwaysStatus(status, body) => {
            return Response::builder()
                .status(*status)
                .body(Body::from(body.clone()))
                .expect("status fake response");
        }
        FakeMode::Oversized(size) => {
            return Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(vec![b'x'; *size]))
                .expect("oversized fake response");
        }
        FakeMode::Normal | FakeMode::FailFirst(_) | FakeMode::MismatchedSession => {}
    }

    let status = if parts.uri.path().ends_with("/approve") {
        "approved"
    } else if parts.uri.path().ends_with("/reject") {
        "rejected"
    } else if parts.uri.path().ends_with("/close") {
        "closed"
    } else if parts.uri.path().ends_with("/revoke") {
        "revoked"
    } else {
        "requested"
    };
    let mut response = if parts.uri.path() == "/api/v1/relays/access" {
        relay_access_response(&state)
    } else {
        session_response(&state, status)
    };
    if matches!(state.mode, FakeMode::MismatchedSession) {
        response["session_id"] = json!("another-session");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&response).expect("encode fake response"),
        ))
        .expect("fake response")
}

fn session_response(state: &FakeState, status: &str) -> Value {
    let approved = status == "approved";
    json!({
        "session_id": state.canonical_request.session_id,
        "request": state.canonical_request,
        "request_commitment": state.commitment,
        "status": status,
        "approved_scopes": if approved { json!(["screen.view"]) } else { Value::Null },
        "approved_profile": null,
        "policy_revision": if approved { json!(29) } else { Value::Null },
        "policy_expires_at": if approved { json!("2026-08-26T12:05:00Z") } else { Value::Null },
        "grant_expires_at": if approved { json!("2026-08-26T12:05:00Z") } else { Value::Null },
        "active_relay_generation": if approved { json!(0) } else { Value::Null }
    })
}

fn relay_access_response(state: &FakeState) -> Value {
    let issued_at_ms = now_ms().saturating_sub(1_000);
    let expires_at_ms = issued_at_ms.saturating_add(120_000);
    let payload = RelayDirectoryPayload {
        format_version: RELAY_DIRECTORY_FORMAT_VERSION,
        policy_revision: 29,
        directory_id: "directory-wan-session-1".into(),
        issued_at_ms,
        expires_at_ms,
        session_id: state.canonical_request.session_id.0.clone(),
        intended_peer_digest: relay_peer_digest("target-1").expect("peer digest"),
        candidates: vec![RelayDirectoryCandidate {
            node_id: "relay-a".into(),
            region: "region-a".into(),
            failure_domain: "host-a".into(),
            endpoints: vec![RelayDirectoryEndpoint {
                transport: RelayDirectoryTransport::Udp,
                host: "relay-a.example.test".into(),
                port: 3478,
            }],
            capabilities: 1,
            load_class: 1,
            selection_reason: "preferred_region".into(),
            reservation: RelayReservation {
                reservation_id: "reservation-wan-session-1-a".into(),
                expires_at_ms,
            },
        }],
    };
    let signature = signing_key().sign(&payload.canonical_signing_bytes().expect("canonical"));
    let directory = SignedRelayDirectory {
        payload,
        signing_key_id: "directory-key-1".into(),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    };
    json!({
        "directory": directory,
        "credentials": [{
            "node_id": "relay-a",
            "urls": ["turn:relay-a.example.test:3478?transport=udp"],
            "username": state.turn_username,
            "credential": state.turn_credential,
            "expires_at_unix_seconds": (expires_at_ms / 1000) + 60
        }]
    })
}

fn client_config(base_url: &str, token: &str) -> WanSessionBackendConfig {
    client_config_with(base_url, token, Duration::from_secs(2), 64 * 1024, 1)
}

fn client_config_with(
    base_url: &str,
    token: &str,
    deadline: Duration,
    max_body_bytes: usize,
    max_attempts: usize,
) -> WanSessionBackendConfig {
    let key = signing_key();
    WanSessionBackendConfig::new(
        base_url,
        token,
        BTreeMap::from([(
            "directory-key-1".to_owned(),
            key.verifying_key().to_bytes().to_vec(),
        )]),
        deadline,
        max_body_bytes,
        max_attempts,
    )
    .expect("valid loopback test configuration")
}

fn assert_no_sensitive_text(text: &str, sensitive: &[&str]) {
    for value in sensitive {
        assert!(
            !text.contains(value),
            "observable WAN backend projection leaked sensitive material"
        );
    }
}

#[tokio::test]
async fn typed_operations_bind_ids_and_send_only_the_device_token_header() {
    let canonical_request = request();
    let expected_binding = binding(&canonical_request);
    let server = FakeBackend::spawn(canonical_request.clone()).await;
    let device_token = private_material("device-auth");
    let backend = HttpWanSessionBackend::new(client_config(&server.base_url, &device_token))
        .expect("construct WAN backend client");

    let created = backend
        .create(&canonical_request)
        .await
        .expect("create WAN session");
    let inspected = backend
        .inspect(&expected_binding)
        .await
        .expect("inspect WAN session");
    let approval = WanSessionApproval::new(vec![WanPermissionScopeV3::ScreenView], None)
        .expect("normalized approval");
    let approved = backend
        .approve(&expected_binding, &approval)
        .await
        .expect("approve WAN session");
    let rejected = backend
        .reject(&expected_binding)
        .await
        .expect("reject WAN session");
    let closed = backend
        .close(&expected_binding)
        .await
        .expect("close WAN session");
    let revoked = backend
        .revoke(&expected_binding)
        .await
        .expect("revoke WAN session");
    let access_request = WanRelayAccessRequest::generation_zero(expected_binding.clone(), 29)
        .expect("generation-zero request");
    let access = backend
        .access(&access_request)
        .await
        .expect("fetch generation zero");

    assert!(created.binding() == &expected_binding);
    assert!(inspected.binding() == &expected_binding);
    assert!(approved.binding() == &expected_binding);
    assert!(rejected.binding() == &expected_binding);
    assert!(closed.binding() == &expected_binding);
    assert!(revoked.binding() == &expected_binding);
    assert!(created.status() == WanSessionStatus::Requested);
    assert!(approved.status() == WanSessionStatus::Approved);
    assert!(rejected.status() == WanSessionStatus::Rejected);
    assert!(closed.status() == WanSessionStatus::Closed);
    assert!(revoked.status() == WanSessionStatus::Revoked);
    assert!(approved.active_relay_generation() == Some(0));
    assert!(access.binding() == &expected_binding);
    assert!(access.generation() == 0);
    assert!(access.directory_id() == "directory-wan-session-1");
    assert!(access.credential_for("relay-a").is_some());

    let captured = server.requests();
    assert!(captured.len() == 7);
    let expected = [
        (Method::POST, "/api/v1/device-sessions"),
        (Method::GET, "/api/v1/device-sessions/wan-session-1"),
        (
            Method::POST,
            "/api/v1/device-sessions/wan-session-1/approve",
        ),
        (Method::POST, "/api/v1/device-sessions/wan-session-1/reject"),
        (Method::POST, "/api/v1/device-sessions/wan-session-1/close"),
        (Method::POST, "/api/v1/device-sessions/wan-session-1/revoke"),
        (Method::POST, "/api/v1/relays/access"),
    ];
    for (captured, (method, path)) in captured.iter().zip(expected) {
        assert!(captured.method == method);
        assert!(captured.path == path);
        let device_header = captured.headers.get("x-rdesk-device-authorization");
        let expected_header = format!("Bearer {device_token}");
        assert!(device_header.is_some_and(|value| value.as_bytes() == expected_header.as_bytes()));
        assert!(captured.headers.get("authorization").is_none());
        assert!(captured.headers.get("proxy-authorization").is_none());
        assert!(captured.headers.get("cookie").is_none());
        assert!(!captured
            .body
            .windows(device_token.len())
            .any(|part| part == device_token.as_bytes()));
    }

    let create_body: Value = serde_json::from_slice(&captured[0].body).expect("create JSON");
    assert!(create_body.get("controller_device_id").is_none());
    assert!(create_body.get("target_device_id") == Some(&json!("target-1")));
    assert!(captured[1].body.is_empty());
    let access_body: Value = serde_json::from_slice(&captured[6].body).expect("access JSON");
    assert!(
        access_body
            == json!({
                "session_id": "wan-session-1",
                "policy_revision": 29,
                "intended_peer_id": "target-1",
                "generation": 0
            })
    );
}

#[tokio::test]
async fn debug_errors_tracing_and_safe_snapshots_never_expose_owned_secrets() {
    let canonical_request = request();
    let expected_binding = binding(&canonical_request);
    let server = FakeBackend::spawn(canonical_request).await;
    let device_token = private_material("device-auth");
    let config = client_config(&server.base_url, &device_token);
    let backend = HttpWanSessionBackend::new(config.clone()).expect("WAN client");
    let access_request = WanRelayAccessRequest::generation_zero(expected_binding, 29)
        .expect("generation-zero request");
    let access = backend
        .access(&access_request)
        .await
        .expect("fetch generation zero");
    let credential = access
        .credential_for("relay-a")
        .expect("node-bound credential");

    let debug_projection = format!("{config:?} {backend:?} {access:?} {credential:?}");
    let safe_snapshot = serde_json::to_string(&access.safe_snapshot()).expect("safe snapshot");
    let trace_buffer = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(trace_buffer.clone())
        .without_time()
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(client = ?backend, relay_access = ?access, "WAN backend canary");
    });
    let trace_projection = trace_buffer.text();
    for projection in [&debug_projection, &safe_snapshot, &trace_projection] {
        assert_no_sensitive_text(
            projection,
            &[
                &device_token,
                &server.state.turn_username,
                &server.state.turn_credential,
                "relay-a.example.test",
            ],
        );
    }
}

#[tokio::test]
async fn idempotent_requests_retry_with_the_exact_same_body() {
    let canonical_request = request();
    let server = FakeBackend::spawn_with_mode(
        canonical_request.clone(),
        FakeMode::FailFirst(StatusCode::SERVICE_UNAVAILABLE),
    )
    .await;
    let token = private_material("device-auth");
    let backend = HttpWanSessionBackend::new(client_config_with(
        &server.base_url,
        &token,
        Duration::from_secs(2),
        64 * 1024,
        2,
    ))
    .expect("WAN client");

    backend
        .create(&canonical_request)
        .await
        .expect("retry idempotent create");

    let captured = server.requests();
    assert!(captured.len() == 2);
    assert!(captured[0].method == Method::POST);
    assert!(captured[0].path == "/api/v1/device-sessions");
    assert!(captured[0].body == captured[1].body);
}

#[tokio::test]
async fn response_bodies_and_total_operation_time_are_strictly_bounded() {
    let canonical_request = request();
    let expected_binding = binding(&canonical_request);
    let token = private_material("device-auth");

    let oversized =
        FakeBackend::spawn_with_mode(canonical_request.clone(), FakeMode::Oversized(2 * 1024))
            .await;
    let backend = HttpWanSessionBackend::new(client_config_with(
        &oversized.base_url,
        &token,
        Duration::from_secs(1),
        1024,
        1,
    ))
    .expect("bounded WAN client");
    assert!(
        backend.inspect(&expected_binding).await == Err(WanSessionBackendError::ResponseTooLarge)
    );

    let delayed = FakeBackend::spawn_with_mode(
        canonical_request,
        FakeMode::Delay(Duration::from_millis(500)),
    )
    .await;
    let backend = HttpWanSessionBackend::new(client_config_with(
        &delayed.base_url,
        &token,
        Duration::from_millis(100),
        64 * 1024,
        3,
    ))
    .expect("deadline WAN client");
    let started = tokio::time::Instant::now();
    assert!(
        backend.inspect(&expected_binding).await == Err(WanSessionBackendError::DeadlineExceeded)
    );
    assert!(started.elapsed() < Duration::from_millis(400));
    assert!(delayed.requests().len() == 1);
}

#[tokio::test]
async fn status_and_binding_failures_have_stable_body_free_errors() {
    let canonical_request = request();
    let expected_binding = binding(&canonical_request);
    let token = private_material("device-auth");
    let cases = [
        (
            StatusCode::BAD_REQUEST,
            WanSessionBackendError::InvalidRequest,
        ),
        (
            StatusCode::UNAUTHORIZED,
            WanSessionBackendError::Unauthorized,
        ),
        (StatusCode::FORBIDDEN, WanSessionBackendError::Unauthorized),
        (StatusCode::NOT_FOUND, WanSessionBackendError::NotFound),
        (StatusCode::CONFLICT, WanSessionBackendError::Conflict),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            WanSessionBackendError::Unavailable,
        ),
    ];
    for (status, expected) in cases {
        let raw_body = private_material("raw-backend-body");
        let server = FakeBackend::spawn_with_mode(
            canonical_request.clone(),
            FakeMode::AlwaysStatus(status, raw_body.clone()),
        )
        .await;
        let backend = HttpWanSessionBackend::new(client_config(&server.base_url, &token))
            .expect("WAN client");
        let error = backend
            .inspect(&expected_binding)
            .await
            .expect_err("stable error");
        assert!(error == expected);
        assert_no_sensitive_text(&format!("{error:?} {error}"), &[&raw_body, &token]);
    }

    let server = FakeBackend::spawn_with_mode(canonical_request, FakeMode::MismatchedSession).await;
    let backend =
        HttpWanSessionBackend::new(client_config(&server.base_url, &token)).expect("WAN client");
    assert!(
        backend.inspect(&expected_binding).await == Err(WanSessionBackendError::BindingMismatch)
    );
}

#[tokio::test]
async fn dropping_a_call_cancels_it_without_a_detached_retry() {
    let canonical_request = request();
    let expected_binding = binding(&canonical_request);
    let server =
        FakeBackend::spawn_with_mode(canonical_request, FakeMode::Delay(Duration::from_secs(1)))
            .await;
    let token = private_material("device-auth");
    let backend = HttpWanSessionBackend::new(client_config_with(
        &server.base_url,
        &token,
        Duration::from_secs(2),
        64 * 1024,
        3,
    ))
    .expect("WAN client");
    let task = tokio::spawn(async move { backend.inspect(&expected_binding).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.requests().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first request was sent");

    task.abort();
    assert!(task.await.expect_err("call was cancelled").is_cancelled());
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(server.requests().len() == 1);
}

#[tokio::test]
async fn app_state_binds_the_service_owned_backend_exactly_once() {
    let server = FakeBackend::spawn(request()).await;
    let token = private_material("device-auth");
    let backend: Arc<dyn WanSessionBackend> = Arc::new(
        HttpWanSessionBackend::new(client_config(&server.base_url, &token)).expect("WAN client"),
    );
    let state = AppState::new();
    assert!(state.wan_session_backend().is_none());
    state
        .bind_wan_session_backend(Arc::clone(&backend))
        .expect("first bind");
    assert!(state.wan_session_backend().is_some());
    assert!(state.bind_wan_session_backend(backend).is_err());
}

#[test]
fn configuration_rejects_remote_cleartext_and_endpoint_userinfo() {
    let token = private_material("device-auth");
    let trusted_keys = BTreeMap::from([(
        "directory-key-1".to_owned(),
        signing_key().verifying_key().to_bytes().to_vec(),
    )]);
    for endpoint in [
        "http://control.example.test/api/v1/",
        "https://user@control.example.test/api/v1/",
        "https://control.example.test/api/v1/?token=value",
    ] {
        assert!(WanSessionBackendConfig::new(
            endpoint,
            &token,
            trusted_keys.clone(),
            Duration::from_secs(2),
            64 * 1024,
            1,
        )
        .is_err());
    }
    assert!(WanSessionBackendConfig::new(
        "https://control.example.test/api/v1/",
        &token,
        trusted_keys,
        Duration::from_secs(2),
        64 * 1024,
        0,
    )
    .is_err());
    assert!(WanSessionBinding::new(
        SessionId("escape/../session".into()),
        DeviceId("controller-1".into()),
        DeviceId("target-1".into()),
    )
    .is_err());
}
