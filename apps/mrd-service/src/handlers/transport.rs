// Transport control handlers for mrd-service
//
// These handlers implement media control (sender/receiver) logic.

use crate::app_state::AppState;
use mrd_application::ports::SessionLifecycleState;
use mrd_ipc::{AttachedRenderSurface, IpcResponse, RemotePermissionScope, RemoteReasonCode};
use mrd_proto::SessionId;
use std::sync::Arc;

/// Handle start sender request (controller role - begins media capture)
pub async fn start_sender(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    tracing::info!("Starting sender for session: {}", session_id.0);

    if let Some(response) = secure_media_denial(app_state, &session_id).await {
        return response;
    }
    let mut sessions = app_state.sessions.lock().await;
    if let Some(snapshot) = sessions.get(&session_id).cloned() {
        if snapshot.lifecycle_state.is_terminal() {
            return IpcResponse::Error {
                code: "E_SESSION_TERMINAL".to_string(),
                message: format!(
                    "cannot start sender for {} session",
                    snapshot.lifecycle_state
                ),
            };
        }
        sessions.insert(
            session_id.clone(),
            mrd_application::ports::SessionSnapshot {
                sender_active: true,
                lifecycle_state: SessionLifecycleState::Streaming,
                last_error: None,
                ..snapshot
            },
        );
        IpcResponse::SenderStarted { session_id }
    } else {
        IpcResponse::Error {
            code: "E404".to_string(),
            message: format!("Session not found: {}", session_id.0),
        }
    }
}

/// Handle start receiver request (agent role - begins media decode/render)
pub async fn start_receiver(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    tracing::info!("Starting receiver for session: {}", session_id.0);

    if let Some(response) = secure_media_denial(app_state, &session_id).await {
        return response;
    }
    let mut sessions = app_state.sessions.lock().await;
    if let Some(snapshot) = sessions.get(&session_id).cloned() {
        if snapshot.lifecycle_state.is_terminal() {
            return IpcResponse::Error {
                code: "E_SESSION_TERMINAL".to_string(),
                message: format!(
                    "cannot start receiver for {} session",
                    snapshot.lifecycle_state
                ),
            };
        }
        sessions.insert(
            session_id.clone(),
            mrd_application::ports::SessionSnapshot {
                receiver_active: true,
                lifecycle_state: SessionLifecycleState::Streaming,
                last_error: None,
                ..snapshot
            },
        );
        IpcResponse::ReceiverStarted { session_id }
    } else {
        IpcResponse::Error {
            code: "E404".to_string(),
            message: format!("Session not found: {}", session_id.0),
        }
    }
}

async fn secure_media_denial(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) -> Option<IpcResponse> {
    let secure = app_state
        .session_authorizations
        .snapshot(session_id)
        .await?;
    if app_state
        .session_authorizations
        .allows_scope(
            session_id,
            RemotePermissionScope::ScreenView,
            current_time_ms(),
        )
        .await
    {
        return None;
    }
    Some(IpcResponse::RemoteAccessError {
        session_id: Some(session_id.clone()),
        peer_key_id: Some(secure.peer_key_id),
        failure: secure.failure.unwrap_or(mrd_ipc::RemoteFailure {
            code: RemoteReasonCode::ScopeDenied,
            message: "screen media requires a current screen.view grant".to_string(),
            suggested_action: None,
        }),
    })
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Handle probe snapshot request
pub async fn probe_snapshot(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    let snapshot = app_state.probes.lock().await.snapshot(&session_id);
    IpcResponse::ProbeSnapshot { snapshot }
}

/// Attach a native render surface to a receiver media pipeline.
pub async fn attach_render_surface(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    surface_id: String,
    backend: String,
    window_handle: Option<i64>,
    render_proxy_endpoint: Option<String>,
) -> IpcResponse {
    tracing::info!(
        session_id = %session_id.0,
        surface_id = %surface_id,
        backend = %backend,
        window_handle = ?window_handle,
        "render-surface ipc attach requested"
    );
    let sessions = app_state.sessions.lock().await;
    if sessions.get(&session_id).is_none() {
        tracing::warn!(
            session_id = %session_id.0,
            surface_id = %surface_id,
            "render-surface ipc attach rejected: session not found"
        );
        return IpcResponse::Error {
            code: "E404".to_string(),
            message: format!("Session not found: {}", session_id.0),
        };
    }
    drop(sessions);

    let surface = AttachedRenderSurface {
        surface_id: surface_id.clone(),
        backend,
        window_handle,
        render_proxy_endpoint,
    };

    #[cfg(any(windows, target_os = "macos"))]
    if let Err(error) = app_state
        .media_surface_renderers
        .lock()
        .await
        .attach_surface(&session_id, &surface)
    {
        tracing::warn!(
            session_id = %session_id.0,
            surface_id = %surface_id,
            backend = %surface.backend,
            error = %error,
            "render-surface renderer attach failed"
        );
        return IpcResponse::Error {
            code: "E_RENDER_ATTACH".to_string(),
            message: error,
        };
    }

    app_state
        .media_pipelines
        .lock()
        .await
        .attach_surface(session_id.clone(), surface);

    tracing::info!(
        session_id = %session_id.0,
        surface_id = %surface_id,
        "render-surface ipc attach completed"
    );
    IpcResponse::RenderSurfaceAttached {
        session_id,
        surface_id,
    }
}

/// Detach a native render surface from a receiver media pipeline.
pub async fn detach_render_surface(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    surface_id: String,
) -> IpcResponse {
    tracing::info!(
        session_id = %session_id.0,
        surface_id = %surface_id,
        "render-surface ipc detach requested"
    );
    let removed_from_pipeline = app_state
        .media_pipelines
        .lock()
        .await
        .detach_surface(&session_id, &surface_id);
    #[cfg(any(windows, target_os = "macos"))]
    app_state
        .media_surface_renderers
        .lock()
        .await
        .detach_surface(&session_id, &surface_id);

    tracing::info!(
        session_id = %session_id.0,
        surface_id = %surface_id,
        removed_from_pipeline,
        "render-surface ipc detach completed"
    );
    IpcResponse::RenderSurfaceDetached {
        session_id,
        surface_id,
    }
}

/// Return the current receiver media pipeline state.
pub async fn media_pipeline_snapshot(
    app_state: &Arc<AppState>,
    session_id: SessionId,
) -> IpcResponse {
    app_state.sync_agent_render_boundary(&session_id).await;
    let snapshot = app_state.media_pipelines.lock().await.snapshot(&session_id);
    IpcResponse::MediaPipelineSnapshot { snapshot }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::session;
    use mrd_proto::DeviceId;

    async fn register_local_test_device(app_state: &Arc<AppState>) -> DeviceId {
        let device_id = DeviceId("agent".to_string());
        app_state
            .devices
            .lock()
            .await
            .register(device_id.clone(), "Test Local Device".to_string());
        device_id
    }

    #[tokio::test]
    async fn start_sender_returns_started_response() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("test-session".to_string());
        let local_device_id = register_local_test_device(&app_state).await;

        let _ = session::start_session(
            &app_state,
            session_id.clone(),
            local_device_id,
            "quic".to_string(),
        )
        .await;

        let response = start_sender(&app_state, session_id.clone()).await;

        match response {
            IpcResponse::SenderStarted {
                session_id: returned_id,
            } => {
                assert_eq!(returned_id, session_id);
            }
            _ => panic!("Expected SenderStarted response"),
        }

        let sessions = app_state.sessions.lock().await;
        let snapshot = sessions.get(&session_id).expect("session snapshot");
        assert!(snapshot.sender_active, "sender should be marked active");
    }

    #[tokio::test]
    async fn start_sender_returns_not_found_for_missing_session() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("missing-session".to_string());

        let response = start_sender(&app_state, session_id.clone()).await;

        match response {
            IpcResponse::Error { code, message } => {
                assert_eq!(code, "E404");
                assert!(message.contains(&session_id.0));
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn start_receiver_returns_started_response() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("test-session".to_string());
        let local_device_id = register_local_test_device(&app_state).await;

        let _ = session::start_session(
            &app_state,
            session_id.clone(),
            local_device_id,
            "webrtc".to_string(),
        )
        .await;

        let response = start_receiver(&app_state, session_id.clone()).await;

        match response {
            IpcResponse::ReceiverStarted {
                session_id: returned_id,
            } => {
                assert_eq!(returned_id, session_id);
            }
            _ => panic!("Expected ReceiverStarted response"),
        }

        let sessions = app_state.sessions.lock().await;
        let snapshot = sessions.get(&session_id).expect("session snapshot");
        assert!(snapshot.receiver_active, "receiver should be marked active");
    }

    #[tokio::test]
    async fn start_receiver_returns_not_found_for_missing_session() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("missing-session".to_string());

        let response = start_receiver(&app_state, session_id.clone()).await;

        match response {
            IpcResponse::Error { code, message } => {
                assert_eq!(code, "E404");
                assert!(message.contains(&session_id.0));
            }
            _ => panic!("Expected Error response"),
        }
    }

    #[tokio::test]
    async fn probe_snapshot_returns_recorded_lan_probe_frames() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("probe-session".to_string());
        app_state
            .probes
            .lock()
            .await
            .record_probe_frame(&session_id, 1200, 1_000);

        let response = probe_snapshot(&app_state, session_id.clone()).await;

        match response {
            IpcResponse::ProbeSnapshot { snapshot } => {
                assert_eq!(snapshot.session_id, session_id);
                assert_eq!(snapshot.frames_received, 1);
                assert_eq!(snapshot.frames_decoded, 1);
            }
            _ => panic!("Expected ProbeSnapshot response"),
        }
    }

    #[tokio::test]
    async fn render_surface_attach_detach_updates_pipeline_snapshot() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("surface-session".to_string());
        let local_device_id = register_local_test_device(&app_state).await;

        let _ = session::start_session(
            &app_state,
            session_id.clone(),
            local_device_id,
            "quic".to_string(),
        )
        .await;

        let attached = attach_render_surface(
            &app_state,
            session_id.clone(),
            "surface-1".to_string(),
            "web".to_string(),
            None,
            None,
        )
        .await;
        assert!(matches!(
            attached,
            IpcResponse::RenderSurfaceAttached { .. }
        ));

        let snapshot = app_state.media_pipelines.lock().await.snapshot(&session_id);
        assert_eq!(snapshot.attached_surfaces.len(), 1);
        assert_eq!(snapshot.active_renderer.as_deref(), Some("web"));

        let detached =
            detach_render_surface(&app_state, session_id.clone(), "surface-1".to_string()).await;
        assert!(matches!(
            detached,
            IpcResponse::RenderSurfaceDetached { .. }
        ));

        let snapshot = app_state.media_pipelines.lock().await.snapshot(&session_id);
        assert!(snapshot.attached_surfaces.is_empty());
        assert_eq!(snapshot.active_renderer, None);
    }
}
