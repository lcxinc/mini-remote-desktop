// IPC transport layer integration tests
//
// These tests verify that the actual named pipe / Unix socket transport
// works correctly for communication between shell and service.
//
// Unlike hard_cut_smoke.rs which uses in-process IpcServer, these tests
// go through the real transport layer.

use mrd_ipc::{client::IpcClient, transport::IpcEndpoint, IpcRequest, IpcResponse};
use mrd_proto::{DeviceId, SessionId};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use tokio::time::sleep;

fn test_endpoint(test_name: &str) -> IpcEndpoint {
    #[cfg(windows)]
    {
        IpcEndpoint::named_pipe(format!(
            r"\\.\pipe\mrd-service-{}-{}",
            test_name,
            std::process::id()
        ))
    }

    #[cfg(unix)]
    {
        IpcEndpoint::unix_socket(format!(
            "/tmp/mrd-service-{}-{}.sock",
            test_name,
            std::process::id()
        ))
    }
}

/// Start a real IPC server in the background
#[allow(dead_code)]
async fn start_ipc_server() -> anyhow::Result<()> {
    let app_state = Arc::new(mrd_service::app_state::AppState::new());
    let server =
        mrd_service::ipc_server::IpcServer::new_with_endpoint(app_state, test_endpoint("helper"));

    // Run server in background
    tokio::spawn(async move {
        // Server will run until the test completes
        let _ = server.run().await;
    });

    // Give server time to start listening
    sleep(Duration::from_millis(100)).await;
    Ok(())
}

#[tokio::test]
async fn ipc_transport_health_check_works() {
    let endpoint = test_endpoint("health");

    // Start server in background
    let server_endpoint = endpoint.clone();
    let server_handle = tokio::spawn(async {
        let app_state = Arc::new(mrd_service::app_state::AppState::new());
        let server =
            mrd_service::ipc_server::IpcServer::new_with_endpoint(app_state, server_endpoint);
        let _ = server.run().await;
    });

    // Give server time to start
    sleep(Duration::from_millis(200)).await;

    // Connect via real transport
    let mut client = IpcClient::with_endpoint(endpoint);
    let response = client.send_request(IpcRequest::ServiceHealth).await;

    // Clean up server
    server_handle.abort();

    match response {
        Ok(IpcResponse::ServiceHealth { status }) => {
            assert!(status.running);
            assert!(status.healthy);
        }
        Ok(other) => panic!("Expected ServiceHealth response, got {:?}", other),
        Err(e) => panic!("Failed to get response: {}", e),
    }
}

#[tokio::test]
async fn ipc_transport_handles_startup_connection_bursts() {
    let endpoint = test_endpoint("startup-burst");

    let server_endpoint = endpoint.clone();
    let server_handle = tokio::spawn(async {
        let app_state = Arc::new(mrd_service::app_state::AppState::new());
        let server =
            mrd_service::ipc_server::IpcServer::new_with_endpoint(app_state, server_endpoint);
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let client_count = 24;
    let barrier = Arc::new(Barrier::new(client_count));
    let mut handles = Vec::with_capacity(client_count);

    for _ in 0..client_count {
        let endpoint = endpoint.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut client = IpcClient::with_endpoint(endpoint);
            client.send_request(IpcRequest::ServiceHealth).await
        }));
    }

    let mut errors = Vec::new();
    for handle in handles {
        match handle.await.expect("client task panicked") {
            Ok(IpcResponse::ServiceHealth { status }) => {
                assert!(status.running);
                assert!(status.healthy);
            }
            Ok(other) => errors.push(format!("unexpected response: {other:?}")),
            Err(error) => errors.push(error.to_string()),
        }
    }

    server_handle.abort();

    assert!(
        errors.is_empty(),
        "startup IPC burst produced errors: {}",
        errors.join("; ")
    );
}

#[tokio::test]
async fn ipc_transport_device_registration_flow() {
    let endpoint = test_endpoint("device-registration");

    // Start server in background
    let server_endpoint = endpoint.clone();
    let server_handle = tokio::spawn(async {
        let app_state = Arc::new(mrd_service::app_state::AppState::new());
        let server =
            mrd_service::ipc_server::IpcServer::new_with_endpoint(app_state, server_endpoint);
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let mut client = IpcClient::with_endpoint(endpoint);
    let device_id = DeviceId("transport-test-device".to_string());

    // Register device
    let register_response = client
        .send_request(IpcRequest::RegisterDevice {
            device_id: device_id.clone(),
            device_name: "Transport Test Device".to_string(),
        })
        .await;

    match register_response {
        Ok(IpcResponse::DeviceRegistered {
            device_id: registered_id,
        }) => {
            assert_eq!(registered_id, device_id);
        }
        Ok(other) => {
            server_handle.abort();
            panic!("Expected DeviceRegistered response, got {:?}", other);
        }
        Err(e) => {
            server_handle.abort();
            panic!("Failed to register device: {}", e);
        }
    }

    // List devices (should return our device)
    let list_response = client.send_request(IpcRequest::ListDevices).await;

    server_handle.abort();

    match list_response {
        Ok(IpcResponse::DeviceList { devices }) => {
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].device_id, device_id);
            assert_eq!(devices[0].device_name, "Transport Test Device");
            assert!(devices[0].is_online);
        }
        Ok(other) => panic!("Expected DeviceList response, got {:?}", other),
        Err(e) => panic!("Failed to list devices: {}", e),
    }
}

#[tokio::test]
async fn ipc_transport_session_flow_through_transport() {
    let endpoint = test_endpoint("session-flow");

    // Start server in background
    let server_endpoint = endpoint.clone();
    let server_handle = tokio::spawn(async {
        let app_state = Arc::new(mrd_service::app_state::AppState::new());
        let server =
            mrd_service::ipc_server::IpcServer::new_with_endpoint(app_state, server_endpoint);
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let mut client = IpcClient::with_endpoint(endpoint);
    let session_id = SessionId("transport-session-test".to_string());
    let local_device_id = DeviceId("transport-local-device".to_string());
    let registration = client
        .send_request(IpcRequest::RegisterDevice {
            device_id: local_device_id.clone(),
            device_name: "Transport Local Device".to_string(),
        })
        .await;
    assert!(matches!(
        registration,
        Ok(IpcResponse::DeviceRegistered { .. })
    ));

    // Start the explicit local self-test session.
    let start_response = client
        .send_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: local_device_id,
            transport_kind: "quic".to_string(),
        })
        .await;

    match start_response {
        Ok(IpcResponse::SessionStarted { .. }) => {}
        Ok(other) => {
            server_handle.abort();
            panic!("Expected SessionStarted response, got {:?}", other);
        }
        Err(e) => {
            server_handle.abort();
            panic!("Failed to start session: {}", e);
        }
    }

    // Get session snapshot
    let snap_response = client
        .send_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await;

    match snap_response {
        Ok(IpcResponse::SessionSnapshot { snapshot }) => {
            assert_eq!(snapshot.session_id, session_id);
        }
        Ok(other) => {
            server_handle.abort();
            panic!("Expected SessionSnapshot response, got {:?}", other);
        }
        Err(e) => {
            server_handle.abort();
            panic!("Failed to get snapshot: {}", e);
        }
    }

    // Stop session
    let stop_response = client
        .send_request(IpcRequest::StopSession {
            session_id: session_id.clone(),
        })
        .await;

    server_handle.abort();

    match stop_response {
        Ok(IpcResponse::SessionStopped { .. }) => {}
        Ok(other) => panic!("Expected SessionStopped response, got {:?}", other),
        Err(e) => panic!("Failed to stop session: {}", e),
    }
}

#[tokio::test]
async fn ipc_transport_error_propagation() {
    let endpoint = test_endpoint("error-propagation");

    // Start server in background
    let server_endpoint = endpoint.clone();
    let server_handle = tokio::spawn(async {
        let app_state = Arc::new(mrd_service::app_state::AppState::new());
        let server =
            mrd_service::ipc_server::IpcServer::new_with_endpoint(app_state, server_endpoint);
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let mut client = IpcClient::with_endpoint(endpoint);

    // Try to get snapshot of non-existent session
    let response = client
        .send_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: SessionId("non-existent-session".to_string()),
        })
        .await;

    server_handle.abort();

    match response {
        Ok(IpcResponse::Error { code, .. }) => {
            assert_eq!(code, "E404");
        }
        Ok(other) => panic!("Expected error response, got {:?}", other),
        Err(e) => panic!("Failed to get error response: {}", e),
    }
}
