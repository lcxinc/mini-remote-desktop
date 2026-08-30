use std::sync::Arc;
use std::time::Duration;

use mrd_ipc::{client::IpcClient, transport::IpcEndpoint, IpcRequest, IpcResponse};
use mrd_proto::{DeviceId, SessionId};
use tokio::{task::JoinHandle, time::sleep};

fn test_endpoint(test_name: &str) -> IpcEndpoint {
    #[cfg(windows)]
    {
        IpcEndpoint::named_pipe(format!(
            r"\\.\pipe\rdesk-shell-smoke-{}-{}",
            test_name,
            std::process::id()
        ))
    }

    #[cfg(unix)]
    {
        IpcEndpoint::unix_socket(format!(
            "/tmp/rdesk-shell-smoke-{}-{}.sock",
            test_name,
            std::process::id()
        ))
    }
}

async fn spawn_service(test_name: &str) -> (IpcEndpoint, JoinHandle<()>) {
    let endpoint = test_endpoint(test_name);
    let server = mrd_service::ipc_server::IpcServer::new_with_endpoint(
        Arc::new(mrd_service::app_state::AppState::new()),
        endpoint.clone(),
    );

    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(200)).await;
    (endpoint, handle)
}

#[tokio::test]
async fn smoke_shell_can_check_service_health() {
    let (endpoint, server) = spawn_service("health").await;
    let mut client = IpcClient::with_endpoint(endpoint);

    let response = client
        .send_request(IpcRequest::ServiceHealth)
        .await
        .expect("service health response");

    server.abort();

    match response {
        IpcResponse::ServiceHealth { status } => {
            assert!(status.running);
            assert!(status.healthy);
            assert!(status.pid.is_some());
        }
        other => panic!("expected ServiceHealth response, got {:?}", other),
    }
}

#[tokio::test]
async fn smoke_shell_full_ipc_session_flow() {
    let (endpoint, server) = spawn_service("full-flow").await;
    let mut client = IpcClient::with_endpoint(endpoint);

    let device_id = DeviceId("flow-test-device".to_string());
    let session_id = SessionId("flow-test-session".to_string());

    let register_response = client
        .send_request(IpcRequest::RegisterDevice {
            device_id: device_id.clone(),
            device_name: "Flow Test Device".to_string(),
        })
        .await
        .expect("register device");
    assert!(matches!(
        register_response,
        IpcResponse::DeviceRegistered { .. }
    ));

    let list_devices = client
        .send_request(IpcRequest::ListDevices)
        .await
        .expect("list devices");
    match list_devices {
        IpcResponse::DeviceList { devices } => {
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].device_id, device_id);
        }
        other => panic!("expected DeviceList response, got {:?}", other),
    }

    let start_response = client
        .send_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: device_id.clone(),
            transport_kind: "quic".to_string(),
        })
        .await
        .expect("start session");
    assert!(matches!(start_response, IpcResponse::SessionStarted { .. }));

    let sender_response = client
        .send_request(IpcRequest::StartSender {
            session_id: session_id.clone(),
        })
        .await
        .expect("start sender");
    assert!(matches!(sender_response, IpcResponse::SenderStarted { .. }));

    let receiver_response = client
        .send_request(IpcRequest::StartReceiver {
            session_id: session_id.clone(),
        })
        .await
        .expect("start receiver");
    assert!(matches!(
        receiver_response,
        IpcResponse::ReceiverStarted { .. }
    ));

    let snapshot_response = client
        .send_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await
        .expect("session snapshot");
    match snapshot_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert_eq!(snapshot.session_id, session_id);
            assert_eq!(snapshot.role, "controller");
            assert!(snapshot.sender_active);
            assert!(snapshot.receiver_active);
        }
        other => panic!("expected SessionSnapshot response, got {:?}", other),
    }

    let stop_response = client
        .send_request(IpcRequest::StopSession {
            session_id: session_id.clone(),
        })
        .await
        .expect("stop session");
    assert!(matches!(stop_response, IpcResponse::SessionStopped { .. }));

    let stopped_snapshot_response = client
        .send_request(IpcRequest::SessionRuntimeSnapshot { session_id })
        .await
        .expect("stopped session snapshot");

    server.abort();

    match stopped_snapshot_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert_eq!(snapshot.state, "closed");
            assert!(!snapshot.sender_active);
            assert!(!snapshot.receiver_active);
        }
        other => panic!("expected closed SessionSnapshot response, got {:?}", other),
    }
}

#[tokio::test]
async fn smoke_shell_auto_reconnects_to_service() {
    let endpoint = test_endpoint("reconnect");
    let mut client = IpcClient::with_endpoint(endpoint.clone());

    let first_server = mrd_service::ipc_server::IpcServer::new_with_endpoint(
        Arc::new(mrd_service::app_state::AppState::new()),
        endpoint.clone(),
    );
    let first_handle = tokio::spawn(async move {
        let _ = first_server.run().await;
    });
    sleep(Duration::from_millis(200)).await;

    let first = client
        .send_request(IpcRequest::ServiceHealth)
        .await
        .expect("first health check");
    assert!(matches!(first, IpcResponse::ServiceHealth { .. }));

    first_handle.abort();
    sleep(Duration::from_millis(200)).await;
    client.disconnect();

    let failed = client
        .send_request_no_reconnect(IpcRequest::ServiceHealth)
        .await;
    assert!(failed.is_err(), "request should fail while service is down");

    let second_server = mrd_service::ipc_server::IpcServer::new_with_endpoint(
        Arc::new(mrd_service::app_state::AppState::new()),
        endpoint,
    );
    let second_handle = tokio::spawn(async move {
        let _ = second_server.run().await;
    });
    sleep(Duration::from_millis(200)).await;

    let recovered = client
        .send_request(IpcRequest::ServiceHealth)
        .await
        .expect("health check after restart");

    second_handle.abort();

    assert!(matches!(recovered, IpcResponse::ServiceHealth { .. }));
}
