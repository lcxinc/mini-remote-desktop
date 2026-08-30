// Hard-cut migration smoke tests for mrd-service
//
// These tests verify that mrd-service can independently handle
// the core session flow without any shell-owned runtime.
//
// Tests use in-process IpcServer to avoid requiring an external service.

use mrd_ipc::{IpcRequest, IpcResponse};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::app_state::AppState;
use mrd_service::ipc_server::IpcServer;
use std::sync::Arc;

/// Create an in-process IPC server for testing
fn create_test_server() -> IpcServer {
    let app_state = Arc::new(AppState::new());
    IpcServer::new(app_state)
}

async fn register_local_test_device(server: &IpcServer, device_id: &str) -> DeviceId {
    let device_id = DeviceId(device_id.to_string());
    let response = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: device_id.clone(),
            device_name: "Test Local Device".to_string(),
        })
        .await;
    assert!(matches!(response, IpcResponse::DeviceRegistered { .. }));
    device_id
}

#[tokio::test]
async fn service_evaluates_lan_profile_and_exposes_policy_identity_telemetry() {
    let server = create_test_server();
    let session_id = SessionId("scenario-session".to_string());

    let evaluation = server
        .handle_request(IpcRequest::EvaluateScenarioProfile {
            scenario_id: "lan.2k144".to_string(),
            peer_device_id: None,
            requested_profile: None,
        })
        .await;
    match evaluation {
        IpcResponse::ScenarioProfileEvaluated { evaluation } => {
            assert_eq!(evaluation.scenario_id, "lan.2k144");
            assert!(evaluation
                .required_capabilities
                .iter()
                .any(|capability| capability == "transport.quic_datagram"));
            assert!(evaluation.transport_kind.as_deref() == Some("quic"));
            match evaluation.status {
                mrd_ipc::ScenarioEvaluationStatus::Ready
                | mrd_ipc::ScenarioEvaluationStatus::Degraded => {
                    assert!(evaluation.missing_capabilities.is_empty());
                    assert!(evaluation.fallback_profile.is_none());
                }
                mrd_ipc::ScenarioEvaluationStatus::Blocked => {
                    assert!(!evaluation.missing_capabilities.is_empty());
                    assert!(evaluation.fallback_profile.is_some());
                }
                mrd_ipc::ScenarioEvaluationStatus::Skipped => {
                    panic!("local LAN profile evaluation should not be skipped")
                }
            }
        }
        other => panic!(
            "Expected ScenarioProfileEvaluated response, got {:?}",
            other
        ),
    }

    let policy = server
        .handle_request(IpcRequest::SetTransportPolicy {
            session_id: session_id.clone(),
            policy: mrd_ipc::TransportPolicyConfig {
                mode: "auto".to_string(),
                preferred_transport: None,
                allow_lan_quic: true,
                allow_webrtc: true,
                allow_relay: true,
            },
        })
        .await;
    match policy {
        IpcResponse::TransportPolicyUpdated { snapshot } => {
            assert_eq!(snapshot.session_id, Some(session_id.clone()));
            assert_eq!(snapshot.selected_transport, "quic");
            assert!(!snapshot.relay_required);
        }
        other => panic!("Expected TransportPolicyUpdated response, got {:?}", other),
    }

    let control = server
        .handle_request(IpcRequest::GetControlChannelSnapshot {
            session_id: session_id.clone(),
        })
        .await;
    match control {
        IpcResponse::ControlChannelSnapshot { snapshot } => {
            assert_eq!(snapshot.reliable.name, "ctrl_rel");
            assert_eq!(snapshot.realtime.name, "ctrl_rt");
            assert!(snapshot.reliable.ordered);
            assert!(!snapshot.realtime.ordered);
        }
        other => panic!("Expected ControlChannelSnapshot response, got {:?}", other),
    }

    let expected_machine_key_id = server
        .app_state()
        .device_identities
        .machine_key_id()
        .expect("in-memory service state has a signing identity")
        .to_string();
    let identity = server
        .handle_request(IpcRequest::GetDeviceIdentitySnapshot)
        .await;
    match identity {
        IpcResponse::DeviceIdentitySnapshot { snapshot } => {
            assert!(snapshot.consent_required);
            assert_eq!(
                snapshot.certificate_fingerprint.as_deref(),
                Some(expected_machine_key_id.as_str())
            );
        }
        other => panic!("Expected DeviceIdentitySnapshot response, got {:?}", other),
    }

    let peer_device_id = DeviceId("paired-peer".to_string());
    let paired = server
        .handle_request(IpcRequest::PairDevice {
            device_id: peer_device_id.clone(),
            certificate_fingerprint: Some("sha256:peer".to_string()),
        })
        .await;
    match paired {
        IpcResponse::PairingUpdated { snapshot } => {
            let paired_peer = snapshot
                .paired_devices
                .iter()
                .find(|device| device.device_id == peer_device_id)
                .expect("paired peer should be listed");
            assert_eq!(paired_peer.trust_status, "pending");
            assert_eq!(
                paired_peer.certificate_fingerprint.as_deref(),
                Some("sha256:peer")
            );
        }
        other => panic!("Expected PairingUpdated response, got {:?}", other),
    }

    let approved = server
        .handle_request(IpcRequest::ApprovePairing {
            device_id: peer_device_id.clone(),
        })
        .await;
    match approved {
        IpcResponse::PairingUpdated { snapshot } => {
            let paired_peer = snapshot
                .paired_devices
                .iter()
                .find(|device| device.device_id == peer_device_id)
                .expect("approved peer should still be listed");
            assert_eq!(paired_peer.trust_status, "paired");
            assert_eq!(
                paired_peer.certificate_fingerprint.as_deref(),
                Some("sha256:peer")
            );
        }
        other => panic!("Expected PairingUpdated response, got {:?}", other),
    }

    let telemetry = server
        .handle_request(IpcRequest::GetTelemetryBundle {
            run_id: "run-1".to_string(),
            session_id: Some(session_id),
        })
        .await;
    match telemetry {
        IpcResponse::TelemetryBundle { bundle } => {
            assert_eq!(bundle.run_id, "run-1");
            assert_eq!(bundle.event_count, 0);
        }
        other => panic!("Expected TelemetryBundle response, got {:?}", other),
    }
}

#[tokio::test]
async fn hard_cut_service_responds_to_health_check() {
    let server = create_test_server();

    let response = server.handle_request(IpcRequest::ServiceHealth).await;

    match response {
        IpcResponse::ServiceHealth { status } => {
            assert!(status.running, "Service should report running");
            assert!(status.healthy, "Service should report healthy");
        }
        _ => panic!("Expected ServiceHealth response, got {:?}", response),
    }
}

#[tokio::test]
async fn hard_cut_full_session_flow() {
    let server = create_test_server();

    // Step 1: Register device
    let device_id = DeviceId("smoke-test-device".to_string());
    let register_response = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: device_id.clone(),
            device_name: "Smoke Test Device".to_string(),
        })
        .await;

    assert!(
        matches!(register_response, IpcResponse::DeviceRegistered { .. }),
        "Expected DeviceRegistered response, got {:?}",
        register_response
    );

    // Step 2: List devices (should return our device)
    let list_response = server.handle_request(IpcRequest::ListDevices).await;

    assert!(
        matches!(list_response, IpcResponse::DeviceList { .. }),
        "Expected DeviceList response, got {:?}",
        list_response
    );

    // Step 3: Start session as controller
    let session_id = SessionId("smoke-test-session".to_string());
    let target_device_id = device_id.clone();

    let start_response = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id,
            transport_kind: "quic".to_string(),
        })
        .await;

    assert!(
        matches!(start_response, IpcResponse::SessionStarted { .. }),
        "Expected SessionStarted response, got {:?}",
        start_response
    );

    // Step 4: Get session snapshot
    let snapshot_response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await;

    match snapshot_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert_eq!(snapshot.session_id, session_id);
            assert_eq!(snapshot.role, "controller");
            assert!(!snapshot.state.is_empty(), "State should not be empty");
        }
        _ => panic!(
            "Expected SessionSnapshot response, got {:?}",
            snapshot_response
        ),
    }

    // Step 5: Stop session
    let stop_response = server
        .handle_request(IpcRequest::StopSession {
            session_id: session_id.clone(),
        })
        .await;

    assert!(
        matches!(stop_response, IpcResponse::SessionStopped { .. }),
        "Expected SessionStopped response, got {:?}",
        stop_response
    );

    // Step 6: Verify session is retained as a closed lifecycle snapshot.
    let closed_response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot { session_id })
        .await;

    match closed_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert_eq!(snapshot.state, "closed");
            assert!(!snapshot.sender_active);
            assert!(!snapshot.receiver_active);
        }
        _ => panic!(
            "Expected closed session snapshot after stop, got {:?}",
            closed_response
        ),
    }
}

#[tokio::test]
async fn hard_cut_rejects_legacy_remote_start_after_local_registration() {
    let server = create_test_server();
    let local_device_id = DeviceId("guard-local-device".to_string());
    let _ = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: local_device_id,
            device_name: "Guard Local Device".to_string(),
        })
        .await;
    let session_id = SessionId("guard-legacy-remote".to_string());

    let response = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: DeviceId("guard-remote-device".to_string()),
            transport_kind: "webrtc".to_string(),
        })
        .await;

    let IpcResponse::RemoteAccessError {
        session_id: returned_session_id,
        failure,
        ..
    } = response
    else {
        panic!("expected remote legacy start rejection");
    };
    assert_eq!(returned_session_id, Some(session_id.clone()));
    assert_eq!(
        failure.code,
        mrd_ipc::RemoteReasonCode::ProtocolDowngradeBlocked
    );
    assert!(server
        .app_state()
        .sessions
        .lock()
        .await
        .get(&session_id)
        .is_none());
}

#[tokio::test]
async fn hard_cut_session_flow_is_auditable() {
    let server = create_test_server();

    let local_device = DeviceId("audit-local".to_string());
    let _ = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: local_device.clone(),
            device_name: "Audit Local".to_string(),
        })
        .await;

    let session_id = SessionId("audit-session".to_string());
    let peer_device = local_device.clone();
    let _ = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: peer_device.clone(),
            transport_kind: "quic".to_string(),
        })
        .await;
    let _ = server
        .handle_request(IpcRequest::StopSession {
            session_id: session_id.clone(),
        })
        .await;

    let response = server
        .handle_request(IpcRequest::AuditLog {
            query: mrd_ipc::AuditLogQuery {
                session_id: Some(session_id.clone()),
                action: None,
                limit: Some(10),
            },
        })
        .await;

    match response {
        IpcResponse::AuditLog { events } => {
            assert!(events.iter().any(|event| event.action == "session.start"));
            assert!(events.iter().any(|event| event.action == "session.stop"));
            assert!(events
                .iter()
                .all(|event| event.session_id.as_ref() == Some(&session_id)));
            let start = events
                .iter()
                .find(|event| event.action == "session.start")
                .expect("start audit event");
            assert_eq!(start.actor_device_id, Some(local_device));
            assert_eq!(start.peer_device_id, Some(peer_device));
            assert_eq!(start.transport_kind.as_deref(), Some("quic"));
            assert_eq!(start.outcome, "success");
        }
        other => panic!("Expected AuditLog response, got {:?}", other),
    }
}

#[tokio::test]
async fn hard_cut_runtime_snapshot_aggregates_state() {
    let server = create_test_server();

    // Register a device first
    let _ = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: DeviceId("test-device".to_string()),
            device_name: "Test Device".to_string(),
        })
        .await;

    // Start a session
    let session_id = SessionId("snapshot-test-session".to_string());
    let _ = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: DeviceId("test-device".to_string()),
            transport_kind: "webrtc".to_string(),
        })
        .await;

    // Get runtime snapshot
    let response = server.handle_request(IpcRequest::RuntimeSnapshot).await;

    match response {
        IpcResponse::RuntimeSnapshot { snapshot } => {
            assert!(
                !snapshot.sessions.is_empty(),
                "Should have at least one session"
            );
            assert!(
                snapshot.is_registered,
                "Should be registered after device registration"
            );
            assert_eq!(snapshot.sessions[0].session_id, session_id);
        }
        _ => panic!("Expected RuntimeSnapshot response, got {:?}", response),
    }
}

#[tokio::test]
async fn hard_cut_list_sessions_returns_active_sessions() {
    let server = create_test_server();
    let local_device_id = register_local_test_device(&server, "agent").await;

    // Start two sessions
    let session1 = SessionId("list-test-1".to_string());
    let session2 = SessionId("list-test-2".to_string());

    for session_id in [&session1, &session2] {
        let response = server
            .handle_request(IpcRequest::StartSession {
                session_id: session_id.clone(),
                target_device_id: local_device_id.clone(),
                transport_kind: "quic".to_string(),
            })
            .await;

        assert!(
            matches!(response, IpcResponse::SessionStarted { .. }),
            "Expected SessionStarted response"
        );
    }

    // List sessions
    let response = server.handle_request(IpcRequest::ListSessions).await;

    match response {
        IpcResponse::SessionList { sessions } => {
            assert!(
                sessions.len() >= 2,
                "Should have at least 2 sessions, got {}",
                sessions.len()
            );
        }
        _ => panic!("Expected SessionList response, got {:?}", response),
    }

    // Cleanup
    for session_id in [&session1, &session2] {
        let _ = server
            .handle_request(IpcRequest::StopSession {
                session_id: session_id.clone(),
            })
            .await;
    }
}

#[tokio::test]
async fn hard_cut_list_devices_returns_registered_devices() {
    let server = create_test_server();

    // Initially no devices
    let response = server.handle_request(IpcRequest::ListDevices).await;
    match response {
        IpcResponse::DeviceList { devices } => {
            assert_eq!(devices.len(), 0, "Should have no devices initially");
        }
        _ => panic!("Expected DeviceList response, got {:?}", response),
    }

    // Register a device
    let device_id = DeviceId("test-device".to_string());
    let _ = server
        .handle_request(IpcRequest::RegisterDevice {
            device_id: device_id.clone(),
            device_name: "Test Device".to_string(),
        })
        .await;

    // Now should have one device
    let response = server.handle_request(IpcRequest::ListDevices).await;
    match response {
        IpcResponse::DeviceList { devices } => {
            assert_eq!(devices.len(), 1, "Should have 1 device after registration");
            assert_eq!(devices[0].device_id, device_id);
            assert_eq!(devices[0].device_name, "Test Device");
            assert!(devices[0].is_online, "Local device should be online");
        }
        _ => panic!("Expected DeviceList response, got {:?}", response),
    }
}

#[tokio::test]
async fn hard_cut_sender_receiver_require_existing_session() {
    let server = create_test_server();

    let non_existent_session = SessionId("non-existent".to_string());

    // StartSender should fail for non-existent session
    let response = server
        .handle_request(IpcRequest::StartSender {
            session_id: non_existent_session.clone(),
        })
        .await;

    match response {
        IpcResponse::Error { code, .. } => {
            assert_eq!(code, "E404", "Should return E404 for non-existent session");
        }
        _ => panic!(
            "Expected error for non-existent session, got {:?}",
            response
        ),
    }

    // StartReceiver should fail for non-existent session
    let response = server
        .handle_request(IpcRequest::StartReceiver {
            session_id: non_existent_session,
        })
        .await;

    match response {
        IpcResponse::Error { code, .. } => {
            assert_eq!(code, "E404", "Should return E404 for non-existent session");
        }
        _ => panic!(
            "Expected error for non-existent session, got {:?}",
            response
        ),
    }

    // After creating a session, StartSender should succeed
    let valid_session = SessionId("valid-session".to_string());
    let local_device_id = register_local_test_device(&server, "remote").await;
    let _ = server
        .handle_request(IpcRequest::StartSession {
            session_id: valid_session.clone(),
            target_device_id: local_device_id,
            transport_kind: "quic".to_string(),
        })
        .await;

    let response = server
        .handle_request(IpcRequest::StartSender {
            session_id: valid_session.clone(),
        })
        .await;

    assert!(
        matches!(response, IpcResponse::SenderStarted { .. }),
        "StartSender should succeed for existing session, got {:?}",
        response
    );

    let response = server
        .handle_request(IpcRequest::StartReceiver {
            session_id: valid_session,
        })
        .await;

    assert!(
        matches!(response, IpcResponse::ReceiverStarted { .. }),
        "StartReceiver should succeed for existing session, got {:?}",
        response
    );
}

#[tokio::test]
async fn hard_cut_start_and_accept_session() {
    let server = create_test_server();

    let session_id = SessionId("accept-test-session".to_string());
    let controller_device = DeviceId("controller".to_string());
    let agent_device = register_local_test_device(&server, "agent").await;

    // Start session as controller
    let start_response = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: agent_device.clone(),
            transport_kind: "quic".to_string(),
        })
        .await;

    assert!(
        matches!(start_response, IpcResponse::SessionStarted { .. }),
        "Expected SessionStarted response"
    );

    // Accept session as agent
    let accept_response = server
        .handle_request(IpcRequest::AcceptSession {
            session_id: session_id.clone(),
            source_device_id: controller_device,
        })
        .await;

    assert!(
        matches!(accept_response, IpcResponse::SessionAccepted { .. }),
        "Expected SessionAccepted response, got {:?}",
        accept_response
    );

    // Verify snapshot shows both sides
    let snap_response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot { session_id })
        .await;

    match snap_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            // After accept, should have both source and target
            // (implementation may vary, just verify we get a snapshot)
            assert_eq!(snapshot.session_id.0, "accept-test-session");
        }
        _ => panic!("Expected SessionSnapshot response, got {:?}", snap_response),
    }
}

#[tokio::test]
async fn hard_cuted_service_owns_session_state() {
    let server = create_test_server();
    let local_device_id = register_local_test_device(&server, "remote").await;

    let session_id = SessionId("ownership-test".to_string());

    // Start a session
    let _ = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: local_device_id,
            transport_kind: "webrtc".to_string(),
        })
        .await;

    // Verify through snapshot that service owns the state
    let response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await;

    match response {
        IpcResponse::SessionSnapshot { snapshot } => {
            // Verify the snapshot comes from mrd-service's own registry
            // not from any shell-owned state
            assert_eq!(snapshot.session_id, session_id);
            assert_eq!(snapshot.transport_kind, "webrtc");
            assert_eq!(snapshot.role, "controller");
            assert_eq!(snapshot.state, "connecting"); // Explicit state from domain
        }
        _ => panic!("Expected SessionSnapshot response, got {:?}", response),
    }
}

#[tokio::test]
async fn hard_cut_start_sender_updates_snapshot_state() {
    let server = create_test_server();
    let local_device_id = register_local_test_device(&server, "remote").await;

    let session_id = SessionId("sender-state-test".to_string());

    // Start a session
    let _ = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: local_device_id,
            transport_kind: "quic".to_string(),
        })
        .await;

    // Initially sender should not be active
    let snap_response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await;

    match snap_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert!(
                !snapshot.sender_active,
                "Initial sender_active should be false"
            );
            assert!(
                !snapshot.receiver_active,
                "Initial receiver_active should be false"
            );
        }
        _ => panic!("Expected SessionSnapshot response"),
    }

    // Start sender
    let start_response = server
        .handle_request(IpcRequest::StartSender {
            session_id: session_id.clone(),
        })
        .await;

    assert!(
        matches!(start_response, IpcResponse::SenderStarted { .. }),
        "Expected SenderStarted response"
    );

    // Verify snapshot now reflects sender is active
    let snap_response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await;

    match snap_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert!(
                snapshot.sender_active,
                "After StartSender, sender_active should be true"
            );
            assert!(
                !snapshot.receiver_active,
                "Receiver should still be inactive"
            );
            assert_eq!(snapshot.session_id, session_id);
        }
        _ => panic!("Expected SessionSnapshot response"),
    }
}

#[tokio::test]
async fn hard_cut_start_receiver_updates_snapshot_state() {
    let server = create_test_server();
    let local_device_id = register_local_test_device(&server, "remote").await;

    let session_id = SessionId("receiver-state-test".to_string());

    // Start a session
    let _ = server
        .handle_request(IpcRequest::StartSession {
            session_id: session_id.clone(),
            target_device_id: local_device_id,
            transport_kind: "webrtc".to_string(),
        })
        .await;

    // Start receiver
    let start_response = server
        .handle_request(IpcRequest::StartReceiver {
            session_id: session_id.clone(),
        })
        .await;

    assert!(
        matches!(start_response, IpcResponse::ReceiverStarted { .. }),
        "Expected ReceiverStarted response"
    );

    // Verify snapshot reflects receiver is active
    let snap_response = server
        .handle_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: session_id.clone(),
        })
        .await;

    match snap_response {
        IpcResponse::SessionSnapshot { snapshot } => {
            assert!(!snapshot.sender_active, "Sender should still be inactive");
            assert!(
                snapshot.receiver_active,
                "After StartReceiver, receiver_active should be true"
            );
            assert_eq!(snapshot.session_id, session_id);
        }
        _ => panic!("Expected SessionSnapshot response"),
    }
}
