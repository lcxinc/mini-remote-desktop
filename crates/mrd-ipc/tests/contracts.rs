// IPC contract tests
// Verify serialization/deserialization of all IPC messages

use mrd_ipc::{
    AdaptiveMediaConfig, AgentRenderBoundarySnapshot, AttachedRenderSurface, AuditEvent,
    AuditLogQuery, CapabilityConstraint, CapabilityConstraintStatus, CapabilityDomain,
    CapabilityItem, CapabilityPlatform, CapabilityProfile, CapabilitySnapshot, CapabilityStatus,
    CaptureSource, CaptureSourceSelection, ControlChannelLaneSnapshot, ControlChannelReliability,
    ControlChannelSnapshot, ControlInputButton, ControlInputEvent, ControlInputKey,
    ControlInputLane, CrossE2EFaultInjectionResult, DeviceIdentitySnapshot, DeviceInfo,
    DevicePreference, DevicePreferenceUpdate, DirectoryList, FileEntry, FileEntryKind,
    FileTransferConflictPolicy, FileTransferEntry, FileTransferProviderDescriptor,
    FileTransferProviderHandoffHint, FileTransferStartRequest, FileTransferStatus,
    FileTransferTaskSnapshot, IpcRequest, IpcResponse, MediaAdaptationSnapshot,
    MediaPipelineSnapshot, MediaProfile, MediaProfileNegotiation, MediaSenderTransportSnapshot,
    MediaStageMetrics, MediaTestImpairmentSnapshot, PairedDeviceIdentity, ScenarioEvaluation,
    ScenarioEvaluationReason, ScenarioEvaluationStatus, SessionBootstrap, SessionRuntimeSnapshot,
    TelemetryArtifactRef, TelemetryBundle, TelemetryMetricSummary, TransportPolicyConfig,
    TransportPolicySnapshot,
};
use mrd_proto::{DeviceId, SessionId};

fn test_device_id() -> DeviceId {
    DeviceId("test-device".to_string())
}

fn test_session_id() -> SessionId {
    SessionId("test-session-123".to_string())
}

fn test_media_profile() -> MediaProfile {
    MediaProfile {
        width: 2560,
        height: 1440,
        fps: 144,
        bitrate_mbps: 64,
        codec: "h264".to_string(),
        ..MediaProfile::default()
    }
}

fn test_capture_source() -> CaptureSource {
    CaptureSource {
        id: "windows:window:0x1234".to_string(),
        platform: "windows".to_string(),
        source_kind: "window".to_string(),
        title: "Target App".to_string(),
        class_name: "ApplicationFrameWindow".to_string(),
        width: 1280,
        height: 720,
        process_id: 4242,
        app_name: Some("Target App".to_string()),
        bundle_identifier: None,
        preview_data_url: Some("legacy-preview-token".to_string()),
        preview_width: Some(320),
        preview_height: Some(180),
    }
}

fn test_capability_snapshot() -> CapabilitySnapshot {
    CapabilitySnapshot {
        schema_version: 1,
        platform: CapabilityPlatform::Windows,
        service_version: "0.1.0".to_string(),
        capabilities: vec![CapabilityItem {
            id: "transport.quic_datagram".to_string(),
            domain: CapabilityDomain::Transport,
            label: "QUIC datagram media".to_string(),
            status: CapabilityStatus::Available,
            platform: CapabilityPlatform::Windows,
            reason: None,
            detail: None,
            requires: Vec::new(),
            conflicts_with: Vec::new(),
            depends_on: Vec::new(),
            fallback_ids: Vec::new(),
            last_probe_time_ms: Some(1_700_000_000_000),
        }],
        constraints: vec![CapabilityConstraint {
            id: "openh264_requires_cpu_input".to_string(),
            applies_to: vec![
                "encode.openh264".to_string(),
                "memory.d3d11_shared".to_string(),
            ],
            status: CapabilityConstraintStatus::Block,
            reason: "OpenH264 requires CPU-backed input".to_string(),
            fallback_ids: vec!["memory.cpu".to_string()],
        }],
        profiles: vec![
            CapabilityProfile {
                id: "lan.2k144".to_string(),
                width: 2560,
                height: 1440,
                fps: 144,
                bitrate_mbps: 64,
                codec: "h264".to_string(),
                codec_profile: None,
                bit_depth: None,
                chroma_subsampling: None,
                pixel_format: None,
                hdr_enabled: None,
                color_mode: None,
                color_pipeline: None,
                latency_budget_ms: None,
                min_stable_fps_ratio: Some(0.8),
                max_drop_ratio: Some(0.02),
                required_capabilities: vec![
                    "transport.quic_datagram".to_string(),
                    "transport.media_profile_control_v1".to_string(),
                ],
            },
            CapabilityProfile {
                id: "lan.1600p165".to_string(),
                width: 2560,
                height: 1600,
                fps: 165,
                bitrate_mbps: 80,
                codec: "h264".to_string(),
                codec_profile: None,
                bit_depth: None,
                chroma_subsampling: None,
                pixel_format: None,
                hdr_enabled: None,
                color_mode: None,
                color_pipeline: None,
                latency_budget_ms: None,
                min_stable_fps_ratio: Some(0.8),
                max_drop_ratio: Some(0.02),
                required_capabilities: vec![
                    "transport.quic_datagram".to_string(),
                    "transport.media_profile_control_v1".to_string(),
                ],
            },
        ],
        updated_at_ms: 1_700_000_000_000,
    }
}

#[test]
fn serialize_deserialize_register_device() {
    let request = IpcRequest::RegisterDevice {
        device_id: test_device_id(),
        device_name: "Test Device".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_list_devices() {
    let request = IpcRequest::ListDevices;

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_start_session() {
    let request = IpcRequest::StartSession {
        session_id: test_session_id(),
        target_device_id: test_device_id(),
        transport_kind: "quic".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_start_lan_remote_session_with_media_profile() {
    let request = IpcRequest::StartLanRemoteSession {
        session_id: test_session_id(),
        target_device_id: test_device_id(),
        transport_kind: "quic".to_string(),
        requested_profile: Some(test_media_profile()),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("requested_profile"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_update_media_profile() {
    let request = IpcRequest::UpdateMediaProfile {
        session_id: test_session_id(),
        requested_profile: test_media_profile(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_configure_media_adaptation() {
    let config = AdaptiveMediaConfig {
        enabled: true,
        mode: "keyframe_ladder".to_string(),
        ceiling_profile: Some(test_media_profile()),
        floor_profile: Some(MediaProfile {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_mbps: 10,
            codec: "h264".to_string(),
            ..MediaProfile::default()
        }),
        ladder: vec![test_media_profile()],
        dynamic_resolution_enabled: true,
        downshift_cooldown_ms: 2_000,
        upshift_hold_ms: 5_000,
    };
    let request = IpcRequest::ConfigureMediaAdaptation {
        session_id: test_session_id(),
        config,
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("ConfigureMediaAdaptation"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);

    let legacy_json = r#"{
        "type":"ConfigureMediaAdaptation",
        "session_id":"session-123",
        "config":{
            "enabled":true,
            "mode":"keyframe_ladder",
            "ladder":[],
            "downshift_cooldown_ms":2000,
            "upshift_hold_ms":5000
        }
    }"#;
    let legacy: IpcRequest = serde_json::from_str(legacy_json).unwrap();
    let IpcRequest::ConfigureMediaAdaptation { config, .. } = legacy else {
        panic!("expected ConfigureMediaAdaptation request");
    };
    assert!(!config.dynamic_resolution_enabled);
}

#[test]
fn serialize_deserialize_audit_log_query_and_response() {
    let query = AuditLogQuery {
        session_id: Some(test_session_id()),
        action: Some("session.start".to_string()),
        limit: Some(50),
    };
    let request = IpcRequest::AuditLog {
        query: query.clone(),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("AuditLog"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let event = AuditEvent {
        id: 1,
        timestamp_ms: 1_700_000_000_000,
        action: "session.start".to_string(),
        outcome: "success".to_string(),
        session_id: query.session_id,
        actor_device_id: Some(DeviceId("local".to_string())),
        peer_device_id: Some(DeviceId("remote".to_string())),
        transport_kind: Some("quic".to_string()),
        reason: None,
        details: vec![("source".to_string(), "ipc".to_string())],
    };
    let response = IpcResponse::AuditLog {
        events: vec![event.clone()],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("session.start"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_list_remote_capture_sources() {
    let request = IpcRequest::ListRemoteCaptureSources {
        session_id: test_session_id(),
        include_previews: true,
        limit: Some(32),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("ListRemoteCaptureSources"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_list_local_capture_sources() {
    let request = IpcRequest::ListLocalCaptureSources {
        include_previews: false,
        limit: Some(24),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("ListLocalCaptureSources"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_select_remote_capture_source() {
    let request = IpcRequest::SelectRemoteCaptureSource {
        session_id: test_session_id(),
        source_id: "windows:window:0x1234".to_string(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_accept_session() {
    let request = IpcRequest::AcceptSession {
        session_id: test_session_id(),
        source_device_id: test_device_id(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_start_sender() {
    let request = IpcRequest::StartSender {
        session_id: test_session_id(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_start_receiver() {
    let request = IpcRequest::StartReceiver {
        session_id: test_session_id(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_stop_session() {
    let request = IpcRequest::StopSession {
        session_id: test_session_id(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_session_runtime_snapshot_request() {
    let request = IpcRequest::SessionRuntimeSnapshot {
        session_id: test_session_id(),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_capability_snapshot_request() {
    let request = IpcRequest::CapabilitySnapshot;

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("CapabilitySnapshot"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request, deserialized);
}

#[test]
fn serialize_deserialize_scenario_evaluation_contracts() {
    let request = IpcRequest::EvaluateScenarioProfile {
        scenario_id: "lan.2k144".to_string(),
        peer_device_id: Some(test_device_id()),
        requested_profile: Some(test_media_profile()),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("EvaluateScenarioProfile"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let evaluation = ScenarioEvaluation {
        scenario_id: "lan.2k144".to_string(),
        status: ScenarioEvaluationStatus::Ready,
        selected_profile: Some(test_media_profile()),
        transport_kind: Some("quic".to_string()),
        reasons: vec![ScenarioEvaluationReason {
            code: "profile.ready".to_string(),
            severity: "info".to_string(),
            message: "All required capabilities are present.".to_string(),
            capability_id: None,
        }],
        required_capabilities: vec!["transport.quic_datagram".to_string()],
        missing_capabilities: Vec::new(),
        fallback_profile: None,
    };
    let response = IpcResponse::ScenarioProfileEvaluated {
        evaluation: evaluation.clone(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"status\":\"ready\""));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_policy_identity_control_and_telemetry_contracts() {
    let policy = TransportPolicyConfig {
        mode: "auto".to_string(),
        preferred_transport: Some("quic".to_string()),
        allow_lan_quic: true,
        allow_webrtc: true,
        allow_relay: true,
    };
    let request = IpcRequest::SetTransportPolicy {
        session_id: test_session_id(),
        policy,
    };
    let json = serde_json::to_string(&request).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let policy_snapshot = TransportPolicySnapshot {
        session_id: Some(test_session_id()),
        mode: "auto".to_string(),
        selected_transport: "quic".to_string(),
        candidate_transports: vec!["quic".to_string(), "webrtc".to_string()],
        relay_required: false,
        reason: Some("LAN high-refresh profile selected QUIC datagram.".to_string()),
        fallback_reason: None,
    };
    let response = IpcResponse::TransportPolicyUpdated {
        snapshot: policy_snapshot,
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("TransportPolicyUpdated"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let control_snapshot = ControlChannelSnapshot {
        session_id: test_session_id(),
        reliable: ControlChannelLaneSnapshot {
            name: "ctrl_rel".to_string(),
            reliability: ControlChannelReliability::ReliableOrdered,
            ordered: true,
            max_retransmits: None,
            queued_messages: 2,
            dropped_messages: 0,
            coalesced_messages: 0,
            accepted_messages: 4,
            injected_messages: 4,
            failed_messages: 0,
            last_error: None,
        },
        realtime: ControlChannelLaneSnapshot {
            name: "ctrl_rt".to_string(),
            reliability: ControlChannelReliability::UnreliableRealtime,
            ordered: false,
            max_retransmits: Some(0),
            queued_messages: 0,
            dropped_messages: 3,
            coalesced_messages: 9,
            accepted_messages: 12,
            injected_messages: 12,
            failed_messages: 1,
            last_error: Some("coalesced stale pointer sample".to_string()),
        },
    };
    let response = IpcResponse::ControlChannelSnapshot {
        snapshot: control_snapshot,
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("ctrl_rel"));
    assert!(json.contains("ctrl_rt"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let identity = DeviceIdentitySnapshot {
        local_device_id: Some(test_device_id()),
        display_name: Some("Controller".to_string()),
        certificate_fingerprint: Some("sha256:abc".to_string()),
        consent_required: true,
        paired_devices: vec![PairedDeviceIdentity {
            device_id: DeviceId("peer".to_string()),
            display_name: "Peer".to_string(),
            certificate_fingerprint: Some("sha256:def".to_string()),
            trust_status: "paired".to_string(),
            last_seen_ms: Some(1_700_000_000_000),
        }],
    };
    let response = IpcResponse::DeviceIdentitySnapshot { snapshot: identity };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("sha256:abc"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let bundle = TelemetryBundle {
        run_id: "run-1".to_string(),
        session_id: Some(test_session_id()),
        metrics: vec![TelemetryMetricSummary {
            name: "fps".to_string(),
            unit: "fps".to_string(),
            sample_count: 100,
            p50: Some(143.0),
            p95: Some(145.0),
        }],
        event_count: 4,
        log_count: 12,
        artifacts: vec![TelemetryArtifactRef {
            name: "report".to_string(),
            path: "target/report.md".to_string(),
            kind: "markdown".to_string(),
        }],
    };
    let response = IpcResponse::TelemetryBundle { bundle };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("TelemetryBundle"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_cross_e2e_fault_injection_contracts() {
    let request = IpcRequest::CrossE2EInjectFault {
        session_id: test_session_id(),
        fault_type: "network.pause_peer".to_string(),
        duration_ms: Some(500),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("CrossE2EInjectFault"));
    assert!(json.contains("network.pause_peer"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let result = CrossE2EFaultInjectionResult {
        session_id: test_session_id(),
        fault_type: "network.pause_peer".to_string(),
        status: "injected".to_string(),
        message: "network pause fault injected".to_string(),
        duration_ms: Some(500),
        affected_surface_ids: vec![],
        impairment: Some(MediaTestImpairmentSnapshot {
            loss_pct: 1.0,
            base_delay_ms: 500,
            jitter_ms: 0,
            mtu_bytes: None,
            seed: 1,
            datagrams_sent: 0,
            datagrams_dropped: 0,
            datagrams_delayed: 0,
            datagrams_fragmented_by_mtu: 0,
        }),
    };
    let response = IpcResponse::CrossE2EFaultInjected { result };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("CrossE2EFaultInjected"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_control_input_contracts() {
    let session_id = test_session_id();
    let request = IpcRequest::SendControlInput {
        session_id: session_id.clone(),
        event: ControlInputEvent::MouseButton {
            button: ControlInputButton::Left,
            pressed: true,
        },
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("SendControlInput"));
    assert!(json.contains("\"button\":\"left\""));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let key_request = IpcRequest::SendControlInput {
        session_id: session_id.clone(),
        event: ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey { code: 0x41 },
            pressed: false,
        },
    };
    let json = serde_json::to_string(&key_request).unwrap();
    assert!(json.contains("\"kind\":\"virtual_key\""));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(key_request, deserialized);

    let release_request = IpcRequest::SendControlInput {
        session_id: session_id.clone(),
        event: ControlInputEvent::ReleaseAll,
    };
    let json = serde_json::to_string(&release_request).unwrap();
    assert!(json.contains("\"kind\":\"release_all\""));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(release_request, deserialized);

    let horizontal_wheel_request = IpcRequest::SendControlInput {
        session_id: session_id.clone(),
        event: ControlInputEvent::MouseHorizontalWheel { delta: 120 },
    };
    let json = serde_json::to_string(&horizontal_wheel_request).unwrap();
    assert!(json.contains("\"kind\":\"mouse_horizontal_wheel\""));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(horizontal_wheel_request, deserialized);

    let response = IpcResponse::ControlInputAccepted {
        session_id,
        lane: ControlInputLane::Reliable,
        event_count: 1,
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("ControlInputAccepted"));
    assert!(json.contains("\"lane\":\"reliable\""));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_file_directory_contracts() {
    let request = IpcRequest::ListDirectory {
        path: Some("C:\\Users\\tester".to_string()),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("ListDirectory"));
    assert!(json.contains("C:\\\\Users\\\\tester"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let listing = DirectoryList {
        path: "C:\\Users\\tester".to_string(),
        parent_path: Some("C:\\Users".to_string()),
        entries: vec![FileEntry {
            name: "Downloads".to_string(),
            path: "C:\\Users\\tester\\Downloads".to_string(),
            kind: FileEntryKind::Directory,
            size_bytes: None,
            modified_ms: Some(1_776_000_000_000),
            readonly: false,
        }],
    };
    let response = IpcResponse::DirectoryList { listing };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("DirectoryList"));
    assert!(json.contains("\"kind\":\"directory\""));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_file_transfer_contracts() {
    let request = IpcRequest::StartFileTransfer {
        request: FileTransferStartRequest {
            source_device_id: Some(DeviceId("source-device".to_string())),
            target_device_id: Some(DeviceId("target-device".to_string())),
            entries: vec![FileTransferEntry {
                source_path: "C:\\Users\\tester\\source.txt".to_string(),
                file_name: Some("source.txt".to_string()),
                kind: FileEntryKind::File,
            }],
            target_path: "C:\\Users\\tester\\Downloads".to_string(),
            conflict_policy: FileTransferConflictPolicy::Rename,
            transport_hint: Some("local".to_string()),
            provider_hint: Some("mrd-local".to_string()),
        },
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("StartFileTransfer"));
    assert!(json.contains("\"source_device_id\":\"source-device\""));
    assert!(json.contains("\"conflict_policy\":\"rename\""));
    assert!(json.contains("\"transport_hint\":\"local\""));
    assert!(json.contains("\"provider_hint\":\"mrd-local\""));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let request = IpcRequest::ListFileTransfers;
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("ListFileTransfers"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let request = IpcRequest::CancelFileTransfer {
        transfer_id: "file-transfer-1".to_string(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("CancelFileTransfer"));
    assert!(json.contains("\"transfer_id\":\"file-transfer-1\""));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let transfer = FileTransferTaskSnapshot {
        transfer_id: "file-transfer-1".to_string(),
        status: FileTransferStatus::Completed,
        source_device_id: Some(DeviceId("source-device".to_string())),
        target_device_id: Some(DeviceId("target-device".to_string())),
        transport_kind: "local".to_string(),
        provider_kind: "mrd-local".to_string(),
        provider_capabilities: vec!["service.file_transfer.local".to_string()],
        total_entries: 1,
        copied_entries: 1,
        total_bytes: Some(5),
        copied_bytes: 5,
        error: None,
        entries: vec![FileEntry {
            name: "source.txt".to_string(),
            path: "C:\\Users\\tester\\Downloads\\source.txt".to_string(),
            kind: FileEntryKind::File,
            size_bytes: Some(5),
            modified_ms: None,
            readonly: false,
        }],
    };
    let response = IpcResponse::FileTransferStarted {
        transfer: transfer.clone(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("FileTransferStarted"));
    assert!(json.contains("\"status\":\"completed\""));
    assert!(json.contains("\"provider_kind\":\"mrd-local\""));
    assert!(json.contains("\"service.file_transfer.local\""));
    assert!(json.contains("\"copied_bytes\":5"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let response = IpcResponse::FileTransferCancelled {
        transfer: transfer.clone(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("FileTransferCancelled"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let response = IpcResponse::FileTransferList {
        transfers: vec![transfer],
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("FileTransferList"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let request = IpcRequest::ListFileTransferProviders;
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("ListFileTransferProviders"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request, deserialized);

    let response = IpcResponse::FileTransferProviderList {
        providers: vec![
            FileTransferProviderDescriptor {
                provider_kind: "mrd-local".to_string(),
                display_name: "MRD local file transfer".to_string(),
                status: CapabilityStatus::Available,
                capabilities: vec!["service.file_transfer.local".to_string()],
                reason: None,
                handoff_hint: None,
            },
            FileTransferProviderDescriptor {
                provider_kind: "r-file".to_string(),
                display_name: "R-File external bridge".to_string(),
                status: CapabilityStatus::Unimplemented,
                capabilities: vec!["service.file_transfer.external_bridge".to_string()],
                reason: Some("reserved provider bridge".to_string()),
                handoff_hint: Some(FileTransferProviderHandoffHint {
                    external_app: "R-File".to_string(),
                    bridge_service: "rfile-bridge".to_string(),
                    control_endpoint: Some("http://127.0.0.1:18100".to_string()),
                    data_endpoint: Some("http://127.0.0.1:18080".to_string()),
                    capabilities: vec![
                        "rfile.bridge.session_v1".to_string(),
                        "rfile.watch.http_v1".to_string(),
                        "rfile.remote_mount.v1".to_string(),
                    ],
                }),
            },
        ],
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("FileTransferProviderList"));
    assert!(json.contains("\"provider_kind\":\"r-file\""));
    assert!(json.contains("\"status\":\"unimplemented\""));
    assert!(json.contains("\"service.file_transfer.external_bridge\""));
    assert!(json.contains("\"bridge_service\":\"rfile-bridge\""));
    assert!(json.contains("\"control_endpoint\":\"http://127.0.0.1:18100\""));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_device_registered_response() {
    let response = IpcResponse::DeviceRegistered {
        device_id: test_device_id(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_device_list_response() {
    let response = IpcResponse::DeviceList {
        devices: vec![DeviceInfo {
            device_id: test_device_id(),
            device_name: "Test Device".to_string(),
            is_online: true,
        }],
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_device_preference_contracts() {
    let update_request = IpcRequest::UpdateDevicePreference {
        device_id: test_device_id(),
        update: DevicePreferenceUpdate {
            favorite: Some(true),
            disabled: Some(false),
            removed: Some(false),
        },
    };
    let json = serde_json::to_string(&update_request).unwrap();
    assert!(json.contains("UpdateDevicePreference"));
    assert!(json.contains("\"favorite\":true"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(update_request, deserialized);

    let list_request = IpcRequest::GetDevicePreferences;
    let json = serde_json::to_string(&list_request).unwrap();
    assert!(json.contains("GetDevicePreferences"));
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(list_request, deserialized);

    let preference = DevicePreference {
        device_id: test_device_id(),
        favorite: true,
        disabled: false,
        removed: false,
    };
    let response = IpcResponse::DevicePreferenceUpdated {
        preference: preference.clone(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("DevicePreferenceUpdated"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);

    let response = IpcResponse::DevicePreferences {
        preferences: vec![preference],
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("DevicePreferences"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_session_snapshot_response() {
    let response = IpcResponse::SessionSnapshot {
        snapshot: SessionRuntimeSnapshot {
            session_id: test_session_id(),
            role: "controller".to_string(),
            state: "connected".to_string(),
            transport_kind: "quic".to_string(),
            local_bootstrap: Some(SessionBootstrap {
                listen_addr: Some("127.0.0.1:4433".to_string()),
                server_name: Some("localhost".to_string()),
                cert_der: Some("base64cert".to_string()),
            }),
            remote_bootstrap: None,
            last_error: None,
            sender_active: false,
            receiver_active: false,
            peer_device_id: Some(test_device_id()),
        },
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"peer_device_id\""));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_capability_snapshot_response() {
    let response = IpcResponse::CapabilitySnapshot {
        snapshot: test_capability_snapshot(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("lan.2k144"));
    assert!(json.contains("lan.1600p165"));
    assert!(json.contains("transport.quic_datagram"));
    assert!(json.contains("\"platform\":\"windows\""));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_error_response() {
    let response = IpcResponse::Error {
        code: "E001".to_string(),
        message: "Test error".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_media_profile_updated_response() {
    let negotiation = MediaProfileNegotiation {
        requested: MediaProfile {
            width: 3840,
            height: 2160,
            fps: 240,
            bitrate_mbps: 120,
            codec: "h264".to_string(),
            ..MediaProfile::default()
        },
        selected: test_media_profile(),
        status: "downgraded".to_string(),
        reason: Some("clamped to LAN QUIC profile capability".to_string()),
        selected_source_id: Some("windows:display:0".to_string()),
        selected_width: Some(2560),
        selected_height: Some(1440),
        downgrade_reason: Some("clamped to LAN QUIC profile capability".to_string()),
    };
    let response = IpcResponse::MediaProfileUpdated {
        session_id: test_session_id(),
        negotiation: negotiation.clone(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, response);
}

#[test]
fn serialize_deserialize_render_surface_control_contracts() {
    let attach = IpcRequest::AttachRenderSurface {
        session_id: test_session_id(),
        surface_id: "surface-1".to_string(),
        backend: "d3d11".to_string(),
        window_handle: Some(0x1234),
        render_proxy_endpoint: None,
    };
    let json = serde_json::to_string(&attach).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(attach, deserialized);

    let detach = IpcRequest::DetachRenderSurface {
        session_id: test_session_id(),
        surface_id: "surface-1".to_string(),
    };
    let json = serde_json::to_string(&detach).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(detach, deserialized);

    let response = IpcResponse::RenderSurfaceAttached {
        session_id: test_session_id(),
        surface_id: "surface-1".to_string(),
    };
    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_media_pipeline_snapshot_contract() {
    let response = IpcResponse::MediaPipelineSnapshot {
        snapshot: MediaPipelineSnapshot {
            session_id: test_session_id(),
            attached_surfaces: vec![AttachedRenderSurface {
                surface_id: "surface-1".to_string(),
                backend: "d3d11".to_string(),
                window_handle: Some(0x1234),
                render_proxy_endpoint: None,
            }],
            active_encoder: Some("nvenc_hevc".to_string()),
            active_decoder: Some("nvdec".to_string()),
            active_renderer: Some("d3d11".to_string()),
            active_codec: Some("hevc".to_string()),
            active_codec_profile: Some("main".to_string()),
            active_bit_depth: Some(8),
            active_chroma_subsampling: Some("4:2:0".to_string()),
            active_pixel_format: Some("d3d11_shared_nv12".to_string()),
            active_hdr_enabled: Some(false),
            active_color_mode: Some("monochrome".to_string()),
            active_color_pipeline: Some("sdr8".to_string()),
            active_width: Some(2560),
            active_height: Some(1440),
            active_fps: Some(144),
            active_bitrate_mbps: Some(80),
            codec_fallback_reason: None,
            queue_depth: 1,
            dropped_frames: 2,
            render_presented_frames: 120,
            render_queue_replacements: 1,
            render_stale_frame_drops: 1,
            render_lock_drops: 1,
            render_present_skips: 2,
            render_pacing_target_fps: Some(144),
            render_queue_policy: Some("latest".to_string()),
            swap_chain_max_frame_latency: Some(1),
            swap_chain_allow_tearing: Some(true),
            swap_chain_waitable_object: Some(true),
            swap_chain_present_mode: Some("waitable".to_string()),
            display_refresh_hz: Some(144),
            render_thread_priority: Some("highest".to_string()),
            render_waitable_timeouts: 1,
            agent_render_boundary: Some(AgentRenderBoundarySnapshot {
                resource_id: [7; 16],
                decoder_backend: "nvdec_d3d11_shared".into(),
                enqueued_units: 120,
                queue_replacements: 1,
                decoded_frames: 119,
                presented_frames: 118,
            }),
            stage_metrics: vec![MediaStageMetrics {
                stage: "decode".to_string(),
                p50_ms: Some(1.0),
                p95_ms: Some(2.0),
            }],
            test_impairment: None,
            sender_transport: MediaSenderTransportSnapshot {
                capture_source_id: Some("windows:window:0x1234".to_string()),
                capture_source_kind: Some("window".to_string()),
                capture_memory_path: Some("d3d11_shared_bgra".to_string()),
                dynamic_fps_tier: Some("active".to_string()),
                target_fps: Some(144),
                frames_completed: 12,
                repeated_latest_frames: 2,
                access_units_encoded: 12,
                keyframes_encoded: 1,
                encoded_access_unit_bytes: 65_536,
                datagram_fragments_attempted: 4,
                datagram_fragments_sent: 3,
                datagram_fragments_delayed: 0,
                datagram_fragments_dropped_by_impairment: 0,
                datagram_fragments_dropped_for_capacity: 1,
                datagram_fragments_dropped_for_budget: 0,
                datagram_frames_cut_short_for_capacity: 1,
                datagram_frames_cut_short_for_budget: 0,
                reliable_fragments_sent: 0,
                reliable_frames_sent: 0,
                ..MediaSenderTransportSnapshot::default()
            },
            adaptation: Some(MediaAdaptationSnapshot {
                enabled: true,
                state: "stable".to_string(),
                ladder_index: 0,
                current_profile: test_media_profile(),
                target_profile: test_media_profile(),
                last_reason: Some("configured".to_string()),
                last_change_ms: 1_700_000_000_000,
                observed_fps: 144.0,
                drop_ratio: 0.0,
                queue_depth: 0,
            }),
        },
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn media_sender_snapshot_serializes_window_dynamic_fps_fields() {
    let snapshot = MediaSenderTransportSnapshot {
        capture_source_id: Some("windows:window:0x1234".to_string()),
        capture_source_kind: Some("window".to_string()),
        capture_memory_path: Some("d3d11_shared_bgra".to_string()),
        dynamic_fps_tier: Some("active".to_string()),
        target_fps: Some(120),
        ..MediaSenderTransportSnapshot::default()
    };

    let json = serde_json::to_string(&snapshot).unwrap();

    assert!(json.contains("windows:window:0x1234"));
    assert!(json.contains("capture_source_kind"));
    assert!(json.contains("capture_memory_path"));
    assert!(json.contains("dynamic_fps_tier"));
    assert!(json.contains("target_fps"));

    let deserialized: MediaSenderTransportSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot, deserialized);
}

#[test]
fn serialize_deserialize_media_adaptation_configured_response() {
    let response = IpcResponse::MediaAdaptationConfigured {
        session_id: test_session_id(),
        snapshot: MediaAdaptationSnapshot {
            enabled: true,
            state: "stable".to_string(),
            ladder_index: 0,
            current_profile: test_media_profile(),
            target_profile: test_media_profile(),
            last_reason: Some("configured".to_string()),
            last_change_ms: 1_700_000_000_000,
            observed_fps: 144.0,
            drop_ratio: 0.0,
            queue_depth: 0,
        },
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("MediaAdaptationConfigured"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response, deserialized);
}

#[test]
fn serialize_deserialize_capture_source_list_response() {
    let response = IpcResponse::CaptureSourceList {
        session_id: test_session_id(),
        sources: vec![test_capture_source()],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("preview_data_url"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, response);
}

#[test]
fn serialize_deserialize_local_capture_source_list_response() {
    let response = IpcResponse::LocalCaptureSourceList {
        sources: vec![test_capture_source()],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("LocalCaptureSourceList"));
    assert!(json.contains("windows:window:0x1234"));
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, response);
}

#[test]
fn serialize_deserialize_capture_source_selected_response() {
    let selection = CaptureSourceSelection {
        session_id: test_session_id(),
        source: test_capture_source(),
        status: "selected".to_string(),
        reason: None,
    };
    let response = IpcResponse::CaptureSourceSelected {
        session_id: test_session_id(),
        selection,
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized, response);
}

#[test]
fn serialize_deserialize_all_request_types() {
    let requests = vec![
        IpcRequest::RegisterDevice {
            device_id: test_device_id(),
            device_name: "Device".to_string(),
        },
        IpcRequest::ListDevices,
        IpcRequest::StartSession {
            session_id: test_session_id(),
            target_device_id: test_device_id(),
            transport_kind: "webrtc".to_string(),
        },
        IpcRequest::StartLanRemoteSession {
            session_id: test_session_id(),
            target_device_id: test_device_id(),
            transport_kind: "quic".to_string(),
            requested_profile: Some(test_media_profile()),
        },
        IpcRequest::UpdateMediaProfile {
            session_id: test_session_id(),
            requested_profile: test_media_profile(),
        },
        IpcRequest::ListLocalCaptureSources {
            include_previews: true,
            limit: Some(16),
        },
        IpcRequest::ListRemoteCaptureSources {
            session_id: test_session_id(),
            include_previews: true,
            limit: Some(16),
        },
        IpcRequest::SelectRemoteCaptureSource {
            session_id: test_session_id(),
            source_id: "windows:window:0x1234".to_string(),
        },
        IpcRequest::AcceptSession {
            session_id: test_session_id(),
            source_device_id: test_device_id(),
        },
        IpcRequest::StartSender {
            session_id: test_session_id(),
        },
        IpcRequest::StartReceiver {
            session_id: test_session_id(),
        },
        IpcRequest::StopSession {
            session_id: test_session_id(),
        },
        IpcRequest::SessionRuntimeSnapshot {
            session_id: test_session_id(),
        },
        IpcRequest::AuditLog {
            query: AuditLogQuery {
                session_id: Some(test_session_id()),
                action: Some("session.start".to_string()),
                limit: Some(25),
            },
        },
        IpcRequest::CapabilitySnapshot,
        IpcRequest::EvaluateScenarioProfile {
            scenario_id: "lan.2k144".to_string(),
            peer_device_id: Some(test_device_id()),
            requested_profile: Some(test_media_profile()),
        },
        IpcRequest::GetPeerCapabilitySnapshot {
            peer_device_id: test_device_id(),
        },
        IpcRequest::SetTransportPolicy {
            session_id: test_session_id(),
            policy: TransportPolicyConfig {
                mode: "auto".to_string(),
                preferred_transport: None,
                allow_lan_quic: true,
                allow_webrtc: true,
                allow_relay: true,
            },
        },
        IpcRequest::GetControlChannelSnapshot {
            session_id: test_session_id(),
        },
        IpcRequest::SendControlInput {
            session_id: test_session_id(),
            event: ControlInputEvent::MouseMove { x: 120, y: 80 },
        },
        IpcRequest::PairDevice {
            device_id: test_device_id(),
            certificate_fingerprint: Some("sha256:peer".to_string()),
        },
        IpcRequest::ApprovePairing {
            device_id: test_device_id(),
        },
        IpcRequest::RevokeDevice {
            device_id: test_device_id(),
        },
        IpcRequest::GetDeviceIdentitySnapshot,
        IpcRequest::GetTelemetryBundle {
            run_id: "run-1".to_string(),
            session_id: Some(test_session_id()),
        },
        IpcRequest::StreamProbeEvents,
    ];

    for request in requests {
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request, deserialized);
    }
}

use mrd_ipc::{
    AuditEventMetadataV2, AuditEventPageV2, AuditEventV2, AuditEventsQueryV2, ConsentDecision,
    ConsentResponse, DecimalU64, RemoteAccessMode, RemoteAuthorizationState, RemoteCursorState,
    RemoteFailure, RemoteMediaState, RemotePermissionScope, RemotePresentationState,
    RemoteReasonCode, RemoteRouteKind, RemoteRoutePreference, RemoteRouteState, RemoteSessionEvent,
    RemoteSessionEventEnvelope, RemoteSessionRequest, RemoteSessionRole, RemoteSessionSnapshot,
    RouteCandidateEvidence, RouteCandidateState, RouteEvidence, SessionEventSubscription,
    SessionEventSubscriptionQuery, SessionPermissionChange, TrustedDeviceApproval,
    TrustedDeviceRotation, TrustedDeviceSnapshot, TrustedDeviceState, UnattendedAccessPolicy,
    UnattendedAccessSnapshot,
};

fn du64(value: u64) -> DecimalU64 {
    DecimalU64::new(value)
}

fn secure_remote_session_fixture() -> RemoteSessionSnapshot {
    RemoteSessionSnapshot {
        session_id: test_session_id(),
        role: RemoteSessionRole::Controller,
        peer_device_id: test_device_id(),
        peer_key_id: "sha256:peer-key".to_string(),
        access_mode: RemoteAccessMode::Attended,
        authorization_state: RemoteAuthorizationState::AwaitingLocalConsent,
        route_state: RemoteRouteState::Connecting,
        route_kind: Some(RemoteRouteKind::LanQuic),
        media_state: RemoteMediaState::Idle,
        presentation_state: RemotePresentationState::IncomingApprovalRequired,
        requested_scopes: vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputPointer,
        ],
        granted_scopes: Vec::new(),
        policy_revision: du64(7),
        failure: None,
        created_at_ms: 1_700_000_000_000,
        updated_at_ms: 1_700_000_000_100,
        authorization_expires_at_ms: Some(1_700_000_030_000),
    }
}

#[test]
fn remote_route_preference_defaults_to_auto_when_omitted() {
    let decoded: RemoteSessionRequest = serde_json::from_value(serde_json::json!({
        "session_id": test_session_id(),
        "target_device_id": test_device_id(),
        "access_mode": "attended",
        "requested_scopes": ["screen.view"],
        "requested_profile": null
    }))
    .unwrap();

    assert_eq!(decoded.route_preference, RemoteRoutePreference::Auto);
}

#[test]
fn remote_route_preference_has_exact_wire_values() {
    for (preference, expected) in [
        (RemoteRoutePreference::Auto, "auto"),
        (RemoteRoutePreference::Lan, "lan"),
        (RemoteRoutePreference::WanRelay, "wan_relay"),
    ] {
        assert_eq!(serde_json::to_value(preference).unwrap(), expected);
    }
}

fn unattended_policy_fixture() -> UnattendedAccessPolicy {
    UnattendedAccessPolicy {
        trusted_devices_only: true,
        allowed_peer_key_ids: vec!["sha256:peer-key".to_string()],
        permission_ceiling: vec![RemotePermissionScope::ScreenView],
        expires_at_ms: Some(1_800_000_000_000),
    }
}

fn trusted_device_fixture() -> TrustedDeviceSnapshot {
    TrustedDeviceSnapshot {
        peer_key_id: "sha256:peer-key".to_string(),
        display_name: Some("Peer workstation".to_string()),
        key_epoch: du64(2),
        state: TrustedDeviceState::Trusted,
        permission_ceiling: vec![RemotePermissionScope::ScreenView],
        trust_revision: du64(9),
        approved_at_ms: Some(1_700_000_000_000),
        updated_at_ms: 1_700_000_000_100,
    }
}

#[test]
fn secure_remote_permission_and_reason_codes_have_stable_wire_values() {
    let scopes = [
        (RemotePermissionScope::ScreenView, "screen.view"),
        (RemotePermissionScope::InputPointer, "input.pointer"),
        (RemotePermissionScope::InputKeyboard, "input.keyboard"),
        (RemotePermissionScope::ClipboardRead, "clipboard.read"),
        (RemotePermissionScope::ClipboardWrite, "clipboard.write"),
        (RemotePermissionScope::FileRead, "file.read"),
        (RemotePermissionScope::FileWrite, "file.write"),
        (RemotePermissionScope::AudioListen, "audio.listen"),
        (RemotePermissionScope::AudioTalk, "audio.talk"),
        (RemotePermissionScope::DisplaySwitch, "display.switch"),
        (
            RemotePermissionScope::DisplayMultiView,
            "display.multi_view",
        ),
        (RemotePermissionScope::PowerRestart, "power.restart"),
        (RemotePermissionScope::PowerShutdown, "power.shutdown"),
        (RemotePermissionScope::TerminalOpen, "terminal.open"),
        (
            RemotePermissionScope::PrivacyBlockLocalInput,
            "privacy.block_local_input",
        ),
        (
            RemotePermissionScope::PrivacyBlankScreen,
            "privacy.blank_screen",
        ),
        (
            RemotePermissionScope::SecureDesktopView,
            "secure_desktop.view",
        ),
        (
            RemotePermissionScope::SecureDesktopControl,
            "secure_desktop.control",
        ),
    ];
    for (scope, expected) in scopes {
        assert_eq!(
            serde_json::to_value(scope).unwrap(),
            serde_json::json!(expected)
        );
        assert_eq!(
            serde_json::from_value::<RemotePermissionScope>(serde_json::json!(expected)).unwrap(),
            scope
        );
    }

    let reason_codes = [
        (RemoteReasonCode::IdentityMismatch, "identity_mismatch"),
        (
            RemoteReasonCode::CertificateBindingMismatch,
            "certificate_binding_mismatch",
        ),
        (RemoteReasonCode::TrustRequired, "trust_required"),
        (RemoteReasonCode::ConsentDenied, "consent_denied"),
        (RemoteReasonCode::CredentialInvalid, "credential_invalid"),
        (RemoteReasonCode::CredentialLocked, "credential_locked"),
        (
            RemoteReasonCode::AuthorizationTimeout,
            "authorization_timeout",
        ),
        (RemoteReasonCode::GrantExpired, "grant_expired"),
        (RemoteReasonCode::GrantRevoked, "grant_revoked"),
        (RemoteReasonCode::PolicyChanged, "policy_changed"),
        (RemoteReasonCode::ReplayDetected, "replay_detected"),
        (RemoteReasonCode::ScopeDenied, "scope_denied"),
        (
            RemoteReasonCode::ProtocolDowngradeBlocked,
            "protocol_downgrade_blocked",
        ),
        (RemoteReasonCode::LanUnreachable, "lan_unreachable"),
        (RemoteReasonCode::IceDirectFailed, "ice_direct_failed"),
        (
            RemoteReasonCode::TurnAllocationFailed,
            "turn_allocation_failed",
        ),
        (RemoteReasonCode::RouteLost, "route_lost"),
        (
            RemoteReasonCode::RouteMigrationTimeout,
            "route_migration_timeout",
        ),
        (RemoteReasonCode::EncoderUnavailable, "encoder_unavailable"),
        (RemoteReasonCode::DecoderUnavailable, "decoder_unavailable"),
        (RemoteReasonCode::CaptureSourceLost, "capture_source_lost"),
        (RemoteReasonCode::ProfileDowngraded, "profile_downgraded"),
        (
            RemoteReasonCode::CongestionDownshift,
            "congestion_downshift",
        ),
        (
            RemoteReasonCode::RenderBudgetExceeded,
            "render_budget_exceeded",
        ),
    ];
    for (code, expected) in reason_codes {
        assert_eq!(
            serde_json::to_value(code).unwrap(),
            serde_json::json!(expected)
        );
    }
    assert!(serde_json::from_str::<RemoteReasonCode>("\"unknown_security_code\"").is_err());
    assert_eq!(
        serde_json::to_value(RemoteRouteKind::WebRtcDirect).unwrap(),
        serde_json::json!("webrtc_direct")
    );
}

#[test]
fn secure_remote_requests_have_stable_tags_and_required_fields() {
    let requests = vec![
        (
            IpcRequest::GetRemoteSession {
                session_id: test_session_id(),
            },
            "GetRemoteSession",
        ),
        (
            IpcRequest::RequestRemoteSession {
                request: RemoteSessionRequest {
                    session_id: test_session_id(),
                    target_device_id: test_device_id(),
                    access_mode: RemoteAccessMode::Attended,
                    route_preference: RemoteRoutePreference::WanRelay,
                    requested_scopes: vec![RemotePermissionScope::ScreenView],
                    requested_profile: Some(test_media_profile()),
                },
            },
            "RequestRemoteSession",
        ),
        (
            IpcRequest::RespondToConsent {
                response: ConsentResponse {
                    session_id: test_session_id(),
                    decision: ConsentDecision::Approve,
                    approved_scopes: vec![RemotePermissionScope::ScreenView],
                    expected_policy_revision: du64(7),
                },
            },
            "RespondToConsent",
        ),
        (
            IpcRequest::EnableUnattendedAccess {
                policy: unattended_policy_fixture(),
            },
            "EnableUnattendedAccess",
        ),
        (
            IpcRequest::DisableUnattendedAccess {
                expected_policy_revision: du64(7),
            },
            "DisableUnattendedAccess",
        ),
        (
            IpcRequest::RotateUnattendedAccess {
                expected_policy_revision: du64(7),
            },
            "RotateUnattendedAccess",
        ),
        (
            IpcRequest::ListTrustedDevices {
                include_revoked: true,
            },
            "ListTrustedDevices",
        ),
        (
            IpcRequest::ApproveTrustedDevice {
                approval: TrustedDeviceApproval {
                    peer_key_id: "sha256:peer-key".to_string(),
                    key_epoch: du64(2),
                    permission_ceiling: vec![RemotePermissionScope::ScreenView],
                },
            },
            "ApproveTrustedDevice",
        ),
        (
            IpcRequest::SuspendTrustedDevice {
                peer_key_id: "sha256:peer-key".to_string(),
                expected_trust_revision: du64(9),
            },
            "SuspendTrustedDevice",
        ),
        (
            IpcRequest::RevokeTrustedDevice {
                peer_key_id: "sha256:peer-key".to_string(),
                expected_trust_revision: du64(9),
            },
            "RevokeTrustedDevice",
        ),
        (
            IpcRequest::RotateTrustedDevice {
                rotation: TrustedDeviceRotation {
                    peer_key_id: "sha256:peer-key".to_string(),
                    new_peer_key_id: "sha256:new-peer-key".to_string(),
                    new_key_epoch: du64(3),
                    expected_trust_revision: du64(9),
                },
            },
            "RotateTrustedDevice",
        ),
        (
            IpcRequest::ChangeSessionPermissions {
                change: SessionPermissionChange {
                    session_id: test_session_id(),
                    requested_scopes: vec![RemotePermissionScope::ScreenView],
                    expected_policy_revision: du64(7),
                },
            },
            "ChangeSessionPermissions",
        ),
        (
            IpcRequest::SubscribeSessionEvents {
                query: SessionEventSubscriptionQuery {
                    session_id: Some(test_session_id()),
                    after_sequence: Some(du64(41)),
                    limit: 32,
                    wait_timeout_ms: 15_000,
                },
            },
            "SubscribeSessionEvents",
        ),
        (
            IpcRequest::GetRouteEvidence {
                session_id: test_session_id(),
            },
            "GetRouteEvidence",
        ),
        (
            IpcRequest::GetAuditEventsV2 {
                query: AuditEventsQueryV2 {
                    after_sequence: Some(du64(8)),
                    limit: 50,
                    session_id: Some(test_session_id()),
                    action: Some("session.authorized".to_string()),
                    outcome: Some("allowed".to_string()),
                    peer_device_id: Some(test_device_id()),
                },
            },
            "GetAuditEventsV2",
        ),
    ];

    assert!(requests
        .iter()
        .all(|(request, _)| request.is_secure_remote()));
    assert!(!IpcRequest::ListSessions.is_secure_remote());

    for (request, expected_type) in requests {
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["type"], serde_json::json!(expected_type));
        let encoded = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "private_key",
            "protected_blob",
            "credential",
            "proof",
            "verifier",
            "database_id",
            "event_hash",
        ] {
            assert!(!encoded.contains(&format!("\"{forbidden}\"")));
        }
        assert_eq!(
            serde_json::from_value::<IpcRequest>(value).unwrap(),
            request
        );
    }
}

#[test]
fn secure_remote_responses_and_events_round_trip_without_secret_material() {
    let session = secure_remote_session_fixture();
    let access = UnattendedAccessSnapshot {
        enabled: true,
        policy_revision: du64(7),
        access_epoch: du64(3),
        policy: unattended_policy_fixture(),
        locked_until_ms: None,
        updated_at_ms: 1_700_000_000_100,
    };
    let device = trusted_device_fixture();
    let event = RemoteSessionEventEnvelope {
        sequence: du64(42),
        timestamp_ms: 1_700_000_000_200,
        session_id: test_session_id(),
        event: RemoteSessionEvent::PermissionsChanged {
            granted_scopes: vec![RemotePermissionScope::ScreenView],
            policy_revision: du64(8),
        },
    };
    let subscription = SessionEventSubscription {
        events: vec![event.clone()],
        pending_sessions: Vec::new(),
        next_after_sequence: Some(du64(42)),
        cursor_state: RemoteCursorState::Current,
        has_more: false,
        poll_after_ms: 1_000,
    };
    let evidence = RouteEvidence {
        session_id: test_session_id(),
        route_state: RemoteRouteState::Connected,
        selected_route: Some(RemoteRouteKind::LanQuic),
        policy_revision: du64(8),
        transport_fingerprint_sha256: Some("sha256:transport".to_string()),
        candidates: vec![RouteCandidateEvidence {
            route: RemoteRouteKind::LanQuic,
            state: RouteCandidateState::Connected,
            started_at_ms: Some(1_700_000_000_000),
            completed_at_ms: Some(1_700_000_000_020),
            round_trip_ms: Some(3),
            failure: None,
        }],
        observed_at_ms: 1_700_000_000_200,
    };
    let page = AuditEventPageV2 {
        events: vec![AuditEventV2 {
            sequence: du64(9),
            timestamp_ms: 1_700_000_000_000,
            action: "session.authorized".to_string(),
            outcome: "allowed".to_string(),
            session_id: Some(test_session_id()),
            actor_device_id: Some(DeviceId("local-device".to_string())),
            peer_device_id: Some(test_device_id()),
            peer_key_id: Some("sha256:peer-key".to_string()),
            transport_kind: Some(RemoteRouteKind::LanQuic),
            reason_code: None,
            metadata: AuditEventMetadataV2 {
                authorization_state: Some(RemoteAuthorizationState::Granted),
                access_mode: Some(RemoteAccessMode::Attended),
                route_state: Some(RemoteRouteState::Connected),
                media_state: Some(RemoteMediaState::Streaming),
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                granted_scopes: vec![RemotePermissionScope::ScreenView],
                policy_revision: Some(du64(8)),
                trust_revision: Some(du64(9)),
            },
        }],
        next_after_sequence: Some(du64(9)),
        cursor_state: RemoteCursorState::Current,
        has_more: false,
        chain_verified: true,
    };
    let failure = RemoteFailure {
        code: RemoteReasonCode::TrustRequired,
        message: "peer approval is required".to_string(),
        suggested_action: Some("approve the peer key".to_string()),
    };
    let responses = vec![
        (
            IpcResponse::RemoteSession {
                session: session.clone(),
            },
            "RemoteSession",
        ),
        (
            IpcResponse::RemoteSessionRequested {
                session: session.clone(),
            },
            "RemoteSessionRequested",
        ),
        (
            IpcResponse::ConsentRecorded {
                session: session.clone(),
            },
            "ConsentRecorded",
        ),
        (
            IpcResponse::UnattendedAccessUpdated { access },
            "UnattendedAccessUpdated",
        ),
        (
            IpcResponse::TrustedDeviceList {
                devices: vec![device.clone()],
            },
            "TrustedDeviceList",
        ),
        (
            IpcResponse::TrustedDeviceUpdated { device },
            "TrustedDeviceUpdated",
        ),
        (
            IpcResponse::SessionPermissionsChanged {
                session: session.clone(),
            },
            "SessionPermissionsChanged",
        ),
        (
            IpcResponse::SessionEventsSubscribed { subscription },
            "SessionEventsSubscribed",
        ),
        (
            IpcResponse::SessionEvent {
                event: event.clone(),
            },
            "SessionEvent",
        ),
        (IpcResponse::RouteEvidence { evidence }, "RouteEvidence"),
        (IpcResponse::AuditEventsV2 { page }, "AuditEventsV2"),
        (
            IpcResponse::RemoteAccessError {
                session_id: Some(test_session_id()),
                peer_key_id: Some("sha256:peer-key".to_string()),
                failure,
            },
            "RemoteAccessError",
        ),
    ];

    for (response, expected_type) in responses {
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["type"], serde_json::json!(expected_type));
        let encoded = serde_json::to_string(&value).unwrap().to_ascii_lowercase();
        for forbidden in [
            "private_key",
            "protected_blob",
            "credential",
            "password",
            "secret",
            "proof",
            "verifier",
            "database_id",
            "row_id",
            "event_hash",
            "hmac",
        ] {
            assert!(!encoded.contains(forbidden), "response exposed {forbidden}");
        }
        assert_eq!(
            serde_json::from_value::<IpcResponse>(value).unwrap(),
            response
        );
    }
    assert_eq!(
        serde_json::to_value(event.event).unwrap()["kind"],
        serde_json::json!("permissions_changed")
    );
}

#[test]
fn decimal_u64_is_canonical_and_lossless() {
    let maximum = DecimalU64::new(u64::MAX);
    assert_eq!(
        serde_json::to_string(&maximum).unwrap(),
        format!("\"{}\"", u64::MAX)
    );
    assert_eq!(
        serde_json::from_str::<DecimalU64>(&format!("\"{}\"", u64::MAX)).unwrap(),
        maximum
    );

    for invalid in ["-1", "+1", "01", "1e3", "18446744073709551616", ""] {
        assert!(serde_json::from_str::<DecimalU64>(&format!("\"{invalid}\"")).is_err());
    }
    assert!(serde_json::from_str::<DecimalU64>("1").is_err());
}

#[test]
fn all_domain_permission_scopes_have_exact_wire_projections() {
    use mrd_session::PermissionScope as Domain;

    let pairs = [
        (Domain::ScreenView, RemotePermissionScope::ScreenView),
        (Domain::InputPointer, RemotePermissionScope::InputPointer),
        (Domain::InputKeyboard, RemotePermissionScope::InputKeyboard),
        (Domain::ClipboardRead, RemotePermissionScope::ClipboardRead),
        (
            Domain::ClipboardWrite,
            RemotePermissionScope::ClipboardWrite,
        ),
        (Domain::FileRead, RemotePermissionScope::FileRead),
        (Domain::FileWrite, RemotePermissionScope::FileWrite),
        (Domain::AudioListen, RemotePermissionScope::AudioListen),
        (Domain::AudioTalk, RemotePermissionScope::AudioTalk),
        (Domain::DisplaySwitch, RemotePermissionScope::DisplaySwitch),
        (
            Domain::DisplayMultiView,
            RemotePermissionScope::DisplayMultiView,
        ),
        (Domain::PowerRestart, RemotePermissionScope::PowerRestart),
        (Domain::PowerShutdown, RemotePermissionScope::PowerShutdown),
        (Domain::TerminalOpen, RemotePermissionScope::TerminalOpen),
        (
            Domain::PrivacyBlockLocalInput,
            RemotePermissionScope::PrivacyBlockLocalInput,
        ),
        (
            Domain::PrivacyBlankScreen,
            RemotePermissionScope::PrivacyBlankScreen,
        ),
        (
            Domain::SecureDesktopView,
            RemotePermissionScope::SecureDesktopView,
        ),
        (
            Domain::SecureDesktopControl,
            RemotePermissionScope::SecureDesktopControl,
        ),
    ];

    for (domain, wire) in pairs {
        assert_eq!(RemotePermissionScope::from(domain), wire);
        assert_eq!(Domain::from(wire), domain);
    }
}

#[test]
fn remote_session_event_tags_are_exhaustive_and_stable() {
    fn expected_kind(event: &RemoteSessionEvent) -> &'static str {
        match event {
            RemoteSessionEvent::ConsentRequested { .. } => "consent_requested",
            RemoteSessionEvent::ConsentResolved { .. } => "consent_resolved",
            RemoteSessionEvent::AuthorizationChanged { .. } => "authorization_changed",
            RemoteSessionEvent::PermissionsChanged { .. } => "permissions_changed",
            RemoteSessionEvent::TrustChanged { .. } => "trust_changed",
            RemoteSessionEvent::RouteChanged { .. } => "route_changed",
            RemoteSessionEvent::MediaChanged { .. } => "media_changed",
            RemoteSessionEvent::SessionClosed { .. } => "session_closed",
        }
    }

    let failure = RemoteFailure {
        code: RemoteReasonCode::RouteLost,
        message: "route was lost".to_string(),
        suggested_action: Some("retry a policy-allowed route".to_string()),
    };
    let events = [
        RemoteSessionEvent::ConsentRequested {
            requested_scopes: vec![RemotePermissionScope::ScreenView],
        },
        RemoteSessionEvent::ConsentResolved {
            decision: ConsentDecision::Approve,
            approved_scopes: vec![RemotePermissionScope::ScreenView],
        },
        RemoteSessionEvent::AuthorizationChanged {
            state: RemoteAuthorizationState::Granted,
            failure: None,
        },
        RemoteSessionEvent::PermissionsChanged {
            granted_scopes: vec![RemotePermissionScope::ScreenView],
            policy_revision: du64(7),
        },
        RemoteSessionEvent::TrustChanged {
            peer_key_id: "sha256:peer-key".to_string(),
            state: TrustedDeviceState::Trusted,
            trust_revision: du64(9),
        },
        RemoteSessionEvent::RouteChanged {
            state: RemoteRouteState::Failed,
            route: Some(RemoteRouteKind::WebRtcDirect),
            failure: Some(failure.clone()),
        },
        RemoteSessionEvent::MediaChanged {
            state: RemoteMediaState::Degraded,
            failure: Some(failure.clone()),
        },
        RemoteSessionEvent::SessionClosed {
            failure: Some(failure),
        },
    ];

    for event in events {
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["kind"], serde_json::json!(expected_kind(&event)));
        assert_eq!(
            serde_json::from_value::<RemoteSessionEvent>(value).unwrap(),
            event
        );
    }
}
