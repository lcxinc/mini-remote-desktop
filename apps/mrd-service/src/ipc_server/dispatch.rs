use super::{
    audit::{audit_outcome, security_store_unavailable_response},
    IpcServer,
};
use crate::handlers::control;
use crate::handlers::{
    capability, device, files, identity, lan, preflight, session, shell as shell_handlers,
    telemetry, transport as transport_handlers,
};
use mrd_ipc::{IpcRequest, IpcResponse};

pub(super) async fn dispatch_request(server: &IpcServer, request: IpcRequest) -> IpcResponse {
    server.dispatch_request_inner(request).await
}

impl IpcServer {
    async fn dispatch_request_inner(&self, request: IpcRequest) -> IpcResponse {
        let mut security_unhealthy = !self.app_state.security_is_healthy();
        if security_unhealthy && !allowed_when_security_unhealthy(&request) {
            return security_store_unavailable_response();
        }
        if !security_unhealthy
            && requires_durable_audit_preflight(&request)
            && self.verify_audit_integrity().await.is_err()
        {
            security_unhealthy = true;
            if !is_emergency_safety_command(&request) {
                return security_store_unavailable_response();
            }
        }
        match request {
            IpcRequest::RegisterDevice {
                device_id,
                device_name,
            } => {
                let response =
                    device::register_device(&self.app_state, device_id.clone(), device_name).await;
                if !security_unhealthy
                    && self
                        .record_audit_event(
                            "device.register",
                            "success",
                            None,
                            Some(device_id.clone()),
                            None,
                            None,
                            None,
                            Vec::new(),
                        )
                        .await
                        .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::ListDevices => device::list_devices(&self.app_state).await,

            IpcRequest::GetDevicePreferences => {
                device::list_device_preferences(&self.app_state).await
            }

            IpcRequest::UpdateDevicePreference { device_id, update } => {
                device::update_device_preference(&self.app_state, device_id, update).await
            }

            IpcRequest::LanDiscoverySnapshot => lan::lan_discovery_snapshot(&self.app_state).await,

            IpcRequest::RefreshLanDiscovery => lan::refresh_lan_discovery(&self.app_state).await,

            IpcRequest::ListDirectory { path } => files::list_directory(path),

            IpcRequest::StartFileTransfer { request } => {
                files::start_file_transfer(&self.app_state, request).await
            }

            IpcRequest::ListFileTransfers => files::list_file_transfers(&self.app_state).await,

            IpcRequest::ListFileTransferProviders => files::list_file_transfer_providers(),

            IpcRequest::CancelFileTransfer { transfer_id } => {
                files::cancel_file_transfer(&self.app_state, transfer_id).await
            }

            IpcRequest::WakeOnLan {
                device_id,
                mac_address,
                broadcast_addr,
            } => device::wake_on_lan(device_id, mac_address, broadcast_addr),

            IpcRequest::RequestRemoteDevicePowerAction { device_id, action } => {
                device::request_remote_device_power_action(&self.app_state, device_id, action).await
            }

            IpcRequest::ListSessions => session::list_sessions(&self.app_state).await,

            IpcRequest::ListTrustedDevices { include_revoked } => {
                identity::list_trusted_devices(&self.app_state, include_revoked).await
            }

            IpcRequest::ApproveTrustedDevice { .. } => IpcResponse::Error {
                code: "E_AUTHENTICATED_PEER_REQUIRED".to_string(),
                message: "trusted-device approval requires an authenticated pending peer key"
                    .to_string(),
            },

            IpcRequest::SuspendTrustedDevice {
                peer_key_id,
                expected_trust_revision,
            } => {
                identity::suspend_trusted_device(
                    &self.app_state,
                    peer_key_id,
                    expected_trust_revision.get(),
                )
                .await
            }

            IpcRequest::RevokeTrustedDevice {
                peer_key_id,
                expected_trust_revision,
            } => {
                identity::revoke_trusted_device(
                    &self.app_state,
                    peer_key_id,
                    expected_trust_revision.get(),
                )
                .await
            }

            IpcRequest::GetRemoteSession { session_id } => {
                session::get_remote_session(&self.app_state, session_id).await
            }

            IpcRequest::GetRouteEvidence { session_id } => {
                session::get_route_evidence(&self.app_state, session_id).await
            }

            IpcRequest::GetAuditEventsV2 { query } => {
                telemetry::audit_events_v2(&self.app_state, query).await
            }

            IpcRequest::RespondToConsent { response } => {
                session::respond_to_consent(&self.app_state, response).await
            }

            IpcRequest::SubscribeSessionEvents { query } => {
                session::subscribe_session_events(&self.app_state, query).await
            }

            IpcRequest::RequestRemoteSession { request } => {
                let session_id = request.session_id.clone();
                let target_device_id = request.target_device_id.clone();
                let mut details = vec![(
                    "requested_scopes".to_string(),
                    serde_json::to_string(&request.requested_scopes)
                        .unwrap_or_else(|_| "[]".to_string()),
                )];
                if let Some(access_mode) = audit_wire_name(&request.access_mode) {
                    details.push(("access_mode".to_string(), access_mode));
                }
                if let Some(profile) = request.requested_profile.as_ref() {
                    details.push((
                        "requested_profile".to_string(),
                        format!(
                            "{}x{}@{}/{}Mbps/{}",
                            profile.width,
                            profile.height,
                            profile.fps,
                            profile.bitrate_mbps,
                            profile.codec
                        ),
                    ));
                }
                let selected_route =
                    session::resolve_remote_session_route(&self.app_state, &request).await;
                let response = session::request_remote_session_on_route(
                    &self.app_state,
                    request,
                    selected_route,
                )
                .await;
                if let Some(snapshot) = self
                    .app_state
                    .session_authorizations
                    .snapshot(&session_id)
                    .await
                {
                    details.push(("peer_key_id".to_string(), snapshot.peer_key_id));
                    if let Some(state) = audit_wire_name(&snapshot.authorization_state) {
                        details.push(("authorization_state".to_string(), state));
                    }
                    if let Some(state) = audit_wire_name(&snapshot.route_state) {
                        details.push(("route_state".to_string(), state));
                    }
                    if let Some(state) = audit_wire_name(&snapshot.media_state) {
                        details.push(("media_state".to_string(), state));
                    }
                    details.push((
                        "granted_scopes".to_string(),
                        serde_json::to_string(&snapshot.granted_scopes)
                            .unwrap_or_else(|_| "[]".to_string()),
                    ));
                    details.push((
                        "policy_revision".to_string(),
                        snapshot.policy_revision.get().to_string(),
                    ));
                }
                let session_kind = match selected_route {
                    crate::wan_session::media::WanRouteSelection::Lan => SessionStartKind::Lan,
                    crate::wan_session::media::WanRouteSelection::WanRelay => SessionStartKind::Wan,
                };
                self.finish_session_start_audit(
                    response,
                    session_id,
                    target_device_id,
                    session_kind,
                    details,
                )
                .await
            }

            IpcRequest::EnableUnattendedAccess { policy } => {
                session::enable_unattended_access(&self.app_state, policy).await
            }

            IpcRequest::DisableUnattendedAccess {
                expected_policy_revision,
            } => {
                session::disable_unattended_access(&self.app_state, expected_policy_revision.get())
                    .await
            }

            IpcRequest::RotateUnattendedAccess {
                expected_policy_revision,
            } => {
                session::rotate_unattended_access(&self.app_state, expected_policy_revision.get())
                    .await
            }

            IpcRequest::RotateTrustedDevice { .. }
            | IpcRequest::ChangeSessionPermissions { .. } => IpcResponse::Error {
                code: "E_SECURE_REMOTE_UNAVAILABLE".to_string(),
                message: "secure remote session operations are unavailable in this service build"
                    .to_string(),
            },

            IpcRequest::StartSession {
                session_id,
                target_device_id,
                transport_kind,
            } => {
                let response = match preflight::preflight_session_start(
                    &self.app_state,
                    &target_device_id,
                    &transport_kind,
                    None,
                    false,
                )
                .await
                {
                    Ok(()) => {
                        session::start_session(
                            &self.app_state,
                            session_id.clone(),
                            target_device_id.clone(),
                            transport_kind.clone(),
                        )
                        .await
                    }
                    Err(message) => IpcResponse::Error {
                        code: "E_PREFLIGHT".to_string(),
                        message,
                    },
                };
                let (outcome, reason) = audit_outcome(&response);
                if !security_unhealthy
                    && self
                        .record_audit_event(
                            "session.start",
                            outcome,
                            Some(session_id),
                            self.local_device_id().await,
                            Some(target_device_id),
                            Some(transport_kind),
                            reason,
                            Vec::new(),
                        )
                        .await
                        .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::StartLanRemoteSession {
                session_id,
                target_device_id,
                transport_kind,
                requested_profile,
            } => {
                let mut details = Vec::new();
                if let Some(profile) = requested_profile.as_ref() {
                    details.push((
                        "requested_profile".to_string(),
                        format!(
                            "{}x{}@{}/{}Mbps/{}",
                            profile.width,
                            profile.height,
                            profile.fps,
                            profile.bitrate_mbps,
                            profile.codec
                        ),
                    ));
                }
                let response = match preflight::preflight_session_start(
                    &self.app_state,
                    &target_device_id,
                    &transport_kind,
                    requested_profile.as_ref(),
                    true,
                )
                .await
                {
                    Ok(()) => {
                        session::start_lan_remote_session(
                            &self.app_state,
                            session_id.clone(),
                            target_device_id.clone(),
                            transport_kind.clone(),
                            requested_profile,
                        )
                        .await
                    }
                    Err(message) => IpcResponse::Error {
                        code: "E_PREFLIGHT".to_string(),
                        message,
                    },
                };
                self.finish_session_start_audit(
                    response,
                    session_id,
                    target_device_id,
                    SessionStartKind::Lan,
                    details,
                )
                .await
            }

            IpcRequest::UpdateMediaProfile {
                session_id,
                requested_profile,
            } => {
                session::update_media_profile(&self.app_state, session_id, requested_profile).await
            }

            IpcRequest::ConfigureMediaAdaptation { session_id, config } => {
                session::configure_media_adaptation(&self.app_state, session_id, config).await
            }

            IpcRequest::ListLocalCaptureSources {
                include_previews,
                limit,
            } => match crate::capture_source::list_capture_sources(include_previews, limit) {
                Ok(sources) => IpcResponse::LocalCaptureSourceList { sources },
                Err(error) => IpcResponse::Error {
                    code: "CAPTURE_SOURCE_LIST_FAILED".to_string(),
                    message: error.to_string(),
                },
            },

            IpcRequest::ListRemoteCaptureSources {
                session_id,
                include_previews,
                limit,
            } => {
                session::list_remote_capture_sources(
                    &self.app_state,
                    session_id,
                    include_previews,
                    limit,
                )
                .await
            }

            IpcRequest::SelectRemoteCaptureSource {
                session_id,
                source_id,
            } => {
                session::select_remote_capture_source(&self.app_state, session_id, source_id).await
            }

            IpcRequest::ListRemoteDisplayModes { session_id } => {
                session::list_remote_display_modes(&self.app_state, session_id).await
            }

            IpcRequest::SetRemoteDisplayMode {
                session_id,
                mode,
                restore_after_session,
            } => {
                session::set_remote_display_mode(
                    &self.app_state,
                    session_id,
                    mode,
                    restore_after_session,
                )
                .await
            }

            IpcRequest::RestoreRemoteDisplayMode { session_id } => {
                session::restore_remote_display_mode(&self.app_state, session_id).await
            }

            IpcRequest::AttachRenderSurface {
                session_id,
                surface_id,
                backend,
                window_handle,
                render_proxy_endpoint,
            } => {
                transport_handlers::attach_render_surface(
                    &self.app_state,
                    session_id,
                    surface_id,
                    backend,
                    window_handle,
                    render_proxy_endpoint,
                )
                .await
            }

            IpcRequest::DetachRenderSurface {
                session_id,
                surface_id,
            } => {
                transport_handlers::detach_render_surface(&self.app_state, session_id, surface_id)
                    .await
            }

            IpcRequest::AcceptSession {
                session_id,
                source_device_id,
            } => {
                let response = session::accept_session(
                    &self.app_state,
                    session_id.clone(),
                    source_device_id.clone(),
                )
                .await;
                let (outcome, reason) = audit_outcome(&response);
                if self
                    .record_audit_event(
                        "session.accept",
                        outcome,
                        Some(session_id),
                        self.local_device_id().await,
                        Some(source_device_id),
                        None,
                        reason,
                        Vec::new(),
                    )
                    .await
                    .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::StartSender { session_id } => {
                transport_handlers::start_sender(&self.app_state, session_id).await
            }

            IpcRequest::StartReceiver { session_id } => {
                transport_handlers::start_receiver(&self.app_state, session_id).await
            }

            IpcRequest::StopSession { session_id } => {
                let (peer_device_id, transport_kind) =
                    self.session_audit_context(&session_id).await;
                let response = session::stop_session(&self.app_state, session_id.clone()).await;
                let (outcome, reason) = audit_outcome(&response);
                if !security_unhealthy
                    && self
                        .record_audit_event(
                            "session.stop",
                            outcome,
                            Some(session_id),
                            self.local_device_id().await,
                            peer_device_id,
                            transport_kind,
                            reason,
                            Vec::new(),
                        )
                        .await
                        .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::FailSession { session_id, reason } => {
                let (peer_device_id, transport_kind) =
                    self.session_audit_context(&session_id).await;
                let response =
                    session::fail_session(&self.app_state, session_id.clone(), reason.clone())
                        .await;
                let (outcome, response_reason) = audit_outcome(&response);
                if !security_unhealthy
                    && self
                        .record_audit_event(
                            "session.fail",
                            outcome,
                            Some(session_id),
                            self.local_device_id().await,
                            peer_device_id,
                            transport_kind,
                            response_reason.or(Some("session_failed".to_string())),
                            Vec::new(),
                        )
                        .await
                        .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::RecoverSession { session_id } => {
                let (peer_device_id, transport_kind) =
                    self.session_audit_context(&session_id).await;
                let response = session::recover_session(&self.app_state, session_id.clone()).await;
                let (outcome, reason) = audit_outcome(&response);
                if self
                    .record_audit_event(
                        "session.recover",
                        outcome,
                        Some(session_id),
                        self.local_device_id().await,
                        peer_device_id,
                        transport_kind,
                        reason,
                        Vec::new(),
                    )
                    .await
                    .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::SessionRuntimeSnapshot { session_id } => {
                session::session_snapshot(&self.app_state, session_id).await
            }

            IpcRequest::RuntimeSnapshot => session::runtime_snapshot(&self.app_state).await,

            IpcRequest::AuditLog { query } => telemetry::audit_log(&self.app_state, query).await,

            IpcRequest::CapabilitySnapshot => {
                capability::capability_snapshot(&self.app_state).await
            }

            IpcRequest::EvaluateScenarioProfile {
                scenario_id,
                peer_device_id,
                requested_profile,
            } => {
                capability::evaluate_scenario_profile(
                    &self.app_state,
                    scenario_id,
                    peer_device_id,
                    requested_profile,
                )
                .await
            }

            IpcRequest::GetPeerCapabilitySnapshot { peer_device_id } => {
                capability::peer_capability_snapshot(&self.app_state, peer_device_id).await
            }

            IpcRequest::SetTransportPolicy { session_id, policy } => {
                control::set_transport_policy(session_id, policy)
            }

            IpcRequest::GetControlChannelSnapshot { session_id } => {
                control::control_channel_snapshot(&self.app_state, session_id).await
            }

            IpcRequest::SendControlInput { session_id, event } => {
                let authorization = self
                    .app_state
                    .session_authorizations
                    .snapshot(&session_id)
                    .await;
                let response =
                    session::send_control_input(&self.app_state, session_id.clone(), event).await;
                if let IpcResponse::RemoteAccessError { failure, .. } = &response {
                    let peer_device_id = authorization
                        .as_ref()
                        .map(|snapshot| snapshot.peer_device_id.clone());
                    if self
                        .record_audit_event(
                            "session.control_input_decision",
                            "denied",
                            Some(session_id),
                            self.local_device_id().await,
                            peer_device_id,
                            Some("lan_quic".to_string()),
                            Some(crate::lan_discovery::remote_reason_code_wire_name(
                                failure.code,
                            )),
                            Vec::new(),
                        )
                        .await
                        .is_err()
                    {
                        return security_store_unavailable_response();
                    }
                }
                response
            }

            IpcRequest::CrossE2EInjectFault {
                session_id,
                fault_type,
                duration_ms,
            } => {
                session::cross_e2e_inject_fault(
                    &self.app_state,
                    session_id,
                    fault_type,
                    duration_ms,
                )
                .await
            }

            IpcRequest::PairDevice {
                device_id,
                certificate_fingerprint,
            } => {
                let response = identity::pair_device(
                    &self.app_state,
                    device_id.clone(),
                    certificate_fingerprint,
                )
                .await;
                let (outcome, reason) = audit_outcome(&response);
                if self
                    .record_audit_event(
                        "device.pair",
                        outcome,
                        None,
                        self.local_device_id().await,
                        Some(device_id),
                        None,
                        reason,
                        Vec::new(),
                    )
                    .await
                    .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::ApprovePairing { device_id } => {
                let response = identity::approve_pairing(&self.app_state, device_id.clone()).await;
                let (outcome, reason) = audit_outcome(&response);
                if self
                    .record_audit_event(
                        "device.approve_pairing",
                        outcome,
                        None,
                        self.local_device_id().await,
                        Some(device_id),
                        None,
                        reason,
                        Vec::new(),
                    )
                    .await
                    .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::RevokeDevice { device_id } => {
                let response = identity::revoke_device(&self.app_state, device_id.clone()).await;
                let (outcome, reason) = audit_outcome(&response);
                if self
                    .record_audit_event(
                        "device.revoke",
                        outcome,
                        None,
                        self.local_device_id().await,
                        Some(device_id),
                        None,
                        reason,
                        Vec::new(),
                    )
                    .await
                    .is_err()
                {
                    return security_store_unavailable_response();
                }
                response
            }

            IpcRequest::GetDeviceIdentitySnapshot => {
                identity::get_device_identity_snapshot(&self.app_state).await
            }

            IpcRequest::GetTelemetryBundle { run_id, session_id } => {
                telemetry::telemetry_bundle(run_id, session_id)
            }

            IpcRequest::MediaPipelineSnapshot { session_id } => {
                transport_handlers::media_pipeline_snapshot(&self.app_state, session_id).await
            }

            IpcRequest::ServiceHealth => telemetry::service_health(&self.app_state),

            IpcRequest::ProbeSnapshot { session_id } => {
                transport_handlers::probe_snapshot(&self.app_state, session_id).await
            }

            IpcRequest::StreamProbeEvents => telemetry::stream_probe_events(),

            IpcRequest::OpenUi { reason } => shell_handlers::open_ui(&self.ui_launcher, reason),

            IpcRequest::FocusUi => shell_handlers::focus_ui(&self.ui_launcher),

            IpcRequest::UiAttached {
                pid,
                executable_path,
            } => {
                shell_handlers::ui_attached(
                    &self.app_state,
                    &self.ui_launcher,
                    pid,
                    executable_path,
                )
                .await
            }

            IpcRequest::UiDetached { pid, reason } => {
                shell_handlers::ui_detached(&self.app_state, pid, reason).await
            }

            IpcRequest::GetShellStatus => shell_handlers::shell_status(&self.app_state).await,

            IpcRequest::SetAutostart { enabled } => {
                shell_handlers::set_autostart(&self.app_state, &self.autostart, enabled).await
            }

            IpcRequest::GetAutostartStatus => shell_handlers::autostart_status(&self.autostart),

            IpcRequest::ShutdownService { mode } => shell_handlers::shutdown_service(mode),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionStartKind {
    Lan,
    Wan,
}

impl SessionStartKind {
    fn audit_action(self) -> &'static str {
        match self {
            Self::Lan => "session.start_lan",
            Self::Wan => "session.start_wan",
        }
    }

    fn transport_kind(self) -> &'static str {
        match self {
            Self::Lan => "lan_quic",
            Self::Wan => "webrtc_relay",
        }
    }
}

impl IpcServer {
    async fn finish_session_start_audit(
        &self,
        response: IpcResponse,
        session_id: mrd_proto::SessionId,
        target_device_id: mrd_proto::DeviceId,
        session_kind: SessionStartKind,
        details: Vec<(String, String)>,
    ) -> IpcResponse {
        let action = session_kind.audit_action();
        let (outcome, reason) = audit_outcome(&response);
        if self
            .record_audit_event(
                action,
                outcome,
                Some(session_id.clone()),
                self.local_device_id().await,
                Some(target_device_id),
                Some(session_kind.transport_kind().to_owned()),
                reason,
                details,
            )
            .await
            .is_err()
        {
            let failed_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let _authorization_guard = self.app_state.authorization_security_gate.lock().await;
            let _ = self
                .app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    mrd_ipc::RemoteAuthorizationState::Revoked,
                    mrd_ipc::RemoteFailure {
                        code: mrd_ipc::RemoteReasonCode::PolicyChanged,
                        message: "session start could not be durably audited".to_string(),
                        suggested_action: Some(
                            "repair the local security store before reconnecting".to_string(),
                        ),
                    },
                    failed_at_ms,
                )
                .await;
            match session_kind {
                SessionStartKind::Lan => {
                    crate::lan_discovery::terminate_authorized_remote_sessions_under_security_gate(
                        &self.app_state,
                        std::slice::from_ref(&session_id),
                    )
                    .await;
                }
                SessionStartKind::Wan => {
                    match crate::wan_session::service::terminalize_wan_session_under_security_gate(
                        &self.app_state,
                        &session_id,
                        crate::wan_session::service::ServiceWanTerminalRequest::Fail {
                            failure: crate::wan_session::model::WanSessionFailure::Internal,
                            remote_failure: mrd_ipc::RemoteFailure {
                                code: mrd_ipc::RemoteReasonCode::PolicyChanged,
                                message: "session start could not be durably audited".to_owned(),
                                suggested_action: Some(
                                    "repair the local security store before reconnecting"
                                        .to_owned(),
                                ),
                            },
                        },
                    )
                    .await
                    {
                        Ok(Some(_)) => {}
                        Ok(None) | Err(_) => {
                            tracing::error!(
                                session_id = %session_id.0,
                                "session audit failure left WAN cleanup incomplete"
                            );
                        }
                    }
                }
            }
            return security_store_unavailable_response();
        }
        response
    }
}

fn audit_wire_name<T: serde::Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()?
        .as_str()
        .map(str::to_string)
}

fn allowed_when_security_unhealthy(request: &IpcRequest) -> bool {
    matches!(
        request,
        IpcRequest::ServiceHealth
            | IpcRequest::ListSessions
            | IpcRequest::SessionRuntimeSnapshot { .. }
            | IpcRequest::RuntimeSnapshot
            | IpcRequest::StopSession { .. }
            | IpcRequest::FailSession { .. }
            | IpcRequest::SuspendTrustedDevice { .. }
            | IpcRequest::RevokeTrustedDevice { .. }
            | IpcRequest::GetShellStatus
            | IpcRequest::ShutdownService { .. }
    )
}

fn requires_durable_audit_preflight(request: &IpcRequest) -> bool {
    matches!(
        request,
        IpcRequest::RegisterDevice { .. }
            | IpcRequest::RequestRemoteSession { .. }
            | IpcRequest::RespondToConsent { .. }
            | IpcRequest::EnableUnattendedAccess { .. }
            | IpcRequest::DisableUnattendedAccess { .. }
            | IpcRequest::RotateUnattendedAccess { .. }
            | IpcRequest::StartSession { .. }
            | IpcRequest::StartLanRemoteSession { .. }
            | IpcRequest::AcceptSession { .. }
            | IpcRequest::StopSession { .. }
            | IpcRequest::FailSession { .. }
            | IpcRequest::RecoverSession { .. }
            | IpcRequest::PairDevice { .. }
            | IpcRequest::ApprovePairing { .. }
            | IpcRequest::RevokeDevice { .. }
    )
}

fn is_emergency_safety_command(request: &IpcRequest) -> bool {
    matches!(
        request,
        IpcRequest::StopSession { .. } | IpcRequest::FailSession { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::{dispatch_request, SessionStartKind};
    use crate::app_state::AppState;
    use crate::ipc_server::IpcServer;
    use crate::session_authorization::VerifiedIncomingAuthorizationRequest;
    use mrd_application::ports::{SessionLifecycleState, SessionSnapshot};
    use mrd_ipc::{
        AuditLogQuery, DecimalU64, IpcRequest, IpcResponse, RemoteAccessMode,
        RemotePermissionScope, RemoteReasonCode,
    };
    use mrd_proto::{DeviceId, SessionId};
    use std::sync::Arc;

    #[tokio::test]
    async fn dispatch_request_routes_capability_snapshot_without_accept_loop() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state);

        let response = dispatch_request(&server, IpcRequest::CapabilitySnapshot).await;

        assert!(matches!(response, IpcResponse::CapabilitySnapshot { .. }));
    }

    #[tokio::test]
    async fn unsupported_secure_remote_mutations_remain_fail_closed() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state);
        let requests = [
            serde_json::json!({"type":"ApproveTrustedDevice","approval":{"peer_key_id":"sha256:peer","key_epoch":"2","permission_ceiling":["screen.view"]}}),
            serde_json::json!({"type":"RotateTrustedDevice","rotation":{"peer_key_id":"sha256:peer","new_peer_key_id":"sha256:new-peer","new_key_epoch":"3","expected_trust_revision":"9"}}),
            serde_json::json!({"type":"ChangeSessionPermissions","change":{"session_id":"session-1","requested_scopes":["screen.view"],"expected_policy_revision":"7"}}),
        ]
        .into_iter()
        .map(|value| serde_json::from_value::<IpcRequest>(value).expect("valid secure request"));

        for request in requests {
            assert!(request.is_secure_remote());
            let response = dispatch_request(&server, request).await;
            assert!(matches!(response, IpcResponse::Error { .. }));
        }
    }

    #[tokio::test]
    async fn task18_secure_remote_handlers_are_reachable() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state);

        assert!(matches!(
            dispatch_request(
                &server,
                IpcRequest::GetRemoteSession {
                    session_id: mrd_proto::SessionId("missing".to_string()),
                },
            )
            .await,
            IpcResponse::Error { .. }
        ));
        assert!(matches!(
            dispatch_request(
                &server,
                IpcRequest::SubscribeSessionEvents {
                    query: mrd_ipc::SessionEventSubscriptionQuery {
                        session_id: None,
                        after_sequence: None,
                        limit: 16,
                        wait_timeout_ms: 0,
                    },
                },
            )
            .await,
            IpcResponse::SessionEventsSubscribed { .. }
        ));
    }

    #[tokio::test]
    async fn unattended_enrollment_and_rotation_fail_closed_until_task40() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state);

        let enabled = dispatch_request(
            &server,
            IpcRequest::EnableUnattendedAccess {
                policy: mrd_ipc::UnattendedAccessPolicy {
                    trusted_devices_only: true,
                    allowed_peer_key_ids: vec!["sha256:peer".to_string()],
                    permission_ceiling: vec![mrd_ipc::RemotePermissionScope::ScreenView],
                    expires_at_ms: None,
                },
            },
        )
        .await;
        let IpcResponse::RemoteAccessError { failure, .. } = enabled else {
            panic!("unattended enrollment must fail closed, got {enabled:?}");
        };
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
        assert!(failure.message.contains("enrollment"));

        let rotated = dispatch_request(
            &server,
            IpcRequest::RotateUnattendedAccess {
                expected_policy_revision: DecimalU64::new(1),
            },
        )
        .await;
        let IpcResponse::RemoteAccessError { failure, .. } = rotated else {
            panic!("unattended rotation must fail closed, got {rotated:?}");
        };
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
        assert!(failure.message.contains("enrollment"));

        let disabled = dispatch_request(
            &server,
            IpcRequest::DisableUnattendedAccess {
                expected_policy_revision: DecimalU64::new(1),
            },
        )
        .await;
        let IpcResponse::UnattendedAccessUpdated { access } = disabled else {
            panic!("failed enable must leave the default policy disable-able, got {disabled:?}");
        };
        assert!(!access.enabled);
    }

    #[tokio::test]
    async fn unattended_session_request_fails_before_lan_request_without_enrollment() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state.clone());
        let session_id = SessionId("unattended-without-enrollment".to_string());

        let response = dispatch_request(
            &server,
            IpcRequest::RequestRemoteSession {
                request: mrd_ipc::RemoteSessionRequest {
                    session_id: session_id.clone(),
                    target_device_id: DeviceId("missing-target".to_string()),
                    route_preference: mrd_ipc::RemoteRoutePreference::Auto,
                    access_mode: RemoteAccessMode::Unattended,
                    requested_scopes: vec![RemotePermissionScope::ScreenView],
                    requested_profile: None,
                },
            },
        )
        .await;

        let IpcResponse::RemoteAccessError {
            session_id: response_session_id,
            peer_key_id,
            failure,
        } = response
        else {
            panic!("unattended request must fail closed, got {response:?}");
        };
        assert_eq!(response_session_id, Some(session_id.clone()));
        assert_eq!(peer_key_id, None);
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
        assert!(failure.message.contains("enrollment"));
        assert!(app_state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .is_none());
        assert!(app_state.sessions.lock().await.get(&session_id).is_none());
    }

    #[tokio::test]
    async fn attended_remote_session_rejection_emits_typed_lan_lifecycle_audit() {
        let app_state = Arc::new(AppState::new());
        let controller_id = DeviceId("audit-controller".to_string());
        app_state
            .devices
            .lock()
            .await
            .register(controller_id.clone(), "Audit Controller".to_string());
        let server = IpcServer::new(app_state.clone());
        let session_id = SessionId("audited-secure-request".to_string());
        let target_device_id = DeviceId("untrusted-target".to_string());

        let response = dispatch_request(
            &server,
            IpcRequest::RequestRemoteSession {
                request: mrd_ipc::RemoteSessionRequest {
                    session_id: session_id.clone(),
                    target_device_id: target_device_id.clone(),
                    route_preference: mrd_ipc::RemoteRoutePreference::Lan,
                    access_mode: RemoteAccessMode::Attended,
                    requested_scopes: vec![
                        RemotePermissionScope::ScreenView,
                        RemotePermissionScope::InputPointer,
                        RemotePermissionScope::InputKeyboard,
                    ],
                    requested_profile: None,
                },
            },
        )
        .await;

        let IpcResponse::RemoteAccessError { failure, .. } = response else {
            panic!("untrusted target must be rejected, got {response:?}");
        };
        assert_eq!(failure.code, RemoteReasonCode::TrustRequired);
        let events = app_state
            .audit_log
            .query(&AuditLogQuery {
                session_id: Some(session_id),
                action: Some("session.start_lan".to_string()),
                limit: Some(8),
            })
            .expect("query secure request audit");
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.outcome, "denied");
        assert_eq!(event.actor_device_id.as_ref(), Some(&controller_id));
        assert_eq!(event.peer_device_id.as_ref(), Some(&target_device_id));
        assert_eq!(event.transport_kind.as_deref(), Some("lan_quic"));
        assert_eq!(event.reason.as_deref(), Some("trust_required"));
    }

    #[tokio::test]
    async fn lan_start_audit_append_failure_terminates_started_media() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state.clone());
        let session_id = SessionId("unaudited-start-cleanup".to_string());
        let target_device_id = DeviceId("audit-failure-target".to_string());
        app_state.sessions.lock().await.insert(
            session_id.clone(),
            SessionSnapshot {
                session_id: session_id.clone(),
                transport: "quic".to_string(),
                source_device_id: Some(DeviceId("audit-controller".to_string())),
                target_device_id: Some(target_device_id.clone()),
                local_listen_addr: None,
                local_server_name: None,
                local_cert_der_b64: None,
                remote_listen_addr: None,
                remote_server_name: None,
                remote_cert_der_b64: None,
                lifecycle_state: SessionLifecycleState::Streaming,
                last_error: None,
                sender_active: true,
                receiver_active: false,
            },
        );
        let media_task = tokio::spawn(std::future::pending::<()>());
        app_state
            .media_tasks
            .lock()
            .await
            .register(session_id.clone(), media_task.abort_handle());
        app_state.audit_log.fail_action("session.start_lan");

        let response = server
            .finish_session_start_audit(
                IpcResponse::SessionStarted {
                    session_id: session_id.clone(),
                },
                session_id.clone(),
                target_device_id,
                SessionStartKind::Lan,
                Vec::new(),
            )
            .await;

        let IpcResponse::Error { code, .. } = response else {
            panic!("audit append failure must fail closed, got {response:?}");
        };
        assert_eq!(code, "E_SECURITY_STORE_UNAVAILABLE");
        assert!(!app_state.security_is_healthy());
        let sessions = app_state.sessions.lock().await;
        let snapshot = sessions.get(&session_id).expect("closed session retained");
        assert_eq!(snapshot.lifecycle_state, SessionLifecycleState::Closed);
        assert!(!snapshot.sender_active);
        assert!(!snapshot.receiver_active);
        drop(sessions);
        assert_eq!(
            app_state.media_tasks.lock().await.active_count(&session_id),
            0
        );
        assert!(media_task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn wan_start_audit_failure_without_coordinator_never_falls_back_to_lan_cleanup() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(Arc::clone(&app_state));
        let session_id = SessionId("wan-audit-no-lan-fallback".to_owned());
        let target_device_id = DeviceId("wan-audit-target".to_owned());
        app_state.sessions.lock().await.insert(
            session_id.clone(),
            SessionSnapshot {
                session_id: session_id.clone(),
                transport: "quic".to_owned(),
                source_device_id: Some(DeviceId("unrelated-lan-controller".to_owned())),
                target_device_id: Some(target_device_id.clone()),
                local_listen_addr: None,
                local_server_name: None,
                local_cert_der_b64: None,
                remote_listen_addr: None,
                remote_server_name: None,
                remote_cert_der_b64: None,
                lifecycle_state: SessionLifecycleState::Streaming,
                last_error: None,
                sender_active: true,
                receiver_active: false,
            },
        );
        let media_task = tokio::spawn(std::future::pending::<()>());
        app_state
            .media_tasks
            .lock()
            .await
            .register(session_id.clone(), media_task.abort_handle());
        app_state.audit_log.fail_action("session.start_wan");

        let response = server
            .finish_session_start_audit(
                IpcResponse::SessionStarted {
                    session_id: session_id.clone(),
                },
                session_id.clone(),
                target_device_id,
                SessionStartKind::Wan,
                Vec::new(),
            )
            .await;

        assert!(matches!(
            response,
            IpcResponse::Error { ref code, .. } if code == "E_SECURITY_STORE_UNAVAILABLE"
        ));
        let sessions = app_state.sessions.lock().await;
        let unrelated_lan = sessions
            .get(&session_id)
            .expect("unrelated LAN projection must remain present");
        assert_eq!(
            unrelated_lan.lifecycle_state,
            SessionLifecycleState::Streaming
        );
        assert!(unrelated_lan.sender_active);
        drop(sessions);
        assert_eq!(
            app_state.media_tasks.lock().await.active_count(&session_id),
            1
        );
        media_task.abort();
        let _ = media_task.await;
    }

    #[tokio::test]
    async fn secure_session_control_input_requires_an_active_streaming_grant() {
        let app_state = Arc::new(AppState::new());
        let server = IpcServer::new(app_state.clone());
        let session_id = SessionId("secure-control-input".to_string());
        app_state
            .session_authorizations
            .begin_verified_incoming(VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: DeviceId("controller-device".to_string()),
                peer_key_id: "sha256:controller-key".to_string(),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: vec![RemotePermissionScope::ScreenView],
                peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
                runtime_capabilities: vec![RemotePermissionScope::ScreenView],
                transport_kind: "quic".to_string(),
                request_nonce: [7; 16],
                created_at_ms: 1,
                expires_at_ms: u64::MAX,
            })
            .await
            .expect("create secure session projection");

        let response = dispatch_request(
            &server,
            IpcRequest::SendControlInput {
                session_id: session_id.clone(),
                event: mrd_ipc::ControlInputEvent::Key {
                    key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            },
        )
        .await;

        let IpcResponse::RemoteAccessError {
            session_id: response_session_id,
            peer_key_id,
            failure,
        } = response
        else {
            panic!("secure control input must fail closed, got {response:?}");
        };
        assert_eq!(response_session_id, Some(session_id));
        assert_eq!(peer_key_id.as_deref(), Some("sha256:controller-key"));
        assert_eq!(failure.code, RemoteReasonCode::PolicyChanged);
        assert!(failure.message.contains("not granted"));
    }
}
