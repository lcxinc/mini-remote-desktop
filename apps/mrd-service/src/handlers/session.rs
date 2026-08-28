// Session control handlers for mrd-service
//
// These handlers implement the core session orchestration logic.

use crate::app_state::AppState;
use mrd_application::ports::{SessionLifecycleState, SessionSnapshot};
use mrd_ipc::{
    ControlInputEvent, CrossE2EFaultInjectionResult, DisplayMode, IpcResponse, MediaProfile,
    MediaTestImpairmentSnapshot, RemoteAccessMode, RemoteAuthorizationState, RemoteFailure,
    RemoteReasonCode, RemoteRoutePreference, RemoteSessionRequest,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{WanAccessModeV3, WanRoutePolicyV3, WanSessionRequestV3};
use ring::digest::{digest, SHA256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Return the authoritative secure remote-session projection.
pub async fn get_remote_session(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    let session = app_state
        .session_authorizations
        .snapshot_at(&session_id, current_time_ms())
        .await;
    if session.as_ref().is_some_and(|snapshot| {
        matches!(
            snapshot.authorization_state,
            RemoteAuthorizationState::Denied
                | RemoteAuthorizationState::Expired
                | RemoteAuthorizationState::Revoked
                | RemoteAuthorizationState::LockedOut
                | RemoteAuthorizationState::PolicyChanged
        )
    }) {
        crate::lan_discovery::terminate_authorized_remote_sessions_under_security_gate(
            app_state,
            std::slice::from_ref(&session_id),
        )
        .await;
    }
    match session {
        Some(session) => IpcResponse::RemoteSession { session },
        None => IpcResponse::Error {
            code: "E_REMOTE_SESSION_NOT_FOUND".to_string(),
            message: format!("remote session not found: {}", session_id.0),
        },
    }
}

/// Return route evidence only when it is bound to the active verified session grant.
pub async fn get_route_evidence(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    let _authorization_guard = app_state.authorization_security_gate.lock().await;
    let result = app_state
        .session_authorizations
        .verified_route_evidence_at(&session_id, current_time_ms())
        .await;
    let terminal = if result.is_err() {
        app_state
            .session_authorizations
            .snapshot_at(&session_id, current_time_ms())
            .await
            .is_some_and(|snapshot| {
                matches!(
                    snapshot.authorization_state,
                    RemoteAuthorizationState::Denied
                        | RemoteAuthorizationState::Expired
                        | RemoteAuthorizationState::Revoked
                        | RemoteAuthorizationState::LockedOut
                        | RemoteAuthorizationState::PolicyChanged
                )
            })
    } else {
        false
    };
    if terminal {
        crate::lan_discovery::terminate_authorized_remote_sessions_under_security_gate(
            app_state,
            std::slice::from_ref(&session_id),
        )
        .await;
    }
    match result {
        Ok(Some(evidence)) => IpcResponse::RouteEvidence { evidence },
        Ok(None) => IpcResponse::Error {
            code: "E_REMOTE_SESSION_NOT_FOUND".to_string(),
            message: format!("remote session not found: {}", session_id.0),
        },
        Err(failure) => IpcResponse::RemoteAccessError {
            session_id: Some(session_id),
            peer_key_id: None,
            failure,
        },
    }
}

/// Resolve a single exact attended-consent request.
pub async fn respond_to_consent(
    app_state: &Arc<AppState>,
    response: mrd_ipc::ConsentResponse,
) -> IpcResponse {
    let session_id = response.session_id.clone();
    let decision = response.decision;
    let approved_scope_count = response.approved_scopes.len();
    let peer_device_id = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .map(|snapshot| snapshot.peer_device_id);
    let wan_coordinator = app_state.wan_session_coordinator();
    let wan_state = if let Some(coordinator) = wan_coordinator.as_ref() {
        coordinator.snapshot(&session_id).await.ok()
    } else {
        None
    };
    let transport_kind = if wan_state.is_some() {
        "webrtc_relay"
    } else {
        "lan_quic"
    };
    let result = app_state
        .session_authorizations
        .respond_to_consent_with_audit(response, current_time_ms(), |snapshot, response| {
            let decision = match response.decision {
                mrd_ipc::ConsentDecision::Approve => "approve",
                mrd_ipc::ConsentDecision::Deny => "deny",
            };
            app_state
                .audit_log
                .record(
                    "session.consent_decision",
                    decision,
                    Some(session_id.clone()),
                    None,
                    Some(snapshot.peer_device_id.clone()),
                    Some(transport_kind.to_string()),
                    (response.decision == mrd_ipc::ConsentDecision::Deny)
                        .then(|| "consent_denied".to_string()),
                    vec![(
                        "approved_scope_count".to_string(),
                        response.approved_scopes.len().to_string(),
                    )],
                )
                .is_ok()
        })
        .await;
    match result {
        Ok(session) => {
            // The coordinator is authoritative for WAN target consent.  Use
            // the exact session id captured above; never approve whichever
            // session happens to be newest or merely shares the peer device.
            if let (Some(coordinator), Some(state)) = (wan_coordinator, wan_state) {
                if state.role() == crate::wan_session::model::WanSessionRole::Target
                    && state.phase() == crate::wan_session::model::WanSessionPhase::AwaitingConsent
                {
                    let coordinator_result = match decision {
                        mrd_ipc::ConsentDecision::Approve => {
                            coordinator.approve_target(&session_id).await
                        }
                        mrd_ipc::ConsentDecision::Deny => {
                            coordinator
                                .fail(
                                    &session_id,
                                    crate::wan_session::model::WanSessionFailure::Cancelled,
                                )
                                .await
                        }
                    };
                    let denial_already_terminal = coordinator_result.is_err()
                        && decision == mrd_ipc::ConsentDecision::Deny
                        && coordinator.snapshot(&session_id).await.is_ok_and(|state| {
                            state.phase() == crate::wan_session::model::WanSessionPhase::Failed
                                && state.failure()
                                    == Some(crate::wan_session::model::WanSessionFailure::Cancelled)
                        });
                    if coordinator_result.is_err() && !denial_already_terminal {
                        return IpcResponse::RemoteAccessError {
                            session_id: Some(session_id),
                            peer_key_id: peer_device_id.map(|device| device.0),
                            failure: RemoteFailure {
                                code: RemoteReasonCode::PolicyChanged,
                                message: "WAN consent could not be applied to the session"
                                    .to_string(),
                                suggested_action: Some(
                                    "start a new secure session request".to_string(),
                                ),
                            },
                        };
                    }
                }
            }
            IpcResponse::ConsentRecorded { session }
        }
        Err(crate::session_authorization::ConsentResolutionError::AuditUnavailable) => {
            app_state.mark_security_unhealthy();
            IpcResponse::Error {
                code: "E_SECURITY_STORE_UNAVAILABLE".to_string(),
                message: "consent decision could not be durably audited".to_string(),
            }
        }
        Err(crate::session_authorization::ConsentResolutionError::Rejected(failure)) => {
            let failure_reason = crate::lan_discovery::remote_reason_code_wire_name(failure.code);
            if app_state
                .audit_log
                .record(
                    "session.consent_decision",
                    "rejected",
                    Some(session_id.clone()),
                    None,
                    peer_device_id,
                    Some(transport_kind.to_string()),
                    Some(failure_reason),
                    vec![(
                        "approved_scope_count".to_string(),
                        approved_scope_count.to_string(),
                    )],
                )
                .is_err()
            {
                app_state.mark_security_unhealthy();
                return IpcResponse::Error {
                    code: "E_SECURITY_STORE_UNAVAILABLE".to_string(),
                    message: "rejected consent decision could not be durably audited".to_string(),
                };
            }
            IpcResponse::RemoteAccessError {
                session_id: Some(session_id),
                peer_key_id: None,
                failure,
            }
        }
    }
}

/// Fetch one bounded service-global remote-session event batch.
pub async fn subscribe_session_events(
    app_state: &Arc<AppState>,
    query: mrd_ipc::SessionEventSubscriptionQuery,
) -> IpcResponse {
    match app_state.session_authorizations.subscribe(query).await {
        Ok(subscription) => IpcResponse::SessionEventsSubscribed { subscription },
        Err(failure) => IpcResponse::RemoteAccessError {
            session_id: None,
            peer_key_id: None,
            failure,
        },
    }
}

/// Request a LAN remote session through the secure authorization pipeline.
pub async fn request_remote_session(
    app_state: &Arc<AppState>,
    request: RemoteSessionRequest,
) -> IpcResponse {
    let session_id = request.session_id.clone();
    if request.access_mode == RemoteAccessMode::Unattended {
        return unattended_enrollment_unavailable(Some(session_id));
    }

    // Auto is deliberately cache-only.  The security gate serializes this
    // read with trust changes, while `fresh_authenticated_lan_evidence` does
    // not issue a discovery probe or wait for a peer announcement.
    let cached_lan = if request.route_preference == RemoteRoutePreference::Auto {
        let _authorization_security_guard = app_state.authorization_security_gate.lock().await;
        crate::wan_session::media::fresh_authenticated_lan_evidence(
            app_state,
            &request.target_device_id,
            current_time_ms(),
            crate::wan_session::media::DEFAULT_LAN_DISCOVERY_MAX_AGE_MS,
        )
        .await
    } else {
        None
    };
    let route = crate::wan_session::media::select_route(request.route_preference, cached_lan);
    if route == crate::wan_session::media::WanRouteSelection::WanRelay {
        return request_wan_remote_session(app_state, request).await;
    }

    let peer_device_id = request.target_device_id.clone();
    match crate::lan_discovery::request_lan_remote_session_authorized(
        app_state,
        &request.target_device_id,
        &request.session_id,
        "quic",
        request.requested_profile,
        request.access_mode,
        request.requested_scopes,
        None,
    )
    .await
    {
        Ok(_) => match app_state.session_authorizations.snapshot(&session_id).await {
            Some(session) => IpcResponse::RemoteSessionRequested { session },
            None => IpcResponse::RemoteAccessError {
                session_id: Some(session_id),
                peer_key_id: None,
                failure: RemoteFailure {
                    code: RemoteReasonCode::PolicyChanged,
                    message: "authorized LAN session has no service snapshot".to_string(),
                    suggested_action: Some("retry the connection".to_string()),
                },
            },
        },
        Err(error) => {
            let mut secure_session = app_state.session_authorizations.snapshot(&session_id).await;
            if let Some(session) = secure_session.as_ref() {
                if let Some(failure) = session.failure.as_ref() {
                    return IpcResponse::RemoteAccessError {
                        session_id: Some(session_id.clone()),
                        peer_key_id: Some(session.peer_key_id.clone()),
                        failure: failure.clone(),
                    };
                }
            }
            let failure = map_lan_remote_session_error(&error, &peer_device_id);
            if let Some(session) = secure_session.as_ref() {
                let terminal_state =
                    if session.authorization_state == mrd_ipc::RemoteAuthorizationState::Granted {
                        mrd_ipc::RemoteAuthorizationState::Revoked
                    } else {
                        mrd_ipc::RemoteAuthorizationState::Denied
                    };
                secure_session = app_state
                    .session_authorizations
                    .record_failure(
                        &session_id,
                        terminal_state,
                        failure.clone(),
                        current_time_ms(),
                    )
                    .await;
            }
            IpcResponse::RemoteAccessError {
                session_id: Some(session_id),
                peer_key_id: secure_session.map(|session| session.peer_key_id),
                failure,
            }
        }
    }
}

/// Start the initial attended WAN relay workflow through the bound
/// coordinator.  This path has no LAN fallback once route selection chose
/// `WanRelay`.
async fn request_wan_remote_session(
    app_state: &Arc<AppState>,
    request: RemoteSessionRequest,
) -> IpcResponse {
    let session_id = request.session_id.clone();
    let target_device_id = request.target_device_id.clone();
    let Some(coordinator) = app_state.wan_session_coordinator() else {
        return wan_remote_failure(
            session_id,
            None,
            RemoteReasonCode::TurnAllocationFailed,
            "WAN relay coordinator is unavailable",
            "enable the authenticated WAN relay service before retrying",
        );
    };

    let Some((controller_device_id, _)) =
        app_state.devices.lock().await.get_local_device().cloned()
    else {
        return wan_remote_failure(
            session_id,
            None,
            RemoteReasonCode::IdentityMismatch,
            "local device identity is not registered",
            "register this device before starting a secure WAN session",
        );
    };
    let Some(controller_key_fingerprint) = app_state
        .device_identities
        .machine_key_id()
        .map(str::to_owned)
    else {
        return wan_remote_failure(
            session_id,
            None,
            RemoteReasonCode::IdentityMismatch,
            "local machine key identity is unavailable",
            "repair the local identity store before retrying",
        );
    };
    let mut requested_scopes = request
        .requested_scopes
        .into_iter()
        .map(wan_permission_scope)
        .collect::<Option<Vec<_>>>();
    let Some(mut requested_scopes) = requested_scopes.take() else {
        return wan_remote_failure(
            session_id,
            None,
            RemoteReasonCode::ScopeDenied,
            "requested permission scope is not supported by WAN relay",
            "request only supported secure remote scopes",
        );
    };
    requested_scopes.sort_unstable();
    requested_scopes.dedup();
    if requested_scopes.is_empty() {
        return wan_remote_failure(
            session_id,
            None,
            RemoteReasonCode::ScopeDenied,
            "WAN relay requires at least one permission scope",
            "request screen.view or another approved remote scope",
        );
    }

    let requested_profile = request
        .requested_profile
        .as_ref()
        .map(crate::wan_session::media::wan_media_profile);
    let deadline_unix_ms = current_time_ms().saturating_add(30_000);
    let wan_request = WanSessionRequestV3 {
        session_id: request.session_id.clone(),
        idempotency_key: wan_idempotency_key(&request.session_id),
        controller_device_id: controller_device_id.clone(),
        target_device_id: target_device_id.clone(),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes,
        requested_profile,
        route_policy: WanRoutePolicyV3::RelayOnly,
    };
    let identity =
        match crate::wan_session::model::WanSessionIdentity::new_controller_pending_target(
            request.session_id.clone(),
            controller_device_id,
            target_device_id.clone(),
            controller_key_fingerprint,
            deadline_unix_ms,
        ) {
            Ok(identity) => identity,
            Err(_) => {
                return wan_remote_failure(
                    session_id,
                    None,
                    RemoteReasonCode::IdentityMismatch,
                    "WAN session identity could not be initialized",
                    "repair the local identity store and retry the secure session",
                )
            }
        };

    match coordinator.start_controller(identity, wan_request).await {
        Ok(_) => match coordinator.snapshot(&session_id).await {
            Ok(state) => IpcResponse::RemoteSessionRequested {
                session: project_wan_snapshot(&state, current_time_ms()),
            },
            Err(_) => wan_remote_failure(
                session_id,
                None,
                RemoteReasonCode::PolicyChanged,
                "WAN session started without a readable service snapshot",
                "start a new secure session request",
            ),
        },
        Err(error) => wan_remote_failure(
            session_id,
            None,
            map_wan_coordinator_reason(&error),
            "WAN relay session could not be started",
            "verify the WAN relay backend and retry the secure session",
        ),
    }
}

fn wan_permission_scope(
    scope: mrd_ipc::RemotePermissionScope,
) -> Option<mrd_signal_proto::WanPermissionScopeV3> {
    use mrd_ipc::RemotePermissionScope as Ipc;
    use mrd_signal_proto::WanPermissionScopeV3 as Wan;
    Some(match scope {
        Ipc::ScreenView => Wan::ScreenView,
        Ipc::InputPointer => Wan::InputPointer,
        Ipc::InputKeyboard => Wan::InputKeyboard,
        Ipc::ClipboardRead => Wan::ClipboardRead,
        Ipc::ClipboardWrite => Wan::ClipboardWrite,
        Ipc::FileRead => Wan::FileRead,
        Ipc::FileWrite => Wan::FileWrite,
        Ipc::AudioListen => Wan::AudioListen,
        Ipc::AudioTalk => Wan::AudioTalk,
        Ipc::DisplaySwitch => Wan::DisplaySwitch,
        Ipc::DisplayMultiView => Wan::DisplayMultiView,
        Ipc::PowerRestart => Wan::PowerRestart,
        Ipc::PowerShutdown => Wan::PowerShutdown,
        Ipc::TerminalOpen => Wan::TerminalOpen,
        Ipc::PrivacyBlockLocalInput => Wan::PrivacyBlockLocalInput,
        Ipc::PrivacyBlankScreen => Wan::PrivacyBlankScreen,
        Ipc::SecureDesktopView => Wan::SecureDesktopView,
        Ipc::SecureDesktopControl => Wan::SecureDesktopControl,
    })
}

fn ipc_permission_scope(
    scope: mrd_signal_proto::WanPermissionScopeV3,
) -> mrd_ipc::RemotePermissionScope {
    use mrd_ipc::RemotePermissionScope as Ipc;
    use mrd_signal_proto::WanPermissionScopeV3 as Wan;
    match scope {
        Wan::ScreenView => Ipc::ScreenView,
        Wan::InputPointer => Ipc::InputPointer,
        Wan::InputKeyboard => Ipc::InputKeyboard,
        Wan::ClipboardRead => Ipc::ClipboardRead,
        Wan::ClipboardWrite => Ipc::ClipboardWrite,
        Wan::FileRead => Ipc::FileRead,
        Wan::FileWrite => Ipc::FileWrite,
        Wan::AudioListen => Ipc::AudioListen,
        Wan::AudioTalk => Ipc::AudioTalk,
        Wan::DisplaySwitch => Ipc::DisplaySwitch,
        Wan::DisplayMultiView => Ipc::DisplayMultiView,
        Wan::PowerRestart => Ipc::PowerRestart,
        Wan::PowerShutdown => Ipc::PowerShutdown,
        Wan::TerminalOpen => Ipc::TerminalOpen,
        Wan::PrivacyBlockLocalInput => Ipc::PrivacyBlockLocalInput,
        Wan::PrivacyBlankScreen => Ipc::PrivacyBlankScreen,
        Wan::SecureDesktopView => Ipc::SecureDesktopView,
        Wan::SecureDesktopControl => Ipc::SecureDesktopControl,
    }
}

fn wan_idempotency_key(session_id: &SessionId) -> [u8; 16] {
    let digest = digest(&SHA256, session_id.0.as_bytes());
    let mut key = [0; 16];
    key.copy_from_slice(&digest.as_ref()[..16]);
    if key == [0; 16] {
        key[0] = 1;
    }
    key
}

fn map_wan_coordinator_reason(
    error: &crate::wan_session::coordinator::WanSessionCoordinatorError,
) -> RemoteReasonCode {
    use crate::wan_session::coordinator::WanSessionCoordinatorError as Error;
    match error {
        Error::DeadlineExceeded => RemoteReasonCode::AuthorizationTimeout,
        Error::Backend(_) => RemoteReasonCode::TurnAllocationFailed,
        Error::Signaling(_) | Error::WorkflowUnavailable => RemoteReasonCode::RouteLost,
        Error::RoleOrPhaseMismatch | Error::SessionConflict | Error::BackendBindingMismatch => {
            RemoteReasonCode::IdentityMismatch
        }
        _ => RemoteReasonCode::RouteLost,
    }
}

fn project_wan_snapshot(
    state: &crate::wan_session::model::WanSessionState,
    now_ms: u64,
) -> mrd_ipc::RemoteSessionSnapshot {
    use mrd_ipc::{
        DecimalU64, RemoteAuthorizationState, RemoteMediaState, RemotePresentationState,
        RemoteRouteKind, RemoteRouteState, RemoteSessionRole,
    };
    let phase = state.phase();
    let authorization_state = match phase {
        crate::wan_session::model::WanSessionPhase::AwaitingConsent => {
            RemoteAuthorizationState::Authorizing
        }
        crate::wan_session::model::WanSessionPhase::Granted
        | crate::wan_session::model::WanSessionPhase::AccessBound
        | crate::wan_session::model::WanSessionPhase::Negotiating
        | crate::wan_session::model::WanSessionPhase::RelayVerified
        | crate::wan_session::model::WanSessionPhase::Streaming => {
            RemoteAuthorizationState::Granted
        }
        crate::wan_session::model::WanSessionPhase::Failed => RemoteAuthorizationState::Revoked,
        _ => RemoteAuthorizationState::Authorizing,
    };
    let (route_state, media_state, presentation_state) = match phase {
        crate::wan_session::model::WanSessionPhase::RelayVerified => (
            RemoteRouteState::Connected,
            RemoteMediaState::Starting,
            RemotePresentationState::ConnectedWithoutMedia,
        ),
        crate::wan_session::model::WanSessionPhase::Streaming => (
            RemoteRouteState::Connected,
            RemoteMediaState::Streaming,
            RemotePresentationState::Streaming,
        ),
        crate::wan_session::model::WanSessionPhase::Failed => (
            RemoteRouteState::Failed,
            RemoteMediaState::Failed,
            RemotePresentationState::Failed,
        ),
        _ => (
            RemoteRouteState::Connecting,
            RemoteMediaState::Idle,
            RemotePresentationState::Connecting,
        ),
    };
    let requested_scopes = state
        .grant()
        .map(|grant| grant.approved_scopes())
        .unwrap_or_default()
        .iter()
        .map(|scope| ipc_permission_scope(*scope))
        .collect::<Vec<_>>();
    let granted_scopes = requested_scopes.clone();
    let (requested_scopes, granted_scopes) = if state.grant().is_none() {
        (Vec::new(), Vec::new())
    } else {
        (requested_scopes, granted_scopes)
    };
    mrd_ipc::RemoteSessionSnapshot {
        session_id: state.identity().session_id().clone(),
        role: match state.role() {
            crate::wan_session::model::WanSessionRole::Controller => RemoteSessionRole::Controller,
            crate::wan_session::model::WanSessionRole::Target => RemoteSessionRole::Agent,
        },
        peer_device_id: match state.role() {
            crate::wan_session::model::WanSessionRole::Controller => {
                state.identity().target_device_id().clone()
            }
            crate::wan_session::model::WanSessionRole::Target => {
                state.identity().controller_device_id().clone()
            }
        },
        peer_key_id: match state.role() {
            crate::wan_session::model::WanSessionRole::Controller => state
                .identity()
                .target_key_fingerprint()
                .unwrap_or("pending_verified_peer")
                .to_string(),
            crate::wan_session::model::WanSessionRole::Target => {
                state.identity().controller_key_fingerprint().to_string()
            }
        },
        access_mode: mrd_ipc::RemoteAccessMode::Attended,
        authorization_state,
        route_state,
        route_kind: Some(RemoteRouteKind::WebRtcRelay),
        media_state,
        presentation_state,
        requested_scopes,
        granted_scopes,
        policy_revision: DecimalU64::new(state.grant().map_or(0, |grant| grant.policy_revision())),
        failure: state.failure().map(|_failure| RemoteFailure {
            code: RemoteReasonCode::RouteLost,
            message: "WAN relay session failed".to_string(),
            suggested_action: Some("start a new secure session request".to_string()),
        }),
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
        authorization_expires_at_ms: Some(state.identity().deadline_unix_ms()),
    }
}

fn wan_remote_failure(
    session_id: SessionId,
    peer_key_id: Option<String>,
    code: RemoteReasonCode,
    message: &str,
    suggested_action: &str,
) -> IpcResponse {
    IpcResponse::RemoteAccessError {
        session_id: Some(session_id),
        peer_key_id,
        failure: RemoteFailure {
            code,
            message: message.to_string(),
            suggested_action: Some(suggested_action.to_string()),
        },
    }
}

fn map_lan_remote_session_error(error: &anyhow::Error, peer_device_id: &DeviceId) -> RemoteFailure {
    let message = error.to_string();
    let diagnostic = format!("{error:#}").to_ascii_lowercase();
    let authorization_timeout = (diagnostic.contains("authorization")
        || diagnostic.contains("consent"))
        && (diagnostic.contains("timed out")
            || diagnostic.contains("timeout")
            || diagnostic.contains("expired"));
    let protocol_reason =
        crate::lan_discovery::LanProtocolError::remote_reason_code_from_diagnostic(&diagnostic);
    let code = if let Some(code) = protocol_reason {
        code
    } else if diagnostic.contains("fingerprint")
        || diagnostic.contains("identity")
        || diagnostic.contains("signature")
        || diagnostic.contains("public key")
        || diagnostic.contains("key identifier")
        || diagnostic.contains("key epoch")
        || diagnostic.contains("certificate")
    {
        RemoteReasonCode::IdentityMismatch
    } else if diagnostic.contains("trust")
        || diagnostic.contains("not authenticated")
        || diagnostic.contains("not trusted")
    {
        RemoteReasonCode::TrustRequired
    } else if authorization_timeout {
        RemoteReasonCode::AuthorizationTimeout
    } else if diagnostic.contains("decoder") {
        RemoteReasonCode::DecoderUnavailable
    } else if diagnostic.contains("encoder") {
        RemoteReasonCode::EncoderUnavailable
    } else if diagnostic.contains("media profile")
        || diagnostic.contains("media capabilities")
        || diagnostic.contains("codec")
    {
        RemoteReasonCode::ProfileDowngraded
    } else if diagnostic.contains("protocol")
        || diagnostic.contains("signed")
        || diagnostic.contains("bootstrap")
        || diagnostic.contains("grant")
        || diagnostic.contains("downgrade")
        || diagnostic.contains("unexpected lan remote session response")
    {
        RemoteReasonCode::ProtocolDowngradeBlocked
    } else {
        RemoteReasonCode::LanUnreachable
    };
    let suggested_action = match code {
        RemoteReasonCode::IdentityMismatch | RemoteReasonCode::CertificateBindingMismatch => {
            Some("verify the peer identity and pair the device again".to_string())
        }
        RemoteReasonCode::TrustRequired => Some(format!(
            "pair and trust {} before connecting",
            peer_device_id.0
        )),
        RemoteReasonCode::AuthorizationTimeout => {
            Some("ask the remote user to approve a new connection request".to_string())
        }
        RemoteReasonCode::ReplayDetected => Some("start a new secure session request".to_string()),
        RemoteReasonCode::DecoderUnavailable
        | RemoteReasonCode::EncoderUnavailable
        | RemoteReasonCode::ProfileDowngraded => {
            Some("choose a media profile supported by both devices".to_string())
        }
        RemoteReasonCode::ProtocolDowngradeBlocked => {
            Some("update both devices to compatible secure LAN protocol versions".to_string())
        }
        _ => Some(format!(
            "verify that {} is online and reachable on the LAN",
            peer_device_id.0
        )),
    };
    RemoteFailure {
        code,
        message,
        suggested_action,
    }
}

async fn finish_start_lan_remote_session_error(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    peer_device_id: &DeviceId,
    error: anyhow::Error,
) -> IpcResponse {
    let mut failure = map_lan_remote_session_error(&error, peer_device_id);
    let mut peer_key_id = None;
    if let Some(session) = app_state.session_authorizations.snapshot(&session_id).await {
        peer_key_id = Some(session.peer_key_id.clone());
        if let Some(existing_failure) = session.failure {
            failure = existing_failure;
        } else {
            let terminal_state =
                if session.authorization_state == mrd_ipc::RemoteAuthorizationState::Granted {
                    mrd_ipc::RemoteAuthorizationState::Revoked
                } else {
                    mrd_ipc::RemoteAuthorizationState::Denied
                };
            app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    terminal_state,
                    failure.clone(),
                    current_time_ms(),
                )
                .await;
        }
    }
    IpcResponse::RemoteAccessError {
        session_id: Some(session_id),
        peer_key_id,
        failure,
    }
}

pub async fn enable_unattended_access(
    app_state: &Arc<AppState>,
    policy: mrd_ipc::UnattendedAccessPolicy,
) -> IpcResponse {
    if app_state
        .audit_log
        .record(
            "unattended.enable",
            "requested",
            None,
            None,
            None,
            None,
            None,
            vec![(
                "permission_scope_count".to_string(),
                policy.permission_ceiling.len().to_string(),
            )],
        )
        .is_err()
    {
        app_state.mark_security_unhealthy();
        return IpcResponse::Error {
            code: "E_SECURITY_STORE_UNAVAILABLE".to_string(),
            message: "unattended policy could not be audited".to_string(),
        };
    }
    unattended_enrollment_unavailable(None)
}

pub async fn disable_unattended_access(
    app_state: &Arc<AppState>,
    expected_policy_revision: u64,
) -> IpcResponse {
    let _authorization_security_guard = app_state.authorization_security_gate.lock().await;
    if !audit_unattended_mutation(app_state, "unattended.disable", expected_policy_revision) {
        return security_audit_unavailable();
    }
    match app_state
        .session_authorizations
        .disable_unattended(expected_policy_revision, current_time_ms())
        .await
    {
        Ok(access) => {
            let revoked_session_ids = app_state
                .session_authorizations
                .revoke_unattended_authorizations(current_time_ms())
                .await;
            crate::lan_discovery::terminate_authorized_remote_sessions_under_security_gate(
                app_state,
                &revoked_session_ids,
            )
            .await;
            IpcResponse::UnattendedAccessUpdated { access }
        }
        Err(failure) => unattended_result(Err(failure)),
    }
}

pub async fn rotate_unattended_access(
    app_state: &Arc<AppState>,
    expected_policy_revision: u64,
) -> IpcResponse {
    if !audit_unattended_mutation(app_state, "unattended.rotate", expected_policy_revision) {
        return security_audit_unavailable();
    }
    unattended_enrollment_unavailable(None)
}

fn unattended_enrollment_unavailable(session_id: Option<SessionId>) -> IpcResponse {
    IpcResponse::RemoteAccessError {
        session_id,
        peer_key_id: None,
        failure: RemoteFailure {
            code: RemoteReasonCode::ProtocolDowngradeBlocked,
            message: "unattended credential enrollment is unavailable in this service build"
                .to_string(),
            suggested_action: Some(
                "use attended access until credential enrollment is available".to_string(),
            ),
        },
    }
}

fn audit_unattended_mutation(
    app_state: &Arc<AppState>,
    action: &str,
    expected_policy_revision: u64,
) -> bool {
    if app_state
        .audit_log
        .record(
            action,
            "requested",
            None,
            None,
            None,
            None,
            None,
            vec![(
                "expected_policy_revision".to_string(),
                expected_policy_revision.to_string(),
            )],
        )
        .is_ok()
    {
        true
    } else {
        app_state.mark_security_unhealthy();
        false
    }
}

fn security_audit_unavailable() -> IpcResponse {
    IpcResponse::Error {
        code: "E_SECURITY_STORE_UNAVAILABLE".to_string(),
        message: "security policy mutation could not be audited".to_string(),
    }
}

fn unattended_result(
    result: Result<mrd_ipc::UnattendedAccessSnapshot, mrd_ipc::RemoteFailure>,
) -> IpcResponse {
    match result {
        Ok(access) => IpcResponse::UnattendedAccessUpdated { access },
        Err(failure) => IpcResponse::RemoteAccessError {
            session_id: None,
            peer_key_id: None,
            failure,
        },
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Handle session start request
pub async fn start_session(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    target_device_id: DeviceId,
    transport_kind: String,
) -> IpcResponse {
    tracing::info!(
        "Starting session: {} -> {} via {}",
        session_id.0,
        target_device_id.0,
        transport_kind
    );

    let _authorization_security_guard = app_state.authorization_security_gate.lock().await;
    if app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .is_some()
    {
        return secure_legacy_bypass_error(session_id, "StartSession");
    }
    let mut sessions = app_state.sessions.lock().await;
    if sessions.get(&session_id).is_some() {
        return IpcResponse::Error {
            code: "E409".to_string(),
            message: format!("Session already exists: {}", session_id.0),
        };
    }
    sessions.insert(
        session_id.clone(),
        SessionSnapshot {
            session_id: session_id.clone(),
            transport: transport_kind.clone(),
            source_device_id: None,
            target_device_id: Some(target_device_id),
            local_listen_addr: None,
            local_server_name: None,
            local_cert_der_b64: None,
            remote_listen_addr: None,
            remote_server_name: None,
            remote_cert_der_b64: None,
            lifecycle_state: SessionLifecycleState::Connecting,
            last_error: None,
            sender_active: false,
            receiver_active: false,
        },
    );

    IpcResponse::SessionStarted { session_id }
}

/// Start a LAN P2P remote session through attended authorization.
pub async fn start_lan_remote_session(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    target_device_id: DeviceId,
    transport_kind: String,
    requested_profile: Option<MediaProfile>,
) -> IpcResponse {
    tracing::info!(
        "Starting LAN remote session: {} -> {} via {}",
        session_id.0,
        target_device_id.0,
        transport_kind
    );

    match crate::lan_discovery::request_lan_remote_session(
        app_state,
        &target_device_id,
        &session_id,
        &transport_kind,
        requested_profile,
    )
    .await
    {
        // The secure LAN flow already commits the compatibility snapshot with
        // its authoritative Streaming state. Do not downgrade it back to
        // Connected after the request completes.
        Ok(_negotiation) => IpcResponse::SessionStarted { session_id },
        Err(error) => {
            finish_start_lan_remote_session_error(app_state, session_id, &target_device_id, error)
                .await
        }
    }
}

/// Handle a runtime media profile switch request.
pub async fn update_media_profile(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    requested_profile: MediaProfile,
) -> IpcResponse {
    tracing::info!(
        "Updating media profile: {} -> {}x{}@{} {}Mbps {}",
        session_id.0,
        requested_profile.width,
        requested_profile.height,
        requested_profile.fps,
        requested_profile.bitrate_mbps,
        requested_profile.codec
    );

    match crate::lan_discovery::request_lan_media_profile_update(
        app_state,
        &session_id,
        requested_profile,
    )
    .await
    {
        Ok(negotiation) => IpcResponse::MediaProfileUpdated {
            session_id,
            negotiation,
        },
        Err(error) => IpcResponse::Error {
            code: "E_MEDIA_PROFILE".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle a runtime LAN media adaptation configuration request.
pub async fn configure_media_adaptation(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    config: mrd_ipc::AdaptiveMediaConfig,
) -> IpcResponse {
    tracing::info!(
        "Configuring media adaptation: {} enabled={} mode={}",
        session_id.0,
        config.enabled,
        config.mode
    );

    match crate::media_adaptation::configure_media_adaptation(app_state, session_id.clone(), config)
        .await
    {
        Ok(snapshot) => IpcResponse::MediaAdaptationConfigured {
            session_id,
            snapshot,
        },
        Err(error) => IpcResponse::Error {
            code: "E_MEDIA_ADAPTATION".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle a control input request.
pub async fn send_control_input(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    event: ControlInputEvent,
) -> IpcResponse {
    if let Some(secure_session) = app_state.session_authorizations.snapshot(&session_id).await {
        let peer_key_id = Some(secure_session.peer_key_id);
        return match crate::lan_discovery::request_authenticated_lan_control_input(
            app_state,
            &session_id,
            event,
        )
        .await
        {
            Ok(result) => IpcResponse::ControlInputAccepted {
                session_id,
                lane: result.lane,
                event_count: result.event_count,
            },
            Err(failure) => IpcResponse::RemoteAccessError {
                session_id: Some(session_id),
                peer_key_id,
                failure,
            },
        };
    }
    let session_snapshot = {
        let sessions = app_state.sessions.lock().await;
        sessions.get(&session_id).cloned()
    };
    let route_to_peer = match session_snapshot {
        Some(snapshot) if snapshot.lifecycle_state.is_terminal() => {
            return IpcResponse::Error {
                code: "E_CONTROL_INPUT".to_string(),
                message: format!(
                    "control input rejected for {} session",
                    snapshot.lifecycle_state
                ),
            };
        }
        Some(snapshot) => {
            let route_to_peer = snapshot.target_device_id.is_some();
            if route_to_peer
                && (snapshot.lifecycle_state != SessionLifecycleState::Streaming
                    || !snapshot.receiver_active)
            {
                return IpcResponse::Error {
                    code: "E_CONTROL_INPUT".to_string(),
                    message: format!(
                        "control input requires a streaming receiver for session {}",
                        session_id.0
                    ),
                };
            }
            if !route_to_peer && !snapshot.sender_active {
                return IpcResponse::Error {
                    code: "E_CONTROL_INPUT".to_string(),
                    message: format!(
                        "control input requires an active local sender for session {}",
                        session_id.0
                    ),
                };
            }
            route_to_peer
        }
        None => {
            return IpcResponse::Error {
                code: "E_CONTROL_INPUT".to_string(),
                message: format!("session not found: {}", session_id.0),
            };
        }
    };

    let result = if route_to_peer {
        crate::lan_discovery::request_lan_control_input(app_state, &session_id, event).await
    } else {
        app_state
            .control_input()
            .lock()
            .await
            .handle_session_event(&session_id, &event)
            .map_err(Into::into)
    };

    match result {
        Ok(result) => IpcResponse::ControlInputAccepted {
            session_id,
            lane: result.lane,
            event_count: result.event_count,
        },
        Err(error) => IpcResponse::Error {
            code: "E_CONTROL_INPUT".to_string(),
            message: error.to_string(),
        },
    }
}

/// Inject a test-only cross-device E2E fault into an active session.
pub async fn cross_e2e_inject_fault(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    fault_type: String,
    duration_ms: Option<u64>,
) -> IpcResponse {
    if let Some(error) = validate_fault_session(app_state, &session_id).await {
        return error;
    }

    match fault_type.as_str() {
        "renderer.detach_surface" => {
            let surface_ids: Vec<String> = app_state
                .media_pipelines
                .lock()
                .await
                .snapshot(&session_id)
                .attached_surfaces
                .into_iter()
                .map(|surface| surface.surface_id)
                .collect();
            if surface_ids.is_empty() {
                return IpcResponse::Error {
                    code: "E_CROSS_E2E_FAULT".to_string(),
                    message: format!("no attached render surfaces for session {}", session_id.0),
                };
            }

            {
                let mut pipelines = app_state.media_pipelines.lock().await;
                for surface_id in &surface_ids {
                    pipelines.detach_surface(&session_id, surface_id);
                }
            }
            #[cfg(any(windows, target_os = "macos"))]
            {
                let mut renderers = app_state.media_surface_renderers.lock().await;
                for surface_id in &surface_ids {
                    renderers.detach_surface(&session_id, surface_id);
                }
            }

            IpcResponse::CrossE2EFaultInjected {
                result: CrossE2EFaultInjectionResult {
                    session_id,
                    fault_type,
                    status: "injected".to_string(),
                    message: format!("detached {} native render surface(s)", surface_ids.len()),
                    duration_ms,
                    affected_surface_ids: surface_ids,
                    impairment: None,
                },
            }
        }
        "network.pause_peer" => {
            let pause_ms = duration_ms.unwrap_or(1_000).max(1);
            let impairment = MediaTestImpairmentSnapshot {
                loss_pct: 1.0,
                base_delay_ms: pause_ms,
                jitter_ms: 0,
                mtu_bytes: None,
                seed: now_unix_ms_lossy(),
                datagrams_sent: 0,
                datagrams_dropped: 0,
                datagrams_delayed: 0,
                datagrams_fragmented_by_mtu: 0,
            };
            app_state
                .media_pipelines
                .lock()
                .await
                .set_test_impairment(session_id.clone(), Some(impairment.clone()));
            app_state.probes.lock().await.record_transient_frame_drop(
                &session_id,
                0,
                now_unix_ms_lossy(),
            );

            let app_state_for_restore = app_state.clone();
            let session_id_for_restore = session_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
                app_state_for_restore
                    .media_pipelines
                    .lock()
                    .await
                    .set_test_impairment(session_id_for_restore, None);
            });

            IpcResponse::CrossE2EFaultInjected {
                result: CrossE2EFaultInjectionResult {
                    session_id,
                    fault_type,
                    status: "injected".to_string(),
                    message: format!("recorded test network pause impairment for {} ms", pause_ms),
                    duration_ms: Some(pause_ms),
                    affected_surface_ids: vec![],
                    impairment: Some(impairment),
                },
            }
        }
        _ => IpcResponse::Error {
            code: "E_CROSS_E2E_FAULT".to_string(),
            message: format!("unsupported cross-device E2E fault: {fault_type}"),
        },
    }
}

async fn validate_fault_session(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
) -> Option<IpcResponse> {
    match app_state.sessions.lock().await.get(session_id).cloned() {
        Some(snapshot) if snapshot.lifecycle_state.is_terminal() => Some(IpcResponse::Error {
            code: "E_CROSS_E2E_FAULT".to_string(),
            message: format!(
                "fault injection rejected for {} session",
                snapshot.lifecycle_state
            ),
        }),
        Some(_) => None,
        None => Some(IpcResponse::Error {
            code: "E_CROSS_E2E_FAULT".to_string(),
            message: format!("session not found: {}", session_id.0),
        }),
    }
}

fn now_unix_ms_lossy() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Handle a remote capture source listing request.
pub async fn list_remote_capture_sources(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    include_previews: bool,
    limit: Option<u32>,
) -> IpcResponse {
    match crate::lan_discovery::request_lan_capture_sources(
        app_state,
        &session_id,
        include_previews,
        limit,
    )
    .await
    {
        Ok(sources) => IpcResponse::CaptureSourceList {
            session_id,
            sources,
        },
        Err(error) => IpcResponse::Error {
            code: "E_CAPTURE_SOURCES".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle a remote capture source selection request.
pub async fn select_remote_capture_source(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    source_id: String,
) -> IpcResponse {
    match crate::lan_discovery::request_lan_capture_source_select(app_state, &session_id, source_id)
        .await
    {
        Ok(selection) => IpcResponse::CaptureSourceSelected {
            session_id,
            selection,
        },
        Err(error) => IpcResponse::Error {
            code: "E_CAPTURE_SOURCE_SELECT".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle a remote display mode listing request.
pub async fn list_remote_display_modes(
    app_state: &Arc<AppState>,
    session_id: SessionId,
) -> IpcResponse {
    let source_id = app_state
        .capture_sources
        .lock()
        .await
        .get(&session_id)
        .map(|selection| selection.source.id);
    match crate::lan_discovery::request_lan_display_modes(app_state, &session_id, source_id).await {
        Ok(modes) => IpcResponse::DisplayModeList { session_id, modes },
        Err(error) => IpcResponse::Error {
            code: "E_DISPLAY_MODES".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle a remote display mode set request.
pub async fn set_remote_display_mode(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    mode: DisplayMode,
    restore_after_session: bool,
) -> IpcResponse {
    match crate::lan_discovery::request_lan_display_mode_set(
        app_state,
        &session_id,
        mode,
        restore_after_session,
    )
    .await
    {
        Ok(change) => IpcResponse::DisplayModeChanged { session_id, change },
        Err(error) => IpcResponse::Error {
            code: "E_DISPLAY_MODE_SET".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle a remote display mode restore request.
pub async fn restore_remote_display_mode(
    app_state: &Arc<AppState>,
    session_id: SessionId,
) -> IpcResponse {
    match crate::lan_discovery::request_lan_display_mode_restore(app_state, &session_id).await {
        Ok(change) => IpcResponse::DisplayModeChanged { session_id, change },
        Err(error) => IpcResponse::Error {
            code: "E_DISPLAY_MODE_RESTORE".to_string(),
            message: error.to_string(),
        },
    }
}

/// Handle session accept request
pub async fn accept_session(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    source_device_id: DeviceId,
) -> IpcResponse {
    let _authorization_security_guard = app_state.authorization_security_gate.lock().await;
    if app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .is_some()
    {
        return secure_legacy_bypass_error(session_id, "AcceptSession");
    }
    tracing::info!(
        "Accepting session: {} from {}",
        session_id.0,
        source_device_id.0
    );

    let mut sessions = app_state.sessions.lock().await;
    let existing = sessions.get(&session_id);

    if let Some(snap) = existing {
        // Update existing session
        let new_snapshot = SessionSnapshot {
            source_device_id: Some(source_device_id),
            ..snap.clone()
        };
        sessions.insert(session_id.clone(), new_snapshot);
    } else {
        // Create new session
        sessions.insert(
            session_id.clone(),
            SessionSnapshot {
                session_id: session_id.clone(),
                transport: "unknown".to_string(),
                source_device_id: Some(source_device_id),
                target_device_id: None,
                local_listen_addr: None,
                local_server_name: None,
                local_cert_der_b64: None,
                remote_listen_addr: None,
                remote_server_name: None,
                remote_cert_der_b64: None,
                lifecycle_state: SessionLifecycleState::Listening,
                last_error: None,
                sender_active: false,
                receiver_active: false,
            },
        );
    }

    IpcResponse::SessionAccepted { session_id }
}

fn secure_legacy_bypass_error(session_id: SessionId, operation: &str) -> IpcResponse {
    IpcResponse::RemoteAccessError {
        session_id: Some(session_id),
        peer_key_id: None,
        failure: RemoteFailure {
            code: RemoteReasonCode::ProtocolDowngradeBlocked,
            message: format!("{operation} cannot mutate a secure remote session"),
            suggested_action: Some("use the secure remote-session IPC contract".to_string()),
        },
    }
}

/// Handle session stop request
pub async fn stop_session(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    tracing::info!("Stopping session: {}", session_id.0);

    let authorization_security_guard = app_state.authorization_security_gate.lock().await;
    let secure_session_exists = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .is_some();
    let snapshot = {
        let sessions = app_state.sessions.lock().await;
        sessions.get(&session_id).cloned()
    };
    if snapshot.is_none() && !secure_session_exists {
        return IpcResponse::Error {
            code: "E404".to_string(),
            message: format!("Session not found: {}", session_id.0),
        };
    }
    if let Some(snapshot) = snapshot.as_ref() {
        release_control_input_for_terminal_session(
            app_state,
            &session_id,
            snapshot,
            secure_session_exists,
            "stopping",
        )
        .await;
    }
    if secure_session_exists {
        terminalize_secure_session(
            app_state,
            &session_id,
            RemoteReasonCode::GrantRevoked,
            "session stopped".to_string(),
            None,
        )
        .await;
    }
    drop(authorization_security_guard);

    if secure_session_exists {
        crate::lan_discovery::terminate_authorized_remote_sessions(
            app_state,
            std::slice::from_ref(&session_id),
        )
        .await;
    } else {
        app_state
            .media_tasks
            .lock()
            .await
            .abort_session(&session_id);
        clear_session_media_state(app_state, &session_id).await;
    }
    if let Some(snapshot) = snapshot {
        let mut sessions = app_state.sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            SessionSnapshot {
                lifecycle_state: SessionLifecycleState::Closed,
                last_error: None,
                sender_active: false,
                receiver_active: false,
                ..snapshot
            },
        );
    }
    IpcResponse::SessionStopped { session_id }
}

/// Handle session failure request.
pub async fn fail_session(
    app_state: &Arc<AppState>,
    session_id: SessionId,
    reason: String,
) -> IpcResponse {
    tracing::warn!("Failing session: {} reason={}", session_id.0, reason);

    let authorization_security_guard = app_state.authorization_security_gate.lock().await;
    let secure_session_exists = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .is_some();
    let snapshot = {
        let sessions = app_state.sessions.lock().await;
        sessions.get(&session_id).cloned()
    };
    if snapshot.is_none() && !secure_session_exists {
        return IpcResponse::Error {
            code: "E404".to_string(),
            message: format!("Session not found: {}", session_id.0),
        };
    }
    if let Some(snapshot) = snapshot.as_ref() {
        release_control_input_for_terminal_session(
            app_state,
            &session_id,
            snapshot,
            secure_session_exists,
            "failing",
        )
        .await;
    }
    if secure_session_exists {
        terminalize_secure_session(
            app_state,
            &session_id,
            RemoteReasonCode::RouteLost,
            reason.clone(),
            Some("retry the secure remote session".to_string()),
        )
        .await;
    }
    drop(authorization_security_guard);

    if secure_session_exists {
        crate::lan_discovery::terminate_authorized_remote_sessions(
            app_state,
            std::slice::from_ref(&session_id),
        )
        .await;
    } else {
        app_state
            .media_tasks
            .lock()
            .await
            .abort_session(&session_id);
        clear_session_media_state(app_state, &session_id).await;
    }
    if let Some(snapshot) = snapshot {
        let mut sessions = app_state.sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            SessionSnapshot {
                lifecycle_state: SessionLifecycleState::Failed {
                    message: reason.clone(),
                },
                last_error: Some(reason.clone()),
                sender_active: false,
                receiver_active: false,
                ..snapshot
            },
        );
    }

    let mut shell = app_state.shell.lock().await;
    shell.last_error = Some(reason);

    IpcResponse::SessionFailed { session_id }
}

async fn terminalize_secure_session(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    code: RemoteReasonCode,
    message: String,
    suggested_action: Option<String>,
) {
    let _ = app_state
        .session_authorizations
        .record_failure(
            session_id,
            mrd_ipc::RemoteAuthorizationState::Revoked,
            RemoteFailure {
                code,
                message,
                suggested_action,
            },
            current_time_ms(),
        )
        .await;
}

async fn clear_session_media_state(app_state: &Arc<AppState>, session_id: &SessionId) {
    app_state.media_profiles.lock().await.remove(session_id);
    app_state.capture_sources.lock().await.remove(session_id);
    app_state
        .peer_media_capabilities
        .lock()
        .await
        .remove(session_id);
    #[cfg(windows)]
    app_state
        .media_surface_renderers
        .lock()
        .await
        .detach_session(session_id);
    app_state.media_pipelines.lock().await.remove(session_id);
}

async fn release_control_input_for_terminal_session(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    snapshot: &SessionSnapshot,
    secure_session_exists: bool,
    action: &'static str,
) {
    let route_release_to_peer = snapshot.target_device_id.is_some()
        && snapshot.lifecycle_state == SessionLifecycleState::Streaming
        && snapshot.receiver_active;
    let result = if route_release_to_peer && secure_session_exists {
        crate::lan_discovery::request_authenticated_lan_control_input_under_security_gate(
            app_state,
            session_id,
            ControlInputEvent::ReleaseAll,
        )
        .await
        .map(|_| ())
        .map_err(|failure| anyhow::anyhow!(failure.message))
    } else if route_release_to_peer {
        crate::lan_discovery::request_lan_control_input(
            app_state,
            session_id,
            ControlInputEvent::ReleaseAll,
        )
        .await
        .map(|_| ())
    } else {
        app_state
            .control_input()
            .lock()
            .await
            .handle_session_event(session_id, &ControlInputEvent::ReleaseAll)
            .map(|_| ())
            .map_err(Into::into)
    };
    if let Err(error) = result {
        tracing::warn!(
            session_id = %session_id.0,
            %error,
            "failed to release active control input while {action} session"
        );
    }
}

/// Recover a failed or closed session into the startup state for its role.
pub async fn recover_session(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    tracing::info!("Recovering session: {}", session_id.0);

    let _authorization_security_guard = app_state.authorization_security_gate.lock().await;
    if app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .is_some()
    {
        return secure_legacy_bypass_error(session_id, "RecoverSession");
    }
    let mut sessions = app_state.sessions.lock().await;
    if let Some(snapshot) = sessions.get(&session_id).cloned() {
        let lifecycle_state = recovery_state_for(&snapshot);
        sessions.insert(
            session_id.clone(),
            SessionSnapshot {
                lifecycle_state,
                last_error: None,
                sender_active: false,
                receiver_active: false,
                ..snapshot
            },
        );
        drop(sessions);

        let mut shell = app_state.shell.lock().await;
        shell.last_error = None;

        return IpcResponse::SessionRecovered { session_id };
    }

    IpcResponse::Error {
        code: "E404".to_string(),
        message: format!("Session not found: {}", session_id.0),
    }
}

/// Handle session list request.
pub async fn list_sessions(app_state: &Arc<AppState>) -> IpcResponse {
    let sessions = app_state.sessions.lock().await;
    let session_list = sessions
        .list_all()
        .into_iter()
        .map(|snap| mrd_ipc::SessionInfo {
            session_id: snap.session_id.clone(),
            role: session_role(&snap),
            state: snap.lifecycle_state.as_str().to_string(),
            transport_kind: snap.transport.clone(),
            last_error: snap.last_error.clone(),
            sender_active: snap.sender_active,
            receiver_active: snap.receiver_active,
            peer_device_id: peer_device_id(&snap),
        })
        .collect();

    IpcResponse::SessionList {
        sessions: session_list,
    }
}

/// Handle aggregated runtime snapshot request.
pub async fn runtime_snapshot(app_state: &Arc<AppState>) -> IpcResponse {
    let sessions = app_state.sessions.lock().await;
    let session_snapshots: Vec<mrd_ipc::SessionRuntimeSnapshot> = sessions
        .list_all()
        .into_iter()
        .map(|snap| session_runtime_snapshot(&snap))
        .collect();
    drop(sessions);

    let devices = app_state.devices.lock().await;
    let device_id = devices.get_local_device().map(|(id, _)| id.clone());

    IpcResponse::RuntimeSnapshot {
        snapshot: mrd_ipc::RuntimeSnapshot {
            sessions: session_snapshots,
            device_id,
            is_registered: devices.is_registered(),
            signaling: signaling_runtime_snapshot(&app_state.signaling_status.snapshot()),
        },
    }
}

fn signaling_runtime_snapshot(
    snapshot: &crate::signaling::SignalingRuntimeSnapshot,
) -> mrd_ipc::SignalingRuntimeSnapshot {
    let state = match snapshot.state {
        crate::signaling::SignalingConnectionState::Disabled => "disabled",
        crate::signaling::SignalingConnectionState::Connecting => "connecting",
        crate::signaling::SignalingConnectionState::Authenticated => "authenticated",
        crate::signaling::SignalingConnectionState::Backoff => "backoff",
        crate::signaling::SignalingConnectionState::Stopped => "stopped",
    };
    mrd_ipc::SignalingRuntimeSnapshot {
        state: state.into(),
        reconnect_attempt: snapshot.reconnect_attempt,
        next_retry_at_ms: snapshot.next_retry_at_ms,
        last_connected_at_ms: snapshot.last_connected_at_ms,
        last_message_at_ms: snapshot.last_message_at_ms,
        last_error: snapshot.last_error.clone(),
    }
}

/// Handle session snapshot request
pub async fn session_snapshot(app_state: &Arc<AppState>, session_id: SessionId) -> IpcResponse {
    let sessions = app_state.sessions.lock().await;
    let snap = sessions.get(&session_id);

    match snap {
        Some(s) => IpcResponse::SessionSnapshot {
            snapshot: session_runtime_snapshot(s),
        },
        None => IpcResponse::Error {
            code: "E404".to_string(),
            message: format!("Session not found: {}", session_id.0),
        },
    }
}

fn session_runtime_snapshot(s: &SessionSnapshot) -> mrd_ipc::SessionRuntimeSnapshot {
    mrd_ipc::SessionRuntimeSnapshot {
        session_id: s.session_id.clone(),
        role: session_role(s),
        state: s.lifecycle_state.as_str().to_string(),
        transport_kind: s.transport.clone(),
        local_bootstrap: bootstrap(
            &s.local_listen_addr,
            &s.local_server_name,
            &s.local_cert_der_b64,
        ),
        remote_bootstrap: bootstrap(
            &s.remote_listen_addr,
            &s.remote_server_name,
            &s.remote_cert_der_b64,
        ),
        last_error: s.last_error.clone(),
        sender_active: s.sender_active,
        receiver_active: s.receiver_active,
        peer_device_id: peer_device_id(s),
    }
}

fn session_role(s: &SessionSnapshot) -> String {
    if s.target_device_id.is_some() {
        "controller"
    } else if s.source_device_id.is_some() {
        "agent"
    } else {
        "unknown"
    }
    .to_string()
}

fn peer_device_id(s: &SessionSnapshot) -> Option<DeviceId> {
    s.target_device_id
        .clone()
        .or_else(|| s.source_device_id.clone())
}

fn bootstrap(
    listen_addr: &Option<String>,
    server_name: &Option<String>,
    cert_der: &Option<String>,
) -> Option<mrd_ipc::SessionBootstrap> {
    if listen_addr.is_some() || server_name.is_some() {
        Some(mrd_ipc::SessionBootstrap {
            listen_addr: listen_addr.clone(),
            server_name: server_name.clone(),
            cert_der: cert_der.clone(),
        })
    } else {
        None
    }
}

fn recovery_state_for(snapshot: &SessionSnapshot) -> SessionLifecycleState {
    if snapshot.target_device_id.is_some() {
        SessionLifecycleState::Connecting
    } else if snapshot.source_device_id.is_some() {
        SessionLifecycleState::Listening
    } else {
        SessionLifecycleState::Created
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_input::{InputError, InputEvent, InputInjector};
    use std::sync::Mutex as StdMutex;

    #[derive(Clone)]
    struct SharedRecordingInputInjector {
        events: Arc<StdMutex<Vec<InputEvent>>>,
    }

    impl InputInjector for SharedRecordingInputInjector {
        fn is_available(&self) -> bool {
            true
        }

        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(*event);
            Ok(())
        }
    }

    async fn begin_secure_outgoing_authorization(app_state: &Arc<AppState>, session_id: SessionId) {
        let created_at_ms = current_time_ms();
        app_state
            .session_authorizations
            .begin_outgoing(
                crate::session_authorization::VerifiedIncomingAuthorizationRequest {
                    session_id,
                    peer_device_id: DeviceId("secure-peer".to_string()),
                    peer_key_id: "secure-peer-key".to_string(),
                    peer_key_epoch: 1,
                    access_mode: RemoteAccessMode::Attended,
                    requested_scopes: vec![mrd_ipc::RemotePermissionScope::ScreenView],
                    peer_permission_ceiling: vec![mrd_ipc::RemotePermissionScope::ScreenView],
                    machine_permission_ceiling: vec![mrd_ipc::RemotePermissionScope::ScreenView],
                    runtime_capabilities: vec![mrd_ipc::RemotePermissionScope::ScreenView],
                    transport_kind: "quic".to_string(),
                    request_nonce: [7; 16],
                    created_at_ms,
                    expires_at_ms: created_at_ms.saturating_add(60_000),
                },
            )
            .await
            .expect("secure outgoing authorization");
    }

    #[tokio::test]
    async fn start_session_creates_session_in_registry() {
        let app_state = Arc::new(AppState::new());

        let session_id = SessionId("test-session".to_string());
        let target_device_id = DeviceId("agent".to_string());

        let response = start_session(
            &app_state,
            session_id.clone(),
            target_device_id,
            "quic".to_string(),
        )
        .await;

        match response {
            IpcResponse::SessionStarted {
                session_id: returned_id,
            } => {
                assert_eq!(returned_id, session_id);
            }
            _ => panic!("Expected SessionStarted response"),
        }

        // Verify session was stored
        let sessions = app_state.sessions.lock().await;
        let stored = sessions.get(&session_id);
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn start_session_rejects_secure_remote_session_bypass() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("secure-start-session".to_string());
        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;

        let response = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("legacy-target".to_string()),
            "quic".to_string(),
        )
        .await;

        let IpcResponse::RemoteAccessError {
            session_id: returned_session_id,
            failure,
            ..
        } = response
        else {
            panic!("expected secure legacy bypass error");
        };
        assert_eq!(returned_session_id, Some(session_id.clone()));
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
        assert!(app_state.sessions.lock().await.get(&session_id).is_none());
    }

    #[tokio::test]
    async fn accept_session_rechecks_secure_authorization_after_gate_contention() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("secure-accept-race".to_string());
        let authorization_guard = app_state.authorization_security_gate.lock().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task_state = app_state.clone();
        let task_session_id = session_id.clone();
        let mut accept_task = tokio::spawn(async move {
            started_tx.send(()).expect("signal accept task start");
            accept_session(
                &task_state,
                task_session_id,
                DeviceId("legacy-source".to_string()),
            )
            .await
        });

        started_rx.await.expect("accept task started");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut accept_task)
                .await
                .is_err(),
            "AcceptSession must serialize with secure authorization admission"
        );

        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;
        drop(authorization_guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(1), accept_task)
            .await
            .expect("AcceptSession resumed after authorization gate release")
            .expect("AcceptSession task completed");
        let IpcResponse::RemoteAccessError { failure, .. } = response else {
            panic!("expected secure legacy bypass error");
        };
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
        assert!(app_state.sessions.lock().await.get(&session_id).is_none());
    }

    #[tokio::test]
    async fn accept_session_holds_authorization_gate_through_legacy_mutation() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("legacy-accept-gate-symmetry".to_string());
        let sessions_guard = app_state.sessions.lock().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task_state = app_state.clone();
        let task_session_id = session_id.clone();
        let accept_task = tokio::spawn(async move {
            started_tx.send(()).expect("signal accept task start");
            accept_session(
                &task_state,
                task_session_id,
                DeviceId("legacy-source".to_string()),
            )
            .await
        });

        started_rx.await.expect("accept task started");
        let gate_was_held = tokio::time::timeout(std::time::Duration::from_millis(250), async {
            loop {
                match app_state.authorization_security_gate.try_lock() {
                    Ok(guard) => drop(guard),
                    Err(_) => break,
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        assert!(
            gate_was_held,
            "AcceptSession must retain the authorization gate while waiting to mutate sessions"
        );

        drop(sessions_guard);
        let response = tokio::time::timeout(std::time::Duration::from_secs(1), accept_task)
            .await
            .expect("AcceptSession completed after session registry release")
            .expect("AcceptSession task completed");
        assert!(matches!(response, IpcResponse::SessionAccepted { .. }));
        assert!(app_state.authorization_security_gate.try_lock().is_ok());
    }

    #[tokio::test]
    async fn get_remote_session_expires_a_grant_even_without_a_media_task() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("secure-snapshot-expiry".to_string());
        let injected = Arc::new(StdMutex::new(Vec::new()));
        *app_state.control_input().lock().await =
            crate::control_input::ControlInputRegistry::with_injector(
                SharedRecordingInputInjector {
                    events: Arc::clone(&injected),
                },
            );
        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;
        let issued_at_ms = current_time_ms();
        app_state
            .session_authorizations
            .install_verified_grant(
                crate::session_authorization::VerifiedSessionGrant {
                    grant_id: "snapshot-expiry-grant".to_string(),
                    session_id: session_id.clone(),
                    granted_scopes: vec![mrd_ipc::RemotePermissionScope::ScreenView],
                    issued_at_ms,
                    expires_at_ms: issued_at_ms.saturating_add(1),
                    policy_revision: 1,
                    route_constraint: "quic".to_string(),
                    transport_fingerprint_sha256: [0x71; 32],
                },
                issued_at_ms,
            )
            .await
            .expect("short-lived grant");
        app_state
            .control_input()
            .lock()
            .await
            .handle_session_event(
                &session_id,
                &ControlInputEvent::Key {
                    key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            )
            .expect("key down before grant expiry");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let IpcResponse::RemoteSession { session } =
            get_remote_session(&app_state, session_id).await
        else {
            panic!("expected authoritative remote session snapshot");
        };
        assert_eq!(
            session.authorization_state,
            mrd_ipc::RemoteAuthorizationState::Expired
        );
        assert_eq!(
            session.failure.as_ref().map(|failure| failure.code),
            Some(RemoteReasonCode::GrantExpired)
        );
        assert_eq!(
            injected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[
                InputEvent::Key {
                    key: mrd_input::InputKey::VirtualKey(0x41),
                    pressed: true,
                },
                InputEvent::Key {
                    key: mrd_input::InputKey::VirtualKey(0x41),
                    pressed: false,
                },
            ]
        );
    }

    #[tokio::test]
    async fn duplicate_start_session_returns_conflict_without_overwriting() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("duplicate-start-session".to_string());
        let original_target = DeviceId("original-target".to_string());
        let _ = start_session(
            &app_state,
            session_id.clone(),
            original_target.clone(),
            "quic".to_string(),
        )
        .await;

        let response = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("replacement-target".to_string()),
            "webrtc".to_string(),
        )
        .await;

        let IpcResponse::Error { code, message } = response else {
            panic!("expected duplicate-session conflict");
        };
        assert_eq!(code, "E409");
        assert!(message.contains(&session_id.0));
        let sessions = app_state.sessions.lock().await;
        let stored = sessions
            .get(&session_id)
            .expect("original session retained");
        assert_eq!(stored.target_device_id, Some(original_target));
        assert_eq!(stored.transport, "quic");
    }

    #[tokio::test]
    async fn start_lan_remote_session_rejects_missing_peer_without_session_side_effects() {
        let app_state = Arc::new(AppState::new());
        app_state
            .devices
            .lock()
            .await
            .register(DeviceId("controller".to_string()), "Controller".to_string());
        let session_id = SessionId("lan-session".to_string());

        let response = start_lan_remote_session(
            &app_state,
            session_id.clone(),
            DeviceId("missing-peer".to_string()),
            "webrtc".to_string(),
            None,
        )
        .await;

        let IpcResponse::RemoteAccessError {
            session_id: failed_session_id,
            peer_key_id,
            failure,
        } = response
        else {
            panic!("expected typed LAN remote error response");
        };
        assert_eq!(failed_session_id, Some(session_id.clone()));
        assert_eq!(peer_key_id, None);
        assert_eq!(failure.code, RemoteReasonCode::TrustRequired);
        assert!(failure.message.contains("missing-peer"));

        let sessions = app_state.sessions.lock().await;
        assert!(sessions.get(&session_id).is_none());
    }

    #[tokio::test]
    async fn start_lan_remote_session_error_terminalizes_admitted_authorization() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("failed-admitted-lan-session".to_string());
        let peer_device_id = DeviceId("secure-peer".to_string());
        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;

        let response = finish_start_lan_remote_session_error(
            &app_state,
            session_id.clone(),
            &peer_device_id,
            anyhow::anyhow!("LAN remote request timed out"),
        )
        .await;

        let IpcResponse::RemoteAccessError {
            session_id: failed_session_id,
            peer_key_id,
            failure,
        } = response
        else {
            panic!("expected typed LAN start error response");
        };
        assert_eq!(failed_session_id, Some(session_id.clone()));
        assert_eq!(peer_key_id.as_deref(), Some("secure-peer-key"));
        assert_eq!(failure.code, RemoteReasonCode::LanUnreachable);
        assert!(failure.message.contains("timed out"));
        let authorization = app_state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("terminal outgoing authorization");
        assert_eq!(
            authorization.authorization_state,
            mrd_ipc::RemoteAuthorizationState::Denied
        );
        assert_eq!(
            authorization.presentation_state,
            mrd_ipc::RemotePresentationState::Failed
        );
        assert_eq!(
            authorization.failure.as_ref().map(|failure| failure.code),
            Some(RemoteReasonCode::LanUnreachable)
        );
        assert!(authorization.granted_scopes.is_empty());
    }

    #[tokio::test]
    async fn list_sessions_returns_peer_device_context() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("listed-session".to_string());
        {
            let mut sessions = app_state.sessions.lock().await;
            sessions.insert(
                session_id.clone(),
                SessionSnapshot {
                    session_id: session_id.clone(),
                    transport: "quic".to_string(),
                    source_device_id: None,
                    target_device_id: Some(DeviceId("agent".to_string())),
                    local_listen_addr: None,
                    local_server_name: None,
                    local_cert_der_b64: None,
                    remote_listen_addr: None,
                    remote_server_name: None,
                    remote_cert_der_b64: None,
                    lifecycle_state: SessionLifecycleState::Streaming,
                    last_error: None,
                    sender_active: false,
                    receiver_active: true,
                },
            );
        }

        let response = list_sessions(&app_state).await;

        match response {
            IpcResponse::SessionList { sessions } => {
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].session_id, session_id);
                assert_eq!(sessions[0].role, "controller");
                assert_eq!(
                    sessions[0].peer_device_id,
                    Some(DeviceId("agent".to_string()))
                );
            }
            other => panic!("Expected SessionList response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn runtime_snapshot_reports_device_and_session_state() {
        let app_state = Arc::new(AppState::new());
        let device_id = DeviceId("local-device".to_string());
        app_state
            .devices
            .lock()
            .await
            .register(device_id.clone(), "Local Device".to_string());
        let session_id = SessionId("runtime-session".to_string());
        let _ = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("agent".to_string()),
            "quic".to_string(),
        )
        .await;

        let response = runtime_snapshot(&app_state).await;

        match response {
            IpcResponse::RuntimeSnapshot { snapshot } => {
                assert!(snapshot.is_registered);
                assert_eq!(snapshot.device_id, Some(device_id));
                assert_eq!(snapshot.sessions.len(), 1);
                assert_eq!(snapshot.sessions[0].session_id, session_id);
                assert_eq!(
                    snapshot.sessions[0].peer_device_id,
                    Some(DeviceId("agent".to_string()))
                );
            }
            other => panic!("Expected RuntimeSnapshot response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stop_session_removes_from_registry() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("test-session".to_string());

        // First create a session
        let _ = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("agent".to_string()),
            "quic".to_string(),
        )
        .await;

        // Then stop it
        let response = stop_session(&app_state, session_id.clone()).await;

        match response {
            IpcResponse::SessionStopped { .. } => {}
            _ => panic!("Expected SessionStopped response"),
        }

        // Verify session was retained as closed so UI can observe the stop.
        let sessions = app_state.sessions.lock().await;
        let stored = sessions
            .get(&session_id)
            .expect("closed session should remain");
        assert_eq!(stored.lifecycle_state, SessionLifecycleState::Closed);
        assert!(!stored.sender_active);
        assert!(!stored.receiver_active);
    }

    #[tokio::test]
    async fn stop_session_revokes_authorization_only_session_and_terminates_media() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("authorization-only-stop".to_string());
        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;
        let media_task = tokio::spawn(std::future::pending::<()>());
        app_state
            .media_tasks
            .lock()
            .await
            .register(session_id.clone(), media_task.abort_handle());

        let response = stop_session(&app_state, session_id.clone()).await;

        assert!(matches!(response, IpcResponse::SessionStopped { .. }));
        let authorization = app_state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("authorization retained for diagnostics");
        assert_eq!(
            authorization.authorization_state,
            mrd_ipc::RemoteAuthorizationState::Revoked
        );
        assert_eq!(
            authorization.failure.map(|failure| failure.code),
            Some(RemoteReasonCode::GrantRevoked)
        );
        tokio::task::yield_now().await;
        assert!(media_task.is_finished(), "authorization media must stop");
    }

    #[tokio::test]
    async fn stop_session_releases_active_control_input() {
        let app_state = Arc::new(AppState::new());
        app_state
            .replace_control_input_for_test(mrd_input::RecordingInputInjector::available())
            .await;
        let session_id = SessionId("control-stop-session".to_string());
        {
            let mut sessions = app_state.sessions.lock().await;
            sessions.insert(
                session_id.clone(),
                SessionSnapshot {
                    session_id: session_id.clone(),
                    transport: "quic".to_string(),
                    source_device_id: Some(DeviceId("controller-device".to_string())),
                    target_device_id: None,
                    local_listen_addr: None,
                    local_server_name: None,
                    local_cert_der_b64: None,
                    remote_listen_addr: None,
                    remote_server_name: None,
                    remote_cert_der_b64: None,
                    lifecycle_state: SessionLifecycleState::Listening,
                    last_error: None,
                    sender_active: true,
                    receiver_active: false,
                },
            );
        }

        app_state
            .control_input()
            .lock()
            .await
            .handle_session_event(
                &session_id,
                &mrd_ipc::ControlInputEvent::Key {
                    key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            )
            .expect("key down");

        let response = stop_session(&app_state, session_id.clone()).await;
        assert!(matches!(response, IpcResponse::SessionStopped { .. }));

        let snapshot = app_state.control_input().lock().await.snapshot(session_id);
        assert_eq!(snapshot.reliable.accepted_messages, 2);
        assert_eq!(snapshot.reliable.injected_messages, 2);
    }

    #[tokio::test]
    async fn fail_session_releases_active_control_input() {
        let app_state = Arc::new(AppState::new());
        app_state
            .replace_control_input_for_test(mrd_input::RecordingInputInjector::available())
            .await;
        let session_id = SessionId("control-fail-session".to_string());
        {
            let mut sessions = app_state.sessions.lock().await;
            sessions.insert(
                session_id.clone(),
                SessionSnapshot {
                    session_id: session_id.clone(),
                    transport: "quic".to_string(),
                    source_device_id: Some(DeviceId("controller-device".to_string())),
                    target_device_id: None,
                    local_listen_addr: None,
                    local_server_name: None,
                    local_cert_der_b64: None,
                    remote_listen_addr: None,
                    remote_server_name: None,
                    remote_cert_der_b64: None,
                    lifecycle_state: SessionLifecycleState::Listening,
                    last_error: None,
                    sender_active: true,
                    receiver_active: false,
                },
            );
        }

        app_state
            .control_input()
            .lock()
            .await
            .handle_session_event(
                &session_id,
                &mrd_ipc::ControlInputEvent::Key {
                    key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            )
            .expect("key down");

        let response =
            fail_session(&app_state, session_id.clone(), "transport lost".to_string()).await;
        assert!(matches!(response, IpcResponse::SessionFailed { .. }));

        let snapshot = app_state.control_input().lock().await.snapshot(session_id);
        assert_eq!(snapshot.reliable.accepted_messages, 2);
        assert_eq!(snapshot.reliable.injected_messages, 2);
    }

    #[tokio::test]
    async fn fail_session_terminalizes_authorization_only_session_and_terminates_media() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("authorization-only-fail".to_string());
        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;
        let media_task = tokio::spawn(std::future::pending::<()>());
        app_state
            .media_tasks
            .lock()
            .await
            .register(session_id.clone(), media_task.abort_handle());

        let response = fail_session(
            &app_state,
            session_id.clone(),
            "route handshake failed".to_string(),
        )
        .await;

        assert!(matches!(response, IpcResponse::SessionFailed { .. }));
        let authorization = app_state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("authorization retained for diagnostics");
        assert_eq!(
            authorization.authorization_state,
            mrd_ipc::RemoteAuthorizationState::Revoked
        );
        let failure = authorization.failure.expect("terminal failure");
        assert_eq!(failure.code, RemoteReasonCode::RouteLost);
        assert_eq!(failure.message, "route handshake failed");
        tokio::task::yield_now().await;
        assert!(media_task.is_finished(), "authorization media must stop");
    }

    #[tokio::test]
    async fn fail_session_clears_media_negotiation_state() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("media-fail-session".to_string());
        {
            let mut sessions = app_state.sessions.lock().await;
            sessions.insert(
                session_id.clone(),
                SessionSnapshot {
                    session_id: session_id.clone(),
                    transport: "quic".to_string(),
                    source_device_id: Some(DeviceId("controller-device".to_string())),
                    target_device_id: None,
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
        }

        let profile = MediaProfile {
            codec: "av1".to_string(),
            width: 2560,
            height: 1440,
            fps: 144,
            bitrate_mbps: 80,
            ..MediaProfile::default()
        };
        app_state.media_profiles.lock().await.set(
            session_id.clone(),
            mrd_ipc::MediaProfileNegotiation {
                requested: profile.clone(),
                selected: profile,
                status: "accepted".to_string(),
                reason: None,
                selected_source_id: Some("display:0".to_string()),
                selected_width: Some(2560),
                selected_height: Some(1440),
                downgrade_reason: None,
            },
        );
        app_state.capture_sources.lock().await.set(
            session_id.clone(),
            mrd_ipc::CaptureSourceSelection {
                session_id: session_id.clone(),
                source: mrd_ipc::CaptureSource {
                    id: "display:0".to_string(),
                    platform: "windows".to_string(),
                    source_kind: "display".to_string(),
                    title: "Primary".to_string(),
                    class_name: String::new(),
                    width: 2560,
                    height: 1440,
                    process_id: 0,
                    app_name: None,
                    bundle_identifier: None,
                    preview_data_url: None,
                    preview_width: None,
                    preview_height: None,
                },
                status: "selected".to_string(),
                reason: None,
            },
        );
        app_state.peer_media_capabilities.lock().await.set(
            session_id.clone(),
            vec![
                "media.codec.av1".to_string(),
                "media.color_mode_v1".to_string(),
            ],
        );

        let response =
            fail_session(&app_state, session_id.clone(), "transport lost".to_string()).await;
        assert!(matches!(response, IpcResponse::SessionFailed { .. }));

        assert!(app_state
            .media_profiles
            .lock()
            .await
            .get(&session_id)
            .is_none());
        assert!(app_state
            .capture_sources
            .lock()
            .await
            .get(&session_id)
            .is_none());
        assert!(!app_state
            .peer_media_capabilities
            .lock()
            .await
            .supports(&session_id, "media.codec.av1"));
    }

    #[tokio::test]
    async fn inactive_local_sender_session_rejects_control_input_without_injection() {
        let app_state = Arc::new(AppState::new());
        app_state
            .replace_control_input_for_test(mrd_input::RecordingInputInjector::available())
            .await;
        let session_id = SessionId("inactive-local-input-session".to_string());
        {
            let mut sessions = app_state.sessions.lock().await;
            sessions.insert(
                session_id.clone(),
                SessionSnapshot {
                    session_id: session_id.clone(),
                    transport: "quic".to_string(),
                    source_device_id: Some(DeviceId("controller-device".to_string())),
                    target_device_id: None,
                    local_listen_addr: None,
                    local_server_name: None,
                    local_cert_der_b64: None,
                    remote_listen_addr: None,
                    remote_server_name: None,
                    remote_cert_der_b64: None,
                    lifecycle_state: SessionLifecycleState::Connected,
                    last_error: None,
                    sender_active: false,
                    receiver_active: false,
                },
            );
        }

        let response = send_control_input(
            &app_state,
            session_id.clone(),
            mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            },
        )
        .await;

        match response {
            IpcResponse::Error { code, message } => {
                assert_eq!(code, "E_CONTROL_INPUT");
                assert!(message.contains("active local sender"));
            }
            other => panic!("expected inactive local sender control input error, got {other:?}"),
        }

        let snapshot = app_state.control_input().lock().await.snapshot(session_id);
        assert_eq!(snapshot.reliable.accepted_messages, 0);
        assert_eq!(snapshot.reliable.injected_messages, 0);
    }

    #[tokio::test]
    async fn stop_session_aborts_registered_media_tasks() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("test-session".to_string());

        let _ = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("agent".to_string()),
            "quic".to_string(),
        )
        .await;

        let task = tokio::spawn(async { std::future::pending::<()>().await });
        app_state
            .media_tasks
            .lock()
            .await
            .register(session_id.clone(), task.abort_handle());

        let response = stop_session(&app_state, session_id.clone()).await;

        assert!(matches!(response, IpcResponse::SessionStopped { .. }));
        tokio::task::yield_now().await;
        assert!(task.is_finished(), "media task should be aborted on stop");
        assert_eq!(
            app_state.media_tasks.lock().await.active_count(&session_id),
            0
        );
    }

    #[tokio::test]
    async fn fail_and_recover_session_updates_lifecycle_state() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("test-session".to_string());

        let _ = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("agent".to_string()),
            "quic".to_string(),
        )
        .await;

        let response =
            fail_session(&app_state, session_id.clone(), "transport lost".to_string()).await;
        assert!(matches!(response, IpcResponse::SessionFailed { .. }));

        {
            let sessions = app_state.sessions.lock().await;
            let stored = sessions.get(&session_id).expect("failed session");
            assert!(matches!(
                stored.lifecycle_state,
                SessionLifecycleState::Failed { .. }
            ));
            assert_eq!(stored.last_error.as_deref(), Some("transport lost"));
        }

        let response = recover_session(&app_state, session_id.clone()).await;
        assert!(matches!(response, IpcResponse::SessionRecovered { .. }));

        let sessions = app_state.sessions.lock().await;
        let stored = sessions.get(&session_id).expect("recovered session");
        assert_eq!(stored.lifecycle_state, SessionLifecycleState::Connecting);
        assert!(stored.last_error.is_none());
    }

    #[tokio::test]
    async fn recover_session_rejects_secure_remote_session_bypass() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("secure-recover-session".to_string());
        let _ = start_session(
            &app_state,
            session_id.clone(),
            DeviceId("secure-peer".to_string()),
            "quic".to_string(),
        )
        .await;
        let _ = fail_session(&app_state, session_id.clone(), "route lost".to_string()).await;
        begin_secure_outgoing_authorization(&app_state, session_id.clone()).await;

        let response = recover_session(&app_state, session_id.clone()).await;

        let IpcResponse::RemoteAccessError { failure, .. } = response else {
            panic!("expected secure legacy bypass error");
        };
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
        let sessions = app_state.sessions.lock().await;
        assert!(matches!(
            sessions
                .get(&session_id)
                .expect("legacy diagnostic projection retained")
                .lifecycle_state,
            SessionLifecycleState::Failed { .. }
        ));
    }

    #[test]
    fn lan_error_mapping_classifies_trust_failures() {
        let failure = map_lan_remote_session_error(
            &anyhow::anyhow!("LAN peer is not authenticated and trusted"),
            &DeviceId("peer".to_string()),
        );
        assert_eq!(failure.code, RemoteReasonCode::TrustRequired);
    }

    #[test]
    fn lan_error_mapping_classifies_protocol_failures() {
        let failure = map_lan_remote_session_error(
            &anyhow::anyhow!("signed LAN bootstrap has unsupported protocol version"),
            &DeviceId("peer".to_string()),
        );
        assert_eq!(failure.code, RemoteReasonCode::ProtocolDowngradeBlocked);
    }

    #[test]
    fn lan_error_mapping_classifies_identity_failures() {
        let failure = map_lan_remote_session_error(
            &anyhow::anyhow!("LAN QUIC certificate fingerprint does not match signed bootstrap"),
            &DeviceId("peer".to_string()),
        );
        assert_eq!(failure.code, RemoteReasonCode::IdentityMismatch);
    }

    #[test]
    fn lan_error_mapping_classifies_identity_protocol_errors() {
        for error in [
            crate::lan_discovery::LanProtocolError::InvalidKeyBinding,
            crate::lan_discovery::LanProtocolError::InvalidKeyEpoch,
            crate::lan_discovery::LanProtocolError::InvalidSignature,
            crate::lan_discovery::LanProtocolError::PeerBindingMismatch,
        ] {
            let failure = map_lan_remote_session_error(
                &anyhow::Error::new(error),
                &DeviceId("peer".to_string()),
            );
            assert_eq!(
                failure.code,
                RemoteReasonCode::IdentityMismatch,
                "{} must be classified as an identity failure",
                error
            );
        }

        let certificate_failure = map_lan_remote_session_error(
            &anyhow::Error::new(
                crate::lan_discovery::LanProtocolError::CertificateFingerprintMismatch,
            ),
            &DeviceId("peer".to_string()),
        );
        assert_eq!(
            certificate_failure.code,
            RemoteReasonCode::CertificateBindingMismatch
        );
    }

    #[tokio::test]
    async fn legacy_start_lan_error_preserves_typed_certificate_failure() {
        let app_state = Arc::new(AppState::new());
        let session_id = SessionId("certificate-session".to_string());

        let response = finish_start_lan_remote_session_error(
            &app_state,
            session_id.clone(),
            &DeviceId("peer".to_string()),
            anyhow::Error::new(
                crate::lan_discovery::LanProtocolError::CertificateFingerprintMismatch,
            ),
        )
        .await;

        let IpcResponse::RemoteAccessError {
            session_id: actual_session_id,
            failure,
            ..
        } = response
        else {
            panic!("expected typed remote-access failure");
        };
        assert_eq!(actual_session_id, Some(session_id));
        assert_eq!(failure.code, RemoteReasonCode::CertificateBindingMismatch);
    }

    #[test]
    fn lan_error_mapping_classifies_nonce_protocol_error_as_replay() {
        let error = crate::lan_discovery::LanProtocolError::InvalidNonce;
        let failure =
            map_lan_remote_session_error(&anyhow::Error::new(error), &DeviceId("peer".to_string()));
        assert_eq!(failure.code, RemoteReasonCode::ReplayDetected);
    }

    #[test]
    fn lan_error_mapping_classifies_remaining_protocol_errors_as_downgrade_blocked() {
        for error in [
            crate::lan_discovery::LanProtocolError::PayloadEncoding,
            crate::lan_discovery::LanProtocolError::SigningFailed,
            crate::lan_discovery::LanProtocolError::InvalidNamespace,
            crate::lan_discovery::LanProtocolError::UnsupportedProtocol,
            crate::lan_discovery::LanProtocolError::InvalidPayload,
            crate::lan_discovery::LanProtocolError::InvalidLifetime,
            crate::lan_discovery::LanProtocolError::NotYetValid,
            crate::lan_discovery::LanProtocolError::Expired,
            crate::lan_discovery::LanProtocolError::CapabilityMismatch,
            crate::lan_discovery::LanProtocolError::InvalidBootstrap,
        ] {
            let failure = map_lan_remote_session_error(
                &anyhow::Error::new(error),
                &DeviceId("peer".to_string()),
            );
            assert_eq!(
                failure.code,
                RemoteReasonCode::ProtocolDowngradeBlocked,
                "{} must be classified as a secure protocol failure",
                error
            );
        }
    }

    #[test]
    fn lan_error_mapping_classifies_media_profile_failures() {
        let failure = map_lan_remote_session_error(
            &anyhow::anyhow!("LAN peer does not advertise required media capabilities for av1"),
            &DeviceId("peer".to_string()),
        );
        assert_eq!(failure.code, RemoteReasonCode::ProfileDowngraded);
    }

    #[test]
    fn lan_error_mapping_distinguishes_authorization_timeout() {
        let failure = map_lan_remote_session_error(
            &anyhow::anyhow!("LAN authorization timed out waiting for local consent"),
            &DeviceId("peer".to_string()),
        );
        assert_eq!(failure.code, RemoteReasonCode::AuthorizationTimeout);
    }

    #[test]
    fn lan_error_mapping_keeps_route_timeout_and_unknown_io_unreachable() {
        for error in [
            anyhow::anyhow!("LAN remote request timed out"),
            anyhow::anyhow!("failed to bind LAN remote request UDP socket"),
        ] {
            let failure = map_lan_remote_session_error(&error, &DeviceId("peer".to_string()));
            assert_eq!(failure.code, RemoteReasonCode::LanUnreachable);
        }
    }
}
