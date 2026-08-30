use crate::app_state::{redact_audit_correlation_id, AppState, DeviceIdentityRegistryError};
use mrd_ipc::{
    DecimalU64, DeviceIdentitySnapshot, IpcResponse, RemoteFailure, RemoteReasonCode,
    TrustedDeviceSnapshot, TrustedDeviceState,
};
use mrd_proto::DeviceId;
use mrd_store_sqlite::{
    AuditDraft, AuditedTrustTransition, StoreError, TrustRecord, TrustState,
    TrustTransitionRejection,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Create or refresh a pending pairing record for a peer device.
pub async fn pair_device(
    app_state: &Arc<AppState>,
    device_id: DeviceId,
    certificate_fingerprint: Option<String>,
) -> IpcResponse {
    let registry = app_state.device_identities.clone();
    let result = tokio::task::spawn_blocking(move || {
        registry.upsert(device_id, certificate_fingerprint, "pending")
    })
    .await;
    if let Err(failure) = identity_mutation_result(app_state, result) {
        return failure.into_response();
    }
    IpcResponse::PairingUpdated {
        snapshot: identity_snapshot(app_state).await,
    }
}

/// Mark a known peer identity as paired while preserving its pinned fingerprint.
pub async fn approve_pairing(app_state: &Arc<AppState>, device_id: DeviceId) -> IpcResponse {
    let registry = app_state.device_identities.clone();
    let result =
        tokio::task::spawn_blocking(move || registry.upsert(device_id, None, "paired")).await;
    if let Err(failure) = identity_mutation_result(app_state, result) {
        return failure.into_response();
    }
    IpcResponse::PairingUpdated {
        snapshot: identity_snapshot(app_state).await,
    }
}

/// Revoke trust for a peer identity.
pub async fn revoke_device(app_state: &Arc<AppState>, device_id: DeviceId) -> IpcResponse {
    let registry = app_state.device_identities.clone();
    let result = tokio::task::spawn_blocking(move || registry.revoke(&device_id)).await;
    if let Err(failure) = identity_mutation_result(app_state, result) {
        return failure.into_response();
    }
    IpcResponse::PairingUpdated {
        snapshot: identity_snapshot(app_state).await,
    }
}

/// Return the current local identity and known peer trust state.
pub async fn identity_snapshot(app_state: &Arc<AppState>) -> DeviceIdentitySnapshot {
    let devices = app_state.devices.lock().await;
    let (local_device_id, display_name) = devices
        .get_local_device()
        .map(|(device_id, name)| (Some(device_id.clone()), Some(name.clone())))
        .unwrap_or((None, None));
    drop(devices);
    let paired_devices = app_state.device_identities.list().unwrap_or_default();
    DeviceIdentitySnapshot {
        local_device_id,
        display_name,
        certificate_fingerprint: app_state
            .device_identities
            .machine_key_id()
            .map(str::to_owned),
        consent_required: true,
        paired_devices,
    }
}

fn identity_mutation_result(
    app_state: &AppState,
    result: Result<Result<(), DeviceIdentityRegistryError>, tokio::task::JoinError>,
) -> Result<(), IdentityMutationFailure> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(DeviceIdentityRegistryError::AuthenticatedPeerRequired)) => {
            Err(IdentityMutationFailure::AuthenticatedPeerRequired)
        }
        Ok(Err(DeviceIdentityRegistryError::Store(_))) | Err(_) => {
            app_state.mark_security_unhealthy();
            Err(IdentityMutationFailure::StoreUnavailable)
        }
    }
}

enum IdentityMutationFailure {
    AuthenticatedPeerRequired,
    StoreUnavailable,
}

impl IdentityMutationFailure {
    fn into_response(self) -> IpcResponse {
        match self {
            Self::AuthenticatedPeerRequired => IpcResponse::Error {
                code: "E_AUTHENTICATED_PEER_REQUIRED".to_string(),
                message: "pairing requires an authenticated peer public key".to_string(),
            },
            Self::StoreUnavailable => IpcResponse::Error {
                code: "E_SECURITY_STORE_UNAVAILABLE".to_string(),
                message: "authoritative security state is unavailable".to_string(),
            },
        }
    }
}

/// Wrap the identity snapshot in its IPC response contract.
pub async fn get_device_identity_snapshot(app_state: &Arc<AppState>) -> IpcResponse {
    IpcResponse::DeviceIdentitySnapshot {
        snapshot: identity_snapshot(app_state).await,
    }
}

/// List durable public-key-pinned trust records without exposing pinned key bytes.
pub async fn list_trusted_devices(app_state: &Arc<AppState>, include_revoked: bool) -> IpcResponse {
    let registry = app_state.device_identities.clone();
    match tokio::task::spawn_blocking(move || registry.trusted_records(include_revoked)).await {
        Ok(Ok(records)) => IpcResponse::TrustedDeviceList {
            devices: records.into_iter().map(project_trust_record).collect(),
        },
        Ok(Err(error)) => identity_registry_error_response(app_state, error),
        Err(_) => security_store_error(app_state),
    }
}

/// Suspend a pinned peer under optimistic trust revision and atomic durable audit.
pub async fn suspend_trusted_device(
    app_state: &Arc<AppState>,
    peer_key_id: String,
    expected_revision: u64,
) -> IpcResponse {
    transition_trusted_device(
        app_state,
        peer_key_id,
        expected_revision,
        TrustState::Suspended,
        "trust.suspended",
    )
    .await
}

/// Permanently revoke a pinned peer under optimistic trust revision and atomic durable audit.
pub async fn revoke_trusted_device(
    app_state: &Arc<AppState>,
    peer_key_id: String,
    expected_revision: u64,
) -> IpcResponse {
    transition_trusted_device(
        app_state,
        peer_key_id,
        expected_revision,
        TrustState::Revoked,
        "trust.revoked",
    )
    .await
}

async fn transition_trusted_device(
    app_state: &Arc<AppState>,
    peer_key_id: String,
    expected_revision: u64,
    next: TrustState,
    action: &'static str,
) -> IpcResponse {
    if !valid_peer_key_id(&peer_key_id) {
        return IpcResponse::Error {
            code: "E_INVALID_PEER_KEY_ID".to_string(),
            message: "peer key identifier must be a SHA-256 hex value".to_string(),
        };
    }
    let _authorization_security_guard = app_state.authorization_security_gate.lock().await;
    let actor_device_id = app_state
        .devices
        .lock()
        .await
        .get_local_device()
        .map(|(device_id, _)| redact_audit_correlation_id(device_id.0.clone()));
    let audit = AuditDraft {
        timestamp_ms: now_unix_ms(),
        action: action.to_owned(),
        outcome: "attempted".to_owned(),
        session_id: None,
        actor_device_id,
        peer_device_id: None,
        transport_kind: None,
        reason_code: None,
        details: BTreeMap::from([("peer_key_id".to_owned(), peer_key_id.clone())]),
    };
    let registry = app_state.device_identities.clone();
    let transition_peer_key_id = peer_key_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        registry.transition_authenticated_peer(
            &transition_peer_key_id,
            expected_revision,
            next,
            audit,
        )
    })
    .await;
    match result {
        Ok(Ok(AuditedTrustTransition::Applied(applied))) => {
            let device = project_trust_record(applied.record);
            let revoked_session_ids = app_state
                .session_authorizations
                .revoke_peer_authorizations(&peer_key_id, now_unix_ms())
                .await;
            let mut lan_session_ids = Vec::new();
            for session_id in revoked_session_ids {
                match crate::wan_session::service::resolve_session_kind_under_security_gate(
                    app_state,
                    &session_id,
                )
                .await
                {
                    crate::wan_session::service::ServiceSessionKind::Wan => {
                    match crate::wan_session::service::terminalize_wan_session_under_security_gate(
                        app_state,
                        &session_id,
                        crate::wan_session::service::ServiceWanTerminalRequest::Fail {
                            failure: crate::wan_session::model::WanSessionFailure::Cancelled,
                            remote_failure: RemoteFailure {
                                code: RemoteReasonCode::GrantRevoked,
                                message: "trusted device access was revoked".to_owned(),
                                suggested_action: Some(
                                    "start a new session after restoring trust".to_owned(),
                                ),
                            },
                        },
                    )
                    .await
                    {
                        Ok(Some(_)) | Ok(None) => {}
                        Err(_) => {
                            app_state.mark_security_unhealthy();
                            tracing::error!(
                                session_id = %session_id.0,
                                "trusted-device transition left WAN cleanup incomplete"
                            );
                        }
                    }
                    }
                    crate::wan_session::service::ServiceSessionKind::Lan => {
                        lan_session_ids.push(session_id);
                    }
                    crate::wan_session::service::ServiceSessionKind::Unknown => {
                        app_state.mark_security_unhealthy();
                        tracing::error!(
                            session_id = %session_id.0,
                            "trusted-device transition could not resolve session authority"
                        );
                    }
                }
            }
            crate::lan_discovery::terminate_authorized_remote_sessions_under_security_gate(
                app_state,
                &lan_session_ids,
            )
            .await;
            IpcResponse::TrustedDeviceUpdated { device }
        }
        Ok(Ok(AuditedTrustTransition::Rejected { rejection, .. })) => {
            trust_rejection_response(rejection)
        }
        Ok(Err(error)) => identity_registry_error_response(app_state, error),
        Err(_) => security_store_error(app_state),
    }
}

fn project_trust_record(record: TrustRecord) -> TrustedDeviceSnapshot {
    // Store format v2 pins identity/state only. Empty scopes are a deny-all projection;
    // optional presentation/approval metadata remains unknown rather than fabricated.
    TrustedDeviceSnapshot {
        peer_key_id: record.peer_key_id,
        display_name: None,
        key_epoch: DecimalU64::from(record.epoch),
        state: match record.state {
            TrustState::Trusted => TrustedDeviceState::Trusted,
            TrustState::Suspended => TrustedDeviceState::Suspended,
            TrustState::Revoked => TrustedDeviceState::Revoked,
        },
        permission_ceiling: Vec::new(),
        trust_revision: DecimalU64::from(record.revision),
        approved_at_ms: None,
        updated_at_ms: record.updated_at_ms,
    }
}

fn identity_registry_error_response(
    app_state: &AppState,
    error: DeviceIdentityRegistryError,
) -> IpcResponse {
    match error {
        DeviceIdentityRegistryError::AuthenticatedPeerRequired => IpcResponse::Error {
            code: "E_SECURE_REMOTE_UNAVAILABLE".to_string(),
            message: "persistent trust state is unavailable in this service mode".to_string(),
        },
        DeviceIdentityRegistryError::Store(StoreError::InvalidAuditEvent) => IpcResponse::Error {
            code: "E_INVALID_TRUST_REQUEST".to_string(),
            message: "trust request is outside the supported bounds".to_string(),
        },
        DeviceIdentityRegistryError::Store(_) => security_store_error(app_state),
    }
}

fn security_store_error(app_state: &AppState) -> IpcResponse {
    app_state.mark_security_unhealthy();
    IpcResponse::Error {
        code: "E_SECURITY_STORE_UNAVAILABLE".to_string(),
        message: "authoritative security state is unavailable".to_string(),
    }
}

fn trust_rejection_response(rejection: TrustTransitionRejection) -> IpcResponse {
    let code = match rejection {
        TrustTransitionRejection::NotFound => "E_TRUST_NOT_FOUND",
        TrustTransitionRejection::RevisionMismatch => "E_TRUST_REVISION_MISMATCH",
        TrustTransitionRejection::RevokedTerminal => "E_TRUST_REVOKED_TERMINAL",
    };
    IpcResponse::Error {
        code: code.to_string(),
        message: "trust transition was rejected".to_string(),
    }
}

fn valid_peer_key_id(peer_key_id: &str) -> bool {
    peer_key_id.len() == 64
        && peer_key_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
