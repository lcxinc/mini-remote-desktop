//! Production registration boundary for an already connected relay-only WebRTC session.

use super::{RelayAccessContext, RelayFailoverConfigError, VerifiedRelayAccess};
use crate::{transports::webrtc::ServiceWebRtcTransportError, AppState};
use mrd_application::ports::TransportMuxPort;
use mrd_proto::SessionId;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelaySessionInstallError {
    #[error("relay failover runtime is unavailable")]
    RuntimeUnavailable,
    #[error("relay session lacks a current controller or agent authorization grant")]
    AuthorizationUnavailable,
    #[error("initial relay route could not be verified")]
    Transport(#[from] ServiceWebRtcTransportError),
    #[error("initial relay session registration failed")]
    Coordinator(#[from] RelayFailoverConfigError),
}

/// Register a connected WebRTC session only after generation-zero selected-pair evidence
/// proves that both endpoints are relay candidates from the exact signed-directory URL set.
pub async fn install_connected_relay_session(
    app_state: &Arc<AppState>,
    context: RelayAccessContext,
    access: Arc<VerifiedRelayAccess>,
    active_node_id: &str,
) -> Result<(), RelaySessionInstallError> {
    let coordinator = app_state
        .relay_failover_coordinator()
        .ok_or(RelaySessionInstallError::RuntimeUnavailable)?;
    let session_id = SessionId(context.session_id.clone());
    let authorization = app_state
        .session_authorizations
        .snapshot(&session_id)
        .await
        .filter(|snapshot| {
            snapshot.authorization_state == mrd_ipc::RemoteAuthorizationState::Granted
        })
        .ok_or(RelaySessionInstallError::AuthorizationUnavailable)?;
    let route = access
        .route_evidence(active_node_id, 0)
        .map_err(|_| RelayFailoverConfigError::ActiveRelayEvidenceMismatch)?;
    let evidence = app_state
        .webrtc_host
        .verify_active_relay(&session_id, route)
        .await?;
    let mux: Arc<dyn TransportMuxPort> = app_state.webrtc_host.transport_mux(&session_id).await?;
    coordinator
        .install_verified_session(context, access, active_node_id, evidence, mux)
        .await?;
    if let Err(error) = app_state
        .webrtc_host
        .enable_relay_failover(&session_id)
        .await
    {
        let _ = coordinator
            .terminate_security(
                &session_id,
                super::RelayTerminalSecurityReason::RouteEvidenceMismatch,
            )
            .await;
        return Err(error.into());
    }
    if authorization.role == mrd_ipc::RemoteSessionRole::Controller {
        spawn_controller_health_monitor(
            Arc::clone(&app_state.webrtc_host),
            coordinator,
            session_id,
        );
    }
    Ok(())
}

fn spawn_controller_health_monitor(
    host: Arc<crate::transports::webrtc::ServiceWebRtcTransportHost>,
    coordinator: Arc<super::RelayFailoverCoordinator>,
    session_id: SessionId,
) {
    tokio::spawn(async move {
        loop {
            let observed_generation = match host.wait_failover_needed(&session_id).await {
                Ok(generation) => generation,
                Err(_) => break,
            };
            let outcome = coordinator
                .observe_health(
                    &session_id,
                    observed_generation,
                    super::RelayConnectionHealth::Failed,
                )
                .await;
            match outcome {
                Ok(super::RelayRecoveryOutcome::Migrated { .. }) => continue,
                Ok(super::RelayRecoveryOutcome::Terminal { .. }) | Err(_) => break,
                Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            }
        }
    });
}
