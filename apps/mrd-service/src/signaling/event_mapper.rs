use crate::{session_authorization::VerifiedIncomingAuthorizationRequest, AppState};
use anyhow::{bail, Context, Result};
use mrd_application::{
    AuthenticatedSessionSignal, AuthenticatedSessionSignalPort, SessionLifecycleState,
    SessionSnapshot, VerifiedSignalingEvent,
};
use mrd_ipc::{RemoteAccessMode, RemotePermissionScope};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct WebRtcGrantBinding {
    peer_key_id: String,
    accepted_fingerprints: Vec<String>,
}

#[derive(Clone)]
struct RelayMigrationBinding {
    peer_key_id: String,
    generation: u64,
    directory_id: String,
    node_id: String,
    restart_route_token: String,
    peer_candidate_fingerprints: HashSet<String>,
    direction: RelayMigrationDirection,
}

impl std::fmt::Debug for RelayMigrationBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayMigrationBinding")
            .field("generation", &self.generation)
            .field("direction", &self.direction)
            .field("body", &"REDACTED")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMigrationDirection {
    IncomingOffer,
    OutboundOffer,
}

/// Applies verified WAN signaling to the service's authoritative aggregates.
pub struct ServiceSignalingMapper {
    app_state: Arc<AppState>,
    signaling_state_gate: Mutex<()>,
    webrtc_grants: Mutex<HashMap<mrd_proto::SessionId, WebRtcGrantBinding>>,
    relay_migrations: Mutex<HashMap<mrd_proto::SessionId, RelayMigrationBinding>>,
    relay_signaling: Arc<super::RelaySignalingBus>,
}

impl ServiceSignalingMapper {
    /// Bind the mapper to the service-owned application state.
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self {
            relay_signaling: Arc::clone(&app_state.relay_signaling),
            app_state,
            signaling_state_gate: Mutex::new(()),
            webrtc_grants: Mutex::new(HashMap::new()),
            relay_migrations: Mutex::new(HashMap::new()),
        }
    }

    async fn apply_intent(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: mrd_proto::SessionId,
        idempotency_key: [u8; 16],
        requested_transport: String,
    ) -> Result<()> {
        let _authorization_guard = self.app_state.authorization_security_gate.lock().await;
        if let Some(existing) = self
            .app_state
            .sessions
            .lock()
            .await
            .get(&session_id)
            .cloned()
        {
            if existing.source_device_id.as_ref() == Some(&event.sender.device_id)
                && existing.transport == requested_transport
            {
                let authorization = self
                    .app_state
                    .session_authorizations
                    .snapshot_at(&session_id, event.sender.issued_at_ms)
                    .await
                    .context("existing session has no authenticated authorization aggregate")?;
                if authorization.peer_device_id == event.sender.device_id
                    && authorization.peer_key_id == event.sender.key_id
                    && authorization.role == mrd_ipc::RemoteSessionRole::Agent
                {
                    return Ok(());
                }
            }
            bail!("signaling session identifier is already bound to another peer");
        }

        let interactive_scopes = vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputPointer,
            RemotePermissionScope::InputKeyboard,
        ];
        self.app_state
            .session_authorizations
            .begin_verified_incoming(VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: event.sender.device_id.clone(),
                peer_key_id: event.sender.key_id.clone(),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: interactive_scopes.clone(),
                peer_permission_ceiling: interactive_scopes.clone(),
                machine_permission_ceiling: interactive_scopes.clone(),
                runtime_capabilities: interactive_scopes,
                transport_kind: requested_transport.clone(),
                request_nonce: idempotency_key,
                created_at_ms: event.sender.issued_at_ms,
                expires_at_ms: event.sender.expires_at_ms,
            })
            .await
            .map_err(|failure| anyhow::anyhow!(failure.message))?;
        if let Err(failure) = self
            .app_state
            .session_authorizations
            .bind_authenticated_peer_key(
                &session_id,
                &event.sender.public_key,
                event.sender.issued_at_ms,
            )
            .await
        {
            let _ = self
                .app_state
                .session_authorizations
                .record_failure(
                    &session_id,
                    mrd_ipc::RemoteAuthorizationState::Denied,
                    failure.clone(),
                    event.sender.issued_at_ms,
                )
                .await;
            bail!(failure.message);
        }
        self.app_state.sessions.lock().await.insert(
            session_id.clone(),
            SessionSnapshot {
                session_id,
                transport: requested_transport,
                source_device_id: Some(event.sender.device_id.clone()),
                target_device_id: None,
                local_listen_addr: None,
                local_server_name: None,
                local_cert_der_b64: None,
                remote_listen_addr: None,
                remote_server_name: None,
                remote_cert_der_b64: None,
                lifecycle_state: SessionLifecycleState::Created,
                last_error: None,
                sender_active: false,
                receiver_active: false,
            },
        );
        Ok(())
    }

    async fn update_session<F>(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: &mrd_proto::SessionId,
        update: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut SessionSnapshot) -> Result<()>,
    {
        let authorization = self
            .app_state
            .session_authorizations
            .snapshot_at(session_id, event.sender.issued_at_ms)
            .await;
        let mut sessions = self.app_state.sessions.lock().await;
        let mut snapshot = sessions
            .get(session_id)
            .cloned()
            .with_context(|| format!("signaling session not found: {}", session_id.0))?;
        let expected_peer = snapshot
            .target_device_id
            .as_ref()
            .or(snapshot.source_device_id.as_ref());
        if expected_peer != Some(&event.sender.device_id) {
            bail!("signaling sender is not the session peer");
        }
        if let Some(authorization) = authorization {
            if authorization.peer_device_id != event.sender.device_id
                || authorization.peer_key_id != event.sender.key_id
            {
                bail!("signaling sender key does not match the session authorization");
            }
        }
        update(&mut snapshot)?;
        sessions.insert(session_id.clone(), snapshot);
        Ok(())
    }

    async fn require_webrtc_fingerprint(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: &mrd_proto::SessionId,
        fingerprint: &str,
    ) -> Result<()> {
        let grants = self.webrtc_grants.lock().await;
        let binding = grants
            .get(session_id)
            .context("WebRTC signaling arrived without an authenticated grant")?;
        if binding.peer_key_id != event.sender.key_id
            || !binding
                .accepted_fingerprints
                .iter()
                .any(|accepted| accepted == fingerprint)
        {
            bail!("WebRTC candidate is not bound to the authenticated grant");
        }
        Ok(())
    }

    async fn require_webrtc_grant(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: &mrd_proto::SessionId,
    ) -> Result<()> {
        let grants = self.webrtc_grants.lock().await;
        let binding = grants
            .get(session_id)
            .context("WebRTC signaling arrived without an authenticated grant")?;
        if binding.peer_key_id != event.sender.key_id {
            bail!("WebRTC signaling peer does not match the authenticated grant");
        }
        Ok(())
    }

    async fn require_live_session(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: &mrd_proto::SessionId,
    ) -> Result<()> {
        self.update_session(event, session_id, |snapshot| {
            if snapshot.lifecycle_state.is_terminal() {
                bail!("terminal session cannot accept relay migration signaling");
            }
            Ok(())
        })
        .await
    }

    async fn terminate_relay_if_installed(
        &self,
        session_id: &mrd_proto::SessionId,
        reason: crate::relay::RelayTerminalSecurityReason,
    ) -> Result<()> {
        let Some(coordinator) = self.app_state.relay_failover_coordinator() else {
            return Ok(());
        };
        if coordinator.snapshot(session_id).await.is_err() {
            return Ok(());
        }
        coordinator
            .terminate_security(session_id, reason)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_relay_migration_offer(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: &mrd_proto::SessionId,
        generation: u64,
        directory_id: &str,
        node_id: &str,
        restart_route_token: &str,
        candidate_fingerprints: &[String],
    ) -> Result<()> {
        self.require_live_session(event, session_id).await?;
        self.require_webrtc_grant(event, session_id).await?;
        let mut migrations = self.relay_migrations.lock().await;
        let expected = match migrations.get(session_id) {
            Some(binding) => binding
                .generation
                .checked_add(1)
                .context("relay migration generation is exhausted")?,
            None => 1,
        };
        if generation == 0 || generation != expected {
            bail!("relay migration generation is stale or skipped");
        }
        migrations.insert(
            session_id.clone(),
            RelayMigrationBinding {
                peer_key_id: event.sender.key_id.clone(),
                generation,
                directory_id: directory_id.to_owned(),
                node_id: node_id.to_owned(),
                restart_route_token: restart_route_token.to_owned(),
                peer_candidate_fingerprints: candidate_fingerprints.iter().cloned().collect(),
                direction: RelayMigrationDirection::IncomingOffer,
            },
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn require_relay_migration_binding(
        &self,
        event: &VerifiedSignalingEvent,
        session_id: &mrd_proto::SessionId,
        generation: u64,
        directory_id: &str,
        node_id: &str,
        restart_route_token: &str,
        required_direction: Option<RelayMigrationDirection>,
    ) -> Result<()> {
        self.require_live_session(event, session_id).await?;
        let migrations = self.relay_migrations.lock().await;
        let binding = migrations
            .get(session_id)
            .context("relay migration signaling arrived without an active generation")?;
        if binding.peer_key_id != event.sender.key_id
            || binding.generation != generation
            || binding.directory_id != directory_id
            || binding.node_id != node_id
            || binding.restart_route_token != restart_route_token
            || required_direction.is_some_and(|direction| binding.direction != direction)
        {
            bail!("relay migration signaling does not match the active generation");
        }
        Ok(())
    }

    /// Bind a locally initiated relay migration before its signed offer is sent.
    pub async fn bind_outbound_relay_migration(
        &self,
        session_id: mrd_proto::SessionId,
        peer_key_id: String,
        generation: u64,
        directory_id: String,
        node_id: String,
        restart_route_token: String,
    ) -> Result<()> {
        if generation == 0
            || peer_key_id.is_empty()
            || peer_key_id.len() > 256
            || directory_id.is_empty()
            || directory_id.len() > 256
            || directory_id.chars().any(char::is_control)
            || node_id.is_empty()
            || node_id.len() > 256
            || node_id.chars().any(char::is_control)
            || !valid_restart_route_token(&restart_route_token)
        {
            bail!("outbound relay migration binding is invalid");
        }
        let _signaling_state_guard = self.signaling_state_gate.lock().await;
        let session = self
            .app_state
            .sessions
            .lock()
            .await
            .get(&session_id)
            .cloned()
            .context("outbound relay migration session does not exist")?;
        if session.lifecycle_state.is_terminal() {
            bail!("terminal session cannot start relay migration");
        }
        let grants = self.webrtc_grants.lock().await;
        let grant = grants
            .get(&session_id)
            .context("outbound relay migration requires an authenticated grant")?;
        if grant.peer_key_id != peer_key_id {
            bail!("outbound relay migration peer does not match the authenticated grant");
        }
        drop(grants);
        let mut migrations = self.relay_migrations.lock().await;
        let expected = match migrations.get(&session_id) {
            Some(binding) => binding
                .generation
                .checked_add(1)
                .context("outbound relay migration generation is exhausted")?,
            None => 1,
        };
        if generation != expected {
            bail!("outbound relay migration generation is stale or skipped");
        }
        migrations.insert(
            session_id,
            RelayMigrationBinding {
                peer_key_id,
                generation,
                directory_id,
                node_id,
                restart_route_token,
                peer_candidate_fingerprints: HashSet::new(),
                direction: RelayMigrationDirection::OutboundOffer,
            },
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthenticatedSessionSignalPort for ServiceSignalingMapper {
    async fn apply_authenticated_signal(&self, event: VerifiedSignalingEvent) -> Result<()> {
        // Grant replacement, terminalization, and migration generation changes form one
        // security state machine. Serialize them so a migration cannot be installed from a
        // grant that is concurrently being replaced or revoked.
        let _signaling_state_guard = self.signaling_state_gate.lock().await;
        match event.signal.clone() {
            AuthenticatedSessionSignal::SessionIntentV3 { .. }
            | AuthenticatedSessionSignal::WebRtcOfferV3 { .. }
            | AuthenticatedSessionSignal::WebRtcAnswerV3 { .. }
            | AuthenticatedSessionSignal::WebRtcCandidateV3 { .. } => {
                self.relay_signaling.publish(event).await;
                Ok(())
            }
            AuthenticatedSessionSignal::SessionGrantV3 { ref message } => {
                let _authorization_guard = self.app_state.authorization_security_gate.lock().await;
                let authorization = self
                    .app_state
                    .session_authorizations
                    .snapshot_at(&message.payload.session_id, event.sender.issued_at_ms)
                    .await
                    .context("WAN grant has no pending controller authorization")?;
                if authorization.role != mrd_ipc::RemoteSessionRole::Controller
                    || authorization.authorization_state
                        != mrd_ipc::RemoteAuthorizationState::Authorizing
                    || authorization.peer_device_id != event.sender.device_id
                    || authorization
                        .authorization_expires_at_ms
                        .is_none_or(|expires_at_ms| expires_at_ms < event.sender.expires_at_ms)
                {
                    bail!("WAN grant does not match the pending controller authorization");
                }
                self.relay_signaling.publish(event).await;
                Ok(())
            }
            AuthenticatedSessionSignal::AuthorizationRequested {
                session_id,
                idempotency_key,
                requested_transport,
            } => {
                self.apply_intent(&event, session_id, idempotency_key, requested_transport)
                    .await
            }
            AuthenticatedSessionSignal::Granted {
                session_id,
                accepted_transport,
                accepted_candidate_fingerprints,
            } => {
                self.terminate_relay_if_installed(
                    &session_id,
                    crate::relay::RelayTerminalSecurityReason::PolicyChanged,
                )
                .await?;
                self.update_session(&event, &session_id, |snapshot| {
                    if snapshot.lifecycle_state.is_terminal() {
                        bail!("terminal session cannot accept a signaling grant");
                    }
                    snapshot.transport = accepted_transport.clone();
                    snapshot.lifecycle_state = SessionLifecycleState::Connecting;
                    snapshot.last_error = None;
                    Ok(())
                })
                .await?;
                self.webrtc_grants.lock().await.insert(
                    session_id.clone(),
                    WebRtcGrantBinding {
                        peer_key_id: event.sender.key_id,
                        accepted_fingerprints: accepted_candidate_fingerprints,
                    },
                );
                self.relay_migrations.lock().await.remove(&session_id);
                Ok(())
            }
            AuthenticatedSessionSignal::Denied { session_id, reason } => {
                self.update_session(&event, &session_id, |snapshot| {
                    let message = format!("remote session denied: {reason:?}");
                    snapshot.lifecycle_state = SessionLifecycleState::Failed {
                        message: message.clone(),
                    };
                    snapshot.last_error = Some(message);
                    snapshot.sender_active = false;
                    snapshot.receiver_active = false;
                    Ok(())
                })
                .await?;
                self.webrtc_grants.lock().await.remove(&session_id);
                self.relay_migrations.lock().await.remove(&session_id);
                self.terminate_relay_if_installed(
                    &session_id,
                    crate::relay::RelayTerminalSecurityReason::RelayRevoked,
                )
                .await?;
                Ok(())
            }
            AuthenticatedSessionSignal::Closed { session_id, .. } => {
                self.update_session(&event, &session_id, |snapshot| {
                    snapshot.lifecycle_state = SessionLifecycleState::Closed;
                    snapshot.sender_active = false;
                    snapshot.receiver_active = false;
                    Ok(())
                })
                .await?;
                self.webrtc_grants.lock().await.remove(&session_id);
                self.relay_migrations.lock().await.remove(&session_id);
                self.terminate_relay_if_installed(
                    &session_id,
                    crate::relay::RelayTerminalSecurityReason::RelayRevoked,
                )
                .await?;
                self.relay_signaling
                    .close_authenticated_session(&session_id)
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                Ok(())
            }
            AuthenticatedSessionSignal::WebRtcCandidate {
                session_id,
                candidate_fingerprint,
                ..
            } => {
                self.require_webrtc_fingerprint(&event, &session_id, &candidate_fingerprint)
                    .await
            }
            AuthenticatedSessionSignal::WebRtcOffer {
                session_id,
                candidate_fingerprints,
                ..
            }
            | AuthenticatedSessionSignal::WebRtcAnswer {
                session_id,
                candidate_fingerprints,
                ..
            } => {
                self.require_webrtc_grant(&event, &session_id).await?;
                for fingerprint in candidate_fingerprints {
                    self.require_webrtc_fingerprint(&event, &session_id, &fingerprint)
                        .await?;
                }
                Ok(())
            }
            AuthenticatedSessionSignal::RelayMigrationOffer {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                restart_route_token,
                candidate_fingerprints,
                ..
            } => {
                self.apply_relay_migration_offer(
                    &event,
                    &session_id,
                    migration_generation,
                    &directory_id,
                    &node_id,
                    &restart_route_token,
                    &candidate_fingerprints,
                )
                .await?;
                self.relay_signaling.publish(event).await;
                Ok(())
            }
            AuthenticatedSessionSignal::RelayMigrationAnswer {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                restart_route_token,
                candidate_fingerprints,
                ..
            } => {
                self.require_relay_migration_binding(
                    &event,
                    &session_id,
                    migration_generation,
                    &directory_id,
                    &node_id,
                    &restart_route_token,
                    Some(RelayMigrationDirection::OutboundOffer),
                )
                .await?;
                self.require_webrtc_grant(&event, &session_id).await?;
                let mut migrations = self.relay_migrations.lock().await;
                let binding = migrations
                    .get_mut(&session_id)
                    .context("relay migration answer has no active binding")?;
                binding.peer_candidate_fingerprints = candidate_fingerprints.into_iter().collect();
                drop(migrations);
                self.relay_signaling.publish(event).await;
                Ok(())
            }
            AuthenticatedSessionSignal::RelayMigrationCandidate {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
                restart_route_token,
                candidate_fingerprint,
            } => {
                self.require_relay_migration_binding(
                    &event,
                    &session_id,
                    migration_generation,
                    &directory_id,
                    &node_id,
                    &restart_route_token,
                    None,
                )
                .await?;
                let computed = super::relay_candidate_fingerprint(
                    &session_id,
                    migration_generation,
                    &candidate,
                    sdp_mid.as_deref(),
                    sdp_mline_index,
                    username_fragment.as_deref(),
                    &restart_route_token,
                );
                if computed != candidate_fingerprint {
                    bail!("relay migration candidate fingerprint does not match its payload");
                }
                let migrations = self.relay_migrations.lock().await;
                let binding = migrations
                    .get(&session_id)
                    .context("relay migration candidate has no active binding")?;
                if !binding
                    .peer_candidate_fingerprints
                    .contains(&candidate_fingerprint)
                {
                    bail!("relay migration candidate was not committed by its description");
                }
                drop(migrations);
                self.relay_signaling.publish(event).await;
                Ok(())
            }
        }
    }
}

fn valid_restart_route_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{RelayMigrationBinding, RelayMigrationDirection};
    use std::collections::HashSet;

    #[test]
    fn relay_migration_binding_debug_redacts_route_token() {
        let binding = RelayMigrationBinding {
            peer_key_id: "peer-key".into(),
            generation: 1,
            directory_id: "directory-1".into(),
            node_id: "relay-1".into(),
            restart_route_token: "TEST_ONLY_RESTART_ROUTE_TOKEN_SENTINEL".into(),
            peer_candidate_fingerprints: HashSet::new(),
            direction: RelayMigrationDirection::IncomingOffer,
        };

        let rendered = format!("{binding:?}");
        assert!(!rendered.contains("TEST_ONLY_RESTART_ROUTE_TOKEN_SENTINEL"));
        assert!(rendered.contains("REDACTED"));
    }
}
