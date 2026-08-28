use super::coordinator::{WanSessionPortError, WanSessionWorkflowSignaling};
use super::model::{GrantBinding, RelayAccessBinding, WanSessionIdentity};
use crate::signaling::{
    AuthenticatedSessionSignalingCommand, AuthenticatedSessionSignalingOutcome,
    AuthenticatedSessionSignalingSendError, OutboundAuthenticatedSessionSignal, RelaySignalingBus,
};
use async_trait::async_trait;
use mrd_signal_proto::WanSessionRequestV3;
use std::{future::Future, pin::Pin, sync::Arc};

type SendOutcomeFuture =
    Pin<Box<dyn Future<Output = AuthenticatedSessionSignalingOutcome> + Send + 'static>>;

trait AuthenticatedSessionSignalingSender: Send + Sync {
    fn try_send_authenticated(
        &self,
        command: AuthenticatedSessionSignalingCommand,
    ) -> Result<SendOutcomeFuture, AuthenticatedSessionSignalingSendError>;
}

impl AuthenticatedSessionSignalingSender for RelaySignalingBus {
    fn try_send_authenticated(
        &self,
        command: AuthenticatedSessionSignalingCommand,
    ) -> Result<SendOutcomeFuture, AuthenticatedSessionSignalingSendError> {
        let receipt = RelaySignalingBus::try_send_authenticated(self, command)?;
        Ok(Box::pin(
            async move { receipt.wait_with_commitment().await },
        ))
    }
}

#[derive(Clone)]
pub struct ServiceWanSessionWorkflowSignaling {
    sender: Arc<dyn AuthenticatedSessionSignalingSender>,
}

impl ServiceWanSessionWorkflowSignaling {
    pub fn new(relay_signaling: Arc<RelaySignalingBus>) -> Self {
        Self {
            sender: relay_signaling,
        }
    }

    #[cfg(test)]
    fn from_sender(sender: Arc<dyn AuthenticatedSessionSignalingSender>) -> Self {
        Self { sender }
    }

    async fn send_once(
        &self,
        command: AuthenticatedSessionSignalingCommand,
    ) -> Result<Option<String>, WanSessionPortError> {
        let completion = self
            .sender
            .try_send_authenticated(command)
            .map_err(map_send_error)?;
        completion.await.map_err(map_send_error)
    }

    async fn send_grant_once(
        &self,
        identity: &WanSessionIdentity,
        intent_commitment: &str,
        grant: &GrantBinding,
        access: &RelayAccessBinding,
    ) -> Result<Option<String>, WanSessionPortError> {
        self.send_once(AuthenticatedSessionSignalingCommand {
            peer_device_id: identity.controller_device_id().clone(),
            signal: OutboundAuthenticatedSessionSignal::SessionGrant {
                session_id: identity.session_id().clone(),
                controller_device_id: identity.controller_device_id().clone(),
                target_device_id: identity.target_device_id().clone(),
                intent_commitment: intent_commitment.to_owned(),
                approved_scopes: grant.approved_scopes().to_vec(),
                approved_profile: grant.approved_profile().cloned(),
                backend_policy_revision: grant.policy_revision(),
                policy_expires_at_ms: grant.policy_expires_at_ms(),
                relay_generation: access.generation(),
                relay_directory_id: access.directory_id().to_owned(),
                primary_relay_node_id: access.primary_node_id().to_owned(),
                route_policy: grant.route_policy(),
            },
        })
        .await
    }
}

#[async_trait]
impl WanSessionWorkflowSignaling for ServiceWanSessionWorkflowSignaling {
    async fn send_intent(
        &self,
        identity: &WanSessionIdentity,
        request: &WanSessionRequestV3,
        request_commitment: &str,
        _absolute_deadline_unix_ms: u64,
    ) -> Result<String, WanSessionPortError> {
        let calculated = request
            .commitment()
            .map_err(|_| WanSessionPortError::Rejected)?;
        if calculated != request_commitment
            || request.session_id != *identity.session_id()
            || request.controller_device_id != *identity.controller_device_id()
            || request.target_device_id != *identity.target_device_id()
        {
            return Err(WanSessionPortError::Rejected);
        }
        self.send_once(AuthenticatedSessionSignalingCommand {
            peer_device_id: identity.target_device_id().clone(),
            signal: OutboundAuthenticatedSessionSignal::SessionIntent {
                request: request.clone(),
            },
        })
        .await?
        .ok_or(WanSessionPortError::Rejected)
    }

    async fn send_grant_with_commitment(
        &self,
        identity: &WanSessionIdentity,
        intent_commitment: &str,
        grant: &GrantBinding,
        access: &RelayAccessBinding,
        _absolute_deadline_unix_ms: u64,
    ) -> Result<String, WanSessionPortError> {
        self.send_grant_once(identity, intent_commitment, grant, access)
            .await
            .and_then(|commitment| commitment.ok_or(WanSessionPortError::Rejected))
    }
}

fn map_send_error(error: AuthenticatedSessionSignalingSendError) -> WanSessionPortError {
    match error {
        AuthenticatedSessionSignalingSendError::Unavailable
        | AuthenticatedSessionSignalingSendError::SessionClosed => WanSessionPortError::Unavailable,
        AuthenticatedSessionSignalingSendError::Backpressure
        | AuthenticatedSessionSignalingSendError::Invalid => WanSessionPortError::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceWanSessionWorkflowSignaling;
    use crate::signaling::{
        AuthenticatedSessionSignalingCommand, AuthenticatedSessionSignalingOutcome,
        AuthenticatedSessionSignalingSendError, OutboundAuthenticatedSessionSignal,
        RelaySignalingBus,
    };
    use crate::wan_session::coordinator::{WanSessionPortError, WanSessionWorkflowSignaling};
    use crate::wan_session::model::{GrantBinding, RelayAccessBinding, WanSessionIdentity};
    use mrd_proto::{DeviceId, SessionId};
    use mrd_signal_proto::{
        WanAccessModeV3, WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
    };
    use std::sync::{Arc, Mutex};

    struct RecordingSender {
        calls: Mutex<Vec<AuthenticatedSessionSignalingCommand>>,
        outcome: Mutex<Option<AuthenticatedSessionSignalingOutcome>>,
    }

    impl RecordingSender {
        fn with_outcome(outcome: AuthenticatedSessionSignalingOutcome) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outcome: Mutex::new(Some(outcome)),
            })
        }
    }

    impl super::AuthenticatedSessionSignalingSender for RecordingSender {
        fn try_send_authenticated(
            &self,
            command: AuthenticatedSessionSignalingCommand,
        ) -> Result<super::SendOutcomeFuture, AuthenticatedSessionSignalingSendError> {
            self.calls.lock().unwrap().push(command);
            let outcome = self.outcome.lock().unwrap().take().unwrap_or(Ok(None));
            Ok(Box::pin(async move { outcome }))
        }
    }

    fn identity() -> WanSessionIdentity {
        WanSessionIdentity::new(
            SessionId("adapter-red-session".into()),
            DeviceId("local-device".into()),
            DeviceId("peer-device".into()),
            "a".repeat(64),
            "b".repeat(64),
            2_000,
        )
        .unwrap()
    }

    fn request() -> WanSessionRequestV3 {
        WanSessionRequestV3 {
            session_id: SessionId("adapter-red-session".into()),
            idempotency_key: [9; 16],
            controller_device_id: DeviceId("local-device".into()),
            target_device_id: DeviceId("peer-device".into()),
            access_mode: WanAccessModeV3::Attended,
            requested_scopes: vec![WanPermissionScopeV3::ScreenView],
            requested_profile: None,
            route_policy: WanRoutePolicyV3::RelayOnly,
        }
    }

    #[tokio::test]
    async fn send_intent_rejects_a_mismatched_request_commitment_before_enqueue() {
        let adapter =
            ServiceWanSessionWorkflowSignaling::new(Arc::new(RelaySignalingBus::default()));
        let result = adapter
            .send_intent(&identity(), &request(), &"c".repeat(64), 2_000)
            .await;

        assert_eq!(result, Err(WanSessionPortError::Rejected));
    }

    #[tokio::test]
    async fn send_intent_queues_once_and_returns_the_signed_commitment() {
        let expected_commitment = "d".repeat(64);
        let sender = RecordingSender::with_outcome(Ok(Some(expected_commitment.clone())));
        let adapter = ServiceWanSessionWorkflowSignaling::from_sender(sender.clone());
        let identity = identity();
        let request = request();
        let request_commitment = request.commitment().unwrap();

        assert_eq!(
            adapter
                .send_intent(&identity, &request, &request_commitment, 2_000)
                .await,
            Ok(expected_commitment)
        );

        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].peer_device_id, *identity.target_device_id());
        assert!(matches!(
            &calls[0].signal,
            OutboundAuthenticatedSessionSignal::SessionIntent { request: sent }
                if sent == &request
        ));
    }

    #[tokio::test]
    async fn send_grant_with_commitment_queues_once_and_maps_all_grant_fields() {
        let expected_commitment = "e".repeat(64);
        let sender = RecordingSender::with_outcome(Ok(Some(expected_commitment.clone())));
        let adapter = ServiceWanSessionWorkflowSignaling::from_sender(sender.clone());
        let identity = identity();
        let request_commitment = request().commitment().unwrap();
        let grant = GrantBinding::new(
            request_commitment,
            vec![WanPermissionScopeV3::ScreenView],
            7,
            1_900,
            1_800,
            WanRoutePolicyV3::RelayOnly,
        )
        .unwrap();
        let access = RelayAccessBinding::generation_zero(
            7,
            "directory-0".into(),
            "relay-primary".into(),
            "f".repeat(64),
        )
        .unwrap();

        assert_eq!(
            adapter
                .send_grant_with_commitment(&identity, &"a".repeat(64), &grant, &access, 2_000,)
                .await,
            Ok(expected_commitment)
        );

        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].peer_device_id, *identity.controller_device_id());
        assert!(matches!(
            &calls[0].signal,
            OutboundAuthenticatedSessionSignal::SessionGrant {
                session_id,
                controller_device_id,
                target_device_id,
                intent_commitment,
                approved_scopes,
                approved_profile,
                backend_policy_revision,
                policy_expires_at_ms,
                relay_generation,
                relay_directory_id,
                primary_relay_node_id,
                route_policy,
            } if session_id == identity.session_id()
                && controller_device_id == identity.controller_device_id()
                && target_device_id == identity.target_device_id()
                && intent_commitment == &"a".repeat(64)
                && approved_scopes == grant.approved_scopes()
                && approved_profile.is_none()
                && *backend_policy_revision == grant.policy_revision()
                && *policy_expires_at_ms == grant.policy_expires_at_ms()
                && *relay_generation == access.generation()
                && relay_directory_id == access.directory_id()
                && primary_relay_node_id == access.primary_node_id()
                && *route_policy == grant.route_policy()
        ));
    }

    #[tokio::test]
    async fn send_grant_with_commitment_rejects_a_missing_signed_commitment() {
        let sender = RecordingSender::with_outcome(Ok(None));
        let adapter = ServiceWanSessionWorkflowSignaling::from_sender(sender.clone());
        let request_commitment = request().commitment().unwrap();
        let grant = GrantBinding::new(
            request_commitment,
            vec![WanPermissionScopeV3::ScreenView],
            7,
            1_900,
            1_800,
            WanRoutePolicyV3::RelayOnly,
        )
        .unwrap();
        let access = RelayAccessBinding::generation_zero(
            7,
            "directory-0".into(),
            "relay-primary".into(),
            "f".repeat(64),
        )
        .unwrap();

        assert_eq!(
            adapter
                .send_grant_with_commitment(&identity(), &"a".repeat(64), &grant, &access, 2_000,)
                .await,
            Err(WanSessionPortError::Rejected)
        );
        assert_eq!(sender.calls.lock().unwrap().len(), 1);
    }
}
