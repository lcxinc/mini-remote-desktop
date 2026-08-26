//! Production authenticated-signaling/WebRTC relay migration executor.

use super::{
    RelayMigrationAttempt, RelayMigrationCommit, RelayMigrationExecutor, RelayMigrationFailure,
    RelayMigrationFailureCode, RelayMigrationOffer,
};
use crate::{
    signaling::{
        relay_candidate_fingerprint, OutboundRelayMigrationSignal, RelaySignalingCommand,
        RelaySignalingReceiveError,
    },
    transports::webrtc::{
        PendingWebRtcReplacement, ServiceWebRtcTransportError, ServiceWebRtcTransportHost,
    },
    AppState,
};
use async_trait::async_trait;
use mrd_application::{AuthenticatedSessionSignal, VerifiedSignalingEvent};
use mrd_ipc::{RemoteAuthorizationState, RemoteSessionRole};
use mrd_proto::{DeviceId, SessionId};
use mrd_transport_webrtc::{IceCandidate, SessionDescription, SessionDescriptionType};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Weak},
    time::Duration,
};
use thiserror::Error;

const MAX_MIGRATION_CANDIDATES: usize = 256;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ServiceRelayMigrationConfigError {
    #[error("relay migration negotiation timeout is invalid")]
    InvalidTimeout,
}

/// Negotiates one controller-initiated relay replacement over authenticated signaling.
pub struct ServiceRelayMigrationExecutor {
    app_state: Weak<AppState>,
    authorization: Arc<crate::session_authorization::SessionAuthorizationRegistry>,
    relay_signaling: Arc<crate::signaling::RelaySignalingBus>,
    host: Arc<ServiceWebRtcTransportHost>,
    negotiation_timeout: Duration,
}

impl fmt::Debug for ServiceRelayMigrationExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRelayMigrationExecutor")
            .field("negotiation_timeout", &self.negotiation_timeout)
            .finish_non_exhaustive()
    }
}

impl ServiceRelayMigrationExecutor {
    pub fn new(
        app_state: Arc<AppState>,
        negotiation_timeout: Duration,
    ) -> Result<Self, ServiceRelayMigrationConfigError> {
        if !(Duration::from_millis(100)..=Duration::from_secs(60)).contains(&negotiation_timeout) {
            return Err(ServiceRelayMigrationConfigError::InvalidTimeout);
        }
        Ok(Self {
            host: Arc::clone(&app_state.webrtc_host),
            authorization: Arc::clone(&app_state.session_authorizations),
            relay_signaling: Arc::clone(&app_state.relay_signaling),
            app_state: Arc::downgrade(&app_state),
            negotiation_timeout,
        })
    }

    async fn migrate_inner(
        &self,
        attempt: &RelayMigrationAttempt,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        let (peer_device_id, peer_key_id) = self.controller_peer(attempt.session_id()).await?;
        let pending = self
            .host
            .begin_replacement(
                attempt.session_id(),
                attempt.generation(),
                attempt.peer_config().clone(),
            )
            .await
            .map_err(retryable_transport)?;
        let local_description = pending.local_description();
        let route_token = local_description
            .restart_route_token()
            .ok_or_else(terminal_security)?
            .to_wire();
        let local_candidates = self.collect_local_candidates(&pending).await?;
        if local_candidates.is_empty() {
            return Err(RelayMigrationFailure::retryable(
                RelayMigrationFailureCode::TransportUnavailable,
            ));
        }
        let fingerprints = local_candidates.keys().cloned().collect::<BTreeSet<_>>();
        let app_state = self.app_state.upgrade().ok_or_else(|| {
            RelayMigrationFailure::retryable(RelayMigrationFailureCode::SignalingUnavailable)
        })?;
        let mapper = app_state.signaling_mapper().ok_or_else(|| {
            RelayMigrationFailure::retryable(RelayMigrationFailureCode::SignalingUnavailable)
        })?;
        let mut inbound = self
            .relay_signaling
            .subscribe_migration(attempt.session_id().clone(), attempt.generation());
        mapper
            .bind_outbound_relay_migration(
                attempt.session_id().clone(),
                peer_key_id,
                attempt.generation(),
                attempt.route_evidence().directory_id().to_owned(),
                attempt.route_evidence().node_id().to_owned(),
                route_token.to_string(),
            )
            .await
            .map_err(|_| terminal_security())?;

        self.send(
            peer_device_id.clone(),
            OutboundRelayMigrationSignal::Offer {
                session_id: attempt.session_id().clone(),
                migration_generation: attempt.generation(),
                directory_id: attempt.route_evidence().directory_id().to_owned(),
                node_id: attempt.route_evidence().node_id().to_owned(),
                sdp: local_description.sdp.clone(),
                restart_route_token: route_token.to_string(),
                candidate_fingerprints: fingerprints,
            },
        )
        .await?;
        for (fingerprint, candidate) in local_candidates {
            self.send(
                peer_device_id.clone(),
                OutboundRelayMigrationSignal::Candidate {
                    session_id: attempt.session_id().clone(),
                    migration_generation: attempt.generation(),
                    directory_id: attempt.route_evidence().directory_id().to_owned(),
                    node_id: attempt.route_evidence().node_id().to_owned(),
                    candidate: candidate.candidate.clone(),
                    sdp_mid: candidate.sdp_mid.clone(),
                    sdp_mline_index: candidate.sdp_mline_index,
                    username_fragment: candidate.username_fragment.clone(),
                    restart_route_token: route_token.to_string(),
                    candidate_fingerprint: fingerprint,
                },
            )
            .await?;
        }

        let expected_candidates = self
            .accept_remote_answer(attempt, &pending, &route_token, &mut inbound)
            .await?;
        self.accept_remote_candidates(
            attempt,
            &pending,
            &route_token,
            expected_candidates,
            &mut inbound,
        )
        .await?;
        let evidence = self
            .host
            .validate_replacement(&pending, attempt.route_evidence().clone())
            .await
            .map_err(classify_validation_error)?;
        let mux = self
            .host
            .commit_replacement(pending, evidence)
            .await
            .map_err(classify_validation_error)?;
        Ok(RelayMigrationCommit::for_attempt(attempt, mux))
    }

    async fn controller_peer(
        &self,
        session_id: &SessionId,
    ) -> Result<(DeviceId, String), RelayMigrationFailure> {
        let authorization = self
            .authorization
            .snapshot(session_id)
            .await
            .ok_or_else(terminal_security)?;
        if authorization.role != RemoteSessionRole::Controller
            || authorization.authorization_state != RemoteAuthorizationState::Granted
            || authorization.peer_key_id.is_empty()
        {
            return Err(terminal_security());
        }
        Ok((authorization.peer_device_id, authorization.peer_key_id))
    }

    async fn require_answerer_peer(
        &self,
        offer: &RelayMigrationOffer,
    ) -> Result<(), RelayMigrationFailure> {
        let authorization = self
            .authorization
            .snapshot(&offer.session_id)
            .await
            .ok_or_else(terminal_security)?;
        if authorization.role != RemoteSessionRole::Agent
            || authorization.authorization_state != RemoteAuthorizationState::Granted
            || authorization.peer_device_id != offer.peer_device_id
            || authorization.peer_key_id != offer.peer_key_id
        {
            return Err(terminal_security());
        }
        Ok(())
    }

    async fn respond_inner(
        &self,
        attempt: &RelayMigrationAttempt,
        mut offer: RelayMigrationOffer,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        self.require_answerer_peer(&offer).await?;
        if offer.session_id != *attempt.session_id()
            || offer.generation != attempt.generation()
            || offer.directory_id != attempt.route_evidence().directory_id()
            || offer.node_id != attempt.route_evidence().node_id()
        {
            return Err(terminal_security());
        }
        let expected_candidates = std::mem::take(&mut offer.candidate_fingerprints)
            .into_iter()
            .collect::<BTreeSet<_>>();
        if expected_candidates.is_empty() || expected_candidates.len() > MAX_MIGRATION_CANDIDATES {
            return Err(terminal_security());
        }
        let route_token = std::mem::take(&mut offer.restart_route_token);
        let remote_offer = SessionDescription::from_wire(
            SessionDescriptionType::Offer,
            std::mem::take(&mut offer.sdp),
            attempt.generation(),
            Some(&route_token),
        )
        .map_err(|_| terminal_security())?;
        let mut inbound = self
            .relay_signaling
            .subscribe_migration(attempt.session_id().clone(), attempt.generation());
        let pending = self
            .host
            .begin_replacement_from_offer(
                attempt.session_id(),
                attempt.generation(),
                attempt.peer_config().clone(),
                remote_offer,
            )
            .await
            .map_err(|_| terminal_security())?;
        let local_description = pending.local_description();
        let answer_token = local_description
            .restart_route_token()
            .ok_or_else(terminal_security)?
            .to_wire();
        if answer_token.as_str() != route_token {
            return Err(terminal_security());
        }
        let local_candidates = self.collect_local_candidates(&pending).await?;
        if local_candidates.is_empty() {
            return Err(RelayMigrationFailure::retryable(
                RelayMigrationFailureCode::TransportUnavailable,
            ));
        }
        let fingerprints = local_candidates.keys().cloned().collect::<BTreeSet<_>>();
        self.send(
            offer.peer_device_id.clone(),
            OutboundRelayMigrationSignal::Answer {
                session_id: attempt.session_id().clone(),
                migration_generation: attempt.generation(),
                directory_id: attempt.route_evidence().directory_id().to_owned(),
                node_id: attempt.route_evidence().node_id().to_owned(),
                sdp: local_description.sdp.clone(),
                restart_route_token: route_token.clone(),
                candidate_fingerprints: fingerprints,
            },
        )
        .await?;
        for (fingerprint, candidate) in local_candidates {
            self.send(
                offer.peer_device_id.clone(),
                OutboundRelayMigrationSignal::Candidate {
                    session_id: attempt.session_id().clone(),
                    migration_generation: attempt.generation(),
                    directory_id: attempt.route_evidence().directory_id().to_owned(),
                    node_id: attempt.route_evidence().node_id().to_owned(),
                    candidate: candidate.candidate.clone(),
                    sdp_mid: candidate.sdp_mid.clone(),
                    sdp_mline_index: candidate.sdp_mline_index,
                    username_fragment: candidate.username_fragment.clone(),
                    restart_route_token: route_token.clone(),
                    candidate_fingerprint: fingerprint,
                },
            )
            .await?;
        }
        self.accept_remote_candidates(
            attempt,
            &pending,
            &route_token,
            expected_candidates,
            &mut inbound,
        )
        .await?;
        let evidence = self
            .host
            .validate_replacement(&pending, attempt.route_evidence().clone())
            .await
            .map_err(classify_validation_error)?;
        let mux = self
            .host
            .commit_replacement(pending, evidence)
            .await
            .map_err(classify_validation_error)?;
        Ok(RelayMigrationCommit::for_attempt(attempt, mux))
    }

    async fn collect_local_candidates(
        &self,
        pending: &PendingWebRtcReplacement,
    ) -> Result<BTreeMap<String, IceCandidate>, RelayMigrationFailure> {
        let route_token = pending
            .local_description()
            .restart_route_token()
            .ok_or_else(terminal_security)?
            .to_wire();
        let mut candidates = BTreeMap::new();
        while let Some(candidate) = self
            .host
            .next_replacement_candidate_optional(pending)
            .await
            .map_err(retryable_transport)?
        {
            if candidates.len() == MAX_MIGRATION_CANDIDATES {
                return Err(terminal_security());
            }
            let fingerprint = relay_candidate_fingerprint(
                pending.session_id(),
                pending.generation(),
                &candidate.candidate,
                candidate.sdp_mid.as_deref(),
                candidate.sdp_mline_index,
                candidate.username_fragment.as_deref(),
                &route_token,
            );
            if candidates.insert(fingerprint, candidate).is_some() {
                return Err(terminal_security());
            }
        }
        Ok(candidates)
    }

    async fn send(
        &self,
        peer_device_id: DeviceId,
        signal: OutboundRelayMigrationSignal,
    ) -> Result<(), RelayMigrationFailure> {
        self.relay_signaling
            .send(RelaySignalingCommand {
                peer_device_id,
                signal,
            })
            .await
            .map_err(|_| {
                RelayMigrationFailure::retryable(RelayMigrationFailureCode::SignalingUnavailable)
            })
    }

    async fn accept_remote_answer(
        &self,
        attempt: &RelayMigrationAttempt,
        pending: &PendingWebRtcReplacement,
        route_token: &str,
        inbound: &mut crate::signaling::RelaySignalingSubscription,
    ) -> Result<BTreeSet<String>, RelayMigrationFailure> {
        loop {
            let event = recv_event(inbound).await?;
            let AuthenticatedSessionSignal::RelayMigrationAnswer {
                session_id,
                migration_generation,
                directory_id,
                node_id,
                sdp,
                restart_route_token,
                candidate_fingerprints,
            } = event.signal
            else {
                continue;
            };
            if session_id != *attempt.session_id()
                || migration_generation != attempt.generation()
                || directory_id != attempt.route_evidence().directory_id()
                || node_id != attempt.route_evidence().node_id()
                || restart_route_token != route_token
            {
                return Err(terminal_security());
            }
            let expected = candidate_fingerprints.into_iter().collect::<BTreeSet<_>>();
            if expected.is_empty() || expected.len() > MAX_MIGRATION_CANDIDATES {
                return Err(terminal_security());
            }
            let answer = SessionDescription::from_wire(
                SessionDescriptionType::Answer,
                sdp,
                migration_generation,
                Some(route_token),
            )
            .map_err(|_| terminal_security())?;
            self.host
                .accept_replacement_answer(pending, answer)
                .await
                .map_err(|_| terminal_security())?;
            return Ok(expected);
        }
    }

    async fn accept_remote_candidates(
        &self,
        attempt: &RelayMigrationAttempt,
        pending: &PendingWebRtcReplacement,
        route_token: &str,
        expected: BTreeSet<String>,
        inbound: &mut crate::signaling::RelaySignalingSubscription,
    ) -> Result<(), RelayMigrationFailure> {
        let mut accepted = BTreeSet::new();
        while accepted.len() < expected.len() {
            let event = recv_event(inbound).await?;
            let AuthenticatedSessionSignal::RelayMigrationCandidate {
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
            } = event.signal
            else {
                continue;
            };
            if session_id != *attempt.session_id()
                || migration_generation != attempt.generation()
                || directory_id != attempt.route_evidence().directory_id()
                || node_id != attempt.route_evidence().node_id()
                || restart_route_token != route_token
                || !expected.contains(&candidate_fingerprint)
            {
                return Err(terminal_security());
            }
            let computed = relay_candidate_fingerprint(
                &session_id,
                migration_generation,
                &candidate,
                sdp_mid.as_deref(),
                sdp_mline_index,
                username_fragment.as_deref(),
                route_token,
            );
            if computed != candidate_fingerprint {
                return Err(terminal_security());
            }
            if !accepted.insert(candidate_fingerprint) {
                continue;
            }
            let candidate = IceCandidate::from_wire(
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
                migration_generation,
                Some(route_token),
            )
            .map_err(|_| terminal_security())?;
            self.host
                .add_replacement_candidate(pending, candidate)
                .await
                .map_err(|_| terminal_security())?;
        }
        Ok(())
    }
}

#[async_trait]
impl RelayMigrationExecutor for ServiceRelayMigrationExecutor {
    async fn migrate(
        &self,
        attempt: &RelayMigrationAttempt,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        tokio::time::timeout(self.negotiation_timeout, self.migrate_inner(attempt))
            .await
            .map_err(|_| {
                RelayMigrationFailure::retryable(RelayMigrationFailureCode::SignalingUnavailable)
            })?
    }

    async fn respond(
        &self,
        attempt: &RelayMigrationAttempt,
        offer: RelayMigrationOffer,
    ) -> Result<RelayMigrationCommit, RelayMigrationFailure> {
        tokio::time::timeout(self.negotiation_timeout, self.respond_inner(attempt, offer))
            .await
            .map_err(|_| {
                RelayMigrationFailure::retryable(RelayMigrationFailureCode::SignalingUnavailable)
            })?
    }

    async fn discard_loser(&self, session_id: &SessionId, generation: u64) {
        let _ = self
            .host
            .close_session_if_generation(session_id, generation)
            .await;
    }

    async fn close_all(&self, session_id: &SessionId) {
        match self.host.close_session(session_id).await {
            Ok(()) | Err(ServiceWebRtcTransportError::SessionNotFound(_)) => {}
            Err(_) => {}
        }
    }
}

async fn recv_event(
    inbound: &mut crate::signaling::RelaySignalingSubscription,
) -> Result<VerifiedSignalingEvent, RelayMigrationFailure> {
    inbound.recv().await.map_err(|error| match error {
        RelaySignalingReceiveError::Closed | RelaySignalingReceiveError::Lagged => {
            RelayMigrationFailure::retryable(RelayMigrationFailureCode::SignalingUnavailable)
        }
    })
}

fn retryable_transport(_: ServiceWebRtcTransportError) -> RelayMigrationFailure {
    RelayMigrationFailure::retryable(RelayMigrationFailureCode::TransportUnavailable)
}

fn classify_validation_error(error: ServiceWebRtcTransportError) -> RelayMigrationFailure {
    match error {
        ServiceWebRtcTransportError::ReplacementEvidenceMismatch
        | ServiceWebRtcTransportError::InvalidReplacement => terminal_security(),
        _ => retryable_transport(error),
    }
}

fn terminal_security() -> RelayMigrationFailure {
    RelayMigrationFailure::terminal(RelayMigrationFailureCode::SecurityViolation)
}
