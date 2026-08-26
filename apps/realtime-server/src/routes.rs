use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{
    relay_candidate_fingerprint, RelayMigrationAnswerPayload, RelayMigrationCandidatePayload,
    RelayMigrationOfferPayload, SessionGrantPayload, SessionIntentPayload, WebRtcAnswerPayload,
    WebRtcCandidatePayload, WebRtcOfferPayload,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Clone)]
struct SessionRoute {
    controller: DeviceId,
    target: DeviceId,
    idempotency_key: [u8; 16],
    granted_fingerprints: Option<HashSet<String>>,
    latest_migration_generation: u64,
    migration: Option<MigrationBinding>,
    last_activity_ms: u64,
}

#[derive(Debug, Clone)]
struct MigrationBinding {
    generation: u64,
    directory_id: String,
    node_id: String,
    offerer: DeviceId,
    restart_route_token: String,
    offerer_fingerprints: HashSet<String>,
    answerer_fingerprints: Option<HashSet<String>>,
}

#[derive(Debug, Default)]
pub struct AuthorizedRoutes {
    routes: HashMap<SessionId, SessionRoute>,
    idempotency: HashMap<(DeviceId, [u8; 16]), SessionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentDisposition {
    Created,
    Duplicate,
}

impl AuthorizedRoutes {
    pub fn apply_intent(
        &mut self,
        controller: &DeviceId,
        intent: &SessionIntentPayload,
        now_ms: u64,
    ) -> Result<IntentDisposition, RouteError> {
        let key = (controller.clone(), intent.idempotency_key);
        if let Some(existing) = self.idempotency.get(&key) {
            let route = self.routes.get(existing).ok_or(RouteError::Conflict)?;
            return if existing == &intent.session_id
                && &route.controller == controller
                && route.target == intent.target_device_id
            {
                Ok(IntentDisposition::Duplicate)
            } else {
                Err(RouteError::Conflict)
            };
        }
        if self.routes.contains_key(&intent.session_id) {
            return Err(RouteError::Conflict);
        }
        self.routes.insert(
            intent.session_id.clone(),
            SessionRoute {
                controller: controller.clone(),
                target: intent.target_device_id.clone(),
                idempotency_key: intent.idempotency_key,
                granted_fingerprints: None,
                latest_migration_generation: 0,
                migration: None,
                last_activity_ms: now_ms,
            },
        );
        self.idempotency.insert(key, intent.session_id.clone());
        Ok(IntentDisposition::Created)
    }

    pub fn apply_grant(
        &mut self,
        target: &DeviceId,
        grant: &SessionGrantPayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&grant.session_id)
            .ok_or(RouteError::UnknownSession)?;
        if &route.target != target || route.controller != grant.controller_device_id {
            return Err(RouteError::Unauthorized);
        }
        route.granted_fingerprints = Some(
            grant
                .accepted_candidate_fingerprints
                .iter()
                .cloned()
                .collect(),
        );
        route.latest_migration_generation = 0;
        route.migration = None;
        route.last_activity_ms = now_ms;
        Ok(route.controller.clone())
    }

    pub fn resolve_granted(
        &mut self,
        session_id: &SessionId,
        sender: &DeviceId,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(session_id)
            .ok_or(RouteError::UnknownSession)?;
        if route.granted_fingerprints.is_none() {
            return Err(RouteError::NotGranted);
        }
        let peer = peer(route, sender)?;
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn resolve_offer(
        &mut self,
        sender: &DeviceId,
        offer: &WebRtcOfferPayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&offer.session_id)
            .ok_or(RouteError::UnknownSession)?;
        let accepted = route
            .granted_fingerprints
            .as_ref()
            .ok_or(RouteError::NotGranted)?;
        if !offer
            .candidate_fingerprints
            .iter()
            .all(|fingerprint| accepted.contains(fingerprint))
        {
            return Err(RouteError::FingerprintNotGranted);
        }
        let peer = peer(route, sender)?;
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn resolve_answer(
        &mut self,
        sender: &DeviceId,
        answer: &WebRtcAnswerPayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&answer.session_id)
            .ok_or(RouteError::UnknownSession)?;
        let accepted = route
            .granted_fingerprints
            .as_ref()
            .ok_or(RouteError::NotGranted)?;
        if !answer
            .candidate_fingerprints
            .iter()
            .all(|fingerprint| accepted.contains(fingerprint))
        {
            return Err(RouteError::FingerprintNotGranted);
        }
        let peer = peer(route, sender)?;
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn resolve_candidate(
        &mut self,
        sender: &DeviceId,
        candidate: &WebRtcCandidatePayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&candidate.session_id)
            .ok_or(RouteError::UnknownSession)?;
        if !route
            .granted_fingerprints
            .as_ref()
            .is_some_and(|accepted| accepted.contains(&candidate.candidate_fingerprint))
        {
            return Err(RouteError::FingerprintNotGranted);
        }
        let peer = peer(route, sender)?;
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn resolve_migration_offer(
        &mut self,
        sender: &DeviceId,
        offer: &RelayMigrationOfferPayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&offer.session_id)
            .ok_or(RouteError::UnknownSession)?;
        let peer = peer(route, sender)?;
        let expected = route
            .latest_migration_generation
            .checked_add(1)
            .ok_or(RouteError::MigrationConflict)?;
        if offer.migration_generation != expected {
            return Err(RouteError::MigrationConflict);
        }
        route.latest_migration_generation = offer.migration_generation;
        route.migration = Some(MigrationBinding {
            generation: offer.migration_generation,
            directory_id: offer.directory_id.clone(),
            node_id: offer.node_id.clone(),
            offerer: sender.clone(),
            restart_route_token: offer.restart_route_token.clone(),
            offerer_fingerprints: offer.candidate_fingerprints.iter().cloned().collect(),
            answerer_fingerprints: None,
        });
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn resolve_migration_answer(
        &mut self,
        sender: &DeviceId,
        answer: &RelayMigrationAnswerPayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&answer.session_id)
            .ok_or(RouteError::UnknownSession)?;
        let peer = peer(route, sender)?;
        let binding = route
            .migration
            .as_mut()
            .ok_or(RouteError::MigrationConflict)?;
        if &binding.offerer == sender
            || binding.generation != answer.migration_generation
            || binding.directory_id != answer.directory_id
            || binding.node_id != answer.node_id
            || binding.restart_route_token != answer.restart_route_token
        {
            return Err(RouteError::MigrationConflict);
        }
        binding.answerer_fingerprints =
            Some(answer.candidate_fingerprints.iter().cloned().collect());
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn resolve_migration_candidate(
        &mut self,
        sender: &DeviceId,
        candidate: &RelayMigrationCandidatePayload,
        now_ms: u64,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get_mut(&candidate.session_id)
            .ok_or(RouteError::UnknownSession)?;
        let peer = peer(route, sender)?;
        let binding = route
            .migration
            .as_ref()
            .ok_or(RouteError::MigrationConflict)?;
        if binding.generation != candidate.migration_generation
            || binding.directory_id != candidate.directory_id
            || binding.node_id != candidate.node_id
            || binding.restart_route_token != candidate.restart_route_token
        {
            return Err(RouteError::MigrationConflict);
        }
        let accepted = if &binding.offerer == sender {
            Some(&binding.offerer_fingerprints)
        } else {
            binding.answerer_fingerprints.as_ref()
        };
        let computed = relay_candidate_fingerprint(
            &candidate.session_id,
            candidate.migration_generation,
            &candidate.candidate,
            candidate.sdp_mid.as_deref(),
            candidate.sdp_mline_index,
            candidate.username_fragment.as_deref(),
            &candidate.restart_route_token,
        );
        if computed != candidate.candidate_fingerprint
            || !accepted.is_some_and(|accepted| accepted.contains(&candidate.candidate_fingerprint))
        {
            return Err(RouteError::FingerprintNotGranted);
        }
        route.last_activity_ms = now_ms;
        Ok(peer)
    }

    pub fn close(
        &mut self,
        session_id: &SessionId,
        sender: &DeviceId,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get(session_id)
            .ok_or(RouteError::UnknownSession)?;
        let target = peer(route, sender)?;
        self.remove(session_id);
        Ok(target)
    }

    pub fn deny(
        &mut self,
        session_id: &SessionId,
        sender: &DeviceId,
    ) -> Result<DeviceId, RouteError> {
        let route = self
            .routes
            .get(session_id)
            .ok_or(RouteError::UnknownSession)?;
        if &route.target != sender {
            return Err(RouteError::Unauthorized);
        }
        let controller = route.controller.clone();
        self.remove(session_id);
        Ok(controller)
    }

    pub fn remove_device(&mut self, device: &DeviceId) {
        let sessions: Vec<SessionId> = self
            .routes
            .iter()
            .filter(|(_, route)| &route.controller == device || &route.target == device)
            .map(|(session, _)| session.clone())
            .collect();
        for session in sessions {
            self.remove(&session);
        }
    }

    pub fn prune(&mut self, now_ms: u64, ttl_ms: u64) {
        let sessions: Vec<SessionId> = self
            .routes
            .iter()
            .filter(|(_, route)| now_ms >= route.last_activity_ms.saturating_add(ttl_ms))
            .map(|(session, _)| session.clone())
            .collect();
        for session in sessions {
            self.remove(&session);
        }
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    fn remove(&mut self, session_id: &SessionId) {
        if let Some(route) = self.routes.remove(session_id) {
            self.idempotency
                .remove(&(route.controller, route.idempotency_key));
        }
    }
}

fn peer(route: &SessionRoute, sender: &DeviceId) -> Result<DeviceId, RouteError> {
    if &route.controller == sender {
        Ok(route.target.clone())
    } else if &route.target == sender {
        Ok(route.controller.clone())
    } else {
        Err(RouteError::Unauthorized)
    }
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("session route is unknown")]
    UnknownSession,
    #[error("sender is not a route participant")]
    Unauthorized,
    #[error("session route conflicts with an existing route")]
    Conflict,
    #[error("session route has not been granted")]
    NotGranted,
    #[error("candidate fingerprint was not granted")]
    FingerprintNotGranted,
    #[error("relay migration generation or binding conflicts with the session route")]
    MigrationConflict,
}
