use mrd_identity::{DeviceIdentity, UnattendedCredential};
use mrd_ipc::{
    AuditLogQuery, ConsentDecision, ConsentResponse, DecimalU64, IpcRequest, IpcResponse,
    RemoteAccessMode, RemoteAuthorizationState, RemoteCursorState, RemoteFailure, RemoteMediaState,
    RemotePermissionScope, RemotePresentationState, RemoteReasonCode, RemoteRouteKind,
    RemoteRouteState, RemoteSessionEvent, RemoteSessionRole, SessionEventSubscriptionQuery,
    UnattendedAccessPolicy,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::{
    session_authorization::{VerifiedIncomingAuthorizationRequest, VerifiedSessionGrant},
    AppState,
};
use std::sync::Arc;

use ring::rand::SystemRandom;

fn attended_request(session_id: &str) -> VerifiedIncomingAuthorizationRequest {
    let created_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_millis() as u64;
    VerifiedIncomingAuthorizationRequest {
        session_id: SessionId(session_id.to_string()),
        peer_device_id: DeviceId("controller-device".to_string()),
        peer_key_id: "controller-key".to_string(),
        peer_key_epoch: 7,
        access_mode: RemoteAccessMode::Attended,
        requested_scopes: vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputKeyboard,
        ],
        peer_permission_ceiling: vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputKeyboard,
        ],
        machine_permission_ceiling: vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputKeyboard,
        ],
        runtime_capabilities: vec![RemotePermissionScope::ScreenView],
        transport_kind: "quic".to_string(),
        request_nonce: [1; 16],
        created_at_ms,
        expires_at_ms: created_at_ms + 30_000,
    }
}

#[tokio::test]
async fn outgoing_wan_authorization_binds_one_verified_peer_and_relay_route() {
    let state = AppState::new();
    let target_device_id = DeviceId("outgoing-wan-target".to_owned());
    let target_identity = DeviceIdentity::generate(&SystemRandom::new()).unwrap();
    let created_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let request = VerifiedIncomingAuthorizationRequest {
        session_id: SessionId("outgoing-wan-authorization".to_owned()),
        peer_device_id: target_device_id.clone(),
        peer_key_id: format!("pending_authenticated_peer:{}", target_device_id.0),
        peer_key_epoch: 1,
        access_mode: RemoteAccessMode::Attended,
        requested_scopes: vec![RemotePermissionScope::ScreenView],
        peer_permission_ceiling: vec![RemotePermissionScope::ScreenView],
        machine_permission_ceiling: vec![RemotePermissionScope::ScreenView],
        runtime_capabilities: vec![RemotePermissionScope::ScreenView],
        transport_kind: "webrtc_relay".to_owned(),
        request_nonce: [0x51; 16],
        created_at_ms,
        expires_at_ms: created_at_ms + 30_000,
    };
    state
        .session_authorizations
        .begin_outgoing(request.clone())
        .await
        .expect("pending outgoing WAN authorization");
    assert!(state
        .session_authorizations
        .bind_outgoing_authenticated_peer(
            &request.session_id,
            &DeviceId("wrong-target".to_owned()),
            target_identity.key_id(),
            target_identity.public_key(),
            created_at_ms + 1,
        )
        .await
        .is_err());
    let bound = state
        .session_authorizations
        .bind_outgoing_authenticated_peer(
            &request.session_id,
            &target_device_id,
            target_identity.key_id(),
            target_identity.public_key(),
            created_at_ms + 1,
        )
        .await
        .expect("exact outgoing peer binding");
    assert_eq!(bound.peer_key_id, target_identity.key_id());

    let granted = state
        .session_authorizations
        .install_verified_grant(
            VerifiedSessionGrant {
                grant_id: format!("sha256:{}", "8".repeat(64)),
                session_id: request.session_id,
                granted_scopes: vec![RemotePermissionScope::ScreenView],
                issued_at_ms: created_at_ms + 1,
                expires_at_ms: created_at_ms + 20_000,
                policy_revision: 7,
                route_constraint: "webrtc_relay".to_owned(),
                transport_fingerprint_sha256: [0x81; 32],
            },
            created_at_ms + 1,
        )
        .await
        .expect("verified WAN grant");
    assert_eq!(
        granted.authorization_state,
        RemoteAuthorizationState::Granted
    );
    assert_eq!(granted.route_kind, Some(RemoteRouteKind::WebRtcRelay));
}

#[tokio::test]
async fn deny_returns_stable_reason_and_starts_no_media() {
    let state = Arc::new(AppState::new());
    let pending = state
        .session_authorizations
        .begin_verified_incoming(attended_request("consent-denied"))
        .await
        .expect("pending consent");
    let server = mrd_service::ipc_server::IpcServer::new(state.clone());

    let response = server
        .handle_request(IpcRequest::RespondToConsent {
            response: ConsentResponse {
                session_id: pending.session_id.clone(),
                decision: ConsentDecision::Deny,
                approved_scopes: Vec::new(),
                expected_policy_revision: DecimalU64::new(1),
            },
        })
        .await;

    let IpcResponse::ConsentRecorded { session } = response else {
        panic!("expected authoritative denied snapshot, got {response:?}");
    };
    assert_eq!(
        session.authorization_state,
        RemoteAuthorizationState::Denied
    );
    assert_eq!(
        session.failure.as_ref().map(|failure| failure.code),
        Some(RemoteReasonCode::ConsentDenied)
    );
    assert!(session.granted_scopes.is_empty());
    assert!(state
        .sessions
        .lock()
        .await
        .get(&session.session_id)
        .is_none());
    assert_eq!(
        state
            .media_tasks
            .lock()
            .await
            .active_count(&session.session_id),
        0
    );
    assert!(state
        .session_authorizations
        .active_grant(&session.session_id)
        .await
        .is_none());
}

#[tokio::test]
async fn timeout_expires_request_and_late_consent_cannot_revive_it() {
    let state = Arc::new(AppState::new());
    let mut request = attended_request("consent-timeout");
    request.expires_at_ms = request.created_at_ms + 50;
    let pending = state
        .session_authorizations
        .begin_verified_incoming(request.clone())
        .await
        .expect("pending consent");

    let expired = state
        .session_authorizations
        .expire_pending(&pending.session_id, request.expires_at_ms + 1)
        .await
        .expect("timeout should win pending CAS");
    assert_eq!(
        expired.authorization_state,
        RemoteAuthorizationState::Expired
    );
    assert_eq!(
        expired.failure.as_ref().map(|failure| failure.code),
        Some(RemoteReasonCode::AuthorizationTimeout)
    );

    let response = mrd_service::ipc_server::IpcServer::new(state.clone())
        .handle_request(IpcRequest::RespondToConsent {
            response: ConsentResponse {
                session_id: pending.session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
        })
        .await;
    let IpcResponse::RemoteAccessError { failure, .. } = response else {
        panic!("late consent must fail closed, got {response:?}");
    };
    assert_eq!(failure.code, RemoteReasonCode::AuthorizationTimeout);
    assert!(state
        .session_authorizations
        .active_grant(&pending.session_id)
        .await
        .is_none());
    assert_eq!(
        state
            .media_tasks
            .lock()
            .await
            .active_count(&pending.session_id),
        0
    );
}

#[tokio::test]
async fn attended_approval_grants_only_the_five_way_scope_intersection() {
    let state = Arc::new(AppState::new());
    let pending = state
        .session_authorizations
        .begin_verified_incoming(attended_request("scope-intersection"))
        .await
        .expect("pending consent");
    let server = mrd_service::ipc_server::IpcServer::new(state.clone());

    let events = server
        .handle_request(IpcRequest::SubscribeSessionEvents {
            query: SessionEventSubscriptionQuery {
                session_id: None,
                after_sequence: None,
                limit: 16,
                wait_timeout_ms: 0,
            },
        })
        .await;
    let IpcResponse::SessionEventsSubscribed { subscription } = events else {
        panic!("expected consent event subscription, got {events:?}");
    };
    assert!(matches!(
        subscription.events.as_slice(),
        [event]
            if event.session_id == pending.session_id
                && matches!(event.event, RemoteSessionEvent::ConsentRequested { .. })
    ));

    let response = server
        .handle_request(IpcRequest::RespondToConsent {
            response: ConsentResponse {
                session_id: pending.session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![
                    RemotePermissionScope::ScreenView,
                    RemotePermissionScope::InputKeyboard,
                ],
                expected_policy_revision: DecimalU64::new(1),
            },
        })
        .await;
    let IpcResponse::ConsentRecorded { session } = response else {
        panic!("expected approved authorization snapshot, got {response:?}");
    };
    assert_eq!(
        session.authorization_state,
        RemoteAuthorizationState::Authorizing
    );
    assert_eq!(
        session.granted_scopes,
        vec![RemotePermissionScope::ScreenView]
    );
    assert!(state
        .session_authorizations
        .active_grant(&pending.session_id)
        .await
        .is_none());
    assert_eq!(
        state
            .media_tasks
            .lock()
            .await
            .active_count(&pending.session_id),
        0
    );
}

#[tokio::test]
async fn grant_is_installed_before_media_authority_is_exposed() {
    let state = Arc::new(AppState::new());
    let pending = state
        .session_authorizations
        .begin_verified_incoming(attended_request("grant-before-media"))
        .await
        .expect("pending consent");
    let approved = state
        .session_authorizations
        .respond_to_consent(
            ConsentResponse {
                session_id: pending.session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
            pending.created_at_ms + 1,
        )
        .await
        .expect("approve screen view");
    assert!(
        !state
            .session_authorizations
            .allows_scope(
                &pending.session_id,
                RemotePermissionScope::ScreenView,
                pending.created_at_ms + 2,
            )
            .await
    );

    let grant = VerifiedSessionGrant {
        grant_id: "sha256:verified-grant".to_string(),
        session_id: pending.session_id.clone(),
        granted_scopes: approved.granted_scopes.clone(),
        issued_at_ms: pending.created_at_ms + 2,
        expires_at_ms: pending.created_at_ms + 20_000,
        policy_revision: approved.policy_revision.get(),
        route_constraint: "quic".to_string(),
        transport_fingerprint_sha256: [9; 32],
    };
    let granted = state
        .session_authorizations
        .install_verified_grant(grant.clone(), pending.created_at_ms + 2)
        .await
        .expect("install verified target grant before transport commit");

    assert_eq!(
        granted.authorization_state,
        RemoteAuthorizationState::Granted
    );
    assert_eq!(
        state
            .session_authorizations
            .active_grant(&pending.session_id)
            .await,
        Some(grant)
    );
    assert!(
        state
            .session_authorizations
            .allows_scope(
                &pending.session_id,
                RemotePermissionScope::ScreenView,
                pending.created_at_ms + 3,
            )
            .await
    );
    assert_eq!(
        state
            .media_tasks
            .lock()
            .await
            .active_count(&pending.session_id),
        0
    );
}

#[tokio::test]
async fn valid_unattended_proof_grants_only_configured_scopes() {
    let state = Arc::new(AppState::new());
    let secret = [23; 16];
    state
        .session_authorizations
        .configure_unattended_for_test(
            UnattendedCredential::from_secret(secret),
            4,
            9,
            UnattendedAccessPolicy {
                trusted_devices_only: true,
                allowed_peer_key_ids: vec!["controller-key".to_string()],
                permission_ceiling: vec![RemotePermissionScope::ScreenView],
                expires_at_ms: None,
            },
        )
        .await;
    let mut request = attended_request("unattended-scopes");
    request.access_mode = RemoteAccessMode::Unattended;
    request.runtime_capabilities = vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputKeyboard,
    ];
    let pending = state
        .session_authorizations
        .begin_verified_incoming(request.clone())
        .await
        .expect("trusted unattended request");
    assert_eq!(
        pending.authorization_state,
        RemoteAuthorizationState::VerifyingUnattendedCredential
    );
    let transcript = b"signed request transcript";
    let proof = UnattendedCredential::from_secret(secret).prove(transcript, request.request_nonce);

    let authorized = state
        .session_authorizations
        .verify_unattended(
            &pending.session_id,
            transcript,
            request.request_nonce,
            4,
            &proof,
            request.created_at_ms + 1,
        )
        .await
        .expect("valid transcript-bound proof");

    assert_eq!(
        authorized.authorization_state,
        RemoteAuthorizationState::Authorizing
    );
    assert_eq!(
        authorized.granted_scopes,
        vec![RemotePermissionScope::ScreenView]
    );
    assert!(state
        .session_authorizations
        .active_grant(&pending.session_id)
        .await
        .is_none());
}

#[tokio::test]
async fn trusted_peer_requires_consent_when_unattended_is_disabled() {
    let state = Arc::new(AppState::new());
    let request = attended_request("consent-required");
    let deadline = request.expires_at_ms;

    let snapshot = state
        .session_authorizations
        .begin_verified_incoming(request)
        .await
        .expect("verified trusted request should become pending consent");

    assert_eq!(snapshot.role, RemoteSessionRole::Agent);
    assert_eq!(snapshot.access_mode, RemoteAccessMode::Attended);
    assert_eq!(snapshot.authorization_expires_at_ms, Some(deadline));
    assert_eq!(
        snapshot.authorization_state,
        RemoteAuthorizationState::AwaitingLocalConsent
    );
    assert!(snapshot.granted_scopes.is_empty());
    assert!(state
        .sessions
        .lock()
        .await
        .get(&snapshot.session_id)
        .is_none());
    assert_eq!(
        state
            .media_tasks
            .lock()
            .await
            .active_count(&snapshot.session_id),
        0
    );

    let response = mrd_service::ipc_server::IpcServer::new(state)
        .handle_request(IpcRequest::GetRemoteSession {
            session_id: snapshot.session_id.clone(),
        })
        .await;
    assert_eq!(response, IpcResponse::RemoteSession { session: snapshot });
}

#[tokio::test]
async fn incoming_authorization_applies_global_and_per_peer_pending_quotas() {
    let state = AppState::new();
    for index in 0..4 {
        state
            .session_authorizations
            .begin_verified_incoming(attended_request(&format!("pending-{index}")))
            .await
            .expect("per-peer pending request within quota");
    }

    let failure = state
        .session_authorizations
        .begin_verified_incoming(attended_request("pending-overflow"))
        .await
        .expect_err("fifth pending request from one peer must fail closed");
    assert_eq!(failure.code, RemoteReasonCode::CredentialLocked);
}

#[tokio::test]
async fn incoming_authorization_applies_global_pending_quota_across_peers() {
    let state = AppState::new();
    for index in 0..64 {
        let mut request = attended_request(&format!("global-pending-{index}"));
        request.peer_key_id = format!("controller-key-{index}");
        request.peer_device_id = DeviceId(format!("controller-device-{index}"));
        state
            .session_authorizations
            .begin_verified_incoming(request)
            .await
            .expect("global pending request within quota");
    }
    let mut overflow = attended_request("global-pending-overflow");
    overflow.peer_key_id = "controller-key-overflow".to_string();
    overflow.peer_device_id = DeviceId("controller-device-overflow".to_string());

    let failure = state
        .session_authorizations
        .begin_verified_incoming(overflow)
        .await
        .expect_err("global pending overflow must fail closed");
    assert_eq!(failure.code, RemoteReasonCode::CredentialLocked);
}

#[tokio::test]
async fn terminal_authorization_history_is_bounded() {
    let state = AppState::new();
    let base_ms = attended_request("clock").created_at_ms;
    for index in 0..2_050_u64 {
        let request = attended_request(&format!("terminal-record-{index}"));
        let session_id = request.session_id.clone();
        state
            .session_authorizations
            .begin_verified_incoming(request)
            .await
            .expect("terminal record admitted within bounded history");
        state
            .session_authorizations
            .respond_to_consent(
                ConsentResponse {
                    session_id,
                    decision: ConsentDecision::Deny,
                    approved_scopes: Vec::new(),
                    expected_policy_revision: DecimalU64::new(1),
                },
                base_ms + index,
            )
            .await
            .expect("terminal denial");
    }

    let mut retained = 0;
    for index in 0..2_050_u64 {
        if state
            .session_authorizations
            .snapshot(&SessionId(format!("terminal-record-{index}")))
            .await
            .is_some()
        {
            retained += 1;
        }
    }
    assert_eq!(retained, 2_048);
}

#[tokio::test]
async fn initial_and_reset_subscriptions_include_authoritative_pending_consent() {
    let state = AppState::new();
    let survivor = attended_request("pending-after-history-truncation");
    state
        .session_authorizations
        .begin_verified_incoming(survivor.clone())
        .await
        .expect("pending survivor");

    for index in 0..600 {
        let request = attended_request(&format!("terminal-churn-{index}"));
        let session_id = request.session_id.clone();
        state
            .session_authorizations
            .begin_verified_incoming(request)
            .await
            .expect("bounded churn request");
        state
            .session_authorizations
            .respond_to_consent(
                ConsentResponse {
                    session_id,
                    decision: ConsentDecision::Deny,
                    approved_scopes: Vec::new(),
                    expected_policy_revision: DecimalU64::new(1),
                },
                survivor.created_at_ms + index + 1,
            )
            .await
            .expect("deny churn request");
    }

    let initial = state
        .session_authorizations
        .subscribe(SessionEventSubscriptionQuery {
            session_id: None,
            after_sequence: None,
            limit: 16,
            wait_timeout_ms: 0,
        })
        .await
        .expect("initial subscription");
    assert_eq!(initial.cursor_state, RemoteCursorState::Current);
    assert!(initial
        .pending_sessions
        .iter()
        .any(|session| session.session_id == survivor.session_id));

    let reset = state
        .session_authorizations
        .subscribe(SessionEventSubscriptionQuery {
            session_id: None,
            after_sequence: Some(DecimalU64::new(1)),
            limit: 16,
            wait_timeout_ms: 0,
        })
        .await
        .expect("stale cursor reset");
    assert_eq!(reset.cursor_state, RemoteCursorState::ResetRequired);
    assert!(reset.events.is_empty());
    assert!(reset
        .pending_sessions
        .iter()
        .any(|session| session.session_id == survivor.session_id));
}

#[tokio::test]
async fn grant_expiry_updates_authoritative_route_media_and_failure_state() {
    let state = AppState::new();
    let request = attended_request("grant-expiry-projection");
    let session_id = request.session_id.clone();
    let now_ms = request.created_at_ms + 10;
    state
        .session_authorizations
        .begin_verified_incoming(request)
        .await
        .expect("pending authorization");
    state
        .session_authorizations
        .respond_to_consent(
            ConsentResponse {
                session_id: session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
            now_ms,
        )
        .await
        .expect("approved consent");
    state
        .session_authorizations
        .install_verified_grant(
            VerifiedSessionGrant {
                grant_id: "expiring-grant".to_string(),
                session_id: session_id.clone(),
                granted_scopes: vec![RemotePermissionScope::ScreenView],
                issued_at_ms: now_ms,
                expires_at_ms: now_ms + 10,
                policy_revision: 1,
                route_constraint: "quic".to_string(),
                transport_fingerprint_sha256: [5; 32],
            },
            now_ms,
        )
        .await
        .expect("verified grant");
    state
        .session_authorizations
        .mark_streaming(&session_id, now_ms + 1)
        .await
        .expect("streaming projection");

    let expired = state
        .session_authorizations
        .snapshot_at(&session_id, now_ms + 11)
        .await
        .expect("expired snapshot retained");
    assert_eq!(
        expired.authorization_state,
        RemoteAuthorizationState::Expired
    );
    assert_eq!(expired.route_state, RemoteRouteState::Closed);
    assert_eq!(expired.media_state, RemoteMediaState::Stopped);
    assert_eq!(expired.presentation_state, RemotePresentationState::Closed);
    assert!(expired.granted_scopes.is_empty());
    assert_eq!(expired.authorization_expires_at_ms, Some(now_ms + 10));
    assert_eq!(
        expired.failure.as_ref().map(|failure| failure.code),
        Some(RemoteReasonCode::GrantExpired)
    );
}

#[tokio::test]
async fn media_preparation_failure_after_consent_is_presented_as_failed_not_denied() {
    let state = AppState::new();
    let request = attended_request("encoder-failure-after-consent");
    let session_id = request.session_id.clone();
    let decided_at_ms = request.created_at_ms + 1;
    state
        .session_authorizations
        .begin_verified_incoming(request)
        .await
        .expect("pending authorization");
    state
        .session_authorizations
        .respond_to_consent(
            ConsentResponse {
                session_id: session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
            decided_at_ms,
        )
        .await
        .expect("approved consent");

    let failed = state
        .session_authorizations
        .record_failure(
            &session_id,
            RemoteAuthorizationState::Denied,
            RemoteFailure {
                code: RemoteReasonCode::EncoderUnavailable,
                message: "no compatible encoder".to_string(),
                suggested_action: None,
            },
            decided_at_ms + 1,
        )
        .await
        .expect("terminal snapshot");

    assert_eq!(failed.presentation_state, RemotePresentationState::Failed);
    assert_eq!(failed.media_state, RemoteMediaState::Failed);
    assert_eq!(failed.route_state, RemoteRouteState::Idle);
}

#[tokio::test]
async fn rejected_consent_attempt_is_not_audited_as_an_applied_decision() {
    let state = Arc::new(AppState::new());
    let request = attended_request("stale-consent-audit");
    let session_id = request.session_id.clone();
    state
        .session_authorizations
        .begin_verified_incoming(request)
        .await
        .expect("pending consent");
    let server = mrd_service::ipc_server::IpcServer::new(state.clone());

    let rejected = server
        .handle_request(IpcRequest::RespondToConsent {
            response: ConsentResponse {
                session_id: session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(99),
            },
        })
        .await;
    assert!(matches!(rejected, IpcResponse::RemoteAccessError { .. }));
    let before = state
        .audit_log
        .query(&AuditLogQuery {
            session_id: Some(session_id.clone()),
            action: Some("session.consent_decision".to_string()),
            limit: None,
        })
        .expect("audit query");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].outcome, "rejected");
    assert_eq!(before[0].reason.as_deref(), Some("policy_changed"));
    assert_eq!(
        state
            .session_authorizations
            .snapshot(&session_id)
            .await
            .expect("pending consent survives a rejected stale response")
            .authorization_state,
        RemoteAuthorizationState::AwaitingLocalConsent
    );

    let applied = server
        .handle_request(IpcRequest::RespondToConsent {
            response: ConsentResponse {
                session_id: session_id.clone(),
                decision: ConsentDecision::Approve,
                approved_scopes: vec![RemotePermissionScope::ScreenView],
                expected_policy_revision: DecimalU64::new(1),
            },
        })
        .await;
    assert!(matches!(applied, IpcResponse::ConsentRecorded { .. }));
    let after = state
        .audit_log
        .query(&AuditLogQuery {
            session_id: Some(session_id),
            action: Some("session.consent_decision".to_string()),
            limit: None,
        })
        .expect("audit query");
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].outcome, "rejected");
    assert_eq!(after[1].outcome, "approve");
}

#[tokio::test]
async fn disabling_unattended_access_via_ipc_revokes_existing_grant_and_media() {
    let state = Arc::new(AppState::new());
    let secret = [47; 16];
    state
        .session_authorizations
        .configure_unattended_for_test(
            UnattendedCredential::from_secret(secret),
            3,
            11,
            UnattendedAccessPolicy {
                trusted_devices_only: true,
                allowed_peer_key_ids: vec!["controller-key".to_string()],
                permission_ceiling: vec![RemotePermissionScope::ScreenView],
                expires_at_ms: None,
            },
        )
        .await;

    let mut request = attended_request("disable-unattended-revokes-grant");
    request.access_mode = RemoteAccessMode::Unattended;
    let pending = state
        .session_authorizations
        .begin_verified_incoming(request.clone())
        .await
        .expect("unattended authorization record");
    let transcript = b"disable unattended transcript";
    let proof = UnattendedCredential::from_secret(secret).prove(transcript, request.request_nonce);
    let authorized = state
        .session_authorizations
        .verify_unattended(
            &pending.session_id,
            transcript,
            request.request_nonce,
            3,
            &proof,
            request.created_at_ms + 1,
        )
        .await
        .expect("valid unattended proof");
    state
        .session_authorizations
        .install_verified_grant(
            VerifiedSessionGrant {
                grant_id: "disable-unattended-grant".to_string(),
                session_id: pending.session_id.clone(),
                granted_scopes: authorized.granted_scopes,
                issued_at_ms: request.created_at_ms + 2,
                expires_at_ms: request.created_at_ms + 20_000,
                policy_revision: 11,
                route_constraint: "quic".to_string(),
                transport_fingerprint_sha256: [17; 32],
            },
            request.created_at_ms + 2,
        )
        .await
        .expect("installed unattended grant");
    let media_task = tokio::spawn(std::future::pending::<()>());
    state
        .media_tasks
        .lock()
        .await
        .register(pending.session_id.clone(), media_task.abort_handle());

    let response = mrd_service::ipc_server::IpcServer::new(state.clone())
        .handle_request(IpcRequest::DisableUnattendedAccess {
            expected_policy_revision: DecimalU64::new(11),
        })
        .await;

    let IpcResponse::UnattendedAccessUpdated { access } = response else {
        panic!("expected disabled unattended snapshot, got {response:?}");
    };
    assert!(!access.enabled);
    let revoked = state
        .session_authorizations
        .snapshot(&pending.session_id)
        .await
        .expect("revoked unattended session retained");
    assert_eq!(
        revoked.authorization_state,
        RemoteAuthorizationState::PolicyChanged
    );
    assert_eq!(
        revoked.failure.as_ref().map(|failure| failure.code),
        Some(RemoteReasonCode::GrantRevoked)
    );
    assert!(state
        .session_authorizations
        .active_grant(&pending.session_id)
        .await
        .is_none());
    tokio::task::yield_now().await;
    assert!(
        media_task.is_finished(),
        "revoked media task must be aborted"
    );
}
