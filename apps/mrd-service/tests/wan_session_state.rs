use async_trait::async_trait;
use mrd_application::{
    AuthenticatedSessionSignal, VerifiedSignalingEvent, VerifiedSignalingIdentity,
};
use mrd_identity::DeviceIdentity;
use mrd_proto::{DeviceId, SessionId};
use mrd_service::{
    app_state::AppState,
    wan_session::{
        backend::WanSessionApproval,
        coordinator::{
            VerifiedWanSessionGrant, VerifiedWanSessionIntent, WanBackendSessionSnapshot,
            WanSessionCancellation, WanSessionCleanup, WanSessionClock, WanSessionConsentPublisher,
            WanSessionCoordinator, WanSessionCoordinatorConfig, WanSessionCoordinatorError,
            WanSessionPortError, WanSessionWorkflowBackend, WanSessionWorkflowPorts,
            WanSessionWorkflowSignaling,
        },
        model::{
            GrantBinding, RelayAccessBinding, RelayRouteProof, TransitionResult, WanSessionEvent,
            WanSessionFailure, WanSessionIdentity, WanSessionPhase, WanSessionRole,
            WanSessionState,
        },
    },
};
use mrd_signal_proto::{
    AuthClaims, SessionGrantV3, SessionGrantV3Payload, SessionIntentV3, SessionIntentV3Payload,
    WanAccessModeV3, WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3,
};
use ring::rand::SystemRandom;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};

const CONTROLLER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TARGET_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const REQUEST_COMMITMENT: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const RELAY_URL_DIGEST: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const INTENT_COMMITMENT: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const GRANT_COMMITMENT: &str = "6666666666666666666666666666666666666666666666666666666666666666";

#[test]
fn controller_can_defer_target_signing_key_until_the_verified_grant() {
    let identity = WanSessionIdentity::new_controller_pending_target(
        SessionId("wan-session-pending-target-key".into()),
        DeviceId("controller-pending-target-key".into()),
        DeviceId("target-pending-target-key".into()),
        CONTROLLER_KEY.to_owned(),
        2_000,
    )
    .unwrap();

    assert_eq!(identity.target_key_fingerprint(), None);
    assert!(identity.verify_actor(
        WanSessionRole::Controller,
        identity.controller_device_id(),
        CONTROLLER_KEY,
    ));
    assert!(!identity.verify_actor(
        WanSessionRole::Target,
        identity.target_device_id(),
        TARGET_KEY,
    ));
}

fn identity(suffix: &str) -> WanSessionIdentity {
    WanSessionIdentity::new(
        SessionId(format!("wan-session-{suffix}")),
        DeviceId(format!("controller-{suffix}")),
        DeviceId(format!("target-{suffix}")),
        CONTROLLER_KEY.to_owned(),
        TARGET_KEY.to_owned(),
        20_000,
    )
    .unwrap()
}

fn controller_identity_with_keys(
    suffix: &str,
) -> (WanSessionIdentity, DeviceIdentity, DeviceIdentity) {
    let controller_key = DeviceIdentity::generate(&SystemRandom::new()).unwrap();
    let target_key = DeviceIdentity::generate(&SystemRandom::new()).unwrap();
    let identity = WanSessionIdentity::new(
        SessionId(format!("wan-session-{suffix}")),
        DeviceId(format!("controller-{suffix}")),
        DeviceId(format!("target-{suffix}")),
        controller_key.key_id().to_owned(),
        target_key.key_id().to_owned(),
        20_000,
    )
    .unwrap();
    (identity, controller_key, target_key)
}

fn grant(revision: u64) -> GrantBinding {
    GrantBinding::new(
        REQUEST_COMMITMENT.to_owned(),
        vec![WanPermissionScopeV3::ScreenView],
        revision,
        18_000,
        17_000,
        WanRoutePolicyV3::RelayOnly,
    )
    .unwrap()
}

fn access(revision: u64) -> RelayAccessBinding {
    RelayAccessBinding::generation_zero(
        revision,
        "directory-cn-east".to_owned(),
        "relay-cn-east-1".to_owned(),
        RELAY_URL_DIGEST.to_owned(),
    )
    .unwrap()
}

fn full_path() -> Vec<WanSessionEvent> {
    vec![
        WanSessionEvent::BackendBound {
            request_commitment: REQUEST_COMMITMENT.to_owned(),
        },
        WanSessionEvent::AwaitingConsent {
            intent_commitment: INTENT_COMMITMENT.to_owned(),
        },
        WanSessionEvent::Granted(grant(7)),
        WanSessionEvent::AccessBound(access(7)),
        WanSessionEvent::Negotiating,
        WanSessionEvent::RelayVerified(RelayRouteProof::for_test(&access(7), true, true).unwrap()),
        WanSessionEvent::Streaming,
        WanSessionEvent::Closed,
    ]
}

#[test]
fn both_roles_follow_every_phase_without_mutating_identity() {
    for role in [WanSessionRole::Controller, WanSessionRole::Target] {
        let original = identity(match role {
            WanSessionRole::Controller => "controller-role",
            WanSessionRole::Target => "target-role",
        });
        let mut state = WanSessionState::new(role, original.clone());
        let expected = [
            WanSessionPhase::BackendBound,
            WanSessionPhase::AwaitingConsent,
            WanSessionPhase::Granted,
            WanSessionPhase::AccessBound,
            WanSessionPhase::Negotiating,
            WanSessionPhase::RelayVerified,
            WanSessionPhase::Streaming,
            WanSessionPhase::Closed,
        ];

        for (event, phase) in full_path().into_iter().zip(expected) {
            assert_eq!(
                state.apply(event, 10_000).unwrap(),
                TransitionResult::Applied
            );
            assert_eq!(state.phase(), phase);
            assert_eq!(state.identity(), &original);
        }
    }
}

#[test]
fn duplicates_are_idempotent_but_conflicts_and_skips_fail_closed() {
    let mut duplicate = WanSessionState::new(WanSessionRole::Controller, identity("duplicate"));
    let backend = WanSessionEvent::BackendBound {
        request_commitment: REQUEST_COMMITMENT.to_owned(),
    };
    assert_eq!(
        duplicate.apply(backend.clone(), 1).unwrap(),
        TransitionResult::Applied
    );
    assert_eq!(
        duplicate.apply(backend, 2).unwrap(),
        TransitionResult::Duplicate
    );
    duplicate
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: INTENT_COMMITMENT.to_owned(),
            },
            2,
        )
        .unwrap();
    assert_eq!(
        duplicate
            .apply(
                WanSessionEvent::BackendBound {
                    request_commitment: REQUEST_COMMITMENT.to_owned(),
                },
                3,
            )
            .unwrap(),
        TransitionResult::Duplicate
    );

    let conflict = WanSessionEvent::BackendBound {
        request_commitment: RELAY_URL_DIGEST.to_owned(),
    };
    assert!(duplicate.apply(conflict, 4).is_err());
    assert_eq!(duplicate.phase(), WanSessionPhase::Failed);
    assert_eq!(
        duplicate.failure(),
        Some(WanSessionFailure::ConflictingDuplicate)
    );

    let mut skipped = WanSessionState::new(WanSessionRole::Target, identity("skipped"));
    assert!(skipped
        .apply(WanSessionEvent::Granted(grant(7)), 1)
        .is_err());
    assert_eq!(skipped.phase(), WanSessionPhase::Failed);
    assert_eq!(
        skipped.failure(),
        Some(WanSessionFailure::InvalidTransition)
    );
    assert!(skipped.apply(WanSessionEvent::Streaming, 2).is_err());
    assert_eq!(skipped.phase(), WanSessionPhase::Failed);

    let original_failure = skipped.failure();
    assert!(skipped.apply(WanSessionEvent::Streaming, 30_000).is_err());
    assert_eq!(skipped.failure(), original_failure);
}

#[test]
fn deadline_generation_and_route_proof_are_fail_closed() {
    let mut expired = WanSessionState::new(WanSessionRole::Controller, identity("expired"));
    assert!(expired
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: REQUEST_COMMITMENT.to_owned(),
            },
            20_001,
        )
        .is_err());
    assert_eq!(expired.failure(), Some(WanSessionFailure::DeadlineExceeded));

    assert!(RelayAccessBinding::exact_generation(
        7,
        1,
        "directory-cn-east".to_owned(),
        "relay-cn-east-1".to_owned(),
        RELAY_URL_DIGEST.to_owned(),
    )
    .is_err());

    let mut state = WanSessionState::new(WanSessionRole::Controller, identity("proof"));
    for event in full_path().into_iter().take(5) {
        state.apply(event, 1).unwrap();
    }
    let wrong_access = RelayAccessBinding::generation_zero(
        7,
        "directory-cn-east".to_owned(),
        "relay-cn-east-2".to_owned(),
        RELAY_URL_DIGEST.to_owned(),
    )
    .unwrap();
    let wrong_proof = RelayRouteProof::for_test(&wrong_access, true, true).unwrap();
    assert!(state
        .apply(WanSessionEvent::RelayVerified(wrong_proof), 2)
        .is_err());
    assert_eq!(state.failure(), Some(WanSessionFailure::RouteMismatch));
}

#[derive(Default)]
struct RecordingCleanup {
    calls: Mutex<Vec<&'static str>>,
    fail_step: Option<&'static str>,
}

#[derive(Default)]
struct CancellationSafeCleanup {
    freeze_calls: AtomicUsize,
    total_calls: AtomicUsize,
    freeze_started: tokio::sync::Notify,
    release_freeze: tokio::sync::Notify,
}

impl CancellationSafeCleanup {
    fn record(&self) {
        self.total_calls.fetch_add(1, Ordering::AcqRel);
    }
}

#[async_trait]
impl WanSessionCleanup for CancellationSafeCleanup {
    async fn freeze_input(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record();
        self.freeze_calls.fetch_add(1, Ordering::AcqRel);
        self.freeze_started.notify_one();
        self.release_freeze.notified().await;
        Ok(())
    }

    async fn stop_media(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn close_transport(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn remove_failover(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn clear_signaling(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }

    async fn close_backend(
        &self,
        _: &SessionId,
        _: bool,
    ) -> Result<(), WanSessionCoordinatorError> {
        self.record();
        Ok(())
    }
}

impl RecordingCleanup {
    fn failing(step: &'static str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail_step: Some(step),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, value: &'static str) -> Result<(), WanSessionCoordinatorError> {
        self.calls.lock().unwrap().push(value);
        if self.fail_step == Some(value) {
            Err(WanSessionCoordinatorError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl WanSessionCleanup for RecordingCleanup {
    async fn freeze_input(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record("freeze_input")
    }

    async fn stop_media(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record("stop_media")
    }

    async fn close_transport(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record("close_transport")
    }

    async fn remove_failover(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record("remove_failover")
    }

    async fn clear_signaling(&self, _: &SessionId) -> Result<(), WanSessionCoordinatorError> {
        self.record("clear_signaling")
    }

    async fn close_backend(
        &self,
        _: &SessionId,
        failed: bool,
    ) -> Result<(), WanSessionCoordinatorError> {
        self.record(if failed {
            "revoke_backend"
        } else {
            "close_backend"
        })
    }
}

fn coordinator(cleanup: Arc<RecordingCleanup>, max_sessions: usize) -> WanSessionCoordinator {
    coordinator_with_clock(cleanup, max_sessions, Arc::new(FakeClock::default()))
}

fn coordinator_with_clock(
    cleanup: Arc<RecordingCleanup>,
    max_sessions: usize,
    clock: Arc<FakeClock>,
) -> WanSessionCoordinator {
    WanSessionCoordinator::new(
        WanSessionCoordinatorConfig {
            max_sessions,
            max_terminal_sessions: 8,
            max_tasks_per_session: 2,
            max_buffered_events_per_session: 2,
            max_retries_per_session: 1,
        },
        cleanup,
        clock,
    )
    .unwrap()
}

#[tokio::test]
async fn registry_is_bounded_and_terminal_cleanup_cancels_and_joins_owned_tasks() {
    let cleanup = Arc::new(RecordingCleanup::default());
    let coordinator = coordinator(cleanup.clone(), 1);
    let first = identity("first");
    let first_id = first.session_id().clone();
    coordinator
        .begin(WanSessionState::new(WanSessionRole::Controller, first))
        .await
        .unwrap();
    assert!(coordinator
        .begin(WanSessionState::new(
            WanSessionRole::Target,
            identity("second"),
        ))
        .await
        .is_err());

    let joined = Arc::new(AtomicBool::new(false));
    let joined_after_cancel = joined.clone();
    coordinator
        .spawn_owned_task(
            &first_id,
            move |mut cancellation: WanSessionCancellation| async move {
                cancellation.cancelled().await;
                joined_after_cancel.store(true, Ordering::SeqCst);
            },
        )
        .await
        .unwrap();

    coordinator
        .fail(&first_id, WanSessionFailure::Transport)
        .await
        .unwrap();
    assert!(joined.load(Ordering::SeqCst));
    assert_eq!(
        cleanup.calls(),
        vec![
            "freeze_input",
            "stop_media",
            "close_transport",
            "remove_failover",
            "clear_signaling",
            "revoke_backend",
        ]
    );
    assert_eq!(
        coordinator.snapshot(&first_id).await.unwrap().phase(),
        WanSessionPhase::Failed
    );

    coordinator
        .begin(WanSessionState::new(
            WanSessionRole::Target,
            identity("second"),
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn terminal_cleanup_receipt_replays_the_first_result_without_running_twice() {
    let cleanup = Arc::new(RecordingCleanup::failing("close_transport"));
    let coordinator = coordinator(cleanup.clone(), 1);
    let state = WanSessionState::new(WanSessionRole::Controller, identity("cleanup-receipt"));
    let session_id = state.identity().session_id().clone();
    coordinator.begin(state).await.unwrap();

    assert!(matches!(
        coordinator.close(&session_id).await,
        Err(WanSessionCoordinatorError::CleanupFailed)
    ));
    assert!(matches!(
        coordinator.close(&session_id).await,
        Err(WanSessionCoordinatorError::CleanupFailed)
    ));
    assert_eq!(
        cleanup.calls(),
        vec![
            "freeze_input",
            "stop_media",
            "close_transport",
            "remove_failover",
            "clear_signaling",
            "close_backend",
        ],
        "the stored cleanup receipt must prevent a second side-effect pass"
    );
}

#[tokio::test]
async fn terminal_cleanup_survives_caller_cancellation_without_replaying_side_effects() {
    let cleanup = Arc::new(CancellationSafeCleanup::default());
    let coordinator = Arc::new(
        WanSessionCoordinator::new(
            WanSessionCoordinatorConfig::default(),
            cleanup.clone(),
            Arc::new(FakeClock::default()),
        )
        .unwrap(),
    );
    let state = WanSessionState::new(WanSessionRole::Controller, identity("cleanup-cancel"));
    let session_id = state.identity().session_id().clone();
    coordinator.begin(state).await.unwrap();

    let first_coordinator = coordinator.clone();
    let first_session_id = session_id.clone();
    let first = tokio::spawn(async move { first_coordinator.close(&first_session_id).await });
    cleanup.freeze_started.notified().await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    cleanup.release_freeze.notify_one();

    assert!(tokio::time::timeout(
        std::time::Duration::from_secs(1),
        coordinator.close(&session_id),
    )
    .await
    .expect("stored cleanup must complete after caller cancellation")
    .is_ok());
    assert_eq!(cleanup.freeze_calls.load(Ordering::Acquire), 1);
    assert_eq!(cleanup.total_calls.load(Ordering::Acquire), 6);
}

#[tokio::test]
async fn an_owned_task_can_terminalize_its_session_without_joining_itself() {
    let coordinator = Arc::new(coordinator(Arc::new(RecordingCleanup::default()), 1));
    let state = WanSessionState::new(WanSessionRole::Controller, identity("self-finalize"));
    let session_id = state.identity().session_id().clone();
    coordinator.begin(state).await.unwrap();
    let (completed, completion) = tokio::sync::oneshot::channel();
    let task_coordinator = Arc::clone(&coordinator);
    let task_session_id = session_id.clone();
    coordinator
        .spawn_owned_task(&session_id, move |_| async move {
            let result = task_coordinator
                .fail(&task_session_id, WanSessionFailure::Transport)
                .await;
            let _ = completed.send(result.is_ok());
        })
        .await
        .unwrap();

    let completed = tokio::time::timeout(std::time::Duration::from_millis(250), completion).await;
    assert!(matches!(completed, Ok(Ok(true))));
    assert_eq!(
        coordinator.snapshot(&session_id).await.unwrap().phase(),
        WanSessionPhase::Failed
    );
}

#[tokio::test]
async fn failure_from_every_construction_phase_runs_the_full_cleanup_sequence() {
    let phases_before_failure = full_path().len() - 1;
    for prefix_len in 0..=phases_before_failure {
        let cleanup = Arc::new(RecordingCleanup::default());
        let coordinator = coordinator(cleanup.clone(), 1);
        let mut state = WanSessionState::new(
            WanSessionRole::Controller,
            identity(&format!("cleanup-{prefix_len}")),
        );
        let session_id = state.identity().session_id().clone();
        for event in full_path().into_iter().take(prefix_len) {
            state.apply(event, 1).unwrap();
        }
        coordinator.begin(state).await.unwrap();
        coordinator
            .fail(&session_id, WanSessionFailure::Internal)
            .await
            .unwrap();
        assert_eq!(
            cleanup.calls(),
            vec![
                "freeze_input",
                "stop_media",
                "close_transport",
                "remove_failover",
                "clear_signaling",
                "revoke_backend",
            ]
        );
    }
}

#[tokio::test]
async fn retry_and_buffer_budgets_are_hard_limits_under_one_deadline() {
    let clock = Arc::new(FakeClock::default());
    let coordinator =
        coordinator_with_clock(Arc::new(RecordingCleanup::default()), 1, clock.clone());
    let state = WanSessionState::new(WanSessionRole::Controller, identity("budgets"));
    let id = state.identity().session_id().clone();
    coordinator.begin(state).await.unwrap();

    coordinator.consume_retry(&id).await.unwrap();
    assert!(coordinator.consume_retry(&id).await.is_err());
    coordinator.reserve_buffered_event(&id).await.unwrap();
    coordinator.reserve_buffered_event(&id).await.unwrap();
    assert!(coordinator.reserve_buffered_event(&id).await.is_err());
    coordinator.release_buffered_event(&id).await.unwrap();
    coordinator.reserve_buffered_event(&id).await.unwrap();
    clock.0.store(20_000, Ordering::SeqCst);
    assert!(coordinator.consume_retry(&id).await.is_err());
    assert_eq!(coordinator.expire_due_sessions().await, 1);
    assert_eq!(
        coordinator.snapshot(&id).await.unwrap().failure(),
        Some(WanSessionFailure::DeadlineExceeded)
    );
}

#[tokio::test]
async fn streaming_session_expires_at_the_earliest_grant_or_policy_deadline() {
    let clock = Arc::new(FakeClock::default());
    let cleanup = Arc::new(RecordingCleanup::default());
    let coordinator = coordinator_with_clock(cleanup.clone(), 1, clock.clone());
    let mut state = WanSessionState::new(
        WanSessionRole::Controller,
        identity("streaming-grant-expiry"),
    );
    let session_id = state.identity().session_id().clone();
    for event in full_path().into_iter().take(7) {
        state.apply(event, 10_000).unwrap();
    }
    assert_eq!(state.phase(), WanSessionPhase::Streaming);
    coordinator.begin(state).await.unwrap();

    clock.0.store(17_000, Ordering::SeqCst);
    assert_eq!(coordinator.expire_due_sessions().await, 1);
    let expired = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(expired.phase(), WanSessionPhase::Failed);
    assert_eq!(expired.failure(), Some(WanSessionFailure::DeadlineExceeded));
    assert_eq!(cleanup.calls().len(), 6);
}

#[test]
fn app_state_binds_the_process_wide_coordinator_exactly_once() {
    let state = AppState::new();
    let first = Arc::new(coordinator(Arc::new(RecordingCleanup::default()), 4));
    let second = Arc::new(coordinator(Arc::new(RecordingCleanup::default()), 4));

    state.bind_wan_session_coordinator(first.clone()).unwrap();
    assert!(Arc::ptr_eq(
        &state.wan_session_coordinator().unwrap(),
        &first
    ));
    assert!(state.bind_wan_session_coordinator(second).is_err());
}

fn request_for(identity: &WanSessionIdentity) -> WanSessionRequestV3 {
    WanSessionRequestV3 {
        session_id: identity.session_id().clone(),
        idempotency_key: [9; 16],
        controller_device_id: identity.controller_device_id().clone(),
        target_device_id: identity.target_device_id().clone(),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![WanPermissionScopeV3::ScreenView],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    }
}

fn verified_target_intent(request: WanSessionRequestV3) -> (VerifiedWanSessionIntent, String) {
    let signer = DeviceIdentity::generate(&SystemRandom::new()).unwrap();
    let target_identity = DeviceIdentity::generate(&SystemRandom::new()).unwrap();
    let request_commitment = request.commitment().unwrap();
    let claims = AuthClaims {
        issuer_device_id: request.controller_device_id.clone(),
        issuer_key_id: signer.key_id().to_owned(),
        intended_peer_device_id: request.target_device_id.clone(),
        issued_at_ms: 1_000,
        expires_at_ms: 20_000,
        counter: 1,
        nonce: [7; 16],
    };
    let message = SessionIntentV3::sign(
        &signer,
        SessionIntentV3Payload {
            claims: claims.clone(),
            request,
            request_commitment: request_commitment.clone(),
        },
    )
    .unwrap();
    let event = VerifiedSignalingEvent {
        sender: VerifiedSignalingIdentity {
            device_id: claims.issuer_device_id.clone(),
            key_id: claims.issuer_key_id.clone(),
            public_key: signer.public_key().to_vec(),
            counter: claims.counter,
            nonce: claims.nonce,
            issued_at_ms: claims.issued_at_ms,
            expires_at_ms: claims.expires_at_ms,
        },
        signal: AuthenticatedSessionSignal::SessionIntentV3 { message },
    };
    (
        VerifiedWanSessionIntent::verify_event(
            event,
            &claims.intended_peer_device_id,
            &target_identity,
            1_000,
        )
        .unwrap(),
        request_commitment,
    )
}

fn verified_controller_grant(
    identity: &WanSessionIdentity,
    controller_key: &DeviceIdentity,
    target_key: &DeviceIdentity,
) -> VerifiedWanSessionGrant {
    let claims = AuthClaims {
        issuer_device_id: identity.target_device_id().clone(),
        issuer_key_id: target_key.key_id().to_owned(),
        intended_peer_device_id: identity.controller_device_id().clone(),
        issued_at_ms: 1_000,
        expires_at_ms: 19_000,
        counter: 1,
        nonce: [8; 16],
    };
    let message = SessionGrantV3::sign(
        target_key,
        SessionGrantV3Payload {
            claims: claims.clone(),
            session_id: identity.session_id().clone(),
            controller_device_id: identity.controller_device_id().clone(),
            target_device_id: identity.target_device_id().clone(),
            intent_commitment: INTENT_COMMITMENT.to_owned(),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: None,
            backend_policy_revision: 7,
            policy_expires_at_ms: 18_000,
            relay_generation: 0,
            relay_directory_id: "directory-cn-east".to_owned(),
            primary_relay_node_id: "relay-cn-east-1".to_owned(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .unwrap();
    let event = VerifiedSignalingEvent {
        sender: VerifiedSignalingIdentity {
            device_id: claims.issuer_device_id,
            key_id: claims.issuer_key_id,
            public_key: target_key.public_key().to_vec(),
            counter: claims.counter,
            nonce: claims.nonce,
            issued_at_ms: claims.issued_at_ms,
            expires_at_ms: claims.expires_at_ms,
        },
        signal: AuthenticatedSessionSignal::SessionGrantV3 { message },
    };
    VerifiedWanSessionGrant::verify_event(
        event,
        identity.controller_device_id(),
        controller_key,
        1_000,
    )
    .unwrap()
}

#[derive(Default)]
struct FakeClock(AtomicU64);

impl WanSessionClock for FakeClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct FakeBackend {
    requested: WanBackendSessionSnapshot,
    approved: WanBackendSessionSnapshot,
    access: RelayAccessBinding,
    create_calls: AtomicUsize,
    inspect_calls: AtomicUsize,
    approve_calls: AtomicUsize,
    access_calls: AtomicUsize,
    deadlines: Mutex<Vec<u64>>,
}

impl FakeBackend {
    fn new(request: WanSessionRequestV3) -> Self {
        let commitment = request.commitment().unwrap();
        let grant = GrantBinding::new(
            commitment.clone(),
            vec![WanPermissionScopeV3::ScreenView],
            7,
            18_000,
            17_000,
            WanRoutePolicyV3::RelayOnly,
        )
        .unwrap();
        Self {
            requested: WanBackendSessionSnapshot::requested(request.clone(), commitment.clone())
                .unwrap(),
            approved: WanBackendSessionSnapshot::approved(request, commitment, grant).unwrap(),
            access: access(7),
            create_calls: AtomicUsize::new(0),
            inspect_calls: AtomicUsize::new(0),
            approve_calls: AtomicUsize::new(0),
            access_calls: AtomicUsize::new(0),
            deadlines: Mutex::new(Vec::new()),
        }
    }

    fn record_deadline(&self, deadline: u64) {
        self.deadlines.lock().unwrap().push(deadline);
    }
}

#[async_trait]
impl WanSessionWorkflowBackend for FakeBackend {
    async fn create(
        &self,
        _: &WanSessionRequestV3,
        deadline: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        self.record_deadline(deadline);
        Ok(self.requested.clone())
    }

    async fn inspect(
        &self,
        _: &mrd_service::wan_session::backend::WanSessionBinding,
        deadline: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError> {
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        self.record_deadline(deadline);
        if self.create_calls.load(Ordering::SeqCst) > 0 {
            Ok(self.approved.clone())
        } else {
            Ok(self.requested.clone())
        }
    }

    async fn approve(
        &self,
        _: &mrd_service::wan_session::backend::WanSessionBinding,
        _: &WanSessionApproval,
        deadline: u64,
    ) -> Result<WanBackendSessionSnapshot, WanSessionPortError> {
        self.approve_calls.fetch_add(1, Ordering::SeqCst);
        self.record_deadline(deadline);
        Ok(self.approved.clone())
    }

    async fn access_generation_zero(
        &self,
        _: &mrd_service::wan_session::backend::WanSessionBinding,
        _: u64,
        deadline: u64,
    ) -> Result<RelayAccessBinding, WanSessionPortError> {
        self.access_calls.fetch_add(1, Ordering::SeqCst);
        self.record_deadline(deadline);
        Ok(self.access.clone())
    }
}

#[derive(Default)]
struct FakeSignaling {
    intents: AtomicUsize,
    grants: AtomicUsize,
    deadlines: Mutex<Vec<u64>>,
}

#[async_trait]
impl WanSessionWorkflowSignaling for FakeSignaling {
    async fn send_intent(
        &self,
        _: &WanSessionIdentity,
        _: &WanSessionRequestV3,
        _: &str,
        deadline: u64,
    ) -> Result<String, WanSessionPortError> {
        self.intents.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().unwrap().push(deadline);
        Ok(INTENT_COMMITMENT.to_owned())
    }

    async fn send_grant_with_commitment(
        &self,
        _: &WanSessionIdentity,
        _: &str,
        _: &GrantBinding,
        _: &RelayAccessBinding,
        deadline: u64,
    ) -> Result<String, WanSessionPortError> {
        self.grants.fetch_add(1, Ordering::SeqCst);
        self.deadlines.lock().unwrap().push(deadline);
        Ok(GRANT_COMMITMENT.to_owned())
    }
}

#[derive(Default)]
struct FakeConsent(AtomicUsize);

#[async_trait]
impl WanSessionConsentPublisher for FakeConsent {
    async fn publish_attended_request(
        &self,
        _: &WanSessionIdentity,
        _: &WanSessionRequestV3,
        _: u64,
    ) -> Result<(), WanSessionPortError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn load_attended_approval(
        &self,
        _: &WanSessionIdentity,
        _: u64,
    ) -> Result<WanSessionApproval, WanSessionPortError> {
        WanSessionApproval::new(vec![WanPermissionScopeV3::ScreenView], None)
            .map_err(|_| WanSessionPortError::Rejected)
    }
}

struct RejectingConsent;

#[async_trait]
impl WanSessionConsentPublisher for RejectingConsent {
    async fn publish_attended_request(
        &self,
        _: &WanSessionIdentity,
        _: &WanSessionRequestV3,
        _: u64,
    ) -> Result<(), WanSessionPortError> {
        Ok(())
    }

    async fn load_attended_approval(
        &self,
        _: &WanSessionIdentity,
        _: u64,
    ) -> Result<WanSessionApproval, WanSessionPortError> {
        Err(WanSessionPortError::Rejected)
    }
}

fn workflow_coordinator(
    backend: Arc<FakeBackend>,
    signaling: Arc<FakeSignaling>,
    consent: Arc<FakeConsent>,
    clock: Arc<FakeClock>,
) -> WanSessionCoordinator {
    WanSessionCoordinator::with_workflow_ports(
        WanSessionCoordinatorConfig {
            max_sessions: 4,
            max_terminal_sessions: 8,
            max_tasks_per_session: 2,
            max_buffered_events_per_session: 4,
            max_retries_per_session: 1,
        },
        Arc::new(RecordingCleanup::default()),
        WanSessionWorkflowPorts::new(backend, signaling, consent, clock),
    )
    .unwrap()
}

#[tokio::test]
async fn controller_creates_backend_before_intent_and_installs_exact_approved_generation_zero() {
    let (known_identity, controller_key, target_key) =
        controller_identity_with_keys("workflow-controller");
    let identity = WanSessionIdentity::new_controller_pending_target(
        known_identity.session_id().clone(),
        known_identity.controller_device_id().clone(),
        known_identity.target_device_id().clone(),
        controller_key.key_id().to_owned(),
        known_identity.deadline_unix_ms(),
    )
    .unwrap();
    let request = request_for(&identity);
    let backend = Arc::new(FakeBackend::new(request.clone()));
    let signaling = Arc::new(FakeSignaling::default());
    let consent = Arc::new(FakeConsent::default());
    let clock = Arc::new(FakeClock::default());
    clock.0.store(1_000, Ordering::SeqCst);
    let coordinator = workflow_coordinator(backend.clone(), signaling.clone(), consent, clock);

    coordinator
        .start_controller(identity.clone(), request)
        .await
        .unwrap();
    assert_eq!(backend.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(signaling.intents.load(Ordering::SeqCst), 1);
    assert_eq!(
        coordinator
            .snapshot(identity.session_id())
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::AwaitingConsent
    );

    let approved_grant = verified_controller_grant(&identity, &controller_key, &target_key);
    coordinator
        .install_controller_grant(identity.session_id(), approved_grant)
        .await
        .unwrap();
    let snapshot = coordinator.snapshot(identity.session_id()).await.unwrap();
    assert_eq!(snapshot.phase(), WanSessionPhase::AccessBound);
    assert_eq!(
        snapshot.identity().target_key_fingerprint(),
        Some(target_key.key_id())
    );
    assert_eq!(snapshot.access().unwrap().generation(), 0);
    assert_eq!(backend.access_calls.load(Ordering::SeqCst), 1);
    assert!(backend
        .deadlines
        .lock()
        .unwrap()
        .iter()
        .all(|deadline| *deadline == 20_000));
}

#[tokio::test]
async fn target_independently_inspects_then_publishes_consent_without_access_until_approval() {
    let seed_identity = identity("workflow-target");
    let request = request_for(&seed_identity);
    let (verified_intent, _) = verified_target_intent(request.clone());
    let identity = verified_intent.identity().clone();
    let backend = Arc::new(FakeBackend::new(request.clone()));
    let signaling = Arc::new(FakeSignaling::default());
    let consent = Arc::new(FakeConsent::default());
    let clock = Arc::new(FakeClock::default());
    clock.0.store(1_000, Ordering::SeqCst);
    let coordinator =
        workflow_coordinator(backend.clone(), signaling.clone(), consent.clone(), clock);

    coordinator
        .accept_verified_target_intent(verified_intent)
        .await
        .unwrap();
    assert_eq!(backend.inspect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(consent.0.load(Ordering::SeqCst), 1);
    assert_eq!(backend.access_calls.load(Ordering::SeqCst), 0);
    assert_eq!(signaling.grants.load(Ordering::SeqCst), 0);
    assert_eq!(
        coordinator
            .snapshot(identity.session_id())
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::AwaitingConsent
    );

    coordinator
        .approve_target(identity.session_id())
        .await
        .unwrap();
    assert_eq!(backend.approve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.access_calls.load(Ordering::SeqCst), 1);
    assert_eq!(signaling.grants.load(Ordering::SeqCst), 1);
    assert_eq!(
        coordinator
            .snapshot(identity.session_id())
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::AccessBound
    );
}

#[tokio::test]
async fn rejected_target_consent_terminalizes_without_relocking_the_operation_mutex() {
    let seed_identity = identity("reject");
    let request = request_for(&seed_identity);
    let (verified_intent, _) = verified_target_intent(request.clone());
    let session_id = verified_intent.identity().session_id().clone();
    let backend = Arc::new(FakeBackend::new(request));
    let clock = Arc::new(FakeClock::default());
    clock.0.store(1_000, Ordering::SeqCst);
    let coordinator = WanSessionCoordinator::with_workflow_ports(
        WanSessionCoordinatorConfig::default(),
        Arc::new(RecordingCleanup::default()),
        WanSessionWorkflowPorts::new(
            backend,
            Arc::new(FakeSignaling::default()),
            Arc::new(RejectingConsent),
            clock,
        ),
    )
    .unwrap();
    coordinator
        .accept_verified_target_intent(verified_intent)
        .await
        .unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        coordinator.approve_target(&session_id),
    )
    .await;
    assert!(result.is_ok(), "rejected consent must not deadlock cleanup");
    assert!(result.unwrap().is_err());
    let failed = coordinator.snapshot(&session_id).await.unwrap();
    assert_eq!(failed.phase(), WanSessionPhase::Failed);
    assert_eq!(failed.failure(), Some(WanSessionFailure::Cancelled));
}

#[tokio::test]
async fn request_conflicts_and_parallel_approval_are_serialized_fail_closed() {
    let conflict_identity = identity("workflow-concurrency");
    let request = request_for(&conflict_identity);
    let backend = Arc::new(FakeBackend::new(request.clone()));
    let signaling = Arc::new(FakeSignaling::default());
    let consent = Arc::new(FakeConsent::default());
    let clock = Arc::new(FakeClock::default());
    clock.0.store(1_000, Ordering::SeqCst);
    let coordinator = Arc::new(workflow_coordinator(
        backend.clone(),
        signaling.clone(),
        consent,
        clock,
    ));

    coordinator
        .start_controller(conflict_identity.clone(), request.clone())
        .await
        .unwrap();
    let mut conflicting_request = request;
    conflicting_request.idempotency_key = [8; 16];
    assert!(matches!(
        coordinator
            .start_controller(conflict_identity.clone(), conflicting_request)
            .await,
        Err(WanSessionCoordinatorError::SessionConflict)
    ));
    assert_eq!(
        coordinator
            .snapshot(conflict_identity.session_id())
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::Failed
    );

    let (identity, controller_key, target_key) =
        controller_identity_with_keys("workflow-parallel-grant");
    let request = request_for(&identity);
    let backend = Arc::new(FakeBackend::new(request.clone()));
    let signaling = Arc::new(FakeSignaling::default());
    let consent = Arc::new(FakeConsent::default());
    let clock = Arc::new(FakeClock::default());
    clock.0.store(1_000, Ordering::SeqCst);
    let coordinator = Arc::new(workflow_coordinator(
        backend.clone(),
        signaling,
        consent,
        clock,
    ));
    coordinator
        .start_controller(identity.clone(), request)
        .await
        .unwrap();

    let grant = verified_controller_grant(&identity, &controller_key, &target_key);
    let left = coordinator.install_controller_grant(identity.session_id(), grant.clone());
    let right = coordinator.install_controller_grant(identity.session_id(), grant);
    let (left, right) = tokio::join!(left, right);
    assert!(left.is_ok());
    assert!(right.is_ok());
    assert_eq!(backend.inspect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.access_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        coordinator
            .snapshot(identity.session_id())
            .await
            .unwrap()
            .phase(),
        WanSessionPhase::AccessBound
    );
}
