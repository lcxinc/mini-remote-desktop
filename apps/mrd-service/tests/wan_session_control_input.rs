use common_control_proto::ControlEvent;
use mrd_application::ports::{
    TransportEnvelope, TransportLane, TransportMuxPort, TransportSendOutcome,
};
use mrd_input::{InputError, InputEvent, InputInjector};
use mrd_ipc::{
    ConsentDecision, ConsentResponse, ControlInputEvent, ControlInputKey, DecimalU64, IpcResponse,
    RemoteAccessMode, RemoteAuthorizationState, RemotePermissionScope,
};
use mrd_proto::{DeviceId, SessionId};
use mrd_service::{
    control_input::ControlInputRegistry,
    handlers::session::send_control_input,
    lan_discovery::{process_lan_discovery_packet, AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX},
    session_authorization::{VerifiedIncomingAuthorizationRequest, VerifiedSessionGrant},
    transports::{memory::MemoryTransportMux, TransportMuxConfig},
    wan_session::{
        control_input::ServiceWanControlInputPort,
        media::{WanInputActivationPort, WanMediaAuthority},
        model::{
            GrantBinding, RelayAccessBinding, RelayRouteProof, WanSessionEvent, WanSessionIdentity,
            WanSessionRole, WanSessionState,
        },
    },
    AppState,
};
use mrd_session::{PermissionScope, SignedControlEnvelopeV2};
use mrd_signal_proto::{WanPermissionScopeV3, WanRoutePolicyV3};
use std::{
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

#[derive(Clone)]
struct RecordingInputInjector {
    events: Arc<StdMutex<Vec<InputEvent>>>,
}

impl InputInjector for RecordingInputInjector {
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

struct WanControlFixture {
    controller_state: Arc<AppState>,
    target_state: Arc<AppState>,
    controller_input: ServiceWanControlInputPort,
    session_id: SessionId,
    controller_device_id: DeviceId,
    target_device_id: DeviceId,
    controller_mux: Arc<dyn TransportMuxPort>,
    target_input: ServiceWanControlInputPort,
    injected: Arc<StdMutex<Vec<InputEvent>>>,
}

impl WanControlFixture {
    async fn new(granted_scopes: Vec<RemotePermissionScope>) -> Self {
        let controller_state = Arc::new(AppState::new());
        let target_state = Arc::new(AppState::new());
        let controller_key_id = controller_state
            .device_identities
            .machine_key_id()
            .expect("controller key id")
            .to_owned();
        let controller_public_key = controller_state
            .device_identities
            .machine_public_key()
            .expect("controller public key")
            .to_vec();
        let target_key_id = target_state
            .device_identities
            .machine_key_id()
            .expect("target key id")
            .to_owned();
        let target_public_key = target_state
            .device_identities
            .machine_public_key()
            .expect("target public key")
            .to_vec();
        let now = now_ms().saturating_sub(1_000);
        let expires_at_ms = now.saturating_add(60_000);
        let session_id = SessionId(format!("wan-control-{}", now_ms()));
        let controller_device_id = DeviceId(format!("controller-{}", session_id.0));
        let target_device_id = DeviceId(format!("target-{}", session_id.0));
        target_state
            .devices
            .lock()
            .await
            .register(target_device_id.clone(), "WAN target".to_owned());
        let requested_scopes = vec![
            RemotePermissionScope::ScreenView,
            RemotePermissionScope::InputPointer,
            RemotePermissionScope::InputKeyboard,
        ];

        target_state
            .session_authorizations
            .begin_verified_incoming(VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: controller_device_id.clone(),
                peer_key_id: controller_key_id.clone(),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: requested_scopes.clone(),
                peer_permission_ceiling: requested_scopes.clone(),
                machine_permission_ceiling: requested_scopes.clone(),
                runtime_capabilities: requested_scopes.clone(),
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [0x41; 16],
                created_at_ms: now,
                expires_at_ms,
            })
            .await
            .expect("target begins verified WAN authorization");
        target_state
            .session_authorizations
            .bind_authenticated_peer_key(&session_id, &controller_public_key, now + 1)
            .await
            .expect("target binds controller key");
        let approved = target_state
            .session_authorizations
            .respond_to_consent(
                ConsentResponse {
                    session_id: session_id.clone(),
                    decision: ConsentDecision::Approve,
                    approved_scopes: granted_scopes.clone(),
                    expected_policy_revision: DecimalU64::new(1),
                },
                now + 2,
            )
            .await
            .expect("target approves WAN scopes");
        let policy_revision = approved.policy_revision.get();
        let grant_id = [0x52; 32];
        let grant = VerifiedSessionGrant {
            grant_id: format!("sha256:{}", hex_bytes(&grant_id)),
            session_id: session_id.clone(),
            granted_scopes: granted_scopes.clone(),
            issued_at_ms: now + 3,
            expires_at_ms,
            policy_revision,
            route_constraint: "webrtc_relay".to_owned(),
            transport_fingerprint_sha256: [0x63; 32],
        };
        target_state
            .session_authorizations
            .install_verified_grant(grant.clone(), now + 3)
            .await
            .expect("target installs WAN grant");
        target_state
            .session_authorizations
            .mark_streaming(&session_id, now + 4)
            .await
            .expect("target marks WAN streaming");

        controller_state
            .session_authorizations
            .begin_outgoing(VerifiedIncomingAuthorizationRequest {
                session_id: session_id.clone(),
                peer_device_id: target_device_id.clone(),
                peer_key_id: format!("pending_authenticated_peer:{}", target_device_id.0),
                peer_key_epoch: 1,
                access_mode: RemoteAccessMode::Attended,
                requested_scopes: requested_scopes.clone(),
                peer_permission_ceiling: requested_scopes.clone(),
                machine_permission_ceiling: requested_scopes.clone(),
                runtime_capabilities: requested_scopes,
                transport_kind: "webrtc_relay".to_owned(),
                request_nonce: [0x42; 16],
                created_at_ms: now,
                expires_at_ms,
            })
            .await
            .expect("controller begins WAN authorization");
        controller_state
            .session_authorizations
            .bind_outgoing_authenticated_peer(
                &session_id,
                &target_device_id,
                &target_key_id,
                &target_public_key,
                now + 1,
            )
            .await
            .expect("controller binds target key");
        controller_state
            .session_authorizations
            .install_verified_grant(grant, now + 3)
            .await
            .expect("controller installs WAN grant");
        controller_state
            .session_authorizations
            .mark_streaming(&session_id, now + 4)
            .await
            .expect("controller marks WAN streaming");

        let mut approved_v3 = granted_scopes
            .iter()
            .copied()
            .map(v3_scope)
            .collect::<Vec<_>>();
        approved_v3.sort_unstable();
        let controller_authority = relay_verified_authority(
            session_id.clone(),
            WanSessionRole::Controller,
            controller_device_id.clone(),
            target_device_id.clone(),
            &controller_key_id,
            &target_key_id,
            approved_v3.clone(),
            policy_revision,
            expires_at_ms,
        );
        let target_authority = relay_verified_authority(
            session_id.clone(),
            WanSessionRole::Target,
            controller_device_id.clone(),
            target_device_id.clone(),
            &controller_key_id,
            &target_key_id,
            approved_v3,
            policy_revision,
            expires_at_ms,
        );
        let (controller_mux, target_mux) = MemoryTransportMux::pair(
            session_id.clone(),
            TransportMuxConfig {
                lane_capacity: 16,
                ..TransportMuxConfig::test()
            },
        );
        let controller_mux: Arc<dyn TransportMuxPort> = Arc::new(controller_mux);
        let target_mux: Arc<dyn TransportMuxPort> = Arc::new(target_mux);
        let controller_input = ServiceWanControlInputPort::with_test_mux(
            &controller_state,
            controller_authority,
            Arc::clone(&controller_mux),
        )
        .await
        .expect("bind controller WAN control mux");
        let target_input = ServiceWanControlInputPort::with_test_mux(
            &target_state,
            target_authority.clone(),
            target_mux,
        )
        .await
        .expect("bind target WAN control mux");
        let injected = Arc::new(StdMutex::new(Vec::new()));
        *target_state.control_input().lock().await =
            ControlInputRegistry::with_injector(RecordingInputInjector {
                events: Arc::clone(&injected),
            });
        target_input
            .enable_input(&target_authority)
            .await
            .expect("start target WAN input receiver");

        Self {
            controller_state,
            target_state,
            controller_input,
            session_id,
            controller_device_id,
            target_device_id,
            controller_mux,
            target_input,
            injected,
        }
    }

    async fn signed(
        &self,
        scope: PermissionScope,
        sequence: u64,
        event_id: u64,
        event: ControlEvent,
    ) -> SignedControlEnvelopeV2 {
        self.signed_from(
            self.controller_device_id.clone(),
            scope,
            sequence,
            event_id,
            event,
        )
        .await
    }

    async fn signed_from(
        &self,
        source_device_id: DeviceId,
        scope: PermissionScope,
        sequence: u64,
        event_id: u64,
        event: ControlEvent,
    ) -> SignedControlEnvelopeV2 {
        self.controller_input
            .signed_event_for_test(
                &self.session_id,
                source_device_id,
                self.target_device_id.clone(),
                scope,
                sequence,
                event_id,
                event,
            )
            .await
            .expect("sign test WAN control envelope")
    }

    async fn send_raw(&self, envelope: &SignedControlEnvelopeV2, lane: TransportLane) {
        let outcome = self
            .controller_mux
            .send(TransportEnvelope {
                session_id: envelope.payload.session_id.clone(),
                lane,
                sequence: envelope.payload.sequence,
                payload: serde_json::to_vec(envelope).expect("encode signed WAN input"),
                video: None,
            })
            .await
            .expect("send raw WAN control envelope");
        assert!(matches!(
            outcome,
            TransportSendOutcome::Enqueued | TransportSendOutcome::ReplacedStale
        ));
    }

    fn injected(&self) -> Vec<InputEvent> {
        self.injected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_pointer_and_keyboard_use_the_wan_mux_and_inject_once() {
    let fixture = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputPointer,
        RemotePermissionScope::InputKeyboard,
    ])
    .await;

    let pointer = send_control_input(
        &fixture.controller_state,
        fixture.session_id.clone(),
        ControlInputEvent::MouseMove { x: 320, y: 240 },
    )
    .await;
    assert!(matches!(pointer, IpcResponse::ControlInputAccepted { .. }));
    let keyboard = send_control_input(
        &fixture.controller_state,
        fixture.session_id.clone(),
        ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey { code: 0x41 },
            pressed: true,
        },
    )
    .await;
    assert!(matches!(keyboard, IpcResponse::ControlInputAccepted { .. }));

    wait_for_injected(&fixture, 2).await;
    assert_eq!(fixture.injected().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_reliable_wan_envelope_is_acknowledged_without_reinjection() {
    let fixture = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputKeyboard,
    ])
    .await;
    let envelope = fixture
        .signed(
            PermissionScope::InputKeyboard,
            1,
            71,
            ControlEvent::Key {
                key: 0x42,
                pressed: true,
            },
        )
        .await;

    fixture
        .send_raw(&envelope, TransportLane::ControlReliable)
        .await;
    wait_for_injected(&fixture, 1).await;
    fixture
        .send_raw(&envelope, TransportLane::ControlReliable)
        .await;
    tokio::time::sleep(Duration::from_millis(75)).await;

    assert_eq!(fixture.injected().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_realtime_wan_sequence_is_rejected_without_reinjection() {
    let fixture = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputPointer,
    ])
    .await;
    let newest = fixture
        .signed(
            PermissionScope::InputPointer,
            2,
            75,
            ControlEvent::MouseMove { x: 200, y: 210 },
        )
        .await;
    fixture
        .send_raw(&newest, TransportLane::ControlRealtime)
        .await;
    wait_for_injected(&fixture, 1).await;
    let stale = fixture
        .signed(
            PermissionScope::InputPointer,
            1,
            76,
            ControlEvent::MouseMove { x: 100, y: 110 },
        )
        .await;
    fixture
        .send_raw(&stale, TransportLane::ControlRealtime)
        .await;
    tokio::time::sleep(Duration::from_millis(75)).await;

    assert_eq!(fixture.injected().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_wan_control_envelope_cannot_be_replayed_into_the_lan_udp_receiver() {
    let fixture = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputKeyboard,
    ])
    .await;
    let envelope = fixture
        .signed(
            PermissionScope::InputKeyboard,
            1,
            77,
            ControlEvent::Key {
                key: 0x46,
                pressed: true,
            },
        )
        .await;
    let mut datagram = AUTHENTICATED_CONTROL_INPUT_DATAGRAM_PREFIX.to_vec();
    datagram.extend_from_slice(&serde_json::to_vec(&envelope).expect("encode WAN envelope"));
    let service_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("LAN receiver socket");
    let source_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("LAN source socket");

    process_lan_discovery_packet(
        &service_socket,
        &fixture.target_state,
        &datagram,
        source_socket.local_addr().expect("LAN source address"),
    )
    .await
    .expect("process cross-route replay");

    assert!(fixture.injected().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_peer_and_missing_scope_never_reach_the_target_injector() {
    let wrong_peer = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputPointer,
    ])
    .await;
    let forged = wrong_peer
        .signed_from(
            DeviceId("different-controller".to_owned()),
            PermissionScope::InputPointer,
            1,
            81,
            ControlEvent::MouseMove { x: 10, y: 20 },
        )
        .await;
    wrong_peer
        .send_raw(&forged, TransportLane::ControlRealtime)
        .await;
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(wrong_peer.injected().is_empty());

    let missing_scope = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputPointer,
    ])
    .await;
    let keyboard = missing_scope
        .signed(
            PermissionScope::InputKeyboard,
            1,
            82,
            ControlEvent::Key {
                key: 0x43,
                pressed: true,
            },
        )
        .await;
    missing_scope
        .send_raw(&keyboard, TransportLane::ControlReliable)
        .await;
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(missing_scope.injected().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_or_closed_wan_session_rejects_control_without_lan_fallback() {
    let fixture = WanControlFixture::new(vec![
        RemotePermissionScope::ScreenView,
        RemotePermissionScope::InputKeyboard,
    ])
    .await;
    fixture
        .target_state
        .session_authorizations
        .record_failure(
            &fixture.session_id,
            RemoteAuthorizationState::Revoked,
            mrd_ipc::RemoteFailure {
                code: mrd_ipc::RemoteReasonCode::GrantRevoked,
                message: "test revocation".to_owned(),
                suggested_action: None,
            },
            now_ms(),
        )
        .await
        .expect("revoke target authorization");
    let envelope = fixture
        .signed(
            PermissionScope::InputKeyboard,
            1,
            91,
            ControlEvent::Key {
                key: 0x44,
                pressed: true,
            },
        )
        .await;
    fixture
        .send_raw(&envelope, TransportLane::ControlReliable)
        .await;
    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(fixture.injected().is_empty());

    fixture
        .target_input
        .stop_for_test(&fixture.session_id)
        .await;
    let controller_result = send_control_input(
        &fixture.controller_state,
        fixture.session_id.clone(),
        ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey { code: 0x45 },
            pressed: true,
        },
    )
    .await;
    assert!(!matches!(
        controller_result,
        IpcResponse::ControlInputAccepted { .. }
    ));
    assert!(fixture.injected().is_empty());
}

async fn wait_for_injected(fixture: &WanControlFixture, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture.injected().len() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("WAN control injection converges");
}

#[allow(clippy::too_many_arguments)]
fn relay_verified_authority(
    session_id: SessionId,
    role: WanSessionRole,
    controller_device_id: DeviceId,
    target_device_id: DeviceId,
    controller_key_id: &str,
    target_key_id: &str,
    scopes: Vec<WanPermissionScopeV3>,
    policy_revision: u64,
    expires_at_ms: u64,
) -> WanMediaAuthority {
    let identity = WanSessionIdentity::new(
        session_id,
        controller_device_id,
        target_device_id,
        controller_key_id.to_owned(),
        target_key_id.to_owned(),
        expires_at_ms,
    )
    .expect("valid WAN control identity");
    let mut state = WanSessionState::new(role, identity);
    state
        .apply(
            WanSessionEvent::BackendBound {
                request_commitment: "11".repeat(32),
            },
            now_ms().saturating_sub(10),
        )
        .unwrap();
    state
        .apply(
            WanSessionEvent::AwaitingConsent {
                intent_commitment: "22".repeat(32),
            },
            now_ms().saturating_sub(9),
        )
        .unwrap();
    let grant = GrantBinding::new(
        "11".repeat(32),
        scopes,
        policy_revision,
        expires_at_ms,
        expires_at_ms,
        WanRoutePolicyV3::RelayOnly,
    )
    .unwrap()
    .with_grant_commitment(hex_bytes(&[0x52; 32]))
    .unwrap();
    let access = RelayAccessBinding::generation_zero(
        policy_revision,
        "wan-control-directory".to_owned(),
        "wan-control-relay".to_owned(),
        "63".repeat(32),
    )
    .unwrap();
    state
        .apply(WanSessionEvent::Granted(grant), now_ms() - 8)
        .unwrap();
    state
        .apply(WanSessionEvent::AccessBound(access.clone()), now_ms() - 7)
        .unwrap();
    state
        .apply(WanSessionEvent::Negotiating, now_ms() - 6)
        .unwrap();
    state
        .apply(
            WanSessionEvent::RelayVerified(RelayRouteProof::for_test(&access, true, true).unwrap()),
            now_ms() - 5,
        )
        .unwrap();
    WanMediaAuthority::from_relay_verified(&state).expect("verified WAN control authority")
}

fn v3_scope(scope: RemotePermissionScope) -> WanPermissionScopeV3 {
    match scope {
        RemotePermissionScope::ScreenView => WanPermissionScopeV3::ScreenView,
        RemotePermissionScope::InputPointer => WanPermissionScopeV3::InputPointer,
        RemotePermissionScope::InputKeyboard => WanPermissionScopeV3::InputKeyboard,
        _ => panic!("WAN control fixture uses only screen and input scopes"),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
