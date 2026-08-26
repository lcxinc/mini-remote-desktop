use super::{
    AuditLogRegistry, CapabilitySnapshotRegistry, CaptureSourceRegistry, DeviceIdentityRegistry,
    DevicePreferenceRegistry, DeviceRegistry, DisplayModeRegistry, FileTransferRegistry,
    MediaPipelineRegistry, MediaProfileRegistry, MediaTaskRegistry, ProbeRegistry,
    SessionPeerMediaCapabilityRegistry, SessionRegistry, ShellState, TrayPortRef,
};
#[cfg(any(windows, target_os = "macos"))]
use super::{MediaRenderQueueRegistry, MediaSurfaceRendererRegistry};
use crate::control_input::ControlInputRegistry;
use mrd_identity::DeviceIdentity;
use mrd_ipc::CapabilitySnapshot;
use mrd_store_sqlite::{PersistentStore, SecretProtector, StoreError};
use ring::rand::SystemRandom;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};
use tokio::sync::Mutex;

/// Application state for mrd-service
///
/// This is the shared state that will be injected into IPC handlers.
/// After migration, it will own:
/// - RealtimeRuntime / signaling client
/// - WebrtcHost / WebrtcSessionCoordinator
/// - QuicHost / QuicSessionCoordinator
/// - Media senders/receivers
/// - Probe/telemetry state
/// - Shell/UI lifecycle state
/// - Tray port (Phase 4)
pub struct AppState {
    /// Authenticated interactive-session agent registrations.
    pub agent_registry: Arc<crate::agent_runtime::AgentRegistry>,
    /// Session registry - single source of truth for all sessions
    pub sessions: Arc<Mutex<SessionRegistry>>,
    /// Device registry
    pub devices: Arc<Mutex<DeviceRegistry>>,
    /// Service-owned authenticated signaling connection health.
    pub signaling_status: Arc<crate::signaling::SignalingStatus>,
    /// Bounded authenticated relay-migration signaling commands and verified events.
    pub relay_signaling: Arc<crate::signaling::RelaySignalingBus>,
    signaling_mapper: Arc<RwLock<Option<Arc<crate::signaling::ServiceSignalingMapper>>>>,
    /// Service-owned WebRTC host whose stable muxes survive atomic relay replacement.
    pub webrtc_host: Arc<crate::transports::webrtc::ServiceWebRtcTransportHost>,
    /// Optional verified relay-directory client configured at process startup.
    relay_directory_client: Arc<RwLock<Option<Arc<crate::relay::RelayDirectoryClient>>>>,
    /// Optional production relay failover coordinator configured after signaling starts.
    relay_failover_coordinator: Arc<RwLock<Option<Arc<crate::relay::RelayFailoverCoordinator>>>>,
    /// Service-owned security and operations audit events.
    pub audit_log: Arc<AuditLogRegistry>,
    /// Service-owned device pairing and identity state.
    pub device_identities: Arc<DeviceIdentityRegistry>,
    /// Authoritative authorization, consent, grant, and event state.
    pub session_authorizations: Arc<crate::session_authorization::SessionAuthorizationRegistry>,
    /// Serializes trust/policy transitions with authorization grant issuance.
    pub authorization_security_gate: Arc<Mutex<()>>,
    /// Latched health of the authoritative security store.
    security_healthy: Arc<AtomicBool>,
    /// Service-owned device preference flags.
    pub device_preferences: Arc<Mutex<DevicePreferenceRegistry>>,
    /// Shell state - UI presence and service lifecycle
    pub shell: Arc<Mutex<ShellState>>,
    /// Tray port (Phase 4)
    pub tray: TrayPortRef,
    /// Peer-to-peer LAN discovery state.
    pub lan_discovery: Arc<crate::lan_discovery::LanDiscoveryState>,
    /// LAN probe telemetry keyed by session.
    pub probes: Arc<Mutex<ProbeRegistry>>,
    /// Negotiated media profile keyed by session.
    pub media_profiles: Arc<Mutex<MediaProfileRegistry>>,
    /// Selected capture source keyed by session.
    pub capture_sources: Arc<Mutex<CaptureSourceRegistry>>,
    /// Temporary display mode state keyed by session.
    pub display_modes: Arc<Mutex<DisplayModeRegistry>>,
    /// Peer media capabilities keyed by session.
    pub peer_media_capabilities: Arc<Mutex<SessionPeerMediaCapabilityRegistry>>,
    /// Cached local capability facts refreshed outside request handling.
    pub capability_snapshot: Arc<Mutex<CapabilitySnapshotRegistry>>,
    /// Service-owned keyboard and mouse injection state.
    pub control_input: Arc<Mutex<ControlInputRegistry>>,
    /// Service-owned file transfer task snapshots.
    pub file_transfers: Arc<Mutex<FileTransferRegistry>>,
    /// Receiver pipeline state keyed by session.
    pub media_pipelines: Arc<Mutex<MediaPipelineRegistry>>,
    /// Native renderer instances keyed by receiver session/surface.
    #[cfg(any(windows, target_os = "macos"))]
    pub media_surface_renderers: Arc<Mutex<MediaSurfaceRendererRegistry>>,
    /// Drop-oldest receiver render queues keyed by session.
    #[cfg(any(windows, target_os = "macos"))]
    pub media_render_queues: Arc<Mutex<MediaRenderQueueRegistry>>,
    /// Abort handles for active media tasks keyed by session.
    pub media_tasks: Arc<Mutex<MediaTaskRegistry>>,
    /// Bounded encoded media ingress from authenticated session agents.
    pub agent_media_ingress: Arc<Mutex<crate::agent_runtime::AgentMediaIngress>>,
    /// Exact service-to-agent render routes keyed by logical session.
    agent_render_routes: Arc<
        Mutex<crate::agent_runtime::AgentRenderRouteRegistry<crate::agent_runtime::AgentBinding>>,
    >,
    /// Authenticated server used to deliver prepared render access units.
    agent_media_server: Arc<RwLock<Option<Arc<crate::agent_runtime::AgentServer>>>>,
}

impl AppState {
    /// Binds an authenticated agent server to this service's media ingress.
    pub fn bind_agent_media_server(&self, server: Arc<crate::agent_runtime::AgentServer>) {
        server.set_media_ingress(self.agent_media_ingress.clone());
        if let Ok(mut slot) = self.agent_media_server.write() {
            *slot = Some(server);
        }
    }

    /// Install one exact render binding after `StartRender` succeeds.
    pub async fn install_agent_render_route(
        &self,
        session_id: mrd_proto::SessionId,
        binding: crate::agent_runtime::AgentBinding,
        resource_id: [u8; 16],
    ) -> Result<(), crate::agent_runtime::AgentRenderRouteError> {
        if binding.required_capability() != mrd_agent_ipc::AgentCapability::Render {
            return Err(crate::agent_runtime::AgentRenderRouteError::InvalidBinding);
        }
        self.agent_render_routes
            .lock()
            .await
            .install(session_id, binding, resource_id)
    }

    /// Reserve, sign, execute, and activate one exact Agent render resource.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_agent_render_route(
        &self,
        issuer: &crate::agent_runtime::ExecuteGrantIssuer,
        binding: crate::agent_runtime::AgentBinding,
        template: crate::agent_runtime::ExecuteGrantTemplate,
        resource_id: [u8; 16],
        display_id: u32,
        surface: mrd_agent_ipc::RenderSurfaceTarget,
        command_id: [u8; 16],
        grant_id: [u8; 32],
    ) -> Result<(), crate::agent_runtime::AgentRenderControlError> {
        if binding.required_capability() != mrd_agent_ipc::AgentCapability::Render
            || !template.matches_binding(&binding)
        {
            return Err(crate::agent_runtime::ExecuteGrantIssueError::CapabilityMismatch.into());
        }
        let server = self
            .agent_media_server
            .read()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or(crate::agent_runtime::AgentRenderControlError::ServerUnavailable)?;
        let session_id = template.session_id().clone();
        let execute = issuer.issue(
            command_id,
            grant_id,
            mrd_agent_ipc::AgentCommand::StartRender {
                resource_id,
                display_id,
                surface,
            },
            template,
        )?;
        self.agent_render_routes.lock().await.reserve(
            session_id.clone(),
            binding.clone(),
            resource_id,
        )?;
        let result = server.request_execute(&binding, execute).await;
        let completed = matches!(
            &result,
            Ok(mrd_agent_ipc::CommandResult {
                outcome: mrd_agent_ipc::CommandOutcome::Completed,
                ..
            })
        );
        if !completed {
            self.agent_render_routes.lock().await.cancel(&session_id);
            return match result {
                Ok(_) => Err(crate::agent_runtime::AgentRenderControlError::CommandRejected),
                Err(error) => Err(error.into()),
            };
        }
        if !self.agent_render_routes.lock().await.activate(&session_id) {
            return Err(crate::agent_runtime::AgentRenderControlError::ActivationLost);
        }
        Ok(())
    }

    /// Deactivate, sign, execute, and remove one exact Agent render resource.
    pub async fn stop_agent_render_route(
        &self,
        issuer: &crate::agent_runtime::ExecuteGrantIssuer,
        session_id: &mrd_proto::SessionId,
        template: crate::agent_runtime::ExecuteGrantTemplate,
        command_id: [u8; 16],
        grant_id: [u8; 32],
    ) -> Result<(), crate::agent_runtime::AgentRenderControlError> {
        let server = self
            .agent_media_server
            .read()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or(crate::agent_runtime::AgentRenderControlError::ServerUnavailable)?;
        let Some((binding, resource_id)) =
            self.agent_render_routes.lock().await.begin_stop(session_id)
        else {
            return Err(crate::agent_runtime::AgentRenderRouteError::MissingSession.into());
        };
        if template.session_id() != session_id || !template.matches_binding(&binding) {
            self.agent_render_routes.lock().await.activate(session_id);
            return Err(crate::agent_runtime::ExecuteGrantIssueError::CapabilityMismatch.into());
        }
        let execute = match issuer.issue(
            command_id,
            grant_id,
            mrd_agent_ipc::AgentCommand::StopRender { resource_id },
            template,
        ) {
            Ok(execute) => execute,
            Err(error) => {
                self.agent_render_routes.lock().await.activate(session_id);
                return Err(error.into());
            }
        };
        let result = server.request_execute(&binding, execute).await;
        self.agent_render_routes.lock().await.remove(session_id);
        server.clear_render_boundary_metrics(session_id);
        match result {
            Ok(mrd_agent_ipc::CommandResult {
                outcome:
                    mrd_agent_ipc::CommandOutcome::Completed
                    | mrd_agent_ipc::CommandOutcome::AlreadyStopped,
                ..
            }) => Ok(()),
            Ok(_) => Err(crate::agent_runtime::AgentRenderControlError::CommandRejected),
            Err(error) => Err(error.into()),
        }
    }

    /// Revoke one logical session's render route without implicit retargeting.
    pub async fn remove_agent_render_route(&self, session_id: &mrd_proto::SessionId) -> bool {
        let removed = self
            .agent_render_routes
            .lock()
            .await
            .remove(session_id)
            .is_some();
        if removed {
            if let Some(server) = self
                .agent_media_server
                .read()
                .ok()
                .and_then(|slot| slot.clone())
            {
                server.clear_render_boundary_metrics(session_id);
            }
        }
        removed
    }

    /// Merge the latest authenticated Agent render counters into the product snapshot.
    pub async fn sync_agent_render_boundary(&self, session_id: &mrd_proto::SessionId) {
        let metrics = self
            .agent_media_server
            .read()
            .ok()
            .and_then(|slot| slot.clone())
            .and_then(|server| server.render_boundary_metrics(session_id));
        if let Some(metrics) = metrics {
            self.media_pipelines
                .lock()
                .await
                .set_agent_render_boundary(session_id.clone(), metrics);
        }
    }

    /// Validate and deliver one encoded receiver unit to its exact session agent.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_agent_render_access_unit(
        &self,
        session_id: &mrd_proto::SessionId,
        sequence: u64,
        timestamp_us: u64,
        codec: mrd_agent_ipc::MediaCodec,
        is_keyframe: bool,
        payload: Vec<u8>,
    ) -> crate::agent_runtime::AgentRenderDispatch {
        let prepared = match self.agent_render_routes.lock().await.prepare(
            session_id,
            sequence,
            timestamp_us,
            codec,
            is_keyframe,
            payload,
        ) {
            Ok(prepared) => prepared,
            Err(crate::agent_runtime::AgentRenderRouteError::MissingSession) => {
                return crate::agent_runtime::AgentRenderDispatch::Unavailable;
            }
            Err(_) => return crate::agent_runtime::AgentRenderDispatch::Rejected,
        };
        let server = self
            .agent_media_server
            .read()
            .ok()
            .and_then(|slot| slot.clone());
        let Some(server) = server else {
            return crate::agent_runtime::AgentRenderDispatch::Rejected;
        };
        let (binding, unit) = prepared.into_parts();
        match server.send_render_access_unit(&binding, unit) {
            Ok(()) => crate::agent_runtime::AgentRenderDispatch::Delivered,
            Err(_) => crate::agent_runtime::AgentRenderDispatch::Rejected,
        }
    }

    /// Clears queued agent media after the owning session is revoked.
    pub async fn clear_agent_media_ingress(&self) {
        self.agent_media_ingress.lock().await.clear();
    }

    /// Drains one bounded batch for the LAN sender scheduler.
    pub async fn drain_agent_media_batch(
        &self,
        limit: usize,
    ) -> Vec<mrd_agent_ipc::MediaAccessUnit> {
        self.agent_media_ingress.lock().await.drain(limit)
    }

    /// Drains and validates a bounded batch in the LAN sender representation.
    pub(crate) async fn drain_agent_media_for_sender(
        &self,
        limit: usize,
    ) -> Vec<crate::lan_discovery::media_sender::AgentEncodedAccessUnit> {
        let mut ingress = self.agent_media_ingress.lock().await;
        crate::lan_discovery::media_sender::drain_agent_access_units(&mut ingress, limit)
    }

    /// Drains sender-ready units for one exact session.
    pub(crate) async fn drain_agent_media_for_session_sender(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Vec<crate::lan_discovery::media_sender::AgentEncodedAccessUnit> {
        let mut ingress = self.agent_media_ingress.lock().await;
        crate::lan_discovery::media_sender::drain_agent_access_units_for_session(
            &mut ingress,
            session_id,
            limit,
        )
    }

    /// Reports whether the next sender turn should use agent or local media.
    pub(crate) async fn media_source_selection(
        &self,
        session_id: &str,
    ) -> crate::lan_discovery::media_sender::MediaSourceSelection {
        let depth = self
            .agent_media_ingress
            .lock()
            .await
            .session_len(session_id);
        crate::lan_discovery::media_sender::select_media_source(depth)
    }

    /// Atomically selects and takes one sender turn for an exact session.
    pub(crate) async fn take_agent_media_turn(
        &self,
        session_id: &str,
        limit: usize,
        negotiated_codec: crate::lan_discovery::media_sender::LanAccessUnitCodec,
    ) -> Result<
        crate::lan_discovery::media_sender::SenderMediaTurn,
        crate::lan_discovery::media_sender::AgentTransportUnitError,
    > {
        let mut ingress = self.agent_media_ingress.lock().await;
        crate::lan_discovery::media_sender::take_sender_media_turn(
            &mut ingress,
            session_id,
            limit,
            negotiated_codec,
        )
    }

    /// Drains sender-ready units for one exact logical session.
    pub(crate) async fn drain_agent_media_for_session(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Vec<mrd_agent_ipc::MediaAccessUnit> {
        self.agent_media_ingress
            .lock()
            .await
            .drain_session(session_id, limit)
    }

    #[cfg(any(test, debug_assertions))]
    pub fn new() -> Self {
        Self::with_tray(Arc::new(std::sync::Mutex::new(
            crate::shell::NoOpTray::new(),
        )))
    }

    #[cfg(any(test, debug_assertions))]
    pub fn with_tray(tray: TrayPortRef) -> Self {
        Self::with_tray_and_lan_discovery_config(
            tray,
            crate::lan_discovery::LanDiscoveryConfig::default(),
        )
    }

    #[cfg(any(test, debug_assertions))]
    pub fn with_tray_and_lan_discovery_config(
        tray: TrayPortRef,
        lan_discovery_config: crate::lan_discovery::LanDiscoveryConfig,
    ) -> Self {
        Self::with_security_adapters(
            tray,
            lan_discovery_config,
            AuditLogRegistry::default(),
            DeviceIdentityRegistry::default(),
        )
    }

    /// Opens sealed machine identity, trust, and audit state for a service instance.
    pub fn open_persistent(
        store_path: impl AsRef<Path>,
        protector: Arc<dyn SecretProtector>,
    ) -> Result<Self, StoreError> {
        Self::open_persistent_with_tray_and_lan_discovery_config(
            Arc::new(std::sync::Mutex::new(crate::shell::NoOpTray::new())),
            crate::lan_discovery::LanDiscoveryConfig::default(),
            store_path,
            protector,
        )
    }

    /// Opens sealed security state while injecting production shell and LAN adapters.
    pub fn open_persistent_with_tray_and_lan_discovery_config(
        tray: TrayPortRef,
        lan_discovery_config: crate::lan_discovery::LanDiscoveryConfig,
        store_path: impl AsRef<Path>,
        protector: Arc<dyn SecretProtector>,
    ) -> Result<Self, StoreError> {
        let store = Arc::new(PersistentStore::open(store_path, protector)?);
        let machine_identity = store.load_or_create_identity(|| {
            DeviceIdentity::generate(&SystemRandom::new()).map_err(|_| StoreError::InvalidIdentity)
        })?;
        let machine_epoch = store.load_identity_epoch()?;
        Ok(Self::with_security_adapters(
            tray,
            lan_discovery_config,
            AuditLogRegistry::persistent(store.clone()),
            DeviceIdentityRegistry::persistent(store, machine_identity, machine_epoch),
        ))
    }

    fn with_security_adapters(
        tray: TrayPortRef,
        lan_discovery_config: crate::lan_discovery::LanDiscoveryConfig,
        audit_log: AuditLogRegistry,
        device_identities: DeviceIdentityRegistry,
    ) -> Self {
        Self {
            agent_registry: Arc::new(crate::agent_runtime::AgentRegistry::default()),
            sessions: Arc::new(Mutex::new(SessionRegistry::default())),
            devices: Arc::new(Mutex::new(DeviceRegistry::default())),
            signaling_status: Arc::new(crate::signaling::SignalingStatus::default()),
            relay_signaling: Arc::new(crate::signaling::RelaySignalingBus::default()),
            signaling_mapper: Arc::new(RwLock::new(None)),
            webrtc_host: Arc::new(crate::transports::webrtc::ServiceWebRtcTransportHost::new()),
            relay_directory_client: Arc::new(RwLock::new(None)),
            relay_failover_coordinator: Arc::new(RwLock::new(None)),
            audit_log: Arc::new(audit_log),
            device_identities: Arc::new(device_identities),
            session_authorizations: Arc::new(
                crate::session_authorization::SessionAuthorizationRegistry::default(),
            ),
            authorization_security_gate: Arc::new(Mutex::new(())),
            security_healthy: Arc::new(AtomicBool::new(true)),
            device_preferences: Arc::new(Mutex::new(DevicePreferenceRegistry::default())),
            shell: Arc::new(Mutex::new(ShellState::default())),
            tray,
            lan_discovery: Arc::new(crate::lan_discovery::LanDiscoveryState::new(
                lan_discovery_config,
            )),
            probes: Arc::new(Mutex::new(ProbeRegistry::default())),
            media_profiles: Arc::new(Mutex::new(MediaProfileRegistry::default())),
            capture_sources: Arc::new(Mutex::new(CaptureSourceRegistry::default())),
            display_modes: Arc::new(Mutex::new(DisplayModeRegistry::default())),
            peer_media_capabilities: Arc::new(Mutex::new(
                SessionPeerMediaCapabilityRegistry::default(),
            )),
            capability_snapshot: Arc::new(Mutex::new(CapabilitySnapshotRegistry::default())),
            control_input: Arc::new(Mutex::new(ControlInputRegistry::default())),
            file_transfers: Arc::new(Mutex::new(FileTransferRegistry::default())),
            media_pipelines: Arc::new(Mutex::new(MediaPipelineRegistry::default())),
            #[cfg(any(windows, target_os = "macos"))]
            media_surface_renderers: Arc::new(Mutex::new(MediaSurfaceRendererRegistry::default())),
            #[cfg(any(windows, target_os = "macos"))]
            media_render_queues: Arc::new(Mutex::new(MediaRenderQueueRegistry::default())),
            media_tasks: Arc::new(Mutex::new(MediaTaskRegistry::default())),
            agent_media_ingress: Arc::new(Mutex::new(
                crate::agent_runtime::AgentMediaIngress::new(32)
                    .expect("non-zero agent media ingress capacity"),
            )),
            agent_render_routes: Arc::new(Mutex::new(
                crate::agent_runtime::AgentRenderRouteRegistry::new(32)
                    .expect("non-zero agent render route capacity"),
            )),
            agent_media_server: Arc::new(RwLock::new(None)),
        }
    }

    /// Get a clone of the sessions Arc for injection into handlers
    pub fn sessions(&self) -> Arc<Mutex<SessionRegistry>> {
        self.sessions.clone()
    }

    /// Get a clone of the devices Arc for injection into handlers
    pub fn devices(&self) -> Arc<Mutex<DeviceRegistry>> {
        self.devices.clone()
    }

    /// Get a clone of the service audit log registry.
    pub fn audit_log(&self) -> Arc<AuditLogRegistry> {
        self.audit_log.clone()
    }

    /// Get a clone of the device identity registry.
    pub fn device_identities(&self) -> Arc<DeviceIdentityRegistry> {
        self.device_identities.clone()
    }

    /// Install the process-wide verified relay-directory client exactly once.
    pub fn bind_relay_directory_client(
        &self,
        client: Arc<crate::relay::RelayDirectoryClient>,
    ) -> Result<(), &'static str> {
        let mut slot = self
            .relay_directory_client
            .write()
            .map_err(|_| "relay directory client lock poisoned")?;
        if slot.is_some() {
            return Err("relay directory client is already bound");
        }
        *slot = Some(client);
        Ok(())
    }

    /// Return the configured verified relay-directory client, if WAN relay is enabled.
    pub fn relay_directory_client(&self) -> Option<Arc<crate::relay::RelayDirectoryClient>> {
        self.relay_directory_client
            .read()
            .ok()
            .and_then(|slot| slot.clone())
    }

    /// Install the production failover coordinator exactly once.
    pub fn bind_relay_failover_coordinator(
        &self,
        coordinator: Arc<crate::relay::RelayFailoverCoordinator>,
    ) -> Result<(), &'static str> {
        let mut slot = self
            .relay_failover_coordinator
            .write()
            .map_err(|_| "relay failover coordinator lock poisoned")?;
        if slot.is_some() {
            return Err("relay failover coordinator is already bound");
        }
        *slot = Some(coordinator);
        Ok(())
    }

    pub fn relay_failover_coordinator(
        &self,
    ) -> Option<Arc<crate::relay::RelayFailoverCoordinator>> {
        self.relay_failover_coordinator
            .read()
            .ok()
            .and_then(|slot| slot.clone())
    }

    pub(crate) fn bind_signaling_mapper(
        &self,
        mapper: Arc<crate::signaling::ServiceSignalingMapper>,
    ) -> Result<(), &'static str> {
        let mut slot = self
            .signaling_mapper
            .write()
            .map_err(|_| "signaling mapper lock poisoned")?;
        if slot.is_some() {
            return Err("signaling mapper is already bound");
        }
        *slot = Some(mapper);
        Ok(())
    }

    pub(crate) fn signaling_mapper(&self) -> Option<Arc<crate::signaling::ServiceSignalingMapper>> {
        self.signaling_mapper
            .read()
            .ok()
            .and_then(|slot| slot.clone())
    }

    /// Get a clone of the service-owned device preference registry.
    pub fn device_preferences(&self) -> Arc<Mutex<DevicePreferenceRegistry>> {
        self.device_preferences.clone()
    }

    /// Get the authenticated interactive-session agent registry.
    pub fn agent_registry(&self) -> Arc<crate::agent_runtime::AgentRegistry> {
        Arc::clone(&self.agent_registry)
    }

    /// Returns whether the authoritative security store has remained usable.
    pub fn security_is_healthy(&self) -> bool {
        self.security_healthy.load(Ordering::Acquire)
    }

    /// Permanently marks security state unavailable until process restart and re-verification.
    pub fn mark_security_unhealthy(&self) {
        if self
            .security_healthy
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        if let Err(error) = self.agent_registry.invalidate_all() {
            tracing::error!(%error, "failed to revoke desktop agents after security became unhealthy");
        }
        let authorization_security_gate = Arc::clone(&self.authorization_security_gate);
        let control_input = Arc::clone(&self.control_input);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _authorization_guard = authorization_security_gate.lock().await;
                if let Err(error) = control_input.lock().await.release_all_sessions() {
                    tracing::error!(%error, "failed to release pressed input after security became unhealthy");
                }
            });
        }
    }

    /// Get a clone of the shell Arc for injection into handlers
    pub fn shell(&self) -> Arc<Mutex<ShellState>> {
        self.shell.clone()
    }

    /// Get a clone of the tray Arc for injection into handlers
    pub fn tray(&self) -> TrayPortRef {
        self.tray.clone()
    }

    /// Get a clone of the LAN discovery state.
    pub fn lan_discovery(&self) -> Arc<crate::lan_discovery::LanDiscoveryState> {
        self.lan_discovery.clone()
    }

    /// Get a clone of the probe telemetry registry.
    pub fn probes(&self) -> Arc<Mutex<ProbeRegistry>> {
        self.probes.clone()
    }

    /// Get a clone of the media profile registry.
    pub fn media_profiles(&self) -> Arc<Mutex<MediaProfileRegistry>> {
        self.media_profiles.clone()
    }

    /// Get a clone of the capture source registry.
    pub fn capture_sources(&self) -> Arc<Mutex<CaptureSourceRegistry>> {
        self.capture_sources.clone()
    }

    /// Get a clone of the display mode registry.
    pub fn display_modes(&self) -> Arc<Mutex<DisplayModeRegistry>> {
        self.display_modes.clone()
    }

    /// Get a clone of the peer media capability registry.
    pub fn peer_media_capabilities(&self) -> Arc<Mutex<SessionPeerMediaCapabilityRegistry>> {
        self.peer_media_capabilities.clone()
    }

    /// Get a clone of the local capability snapshot registry.
    pub fn capability_snapshot(&self) -> Arc<Mutex<CapabilitySnapshotRegistry>> {
        self.capability_snapshot.clone()
    }

    /// Get a clone of the service-owned control input registry.
    pub fn control_input(&self) -> Arc<Mutex<ControlInputRegistry>> {
        self.control_input.clone()
    }

    /// Get a clone of the file transfer registry.
    pub fn file_transfers(&self) -> Arc<Mutex<FileTransferRegistry>> {
        self.file_transfers.clone()
    }

    /// Return the currently cached local capability snapshot without running runtime probes.
    pub async fn cached_capability_snapshot(&self) -> CapabilitySnapshot {
        let mut snapshot = self.capability_snapshot.lock().await.snapshot();
        let input_injector_available = self.control_input.lock().await.is_available();
        crate::capabilities::apply_control_input_capability_status(
            &mut snapshot,
            input_injector_available,
        );
        snapshot
    }

    /// Refresh the local capability snapshot on a blocking worker without delaying IPC handlers.
    pub fn refresh_capability_snapshot_in_background(self: &Arc<Self>) {
        let app_state = Arc::clone(self);
        tokio::spawn(async move {
            let should_refresh = {
                let mut registry = app_state.capability_snapshot.lock().await;
                registry.begin_refresh()
            };
            if !should_refresh {
                return;
            }

            let snapshot =
                tokio::task::spawn_blocking(crate::capabilities::local_capability_snapshot)
                    .await
                    .map_err(|error| {
                        tracing::warn!("capability snapshot refresh task failed: {}", error);
                        error
                    })
                    .ok();
            app_state
                .capability_snapshot
                .lock()
                .await
                .finish_refresh(snapshot);
        });
    }

    #[cfg(test)]
    pub async fn replace_capability_snapshot_for_test(&self, snapshot: CapabilitySnapshot) {
        self.capability_snapshot.lock().await.replace(snapshot);
    }

    #[cfg(test)]
    pub async fn replace_control_input_for_test<I>(&self, injector: I)
    where
        I: mrd_input::InputInjector + 'static,
    {
        *self.control_input.lock().await = ControlInputRegistry::with_injector(injector);
    }

    /// Get a clone of the receiver media pipeline registry.
    pub fn media_pipelines(&self) -> Arc<Mutex<MediaPipelineRegistry>> {
        self.media_pipelines.clone()
    }

    /// Get a clone of the native receiver renderer registry.
    #[cfg(any(windows, target_os = "macos"))]
    pub fn media_surface_renderers(&self) -> Arc<Mutex<MediaSurfaceRendererRegistry>> {
        self.media_surface_renderers.clone()
    }

    #[cfg(any(windows, target_os = "macos"))]
    pub fn media_render_queues(&self) -> Arc<Mutex<MediaRenderQueueRegistry>> {
        self.media_render_queues.clone()
    }

    /// Get a clone of the media task registry.
    pub fn media_tasks(&self) -> Arc<Mutex<MediaTaskRegistry>> {
        self.media_tasks.clone()
    }
}

#[cfg(any(test, debug_assertions))]
impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_input::{InputError, InputEvent, InputInjector};
    use mrd_ipc::{ControlInputEvent, ControlInputKey};
    use mrd_proto::SessionId;
    use std::sync::Mutex as StdMutex;

    #[derive(Clone)]
    struct SharedRecordingInjector {
        events: Arc<StdMutex<Vec<InputEvent>>>,
    }

    impl InputInjector for SharedRecordingInjector {
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

    #[test]
    fn app_state_core_initializes_empty_runtime_registries() {
        let state = AppState::new();

        assert!(!state.devices.try_lock().expect("devices").is_registered());
        assert_eq!(
            state
                .media_tasks
                .try_lock()
                .expect("media tasks")
                .active_count(&mrd_proto::SessionId("missing-session".to_string())),
            0
        );
    }

    #[tokio::test]
    async fn security_health_transition_releases_all_pressed_input() {
        let state = AppState::new();
        let events = Arc::new(StdMutex::new(Vec::new()));
        *state.control_input.lock().await =
            ControlInputRegistry::with_injector(SharedRecordingInjector {
                events: Arc::clone(&events),
            });
        state
            .control_input
            .lock()
            .await
            .handle_session_event(
                &SessionId("security-health-session".to_string()),
                &ControlInputEvent::Key {
                    key: ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            )
            .expect("key down before security failure");

        state.mark_security_unhealthy();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
                    >= 2
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("security cleanup completes");

        assert!(!state.security_is_healthy());
        assert_eq!(
            events
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
}
