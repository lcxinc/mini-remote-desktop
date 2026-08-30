//! Platform-neutral Windows service lifecycle policy.

use std::collections::BTreeSet;

/// Stable SCM service name used by the binary, installer, and service SID ACL.
pub const MRD_WINDOWS_SERVICE_NAME: &str = "MiniRemoteDesktop";

/// Per-service SID deterministically assigned by SCM to `MiniRemoteDesktop`.
pub const MRD_WINDOWS_SERVICE_SID: &str =
    "S-1-5-80-1879472017-33930626-126605267-2295067401-1052995421";

/// Current SCM-visible service state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// No product work or Agent process is live.
    #[default]
    Stopped,
    /// IPC, transports, and Agent supervision are accepting work.
    Running,
}

/// Why an orderly service shutdown began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SCM stop control.
    Stop,
    /// SCM preshutdown control before system shutdown.
    PreShutdown,
}

/// Trusted Windows session transition delivered by SCM/WTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionChange {
    /// A user logged on to an interactive session.
    Logon(u32),
    /// A user session reconnected.
    Connect(u32),
    /// A user session disconnected during fast-user-switch or remote disconnect.
    Disconnect(u32),
    /// A user logged off and its session is terminal.
    Logoff(u32),
}

impl SessionChange {
    fn session_id(self) -> u32 {
        match self {
            Self::Logon(id) | Self::Connect(id) | Self::Disconnect(id) | Self::Logoff(id) => id,
        }
    }
}

/// Input event accepted by the lifecycle policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceControl {
    /// Start the machine service.
    Start,
    /// Stop the machine service.
    Stop,
    /// Begin bounded cleanup before operating-system shutdown.
    PreShutdown,
    /// Reconcile one interactive-session transition.
    SessionChange(SessionChange),
}

/// Ordered side effect that the Windows host must execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEffect {
    /// Verify or initialize the protected machine-wide product directory.
    InitializeProtectedProductData,
    /// Invalidate all process-local execution grants from an earlier service generation.
    InvalidateExecutionGrants,
    /// Begin accepting authenticated Session Agent connections.
    StartAgentServer,
    /// Start LAN/signaling/media transport listeners.
    StartTransports,
    /// Report `SERVICE_RUNNING` to SCM.
    ReportRunning,
    /// Stop accepting new product work.
    StopAcceptingWork,
    /// Stop transport tasks before Agent teardown.
    StopTransports,
    /// Revoke and join all Session Agents.
    StopAgents,
    /// Report `SERVICE_STOPPED` to SCM.
    ReportStopped,
    /// Launch one Agent in an eligible interactive session.
    LaunchAgent(u32),
    /// Revoke and join the Agent bound to a session.
    RevokeAgentSession(u32),
    /// Destructive trust reset. Normal restart must never emit this effect.
    ResetTrustStore,
}

/// Deterministic lifecycle policy shared by SCM and contract tests.
#[derive(Debug, Default)]
pub struct ServiceLifecycle {
    state: ServiceState,
    agents: BTreeSet<u32>,
    last_shutdown_reason: Option<ShutdownReason>,
}

impl ServiceLifecycle {
    /// Create a stopped service generation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ServiceState {
        self.state
    }

    /// Most recent orderly shutdown reason.
    pub fn last_shutdown_reason(&self) -> Option<ShutdownReason> {
        self.last_shutdown_reason
    }

    /// Whether this service generation owns an Agent for the session.
    pub fn has_agent(&self, session_id: u32) -> bool {
        self.agents.contains(&session_id)
    }

    /// Apply one control and return its strictly ordered host effects.
    pub fn apply(&mut self, control: ServiceControl) -> Vec<ServiceEffect> {
        match control {
            ServiceControl::Start if self.state == ServiceState::Stopped => {
                self.agents.clear();
                self.last_shutdown_reason = None;
                self.state = ServiceState::Running;
                vec![
                    ServiceEffect::InitializeProtectedProductData,
                    ServiceEffect::InvalidateExecutionGrants,
                    ServiceEffect::StartAgentServer,
                    ServiceEffect::StartTransports,
                    ServiceEffect::ReportRunning,
                ]
            }
            ServiceControl::Stop if self.state == ServiceState::Running => {
                self.shutdown(ShutdownReason::Stop)
            }
            ServiceControl::PreShutdown if self.state == ServiceState::Running => {
                self.shutdown(ShutdownReason::PreShutdown)
            }
            ServiceControl::SessionChange(change) if self.state == ServiceState::Running => {
                self.apply_session_change(change)
            }
            _ => Vec::new(),
        }
    }

    fn shutdown(&mut self, reason: ShutdownReason) -> Vec<ServiceEffect> {
        self.state = ServiceState::Stopped;
        self.last_shutdown_reason = Some(reason);
        self.agents.clear();
        vec![
            ServiceEffect::StopAcceptingWork,
            ServiceEffect::StopTransports,
            ServiceEffect::StopAgents,
            ServiceEffect::ReportStopped,
        ]
    }

    fn apply_session_change(&mut self, change: SessionChange) -> Vec<ServiceEffect> {
        let session_id = change.session_id();
        if session_id == 0 {
            return Vec::new();
        }
        match change {
            SessionChange::Logon(_) | SessionChange::Connect(_) => self
                .agents
                .insert(session_id)
                .then_some(ServiceEffect::LaunchAgent(session_id))
                .into_iter()
                .collect(),
            SessionChange::Disconnect(_) | SessionChange::Logoff(_) => self
                .agents
                .remove(&session_id)
                .then_some(ServiceEffect::RevokeAgentSession(session_id))
                .into_iter()
                .collect(),
        }
    }
}
