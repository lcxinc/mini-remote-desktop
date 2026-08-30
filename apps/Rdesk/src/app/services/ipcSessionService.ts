/**
 * IPC-based session service
 *
 * This service uses the new mrd-service IPC interface instead of the old
 * direct realtime_* commands. WebRTC signaling is now handled internally
 * by mrd-service.
 *
 * This service imports from the Tauri adapter layer, not directly from
 * @tauri-apps/api/tauri. This ensures that if commands are removed/renamed
 * in main.rs, the adapter contract tests will fail.
 */

import * as tauriAdapter from '../adapters/tauri';
import type {
  RemoteRoutePreference,
  RemoteSessionSnapshot,
  SessionEventSubscription,
  SessionEventSubscriptionQuery,
} from '../adapters/tauri/types';

// ============================================================================
// Types
// ============================================================================

export type SessionRole = "controller" | "agent";
export type TransportKind = "quic" | "webrtc";
export type SessionState =
  | "created"
  | "listening"
  | "connecting"
  | "connected"
  | "streaming"
  | "failed"
  | "closed";

export interface DeviceInfo {
  device_id: string;
  device_name: string;
  is_online: boolean;
}

export interface SessionInfo {
  session_id: string;
  role: SessionRole | "unknown";
  state: SessionState;
  transport_kind: TransportKind | string;
  last_error?: string | null;
  sender_active: boolean;
  receiver_active: boolean;
  peer_device_id?: string | null;
}

export interface SessionBootstrap {
  listen_addr?: string;
  server_name?: string;
  cert_der?: string;
}

export interface SessionRuntimeSnapshot {
  session_id: string;
  role: SessionRole | "unknown";
  state: SessionState;
  transport_kind: TransportKind;
  local_bootstrap?: SessionBootstrap;
  remote_bootstrap?: SessionBootstrap;
  last_error?: string;
  sender_active: boolean;
  receiver_active: boolean;
  peer_device_id?: string | null;
}

export interface RuntimeSnapshot {
  sessions: SessionRuntimeSnapshot[];
  device_id?: string | null;
  is_registered: boolean;
  signaling?: SignalingRuntimeSnapshot;
}

export interface SignalingRuntimeSnapshot {
  state: 'disabled' | 'connecting' | 'authenticated' | 'backoff' | 'stopped';
  reconnect_attempt: number;
  next_retry_at_ms: number | null;
  last_connected_at_ms: number | null;
  last_message_at_ms: number | null;
  last_error: string | null;
}

export type MediaProfile = tauriAdapter.MediaProfile;
export type MediaProfileNegotiation = tauriAdapter.MediaProfileNegotiation;
export type AdaptiveMediaConfig = tauriAdapter.AdaptiveMediaConfig;
export type MediaAdaptationSnapshot = tauriAdapter.MediaAdaptationSnapshot;
export type CaptureSource = tauriAdapter.CaptureSource;
export type CaptureSourceSelection = tauriAdapter.CaptureSourceSelection;
export type DisplayMode = tauriAdapter.DisplayMode;
export type DisplayModeChange = tauriAdapter.DisplayModeChange;

export interface ProbeSnapshot {
  session_id: string;
  frames_received: number;
  frames_decoded: number;
  frames_dropped: number;
  current_fps?: number | null;
  bitrate_mbps?: number | null;
  media_probe_valid?: boolean;
  media_probe_format?: string | null;
  media_probe_width?: number | null;
  media_probe_height?: number | null;
  media_probe_target_fps?: number | null;
  media_probe_target_bitrate_mbps?: number | null;
  media_probe_payload_bytes?: number | null;
  last_media_sequence?: number | null;
  last_media_timestamp_us?: number | null;
  last_media_payload_hash?: string | null;
  latest_frame_data_url?: string | null;
  latest_frame_width?: number | null;
  latest_frame_height?: number | null;
  latest_frame_pixel_format?: string | null;
  last_error?: string | null;
}

/**
 * Error thrown when an adapter command fails
 */
export class ServiceCommandError extends Error {
  constructor(message: string, public readonly code?: string) {
    super(message);
    this.name = 'ServiceCommandError';
  }
}

/**
 * Unwrap an adapter result, throwing a ServiceCommandError if failed
 */
function unwrapAdapterResult<T>(result: tauriAdapter.AdapterResult<T>): T {
  if (result.ok) {
    return result.value;
  }
  throw new ServiceCommandError(result.error.message, result.error.code);
}

// ============================================================================
// Device Commands
// ============================================================================

/**
 * Register this device with mrd-service
 */
export const registerDevice = async (
  deviceId: string,
  deviceName: string
): Promise<string> => {
  const result = await tauriAdapter.ipcRegisterDevice(deviceId, deviceName);
  return unwrapAdapterResult(result);
};

/**
 * List available devices
 */
export const listDevices = async (): Promise<DeviceInfo[]> => {
  const result = await tauriAdapter.ipcListDevices();
  return unwrapAdapterResult(result);
};

// ============================================================================
// Session Commands
// ============================================================================

/**
 * Create the legacy runtime session used exclusively by the explicit local
 * display self-test. The service rejects this contract for registered remote
 * targets; production remote control must use requestRemoteSession.
 */
export const startLocalTestSession = async (
  sessionId: string,
  localDeviceId: string,
  transportKind: TransportKind = "webrtc",
): Promise<string> => {
  const result = await tauriAdapter.ipcStartSession(
    sessionId,
    localDeviceId,
    transportKind,
  );
  return unwrapAdapterResult(result);
};

/**
 * Start a remote session as controller through attended authorization.
 *
 * The service owns route selection. QUIC is required only when the caller
 * explicitly requires LAN; Auto may select WAN relay when no fresh LAN path
 * is available.
 */
export const requestRemoteSession = async (
  sessionId: string,
  targetDeviceId: string,
  transportKind: TransportKind = "webrtc",
  requestedProfile?: MediaProfile,
  routePreference: RemoteRoutePreference = "auto",
): Promise<RemoteSessionSnapshot> => {
  if (routePreference === "lan" && transportKind !== "quic") {
    throw new ServiceCommandError(
      "Explicit LAN remote sessions currently require QUIC",
      "E_SECURE_LAN_TRANSPORT"
    );
  }
  const result = await tauriAdapter.ipcRequestRemoteSession({
    session_id: sessionId,
    target_device_id: targetDeviceId,
    access_mode: "attended",
    route_preference: routePreference,
    requested_scopes: ["screen.view", "input.pointer", "input.keyboard"],
    requested_profile: requestedProfile ?? null,
  });
  const snapshot = unwrapAdapterResult(result);
  if (
    snapshot.session_id !== sessionId ||
    snapshot.peer_device_id !== targetDeviceId ||
    snapshot.role !== "controller"
  ) {
    throw new ServiceCommandError(
      "Remote session response binding mismatch",
      "E_REMOTE_SESSION_BINDING",
    );
  }
  return snapshot;
};

/**
 * Read the authoritative secure remote-session projection.
 */
export const getRemoteSession = async (
  sessionId: string
): Promise<RemoteSessionSnapshot> => {
  const result = await tauriAdapter.ipcGetRemoteSession(sessionId);
  return unwrapAdapterResult(result);
};

/**
 * Long-poll typed secure remote-session events.
 */
export const subscribeSessionEvents = async (
  query: SessionEventSubscriptionQuery
): Promise<SessionEventSubscription> => {
  const result = await tauriAdapter.ipcSubscribeSessionEvents(query);
  return unwrapAdapterResult(result);
};

/**
 * Accept an incoming session as agent
 */
export const acceptSession = async (
  sessionId: string,
  sourceDeviceId: string
): Promise<string> => {
  const result = await tauriAdapter.ipcAcceptSession(sessionId, sourceDeviceId);
  return unwrapAdapterResult(result);
};

/**
 * Stop a session
 */
export const stopSession = async (sessionId: string): Promise<string> => {
  const result = await tauriAdapter.ipcStopSession(sessionId);
  return unwrapAdapterResult(result);
};

/**
 * Mark a session failed.
 */
export const failSession = async (
  sessionId: string,
  reason: string
): Promise<string> => {
  const result = await tauriAdapter.ipcFailSession(sessionId, reason);
  return unwrapAdapterResult(result);
};

/**
 * Recover a failed or closed session.
 */
export const recoverSession = async (sessionId: string): Promise<string> => {
  const result = await tauriAdapter.ipcRecoverSession(sessionId);
  return unwrapAdapterResult(result);
};

// ============================================================================
// Media Commands
// ============================================================================

/**
 * Start sending media (controller role)
 */
export const startSender = async (sessionId: string): Promise<string> => {
  const result = await tauriAdapter.ipcStartSender(sessionId);
  return unwrapAdapterResult(result);
};

/**
 * Start receiving media (agent role)
 */
export const startReceiver = async (sessionId: string): Promise<string> => {
  const result = await tauriAdapter.ipcStartReceiver(sessionId);
  return unwrapAdapterResult(result);
};

/**
 * Request a runtime media profile switch for an active LAN session.
 */
export const updateMediaProfile = async (
  sessionId: string,
  requestedProfile: MediaProfile
): Promise<MediaProfileNegotiation> => {
  const result = await tauriAdapter.ipcUpdateMediaProfile(sessionId, requestedProfile);
  return unwrapAdapterResult(result);
};

/**
 * Configure runtime media adaptation for an active LAN session.
 */
export const configureMediaAdaptation = async (
  sessionId: string,
  config: AdaptiveMediaConfig
): Promise<MediaAdaptationSnapshot> => {
  const result = await tauriAdapter.ipcConfigureMediaAdaptation(sessionId, config);
  return unwrapAdapterResult(result);
};

/**
 * List local capture sources. Image previews are disabled on native paths.
 */
export const listLocalCaptureSources = async (
  includePreviews = false,
  limit?: number
): Promise<CaptureSource[]> => {
  const result = await tauriAdapter.ipcListLocalCaptureSources(includePreviews, limit);
  return unwrapAdapterResult(result);
};

/**
 * List remote capture sources. Image previews are disabled on native paths.
 */
export const listRemoteCaptureSources = async (
  sessionId: string,
  includePreviews = false,
  limit?: number
): Promise<CaptureSource[]> => {
  const result = await tauriAdapter.ipcListRemoteCaptureSources(
    sessionId,
    includePreviews,
    limit
  );
  return unwrapAdapterResult(result);
};

/**
 * Select one remote capture source for the session.
 */
export const selectRemoteCaptureSource = async (
  sessionId: string,
  sourceId: string
): Promise<CaptureSourceSelection> => {
  const result = await tauriAdapter.ipcSelectRemoteCaptureSource(sessionId, sourceId);
  return unwrapAdapterResult(result);
};

/**
 * List remote display modes for the selected remote display source.
 */
export const listRemoteDisplayModes = async (
  sessionId: string
): Promise<DisplayMode[]> => {
  const result = await tauriAdapter.ipcListRemoteDisplayModes(sessionId);
  return unwrapAdapterResult(result);
};

/**
 * Set the remote display mode for the session.
 */
export const setRemoteDisplayMode = async (
  sessionId: string,
  mode: DisplayMode,
  restoreAfterSession = true
): Promise<DisplayModeChange> => {
  const result = await tauriAdapter.ipcSetRemoteDisplayMode(
    sessionId,
    mode,
    restoreAfterSession
  );
  return unwrapAdapterResult(result);
};

/**
 * Restore a remote display mode previously changed for the session.
 */
export const restoreRemoteDisplayMode = async (
  sessionId: string
): Promise<DisplayModeChange> => {
  const result = await tauriAdapter.ipcRestoreRemoteDisplayMode(sessionId);
  return unwrapAdapterResult(result);
};

// ============================================================================
// Snapshot Commands
// ============================================================================

/**
 * Get session runtime snapshot
 */
export const getSessionSnapshot = async (
  sessionId: string
): Promise<SessionRuntimeSnapshot> => {
  const result = await tauriAdapter.ipcSessionSnapshot(sessionId);
  return unwrapAdapterResult(result);
};

/**
 * List session summaries.
 */
export const listSessions = async (): Promise<SessionInfo[]> => {
  const result = await tauriAdapter.ipcListSessions();
  return unwrapAdapterResult(result);
};

/**
 * Get aggregated runtime snapshot (all sessions)
 */
export const getRuntimeSnapshot = async (): Promise<RuntimeSnapshot> => {
  const result = await tauriAdapter.ipcRuntimeSnapshot();
  return unwrapAdapterResult(result);
};

/**
 * Get probe snapshot data
 */
export const getProbeSnapshot = async (sessionId: string): Promise<ProbeSnapshot> => {
  const result = await tauriAdapter.ipcProbeSnapshot(sessionId);
  return unwrapAdapterResult(result);
};
