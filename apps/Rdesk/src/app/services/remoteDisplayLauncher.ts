import { openRemoteDisplayWindow } from "../adapters/tauri";
import type { RemoteRoutePreference } from "../adapters/tauri/types";
import { isTauriRuntime } from "../utils/runtime";
import { deviceService } from "./deviceService";
import {
  listRemoteCaptureSources,
  selectRemoteCaptureSource,
  startLanRemoteSession,
  startSession,
  stopSession,
  type CaptureSource,
  type CaptureSourceSelection,
  type MediaProfile,
  type TransportKind,
} from "./ipcSessionService";
import { saveWebRemoteSession } from "./webRemoteSessionService";

export type RemoteDisplayLaunchResult = {
  sessionId: string;
  windowLabel: string | null;
  mode: "native_window" | "route";
  captureSourceSelection?: CaptureSourceSelection | null;
};

export type RemoteApplicationCatalogResult = {
  sessionId: string;
  sources: CaptureSource[];
  windows: CaptureSource[];
  displays: CaptureSource[];
};

const randomToken = () => Math.random().toString(36).slice(2, 8);

const DEFAULT_REMOTE_MEDIA_PROFILE: MediaProfile = {
  width: 1920,
  height: 1080,
  fps: 60,
  bitrate_mbps: 20,
  codec: "hevc",
  codec_profile: "main",
  bit_depth: 8,
  chroma_subsampling: "4:2:0",
  pixel_format: "nv12",
  hdr_enabled: false,
  color_mode: "full",
  color_pipeline: "sdr8",
};

const DEFAULT_REMOTE_MACOS_HEVC_MEDIA_PROFILE: MediaProfile = {
  width: 2560,
  height: 1440,
  fps: 144,
  bitrate_mbps: 40,
  codec: "hevc",
  codec_profile: "main",
  bit_depth: 8,
  chroma_subsampling: "4:2:0",
  pixel_format: "nv12",
  hdr_enabled: false,
  color_mode: "full",
  color_pipeline: "sdr8",
};

function defaultRemoteMediaProfileForTarget(targetOs?: string): MediaProfile {
  return isMacOsTarget(targetOs)
    ? { ...DEFAULT_REMOTE_MACOS_HEVC_MEDIA_PROFILE }
    : { ...DEFAULT_REMOTE_MEDIA_PROFILE };
}

function isMacOsTarget(targetOs?: string): boolean {
  const normalized = (targetOs ?? "").trim().toLowerCase();
  return (
    normalized === "mac" ||
    normalized.includes("macos") ||
    normalized.includes("mac os") ||
    normalized.includes("macintel") ||
    normalized.includes("macintosh") ||
    normalized.includes("darwin") ||
    normalized.includes("osx") ||
    normalized.includes("os x")
  );
}

export type RemoteDisplayLaunchOptions = {
  transportKind?: TransportKind;
  sessionId?: string;
  openWindow?: boolean;
  targetDeviceName?: string;
  targetOs?: string;
  targetIp?: string;
  localTest?: boolean;
  lanP2P?: boolean;
  routePreference?: RemoteRoutePreference;
  requestedProfile?: MediaProfile;
  captureSourceId?: string;
};

type RemoteApplicationCatalogOptions = Omit<
  RemoteDisplayLaunchOptions,
  "openWindow" | "captureSourceId" | "localTest"
> & {
  sessionAlreadyStarted?: boolean;
  includePreviews?: boolean;
  limit?: number;
};

type RemoteApplicationLaunchOptions = Omit<
  RemoteDisplayLaunchOptions,
  "openWindow" | "captureSourceId" | "localTest"
> & {
  sessionAlreadyStarted?: boolean;
};

export function createSessionId(prefix: string): string {
  return `${prefix}-${Date.now()}-${randomToken()}`;
}

export async function launchRemoteDisplayForDevice(
  targetDeviceId: string,
  options?: RemoteDisplayLaunchOptions
): Promise<RemoteDisplayLaunchResult> {
  const tauriRuntime = isTauriRuntime();
  const transportKind = tauriRuntime
    ? (options?.transportKind ?? (options?.lanP2P ? "quic" : "webrtc"))
    : "webrtc";
  const localDeviceInfo = tauriRuntime
    ? deviceService.getDeviceInfo() ?? (await deviceService.initialize())
    : null;
  const targetIsLocal = Boolean(
    options?.localTest ||
      (localDeviceInfo?.device_id && localDeviceInfo.device_id === targetDeviceId)
  );
  const sessionId =
    options?.sessionId ??
    createSessionId(targetIsLocal ? "local-display-test" : `p2p-${transportKind}`);
  const lanRequestedProfile =
    !targetIsLocal && options?.lanP2P
      ? (options?.requestedProfile ??
        defaultRemoteMediaProfileForTarget(options?.targetOs))
      : undefined;

  if (!tauriRuntime) {
    saveWebRemoteSession({
      sessionId,
      targetDeviceId,
      targetDeviceName: options?.targetDeviceName ?? "Local WebRTC Device",
      targetOs: options?.targetOs ?? "Browser WebRTC",
      targetIp: options?.targetIp ?? "127.0.0.1",
      transportKind: "webrtc",
      createdAt: Date.now(),
      mode: options?.localTest ? "web_to_local" : "web_to_peer",
    });
    return { sessionId, windowLabel: null, mode: "route" };
  }

  const hasExplicitRoutePreference = options?.routePreference !== undefined;
  const shouldUseAuthorizedRemoteRequest = Boolean(
    !targetIsLocal && (options?.lanP2P || hasExplicitRoutePreference),
  );
  const startedSessionId = targetIsLocal
    ? sessionId
    : shouldUseAuthorizedRemoteRequest
      ? hasExplicitRoutePreference
        ? await startLanRemoteSession(
            sessionId,
            targetDeviceId,
            transportKind,
            lanRequestedProfile,
            options.routePreference,
          )
        : await startLanRemoteSession(
            sessionId,
            targetDeviceId,
            transportKind,
            lanRequestedProfile,
          )
      : await startSession(sessionId, targetDeviceId, transportKind);

  let captureSourceSelection: CaptureSourceSelection | null = null;
  if (options?.captureSourceId) {
    captureSourceSelection = await selectRemoteCaptureSource(
      startedSessionId,
      options.captureSourceId
    );
  }

  if (options?.openWindow === false) {
    const result: RemoteDisplayLaunchResult = {
      sessionId: startedSessionId,
      windowLabel: null,
      mode: "route",
    };
    if (captureSourceSelection) result.captureSourceSelection = captureSourceSelection;
    return result;
  }

  const windowParams: Parameters<typeof openRemoteDisplayWindow>[0] = {
    sessionId: startedSessionId,
  };
  if (captureSourceSelection) {
    windowParams.captureSourceId = captureSourceSelection.source.id;
  }
  if (lanRequestedProfile) {
    windowParams.requestedProfile = lanRequestedProfile;
  }
  const windowResult = await openRemoteDisplayWindow(windowParams);
  if (!windowResult.ok) {
    throw new Error(windowResult.error.message);
  }

  const result: RemoteDisplayLaunchResult = {
    sessionId: startedSessionId,
    windowLabel: windowResult.value.label,
    mode: "native_window",
  };
  if (captureSourceSelection) result.captureSourceSelection = captureSourceSelection;
  return result;
}

export async function prepareRemoteApplicationCatalogForDevice(
  targetDeviceId: string,
  options?: RemoteApplicationCatalogOptions
): Promise<RemoteApplicationCatalogResult> {
  if (!isTauriRuntime()) {
    throw new Error("远程应用列表需要在桌面端运行");
  }

  if (!options?.lanP2P) {
    throw new Error("远程应用当前需要 LAN P2P 会话");
  }

  const usingExistingSession = Boolean(
    options?.sessionAlreadyStarted && options.sessionId
  );
  const sessionId = usingExistingSession
    ? options!.sessionId!
    : (
        await launchRemoteDisplayForDevice(targetDeviceId, {
          ...options,
          openWindow: false,
        })
      ).sessionId;

  let sources: CaptureSource[];
  try {
    sources = await listRemoteCaptureSources(
      sessionId,
      options?.includePreviews ?? false,
      options?.limit ?? 48
    );
  } catch (error) {
    if (!usingExistingSession) {
      await stopSession(sessionId).catch(() => undefined);
    }
    throw error;
  }

  return buildRemoteApplicationCatalog(sessionId, sources);
}

export async function launchRemoteApplicationForDevice(
  targetDeviceId: string,
  sourceId: string,
  options?: RemoteApplicationLaunchOptions
): Promise<RemoteDisplayLaunchResult> {
  if (!isTauriRuntime()) {
    throw new Error("远程应用需要在桌面端运行");
  }

  if (!options?.lanP2P) {
    throw new Error("远程应用当前需要 LAN P2P 会话");
  }

  const usingExistingSession = Boolean(
    options?.sessionAlreadyStarted && options.sessionId
  );
  const sessionId = usingExistingSession
    ? options!.sessionId!
    : (
        await launchRemoteDisplayForDevice(targetDeviceId, {
          ...options,
          openWindow: false,
        })
      ).sessionId;

  let captureSourceSelection: CaptureSourceSelection;
  let windowResult: Awaited<ReturnType<typeof openRemoteDisplayWindow>>;
  try {
    captureSourceSelection = await selectRemoteCaptureSource(sessionId, sourceId);
    const requestedProfile =
      options?.requestedProfile ?? defaultRemoteMediaProfileForTarget(options?.targetOs);
    const windowParams: Parameters<typeof openRemoteDisplayWindow>[0] = {
      sessionId,
      captureSourceId: captureSourceSelection.source.id,
    };
    if (requestedProfile) {
      windowParams.requestedProfile = requestedProfile;
    }
    windowResult = await openRemoteDisplayWindow(windowParams);
    if (!windowResult.ok) {
      throw new Error(windowResult.error.message);
    }
  } catch (error) {
    if (!usingExistingSession) {
      await stopSession(sessionId).catch(() => undefined);
    }
    throw error;
  }

  return {
    sessionId,
    windowLabel: windowResult.value.label,
    mode: "native_window",
    captureSourceSelection,
  };
}

function buildRemoteApplicationCatalog(
  sessionId: string,
  sources: CaptureSource[]
): RemoteApplicationCatalogResult {
  const normalizedSources = Array.isArray(sources) ? sources : [];
  return {
    sessionId,
    sources: normalizedSources,
    windows: normalizedSources.filter((source) => source.source_kind === "window"),
    displays: normalizedSources.filter(
      (source) =>
        source.source_kind === "display" || source.source_kind === "display_shared"
    ),
  };
}

export async function launchLocalRemoteDisplayTest(): Promise<RemoteDisplayLaunchResult> {
  const deviceInfo = deviceService.getDeviceInfo() ?? await deviceService.initialize();
  const targetDeviceId = deviceInfo?.device_id ?? "local-test-device";
  return launchRemoteDisplayForDevice(targetDeviceId, {
    sessionId: createSessionId("local-display-test"),
    transportKind: "webrtc",
    targetDeviceName: deviceInfo?.device_name ?? "Local WebRTC Device",
    targetOs: "Browser WebRTC",
    targetIp: "127.0.0.1",
    localTest: true,
  });
}
