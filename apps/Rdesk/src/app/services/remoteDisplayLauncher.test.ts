import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  launchRemoteApplicationForDevice,
  launchRemoteDisplayForDevice,
  prepareRemoteApplicationCatalogForDevice,
} from "./remoteDisplayLauncher";

const mocks = vi.hoisted(() => ({
  openRemoteDisplayWindow: vi.fn(),
  listRemoteCaptureSources: vi.fn(),
  selectRemoteCaptureSource: vi.fn(),
  requestRemoteSession: vi.fn(),
  startLocalTestSession: vi.fn(),
  stopSession: vi.fn(),
  saveWebRemoteSession: vi.fn(),
  getDeviceInfo: vi.fn(),
  initialize: vi.fn(),
  waitForRemoteSessionStreaming: vi.fn(),
  runtime: { isTauri: true },
}));

const DEFAULT_HEVC_1080P60_PROFILE = {
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

const MACOS_HEVC_2K144_PROFILE = {
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

vi.mock("../adapters/tauri", () => ({
  openRemoteDisplayWindow: mocks.openRemoteDisplayWindow,
}));

vi.mock("../utils/runtime", () => ({
  isTauriRuntime: () => mocks.runtime.isTauri,
}));

vi.mock("./deviceService", () => ({
  deviceService: {
    getDeviceInfo: mocks.getDeviceInfo,
    initialize: mocks.initialize,
  },
}));

vi.mock("./ipcSessionService", () => ({
  listRemoteCaptureSources: mocks.listRemoteCaptureSources,
  selectRemoteCaptureSource: mocks.selectRemoteCaptureSource,
  requestRemoteSession: mocks.requestRemoteSession,
  startLocalTestSession: mocks.startLocalTestSession,
  stopSession: mocks.stopSession,
}));

vi.mock("./webRemoteSessionService", () => ({
  saveWebRemoteSession: mocks.saveWebRemoteSession,
}));

vi.mock("./remoteSessionStateService", () => ({
  waitForRemoteSessionStreaming: mocks.waitForRemoteSessionStreaming,
}));

describe("launchRemoteDisplayForDevice", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.runtime.isTauri = true;
    mocks.openRemoteDisplayWindow.mockResolvedValue({
      ok: true,
      value: { label: "render-local-display-test-1" },
    });
    mocks.requestRemoteSession.mockResolvedValue({
      session_id: "p2p-quic-session",
      presentation_state: "authenticating",
    });
    mocks.startLocalTestSession.mockResolvedValue("local-display-test-explicit");
    mocks.stopSession.mockResolvedValue("p2p-quic-session");
    mocks.listRemoteCaptureSources.mockResolvedValue([]);
    mocks.selectRemoteCaptureSource.mockResolvedValue({
      session_id: "p2p-quic-session",
      source: {
        id: "windows:window:0x1234",
        platform: "windows",
        source_kind: "window",
        title: "Calculator",
        class_name: "ApplicationFrameWindow",
        width: 800,
        height: 600,
        process_id: 1111,
        app_name: "Calculator",
        bundle_identifier: null,
        preview_data_url: null,
        preview_width: null,
        preview_height: null,
      },
      status: "selected",
      reason: null,
    });
    mocks.getDeviceInfo.mockReturnValue({
      device_id: "local-device",
      device_name: "Local PC",
    });
    mocks.initialize.mockResolvedValue({
      device_id: "local-device",
      device_name: "Local PC",
    });
    mocks.waitForRemoteSessionStreaming.mockImplementation(
      async (sessionId: string) => ({
        session_id: sessionId,
        peer_device_id: sessionId.includes("mac") ? "remote-mac" : "remote-device",
        role: "controller",
        route_kind: "lan_quic",
        presentation_state: "streaming",
      }),
    );
  });

  it("starts a local E2E display flow when the selected target is this device", async () => {
    const result = await launchRemoteDisplayForDevice("local-device", {
      sessionId: "local-display-test-explicit",
      transportKind: "quic",
      lanP2P: true,
    });

    expect(mocks.requestRemoteSession).not.toHaveBeenCalled();
    expect(mocks.startLocalTestSession).toHaveBeenCalledWith(
      "local-display-test-explicit",
      "local-device",
      "quic",
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "local-display-test-explicit",
    });
    expect(result).toEqual({
      sessionId: "local-display-test-explicit",
      windowLabel: "render-local-display-test-1",
      mode: "native_window",
    });
  });

  it("requests the default HEVC 1080p60 QUIC media profile for LAN P2P remote display", async () => {
    const result = await launchRemoteDisplayForDevice("remote-device", {
      sessionId: "p2p-quic-session",
      transportKind: "quic",
      lanP2P: true,
    });

    expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
      "p2p-quic-session",
      "remote-device",
      "quic",
      DEFAULT_HEVC_1080P60_PROFILE,
      "lan",
    );
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
    expect(result).toEqual({
      sessionId: "p2p-quic-session",
      windowLabel: null,
      mode: "route",
      remoteSession: {
        session_id: "p2p-quic-session",
        presentation_state: "authenticating",
      },
    });
    mocks.waitForRemoteSessionStreaming.mockResolvedValue({
      session_id: "p2p-quic-session",
      presentation_state: "streaming",
    });
  });

  it("uses the authenticated Auto request for every non-local device", async () => {
    const result = await launchRemoteDisplayForDevice("remote-device", {
      sessionId: "auto-remote-session",
      transportKind: "webrtc",
    });

    expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
      "auto-remote-session",
      "remote-device",
      "webrtc",
      undefined,
      "auto",
    );
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
    expect(result.mode).toBe("route");
    expect(result.windowLabel).toBeNull();
  });

  it.each([
    ["auto", "auto"],
    ["lan", "lan"],
    ["wan_relay", "wan_relay"],
  ] as const)(
    "forwards the %s route preference through the remote session launcher",
    async (_label, routePreference) => {
      await launchRemoteDisplayForDevice("remote-device", {
        sessionId: "p2p-quic-session",
        transportKind: "quic",
        lanP2P: true,
        routePreference,
      });

      expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
        "p2p-quic-session",
        "remote-device",
        "quic",
        DEFAULT_HEVC_1080P60_PROFILE,
        routePreference,
      );
    },
  );

  it.each([
    ["auto", "webrtc"],
    ["lan", "quic"],
    ["wan_relay", "webrtc"],
  ] as const)(
    "uses the authorized request path for an explicit %s route even without LAN discovery",
    async (routePreference, transportKind) => {
      await launchRemoteDisplayForDevice("remote-device", {
        sessionId: `${routePreference}-session`,
        transportKind,
        routePreference,
      });

      expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
        `${routePreference}-session`,
        "remote-device",
        transportKind,
        undefined,
        routePreference,
      );
    },
  );

  it("requests the macOS VideoToolbox HEVC 2K144 profile for macOS LAN P2P remote display", async () => {
    await launchRemoteDisplayForDevice("remote-mac", {
      sessionId: "p2p-quic-mac-session",
      transportKind: "quic",
      targetOs: "macOS Sonoma",
      lanP2P: true,
    });

    expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
      "p2p-quic-mac-session",
      "remote-mac",
      "quic",
      MACOS_HEVC_2K144_PROFILE,
      "lan",
    );
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
  });

  it("recognizes browser-style MacIntel target labels as macOS LAN P2P devices", async () => {
    await launchRemoteDisplayForDevice("remote-mac", {
      sessionId: "p2p-quic-macintel-session",
      transportKind: "quic",
      targetOs: "MacIntel / quic",
      lanP2P: true,
    });

    expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
      "p2p-quic-macintel-session",
      "remote-mac",
      "quic",
      MACOS_HEVC_2K144_PROFILE,
      "lan",
    );
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
  });

  it("records a remote capture source without opening media before streaming", async () => {
    const result = await launchRemoteDisplayForDevice("remote-device", {
      sessionId: "p2p-quic-session",
      transportKind: "quic",
      lanP2P: true,
      captureSourceId: "windows:window:0x1234",
    });

    expect(mocks.selectRemoteCaptureSource).toHaveBeenCalledWith(
      "p2p-quic-session",
      "windows:window:0x1234"
    );
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
    expect(result.mode).toBe("route");
    expect(result.captureSourceSelection?.source.id).toBe("windows:window:0x1234");
  });

  it("fails closed instead of simulating a peer connection in a browser", async () => {
    mocks.runtime.isTauri = false;

    await expect(
      launchRemoteDisplayForDevice("remote-device", {
        sessionId: "browser-peer-session",
        transportKind: "webrtc",
      }),
    ).rejects.toThrow("Secure remote sessions require the desktop client");

    expect(mocks.saveWebRemoteSession).not.toHaveBeenCalled();
    expect(mocks.requestRemoteSession).not.toHaveBeenCalled();
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
  });

  it("retains the explicit browser-local WebRTC self-test", async () => {
    mocks.runtime.isTauri = false;

    const result = await launchRemoteDisplayForDevice("local-test-device", {
      sessionId: "browser-local-session",
      localTest: true,
    });

    expect(mocks.saveWebRemoteSession).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionId: "browser-local-session",
        mode: "web_to_local",
      }),
    );
    expect(result).toEqual({
      sessionId: "browser-local-session",
      windowLabel: null,
      mode: "route",
    });
  });

  it("loads a LAN remote application catalog from real capture sources", async () => {
    mocks.listRemoteCaptureSources.mockResolvedValue([
      {
        id: "windows:display:0",
        platform: "windows",
        source_kind: "display",
        title: "Display 1",
        class_name: "WinRTMonitor",
        width: 1920,
        height: 1080,
        process_id: 0,
        app_name: "Display",
        bundle_identifier: null,
        preview_data_url: null,
        preview_width: null,
        preview_height: null,
      },
      {
        id: "windows:window:0x1234",
        platform: "windows",
        source_kind: "window",
        title: "Calculator",
        class_name: "ApplicationFrameWindow",
        width: 800,
        height: 600,
        process_id: 1111,
        app_name: "Calculator",
        bundle_identifier: null,
        preview_data_url: null,
        preview_width: null,
        preview_height: null,
      },
    ]);

    const catalog = await prepareRemoteApplicationCatalogForDevice("remote-device", {
      sessionId: "remote-app-session",
      transportKind: "quic",
      lanP2P: true,
      includePreviews: false,
      limit: 48,
    });

    expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
      "remote-app-session",
      "remote-device",
      "quic",
      DEFAULT_HEVC_1080P60_PROFILE,
      "lan",
    );
    expect(mocks.listRemoteCaptureSources).toHaveBeenCalledWith(
      "p2p-quic-session",
      false,
      48
    );
    expect(mocks.waitForRemoteSessionStreaming).toHaveBeenCalledWith(
      "p2p-quic-session",
    );
    expect(
      mocks.waitForRemoteSessionStreaming.mock.invocationCallOrder[0]!,
    ).toBeLessThan(mocks.listRemoteCaptureSources.mock.invocationCallOrder[0]!);
    expect(catalog.sessionId).toBe("p2p-quic-session");
    expect(catalog.windows.map((source) => source.id)).toEqual(["windows:window:0x1234"]);
    expect(catalog.displays.map((source) => source.id)).toEqual(["windows:display:0"]);
  });

  it("uses the macOS VideoToolbox HEVC profile for LAN remote application catalog sessions", async () => {
    mocks.waitForRemoteSessionStreaming.mockResolvedValueOnce({
      session_id: "p2p-quic-session",
      peer_device_id: "remote-mac",
      role: "controller",
      route_kind: "lan_quic",
      presentation_state: "streaming",
    });
    const catalog = await prepareRemoteApplicationCatalogForDevice("remote-mac", {
      sessionId: "remote-mac-app-session",
      transportKind: "quic",
      targetOs: "Darwin 23",
      lanP2P: true,
      includePreviews: true,
      limit: 12,
    });

    expect(mocks.requestRemoteSession).toHaveBeenCalledWith(
      "remote-mac-app-session",
      "remote-mac",
      "quic",
      MACOS_HEVC_2K144_PROFILE,
      "lan",
    );
    expect(mocks.listRemoteCaptureSources).toHaveBeenCalledWith(
      "p2p-quic-session",
      true,
      12
    );
    expect(catalog.sessionId).toBe("p2p-quic-session");
  });

  it("opens a selected remote application using an existing application session", async () => {
    const result = await launchRemoteApplicationForDevice(
      "remote-device",
      "windows:window:0x1234",
      {
        sessionId: "remote-app-session",
        sessionAlreadyStarted: true,
        transportKind: "quic",
        lanP2P: true,
      }
    );

    expect(mocks.requestRemoteSession).not.toHaveBeenCalled();
    expect(mocks.selectRemoteCaptureSource).toHaveBeenCalledWith(
      "remote-app-session",
      "windows:window:0x1234"
    );
    expect(mocks.waitForRemoteSessionStreaming).toHaveBeenCalledWith(
      "remote-app-session",
    );
    expect(
      mocks.waitForRemoteSessionStreaming.mock.invocationCallOrder[0]!,
    ).toBeLessThan(mocks.selectRemoteCaptureSource.mock.invocationCallOrder[0]!);
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "remote-app-session",
      captureSourceId: "windows:window:0x1234",
      requestedProfile: DEFAULT_HEVC_1080P60_PROFILE,
    });
    expect(result.sessionId).toBe("remote-app-session");
  });

  it("keeps the macOS VideoToolbox profile when opening an app from an existing catalog session", async () => {
    const result = await launchRemoteApplicationForDevice(
      "remote-mac",
      "macos:window:0x1234",
      {
        sessionId: "remote-mac-app-session",
        sessionAlreadyStarted: true,
        transportKind: "quic",
        targetOs: "macOS Sonoma",
        lanP2P: true,
      }
    );

    expect(mocks.requestRemoteSession).not.toHaveBeenCalled();
    expect(mocks.selectRemoteCaptureSource).toHaveBeenCalledWith(
      "remote-mac-app-session",
      "macos:window:0x1234"
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "remote-mac-app-session",
      captureSourceId: "windows:window:0x1234",
      requestedProfile: MACOS_HEVC_2K144_PROFILE,
    });
    expect(result.sessionId).toBe("remote-mac-app-session");
  });

  it("rejects an existing application session bound to another peer", async () => {
    mocks.waitForRemoteSessionStreaming.mockResolvedValueOnce({
      session_id: "remote-app-session",
      peer_device_id: "different-peer",
      role: "controller",
      route_kind: "lan_quic",
      presentation_state: "streaming",
    });

    await expect(
      launchRemoteApplicationForDevice(
        "remote-device",
        "windows:window:0x1234",
        {
          sessionId: "remote-app-session",
          sessionAlreadyStarted: true,
          transportKind: "quic",
          lanP2P: true,
        },
      ),
    ).rejects.toThrow(
      "Remote application session is not bound to the requested LAN peer",
    );
    expect(mocks.selectRemoteCaptureSource).not.toHaveBeenCalled();
    expect(mocks.openRemoteDisplayWindow).not.toHaveBeenCalled();
  });
});
