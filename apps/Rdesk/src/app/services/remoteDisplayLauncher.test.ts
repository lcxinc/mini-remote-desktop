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
  startLanRemoteSession: vi.fn(),
  startSession: vi.fn(),
  stopSession: vi.fn(),
  saveWebRemoteSession: vi.fn(),
  getDeviceInfo: vi.fn(),
  initialize: vi.fn(),
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
  isTauriRuntime: () => true,
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
  startLanRemoteSession: mocks.startLanRemoteSession,
  startSession: mocks.startSession,
  stopSession: mocks.stopSession,
}));

vi.mock("./webRemoteSessionService", () => ({
  saveWebRemoteSession: mocks.saveWebRemoteSession,
}));

describe("launchRemoteDisplayForDevice", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.openRemoteDisplayWindow.mockResolvedValue({
      ok: true,
      value: { label: "render-local-display-test-1" },
    });
    mocks.startLanRemoteSession.mockResolvedValue("p2p-quic-session");
    mocks.startSession.mockResolvedValue("service-session");
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
  });

  it("starts a local E2E display flow when the selected target is this device", async () => {
    const result = await launchRemoteDisplayForDevice("local-device", {
      sessionId: "local-display-test-explicit",
      transportKind: "quic",
      lanP2P: true,
    });

    expect(mocks.startSession).not.toHaveBeenCalled();
    expect(mocks.startLanRemoteSession).not.toHaveBeenCalled();
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
    await launchRemoteDisplayForDevice("remote-device", {
      sessionId: "p2p-quic-session",
      transportKind: "quic",
      lanP2P: true,
    });

    expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
      "p2p-quic-session",
      "remote-device",
      "quic",
      DEFAULT_HEVC_1080P60_PROFILE
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "p2p-quic-session",
      requestedProfile: DEFAULT_HEVC_1080P60_PROFILE,
    });
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

      expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
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

      expect(mocks.startSession).not.toHaveBeenCalled();
      expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
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

    expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
      "p2p-quic-mac-session",
      "remote-mac",
      "quic",
      MACOS_HEVC_2K144_PROFILE
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "p2p-quic-session",
      requestedProfile: MACOS_HEVC_2K144_PROFILE,
    });
  });

  it("recognizes browser-style MacIntel target labels as macOS LAN P2P devices", async () => {
    await launchRemoteDisplayForDevice("remote-mac", {
      sessionId: "p2p-quic-macintel-session",
      transportKind: "quic",
      targetOs: "MacIntel / quic",
      lanP2P: true,
    });

    expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
      "p2p-quic-macintel-session",
      "remote-mac",
      "quic",
      MACOS_HEVC_2K144_PROFILE
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "p2p-quic-session",
      requestedProfile: MACOS_HEVC_2K144_PROFILE,
    });
  });

  it("selects a remote capture source before opening the display window", async () => {
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
    expect(mocks.selectRemoteCaptureSource.mock.invocationCallOrder[0]!).toBeLessThan(
      mocks.openRemoteDisplayWindow.mock.invocationCallOrder[0]!
    );
    expect(result.captureSourceSelection?.source.id).toBe("windows:window:0x1234");
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

    expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
      "remote-app-session",
      "remote-device",
      "quic",
      DEFAULT_HEVC_1080P60_PROFILE
    );
    expect(mocks.listRemoteCaptureSources).toHaveBeenCalledWith(
      "p2p-quic-session",
      false,
      48
    );
    expect(catalog.sessionId).toBe("p2p-quic-session");
    expect(catalog.windows.map((source) => source.id)).toEqual(["windows:window:0x1234"]);
    expect(catalog.displays.map((source) => source.id)).toEqual(["windows:display:0"]);
  });

  it("uses the macOS VideoToolbox HEVC profile for LAN remote application catalog sessions", async () => {
    const catalog = await prepareRemoteApplicationCatalogForDevice("remote-mac", {
      sessionId: "remote-mac-app-session",
      transportKind: "quic",
      targetOs: "Darwin 23",
      lanP2P: true,
      includePreviews: true,
      limit: 12,
    });

    expect(mocks.startLanRemoteSession).toHaveBeenCalledWith(
      "remote-mac-app-session",
      "remote-mac",
      "quic",
      MACOS_HEVC_2K144_PROFILE
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

    expect(mocks.startLanRemoteSession).not.toHaveBeenCalled();
    expect(mocks.selectRemoteCaptureSource).toHaveBeenCalledWith(
      "remote-app-session",
      "windows:window:0x1234"
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "remote-app-session",
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

    expect(mocks.startLanRemoteSession).not.toHaveBeenCalled();
    expect(mocks.selectRemoteCaptureSource).toHaveBeenCalledWith(
      "remote-mac-app-session",
      "macos:window:0x1234"
    );
    expect(mocks.openRemoteDisplayWindow).toHaveBeenCalledWith({
      sessionId: "remote-mac-app-session",
      requestedProfile: MACOS_HEVC_2K144_PROFILE,
    });
    expect(result.sessionId).toBe("remote-mac-app-session");
  });
});
