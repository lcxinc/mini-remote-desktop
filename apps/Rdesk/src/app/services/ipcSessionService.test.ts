import { beforeEach, describe, expect, it, vi } from "vitest";

const adapter = vi.hoisted(() => ({
  requestRemoteSession: vi.fn(),
  startSession: vi.fn(),
}));

vi.mock("../adapters/tauri", () => ({
  ipcRequestRemoteSession: adapter.requestRemoteSession,
  ipcStartSession: adapter.startSession,
}));

import {
  requestRemoteSession,
  startLocalTestSession,
} from "./ipcSessionService";

describe("startLocalTestSession", () => {
  it("uses the legacy contract only for the explicitly named local test path", async () => {
    adapter.startSession.mockResolvedValueOnce({
      ok: true,
      value: "local-test-session",
    });

    await expect(
      startLocalTestSession(
        "local-test-session",
        "local-device",
        "webrtc",
      ),
    ).resolves.toBe("local-test-session");
    expect(adapter.startSession).toHaveBeenCalledWith(
      "local-test-session",
      "local-device",
      "webrtc",
    );
  });
});

describe("requestRemoteSession", () => {
  beforeEach(() => {
    adapter.requestRemoteSession.mockReset();
    adapter.requestRemoteSession.mockResolvedValue({
      ok: true,
      value: {
        session_id: "session-1",
        peer_device_id: "target-1",
        role: "controller",
      },
    });
  });

  it("requests screen viewing and scoped authenticated input for attended control", async () => {
    const profile = {
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
    } as const;

    const snapshot = await requestRemoteSession(
      "session-1",
      "target-1",
      "quic",
      profile,
    );

    expect(adapter.requestRemoteSession).toHaveBeenCalledWith({
      session_id: "session-1",
      target_device_id: "target-1",
      access_mode: "attended",
      route_preference: "auto",
      requested_scopes: ["screen.view", "input.pointer", "input.keyboard"],
      requested_profile: profile,
    });
    expect(snapshot).toEqual({
      session_id: "session-1",
      peer_device_id: "target-1",
      role: "controller",
    });
  });

  it("forwards only the selected route preference enum", async () => {
    await requestRemoteSession(
      "session-1",
      "target-1",
      "quic",
      undefined,
      "wan_relay",
    );

    expect(adapter.requestRemoteSession).toHaveBeenCalledWith({
      session_id: "session-1",
      target_device_id: "target-1",
      access_mode: "attended",
      route_preference: "wan_relay",
      requested_scopes: ["screen.view", "input.pointer", "input.keyboard"],
      requested_profile: null,
    });
  });

  it("allows an explicitly selected WAN relay route without LAN QUIC", async () => {
    await requestRemoteSession(
      "session-1",
      "target-1",
      "webrtc",
      undefined,
      "wan_relay",
    );

    expect(adapter.requestRemoteSession).toHaveBeenCalledWith({
      session_id: "session-1",
      target_device_id: "target-1",
      access_mode: "attended",
      route_preference: "wan_relay",
      requested_scopes: ["screen.view", "input.pointer", "input.keyboard"],
      requested_profile: null,
    });
  });

  it("rejects a response that is not bound to the requested session and peer", async () => {
    adapter.requestRemoteSession.mockResolvedValueOnce({
      ok: true,
      value: {
        session_id: "other-session",
        peer_device_id: "other-target",
        role: "controller",
      },
    });

    await expect(
      requestRemoteSession("session-1", "target-1", "webrtc"),
    ).rejects.toMatchObject({ code: "E_REMOTE_SESSION_BINDING" });
  });
});
