import { beforeEach, describe, expect, it, vi } from "vitest";

const adapter = vi.hoisted(() => ({
  requestRemoteSession: vi.fn(),
}));

vi.mock("../adapters/tauri", () => ({
  ipcRequestRemoteSession: adapter.requestRemoteSession,
}));

import { startLanRemoteSession } from "./ipcSessionService";

describe("startLanRemoteSession", () => {
  beforeEach(() => {
    adapter.requestRemoteSession.mockReset();
    adapter.requestRemoteSession.mockResolvedValue({
      ok: true,
      value: { session_id: "session-1" },
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

    await startLanRemoteSession("session-1", "target-1", "quic", profile);

    expect(adapter.requestRemoteSession).toHaveBeenCalledWith({
      session_id: "session-1",
      target_device_id: "target-1",
      access_mode: "attended",
      route_preference: "auto",
      requested_scopes: ["screen.view", "input.pointer", "input.keyboard"],
      requested_profile: profile,
    });
  });
});
