import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  RemoteSessionSnapshot,
  SessionEventSubscription,
} from "../adapters/tauri/types";

const ipc = vi.hoisted(() => ({
  getRemoteSession: vi.fn(),
  subscribeSessionEvents: vi.fn(),
}));

vi.mock("./ipcSessionService", () => ({
  getRemoteSession: ipc.getRemoteSession,
  subscribeSessionEvents: ipc.subscribeSessionEvents,
}));

import {
  observeRemoteSession,
  waitForRemoteSessionStreaming,
} from "./remoteSessionStateService";

function snapshot(
  presentationState: RemoteSessionSnapshot["presentation_state"],
): RemoteSessionSnapshot {
  return {
    session_id: "secure-session",
    role: "controller",
    peer_device_id: "remote-device",
    peer_key_id: "remote-key",
    access_mode: "attended",
    authorization_state:
      presentationState === "streaming" ? "granted" : "authenticating",
    route_state: presentationState === "streaming" ? "connected" : "connecting",
    route_kind: presentationState === "streaming" ? "webrtc_relay" : null,
    media_state: presentationState === "streaming" ? "streaming" : "idle",
    presentation_state: presentationState,
    requested_scopes: ["screen.view"],
    granted_scopes: presentationState === "streaming" ? ["screen.view"] : [],
    policy_revision: "1",
    failure: null,
    created_at_ms: 1,
    updated_at_ms: 2,
    authorization_expires_at_ms: 60_000,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

describe("observeRemoteSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("publishes the authoritative snapshot and refreshes it after typed events", async () => {
    const eventPage = deferred<SessionEventSubscription>();
    ipc.getRemoteSession
      .mockResolvedValueOnce(snapshot("authenticating"))
      .mockResolvedValueOnce(snapshot("streaming"));
    ipc.subscribeSessionEvents.mockReturnValueOnce(eventPage.promise);
    const onSnapshot = vi.fn();

    const stop = observeRemoteSession("secure-session", { onSnapshot });

    await vi.waitFor(() => {
      expect(onSnapshot).toHaveBeenLastCalledWith(snapshot("authenticating"));
    });
    expect(ipc.subscribeSessionEvents).toHaveBeenCalledWith({
      session_id: "secure-session",
      after_sequence: null,
      limit: 64,
      wait_timeout_ms: 15_000,
    });

    eventPage.resolve({
      events: [
        {
          sequence: "4",
          timestamp_ms: 3,
          session_id: "secure-session",
          event: { kind: "media_changed", state: "streaming", failure: null },
        },
      ],
      pending_sessions: [],
      next_after_sequence: "4",
      cursor_state: "current",
      has_more: false,
      poll_after_ms: 10_000,
    });

    await vi.waitFor(() => {
      expect(onSnapshot).toHaveBeenLastCalledWith(snapshot("streaming"));
    });
    stop();
  });

  it("reports exact service failures without manufacturing a connected state", async () => {
    const error = new Error("authorization denied by target");
    ipc.getRemoteSession.mockRejectedValueOnce(error);
    ipc.subscribeSessionEvents.mockReturnValue(new Promise(() => undefined));
    const onError = vi.fn();

    const stop = observeRemoteSession("secure-session", {
      onSnapshot: vi.fn(),
      onError,
    });

    await vi.waitFor(() => expect(onError).toHaveBeenCalledWith(error));
    stop();
  });

  it("rejects a cross-session snapshot instead of publishing it", async () => {
    ipc.getRemoteSession.mockResolvedValueOnce({
      ...snapshot("streaming"),
      session_id: "other-session",
    });
    const onSnapshot = vi.fn();
    const onError = vi.fn();

    const stop = observeRemoteSession("secure-session", {
      onSnapshot,
      onError,
    });

    await vi.waitFor(() => {
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          message: "remote session snapshot binding mismatch",
        }),
      );
    });
    expect(onSnapshot).not.toHaveBeenCalled();
    stop();
  });

  it("resolves media launch only from an authoritative streaming snapshot", async () => {
    ipc.getRemoteSession.mockResolvedValueOnce(snapshot("streaming"));
    ipc.subscribeSessionEvents.mockReturnValue(new Promise(() => undefined));

    await expect(
      waitForRemoteSessionStreaming("secure-session", 1_000),
    ).resolves.toEqual(snapshot("streaming"));
  });

  it("rejects a terminal snapshot with the exact service failure", async () => {
    const failed = snapshot("failed");
    failed.failure = {
      code: "consent_denied",
      message: "Target denied attended access",
      suggested_action: null,
    };
    ipc.getRemoteSession.mockResolvedValueOnce(failed);
    ipc.subscribeSessionEvents.mockReturnValue(new Promise(() => undefined));

    await expect(
      waitForRemoteSessionStreaming("secure-session", 1_000),
    ).rejects.toThrow("Target denied attended access");
  });
});
