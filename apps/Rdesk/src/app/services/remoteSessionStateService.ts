import type { RemoteSessionSnapshot } from "../adapters/tauri/types";
import {
  getRemoteSession,
  subscribeSessionEvents,
} from "./ipcSessionService";

const EVENT_PAGE_SIZE = 64;
const EVENT_WAIT_TIMEOUT_MS = 15_000;
const RETRY_AFTER_ERROR_MS = 250;

export type RemoteSessionObserver = {
  onSnapshot: (snapshot: RemoteSessionSnapshot) => void;
  onError?: (error: unknown) => void;
};

/**
 * Observe one secure remote session using the service-global typed event
 * cursor. Every event page is resolved back to an authoritative snapshot;
 * callers never infer "connected" from request acknowledgement alone.
 */
export function observeRemoteSession(
  sessionId: string,
  observer: RemoteSessionObserver,
): () => void {
  let stopped = false;
  let initialized = false;
  let cursor: string | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const schedule = (delayMs: number) => {
    if (stopped) return;
    timer = setTimeout(() => {
      void poll();
    }, Math.max(0, delayMs));
  };

  const refresh = async () => {
    const snapshot = await getRemoteSession(sessionId);
    if (snapshot.session_id !== sessionId) {
      throw new Error("remote session snapshot binding mismatch");
    }
    if (!stopped) observer.onSnapshot(snapshot);
  };

  const poll = async (): Promise<void> => {
    try {
      if (!initialized) {
        await refresh();
        if (stopped) return;
        initialized = true;
      }

      const page = await subscribeSessionEvents({
        session_id: sessionId,
        after_sequence: cursor,
        limit: EVENT_PAGE_SIZE,
        wait_timeout_ms: EVENT_WAIT_TIMEOUT_MS,
      });
      if (stopped) return;

      const hasAuthoritativeUpdate =
        page.cursor_state === "reset_required" ||
        page.events.length > 0 ||
        page.pending_sessions.some(
          (snapshot) => snapshot.session_id === sessionId,
        );
      if (hasAuthoritativeUpdate) {
        await refresh();
        if (stopped) return;
      }

      cursor = page.next_after_sequence ?? cursor;
      schedule(page.has_more ? 0 : page.poll_after_ms);
    } catch (error) {
      if (stopped) return;
      // Re-read the authoritative projection before retrying the event stream
      // so a temporary subscription failure cannot leave a stale connected
      // snapshot on screen indefinitely.
      initialized = false;
      observer.onError?.(error);
      schedule(RETRY_AFTER_ERROR_MS);
    }
  };

  void poll();

  return () => {
    stopped = true;
    if (timer !== undefined) clearTimeout(timer);
  };
}

/**
 * Fence media/window creation on the authoritative presentation state.
 */
export function waitForRemoteSessionStreaming(
  sessionId: string,
  timeoutMs = 30_000,
): Promise<RemoteSessionSnapshot> {
  return new Promise((resolve, reject) => {
    let stopped = false;
    let lastError: unknown;
    let stopObserving: () => void = () => undefined;

    const finish = (
      result:
        | { kind: "resolve"; snapshot: RemoteSessionSnapshot }
        | { kind: "reject"; error: Error },
    ) => {
      if (stopped) return;
      stopped = true;
      clearTimeout(timeout);
      stopObserving();
      if (result.kind === "resolve") resolve(result.snapshot);
      else reject(result.error);
    };

    const timeout = setTimeout(() => {
      finish({
        kind: "reject",
        error:
          lastError instanceof Error
            ? lastError
            : new Error("remote session did not reach streaming before timeout"),
      });
    }, Math.max(1, timeoutMs));

    stopObserving = observeRemoteSession(sessionId, {
      onSnapshot: (snapshot) => {
        if (snapshot.presentation_state === "streaming") {
          finish({ kind: "resolve", snapshot });
          return;
        }
        if (
          snapshot.presentation_state === "denied" ||
          snapshot.presentation_state === "failed" ||
          snapshot.presentation_state === "closed"
        ) {
          finish({
            kind: "reject",
            error: new Error(
              snapshot.failure?.message ??
                `remote session entered ${snapshot.presentation_state}`,
            ),
          });
        }
      },
      onError: (error) => {
        lastError = error;
      },
    });
  });
}
