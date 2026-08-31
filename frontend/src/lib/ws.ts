"use client";

/**
 * Agent event stream — a React hook over the outbound-only WS `/ws/agent/{session_id}`.
 *
 * Protocol (server-confirmed): the socket is accepted immediately, then the FIRST text frame
 * must be `{"type":"auth","token":"<jwt>"}` (within ~10s) — the token never rides the query
 * string. `?after_seq=<n>` asks the server to replay everything after seq `n`, which is exactly
 * what we resume from on reconnect, so no events are lost across a drop. The socket carries no
 * client turns; posting a message is `POST /agent/messages` (see api.ts). Keepalive is a
 * `{"type":"ping"}` frame answered by a `pong` event.
 *
 * Close-code policy: 4401 (stale token) → refresh once, then reconnect; 4403/4404
 * (forbidden / not-found / cross-tenant) → give up, surface the error; anything else →
 * reconnect with capped exponential backoff, resuming from the last seq seen.
 */

import * as React from "react";

import { agentSocketUrl, api } from "./api";
import { getAccessToken, getRefreshToken } from "./tokens";
import type { AgentEventType, TypedAgentEvent } from "./types";

export type StreamState = "idle" | "connecting" | "open" | "reconnecting" | "closed" | "error";

interface UseAgentStreamOptions {
  /** Session to stream. `null` keeps the hook idle (no socket). */
  sessionId: string | null;
  /** Master switch; default true. */
  enabled?: boolean;
  /** Initial resume cursor; default 0 = full backlog. */
  afterSeq?: number;
  /** Called for every decoded event, in arrival order (including `pong`). */
  onEvent?: (event: TypedAgentEvent) => void;
}

interface UseAgentStreamResult {
  state: StreamState;
  /** Highest event seq observed — the live resume cursor. */
  lastSeq: number;
  /** User-safe message when `state === "error"`, else null. */
  error: string | null;
  /** Force a fresh connection now (resets backoff). */
  reconnect: () => void;
}

const PING_INTERVAL_MS = 25_000;
const MAX_BACKOFF_MS = 30_000;

const EVENT_TYPES: ReadonlySet<string> = new Set<AgentEventType>([
  "agent_thinking",
  "agent_plan_step",
  "agent_tool_call",
  "agent_approval_required",
  "agent_findings_update",
  "agent_error",
  "agent_complete",
  "agent_message",
  "agent_progress",
  "pong",
]);

function isAgentEvent(value: unknown): value is TypedAgentEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { type?: unknown }).type === "string" &&
    EVENT_TYPES.has((value as { type: string }).type)
  );
}

export function useAgentStream(options: UseAgentStreamOptions): UseAgentStreamResult {
  const { sessionId, enabled = true, afterSeq = 0 } = options;

  const [state, setState] = React.useState<StreamState>("idle");
  const [error, setError] = React.useState<string | null>(null);
  const [lastSeq, setLastSeq] = React.useState(afterSeq);

  // Mutable connection internals kept out of render.
  const onEventRef = React.useRef(options.onEvent);
  onEventRef.current = options.onEvent;

  const socketRef = React.useRef<WebSocket | null>(null);
  const pingRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const reconnectRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const attemptRef = React.useRef(0);
  const lastSeqRef = React.useRef(afterSeq);
  const stoppedRef = React.useRef(false);
  const connectRef = React.useRef<() => void>(() => {});

  const clearTimers = React.useCallback(() => {
    if (pingRef.current) {
      clearInterval(pingRef.current);
      pingRef.current = null;
    }
    if (reconnectRef.current) {
      clearTimeout(reconnectRef.current);
      reconnectRef.current = null;
    }
  }, []);

  const teardownSocket = React.useCallback(() => {
    const socket = socketRef.current;
    socketRef.current = null;
    if (socket) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close();
      }
    }
  }, []);

  const scheduleReconnect = React.useCallback(() => {
    if (stoppedRef.current) return;
    const attempt = attemptRef.current++;
    const backoff = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** attempt);
    const delay = backoff / 2 + Math.random() * (backoff / 2);
    setState("reconnecting");
    reconnectRef.current = setTimeout(() => connectRef.current(), delay);
  }, []);

  const connect = React.useCallback(() => {
    if (stoppedRef.current || !sessionId) return;

    const token = getAccessToken();
    if (!token) {
      setError("Your session has expired. Please sign in again.");
      setState("error");
      return;
    }

    clearTimers();
    teardownSocket();
    setState((prev) => (prev === "reconnecting" ? prev : "connecting"));

    let socket: WebSocket;
    try {
      socket = new WebSocket(agentSocketUrl(sessionId, lastSeqRef.current));
    } catch {
      scheduleReconnect();
      return;
    }
    socketRef.current = socket;

    socket.onopen = () => {
      if (socketRef.current !== socket) return;
      attemptRef.current = 0;
      setState("open");
      setError(null);
      socket.send(JSON.stringify({ type: "auth", token: getAccessToken() }));
      pingRef.current = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: "ping" }));
        }
      }, PING_INTERVAL_MS);
    };

    socket.onmessage = (message) => {
      if (socketRef.current !== socket) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(typeof message.data === "string" ? message.data : "");
      } catch {
        return; // malformed frame — ignore, per protocol
      }
      if (!isAgentEvent(parsed)) return;
      if (typeof parsed.seq === "number" && parsed.seq > lastSeqRef.current) {
        lastSeqRef.current = parsed.seq;
        setLastSeq(parsed.seq);
      }
      onEventRef.current?.(parsed);
    };

    socket.onerror = () => {
      // The paired onclose drives reconnect/backoff; nothing to do here.
    };

    socket.onclose = (event) => {
      if (socketRef.current !== socket) return;
      socketRef.current = null;
      clearTimers();
      if (stoppedRef.current) return;

      if (event.code === 4403 || event.code === 4404) {
        setError(
          event.code === 4403
            ? "You do not have access to this agent session."
            : "This agent session could not be found.",
        );
        setState("error");
        return;
      }

      if (event.code === 4401) {
        // Stale access token: piggyback on the api refresh path, then reconnect once refreshed.
        if (!getRefreshToken()) {
          setError("Your session has expired. Please sign in again.");
          setState("error");
          return;
        }
        setState("reconnecting");
        void api.auth
          .me()
          .then(() => {
            if (!stoppedRef.current) {
              attemptRef.current = 0;
              connectRef.current();
            }
          })
          .catch(() => {
            if (!stoppedRef.current) {
              setError("Your session has expired. Please sign in again.");
              setState("error");
            }
          });
        return;
      }

      scheduleReconnect();
    };
  }, [sessionId, clearTimers, teardownSocket, scheduleReconnect]);

  connectRef.current = connect;

  const reconnect = React.useCallback(() => {
    attemptRef.current = 0;
    stoppedRef.current = false;
    connectRef.current();
  }, []);

  React.useEffect(() => {
    if (!enabled || !sessionId) {
      setState("idle");
      return;
    }
    stoppedRef.current = false;
    lastSeqRef.current = afterSeq;
    setLastSeq(afterSeq);
    attemptRef.current = 0;
    connect();

    return () => {
      stoppedRef.current = true;
      clearTimers();
      teardownSocket();
    };
    // `afterSeq` is only the *initial* cursor; live progress is tracked in lastSeqRef, so it is
    // intentionally excluded to avoid reconnecting on every parent re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, sessionId, connect, clearTimers, teardownSocket]);

  return { state, lastSeq, error, reconnect };
}
