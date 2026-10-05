import type { AgentEventType } from "./types";
import type { StreamState } from "./ws";

export function shouldReplayAgentEvents(state: StreamState): boolean {
  return state !== "open";
}

export function shouldResetAgentActivity(eventType: AgentEventType): boolean {
  return eventType === "agent_error" || eventType === "agent_complete";
}
