import { describe, expect, it } from "vitest";

import { shouldReplayAgentEvents, shouldResetAgentActivity } from "./agent-event-recovery";

describe("agent event recovery", () => {
  it("replays durable events when the socket failed instead of leaving the worker spinning", () => {
    expect(shouldReplayAgentEvents("error")).toBe(true);
    expect(shouldReplayAgentEvents("reconnecting")).toBe(true);
    expect(shouldReplayAgentEvents("open")).toBe(false);
  });

  it("resets transient activity after a terminal failure or completion", () => {
    expect(shouldResetAgentActivity("agent_error")).toBe(true);
    expect(shouldResetAgentActivity("agent_complete")).toBe(true);
    expect(shouldResetAgentActivity("agent_thinking")).toBe(false);
  });
});
