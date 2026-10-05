import { describe, expect, it } from "vitest";

import { approveAndRunAgentAction, canApproveAgentAction, requireExecutedAgentAction } from "./agent-action-workflow";

describe("agent action approval workflow", () => {
  it("uses remediation permission for canonical triage", () => {
    expect(canApproveAgentAction("update_canonical_work", (permission) => permission === "finding:remediate")).toBe(true);
    expect(canApproveAgentAction("update_canonical_work", (permission) => permission === "integration:manage")).toBe(false);
  });
  it("runs only after the exact action was approved", async () => {
    const calls: string[] = [];
    await approveAndRunAgentAction("action-1", {
      resolveAction: async (id, approve) => { calls.push(`approve:${id}:${approve}`); },
      executeAction: async (id) => { calls.push(`execute:${id}`); return { status: "executed", result_summary: "2 alerts synced" }; },
    });
    expect(calls).toEqual(["approve:action-1:true", "execute:action-1"]);
  });

  it("never executes when approval fails", async () => {
    let executed = false;
    await expect(approveAndRunAgentAction("action-2", {
      resolveAction: async () => { throw new Error("approval denied"); },
      executeAction: async () => { executed = true; return { status: "executed", result_summary: null }; },
    })).rejects.toThrow("approval denied");
    expect(executed).toBe(false);
  });

  it("shows a persisted provider failure instead of reporting completion", async () => {
    await expect(approveAndRunAgentAction("action-3", {
      resolveAction: async () => undefined,
      executeAction: async () => ({ status: "failed", result_summary: "GitHub unavailable" }),
    })).rejects.toThrow("GitHub unavailable");
    expect(() => requireExecutedAgentAction({ status: "failed", result_summary: "Jira unavailable" }))
      .toThrow("Jira unavailable");
  });
});
