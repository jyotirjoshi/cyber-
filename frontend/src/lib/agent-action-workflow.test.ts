import { describe, expect, it } from "vitest";

import { actionPrerequisiteReady, agentActionSuccessTitle, assessmentWorkSummary, approveAndRunAgentAction, canApproveAgentAction, requireExecutedAgentAction, settledActionSignature } from "./agent-action-workflow";

describe("agent action approval workflow", () => {
  it("keeps a dependent ticket queued until its exact triage action executes", () => {
    const ticket = { depends_on_action_id: "triage-1" };
    expect(actionPrerequisiteReady(ticket, [{ id: "triage-1", status: "approved" }])).toBe(false);
    expect(actionPrerequisiteReady(ticket, [{ id: "other", status: "executed" }])).toBe(false);
    expect(actionPrerequisiteReady(ticket, [{ id: "triage-1", status: "executed" }])).toBe(true);
  });
  it("detects background action and worker-run status changes for transcript refresh", () => {
    expect(settledActionSignature([{ id: "a", status: "approved", run_status: null }])).toBe("");
    expect(settledActionSignature([{ id: "a", status: "executed", run_status: "queued" }])).toBe("a:executed:queued");
    expect(settledActionSignature([{ id: "a", status: "executed", run_status: "completed" }]))
      .not.toBe(settledActionSignature([{ id: "a", status: "executed", run_status: "queued" }]));
  });
  it("does not claim that a queued assessment is completed", () => {
    expect(agentActionSuccessTitle("start_assessment", "approve")).toContain("queued");
    expect(agentActionSuccessTitle("sync_github_alerts", "approve")).toBe("Action completed");
    expect(agentActionSuccessTitle("start_assessment", "reject")).toBe("Action rejected");
  });
  it("summarizes a real assessment result and coverage gaps", () => {
    expect(assessmentWorkSummary({
      run_status: "completed",
      assessment: {
        id: "assessment-1", status: "COMPLETED", current_stage: "completed",
        progress_percent: 100, findings_total: 5, findings_critical: 1,
        findings_high: 2, assets_discovered: 3, coverage_gap_count: 1,
        failure_reason: "",
      },
    })).toContain("5 findings");
    expect(assessmentWorkSummary({ run_status: "running", assessment: null })).toBe("Running");
  });
  it("uses remediation permission for canonical triage", () => {
    expect(canApproveAgentAction("update_canonical_work", (permission) => permission === "finding:remediate")).toBe(true);
    expect(canApproveAgentAction("update_canonical_work", (permission) => permission === "integration:manage")).toBe(false);
  });
  it("requires assessment creation permission before approving a scan", () => {
    expect(canApproveAgentAction("start_assessment", (permission) => permission === "assessment:create")).toBe(true);
    expect(canApproveAgentAction("start_assessment", (permission) => permission === "integration:manage")).toBe(false);
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

  it("refreshes the conversation after execution settles, including failure", async () => {
    const calls: string[] = [];
    await expect(approveAndRunAgentAction("action-4", {
      resolveAction: async () => { calls.push("approved"); },
      executeAction: async () => {
        calls.push("executed");
        return { status: "failed", result_summary: "GitHub unavailable" };
      },
    }, async () => { calls.push("refreshed"); })).rejects.toThrow("GitHub unavailable");
    expect(calls).toEqual(["approved", "executed", "refreshed"]);
  });

  it("does not misreport a completed action when a transcript refresh fails", async () => {
    await expect(approveAndRunAgentAction("action-5", {
      resolveAction: async () => undefined,
      executeAction: async () => ({ status: "executed", result_summary: "2 alerts synced" }),
    }, async () => { throw new Error("refresh unavailable"); })).resolves.toBeUndefined();
  });
});
