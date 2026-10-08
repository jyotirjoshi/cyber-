/** One approval click runs the exact approved action and reports its durable outcome. */
import type { AgentActionName, AgentActionOut, Permission } from "./types";

type ActionExecutionResult = { status: string; result_summary?: string | null };

/** A stable marker for work that has settled (including a later scan-run transition). */
export function settledActionSignature(
  actions: ReadonlyArray<Pick<AgentActionOut, "id" | "status" | "run_status">>,
): string {
  return actions
    .filter((action) => action.status === "executed" || action.status === "failed")
    .map((action) => `${action.id}:${action.status}:${action.run_status ?? ""}`)
    .sort()
    .join("|");
}

export function agentActionSuccessTitle(
  action: AgentActionName, decision: "approve" | "reject" | "execute",
): string {
  if (decision === "reject") return "Action rejected";
  if (action === "start_assessment") return "Assessment queued — track worker progress below";
  return "Action completed";
}

export function assessmentWorkSummary(
  item: Pick<AgentActionOut, "run_status" | "assessment">,
): string {
  const run = item.run_status;
  const assessment = item.assessment;
  if (run === "queued") return "Queued for the worker";
  if (run === "interrupted") return "Paused for scan approval";
  if (run === "running") {
    if (!assessment) return "Running";
    return `Running · ${assessment.progress_percent}% · ${assessment.current_stage.replaceAll("_", " ")}`;
  }
  if (run === "failed") return `Failed${assessment?.failure_reason ? ` · ${assessment.failure_reason}` : ""}`;
  if (run === "cancelled") return "Cancelled";
  if (run === "completed" && assessment?.status === "COMPLETED") {
    const gaps = assessment.coverage_gap_count;
    return `Completed · ${assessment.findings_total} findings (${assessment.findings_critical} critical, ${assessment.findings_high} high) · ${assessment.assets_discovered} assets${gaps ? ` · ${gaps} coverage gap${gaps === 1 ? "" : "s"}` : ""}`;
  }
  if (run === "completed") return "Worker completed; assessment results are unavailable";
  return "Assessment queued; worker status unavailable";
}

export function requireExecutedAgentAction(result: ActionExecutionResult): void {
  if (result.status !== "executed") {
    throw new Error(result.result_summary || "The action did not complete. Check its recorded status.");
  }
}

export function canApproveAgentAction(
  action: AgentActionName,
  can: (permission: Permission) => boolean,
): boolean {
  if (action === "create_jira_ticket") return can("ticket:create");
  if (action === "update_canonical_work") return can("finding:remediate");
  if (action === "start_assessment") return can("assessment:create");
  if (action === "update_github_alert") return can("integration:manage") && can("finding:validate");
  return can("integration:manage");
}

export function actionPrerequisiteReady(
  action: Pick<AgentActionOut, "depends_on_action_id">,
  actions: ReadonlyArray<Pick<AgentActionOut, "id" | "status">>,
): boolean {
  if (!action.depends_on_action_id) return true;
  return actions.some((candidate) =>
    candidate.id === action.depends_on_action_id && candidate.status === "executed");
}

export async function approveAndRunAgentAction(
  id: string,
  actions: {
    resolveAction: (id: string, approve: boolean) => Promise<unknown>;
    executeAction: (id: string) => Promise<ActionExecutionResult>;
  },
  afterExecution?: () => Promise<unknown> | unknown,
): Promise<void> {
  await actions.resolveAction(id, true);
  try {
    requireExecutedAgentAction(await actions.executeAction(id));
  } finally {
    try {
      await afterExecution?.();
    } catch {
      // The persisted execution outcome, not a transient reload, controls the UI result.
    }
  }
}
