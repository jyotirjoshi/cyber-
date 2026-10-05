/** One approval click runs the exact approved action and reports its durable outcome. */
import type { AgentActionName, Permission } from "./types";

type ActionExecutionResult = { status: string; result_summary?: string | null };

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
  if (action === "update_github_alert") return can("integration:manage") && can("finding:validate");
  return can("integration:manage");
}

export async function approveAndRunAgentAction(
  id: string,
  actions: {
    resolveAction: (id: string, approve: boolean) => Promise<unknown>;
    executeAction: (id: string) => Promise<ActionExecutionResult>;
  },
): Promise<void> {
  await actions.resolveAction(id, true);
  requireExecutedAgentAction(await actions.executeAction(id));
}
