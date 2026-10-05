export type GithubAlertDecision = "dismiss" | "reopen";

type Reason = { value: string; label: string };

const ACTIONS: Record<string, { verb: string; reasons: readonly Reason[] }> = {
  dependabot: {
    verb: "Dismiss",
    reasons: [
      { value: "fix_started", label: "Fix started" },
      { value: "inaccurate", label: "Inaccurate" },
      { value: "no_bandwidth", label: "No bandwidth" },
      { value: "not_used", label: "Not used" },
      { value: "tolerable_risk", label: "Tolerable risk" },
    ],
  },
  code_scanning: {
    verb: "Dismiss",
    reasons: [
      { value: "false positive", label: "False positive" },
      { value: "won't fix", label: "Won't fix" },
      { value: "used in tests", label: "Used in tests" },
      { value: "mitigated", label: "Mitigated" },
    ],
  },
  secret_scanning: {
    verb: "Resolve",
    reasons: [
      { value: "false_positive", label: "False positive" },
      { value: "wont_fix", label: "Won't fix" },
      { value: "revoked", label: "Revoked (only after verifying revocation)" },
      { value: "used_in_tests", label: "Used in tests" },
    ],
  },
};

export function githubAlertAction(category: string) {
  return ACTIONS[category] ?? null;
}

export function canSubmitGithubAlertDecision(decision: GithubAlertDecision, reason: string, comment: string): boolean {
  return decision === "reopen" || (Boolean(reason) && Boolean(comment.trim()));
}

export function githubAgentActionRequest(
  alert: Pick<ExternalAlertOut, "id" | "provider" | "category" | "status">,
  decision: GithubAlertDecision,
  reason = "",
  comment = "",
): Pick<AgentActionProposeIn, "action" | "label" | "payload"> | null {
  const spec = alert.provider === "github" ? githubAlertAction(alert.category) : null;
  if (!spec || (decision === "dismiss" ? alert.status !== "open" : !["dismissed", "resolved"].includes(alert.status))) {
    return null;
  }
  if (decision === "dismiss" && (!spec.reasons.some((item) => item.value === reason) || !comment.trim())) {
    return null;
  }
  return {
    action: "update_github_alert",
    label: `${decision === "dismiss" ? spec.verb : "Reopen"} GitHub ${alert.category.replaceAll("_", " ")} alert`,
    payload: decision === "reopen"
      ? { alert_id: alert.id, decision }
      : { alert_id: alert.id, decision, reason, comment: comment.trim() },
  };
}
import type { AgentActionProposeIn, ExternalAlertOut } from "./types";
