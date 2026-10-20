import type { AssuranceSummary } from "./types";

export type AssuranceTone = "neutral" | "ok" | "warn" | "danger";

export function assuranceStatusTone(status: string): AssuranceTone {
  if (["succeeded", "verified", "passed", "generated", "published"].includes(status)) return "ok";
  if (["failed", "rollback_pending", "rolled_back", "revoked"].includes(status)) return "danger";
  if (["approved", "applying", "observing", "verifying", "executing"].includes(status)) return "warn";
  return "neutral";
}

export function assuranceCounts(summary: AssuranceSummary) {
  return {
    transactions: summary.transactions.length,
    aiReceipts: summary.ai.receipts.length,
    verifiedAgents: summary.agent_assurance.filter((item) => item.verifier_status === "passed").length,
    validations: summary.validation_recipes.length,
    evidenceExports: summary.compliance_exports.length,
  };
}

export function validRiskInterval(trial: AssuranceSummary["risk_trials"][number]): boolean {
  const values = [trial.p05, trial.p50, trial.p95].map(Number);
  return values.every(Number.isFinite) && 0 <= values[0] && values[0] <= values[1] && values[1] <= values[2];
}
