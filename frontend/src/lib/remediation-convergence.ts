import type { CanonicalRemediationOperationOut, RemediationConvergenceState } from "./types";

export function convergenceTone(state: RemediationConvergenceState): "danger" | "warn" | "primary" | "ok" | "info" | "neutral" {
  if (state === "reopened" || state === "fix_not_verified" || state === "verification_failed") return "danger";
  if (state === "verification_required" || state === "closed_unverified") return "warn";
  if (state === "verification_pending") return "primary";
  if (state === "verified_closed") return "ok";
  if (state === "accepted_risk") return "info";
  return "neutral";
}

export function summarizeConvergence(
  operations: ReadonlyArray<Pick<CanonicalRemediationOperationOut["convergence"], "state">>,
) {
  return {
    needsVerification: operations.filter(({ state }) => state === "verification_required" || state === "verification_pending" || state === "closed_unverified").length,
    verifiedClosed: operations.filter(({ state }) => state === "verified_closed").length,
    failedVerification: operations.filter(({ state }) => state === "fix_not_verified" || state === "verification_failed" || state === "reopened").length,
  };
}
