import type { TriageStatus } from "./types";

type TriageDecision = { status: TriageStatus; note: string | null };

export function canSaveExternalAlertTriage(
  next: TriageDecision,
  current: TriageDecision,
): boolean {
  const note = next.note?.trim() || null;
  if (["risk_accepted", "false_positive", "closed"].includes(next.status) && !note) {
    return false;
  }
  return next.status !== current.status || note !== (current.note?.trim() || null);
}
