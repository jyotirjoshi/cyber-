export type DuplicateCandidate = {
  representativeFindingId: string;
  representativeTitle: string;
  groupSize: number;
  reason: string;
};

/**
 * Read only the bounded correlation advisory produced from current assessment
 * evidence. It is deliberately separate from a provider-verified duplicate state.
 */
export function duplicateCandidate(
  riskFactors: Record<string, unknown> | null | undefined,
): DuplicateCandidate | null {
  const value = riskFactors?.duplicate_candidate;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (candidate.source !== "correlation" || candidate.confidence !== "high") return null;
  if (
    typeof candidate.representative_finding_id !== "string"
    || !candidate.representative_finding_id.trim()
    || typeof candidate.representative_title !== "string"
    || !candidate.representative_title.trim()
    || typeof candidate.reason !== "string"
    || !candidate.reason.trim()
    || typeof candidate.group_size !== "number"
    || !Number.isInteger(candidate.group_size)
    || candidate.group_size < 2
  ) return null;
  return {
    representativeFindingId: candidate.representative_finding_id.trim(),
    representativeTitle: candidate.representative_title.trim().slice(0, 500),
    groupSize: candidate.group_size,
    reason: candidate.reason.trim().slice(0, 500),
  };
}
