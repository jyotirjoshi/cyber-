export type FalsePositiveCandidate = { confidence: "high"; reason: string };

export function falsePositiveCandidate(
  riskFactors: Record<string, unknown> | null | undefined,
): FalsePositiveCandidate | null {
  const value = riskFactors?.false_positive_candidate;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (candidate.source !== "ai_correlation" || candidate.confidence !== "high") return null;
  if (typeof candidate.reason !== "string" || !candidate.reason.trim()) return null;
  return { confidence: "high", reason: candidate.reason.trim().slice(0, 500) };
}
