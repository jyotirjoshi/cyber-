export type CertificationGrade = "certified" | "operational" | "degraded" | "failed";
type CertificationTone = "ok" | "primary" | "warn" | "danger";

const CERTIFICATION_TONES: Record<CertificationGrade, CertificationTone> = {
  certified: "ok",
  operational: "primary",
  degraded: "warn",
  failed: "danger",
};

export function certificationTone(grade: CertificationGrade): CertificationTone {
  return CERTIFICATION_TONES[grade];
}

export function summarizeCertification(blockers: string[]): string {
  if (!blockers.length) return "All operational checks passed.";
  return blockers.length === 1 ? blockers[0] : `${blockers[0]} · +${blockers.length - 1} more`;
}
