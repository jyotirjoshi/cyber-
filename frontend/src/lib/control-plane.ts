import type { BadgeTone } from "@/components/ui/Badge";
import type { SecurityPosture, SecurityRecommendationStatus } from "./types";

export interface PostureCard {
  label: string;
  value: string;
  tone: BadgeTone;
}

export function riskTone(score: number): BadgeTone {
  return score >= 80 ? "danger" : score >= 50 ? "warn" : "ok";
}

export function projectPostureCards(posture: SecurityPosture): PostureCard[] {
  const confidence = Number(posture.average_identity_confidence) * 100;
  return [
    { label: "Resources", value: String(posture.total_resources), tone: "neutral" },
    { label: "Source confidence", value: `${confidence.toFixed(1)}%`, tone: confidence >= 85 ? "ok" : confidence >= 60 ? "warn" : "danger" },
    { label: "At risk", value: String(posture.at_risk + posture.non_compliant), tone: posture.at_risk + posture.non_compliant > 0 ? "warn" : "ok" },
    { label: "Unapproved AI", value: String(posture.unapproved_ai), tone: posture.unapproved_ai > 0 ? "danger" : "ok" },
  ];
}

export function recommendationDecisionLabel(status: SecurityRecommendationStatus): string {
  return {
    proposed: "Awaiting review",
    approved: "Approved — ready to apply",
    applying: "Applying provider change",
    applied: "Applied and receipted",
    rejected: "Rejected",
    failed: "Provider action failed",
    superseded: "Superseded",
  }[status];
}
