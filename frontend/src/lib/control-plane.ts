import type { BadgeTone } from "@/components/ui/Badge";
import type { NativeEndpointEventInput, SecurityPosture, SecurityRecommendationStatus } from "./types";

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

export function endpointFleetSummary(
  endpoints: Array<{ posture_status: string; attributes: Record<string, unknown> }>,
  events: Array<{ severity: string; evidence: Record<string, unknown> }>,
): { endpoints: number; reporting: number; atRisk: number; activeDetections: number } {
  return {
    endpoints: endpoints.length,
    reporting: endpoints.filter((item) => item.attributes.sensor_status === "reporting").length,
    atRisk: endpoints.filter((item) => item.posture_status === "at_risk" || item.posture_status === "non_compliant").length,
    activeDetections: events.filter((item) => item.evidence.verdict === "detect" && ["high", "critical"].includes(item.severity)).length,
  };
}

export function socOperationsSummary(
  cases: Array<{ status: string; severity: string }>,
): { active: number; critical: number; investigating: number; contained: number } {
  const active = cases.filter((item) => !["resolved", "dismissed"].includes(item.status));
  return {
    active: active.length,
    critical: active.filter((item) => item.severity === "critical").length,
    investigating: active.filter((item) => item.status === "investigating").length,
    contained: active.filter((item) => item.status === "contained").length,
  };
}

export function buildDemoEndpointEvent(eventId: string, occurredAt: string): NativeEndpointEventInput {
  return {
    event_key: `demo-${eventId}`,
    endpoint_key: "cynux-demo-endpoint",
    hostname: "demo-finance-workstation",
    operating_system: "windows",
    occurred_at: occurredAt,
    event_type: "process_start",
    process_name: "powershell.exe",
    parent_process_name: "winword.exe",
    executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line: "powershell.exe -NoProfile Get-Date",
    signature_status: "signed",
    environment: "test",
  };
}
