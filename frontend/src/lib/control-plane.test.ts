import { describe, expect, it } from "vitest";

import { buildDemoEndpointEvent, endpointFleetSummary, projectPostureCards, recommendationDecisionLabel, riskTone } from "./control-plane";
import type { SecurityPosture } from "./types";

const posture: SecurityPosture = {
  total_resources: 125,
  active_sources: 8,
  stale_resources: 7,
  unknown_owner: 11,
  internet_exposed: 19,
  non_compliant: 6,
  at_risk: 13,
  approved_ai: 9,
  unapproved_ai: 4,
  source_coverage: { zscaler_zpa: 40, aws: 85 },
  kind_coverage: { asset: 100, ai_application: 25 },
  average_identity_confidence: "0.913",
};

describe("control-plane projections", () => {
  it("projects posture into stable operator cards", () => {
    expect(projectPostureCards(posture)).toEqual([
      { label: "Resources", value: "125", tone: "neutral" },
      { label: "Source confidence", value: "91.3%", tone: "ok" },
      { label: "At risk", value: "19", tone: "warn" },
      { label: "Unapproved AI", value: "4", tone: "danger" },
    ]);
  });

  it("uses explicit operator language for recommendation states", () => {
    expect(recommendationDecisionLabel("proposed")).toBe("Awaiting review");
    expect(recommendationDecisionLabel("approved")).toBe("Approved — ready to apply");
    expect(recommendationDecisionLabel("applied")).toBe("Applied and receipted");
    expect(recommendationDecisionLabel("failed")).toBe("Provider action failed");
  });

  it("maps deterministic risk bands to UI tones", () => {
    expect(riskTone(82)).toBe("danger");
    expect(riskTone(60)).toBe("warn");
    expect(riskTone(20)).toBe("ok");
  });

  it("summarizes native endpoint coverage and active detections", () => {
    expect(endpointFleetSummary(
      [
        { posture_status: "healthy", attributes: { sensor_status: "reporting" } },
        { posture_status: "at_risk", attributes: { sensor_status: "reporting" } },
        { posture_status: "inactive", attributes: { sensor_status: "stale" } },
      ],
      [
        { severity: "critical", evidence: { verdict: "detect" } },
        { severity: "info", evidence: { verdict: "observe" } },
      ],
    )).toEqual({ endpoints: 3, reporting: 2, atRisk: 1, activeDetections: 1 });
  });

  it("keeps endpoint identity stable while making demo telemetry idempotent per event", () => {
    const event = buildDemoEndpointEvent("event-42", "2026-10-21T00:00:00.000Z");
    expect(event.endpoint_key).toBe("cynux-demo-endpoint");
    expect(event.event_key).toBe("demo-event-42");
    expect(event.environment).toBe("test");
    expect(event.parent_process_name).toBe("winword.exe");
    expect(event.process_name).toBe("powershell.exe");
  });
});
