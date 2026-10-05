import { describe, expect, it } from "vitest";

import { canSaveExternalAlertTriage } from "./external-alert-triage";

const current = { status: "new" as const, note: null };

describe("canSaveExternalAlertTriage", () => {
  it("requires a rationale before a terminal decision", () => {
    expect(canSaveExternalAlertTriage({ status: "risk_accepted", note: "   " }, current)).toBe(false);
    expect(canSaveExternalAlertTriage({ status: "risk_accepted", note: "Network isolation" }, current)).toBe(true);
  });

  it("does not submit an unchanged decision but permits an updated note", () => {
    expect(canSaveExternalAlertTriage({ status: "new", note: "" }, current)).toBe(false);
    expect(canSaveExternalAlertTriage({ status: "new", note: "Needs review" }, current)).toBe(true);
  });
});
