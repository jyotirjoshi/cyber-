import { describe, expect, it } from "vitest";

import { assuranceStatusTone, validRiskInterval } from "./assurance-runtime";

describe("assurance runtime projections", () => {
  it("distinguishes successful, observing, and rollback states", () => {
    expect(assuranceStatusTone("succeeded")).toBe("ok");
    expect(assuranceStatusTone("observing")).toBe("warn");
    expect(assuranceStatusTone("rollback_pending")).toBe("danger");
  });

  it("rejects misleading or unordered risk intervals", () => {
    const base = {
      id: "trial-1",
      simulation_id: "simulation-1",
      p05: "100",
      p50: "500",
      p95: "1000",
      mean_annual_loss: "550",
      iterations: 10_000,
      seed: 42,
    };
    expect(validRiskInterval(base)).toBe(true);
    expect(validRiskInterval({ ...base, p50: "2000" })).toBe(false);
    expect(validRiskInterval({ ...base, p05: "not-a-number" })).toBe(false);
  });
});
