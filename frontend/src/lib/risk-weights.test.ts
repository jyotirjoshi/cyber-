import { describe, expect, it } from "vitest";

import { totalRiskWeights } from "./risk-weights";

describe("totalRiskWeights", () => {
  it("sums every tenant risk component before submitting a policy", () => {
    expect(totalRiskWeights({
      severity: 30, exploitation: 35, exploit_probability: 10,
      exposure: 15, asset_criticality: 5, ransomware: 5,
    })).toBe(100);
  });
});
