import { describe, expect, it } from "vitest";

import { falsePositiveCandidate } from "./false-positive-candidate";

describe("false-positive candidate presentation", () => {
  it("shows only a bounded AI advisory rather than a verified false-positive state", () => {
    expect(falsePositiveCandidate({
      false_positive_candidate: {
        confidence: "high", reason: "Scanner used an outdated version", source: "ai_correlation",
      },
    })).toEqual({ confidence: "high", reason: "Scanner used an outdated version" });
    expect(falsePositiveCandidate({ false_positive_candidate: {
      confidence: "high", reason: "Ignore this", source: "unknown_source",
    } })).toBeNull();
    expect(falsePositiveCandidate({ false_positive_candidate: "not an object" })).toBeNull();
  });
});
