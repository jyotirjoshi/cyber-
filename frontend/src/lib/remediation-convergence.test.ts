import { describe, expect, it } from "vitest";

import { convergenceTone, summarizeConvergence } from "./remediation-convergence";

describe("remediation convergence presentation", () => {
  it("makes failed and reopened remediation urgent", () => {
    expect(convergenceTone("fix_not_verified")).toBe("danger");
    expect(convergenceTone("verification_failed")).toBe("danger");
    expect(convergenceTone("reopened")).toBe("danger");
  });

  it("summarizes exact server-derived states", () => {
    expect(summarizeConvergence([
      { state: "verification_required" },
      { state: "verification_pending" },
      { state: "verified_closed" },
      { state: "fix_not_verified" },
    ])).toEqual({ needsVerification: 2, verifiedClosed: 1, failedVerification: 1 });
  });
});
