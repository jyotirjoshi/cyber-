import { describe, expect, it } from "vitest";

import { certificationTone, summarizeCertification } from "./integration-certification";

describe("connector certification presentation", () => {
  it("maps operational grades to stable visual tones", () => {
    expect(certificationTone("certified")).toBe("ok");
    expect(certificationTone("operational")).toBe("primary");
    expect(certificationTone("degraded")).toBe("warn");
    expect(certificationTone("failed")).toBe("danger");
  });

  it("summarizes blockers without hiding additional failures", () => {
    expect(summarizeCertification(["Credential missing", "Sync stale", "Circuit open"]))
      .toBe("Credential missing · +2 more");
    expect(summarizeCertification([])).toBe("All operational checks passed.");
  });
});
