import { describe, expect, it } from "vitest";

import { readinessTone, readinessProgress } from "./platform-readiness";

describe("platform readiness presentation", () => {
  it("uses blocked tone until every required control passes", () => {
    expect(readinessTone({ ready: false, score: 90 })).toBe("warn");
    expect(readinessTone({ ready: false, score: 40 })).toBe("danger");
    expect(readinessTone({ ready: true, score: 100 })).toBe("ok");
  });

  it("formats completion as passed controls over total controls", () => {
    expect(readinessProgress({ passed: 7, total: 10 })).toBe("7 of 10 controls ready");
  });
});
