import { describe, expect, it } from "vitest";

import { onboardingSummary, onboardingTone } from "./onboarding";

describe("onboarding presentation", () => {
  it("explains incomplete and complete progress", () => {
    expect(onboardingSummary({ completed: 3, total: 8 })).toBe("3 of 8 milestones complete");
    expect(onboardingSummary({ completed: 8, total: 8 })).toBe("All 8 milestones complete");
  });

  it("does not show an incomplete tenant as healthy", () => {
    expect(onboardingTone({ complete: false, percent: 75 })).toBe("warn");
    expect(onboardingTone({ complete: false, percent: 25 })).toBe("danger");
    expect(onboardingTone({ complete: true, percent: 100 })).toBe("ok");
  });
});
