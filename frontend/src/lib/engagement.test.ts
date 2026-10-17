import { describe, expect, it } from "vitest";

import { allowedEngagementStatuses, engagementProgress } from "./engagement";

describe("engagement portal helpers", () => {
  it("only offers lifecycle transitions allowed by the service", () => {
    expect(allowedEngagementStatuses("draft")).toEqual(["scoping", "cancelled"]);
    expect(allowedEngagementStatuses("active")).toEqual([
      "retesting",
      "completed",
      "cancelled",
    ]);
    expect(allowedEngagementStatuses("completed")).toEqual([]);
  });

  it("projects stable progress for each delivery state", () => {
    expect(engagementProgress("draft")).toBe(5);
    expect(engagementProgress("active")).toBe(55);
    expect(engagementProgress("completed")).toBe(100);
    expect(engagementProgress("cancelled")).toBe(0);
  });
});
