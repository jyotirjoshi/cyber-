import { describe, expect, it } from "vitest";

import { findingViewFromSearch } from "./finding-view";

describe("findingViewFromSearch", () => {
  it("opens the external inbox from a dashboard deep link", () => {
    expect(findingViewFromSearch("?view=external")).toBe("external");
  });

  it("opens the source-preserving unified feed", () => {
    expect(findingViewFromSearch("?view=all")).toBe("all");
  });

  it("defaults unknown views to canonical findings", () => {
    expect(findingViewFromSearch("?view=anything-else")).toBe("canonical");
    expect(findingViewFromSearch("")).toBe("canonical");
    expect(findingViewFromSearch("?view=canonical")).toBe("canonical");
  });
});
