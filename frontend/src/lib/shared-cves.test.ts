import { describe, expect, it } from "vitest";

import { sharedCves } from "./shared-cves";

describe("sharedCves", () => {
  it("returns only unique CVEs present in both records", () => {
    expect(sharedCves(
      ["CVE-2026-1234", "CVE-2026-5678"],
      ["cve-2026-1234", "CVE-2026-1234", "CVE-2025-0001"],
    )).toEqual(["CVE-2026-1234"]);
  });

  it("does not invent a match when either record has no CVE", () => {
    expect(sharedCves([], ["CVE-2026-1234"])).toEqual([]);
  });
});
