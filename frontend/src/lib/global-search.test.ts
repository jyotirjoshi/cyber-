import { describe, expect, it } from "vitest";

import { groupSearchResults } from "./global-search";

describe("global search results", () => {
  it("groups results in a stable product order", () => {
    const grouped = groupSearchResults([
      { kind: "ticket", id: "1", title: "SEC-1", subtitle: "Jira", href: "/remediation" },
      { kind: "asset", id: "2", title: "api.example.com", subtitle: "Asset", href: "/assets/2" },
      { kind: "finding", id: "3", title: "SQL injection", subtitle: "Critical", href: "/findings/canonical/3" },
    ]);

    expect(grouped.map(([kind]) => kind)).toEqual(["asset", "finding", "ticket"]);
  });
});
