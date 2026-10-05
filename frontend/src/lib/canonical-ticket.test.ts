import { describe, expect, it } from "vitest";

import { canCreateCanonicalTicket } from "./canonical-ticket";

describe("canonical ticket action", () => {
  it("offers Jira only for active findings without an existing Jira link", () => {
    expect(canCreateCanonicalTicket("open", [], true)).toBe(true);
    expect(canCreateCanonicalTicket("open", [{ provider: "jira" }], true)).toBe(false);
    expect(canCreateCanonicalTicket("closed", [], true)).toBe(false);
    expect(canCreateCanonicalTicket("accepted_risk", [], true)).toBe(false);
    expect(canCreateCanonicalTicket("open", [], false)).toBe(false);
  });
});
