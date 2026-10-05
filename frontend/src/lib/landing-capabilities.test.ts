import { describe, expect, it } from "vitest";

import { PUBLIC_CAPABILITIES } from "./landing-capabilities";

describe("public capability claims", () => {
  it("contains real scanner and integration names without invented live connectors", () => {
    const claims = PUBLIC_CAPABILITIES.join(" ");
    expect(claims).toContain("Nmap");
    expect(claims).toContain("Nuclei");
    expect(claims).toContain("OWASP ZAP");
    expect(claims).toContain("SonarQube");
    expect(claims).not.toMatch(/Qualys|Burp Suite|Snyk|50\+|100\+/i);
  });
});
