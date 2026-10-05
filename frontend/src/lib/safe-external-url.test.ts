import { describe, expect, it } from "vitest";

import { safeExternalUrl } from "./safe-external-url";

describe("safeExternalUrl", () => {
  it("keeps ordinary HTTPS provider links", () => {
    expect(safeExternalUrl("https://gitlab.example.test/acme/app/-/security/1"))
      .toBe("https://gitlab.example.test/acme/app/-/security/1");
  });

  it("rejects executable and credential-bearing links", () => {
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
    expect(safeExternalUrl("https://user:password@gitlab.example.test/alert")).toBeNull();
    expect(safeExternalUrl("https://gitlab.example.test\\@evil.example/alert")).toBeNull();
  });
});
