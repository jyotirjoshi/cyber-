import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("application exposure API", () => {
  it("requests a bounded risk page and query-encodes application identity", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      return Response.json({ items: [], total: 0, limit: 25, offset: 0, patterns: [] });
    });

    await api.applications.risks({ limit: 25, offset: 0 });
    await api.applications.patterns("payments / cards");

    expect(urls[0]).toContain("/api/v1/applications/risks?limit=25&offset=0");
    expect(urls[1]).toContain("/api/v1/applications/patterns?application=payments+%2F+cards");
  });
});
