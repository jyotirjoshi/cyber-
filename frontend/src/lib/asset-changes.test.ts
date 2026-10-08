import { afterEach, expect, it, vi } from "vitest";

import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

it("loads a bounded asset-change page through the authenticated API client", async () => {
  const urls: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    urls.push(url);
    return Response.json({ items: [], total: 0, limit: 20, offset: 0 });
  });

  const page = await api.assets.changes({ limit: 20, offset: 0 });

  expect(page.total).toBe(0);
  expect(urls).toEqual(["http://localhost:8000/api/v1/assets/changes?limit=20&offset=0"]);
});
