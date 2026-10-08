import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("CMDB asset import", () => {
  it("uploads a CSV with an explicit dry-run switch and no JSON content type", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return Response.json({ dry_run: true, matched: 1, updated: 1, unmatched: [] });
    });

    const file = new File(["asset_type,asset_value,tier\ndomain,api.example.com,tier1\n"], "cmdb.csv");
    const result = await api.assets.importCmdb(file, true);

    expect(result).toEqual({ dry_run: true, matched: 1, updated: 1, unmatched: [] });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain("/api/v1/assets/cmdb-import");
    expect(calls[0].init.headers).not.toHaveProperty("content-type");
    const body = calls[0].init.body as FormData;
    expect(body).toBeInstanceOf(FormData);
    expect((body.get("file") as File).name).toBe("cmdb.csv");
    expect(body.get("dry_run")).toBe("true");
  });

  it("requires a preview of the same file before applying changes", async () => {
    const { canApplyCmdbPreview } = await import("./asset-cmdb");
    const first = new File(["a"], "cmdb.csv");
    const second = new File(["b"], "cmdb.csv");
    const preview = { dry_run: true, matched: 1, updated: 1, unmatched: [] };
    expect(canApplyCmdbPreview(first, first, preview)).toBe(true);
    expect(canApplyCmdbPreview(second, first, preview)).toBe(false);
    expect(canApplyCmdbPreview(first, first, { ...preview, matched: 0 })).toBe(false);
    expect(canApplyCmdbPreview(first, first, { ...preview, dry_run: false })).toBe(false);
  });
});
