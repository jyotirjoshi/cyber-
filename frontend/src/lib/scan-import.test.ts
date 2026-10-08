import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("scanner export upload", () => {
  it("sends a multipart file and mapping without forcing a JSON content type", async () => {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      requests.push({ url, init });
      return Response.json({ findings_staged: 1 });
    });

    const file = new File(["key,title\nA-1,Example\n"], "findings.csv", { type: "text/csv" });
    const result = await api.integrations.importScanExport({
      file,
      formatName: "generic_csv",
      provider: "vendorx",
      assetType: "repo",
      assetValue: "acme/api",
      fieldMapping: { id: "key", title: "title" },
    });

    expect(result).toEqual({ findings_staged: 1 });
    expect(requests).toHaveLength(1);
    expect(requests[0].url).toContain("/api/v1/integrations/imports/scan");
    expect(requests[0].init.headers).not.toHaveProperty("content-type");
    const body = requests[0].init.body;
    expect(body).toBeInstanceOf(FormData);
    const form = body as FormData;
    expect(form.get("format_name")).toBe("generic_csv");
    expect(form.get("asset_value")).toBe("acme/api");
    expect(form.get("mapping_json")).toBe('{"id":"key","title":"title"}');
    expect((form.get("file") as File).name).toBe("findings.csv");
  });
});
