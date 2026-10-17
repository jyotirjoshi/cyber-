import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("PTaaS evidence upload", () => {
  it("sends bounded document metadata and bytes as multipart data", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return Response.json({ id: "document-id" });
    });
    const file = new File(["authorized scope"], "authorization.txt", {
      type: "text/plain",
    });

    await api.engagements.uploadDocument("engagement-id", {
      file,
      title: "Authorization letter",
      kind: "authorization",
      clientVisible: true,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain(
      "/api/v1/engagements/engagement-id/documents/upload",
    );
    expect(calls[0].init.headers).not.toHaveProperty("content-type");
    const form = calls[0].init.body as FormData;
    expect((form.get("file") as File).name).toBe("authorization.txt");
    expect(form.get("title")).toBe("Authorization letter");
    expect(form.get("kind")).toBe("authorization");
    expect(form.get("client_visible")).toBe("true");
  });
});
