import { describe, expect, it } from "vitest";

import { workspaceManifestFilename, workspaceQuotaPercent } from "./agent-workspace";

describe("agent workspace presentation", () => {
  it("bounds quota utilization", () => {
    expect(workspaceQuotaPercent(25, 100)).toBe(25);
    expect(workspaceQuotaPercent(120, 100)).toBe(100);
    expect(workspaceQuotaPercent(1, 0)).toBe(0);
  });

  it("creates a safe evidence export filename", () => {
    expect(workspaceManifestFilename("Acme / Web pentest")).toBe("Acme-Web-pentest-evidence.json");
    expect(workspaceManifestFilename(" ../ ")).toBe("..-evidence.json");
  });
});
