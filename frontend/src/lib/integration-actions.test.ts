import { describe, expect, it, vi } from "vitest";

import { canReplaySyncRun, configuredTenableScanIds, handleIntegrationSyncSuccess, handleIntegrationTestSuccess } from "./integration-actions";

describe("handleIntegrationTestSuccess", () => {
  it("refreshes the integration list after a healthy test", () => {
    const refresh = vi.fn();
    const toast = vi.fn();

    handleIntegrationTestSuccess(
      { healthy: true, detail: "Reachable and authenticated." },
      { refresh, toast },
    );

    expect(refresh).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith({
      title: "Healthy",
      description: "Reachable and authenticated.",
      tone: "ok",
    });
  });
});

describe("handleIntegrationSyncSuccess", () => {
  it("shows the ingested alert count without exposing provider evidence", () => {
    const toast = vi.fn();

    handleIntegrationSyncSuccess({ alerts_staged: 12 }, { toast });

    expect(toast).toHaveBeenCalledWith({
      title: "Security alerts synchronized",
      description: "12 alerts are available in Findings → External alerts.",
      tone: "ok",
    });
  });
});

describe("canReplaySyncRun", () => {
  it("allows replay only for failed executions", () => {
    expect(canReplaySyncRun("failed")).toBe(true);
    expect(canReplaySyncRun("running")).toBe(false);
    expect(canReplaySyncRun("succeeded")).toBe(false);
  });
});

describe("configuredTenableScanIds", () => {
  it("offers only saved scan UUIDs for launch", () => {
    expect(configuredTenableScanIds({ scan_ids: ["11111111-1111-4111-8111-111111111111", "not-a-uuid"] }))
      .toEqual(["11111111-1111-4111-8111-111111111111"]);
  });
});
