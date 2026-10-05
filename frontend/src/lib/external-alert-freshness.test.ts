import { describe, expect, it } from "vitest";

import { externalAlertFreshnessWarning } from "./external-alert-freshness";

describe("externalAlertFreshnessWarning", () => {
  it("flags an open alert absent from a successful sync without calling it fixed", () => {
    expect(externalAlertFreshnessWarning({ status: "open", missing_sync_count: 2 }))
      .toBe("Not observed in 2 recent complete syncs; confirm in the source before closing.");
  });

  it("does not warn on an observed or non-open alert", () => {
    expect(externalAlertFreshnessWarning({ status: "open", missing_sync_count: 0 })).toBeNull();
    expect(externalAlertFreshnessWarning({ status: "fixed", missing_sync_count: 2 })).toBeNull();
  });
});
