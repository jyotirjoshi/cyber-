import { describe, expect, it } from "vitest";

import { STAGE_LABELS, STAGE_ORDER } from "./types";
import { ADDABLE_INTEGRATIONS } from "./integration-catalog";

describe("cloud assessment setup", () => {
  it("shows the Prowler configuration option and scan progress", () => {
    expect(ADDABLE_INTEGRATIONS.some((item) => item.kind === "prowler_aws")).toBe(true);
    expect(STAGE_ORDER).toContain("scanning_prowler_aws");
    expect(STAGE_LABELS.scanning_prowler_aws).toContain("Prowler");
    expect(ADDABLE_INTEGRATIONS.some((item) => item.kind === "prowler_azure")).toBe(true);
    expect(STAGE_ORDER).toContain("scanning_prowler_azure");
    expect(STAGE_LABELS.scanning_prowler_azure).toContain("Prowler");
    expect(ADDABLE_INTEGRATIONS.some((item) => item.kind === "prowler_gcp")).toBe(true);
    expect(STAGE_ORDER).toContain("scanning_prowler_gcp");
    expect(STAGE_LABELS.scanning_prowler_gcp).toContain("Prowler");
  });
});
