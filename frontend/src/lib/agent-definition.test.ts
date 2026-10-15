import { describe, expect, it } from "vitest";
import { approvalLabel, configurationFromVersion, defaultAgentConfiguration } from "./agent-definition";

describe("custom agent editor contracts", () => {
  it("never suggests an external write can bypass approval", () => {
    expect(approvalLabel("bounded", { side_effect: "external_write", approval: "always" })).toBe("Approval required");
    expect(approvalLabel("supervised", { side_effect: "tenant_write", approval: "policy" })).toBe("Approval required");
    expect(approvalLabel("manual", { side_effect: "tenant_write", approval: "policy" })).toBe("Unavailable in manual mode");
  });
  it("edits only configuration and does not send immutable database fields", () => {
    const config = configurationFromVersion({ ...defaultAgentConfiguration(), id: "old", version: 3,
      tool_names: ["read_assets"], collection_ids: ["kb"], configuration_digest: "digest" });
    expect(config).not.toHaveProperty("id");
    expect(config).not.toHaveProperty("configuration_digest");
    expect(config.tool_names).toEqual(["read_assets"]);
    config.collection_ids.push("new");
    expect(defaultAgentConfiguration().collection_ids).toEqual([]);
  });
});
