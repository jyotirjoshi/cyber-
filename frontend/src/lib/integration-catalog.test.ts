import { describe, expect, it } from "vitest";

import { ADDABLE_INTEGRATIONS, BYOK_PROVIDERS, INTEGRATION_SETUP_HINTS } from "./integration-catalog";

describe("ADDABLE_INTEGRATIONS", () => {
  it("includes the backend-supported Wazuh connector", () => {
    expect(ADDABLE_INTEGRATIONS).toContainEqual({ kind: "wazuh", label: "Wazuh" });
  });

  it("offers the SonarQube vulnerability connector", () => {
    expect(ADDABLE_INTEGRATIONS).toContainEqual({ kind: "sonarqube", label: "SonarQube" });
    expect(INTEGRATION_SETUP_HINTS.sonarqube).toEqual({
      config: '{"project_keys":["my-project"]}',
      credential: "api_token",
    });
  });

  it("offers the Snyk connector with its organization scope and token slots", () => {
    expect(ADDABLE_INTEGRATIONS).toContainEqual({ kind: "snyk", label: "Snyk" });
    expect(ADDABLE_INTEGRATIONS).toContainEqual({ kind: "tenable", label: "Tenable VM" });
    expect(INTEGRATION_SETUP_HINTS.snyk).toEqual({
      config: '{"organization_id":"11111111-1111-4111-8111-111111111111"}',
      credential: "api_token",
    });
  });

  it("offers Zscaler inventory and control-plane credentials", () => {
    expect(ADDABLE_INTEGRATIONS).toContainEqual({
      kind: "zscaler",
      label: "Zscaler Zero Trust Exchange",
    });
    expect(INTEGRATION_SETUP_HINTS.zscaler.credential).toBe("client_id + client_secret");
  });
});

describe("BYOK_PROVIDERS", () => {
  it("offers OpenRouter for compatible third-party API keys", () => {
    expect(BYOK_PROVIDERS).toContainEqual({ kind: "openrouter", label: "OpenRouter" });
  });
});
