import { describe, expect, it } from "vitest";

import { githubAlertAction, canSubmitGithubAlertDecision, githubAgentActionRequest } from "./github-alert-actions";

describe("GitHub source decisions", () => {
  it("uses provider-specific reasons and labels", () => {
    expect(githubAlertAction("dependabot")?.reasons.map((item) => item.value))
      .toContain("tolerable_risk");
    expect(githubAlertAction("code_scanning")?.reasons.map((item) => item.value))
      .toContain("false positive");
    expect(githubAlertAction("secret_scanning")?.verb).toBe("Resolve");
    expect(githubAlertAction("unknown")).toBeNull();
  });

  it("requires a rationale to close an alert but not to reopen one", () => {
    expect(canSubmitGithubAlertDecision("dismiss", "tolerable_risk", "  ")).toBe(false);
    expect(canSubmitGithubAlertDecision("dismiss", "tolerable_risk", "Reviewed risk")).toBe(true);
    expect(canSubmitGithubAlertDecision("reopen", "", "")).toBe(true);
  });

  it("binds an agent approval to one alert and provider-specific reason", () => {
    const alert = { id: "b0b5e0d7-5482-4211-a522-ea80c75b66a1", provider: "github" as const,
      category: "secret_scanning", status: "open" as const };
    expect(githubAgentActionRequest(alert, "dismiss", "revoked", "Confirmed token rotation"))
      .toEqual({
        action: "update_github_alert", label: "Resolve GitHub secret scanning alert",
        payload: { alert_id: alert.id, decision: "dismiss", reason: "revoked", comment: "Confirmed token rotation" },
      });
    expect(githubAgentActionRequest(alert, "dismiss", "tolerable_risk", "Reviewed"))
      .toBeNull();
    expect(githubAgentActionRequest({ ...alert, provider: "gitlab" }, "dismiss", "revoked", "Reviewed"))
      .toBeNull();
    expect(githubAgentActionRequest({ ...alert, status: "dismissed" }, "dismiss", "revoked", "Reviewed"))
      .toBeNull();
  });
});
