import { describe, expect, it } from "vitest";

import { serializeWorkflow, validateWorkflow } from "./workflow-builder";

describe("workflow builder", () => {
  it("rejects cycles and unknown edge references", () => {
    const cyclic = {
      name: "Cyclic",
      nodes: [
        { id: "trigger", type: "trigger" as const, config: { event: "cron" } },
        { id: "notify", type: "action" as const, config: { action: "notify" } },
      ],
      edges: [
        { source: "trigger", target: "notify" },
        { source: "notify", target: "trigger" },
      ],
    };

    expect(validateWorkflow(cyclic)).toContain("Workflow must be acyclic.");
    expect(validateWorkflow({ ...cyclic, edges: [{ source: "trigger", target: "missing" }] }))
      .toContain("Edge references an unknown node.");
  });

  it("serializes nodes and edges deterministically", () => {
    const value = serializeWorkflow({
      name: " Critical workflow ",
      nodes: [
        { id: "ticket", type: "action", config: { action: "create_ticket" } },
        { id: "trigger", type: "trigger", config: { event: "finding.created" } },
      ],
      edges: [{ source: "trigger", target: "ticket" }],
    });

    expect(value.name).toBe("Critical workflow");
    expect(value.nodes.map((node) => node.id)).toEqual(["ticket", "trigger"]);
    expect(value.edges).toEqual([{ source: "trigger", target: "ticket" }]);
  });
});
