import { describe, expect, it } from "vitest";

import { layoutDag } from "./agent-run-dag";
import type { AgentTaskOut } from "./types";

const task = (task_key: string, depends_on: string[] = []): AgentTaskOut => ({
  id: task_key,
  task_key,
  kind: task_key === "join" ? "join" : task_key === "finalize" ? "finalize" : "agent",
  status: "pending",
  depends_on,
  required: true,
  plan_index: ["triage", "intel", "asset", "join", "finalize"].indexOf(task_key),
  priority: 100,
  attempt_count: 0,
  max_attempts: 3,
  tool_name: null,
  provider: null,
  output_summary: {},
  failure_code: null,
  failure_detail: null,
  started_at: null,
  settled_at: null,
  cancellation_requested_at: null,
  evidence: [],
});

describe("layoutDag", () => {
  it("orders tasks topologically and preserves parallel lanes", () => {
    const fanoutRun = [
      task("triage"),
      task("intel"),
      task("asset"),
      task("join", ["triage", "intel", "asset"]),
      task("finalize", ["join"]),
    ];

    expect(layoutDag(fanoutRun).lanes).toEqual([
      ["triage", "intel", "asset"],
      ["join"],
      ["finalize"],
    ]);
  });

  it("reports a broken dependency instead of implying success", () => {
    const layout = layoutDag([task("finalize", ["missing"])]);
    expect(layout.lanes).toEqual([]);
    expect(layout.errors).toEqual(["finalize depends on missing task missing"]);
  });
});
