import { describe, expect, it } from "vitest";

import { buildCanonicalWorkUpdate, toLocalDateTimeInput } from "./canonical-work";

const current = {
  assignee_user_id: "11111111-1111-4111-8111-111111111111",
  due_at: "2026-11-05T12:00:00Z",
  remediation_plan: "Upgrade package",
  status_version: 3,
};

describe("canonical remediation work form", () => {
  it("does not submit an unchanged form", () => {
    expect(buildCanonicalWorkUpdate(current, {
      assignee: current.assignee_user_id,
      dueLocal: toLocalDateTimeInput(current.due_at),
      plan: current.remediation_plan,
    })).toBeNull();
  });

  it("sends explicit nulls when ownership and deadline are cleared", () => {
    expect(buildCanonicalWorkUpdate(current, {
      assignee: "", dueLocal: "", plan: "  ",
    })).toEqual({
      expected_version: 3,
      assignee_user_id: null,
      due_at: null,
      remediation_plan: null,
    });
  });
});
