import { expect, test } from "@playwright/test";

const runId = "10000000-0000-4000-8000-000000000001";
const sessionId = "10000000-0000-4000-8000-000000000002";
const taskOne = "10000000-0000-4000-8000-000000000003";
const taskTwo = "10000000-0000-4000-8000-000000000004";

const run = {
  id: runId,
  session_id: sessionId,
  assessment_id: null,
  thread_id: sessionId,
  graph: "multi_agent",
  objective: "Investigate the exposed production API and prepare verified remediation evidence",
  status: "running",
  current_node: "execute",
  interrupt_kind: null,
  pending_approval_id: null,
  resumed_count: 0,
  failure_reason: null,
  failure_category: null,
  trace_url: null,
  total_input_tokens: 1250,
  total_output_tokens: 410,
  tool_call_count: 1,
  total_spend_micros: 28500,
  started_at: "2026-10-16T06:00:00Z",
  completed_at: null,
  stop_reason: null,
  steps: [],
  specialist_tasks: [],
  tasks: [
    {
      id: taskOne,
      task_key: "inventory",
      kind: "tool",
      status: "completed",
      depends_on: [],
      required: true,
      plan_index: 0,
      priority: 100,
      attempt_count: 1,
      max_attempts: 3,
      tool_name: "asset_inventory",
      provider: "cynux",
      output_summary: { assets: 4 },
      failure_code: null,
      failure_detail: null,
      started_at: "2026-10-16T06:00:01Z",
      settled_at: "2026-10-16T06:00:02Z",
      cancellation_requested_at: null,
      evidence: [
        {
          id: "10000000-0000-4000-8000-000000000005",
          evidence_key: "inventory-receipt",
          kind: "provider_receipt",
          artifact_reference: "gs://cynux-artifacts/runs/inventory.json",
          content_digest: "a".repeat(64),
          content_type: "application/json",
          summary: { assets: 4 },
          verified: true,
          produced_at: "2026-10-16T06:00:02Z",
        },
      ],
    },
    {
      id: taskTwo,
      task_key: "validate-production-exposure",
      kind: "tool",
      status: "awaiting_approval",
      depends_on: ["inventory"],
      required: true,
      plan_index: 1,
      priority: 90,
      attempt_count: 0,
      max_attempts: 3,
      tool_name: "active_validation",
      provider: "cynux",
      output_summary: {},
      failure_code: null,
      failure_detail: null,
      started_at: null,
      settled_at: null,
      cancellation_requested_at: null,
      evidence: [],
    },
  ],
};

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("cynux.access_token", "e2e-access");
    window.localStorage.setItem("cynux.refresh_token", "e2e-refresh");
  });
  await page.route("**/api/v1/auth/me", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        user: {
          id: "10000000-0000-4000-8000-000000000010",
          email: "operator@example.com",
          full_name: "Production Operator",
          is_active: true,
          is_email_verified: true,
          created_at: "2026-01-01T00:00:00Z",
          last_login_at: "2026-10-16T05:00:00Z",
        },
        organizations: [
          {
            organization_id: "10000000-0000-4000-8000-000000000011",
            organization_name: "Cynux Demo",
            organization_slug: "cynux-demo",
            role: "owner",
            is_default: true,
            joined_at: "2026-01-01T00:00:00Z",
          },
        ],
        active_organization_id: "10000000-0000-4000-8000-000000000011",
        active_role: "owner",
        permissions: ["agent:chat"],
      }),
    }),
  );
});

test("shows the durable DAG, evidence, approval action, and cancellation", async ({ page }) => {
  let currentRun: Omit<typeof run, "stop_reason"> & { stop_reason: string | null } =
    structuredClone(run);
  let approvalRequests = 0;
  await page.route(`**/api/v1/agent/runs/${runId}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(currentRun) }),
  );
  await page.route(`**/api/v1/agent/runs/${runId}/events**`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        { seq: 1, type: "run.started", at: "2026-10-16T06:00:00Z", data: {} },
        { seq: 2, type: "task.completed", at: "2026-10-16T06:00:02Z", data: { task_id: taskOne } },
      ]),
    }),
  );
  await page.route(`**/api/v1/agent/runs/${runId}/tasks/${taskTwo}/approve`, async (route) => {
    approvalRequests += 1;
    currentRun = {
      ...currentRun,
      tasks: currentRun.tasks.map((task) =>
        task.id === taskTwo ? { ...task, status: "queued" } : task,
      ),
    };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(currentRun) });
  });
  await page.route(`**/api/v1/agent/runs/${runId}/cancel`, async (route) => {
    currentRun = { ...currentRun, status: "cancelled", stop_reason: "operator_cancelled" };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(currentRun) });
  });

  await page.goto(`/agent/runs/${runId}`);

  await expect(page.getByRole("heading", { name: "Multi-agent run" })).toBeVisible();
  await expect(page.getByText(run.objective)).toBeVisible();
  await expect(page.getByLabel("Agent task graph")).toContainText("inventory");
  await expect(page.getByLabel("Agent task graph")).toContainText("validate-production-exposure");
  await expect(page.getByText("inventory-receipt")).toBeVisible();
  await expect(page.getByText("2 replayable events")).toBeVisible();

  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Review & approve" }).click();
  await expect(page.getByText("Task approved and queued")).toBeVisible();
  expect(approvalRequests).toBe(1);

  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Cancel run" }).click();
  await expect(page.getByText("Cancelled", { exact: true })).toBeVisible();
  await expect(page.getByText("Operator cancelled")).toBeVisible();
});
