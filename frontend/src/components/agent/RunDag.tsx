"use client";

import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { layoutDag } from "@/lib/agent-run-dag";
import type { AgentRunOut, AgentTaskOut, AgentTaskStatus } from "@/lib/types";

const STATUS_META: Record<AgentTaskStatus, { label: string; tone: BadgeTone; active?: boolean }> = {
  pending: { label: "Pending", tone: "neutral" },
  blocked: { label: "Blocked", tone: "neutral" },
  ready: { label: "Ready", tone: "info" },
  queued: { label: "Queued", tone: "primary", active: true },
  running: { label: "Running", tone: "primary", active: true },
  awaiting_approval: { label: "Approval required", tone: "warn", active: true },
  completed: { label: "Completed", tone: "ok" },
  degraded: { label: "Degraded", tone: "warn" },
  skipped: { label: "Skipped", tone: "neutral" },
  failed: { label: "Failed", tone: "danger" },
  rejected: { label: "Rejected", tone: "danger" },
  cancelled: { label: "Cancelled", tone: "neutral" },
};

function Evidence({ task }: { task: AgentTaskOut }) {
  if (task.evidence.length === 0) return <p className="text-xs text-muted">No evidence produced.</p>;
  return (
    <ul className="space-y-1 text-xs">
      {task.evidence.map((item) => {
        const external = /^https?:\/\//i.test(item.artifact_reference);
        return (
          <li key={item.id} className="flex items-center justify-between gap-2">
            <span className="truncate text-muted">{item.evidence_key}</span>
            {external ? (
              <a
                className="shrink-0 text-primary hover:underline"
                href={item.artifact_reference}
                target="_blank"
                rel="noreferrer"
              >
                Open evidence
              </a>
            ) : (
              <span className="max-w-40 truncate font-mono text-faint" title={item.artifact_reference}>
                {item.artifact_reference}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function TaskCard({
  task,
  busy,
  onRetry,
  onApprove,
}: {
  task: AgentTaskOut;
  busy: boolean;
  onRetry: (taskId: string) => void;
  onApprove: (taskId: string) => void;
}) {
  const meta = STATUS_META[task.status];
  const retryable = ["failed", "degraded"].includes(task.status) && task.attempt_count < task.max_attempts;
  return (
    <Card className="min-w-72 max-w-md flex-1">
      <CardHeader className="items-start">
        <div className="min-w-0">
          <CardTitle className="truncate">{task.task_key}</CardTitle>
          <p className="mt-1 text-xs text-muted">
            {task.kind}{task.tool_name ? ` · ${task.tool_name}` : ""}
          </p>
        </div>
        <Badge tone={meta.tone} dot={meta.active} pulse={meta.active}>{meta.label}</Badge>
      </CardHeader>
      <CardBody className="space-y-3">
        <div className="flex flex-wrap gap-2 text-xs text-muted">
          <span>Attempt {task.attempt_count}/{task.max_attempts}</span>
          <span>Priority {task.priority}</span>
          {task.provider && <span>Provider {task.provider}</span>}
        </div>
        {task.depends_on.length > 0 && (
          <p className="text-xs text-muted">Depends on: {task.depends_on.join(", ")}</p>
        )}
        {task.failure_detail && (
          <div className="rounded-lg border border-danger/30 bg-danger/5 p-2 text-xs text-danger">
            {task.failure_code ? `${task.failure_code}: ` : ""}{task.failure_detail}
          </div>
        )}
        {Object.keys(task.output_summary).length > 0 && (
          <pre className="max-h-28 overflow-auto rounded-lg bg-surface-2 p-2 text-xs text-muted">
            {JSON.stringify(task.output_summary, null, 2)}
          </pre>
        )}
        <Evidence task={task} />
        {(retryable || task.status === "awaiting_approval") && (
          <div className="flex justify-end gap-2">
            {retryable && <Button size="sm" variant="outline" loading={busy} onClick={() => onRetry(task.id)}>Retry</Button>}
            {task.status === "awaiting_approval" && <Button size="sm" loading={busy} onClick={() => onApprove(task.id)}>Review & approve</Button>}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

export function RunDag({
  run,
  busyTaskId,
  onRetry,
  onApprove,
}: {
  run: AgentRunOut;
  busyTaskId?: string | null;
  onRetry: (taskId: string) => void;
  onApprove: (taskId: string) => void;
}) {
  const layout = layoutDag(run.tasks ?? []);
  if (layout.errors.length > 0) {
    return (
      <Card><CardBody><p className="text-sm text-danger">The persisted task graph is invalid: {layout.errors.join("; ")}</p></CardBody></Card>
    );
  }
  if (layout.lanes.length === 0) {
    return <Card><CardBody><p className="text-sm text-muted">The supervisor has not materialized a task graph yet.</p></CardBody></Card>;
  }
  return (
    <div className="space-y-5" aria-label="Agent task graph">
      {layout.lanes.map((lane, index) => (
        <section key={lane.join(":")}>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-faint">Execution lane {index + 1}</p>
          <div className="flex flex-wrap gap-3">
            {lane.map((key) => {
              const task = layout.tasks.get(key)!;
              return <TaskCard key={key} task={task} busy={busyTaskId === task.id} onRetry={onRetry} onApprove={onApprove} />;
            })}
          </div>
        </section>
      ))}
    </div>
  );
}
