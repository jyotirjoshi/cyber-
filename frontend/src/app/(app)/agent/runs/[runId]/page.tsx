"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { RunDag } from "@/components/agent/RunDag";
import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { humanize } from "@/lib/format";
import type { AgentRunStatus } from "@/lib/types";

const RUN_STATUS: Record<AgentRunStatus, { tone: BadgeTone; label: string; active?: boolean }> = {
  queued: { tone: "neutral", label: "Queued", active: true },
  running: { tone: "primary", label: "Running", active: true },
  interrupted: { tone: "warn", label: "Needs attention", active: true },
  completed: { tone: "ok", label: "Completed" },
  failed: { tone: "danger", label: "Failed" },
  cancelled: { tone: "neutral", label: "Cancelled" },
};

const TERMINAL = new Set<AgentRunStatus>(["completed", "failed", "cancelled"]);

export default function AgentRunPage() {
  const params = useParams<{ runId: string }>();
  const runId = params?.runId ?? "";
  const { can } = useAuth();
  const { toast } = useToast();
  const allowed = can("agent:chat");
  const run = useApiResource(() => api.agent.run(runId), [runId], {
    enabled: allowed && !!runId,
    refetchInterval: 4000,
  });
  const events = useApiResource(() => api.agent.runEvents(runId), [runId], {
    enabled: allowed && !!runId,
    refetchInterval: 4000,
  });
  const [busyTaskId, setBusyTaskId] = React.useState<string | null>(null);
  const [cancelling, setCancelling] = React.useState(false);

  const mutateTask = React.useCallback(async (taskId: string, action: "retry" | "approve") => {
    if (action === "approve") {
      const accepted = window.confirm(
        "Approve this exact tool payload? The worker will revalidate your permission, agent policy, and payload digest immediately before execution.",
      );
      if (!accepted) return;
    }
    setBusyTaskId(taskId);
    try {
      const next = action === "retry"
        ? await api.agent.retryRunTask(runId, taskId)
        : await api.agent.approveRunTask(runId, taskId);
      run.setData(next);
      toast({ title: action === "retry" ? "Task queued for retry" : "Task approved and queued", tone: "ok" });
    } catch (error) {
      toast({ title: `Could not ${action} task`, description: getErrorMessage(error), tone: "danger" });
    } finally {
      setBusyTaskId(null);
    }
  }, [runId, run, toast]);

  const cancel = React.useCallback(async () => {
    if (!window.confirm("Cancel this run and every queued or running child task?")) return;
    setCancelling(true);
    try {
      const next = await api.agent.cancelRun(runId);
      run.setData(next);
      toast({ title: "Run cancellation recorded", tone: "ok" });
    } catch (error) {
      toast({ title: "Could not cancel run", description: getErrorMessage(error), tone: "danger" });
    } finally {
      setCancelling(false);
    }
  }, [runId, run, toast]);

  if (!allowed) return <ErrorState message="You do not have permission to view agent runs." />;
  if (run.loading && !run.data) return <LoadingState label="Loading agent run…" />;
  if (run.error || !run.data) return <ErrorState message={run.error ?? "Agent run not found."} onRetry={run.refetch} />;

  const value = run.data;
  const status = RUN_STATUS[value.status];
  const taskCount = value.tasks?.length ?? 0;
  const completed = value.tasks?.filter((task) => ["completed", "degraded", "skipped"].includes(task.status)).length ?? 0;
  const totalTokens = value.total_input_tokens + value.total_output_tokens;
  const spend = `$${(value.total_spend_micros / 1_000_000).toFixed(4)}`;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Multi-agent run"
        description={value.objective ?? `Run ${value.id}`}
        actions={
          <>
            <Link className="text-sm text-muted hover:text-fg" href={value.session_id ? `/agent/${value.session_id}` : "/agent"}>Conversation</Link>
            <Badge tone={status.tone} dot={status.active} pulse={status.active}>{status.label}</Badge>
            {!TERMINAL.has(value.status) && <Button variant="danger" size="sm" loading={cancelling} onClick={cancel}>Cancel run</Button>}
          </>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        {[
          ["Tasks", taskCount ? `${completed}/${taskCount}` : "Planning"],
          ["Input tokens", value.total_input_tokens.toLocaleString()],
          ["Output tokens", value.total_output_tokens.toLocaleString()],
          ["Total tokens", totalTokens.toLocaleString()],
          ["Tool calls", value.tool_call_count.toLocaleString()],
          ["Model/tool spend", spend],
        ].map(([label, metric]) => (
          <Card key={label}><CardBody><p className="text-xs text-muted">{label}</p><p className="mt-1 text-xl font-semibold text-fg">{metric}</p></CardBody></Card>
        ))}
      </div>

      {(value.stop_reason || value.failure_reason) && (
        <Card className={value.failure_reason ? "border-danger/30" : "border-ok/30"}>
          <CardBody>
            <p className="text-xs font-medium uppercase tracking-wide text-muted">Final outcome</p>
            <p className="mt-1 text-sm text-fg">{value.failure_reason ?? humanize(value.stop_reason ?? "")}</p>
          </CardBody>
        </Card>
      )}

      <section className="space-y-3">
        <h2 className="text-base font-semibold text-fg">Execution graph</h2>
        <RunDag
          run={value}
          busyTaskId={busyTaskId}
          onRetry={(taskId) => void mutateTask(taskId, "retry")}
          onApprove={(taskId) => void mutateTask(taskId, "approve")}
        />
      </section>

      <Card>
        <CardHeader><CardTitle>Live run events</CardTitle><span className="text-xs text-muted">{events.data?.length ?? 0} replayable events</span></CardHeader>
        <CardBody>
          {events.loading && !events.data ? <LoadingState label="Loading events…" className="py-8" /> : events.error ? (
            <ErrorState message={events.error} onRetry={events.refetch} className="py-8" />
          ) : events.data?.length ? (
            <ol className="space-y-2">
              {events.data.slice(-50).reverse().map((event) => (
                <li key={`${event.seq}:${event.type}`} className="flex items-start justify-between gap-4 rounded-lg border border-line px-3 py-2 text-sm">
                  <div><span className="font-medium text-fg">{humanize(event.type)}</span><span className="ml-2 text-xs text-faint">#{event.seq}</span></div>
                  <time className="shrink-0 text-xs text-muted">{new Date(event.at).toLocaleString()}</time>
                </li>
              ))}
            </ol>
          ) : <p className="text-sm text-muted">No events have been emitted for this run yet.</p>}
        </CardBody>
      </Card>
    </div>
  );
}
