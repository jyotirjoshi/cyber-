"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { Badge, RiskBadge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Textarea } from "@/components/ui/Input";
import { StageChecklist } from "@/components/ui/StageChecklist";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { Spinner } from "@/components/ui/Spinner";
import { ApprovalCard } from "@/components/approval/ApprovalCard";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { getErrorMessage } from "@/lib/errors";
import { formatDuration, humanize } from "@/lib/format";
import { useAgentStream, type StreamState } from "@/lib/ws";
import {
  MAX_MESSAGE_LENGTH,
  type AgentEvent,
  type AgentEventType,
  type AgentMessageOut,
  type ApprovalOut,
  type ApproveIn,
  type FindingsUpdateData,
  type PlanStepData,
  type ProgressData,
  type StepStatus,
  type ToolCallData,
  type TypedAgentEvent,
} from "@/lib/types";

// ---------------------------------------------------------------------------
// Event replay helpers (shared by the WS stream and the REST fallback poll).
// ---------------------------------------------------------------------------

const KNOWN_EVENT_TYPES: ReadonlySet<string> = new Set<AgentEventType>([
  "agent_thinking",
  "agent_plan_step",
  "agent_tool_call",
  "agent_approval_required",
  "agent_findings_update",
  "agent_error",
  "agent_complete",
  "agent_message",
  "agent_progress",
  "pong",
]);

/** Narrow a raw REST-replayed envelope to the discriminated event union. */
function asTyped(event: AgentEvent): TypedAgentEvent | null {
  return KNOWN_EVENT_TYPES.has(event.type) ? (event as unknown as TypedAgentEvent) : null;
}

const STREAM_META: Record<StreamState, { tone: BadgeTone; label: string; live: boolean }> = {
  idle: { tone: "neutral", label: "Idle", live: false },
  connecting: { tone: "warn", label: "Connecting", live: true },
  open: { tone: "ok", label: "Live", live: true },
  reconnecting: { tone: "warn", label: "Reconnecting", live: true },
  closed: { tone: "neutral", label: "Closed", live: false },
  error: { tone: "danger", label: "Disconnected", live: false },
};

const STEP_TONE: Record<StepStatus, BadgeTone> = {
  pending: "neutral",
  running: "primary",
  completed: "ok",
  failed: "danger",
  skipped: "neutral",
  degraded: "warn",
};

const TOOL_STATUS_TONE: Record<ToolCallData["status"], BadgeTone> = {
  started: "primary",
  succeeded: "ok",
  failed: "danger",
};

// ---------------------------------------------------------------------------
// Conversation screen.
// ---------------------------------------------------------------------------

export default function AgentConversationPage() {
  const params = useParams<{ sessionId: string }>();
  const sessionId = params?.sessionId ?? null;
  const { toast } = useToast();
  const { can } = useAuth();
  const canChat = can("agent:chat");
  const canApprove = can("assessment:approve");

  const session = useApiResource(
    () => api.agent.session(sessionId as string),
    [sessionId],
    { enabled: canChat && !!sessionId },
  );

  // Durable turns, keyed by id so REST loads and live `agent_message` events merge idempotently.
  const [messagesById, setMessagesById] = React.useState<Record<string, AgentMessageOut>>({});
  // Current-run streaming state (ephemeral; reset on a new turn / cleared on complete).
  const [planSteps, setPlanSteps] = React.useState<Record<number, PlanStepData>>({});
  const [toolActivity, setToolActivity] = React.useState<Array<{ seq: number; data: ToolCallData }>>([]);
  const [progress, setProgress] = React.useState<ProgressData | null>(null);
  const [findings, setFindings] = React.useState<FindingsUpdateData | null>(null);
  const [thinking, setThinking] = React.useState<string | null>(null);
  const [pendingApproval, setPendingApproval] = React.useState<ApprovalOut | null>(null);
  const [agentBusy, setAgentBusy] = React.useState(false);
  const [eventError, setEventError] = React.useState<string | null>(null);

  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [resolving, setResolving] = React.useState(false);

  // Highest event seq processed — dedup guard + REST replay cursor (WS and REST share the space).
  const maxSeqRef = React.useRef(0);
  const refetchRef = React.useRef(session.refetch);
  refetchRef.current = session.refetch;
  const approvalSeededRef = React.useRef(false);
  const bottomRef = React.useRef<HTMLDivElement | null>(null);

  const handleEvent = React.useCallback((event: TypedAgentEvent) => {
    if (event.type !== "pong" && typeof event.seq === "number") {
      if (event.seq <= maxSeqRef.current) return;
      maxSeqRef.current = event.seq;
    }

    switch (event.type) {
      case "agent_message": {
        const message = event.data;
        setMessagesById((prev) => ({ ...prev, [message.id]: message }));
        if (message.role === "assistant") setThinking(null);
        break;
      }
      case "agent_thinking":
        setThinking(event.data.text);
        setAgentBusy(true);
        break;
      case "agent_plan_step":
        setPlanSteps((prev) => ({ ...prev, [event.data.step_index]: event.data }));
        setAgentBusy(true);
        break;
      case "agent_tool_call":
        setToolActivity((prev) => [...prev, { seq: event.seq, data: event.data }].slice(-60));
        setAgentBusy(true);
        break;
      case "agent_progress":
        setProgress(event.data);
        setAgentBusy(true);
        break;
      case "agent_findings_update":
        setFindings(event.data);
        break;
      case "agent_approval_required":
        setPendingApproval(event.data);
        setAgentBusy(false);
        break;
      case "agent_error":
        setEventError(event.data.user_message);
        setAgentBusy(false);
        break;
      case "agent_complete":
        setAgentBusy(false);
        setThinking(null);
        setPendingApproval(null);
        refetchRef.current();
        break;
      default:
        break;
    }
  }, []);

  const stream = useAgentStream({
    sessionId,
    enabled: canChat && !!sessionId,
    onEvent: handleEvent,
  });

  // Seed durable messages + resume a pending approval from an interrupted run (survives reload).
  React.useEffect(() => {
    const data = session.data;
    if (!data) return;
    setMessagesById((prev) => {
      const next = { ...prev };
      for (const message of data.messages) next[message.id] = message;
      return next;
    });
    if (!approvalSeededRef.current) {
      const interrupted = data.runs.find((run) => run.pending_approval_id);
      if (interrupted?.pending_approval_id) {
        approvalSeededRef.current = true;
        void api.approvals
          .get(interrupted.pending_approval_id)
          .then((approval) => {
            if (approval.decision === "pending") setPendingApproval(approval);
          })
          .catch(() => {
            /* best effort — the live stream will re-surface it if still pending */
          });
      }
    }
  }, [session.data]);

  // REST replay fallback: while the socket is not open, poll the event log from our cursor so the
  // timeline keeps advancing even if the WS is blocked (INTERFACES §14).
  React.useEffect(() => {
    if (!sessionId || !canChat || stream.state === "open" || stream.state === "error") return;
    const interval = setInterval(() => {
      void api.agent
        .events(sessionId, maxSeqRef.current)
        .then((events) => {
          for (const raw of events) {
            const typed = asTyped(raw);
            if (typed) handleEvent(typed);
          }
        })
        .catch(() => {
          /* transient — WS reconnect or the next poll will catch up */
        });
    }, 4000);
    return () => clearInterval(interval);
  }, [sessionId, canChat, stream.state, handleEvent]);

  const messages = React.useMemo(
    () => Object.values(messagesById).sort((a, b) => a.seq - b.seq),
    [messagesById],
  );
  const plan = React.useMemo(
    () => Object.values(planSteps).sort((a, b) => a.step_index - b.step_index),
    [planSteps],
  );

  // Keep the newest turn / activity in view.
  React.useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages.length, thinking, toolActivity.length, progress, pendingApproval, agentBusy]);

  const send = async () => {
    const content = input.trim();
    if (!content || sending || !sessionId) return;
    setSending(true);
    setEventError(null);
    try {
      const message = await api.agent.sendMessage({ session_id: sessionId, content });
      setMessagesById((prev) => ({ ...prev, [message.id]: message }));
      setInput("");
      setThinking(null);
      setPlanSteps({});
      setToolActivity([]);
      setProgress(null);
      setAgentBusy(true);
    } catch (error) {
      toast({ title: "Message failed", description: getErrorMessage(error), tone: "danger" });
    } finally {
      setSending(false);
    }
  };

  const resolveApproval = React.useCallback(
    async (body: ApproveIn) => {
      if (!pendingApproval || resolving) return;
      setResolving(true);
      try {
        await api.approvals.resolve(pendingApproval.id, body);
        toast({
          title:
            body.decision === "rejected"
              ? "Approval rejected"
              : "Approved — the assessment will proceed",
          tone: body.decision === "rejected" ? "warn" : "ok",
        });
        setPendingApproval(null);
        if (body.decision !== "rejected") setAgentBusy(true);
        refetchRef.current();
      } catch (error) {
        toast({
          title: "Could not resolve approval",
          description: getErrorMessage(error),
          tone: "danger",
        });
      } finally {
        setResolving(false);
      }
    },
    [pendingApproval, resolving, toast],
  );

  if (!canChat) {
    return (
      <EmptyState
        title="No access"
        description="You don't have permission to use the security agent."
      />
    );
  }

  if (session.loading && !session.data) return <LoadingState label="Loading conversation…" />;
  if (session.error && !session.data) {
    return <ErrorState message={session.error} onRetry={session.refetch} />;
  }

  const streamMeta = STREAM_META[stream.state];
  const showLiveRegion =
    agentBusy || plan.length > 0 || toolActivity.length > 0 || !!progress || !!thinking;

  return (
    <div className="flex h-full flex-col space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <Link href="/agent" className="text-xs text-muted hover:text-fg">
            ← All conversations
          </Link>
          <h1 className="mt-1 truncate text-lg font-semibold text-fg">
            {session.data?.title ?? "Conversation"}
          </h1>
        </div>
        <Badge tone={streamMeta.tone} dot pulse={streamMeta.live && stream.state !== "open"}>
          {streamMeta.label}
        </Badge>
      </div>

      {stream.error && (
        <InlineError message={stream.error} />
      )}
      {stream.state === "reconnecting" && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-line bg-surface-2 px-3 py-2">
          <span className="flex items-center gap-2 text-sm text-muted">
            <Spinner className="h-3.5 w-3.5" />
            Reconnecting to the live feed…
          </span>
          <Button size="sm" variant="outline" onClick={stream.reconnect}>
            Retry now
          </Button>
        </div>
      )}

      {/* Timeline */}
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
        {session.data?.context_summary && (
          <p className="rounded-lg border border-line bg-surface-2/60 px-3 py-2 text-xs text-muted">
            <span className="font-medium text-fg">Context so far:</span> {session.data.context_summary}
          </p>
        )}

        {messages.length === 0 && !showLiveRegion && (
          <EmptyState
            title="No messages yet"
            description="Send a message below to get started."
          />
        )}

        {messages.map((message) => (
          <MessageBubble key={message.id} message={message} />
        ))}

        {showLiveRegion && (
          <LiveActivity
            plan={plan}
            toolActivity={toolActivity}
            progress={progress}
            findings={findings}
            thinking={thinking}
            busy={agentBusy}
          />
        )}

        {eventError && (
          <div className="rounded-lg border border-danger/30 bg-danger/5 px-3 py-2 text-sm text-danger">
            {eventError}
          </div>
        )}

        {pendingApproval && (
          <ApprovalCard
            approval={pendingApproval}
            canApprove={canApprove}
            busy={resolving}
            onResolve={resolveApproval}
          />
        )}

        <div ref={bottomRef} />
      </div>

      {/* Composer */}
      <div className="shrink-0 border-t border-line pt-3">
        <div className="flex items-end gap-2">
          <Textarea
            aria-label="Message the agent"
            placeholder="Reply, refine the objective, or ask a question…"
            rows={2}
            maxLength={MAX_MESSAGE_LENGTH}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void send();
              }
            }}
          />
          <Button
            className="h-10"
            loading={sending}
            disabled={!input.trim()}
            onClick={() => void send()}
          >
            Send
          </Button>
        </div>
        <p className="mt-1 text-xs text-faint">
          Enter to send · Shift + Enter for a new line · {input.length}/{MAX_MESSAGE_LENGTH}
        </p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Message bubble.
// ---------------------------------------------------------------------------

function MessageBubble({ message }: { message: AgentMessageOut }) {
  if (message.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] rounded-xl rounded-br-sm border border-primary/30 bg-primary/10 px-4 py-2.5">
          <p className="whitespace-pre-wrap break-words text-sm text-fg">{message.content}</p>
        </div>
      </div>
    );
  }

  if (message.role === "assistant") {
    return (
      <div className="flex justify-start">
        <div className="max-w-[85%] rounded-xl rounded-bl-sm border border-line bg-surface px-4 py-2.5">
          {message.content && (
            <p className="whitespace-pre-wrap break-words text-sm text-fg">{message.content}</p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {message.model && <span className="text-xs text-faint">{message.model}</span>}
            {message.tool_calls.length > 0 && (
              <Badge tone="neutral">
                {message.tool_calls.length} tool {message.tool_calls.length === 1 ? "call" : "calls"}
              </Badge>
            )}
            {message.citations.length > 0 && (
              <Badge tone="info">
                {message.citations.length} {message.citations.length === 1 ? "citation" : "citations"}
              </Badge>
            )}
            {message.guardrail_applied && (
              <Badge tone="warn">Guardrail: {humanize(message.guardrail_applied)}</Badge>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (message.role === "tool") {
    return (
      <div className="flex justify-start">
        <p className="font-mono text-xs text-faint">
          ⚙ {message.tool_name ?? "tool"}
          {message.tool_status ? ` → ${message.tool_status}` : ""}
        </p>
      </div>
    );
  }

  // system
  return (
    <p className="text-center text-xs italic text-faint">{message.content}</p>
  );
}

// ---------------------------------------------------------------------------
// Live activity for the in-progress run.
// ---------------------------------------------------------------------------

function LiveActivity({
  plan,
  toolActivity,
  progress,
  findings,
  thinking,
  busy,
}: {
  plan: PlanStepData[];
  toolActivity: Array<{ seq: number; data: ToolCallData }>;
  progress: ProgressData | null;
  findings: FindingsUpdateData | null;
  thinking: string | null;
  busy: boolean;
}) {
  return (
    <Card className="border-primary/25 bg-surface/60">
      <CardBody className="space-y-4">
        {busy && (
          <div className="flex items-center gap-2 text-sm text-primary">
            <Spinner className="h-4 w-4" />
            <span>{thinking ? thinking : "Working…"}</span>
          </div>
        )}

        {plan.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-faint">Plan</p>
            <ol className="space-y-1.5">
              {plan.map((step) => (
                <li key={step.step_index} className="flex items-center gap-2 text-sm">
                  <Badge tone={STEP_TONE[step.status]}>{humanize(step.status)}</Badge>
                  <span className={cn("text-fg", step.status === "skipped" && "text-faint line-through")}>
                    {step.title}
                  </span>
                </li>
              ))}
            </ol>
          </div>
        )}

        {progress && (
          <div>
            <div className="mb-2 flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-wide text-faint">Progress</p>
              <span className="text-xs text-muted">{Math.round(progress.progress_percent)}%</span>
            </div>
            <div className="mb-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${Math.min(100, Math.max(0, progress.progress_percent))}%` }}
              />
            </div>
            <StageChecklist stages={progress.stages} />
          </div>
        )}

        {toolActivity.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-faint">Tool activity</p>
            <ul className="space-y-1.5">
              {toolActivity.map((entry) => (
                <li key={`${entry.data.tool}-${entry.seq}`} className="flex items-center gap-2 text-sm">
                  <Badge tone={TOOL_STATUS_TONE[entry.data.status]}>{humanize(entry.data.status)}</Badge>
                  <span className="font-mono text-xs text-fg">{entry.data.tool}</span>
                  {entry.data.risk_level && <RiskBadge risk={entry.data.risk_level} />}
                  {entry.data.summary && <span className="text-xs text-muted">{entry.data.summary}</span>}
                  {typeof entry.data.duration_ms === "number" && (
                    <span className="text-xs text-faint">
                      {formatDuration(entry.data.duration_ms / 1000)}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}

        {findings && (
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-faint">Findings</p>
            <Badge tone="neutral">{findings.total} total</Badge>
            {findings.critical > 0 && <Badge tone="critical">{findings.critical} critical</Badge>}
            {findings.high > 0 && <Badge tone="high">{findings.high} high</Badge>}
            {findings.medium > 0 && <Badge tone="medium">{findings.medium} medium</Badge>}
            {findings.new_since_last > 0 && (
              <span className="text-xs text-muted">+{findings.new_since_last} new</span>
            )}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
