"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { AssessmentStatusBadge, Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { StageChecklist } from "@/components/ui/StageChecklist";
import { useToast } from "@/components/ui/Toast";
import { ApprovalCard } from "@/components/approval/ApprovalCard";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api, saveBlob } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import {
  countLabel,
  formatDateTime,
  formatDuration,
  formatNumber,
  humanize,
} from "@/lib/format";
import type {
  ApproveIn,
  AssessmentStatus,
  ReportOut,
  Severity,
  StepStatus,
} from "@/lib/types";

// Statuses for which the backend is still doing work — drives the live poll + cancel affordance.
const ACTIVE_STATUSES: ReadonlySet<AssessmentStatus> = new Set<AssessmentStatus>([
  "CREATED",
  "PLANNING",
  "DISCOVERY",
  "WAITING_FOR_APPROVAL",
  "SCANNING",
  "ANALYZING",
  "REMEDIATING",
  "CANCELLING",
]);

const STEP_TONE: Record<StepStatus, BadgeTone> = {
  pending: "neutral",
  running: "primary",
  completed: "ok",
  failed: "danger",
  skipped: "neutral",
  degraded: "warn",
};

const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

function Detail({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="mt-0.5 break-words text-sm text-fg">{value ?? "—"}</dd>
    </div>
  );
}

/** Read a string field off the loosely-typed request_interpretation without an `any` cast. */
function readString(obj: Record<string, unknown>, key: string): string | null {
  const value = obj[key];
  return typeof value === "string" && value.trim() ? value : null;
}

export default function AssessmentDetailPage() {
  const params = useParams();
  const rawId = params.id;
  const id = (Array.isArray(rawId) ? rawId[0] : rawId) ?? "";
  const { toast } = useToast();
  const { can } = useAuth();

  const canRead = can("assessment:read");
  const canApprove = can("assessment:approve");
  const canCancel = can("assessment:cancel");
  const canGenerateReport = can("report:generate");
  const canReadReports = can("report:read");

  const assessment = useApiResource(() => api.assessments.get(id), [id], {
    enabled: canRead && !!id,
  });

  const isActive = assessment.data ? ACTIVE_STATUSES.has(assessment.data.status) : false;

  // Poll while the run is active so the stage checklist and findings tally advance on their own.
  const activePoll = useApiResource(() => api.assessments.get(id), [id, isActive], {
    enabled: canRead && !!id && isActive,
    refetchInterval: 5000,
  });
  // Fold the poll's fresher snapshot back into the primary resource.
  React.useEffect(() => {
    if (activePoll.data) assessment.setData(activePoll.data);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activePoll.data]);

  const reports = useApiResource(() => api.assessments.reports(id), [id], {
    enabled: canReadReports && !!id,
  });

  const [downloadingId, setDownloadingId] = React.useState<string | null>(null);

  const cancelMut = useMutation((reason: string | null) => api.assessments.cancel(id, { reason }), {
    onSuccess: (next) => {
      assessment.setData(next);
      toast({ title: "Cancellation requested", tone: "warn" });
    },
    onError: (e) =>
      toast({ title: "Couldn't cancel", description: getErrorMessage(e), tone: "danger" }),
  });

  const generateMut = useMutation(() => api.assessments.generateReport(id, {}), {
    onSuccess: () => {
      reports.refetch();
      toast({ title: "Report generation started", tone: "ok" });
    },
    onError: (e) =>
      toast({ title: "Couldn't generate report", description: getErrorMessage(e), tone: "danger" }),
  });

  const resolveApproval = React.useCallback(
    async (body: ApproveIn) => {
      const approvalId = assessment.data?.pending_approval?.id;
      if (!approvalId) return;
      try {
        await api.approvals.resolve(approvalId, body);
        toast({
          title:
            body.decision === "rejected"
              ? "Approval rejected"
              : "Approved — the assessment will proceed",
          tone: body.decision === "rejected" ? "warn" : "ok",
        });
        assessment.refetch();
      } catch (e) {
        toast({
          title: "Could not resolve approval",
          description: getErrorMessage(e),
          tone: "danger",
        });
      }
    },
    // refetch/setData are stable; re-bind only when the target approval changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [assessment.data?.pending_approval?.id, toast],
  );

  const [resolving, setResolving] = React.useState(false);
  const onResolve = React.useCallback(
    (body: ApproveIn) => {
      setResolving(true);
      void resolveApproval(body).finally(() => setResolving(false));
    },
    [resolveApproval],
  );

  const downloadReport = async (report: ReportOut) => {
    setDownloadingId(report.id);
    try {
      saveBlob(await api.reports.download(report.id));
    } catch (e) {
      toast({ title: "Download failed", description: getErrorMessage(e), tone: "danger" });
    } finally {
      setDownloadingId(null);
    }
  };

  if (!canRead) {
    return <EmptyState title="No access" description="You don't have permission to view this." />;
  }
  if (assessment.loading && !assessment.data) return <LoadingState label="Loading assessment…" />;
  if (assessment.error && !assessment.data) {
    return <ErrorState message={assessment.error} onRetry={assessment.refetch} />;
  }
  if (!assessment.data) {
    return <EmptyState title="Assessment not found" description="This assessment may have been removed." />;
  }

  const a = assessment.data;
  const interpretationSummary = readString(a.request_interpretation, "summary");
  const severityCounts: Record<Severity, number> = {
    critical: a.findings_critical,
    high: a.findings_high,
    medium: a.findings_medium,
    low: a.findings_low,
    info: a.findings_info,
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <span className="text-faint">#{a.reference}</span>
            <span className="truncate">{a.title}</span>
          </span>
        }
        description={`${humanize(a.scope)} · ${humanize(a.depth)} depth`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <AssessmentStatusBadge status={a.status} />
            {a.agent_session_id && (
              <Link
                href={`/agent/${a.agent_session_id}`}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line px-3 text-xs font-medium text-fg transition-colors hover:bg-surface-2"
              >
                Open agent conversation
              </Link>
            )}
            {canGenerateReport && a.status === "COMPLETED" && (
              <Button size="sm" variant="secondary" loading={generateMut.loading} onClick={() => void generateMut.run()}>
                Generate report
              </Button>
            )}
            {canCancel && isActive && a.status !== "CANCELLING" && (
              <Button
                size="sm"
                variant="danger"
                loading={cancelMut.loading}
                onClick={() => {
                  if (window.confirm("Cancel this assessment? Running scanners will be stopped.")) {
                    void cancelMut.run(null);
                  }
                }}
              >
                Cancel
              </Button>
            )}
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main column */}
        <div className="space-y-6 lg:col-span-2">
          {a.failure_reason && (
            <div className="rounded-xl border border-danger/30 bg-danger/5 px-4 py-3">
              <p className="text-sm font-medium text-danger">
                {a.failure_category ? `${humanize(a.failure_category)} — ` : ""}Assessment failed
              </p>
              <p className="mt-1 text-sm text-muted">{a.failure_reason}</p>
            </div>
          )}

          {a.pending_approval && a.pending_approval.decision === "pending" && (
            <ApprovalCard
              approval={a.pending_approval}
              canApprove={canApprove}
              busy={resolving}
              onResolve={onResolve}
            />
          )}

          <Card>
            <CardHeader>
              <CardTitle>Progress</CardTitle>
              <span className="text-xs text-muted">{Math.round(a.progress_percent)}%</span>
            </CardHeader>
            <CardBody className="space-y-4">
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
                <div
                  className="h-full rounded-full bg-primary transition-all"
                  style={{ width: `${Math.min(100, Math.max(0, a.progress_percent))}%` }}
                />
              </div>
              {a.stages.length > 0 ? (
                <StageChecklist stages={a.stages} />
              ) : (
                <p className="text-sm text-muted">No stage activity yet.</p>
              )}
            </CardBody>
          </Card>

          {a.degradations.length > 0 && (
            <Card className="border-warn/30">
              <CardHeader className="border-warn/20">
                <CardTitle>Degradations</CardTitle>
                <Badge tone="warn">{countLabel(a.degradations.length, "degradation")}</Badge>
              </CardHeader>
              <CardBody className="space-y-3">
                <p className="text-xs text-muted">
                  These dependencies were unavailable but did not stop the assessment (FR-020/FR-039).
                </p>
                <ul className="space-y-3">
                  {a.degradations.map((d, index) => (
                    <li key={`${d.component}-${index}`} className="rounded-lg border border-warn/20 bg-warn/5 px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone="warn">{d.component}</Badge>
                        <span className="text-xs text-faint">{humanize(d.stage)}</span>
                        {d.occurred_at && (
                          <span className="text-xs text-faint">· {formatDateTime(d.occurred_at)}</span>
                        )}
                      </div>
                      <p className="mt-1.5 text-sm text-fg">{d.reason}</p>
                      {d.impact && <p className="mt-0.5 text-xs text-muted">Impact: {d.impact}</p>}
                    </li>
                  ))}
                </ul>
              </CardBody>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Plan</CardTitle>
            </CardHeader>
            <CardBody>
              {a.plan.length === 0 ? (
                <p className="text-sm text-muted">The agent has not produced a plan yet.</p>
              ) : (
                <ol className="space-y-3">
                  {a.plan.map((step) => (
                    <li key={step.index} className="flex gap-3">
                      <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-surface-2 text-xs font-medium text-muted">
                        {step.index + 1}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium text-fg">{step.title}</span>
                          <Badge tone={STEP_TONE[step.status]}>{humanize(step.status)}</Badge>
                          {step.requires_approval && <Badge tone="warn">Needs approval</Badge>}
                          {step.tool && (
                            <span className="font-mono text-xs text-faint">{step.tool}</span>
                          )}
                        </div>
                        {step.rationale && (
                          <p className="mt-0.5 text-xs text-muted">{step.rationale}</p>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </CardBody>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Summary</CardTitle>
            </CardHeader>
            <CardBody>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-4">
                <Detail label="Current stage" value={humanize(a.current_stage)} />
                <Detail label="Created by" value={a.created_by} />
                <Detail label="Created" value={formatDateTime(a.created_at)} />
                <Detail label="Started" value={formatDateTime(a.started_at)} />
                <Detail label="Completed" value={formatDateTime(a.completed_at)} />
                <Detail
                  label="Duration"
                  value={a.duration_seconds != null ? formatDuration(a.duration_seconds) : "—"}
                />
              </dl>
              {interpretationSummary && (
                <div className="mt-4 border-t border-line pt-4">
                  <p className="text-xs font-medium text-muted">Interpreted objective</p>
                  <p className="mt-1 text-sm text-fg">{interpretationSummary}</p>
                </div>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Findings</CardTitle>
              <Link href="/findings" className="text-xs text-primary hover:underline">
                View all →
              </Link>
            </CardHeader>
            <CardBody className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {SEVERITY_ORDER.map((sev) => (
                  <Badge key={sev} tone={sev}>
                    {formatNumber(severityCounts[sev])} {humanize(sev)}
                  </Badge>
                ))}
              </div>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line pt-3">
                <Detail label="Total findings" value={formatNumber(a.findings_total)} />
                <Detail label="Assets discovered" value={formatNumber(a.assets_discovered)} />
                <Detail label="Assets in scope" value={formatNumber(a.assets_in_scope)} />
              </dl>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Targets</CardTitle>
            </CardHeader>
            <CardBody>
              {a.targets.length === 0 ? (
                <p className="text-sm text-muted">No targets recorded.</p>
              ) : (
                <ul className="space-y-2">
                  {a.targets.map((t) => (
                    <li key={t.id} className="rounded-lg border border-line px-3 py-2">
                      <p className="truncate font-mono text-sm text-fg">{t.canonical_value}</p>
                      <p className="mt-0.5 text-xs text-muted">
                        {humanize(t.target_type)}
                        {t.host_count > 1 ? ` · ${countLabel(t.host_count, "host")}` : ""}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>

          {canReadReports && (
            <Card>
              <CardHeader>
                <CardTitle>Reports</CardTitle>
              </CardHeader>
              <CardBody className="space-y-3">
                {reports.loading && !reports.data ? (
                  <LoadingState />
                ) : reports.error ? (
                  <InlineError message={reports.error} />
                ) : !reports.data || reports.data.length === 0 ? (
                  <p className="text-sm text-muted">No reports generated yet.</p>
                ) : (
                  <ul className="space-y-2">
                    {reports.data.map((r) => (
                      <li
                        key={r.id}
                        className="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2"
                      >
                        <div className="min-w-0">
                          <p className="truncate text-sm text-fg">{r.title}</p>
                          <p className="mt-0.5 text-xs text-muted">
                            {r.format.toUpperCase()} · {humanize(r.audience)} · {humanize(r.status)}
                          </p>
                        </div>
                        {r.status === "ready" ? (
                          <Button
                            size="sm"
                            variant="outline"
                            loading={downloadingId === r.id}
                            onClick={() => void downloadReport(r)}
                          >
                            Download
                          </Button>
                        ) : r.status === "failed" ? (
                          <Badge tone="danger">Failed</Badge>
                        ) : (
                          <Badge tone="neutral">{humanize(r.status)}</Badge>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </CardBody>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
