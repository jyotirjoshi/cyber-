"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";

import {
  AssessmentStatusBadge,
  Badge,
  KevBadge,
  PriorityBadge,
  SeverityBadge,
} from "@/components/ui/Badge";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { AttackPathCard } from "@/components/ui/AttackPathCard";
import { RiskHeatmap, type HeatmapCell } from "@/components/ui/RiskHeatmap";
import { SSVCBadge } from "@/components/ui/SSVCBadge";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import {
  countLabel,
  formatNumber,
  formatRelative,
  humanize,
} from "@/lib/format";
import type {
  AssessmentDetailOut,
  DashboardOut,
  FindingOut,
  IntegrationStatus,
  Priority,
  Severity,
} from "@/lib/types";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const PRIORITIES: readonly Priority[] = ["P1", "P2", "P3", "P4", "P5"];

const INTEGRATION_TONE: Record<
  IntegrationStatus,
  "ok" | "warn" | "danger" | "neutral"
> = {
  configured: "ok",
  unverified: "warn",
  error: "danger",
  disabled: "neutral",
};

// SSVC outcome → display urgency for dashboard stat
const SSVC_URGENCY: Record<string, string> = {
  act: "text-red-600 font-bold",
  attend: "text-orange-500 font-semibold",
  "track*": "text-yellow-600",
  track: "text-green-600",
};

function StatCard({
  label,
  value,
  note,
  urgent,
}: {
  label: string;
  value: React.ReactNode;
  note?: string;
  urgent?: boolean;
}) {
  return (
    <Card>
      <CardBody>
        <p className="text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
        <p
          className={`mt-2 text-2xl font-semibold tabular-nums ${urgent ? "text-red-600" : "text-fg"}`}
        >
          {value}
        </p>
        {note && <p className="mt-1 text-xs text-faint">{note}</p>}
      </CardBody>
    </Card>
  );
}

function NothingYet() {
  return <p className="px-2 py-2 text-sm text-muted">Nothing yet</p>;
}

/** Derive heatmap cells from the priority/severity breakdown. */
function buildHeatmapCells(
  findings: FindingOut[],
): HeatmapCell[] {
  // Map severity → likelihood (1–5) and priority → impact (1–5)
  const severityToLikelihood: Record<string, 1 | 2 | 3 | 4 | 5> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  const priorityToImpact: Record<string, 1 | 2 | 3 | 4 | 5> = {
    P1: 5,
    P2: 4,
    P3: 3,
    P4: 2,
    P5: 1,
  };

  const counts = new Map<string, { count: number; ids: string[] }>();
  for (const f of findings) {
    const l = severityToLikelihood[f.severity] ?? 3;
    const i = f.priority ? priorityToImpact[f.priority] ?? 3 : 3;
    const key = `${l},${i}`;
    const existing = counts.get(key) ?? { count: 0, ids: [] };
    existing.count++;
    existing.ids.push(f.id);
    counts.set(key, existing);
  }

  const cells: HeatmapCell[] = [];
  for (const [key, { count, ids }] of counts) {
    const [l, i] = key.split(",").map(Number) as [1 | 2 | 3 | 4 | 5, 1 | 2 | 3 | 4 | 5];
    cells.push({ likelihood: l, impact: i, count, findingIds: ids });
  }
  return cells;
}

/** Derive SSVC summary counts from top findings' risk_factors. */
function computeSSVCSummary(findings: FindingOut[]): Record<string, number> {
  const counts: Record<string, number> = { act: 0, attend: 0, "track*": 0, track: 0 };
  for (const f of findings) {
    const ssvc = (f.risk_factors?.ssvc as { outcome?: string } | undefined)?.outcome;
    if (ssvc && ssvc in counts) counts[ssvc]++;
  }
  return counts;
}

function DashboardBody({ data }: { data: DashboardOut }) {
  const router = useRouter();
  const mttr = data.mean_time_to_remediate_days;
  const heatmapCells = React.useMemo(
    () => buildHeatmapCells(data.top_findings),
    [data.top_findings],
  );
  const ssvcSummary = React.useMemo(
    () => computeSSVCSummary(data.top_findings),
    [data.top_findings],
  );

  // Latest completed assessment — for attack path panel
  const latestCompleted = data.recent_assessments.find(
    (a) => a.status === "COMPLETED",
  );
  const { data: assessmentDetail } = useApiResource(
    () => (latestCompleted ? api.assessments.get(latestCompleted.id) : Promise.resolve(null)),
    [latestCompleted?.id],
    { enabled: !!latestCompleted },
  );
  const attackPaths: import("@/components/ui/AttackPathCard").AttackPathData[] =
    (assessmentDetail as AssessmentDetailOut & { extra_data?: Record<string, unknown> } | null)
      ?.extra_data?.["attack_paths"] as never ?? [];

  return (
    <div className="space-y-6">
      {/* ── Top stat strip ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Active assessments"  value={formatNumber(data.assessments_active)} />
        <StatCard label="Awaiting approval"   value={formatNumber(data.assessments_awaiting_approval)} />
        <StatCard label="Open findings"       value={formatNumber(data.findings_open)} />
        <StatCard label="Critical assets"     value={formatNumber(data.assets_critical)} />
        <StatCard
          label="KEV findings"
          value={formatNumber(data.kev_findings)}
          note="confirmed active exploitation"
          urgent={data.kev_findings > 0}
        />
        <StatCard
          label="Mean time to remediate"
          value={mttr === null ? "—" : `${mttr.toFixed(1)}d`}
        />
      </div>

      {/* ── SSVC urgency strip ─────────────────────────────────────────── */}
      {Object.values(ssvcSummary).some((v) => v > 0) && (
        <Card>
          <CardHeader>
            <CardTitle>SSVC Triage Summary</CardTitle>
          </CardHeader>
          <CardBody>
            <div className="flex flex-wrap items-center gap-6">
              {(["act", "attend", "track*", "track"] as const).map((outcome) => (
                <div key={outcome} className="flex items-center gap-2">
                  <SSVCBadge outcome={outcome} showTooltip />
                  <span className={`text-xl font-bold tabular-nums ${SSVC_URGENCY[outcome] ?? "text-fg"}`}>
                    {ssvcSummary[outcome]}
                  </span>
                  <span className="text-xs text-muted capitalize">
                    {outcome === "track*" ? "Track closely" :
                     outcome === "act" ? "Act now" :
                     outcome === "attend" ? "Attend this week" : "Monitor"}
                  </span>
                </div>
              ))}
              <p className="ml-auto text-xs text-faint">
                Stakeholder-Specific Vulnerability Categorization (CISA SSVC v2.0)
              </p>
            </div>
          </CardBody>
        </Card>
      )}

      {/* ── Risk heatmap + severity/priority breakdowns ────────────────── */}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Risk Heat Map</CardTitle>
          </CardHeader>
          <CardBody>
            {heatmapCells.length > 0 ? (
              <RiskHeatmap
                cells={heatmapCells}
                onCellClick={(cell) => {
                  if (cell.findingIds?.[0]) {
                    router.push(`/findings?priority=${encodeURIComponent("")}`);
                  }
                }}
              />
            ) : (
              <p className="text-sm text-muted">No findings to plot yet.</p>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Severity breakdown</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            {SEVERITIES.map((s) => {
              const count = data.severity_breakdown[s] ?? 0;
              const total = Object.values(data.severity_breakdown).reduce((a, b) => a + b, 0);
              const pct = total > 0 ? Math.round((count / total) * 100) : 0;
              return (
                <div key={s}>
                  <div className="flex items-center justify-between gap-3 mb-0.5">
                    <SeverityBadge severity={s} />
                    <span className="text-sm font-medium tabular-nums text-fg">
                      {formatNumber(count)}
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-surface-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        s === "critical" ? "bg-red-600" :
                        s === "high"     ? "bg-orange-500" :
                        s === "medium"   ? "bg-yellow-400" :
                        s === "low"      ? "bg-blue-400" : "bg-green-400"
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Priority breakdown</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            {PRIORITIES.map((p) => {
              const count = data.priority_breakdown[p] ?? 0;
              const total = Object.values(data.priority_breakdown).reduce((a, b) => a + b, 0);
              const pct = total > 0 ? Math.round((count / total) * 100) : 0;
              return (
                <div key={p}>
                  <div className="flex items-center justify-between gap-3 mb-0.5">
                    <PriorityBadge priority={p} />
                    <span className="text-sm font-medium tabular-nums text-fg">
                      {formatNumber(count)}
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-surface-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        p === "P1" ? "bg-red-600" :
                        p === "P2" ? "bg-orange-500" :
                        p === "P3" ? "bg-yellow-400" :
                        p === "P4" ? "bg-blue-400" : "bg-green-400"
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </CardBody>
        </Card>
      </div>

      {/* ── Attack paths ───────────────────────────────────────────────── */}
      {attackPaths.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted px-1">
            Kill-Chain Attack Paths — {latestCompleted?.title}
          </h2>
          <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
            {attackPaths.map((path, i) => (
              <AttackPathCard
                key={i}
                path={path}
                index={i}
                onFindingClick={(fid) => router.push(`/findings/${fid}`)}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── Recent assessments + top findings ──────────────────────────── */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent assessments</CardTitle>
          </CardHeader>
          <CardBody className="space-y-1">
            {data.recent_assessments.length === 0 ? (
              <NothingYet />
            ) : (
              data.recent_assessments.map((a) => (
                <Link
                  key={a.id}
                  href={`/assessments/${a.id}`}
                  className="flex items-center gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-surface-2"
                >
                  <span className="shrink-0 text-xs font-medium tabular-nums text-faint">
                    #{a.reference}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm text-fg">{a.title}</span>
                  <AssessmentStatusBadge status={a.status} />
                  <span className="hidden shrink-0 text-xs text-muted sm:inline">
                    {countLabel(a.findings_total, "finding")}
                  </span>
                  <span className="shrink-0 text-xs text-faint">
                    {formatRelative(a.created_at)}
                  </span>
                </Link>
              ))
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top findings</CardTitle>
          </CardHeader>
          <CardBody className="space-y-1">
            {data.top_findings.length === 0 ? (
              <NothingYet />
            ) : (
              data.top_findings.map((f) => {
                const ssvcOutcome = (
                  f.risk_factors?.ssvc as { outcome?: string } | undefined
                )?.outcome;
                return (
                  <Link
                    key={f.id}
                    href={`/findings/${f.id}`}
                    className="flex items-center gap-2 rounded-lg px-2 py-2 transition-colors hover:bg-surface-2"
                  >
                    <SeverityBadge severity={f.severity} />
                    <span
                      className="min-w-0 flex-1 truncate text-sm text-fg"
                      title={f.title}
                    >
                      {f.title}
                    </span>
                    {f.priority && <PriorityBadge priority={f.priority} />}
                    {ssvcOutcome && (
                      <SSVCBadge outcome={ssvcOutcome} showTooltip />
                    )}
                    <KevBadge inKev={f.in_kev} />
                  </Link>
                );
              })
            )}
          </CardBody>
        </Card>
      </div>

      {/* ── Activity + integration health ──────────────────────────────── */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Activity</CardTitle>
          </CardHeader>
          <CardBody className="space-y-1">
            {data.activity.length === 0 ? (
              <NothingYet />
            ) : (
              data.activity.map((ev) => (
                <div key={ev.id} className="flex items-start gap-3 px-2 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-fg">
                      <span className="font-medium">{ev.actor ?? ev.actor_type}</span>{" "}
                      <span className="text-muted">{ev.action}</span>
                    </p>
                    {ev.summary && (
                      <p className="truncate text-xs text-faint">{ev.summary}</p>
                    )}
                  </div>
                  <span className="shrink-0 text-xs text-faint">
                    {formatRelative(ev.at)}
                  </span>
                </div>
              ))
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Integration health</CardTitle>
          </CardHeader>
          <CardBody className="space-y-1">
            {data.integration_health.length === 0 ? (
              <NothingYet />
            ) : (
              data.integration_health.map((h) => (
                <div
                  key={h.kind}
                  className="flex items-center justify-between gap-3 px-2 py-2"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-sm text-fg">{humanize(h.kind)}</span>
                    {h.name && h.name !== h.kind && (
                      <span className="truncate text-xs text-faint">{h.name}</span>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {h.circuit_open && <Badge tone="danger">Circuit open</Badge>}
                    <Badge tone={INTEGRATION_TONE[h.status]}>{humanize(h.status)}</Badge>
                  </div>
                </div>
              ))
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { data, error, loading, refetch } = useApiResource(
    () => api.dashboard.get(),
    [],
    { refetchInterval: 30000 },
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Security posture at a glance" />
      {loading && !data ? (
        <LoadingState label="Loading dashboard…" />
      ) : error && !data ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : data ? (
        <DashboardBody data={data} />
      ) : null}
    </div>
  );
}
