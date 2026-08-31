"use client";

import Link from "next/link";
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
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { countLabel, formatNumber, formatRelative, humanize } from "@/lib/format";
import type { DashboardOut, IntegrationStatus, Priority, Severity } from "@/lib/types";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const PRIORITIES: readonly Priority[] = ["P1", "P2", "P3", "P4", "P5"];

/** FR-032: integration health status → Badge tone (subset of BadgeTone). */
const INTEGRATION_TONE: Record<IntegrationStatus, "ok" | "warn" | "danger" | "neutral"> = {
  configured: "ok",
  unverified: "warn",
  error: "danger",
  disabled: "neutral",
};

function StatCard({
  label,
  value,
  note,
}: {
  label: string;
  value: React.ReactNode;
  note?: string;
}) {
  return (
    <Card>
      <CardBody>
        <p className="text-xs font-medium uppercase tracking-wide text-muted">{label}</p>
        <p className="mt-2 text-2xl font-semibold tabular-nums text-fg">{value}</p>
        {note && <p className="mt-1 text-xs text-faint">{note}</p>}
      </CardBody>
    </Card>
  );
}

function NothingYet() {
  return <p className="px-2 py-2 text-sm text-muted">Nothing yet</p>;
}

function DashboardBody({ data }: { data: DashboardOut }) {
  const mttr = data.mean_time_to_remediate_days;

  return (
    <div className="space-y-6">
      {/* Top stat cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Active assessments" value={formatNumber(data.assessments_active)} />
        <StatCard
          label="Awaiting approval"
          value={formatNumber(data.assessments_awaiting_approval)}
        />
        <StatCard label="Open findings" value={formatNumber(data.findings_open)} />
        <StatCard label="Critical assets" value={formatNumber(data.assets_critical)} />
        <StatCard label="KEV findings" value={formatNumber(data.kev_findings)} note="confirmed" />
        <StatCard
          label="Mean time to remediate"
          value={mttr === null ? "—" : `${mttr.toFixed(1)}d`}
        />
      </div>

      {/* Severity + priority breakdowns */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Severity breakdown</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            {SEVERITIES.map((s) => (
              <div key={s} className="flex items-center justify-between gap-3">
                <SeverityBadge severity={s} />
                <span className="text-sm font-medium tabular-nums text-fg">
                  {formatNumber(data.severity_breakdown[s] ?? 0)}
                </span>
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Priority breakdown</CardTitle>
          </CardHeader>
          <CardBody className="space-y-2">
            {PRIORITIES.map((p) => (
              <div key={p} className="flex items-center justify-between gap-3">
                <PriorityBadge priority={p} />
                <span className="text-sm font-medium tabular-nums text-fg">
                  {formatNumber(data.priority_breakdown[p] ?? 0)}
                </span>
              </div>
            ))}
          </CardBody>
        </Card>
      </div>

      {/* Recent assessments + top findings */}
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
              data.top_findings.map((f) => (
                <div key={f.id} className="flex items-center gap-2 px-2 py-2">
                  <SeverityBadge severity={f.severity} />
                  <Link
                    href={`/findings/${f.id}`}
                    className="min-w-0 flex-1 truncate text-sm text-fg hover:text-primary hover:underline"
                  >
                    {f.title}
                  </Link>
                  {f.priority && <PriorityBadge priority={f.priority} />}
                  <KevBadge inKev={f.in_kev} />
                </div>
              ))
            )}
          </CardBody>
        </Card>
      </div>

      {/* Activity + integration health */}
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
                    {ev.summary && <p className="truncate text-xs text-faint">{ev.summary}</p>}
                  </div>
                  <span className="shrink-0 text-xs text-faint">{formatRelative(ev.at)}</span>
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
  const { data, error, loading, refetch } = useApiResource(() => api.dashboard.get(), [], {
    refetchInterval: 30000,
  });

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
