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
import { Button } from "@/components/ui/Button";
import { Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { AttackPathCard } from "@/components/ui/AttackPathCard";
import { RiskHeatmap, type HeatmapCell } from "@/components/ui/RiskHeatmap";
import { SSVCBadge } from "@/components/ui/SSVCBadge";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import {
  countLabel,
  formatNumber,
  formatRelative,
  humanize,
} from "@/lib/format";
import type {
  AssessmentDetailOut,
  DashboardOut,
  DashboardFindingOut,
  DashboardLayoutIn,
  DashboardLayoutOut,
  AssetGroupRiskOut,
  IntegrationStatus,
  Priority,
  Severity,
  TeamDashboardOut,
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

const DASHBOARD_WIDGETS = [
  ["posture", "Posture overview"],
  ["exposure_trend", "Exposure trend"],
  ["risk_heatmap", "Risk heatmap"],
  ["team_exposure", "Team exposure"],
  ["asset_group_risk", "Asset-group risk"],
  ["fix_first", "Fix-first remediation"],
  ["top_findings", "Top findings"],
  ["recent_assessments", "Recent assessments"],
  ["compliance", "Compliance"],
  ["integration_health", "Integration health"],
  ["activity", "Activity"],
  ["attack_paths", "Attack paths"],
] as const;

function DashboardLayoutBuilder({
  layouts,
  selectedLayout,
  onSelect,
  onChanged,
}: {
  layouts: DashboardLayoutOut[];
  selectedLayout: DashboardLayoutOut | undefined;
  onSelect: (id: string) => void;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [editing, setEditing] = React.useState(false);
  const [mode, setMode] = React.useState<"create" | "edit">("create");
  const [name, setName] = React.useState("");
  const [audience, setAudience] = React.useState<DashboardLayoutIn["audience"]>("technical");
  const [widgets, setWidgets] = React.useState<string[]>(["posture", "top_findings", "activity"]);
  const [isDefault, setIsDefault] = React.useState(false);

  const create = useMutation(api.dashboard.createLayout, {
    onSuccess: (layout) => {
      toast({ title: "Dashboard layout created", tone: "ok" });
      setEditing(false);
      onSelect(layout.id);
      onChanged();
    },
  });
  const update = useMutation(
    (body: DashboardLayoutIn) => selectedLayout ? api.dashboard.updateLayout(selectedLayout.id, body) : Promise.reject(new Error("Select a layout first")),
    {
      onSuccess: (layout) => {
        toast({ title: "Dashboard layout updated", tone: "ok" });
        setEditing(false);
        onSelect(layout.id);
        onChanged();
      },
    },
  );
  const remove = useMutation(api.dashboard.deleteLayout, {
    onSuccess: () => {
      toast({ title: "Dashboard layout deleted", tone: "ok" });
      setEditing(false);
      onSelect("all");
      onChanged();
    },
  });

  function beginCreate() {
    setName("");
    setAudience("technical");
    setWidgets(["posture", "top_findings", "activity"]);
    setIsDefault(false);
    setMode("create");
    setEditing(true);
  }

  function beginEdit() {
    if (!selectedLayout) return;
    setName(selectedLayout.name);
    setAudience(selectedLayout.audience);
    setWidgets(selectedLayout.widgets.map((widget) => widget.key));
    setIsDefault(selectedLayout.is_default);
    setMode("edit");
    setEditing(true);
  }

  function toggleWidget(key: string) {
    setWidgets((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key]);
  }

  function save(event: React.FormEvent) {
    event.preventDefault();
    const trimmedName = name.trim();
    if (trimmedName.length < 2) {
      toast({ title: "Layout name must contain at least two characters", tone: "danger" });
      return;
    }
    if (!widgets.length) {
      toast({ title: "Select at least one dashboard widget", tone: "danger" });
      return;
    }
    const body: DashboardLayoutIn = { name: trimmedName, audience, widgets, is_default: isDefault };
    if (mode === "edit" && selectedLayout) {
      void update.run(body);
    } else {
      void create.run(body);
    }
  }

  const isUpdating = mode === "edit";
  const pending = create.loading || update.loading || remove.loading;

  return <Card>
    <CardBody className="space-y-3 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-fg">Custom dashboard views</p>
          <p className="text-xs text-muted">Create role-focused, governed widget layouts. Layouts never change underlying access controls.</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={beginCreate}>New layout</Button>
          {selectedLayout && <Button size="sm" variant="outline" onClick={beginEdit}>Edit selected</Button>}
        </div>
      </div>
      {editing && <form onSubmit={save} className="grid gap-3 border-t border-line pt-3 md:grid-cols-2">
        <label className="text-xs font-medium text-muted">Layout name<Input value={name} onChange={(event) => setName(event.target.value)} maxLength={160} required /></label>
        <label className="text-xs font-medium text-muted">Audience<Select value={audience} onChange={(event) => setAudience(event.target.value as DashboardLayoutIn["audience"])}><option value="technical">Technical</option><option value="executive">Executive</option><option value="team">Team</option></Select></label>
        <fieldset className="md:col-span-2"><legend className="text-xs font-medium text-muted">Visible widgets</legend><div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{DASHBOARD_WIDGETS.map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm text-fg"><input type="checkbox" checked={widgets.includes(key)} onChange={() => toggleWidget(key)} />{label}</label>)}</div></fieldset>
        <label className="flex items-center gap-2 text-sm text-fg"><input type="checkbox" checked={isDefault} onChange={(event) => setIsDefault(event.target.checked)} />Use as the {audience} default</label>
        <div className="flex flex-wrap justify-end gap-2 md:col-span-2"><Button type="button" variant="ghost" onClick={() => setEditing(false)} disabled={pending}>Cancel</Button>{selectedLayout && <Button type="button" variant="danger" onClick={() => void remove.run(selectedLayout.id)} loading={remove.loading}>Delete</Button>}<Button type="submit" loading={create.loading || update.loading}>{isUpdating ? "Save layout" : "Create layout"}</Button></div>
      </form>}
      {layouts.length === 0 && !editing && <p className="text-sm text-muted">No saved layouts yet. Create one to tailor the dashboard for a security audience.</p>}
    </CardBody>
  </Card>;
}

/** Derive heatmap cells from the priority/severity breakdown. */
function buildHeatmapCells(
  findings: DashboardFindingOut[],
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
function computeSSVCSummary(findings: DashboardFindingOut[]): Record<string, number> {
  const counts: Record<string, number> = { act: 0, attend: 0, "track*": 0, track: 0 };
  for (const f of findings) {
    const ssvc = (f.risk_factors?.ssvc as { outcome?: string } | undefined)?.outcome;
    if (ssvc && ssvc in counts) counts[ssvc]++;
  }
  return counts;
}

function DashboardBody({ data }: { data: DashboardOut }) {
  const router = useRouter();
  const { can } = useAuth();
  const canManageLayouts = can("org:manage");
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
  const teams = useApiResource(
    () => api.dashboard.teams(),
    [],
    { refetchInterval: 30000 },
  );
  const assetGroups = useApiResource(
    () => api.dashboard.assetGroups(),
    [],
    { refetchInterval: 30000 },
  );
  const layouts = useApiResource(() => api.dashboard.layouts(), []);
  const [layoutId, setLayoutId] = React.useState("");
  const selectedLayout = layoutId === "all" ? undefined : (
    layouts.data?.find((layout) => layout.id === layoutId)
      ?? layouts.data?.find((layout) => layout.is_default)
  );
  const enabledWidgets = React.useMemo(
    () => new Set(selectedLayout?.widgets.map((widget) => widget.key) ?? []),
    [selectedLayout],
  );
  const show = (widget: string) => !selectedLayout || enabledWidgets.has(widget);
  const compliance = useApiResource(
    () => api.compliance.overview(),
    [],
    { enabled: show("compliance") },
  );
  const riskTrend = useApiResource(
    () => api.dashboard.riskTrend(),
    [],
    { refetchInterval: 30000 },
  );
  const remediation = useApiResource(
    () => api.canonicalFindings.operations({ limit: 5, attention_only: true }),
    [],
    { enabled: show("fix_first"), refetchInterval: 30000 },
  );
  const attackPaths: import("@/components/ui/AttackPathCard").AttackPathData[] =
    (assessmentDetail as AssessmentDetailOut & { extra_data?: Record<string, unknown> } | null)
      ?.extra_data?.["attack_paths"] as never ?? [];

  return (
    <div className="space-y-6">
      {layouts.data?.length ? <Card><CardBody className="flex flex-wrap items-center gap-3 py-3"><label htmlFor="dashboard-layout" className="text-sm font-medium">Dashboard layout</label><select id="dashboard-layout" value={layoutId || selectedLayout?.id || "all"} onChange={(event) => setLayoutId(event.target.value)} className="rounded-lg border border-line bg-surface px-3 py-2 text-sm text-fg"><option value="all">All widgets</option>{layouts.data.map((layout) => <option key={layout.id} value={layout.id}>{layout.name} · {humanize(layout.audience)}</option>)}</select><span className="text-xs text-muted">Saved layouts only control visibility; data permissions remain unchanged.</span></CardBody></Card> : null}
      {canManageLayouts && <DashboardLayoutBuilder layouts={layouts.data ?? []} selectedLayout={selectedLayout} onSelect={setLayoutId} onChanged={() => void layouts.refetch()} />}
      {/* ── Top stat strip ─────────────────────────────────────────────── */}
      {show("posture") && <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
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
      </div>}

      {show("posture") && <Link href="/findings?view=external" className="block">
        <div className="grid grid-cols-2 gap-4">
          <StatCard label="Actionable external alerts" value={formatNumber(data.external_alerts_actionable)}
            note="open at source, not locally closed or accepted" urgent={data.external_alerts_actionable > 0} />
          <StatCard label="Awaiting alert triage" value={formatNumber(data.external_alerts_awaiting_triage)}
            note="new alerts from connected tools" urgent={data.external_alerts_awaiting_triage > 0} />
        </div>
      </Link>}

      {show("exposure_trend") && <Card>
        <CardHeader>
          <CardTitle>Assessment exposure trend</CardTitle>
        </CardHeader>
        <CardBody>
          {riskTrend.loading && !riskTrend.data ? (
            <LoadingState label="Loading exposure trend…" />
          ) : riskTrend.error ? (
            <ErrorState message={riskTrend.error} onRetry={riskTrend.refetch} />
          ) : !riskTrend.data?.points.length ? (
            <p className="text-sm text-muted">Complete at least two assessments to build an immutable exposure trend.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex h-32 items-end gap-1.5" aria-label="Exposure score by completed assessment">
                {riskTrend.data.points.map((point) => (
                  <Link
                    key={point.assessment_id}
                    href={`/assessments/${point.assessment_id}`}
                    title={`Assessment #${point.assessment_reference ?? "—"}: ${point.exposure_score.toFixed(1)} exposure score`}
                    className="group flex min-w-0 flex-1 flex-col justify-end"
                  >
                    <span className="mb-1 text-center text-[10px] tabular-nums text-faint opacity-0 transition-opacity group-hover:opacity-100">{point.exposure_score.toFixed(0)}</span>
                    <span
                      className={`block rounded-t transition-opacity group-hover:opacity-75 ${point.exposure_score >= 70 ? "bg-red-600" : point.exposure_score >= 40 ? "bg-orange-500" : "bg-primary"}`}
                      style={{ height: `${Math.max(6, point.exposure_score)}%` }}
                    />
                  </Link>
                ))}
              </div>
              <div className="flex items-center justify-between gap-3 text-xs text-muted">
                <span>{formatRelative(riskTrend.data.points[0].measured_at)}</span>
                <span>Each bar is a frozen completed-assessment report snapshot.</span>
                <span>{formatRelative(riskTrend.data.points[riskTrend.data.points.length - 1].measured_at)}</span>
              </div>
            </div>
          )}
        </CardBody>
      </Card>}

      {/* ── SSVC urgency strip ─────────────────────────────────────────── */}
      {show("posture") && Object.values(ssvcSummary).some((v) => v > 0) && (
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
      {show("risk_heatmap") && <div className="grid gap-6 lg:grid-cols-3">
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
      </div>}

      {/* ── Attack paths ───────────────────────────────────────────────── */}
      {show("attack_paths") && attackPaths.length > 0 && (
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

      {/* ── Team exposure ─────────────────────────────────────────────── */}
      {show("team_exposure") && <Card>
        <CardHeader>
          <CardTitle>Team exposure</CardTitle>
        </CardHeader>
        <CardBody>
          {teams.loading && !teams.data ? (
            <LoadingState label="Loading team exposure…" />
          ) : teams.error ? (
            <ErrorState message={teams.error} onRetry={teams.refetch} />
          ) : !teams.data?.length ? (
            <p className="text-sm text-muted">No assets have an owner team yet. Import CMDB ownership or set business context on assets to enable team dashboards.</p>
          ) : (
            <TeamExposureTable teams={teams.data} />
          )}
        </CardBody>
      </Card>}

      {show("asset_group_risk") && <Card>
        <CardHeader><CardTitle>Asset-group risk</CardTitle></CardHeader>
        <CardBody>
          {assetGroups.loading && !assetGroups.data ? (
            <LoadingState label="Loading asset-group risk…" />
          ) : assetGroups.error ? (
            <ErrorState message={assetGroups.error} onRetry={assetGroups.refetch} />
          ) : !assetGroups.data?.length ? (
            <p className="text-sm text-muted">Add groups to assets, such as Payments or Customer API, to see business-service exposure here.</p>
          ) : (
            <AssetGroupRiskTable groups={assetGroups.data} />
          )}
        </CardBody>
      </Card>}

      {show("compliance") && <Card>
        <CardHeader><CardTitle>Compliance coverage</CardTitle></CardHeader>
        <CardBody>
          {compliance.loading && !compliance.data ? <LoadingState label="Loading compliance coverage…" /> : compliance.error ? <ErrorState message={compliance.error} onRetry={compliance.refetch} /> : !compliance.data?.frameworks.length ? <p className="text-sm text-muted">No compliance frameworks are active. Activate a framework to map evidence-backed controls.</p> : <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{compliance.data.frameworks.map((framework) => <Link key={framework.framework} href="/compliance" className="rounded-lg border border-line p-3 transition-colors hover:bg-surface-2"><div className="flex items-center justify-between gap-3"><span className="font-medium text-fg">{humanize(framework.framework)}</span><Badge tone={framework.at_risk_control_count ? "danger" : "ok"}>{framework.coverage_percent.toFixed(0)}% mapped</Badge></div><p className="mt-2 text-xs text-muted">{framework.control_count} controls · {framework.active_finding_count} active finding links</p><p className="mt-1 text-xs text-faint">{framework.at_risk_control_count} at risk · {framework.partially_satisfied_control_count} partial</p></Link>)}</div>}
        </CardBody>
      </Card>}

      {show("fix_first") && <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3"><CardTitle>Fix first</CardTitle><Link href="/remediation" className="text-sm text-primary hover:underline">Open remediation queue</Link></div>
        </CardHeader>
        <CardBody className="space-y-2">
          {remediation.loading && !remediation.data ? <LoadingState label="Loading prioritized remediation…" /> : remediation.error ? <ErrorState message={remediation.error} onRetry={remediation.refetch} /> : !remediation.data?.items.length ? <p className="text-sm text-muted">No active canonical findings need remediation.</p> : remediation.data.items.map((operation) => (
            <Link key={operation.finding.id} href={`/findings/canonical/${operation.finding.id}`} className="block rounded-lg border border-line px-3 py-2 transition-colors hover:bg-surface-2">
              <div className="flex flex-wrap items-center gap-2"><span className="font-semibold tabular-nums text-fg">{operation.finding.risk_score.toFixed(1)}</span><SeverityBadge severity={operation.finding.severity} /><span className="min-w-0 flex-1 truncate text-sm font-medium text-fg" title={operation.finding.title}>{operation.finding.title}</span><Badge tone="primary">{operation.next_action}</Badge></div>
              <p className="mt-1 truncate text-xs text-muted">{operation.priority_reasons?.[0] ?? "Composite risk score is the current prioritization signal."}</p>
            </Link>
          ))}
        </CardBody>
      </Card>}

      {/* ── Recent assessments + top findings ──────────────────────────── */}
      {(show("recent_assessments") || show("top_findings")) && <div className="grid gap-6 lg:grid-cols-2">
        {show("recent_assessments") && <Card>
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
        </Card>}

        {show("top_findings") && <Card>
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
                    href={
                      f.source_kind === "canonical"
                        ? `/findings/canonical/${f.id}`
                        : `/findings/${f.id}`
                    }
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
        </Card>}
      </div>}

      {/* ── Activity + integration health ──────────────────────────────── */}
      {(show("activity") || show("integration_health")) && <div className="grid gap-6 lg:grid-cols-2">
        {show("activity") && <Card>
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
        </Card>}

        {show("integration_health") && <Card>
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
                    <div className="min-w-0">
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="truncate text-sm text-fg">{humanize(h.kind)}</span>
                        {h.name && h.name !== h.kind && (
                          <span className="truncate text-xs text-faint">{h.name}</span>
                        )}
                      </div>
                      {h.sync_interval_minutes && (
                        <p className="text-xs text-faint">
                          Sync every {h.sync_interval_minutes} min · last {formatRelative(h.last_sync_at)}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {h.circuit_open && <Badge tone="danger">Circuit open</Badge>}
                    {h.last_sync_status === "failed" && <Badge tone="danger">Sync failed</Badge>}
                    <Badge tone={INTEGRATION_TONE[h.status]}>{humanize(h.status)}</Badge>
                  </div>
                </div>
              ))
            )}
          </CardBody>
        </Card>}
      </div>}
    </div>
  );
}

function TeamExposureTable({ teams }: { teams: TeamDashboardOut[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[42rem] text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr><th className="px-2 py-2 font-medium">Team</th><th className="px-2 py-2 font-medium">Assets</th><th className="px-2 py-2 font-medium">Open</th><th className="px-2 py-2 font-medium">Critical / high</th><th className="px-2 py-2 font-medium">KEV</th><th className="px-2 py-2 font-medium text-right">Top risk</th></tr>
        </thead>
        <tbody>
          {teams.map((team) => (
            <tr key={team.team_name} className="border-b border-line/60 last:border-0">
              <td className="px-2 py-2 font-medium text-fg">{team.team_name}</td>
              <td className="px-2 py-2 text-muted">{team.assets_total} <span className="text-faint">({team.assets_critical} critical)</span></td>
              <td className="px-2 py-2 text-fg">{team.findings_open}</td>
              <td className="px-2 py-2 text-fg">{team.severity_breakdown.critical ?? 0} / {team.severity_breakdown.high ?? 0}</td>
              <td className="px-2 py-2">{team.kev_findings ? <Badge tone="danger">{team.kev_findings}</Badge> : <span className="text-muted">—</span>}</td>
              <td className="px-2 py-2 text-right font-medium tabular-nums text-fg">{team.highest_risk_score === null ? "—" : `${team.highest_risk_score.toFixed(0)}/100`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AssetGroupRiskTable({ groups }: { groups: AssetGroupRiskOut[] }) {
  return <div className="overflow-x-auto"><table className="w-full min-w-[42rem] text-left text-sm"><thead className="border-b border-line text-xs uppercase tracking-wide text-muted"><tr><th className="px-2 py-2 font-medium">Asset group</th><th className="px-2 py-2 font-medium">Assets</th><th className="px-2 py-2 font-medium">Internet-facing</th><th className="px-2 py-2 font-medium">Open</th><th className="px-2 py-2 font-medium">Critical / high</th><th className="px-2 py-2 font-medium text-right">Exposure score</th></tr></thead><tbody>{groups.map((group) => <tr key={group.group_name} className="border-b border-line/60 last:border-0"><td className="px-2 py-2 font-medium text-fg">{group.group_name}</td><td className="px-2 py-2 text-muted">{group.assets_total}</td><td className="px-2 py-2">{group.internet_exposed_assets ? <Badge tone="warn">{group.internet_exposed_assets}</Badge> : <span className="text-muted">—</span>}</td><td className="px-2 py-2 text-fg">{group.findings_open}</td><td className="px-2 py-2">{group.critical_or_high_findings ? <Badge tone="danger">{group.critical_or_high_findings}</Badge> : <span className="text-muted">—</span>}</td><td className="px-2 py-2 text-right"><span className="font-medium tabular-nums text-fg">{group.aggregate_risk_score.toFixed(0)}</span>{group.highest_risk_score !== null && <span className="ml-2 text-xs text-muted">top {group.highest_risk_score.toFixed(0)}</span>}</td></tr>)}</tbody></table></div>;
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
