"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";

import { AssessmentStatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, THead, TD, TH, TR, Table } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatNumber, formatRelative, humanize } from "@/lib/format";
import type { AssessmentDepth, AssessmentStatus, RecurringScanCreateIn, ScanProfileCreateIn, Scope } from "@/lib/types";

const PAGE_SIZE = 25;

// Inline enum option lists (kept local — no shared file may be touched). Order mirrors
// the AssessmentStatus / Scope unions in types.ts; labels come from humanize().
const STATUS_OPTIONS: readonly AssessmentStatus[] = [
  "CREATED",
  "PLANNING",
  "DISCOVERY",
  "WAITING_FOR_APPROVAL",
  "SCANNING",
  "ANALYZING",
  "REMEDIATING",
  "COMPLETED",
  "FAILED",
  "CANCELLING",
  "CANCELLED",
];

const SCOPE_OPTIONS: readonly Scope[] = ["external", "internal", "application", "code"];

export default function AssessmentsPage() {
  const router = useRouter();
  const { can } = useAuth();
  const { toast } = useToast();
  const canRead = can("assessment:read");
  const canCreate = can("assessment:create");

  const [q, setQ] = React.useState("");
  const debouncedQ = useDebouncedValue(q);
  const [status, setStatus] = React.useState<AssessmentStatus | "">("");
  const [scope, setScope] = React.useState<Scope | "">("");
  const [activeOnly, setActiveOnly] = React.useState(false);
  const [awaitingApproval, setAwaitingApproval] = React.useState(false);
  const [offset, setOffset] = React.useState(0);
  const [showProfile, setShowProfile] = React.useState(false);
  const [showSchedule, setShowSchedule] = React.useState(false);
  const [profile, setProfile] = React.useState<ScanProfileCreateIn>({ name: "", scope: "external", depth: "standard", engagement_type: "web_application", execution_mode: "supervised", objective: "", notify: [] });
  const [scheduleName, setScheduleName] = React.useState("");
  const [scheduleProfileId, setScheduleProfileId] = React.useState("");
  const [scheduleTargets, setScheduleTargets] = React.useState("");
  const [scheduleCron, setScheduleCron] = React.useState("0 2 * * 1");
  const [scheduleAuthorization, setScheduleAuthorization] = React.useState("");
  const [scheduleEvidence, setScheduleEvidence] = React.useState("");
  const [scheduleExpiresAt, setScheduleExpiresAt] = React.useState("");

  const trimmedQ = debouncedQ.trim();

  const { data, error, loading, refetch } = useApiResource(
    () =>
      api.assessments.list({
        limit: PAGE_SIZE,
        offset,
        q: trimmedQ || undefined,
        status: status || undefined,
        scope: scope || undefined,
        active: activeOnly || undefined,
        awaiting_approval: awaitingApproval || undefined,
      }),
    [trimmedQ, status, scope, activeOnly, awaitingApproval, offset],
    { enabled: canRead },
  );
  const schedules = useApiResource(() => api.assessments.schedules(), [], { enabled: canRead });
  const profiles = useApiResource(() => api.assessments.profiles(), [], { enabled: canRead });
  const createProfile = useMutation(api.assessments.createProfile, { onSuccess: () => { toast({ title: "Scan profile created", tone: "ok" }); setShowProfile(false); setProfile({ name: "", scope: "external", depth: "standard", engagement_type: "web_application", execution_mode: "supervised", objective: "", notify: [] }); void profiles.refetch(); } });
  const deactivateProfile = useMutation(api.assessments.deactivateProfile, { onSuccess: () => { toast({ title: "Profile retired and dependent schedules paused", tone: "ok" }); void profiles.refetch(); void schedules.refetch(); } });
  const createSchedule = useMutation(api.assessments.createSchedule, { onSuccess: () => { toast({ title: "Recurring scan scheduled", tone: "ok" }); setShowSchedule(false); setScheduleName(""); setScheduleTargets(""); setScheduleAuthorization(""); setScheduleEvidence(""); setScheduleExpiresAt(""); void schedules.refetch(); } });
  const scheduleToggle = useMutation(
    ({ id, resume }: { id: string; resume: boolean }) => resume ? api.assessments.resumeSchedule(id) : api.assessments.pauseSchedule(id),
    { onSuccess: () => { toast({ title: "Recurring scan schedule updated", tone: "ok" }); void schedules.refetch(); } },
  );

  if (!canRead) {
    return (
      <EmptyState
        title="No access"
        description="You don't have permission to view this."
      />
    );
  }

  const hasFilters = Boolean(trimmedQ || status || scope || activeOnly || awaitingApproval);

  function submitSchedule(event: React.FormEvent) {
    event.preventDefault();
    if (!scheduleProfileId) return;
    const targets = scheduleTargets.split(/\r?\n/).map((target) => target.trim()).filter(Boolean);
    const body: RecurringScanCreateIn = {
      name: scheduleName.trim(),
      profile_id: scheduleProfileId,
      targets,
      cron_expression: scheduleCron.trim(),
      timezone: "UTC",
      authorization: { confirmed: true, attestation_text: scheduleAuthorization.trim(), evidence_reference: scheduleEvidence.trim() || null },
      authorization_expires_at: `${scheduleExpiresAt}Z`,
    };
    void createSchedule.run(body);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Assessments"
        description="Natural-language security assessments and their progress."
        actions={
          canCreate ? (
            <div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => setShowProfile(true)}>New scan profile</Button><Button variant="outline" onClick={() => setShowSchedule(true)}>Schedule scan</Button><Link href="/assessments/new"><Button>New assessment</Button></Link></div>
          ) : undefined
        }
      />

      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
        <Input
          type="search"
          aria-label="Search assessments"
          placeholder="Search assessments…"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOffset(0);
          }}
          className="sm:w-64"
        />
        <Select
          aria-label="Filter by status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value as AssessmentStatus | "");
            setOffset(0);
          }}
          className="sm:w-52"
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((value) => (
            <option key={value} value={value}>
              {humanize(value)}
            </option>
          ))}
        </Select>
        <Select
          aria-label="Filter by scope"
          value={scope}
          onChange={(e) => {
            setScope(e.target.value as Scope | "");
            setOffset(0);
          }}
          className="sm:w-44"
        >
          <option value="">All scopes</option>
          {SCOPE_OPTIONS.map((value) => (
            <option key={value} value={value}>
              {humanize(value)}
            </option>
          ))}
        </Select>
        <label className="flex items-center gap-2 text-sm text-muted">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => {
              setActiveOnly(e.target.checked);
              setOffset(0);
            }}
            className="h-4 w-4 rounded border-line bg-surface-2 accent-primary"
          />
          Active only
        </label>
        <label className="flex items-center gap-2 text-sm text-muted">
          <input
            type="checkbox"
            checked={awaitingApproval}
            onChange={(e) => {
              setAwaitingApproval(e.target.checked);
              setOffset(0);
            }}
            className="h-4 w-4 rounded border-line bg-surface-2 accent-primary"
          />
          Awaiting approval
        </label>
      </div>

      <Card>
        <CardHeader><CardTitle>Recurring scan schedules</CardTitle></CardHeader>
        <CardBody>
          {schedules.loading && !schedules.data ? <LoadingState label="Loading recurring schedules…" /> : schedules.error ? <ErrorState message={schedules.error} onRetry={schedules.refetch} /> : !schedules.data?.length ? <p className="text-sm text-muted">No recurring scans configured.</p> : <div className="space-y-2">{schedules.data.map((schedule) => <div key={schedule.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3"><div><p className="text-sm font-medium text-fg">{schedule.name}</p><p className="text-xs text-muted">{schedule.targets.length} target{schedule.targets.length === 1 ? "" : "s"} · {schedule.cron_expression} {schedule.timezone} · next {formatDateTime(schedule.next_run_at)}</p>{schedule.last_error_code && <p className="mt-1 text-xs text-danger">Last scheduler state: {humanize(schedule.last_error_code)}</p>}</div>{canCreate && <Button size="sm" variant="outline" loading={scheduleToggle.loading} onClick={() => void scheduleToggle.run({ id: schedule.id, resume: !schedule.enabled })}>{schedule.enabled ? "Pause" : "Resume"}</Button>}</div>)}</div>}
        </CardBody>
      </Card>

      <Card>
        <CardHeader><CardTitle>Scan profiles</CardTitle></CardHeader>
        <CardBody>
          {profiles.loading && !profiles.data ? <LoadingState label="Loading scan profiles…" /> : profiles.error ? <ErrorState message={profiles.error} onRetry={profiles.refetch} /> : !profiles.data?.length ? <p className="text-sm text-muted">No scan profiles configured.</p> : <div className="space-y-2">{profiles.data.map((item) => <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3"><div><p className="text-sm font-medium text-fg">{item.name}</p><p className="text-xs text-muted">{humanize(String(item.config.scope ?? "external"))} · {humanize(String(item.config.depth ?? "standard"))} · {item.is_active ? "Available for scheduling" : "Retired"}</p></div>{canCreate && item.is_active && <Button size="sm" variant="outline" loading={deactivateProfile.loading} onClick={() => void deactivateProfile.run(item.id)}>Retire profile</Button>}</div>)}</div>}
          {deactivateProfile.errorMessage && <p role="alert" className="mt-3 text-sm text-danger">{deactivateProfile.errorMessage}</p>}
        </CardBody>
      </Card>

      {loading && !data ? (
        <LoadingState label="Loading assessments…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No assessments"
          description={
            hasFilters
              ? "No assessments match the current filters."
              : "Start a new assessment to begin a security review."
          }
          action={
            !hasFilters && canCreate ? (
              <Link href="/assessments/new">
                <Button>New assessment</Button>
              </Link>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH>Ref</TH>
                <TH>Title</TH>
                <TH>Status</TH>
                <TH>Scope</TH>
                <TH>Findings</TH>
                <TH>Progress</TH>
                <TH>Created</TH>
              </TR>
            </THead>
            <TBody>
              {data.items.map((a) => {
                const pct = Math.max(0, Math.min(100, a.progress_percent));
                return (
                  <TR
                    key={a.id}
                    clickable
                    onClick={() => router.push(`/assessments/${a.id}`)}
                  >
                    <TD className="whitespace-nowrap tabular-nums text-muted">
                      #{a.reference}
                    </TD>
                    <TD className="max-w-xs truncate font-medium text-fg">{a.title}</TD>
                    <TD>
                      <AssessmentStatusBadge status={a.status} />
                    </TD>
                    <TD className="text-muted">{humanize(a.scope)}</TD>
                    <TD>
                      <div className="flex items-center gap-2">
                        <span className="tabular-nums">{formatNumber(a.findings_total)}</span>
                        {a.findings_critical > 0 && (
                          <span className="text-xs font-medium tabular-nums text-sev-critical">
                            C:{a.findings_critical}
                          </span>
                        )}
                        {a.findings_high > 0 && (
                          <span className="text-xs font-medium tabular-nums text-sev-high">
                            H:{a.findings_high}
                          </span>
                        )}
                      </div>
                    </TD>
                    <TD>
                      <div className="flex items-center gap-2">
                        <div
                          className="h-1.5 w-24 overflow-hidden rounded-full bg-surface-2"
                          role="progressbar"
                          aria-valuenow={pct}
                          aria-valuemin={0}
                          aria-valuemax={100}
                        >
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="tabular-nums text-xs text-muted">{pct}%</span>
                      </div>
                    </TD>
                    <TD className="whitespace-nowrap text-muted">
                      {formatRelative(a.created_at)}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>

          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </div>
      )}

      {showProfile && <Modal title="New scan profile" onClose={() => setShowProfile(false)}><form onSubmit={(event) => { event.preventDefault(); void createProfile.run(profile); }} className="space-y-4"><Field label="Profile name" htmlFor="scan-profile-name"><Input id="scan-profile-name" required maxLength={160} value={profile.name} onChange={(event) => setProfile((current) => ({ ...current, name: event.target.value }))} /></Field><div className="grid gap-3 sm:grid-cols-2"><Field label="Scope" htmlFor="scan-profile-scope"><Select id="scan-profile-scope" value={profile.scope} onChange={(event) => setProfile((current) => ({ ...current, scope: event.target.value as Scope }))}>{SCOPE_OPTIONS.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</Select></Field><Field label="Depth" htmlFor="scan-profile-depth"><Select id="scan-profile-depth" value={profile.depth} onChange={(event) => setProfile((current) => ({ ...current, depth: event.target.value as AssessmentDepth }))}><option value="passive">Passive</option><option value="standard">Standard</option><option value="deep">Deep</option></Select></Field></div><Field label="Objective (optional)" htmlFor="scan-profile-objective"><Textarea id="scan-profile-objective" maxLength={4000} value={profile.objective ?? ""} onChange={(event) => setProfile((current) => ({ ...current, objective: event.target.value || null }))} /></Field>{createProfile.errorMessage && <p role="alert" className="text-sm text-danger">{createProfile.errorMessage}</p>}<div className="flex justify-end gap-3"><Button type="button" variant="ghost" onClick={() => setShowProfile(false)}>Cancel</Button><Button type="submit" loading={createProfile.loading}>Create profile</Button></div></form></Modal>}

      {showSchedule && <Modal title="Schedule recurring scan" onClose={() => setShowSchedule(false)}><form onSubmit={submitSchedule} className="space-y-4"><Field label="Schedule name" htmlFor="recurring-scan-name"><Input id="recurring-scan-name" required maxLength={160} value={scheduleName} onChange={(event) => setScheduleName(event.target.value)} /></Field><Field label="Scan profile" htmlFor="recurring-scan-profile" hint="Profiles define the bounded scan type and execution mode."><Select id="recurring-scan-profile" required value={scheduleProfileId} onChange={(event) => setScheduleProfileId(event.target.value)}><option value="">Select a profile…</option>{profiles.data?.filter((item) => item.is_active).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field><Field label="Targets (one per line)" htmlFor="recurring-scan-targets"><Textarea id="recurring-scan-targets" required value={scheduleTargets} onChange={(event) => setScheduleTargets(event.target.value)} placeholder={"app.example.com\napi.example.com"} /></Field><div className="grid gap-3 sm:grid-cols-2"><Field label="Cron schedule (UTC)" htmlFor="recurring-scan-cron"><Input id="recurring-scan-cron" required maxLength={120} value={scheduleCron} onChange={(event) => setScheduleCron(event.target.value)} /></Field><Field label="Authorization expires" htmlFor="recurring-scan-expires"><Input id="recurring-scan-expires" required type="datetime-local" value={scheduleExpiresAt} onChange={(event) => setScheduleExpiresAt(event.target.value)} /></Field></div><Field label="Authorization statement" htmlFor="recurring-scan-auth"><Textarea id="recurring-scan-auth" required maxLength={4000} value={scheduleAuthorization} onChange={(event) => setScheduleAuthorization(event.target.value)} placeholder="I confirm written authority to test these targets on this schedule…" /></Field><Field label="Authorization evidence (optional)" htmlFor="recurring-scan-evidence"><Input id="recurring-scan-evidence" maxLength={1024} value={scheduleEvidence} onChange={(event) => setScheduleEvidence(event.target.value)} placeholder="ENG-123 or scope document URL" /></Field>{createSchedule.errorMessage && <p role="alert" className="text-sm text-danger">{createSchedule.errorMessage}</p>}<div className="flex justify-end gap-3"><Button type="button" variant="ghost" onClick={() => setShowSchedule(false)}>Cancel</Button><Button type="submit" loading={createSchedule.loading} disabled={!profiles.data?.some((item) => item.is_active)}>Create schedule</Button></div></form></Modal>}
    </div>
  );
}
