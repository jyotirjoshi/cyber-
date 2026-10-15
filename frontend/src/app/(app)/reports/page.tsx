"use client";

import * as React from "react";
import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api, reportShareUrl, saveBlob } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, formatBytes, humanize } from "@/lib/format";
import type { AssessmentOut, ReportScheduleCreateIn, ReportShareIssuedOut, ReportStatus } from "@/lib/types";

const PAGE_SIZE = 25;

function defaultShareExpiry(): string {
  return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 16);
}

const STATUS_TONE: Record<ReportStatus, "ok" | "warn" | "danger" | "neutral"> = {
  pending: "neutral",
  generating: "warn",
  ready: "ok",
  failed: "danger",
};

export default function ReportsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canGenerate = can("report:generate");
  const canRead = can("report:read");

  const [offset, setOffset] = React.useState(0);
  const [selectedAssessmentId, setSelectedAssessmentId] = React.useState("");
  const [reportFormat, setReportFormat] = React.useState<"pdf" | "html" | "json">("pdf");
  const [reportAudience, setReportAudience] = React.useState<"executive" | "technical">("executive");
  const [reportTitle, setReportTitle] = React.useState("");
  const [templateId, setTemplateId] = React.useState("");
  const [scheduleName, setScheduleName] = React.useState("");
  const [scheduleTitle, setScheduleTitle] = React.useState("");
  const [scheduleCron, setScheduleCron] = React.useState("0 9 * * 1");
  const [scheduleTimezone, setScheduleTimezone] = React.useState("UTC");
  const [scheduleRecipients, setScheduleRecipients] = React.useState("");
  const [scheduleFormat, setScheduleFormat] = React.useState<"pdf" | "html" | "json">("pdf");
  const [scheduleAudience, setScheduleAudience] = React.useState<"executive" | "technical">("executive");
  const [shareReportId, setShareReportId] = React.useState<string | null>(null);
  const [shareExpiresAt, setShareExpiresAt] = React.useState(defaultShareExpiry);
  const [issuedShare, setIssuedShare] = React.useState<ReportShareIssuedOut | null>(null);

  // Load recent assessments for the generate dropdown
  const assessmentsRes = useApiResource(
    () => api.assessments.list({ limit: 50, sort_by: "created_at", sort_dir: "desc" }),
    [],
    { enabled: canGenerate },
  );

  // Load reports for the selected assessment, or all recent reports
  const reportsRes = useApiResource(
    () =>
      selectedAssessmentId
        ? api.assessments.reports(selectedAssessmentId)
        : Promise.resolve([] as Awaited<ReturnType<typeof api.assessments.reports>>),
    [selectedAssessmentId],
    { enabled: canRead },
  );
  const recentReportsRes = useApiResource(
    () => api.reports.list({ limit: PAGE_SIZE, offset }),
    [offset],
    { enabled: canRead && !selectedAssessmentId },
  );
  const schedulesRes = useApiResource(() => api.reports.schedules(), [], { enabled: canRead });
  const templatesRes = useApiResource(() => api.reports.templates(), [], { enabled: canRead });
  const shareLinksRes = useApiResource(
    () => shareReportId ? api.reports.shareLinks(shareReportId) : Promise.resolve([] as Awaited<ReturnType<typeof api.reports.shareLinks>>),
    [shareReportId],
    { enabled: canGenerate && !!shareReportId },
  );

  const generateMut = useMutation(
    ({ assessmentId, title }: { assessmentId: string; title?: string }) =>
      api.assessments.generateReport(assessmentId, { format: reportFormat, audience: reportAudience, title, template_id: templateId || null }),
    {
      onSuccess: () => {
        toast({ title: "Report generation started", tone: "ok" });
        void reportsRes.refetch();
      },
    },
  );

  const downloadMut = useMutation(
    (id: string) => api.reports.download(id),
    {
      onSuccess: (file) => {
        saveBlob(file);
      },
      onError: (e) => toast({ title: "Download failed", description: String(e), tone: "danger" }),
    },
  );
  const createScheduleMut = useMutation(
    (body: ReportScheduleCreateIn) => api.reports.createSchedule(body),
    {
      onSuccess: () => {
        toast({ title: "Scheduled report created", tone: "ok" });
        setScheduleName("");
        setScheduleTitle("");
        setScheduleTimezone("UTC");
        setScheduleRecipients("");
        void schedulesRes.refetch();
      },
    },
  );
  const toggleScheduleMut = useMutation(
    ({ id, resume }: { id: string; resume: boolean }) => resume ? api.reports.resumeSchedule(id) : api.reports.pauseSchedule(id),
    { onSuccess: () => { toast({ title: "Report schedule updated", tone: "ok" }); void schedulesRes.refetch(); } },
  );
  const shareMut = useMutation(
    (reportId: string) => api.reports.createShareLink(reportId, { expires_at: new Date(shareExpiresAt).toISOString() }),
    {
      onSuccess: (issued) => {
        setIssuedShare(issued);
        toast({ title: "Expiring report link created", tone: "ok" });
        void shareLinksRes.refetch();
      },
    },
  );
  const revokeShareMut = useMutation(
    (shareLinkId: string) => api.reports.revokeShareLink(shareLinkId),
    { onSuccess: () => { toast({ title: "Report link revoked", tone: "ok" }); void shareLinksRes.refetch(); } },
  );

  function createSchedule(event: React.FormEvent) {
    event.preventDefault();
    if (!selectedAssessmentId) return;
    const recipients = scheduleRecipients.split(",").map((value) => value.trim()).filter(Boolean);
    void createScheduleMut.run({
      name: scheduleName.trim(),
      assessment_id: selectedAssessmentId,
      title: scheduleTitle.trim() || undefined,
      cron_expression: scheduleCron.trim(),
      timezone: scheduleTimezone.trim() || "UTC",
      recipients,
      format: scheduleFormat,
      audience: scheduleAudience,
      template_id: templateId || null,
    });
  }

  if (!canRead) {
    return (
      <div className="space-y-6">
        <PageHeader title="Reports" />
        <EmptyState title="No access" description="You don't have permission to view reports." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="Board-ready reports generated automatically after every completed assessment."
        action={<div className="flex gap-2"><Link href="/reports/templates"><Button variant="ghost">Templates</Button></Link><Link href="/reports/portfolio"><Button variant="ghost">Portfolio</Button></Link></div>}
      />

      <Card>
        <CardBody className="space-y-4">
          <div className="flex flex-wrap items-end gap-4">
            <Field label="Assessment" htmlFor="rp-assessment" className="flex-1 min-w-[260px]">
              <Select
                id="rp-assessment"
                value={selectedAssessmentId}
                onChange={(e) => setSelectedAssessmentId(e.target.value)}
              >
                <option value="">Select an assessment…</option>
                {(assessmentsRes.data?.items ?? []).map((a: AssessmentOut) => (
                  <option key={a.id} value={a.id}>
                    #{a.reference} — {a.title}
                  </option>
                ))}
              </Select>
            </Field>

            {canGenerate && <Field label="Report title (optional)" htmlFor="rp-title" className="min-w-[240px] flex-1"><Input id="rp-title" maxLength={300} value={reportTitle} onChange={(event) => setReportTitle(event.target.value)} placeholder="Q4 executive exposure review" /></Field>}
            {canGenerate && <Field label="Artifact" htmlFor="rp-format"><Select id="rp-format" value={reportFormat} onChange={(event) => setReportFormat(event.target.value as "pdf" | "html" | "json")}><option value="pdf">PDF</option><option value="html">HTML</option><option value="json">JSON</option></Select></Field>}
            {canGenerate && <Field label="Template" htmlFor="rp-template"><Select id="rp-template" value={templateId} onChange={(event) => setTemplateId(event.target.value)}><option value="">Standard report</option>{(templatesRes.data ?? []).filter((template) => template.is_active).map((template) => <option key={template.id} value={template.id}>{template.name} v{template.version}</option>)}</Select></Field>}
            {canGenerate && <Field label="Audience" htmlFor="rp-audience"><Select id="rp-audience" value={reportAudience} onChange={(event) => setReportAudience(event.target.value as "executive" | "technical")}><option value="executive">Executive</option><option value="technical">Technical</option></Select></Field>}

            {canGenerate && selectedAssessmentId && (
              <Button
                onClick={() => void generateMut.run({ assessmentId: selectedAssessmentId, title: reportTitle.trim() || undefined })}
                loading={generateMut.loading}
              >
                Generate report
              </Button>
            )}
          </div>
        </CardBody>
      </Card>

      {shareReportId && <Card>
        <CardBody className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-sm font-semibold text-fg">Share a ready report</h2><p className="text-xs text-muted">Creates a revocable public download link for this report. The secret link is shown only after it is issued.</p></div><Button size="sm" variant="ghost" onClick={() => { setShareReportId(null); setIssuedShare(null); }}>Cancel</Button></div>
          <div className="flex flex-wrap items-end gap-3"><Field label="Link expires" htmlFor="report-share-expires"><Input id="report-share-expires" type="datetime-local" required value={shareExpiresAt} onChange={(event) => setShareExpiresAt(event.target.value)} /></Field><Button loading={shareMut.loading} onClick={() => void shareMut.run(shareReportId)} disabled={!shareExpiresAt}>Create share link</Button></div>
          {shareMut.errorMessage && <p role="alert" className="text-sm text-danger">{shareMut.errorMessage}</p>}
          {issuedShare && <div className="rounded-lg border border-ok/40 bg-ok/10 p-3 text-sm"><p className="font-medium text-fg">Link created · expires {formatDateTime(issuedShare.expires_at)}</p><a href={reportShareUrl(issuedShare.token)} target="_blank" rel="noreferrer" className="mt-2 block break-all text-primary hover:underline">{reportShareUrl(issuedShare.token)}</a></div>}
          {shareLinksRes.loading && !shareLinksRes.data ? <LoadingState label="Loading issued links…" /> : shareLinksRes.error ? <ErrorState message={shareLinksRes.error} onRetry={shareLinksRes.refetch} /> : shareLinksRes.data?.length ? <div className="space-y-2 border-t border-line pt-3"><p className="text-xs font-medium uppercase tracking-wide text-muted">Issued links</p>{shareLinksRes.data.map((link) => <div key={link.id} className="flex flex-wrap items-center justify-between gap-3 rounded border border-line px-3 py-2 text-sm"><span className="font-mono text-xs text-muted">{link.token_prefix}…</span><span className="text-xs text-muted">Expires {formatDateTime(link.expires_at)}</span>{link.revoked_at ? <Badge tone="neutral">Revoked</Badge> : <Button size="sm" variant="outline" loading={revokeShareMut.loading} onClick={() => void revokeShareMut.run(link.id)}>Revoke</Button>}</div>)}</div> : null}
          {revokeShareMut.errorMessage && <p role="alert" className="text-sm text-danger">{revokeShareMut.errorMessage}</p>}
        </CardBody>
      </Card>}

      <Card>
        <CardBody className="space-y-4">
          <div>
            <h2 className="text-sm font-semibold text-fg">Scheduled distribution</h2>
            <p className="text-xs text-muted">Generate a fresh executive PDF on a cron schedule. Email delivery is used only when outbound email is configured.</p>
          </div>
          {canGenerate && selectedAssessmentId && <form onSubmit={createSchedule} className="grid gap-3 md:grid-cols-2 xl:grid-cols-8">
            <Field label="Schedule name" htmlFor="report-schedule-name"><Input id="report-schedule-name" required minLength={1} maxLength={160} value={scheduleName} onChange={(event) => setScheduleName(event.target.value)} placeholder="Weekly executive report" /></Field>
            <Field label="Report title (optional)" htmlFor="report-schedule-title"><Input id="report-schedule-title" maxLength={300} value={scheduleTitle} onChange={(event) => setScheduleTitle(event.target.value)} placeholder="Board security update" /></Field>
            <Field label="Cron schedule" htmlFor="report-schedule-cron" hint="Example: 0 9 * * 1 for Mondays at 09:00 in the selected timezone"><Input id="report-schedule-cron" required maxLength={120} value={scheduleCron} onChange={(event) => setScheduleCron(event.target.value)} /></Field>
            <Field label="Timezone" htmlFor="report-schedule-timezone" hint="IANA zone, e.g. Asia/Kolkata"><Input id="report-schedule-timezone" required maxLength={80} value={scheduleTimezone} onChange={(event) => setScheduleTimezone(event.target.value)} placeholder="UTC" /></Field>
            <Field label="Recipients (optional)" htmlFor="report-schedule-recipients" hint="Comma-separated email addresses"><Input id="report-schedule-recipients" maxLength={4000} value={scheduleRecipients} onChange={(event) => setScheduleRecipients(event.target.value)} placeholder="security@example.com" /></Field>
            <Field label="Artifact" htmlFor="report-schedule-format"><Select id="report-schedule-format" value={scheduleFormat} onChange={(event) => setScheduleFormat(event.target.value as "pdf" | "html" | "json")}><option value="pdf">PDF</option><option value="html">HTML</option><option value="json">JSON</option></Select></Field>
            <Field label="Audience" htmlFor="report-schedule-audience"><Select id="report-schedule-audience" value={scheduleAudience} onChange={(event) => setScheduleAudience(event.target.value as "executive" | "technical")}><option value="executive">Executive</option><option value="technical">Technical</option></Select></Field>
            <div className="flex items-end"><Button type="submit" loading={createScheduleMut.loading} className="w-full">Create schedule</Button></div>
          </form>}
          {schedulesRes.loading && !schedulesRes.data ? <LoadingState label="Loading scheduled reports…" /> : schedulesRes.error ? <ErrorState message={schedulesRes.error} onRetry={schedulesRes.refetch} /> : !schedulesRes.data?.length ? <p className="text-sm text-muted">No scheduled reports yet.</p> : <div className="space-y-2">{schedulesRes.data.map((schedule) => <div key={schedule.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3"><div><p className="text-sm font-medium text-fg">{schedule.name}</p><p className="text-xs text-muted">{schedule.cron_expression} · {schedule.timezone} · next {formatDateTime(schedule.next_run_at)}{schedule.recipients.length ? ` · ${schedule.recipients.length} recipient${schedule.recipients.length === 1 ? "" : "s"}` : ""}</p></div>{canGenerate && <Button size="sm" variant="outline" loading={toggleScheduleMut.loading} onClick={() => void toggleScheduleMut.run({ id: schedule.id, resume: !schedule.is_enabled })}>{schedule.is_enabled ? "Pause" : "Resume"}</Button>}</div>)}</div>}
          {!selectedAssessmentId && canGenerate && <p className="text-sm text-muted">Select an assessment above to create a schedule.</p>}
        </CardBody>
      </Card>

      {!selectedAssessmentId ? (
        recentReportsRes.loading && !recentReportsRes.data ? <LoadingState label="Loading recent reports…" /> : recentReportsRes.error ? <ErrorState message={recentReportsRes.error} onRetry={recentReportsRes.refetch} /> : !recentReportsRes.data?.items.length ? <EmptyState title="No reports yet" description="Reports are generated automatically after assessment completion, or you can generate one for an assessment above." /> : <><h2 className="text-sm font-semibold text-fg">Recent reports</h2><Table><THead><TR><TH>Title</TH><TH>Format</TH><TH>Audience</TH><TH>Status</TH><TH>Generated</TH><TH className="w-28" /></TR></THead><TBody>{recentReportsRes.data.items.map((r) => <TR key={r.id}><TD className="font-medium text-fg">{r.title}</TD><TD className="font-mono text-xs text-muted">{r.format.toUpperCase()}</TD><TD className="text-muted capitalize">{r.audience}</TD><TD><Badge tone={STATUS_TONE[r.status]}>{humanize(r.status)}</Badge></TD><TD className="text-muted">{r.generated_at ? formatDateTime(r.generated_at) : "—"}</TD><TD>{r.status === "ready" && <div className="flex items-center gap-1"><Button size="sm" variant="ghost" loading={downloadMut.loading} onClick={() => void downloadMut.run(r.id)}>Download</Button>{canGenerate && <Button size="sm" variant="ghost" onClick={() => { setShareReportId(r.id); setShareExpiresAt(defaultShareExpiry()); setIssuedShare(null); }}>Share</Button>}</div>}</TD></TR>)}</TBody></Table><Pagination meta={recentReportsRes.data.meta} onOffsetChange={setOffset} /></>
      ) : reportsRes.loading && !reportsRes.data ? (
        <LoadingState label="Loading reports…" />
      ) : reportsRes.error ? (
        <ErrorState message={reportsRes.error} onRetry={reportsRes.refetch} />
      ) : !reportsRes.data || reportsRes.data.length === 0 ? (
        <EmptyState
          title="No reports yet"
          description="Reports are generated automatically after assessment completion, or you can trigger one manually."
          action={
            canGenerate ? (
              <Button onClick={() => void generateMut.run({ assessmentId: selectedAssessmentId, title: reportTitle.trim() || undefined })} loading={generateMut.loading}>
                Generate report
              </Button>
            ) : undefined
          }
        />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Title</TH>
              <TH>Format</TH>
              <TH>Audience</TH>
              <TH>Status</TH>
              <TH>Size</TH>
              <TH>Generated</TH>
              <TH className="w-28" />
            </TR>
          </THead>
          <TBody>
            {reportsRes.data.map((r) => (
              <TR key={r.id}>
                <TD className="font-medium text-fg">{r.title}</TD>
                <TD><span className="font-mono text-xs text-muted">{r.format.toUpperCase()}</span></TD>
                <TD className="text-muted capitalize">{r.audience}</TD>
                <TD><Badge tone={STATUS_TONE[r.status]}>{humanize(r.status)}</Badge></TD>
                <TD className="text-muted">{r.size_bytes != null ? formatBytes(r.size_bytes) : "—"}</TD>
                <TD className="text-muted">{r.generated_at ? formatDateTime(r.generated_at) : "—"}</TD>
                <TD>
                  {r.status === "ready" && (
                    <div className="flex items-center gap-1"><Button size="sm" variant="ghost" onClick={() => void downloadMut.run(r.id)} loading={downloadMut.loading}>Download</Button>{canGenerate && <Button size="sm" variant="ghost" onClick={() => { setShareReportId(r.id); setShareExpiresAt(defaultShareExpiry()); setIssuedShare(null); }}>Share</Button>}</div>
                  )}
                  {r.failure_reason && (
                    <span className="text-xs text-danger" title={r.failure_reason}>Failed</span>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </div>
  );
}
