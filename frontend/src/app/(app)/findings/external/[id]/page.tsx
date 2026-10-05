"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { PriorityBadge, SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { canSaveExternalAlertTriage } from "@/lib/external-alert-triage";
import { externalAlertFreshnessWarning } from "@/lib/external-alert-freshness";
import { canSubmitGithubAlertDecision, githubAlertAction } from "@/lib/github-alert-actions";
import { formatDateTime, humanize } from "@/lib/format";
import { safeExternalUrl } from "@/lib/safe-external-url";
import { sharedCves } from "@/lib/shared-cves";
import type { TriageStatus } from "@/lib/types";

const TRIAGE_STATUSES: readonly TriageStatus[] = ["new", "investigating", "risk_accepted", "false_positive", "closed"];

function Detail({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="mt-1 break-words text-sm text-fg">{value || "—"}</dd>
    </div>
  );
}

export default function ExternalAlertDetailPage() {
  const params = useParams();
  const rawId = params.id;
  const id = (Array.isArray(rawId) ? rawId[0] : rawId) ?? "";
  const { can } = useAuth();
  const { toast } = useToast();
  const canRead = can("finding:read");
  const canTriage = can("finding:validate");
  const canManageIntegration = can("integration:manage");
  const { data, error, loading, refetch, setData } = useApiResource(
    () => api.externalAlerts.get(id),
    [id],
    { enabled: canRead && !!id },
  );
  const {
    data: relatedFindings,
    error: relatedError,
    loading: relatedLoading,
    refetch: refetchRelated,
  } = useApiResource(
    () => api.externalAlerts.relatedFindings(id),
    [id],
    { enabled: canRead && !!id },
  );
  const {
    data: relatedAlerts,
    error: relatedAlertsError,
    loading: relatedAlertsLoading,
    refetch: refetchRelatedAlerts,
  } = useApiResource(
    () => api.externalAlerts.relatedAlerts(id),
    [id],
    { enabled: canRead && !!id },
  );
  const [triageStatus, setTriageStatus] = React.useState<TriageStatus>("new");
  const [triageNote, setTriageNote] = React.useState("");
  const [githubReason, setGithubReason] = React.useState("");
  const [githubComment, setGithubComment] = React.useState("");
  React.useEffect(() => {
    if (!data) return;
    setTriageStatus(data.triage_status);
    setTriageNote(data.triage_note || "");
  }, [data]);
  const triageMut = useMutation(
    (status: TriageStatus, note: string | null, expectedVersion: number) =>
      api.externalAlerts.triage(id, { status, note, expected_version: expectedVersion }),
    {
      onSuccess: (updated) => {
        setData(updated);
        toast({ title: "Cynux triage updated", tone: "ok" });
      },
    },
  );
  const githubActionMut = useMutation(
    (decision: "dismiss" | "reopen", reason?: string, comment?: string) =>
      api.externalAlerts.githubAction(id, { decision, reason, comment }),
    {
      onSuccess: (updated) => {
        setData(updated);
        setGithubReason("");
        setGithubComment("");
        toast({ title: `GitHub alert ${updated.status}`, description: "GitHub confirmed the source status.", tone: "ok" });
      },
    },
  );

  if (!canRead) return <EmptyState title="No access" description="You don't have permission to view this." />;
  if (loading && !data) return <LoadingState label="Loading external alert…" />;
  if (error && !data) return <ErrorState message={error} onRetry={refetch} />;
  if (!data) return <EmptyState title="Alert not found" description="This alert may have been removed." />;

  const sourceUrl = safeExternalUrl(data.source_url);
  const githubAction = data.provider === "github" ? githubAlertAction(data.category) : null;
  return (
    <div className="space-y-6">
      <Link href="/findings?view=external" className="text-sm text-primary hover:underline">← Back to external alerts</Link>
      <PageHeader title={data.title} description={`${humanize(data.provider)} · ${humanize(data.category)}`} />
      <Card>
        <CardHeader>
          <CardTitle>External alert</CardTitle>
          <SeverityBadge severity={data.severity} />
        </CardHeader>
        <CardBody className="space-y-5">
          <p className="text-sm text-muted">
            This alert is synchronized from a connected tool. Its status and full evidence remain owned by that source.
          </p>
          {externalAlertFreshnessWarning(data) && (
            <p role="status" className="rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-sm text-warn">
              {externalAlertFreshnessWarning(data)}
            </p>
          )}
          <dl className="grid gap-5 sm:grid-cols-2">
            <Detail label="Provider" value={humanize(data.provider)} />
            <Detail label="Provider alert ID" value={data.external_id} />
            <Detail label="Category" value={humanize(data.category)} />
            <Detail label="Source status" value={humanize(data.status)} />
            <Detail label="Cynux triage" value={humanize(data.triage_status)} />
            <Detail label="Triage rationale" value={data.triage_note} />
            <Detail label="Resource" value={data.resource} />
            <Detail label="CVEs" value={data.cve_ids.join(", ")} />
            <Detail label="First seen" value={data.first_seen_at ? formatDateTime(data.first_seen_at) : null} />
            <Detail label="Last seen" value={data.last_seen_at ? formatDateTime(data.last_seen_at) : null} />
            <Detail label="Triaged at" value={data.triaged_at ? formatDateTime(data.triaged_at) : null} />
          </dl>
          {sourceUrl && (
            <a href={sourceUrl} target="_blank" rel="noopener noreferrer"
              className="inline-flex rounded-lg border border-primary/30 px-3 py-2 text-sm font-medium text-primary hover:bg-primary/10">
              View in source tool ↗
            </a>
          )}
        </CardBody>
      </Card>
      {githubAction && (
        <Card>
          <CardHeader><CardTitle>GitHub source action</CardTitle></CardHeader>
          <CardBody className="space-y-4">
            <p className="text-sm text-muted">
              This changes the alert in GitHub, not just Cynux triage. GitHub must confirm the new status.
            </p>
            {!canManageIntegration || !canTriage ? (
              <p className="text-sm text-muted">Your role cannot change provider alerts.</p>
            ) : data.status === "open" ? (
              <form className="space-y-4" onSubmit={(event) => {
                event.preventDefault();
                if (!canSubmitGithubAlertDecision("dismiss", githubReason, githubComment)) return;
                if (window.confirm(`${githubAction.verb} this ${humanize(data.category)} alert in GitHub?`)) {
                  void githubActionMut.run("dismiss", githubReason, githubComment.trim());
                }
              }}>
                <Field label="GitHub reason" htmlFor="github-alert-reason">
                  <Select id="github-alert-reason" value={githubReason}
                    onChange={(event) => setGithubReason(event.target.value)}>
                    <option value="">Choose a reason</option>
                    {githubAction.reasons.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </Select>
                </Field>
                <Field label="Rationale sent to GitHub" htmlFor="github-alert-comment"
                  hint={data.category === "secret_scanning" ? "Do not mark a secret revoked until its revocation is verified." : "Required before changing the source alert."}>
                  <Textarea id="github-alert-comment" value={githubComment} maxLength={2000}
                    onChange={(event) => setGithubComment(event.target.value)} />
                </Field>
                {githubActionMut.errorMessage && <p role="alert" className="text-sm text-danger">{githubActionMut.errorMessage}</p>}
                <Button type="submit" loading={githubActionMut.loading}
                  disabled={!canSubmitGithubAlertDecision("dismiss", githubReason, githubComment)}>
                  {githubAction.verb} in GitHub
                </Button>
              </form>
            ) : data.status === "dismissed" || data.status === "resolved" ? (
              <div className="space-y-3">
                {githubActionMut.errorMessage && <p role="alert" className="text-sm text-danger">{githubActionMut.errorMessage}</p>}
                <Button variant="outline" loading={githubActionMut.loading} onClick={() => {
                  if (window.confirm("Reopen this alert in GitHub?")) void githubActionMut.run("reopen");
                }}>Reopen in GitHub</Button>
              </div>
            ) : (
              <p className="text-sm text-muted">This source status cannot be changed from Cynux.</p>
            )}
          </CardBody>
        </Card>
      )}
      <Card>
        <CardHeader><CardTitle>Cross-tool correlation candidates</CardTitle></CardHeader>
        <CardBody className="space-y-3">
          <p className="text-sm text-muted">
            GitHub and GitLab alerts appear here only when both the repository and a CVE match. These are investigation leads, not confirmed duplicates; no status is changed automatically.
          </p>
          {relatedAlertsLoading && !relatedAlerts ? (
            <LoadingState label="Checking connected tools…" />
          ) : relatedAlertsError ? (
            <ErrorState message={relatedAlertsError} onRetry={refetchRelatedAlerts} />
          ) : !relatedAlerts?.length ? (
            <p className="text-sm text-muted">No cross-tool candidates found with both signals.</p>
          ) : (
            <ul className="divide-y divide-line">
              {relatedAlerts.map((alert) => (
                <li key={alert.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                  <div className="min-w-0">
                    <Link href={`/findings/external/${alert.id}`} className="font-medium text-primary hover:underline">
                      {alert.title}
                    </Link>
                    <p className="mt-1 text-xs text-muted">
                      {humanize(alert.provider)} · {alert.resource || "—"} · Shared CVE: {sharedCves(data.cve_ids, alert.cve_ids).join(", ")}
                    </p>
                  </div>
                  <SeverityBadge severity={alert.severity} />
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Cynux triage</CardTitle></CardHeader>
        <CardBody className="space-y-4">
          {canTriage ? (
            <form className="space-y-4" onSubmit={(event) => {
              event.preventDefault();
              if (!canSaveExternalAlertTriage(
                { status: triageStatus, note: triageNote },
                { status: data.triage_status, note: data.triage_note },
              )) return;
              void triageMut.run(triageStatus, triageNote.trim() || null, data.triage_version);
            }}>
              <Field label="Decision" htmlFor="external-triage-status">
                <Select id="external-triage-status" value={triageStatus}
                  onChange={(event) => setTriageStatus(event.target.value as TriageStatus)}>
                  {TRIAGE_STATUSES.map((status) => (
                    <option key={status} value={status}>{humanize(status)}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Rationale" htmlFor="external-triage-note"
                hint="Required for risk acceptance, false positive, or closure. Visible to authorized users.">
                <Textarea id="external-triage-note" maxLength={2000} value={triageNote}
                  onChange={(event) => setTriageNote(event.target.value)}
                  placeholder="Record the reason for this decision…" />
              </Field>
              {triageMut.errorMessage && (
                <p role="alert" className="text-sm text-danger">{triageMut.errorMessage} Reload the alert before retrying if another analyst changed it.</p>
              )}
              <div className="flex flex-wrap gap-2">
                <Button type="submit" loading={triageMut.loading} disabled={!canSaveExternalAlertTriage(
                  { status: triageStatus, note: triageNote },
                  { status: data.triage_status, note: data.triage_note },
                )}>Save triage</Button>
                <Button type="button" variant="outline" onClick={refetch}>Reload alert</Button>
              </div>
            </form>
          ) : (
            <p className="text-sm text-muted">Your role can view this decision but cannot change it.</p>
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Assessment findings with a shared CVE</CardTitle></CardHeader>
        <CardBody className="space-y-3">
          <p className="text-sm text-muted">
            These are possible related records, not confirmed duplicates. Compare the affected resource and evidence before acting.
          </p>
          {relatedLoading && !relatedFindings ? (
            <LoadingState label="Checking for related findings…" />
          ) : relatedError ? (
            <ErrorState message={relatedError} onRetry={refetchRelated} />
          ) : !relatedFindings?.length ? (
            <p className="text-sm text-muted">No assessment findings share a CVE with this alert.</p>
          ) : (
            <ul className="divide-y divide-line">
              {relatedFindings.map((finding) => (
                <li key={finding.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                  <div className="min-w-0">
                    <Link href={`/findings/${finding.id}`} className="font-medium text-primary hover:underline">
                      {finding.title}
                    </Link>
                    <p className="mt-1 text-xs text-muted">
                      Shared CVE: {sharedCves(data.cve_ids, finding.cve_ids).join(", ") || "—"} · {humanize(finding.status)}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    {finding.priority && <PriorityBadge priority={finding.priority} />}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
