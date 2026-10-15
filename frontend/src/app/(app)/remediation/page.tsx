"use client";

import Link from "next/link";
import * as React from "react";

import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatRelative, humanize } from "@/lib/format";
import { useToast } from "@/components/ui/Toast";
import type { CanonicalRemediationOperationOut } from "@/lib/types";

const PAGE_SIZE = 25;
const IN_PROGRESS_RETESTS = new Set(["requested", "scheduled", "running"]);

function operationTone(operation: CanonicalRemediationOperationOut): "danger" | "warn" | "primary" | "neutral" {
  const { finding } = operation;
  if (finding.due_at && new Date(finding.due_at).getTime() < Date.now()) return "danger";
  if (!finding.assignee_user_id || !finding.remediation_plan) return "warn";
  if (operation.latest_retest && IN_PROGRESS_RETESTS.has(operation.latest_retest.status)) return "primary";
  return "neutral";
}

export default function RemediationOperationsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const [offset, setOffset] = React.useState(0);
  const [mine, setMine] = React.useState(false);
  const [overdue, setOverdue] = React.useState(false);
  const [attentionOnly, setAttentionOnly] = React.useState(true);
  const [assetGroup, setAssetGroup] = React.useState("");
  const [selected, setSelected] = React.useState<string[]>([]);
  const [bulkDueAt, setBulkDueAt] = React.useState("");
  const [bulkPlan, setBulkPlan] = React.useState("");
  const [bulkRemediationGroup, setBulkRemediationGroup] = React.useState("");
  const [remediationGroup, setRemediationGroup] = React.useState("");
  const { data, error, loading, refetch } = useApiResource(
    () => api.canonicalFindings.operations({ limit: PAGE_SIZE, offset, mine, overdue, attention_only: attentionOnly, asset_group: assetGroup.trim() || undefined, remediation_group: remediationGroup.trim() || undefined }),
    [offset, mine, overdue, attentionOnly, assetGroup, remediationGroup],
  );
  const remediationGroups = useApiResource(
    () => api.canonicalFindings.remediationGroups(),
    [],
  );

  const operations = data?.items ?? [];
  const canRemediate = can("finding:remediate");
  const canApproveExceptions = can("finding:validate");
  React.useEffect(() => {
    setSelected((current) => current.filter((id) => operations.some((item) => item.finding.id === id)));
  }, [data]);
  const bulkMutation = useMutation(
    () => api.canonicalFindings.bulkUpdateWork({
      items: operations.filter((item) => selected.includes(item.finding.id)).map((item) => ({
        finding_id: item.finding.id,
        expected_version: item.finding.status_version,
        ...(bulkDueAt ? { due_at: new Date(bulkDueAt).toISOString() } : {}),
        ...(bulkPlan.trim() ? { remediation_plan: bulkPlan.trim() } : {}),
        ...(bulkRemediationGroup.trim() ? { remediation_group: bulkRemediationGroup.trim() } : {}),
      })),
    }),
    { onSuccess: () => { toast({ title: "Remediation work updated", description: `${selected.length} findings updated`, tone: "ok" }); setSelected([]); setBulkDueAt(""); setBulkPlan(""); setBulkRemediationGroup(""); void refetch(); } },
  );
  const approveExceptionMutation = useMutation(
    (acceptanceId: string) => api.canonicalFindings.approveRiskAcceptance(acceptanceId),
    { onSuccess: () => { toast({ title: "Risk acceptance approved and finding status updated", tone: "ok" }); void refetch(); } },
  );
  const groupRetestMutation = useMutation(
    () => api.canonicalFindings.requestRemediationGroupRetests(remediationGroup.trim(), { note: "Group remediation verification requested" }),
    { onSuccess: (requests) => { toast({ title: "Group retest requested", description: `${requests.length} findings queued for verification`, tone: "ok" }); void refetch(); } },
  );
  const summary = {
    overdue: operations.filter((item) => item.finding.due_at && new Date(item.finding.due_at).getTime() < Date.now()).length,
    unowned: operations.filter((item) => !item.finding.assignee_user_id).length,
    waitingForRetest: operations.filter((item) => item.latest_retest && IN_PROGRESS_RETESTS.has(item.latest_retest.status)).length,
    pendingExceptions: operations.filter((item) => item.latest_risk_acceptance?.status === "pending").length,
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation operations"
        description="One work queue for canonical findings, ownership, tracker tickets, time-bound exceptions, and evidence-backed retests."
        action={<div className="flex flex-wrap gap-2"><Button variant="secondary" onClick={() => void refetch()}>Refresh queue</Button>{canApproveExceptions && remediationGroup.trim() && <Button loading={groupRetestMutation.loading} onClick={() => void groupRetestMutation.run()}>Request group retest</Button>}</div>}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Overdue" value={summary.overdue} tone="danger" />
        <Metric label="Needs owner" value={summary.unowned} tone="warn" />
        <Metric label="Retests in progress" value={summary.waitingForRetest} tone="primary" />
        <Metric label="Pending exceptions" value={summary.pendingExceptions} tone="warn" />
      </div>

      <div className="flex flex-wrap items-end gap-5 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" checked={attentionOnly} onChange={(event) => { setAttentionOnly(event.target.checked); setOffset(0); }} /> Action required</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={mine} onChange={(event) => { setMine(event.target.checked); setOffset(0); }} /> Assigned to me</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={overdue} onChange={(event) => { setOverdue(event.target.checked); setOffset(0); }} /> Overdue only</label>
        <Field label="Asset group" htmlFor="remediation-asset-group" className="min-w-56"><Input id="remediation-asset-group" value={assetGroup} maxLength={120} onChange={(event) => { setAssetGroup(event.target.value); setOffset(0); }} placeholder="Payments, Customer API…" /></Field>
        <Field label="Remediation group" htmlFor="remediation-work-group" className="min-w-56"><Input id="remediation-work-group" list="remediation-groups" value={remediationGroup} maxLength={160} onChange={(event) => { setRemediationGroup(event.target.value); setOffset(0); }} placeholder="One patch or upgrade…" /><datalist id="remediation-groups">{(remediationGroups.data ?? []).map((group) => <option key={group.name} value={group.name} />)}</datalist></Field>
      </div>

      {(remediationGroups.data ?? []).length > 0 && (
        <Card>
          <CardHeader><CardTitle>Active remediation groups</CardTitle></CardHeader>
          <CardBody><div className="flex flex-wrap gap-2">{remediationGroups.data!.map((group) => <Button key={group.name} size="sm" variant={group.name === remediationGroup ? "secondary" : "outline"} onClick={() => { setRemediationGroup(group.name); setOffset(0); }}>{group.name} · {group.active_findings} findings · max risk {group.highest_risk_score.toFixed(1)}{group.overdue_findings > 0 ? ` · ${group.overdue_findings} overdue` : ""}</Button>)}</div></CardBody>
        </Card>
      )}

      {canRemediate && selected.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Bulk remediation update · {selected.length} selected</CardTitle></CardHeader>
          <CardBody>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,2fr)_auto] lg:items-end">
              <Field label="Set due date" htmlFor="bulk-due"><Input id="bulk-due" type="datetime-local" value={bulkDueAt} onChange={(event) => setBulkDueAt(event.target.value)} /></Field>
              <Field label="Set remediation group" htmlFor="bulk-remediation-group"><Input id="bulk-remediation-group" value={bulkRemediationGroup} maxLength={160} onChange={(event) => setBulkRemediationGroup(event.target.value)} placeholder="One patch or upgrade…" /></Field>
              <Field label="Append a common remediation plan" htmlFor="bulk-plan" hint="This replaces the current plan only for the selected findings."><Textarea id="bulk-plan" rows={2} value={bulkPlan} onChange={(event) => setBulkPlan(event.target.value)} /></Field>
              <div className="flex gap-2"><Button variant="ghost" onClick={() => setSelected([])}>Clear</Button><Button disabled={!bulkDueAt && !bulkPlan.trim() && !bulkRemediationGroup.trim()} loading={bulkMutation.loading} onClick={() => void bulkMutation.run()}>Apply update</Button></div>
            </div>
            {bulkMutation.errorMessage && <p role="alert" className="mt-3 text-sm text-danger">{bulkMutation.errorMessage}</p>}
          </CardBody>
        </Card>
      )}

      {loading && !data ? <LoadingState label="Loading remediation operations…" /> : error && !data ? <ErrorState message={error} onRetry={refetch} /> : !data || operations.length === 0 ? (
        <EmptyState
          title="No remediation work matches this queue"
          description={attentionOnly ? "All active canonical findings have either been resolved or risk accepted. Turn off Action required to review the full history." : "Run an assessment or import a connected security tool to populate canonical findings."}
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead><TR>{canRemediate && <TH className="w-10" />}<TH>Risk</TH><TH>Finding</TH><TH>Owner & due date</TH><TH>Tickets</TH><TH>Governance</TH><TH>Next action & priority</TH></TR></THead>
            <TBody>{operations.map((operation) => {
              const { finding } = operation;
              return <TR key={finding.id}>
                {canRemediate && <TD><input type="checkbox" aria-label={`Select ${finding.title}`} checked={selected.includes(finding.id)} onChange={(event) => setSelected((current) => event.target.checked ? [...current, finding.id] : current.filter((id) => id !== finding.id))} /></TD>}
                <TD><div className="space-y-1"><span className="font-semibold tabular-nums">{finding.risk_score.toFixed(1)}</span><SeverityBadge severity={finding.severity} /></div></TD>
                <TD><Link href={`/findings/canonical/${finding.id}`} className="block max-w-[23rem] font-medium text-fg hover:text-primary hover:underline" title={finding.title}>{finding.title}</Link><p className="mt-1 text-xs text-muted">{humanize(finding.status)} · {finding.cve_ids.join(", ") || "No CVE"} · {operation.source_observations} source {operation.source_observations === 1 ? "observation" : "observations"}</p>{finding.remediation_group && <p className="mt-1 text-xs font-medium text-primary">Group: {finding.remediation_group}</p>}</TD>
                <TD className="text-sm"><p className={finding.assignee_user_id ? "text-fg" : "font-medium text-warn"}>{finding.assignee_user_id ? "Assigned" : "Unassigned"}</p><p className={finding.due_at && new Date(finding.due_at).getTime() < Date.now() ? "mt-1 font-medium text-danger" : "mt-1 text-muted"}>{finding.due_at ? `Due ${formatRelative(finding.due_at)}` : "No due date"}</p></TD>
                <TD><TicketSummary operation={operation} /></TD>
                <TD><GovernanceSummary operation={operation} canApprove={canApproveExceptions} approving={approveExceptionMutation.loading} onApprove={(acceptanceId) => void approveExceptionMutation.run(acceptanceId)} /></TD>
                <TD><div className="min-w-48 space-y-2"><Badge tone={operationTone(operation)}>{operation.next_action}</Badge><ul className="space-y-1 text-xs text-muted">{operation.priority_reasons.slice(0, 2).map((reason) => <li key={reason}>• {reason}</li>)}</ul></div></TD>
              </TR>;
            })}</TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </div>
      )}
      {approveExceptionMutation.errorMessage && <p role="alert" className="text-sm text-danger">{approveExceptionMutation.errorMessage}</p>}
      {groupRetestMutation.errorMessage && <p role="alert" className="text-sm text-danger">{groupRetestMutation.errorMessage}</p>}
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone: "danger" | "warn" | "primary" }) {
  return <Card><CardHeader><CardTitle className="text-sm font-medium text-muted">{label}</CardTitle></CardHeader><CardBody><p className={`text-3xl font-semibold ${tone === "danger" ? "text-danger" : tone === "warn" ? "text-warn" : "text-primary"}`}>{value}</p></CardBody></Card>;
}

function TicketSummary({ operation }: { operation: CanonicalRemediationOperationOut }) {
  if (!operation.tickets.length) return <span className="text-sm text-muted">No linked ticket</span>;
  return <div className="space-y-1">{operation.tickets.map((ticket) => ticket.url ? <a key={ticket.id} href={ticket.url} target="_blank" rel="noreferrer" className="block text-sm text-primary hover:underline">{humanize(ticket.provider)} {ticket.external_key} ↗</a> : <p key={ticket.id} className="text-sm text-fg">{humanize(ticket.provider)} {ticket.external_key}</p>)}</div>;
}

function GovernanceSummary({ operation, canApprove, approving, onApprove }: {
  operation: CanonicalRemediationOperationOut;
  canApprove: boolean;
  approving: boolean;
  onApprove: (acceptanceId: string) => void;
}) {
  const acceptance = operation.latest_risk_acceptance;
  const retest = operation.latest_retest;
  if (!acceptance && !retest && operation.sla_escalation_level === 0) return <span className="text-sm text-muted">No active request</span>;
  return <div className="flex flex-wrap items-center gap-1.5">
    {operation.sla_escalation_level > 0 && <Badge tone={operation.sla_escalation_level >= 2 ? "danger" : "warn"}>SLA level {operation.sla_escalation_level}</Badge>}
    {acceptance && <Badge tone={acceptance.status === "pending" ? "warn" : acceptance.status === "approved" ? "info" : "neutral"}>Exception {humanize(acceptance.status)}</Badge>}
    {acceptance?.status === "pending" && canApprove && <Button size="sm" variant="outline" loading={approving} onClick={() => onApprove(acceptance.id)}>Approve exception</Button>}
    {retest && <Badge tone={IN_PROGRESS_RETESTS.has(retest.status) ? "primary" : retest.status === "not_confirmed" ? "ok" : retest.status === "confirmed" ? "warn" : "neutral"}>Retest {humanize(retest.status)}</Badge>}
  </div>;
}
