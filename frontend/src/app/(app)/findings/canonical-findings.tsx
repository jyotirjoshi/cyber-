"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { SeverityBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { formatRelative, humanize } from "@/lib/format";

const PAGE_SIZE = 25;

export function CanonicalFindingsPanel() {
  const router = useRouter();
  const [offset, setOffset] = React.useState(0);
  const [mine, setMine] = React.useState(false);
  const [overdue, setOverdue] = React.useState(false);
  const { data, error, loading, refetch } = useApiResource(
    () => api.canonicalFindings.list({ limit: PAGE_SIZE, offset, mine, overdue }),
    [offset, mine, overdue],
  );
  const controls = (
    <div className="flex flex-wrap gap-5 text-sm">
      <label className="flex items-center gap-2"><input type="checkbox" checked={mine} onChange={(event) => { setMine(event.target.checked); setOffset(0); }} /> Assigned to me</label>
      <label className="flex items-center gap-2"><input type="checkbox" checked={overdue} onChange={(event) => { setOverdue(event.target.checked); setOffset(0); }} /> Overdue</label>
    </div>
  );

  if (loading && !data) return <LoadingState label="Loading canonical findings…" />;
  if (error && !data) return <ErrorState message={error} onRetry={refetch} />;
  if (!data) return <EmptyState title="No canonical findings" description="Run an assessment or sync a connected security tool." />;
  if (data.items.length === 0) {
    return <div className="space-y-4">{controls}<EmptyState title="No matching findings" description="Change the work queue filters or add findings through an assessment." /></div>;
  }
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">One finding per validated CVE and asset, while each tool observation remains available on the detail page.</p>
      {controls}
      <Table>
        <THead><TR><TH>Risk</TH><TH>Severity</TH><TH>Finding</TH><TH>CVE</TH><TH>State</TH><TH>Owner</TH><TH>Due</TH><TH>Last seen</TH></TR></THead>
        <TBody>{data.items.map((item) => (
          <TR key={item.id} clickable onClick={() => router.push(`/findings/canonical/${item.id}`)}>
            <TD className="font-semibold tabular-nums">{item.risk_score.toFixed(1)}</TD>
            <TD><SeverityBadge severity={item.severity} /></TD>
            <TD><span className="block max-w-[28rem] truncate font-medium text-fg" title={item.title}>{item.title}</span></TD>
            <TD className="text-muted">{item.cve_ids.join(", ") || "—"}</TD>
            <TD className="text-muted">{humanize(item.status)}</TD>
            <TD className="text-muted">{item.assignee_user_id ? "Assigned" : "Unassigned"}</TD>
            <TD className={item.due_at && new Date(item.due_at).getTime() < Date.now() && !["closed", "false_positive", "accepted_risk"].includes(item.status) ? "font-semibold text-danger" : "text-muted"}>
              {item.due_at ? formatRelative(item.due_at) : "—"}
            </TD>
            <TD className="whitespace-nowrap text-muted">{formatRelative(item.last_seen_at)}</TD>
          </TR>
        ))}</TBody>
      </Table>
      <Pagination meta={data.meta} onOffsetChange={setOffset} />
    </div>
  );
}
