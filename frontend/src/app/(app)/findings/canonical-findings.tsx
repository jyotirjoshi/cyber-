"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatRelative, humanize } from "@/lib/format";

const PAGE_SIZE = 25;
const CANONICAL_STATUSES = ["new", "open", "reopened", "mitigated", "accepted_risk", "false_positive", "closed"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export function CanonicalFindingsPanel() {
  const router = useRouter();
  const { can } = useAuth();
  const [offset, setOffset] = React.useState(0);
  const [mine, setMine] = React.useState(false);
  const [overdue, setOverdue] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [q, setQ] = React.useState("");
  const [severity, setSeverity] = React.useState("");
  const [status, setStatus] = React.useState("");
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [bulkDueAt, setBulkDueAt] = React.useState("");
  const [bulkAssignee, setBulkAssignee] = React.useState("");
  React.useEffect(() => {
    const search = new URLSearchParams(window.location.search);
    setQuery(search.get("query") ?? "");
    setQ(search.get("q") ?? "");
    setSeverity(search.get("severity") ?? "");
    setStatus(search.get("status") ?? "");
    setMine(search.get("mine") === "true");
    setOverdue(search.get("overdue") === "true");
  }, []);
  const debouncedQuery = useDebouncedValue(query);
  const debouncedQ = useDebouncedValue(q);
  const { data, error, loading, refetch } = useApiResource(
    () => api.canonicalFindings.list({
      limit: PAGE_SIZE,
      offset,
      mine,
      overdue,
      q: debouncedQ.trim() || undefined,
      severity: severity || undefined,
      status: status || undefined,
      query: debouncedQuery.trim() || undefined,
    }),
    [offset, mine, overdue, debouncedQ, severity, status, debouncedQuery],
  );
  const bulkUpdate = useMutation(api.canonicalFindings.bulkUpdateWork, {
    onSuccess: () => {
      setSelected(new Set());
      setBulkDueAt("");
      setBulkAssignee("");
      void refetch();
    },
  });
  React.useEffect(() => setSelected(new Set()), [data?.meta.offset]);

  const selectedItems = data?.items.filter((item) => selected.has(item.id)) ?? [];
  const members = useApiResource(
    () => api.organization.members({ limit: 200 }),
    [],
    { enabled: can("finding:remediate") && selectedItems.length > 0 },
  );
  const toggleSelected = (id: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const togglePage = () => {
    if (!data) return;
    const allSelected = data.items.length > 0 && data.items.every((item) => selected.has(item.id));
    setSelected(allSelected ? new Set() : new Set(data.items.map((item) => item.id)));
  };
  const applyBulkWork = (work: { due_at?: string; assignee_user_id?: string | null }) => {
    if (selectedItems.length === 0) return;
    void bulkUpdate.run({
      items: selectedItems.map((item) => ({
        finding_id: item.id,
        expected_version: item.status_version,
        ...work,
      })),
    });
  };
  const applyBulkDueDate = () => {
    if (!bulkDueAt) return;
    const dueAt = new Date(bulkDueAt);
    if (!Number.isNaN(dueAt.getTime())) applyBulkWork({ due_at: dueAt.toISOString() });
  };
  const applyBulkAssignee = () => {
    if (!bulkAssignee) return;
    applyBulkWork({ assignee_user_id: bulkAssignee === "__unassigned" ? null : bulkAssignee });
  };
  const controls = (
    <div className="space-y-3">
      <Field
        label="Advanced query"
        htmlFor="canonical-query"
        hint={'Examples: severity:critical AND risk>=80 · provider:tenable AND kev:true · asset_group:"Payments"'}
      >
        <Input
          id="canonical-query"
          value={query}
          maxLength={1000}
          placeholder="(severity:critical OR kev:true) AND status:open"
          onChange={(event) => { setQuery(event.target.value); setOffset(0); }}
        />
      </Field>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Search" htmlFor="canonical-search">
          <Input id="canonical-search" value={q} placeholder="Title or exact CVE…" onChange={(event) => { setQ(event.target.value); setOffset(0); }} />
        </Field>
        <Field label="Severity" htmlFor="canonical-severity">
          <Select id="canonical-severity" value={severity} onChange={(event) => { setSeverity(event.target.value); setOffset(0); }}><option value="">All severities</option>{SEVERITIES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</Select>
        </Field>
        <Field label="Status" htmlFor="canonical-status">
          <Select id="canonical-status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}><option value="">All statuses</option>{CANONICAL_STATUSES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</Select>
        </Field>
      </div>
      <div className="flex flex-wrap gap-5 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" checked={mine} onChange={(event) => { setMine(event.target.checked); setOffset(0); }} /> Assigned to me</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={overdue} onChange={(event) => { setOverdue(event.target.checked); setOffset(0); }} /> Overdue</label>
      </div>
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
      {error && <InlineError message={error} />}
      {can("finding:remediate") && selectedItems.length > 0 && <div className="flex flex-wrap items-end gap-3 rounded-lg border border-primary/30 bg-primary/5 p-3"><p className="pb-2 text-sm font-medium text-fg">{selectedItems.length} finding{selectedItems.length === 1 ? "" : "s"} selected</p><Field label="Set due date" htmlFor="canonical-bulk-due" className="min-w-56"><Input id="canonical-bulk-due" type="datetime-local" value={bulkDueAt} onChange={(event) => setBulkDueAt(event.target.value)} /></Field><Button size="sm" disabled={!bulkDueAt} loading={bulkUpdate.loading} onClick={applyBulkDueDate}>Apply due date</Button><Field label="Assign owner" htmlFor="canonical-bulk-owner" className="min-w-56"><Select id="canonical-bulk-owner" value={bulkAssignee} onChange={(event) => setBulkAssignee(event.target.value)} disabled={members.loading}><option value="">Select active member…</option><option value="__unassigned">Unassign</option>{members.data?.items.filter((member) => member.is_active && member.accepted_at).map((member) => <option key={member.user_id} value={member.user_id}>{member.full_name || member.email}</option>)}</Select></Field><Button size="sm" variant="outline" disabled={!bulkAssignee || members.loading} loading={bulkUpdate.loading} onClick={applyBulkAssignee}>Apply owner</Button><Button size="sm" variant="ghost" disabled={bulkUpdate.loading} onClick={() => setSelected(new Set())}>Clear</Button><InlineError message={bulkUpdate.errorMessage ?? members.error} /></div>}
      <Table>
        <THead><TR>{can("finding:remediate") && <TH className="w-10"><input aria-label="Select all findings on this page" type="checkbox" checked={data.items.length > 0 && data.items.every((item) => selected.has(item.id))} onChange={togglePage} /></TH>}<TH>Risk</TH><TH>Severity</TH><TH>Finding</TH><TH>CVE</TH><TH>State</TH><TH>Owner</TH><TH>Due</TH><TH>Last seen</TH></TR></THead>
        <TBody>{data.items.map((item) => (
          <TR key={item.id} clickable onClick={() => router.push(`/findings/canonical/${item.id}`)}>
            {can("finding:remediate") && <TD className="w-10" onClick={(event) => event.stopPropagation()}><input aria-label={`Select ${item.title}`} type="checkbox" checked={selected.has(item.id)} onChange={() => toggleSelected(item.id)} /></TD>}
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
