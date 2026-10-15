"use client";

import * as React from "react";
import { useRouter } from "next/navigation";

import { SeverityBadge } from "@/components/ui/Badge";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { externalAlertFreshnessWarning } from "@/lib/external-alert-freshness";
import { formatRelative, humanize } from "@/lib/format";
import type { ExternalAlertOut, Severity, TriageStatus } from "@/lib/types";

const PAGE_SIZE = 25;
const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: readonly ExternalAlertOut["status"][] = ["open", "resolved", "dismissed", "fixed"];
const TRIAGE_STATUSES: readonly TriageStatus[] = ["new", "investigating", "risk_accepted", "false_positive", "closed"];

export function ExternalAlertsPanel() {
  const router = useRouter();
  const [q, setQ] = React.useState("");
  const [provider, setProvider] = React.useState<ExternalAlertOut["provider"] | "">("");
  const [severity, setSeverity] = React.useState<Severity | "">("");
  const [status, setStatus] = React.useState<ExternalAlertOut["status"] | "">("");
  const [triageStatus, setTriageStatus] = React.useState<TriageStatus | "">("");
  const [offset, setOffset] = React.useState(0);
  const debouncedQ = useDebouncedValue(q);

  const { data, error, loading, refetch } = useApiResource(
    () => api.externalAlerts.list({
      limit: PAGE_SIZE,
      offset,
      q: debouncedQ.trim() || undefined,
      provider: provider || undefined,
      severity: severity || undefined,
      status: status || undefined,
      triage_status: triageStatus || undefined,
    }),
    [debouncedQ, provider, severity, status, triageStatus, offset],
  );

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Read-only alerts synchronized from connected security tools. Their status remains owned by the source tool.
      </p>
      <Card>
        <CardBody className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <Field label="Search" htmlFor="ea-q">
            <Input id="ea-q" type="search" placeholder="Title or resource…" value={q}
              onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
          </Field>
          <Field label="Provider" htmlFor="ea-provider" hint="Any normalized intake provider">
            <Input id="ea-provider" value={provider}
              placeholder="e.g. qualys, wiz, burp"
              onChange={(e) => { setProvider(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, "")); setOffset(0); }} />
          </Field>
          <Field label="Severity" htmlFor="ea-severity">
            <Select id="ea-severity" value={severity}
              onChange={(e) => { setSeverity(e.target.value as Severity | ""); setOffset(0); }}>
              <option value="">All severities</option>
              {SEVERITIES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </Select>
          </Field>
          <Field label="Source status" htmlFor="ea-status">
            <Select id="ea-status" value={status}
              onChange={(e) => { setStatus(e.target.value as typeof status); setOffset(0); }}>
              <option value="">All statuses</option>
              {STATUSES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </Select>
          </Field>
          <Field label="Cynux triage" htmlFor="ea-triage">
            <Select id="ea-triage" value={triageStatus}
              onChange={(e) => { setTriageStatus(e.target.value as TriageStatus | ""); setOffset(0); }}>
              <option value="">All decisions</option>
              {TRIAGE_STATUSES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </Select>
          </Field>
        </CardBody>
      </Card>
      {loading && !data ? <LoadingState label="Loading external alerts…" /> : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="No external alerts" description="Sync a connected security tool or adjust the filters." />
      ) : (
        <>
          <Table>
            <THead><TR><TH>Severity</TH><TH>Title</TH><TH>Provider</TH><TH>Resource</TH><TH>CVE</TH><TH>Source status</TH><TH>Cynux triage</TH><TH>Last seen</TH></TR></THead>
            <TBody>{data.items.map((alert) => (
              <TR key={alert.id} clickable onClick={() => router.push(`/findings/external/${alert.id}`)}>
                <TD><SeverityBadge severity={alert.severity} /></TD>
                <TD><span className="block max-w-[25rem] truncate font-medium text-fg" title={alert.title}>{alert.title}</span></TD>
                <TD className="text-muted">{humanize(alert.provider)}</TD>
                <TD className="text-muted">{alert.resource || "—"}</TD>
                <TD className="whitespace-nowrap text-muted">{alert.cve_ids.length ? alert.cve_ids.join(", ") : "—"}</TD>
                <TD className="text-muted">
                  {humanize(alert.status)}
                  {externalAlertFreshnessWarning(alert) && (
                    <span className="block text-xs text-warn" title={externalAlertFreshnessWarning(alert) || undefined}>
                      Not seen ×{alert.missing_sync_count}
                    </span>
                  )}
                </TD>
                <TD className="text-muted">{humanize(alert.triage_status)}</TD>
                <TD className="whitespace-nowrap text-muted">{alert.last_seen_at ? formatRelative(alert.last_seen_at) : "—"}</TD>
              </TR>
            ))}</TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </>
      )}
    </div>
  );
}
