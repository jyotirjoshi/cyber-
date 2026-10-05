"use client";

import * as React from "react";
import { useRouter } from "next/navigation";

import { SeverityBadge } from "@/components/ui/Badge";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Select } from "@/components/ui/Input";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { formatRelative, humanize } from "@/lib/format";
import type { ExposureOut, Severity } from "@/lib/types";

const SOURCES: readonly ExposureOut["source"][] = ["defectdojo", "github", "gitlab", "wazuh", "sonarqube", "snyk", "tenable"];
const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 25;

export function AllExposuresPanel() {
  const router = useRouter();
  const [source, setSource] = React.useState<ExposureOut["source"] | "">("");
  const [severity, setSeverity] = React.useState<Severity | "">("");
  const [offset, setOffset] = React.useState(0);
  const { data, error, loading, refetch } = useApiResource(
    () => api.exposures.list({
      limit: PAGE_SIZE,
      offset,
      source: source || undefined,
      severity: severity || undefined,
    }),
    [source, severity, offset],
  );

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        One view of assessment findings and connected-tool alerts. Records keep their source identity and status; similar records are not automatically merged.
      </p>
      <Card><CardBody className="grid gap-3 sm:grid-cols-2">
        <Field label="Source" htmlFor="exposure-source">
          <Select id="exposure-source" value={source} onChange={(event) => { setSource(event.target.value as typeof source); setOffset(0); }}>
            <option value="">All sources</option>
            {SOURCES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
          </Select>
        </Field>
        <Field label="Severity" htmlFor="exposure-severity">
          <Select id="exposure-severity" value={severity} onChange={(event) => { setSeverity(event.target.value as typeof severity); setOffset(0); }}>
            <option value="">All severities</option>
            {SEVERITIES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
          </Select>
        </Field>
      </CardBody></Card>
      {loading && !data ? <LoadingState label="Loading exposures…" /> : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="No exposures" description="Run an assessment, sync a connected tool, or adjust the filters." />
      ) : (
        <>
          <Table>
            <THead><TR><TH>Severity</TH><TH>Title</TH><TH>Source</TH><TH>Resource</TH><TH>Source status</TH><TH>Last seen</TH></TR></THead>
            <TBody>{data.items.map((item) => (
              <TR key={`${item.source}:${item.id}`} clickable onClick={() => router.push(item.source === "defectdojo" ? `/findings/${item.id}` : `/findings/external/${item.id}`)}>
                <TD><SeverityBadge severity={item.severity} /></TD>
                <TD><span className="block max-w-[28rem] truncate font-medium text-fg" title={item.title}>{item.title}</span></TD>
                <TD className="text-muted">{humanize(item.source)}</TD>
                <TD className="text-muted">{item.resource || "—"}</TD>
                <TD className="text-muted">{humanize(item.status)}</TD>
                <TD className="whitespace-nowrap text-muted">{item.seen_at ? formatRelative(item.seen_at) : "—"}</TD>
              </TR>
            ))}</TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </>
      )}
    </div>
  );
}
