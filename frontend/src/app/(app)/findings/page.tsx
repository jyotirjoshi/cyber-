"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import {
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
  SeverityBadge,
} from "@/components/ui/Badge";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatRelative, humanize } from "@/lib/format";
import type { FindingStatus, Priority, ScannerName, Severity } from "@/lib/types";

const PAGE_SIZE = 25;

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const PRIORITIES: readonly Priority[] = ["P1", "P2", "P3", "P4", "P5"];
const STATUSES: readonly FindingStatus[] = [
  "active",
  "verified",
  "false_positive",
  "risk_accepted",
  "out_of_scope",
  "mitigated",
  "duplicate",
];
const SCANNERS: readonly ScannerName[] = ["reconftw", "nmap", "nuclei", "zap"];

type KevChoice = "all" | "in" | "not";

export default function FindingsPage() {
  const { can } = useAuth();
  const router = useRouter();

  const [q, setQ] = React.useState("");
  const [severity, setSeverity] = React.useState<Severity | "">("");
  const [priority, setPriority] = React.useState<Priority | "">("");
  const [status, setStatus] = React.useState<FindingStatus | "">("");
  const [scanner, setScanner] = React.useState<ScannerName | "">("");
  const [kev, setKev] = React.useState<KevChoice>("all");
  const [includeDuplicates, setIncludeDuplicates] = React.useState(false);
  const [includeFalsePositives, setIncludeFalsePositives] = React.useState(false);
  const [offset, setOffset] = React.useState(0);

  const debouncedQ = useDebouncedValue(q);
  const canRead = can("finding:read");

  const { data, error, loading, refetch } = useApiResource(
    () =>
      api.findings.list({
        limit: PAGE_SIZE,
        offset,
        q: debouncedQ.trim() || undefined,
        severity: severity || undefined,
        priority: priority || undefined,
        status: status || undefined,
        scanner: scanner || undefined,
        in_kev: kev === "all" ? undefined : kev === "in",
        include_duplicates: includeDuplicates || undefined,
        include_false_positives: includeFalsePositives || undefined,
      }),
    [
      debouncedQ,
      severity,
      priority,
      status,
      scanner,
      kev,
      includeDuplicates,
      includeFalsePositives,
      offset,
    ],
    { enabled: canRead },
  );

  if (!canRead) {
    return (
      <div className="space-y-6">
        <PageHeader title="Findings" />
        <EmptyState title="No access" description="You don't have permission to view this." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        description="Vulnerabilities and issues discovered across your assessments."
      />

      <Card>
        <CardBody className="space-y-4">
          <Field label="Search" htmlFor="f-q">
            <Input
              id="f-q"
              type="search"
              placeholder="Search by title, CVE, component…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setOffset(0);
              }}
            />
          </Field>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <Field label="Severity" htmlFor="f-severity">
              <Select
                id="f-severity"
                value={severity}
                onChange={(e) => {
                  setSeverity(e.target.value as Severity | "");
                  setOffset(0);
                }}
              >
                <option value="">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {humanize(s)}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Priority" htmlFor="f-priority">
              <Select
                id="f-priority"
                value={priority}
                onChange={(e) => {
                  setPriority(e.target.value as Priority | "");
                  setOffset(0);
                }}
              >
                <option value="">All priorities</option>
                {PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Status" htmlFor="f-status">
              <Select
                id="f-status"
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value as FindingStatus | "");
                  setOffset(0);
                }}
              >
                <option value="">All statuses</option>
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {humanize(s)}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Scanner" htmlFor="f-scanner">
              <Select
                id="f-scanner"
                value={scanner}
                onChange={(e) => {
                  setScanner(e.target.value as ScannerName | "");
                  setOffset(0);
                }}
              >
                <option value="">All scanners</option>
                {SCANNERS.map((s) => (
                  <option key={s} value={s}>
                    {humanize(s)}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="KEV" htmlFor="f-kev">
              <Select
                id="f-kev"
                value={kev}
                onChange={(e) => {
                  setKev(e.target.value as KevChoice);
                  setOffset(0);
                }}
              >
                <option value="all">All</option>
                <option value="in">In KEV</option>
                <option value="not">Not in KEV</option>
              </Select>
            </Field>
          </div>

          <div className="flex flex-wrap items-center gap-5">
            <label className="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-line bg-surface-2 accent-primary"
                checked={includeDuplicates}
                onChange={(e) => {
                  setIncludeDuplicates(e.target.checked);
                  setOffset(0);
                }}
              />
              Include duplicates
            </label>
            <label className="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-line bg-surface-2 accent-primary"
                checked={includeFalsePositives}
                onChange={(e) => {
                  setIncludeFalsePositives(e.target.checked);
                  setOffset(0);
                }}
              />
              Include false positives
            </label>
          </div>
        </CardBody>
      </Card>

      {loading && !data ? (
        <LoadingState label="Loading findings…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No findings"
          description="No findings match your current filters."
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH>Severity</TH>
                <TH>Title</TH>
                <TH>Priority</TH>
                <TH>Scanner</TH>
                <TH>CVE</TH>
                <TH>KEV</TH>
                <TH>Status</TH>
                <TH>Created</TH>
              </TR>
            </THead>
            <TBody>
              {data.items.map((f) => (
                <TR key={f.id} clickable onClick={() => router.push(`/findings/${f.id}`)}>
                  <TD>
                    <SeverityBadge severity={f.severity} />
                  </TD>
                  <TD>
                    <span
                      className="block max-w-[28rem] truncate font-medium text-fg"
                      title={f.title}
                    >
                      {f.title}
                    </span>
                  </TD>
                  <TD>
                    {f.priority ? (
                      <PriorityBadge priority={f.priority} />
                    ) : (
                      <span className="text-faint">—</span>
                    )}
                  </TD>
                  <TD className="text-muted">{humanize(f.scanner)}</TD>
                  <TD className="whitespace-nowrap text-muted">
                    {f.cve_ids.length > 0
                      ? `${f.cve_ids[0]}${
                          f.cve_ids.length > 1 ? ` +${f.cve_ids.length - 1}` : ""
                        }`
                      : "—"}
                  </TD>
                  <TD>
                    <KevBadge inKev={f.in_kev} />
                  </TD>
                  <TD>
                    <FindingStatusBadge status={f.status} />
                  </TD>
                  <TD className="whitespace-nowrap text-muted">
                    {formatRelative(f.created_at)}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </div>
      )}
    </div>
  );
}
