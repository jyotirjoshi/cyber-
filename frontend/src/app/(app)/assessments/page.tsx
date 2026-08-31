"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";

import { AssessmentStatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, THead, TD, TH, TR, Table } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatNumber, formatRelative, humanize } from "@/lib/format";
import type { AssessmentStatus, Scope } from "@/lib/types";

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
  const canRead = can("assessment:read");
  const canCreate = can("assessment:create");

  const [q, setQ] = React.useState("");
  const debouncedQ = useDebouncedValue(q);
  const [status, setStatus] = React.useState<AssessmentStatus | "">("");
  const [scope, setScope] = React.useState<Scope | "">("");
  const [activeOnly, setActiveOnly] = React.useState(false);
  const [awaitingApproval, setAwaitingApproval] = React.useState(false);
  const [offset, setOffset] = React.useState(0);

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

  if (!canRead) {
    return (
      <EmptyState
        title="No access"
        description="You don't have permission to view this."
      />
    );
  }

  const hasFilters = Boolean(trimmedQ || status || scope || activeOnly || awaitingApproval);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Assessments"
        description="Natural-language security assessments and their progress."
        actions={
          canCreate ? (
            <Link href="/assessments/new">
              <Button>New assessment</Button>
            </Link>
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
    </div>
  );
}
