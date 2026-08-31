"use client";

import * as React from "react";

import { JobStatusBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api, saveBlob } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { formatDuration, formatNumber, formatRelative, humanize } from "@/lib/format";
import type { JobStatus, ScannerName } from "@/lib/types";

const PAGE_SIZE = 25;

const SCANNERS: readonly ScannerName[] = ["reconftw", "nmap", "nuclei", "zap"];

const STATUSES: readonly JobStatus[] = [
  "QUEUED",
  "RUNNING",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
  "TIMEOUT",
];

export default function JobsPage() {
  const { can } = useAuth();
  const { toast } = useToast();

  const canRead = can("assessment:read");
  const canCancel = can("assessment:cancel");

  const [scanner, setScanner] = React.useState<ScannerName | "">("");
  const [status, setStatus] = React.useState<JobStatus | "">("");
  const [activeOnly, setActiveOnly] = React.useState(false);
  const [offset, setOffset] = React.useState(0);
  const [busyCancelId, setBusyCancelId] = React.useState<string | null>(null);
  const [busyArtifactId, setBusyArtifactId] = React.useState<string | null>(null);

  const { data, error, loading, refetch } = useApiResource(
    () =>
      api.jobs.list({
        limit: PAGE_SIZE,
        offset,
        scanner: scanner || undefined,
        status: status || undefined,
        active: activeOnly || undefined,
      }),
    [scanner, status, activeOnly, offset],
    { enabled: canRead, refetchInterval: 15000 },
  );

  const cancelMut = useMutation((id: string) => api.jobs.cancel(id), {
    onSuccess: () => {
      refetch();
      toast({ title: "Cancellation requested", tone: "ok" });
    },
    onError: (err) =>
      toast({ title: "Couldn't cancel job", description: getErrorMessage(err), tone: "danger" }),
  });

  const downloadMut = useMutation(
    (jobId: string, artifactId: string) => api.jobs.downloadArtifact(jobId, artifactId),
    {
      onSuccess: (file) => saveBlob(file),
      onError: (err) =>
        toast({ title: "Download failed", description: getErrorMessage(err), tone: "danger" }),
    },
  );

  async function handleCancel(id: string) {
    setBusyCancelId(id);
    await cancelMut.run(id);
    setBusyCancelId(null);
  }

  async function handleDownload(jobId: string, artifactId: string) {
    setBusyArtifactId(artifactId);
    await downloadMut.run(jobId, artifactId);
    setBusyArtifactId(null);
  }

  if (!canRead) {
    return (
      <EmptyState title="No access" description="You don't have permission to view this." />
    );
  }

  const jobs = data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scanner jobs"
        description="Sandboxed scanner runs across your assessments, refreshed live."
      />

      <Card>
        <CardBody className="flex flex-wrap items-end gap-4">
          <Field label="Scanner" htmlFor="filter-scanner" className="w-44">
            <Select
              id="filter-scanner"
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

          <Field label="Status" htmlFor="filter-status" className="w-44">
            <Select
              id="filter-status"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value as JobStatus | "");
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

          <label className="flex h-10 items-center gap-2 text-sm text-muted">
            <input
              type="checkbox"
              checked={activeOnly}
              onChange={(e) => {
                setActiveOnly(e.target.checked);
                setOffset(0);
              }}
              className="h-4 w-4 rounded border border-line bg-surface-2 accent-primary"
            />
            Active only
          </label>
        </CardBody>
      </Card>

      {loading && !data ? (
        <LoadingState label="Loading scanner jobs…" />
      ) : error && !data ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : jobs.length === 0 ? (
        <EmptyState
          title="No scanner jobs"
          description="Scanner jobs appear here once an assessment begins scanning."
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH>Scanner</TH>
                <TH>Status</TH>
                <TH className="text-right">Targets</TH>
                <TH className="text-right">Findings</TH>
                <TH>Duration</TH>
                <TH>Created</TH>
                <TH className="text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {jobs.map((job) => {
                const rowCanCancel =
                  canCancel && (job.status === "QUEUED" || job.status === "RUNNING");
                const hasActions = rowCanCancel || job.artifacts.length > 0;
                return (
                  <TR key={job.id}>
                    <TD className="font-medium">{humanize(job.scanner)}</TD>
                    <TD>
                      <JobStatusBadge status={job.status} />
                    </TD>
                    <TD className="text-right tabular-nums">
                      {formatNumber(job.targets.length)}
                    </TD>
                    <TD className="text-right tabular-nums">
                      {formatNumber(job.imported_finding_count)}
                    </TD>
                    <TD className="text-muted">{formatDuration(job.duration_seconds)}</TD>
                    <TD className="text-muted">{formatRelative(job.created_at)}</TD>
                    <TD>
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        {rowCanCancel &&
                          (job.cancel_requested ? (
                            <Button size="sm" variant="outline" disabled>
                              Cancelling…
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="outline"
                              loading={busyCancelId === job.id}
                              onClick={() => void handleCancel(job.id)}
                            >
                              Cancel
                            </Button>
                          ))}
                        {job.artifacts.map((artifact) => (
                          <Button
                            key={artifact.id}
                            size="sm"
                            variant="ghost"
                            loading={busyArtifactId === artifact.id}
                            onClick={() => void handleDownload(job.id, artifact.id)}
                          >
                            Download {humanize(artifact.kind)}
                          </Button>
                        ))}
                        {!hasActions && <span className="text-faint">—</span>}
                      </div>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>

          {data && <Pagination meta={data.meta} onOffsetChange={setOffset} />}
        </div>
      )}
    </div>
  );
}
