"use client";

import Link from "next/link";
import * as React from "react";

import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, THead, TD, TH, TR, Table } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { workspaceQuotaPercent } from "@/lib/agent-workspace";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, humanize } from "@/lib/format";
import type { AgentWorkspaceStatus } from "@/lib/types";

const PAGE_SIZE = 25;
const STATUS_TONE: Record<AgentWorkspaceStatus, BadgeTone> = {
  active: "primary",
  suspended: "warn",
  closed: "neutral",
  expired: "danger",
};

export default function AgentWorkspacesPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const [offset, setOffset] = React.useState(0);
  const [open, setOpen] = React.useState(false);
  const [runId, setRunId] = React.useState("");
  const [name, setName] = React.useState("");
  const [quotaGiB, setQuotaGiB] = React.useState(1);
  const [ttlHours, setTtlHours] = React.useState(24);
  const allowed = can("agent:chat");
  const workspaces = useApiResource(
    () => api.agentWorkspaces.list({ limit: PAGE_SIZE, offset }),
    [offset],
    { enabled: allowed },
  );
  const create = useMutation(api.agentWorkspaces.create, {
    onSuccess: () => {
      toast({ title: "Agent workspace created", tone: "ok" });
      setOpen(false);
      setRunId("");
      setName("");
      void workspaces.refetch();
    },
  });

  if (!allowed) {
    return <EmptyState title="No access" description="You cannot use agent workspaces." />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent workspaces"
        description="Durable, quota-bounded evidence and shared state for approved multi-agent runs."
        actions={<Button onClick={() => setOpen(true)}>New workspace</Button>}
      />
      {workspaces.loading && !workspaces.data ? (
        <LoadingState label="Loading agent workspaces…" />
      ) : workspaces.error ? (
        <ErrorState message={workspaces.error} onRetry={workspaces.refetch} />
      ) : !workspaces.data?.items.length ? (
        <EmptyState
          title="No workspaces yet"
          description="Start a multi-agent run, then attach a durable workspace using its run ID."
        />
      ) : (
        <Card><CardBody className="p-0"><Table><THead><TR><TH>Workspace</TH><TH>Status</TH><TH>Storage</TH><TH>Run</TH><TH>Expires</TH></TR></THead><TBody>
          {workspaces.data.items.map((workspace) => {
            const percent = workspaceQuotaPercent(workspace.used_bytes, workspace.max_bytes);
            return <TR key={workspace.id}>
              <TD><Link href={`/agent/workspaces/${workspace.id}`} className="font-medium text-fg hover:text-primary">{workspace.name}</Link></TD>
              <TD><Badge tone={STATUS_TONE[workspace.status]}>{humanize(workspace.status)}</Badge></TD>
              <TD className="min-w-40"><div className="h-1.5 overflow-hidden rounded-full bg-surface-2"><div className="h-full bg-primary" style={{ width: `${percent}%` }} /></div><p className="mt-1 text-xs text-muted">{percent}% used</p></TD>
              <TD><span className="font-mono text-xs text-muted">{workspace.run_id.slice(0, 8)}</span></TD>
              <TD className="text-muted">{formatDateTime(workspace.expires_at)}</TD>
            </TR>;
          })}
        </TBody></Table></CardBody></Card>
      )}
      {workspaces.data && <Pagination meta={workspaces.data.meta} onOffsetChange={setOffset} />}
      {open && <Modal title="New agent workspace" onClose={() => setOpen(false)}><form className="space-y-4" onSubmit={(event) => {
        event.preventDefault();
        void create.run({ run_id: runId.trim(), name: name.trim(), max_bytes: Math.round(quotaGiB * 1_073_741_824), ttl_hours: ttlHours });
      }}>
        <Field label="Agent run ID" htmlFor="workspace-run" hint="Use the durable run ID shown in the Agent run view." required><Input id="workspace-run" value={runId} onChange={(event) => setRunId(event.target.value)} required /></Field>
        <Field label="Workspace name" htmlFor="workspace-name" required><Input id="workspace-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={200} /></Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Quota (GiB)" htmlFor="workspace-quota"><Input id="workspace-quota" type="number" min={0.001} max={10} step={0.25} value={quotaGiB} onChange={(event) => setQuotaGiB(Number(event.target.value))} /></Field>
          <Field label="Lifetime (hours)" htmlFor="workspace-ttl"><Input id="workspace-ttl" type="number" min={1} max={168} value={ttlHours} onChange={(event) => setTtlHours(Number(event.target.value))} /></Field>
        </div>
        {create.errorMessage && <p role="alert" className="text-sm text-danger">{create.errorMessage}</p>}
        <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" loading={create.loading}>Create workspace</Button></div>
      </form></Modal>}
    </div>
  );
}
