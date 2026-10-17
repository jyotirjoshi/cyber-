"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { workspaceManifestFilename, workspaceQuotaPercent } from "@/lib/agent-workspace";
import { api } from "@/lib/api";
import { formatDateTime, humanize } from "@/lib/format";
import type { WorkspaceArtifactOut } from "@/lib/types";

export default function AgentWorkspaceDetailPage() {
  const id = String(useParams<{ id: string }>().id);
  const { toast } = useToast();
  const [file, setFile] = React.useState<File | null>(null);
  const [kind, setKind] = React.useState<WorkspaceArtifactOut["kind"]>("evidence");
  const [taskId, setTaskId] = React.useState("");
  const [namespace, setNamespace] = React.useState("notes");
  const [recordKey, setRecordKey] = React.useState("");
  const [recordValue, setRecordValue] = React.useState("{}");
  const workspace = useApiResource(() => api.agentWorkspaces.get(id), [id]);
  const manifest = useApiResource(() => api.agentWorkspaces.evidenceExport(id), [id]);
  const changeStatus = useMutation(async (status: "active" | "suspended" | "closed") => {
    if (!workspace.data) throw new Error("Workspace unavailable");
    return api.agentWorkspaces.updateStatus(id, status, workspace.data.version);
  }, { onSuccess: () => { toast({ title: "Workspace status updated", tone: "ok" }); void workspace.refetch(); void manifest.refetch(); } });
  const upload = useMutation(async () => {
    if (!file) throw new Error("Choose an artifact");
    return api.agentWorkspaces.uploadArtifact(id, { file, kind, taskId: taskId.trim() || undefined, isEvidence: true });
  }, { onSuccess: () => { toast({ title: "Evidence artifact uploaded", tone: "ok" }); setFile(null); void workspace.refetch(); void manifest.refetch(); } });
  const saveRecord = useMutation(async () => {
    let value: Record<string, unknown>;
    try { value = JSON.parse(recordValue) as Record<string, unknown>; }
    catch { throw new Error("Shared record value must be valid JSON"); }
    return api.agentWorkspaces.putRecord(id, { namespace, key: recordKey.trim(), value });
  }, { onSuccess: () => { toast({ title: "Shared workspace record saved", tone: "ok" }); setRecordKey(""); setRecordValue("{}"); void manifest.refetch(); } });

  if (workspace.loading && !workspace.data) return <LoadingState label="Loading workspace…" />;
  if (workspace.error || !workspace.data) return <ErrorState message={workspace.error ?? "Workspace unavailable"} onRetry={workspace.refetch} />;
  const record = workspace.data;
  const percent = workspaceQuotaPercent(record.used_bytes, record.max_bytes);

  function downloadManifest() {
    if (!manifest.data) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(manifest.data, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = workspaceManifestFilename(record.name);
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return <div className="space-y-6">
    <PageHeader title={record.name} description={`Evidence workspace for agent run ${record.run_id}`} actions={<div className="flex gap-2"><Button variant="ghost" onClick={downloadManifest} disabled={!manifest.data}>Export evidence</Button><Link href="/agent/workspaces"><Button variant="ghost">All workspaces</Button></Link></div>} />
    <div className="grid gap-4 md:grid-cols-4">
      <Card><CardBody><p className="text-xs text-muted">Status</p><Badge tone={record.status === "active" ? "primary" : record.status === "suspended" ? "warn" : "neutral"}>{humanize(record.status)}</Badge></CardBody></Card>
      <Card><CardBody><p className="text-xs text-muted">Storage</p><p className="text-xl font-semibold">{percent}%</p></CardBody></Card>
      <Card><CardBody><p className="text-xs text-muted">Evidence files</p><p className="text-xl font-semibold">{manifest.data?.artifacts.length ?? "—"}</p></CardBody></Card>
      <Card><CardBody><p className="text-xs text-muted">Expires</p><p className="text-sm font-medium">{formatDateTime(record.expires_at)}</p></CardBody></Card>
    </div>
    {record.status !== "closed" && <div className="flex gap-2">{record.status === "active" ? <Button variant="ghost" onClick={() => void changeStatus.run("suspended")} loading={changeStatus.loading}>Suspend</Button> : <Button variant="ghost" onClick={() => void changeStatus.run("active")} loading={changeStatus.loading}>Resume</Button>}<Button variant="danger" onClick={() => void changeStatus.run("closed")} loading={changeStatus.loading}>Close workspace</Button></div>}
    <div className="grid gap-6 xl:grid-cols-2">
      <Card><CardHeader><div><CardTitle>Evidence artifacts</CardTitle><p className="mt-1 text-xs text-muted">Immutable files with SHA-256 integrity metadata.</p></div></CardHeader><CardBody className="space-y-4">
        {record.status === "active" && <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void upload.run(); }}>
          <Field label="File" htmlFor="artifact-file"><Input id="artifact-file" type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} required /></Field>
          <div className="grid gap-3 sm:grid-cols-2"><Field label="Kind" htmlFor="artifact-kind"><Select id="artifact-kind" value={kind} onChange={(event) => setKind(event.target.value as WorkspaceArtifactOut["kind"])}>{["evidence", "screenshot", "har", "console", "report", "output", "input", "archive"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</Select></Field><Field label="Agent task ID (optional)" htmlFor="artifact-task"><Input id="artifact-task" value={taskId} onChange={(event) => setTaskId(event.target.value)} /></Field></div>
          {upload.errorMessage && <p className="text-sm text-danger">{upload.errorMessage}</p>}<Button type="submit" loading={upload.loading}>Upload evidence</Button>
        </form>}
        {manifest.loading ? <LoadingState label="Loading artifacts…" /> : !manifest.data?.artifacts.length ? <EmptyState title="No artifacts" description="Upload evidence generated by an approved task." /> : <ul className="divide-y divide-line">{manifest.data.artifacts.map((artifact) => <li key={artifact.id} className="py-3"><div className="flex items-center justify-between gap-3"><div><p className="text-sm font-medium">{artifact.filename}</p><p className="font-mono text-xs text-muted">{artifact.sha256.slice(0, 16)}… · {artifact.size_bytes.toLocaleString()} bytes</p></div><Badge tone={artifact.is_evidence ? "ok" : "neutral"}>{humanize(artifact.kind)}</Badge></div></li>)}</ul>}
      </CardBody></Card>
      <Card><CardHeader><div><CardTitle>Shared agent state</CardTitle><p className="mt-1 text-xs text-muted">Bounded, versioned records specialists can use for handoffs.</p></div></CardHeader><CardBody className="space-y-4">
        {record.status === "active" && <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void saveRecord.run(); }}><div className="grid gap-3 sm:grid-cols-2"><Field label="Namespace" htmlFor="record-namespace"><Input id="record-namespace" value={namespace} onChange={(event) => setNamespace(event.target.value)} required /></Field><Field label="Key" htmlFor="record-key"><Input id="record-key" value={recordKey} onChange={(event) => setRecordKey(event.target.value)} required /></Field></div><Field label="JSON value" htmlFor="record-value"><Textarea id="record-value" value={recordValue} onChange={(event) => setRecordValue(event.target.value)} className="font-mono" required /></Field>{saveRecord.errorMessage && <p className="text-sm text-danger">{saveRecord.errorMessage}</p>}<Button type="submit" loading={saveRecord.loading}>Save shared record</Button></form>}
        {!manifest.data?.records.length ? <EmptyState title="No shared records" description="Store structured handoff notes, targets, and non-secret observations." /> : <ul className="space-y-3">{manifest.data.records.map((item) => <li key={`${item.namespace}:${item.key}`} className="rounded-lg border border-line bg-surface-2 p-3"><p className="font-mono text-xs text-primary">{item.namespace}/{item.key} · v{item.version}</p><pre className="mt-2 overflow-auto text-xs text-muted">{JSON.stringify(item.value, null, 2)}</pre></li>)}</ul>}
      </CardBody></Card>
    </div>
    <Card><CardHeader><div><CardTitle>Approved execution lineage</CardTitle><p className="mt-1 text-xs text-muted">Fingerprints bound to scheduler tasks and human approvals; raw arguments and secrets are excluded.</p></div></CardHeader><CardBody>{!manifest.data?.executions.length ? <EmptyState title="No execution records" description="Execution lineage appears when an approved agent task binds its workspace metadata." /> : <div className="grid gap-3 md:grid-cols-2">{manifest.data.executions.map((execution) => <div key={execution.id} className="rounded-lg border border-line p-3"><div className="flex justify-between"><p className="font-medium">{execution.executable}</p><Badge tone={execution.status === "completed" ? "ok" : "info"}>{humanize(execution.status)}</Badge></div><p className="mt-2 break-all font-mono text-xs text-muted">{execution.command_digest}</p><p className="mt-2 text-xs text-muted">Task {execution.task_id} · Approval {execution.approval_id}</p></div>)}</div>}</CardBody></Card>
  </div>;
}
