"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { formatDateTime, humanize } from "@/lib/format";
import type {
  ComplianceControlOut,
  ComplianceControlStatus,
  ComplianceEvidenceRequestOut,
  ComplianceFramework,
} from "@/lib/types";

const FRAMEWORKS: Array<{ id: ComplianceFramework; label: string }> = [
  { id: "pci_dss", label: "PCI DSS" },
  { id: "iso_27001", label: "ISO 27001" },
  { id: "soc_2", label: "SOC 2" },
  { id: "hipaa", label: "HIPAA" },
  { id: "nist_csf", label: "NIST CSF" },
  { id: "cis_controls", label: "CIS Controls" },
];

function statusTone(status: ComplianceControlStatus): "ok" | "warn" | "danger" | "neutral" {
  if (status === "satisfied") return "ok";
  if (status === "at_risk") return "danger";
  if (status === "partially_satisfied") return "warn";
  return "neutral";
}

export default function CompliancePage() {
  const { can } = useAuth();
  const canRead = can("finding:read");
  const canManage = can("org:manage");
  const [selectedFramework, setSelectedFramework] = React.useState<ComplianceFramework | "">("");
  const [busyFramework, setBusyFramework] = React.useState<ComplianceFramework | null>(null);
  const [mutationError, setMutationError] = React.useState<string | null>(null);

  const overview = useApiResource(() => api.compliance.overview(), [], { enabled: canRead });
  const controls = useApiResource(
    () => api.compliance.controls(selectedFramework || undefined),
    [selectedFramework],
    { enabled: canRead },
  );

  const seed = async (framework: ComplianceFramework) => {
    if (!canManage || busyFramework) return;
    setBusyFramework(framework);
    setMutationError(null);
    try {
      await api.compliance.seed(framework);
      overview.refetch();
      controls.refetch();
    } catch (error) {
      setMutationError(getErrorMessage(error));
    } finally {
      setBusyFramework(null);
    }
  };

  if (!canRead) {
    return <EmptyState title="No access" description="You don't have permission to view compliance evidence." />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance"
        description="Evidence-backed control coverage from canonical findings. This supports audit readiness; it is not a certification decision."
      />

      {overview.loading && !overview.data ? <LoadingState label="Loading compliance coverage…" /> : overview.error ? <ErrorState message={overview.error} onRetry={overview.refetch} /> : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {overview.data?.frameworks.map((framework) => (
            <Card key={framework.framework}>
              <CardBody className="space-y-2">
                <div className="flex items-center justify-between gap-3"><h2 className="text-sm font-semibold text-fg">{FRAMEWORKS.find((item) => item.id === framework.framework)?.label ?? humanize(framework.framework)}</h2><Badge tone={framework.at_risk_control_count ? "danger" : "neutral"}>{framework.coverage_percent.toFixed(0)}% mapped</Badge></div>
                <p className="text-xs text-muted">{framework.control_count} controls · {framework.mapped_control_count} mapped · {framework.active_finding_count} active finding links</p>
                <div className="text-sm text-fg"><span className="font-semibold text-danger">{framework.at_risk_control_count}</span> at risk · <span className="font-semibold text-warn">{framework.partially_satisfied_control_count}</span> partial · <span className="font-semibold text-ok">{framework.satisfied_control_count}</span> satisfied</div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <Card>
        <CardBody className="space-y-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><h2 className="text-sm font-semibold text-fg">Controls</h2><p className="text-xs text-muted">A control becomes at risk when an unresolved mapped finding has a risk score of 70 or higher.</p></div><select aria-label="Compliance framework" className="h-9 rounded-lg border border-line bg-surface-2 px-2 text-sm text-fg" value={selectedFramework} onChange={(event) => setSelectedFramework(event.target.value as ComplianceFramework | "")}><option value="">All frameworks</option>{FRAMEWORKS.map((framework) => <option key={framework.id} value={framework.id}>{framework.label}</option>)}</select></div>
          {canManage && <div className="flex flex-wrap gap-2 border-t border-line pt-3">{FRAMEWORKS.map((framework) => <Button key={framework.id} size="sm" variant="outline" loading={busyFramework === framework.id} disabled={busyFramework !== null} onClick={() => void seed(framework.id)}>Activate {framework.label}</Button>)}</div>}
          {mutationError && <p role="alert" className="text-sm text-danger">{mutationError}</p>}
          {controls.loading && !controls.data ? <LoadingState label="Loading controls…" /> : controls.error ? <ErrorState message={controls.error} onRetry={controls.refetch} /> : !controls.data?.length ? <EmptyState title="No controls activated" description={canManage ? "Activate a starter framework above, then map its controls to canonical findings." : "Ask an organization manager to activate a framework."} /> : (
            <Table><THead><TR><TH>Framework</TH><TH>Control</TH><TH>Status</TH><TH>Finding links</TH><TH>Highest risk</TH></TR></THead><TBody>{controls.data.map((control) => <TR key={control.id}><TD>{FRAMEWORKS.find((item) => item.id === control.framework)?.label ?? humanize(control.framework)}</TD><TD><div className="font-medium text-fg">{control.control_id}</div><div className="text-xs text-muted">{control.title}</div></TD><TD><Badge tone={statusTone(control.effective_status)}>{humanize(control.effective_status)}</Badge></TD><TD>{control.active_finding_count} active / {control.mapped_finding_count} mapped</TD><TD>{control.highest_risk_score === null ? "—" : `${control.highest_risk_score.toFixed(0)}/100`}</TD></TR>)}</TBody></Table>
          )}
        </CardBody>
      </Card>

      <ComplianceEvidenceWorkflow controls={controls.data ?? []} canManage={canManage} canOperate={can("report:generate")} />
    </div>
  );
}

function requestTone(status: ComplianceEvidenceRequestOut["status"]): "ok" | "warn" | "danger" | "neutral" {
  if (status === "accepted") return "ok";
  if (status === "rejected") return "danger";
  if (status === "submitted") return "warn";
  return "neutral";
}

function ComplianceEvidenceWorkflow({ controls, canManage, canOperate }: { controls: ComplianceControlOut[]; canManage: boolean; canOperate: boolean }) {
  const workspaces = useApiResource(() => api.compliance.workspaces(), [], { enabled: true });
  const requests = useApiResource(() => api.compliance.evidenceRequests(), [], { enabled: true });
  const inheritances = useApiResource(() => api.compliance.inheritances(), [], { enabled: true });
  const [workspaceName, setWorkspaceName] = React.useState("");
  const [workspaceFramework, setWorkspaceFramework] = React.useState<ComplianceFramework>("soc_2");
  const [workspaceDue, setWorkspaceDue] = React.useState("");
  const [requestWorkspace, setRequestWorkspace] = React.useState("");
  const [requestControl, setRequestControl] = React.useState("");
  const [requestTitle, setRequestTitle] = React.useState("");
  const [requestDescription, setRequestDescription] = React.useState("");
  const [requestDue, setRequestDue] = React.useState("");
  const [evidenceControl, setEvidenceControl] = React.useState("");
  const [evidenceTitle, setEvidenceTitle] = React.useState("");
  const [evidenceReference, setEvidenceReference] = React.useState("");
  const [evidenceIds, setEvidenceIds] = React.useState<Record<string, string>>({});
  const [reviewNotes, setReviewNotes] = React.useState<Record<string, string>>({});
  const [inheritanceChild, setInheritanceChild] = React.useState("");
  const [inheritanceParent, setInheritanceParent] = React.useState("");
  const [inheritanceSource, setInheritanceSource] = React.useState("");
  const [inheritancePercentage, setInheritancePercentage] = React.useState("100");

  const selectedWorkspace = workspaces.data?.find((item) => item.id === requestWorkspace);
  const workspaceControls = controls.filter((control) =>
    selectedWorkspace && control.framework === selectedWorkspace.framework &&
      (!selectedWorkspace.control_ids.length || selectedWorkspace.control_ids.includes(control.id)),
  );
  const evidence = useApiResource(
    () => api.compliance.evidence(evidenceControl),
    [evidenceControl],
    { enabled: Boolean(evidenceControl) },
  );

  React.useEffect(() => {
    if (!requestWorkspace && workspaces.data?.[0]) setRequestWorkspace(workspaces.data[0].id);
  }, [requestWorkspace, workspaces.data]);
  React.useEffect(() => {
    if (workspaceControls.length && !workspaceControls.some((item) => item.id === requestControl)) {
      setRequestControl(workspaceControls[0].id);
    }
  }, [requestControl, workspaceControls]);
  React.useEffect(() => {
    if (!evidenceControl && controls[0]) setEvidenceControl(controls[0].id);
  }, [controls, evidenceControl]);
  React.useEffect(() => {
    if (!inheritanceChild && controls[0]) setInheritanceChild(controls[0].id);
    const parent = controls.find((item) => item.id !== (inheritanceChild || controls[0]?.id));
    if ((!inheritanceParent || inheritanceParent === inheritanceChild) && parent) setInheritanceParent(parent.id);
  }, [controls, inheritanceChild, inheritanceParent]);

  const createWorkspace = useMutation(
    () => api.compliance.createWorkspace({
      name: workspaceName.trim(),
      framework: workspaceFramework,
      control_ids: controls.filter((item) => item.framework === workspaceFramework).map((item) => item.id),
      auditor_emails: [],
      due_at: workspaceDue ? new Date(workspaceDue).toISOString() : null,
      evidence_cutoff_at: workspaceDue ? new Date(workspaceDue).toISOString() : null,
    }),
    { onSuccess: (row) => { setWorkspaceName(""); setWorkspaceDue(""); setRequestWorkspace(row.id); workspaces.refetch(); } },
  );
  const createRequest = useMutation(
    () => api.compliance.createEvidenceRequest({
      workspace_id: requestWorkspace,
      control_id: requestControl,
      request_key: `${requestWorkspace.slice(0, 8)}-${requestControl.slice(0, 8)}-${Date.now()}`,
      title: requestTitle.trim(),
      description: requestDescription.trim(),
      freshness_days: 90,
      due_at: requestDue ? new Date(requestDue).toISOString() : null,
    }),
    { onSuccess: () => { setRequestTitle(""); setRequestDescription(""); setRequestDue(""); requests.refetch(); } },
  );
  const addEvidence = useMutation(
    () => api.compliance.addEvidence(evidenceControl, {
      title: evidenceTitle.trim(),
      evidence_type: "artifact",
      source_reference: evidenceReference.trim(),
      metadata: { collected_from: "compliance_workspace" },
    }),
    { onSuccess: () => { setEvidenceTitle(""); setEvidenceReference(""); evidence.refetch(); } },
  );
  const reviewEvidence = useMutation(
    (id: string, decision: "verified" | "rejected") => api.compliance.reviewEvidence(id, {
      decision,
      note: decision === "verified" ? "Evidence independently verified in the compliance workspace." : "Evidence rejected during independent review.",
    }),
    { onSuccess: () => evidence.refetch() },
  );
  const transition = useMutation(
    (row: ComplianceEvidenceRequestOut, status: "collecting" | "submitted" | "accepted" | "rejected" | "cancelled") =>
      api.compliance.transitionEvidenceRequest(row.id, {
        expected_status: row.status as Exclude<ComplianceEvidenceRequestOut["status"], "cancelled">,
        status,
        evidence_ids: status === "submitted" ? (evidenceIds[row.id] ?? "").split(/[\s,]+/).filter(Boolean) : [],
        note: status === "rejected" ? reviewNotes[row.id] ?? "" : null,
      }),
    { onSuccess: () => requests.refetch() },
  );
  const createInheritance = useMutation(
    () => api.compliance.createInheritance({
      control_id: inheritanceChild,
      parent_control_id: inheritanceParent,
      source_system: inheritanceSource.trim(),
      responsibility: "shared",
      inherited_percentage: Number(inheritancePercentage),
      evidence_refs: [],
    }),
    { onSuccess: () => { setInheritanceSource(""); inheritances.refetch(); } },
  );
  const deleteInheritance = useMutation(
    (id: string) => api.compliance.deleteInheritance(id),
    { onSuccess: () => inheritances.refetch() },
  );

  return <div className="space-y-4">
    <Card>
      <CardHeader><div><CardTitle>Audit evidence operations</CardTitle><p className="mt-1 text-xs text-muted">Collect, independently verify, submit, and approve fresh evidence inside a bounded audit workspace.</p></div></CardHeader>
      <CardBody className="space-y-5">
        {canManage && <div className="grid gap-5 xl:grid-cols-3">
          <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void createWorkspace.run(); }}>
            <h3 className="text-sm font-semibold text-fg">1. Create workspace</h3>
            <Field label="Workspace name" htmlFor="compliance-workspace-name"><Input id="compliance-workspace-name" required maxLength={200} value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} /></Field>
            <Field label="Framework" htmlFor="compliance-workspace-framework"><Select id="compliance-workspace-framework" value={workspaceFramework} onChange={(event) => setWorkspaceFramework(event.target.value as ComplianceFramework)}>{FRAMEWORKS.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</Select></Field>
            <Field label="Due date" htmlFor="compliance-workspace-due"><Input id="compliance-workspace-due" type="datetime-local" value={workspaceDue} onChange={(event) => setWorkspaceDue(event.target.value)} /></Field>
            {createWorkspace.errorMessage && <p role="alert" className="text-xs text-danger">{createWorkspace.errorMessage}</p>}
            <Button type="submit" size="sm" loading={createWorkspace.loading} disabled={!controls.some((item) => item.framework === workspaceFramework)}>Create workspace</Button>
          </form>
          <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void createRequest.run(); }}>
            <h3 className="text-sm font-semibold text-fg">2. Request evidence</h3>
            <Field label="Workspace" htmlFor="compliance-request-workspace"><Select id="compliance-request-workspace" required value={requestWorkspace} onChange={(event) => setRequestWorkspace(event.target.value)}><option value="">Select…</option>{workspaces.data?.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field>
            <Field label="Control" htmlFor="compliance-request-control"><Select id="compliance-request-control" required value={requestControl} onChange={(event) => setRequestControl(event.target.value)}><option value="">Select…</option>{workspaceControls.map((item) => <option key={item.id} value={item.id}>{item.control_id} · {item.title}</option>)}</Select></Field>
            <Field label="Request title" htmlFor="compliance-request-title"><Input id="compliance-request-title" required maxLength={300} value={requestTitle} onChange={(event) => setRequestTitle(event.target.value)} /></Field>
            <Field label="Instructions" htmlFor="compliance-request-description"><Textarea id="compliance-request-description" required maxLength={4000} value={requestDescription} onChange={(event) => setRequestDescription(event.target.value)} /></Field>
            <Field label="Due date" htmlFor="compliance-request-due"><Input id="compliance-request-due" type="datetime-local" value={requestDue} onChange={(event) => setRequestDue(event.target.value)} /></Field>
            {createRequest.errorMessage && <p role="alert" className="text-xs text-danger">{createRequest.errorMessage}</p>}
            <Button type="submit" size="sm" loading={createRequest.loading} disabled={!requestWorkspace || !requestControl}>Create request</Button>
          </form>
          <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void addEvidence.run(); }}>
            <h3 className="text-sm font-semibold text-fg">3. Collect evidence</h3>
            <Field label="Control" htmlFor="compliance-evidence-control"><Select id="compliance-evidence-control" required value={evidenceControl} onChange={(event) => setEvidenceControl(event.target.value)}><option value="">Select…</option>{controls.map((item) => <option key={item.id} value={item.id}>{item.control_id} · {item.title}</option>)}</Select></Field>
            <Field label="Evidence title" htmlFor="compliance-evidence-title"><Input id="compliance-evidence-title" required maxLength={300} value={evidenceTitle} onChange={(event) => setEvidenceTitle(event.target.value)} /></Field>
            <Field label="Immutable artifact reference" htmlFor="compliance-evidence-reference"><Input id="compliance-evidence-reference" required maxLength={2048} value={evidenceReference} onChange={(event) => setEvidenceReference(event.target.value)} placeholder="gs://bucket/object, ticket URL, or artifact URI" /></Field>
            {addEvidence.errorMessage && <p role="alert" className="text-xs text-danger">{addEvidence.errorMessage}</p>}
            <Button type="submit" size="sm" loading={addEvidence.loading} disabled={!evidenceControl}>Collect evidence</Button>
          </form>
        </div>}
        {evidenceControl && <div className="border-t border-line pt-4"><h3 className="mb-2 text-sm font-semibold text-fg">Evidence awaiting review</h3>{evidence.loading && !evidence.data ? <LoadingState label="Loading evidence…" /> : !evidence.data?.length ? <p className="text-sm text-muted">No evidence collected for this control.</p> : <Table><THead><TR><TH>Evidence</TH><TH>Status</TH><TH>Artifact</TH><TH>Review</TH></TR></THead><TBody>{evidence.data.map((item) => <TR key={item.id}><TD><div className="font-medium text-fg">{item.title}</div><div className="font-mono text-xs text-muted">{item.id}</div></TD><TD><Badge tone={item.collection_status === "verified" ? "ok" : item.collection_status === "rejected" ? "danger" : "neutral"}>{humanize(item.collection_status)}</Badge></TD><TD className="max-w-72 truncate">{item.source_reference}</TD><TD>{canManage && item.collection_status === "collected" ? <div className="flex gap-2"><Button size="sm" variant="outline" loading={reviewEvidence.loading} onClick={() => void reviewEvidence.run(item.id, "verified")}>Verify</Button><Button size="sm" variant="ghost" loading={reviewEvidence.loading} onClick={() => void reviewEvidence.run(item.id, "rejected")}>Reject</Button></div> : "—"}</TD></TR>)}</TBody></Table>}</div>}
      </CardBody>
    </Card>

    <Card>
      <CardHeader><CardTitle>Evidence request queue</CardTitle></CardHeader>
      <CardBody>{requests.loading && !requests.data ? <LoadingState label="Loading evidence requests…" /> : requests.error ? <ErrorState message={requests.error} onRetry={requests.refetch} /> : !requests.data?.length ? <EmptyState title="No evidence requests" description="Create an audit workspace and request evidence for one of its controls." /> : <Table><THead><TR><TH>Request</TH><TH>Status</TH><TH>Due</TH><TH>Evidence and decision</TH></TR></THead><TBody>{requests.data.map((row) => <TR key={row.id}><TD><div className="font-medium text-fg">{row.title}</div><div className="text-xs text-muted">{controls.find((item) => item.id === row.control_id)?.control_id ?? row.control_id}</div></TD><TD><Badge tone={requestTone(row.status)}>{humanize(row.status)}</Badge>{row.review_note && <p className="mt-1 max-w-56 text-xs text-muted">{row.review_note}</p>}</TD><TD>{formatDateTime(row.due_at)}</TD><TD>{canOperate ? <div className="min-w-72 space-y-2">{row.status === "open" && <div className="flex gap-2"><Button size="sm" onClick={() => void transition.run(row, "collecting")}>Start collection</Button><Button size="sm" variant="ghost" onClick={() => void transition.run(row, "cancelled")}>Cancel</Button></div>}{row.status === "collecting" && <div className="flex gap-2"><Input aria-label={`Evidence IDs for ${row.title}`} value={evidenceIds[row.id] ?? ""} onChange={(event) => setEvidenceIds((current) => ({ ...current, [row.id]: event.target.value }))} placeholder="Verified evidence UUIDs, comma separated" /><Button size="sm" disabled={!evidenceIds[row.id]?.trim()} onClick={() => void transition.run(row, "submitted")}>Submit</Button></div>}{row.status === "submitted" && <div className="space-y-2"><Input aria-label={`Review note for ${row.title}`} value={reviewNotes[row.id] ?? ""} onChange={(event) => setReviewNotes((current) => ({ ...current, [row.id]: event.target.value }))} placeholder="Review note (required for rejection)" /><div className="flex gap-2"><Button size="sm" onClick={() => void transition.run(row, "accepted")}>Accept</Button><Button size="sm" variant="outline" disabled={(reviewNotes[row.id] ?? "").trim().length < 3} onClick={() => void transition.run(row, "rejected")}>Reject</Button></div></div>}{row.status === "rejected" && <Button size="sm" onClick={() => void transition.run(row, "collecting")}>Reopen collection</Button>}{["accepted", "cancelled"].includes(row.status) && <span className="text-xs text-muted">Terminal · {row.fulfilled_evidence_ids.length} linked artifact(s)</span>}{transition.errorMessage && <p role="alert" className="text-xs text-danger">{transition.errorMessage}</p>}</div> : <span className="text-xs text-muted">Read only</span>}</TD></TR>)}</TBody></Table>}</CardBody>
    </Card>

    <Card>
      <CardHeader><div><CardTitle>Control inheritance</CardTitle><p className="mt-1 text-xs text-muted">Reuse provider or shared-control assurance without copying evidence. Cyclic trust chains are rejected.</p></div></CardHeader>
      <CardBody className="space-y-4">
        {canManage && <form className="grid gap-3 md:grid-cols-5" onSubmit={(event) => { event.preventDefault(); void createInheritance.run(); }}>
          <Field label="Child control" htmlFor="inheritance-child"><Select id="inheritance-child" required value={inheritanceChild} onChange={(event) => setInheritanceChild(event.target.value)}>{controls.map((item) => <option key={item.id} value={item.id}>{item.control_id} · {item.title}</option>)}</Select></Field>
          <Field label="Parent control" htmlFor="inheritance-parent"><Select id="inheritance-parent" required value={inheritanceParent} onChange={(event) => setInheritanceParent(event.target.value)}>{controls.filter((item) => item.id !== inheritanceChild).map((item) => <option key={item.id} value={item.id}>{item.control_id} · {item.title}</option>)}</Select></Field>
          <Field label="Source system" htmlFor="inheritance-source"><Input id="inheritance-source" required maxLength={240} value={inheritanceSource} onChange={(event) => setInheritanceSource(event.target.value)} placeholder="Cloud provider, GRC, or service" /></Field>
          <Field label="Inherited %" htmlFor="inheritance-percentage"><Input id="inheritance-percentage" required type="number" min="0" max="100" step="0.01" value={inheritancePercentage} onChange={(event) => setInheritancePercentage(event.target.value)} /></Field>
          <div className="flex items-end"><Button type="submit" size="sm" loading={createInheritance.loading} disabled={!inheritanceChild || !inheritanceParent || inheritanceChild === inheritanceParent}>Add inheritance</Button></div>
          {createInheritance.errorMessage && <p role="alert" className="text-xs text-danger md:col-span-5">{createInheritance.errorMessage}</p>}
        </form>}
        {inheritances.loading && !inheritances.data ? <LoadingState label="Loading inheritance graph…" /> : inheritances.error ? <ErrorState message={inheritances.error} onRetry={inheritances.refetch} /> : !inheritances.data?.length ? <p className="text-sm text-muted">No inherited controls configured.</p> : <Table><THead><TR><TH>Child</TH><TH>Parent</TH><TH>Responsibility</TH><TH>Inherited</TH><TH>Source</TH><TH /></TR></THead><TBody>{inheritances.data.map((row) => <TR key={row.id}><TD>{controls.find((item) => item.id === row.control_id)?.control_id ?? row.control_id}</TD><TD>{controls.find((item) => item.id === row.parent_control_id)?.control_id ?? row.parent_control_id}</TD><TD>{humanize(row.responsibility)}</TD><TD>{Number(row.inherited_percentage).toFixed(2)}%</TD><TD>{row.source_system}</TD><TD>{canManage && <Button size="sm" variant="ghost" loading={deleteInheritance.loading} onClick={() => void deleteInheritance.run(row.id)}>Remove</Button>}</TD></TR>)}</TBody></Table>}
        {deleteInheritance.errorMessage && <p role="alert" className="text-xs text-danger">{deleteInheritance.errorMessage}</p>}
      </CardBody>
    </Card>
  </div>;
}
