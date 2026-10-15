"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, humanize } from "@/lib/format";
import { serializeWorkflow, validateWorkflow } from "@/lib/workflow-builder";
import type { WorkflowDefinitionIn, WorkflowDefinitionOut, WorkflowNodeIn } from "@/lib/types";

const TRIGGERS = ["finding.created", "finding.updated", "ticket.closed", "retest.cleared", "sla.breached", "cron"];
const ACTIONS = ["create_ticket", "notify", "request_retest", "schedule_retest", "assign_owner", "assign_codeowner", "set_remediation_group", "refresh_intelligence"];
const TICKET_PROVIDERS = ["jira", "github", "gitlab", "servicenow", "azure_devops", "linear"];

function blankWorkflow(): WorkflowDefinitionIn {
  return {
    name: "",
    description: "",
    nodes: [
      { id: "trigger", type: "trigger", config: { event: "finding.created" } },
      { id: "action-1", type: "action", config: { action: "create_ticket", provider: "jira" } },
    ],
    edges: [{ source: "trigger", target: "action-1" }],
    is_enabled: true,
    dry_run: true,
  };
}

export default function WorkflowsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("org:manage");
  const [editing, setEditing] = React.useState<WorkflowDefinitionOut | null>(null);
  const [form, setForm] = React.useState<WorkflowDefinitionIn>(blankWorkflow);
  const [showBuilder, setShowBuilder] = React.useState(false);
  const [selected, setSelected] = React.useState<WorkflowDefinitionOut | null>(null);
  const { data, error, loading, refetch } = useApiResource(
    () => api.workflows.list({ limit: 100, offset: 0 }),
    [],
  );
  const runs = useApiResource(
    () => api.workflows.runs(selected?.id ?? "", { limit: 25, offset: 0 }),
    [selected?.id],
    { enabled: selected !== null },
  );
  const save = useMutation(
    (body: WorkflowDefinitionIn) => editing ? api.workflows.update(editing.id, body) : api.workflows.create(body),
    {
      onSuccess: () => {
        toast({ title: editing ? "Workflow updated" : "Workflow created", tone: "ok" });
        setShowBuilder(false);
        setEditing(null);
        void refetch();
      },
    },
  );
  const remove = useMutation((id: string) => api.workflows.delete(id), {
    onSuccess: () => { toast({ title: "Workflow deleted", tone: "ok" }); void refetch(); },
  });

  function openCreate() {
    setEditing(null);
    setForm(blankWorkflow());
    setShowBuilder(true);
  }

  function openEdit(workflow: WorkflowDefinitionOut) {
    setEditing(workflow);
    setForm({
      name: workflow.name,
      description: workflow.description,
      nodes: workflow.nodes.map((node) => ({ ...node, config: { ...node.config } })),
      edges: workflow.edges.map((edge) => ({ ...edge })),
      is_enabled: workflow.is_enabled,
      dry_run: workflow.dry_run,
    });
    setShowBuilder(true);
  }

  function replaceNodes(nodes: WorkflowNodeIn[]) {
    setForm((current) => ({
      ...current,
      nodes,
      edges: nodes.slice(1).map((node, index) => ({
        source: nodes[index].id,
        target: node.id,
        ...(["condition", "branch"].includes(nodes[index].type) ? { branch: "true" as const } : {}),
      })),
    }));
  }

  function addNode(type: "condition" | "action" | "approval" | "delay") {
    const suffix = form.nodes.filter((node) => node.type === type).length + 1;
    const config = type === "condition"
      ? { condition: "severity_at_least", value: "critical" }
      : type === "action"
        ? { action: "notify", channels: ["email"] }
        : type === "approval"
          ? { label: "Security approval" }
          : { seconds: 300 };
    replaceNodes([...form.nodes, { id: `${type}-${suffix}`, type, config }]);
  }

  function updateNode(id: string, config: Record<string, unknown>) {
    replaceNodes(form.nodes.map((node) => node.id === id ? { ...node, config } : node));
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const normalized = serializeWorkflow(form);
    const errors = validateWorkflow(normalized);
    if (errors.length) {
      toast({ title: errors[0], tone: "danger" });
      return;
    }
    void save.run(normalized);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Durable workflows"
        description="Build resumable remediation playbooks with conditions, approvals, delays, and idempotent actions."
        action={canManage ? <Button onClick={openCreate}>New workflow</Button> : undefined}
      />
      {loading && !data ? <LoadingState label="Loading workflows…" /> : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data?.items.length ? (
        <EmptyState title="No workflows" description="Create a visual playbook for multi-step remediation." action={canManage ? <Button onClick={openCreate}>New workflow</Button> : undefined} />
      ) : (
        <Table>
          <THead><TR><TH>Name</TH><TH>Version</TH><TH>Steps</TH><TH>Mode</TH><TH>Updated</TH><TH /></TR></THead>
          <TBody>{data.items.map((workflow) => (
            <TR key={workflow.id}>
              <TD><button className="font-medium text-primary hover:underline" onClick={() => setSelected(workflow)}>{workflow.name}</button></TD>
              <TD>v{workflow.version}</TD>
              <TD>{workflow.nodes.length}</TD>
              <TD><div className="flex gap-2"><Badge tone={workflow.is_enabled ? "ok" : "neutral"}>{workflow.is_enabled ? "Enabled" : "Disabled"}</Badge>{workflow.dry_run && <Badge tone="warn">Dry run</Badge>}</div></TD>
              <TD className="text-muted">{formatDateTime(workflow.updated_at)}</TD>
              <TD>{canManage && <div className="flex gap-3"><button className="text-xs text-primary hover:underline" onClick={() => openEdit(workflow)}>Edit</button><button className="text-xs text-danger hover:underline" onClick={() => void remove.run(workflow.id)}>Delete</button></div>}</TD>
            </TR>
          ))}</TBody>
        </Table>
      )}

      {selected && <Card>
        <CardHeader><div className="flex items-center justify-between"><CardTitle>Runs · {selected.name}</CardTitle><Button size="sm" variant="ghost" onClick={() => setSelected(null)}>Close</Button></div></CardHeader>
        <CardBody>{runs.loading ? <LoadingState label="Loading runs…" /> : runs.error ? <ErrorState message={runs.error} onRetry={runs.refetch} /> : !runs.data?.items.length ? <p className="text-sm text-muted">No events have started this workflow.</p> : <Table><THead><TR><TH>Event</TH><TH>Status</TH><TH>Attempts</TH><TH>Started</TH><TH>Next resume</TH></TR></THead><TBody>{runs.data.items.map((run) => <TR key={run.id}><TD className="font-mono text-xs">{run.event_key}</TD><TD><Badge tone={run.status === "succeeded" ? "ok" : run.status === "failed" ? "danger" : run.status === "waiting" ? "warn" : "primary"}>{humanize(run.status)}</Badge></TD><TD>{run.attempts}</TD><TD className="text-muted">{run.started_at ? formatDateTime(run.started_at) : "—"}</TD><TD className="text-muted">{run.next_resume_at ? formatDateTime(run.next_resume_at) : "—"}</TD></TR>)}</TBody></Table>}</CardBody>
      </Card>}

      {showBuilder && <Modal title={editing ? "Edit workflow" : "New workflow"} onClose={() => setShowBuilder(false)}>
        <form className="space-y-5" onSubmit={submit}>
          <div className="grid gap-3 sm:grid-cols-2"><Field label="Name" htmlFor="wf-name"><Input id="wf-name" required maxLength={160} value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} /></Field><Field label="Description" htmlFor="wf-description"><Textarea id="wf-description" rows={2} maxLength={1000} value={form.description ?? ""} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} /></Field></div>
          <div className="space-y-2 rounded-xl border border-line bg-surface-2 p-3">
            {form.nodes.map((node, index) => <React.Fragment key={node.id}>
              {index > 0 && <div className="mx-auto h-5 w-px bg-line" />}
              <div className="rounded-lg border border-line bg-surface p-3">
                <div className="mb-3 flex items-center justify-between"><div><Badge tone={node.type === "trigger" ? "primary" : node.type === "approval" ? "warn" : "neutral"}>{humanize(node.type)}</Badge><span className="ml-2 font-mono text-xs text-muted">{node.id}</span></div>{node.type !== "trigger" && <button type="button" className="text-xs text-danger hover:underline" onClick={() => replaceNodes(form.nodes.filter((item) => item.id !== node.id))}>Remove</button>}</div>
                {node.type === "trigger" && <div className="space-y-3"><Field label="Event" htmlFor={`${node.id}-event`}><Select id={`${node.id}-event`} value={String(node.config.event)} onChange={(event) => updateNode(node.id, event.target.value === "cron" ? { event: "cron", cron_expression: "0 9 * * *", timezone: "UTC" } : { event: event.target.value })}>{TRIGGERS.map((trigger) => <option key={trigger} value={trigger}>{humanize(trigger)}</option>)}</Select></Field>{node.config.event === "cron" && <div className="grid gap-3 sm:grid-cols-2"><Field label="Cron expression" htmlFor={`${node.id}-cron`}><Input id={`${node.id}-cron`} value={String(node.config.cron_expression)} onChange={(event) => updateNode(node.id, { ...node.config, cron_expression: event.target.value })} /></Field><Field label="Timezone" htmlFor={`${node.id}-timezone`}><Input id={`${node.id}-timezone`} value={String(node.config.timezone)} onChange={(event) => updateNode(node.id, { ...node.config, timezone: event.target.value })} /></Field></div>}</div>}
                {node.type === "condition" && <div className="grid gap-3 sm:grid-cols-2"><Field label="Condition" htmlFor={`${node.id}-condition`}><Select id={`${node.id}-condition`} value={String(node.config.condition)} onChange={(event) => updateNode(node.id, { condition: event.target.value, value: event.target.value === "risk_score_at_least" ? 80 : ["in_kev", "internet_exposed"].includes(event.target.value) ? true : "critical" })}><option value="severity_at_least">Minimum severity</option><option value="risk_score_at_least">Minimum risk score</option><option value="in_kev">Known exploited</option><option value="internet_exposed">Internet exposed</option></Select></Field><Field label="Value" htmlFor={`${node.id}-value`}><Input id={`${node.id}-value`} value={String(node.config.value)} onChange={(event) => updateNode(node.id, { ...node.config, value: ["in_kev", "internet_exposed"].includes(String(node.config.condition)) ? event.target.value === "true" : node.config.condition === "risk_score_at_least" ? Number(event.target.value) : event.target.value })} /></Field></div>}
                {node.type === "action" && <div className="grid gap-3 sm:grid-cols-2"><Field label="Action" htmlFor={`${node.id}-action`}><Select id={`${node.id}-action`} value={String(node.config.action)} onChange={(event) => updateNode(node.id, event.target.value === "create_ticket" ? { action: event.target.value, provider: "jira" } : { action: event.target.value })}>{ACTIONS.map((action) => <option key={action} value={action}>{humanize(action)}</option>)}</Select></Field>{node.config.action === "create_ticket" && <Field label="Provider" htmlFor={`${node.id}-provider`}><Select id={`${node.id}-provider`} value={String(node.config.provider)} onChange={(event) => updateNode(node.id, { ...node.config, provider: event.target.value })}>{TICKET_PROVIDERS.map((provider) => <option key={provider} value={provider}>{humanize(provider)}</option>)}</Select></Field>}</div>}
                {node.type === "approval" && <Field label="Approval label" htmlFor={`${node.id}-label`}><Input id={`${node.id}-label`} value={String(node.config.label)} onChange={(event) => updateNode(node.id, { label: event.target.value })} /></Field>}
                {node.type === "delay" && <Field label="Delay (seconds)" htmlFor={`${node.id}-seconds`}><Input id={`${node.id}-seconds`} type="number" min={1} max={2592000} value={Number(node.config.seconds)} onChange={(event) => updateNode(node.id, { seconds: Number(event.target.value) })} /></Field>}
              </div>
            </React.Fragment>)}
          </div>
          <div className="flex flex-wrap gap-2"><Button type="button" size="sm" variant="secondary" onClick={() => addNode("condition")}>+ Condition</Button><Button type="button" size="sm" variant="secondary" onClick={() => addNode("action")}>+ Action</Button><Button type="button" size="sm" variant="secondary" onClick={() => addNode("approval")}>+ Approval</Button><Button type="button" size="sm" variant="secondary" onClick={() => addNode("delay")}>+ Delay</Button></div>
          <div className="flex flex-wrap gap-5 text-sm"><label className="flex items-center gap-2"><input type="checkbox" checked={form.is_enabled ?? true} onChange={(event) => setForm((current) => ({ ...current, is_enabled: event.target.checked }))} /> Enabled</label><label className="flex items-center gap-2"><input type="checkbox" checked={form.dry_run ?? false} onChange={(event) => setForm((current) => ({ ...current, dry_run: event.target.checked }))} /> Dry run until verified</label></div>
          <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setShowBuilder(false)}>Cancel</Button><Button type="submit" loading={save.loading}>Save workflow</Button></div>
        </form>
      </Modal>}
    </div>
  );
}
