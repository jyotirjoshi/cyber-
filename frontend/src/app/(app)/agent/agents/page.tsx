"use client";
import * as React from "react";
import { AgentEditor } from "@/components/agent/AgentEditor";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { AgentConfiguration, configurationFromVersion, defaultAgentConfiguration } from "@/lib/agent-definition";

export default function AgentsPage() {
  const { activeOrganizationId } = useAuth();
  return <AgentWorkspace key={activeOrganizationId ?? "none"} />;
}

function AgentWorkspace() {
  const { can } = useAuth();
  const manage = can("org:manage");
  const [offset, setOffset] = React.useState(0);
  const list = useApiResource(() => api.customAgents.list(offset), [offset]);
  const tools = useApiResource(api.customAgents.tools, []);
  const collections = useApiResource(api.knowledge.collections, []);
  const [selected, setSelected] = React.useState("");
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const create = useMutation(api.customAgents.create, { onSuccess: (row) => { list.refetch(); setSelected(row.id); } });
  return <div className="space-y-6">
    <PageHeader title="Custom agents" description="Configure reusable workers with immutable versions, selected tools, and organizational knowledge." />
    {[list.error, tools.error, collections.error, create.errorMessage].filter(Boolean).map((error, index) => <p key={index} role="alert" className="text-danger">{error}</p>)}
    <Field label="Agent" htmlFor="selected-agent"><Select id="selected-agent" value={selected} onChange={(e) => setSelected(e.target.value)}><option value="">{manage ? "Create a new agent" : "Select an agent"}</option>{list.data?.map((item) => <option key={item.id} value={item.id}>{item.name} · v{item.version_count}{item.is_enabled ? "" : " · disabled"}</option>)}</Select></Field>
    <div className="flex gap-2"><Button variant="ghost" disabled={!offset} onClick={() => { setSelected(""); setOffset(Math.max(0, offset - 50)); }}>Previous agents</Button><Button variant="ghost" disabled={(list.data?.length ?? 0) < 50} onClick={() => { setSelected(""); setOffset(offset + 50); }}>Next agents</Button></div>
    {!tools.data || !collections.data ? <LoadingState label="Loading agent configuration…" /> : selected ? <ExistingAgent key={selected} id={selected} tools={tools.data} collections={collections.data} onChange={list.refetch} /> : manage ? <section className="space-y-5 rounded-xl border border-line bg-surface p-5"><div className="grid gap-4 md:grid-cols-2"><Field label="Agent name" htmlFor="new-agent-name"><Input id="new-agent-name" required maxLength={160} value={name} onChange={(e) => setName(e.target.value)} /></Field><Field label="Description" htmlFor="new-agent-description"><Input id="new-agent-description" maxLength={10000} value={description} onChange={(e) => setDescription(e.target.value)} /></Field></div><AgentEditor initial={defaultAgentConfiguration()} tools={tools.data} collections={collections.data} saving={create.loading} onSave={(config) => { if (name.trim()) void create.run({ ...config, name: name.trim(), description }); else document.getElementById("new-agent-name")?.focus(); }} /></section> : null}
  </div>;
}

function ExistingAgent({ id, tools, collections, onChange }: { id: string; tools: Awaited<ReturnType<typeof api.customAgents.tools>>; collections: Awaited<ReturnType<typeof api.knowledge.collections>>; onChange: () => void }) {
  const { can } = useAuth();
  const agent = useApiResource(() => api.customAgents.get(id), [id]);
  const [offset, setOffset] = React.useState(0);
  const versions = useApiResource(() => api.customAgents.versions(id, offset), [id, offset]);
  const [editing, setEditing] = React.useState<string | null>(null);
  const save = useMutation((config: AgentConfiguration) => api.customAgents.version(id, { ...config, expected_active_version_id: agent.data!.active_version_id! }), {
    onSuccess: () => { setOffset(0); setEditing(null); agent.refetch(); versions.refetch(); onChange(); },
  });
  const disable = useMutation(api.customAgents.disable, { onSuccess: () => { agent.refetch(); onChange(); } });
  if (agent.error || versions.error) return <ErrorState message={agent.error ?? versions.error ?? "Unable to load agent"} onRetry={() => { agent.refetch(); versions.refetch(); }} />;
  if (!agent.data || !versions.data) return <LoadingState label="Loading agent versions…" />;
  const version = versions.data.find((item) => item.id === editing) ?? versions.data[0];
  return <section className="space-y-5 rounded-xl border border-line bg-surface p-5">
    <div className="flex items-center justify-between"><h2 className="text-lg font-medium">{agent.data.name}{!agent.data.is_enabled && " (disabled)"}</h2>{can("org:manage") && agent.data.is_enabled && <Button variant="danger" disabled={disable.loading} onClick={() => { if (window.confirm("Disable this agent for future runs?")) void disable.run(id); }}>Disable agent</Button>}</div>
    {[save.errorMessage, disable.errorMessage].filter(Boolean).map((error, index) => <p key={index} role="alert" className="text-danger">{error}</p>)}
    <Field label="Version history — editing creates a new version" htmlFor="agent-version"><Select id="agent-version" value={version?.id ?? ""} onChange={(e) => setEditing(e.target.value)}>{versions.data.map((item) => <option key={item.id} value={item.id}>Version {item.version} · {new Date(item.created_at).toLocaleString()}{item.id === agent.data?.active_version_id ? " · active" : ""}</option>)}</Select></Field>
    <div className="flex gap-2"><Button variant="ghost" disabled={!offset} onClick={() => { setEditing(null); setOffset(Math.max(0, offset - 50)); }}>Newer versions</Button><Button variant="ghost" disabled={versions.data.length < 50} onClick={() => { setEditing(null); setOffset(offset + 50); }}>Older versions</Button></div>
    {version && <AgentEditor key={version.id} initial={configurationFromVersion(version)} tools={tools} collections={collections} disabled={!can("org:manage") || !agent.data.is_enabled} saving={save.loading} onSave={(config) => void save.run(config)} />}
  </section>;
}
