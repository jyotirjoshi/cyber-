"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { useApiResource, useMutation, type UseApiResourceResult } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { projectPostureCards, recommendationDecisionLabel, riskTone } from "@/lib/control-plane";
import { assuranceStatusTone } from "@/lib/assurance-runtime";
import { formatDateTime, humanize } from "@/lib/format";
import type {
  AIGatewayDecision,
  AssuranceSummary,
  DataClassification,
  NativeAIPostureAssessment,
  SecurityCanary,
  SecurityExperienceSummary,
  SecurityPolicy,
  SecurityPolicyKind,
  SecurityPosture,
  SecurityRecommendation,
  SecurityResource,
  SecurityRiskSimulation,
  SecurityThreatStory,
} from "@/lib/types";

type Workspace = "overview" | "assurance" | "resources" | "policies" | "ai-data" | "soc" | "deception" | "risk";
const WORKSPACES: Array<{ id: Workspace; label: string }> = [
  { id: "overview", label: "Posture" },
  { id: "assurance", label: "Assurance runtime" },
  { id: "resources", label: "Inventory" },
  { id: "policies", label: "Policies" },
  { id: "ai-data", label: "AI & data" },
  { id: "soc", label: "Threat stories" },
  { id: "deception", label: "Deception" },
  { id: "risk", label: "Risk scenarios" },
];

export default function ControlPlanePage() {
  const { can } = useAuth();
  const canRead = can("org:read");
  const canManage = can("integration:manage");
  const [workspace, setWorkspace] = React.useState<Workspace>("overview");
  const posture = useApiResource(() => api.controlPlane.posture(), [], { enabled: canRead });
  const resources = useApiResource(() => api.controlPlane.resources({ limit: 500 }), [], { enabled: canRead });
  const policies = useApiResource(() => api.controlPlane.policies(), [], { enabled: canRead });
  const recommendations = useApiResource(() => api.controlPlane.recommendations(), [], { enabled: canRead });
  const stories = useApiResource(() => api.controlPlane.threatStories(), [], { enabled: canRead });
  const experience = useApiResource(() => api.controlPlane.experience(), [], { enabled: canRead });
  const canaries = useApiResource(() => api.controlPlane.canaries(), [], { enabled: canRead });
  const risks = useApiResource(() => api.controlPlane.riskSimulations(), [], { enabled: canRead });
  const assurance = useApiResource(() => api.controlPlane.assuranceSummary(), [], { enabled: canRead });
  const [nativeResult, setNativeResult] = React.useState<NativeAIPostureAssessment | null>(null);
  const refresh = React.useCallback(() => {
    posture.refetch(); resources.refetch(); policies.refetch(); recommendations.refetch();
    stories.refetch(); experience.refetch(); canaries.refetch(); risks.refetch(); assurance.refetch();
  }, [posture, resources, policies, recommendations, stories, experience, canaries, risks, assurance]);
  const nativePosture = useMutation(() => api.controlPlane.runNativeAIPosture(), {
    onSuccess: (result) => { setNativeResult(result); refresh(); },
  });

  if (!canRead) return <EmptyState title="No access" description="You do not have permission to view the security control plane." />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security control plane"
        description="Reconcile exposure, data, AI, identity, experience, and threat signals into governed policy actions."
        actions={canManage ? <Button loading={nativePosture.loading} onClick={() => void nativePosture.run()}>Run native posture</Button> : undefined}
      />
      {nativePosture.errorMessage && <p role="alert" className="text-sm text-danger">{nativePosture.errorMessage}</p>}
      {nativeResult && <Card><CardBody className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm"><Badge tone={nativeResult.critical_resources ? "danger" : nativeResult.at_risk_resources ? "warn" : "ok"}>Native assessment complete</Badge><span>{nativeResult.assessed_resources} AI resources assessed</span><span>{nativeResult.at_risk_resources} at risk</span><span>{nativeResult.recommendations_created} new recommendations</span><span className="text-muted">No external connector required</span></CardBody></Card>}
      <div className="flex gap-2 overflow-x-auto border-b border-line pb-2">
        {WORKSPACES.map((item) => <Button key={item.id} size="sm" variant={workspace === item.id ? "primary" : "ghost"} onClick={() => setWorkspace(item.id)}>{item.label}</Button>)}
      </div>

      {workspace === "overview" && <Overview posture={posture} recommendations={recommendations} canManage={canManage} onChanged={refresh} />}
      {workspace === "assurance" && <AssuranceRuntime resource={assurance} />}
      {workspace === "resources" && <Inventory resource={resources} canManage={canManage} onChanged={refresh} />}
      {workspace === "policies" && <Policies resource={policies} canManage={canManage} onChanged={refresh} />}
      {workspace === "ai-data" && <AIDataWorkspace />}
      {workspace === "soc" && <SocWorkspace stories={stories} experience={experience} />}
      {workspace === "deception" && <DeceptionWorkspace resource={canaries} canManage={canManage} onChanged={refresh} />}
      {workspace === "risk" && <RiskWorkspace resource={risks} canManage={can("asset:tag")} onChanged={refresh} />}
    </div>
  );
}

function AssuranceRuntime({ resource }: { resource: UseApiResourceResult<AssuranceSummary> }) {
  if (resource.loading && !resource.data) return <LoadingState label="Loading assurance records…" />;
  if (resource.error || !resource.data) return <ErrorState message={resource.error ?? "Assurance runtime unavailable"} onRetry={resource.refetch} />;
  const data = resource.data;
  const money = (value: string) => new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(Number(value));
  return <div className="space-y-4">
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card><CardBody><Metric label="Enforcement transactions" value={data.transactions.length} /></CardBody></Card>
      <Card><CardBody><Metric label="AI policy receipts" value={data.ai.receipts.length} /></CardBody></Card>
      <Card><CardBody><Metric label="Passed agent evaluations" value={data.agent_evaluations.runs.filter((item) => item.passed).length} /></CardBody></Card>
      <Card><CardBody><Metric label="Validation recipes" value={data.validation_recipes.length} /></CardBody></Card>
    </div>
    <div className="grid gap-4 xl:grid-cols-2">
      <Card><CardHeader><CardTitle>Enforcement lifecycle</CardTitle></CardHeader><CardBody>{!data.transactions.length ? <EmptyState title="No enforcement transactions" description="Prepare a policy recommendation to preview its provider snapshot, diff, blast radius, approval, observation, verification, and rollback." /> : <div className="space-y-3">{data.transactions.map((item) => <div key={item.id} className="rounded-lg border border-line p-3"><div className="flex items-center justify-between gap-3"><p className="font-medium text-fg">{humanize(item.operation)}</p><Badge tone={assuranceStatusTone(item.status)}>{humanize(item.status)}</Badge></div><p className="mt-1 text-xs text-muted">{item.provider} · blast {String(item.blast_radius.level ?? "unknown")} · {formatDateTime(item.created_at)}</p><p className="mt-2 font-mono text-xs text-muted">{item.diff_digest.slice(0, 16)}…</p></div>)}</div>}</CardBody></Card>
      <Card><CardHeader><CardTitle>AI runtime & tool trust</CardTitle></CardHeader><CardBody className="space-y-4"><div className="grid grid-cols-2 gap-3"><Metric label="Pinned manifests" value={data.ai.manifests.length} /><Metric label="Blocked/redacted" value={data.ai.receipts.filter((item) => item.decision !== "allow").length} /></div>{data.ai.manifests.slice(0, 6).map((item) => <div key={item.id} className="flex items-center justify-between rounded border border-line p-3 text-sm"><div><p className="font-medium text-fg">{item.tool_name}</p><p className="text-xs text-muted">{item.server_key} · v{item.version}</p></div><Badge tone={item.approved ? "ok" : "warn"}>{item.status}</Badge></div>)}</CardBody></Card>
      <Card><CardHeader><CardTitle>Agent proof, evaluation & validation</CardTitle></CardHeader><CardBody className="space-y-3">{!data.agent_assurance.length && !data.agent_evaluations.runs.length && !data.validation_recipes.length ? <EmptyState title="No assurance runs" description="Agent plans, outcome evaluation, tool receipts, verifier results, replay digests, and safe validation recipes appear here." /> : <>{data.agent_evaluations.runs.slice(0, 3).map((item) => <div key={item.id} className="rounded border border-line p-3 text-sm"><div className="flex justify-between"><span>Evaluation {item.id.slice(0, 8)}</span><Badge tone={item.passed ? "ok" : "danger"}>{item.passed ? "passed" : "failed"}</Badge></div><p className="mt-1 text-xs text-muted">Completion {Math.round(Number(item.metrics.task_completion_rate ?? 0) * 100)}% · grounded {Math.round(Number(item.metrics.evidence_grounding_rate ?? 0) * 100)}%</p></div>)}{data.agent_assurance.slice(0, 3).map((item) => <div key={item.id} className="flex justify-between rounded border border-line p-3 text-sm"><span>Run {item.run_id.slice(0, 8)}</span><Badge tone={item.verifier_status === "passed" ? "ok" : "warn"}>{item.verifier_status}</Badge></div>)}{data.validation_recipes.slice(0, 3).map((item) => <div key={item.id} className="rounded border border-line p-3 text-sm"><div className="flex justify-between"><span>{item.recipe_key}</span><Badge tone={item.status === "verified" ? "ok" : "warn"}>{item.status}</Badge></div><p className="mt-1 text-xs text-muted">{humanize(item.exploitation_verdict)} · {Number(item.reproducibility_score).toFixed(0)}% reproducible</p></div>)}</>}</CardBody></Card>
      <Card><CardHeader><CardTitle>Data, response, risk & compliance</CardTitle></CardHeader><CardBody className="space-y-3"><div className="grid grid-cols-2 gap-3"><Metric label="DSPM assessments" value={data.data_security.length} /><Metric label="SOC actions" value={data.response_actions.length} /><Metric label="Risk trials" value={data.risk_trials.length} /><Metric label="Signed OSCAL exports" value={data.compliance_exports.length} /></div>{data.risk_trials[0] && <div className="rounded border border-line p-3"><p className="text-xs text-muted">Latest quantitative interval</p><p className="mt-1 text-sm font-medium text-fg">P05 {money(data.risk_trials[0].p05)} · P50 {money(data.risk_trials[0].p50)} · P95 {money(data.risk_trials[0].p95)}</p><p className="mt-1 text-xs text-muted">{data.risk_trials[0].iterations.toLocaleString()} iterations · seed {data.risk_trials[0].seed}</p></div>}{data.compliance_exports[0] && <div className="rounded border border-line p-3"><p className="text-sm font-medium text-fg">{data.compliance_exports[0].package_key}</p><p className="mt-1 text-xs text-muted">{humanize(data.compliance_exports[0].model)} · signed {formatDateTime(data.compliance_exports[0].generated_at)}</p></div>}</CardBody></Card>
    </div>
  </div>;
}

function Overview({ posture, recommendations, canManage, onChanged }: { posture: UseApiResourceResult<SecurityPosture>; recommendations: UseApiResourceResult<SecurityRecommendation[]>; canManage: boolean; onChanged: () => void }) {
  const decide = useMutation((id: string, decision: "approve" | "reject" | "apply") => api.controlPlane.decideRecommendation(id, decision), { onSuccess: onChanged });
  const preview = useMutation((id: string) => api.controlPlane.previewRecommendation(id), { onSuccess: onChanged });
  if (posture.loading && !posture.data) return <LoadingState label="Loading security posture…" />;
  if (posture.error || !posture.data) return <ErrorState message={posture.error ?? "Security posture unavailable"} onRetry={posture.refetch} />;
  return <div className="space-y-6">
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{projectPostureCards(posture.data).map((card) => <Card key={card.label}><CardBody><p className="text-xs uppercase tracking-wide text-muted">{card.label}</p><div className="mt-2 flex items-center justify-between"><span className="text-2xl font-semibold text-fg">{card.value}</span><Badge tone={card.tone}>{card.tone}</Badge></div></CardBody></Card>)}</div>
    <div className="grid gap-4 lg:grid-cols-2">
      <Card><CardHeader><CardTitle>Coverage</CardTitle></CardHeader><CardBody className="space-y-2">{Object.entries(posture.data.source_coverage).sort((a, b) => b[1] - a[1]).map(([source, count]) => <div key={source} className="flex justify-between text-sm"><span className="text-muted">{humanize(source)}</span><span className="font-medium text-fg">{count}</span></div>)}</CardBody></Card>
      <Card><CardHeader><CardTitle>Inventory gaps</CardTitle></CardHeader><CardBody className="grid grid-cols-2 gap-4 text-sm"><Metric label="Stale resources" value={posture.data.stale_resources} /><Metric label="Missing owners" value={posture.data.unknown_owner} /><Metric label="Internet exposed" value={posture.data.internet_exposed} /><Metric label="Active sources" value={posture.data.active_sources} /></CardBody></Card>
    </div>
    <Card><CardHeader><CardTitle>Policy recommendations</CardTitle></CardHeader><CardBody>{recommendations.loading && !recommendations.data ? <LoadingState label="Loading recommendations…" /> : recommendations.error ? <ErrorState message={recommendations.error} onRetry={recommendations.refetch} /> : !recommendations.data?.length ? <EmptyState title="No policy violations" description="Evaluate an active policy to generate evidence-backed recommendations." /> : <div className="space-y-3">{recommendations.data.map((item) => <div key={item.id} className="rounded-lg border border-line p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="flex gap-2"><Badge tone={riskTone(item.severity === "critical" ? 100 : item.severity === "high" ? 70 : 30)}>{item.severity}</Badge><Badge tone="neutral">{recommendationDecisionLabel(item.status)}</Badge></div><h3 className="mt-2 font-medium text-fg">{item.title}</h3><p className="mt-1 text-sm text-muted">{item.rationale}</p></div>{canManage && <div className="flex flex-wrap gap-2">{item.status === "proposed" && <><Button size="sm" variant="outline" onClick={() => void decide.run(item.id, "reject")}>Reject</Button><Button size="sm" onClick={() => void decide.run(item.id, "approve")}>Approve</Button></>}{["proposed", "approved", "failed"].includes(item.status) && <Button size="sm" variant="outline" onClick={() => void preview.run(item.id)}>Preview</Button>}{["approved", "failed"].includes(item.status) && <Button size="sm" onClick={() => void decide.run(item.id, "apply")}>Apply</Button>}</div>}</div>{Object.keys(item.provider_receipt).length > 0 && <pre className="mt-3 overflow-auto rounded bg-surface-2 p-3 text-xs text-muted">{JSON.stringify(item.provider_receipt, null, 2)}</pre>}</div>)}</div>}</CardBody></Card>
  </div>;
}

function Inventory({ resource, canManage, onChanged }: { resource: UseApiResourceResult<SecurityResource[]>; canManage: boolean; onChanged: () => void }) {
  const [form, setForm] = React.useState({
    name: "",
    kind: "ai_application" as SecurityResource["kind"],
    owner_team: "",
    environment: "production" as "production" | "staging" | "development" | "test" | "unknown",
    sensitivity: "internal" as "unknown" | "public" | "internal" | "confidential" | "restricted",
    internet_exposed: false,
    approved: false,
  });
  const register = useMutation(() => {
    const id = crypto.randomUUID();
    return api.controlPlane.registerResource({
      resource_key: `cynux:native:${form.kind}:${id}`,
      kind: form.kind,
      name: form.name,
      source_kind: "cynux_native",
      source_key: id,
      observed_at: new Date().toISOString(),
      confidence: 1,
      provider: "cynux",
      owner_team: form.owner_team || null,
      environment: form.environment,
      internet_exposed: form.internet_exposed,
      approved: form.approved,
      sensitivity: form.sensitivity,
      classifications: ["native_inventory"],
      permissions: {},
      attributes: { authentication: form.internet_exposed ? "unknown" : "private" },
      provenance: { acquisition: "user_registered" },
    });
  }, { onSuccess: () => { setForm((value) => ({ ...value, name: "" })); onChanged(); } });
  if (resource.loading && !resource.data) return <LoadingState label="Loading unified inventory…" />;
  if (resource.error) return <ErrorState message={resource.error} onRetry={resource.refetch} />;
  return <div className="space-y-4">
    {canManage && <Card><CardHeader><CardTitle>Register native AI resource</CardTitle></CardHeader><CardBody><form className="grid gap-3 md:grid-cols-3" onSubmit={(event) => { event.preventDefault(); void register.run(); }}><Field label="Resource name" htmlFor="native-resource-name"><Input id="native-resource-name" required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field><Field label="Resource kind" htmlFor="native-resource-kind"><select id="native-resource-kind" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={form.kind} onChange={(event) => setForm({ ...form, kind: event.target.value as SecurityResource["kind"] })}>{["ai_application", "ai_model", "ai_agent", "mcp_server", "ai_tool"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field><Field label="Owner team" htmlFor="native-resource-owner"><Input id="native-resource-owner" value={form.owner_team} onChange={(event) => setForm({ ...form, owner_team: event.target.value })} /></Field><Field label="Environment" htmlFor="native-resource-environment"><select id="native-resource-environment" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value as typeof form.environment })}>{["production", "staging", "development", "test", "unknown"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field><Field label="Data sensitivity" htmlFor="native-resource-sensitivity"><select id="native-resource-sensitivity" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={form.sensitivity} onChange={(event) => setForm({ ...form, sensitivity: event.target.value as typeof form.sensitivity })}>{["unknown", "public", "internal", "confidential", "restricted"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field><div className="flex items-end gap-4 pb-2"><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.internet_exposed} onChange={(event) => setForm({ ...form, internet_exposed: event.target.checked })} />Internet exposed</label><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.approved} onChange={(event) => setForm({ ...form, approved: event.target.checked })} />Approved</label></div>{register.errorMessage && <p role="alert" className="text-sm text-danger md:col-span-3">{register.errorMessage}</p>}<div className="md:col-span-3"><Button type="submit" loading={register.loading}>Register resource</Button></div></form></CardBody></Card>}
    <Card><CardBody>{!resource.data?.length ? <EmptyState title="No resources yet" description="Register an AI resource here or deploy a Cynux collector for continuous discovery. Third-party connectors are optional." /> : <Table><THead><TR><TH>Resource</TH><TH>Kind</TH><TH>Owner</TH><TH>Sources</TH><TH>Confidence</TH><TH>Posture</TH><TH>Last seen</TH></TR></THead><TBody>{resource.data.map((item) => <TR key={item.id}><TD><p className="font-medium text-fg">{item.name}</p><p className="text-xs text-muted">{item.provider ?? "curated"} · {item.environment}</p></TD><TD>{humanize(item.kind)}</TD><TD>{item.owner_team ?? "Unassigned"}</TD><TD>{item.source_count}</TD><TD>{(Number(item.identity_confidence) * 100).toFixed(1)}%</TD><TD><Badge tone={item.posture_status === "healthy" ? "ok" : item.posture_status === "inactive" ? "neutral" : "warn"}>{humanize(item.posture_status)}</Badge></TD><TD>{formatDateTime(item.last_seen_at)}</TD></TR>)}</TBody></Table>}</CardBody></Card>
  </div>;
}

function Policies({ resource, canManage, onChanged }: { resource: UseApiResourceResult<SecurityPolicy[]>; canManage: boolean; onChanged: () => void }) {
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<SecurityPolicyKind>("ai_gateway");
  const create = useMutation(() => api.controlPlane.createPolicy({ name, kind, mode: "recommend", rules: { require_approved: true, require_owner: true, max_risk_score: 70, block_prompt_injection: true, redact_sensitive_data: true } }), { onSuccess: () => { setName(""); onChanged(); } });
  const evaluate = useMutation((id: string) => api.controlPlane.evaluatePolicy(id), { onSuccess: onChanged });
  return <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
    <Card><CardHeader><CardTitle>Active policies</CardTitle></CardHeader><CardBody>{resource.loading && !resource.data ? <LoadingState label="Loading policies…" /> : resource.error ? <ErrorState message={resource.error} onRetry={resource.refetch} /> : !resource.data?.length ? <EmptyState title="No policies" description="Create a deterministic policy for access, web, data, or AI governance." /> : <div className="space-y-3">{resource.data.map((item) => <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3"><div><p className="font-medium text-fg">{item.name}</p><p className="text-xs text-muted">{humanize(item.kind)} · {item.mode} · v{item.version}</p></div>{canManage && <Button size="sm" loading={evaluate.loading} onClick={() => void evaluate.run(item.id)}>Evaluate inventory</Button>}</div>)}</div>}</CardBody></Card>
    {canManage && <Card><CardHeader><CardTitle>Create policy</CardTitle></CardHeader><CardBody><form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void create.run(); }}><Field label="Name" htmlFor="policy-name"><Input id="policy-name" required value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Control" htmlFor="policy-kind"><select id="policy-kind" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={kind} onChange={(event) => setKind(event.target.value as SecurityPolicyKind)}>{["ztna", "secure_web_gateway", "firewall", "dlp", "casb", "sspm", "ai_gateway", "ai_guard", "endpoint_isolation", "browser_isolation"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field>{create.errorMessage && <p className="text-sm text-danger">{create.errorMessage}</p>}<Button type="submit" loading={create.loading}>Create baseline policy</Button></form></CardBody></Card>}
  </div>;
}

function AIDataWorkspace() {
  const [content, setContent] = React.useState("");
  const [aiResult, setAiResult] = React.useState<AIGatewayDecision | null>(null);
  const [dataResult, setDataResult] = React.useState<DataClassification | null>(null);
  const ai = useMutation(() => api.controlPlane.evaluateAI({ direction: "prompt", content, agent_key: "operator:test" }), { onSuccess: setAiResult });
  const classify = useMutation(() => api.controlPlane.classifyData(content), { onSuccess: setDataResult });
  return <div className="grid gap-4 lg:grid-cols-2"><Card><CardHeader><CardTitle>Transient inspection</CardTitle></CardHeader><CardBody className="space-y-4"><p className="text-sm text-muted">Content is evaluated in memory. Only a digest, length, labels, and decision are persisted.</p><textarea aria-label="Content to inspect" className="min-h-48 w-full rounded-md border border-line bg-surface-2 p-3 text-sm" value={content} onChange={(event) => setContent(event.target.value)} placeholder="Paste a prompt or output to test policy enforcement" /><div className="flex gap-2"><Button disabled={!content} loading={ai.loading} onClick={() => void ai.run()}>Run AI guard</Button><Button variant="outline" disabled={!content} loading={classify.loading} onClick={() => void classify.run()}>Classify & redact</Button></div></CardBody></Card><Card><CardHeader><CardTitle>Decision</CardTitle></CardHeader><CardBody className="space-y-4">{!aiResult && !dataResult ? <EmptyState title="No inspection yet" description="Run AI guard or data classification to see the deterministic decision." /> : <>{aiResult && <div><Badge tone={riskTone(Number(aiResult.score))}>{aiResult.decision}</Badge><p className="mt-2 text-sm text-muted">{aiResult.reasons.map(humanize).join(", ") || "No policy violations"}</p></div>}{dataResult && <div><Badge tone={dataResult.highest_sensitivity === "restricted" ? "danger" : "warn"}>{dataResult.highest_sensitivity}</Badge><p className="mt-2 text-sm text-muted">{dataResult.labels.map(humanize).join(", ") || "No sensitive classes"}</p><pre className="mt-3 whitespace-pre-wrap rounded bg-surface-2 p-3 text-xs">{dataResult.redacted_content}</pre></div>}</>}</CardBody></Card></div>;
}

function SocWorkspace({ stories, experience }: { stories: UseApiResourceResult<SecurityThreatStory[]>; experience: UseApiResourceResult<SecurityExperienceSummary> }) {
  return <div className="space-y-4">{experience.data && <div className="grid gap-4 sm:grid-cols-3"><Card><CardBody><Metric label="Experience score" value={Number(experience.data.average_score).toFixed(1)} /></CardBody></Card><Card><CardBody><Metric label="Degraded journeys" value={experience.data.degraded_journeys} /></CardBody></Card><Card><CardBody><p className="text-xs text-muted">Business impact</p><Badge tone={experience.data.business_impact === "critical" || experience.data.business_impact === "high" ? "danger" : "neutral"}>{experience.data.business_impact}</Badge></CardBody></Card></div>}<Card><CardHeader><CardTitle>Correlated threat stories</CardTitle></CardHeader><CardBody>{stories.loading && !stories.data ? <LoadingState label="Correlating events…" /> : stories.error ? <ErrorState message={stories.error} onRetry={stories.refetch} /> : !stories.data?.length ? <EmptyState title="No threat stories" description="SIEM, EDR, identity, cloud, access, and deception events are correlated here." /> : <div className="space-y-3">{stories.data.map((story) => <div key={story.id} className="rounded-lg border border-line p-4"><div className="flex gap-2"><Badge tone={riskTone(story.severity === "critical" ? 100 : story.severity === "high" ? 70 : 30)}>{story.severity}</Badge><Badge tone="neutral">{story.status}</Badge></div><h3 className="mt-2 font-medium text-fg">{story.title}</h3><p className="text-sm text-muted">{story.summary}</p><p className="mt-2 text-xs text-muted">{story.event_ids.length} events · {(Number(story.confidence) * 100).toFixed(1)}% confidence · Last seen {formatDateTime(story.last_seen_at)}</p></div>)}</div>}</CardBody></Card></div>;
}

function DeceptionWorkspace({ resource, canManage, onChanged }: { resource: UseApiResourceResult<SecurityCanary[]>; canManage: boolean; onChanged: () => void }) {
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<SecurityCanary["kind"]>("credential");
  const create = useMutation(() => api.controlPlane.createCanary({ name, kind, token: `${crypto.randomUUID()}-${crypto.randomUUID()}` }), { onSuccess: () => { setName(""); onChanged(); } });
  return <div className="space-y-4">{canManage && <Card><CardBody><form className="flex flex-col gap-3 sm:flex-row sm:items-end" onSubmit={(event) => { event.preventDefault(); void create.run(); }}><Field label="Canary name" htmlFor="canary-name"><Input id="canary-name" required value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Type" htmlFor="canary-kind"><select id="canary-kind" className="rounded-md border border-line bg-surface px-3 py-2 text-sm" value={kind} onChange={(event) => setKind(event.target.value as SecurityCanary["kind"])}>{["credential", "dns", "http", "file", "cloud_resource", "identity"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field><Button type="submit" loading={create.loading}>Create canary</Button></form></CardBody></Card>}<Card><CardBody>{resource.loading && !resource.data ? <LoadingState label="Loading canaries…" /> : resource.error ? <ErrorState message={resource.error} onRetry={resource.refetch} /> : !resource.data?.length ? <EmptyState title="No canaries" description="Deploy a canary reference and forward interactions to validate lateral movement." /> : <Table><THead><TR><TH>Name</TH><TH>Type</TH><TH>Status</TH><TH>Digest</TH><TH>Last triggered</TH></TR></THead><TBody>{resource.data.map((item) => <TR key={item.id}><TD className="font-medium text-fg">{item.name}</TD><TD>{humanize(item.kind)}</TD><TD><Badge tone={item.status === "triggered" ? "danger" : "ok"}>{item.status}</Badge></TD><TD className="font-mono text-xs">{item.token_digest.slice(0, 12)}…</TD><TD>{item.last_triggered_at ? formatDateTime(item.last_triggered_at) : "Never"}</TD></TR>)}</TBody></Table>}</CardBody></Card></div>;
}

function RiskWorkspace({ resource, canManage, onChanged }: { resource: UseApiResourceResult<SecurityRiskSimulation[]>; canManage: boolean; onChanged: () => void }) {
  const [form, setForm] = React.useState({ name: "", annual_probability: 0.2, loss_min: 10000, loss_likely: 50000, loss_max: 250000, control_effectiveness: 0.5 });
  const create = useMutation(() => api.controlPlane.createRiskSimulation(form), { onSuccess: () => { setForm((value) => ({ ...value, name: "" })); onChanged(); } });
  const money = (value: string) => new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(Number(value));
  return <div className="space-y-4">{canManage && <Card><CardHeader><CardTitle>Model a loss scenario</CardTitle></CardHeader><CardBody><form className="grid gap-3 md:grid-cols-3" onSubmit={(event) => { event.preventDefault(); void create.run(); }}><Field label="Scenario" htmlFor="risk-name"><Input id="risk-name" required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field>{(["annual_probability", "loss_min", "loss_likely", "loss_max", "control_effectiveness"] as const).map((field) => <Field key={field} label={humanize(field)} htmlFor={`risk-${field}`}><Input id={`risk-${field}`} type="number" min="0" step={field.includes("probability") || field.includes("effectiveness") ? "0.01" : "1"} max={field.includes("probability") || field.includes("effectiveness") ? "1" : undefined} value={form[field]} onChange={(event) => setForm({ ...form, [field]: Number(event.target.value) })} /></Field>)}<div className="flex items-end"><Button type="submit" loading={create.loading}>Run simulation</Button></div></form></CardBody></Card>}<div className="grid gap-4 lg:grid-cols-2">{resource.loading && !resource.data ? <LoadingState label="Loading scenarios…" /> : resource.error ? <ErrorState message={resource.error} onRetry={resource.refetch} /> : !resource.data?.length ? <EmptyState title="No risk scenarios" description="Model probability, loss range, and control effectiveness for board-level decisions." /> : resource.data.map((item: SecurityRiskSimulation) => <Card key={item.id}><CardBody><div className="flex justify-between"><h3 className="font-medium text-fg">{item.name}</h3><Badge tone="neutral">{item.acceptance_status}</Badge></div><div className="mt-4 grid grid-cols-2 gap-3"><Metric label="Inherent annual loss" value={money(item.inherent_annual_loss)} /><Metric label="Residual annual loss" value={money(item.residual_annual_loss)} /><Metric label="Annual probability" value={`${(Number(item.annual_probability) * 100).toFixed(1)}%`} /><Metric label="Control effectiveness" value={`${(Number(item.control_effectiveness) * 100).toFixed(1)}%`} /></div>{item.narrative && <p className="mt-3 text-sm text-muted">{item.narrative}</p>}</CardBody></Card>)}</div></div>;
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return <div><p className="text-xs text-muted">{label}</p><p className="mt-1 text-lg font-semibold text-fg">{value}</p></div>;
}
