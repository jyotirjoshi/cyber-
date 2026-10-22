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
import { buildDemoEndpointEvent, endpointFleetSummary, projectPostureCards, recommendationDecisionLabel, riskTone, socOperationsSummary } from "@/lib/control-plane";
import { assuranceStatusTone } from "@/lib/assurance-runtime";
import { formatDateTime, humanize } from "@/lib/format";
import type {
  AIGatewayDecision,
  AssuranceSummary,
  CasbDecision,
  DataClassification,
  NativeAIPostureAssessment,
  Page,
  PrivateAccessDecision,
  SecurityCanary,
  SecurityEvent,
  SecurityExperienceSummary,
  SecurityPolicy,
  SecurityPolicyKind,
  SecurityPosture,
  SecurityRecommendation,
  SecurityResource,
  SecurityRiskSimulation,
  SecurityThreatStory,
  SocIncidentCase,
  DetectionRule,
} from "@/lib/types";

type Workspace = "overview" | "assurance" | "resources" | "endpoint" | "private-access" | "policies" | "ai-data" | "soc" | "deception" | "risk";
const WORKSPACES: Array<{ id: Workspace; label: string }> = [
  { id: "overview", label: "Posture" },
  { id: "assurance", label: "Assurance runtime" },
  { id: "resources", label: "Inventory" },
  { id: "endpoint", label: "Endpoint/XDR" },
  { id: "private-access", label: "Private access" },
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
  const socCases = useApiResource(() => api.controlPlane.socCases(), [], { enabled: canRead });
  const detectionRules = useApiResource(() => api.controlPlane.detectionRules(), [], { enabled: canRead });
  const endpoints = useApiResource(() => api.controlPlane.resources({ kind: "endpoint", limit: 500 }), [], { enabled: canRead });
  const endpointEvents = useApiResource(() => api.controlPlane.events("endpoint", 500), [], { enabled: canRead });
  const experience = useApiResource(() => api.controlPlane.experience(), [], { enabled: canRead });
  const experienceEvents = useApiResource(() => api.controlPlane.events("experience", 100), [], { enabled: canRead });
  const canaries = useApiResource(() => api.controlPlane.canaries(), [], { enabled: canRead });
  const risks = useApiResource(() => api.controlPlane.riskSimulations(), [], { enabled: canRead });
  const assurance = useApiResource(() => api.controlPlane.assuranceSummary(), [], { enabled: canRead });
  const [nativeResult, setNativeResult] = React.useState<NativeAIPostureAssessment | null>(null);
  const refresh = React.useCallback(() => {
    posture.refetch(); resources.refetch(); policies.refetch(); recommendations.refetch();
    stories.refetch(); socCases.refetch(); detectionRules.refetch(); endpoints.refetch(); endpointEvents.refetch(); experience.refetch(); experienceEvents.refetch(); canaries.refetch(); risks.refetch(); assurance.refetch();
  }, [posture, resources, policies, recommendations, stories, socCases, detectionRules, endpoints, endpointEvents, experience, experienceEvents, canaries, risks, assurance]);
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
      {workspace === "endpoint" && <EndpointWorkspace endpoints={endpoints} events={endpointEvents} canManage={canManage} onChanged={refresh} />}
      {workspace === "private-access" && <PrivateAccessWorkspace policies={policies} canManage={canManage} />}
      {workspace === "policies" && <Policies resource={policies} canManage={canManage} onChanged={refresh} />}
      {workspace === "ai-data" && <AIDataWorkspace />}
      {workspace === "soc" && <SocWorkspace stories={stories} cases={socCases} rules={detectionRules} experience={experience} experienceEvents={experienceEvents} canManage={canManage} onChanged={refresh} />}
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

function PrivateAccessWorkspace({ policies, canManage }: { policies: UseApiResourceResult<SecurityPolicy[]>; canManage: boolean }) {
  const ztnaPolicies = (policies.data ?? []).filter((item) => item.kind === "ztna" && item.status === "active");
  const [policyId, setPolicyId] = React.useState("");
  const [form, setForm] = React.useState({
    identity: "user:alice@example.com",
    groups: "employees",
    application: "app:internal-portal",
    tags: "production",
    posture: "managed,encrypted,edr_healthy",
    country: "IN",
    risk: 10,
    minutes: 60,
    mfa: true,
  });
  const [decision, setDecision] = React.useState<PrivateAccessDecision | null>(null);
  React.useEffect(() => {
    if (!policyId && ztnaPolicies[0]) setPolicyId(ztnaPolicies[0].id);
  }, [policyId, ztnaPolicies]);
  const split = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
  const evaluate = useMutation(() => api.controlPlane.evaluatePrivateAccess({
    policy_id: policyId,
    request_id: crypto.randomUUID(),
    identity_ref: form.identity,
    groups: split(form.groups),
    application_ref: form.application,
    application_tags: split(form.tags),
    device_posture: split(form.posture),
    mfa: form.mfa,
    source_country: form.country.toUpperCase(),
    identity_risk_score: form.risk,
    requested_session_minutes: form.minutes,
  }), { onSuccess: setDecision });
  if (policies.loading && !policies.data) return <LoadingState label="Loading private access policies…" />;
  if (policies.error) return <ErrorState message={policies.error} onRetry={policies.refetch} />;
  return <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
    <Card><CardHeader><CardTitle>Request-time private application access</CardTitle></CardHeader><CardBody>
      {!canManage ? <EmptyState title="Read-only access" description="An integration manager can evaluate attested identity and device context." /> : !ztnaPolicies.length ? <EmptyState title="No active ZTNA policy" description="Create an active ZTNA policy with explicit identities or groups, device posture, MFA, geography, risk, and session rules." /> : <form className="grid gap-3 md:grid-cols-2" onSubmit={(event) => { event.preventDefault(); void evaluate.run(); }}>
        <Field label="Policy" htmlFor="access-policy"><select id="access-policy" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={policyId} onChange={(event) => setPolicyId(event.target.value)}>{ztnaPolicies.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.mode}</option>)}</select></Field>
        <Field label="Identity" htmlFor="access-identity"><Input id="access-identity" required value={form.identity} onChange={(event) => setForm({ ...form, identity: event.target.value })} /></Field>
        <Field label="Groups (comma separated)" htmlFor="access-groups"><Input id="access-groups" value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} /></Field>
        <Field label="Private application" htmlFor="access-app"><Input id="access-app" required value={form.application} onChange={(event) => setForm({ ...form, application: event.target.value })} /></Field>
        <Field label="Application tags" htmlFor="access-tags"><Input id="access-tags" value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} /></Field>
        <Field label="Device posture" htmlFor="access-posture"><Input id="access-posture" value={form.posture} onChange={(event) => setForm({ ...form, posture: event.target.value })} /></Field>
        <Field label="Country" htmlFor="access-country"><Input id="access-country" minLength={2} maxLength={2} value={form.country} onChange={(event) => setForm({ ...form, country: event.target.value })} /></Field>
        <Field label="Identity risk (0–100)" htmlFor="access-risk"><Input id="access-risk" type="number" min="0" max="100" value={form.risk} onChange={(event) => setForm({ ...form, risk: Number(event.target.value) })} /></Field>
        <Field label="Requested session minutes" htmlFor="access-minutes"><Input id="access-minutes" type="number" min="1" max="10080" value={form.minutes} onChange={(event) => setForm({ ...form, minutes: Number(event.target.value) })} /></Field>
        <label className="flex items-end gap-2 pb-2 text-sm"><input type="checkbox" checked={form.mfa} onChange={(event) => setForm({ ...form, mfa: event.target.checked })} />MFA verified</label>
        {evaluate.errorMessage && <p role="alert" className="text-sm text-danger md:col-span-2">{evaluate.errorMessage}</p>}
        <div className="md:col-span-2"><Button type="submit" loading={evaluate.loading}>Evaluate access</Button></div>
      </form>}
    </CardBody></Card>
    <Card><CardHeader><CardTitle>Decision</CardTitle></CardHeader><CardBody>{!decision ? <EmptyState title="No decision yet" description="Evaluate a request to produce an auditable allow or deny decision." /> : <div className="space-y-3"><Badge tone={decision.decision === "allow" && !decision.would_block ? "ok" : decision.enforced ? "danger" : "warn"}>{decision.decision}</Badge><p className="text-sm text-muted">{decision.enforced ? "Enforced" : "Observation only"} · session {decision.session_minutes} minutes</p><div className="space-y-1">{decision.reason_codes.map((code) => <p key={code} className="rounded bg-surface-2 px-3 py-2 text-sm">{humanize(code)}</p>)}</div><p className="font-mono text-xs text-muted">Event {decision.event_id}</p></div>}</CardBody></Card>
  </div>;
}

function AIDataWorkspace() {
  const [content, setContent] = React.useState("");
  const [aiResult, setAiResult] = React.useState<AIGatewayDecision | null>(null);
  const [dataResult, setDataResult] = React.useState<DataClassification | null>(null);
  const [casbResult, setCasbResult] = React.useState<CasbDecision | null>(null);
  const [casb, setCasb] = React.useState({ action: "external_share" as const, identity: "user:alice@example.com", application: "saas:drive", destination: "partner.example", managed: true, mfa: true });
  const ai = useMutation(() => api.controlPlane.evaluateAI({ direction: "prompt", content, agent_key: "operator:test" }), { onSuccess: setAiResult });
  const classify = useMutation(() => api.controlPlane.classifyData(content), { onSuccess: setDataResult });
  const evaluateCasb = useMutation(() => api.controlPlane.evaluateCasb({ action: casb.action, content, identity_ref: casb.identity, application_key: casb.application, device_managed: casb.managed, mfa: casb.mfa, destination_domain: casb.destination || null }), { onSuccess: setCasbResult });
  return <div className="space-y-4"><div className="grid gap-4 lg:grid-cols-2"><Card><CardHeader><CardTitle>Transient inspection</CardTitle></CardHeader><CardBody className="space-y-4"><p className="text-sm text-muted">Content is evaluated in memory. Only a digest, length, labels, and decision are persisted.</p><textarea aria-label="Content to inspect" className="min-h-48 w-full rounded-md border border-line bg-surface-2 p-3 text-sm" value={content} onChange={(event) => setContent(event.target.value)} placeholder="Paste a prompt, file content, or SaaS payload to test enforcement" /><div className="flex gap-2"><Button disabled={!content} loading={ai.loading} onClick={() => void ai.run()}>Run AI guard</Button><Button variant="outline" disabled={!content} loading={classify.loading} onClick={() => void classify.run()}>Classify & redact</Button></div></CardBody></Card><Card><CardHeader><CardTitle>Decision</CardTitle></CardHeader><CardBody className="space-y-4">{!aiResult && !dataResult ? <EmptyState title="No inspection yet" description="Run AI guard or data classification to see the deterministic decision." /> : <>{aiResult && <div><Badge tone={riskTone(Number(aiResult.score))}>{aiResult.decision}</Badge><p className="mt-2 text-sm text-muted">{aiResult.reasons.map(humanize).join(", ") || "No policy violations"}</p></div>}{dataResult && <div><Badge tone={dataResult.highest_sensitivity === "restricted" ? "danger" : "warn"}>{dataResult.highest_sensitivity}</Badge><p className="mt-2 text-sm text-muted">{dataResult.labels.map(humanize).join(", ") || "No sensitive classes"}</p><pre className="mt-3 whitespace-pre-wrap rounded bg-surface-2 p-3 text-xs">{dataResult.redacted_content}</pre></div>}</>}</CardBody></Card></div>
    <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]"><Card><CardHeader><CardTitle>Native CASB/DLP action control</CardTitle></CardHeader><CardBody><form className="grid gap-3 md:grid-cols-2" onSubmit={(event) => { event.preventDefault(); void evaluateCasb.run(); }}><Field label="Action" htmlFor="casb-action"><select id="casb-action" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={casb.action} onChange={(event) => setCasb({ ...casb, action: event.target.value as typeof casb.action })}>{["upload", "download", "share", "external_share", "copy", "paste", "print"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field><Field label="Identity" htmlFor="casb-identity"><Input id="casb-identity" value={casb.identity} onChange={(event) => setCasb({ ...casb, identity: event.target.value })} /></Field><Field label="SaaS application" htmlFor="casb-app"><Input id="casb-app" value={casb.application} onChange={(event) => setCasb({ ...casb, application: event.target.value })} /></Field><Field label="Destination domain" htmlFor="casb-destination"><Input id="casb-destination" value={casb.destination} onChange={(event) => setCasb({ ...casb, destination: event.target.value })} /></Field><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={casb.managed} onChange={(event) => setCasb({ ...casb, managed: event.target.checked })} />Managed device</label><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={casb.mfa} onChange={(event) => setCasb({ ...casb, mfa: event.target.checked })} />MFA verified</label>{evaluateCasb.errorMessage && <p role="alert" className="text-sm text-danger md:col-span-2">{evaluateCasb.errorMessage}</p>}<div className="md:col-span-2"><Button type="submit" disabled={!content} loading={evaluateCasb.loading}>Evaluate SaaS action</Button></div></form></CardBody></Card><Card><CardHeader><CardTitle>CASB decision</CardTitle></CardHeader><CardBody>{!casbResult ? <EmptyState title="No SaaS action evaluated" description="Evaluation uses active CASB or DLP policy and stores no raw content." /> : <div className="space-y-3"><Badge tone={casbResult.decision === "block" ? "danger" : casbResult.decision === "allow" ? "ok" : "warn"}>{casbResult.decision}</Badge><p className="text-sm text-muted">{casbResult.reasons.map(humanize).join(", ") || "No policy violations"}</p>{casbResult.redacted_content && <pre className="whitespace-pre-wrap rounded bg-surface-2 p-3 text-xs">{casbResult.redacted_content}</pre>}<p className="font-mono text-xs text-muted">{casbResult.content_digest.slice(0, 16)}…</p></div>}</CardBody></Card></div>
  </div>;
}

function EndpointWorkspace({ endpoints, events, canManage, onChanged }: { endpoints: UseApiResourceResult<SecurityResource[]>; events: UseApiResourceResult<SecurityEvent[]>; canManage: boolean; onChanged: () => void }) {
  const [lastDecision, setLastDecision] = React.useState<{ verdict: string; severity: string; score: number } | null>(null);
  const simulate = useMutation(() => api.controlPlane.ingestEndpointEvent(
    buildDemoEndpointEvent(crypto.randomUUID(), new Date().toISOString()),
  ), { onSuccess: (result) => { setLastDecision(result.decision); onChanged(); } });
  if ((endpoints.loading && !endpoints.data) || (events.loading && !events.data)) return <LoadingState label="Loading endpoint telemetry…" />;
  if (endpoints.error || events.error) return <ErrorState message={endpoints.error ?? events.error ?? "Endpoint telemetry unavailable"} onRetry={() => { endpoints.refetch(); events.refetch(); }} />;
  const summary = endpointFleetSummary(endpoints.data ?? [], events.data ?? []);
  return <div className="space-y-4">
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><Card><CardBody><Metric label="Known endpoints" value={summary.endpoints} /></CardBody></Card><Card><CardBody><Metric label="Sensors reporting" value={summary.reporting} /></CardBody></Card><Card><CardBody><Metric label="Endpoints at risk" value={summary.atRisk} /></CardBody></Card><Card><CardBody><Metric label="High/critical detections" value={summary.activeDetections} /></CardBody></Card></div>
    {canManage && <Card><CardHeader><CardTitle>Native Cynux telemetry</CardTitle></CardHeader><CardBody className="flex flex-wrap items-center justify-between gap-4"><div><p className="text-sm text-fg">The ingestion API registers endpoint identity, evaluates bounded telemetry, and correlates a threat story without storing raw command lines or destinations.</p><p className="mt-1 text-xs text-muted">This module is detection-only. Host isolation still requires a separately installed and approved response agent or provider. The demo creates test-environment telemetry only.</p></div><Button loading={simulate.loading} onClick={() => void simulate.run()}>Generate demo detection</Button>{simulate.errorMessage && <p role="alert" className="w-full text-sm text-danger">{simulate.errorMessage}</p>}{lastDecision && <p className="w-full text-sm"><Badge tone={riskTone(lastDecision.score)}>{lastDecision.severity}</Badge><span className="ml-2 text-muted">{humanize(lastDecision.verdict)} · score {lastDecision.score}</span></p>}</CardBody></Card>}
    <Card><CardHeader><CardTitle>Install the native collector</CardTitle></CardHeader><CardBody className="space-y-3 text-sm">
      <p>Install on each Windows, Linux, or macOS device you want to observe. Python 3.11 or newer is required. The collector reports process activity; local file scanning additionally requires ClamAV and an updated signature database.</p>
      <div className="flex flex-wrap gap-4"><a className="text-accent underline" href="/downloads/endpoint/cynux_endpoint-0.7.0-py3-none-any.whl" download>Download collector 0.7.0</a><a className="text-accent underline" href="/downloads/endpoint/SHA256SUMS">SHA-256 checksum</a><a className="text-accent underline" href="/settings/api-keys">Create an API key</a></div>
      <p>Create a key with only the <code>endpoint:ingest</code> scope and set it in the device&apos;s <code>CYNUX_ENDPOINT_API_KEY</code> environment variable. Keep the same private state directory for collection and scans.</p>
      <pre className="overflow-x-auto rounded-md bg-surface p-3 text-xs">{"python -m pip install --upgrade ./cynux_endpoint-0.7.0-py3-none-any.whl\ncynux-endpoint --server https://cynux-security-prod.web.app --state-dir ./cynux-state\n\n# Run separately to rescan selected files every 5 minutes\ncynux-scan --repeat 300 --state-dir ./cynux-state --server https://cynux-security-prod.web.app ./sample-file"}</pre>
      <p className="text-xs text-muted">Repeat scanning runs locally until stopped. Select up to 1,000 explicit files; directories are not traversed. Scans run serially with a 32 MiB limit per file and a 120-second engine timeout. Omit <code>--repeat</code> for one scan. Keep ClamAV signatures updated separately. Unchanged detections are deduplicated within the running session; restarting may report them again.</p>
      <p className="text-sm font-medium">Operator-controlled file containment</p>
      <p className="text-xs text-muted">After reviewing a scan detection, use its SHA-256 to explicitly move that file into a recovery archive. The state directory must be private and on the same filesystem as the selected file. Restore only after review, to a new destination; existing files are never overwritten. Archives are retained after restore and are not encrypted. Keep the printed quarantine ID for recovery.</p>
      <pre className="overflow-x-auto rounded-md bg-surface p-3 text-xs">{"cynux-quarantine --state-dir ./cynux-state contain ./sample-file --expected-sha256 REVIEWED_SHA256\ncynux-quarantine --state-dir ./cynux-state restore QUARANTINE_ID ./reviewed-restored-file"}</pre>
      <p className="text-xs text-muted">Polling can miss short-lived processes. Scanning never automatically quarantines files. Containment is a local operator command, not a remote console action; it does not stop running processes, isolate the host, or protect against an administrator. On failure, inspect the reported recovery directory. This package is unsigned; endpoint installation is required even though the console is hosted.</p>
      <p className="text-sm font-medium">Local outbound domain enforcement</p>
      <p className="text-xs text-muted">Create a local policy.json with explicit allowed domains. Deny rules override allow rules; unlisted destinations are denied. A wildcard such as *.example.com covers subdomains, not the apex. Policy edits apply to new tunnels immediately; invalid or unreadable policies deny new access. Existing tunnels retain their five-minute cap.</p>
      <pre className="overflow-x-auto rounded-md bg-surface p-3 text-xs">{"# Set CYNUX_PROXY_TOKEN and CYNUX_ENDPOINT_API_KEY first\n# The API key needs only endpoint:ingest permission\ncynux-proxy --server https://cynux-security-prod.web.app --port 8765 --state-dir ./cynux-state\n\n# Local fail-closed policy files remain supported\ncynux-proxy --policy ./policy.json --port 8765 --state-dir ./cynux-state"}</pre>
      <p className="text-xs text-muted">Monitor a customer journey from this device without uploading its URL, query parameters, or response body:</p>
      <pre className="overflow-x-auto rounded-md bg-surface p-3 text-xs">{"# Set CYNUX_ENDPOINT_API_KEY with endpoint:ingest permission\ncynux-journey --server https://cynux-security-prod.web.app --state-dir ./cynux-state --key checkout --name \"Customer checkout\" --location mumbai-office --url https://shop.example/checkout --interval 60"}</pre>
      <p className="text-xs text-muted">Configure a compatible client to use the HTTP proxy at 127.0.0.1:8765 with username cynux and the token as password. Use a separate token, not your Cynux API key. The proxy permits CONNECT tunnels to public domain names on port 443 only, rejects private-network DNS results, and limits concurrency to 32 tunnels, duration to 5 minutes, idle time to 30 seconds, and traffic to 64 MiB per direction.</p>
      <p className="text-xs text-muted">Central policy refreshes every minute and fails closed after five minutes without a verified bundle. This is opt-in domain filtering, not device-wide prevention: direct connections bypass it. It does not decrypt TLS, inspect files or prompts, support plain HTTP forwarding, or change system settings. Run cynux-endpoint alongside the proxy using the same state directory to deliver hashed allowed/blocked decisions to this timeline.</p>
    </CardBody></Card>
    <Card><CardHeader><CardTitle>Endpoint fleet</CardTitle></CardHeader><CardBody>{!endpoints.data?.length ? <EmptyState title="No native endpoints" description="Deploy a Cynux collector or use the test-environment demo event to register an endpoint." /> : <Table><THead><TR><TH>Endpoint</TH><TH>OS</TH><TH>Environment</TH><TH>Risk</TH><TH>Sensor</TH><TH>Last seen</TH></TR></THead><TBody>{endpoints.data.map((item) => <TR key={item.id}><TD className="font-medium text-fg">{item.name}</TD><TD>{humanize(String(item.attributes.operating_system ?? "unknown"))}</TD><TD>{humanize(item.environment)}</TD><TD><Badge tone={riskTone(Number(item.risk_score))}>{Number(item.risk_score).toFixed(0)}</Badge></TD><TD>{humanize(String(item.attributes.sensor_status ?? "unknown"))}</TD><TD>{formatDateTime(item.last_seen_at)}</TD></TR>)}</TBody></Table>}</CardBody></Card>
    <Card><CardHeader><CardTitle>Detection timeline</CardTitle></CardHeader><CardBody>{!events.data?.length ? <EmptyState title="No endpoint events" description="Endpoint observations and deterministic detections appear here." /> : <div className="space-y-3">{events.data.map((event) => <div key={event.id} className="rounded-lg border border-line p-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="flex gap-2"><Badge tone={riskTone(event.severity === "critical" ? 100 : event.severity === "high" ? 70 : 20)}>{event.severity}</Badge><Badge tone="neutral">{humanize(String(event.evidence.network_action ?? event.evidence.verdict ?? "observe"))}</Badge></div><span className="text-xs text-muted">{formatDateTime(event.occurred_at)}</span></div><p className="mt-2 text-sm font-medium text-fg">{event.summary}</p><p className="mt-1 text-xs text-muted">{(Array.isArray(event.evidence.detection_codes) ? event.evidence.detection_codes : []).map((value) => humanize(String(value))).join(", ") || humanize(event.event_type)}</p></div>)}</div>}</CardBody></Card>
  </div>;
}

function SocWorkspace({ stories, cases, rules, experience, experienceEvents, canManage, onChanged }: { stories: UseApiResourceResult<SecurityThreatStory[]>; cases: UseApiResourceResult<Page<SocIncidentCase>>; rules: UseApiResourceResult<Page<DetectionRule>>; experience: UseApiResourceResult<SecurityExperienceSummary>; experienceEvents: UseApiResourceResult<SecurityEvent[]>; canManage: boolean; onChanged: () => void }) {
  const [form, setForm] = React.useState({ name: "", rule_key: "", category: "endpoint", event_type: "", severity: "high" as DetectionRule["severity"], minimum_event_severity: "medium" as DetectionRule["minimum_event_severity"] });
  const [evaluation, setEvaluation] = React.useState<{ evaluated: number; matched: number } | null>(null);
  const createRule = useMutation(() => api.controlPlane.createDetectionRule({ rule_key: form.rule_key, name: form.name, severity: form.severity, minimum_event_severity: form.minimum_event_severity, categories: [form.category], event_types: form.event_type ? [form.event_type] : [], conditions: [], group_by: ["identity_ref", "evidence.host"], status: "active", auto_create_case: true }), { onSuccess: () => { setForm((value) => ({ ...value, name: "", rule_key: "", event_type: "" })); onChanged(); } });
  const evaluate = useMutation((id: string, persist: boolean) => api.controlPlane.evaluateDetectionRule(id, persist), { onSuccess: (result) => { setEvaluation(result); onChanged(); } });
  const transition = useMutation((id: string, status: SocIncidentCase["status"]) => api.controlPlane.transitionSocCase(id, status, `Analyst moved case to ${status}`), { onSuccess: onChanged });
  const summary = socOperationsSummary(cases.data?.items ?? []);
  return <div className="space-y-4">
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><Card><CardBody><Metric label="Active SOC cases" value={summary.active} /></CardBody></Card><Card><CardBody><Metric label="Critical active" value={summary.critical} /></CardBody></Card><Card><CardBody><Metric label="Investigating" value={summary.investigating} /></CardBody></Card><Card><CardBody><Metric label="Contained" value={summary.contained} /></CardBody></Card></div>
    {canManage && <Card><CardHeader><CardTitle>Detection engineering</CardTitle></CardHeader><CardBody><form className="grid gap-3 md:grid-cols-3" onSubmit={(event) => { event.preventDefault(); void createRule.run(); }}><Field label="Rule name" htmlFor="detection-name"><Input id="detection-name" required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field><Field label="Stable rule key" htmlFor="detection-key"><Input id="detection-key" required pattern="[a-z0-9][a-z0-9_.:-]*" value={form.rule_key} onChange={(event) => setForm({ ...form, rule_key: event.target.value.toLowerCase().replace(/[^a-z0-9_.:-]/g, "-") })} /></Field><Field label="Event category" htmlFor="detection-category"><Input id="detection-category" required value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })} /></Field><Field label="Event type (optional)" htmlFor="detection-type"><Input id="detection-type" value={form.event_type} onChange={(event) => setForm({ ...form, event_type: event.target.value })} /></Field><Field label="Case severity" htmlFor="detection-severity"><select id="detection-severity" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value as DetectionRule["severity"] })}>{["info", "low", "medium", "high", "critical"].map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select></Field><div className="flex items-end"><Button type="submit" loading={createRule.loading}>Create active rule</Button></div></form>{createRule.errorMessage && <p role="alert" className="mt-3 text-sm text-danger">{createRule.errorMessage}</p>}</CardBody></Card>}
    <Card><CardHeader><CardTitle>Detection rules</CardTitle></CardHeader><CardBody>{rules.loading && !rules.data ? <LoadingState label="Loading detection rules…" /> : rules.error ? <ErrorState message={rules.error} onRetry={rules.refetch} /> : !rules.data?.items.length ? <EmptyState title="No detection rules" description="Create a bounded rule, dry-run it against normalized events, then persist matches into converged incident cases." /> : <div className="space-y-3">{rules.data.items.map((rule) => <div key={rule.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3"><div><div className="flex gap-2"><Badge tone={riskTone(rule.severity === "critical" ? 100 : rule.severity === "high" ? 70 : 30)}>{rule.severity}</Badge><Badge tone={rule.status === "active" ? "ok" : "neutral"}>{rule.status}</Badge></div><p className="mt-2 font-medium text-fg">{rule.name}</p><p className="text-xs text-muted">{rule.rule_key} · {rule.categories.join(", ")} · v{rule.version}</p></div><div className="flex gap-2"><Button size="sm" variant="outline" loading={evaluate.loading} onClick={() => void evaluate.run(rule.id, false)}>Dry run</Button>{canManage && rule.status === "active" && <Button size="sm" loading={evaluate.loading} onClick={() => void evaluate.run(rule.id, true)}>Evaluate & correlate</Button>}</div></div>)}</div>}{evaluation && <p className="mt-3 text-sm text-muted">Evaluated {evaluation.evaluated} events; {evaluation.matched} matched.</p>}</CardBody></Card>
    <Card><CardHeader><CardTitle>Incident cases</CardTitle></CardHeader><CardBody>{cases.loading && !cases.data ? <LoadingState label="Loading SOC cases…" /> : cases.error ? <ErrorState message={cases.error} onRetry={cases.refetch} /> : !cases.data?.items.length ? <EmptyState title="No incident cases" description="Active detection rules converge matching signals here with evidence-linked timelines." /> : <div className="space-y-3">{cases.data.items.map((item) => <div key={item.id} className="rounded-lg border border-line p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="flex gap-2"><Badge tone={riskTone(item.severity === "critical" ? 100 : item.severity === "high" ? 70 : 30)}>{item.severity}</Badge><Badge tone="neutral">{item.status}</Badge></div><h3 className="mt-2 font-medium text-fg">{item.title}</h3><p className="mt-1 text-sm text-muted">{item.summary}</p><p className="mt-2 text-xs text-muted">Priority {item.priority} · {item.event_ids.length} events · Opened {formatDateTime(item.opened_at)}</p></div>{canManage && <div className="flex flex-wrap gap-2">{item.status === "open" && <Button size="sm" onClick={() => void transition.run(item.id, "investigating")}>Investigate</Button>}{item.status === "investigating" && <><Button size="sm" variant="outline" onClick={() => void transition.run(item.id, "contained")}>Contain</Button><Button size="sm" onClick={() => void transition.run(item.id, "resolved")}>Resolve</Button></>}{item.status === "contained" && <Button size="sm" onClick={() => void transition.run(item.id, "resolved")}>Resolve</Button>}{["resolved", "dismissed"].includes(item.status) && <Button size="sm" variant="outline" onClick={() => void transition.run(item.id, "investigating")}>Reopen</Button>}</div>}</div></div>)}</div>}</CardBody></Card>
    {experience.data && <div className="grid gap-4 sm:grid-cols-3"><Card><CardBody><Metric label="Experience score" value={Number(experience.data.average_score).toFixed(1)} /></CardBody></Card><Card><CardBody><Metric label="Degraded journeys" value={experience.data.degraded_journeys} /></CardBody></Card><Card><CardBody><p className="text-xs text-muted">Business impact</p><Badge tone={experience.data.business_impact === "critical" || experience.data.business_impact === "high" ? "danger" : "neutral"}>{experience.data.business_impact}</Badge></CardBody></Card></div>}
    <Card><CardHeader><CardTitle>Correlated threat stories</CardTitle></CardHeader><CardBody>{stories.loading && !stories.data ? <LoadingState label="Correlating events…" /> : stories.error ? <ErrorState message={stories.error} onRetry={stories.refetch} /> : !stories.data?.length ? <EmptyState title="No threat stories" description="SIEM, EDR, identity, cloud, access, and deception events are correlated here." /> : <div className="space-y-3">{stories.data.map((story) => <div key={story.id} className="rounded-lg border border-line p-4"><div className="flex gap-2"><Badge tone={riskTone(story.severity === "critical" ? 100 : story.severity === "high" ? 70 : 30)}>{story.severity}</Badge><Badge tone="neutral">{story.status}</Badge></div><h3 className="mt-2 font-medium text-fg">{story.title}</h3><p className="text-sm text-muted">{story.summary}</p><p className="mt-2 text-xs text-muted">{story.event_ids.length} events · {(Number(story.confidence) * 100).toFixed(1)}% confidence · Last seen {formatDateTime(story.last_seen_at)}</p></div>)}</div>}</CardBody></Card>
    <Card><CardHeader><CardTitle>Digital experience journeys</CardTitle></CardHeader><CardBody>{experienceEvents.loading && !experienceEvents.data ? <LoadingState label="Loading journey observations…" /> : experienceEvents.error ? <ErrorState message={experienceEvents.error} onRetry={experienceEvents.refetch} /> : !experienceEvents.data?.length ? <EmptyState title="No journey observations" description="Install the Cynux journey probe to measure availability and latency." /> : <div className="space-y-3">{experienceEvents.data.slice(0, 20).map((event) => <div key={event.id} className="rounded-lg border border-line p-3"><div className="flex justify-between gap-2"><p className="font-medium text-fg">{String(event.evidence.journey_name ?? event.metrics.journey_key ?? "Journey")}</p><Badge tone={Number(event.metrics.experience_score ?? 0) < 70 ? "danger" : "ok"}>{Number(event.metrics.experience_score ?? 0).toFixed(1)}</Badge></div><p className="mt-1 text-xs text-muted">{String(event.evidence.location ?? "unknown location")} · {Number(event.metrics.latency_ms ?? 0).toFixed(0)} ms · {formatDateTime(event.occurred_at)}</p></div>)}</div>}</CardBody></Card>
  </div>;
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
