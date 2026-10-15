"use client";
import * as React from "react";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { MemoryCandidate } from "@/lib/agent-definition";

export default function LearningPage() {
  const { activeOrganizationId, can } = useAuth();
  if (!can("org:manage")) return <p className="text-muted">Organization management permission is required to review learning.</p>;
  return <LearningWorkspace key={activeOrganizationId ?? "none"} />;
}

function LearningWorkspace() {
  const [status, setStatus] = React.useState<MemoryCandidate["status"]>("pending");
  const memories = useApiResource(api.agent.memories, []);
  const revoke = useMutation(api.agent.disableMemory, { onSuccess: memories.refetch });
  return <div className="space-y-6">
    <PageHeader title="Organizational learning" description="Review evidence-backed facts before they become reference context for future agent conversations. Proposals do not teach the agent until you approve them." />
    <Field label="Review status" htmlFor="learning-status"><Select id="learning-status" value={status} onChange={(e) => setStatus(e.target.value as MemoryCandidate["status"])}><option value="pending">Pending review</option><option value="approved">Approved</option><option value="rejected">Rejected</option><option value="expired">Expired</option></Select></Field>
    <CandidateList key={status} status={status} onDecision={memories.refetch} />
    <section className="space-y-4"><h2 className="text-lg font-medium">Curated memory</h2><p className="text-sm text-muted">Approved entries use the existing tenant memory system. Revocation prevents an entry from being included in future prompts.</p>
      {(memories.error || revoke.errorMessage) && <p role="alert" className="text-danger">{memories.error || revoke.errorMessage}</p>}
      {memories.data?.map((memory) => <article key={memory.id} className="rounded-xl border border-line p-4"><div className="flex items-center justify-between"><h3 className="font-medium">{memory.key}</h3><span className="text-xs text-muted">{!memory.is_active ? "Revoked" : memory.expires_at && Date.parse(memory.expires_at) <= Date.now() ? "Expired" : "Active"} · {memory.source}</span></div><p className="mt-2 whitespace-pre-wrap text-sm">{memory.content}</p>{memory.expires_at && <p className="mt-2 text-xs text-muted">Expires: {new Date(memory.expires_at).toLocaleString()}</p>}{memory.is_active && <Button className="mt-3" variant="ghost" disabled={revoke.loading} onClick={() => { if (window.confirm(`Revoke memory ${memory.key}?`)) void revoke.run(memory.id); }}>Revoke memory</Button>}</article>)}
      {memories.data?.length === 0 && <p className="text-sm text-muted">No curated memories yet.</p>}
    </section>
  </div>;
}

function CandidateList({ status, onDecision }: { status: MemoryCandidate["status"]; onDecision: () => void }) {
  const [offset, setOffset] = React.useState(0);
  const rows = useApiResource(() => api.customAgents.candidates(status, offset), [status, offset]);
  if (rows.error) return <ErrorState message={rows.error} onRetry={rows.refetch} />;
  return <section className="space-y-4">
    <div className="flex items-center justify-between"><h2 className="font-medium">Learning proposals</h2><Button variant="ghost" onClick={rows.refetch}>Refresh</Button></div>
    {rows.loading ? <LoadingState label="Loading proposals…" /> : rows.data?.map((row) => <CandidateCard key={row.id} row={row} onDecision={() => { rows.refetch(); onDecision(); }} />)}
    {!rows.loading && rows.data?.length === 0 && <p className="text-sm text-muted">No {status} proposals.</p>}
    <div className="flex gap-2"><Button variant="ghost" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</Button><Button variant="ghost" disabled={(rows.data?.length ?? 0) < 50} onClick={() => setOffset(offset + 50)}>Next</Button></div>
  </section>;
}

function CandidateCard({ row, onDecision }: { row: MemoryCandidate; onDecision: () => void }) {
  const [content, setContent] = React.useState(row.content);
  const [rationale, setRationale] = React.useState("");
  const [expiry, setExpiry] = React.useState(row.expires_at?.slice(0, 16) ?? "");
  const approve = useMutation(api.customAgents.approveMemory, { onSuccess: onDecision });
  const reject = useMutation(api.customAgents.rejectMemory, { onSuccess: onDecision });
  const busy = approve.loading || reject.loading;
  return <article className="space-y-4 rounded-xl border border-line bg-surface p-5">
    <div className="flex items-center justify-between"><h3 className="font-medium">{row.key}</h3><span className="text-xs text-muted">{row.category} · proposed confidence {Math.round(row.confidence * 100)}%</span></div>
    <p className="whitespace-pre-wrap text-sm">{row.content}</p>
    <details className="text-sm"><summary className="cursor-pointer">Evidence references ({row.evidence.length})</summary><ul className="mt-2 space-y-2 text-xs text-muted">{row.evidence.map((item) => <li key={`${item.kind}:${item.id}`} className="break-all">{item.kind.replaceAll("_", " ")}: <code>{item.id}</code></li>)}</ul></details>
    {row.decision_rationale && <p className="text-sm text-muted">Review rationale: {row.decision_rationale}</p>}
    {(approve.errorMessage || reject.errorMessage) && <p role="alert" className="text-danger">{approve.errorMessage || reject.errorMessage}</p>}
    {row.status === "pending" && <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void approve.run(row.id, { content: content.trim(), rationale: rationale.trim() || undefined, expires_at: expiry ? new Date(`${expiry}Z`).toISOString() : null }); }}>
      <Field label="Reviewed fact (edit before approval)" htmlFor={`content-${row.id}`}><Textarea id={`content-${row.id}`} required minLength={3} maxLength={2000} value={content} onChange={(e) => setContent(e.target.value)} /></Field>
      <div className="grid gap-4 md:grid-cols-2"><Field label="Expiry (UTC, optional)" htmlFor={`expiry-${row.id}`}><Input id={`expiry-${row.id}`} type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)} /></Field><Field label="Review rationale" htmlFor={`rationale-${row.id}`} hint="Required when rejecting."><Input id={`rationale-${row.id}`} maxLength={2000} value={rationale} onChange={(e) => setRationale(e.target.value)} /></Field></div>
      <div className="flex gap-3"><Button type="submit" disabled={busy || content.trim().length < 3} loading={approve.loading}>Approve learning</Button><Button type="button" variant="danger" disabled={busy || rationale.trim().length < 3} loading={reject.loading} onClick={() => void reject.run(row.id, rationale.trim())}>Reject</Button></div>
    </form>}
  </article>;
}
