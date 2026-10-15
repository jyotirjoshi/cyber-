"use client";

import * as React from "react";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { CollectionCreateInput, KnowledgeHit, sourceStatus, TERMINAL_SOURCE_STATES, validateKnowledgeFile } from "@/lib/knowledge";

export default function KnowledgePage() {
  const { activeOrganizationId } = useAuth();
  return <KnowledgeWorkspace key={activeOrganizationId ?? "none"} />;
}

function KnowledgeWorkspace() {
  const { can, activeOrganizationId } = useAuth();
  const manage = can("org:manage");
  const collections = useApiResource(api.knowledge.collections, [activeOrganizationId]);
  const [selected, setSelected] = React.useState("");
  const [offset, setOffset] = React.useState(0);
  const [name, setName] = React.useState("");
  const [provider, setProvider] = React.useState<"openai" | "google">("openai");
  const [query, setQuery] = React.useState("");
  const [searchQuery, setSearchQuery] = React.useState("");
  const [hits, setHits] = React.useState<KnowledgeHit[] | null>(null);
  const [fileError, setFileError] = React.useState<string | null>(null);
  const [poll, setPoll] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);
  const sources = useApiResource(() => api.knowledge.sources(selected, offset), [selected, offset, activeOrganizationId], {
    enabled: Boolean(selected), refetchInterval: poll ? 10_000 : undefined,
  });
  React.useEffect(() => {
    setSelected(""); setHits(null); setOffset(0); setPoll(false);
  }, [activeOrganizationId]);
  React.useEffect(() => {
    if (collections.data?.length && !selected) setSelected(collections.data[0].id);
  }, [collections.data, selected]);
  React.useEffect(() => {
    setPoll(Boolean(sources.data?.some((source) => !TERMINAL_SOURCE_STATES.has(source.status))));
  }, [sources.data]);
  const create = useMutation(api.knowledge.createCollection, {
    onSuccess: (row) => { collections.refetch(); setSelected(row.id); setName(""); setOffset(0); },
  });
  const upload = useMutation((file: File) => api.knowledge.upload(selected, file), {
    onSuccess: (row) => { sources.refetch(); setPoll(true); if (fileRef.current) fileRef.current.value = "";
      if (row.status === "failed") setFileError(sourceStatus(row)); },
  });
  const remove = useMutation(api.knowledge.deleteSource, { onSuccess: () => { sources.refetch(); setHits(null); } });
  const restore = useMutation(api.knowledge.restoreSource, { onSuccess: () => { sources.refetch(); setPoll(true); } });
  const retry = useMutation(api.knowledge.retrySource, { onSuccess: () => { sources.refetch(); setPoll(true); } });
  const selectedRef = React.useRef(selected);
  selectedRef.current = selected;
  const search = useMutation(async (text: string) => ({ hits: await api.knowledge.search([selected], text), query: text, collection: selected }), {
    onSuccess: (result) => { if (result.collection === selectedRef.current) { setHits(result.hits); setSearchQuery(result.query); } },
  });
  const feedback = useMutation(api.knowledge.feedback);
  const errors = [create.errorMessage, upload.errorMessage, remove.errorMessage, restore.errorMessage, retry.errorMessage, search.errorMessage, feedback.errorMessage, fileError].filter(Boolean);

  function createCollection(event: React.FormEvent) {
    event.preventDefault();
    const body: CollectionCreateInput = { name: name.trim(), retrieval_provider: "internal",
      retrieval_policy: { embedding: { provider, model: provider === "google" ? "gemini-embedding-001" : "text-embedding-3-small" } } };
    void create.run(body);
  }

  return <div className="space-y-6">
    <PageHeader title="Knowledge" description="Give your agents approved runbooks, procedures, and organizational context. Search results cite the document and passage." />
    {errors.map((error, index) => <p key={index} role="alert" className="rounded-lg border border-danger/30 p-3 text-sm text-danger">{error}</p>)}
    {collections.error ? <ErrorState message={collections.error} onRetry={collections.refetch} /> : null}
    {collections.loading && !collections.data ? <LoadingState label="Loading knowledge collections…" /> : null}
    {manage && <form onSubmit={createCollection} className="grid gap-4 rounded-xl border border-line bg-surface p-5 md:grid-cols-3">
      <Field label="New collection" htmlFor="knowledge-name"><Input id="knowledge-name" required maxLength={160} placeholder="Incident response runbooks" value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <Field label="Embedding provider" htmlFor="knowledge-provider" hint="Uses the API key saved in Integrations. Embedding calls may incur provider charges."><Select id="knowledge-provider" value={provider} onChange={(e) => setProvider(e.target.value as typeof provider)}><option value="openai">OpenAI · text-embedding-3-small</option><option value="google">Gemini · gemini-embedding-001</option></Select></Field>
      <div className="flex items-center"><Button type="submit" loading={create.loading} disabled={!name.trim()}>Create collection</Button></div>
    </form>}
    <Field label="Collection" htmlFor="knowledge-collection"><Select id="knowledge-collection" value={selected} onChange={(e) => { setSelected(e.target.value); setOffset(0); setHits(null); setFileError(null); }}><option value="">Select a collection</option>{collections.data?.map((collection) => <option key={collection.id} value={collection.id}>{collection.name}</option>)}</Select></Field>
    {selected && <>
      {manage && <div className="rounded-xl border border-line p-5"><Field label="Upload document" htmlFor="knowledge-file" hint="PDF, Markdown, text, JSON, SARIF, or JSON SBOM. Maximum 20 MB. Indexing continues in the background."><Input ref={fileRef} id="knowledge-file" type="file" accept=".pdf,.md,.txt,.json,.sarif" disabled={upload.loading} onChange={(event) => {
        const file = event.target.files?.[0]; if (!file) return;
        const error = validateKnowledgeFile(file); setFileError(error); if (!error) void upload.run(file);
      }} /></Field>{upload.loading && <p role="status" className="mt-2 text-sm text-muted">Uploading document…</p>}</div>}
      <div className="flex items-center justify-between"><h2 className="font-medium">Documents</h2><Button variant="ghost" onClick={sources.refetch}>Refresh</Button></div>
      {sources.error && <ErrorState message={sources.error} onRetry={sources.refetch} />}
      {sources.loading && !sources.data ? <LoadingState label="Loading documents…" /> : <Table><THead><TR><TH>Document</TH><TH>Size</TH><TH>Status</TH><TH>Passages</TH><TH /></TR></THead><TBody>{sources.data?.map((source) => <TR key={source.id}><TD>{source.filename}</TD><TD>{Math.ceil(source.size_bytes / 1024)} KB</TD><TD>{sourceStatus(source)}</TD><TD>{source.indexed_chunks}/{source.total_chunks}</TD><TD><div className="flex gap-2">{manage && source.status === "failed" && source.error_code !== "storage_failed" && <Button variant="ghost" disabled={retry.loading} onClick={() => void retry.run(source.id)}>Retry</Button>}{manage && source.status === "deleted" && <Button variant="ghost" disabled={restore.loading} onClick={() => void restore.run(source.id)}>Restore</Button>}{manage && source.status !== "deleted" && <Button variant="ghost" disabled={remove.loading} onClick={() => { if (window.confirm(`Remove ${source.filename} from agent knowledge?`)) void remove.run(source.id); }}>Remove</Button>}</div></TD></TR>)}</TBody></Table>}
      {sources.data?.length === 0 && <p className="text-sm text-muted">No documents in this collection yet.</p>}
      <div className="flex gap-3"><Button variant="ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</Button><Button variant="ghost" disabled={(sources.data?.length ?? 0) < 100} onClick={() => setOffset(offset + 100)}>Next</Button></div>
      <form className="space-y-3 rounded-xl border border-line p-5" onSubmit={(event) => { event.preventDefault(); setHits(null); void search.run(query.trim()); }}><Field label="Search preview" htmlFor="knowledge-query" hint="Search ready documents and inspect the citations an agent can use."><Input id="knowledge-query" required maxLength={2000} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="What is the production change approval procedure?" /></Field><Button type="submit" loading={search.loading} disabled={!query.trim()}>Search knowledge</Button></form>
      {hits?.length === 0 && <p role="status" className="text-sm text-muted">No matching passages. Check that documents are ready and try a more specific query.</p>}
      <div className="space-y-4">{hits?.map((hit) => <article key={hit.chunk_id} className="rounded-xl border border-line bg-surface p-5"><h3 className="font-medium">{hit.citation.filename}{hit.citation.page ? ` · Page ${hit.citation.page}` : ""}{hit.citation.section ? ` · ${hit.citation.section}` : ""}</h3><p className="mt-3 whitespace-pre-wrap text-sm">{hit.text}</p><details className="mt-3 text-xs text-muted"><summary>Citation</summary><p className="mt-2 break-all">Passage: {hit.chunk_id}<br />Content hash: {hit.citation.content_hash}</p></details>{hit.citation.provider === "internal" && <div className="mt-3 flex gap-2"><Button variant="ghost" disabled={feedback.loading} onClick={() => void feedback.run(hit.chunk_id, searchQuery, true)}>Useful</Button><Button variant="ghost" disabled={feedback.loading} onClick={() => void feedback.run(hit.chunk_id, searchQuery, false)}>Not useful</Button></div>}</article>)}</div>
    </>}
  </div>;
}
