"use client";

import * as React from "react";
import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { humanize } from "@/lib/format";

const QUERY_BLOCKS = ["risk_summary", "severity_summary", "risk_trend", "mttr_summary", "sla_summary", "top_findings", "asset_risk", "compliance_summary", "assessment_coverage"];

export default function ReportTemplatesPage() {
  const { can } = useAuth();
  const canManage = can("report:generate");
  const templates = useApiResource(() => api.reports.templates(), []);
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [queries, setQueries] = React.useState<string[]>(["risk_summary", "severity_summary", "top_findings"]);
  const create = useMutation(() => api.reports.createTemplate({
    name,
    description: description || null,
    definition: {
      blocks: [
        { type: "title", text: name },
        ...queries.map((query) => ({ type: query === "risk_trend" ? "trend" : query === "top_findings" ? "table" : "metric", query, label: humanize(query), limit: 25 })),
      ],
    },
  }), { onSuccess: () => { setOpen(false); setName(""); templates.refetch(); } });
  return <div className="space-y-6">
    <PageHeader title="Report templates" description="Versioned, safe report layouts built from approved data blocks." action={<div className="flex gap-2"><Link href="/reports"><Button variant="ghost">Reports</Button></Link>{canManage && <Button onClick={() => setOpen(true)}>New version</Button>}</div>} />
    {templates.loading && !templates.data ? <LoadingState label="Loading templates…" /> : templates.error ? <ErrorState message={templates.error} onRetry={templates.refetch} /> : !templates.data?.length ? <EmptyState title="No templates" description="Create an executive, technical, compliance, or portfolio layout." /> : <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{templates.data.map((template) => <Card key={template.id}><CardBody><div className="flex justify-between"><h2 className="font-medium text-fg">{template.name}</h2><Badge tone={template.is_active ? "ok" : "neutral"}>v{template.version}</Badge></div><p className="mt-1 text-sm text-muted">{template.description || "No description"}</p><p className="mt-3 text-xs text-muted">{template.definition.blocks.length} approved block(s) · {template.is_active ? "Current" : "Historical snapshot"}</p></CardBody></Card>)}</div>}
    {open && <Modal title="Create report template version" onClose={() => setOpen(false)}><form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void create.run(); }}><Field label="Template name" htmlFor="template-name"><Input id="template-name" required maxLength={160} value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Description" htmlFor="template-description"><Input id="template-description" maxLength={1000} value={description} onChange={(event) => setDescription(event.target.value)} /></Field><fieldset><legend className="mb-2 text-sm font-medium text-fg">Saved data blocks</legend><div className="grid gap-2 sm:grid-cols-2">{QUERY_BLOCKS.map((query) => <label key={query} className="flex gap-2 rounded-md border border-line p-2 text-sm"><input type="checkbox" checked={queries.includes(query)} onChange={(event) => setQueries((current) => event.target.checked ? [...current, query] : current.filter((value) => value !== query))} />{humanize(query)}</label>)}</div></fieldset>{create.errorMessage && <p className="text-sm text-danger">{create.errorMessage}</p>}<div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" loading={create.loading} disabled={!queries.length}>Create version</Button></div></form></Modal>}
  </div>;
}
