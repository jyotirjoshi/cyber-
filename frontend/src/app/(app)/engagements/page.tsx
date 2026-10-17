"use client";

import Link from "next/link";
import * as React from "react";

import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Textarea } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, THead, TD, TH, TR, Table } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { engagementProgress } from "@/lib/engagement";
import { formatDateTime, humanize } from "@/lib/format";
import type { EngagementCreateIn, EngagementStatus } from "@/lib/types";

const PAGE_SIZE = 25;
const STATUS_TONE: Record<EngagementStatus, BadgeTone> = {
  draft: "neutral",
  scoping: "info",
  active: "primary",
  retesting: "warn",
  completed: "ok",
  cancelled: "danger",
};

export default function EngagementsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canRead = can("assessment:read");
  const canCreate = can("assessment:create");
  const [offset, setOffset] = React.useState(0);
  const [open, setOpen] = React.useState(false);
  const [title, setTitle] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [startsAt, setStartsAt] = React.useState("");
  const [endsAt, setEndsAt] = React.useState("");

  const engagements = useApiResource(
    () => api.engagements.list({ limit: PAGE_SIZE, offset }),
    [offset],
    { enabled: canRead },
  );
  const create = useMutation(api.engagements.create, {
    onSuccess: () => {
      toast({ title: "Engagement created", tone: "ok" });
      setOpen(false);
      setTitle("");
      setDescription("");
      setTargets("");
      setStartsAt("");
      setEndsAt("");
      void engagements.refetch();
    },
  });

  if (!canRead) {
    return <EmptyState title="No access" description="You cannot view PTaaS engagements." />;
  }

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const scopeTargets = targets.split(/\r?\n/).map((target) => target.trim()).filter(Boolean);
    const body: EngagementCreateIn = {
      title: title.trim(),
      description: description.trim() || null,
      scope: { targets: scopeTargets },
      starts_at: startsAt ? new Date(`${startsAt}T00:00:00Z`).toISOString() : null,
      ends_at: endsAt ? new Date(`${endsAt}T23:59:59Z`).toISOString() : null,
      client_visible: true,
    };
    void create.run(body);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="PTaaS engagements"
        description="Scope, staff, deliver, collaborate, and manage evidence-backed retests."
        actions={canCreate ? <Button onClick={() => setOpen(true)}>New engagement</Button> : undefined}
      />

      {engagements.loading && !engagements.data ? <LoadingState label="Loading engagements…" />
        : engagements.error ? <ErrorState message={engagements.error} onRetry={engagements.refetch} />
        : !engagements.data?.items.length ? <EmptyState title="No engagements yet" description="Create an engagement to establish customer scope, staffing, milestones, and retest delivery." />
        : <Card><CardBody className="p-0"><Table><THead><TR><TH>Engagement</TH><TH>Status</TH><TH>Delivery</TH><TH>Window</TH><TH>Visibility</TH></TR></THead><TBody>
          {engagements.data.items.map((engagement) => <TR key={engagement.id}>
            <TD><Link href={`/engagements/${engagement.id}`} className="font-medium text-fg hover:text-primary">{engagement.title}</Link>{engagement.description && <p className="mt-1 line-clamp-1 text-xs text-muted">{engagement.description}</p>}</TD>
            <TD><Badge tone={STATUS_TONE[engagement.status]}>{humanize(engagement.status)}</Badge></TD>
            <TD className="min-w-36"><div className="h-1.5 overflow-hidden rounded-full bg-surface-2"><div className="h-full rounded-full bg-primary" style={{ width: `${engagementProgress(engagement.status)}%` }} /></div><p className="mt-1 text-xs tabular-nums text-muted">{engagementProgress(engagement.status)}%</p></TD>
            <TD className="text-muted">{engagement.starts_at ? formatDateTime(engagement.starts_at) : "Unscheduled"}{engagement.ends_at ? ` – ${formatDateTime(engagement.ends_at)}` : ""}</TD>
            <TD>{engagement.client_visible ? "Client portal" : "Internal"}</TD>
          </TR>)}
        </TBody></Table></CardBody></Card>}

      {engagements.data && <Pagination meta={engagements.data.meta} onOffsetChange={setOffset} />}

      {open && <Modal title="New PTaaS engagement" onClose={() => setOpen(false)}><form className="space-y-4" onSubmit={submit}>
        <Field label="Title" htmlFor="engagement-title" required><Input id="engagement-title" value={title} onChange={(event) => setTitle(event.target.value)} required maxLength={300} /></Field>
        <Field label="Customer-facing description" htmlFor="engagement-description"><Textarea id="engagement-description" value={description} onChange={(event) => setDescription(event.target.value)} maxLength={20000} /></Field>
        <Field label="Targets" htmlFor="engagement-targets" hint="One authorized hostname, URL, CIDR, repository, or cloud scope per line." required><Textarea id="engagement-targets" value={targets} onChange={(event) => setTargets(event.target.value)} required /></Field>
        <div className="grid gap-4 sm:grid-cols-2"><Field label="Starts" htmlFor="engagement-start"><Input id="engagement-start" type="date" value={startsAt} onChange={(event) => setStartsAt(event.target.value)} /></Field><Field label="Ends" htmlFor="engagement-end"><Input id="engagement-end" type="date" value={endsAt} min={startsAt || undefined} onChange={(event) => setEndsAt(event.target.value)} /></Field></div>
        {create.errorMessage && <p role="alert" className="text-sm text-danger">{create.errorMessage}</p>}
        <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" loading={create.loading}>Create engagement</Button></div>
      </form></Modal>}
    </div>
  );
}
