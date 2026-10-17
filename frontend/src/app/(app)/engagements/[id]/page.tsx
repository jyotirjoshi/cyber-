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
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { allowedEngagementStatuses } from "@/lib/engagement";
import { formatDateTime, formatNumber, humanize } from "@/lib/format";
import type { EngagementDocumentOut, EngagementParticipantOut } from "@/lib/types";

export default function EngagementDetailPage() {
  const id = String(useParams<{ id: string }>().id);
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("assessment:create");
  const canRetest = can("finding:validate");
  const engagement = useApiResource(() => api.engagements.get(id), [id]);
  const participants = useApiResource(() => api.engagements.participants(id), [id]);
  const milestones = useApiResource(() => api.engagements.milestones(id), [id]);
  const retests = useApiResource(() => api.engagements.retestRounds(id), [id]);
  const timeEntries = useApiResource(() => api.engagements.timeEntries(id), [id]);
  const documents = useApiResource(() => api.engagements.documents(id), [id]);
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<EngagementParticipantOut["role"]>("tester");
  const [milestone, setMilestone] = React.useState("");
  const [retestNote, setRetestNote] = React.useState("");
  const [minutes, setMinutes] = React.useState("60");
  const [workDate, setWorkDate] = React.useState(() => new Date().toISOString().slice(0, 10));
  const [timeNote, setTimeNote] = React.useState("");
  const [documentFile, setDocumentFile] = React.useState<File | null>(null);
  const [documentTitle, setDocumentTitle] = React.useState("");
  const [documentKind, setDocumentKind] = React.useState<EngagementDocumentOut["kind"]>("evidence");
  const [documentClientVisible, setDocumentClientVisible] = React.useState(false);

  const statusMutation = useMutation(
    ({ status, version }: { status: Parameters<typeof api.engagements.updateStatus>[1]; version: number }) =>
      api.engagements.updateStatus(id, status, version),
    { onSuccess: () => { toast({ title: "Engagement status updated", tone: "ok" }); void engagement.refetch(); } },
  );
  const participantMutation = useMutation(
    () => api.engagements.addParticipant(id, { email: email.trim(), role }),
    { onSuccess: () => { setEmail(""); toast({ title: "Participant added", tone: "ok" }); void participants.refetch(); } },
  );
  const milestoneMutation = useMutation(
    () => api.engagements.addMilestone(id, { title: milestone.trim() }),
    { onSuccess: () => { setMilestone(""); toast({ title: "Milestone added", tone: "ok" }); void milestones.refetch(); } },
  );
  const retestMutation = useMutation(
    () => api.engagements.createRetestRound(id, { note: retestNote.trim() || null }),
    { onSuccess: () => { setRetestNote(""); toast({ title: "Retest round requested", tone: "ok" }); void retests.refetch(); void engagement.refetch(); } },
  );
  const timeMutation = useMutation(
    () => api.engagements.addTimeEntry(id, { minutes: Number(minutes), work_date: workDate, note: timeNote.trim() || null, billable: true }),
    { onSuccess: () => { setTimeNote(""); toast({ title: "Time entry added", tone: "ok" }); void timeEntries.refetch(); } },
  );
  const documentMutation = useMutation(
    () => {
      if (!documentFile) throw new Error("Select a document first.");
      return api.engagements.uploadDocument(id, { file: documentFile, title: documentTitle.trim(), kind: documentKind, clientVisible: documentClientVisible });
    },
    { onSuccess: () => { setDocumentFile(null); setDocumentTitle(""); toast({ title: "Evidence document uploaded", tone: "ok" }); void documents.refetch(); } },
  );

  if (engagement.loading && !engagement.data) return <LoadingState label="Loading engagement…" />;
  if (engagement.error) return <ErrorState message={engagement.error} onRetry={engagement.refetch} />;
  if (!engagement.data) return <EmptyState title="Engagement unavailable" description="The engagement does not exist or is outside your organization." />;
  const record = engagement.data;

  return <div className="space-y-6">
    <PageHeader title={record.title} description={record.description ?? "PTaaS delivery workspace"} actions={<Link href="/engagements"><Button variant="ghost">All engagements</Button></Link>} />
    <Card><CardBody className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Detail label="Status" value={humanize(record.status)} />
      <Detail label="Starts" value={record.starts_at ? formatDateTime(record.starts_at) : "Unscheduled"} />
      <Detail label="Ends" value={record.ends_at ? formatDateTime(record.ends_at) : "Open-ended"} />
      <Detail label="Portal" value={record.client_visible ? "Client visible" : "Internal only"} />
      {canManage && allowedEngagementStatuses(record.status).length > 0 && <div className="sm:col-span-2 lg:col-span-4"><p className="mb-2 text-xs uppercase text-muted">Move engagement</p><div className="flex flex-wrap gap-2">{allowedEngagementStatuses(record.status).map((status) => <Button key={status} size="sm" variant="outline" loading={statusMutation.loading} onClick={() => void statusMutation.run({ status, version: record.version })}>{humanize(status)}</Button>)}</div>{statusMutation.errorMessage && <p role="alert" className="mt-2 text-sm text-danger">{statusMutation.errorMessage}</p>}</div>}
    </CardBody></Card>

    <div className="grid gap-6 lg:grid-cols-2">
      <Card><CardHeader><CardTitle>Delivery milestones</CardTitle></CardHeader><CardBody className="space-y-3">
        {milestones.loading && !milestones.data ? <LoadingState label="Loading milestones…" /> : !milestones.data?.length ? <p className="text-sm text-muted">No milestones yet.</p> : milestones.data.map((item) => <div key={item.id} className="flex items-center justify-between rounded-lg border border-line p-3"><div><p className="text-sm font-medium text-fg">{item.title}</p>{item.due_at && <p className="text-xs text-muted">Due {formatDateTime(item.due_at)}</p>}</div><Badge tone={item.status === "completed" ? "ok" : item.status === "blocked" ? "danger" : "neutral"}>{humanize(item.status)}</Badge></div>)}
        {canManage && <form className="flex gap-2" onSubmit={(event) => { event.preventDefault(); void milestoneMutation.run(); }}><Input aria-label="Milestone title" placeholder="Add milestone" value={milestone} onChange={(event) => setMilestone(event.target.value)} required /><Button type="submit" loading={milestoneMutation.loading}>Add</Button></form>}
      </CardBody></Card>

      <Card><CardHeader><CardTitle>Participants</CardTitle></CardHeader><CardBody className="space-y-3">
        {participants.loading && !participants.data ? <LoadingState label="Loading participants…" /> : !participants.data?.length ? <p className="text-sm text-muted">No participants yet.</p> : participants.data.map((item) => <div key={item.id} className="flex items-center justify-between rounded-lg border border-line p-3"><div><p className="text-sm font-medium text-fg">{item.display_name || item.email}</p><p className="text-xs text-muted">{humanize(item.role)}</p></div><Badge tone={item.status === "active" ? "ok" : "neutral"}>{humanize(item.status)}</Badge></div>)}
        {canManage && <form className="grid gap-2 sm:grid-cols-[1fr_11rem_auto]" onSubmit={(event) => { event.preventDefault(); void participantMutation.run(); }}><Input aria-label="Participant email" type="email" placeholder="person@example.com" value={email} onChange={(event) => setEmail(event.target.value)} required /><Select aria-label="Participant role" value={role} onChange={(event) => setRole(event.target.value as EngagementParticipantOut["role"])}><option value="tester">Tester</option><option value="lead_tester">Lead tester</option><option value="client_manager">Client manager</option><option value="client_observer">Client observer</option></Select><Button type="submit" loading={participantMutation.loading}>Add</Button></form>}
      </CardBody></Card>
    </div>

    <Card><CardHeader><CardTitle>Retest rounds</CardTitle></CardHeader><CardBody className="space-y-3">
      {retests.loading && !retests.data ? <LoadingState label="Loading retests…" /> : !retests.data?.length ? <p className="text-sm text-muted">No retests requested.</p> : retests.data.map((round) => <div key={round.id} className="rounded-lg border border-line p-3"><div className="flex items-center justify-between"><p className="font-medium text-fg">Round {round.ordinal}</p><Badge tone={round.status === "completed" ? "ok" : round.status === "failed" ? "danger" : "warn"}>{humanize(round.status)}</Badge></div>{round.note && <p className="mt-2 text-sm text-muted">{round.note}</p>}<p className="mt-1 text-xs text-muted">Requested {formatDateTime(round.requested_at)}</p></div>)}
      {canRetest && ["active", "retesting"].includes(record.status) && <form className="space-y-2" onSubmit={(event) => { event.preventDefault(); void retestMutation.run(); }}><Field label="Retest request note" htmlFor="retest-note"><Textarea id="retest-note" value={retestNote} onChange={(event) => setRetestNote(event.target.value)} maxLength={10000} /></Field><Button type="submit" loading={retestMutation.loading}>Request retest round</Button></form>}
    </CardBody></Card>

    <div className="grid gap-6 lg:grid-cols-2">
      <Card><CardHeader><CardTitle>Time tracking</CardTitle></CardHeader><CardBody className="space-y-3">
        {timeEntries.loading && !timeEntries.data ? <LoadingState label="Loading time entries…" /> : !timeEntries.data?.length ? <p className="text-sm text-muted">No delivery time logged.</p> : <div className="space-y-2">{timeEntries.data.map((entry) => <div key={entry.id} className="flex items-center justify-between rounded-lg border border-line p-3"><div><p className="text-sm font-medium text-fg">{entry.note || "Engagement work"}</p><p className="text-xs text-muted">{entry.work_date}</p></div><span className="text-sm tabular-nums text-fg">{Math.floor(entry.minutes / 60)}h {entry.minutes % 60}m</span></div>)}</div>}
        {canManage && <form className="grid gap-2 sm:grid-cols-[7rem_9rem_1fr_auto]" onSubmit={(event) => { event.preventDefault(); void timeMutation.run(); }}><Input aria-label="Minutes" type="number" min={1} max={1440} value={minutes} onChange={(event) => setMinutes(event.target.value)} required /><Input aria-label="Work date" type="date" value={workDate} onChange={(event) => setWorkDate(event.target.value)} required /><Input aria-label="Work note" placeholder="Work performed" value={timeNote} onChange={(event) => setTimeNote(event.target.value)} maxLength={1000} /><Button type="submit" loading={timeMutation.loading}>Log</Button></form>}
      </CardBody></Card>

      <Card><CardHeader><CardTitle>Evidence and deliverables</CardTitle></CardHeader><CardBody className="space-y-3">
        {documents.loading && !documents.data ? <LoadingState label="Loading documents…" /> : !documents.data?.length ? <p className="text-sm text-muted">No documents uploaded.</p> : <div className="space-y-2">{documents.data.map((document) => <div key={document.id} className="rounded-lg border border-line p-3"><div className="flex items-center justify-between"><p className="text-sm font-medium text-fg">{document.title}</p><Badge tone={document.client_visible ? "primary" : "neutral"}>{document.client_visible ? "Client" : "Internal"}</Badge></div><p className="mt-1 text-xs text-muted">{humanize(document.kind)} · {formatNumber(document.size_bytes)} bytes · SHA-256 {document.sha256.slice(0, 12)}…</p></div>)}</div>}
        {canManage && <form className="space-y-2" onSubmit={(event) => { event.preventDefault(); void documentMutation.run(); }}><div className="grid gap-2 sm:grid-cols-2"><Input aria-label="Document title" placeholder="Authorization letter" value={documentTitle} onChange={(event) => setDocumentTitle(event.target.value)} required maxLength={300} /><Select aria-label="Document kind" value={documentKind} onChange={(event) => setDocumentKind(event.target.value as EngagementDocumentOut["kind"])}><option value="scope">Scope</option><option value="authorization">Authorization</option><option value="evidence">Evidence</option><option value="report">Report</option><option value="deliverable">Deliverable</option><option value="other">Other</option></Select></div><Input aria-label="Document file" type="file" onChange={(event) => setDocumentFile(event.target.files?.[0] ?? null)} required /><label className="flex items-center gap-2 text-sm text-muted"><input type="checkbox" checked={documentClientVisible} onChange={(event) => setDocumentClientVisible(event.target.checked)} />Visible in client portal</label><Button type="submit" loading={documentMutation.loading} disabled={!documentFile}>Upload document</Button></form>}
      </CardBody></Card>
    </div>
  </div>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><p className="text-xs uppercase text-muted">{label}</p><p className="mt-1 text-sm font-medium text-fg">{value}</p></div>;
}
