"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { buildCanonicalWorkUpdate, toLocalDateTimeInput } from "@/lib/canonical-work";
import { canCreateCanonicalTicket } from "@/lib/canonical-ticket";
import { parseCustomFields } from "@/lib/custom-fields";
import { formatDateTime, humanize } from "@/lib/format";
import { safeExternalUrl } from "@/lib/safe-external-url";

export default function CanonicalFindingPage() {
  const params = useParams();
  const rawId = params.id;
  const id = (Array.isArray(rawId) ? rawId[0] : rawId) ?? "";
  const { can } = useAuth();
  const { toast } = useToast();
  const canRead = can("finding:read");
  const canDecide = can("finding:validate");
  const canRemediate = can("finding:remediate");
  const canTicket = can("ticket:create");
  const [decision, setDecision] = React.useState<"open" | "accepted_risk" | "false_positive" | "">("");
  const [reason, setReason] = React.useState("");
  const [assignee, setAssignee] = React.useState("");
  const [dueLocal, setDueLocal] = React.useState("");
  const [plan, setPlan] = React.useState("");
  const [customFieldsText, setCustomFieldsText] = React.useState("{}");
  const { data, error, loading, refetch } = useApiResource(
    () => api.canonicalFindings.get(id), [id], { enabled: canRead && !!id },
  );
  const members = useApiResource(
    () => api.organization.members({ limit: 100 }), [canRemediate],
    { enabled: canRemediate },
  );
  React.useEffect(() => {
    if (!data) return;
    setAssignee(data.assignee_user_id ?? "");
    setDueLocal(toLocalDateTimeInput(data.due_at));
    setPlan(data.remediation_plan ?? "");
    setCustomFieldsText(JSON.stringify(data.custom_fields ?? {}, null, 2));
  }, [data]);
  const mutation = useMutation(
    (status: "open" | "accepted_risk" | "false_positive", rationale: string, version: number) =>
      api.canonicalFindings.decide(id, { status, reason: rationale, expected_version: version }),
    { onSuccess: () => { setDecision(""); setReason(""); refetch(); toast({ title: "Finding decision saved", tone: "ok" }); } },
  );
  const workMutation = useMutation(
    (body: Parameters<typeof api.canonicalFindings.updateWork>[1]) =>
      api.canonicalFindings.updateWork(id, body),
    { onSuccess: () => { refetch(); toast({ title: "Remediation work saved", tone: "ok" }); } },
  );
  const ticketMutation = useMutation(
    () => api.canonicalFindings.createTicket(id),
    { onSuccess: (ticket) => {
      refetch();
      toast({ title: "Jira ticket linked", description: ticket.external_key, tone: "ok" });
    } },
  );
  const customFieldsMutation = useMutation(
    () => api.canonicalFindings.updateWork(id, {
      expected_version: data!.status_version,
      custom_fields: parseCustomFields(customFieldsText),
    }),
    { onSuccess: () => { refetch(); toast({ title: "Finding custom fields saved", tone: "ok" }); } },
  );
  if (!canRead) return <EmptyState title="No access" description="You don't have permission to view this." />;
  if (loading && !data) return <LoadingState label="Loading canonical finding…" />;
  if (error && !data) return <ErrorState message={error} onRetry={refetch} />;
  if (!data) return <EmptyState title="Finding not found" description="This finding may have been removed." />;

  const allowed = data.status === "new" || data.status === "reopened"
    ? (["open", "accepted_risk", "false_positive"] as const)
    : data.status === "open"
      ? (["accepted_risk", "false_positive"] as const)
      : data.status === "accepted_risk" || data.status === "false_positive"
        ? (["open"] as const)
        : ([] as const);
  const workUpdate = buildCanonicalWorkUpdate(data, { assignee, dueLocal, plan });
  const activeMembers = (members.data?.items ?? []).filter((member) => member.is_active && member.accepted_at);
  const selectedMember = activeMembers.find((member) => member.user_id === data.assignee_user_id);

  return (
    <div className="space-y-6">
      <Link href="/findings?view=canonical" className="text-sm text-primary hover:underline">← Back to canonical findings</Link>
      <PageHeader title={data.title} description={`${humanize(data.status)} · ${data.cve_ids.join(", ") || "No CVE"}`} />
      <Card>
        <CardHeader><CardTitle>Canonical finding</CardTitle><SeverityBadge severity={data.severity} /></CardHeader>
        <CardBody className="grid gap-4 text-sm sm:grid-cols-2">
          <div><span className="text-muted">Asset</span><div><Link className="text-primary hover:underline" href={`/assets/${data.asset_id}`}>View linked asset</Link></div></div>
          <div><span className="text-muted">State</span><div>{humanize(data.status)}</div></div>
          <div><span className="text-muted">Risk score</span><div className="font-semibold">{data.risk_score.toFixed(1)} / 100</div></div>
          <div><span className="text-muted">First seen</span><div>{formatDateTime(data.first_seen_at)}</div></div>
          <div><span className="text-muted">Last seen</span><div>{formatDateTime(data.last_seen_at)}</div></div>
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Remediation ownership</CardTitle></CardHeader>
        <CardBody className="space-y-4 text-sm">
          {!canRemediate || data.status === "closed" || data.status === "false_positive" ? (
            <dl className="grid gap-3 sm:grid-cols-2">
              <div><dt className="text-muted">Assignee</dt><dd>{selectedMember?.email ?? data.assignee_user_id ?? "Unassigned"}</dd></div>
              <div><dt className="text-muted">Due</dt><dd>{data.due_at ? formatDateTime(data.due_at) : "Not set"}</dd></div>
              <div className="sm:col-span-2"><dt className="text-muted">Plan</dt><dd className="whitespace-pre-wrap">{data.remediation_plan || "No plan recorded"}</dd></div>
            </dl>
          ) : (
            <form className="space-y-4" onSubmit={(event) => {
              event.preventDefault();
              if (workUpdate) void workMutation.run(workUpdate);
            }}>
              <Field label="Assignee" htmlFor="canonical-assignee">
                <Select id="canonical-assignee" value={assignee} onChange={(event) => setAssignee(event.target.value)}>
                  <option value="">Unassigned</option>
                  {assignee && !activeMembers.some((member) => member.user_id === assignee) && (
                    <option value={assignee}>Current assignee ({assignee})</option>
                  )}
                  {activeMembers.map((member) => <option key={member.user_id} value={member.user_id}>{member.full_name || member.email}</option>)}
                </Select>
              </Field>
              <Field label="Due date and time" htmlFor="canonical-due">
                <input id="canonical-due" type="datetime-local" value={dueLocal} onChange={(event) => setDueLocal(event.target.value)} className="w-full rounded-lg border border-line bg-surface px-3 py-2 text-fg" />
              </Field>
              <Field label="Remediation plan" htmlFor="canonical-plan">
                <Textarea id="canonical-plan" value={plan} maxLength={4000} onChange={(event) => setPlan(event.target.value)} placeholder="Describe the change, owner action, and evidence expected after the fix." />
              </Field>
              {members.error && <p className="text-muted">Member list unavailable: {members.error}</p>}
              {workMutation.errorMessage && <p role="alert" className="text-sm text-danger">{workMutation.errorMessage}</p>}
              <Button type="submit" disabled={!workUpdate} loading={workMutation.loading}>Save remediation work</Button>
            </form>
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Remediation tickets</CardTitle></CardHeader>
        <CardBody className="space-y-3 text-sm">
          {data.tickets.length === 0 ? <p className="text-muted">No ticket linked yet.</p> : (
            <ul className="space-y-2">{data.tickets.map((ticket) => {
              const url = safeExternalUrl(ticket.url);
              return <li key={ticket.id} className="rounded-lg border border-line p-3">
                {url ? <a href={url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{ticket.external_key} ↗</a> : ticket.external_key}
                <span className="ml-2 text-muted">{humanize(ticket.external_status || "linked")}</span>
              </li>;
            })}</ul>
          )}
          {canCreateCanonicalTicket(data.status, data.tickets, canTicket) && (
            <Button loading={ticketMutation.loading} onClick={() => void ticketMutation.run()}>
              Create Jira ticket
            </Button>
          )}
          {ticketMutation.errorMessage && <p role="alert" className="text-danger">{ticketMutation.errorMessage}</p>}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Custom fields</CardTitle></CardHeader>
        <CardBody className="space-y-3 text-sm">
          <pre className="whitespace-pre-wrap break-words text-xs text-muted">{JSON.stringify(data.custom_fields ?? {}, null, 2)}</pre>
          {canRemediate && data.status !== "closed" && data.status !== "false_positive" && (
            <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void customFieldsMutation.run(); }}>
              <Field label="Custom fields (JSON, non-sensitive metadata only)" htmlFor="finding-custom-fields">
                <Textarea id="finding-custom-fields" value={customFieldsText} onChange={(event) => setCustomFieldsText(event.target.value)} rows={4} />
              </Field>
              {customFieldsMutation.errorMessage && <p role="alert" className="text-danger">{customFieldsMutation.errorMessage}</p>}
              <Button type="submit" size="sm" loading={customFieldsMutation.loading}>Save custom fields</Button>
            </form>
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Risk calculation</CardTitle></CardHeader>
        <CardBody className="space-y-4 text-sm">
          <dl className="grid gap-3 sm:grid-cols-2">
            {Object.entries(data.risk_factors.components ?? {}).map(([name, points]) => (
              <div key={name} className="flex justify-between gap-3 border-b border-line pb-2">
                <dt className="text-muted">{humanize(name)}</dt>
                <dd className="tabular-nums">{points.toFixed(2)} pts</dd>
              </div>
            ))}
          </dl>
          {(data.risk_factors.unavailable ?? []).length > 0 && (
            <p className="text-muted">Not available: {data.risk_factors.unavailable?.map(humanize).join(", ")}. Missing intelligence is not treated as a confirmed negative.</p>
          )}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Source observations ({data.observations.length})</CardTitle></CardHeader>
        <CardBody>
          <Table>
            <THead><TR><TH>Provider</TH><TH>Source status</TH><TH>Source record</TH><TH>Last seen</TH></TR></THead>
            <TBody>{data.observations.map((item) => {
              const url = safeExternalUrl(item.source_url);
              return <TR key={item.id}>
                <TD>{humanize(item.provider)}</TD><TD>{humanize(item.source_status)}</TD>
                <TD>{url ? <a href={url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{item.external_id} ↗</a> : item.external_id}</TD>
                <TD>{formatDateTime(item.last_seen_at)}</TD>
              </TR>;
            })}</TBody>
          </Table>
        </CardBody>
      </Card>
      {canDecide && allowed.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Analyst decision</CardTitle></CardHeader>
          <CardBody>
            <form className="space-y-4" onSubmit={(event) => {
              event.preventDefault();
              if (decision && reason.trim()) void mutation.run(decision, reason.trim(), data.status_version);
            }}>
              <Field label="Decision" htmlFor="canonical-decision">
                <Select id="canonical-decision" value={decision} onChange={(event) => setDecision(event.target.value as typeof decision)}>
                  <option value="">Select a decision</option>
                  {allowed.map((option) => <option key={option} value={option}>{humanize(option)}</option>)}
                </Select>
              </Field>
              <Field label="Rationale" htmlFor="canonical-reason">
                <Textarea id="canonical-reason" value={reason} maxLength={2000} onChange={(event) => setReason(event.target.value)} />
              </Field>
              {mutation.errorMessage && <p role="alert" className="text-sm text-danger">{mutation.errorMessage}</p>}
              <Button type="submit" disabled={!decision || !reason.trim()} loading={mutation.loading}>Save decision</Button>
            </form>
          </CardBody>
        </Card>
      )}
      <Card>
        <CardHeader><CardTitle>Status history</CardTitle></CardHeader>
        <CardBody>
          {data.history.length === 0 ? <p className="text-sm text-muted">No status changes recorded.</p> : (
            <ol className="space-y-3 text-sm">{data.history.map((event) => (
              <li key={event.id} className="border-b border-line pb-3 last:border-0">
                <span className="font-medium">{humanize(event.new_status)}</span> · {formatDateTime(event.occurred_at)}
                <div className="text-muted">{event.reason}</div>
              </li>
            ))}</ol>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
