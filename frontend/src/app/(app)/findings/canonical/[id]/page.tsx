"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import { SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
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

const TICKET_PROVIDERS = ["jira", "github", "gitlab", "servicenow", "azure_devops", "linear"] as const;

function priorityReasons(factors: { inputs?: Record<string, unknown> }, riskScore: number): string[] {
  const inputs = factors.inputs ?? {};
  const reasons: string[] = [];
  if (riskScore >= 80) reasons.push(`Composite exposure score is ${riskScore.toFixed(1)} out of 100.`);
  if (inputs.in_kev === true) reasons.push("CISA KEV identifies this as known exploited.");
  else if (inputs.observed_in_the_wild === true) reasons.push("Exploitation has been observed in the wild.");
  else if (inputs.exploit_available === true) reasons.push("Public exploit evidence is available.");
  if (inputs.ransomware_use === true) reasons.push("Threat intelligence associates this issue with ransomware activity.");
  if (inputs.internet_exposed === true) reasons.push("The affected asset is internet exposed.");
  if (inputs.asset_criticality === "critical" || inputs.asset_criticality === "high") reasons.push("The affected asset has high business criticality.");
  const epss = inputs.epss_score;
  if (typeof epss === "number" && Number.isFinite(epss) && epss >= 0.5) reasons.push(`EPSS estimates a ${Math.round(epss * 100)}% exploitation probability.`);
  return reasons.slice(0, 4);
}

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
  const [decision, setDecision] = React.useState<"open" | "false_positive" | "">("");
  const [reason, setReason] = React.useState("");
  const [assignee, setAssignee] = React.useState("");
  const [dueLocal, setDueLocal] = React.useState("");
  const [plan, setPlan] = React.useState("");
  const [remediationGroup, setRemediationGroup] = React.useState("");
  const [customFieldsText, setCustomFieldsText] = React.useState("{}");
  const [commentBody, setCommentBody] = React.useState("");
  const [commentKind, setCommentKind] = React.useState<"note" | "evidence" | "remediation" | "retest" | "status_update">("note");
  const [evidenceReference, setEvidenceReference] = React.useState("");
  const [visibleToClient, setVisibleToClient] = React.useState(false);
  const [ticketProvider, setTicketProvider] = React.useState<(typeof TICKET_PROVIDERS)[number]>("jira");
  const [exceptionRationale, setExceptionRationale] = React.useState("");
  const [exceptionExpiry, setExceptionExpiry] = React.useState("");
  const [retestNote, setRetestNote] = React.useState("");
  const { data, error, loading, refetch } = useApiResource(
    () => api.canonicalFindings.get(id), [id], { enabled: canRead && !!id },
  );
  const members = useApiResource(
    () => api.organization.members({ limit: 100 }), [canRemediate],
    { enabled: canRemediate },
  );
  const comments = useApiResource(
    () => api.canonicalFindings.comments(id), [id], { enabled: canRead && !!id },
  );
  React.useEffect(() => {
    if (!data) return;
    setAssignee(data.assignee_user_id ?? "");
    setDueLocal(toLocalDateTimeInput(data.due_at));
    setPlan(data.remediation_plan ?? "");
    setRemediationGroup(data.remediation_group ?? "");
    setCustomFieldsText(JSON.stringify(data.custom_fields ?? {}, null, 2));
  }, [data]);
  const mutation = useMutation(
    (status: "open" | "false_positive", rationale: string, version: number) =>
      api.canonicalFindings.decide(id, { status, reason: rationale, expected_version: version }),
    { onSuccess: () => { setDecision(""); setReason(""); refetch(); toast({ title: "Finding decision saved", tone: "ok" }); } },
  );
  const workMutation = useMutation(
    (body: Parameters<typeof api.canonicalFindings.updateWork>[1]) =>
      api.canonicalFindings.updateWork(id, body),
    { onSuccess: () => { refetch(); toast({ title: "Remediation work saved", tone: "ok" }); } },
  );
  const ticketMutation = useMutation(
    (provider: (typeof TICKET_PROVIDERS)[number]) => api.canonicalFindings.createTicket(id, { provider }),
    { onSuccess: (ticket) => {
      refetch();
      toast({ title: `${humanize(ticket.provider)} ticket linked`, description: ticket.external_key, tone: "ok" });
    } },
  );
  const refreshTicketMutation = useMutation(
    (ticketId: string) => api.findings.refreshTicket(ticketId),
    { onSuccess: (ticket) => { void refetch(); toast({ title: `${humanize(ticket.provider)} ticket refreshed`, description: ticket.external_status ?? "Status unavailable", tone: "ok" }); } },
  );
  const ticketStateMutation = useMutation(
    (ticketId: string, closed: boolean) => api.findings.setTicketState(
      ticketId,
      closed,
      closed ? "Cynux marked the remediation ticket complete." : "Cynux reopened the remediation ticket.",
    ),
    { onSuccess: (ticket) => { void refetch(); toast({ title: `${humanize(ticket.provider)} ticket updated`, description: ticket.external_status ?? "Status unavailable", tone: "ok" }); } },
  );
  const customFieldsMutation = useMutation(
    () => api.canonicalFindings.updateWork(id, {
      expected_version: data!.status_version,
      custom_fields: parseCustomFields(customFieldsText),
    }),
    { onSuccess: () => { refetch(); toast({ title: "Finding custom fields saved", tone: "ok" }); } },
  );
  const commentMutation = useMutation(
    () => api.canonicalFindings.addComment(id, {
      body: commentBody,
      kind: commentKind,
      evidence_reference: evidenceReference.trim() || null,
      visible_to_client: visibleToClient,
    }),
    { onSuccess: () => {
      setCommentBody("");
      setEvidenceReference("");
      setCommentKind("note");
      setVisibleToClient(false);
      void comments.refetch();
      toast({ title: "Collaboration update added", tone: "ok" });
    } },
  );
  const riskAcceptanceMutation = useMutation(
    () => api.canonicalFindings.requestRiskAcceptance(id, {
      rationale: exceptionRationale.trim(),
      expires_at: new Date(exceptionExpiry).toISOString(),
    }),
    { onSuccess: () => {
      setExceptionRationale("");
      setExceptionExpiry("");
      toast({ title: "Risk acceptance submitted for independent approval", tone: "ok" });
    } },
  );
  const retestMutation = useMutation(
    () => api.canonicalFindings.requestRetest(id, { note: retestNote.trim() || null }),
    { onSuccess: () => {
      setRetestNote("");
      toast({ title: "Evidence-based retest requested", tone: "ok" });
    } },
  );
  if (!canRead) return <EmptyState title="No access" description="You don't have permission to view this." />;
  if (loading && !data) return <LoadingState label="Loading canonical finding…" />;
  if (error && !data) return <ErrorState message={error} onRetry={refetch} />;
  if (!data) return <EmptyState title="Finding not found" description="This finding may have been removed." />;

  const allowed = data.status === "new" || data.status === "reopened"
    ? (["open", "false_positive"] as const)
    : data.status === "open"
      ? (["false_positive"] as const)
      : data.status === "accepted_risk" || data.status === "false_positive"
        ? (["open"] as const)
        : ([] as const);
  const workUpdate = buildCanonicalWorkUpdate(data, { assignee, dueLocal, plan, remediationGroup });
  const riskReasons = priorityReasons(data.risk_factors, data.risk_score);
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
        <CardHeader><CardTitle>Field provenance</CardTitle></CardHeader>
        <CardBody className="space-y-3 text-sm">
          <p className="text-muted">Each canonical value shows the providers that support it. Conflicts remain visible instead of being discarded during normalization.</p>
          <Table>
            <THead><TR><TH>Field</TH><TH>Selected value</TH><TH>Sources</TH><TH>Confidence</TH></TR></THead>
            <TBody>{data.field_provenance.map((field) => <TR key={field.field}>
              <TD className="font-medium">{humanize(field.field)}</TD>
              <TD className="max-w-[320px] truncate" title={typeof field.value === "string" ? field.value : JSON.stringify(field.value)}>{typeof field.value === "string" ? field.value : JSON.stringify(field.value)}</TD>
              <TD>{field.sources.join(", ") || "No active source"}{field.conflicts ? <span className="ml-2 text-warn">Conflict</span> : null}</TD>
              <TD>{Math.round(field.confidence * 100)}%</TD>
            </TR>)}</TBody>
          </Table>
        </CardBody>
      </Card>
      <Card>
        <CardHeader><CardTitle>Remediation ownership</CardTitle></CardHeader>
        <CardBody className="space-y-4 text-sm">
          {!canRemediate || data.status === "closed" || data.status === "false_positive" ? (
            <dl className="grid gap-3 sm:grid-cols-2">
              <div><dt className="text-muted">Assignee</dt><dd>{selectedMember?.email ?? data.assignee_user_id ?? "Unassigned"}</dd></div>
              <div><dt className="text-muted">Due</dt><dd>{data.due_at ? formatDateTime(data.due_at) : "Not set"}</dd></div>
              <div><dt className="text-muted">Remediation group</dt><dd>{data.remediation_group || "Not grouped"}</dd></div>
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
              <Field label="Remediation group" htmlFor="canonical-remediation-group" hint="Use the same name for findings resolved by one patch, configuration change, or dependency upgrade.">
                <Input id="canonical-remediation-group" value={remediationGroup} maxLength={160} onChange={(event) => setRemediationGroup(event.target.value)} placeholder="Example: upgrade log4j to 2.17.1" />
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
                <div className="mt-2 flex flex-wrap gap-2"><Button size="sm" variant="outline" loading={refreshTicketMutation.loading} onClick={() => void refreshTicketMutation.run(ticket.id)}>Refresh tracker status</Button>{canRemediate && ticket.provider !== "linear" && <Button size="sm" variant="outline" loading={ticketStateMutation.loading} onClick={() => void ticketStateMutation.run(ticket.id, !["closed", "done", "resolved", "completed"].includes((ticket.external_status ?? "").toLowerCase()))}>{["closed", "done", "resolved", "completed"].includes((ticket.external_status ?? "").toLowerCase()) ? "Reopen provider ticket" : "Close provider ticket"}</Button>}</div>
              </li>;
            })}</ul>
          )}
          {canTicket && !["closed", "false_positive", "accepted_risk"].includes(data.status) && <div className="flex flex-wrap items-center gap-2"><Select aria-label="Ticket provider" value={ticketProvider} onChange={(event) => setTicketProvider(event.target.value as (typeof TICKET_PROVIDERS)[number])}>{TICKET_PROVIDERS.map((provider) => <option key={provider} value={provider}>{humanize(provider)}</option>)}</Select><Button loading={ticketMutation.loading} disabled={!canCreateCanonicalTicket(data.status, data.tickets, canTicket, ticketProvider)} onClick={() => void ticketMutation.run(ticketProvider)}>{canCreateCanonicalTicket(data.status, data.tickets, canTicket, ticketProvider) ? `Create ${humanize(ticketProvider)} ticket` : `${humanize(ticketProvider)} ticket already linked`}</Button></div>}
          {ticketMutation.errorMessage && <p role="alert" className="text-danger">{ticketMutation.errorMessage}</p>}
        </CardBody>
      </Card>
      {(canRemediate || canDecide) && !["closed", "false_positive"].includes(data.status) && (
        <Card>
          <CardHeader><CardTitle>Exception and verification</CardTitle></CardHeader>
          <CardBody className="grid gap-6 lg:grid-cols-2">
            {canRemediate && (
              <form className="space-y-3" onSubmit={(event) => {
                event.preventDefault();
                if (exceptionRationale.trim() && exceptionExpiry) void riskAcceptanceMutation.run();
              }}>
                <div><h4 className="font-medium text-fg">Request time-bound risk acceptance</h4><p className="mt-1 text-sm text-muted">A separate authorized reviewer must approve it before the exception becomes active.</p></div>
                <Field label="Business rationale" htmlFor="exception-rationale"><Textarea id="exception-rationale" value={exceptionRationale} maxLength={2000} onChange={(event) => setExceptionRationale(event.target.value)} placeholder="Explain the business reason, compensating controls, and planned review." /></Field>
                <Field label="Exception expiry" htmlFor="exception-expiry"><Input id="exception-expiry" type="datetime-local" value={exceptionExpiry} onChange={(event) => setExceptionExpiry(event.target.value)} /></Field>
                {riskAcceptanceMutation.errorMessage && <p role="alert" className="text-sm text-danger">{riskAcceptanceMutation.errorMessage}</p>}
                <Button type="submit" loading={riskAcceptanceMutation.loading} disabled={!exceptionRationale.trim() || !exceptionExpiry}>Request approval</Button>
              </form>
            )}
            {canDecide && (
              <form className="space-y-3" onSubmit={(event) => {
                event.preventDefault();
                void retestMutation.run();
              }}>
                <div><h4 className="font-medium text-fg">Request remediation retest</h4><p className="mt-1 text-sm text-muted">The result stays linked to the assessment evidence and can close the finding only when the rescan verifies absence.</p></div>
                <Field label="Verification note (optional)" htmlFor="retest-note"><Textarea id="retest-note" value={retestNote} maxLength={2000} onChange={(event) => setRetestNote(event.target.value)} placeholder="State the expected fix and verification scope." /></Field>
                {retestMutation.errorMessage && <p role="alert" className="text-sm text-danger">{retestMutation.errorMessage}</p>}
                <Button type="submit" loading={retestMutation.loading}>Request retest</Button>
              </form>
            )}
          </CardBody>
        </Card>
      )}
      <Card>
        <CardHeader><CardTitle>Engagement collaboration</CardTitle></CardHeader>
        <CardBody className="space-y-4 text-sm">
          <p className="text-muted">Keep tester evidence, remediation updates, and retest context with the unified finding. Internal notes remain private unless explicitly marked for the client portal.</p>
          {comments.loading && !comments.data ? <LoadingState label="Loading collaboration…" /> : comments.error ? (
            <ErrorState message={comments.error} onRetry={comments.refetch} />
          ) : comments.data?.length ? (
            <ol className="space-y-3">
              {comments.data.map((comment) => {
                const evidenceUrl = safeExternalUrl(comment.evidence_reference);
                return <li key={comment.id} className="rounded-lg border border-line p-3">
                  <div className="flex flex-wrap items-center gap-x-2 text-xs text-muted">
                    <span className="font-medium text-fg">{humanize(comment.kind)}</span>
                    <span>{formatDateTime(comment.created_at)}</span>
                    <span>{comment.visible_to_client ? "Client-visible" : "Internal"}</span>
                  </div>
                  <p className="mt-2 whitespace-pre-wrap">{comment.body}</p>
                  {comment.evidence_reference && <div className="mt-2 text-xs">
                    {evidenceUrl ? <a href={evidenceUrl} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Open evidence reference ↗</a> : <span className="text-muted">Evidence: {comment.evidence_reference}</span>}
                  </div>}
                </li>;
              })}
            </ol>
          ) : <p className="text-muted">No collaboration updates yet.</p>}
          {canRemediate && (
            <form className="space-y-3 border-t border-line pt-4" onSubmit={(event) => {
              event.preventDefault();
              if (commentBody.trim()) void commentMutation.run();
            }}>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Update type" htmlFor="collaboration-kind">
                  <Select id="collaboration-kind" value={commentKind} onChange={(event) => setCommentKind(event.target.value as typeof commentKind)}>
                    <option value="note">Note</option><option value="evidence">Evidence</option><option value="remediation">Remediation</option><option value="retest">Retest</option><option value="status_update">Status update</option>
                  </Select>
                </Field>
                <Field label="Evidence reference (optional)" htmlFor="collaboration-evidence">
                  <input id="collaboration-evidence" value={evidenceReference} maxLength={2048} onChange={(event) => setEvidenceReference(event.target.value)} className="w-full rounded-lg border border-line bg-surface px-3 py-2 text-fg" placeholder="https://… or evidence ID" />
                </Field>
              </div>
              <Field label="Collaboration update" htmlFor="collaboration-body">
                <Textarea id="collaboration-body" value={commentBody} maxLength={4000} onChange={(event) => setCommentBody(event.target.value)} placeholder="Record the test result, fix status, or next action." />
              </Field>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={visibleToClient} onChange={(event) => setVisibleToClient(event.target.checked)} /> Mark this update client-visible</label>
              {commentMutation.errorMessage && <p role="alert" className="text-danger">{commentMutation.errorMessage}</p>}
              <Button type="submit" loading={commentMutation.loading} disabled={!commentBody.trim()}>Add update</Button>
            </form>
          )}
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
          {riskReasons.length > 0 && <div className="rounded-lg border border-primary/25 bg-primary/5 p-3"><p className="text-xs font-semibold uppercase tracking-wide text-primary">Why prioritize this</p><ul className="mt-2 space-y-1 text-sm text-fg">{riskReasons.map((item) => <li key={item}>• {item}</li>)}</ul></div>}
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
              const sourceRecord = item.source_record_id
                ? <Link href={`/findings/external/${item.source_record_id}`} className="text-primary hover:underline">Open synchronized alert</Link>
                : url
                  ? <a href={url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">{item.external_id} ↗</a>
                  : item.external_id;
              return <TR key={item.id}>
                <TD>{humanize(item.provider)}</TD><TD>{humanize(item.source_status)}</TD>
                <TD>{sourceRecord}</TD>
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
