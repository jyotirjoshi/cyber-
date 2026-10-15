"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, humanize } from "@/lib/format";
import type { AutomationExecutionOut, AutomationRuleCreateIn, AutomationRuleOut, AutomationTrigger, MemberOut } from "@/lib/types";

const PAGE_SIZE = 25;

const TRIGGERS: AutomationTrigger[] = [
  "finding.created",
  "finding.updated",
  "ticket.closed",
  "retest.confirmed",
  "retest.cleared",
  "sla.breached",
];
const TICKET_PROVIDERS = ["jira", "github", "gitlab", "servicenow", "azure_devops", "linear"] as const;
const ACTIONS = ["create_ticket", "assign_owner", "assign_codeowner", "set_remediation_group", "refresh_intelligence", "notify", "request_retest", "schedule_retest"] as const;
const SEVERITIES = ["", "critical", "high", "medium", "low", "info"] as const;
const ENVIRONMENTS = ["", "production", "staging", "development", "test", "unknown"] as const;
const CRITICALITIES = ["", "critical", "high", "normal", "low"] as const;
const EXECUTION_TONE: Record<AutomationExecutionOut["status"], "ok" | "warn" | "danger" | "neutral" | "primary"> = {
  pending: "primary",
  skipped: "neutral",
  dry_run: "warn",
  executed: "ok",
  failed: "danger",
};

const BLANK: AutomationRuleCreateIn = {
  name: "",
  trigger: "finding.created",
  conditions: {},
  actions: [],
  is_enabled: true,
  dry_run: false,
};

export default function AutomationPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("org:manage");

  const [offset, setOffset] = React.useState(0);
  const [showCreate, setShowCreate] = React.useState(false);
  const [form, setForm] = React.useState<AutomationRuleCreateIn>(BLANK);
  const [actionsText, setActionsText] = React.useState("[]");
  const [conditionsText, setConditionsText] = React.useState("{}");
  const [advancedMode, setAdvancedMode] = React.useState(false);
  const [minimumSeverity, setMinimumSeverity] = React.useState<(typeof SEVERITIES)[number]>("");
  const [kevOnly, setKevOnly] = React.useState(false);
  const [internetExposedOnly, setInternetExposedOnly] = React.useState(false);
  const [minimumRiskScore, setMinimumRiskScore] = React.useState("");
  const [assetGroup, setAssetGroup] = React.useState("");
  const [assetEnvironment, setAssetEnvironment] = React.useState<(typeof ENVIRONMENTS)[number]>("");
  const [minimumAssetCriticality, setMinimumAssetCriticality] = React.useState<(typeof CRITICALITIES)[number]>("");
  const [actionType, setActionType] = React.useState<(typeof ACTIONS)[number]>("create_ticket");
  const [ticketProvider, setTicketProvider] = React.useState<(typeof TICKET_PROVIDERS)[number]>("jira");
  const [notificationChannels, setNotificationChannels] = React.useState<string[]>(["email"]);
  const [authorizationReference, setAuthorizationReference] = React.useState("");
  const [assigneeUserId, setAssigneeUserId] = React.useState("");
  const [remediationGroup, setRemediationGroup] = React.useState("");
  const [scheduleEnabled, setScheduleEnabled] = React.useState(false);
  const [scheduleCron, setScheduleCron] = React.useState("0 9 * * 1");
  const [scheduleTimezone, setScheduleTimezone] = React.useState("UTC");
  const [selectedRule, setSelectedRule] = React.useState<AutomationRuleOut | null>(null);
  const [editingRuleId, setEditingRuleId] = React.useState<string | null>(null);

  const { data, error, loading, refetch } = useApiResource(
    () => api.automation.listRules({ limit: PAGE_SIZE, offset }),
    [offset],
  );
  const executions = useApiResource(
    () => api.automation.executions(selectedRule?.id ?? "", { limit: PAGE_SIZE, offset: 0 }),
    [selectedRule?.id],
    { enabled: selectedRule !== null },
  );
  const members = useApiResource(
    () => api.organization.members({ limit: 100, offset: 0 }),
    [],
    { enabled: canManage },
  );

  const createMut = useMutation(
    (body: AutomationRuleCreateIn) => api.automation.createRule(body),
    {
      onSuccess: () => {
        toast({ title: "Automation rule created", tone: "ok" });
        setShowCreate(false);
        setForm(BLANK);
        setActionsText("[]");
        setConditionsText("{}");
        setAdvancedMode(false);
        setMinimumSeverity("");
        setKevOnly(false);
        setInternetExposedOnly(false);
        setMinimumRiskScore("");
        setAssetGroup("");
        setAssetEnvironment("");
        setMinimumAssetCriticality("");
        setActionType("create_ticket");
        setTicketProvider("jira");
        setNotificationChannels(["email"]);
        setAuthorizationReference("");
        setAssigneeUserId("");
        setRemediationGroup("");
        setScheduleEnabled(false);
        setScheduleCron("0 9 * * 1");
        setScheduleTimezone("UTC");
        void refetch();
      },
    },
  );
  const updateMut = useMutation(
    ({ id, body }: { id: string; body: AutomationRuleCreateIn }) => api.automation.updateRule(id, body),
    {
      onSuccess: () => {
        toast({ title: "Automation rule updated", tone: "ok" });
        setShowCreate(false);
        setEditingRuleId(null);
        void refetch();
      },
    },
  );

  const deleteMut = useMutation(
    (id: string) => api.automation.deleteRule(id),
    {
      onSuccess: () => {
        toast({ title: "Rule deleted", tone: "ok" });
        void refetch();
      },
    },
  );

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!advancedMode) {
      if (actionType === "schedule_retest" && form.trigger !== "ticket.closed") {
        toast({ title: "Automatic retest scheduling requires the Ticket closed trigger", tone: "danger" });
        return;
      }
      if (actionType === "schedule_retest" && !authorizationReference.trim()) {
        toast({ title: "Provide the authorization reference for the scheduled retest", tone: "danger" });
        return;
      }
      if (actionType === "assign_owner" && !assigneeUserId) {
        toast({ title: "Select an owner for the assignment rule", tone: "danger" });
        return;
      }
      if (actionType === "set_remediation_group" && !remediationGroup.trim()) {
        toast({ title: "Provide a remediation group for the campaign", tone: "danger" });
        return;
      }
      if (scheduleEnabled && actionType !== "notify") {
        toast({ title: "Scheduled rules currently support notification actions only", tone: "danger" });
        return;
      }
      if (scheduleEnabled && !scheduleCron.trim()) {
        toast({ title: "Enter a cron schedule for the recurring reminder", tone: "danger" });
        return;
      }
      if (minimumRiskScore.trim() && (
        !Number.isFinite(Number(minimumRiskScore))
        || Number(minimumRiskScore) < 0
        || Number(minimumRiskScore) > 100
      )) {
        toast({ title: "Minimum risk score must be between 0 and 100", tone: "danger" });
        return;
      }
      const conditions: Record<string, unknown> = {
        ...(minimumSeverity ? { severity_at_least: minimumSeverity } : {}),
        ...(kevOnly ? { in_kev: true } : {}),
        ...(internetExposedOnly ? { internet_exposed: true } : {}),
        ...(minimumRiskScore.trim() ? { risk_score_at_least: Number(minimumRiskScore) } : {}),
        ...(assetGroup.trim() ? { asset_group: assetGroup.trim() } : {}),
        ...(assetEnvironment ? { asset_environment: assetEnvironment } : {}),
        ...(minimumAssetCriticality ? { asset_criticality_at_least: minimumAssetCriticality } : {}),
      };
      const action = actionType === "create_ticket"
        ? { type: actionType, provider: ticketProvider }
        : actionType === "notify"
          ? (notificationChannels.length ? { type: actionType, channels: notificationChannels } : { type: actionType })
          : actionType === "assign_owner"
            ? { type: actionType, assignee_user_id: assigneeUserId }
          : actionType === "set_remediation_group"
            ? { type: actionType, remediation_group: remediationGroup.trim() }
          : actionType === "schedule_retest"
            ? { type: actionType, authorization_reference: authorizationReference.trim() }
            : { type: actionType };
      const body = {
        ...form,
        actions: [action],
        conditions,
        cron_expression: scheduleEnabled ? scheduleCron.trim() : null,
        timezone: scheduleTimezone.trim() || "UTC",
      };
      if (editingRuleId) void updateMut.run({ id: editingRuleId, body });
      else void createMut.run(body);
      return;
    }
    let actions: unknown[] = [];
    let conditions: Record<string, unknown> = {};
    try { actions = JSON.parse(actionsText); } catch { toast({ title: "Actions JSON is invalid", tone: "danger" }); return; }
    try { conditions = JSON.parse(conditionsText); } catch { toast({ title: "Conditions JSON is invalid", tone: "danger" }); return; }
    const body = { ...form, actions: actions as AutomationRuleCreateIn["actions"], conditions };
    if (editingRuleId) void updateMut.run({ id: editingRuleId, body });
    else void createMut.run(body);
  }

  function startEdit(rule: AutomationRuleOut) {
    setEditingRuleId(rule.id);
    setForm({
      name: rule.name,
      trigger: rule.trigger,
      conditions: rule.conditions,
      actions: rule.actions,
      cron_expression: rule.cron_expression,
      timezone: rule.timezone,
      is_enabled: rule.is_enabled,
      dry_run: rule.dry_run,
    });
    setConditionsText(JSON.stringify(rule.conditions, null, 2));
    setActionsText(JSON.stringify(rule.actions, null, 2));
    const action = rule.actions.length === 1 ? rule.actions[0] : null;
    const type = typeof action?.type === "string" && ACTIONS.includes(action.type as (typeof ACTIONS)[number])
      ? action.type as (typeof ACTIONS)[number]
      : null;
    const simpleConditionKeys = ["severity_at_least", "in_kev", "asset_group", "asset_environment", "asset_criticality_at_least", "internet_exposed", "risk_score_at_least"];
    const simpleConditions = Object.keys(rule.conditions).every((key) => simpleConditionKeys.includes(key));
    const simpleAction = type !== null && action !== null;
    setAdvancedMode(!(simpleConditions && simpleAction));
    if (simpleConditions && type && action) {
      setMinimumSeverity(typeof rule.conditions.severity_at_least === "string" ? rule.conditions.severity_at_least as typeof minimumSeverity : "");
      setKevOnly(rule.conditions.in_kev === true);
      setInternetExposedOnly(rule.conditions.internet_exposed === true);
      setMinimumRiskScore(typeof rule.conditions.risk_score_at_least === "number" ? String(rule.conditions.risk_score_at_least) : "");
      setAssetGroup(typeof rule.conditions.asset_group === "string" ? rule.conditions.asset_group : "");
      setAssetEnvironment(typeof rule.conditions.asset_environment === "string" ? rule.conditions.asset_environment as typeof assetEnvironment : "");
      setMinimumAssetCriticality(typeof rule.conditions.asset_criticality_at_least === "string" ? rule.conditions.asset_criticality_at_least as typeof minimumAssetCriticality : "");
      setActionType(type);
      setTicketProvider(type === "create_ticket" && typeof action.provider === "string" && TICKET_PROVIDERS.includes(action.provider as (typeof TICKET_PROVIDERS)[number]) ? action.provider as typeof ticketProvider : "jira");
      setNotificationChannels(type === "notify" && Array.isArray(action.channels) ? action.channels.filter((channel): channel is string => typeof channel === "string") : ["email"]);
      setAssigneeUserId(type === "assign_owner" && typeof action.assignee_user_id === "string" ? action.assignee_user_id : "");
      setRemediationGroup(type === "set_remediation_group" && typeof action.remediation_group === "string" ? action.remediation_group : "");
      setAuthorizationReference(type === "schedule_retest" && typeof action.authorization_reference === "string" ? action.authorization_reference : "");
    }
    setScheduleEnabled(!!rule.cron_expression);
    setScheduleCron(rule.cron_expression ?? "0 9 * * 1");
    setScheduleTimezone(rule.timezone || "UTC");
    setShowCreate(true);
  }

  function beginCreate() {
    setEditingRuleId(null);
    setForm(BLANK);
    setActionsText("[]");
    setConditionsText("{}");
    setAdvancedMode(false);
    setMinimumSeverity("");
    setKevOnly(false);
    setInternetExposedOnly(false);
    setMinimumRiskScore("");
    setAssetGroup("");
    setAssetEnvironment("");
    setMinimumAssetCriticality("");
    setActionType("create_ticket");
    setTicketProvider("jira");
    setNotificationChannels(["email"]);
    setAuthorizationReference("");
    setAssigneeUserId("");
    setRemediationGroup("");
    setScheduleEnabled(false);
    setScheduleCron("0 9 * * 1");
    setScheduleTimezone("UTC");
    setShowCreate(true);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Automation"
        description="Event-driven remediation rules and scheduled operational reminders."
        action={
          canManage && (
            <Button onClick={beginCreate}>New rule</Button>
          )
        }
      />

      {loading && !data ? (
        <LoadingState label="Loading rules…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No automation rules"
          description="Create a rule to automatically enrich, ticket, or notify on findings."
          action={canManage ? <Button onClick={beginCreate}>New rule</Button> : undefined}
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Trigger</TH>
                <TH>Actions</TH>
                <TH>Status</TH>
                <TH>Next run</TH>
                <TH className="w-28" />
              </TR>
            </THead>
            <TBody>
              {data.items.map((rule: AutomationRuleOut) => (
                <TR key={rule.id}>
                  <TD className="font-medium text-fg">{rule.name}</TD>
                  <TD><span className="font-mono text-xs text-muted">{rule.trigger}</span></TD>
                  <TD><span className="text-muted">{rule.actions.length} action{rule.actions.length !== 1 ? "s" : ""}</span></TD>
                  <TD>
                    <div className="flex gap-1.5">
                      <Badge tone={rule.is_enabled ? "ok" : "neutral"}>{rule.is_enabled ? "Enabled" : "Disabled"}</Badge>
                      {rule.dry_run && <Badge tone="warn">Dry run</Badge>}
                    </div>
                  </TD>
                  <TD className="text-muted">{rule.next_run_at ? formatDateTime(rule.next_run_at) : rule.cron_expression ?? "Event-driven"}</TD>
                  <TD>
                    <button
                      type="button"
                      className="mr-3 text-xs text-primary hover:underline"
                      onClick={() => setSelectedRule(rule)}
                    >
                      Activity
                    </button>
                    {canManage && <button type="button" className="mr-3 text-xs text-primary hover:underline" onClick={() => startEdit(rule)}>Edit</button>}
                    {canManage && <button
                        type="button"
                        className="text-xs text-danger hover:underline"
                        onClick={() => void deleteMut.run(rule.id)}
                      >
                        Delete
                    </button>}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
          {selectedRule && <Card>
            <CardHeader><div className="flex items-center justify-between gap-3"><CardTitle>Execution activity · {selectedRule.name}</CardTitle><Button size="sm" variant="ghost" onClick={() => setSelectedRule(null)}>Close</Button></div></CardHeader>
            <CardBody>
              {executions.loading && !executions.data ? <LoadingState label="Loading rule activity…" /> : executions.error ? <ErrorState message={executions.error} onRetry={executions.refetch} /> : !executions.data?.items.length ? <p className="text-sm text-muted">This rule has not matched an event yet.</p> : <Table><THead><TR><TH>When</TH><TH>Status</TH><TH>Finding</TH><TH>Event</TH><TH>Retry</TH><TH>Outcome</TH></TR></THead><TBody>{executions.data.items.map((execution) => <TR key={execution.id}><TD className="text-muted">{formatDateTime(execution.created_at)}</TD><TD><Badge tone={EXECUTION_TONE[execution.status]}>{humanize(execution.status)}</Badge></TD><TD className="font-mono text-xs text-muted">{execution.canonical_finding_id ? execution.canonical_finding_id.slice(0, 8) : "Scheduled"}</TD><TD className="font-mono text-xs text-muted">{execution.event_key}</TD><TD className="text-xs text-muted">{execution.next_retry_at ? <span>Attempt {execution.attempts} · {formatDateTime(execution.next_retry_at)}</span> : execution.attempts ? <span>{execution.attempts} attempt{execution.attempts === 1 ? "" : "s"}</span> : "—"}</TD><TD className="max-w-[28rem]"><code className="block max-h-20 overflow-auto whitespace-pre-wrap break-words text-xs text-muted">{JSON.stringify(execution.result)}</code></TD></TR>)}</TBody></Table>}
            </CardBody>
          </Card>}
        </div>
      )}

      {showCreate && (
        <Modal title={editingRuleId ? "Edit automation rule" : "New automation rule"} onClose={() => { setShowCreate(false); setEditingRuleId(null); }}>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Field label="Name" htmlFor="ar-name">
              <Input id="ar-name" required maxLength={160} value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
            </Field>
            <Field label="Trigger" htmlFor="ar-trigger">
              <Select id="ar-trigger" value={form.trigger}
                onChange={(e) => setForm((f) => ({ ...f, trigger: e.target.value as AutomationTrigger }))}>
                {TRIGGERS.map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
              </Select>
            </Field>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={advancedMode} onChange={(event) => setAdvancedMode(event.target.checked)} /> Advanced JSON builder</label>
            {advancedMode ? <>
              <Field label="Conditions (JSON)" htmlFor="ar-cond">
                <Textarea id="ar-cond" rows={3} value={conditionsText}
                  onChange={(e) => setConditionsText(e.target.value)}
                  placeholder='{"severity_at_least":"high","in_kev":true}' />
              </Field>
              <Field label="Actions (JSON array)" htmlFor="ar-actions">
                <Textarea id="ar-actions" rows={4} value={actionsText}
                  onChange={(e) => setActionsText(e.target.value)}
                  placeholder='[{"type":"create_ticket","provider":"jira"}]' />
              </Field>
            </> : <>
              <div className="grid gap-3 sm:grid-cols-4">
                <Field label="Minimum severity" htmlFor="ar-severity"><Select id="ar-severity" value={minimumSeverity} onChange={(event) => setMinimumSeverity(event.target.value as typeof minimumSeverity)}>{SEVERITIES.map((severity) => <option key={severity || "all"} value={severity}>{severity ? humanize(severity) : "Any severity"}</option>)}</Select></Field>
                <label className="flex items-center gap-2 self-end pb-2 text-sm"><input type="checkbox" checked={kevOnly} onChange={(event) => setKevOnly(event.target.checked)} /> Known exploited vulnerabilities only</label>
                <Field label="Asset environment" htmlFor="ar-environment"><Select id="ar-environment" value={assetEnvironment} onChange={(event) => setAssetEnvironment(event.target.value as typeof assetEnvironment)}>{ENVIRONMENTS.map((environment) => <option key={environment || "all"} value={environment}>{environment ? humanize(environment) : "Any environment"}</option>)}</Select></Field>
                <Field label="Minimum asset criticality" htmlFor="ar-criticality"><Select id="ar-criticality" value={minimumAssetCriticality} onChange={(event) => setMinimumAssetCriticality(event.target.value as typeof minimumAssetCriticality)}>{CRITICALITIES.map((criticality) => <option key={criticality || "all"} value={criticality}>{criticality ? humanize(criticality) : "Any criticality"}</option>)}</Select></Field>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Minimum risk score" htmlFor="ar-risk-score" hint="Use the 0–100 composite exposure score."><Input id="ar-risk-score" type="number" min="0" max="100" step="0.1" value={minimumRiskScore} onChange={(event) => setMinimumRiskScore(event.target.value)} placeholder="e.g. 80" /></Field>
                <label className="flex items-center gap-2 self-end pb-2 text-sm"><input type="checkbox" checked={internetExposedOnly} onChange={(event) => setInternetExposedOnly(event.target.checked)} /> Internet-exposed assets only</label>
              </div>
              <Field label="Asset group (optional)" htmlFor="ar-asset-group" hint="Match assets tagged to this business service or product group."><Input id="ar-asset-group" maxLength={120} value={assetGroup} onChange={(event) => setAssetGroup(event.target.value)} placeholder="Payments, Customer API…" /></Field>
              <Field label="Then" htmlFor="ar-action"><Select id="ar-action" value={actionType} onChange={(event) => { const next = event.target.value as typeof actionType; setActionType(next); if (next !== "notify") setScheduleEnabled(false); }}>{ACTIONS.map((action) => <option key={action} value={action}>{humanize(action)}</option>)}</Select></Field>
              {actionType === "create_ticket" && <Field label="Ticket system" htmlFor="ar-ticket-provider"><Select id="ar-ticket-provider" value={ticketProvider} onChange={(event) => setTicketProvider(event.target.value as typeof ticketProvider)}>{TICKET_PROVIDERS.map((provider) => <option key={provider} value={provider}>{humanize(provider)}</option>)}</Select></Field>}
              {actionType === "assign_owner" && <Field label="Assign to" htmlFor="ar-owner"><Select id="ar-owner" value={assigneeUserId} onChange={(event) => setAssigneeUserId(event.target.value)}><option value="">Select an active member…</option>{(members.data?.items ?? []).filter((member: MemberOut) => member.is_active).map((member: MemberOut) => <option key={member.user_id} value={member.user_id}>{member.full_name || member.email} · {humanize(member.role)}</option>)}</Select>{members.error && <p className="mt-1 text-xs text-danger">Unable to load organization members.</p>}</Field>}
              {actionType === "set_remediation_group" && <Field label="Remediation group" htmlFor="ar-remediation-group" hint="Use one shared patch, upgrade, or control-change campaign name."><Input id="ar-remediation-group" required maxLength={160} value={remediationGroup} onChange={(event) => setRemediationGroup(event.target.value)} placeholder="Upgrade log4j to 2.17.1" /></Field>}
              {actionType === "notify" && <fieldset><legend className="mb-1.5 text-xs font-medium text-muted">Notification channels</legend><div className="flex flex-wrap gap-3 text-sm">{["email", "slack", "pagerduty", "splunk"].map((channel) => <label key={channel} className="flex items-center gap-2"><input type="checkbox" checked={notificationChannels.includes(channel)} onChange={(event) => setNotificationChannels((current) => event.target.checked ? [...current, channel] : current.filter((item) => item !== channel))} /> {humanize(channel)}</label>)}</div></fieldset>}
              {actionType === "schedule_retest" && <Field label="Authorization reference" htmlFor="ar-auth-reference" hint="The referenced authorization is carried into the approval-gated retest assessment."><Input id="ar-auth-reference" value={authorizationReference} maxLength={1024} onChange={(event) => setAuthorizationReference(event.target.value)} placeholder="Change reference, approval ticket, or signed scope" /></Field>}
              <fieldset className="rounded-lg border border-line p-3"><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={scheduleEnabled} disabled={actionType !== "notify"} onChange={(event) => setScheduleEnabled(event.target.checked)} /> Send this notification on a recurring schedule</label>{actionType !== "notify" && <p className="mt-1 text-xs text-muted">Recurring automation currently sends operational notifications; finding actions use their event trigger.</p>}{scheduleEnabled && <div className="mt-3 grid gap-3 sm:grid-cols-2"><Field label="Cron schedule" htmlFor="ar-cron" hint="UTC by default; example: 0 9 * * 1"><Input id="ar-cron" required maxLength={120} value={scheduleCron} onChange={(event) => setScheduleCron(event.target.value)} /></Field><Field label="Timezone" htmlFor="ar-timezone"><Input id="ar-timezone" required maxLength={100} value={scheduleTimezone} onChange={(event) => setScheduleTimezone(event.target.value)} placeholder="UTC" /></Field></div>}</fieldset>
            </>}
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.dry_run}
                  onChange={(e) => setForm((f) => ({ ...f, dry_run: e.target.checked }))} />
                Dry run (log only, no actions taken)
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.is_enabled}
                  onChange={(e) => setForm((f) => ({ ...f, is_enabled: e.target.checked }))} />
                Enabled
              </label>
            </div>
            {createMut.errorMessage && <p role="alert" className="text-sm text-danger">{createMut.errorMessage}</p>}
            <div className="flex justify-end gap-3">
              <Button type="button" variant="ghost" onClick={() => { setShowCreate(false); setEditingRuleId(null); }}>Cancel</Button>
              <Button type="submit" loading={createMut.loading || updateMut.loading}>{editingRuleId ? "Save rule" : "Create rule"}</Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
