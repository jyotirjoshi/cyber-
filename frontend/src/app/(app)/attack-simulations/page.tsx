"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Textarea } from "@/components/ui/Input";
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
import type { AttackSimulationCampaignCreateIn, AttackSimulationCampaignOut, AttackSimulationRunDetailOut, AttackSimulationStatus } from "@/lib/types";

const PAGE_SIZE = 25;

const STATUS_TONE: Record<AttackSimulationStatus, "ok" | "warn" | "danger" | "neutral" | "primary"> = {
  draft: "neutral",
  active: "primary",
  paused: "warn",
  completed: "ok",
  failed: "danger",
};

const BLANK: AttackSimulationCampaignCreateIn = {
  name: "",
  authorization_text: "",
  authorization_reference: "",
  authorization_expires_at: "",
  scenarios: [],
  targets: [],
};

export default function AttackSimulationsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("assessment:create");
  const canApprove = can("assessment:approve");

  const [offset, setOffset] = React.useState(0);
  const [showCreate, setShowCreate] = React.useState(false);
  const [form, setForm] = React.useState<AttackSimulationCampaignCreateIn>(BLANK);
  const [targetsText, setTargetsText] = React.useState("");
  const [selectedCampaign, setSelectedCampaign] = React.useState<AttackSimulationCampaignOut | null>(null);
  const [selectedRun, setSelectedRun] = React.useState<AttackSimulationRunDetailOut | null>(null);

  const { data, error, loading, refetch } = useApiResource(
    () => api.attackSimulations.list({ limit: PAGE_SIZE, offset }),
    [offset],
  );
  const catalog = useApiResource(() => api.attackSimulations.catalog(), [], { enabled: showCreate });
  const runs = useApiResource(
    () => api.attackSimulations.runs(selectedCampaign!.id),
    [selectedCampaign?.id],
    { enabled: Boolean(selectedCampaign), refetchInterval: selectedCampaign ? 5000 : undefined },
  );
  const runDetailMut = useMutation((id: string) => api.attackSimulations.runDetail(id), {
    onSuccess: setSelectedRun,
  });

  const createMut = useMutation(
    (body: AttackSimulationCampaignCreateIn) => api.attackSimulations.create(body),
    {
      onSuccess: () => {
        toast({ title: "Campaign created", tone: "ok" });
        setShowCreate(false);
        setForm(BLANK);
        setTargetsText("");
        void refetch();
      },
    },
  );

  const runMut = useMutation(
    (id: string) => api.attackSimulations.run(id),
    { onSuccess: () => { toast({ title: "Campaign run triggered", tone: "ok" }); void refetch(); } },
  );

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const targets = targetsText.split("\n").map((s) => s.trim()).filter(Boolean);
    if (!form.scenarios.length) { toast({ title: "At least one scenario required", tone: "danger" }); return; }
    if (!targets.length) { toast({ title: "At least one target required", tone: "danger" }); return; }
    void createMut.run({ ...form, targets });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack simulation"
        description="Scheduled breach and attack simulation campaigns against authorized targets."
        action={
          canManage && (
            <Button onClick={() => setShowCreate(true)}>New campaign</Button>
          )
        }
      />

      <Card>
        <CardBody className="text-sm text-muted space-y-1">
          <p>All campaigns require explicit written authorization with an expiry date. Simulations only run against verified in-scope targets and are gated on human approval before each execution.</p>
        </CardBody>
      </Card>

      {loading && !data ? (
        <LoadingState label="Loading campaigns…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No campaigns"
          description="Create a campaign to run scheduled breach and attack simulation tests."
          action={canManage ? <Button onClick={() => setShowCreate(true)}>New campaign</Button> : undefined}
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Status</TH>
                <TH>Scenarios</TH>
                <TH>Targets</TH>
                <TH>Next run</TH>
                <TH>Last run</TH>
                <TH className="w-40" />
              </TR>
            </THead>
            <TBody>
              {data.items.map((c: AttackSimulationCampaignOut) => (
                <TR key={c.id}>
                  <TD className="font-medium text-fg">{c.name}</TD>
                  <TD><Badge tone={STATUS_TONE[c.status]}>{humanize(c.status)}</Badge></TD>
                  <TD className="text-muted">{c.scenarios.length}</TD>
                  <TD className="text-muted">{c.targets.length}</TD>
                  <TD className="text-muted">{c.next_run_at ? formatDateTime(c.next_run_at) : c.cron_expression ?? "Manual"}</TD>
                  <TD className="text-muted">{c.last_run_at ? formatDateTime(c.last_run_at) : "Never"}</TD>
                  <TD>
                    <div className="flex gap-1">
                      <Button size="sm" variant="ghost" onClick={() => setSelectedCampaign(c)}>Evidence</Button>
                      {canApprove && c.status === "active" && (
                        <Button size="sm" variant="ghost" onClick={() => void runMut.run(c.id)}>Run now</Button>
                      )}
                    </div>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </div>
      )}

      {showCreate && (
        <Modal title="New attack simulation campaign" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Field label="Name" htmlFor="asc-name">
              <Input id="asc-name" required maxLength={160} value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
            </Field>
            <Field label="Authorization statement" htmlFor="asc-auth">
              <Textarea id="asc-auth" required rows={3} maxLength={2000} value={form.authorization_text}
                onChange={(e) => setForm((f) => ({ ...f, authorization_text: e.target.value }))}
                placeholder="I confirm written authorization to conduct these simulation exercises…" />
            </Field>
            <Field label="Authorization reference (document URL or ID)" htmlFor="asc-ref">
              <Input id="asc-ref" required maxLength={1024} value={form.authorization_reference}
                onChange={(e) => setForm((f) => ({ ...f, authorization_reference: e.target.value }))} />
            </Field>
            <Field label="Authorization expires" htmlFor="asc-exp">
              <Input id="asc-exp" required type="datetime-local" value={form.authorization_expires_at?.replace("Z", "") ?? ""}
                onChange={(e) => setForm((f) => ({ ...f, authorization_expires_at: e.target.value + "Z" }))} />
            </Field>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium text-fg">Validated techniques</legend>
              {catalog.loading ? <p className="text-sm text-muted">Loading technique catalog…</p> : catalog.error ? (
                <p role="alert" className="text-sm text-danger">{catalog.error}</p>
              ) : (
                <div className="grid gap-2 sm:grid-cols-2">
                  {Array.from(new Map((catalog.data ?? []).map((item) => [item.scenario, item])).values()).map((item) => (
                    <label key={item.scenario} className="flex gap-2 rounded-lg border border-line p-3 text-sm">
                      <input type="checkbox" checked={form.scenarios.includes(item.scenario)} onChange={(event) => setForm((current) => ({
                        ...current,
                        scenarios: event.target.checked
                          ? [...current.scenarios, item.scenario]
                          : current.scenarios.filter((scenario) => scenario !== item.scenario),
                      }))} />
                      <span><span className="block font-medium text-fg">{item.title}</span><span className="text-muted">{item.mitre_technique} · {humanize(item.risk_class)} risk · {humanize(item.adapter)}</span></span>
                    </label>
                  ))}
                </div>
              )}
            </fieldset>
            <Field label="Targets (one per line — must be pre-authorized)" htmlFor="asc-targets">
              <Textarea id="asc-targets" required rows={3} value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                placeholder="app.example.com" />
            </Field>
            <Field label="Cron schedule (optional)" htmlFor="asc-cron">
              <Input id="asc-cron" maxLength={120} placeholder="0 2 * * 1"
                onChange={(e) => setForm((f) => ({ ...f, cron_expression: e.target.value || undefined }))} />
            </Field>
            {createMut.errorMessage && <p role="alert" className="text-sm text-danger">{createMut.errorMessage}</p>}
            <div className="flex justify-end gap-3">
              <Button type="button" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" loading={createMut.loading}>Create campaign</Button>
            </div>
          </form>
        </Modal>
      )}

      {selectedCampaign && (
        <Modal title={`${selectedCampaign.name} evidence`} onClose={() => setSelectedCampaign(null)}>
          {runs.loading ? <LoadingState label="Loading simulation runs…" /> : runs.error ? (
            <ErrorState message={runs.error} onRetry={runs.refetch} />
          ) : !runs.data?.length ? (
            <EmptyState title="No runs yet" description="Trigger the campaign, approve its scope, and evidence will appear here." />
          ) : (
            <div className="space-y-2">
              {runs.data.map((run) => {
                const counts = (run.summary.counts ?? {}) as Record<string, number>;
                return (
                  <button key={run.id} type="button" onClick={() => void runDetailMut.run(run.id)} className="w-full rounded-lg border border-line p-3 text-left hover:bg-surface-2">
                    <div className="flex items-center justify-between"><span className="font-medium text-fg">{formatDateTime(run.created_at)}</span><Badge tone={run.status === "completed" ? "ok" : run.status === "failed" ? "danger" : "warn"}>{humanize(run.status)}</Badge></div>
                    <p className="mt-1 text-xs text-muted">Detected {counts.detected ?? 0} · Prevented {counts.prevented ?? 0} · Inconclusive {counts.inconclusive ?? 0} · Catalog {run.catalog_version}</p>
                  </button>
                );
              })}
            </div>
          )}
        </Modal>
      )}

      {selectedRun && (
        <Modal title="Technique evidence" onClose={() => setSelectedRun(null)}>
          <div className="space-y-3">
            {selectedRun.techniques.map((technique) => (
              <div key={technique.id} className="rounded-lg border border-line p-3">
                <div className="flex items-center justify-between"><span className="font-medium text-fg">{humanize(technique.technique_key)}</span><Badge tone={technique.control_result === "prevented" ? "ok" : technique.control_result === "detected" ? "danger" : "warn"}>{humanize(technique.control_result ?? technique.status)}</Badge></div>
                <p className="mt-1 text-xs text-muted">{technique.mitre_technique} · {technique.target} · {humanize(technique.adapter)}</p>
                <p className="mt-1 text-xs text-muted">{technique.evidence_artifact_ids.length} archived artifact(s){technique.scanner_job_id ? ` · job ${technique.scanner_job_id}` : ""}</p>
              </div>
            ))}
          </div>
        </Modal>
      )}
    </div>
  );
}
