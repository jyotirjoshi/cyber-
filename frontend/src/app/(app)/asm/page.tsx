"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Textarea } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/format";
import type { AsmSurfaceCreateIn, AsmSurfaceOut } from "@/lib/types";

const BLANK: AsmSurfaceCreateIn = {
  name: "",
  seeds: [],
  cron_expression: "0 2 * * *",
  timezone: "UTC",
  authorization_text: "",
  authorization_confirmed: false,
  authorization_expires_at: "",
};

export default function AsmPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("assessment:create");

  const [showCreate, setShowCreate] = React.useState(false);
  const [form, setForm] = React.useState<AsmSurfaceCreateIn>(BLANK);
  const [seedsText, setSeedsText] = React.useState("");

  const { data, error, loading, refetch } = useApiResource(
    () => api.asm.list(),
    [],
  );

  const createMut = useMutation(
    (body: AsmSurfaceCreateIn) => api.asm.create(body),
    {
      onSuccess: () => {
        toast({ title: "ASM surface created", tone: "ok" });
        setShowCreate(false);
        setForm(BLANK);
        setSeedsText("");
        void refetch();
      },
    },
  );

  const toggleMut = useMutation(
    ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.asm.update(id, { enabled }),
    {
      onSuccess: () => { void refetch(); },
    },
  );

  const deleteMut = useMutation(
    (id: string) => api.asm.delete(id),
    {
      onSuccess: () => {
        toast({ title: "Surface deleted", tone: "ok" });
        void refetch();
      },
    },
  );

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const seeds = seedsText.split("\n").map((s) => s.trim()).filter(Boolean);
    if (!seeds.length) { toast({ title: "At least one seed required", tone: "danger" }); return; }
    if (!form.authorization_confirmed) { toast({ title: "Authorization must be confirmed", tone: "danger" }); return; }
    const authorizationExpiresAt = new Date(form.authorization_expires_at);
    if (Number.isNaN(authorizationExpiresAt.getTime())) {
      toast({ title: "Enter a valid authorization expiry", tone: "danger" });
      return;
    }
    void createMut.run({ ...form, seeds, authorization_expires_at: authorizationExpiresAt.toISOString() });
  }

  const rows = data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack surface management"
        description="Continuous passive discovery — fingerprinting and drift detection against registered seed targets."
        action={canManage && <Button onClick={() => setShowCreate(true)}>New surface</Button>}
      />

      <Card>
        <CardBody className="text-sm text-muted">
          <p>ASM surfaces run passive reconnaissance (certificate transparency, passive DNS, archival sources) on a cron schedule. No active probing is performed. Each surface requires time-bounded human authorization.</p>
        </CardBody>
      </Card>

      {loading && !rows.length ? (
        <LoadingState label="Loading surfaces…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !rows.length ? (
        <EmptyState
          title="No surfaces"
          description="Add a surface to start continuous passive discovery of your attack surface."
          action={canManage ? <Button onClick={() => setShowCreate(true)}>New surface</Button> : undefined}
        />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Name</TH>
              <TH>Seeds</TH>
              <TH>Schedule</TH>
              <TH>Auth expires</TH>
              <TH>Last run</TH>
              <TH>New assets</TH>
              <TH>Status</TH>
              {canManage && <TH className="w-24" />}
            </TR>
          </THead>
          <TBody>
            {rows.map((s: AsmSurfaceOut) => (
              <TR key={s.id}>
                <TD className="font-medium text-fg">{s.name}</TD>
                <TD className="text-muted">{s.seeds.length} seed{s.seeds.length !== 1 ? "s" : ""}</TD>
                <TD><span className="font-mono text-xs text-muted">{s.cron_expression}</span></TD>
                <TD className="text-muted">{formatDateTime(s.authorization_expires_at)}</TD>
                <TD className="text-muted">{s.last_run_at ? formatDateTime(s.last_run_at) : "Never"}</TD>
                <TD>
                  {s.last_new_count > 0 ? (
                    <Badge tone="primary">+{s.last_new_count}</Badge>
                  ) : (
                    <span className="text-faint">{s.last_asset_count > 0 ? s.last_asset_count : "—"}</span>
                  )}
                </TD>
                <TD>
                  <div className="flex flex-col gap-1">
                    <Badge tone={s.enabled ? "ok" : "neutral"}>{s.enabled ? "Active" : "Paused"}</Badge>
                    {s.last_error_code && <Badge tone="danger">{s.last_error_code}</Badge>}
                  </div>
                </TD>
                {canManage && (
                  <TD>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        className="text-xs text-muted hover:text-fg"
                        onClick={() => void toggleMut.run({ id: s.id, enabled: !s.enabled })}
                      >
                        {s.enabled ? "Pause" : "Resume"}
                      </button>
                      <button
                        type="button"
                        className="text-xs text-danger hover:underline"
                        onClick={() => void deleteMut.run(s.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {showCreate && (
        <Modal title="New ASM surface" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Field label="Name" htmlFor="asm-name">
              <Input id="asm-name" required maxLength={160} value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
            </Field>
            <Field label="Seed domains / IPs (one per line)" htmlFor="asm-seeds">
              <Textarea id="asm-seeds" required rows={4} value={seedsText}
                onChange={(e) => setSeedsText(e.target.value)}
                placeholder={"example.com\napi.example.com\n192.0.2.1"} />
            </Field>
            <Field label="Cron schedule" htmlFor="asm-cron">
              <Input id="asm-cron" required maxLength={120} value={form.cron_expression}
                onChange={(e) => setForm((f) => ({ ...f, cron_expression: e.target.value }))}
                placeholder="0 2 * * *" />
            </Field>
            <Field label="Timezone" htmlFor="asm-tz">
              <Input id="asm-tz" maxLength={100} value={form.timezone}
                onChange={(e) => setForm((f) => ({ ...f, timezone: e.target.value }))} />
            </Field>
            <Field label="Authorization statement" htmlFor="asm-auth">
              <Textarea id="asm-auth" required rows={3} maxLength={2000} value={form.authorization_text}
                onChange={(e) => setForm((f) => ({ ...f, authorization_text: e.target.value }))}
                placeholder="I confirm I am authorized to conduct passive discovery against these assets…" />
            </Field>
            <Field label="Authorization expires" htmlFor="asm-exp">
              <Input id="asm-exp" required type="datetime-local"
                onChange={(e) => setForm((f) => ({ ...f, authorization_expires_at: e.target.value }))} />
            </Field>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={form.authorization_confirmed}
                onChange={(e) => setForm((f) => ({ ...f, authorization_confirmed: e.target.checked }))}
                required />
              I confirm written authorization for passive discovery against these targets
            </label>
            {createMut.errorMessage && <p role="alert" className="text-sm text-danger">{createMut.errorMessage}</p>}
            <div className="flex justify-end gap-3">
              <Button type="button" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" loading={createMut.loading}>Create surface</Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
