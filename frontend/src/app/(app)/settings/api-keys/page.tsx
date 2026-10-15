"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/format";
import type { PlatformApiKeyCreatedOut, PlatformApiKeyOut } from "@/lib/types";

const DEFAULT_SCOPES = ["findings:read", "assets:read", "assessments:read"];

export default function ApiKeysPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("org:manage");

  const [showCreate, setShowCreate] = React.useState(false);
  const [name, setName] = React.useState("");
  const [scopesText, setScopesText] = React.useState(DEFAULT_SCOPES.join("\n"));
  const [expiresAt, setExpiresAt] = React.useState("");
  const [createdKey, setCreatedKey] = React.useState<PlatformApiKeyCreatedOut | null>(null);

  const { data, error, loading, refetch } = useApiResource(
    () => api.platform.listApiKeys(),
    [],
  );

  const createMut = useMutation(
    () => api.platform.createApiKey({
      name,
      scopes: scopesText.split("\n").map((s) => s.trim()).filter(Boolean),
      expires_at: expiresAt ? expiresAt + "Z" : null,
    }),
    {
      onSuccess: (key) => {
        setCreatedKey(key);
        setShowCreate(false);
        setName("");
        setScopesText(DEFAULT_SCOPES.join("\n"));
        setExpiresAt("");
        void refetch();
      },
    },
  );

  const revokeMut = useMutation(
    (id: string) => api.platform.revokeApiKey(id),
    {
      onSuccess: () => {
        toast({ title: "API key revoked", tone: "ok" });
        void refetch();
      },
    },
  );

  const rows: PlatformApiKeyOut[] = data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="API keys"
        description="Scoped machine credentials for CI/CD integrations and external tooling."
        action={canManage && <Button onClick={() => setShowCreate(true)}>Create key</Button>}
      />

      {loading && !rows.length ? (
        <LoadingState label="Loading API keys…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !rows.length ? (
        <EmptyState
          title="No API keys"
          description="Create a scoped API key to integrate with your CI/CD pipeline or external tools."
          action={canManage ? <Button onClick={() => setShowCreate(true)}>Create key</Button> : undefined}
        />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Name</TH>
              <TH>Prefix</TH>
              <TH>Scopes</TH>
              <TH>Last used</TH>
              <TH>Expires</TH>
              <TH>Status</TH>
              {canManage && <TH className="w-24" />}
            </TR>
          </THead>
          <TBody>
            {rows.map((k) => (
              <TR key={k.id}>
                <TD className="font-medium text-fg">{k.name}</TD>
                <TD><span className="font-mono text-sm text-muted">{k.key_prefix}…</span></TD>
                <TD className="text-muted text-xs">{k.scopes.join(", ") || "All"}</TD>
                <TD className="text-muted">{k.last_used_at ? formatDateTime(k.last_used_at) : "Never"}</TD>
                <TD className="text-muted">{k.expires_at ? formatDateTime(k.expires_at) : "Never"}</TD>
                <TD>
                  <Badge tone={k.revoked_at ? "danger" : "ok"}>{k.revoked_at ? "Revoked" : "Active"}</Badge>
                </TD>
                {canManage && (
                  <TD>
                    {!k.revoked_at && (
                      <button
                        type="button"
                        className="text-xs text-danger hover:underline"
                        onClick={() => void revokeMut.run(k.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {/* Create modal */}
      {showCreate && (
        <Modal title="Create API key" onClose={() => setShowCreate(false)}>
          <form onSubmit={(e) => { e.preventDefault(); void createMut.run(); }} className="space-y-4">
            <Field label="Name" htmlFor="ak-name">
              <Input id="ak-name" required maxLength={160} value={name}
                onChange={(e) => setName(e.target.value)} placeholder="CI deployment key" />
            </Field>
            <Field label="Scopes (one per line)" htmlFor="ak-scopes">
              <textarea
                id="ak-scopes"
                rows={4}
                className="w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-fg font-mono"
                value={scopesText}
                onChange={(e) => setScopesText(e.target.value)}
              />
            </Field>
            <Field label="Expires (optional)" htmlFor="ak-exp">
              <Input id="ak-exp" type="datetime-local" value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)} />
            </Field>
            {createMut.errorMessage && <p role="alert" className="text-sm text-danger">{createMut.errorMessage}</p>}
            <div className="flex justify-end gap-3">
              <Button type="button" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" loading={createMut.loading}>Create key</Button>
            </div>
          </form>
        </Modal>
      )}

      {/* Show secret once */}
      {createdKey && (
        <Modal title="API key created" onClose={() => setCreatedKey(null)}>
          <div className="space-y-4">
            <p className="text-sm text-muted">Copy this key now. It will not be shown again.</p>
            <pre className="overflow-x-auto rounded-lg border border-line bg-bg p-4 text-sm font-mono text-fg select-all">
              {createdKey.secret}
            </pre>
            <div className="flex justify-end">
              <Button onClick={() => {
                void navigator.clipboard.writeText(createdKey.secret);
                toast({ title: "Copied to clipboard", tone: "ok" });
              }}>
                Copy
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
