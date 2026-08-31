"use client";

import * as React from "react";

import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardFooter, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Label, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fieldError } from "@/lib/errors";
import { formatDate, formatRelative, humanize } from "@/lib/format";
import type {
  IntegrationKind,
  IntegrationOut,
  IntegrationStatus,
  IntegrationTestOut,
  IntegrationUpsertIn,
} from "@/lib/types";

/** Integration status → shared badge tone. Static map so Tailwind classes stay literal. */
const STATUS_TONE: Record<IntegrationStatus, BadgeTone> = {
  configured: "ok",
  unverified: "warn",
  error: "danger",
  disabled: "neutral",
};

interface CredRow {
  key: string;
  value: string;
}

function IntegrationCard({
  integration,
  canManage,
  onChanged,
}: {
  integration: IntegrationOut;
  canManage: boolean;
  onChanged: () => void;
}) {
  const { toast } = useToast();

  const [open, setOpen] = React.useState(false);
  const [baseUrl, setBaseUrl] = React.useState(integration.base_url ?? "");
  const [enabled, setEnabled] = React.useState(integration.is_enabled);
  const [configText, setConfigText] = React.useState(() =>
    Object.keys(integration.config).length > 0
      ? JSON.stringify(integration.config, null, 2)
      : "",
  );
  const [credRows, setCredRows] = React.useState<CredRow[]>(() =>
    integration.credentials.length > 0
      ? integration.credentials.map((c) => ({ key: c.name, value: "" }))
      : [{ key: "", value: "" }],
  );
  const [formError, setFormError] = React.useState<string | null>(null);

  const test = useMutation((kind: IntegrationKind) => api.integrations.test(kind), {
    onSuccess: (r: IntegrationTestOut) =>
      toast({
        title: r.healthy ? "Healthy" : "Unhealthy",
        description: r.detail || undefined,
        tone: r.healthy ? "ok" : "danger",
      }),
  });

  const remove = useMutation((kind: IntegrationKind) => api.integrations.remove(kind), {
    onSuccess: () => {
      onChanged();
      toast({ title: "Integration removed", tone: "ok" });
    },
  });

  const upsert = useMutation((body: IntegrationUpsertIn) => api.integrations.upsert(body), {
    onSuccess: () => {
      onChanged();
      toast({ title: "Integration saved", tone: "ok" });
      setOpen(false);
    },
  });

  const idBase = integration.kind;

  const updateRow = (idx: number, patch: Partial<CredRow>) =>
    setCredRows((rows) => rows.map((r, i) => (i === idx ? { ...r, ...patch } : r)));

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();

    let parsedConfig: Record<string, unknown> = {};
    const raw = configText.trim();
    if (raw) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        setFormError("Config must be valid JSON.");
        return;
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setFormError("Config must be a JSON object.");
        return;
      }
      parsedConfig = parsed as Record<string, unknown>;
    }
    setFormError(null);

    const creds: Record<string, string> = {};
    for (const row of credRows) {
      const key = row.key.trim();
      if (key && row.value) creds[key] = row.value;
    }

    void upsert.run({
      kind: integration.kind,
      base_url: baseUrl.trim() || null,
      is_enabled: enabled,
      config: parsedConfig,
      credentials: creds,
    });
  };

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="min-w-0">
          <CardTitle className="truncate">{humanize(integration.kind)}</CardTitle>
          <p className="mt-0.5 truncate text-xs text-muted">{integration.name}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Badge tone={STATUS_TONE[integration.status]}>{humanize(integration.status)}</Badge>
          <Badge tone={integration.is_enabled ? "ok" : "neutral"}>
            {integration.is_enabled ? "Enabled" : "Disabled"}
          </Badge>
        </div>
      </CardHeader>

      <CardBody className="flex-1 space-y-3">
        <dl className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <dt className="text-xs text-faint">Endpoint</dt>
            <dd className="min-w-0 truncate font-mono text-xs text-muted">
              {integration.base_url ?? "—"}
            </dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-xs text-faint">Last verified</dt>
            <dd className="text-xs text-muted">{formatRelative(integration.last_verified_at)}</dd>
          </div>
          {integration.failure_count > 0 && (
            <div className="flex items-center justify-between gap-3">
              <dt className="text-xs text-faint">Recent failures</dt>
              <dd className="text-xs font-medium text-danger">{integration.failure_count}</dd>
            </div>
          )}
        </dl>

        {integration.last_error && (
          <p className="rounded-lg border border-danger/30 bg-danger/5 px-2.5 py-1.5 text-xs text-danger">
            {integration.last_error}
          </p>
        )}

        <div className="space-y-1.5">
          <p className="text-xs text-faint">Credentials</p>
          {integration.credentials.length > 0 ? (
            <ul className="space-y-1.5">
              {integration.credentials.map((c) => (
                <li
                  key={c.name}
                  className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted"
                >
                  <span className="font-medium text-fg">{c.name}</span>
                  {c.hint && <span>{c.hint}</span>}
                  <Badge tone="neutral">v{c.key_version}</Badge>
                  {c.expires_at && (
                    <span className="text-faint">expires {formatDate(c.expires_at)}</span>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-faint">No credentials stored.</p>
          )}
        </div>
      </CardBody>

      {canManage && (
        <CardFooter className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            loading={test.loading}
            onClick={() => void test.run(integration.kind)}
          >
            Test
          </Button>
          <Button size="sm" variant="outline" onClick={() => setOpen((o) => !o)}>
            {open ? "Close" : "Configure"}
          </Button>
          <Button
            size="sm"
            variant="danger"
            loading={remove.loading}
            onClick={() => {
              if (window.confirm(`Remove the ${humanize(integration.kind)} integration?`)) {
                void remove.run(integration.kind);
              }
            }}
          >
            Remove
          </Button>
        </CardFooter>
      )}

      {canManage && open && (
        <form onSubmit={handleSubmit} className="space-y-4 border-t border-line px-5 py-4">
          <InlineError
            message={
              formError ?? (fieldError(upsert.error, "base_url") ? null : upsert.errorMessage)
            }
          />

          <Field
            label="Base URL"
            htmlFor={`${idBase}-base_url`}
            hint="Leave blank to clear."
            error={fieldError(upsert.error, "base_url")}
          >
            <Input
              id={`${idBase}-base_url`}
              type="url"
              placeholder="https://…"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </Field>

          <label className="flex items-center gap-2 text-sm text-fg">
            <input
              type="checkbox"
              className="h-4 w-4 accent-primary"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled
          </label>

          <Field
            label="Config (JSON)"
            htmlFor={`${idBase}-config`}
            hint="A JSON object of non-secret settings."
            error={fieldError(upsert.error, "config")}
          >
            <Textarea
              id={`${idBase}-config`}
              className="font-mono text-xs"
              spellCheck={false}
              rows={4}
              placeholder="{}"
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
            />
          </Field>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Credentials</Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setCredRows((rows) => [...rows, { key: "", value: "" }])}
              >
                Add
              </Button>
            </div>
            {credRows.map((row, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <Input
                  placeholder="key"
                  aria-label="Credential key"
                  className="flex-1"
                  value={row.key}
                  onChange={(e) => updateRow(idx, { key: e.target.value })}
                />
                <Input
                  type="password"
                  placeholder="value"
                  aria-label="Credential value"
                  autoComplete="new-password"
                  className="flex-1"
                  value={row.value}
                  onChange={(e) => updateRow(idx, { value: e.target.value })}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label="Remove credential"
                  onClick={() =>
                    setCredRows((rows) =>
                      rows.length > 1 ? rows.filter((_, i) => i !== idx) : rows,
                    )
                  }
                >
                  ✕
                </Button>
              </div>
            ))}
            <p className="text-xs text-faint">
              Write-only. Secrets are encrypted on save and never displayed. Blank rows are ignored.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button type="submit" size="sm" loading={upsert.loading}>
              Save
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </Card>
  );
}

export default function IntegrationsPage() {
  const { can } = useAuth();
  const canRead = can("integration:read");
  const canManage = can("integration:manage");

  const { data, error, loading, refetch } = useApiResource(
    () => api.integrations.list(),
    [],
    { enabled: canRead },
  );

  if (!canRead) {
    return (
      <EmptyState
        title="No access"
        description="You don't have permission to view this."
      />
    );
  }

  let body: React.ReactNode;
  if (loading && !data) {
    body = <LoadingState />;
  } else if (error) {
    body = <ErrorState message={error} onRetry={refetch} />;
  } else if (!data || data.length === 0) {
    body = (
      <EmptyState
        title="No integrations configured"
        description="Connect DefectDojo, Jira, Slack, threat-intel and other services to enrich and route assessment results."
      />
    );
  } else {
    body = (
      <div className="grid gap-4 sm:grid-cols-2">
        {data.map((integration) => (
          <IntegrationCard
            key={integration.kind}
            integration={integration}
            canManage={canManage}
            onChanged={refetch}
          />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Integrations"
        description="Connected services for findings, tickets, notifications and threat intelligence."
      />
      {body}
    </div>
  );
}
