"use client";

import { useParams } from "next/navigation";
import * as React from "react";

import { Badge, CriticalityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { parseCustomFields } from "@/lib/custom-fields";
import { fieldError, getErrorMessage } from "@/lib/errors";
import { formatDateTime, humanize } from "@/lib/format";
import type { AssetEnvironment, AssetOut, Criticality } from "@/lib/types";

const CRITICALITIES: Criticality[] = ["critical", "high", "normal", "low", "unknown"];
const ENVIRONMENTS: AssetEnvironment[] = ["unknown", "production", "staging", "development", "test"];

/** AssetOut carries ip/port rather than a single endpoint field — derive a locator for display. */
function assetEndpoint(asset: AssetOut): string | null {
  if (!asset.ip_address) return null;
  return asset.port != null ? `${asset.ip_address}:${asset.port}` : asset.ip_address;
}

function Detail({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="mt-0.5 break-words text-sm text-fg">{value ? value : "—"}</dd>
    </div>
  );
}

export default function AssetDetailPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const routeParams = useParams();
  const rawId = routeParams.id;
  const id = (Array.isArray(rawId) ? rawId[0] : rawId) ?? "";

  const canRead = can("asset:read");
  const canTag = can("asset:tag");

  const { data, error, loading, refetch, setData } = useApiResource(
    () => api.assets.get(id),
    [id],
    { enabled: canRead && !!id },
  );
  const policyGate = useApiResource(
    () => api.assets.policyGate(id),
    [id],
    { enabled: canRead && !!id },
  );

  const [critValue, setCritValue] = React.useState<Criticality>("normal");
  const [critRationale, setCritRationale] = React.useState("");
  const [tagKey, setTagKey] = React.useState("");
  const [tagValue, setTagValue] = React.useState("");
  const [ownerTeam, setOwnerTeam] = React.useState("");
  const [ownerUserId, setOwnerUserId] = React.useState("");
  const [environment, setEnvironment] = React.useState<AssetEnvironment>("unknown");
  const [groups, setGroups] = React.useState("");
  const [customFieldsText, setCustomFieldsText] = React.useState("{}");

  // Keep the criticality selector in sync with whatever the server currently reports.
  React.useEffect(() => {
    if (data) {
      setCritValue(data.criticality);
      setOwnerTeam(data.owner_team ?? "");
      setOwnerUserId(data.owner_user_id ?? "");
      setEnvironment(data.environment);
      setGroups(data.groups.join(", "));
      setCustomFieldsText(JSON.stringify(data.custom_fields ?? {}, null, 2));
    }
  }, [data]);

  const members = useApiResource(
    () => api.organization.members({ limit: 100 }),
    [canTag],
    { enabled: canTag },
  );

  const contextMut = useMutation(
    () => api.assets.setContext(id, {
      owner_team: ownerTeam.trim() || null,
      owner_user_id: ownerUserId || null,
      environment,
      groups: groups.split(",").map((value) => value.trim()).filter(Boolean),
      custom_fields: parseCustomFields(customFieldsText),
    }),
    {
      onSuccess: (result) => {
        setData(result);
        toast({ title: "Asset context updated", tone: "ok" });
      },
    },
  );

  const critMut = useMutation(
    () =>
      api.assets.setCriticality(id, {
        criticality: critValue,
        rationale: critRationale || null,
      }),
    {
      onSuccess: (result) => {
        setData(result);
        setCritRationale("");
        toast({ title: "Criticality updated", tone: "ok" });
      },
    },
  );

  const tagMut = useMutation(
    () => api.assets.addTag(id, { key: tagKey.trim(), value: tagValue.trim() || null }),
    {
      onSuccess: (result) => {
        setData(result);
        setTagKey("");
        setTagValue("");
        toast({ title: "Tag added", tone: "ok" });
      },
    },
  );

  const scopeMut = useMutation(() => api.assets.markOutOfScope(id), {
    onSuccess: (result) => {
      setData(result);
      toast({ title: "Asset marked out of scope", tone: "ok" });
    },
    onError: (e) =>
      toast({ title: "Couldn't update asset", description: getErrorMessage(e), tone: "danger" }),
  });

  if (!canRead) {
    return (
      <EmptyState title="No access" description="You don't have permission to view this." />
    );
  }
  if (loading && !data) return <LoadingState label="Loading asset…" />;
  if (error) return <ErrorState message={error} onRetry={refetch} />;
  if (!data) {
    return (
      <EmptyState title="Asset not found" description="This asset may have been removed." />
    );
  }

  const asset = data;
  const activeMembers = (members.data?.items ?? []).filter((member) => member.is_active && member.accepted_at);
  const endpoint = assetEndpoint(asset);
  const critFieldError = fieldError(critMut.error, "criticality") ?? fieldError(critMut.error, "rationale");
  const tagFieldError = fieldError(tagMut.error, "key") ?? fieldError(tagMut.error, "value");

  return (
    <div className="space-y-6">
      <PageHeader
        title={asset.name}
        description={endpoint ?? asset.asset_type}
        actions={
          canTag ? (
            <Button
              variant="danger"
              size="sm"
              loading={scopeMut.loading}
              disabled={asset.status === "out_of_scope"}
              onClick={() => {
                if (
                  window.confirm(
                    "Mark this asset out of scope? It will be excluded from future scanning.",
                  )
                ) {
                  void scopeMut.run();
                }
              }}
            >
              Mark out of scope
            </Button>
          ) : undefined
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
            </CardHeader>
            <CardBody className="space-y-5">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
                <Detail label="Type" value={asset.asset_type} />
                <Detail label="IP address" value={asset.ip_address} />
                <Detail label="Port" value={asset.port != null ? String(asset.port) : null} />
                <Detail label="Protocol" value={asset.protocol} />
                <Detail label="Service" value={asset.service} />
                <Detail label="Internet exposed" value={asset.internet_exposed ? "Yes" : "No"} />
                <Detail
                  label="HTTP status"
                  value={asset.http_status_code != null ? String(asset.http_status_code) : null}
                />
                <Detail label="HTTP title" value={asset.http_title} />
                <Detail label="TLS subject" value={asset.tls_subject} />
                <Detail label="Risk score" value={`${(asset.risk_score * 100).toFixed(0)}%`} />
                <Detail label="First seen" value={formatDateTime(asset.first_seen_at)} />
                <Detail label="Last seen" value={formatDateTime(asset.last_seen_at)} />
                <Detail label="Assessments" value={String(asset.seen_in_assessments.length)} />
              </dl>

              {asset.technology.length > 0 && (
                <div>
                  <p className="mb-2 text-xs font-medium text-muted">Technology</p>
                  <div className="flex flex-wrap gap-2">
                    {asset.technology.map((t) => (
                      <span
                        key={t}
                        className="rounded border border-line bg-surface-2 px-2 py-0.5 text-xs text-muted"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Tags</CardTitle>
            </CardHeader>
            <CardBody className="space-y-4">
              {asset.tags.length === 0 ? (
                <p className="text-sm text-muted">No tags applied.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {asset.tags.map((tag) => (
                    <span
                      key={tag.id}
                      className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-2 py-1 text-xs"
                    >
                      <span className="text-fg">
                        {tag.key}
                        {tag.value ? `=${tag.value}` : ""}
                      </span>
                      {tag.is_operator_applied && <Badge tone="primary">operator</Badge>}
                    </span>
                  ))}
                </div>
              )}

              {canTag && (
                <div className="space-y-3 border-t border-line pt-4">
                  <form
                    className="flex flex-col gap-3 sm:flex-row sm:items-end"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void tagMut.run();
                    }}
                  >
                    <Field
                      label="Key"
                      htmlFor="tag-key"
                      required
                      className="flex-1"
                      error={fieldError(tagMut.error, "key")}
                    >
                      <Input
                        id="tag-key"
                        required
                        value={tagKey}
                        onChange={(e) => setTagKey(e.target.value)}
                      />
                    </Field>
                    <Field
                      label="Value"
                      htmlFor="tag-value"
                      className="flex-1"
                      error={fieldError(tagMut.error, "value")}
                    >
                      <Input
                        id="tag-value"
                        placeholder="Optional"
                        value={tagValue}
                        onChange={(e) => setTagValue(e.target.value)}
                      />
                    </Field>
                    <Button type="submit" loading={tagMut.loading} disabled={!tagKey.trim()}>
                      Add tag
                    </Button>
                  </form>
                  <InlineError message={tagFieldError ? null : tagMut.errorMessage} />
                </div>
              )}
            </CardBody>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader><CardTitle>Business context</CardTitle></CardHeader>
            <CardBody className="space-y-4">
              <dl className="grid grid-cols-2 gap-4">
                <Detail label="Environment" value={humanize(asset.environment)} />
                <Detail label="Owner team" value={asset.owner_team} />
                <Detail label="Owner user ID" value={asset.owner_user_id} />
                <Detail label="Groups" value={asset.groups.join(", ") || null} />
                <div className="col-span-2"><dt className="text-xs font-medium text-muted">Custom fields</dt><dd className="mt-1 whitespace-pre-wrap break-words font-mono text-xs text-fg">{JSON.stringify(asset.custom_fields ?? {}, null, 2)}</dd></div>
              </dl>
              {canTag && (
                <form className="space-y-3 border-t border-line pt-4" onSubmit={(e) => {
                  e.preventDefault();
                  void contextMut.run();
                }}>
                  <Field label="Owner team" htmlFor="owner-team" error={fieldError(contextMut.error, "owner_team")}>
                    <Input id="owner-team" maxLength={120} value={ownerTeam} onChange={(e) => setOwnerTeam(e.target.value)} />
                  </Field>
                  <Field label="Accountable owner" htmlFor="asset-owner" error={fieldError(contextMut.error, "owner_user_id")} hint="Only active members of this organization can own an asset.">
                    <Select id="asset-owner" value={ownerUserId} onChange={(e) => setOwnerUserId(e.target.value)}>
                      <option value="">No individual owner</option>
                      {ownerUserId && !activeMembers.some((member) => member.user_id === ownerUserId) && <option value={ownerUserId}>Current owner ({ownerUserId})</option>}
                      {activeMembers.map((member) => <option key={member.user_id} value={member.user_id}>{member.full_name || member.email}</option>)}
                    </Select>
                  </Field>
                  <Field label="Environment" htmlFor="asset-environment" error={fieldError(contextMut.error, "environment")}>
                    <Select id="asset-environment" value={environment} onChange={(e) => setEnvironment(e.target.value as AssetEnvironment)}>
                      {ENVIRONMENTS.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
                    </Select>
                  </Field>
                  <Field label="Groups (comma-separated)" htmlFor="asset-groups" error={fieldError(contextMut.error, "groups")}>
                    <Input id="asset-groups" value={groups} onChange={(e) => setGroups(e.target.value)} />
                  </Field>
                  <Field label="Custom fields (JSON, non-sensitive metadata only)" htmlFor="asset-custom-fields" error={fieldError(contextMut.error, "custom_fields")}>
                    <Textarea id="asset-custom-fields" value={customFieldsText} onChange={(e) => setCustomFieldsText(e.target.value)} rows={4} />
                  </Field>
                  <InlineError message={contextMut.errorMessage} />
                  {members.error && <p className="text-xs text-muted">Member list unavailable: {members.error}</p>}
                  <Button type="submit" size="sm" loading={contextMut.loading}>Save context</Button>
                </form>
              )}
            </CardBody>
          </Card>
          <Card>
            <CardHeader><CardTitle>CI/CD policy gate</CardTitle></CardHeader>
            <CardBody className="space-y-3 text-sm">
              <p className="text-muted">Current fail-closed deployment decision from active canonical findings and recent coverage evidence.</p>
              {policyGate.loading && !policyGate.data ? <LoadingState label="Evaluating deployment gate…" /> : policyGate.error ? (
                <ErrorState message={policyGate.error} onRetry={policyGate.refetch} />
              ) : policyGate.data ? <>
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line p-3">
                  <div><p className="font-medium text-fg">{humanize(policyGate.data.decision)}</p><p className="mt-1 text-xs text-muted">{humanize(policyGate.data.reason_code)}</p></div>
                  <Badge tone={policyGate.data.decision === "block" ? "danger" : policyGate.data.decision === "warn" || policyGate.data.decision === "unknown" ? "warn" : "ok"}>{policyGate.data.allow_deploy ? "Deploy allowed" : "Deploy blocked"}</Badge>
                </div>
                <dl className="grid grid-cols-2 gap-2 text-xs"><div><dt className="text-muted">Critical</dt><dd className="font-medium text-danger">{policyGate.data.counts.critical}</dd></div><div><dt className="text-muted">High</dt><dd className="font-medium text-warn">{policyGate.data.counts.high}</dd></div><div className="col-span-2"><dt className="text-muted">Latest coverage import</dt><dd className="mt-0.5 text-fg">{policyGate.data.scan_imported_at ? formatDateTime(policyGate.data.scan_imported_at) : "No qualifying recent scan"}</dd></div></dl>
                {policyGate.data.blockers.length > 0 && <div className="rounded-lg border border-line p-3"><p className="text-xs font-medium text-fg">Findings requiring attention</p><ul className="mt-2 space-y-1.5 text-xs">{policyGate.data.blockers.map((finding) => <li key={finding.id} className="flex items-center justify-between gap-3"><span className="min-w-0 truncate text-fg">{finding.title}</span><span className={finding.severity === "critical" ? "shrink-0 text-danger" : "shrink-0 text-warn"}>{humanize(finding.severity)} · {finding.risk_score.toFixed(0)}</span></li>)}</ul></div>}
                <Button size="sm" variant="outline" onClick={policyGate.refetch}>Refresh decision</Button>
              </> : null}
            </CardBody>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Criticality</CardTitle>
            </CardHeader>
            <CardBody className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <CriticalityBadge criticality={asset.criticality} />
                <span className="text-xs text-muted">{humanize(asset.criticality_source)}</span>
              </div>
              {asset.criticality_rationale && (
                <p className="text-sm text-muted">{asset.criticality_rationale}</p>
              )}

              {canTag && (
                <form
                  className="space-y-3 border-t border-line pt-4"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void critMut.run();
                  }}
                >
                  <Field
                    label="Set criticality"
                    htmlFor="crit-value"
                    error={fieldError(critMut.error, "criticality")}
                  >
                    <Select
                      id="crit-value"
                      value={critValue}
                      onChange={(e) => setCritValue(e.target.value as Criticality)}
                    >
                      {CRITICALITIES.map((c) => (
                        <option key={c} value={c}>
                          {humanize(c)}
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field
                    label="Rationale"
                    htmlFor="crit-rationale"
                    error={fieldError(critMut.error, "rationale")}
                  >
                    <Input
                      id="crit-rationale"
                      placeholder="Optional"
                      value={critRationale}
                      onChange={(e) => setCritRationale(e.target.value)}
                    />
                  </Field>
                  <InlineError message={critFieldError ? null : critMut.errorMessage} />
                  <Button type="submit" size="sm" loading={critMut.loading}>
                    Update criticality
                  </Button>
                </form>
              )}
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  );
}
