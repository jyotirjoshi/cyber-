"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime } from "@/lib/format";
import type { SavedViewCreateIn, SavedViewOut, SavedViewResource, SavedViewUpdateIn } from "@/lib/types";

function savedViewHref(view: SavedViewOut): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(view.filters)) {
    if (key === "source") continue;
    if (typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
      query.set(key, String(value));
    }
  }
  if (view.resource === "findings") {
    query.set("view", view.filters.source === "canonical" ? "canonical" : "assessment");
  }
  const path = view.resource === "findings" ? "/findings" : "/assets";
  return `${path}${query.size ? `?${query.toString()}` : ""}`;
}

export default function SavedViewsPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const canManage = can("finding:read"); // same gate as creating views

  const [showCreate, setShowCreate] = React.useState(false);
  const [name, setName] = React.useState("");
  const [resource, setResource] = React.useState<SavedViewResource>("findings");
  const [query, setQuery] = React.useState("");
  const [advancedQuery, setAdvancedQuery] = React.useState("");
  const [severity, setSeverity] = React.useState("");
  const [findingStatus, setFindingStatus] = React.useState("");
  const [assetStatus, setAssetStatus] = React.useState("");
  const [environment, setEnvironment] = React.useState("");
  const [criticality, setCriticality] = React.useState("");
  const [internetExposed, setInternetExposed] = React.useState(false);
  const [editingView, setEditingView] = React.useState<SavedViewOut | null>(null);

  const { data, error, loading, refetch } = useApiResource(
    () => api.platform.listSavedViews(),
    [],
  );

  const createMut = useMutation(
    (body: SavedViewCreateIn) => api.platform.createSavedView(body),
    {
      onSuccess: () => {
        toast({ title: "Saved view created", tone: "ok" });
        setShowCreate(false);
        setName("");
        setQuery(""); setAdvancedQuery(""); setSeverity(""); setFindingStatus(""); setAssetStatus("");
        setEnvironment(""); setCriticality(""); setInternetExposed(false);
        void refetch();
      },
    },
  );

  const deleteMut = useMutation(
    (id: string) => api.platform.deleteSavedView(id),
    {
      onSuccess: () => {
        toast({ title: "View deleted", tone: "ok" });
        void refetch();
      },
    },
  );

  const updateMut = useMutation(
    ({ id, body }: { id: string; body: SavedViewUpdateIn }) => api.platform.updateSavedView(id, body),
    { onSuccess: () => { toast({ title: "Saved view updated", tone: "ok" }); setShowCreate(false); setEditingView(null); void refetch(); } },
  );

  function resetForm() {
    setName(""); setResource("findings"); setQuery(""); setAdvancedQuery(""); setSeverity(""); setFindingStatus("");
    setAssetStatus(""); setEnvironment(""); setCriticality(""); setInternetExposed(false);
  }

  function beginCreate() {
    resetForm();
    setEditingView(null);
    setShowCreate(true);
  }

  function beginEdit(view: SavedViewOut) {
    const filters = view.filters;
    setEditingView(view);
    setName(view.name);
    setResource(view.resource);
    setQuery(typeof filters.q === "string" ? filters.q : "");
    setAdvancedQuery(typeof filters.query === "string" ? filters.query : "");
    setSeverity(typeof filters.severity === "string" ? filters.severity : "");
    setFindingStatus(typeof filters.status === "string" && view.resource === "findings" ? filters.status : "");
    setAssetStatus(typeof filters.status === "string" && view.resource === "assets" ? filters.status : "");
    setEnvironment(typeof filters.environment === "string" ? filters.environment : "");
    setCriticality(typeof filters.criticality === "string" ? filters.criticality : "");
    setInternetExposed(filters.internet_exposed === true);
    setShowCreate(true);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const filters: Record<string, unknown> = {
      ...(resource === "findings" ? { source: "canonical" } : {}),
      ...(query.trim() ? { q: query.trim() } : {}),
      ...(advancedQuery.trim() ? { query: advancedQuery.trim() } : {}),
      ...(resource === "findings" && severity ? { severity } : {}),
      ...(resource === "findings" && findingStatus ? { status: findingStatus } : {}),
      ...(resource === "assets" && assetStatus ? { status: assetStatus } : {}),
      ...(resource === "assets" && environment ? { environment } : {}),
      ...(resource === "assets" && criticality ? { criticality } : {}),
      ...(resource === "assets" && internetExposed ? { internet_exposed: true } : {}),
    };
    if (editingView) void updateMut.run({ id: editingView.id, body: { name, filters } });
    else void createMut.run({ name, resource, filters });
  }

  const rows: SavedViewOut[] = data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Saved views"
        description="Named filter presets for findings and assets — shared across your organization."
        action={canManage && <Button onClick={beginCreate}>New view</Button>}
      />

      {loading && !rows.length ? (
        <LoadingState label="Loading saved views…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !rows.length ? (
        <EmptyState
          title="No saved views"
          description="Save a filter preset to quickly return to a commonly used finding or asset query."
          action={canManage ? <Button onClick={beginCreate}>New view</Button> : undefined}
        />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Name</TH>
              <TH>Resource</TH>
              <TH>Filters</TH>
              <TH>Created</TH>
              <TH className="w-32" />
            </TR>
          </THead>
          <TBody>
            {rows.map((v) => (
              <TR key={v.id}>
                <TD className="font-medium text-fg">{v.name}</TD>
                <TD><Badge tone="neutral">{v.resource}</Badge></TD>
                <TD>
                  <span className="block max-w-[30rem] truncate font-mono text-xs text-muted">
                    {JSON.stringify(v.filters)}
                  </span>
                </TD>
                <TD className="text-muted">{formatDateTime(v.created_at)}</TD>
                <TD>
                  <a href={savedViewHref(v)} className="mr-3 text-xs text-primary hover:underline">Open</a>
                  {canManage && (
                    <button type="button" className="mr-3 text-xs text-primary hover:underline" onClick={() => beginEdit(v)}>Edit</button>
                  )}
                  {canManage && (
                    <button
                      type="button"
                      className="text-xs text-danger hover:underline"
                      onClick={() => void deleteMut.run(v.id)}
                    >
                      Delete
                    </button>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {showCreate && (
        <Modal title={editingView ? "Edit saved view" : "New saved view"} onClose={() => { setShowCreate(false); setEditingView(null); }}>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Field label="Name" htmlFor="sv-name">
              <Input id="sv-name" required maxLength={160} value={name}
                onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Resource" htmlFor="sv-resource">
              <Select id="sv-resource" value={resource}
                disabled={!!editingView}
                onChange={(e) => setResource(e.target.value as SavedViewResource)}>
                <option value="findings">Findings</option>
                <option value="assets">Assets</option>
              </Select>
            </Field>
            <Field label="Search" htmlFor="sv-query" hint="Optional free-text filter."><Input id="sv-query" maxLength={200} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={resource === "findings" ? "CVE, component, or finding title" : "Asset name, IP, or service"} /></Field>
            <Field
              label="Advanced query"
              htmlFor="sv-advanced-query"
              hint={resource === "findings" ? "Boolean finding query, e.g. severity:critical AND risk>=80." : "Boolean asset query, e.g. environment:production AND internet_exposed:true."}
            >
              <Input
                id="sv-advanced-query"
                maxLength={1000}
                value={advancedQuery}
                onChange={(e) => setAdvancedQuery(e.target.value)}
                placeholder={resource === "findings" ? "provider:tenable AND kev:true" : "tag.tier:critical OR risk>=0.8"}
              />
            </Field>
            {resource === "findings" ? <div className="grid gap-3 sm:grid-cols-2"><Field label="Severity" htmlFor="sv-severity"><Select id="sv-severity" value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">Any severity</option>{["critical", "high", "medium", "low", "info"].map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field><Field label="Status" htmlFor="sv-finding-status"><Select id="sv-finding-status" value={findingStatus} onChange={(e) => setFindingStatus(e.target.value)}><option value="">Any status</option>{["new", "open", "reopened", "mitigated", "accepted_risk", "false_positive", "closed"].map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</Select></Field></div> : <><div className="grid gap-3 sm:grid-cols-3"><Field label="Status" htmlFor="sv-asset-status"><Select id="sv-asset-status" value={assetStatus} onChange={(e) => setAssetStatus(e.target.value)}><option value="">Any status</option>{["active", "inactive", "unreachable", "out_of_scope"].map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</Select></Field><Field label="Environment" htmlFor="sv-environment"><Select id="sv-environment" value={environment} onChange={(e) => setEnvironment(e.target.value)}><option value="">Any environment</option>{["production", "staging", "development", "test", "unknown"].map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field><Field label="Criticality" htmlFor="sv-criticality"><Select id="sv-criticality" value={criticality} onChange={(e) => setCriticality(e.target.value)}><option value="">Any criticality</option>{["critical", "high", "normal", "low", "unknown"].map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field></div><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={internetExposed} onChange={(e) => setInternetExposed(e.target.checked)} /> Internet-facing assets only</label></>}
            {(createMut.errorMessage || updateMut.errorMessage) && <p role="alert" className="text-sm text-danger">{createMut.errorMessage ?? updateMut.errorMessage}</p>}
            <div className="flex justify-end gap-3">
              <Button type="button" variant="ghost" onClick={() => { setShowCreate(false); setEditingView(null); }}>Cancel</Button>
              <Button type="submit" loading={createMut.loading || updateMut.loading}>{editingView ? "Save changes" : "Save view"}</Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}
