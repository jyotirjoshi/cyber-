"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatDateTime, humanize } from "@/lib/format";
import type { ThreatEntityType, ThreatWatchlistCreateIn } from "@/lib/types";

const EMPTY_WATCH: ThreatWatchlistCreateIn = { entity_type: "cve", entity_key: "", label: "" };

export default function ThreatIntelligencePage() {
  const { can } = useAuth();
  const canRead = can("finding:read");
  const canManage = can("finding:analyze");
  const [search, setSearch] = React.useState("");
  const [offset, setOffset] = React.useState(0);
  const deferredSearch = React.useDeferredValue(search.trim());
  const q = deferredSearch.length >= 3 ? deferredSearch : undefined;
  const [showWatch, setShowWatch] = React.useState(false);
  const [watchForm, setWatchForm] = React.useState<ThreatWatchlistCreateIn>(EMPTY_WATCH);
  const catalog = useApiResource(
    () => api.threatIntelligence.list({ q, limit: 50, offset }),
    [q, offset],
    { enabled: canRead },
  );
  const watchlists = useApiResource(() => api.threatIntelligence.watchlists(), [], { enabled: canRead });
  const createWatch = useMutation((body: ThreatWatchlistCreateIn) => api.threatIntelligence.createWatchlist(body), {
    onSuccess: () => { setShowWatch(false); setWatchForm(EMPTY_WATCH); watchlists.refetch(); },
  });
  const deleteWatch = useMutation((id: string) => api.threatIntelligence.deleteWatchlist(id), {
    onSuccess: () => watchlists.refetch(),
  });

  if (!canRead) {
    return <EmptyState title="No access" description="You don't have permission to view vulnerability intelligence." />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat intelligence"
        description="Locally synchronized NVD, CISA KEV, EPSS, exploit, and ransomware signals used by canonical risk scoring."
        action={canManage ? <Button onClick={() => setShowWatch(true)}>Add watch</Button> : undefined}
      />
      <Card>
        <CardBody className="space-y-3">
          <div><h2 className="font-medium text-fg">Tenant watchlist</h2><p className="text-sm text-muted">Monitor only CVEs, products, actors, domains, or brands that intersect your inventory.</p></div>
          {watchlists.loading && !watchlists.data ? <LoadingState label="Loading watchlist…" /> : watchlists.error ? <ErrorState message={watchlists.error} onRetry={watchlists.refetch} /> : !watchlists.data?.length ? <EmptyState title="No watched threats" description="Add a watch to receive inventory-linked matches without exposing other tenants." /> : (
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">{watchlists.data.map((watch) => <div key={watch.id} className="rounded-lg border border-line p-3">
              <div className="flex items-start justify-between gap-2"><div><Badge tone="primary">{humanize(watch.entity_type)}</Badge><p className="mt-2 font-mono text-sm text-fg">{watch.entity_key}</p>{watch.label && <p className="text-xs text-muted">{watch.label}</p>}</div>{canManage && <Button size="sm" variant="ghost" onClick={() => void deleteWatch.run(watch.id)}>Remove</Button>}</div>
              <p className="mt-2 text-xs text-muted">{watch.last_matched_at ? `Last match ${formatDateTime(watch.last_matched_at)}` : "No inventory match yet"}</p>
            </div>)}</div>
          )}
        </CardBody>
      </Card>
      <Card>
        <CardBody className="space-y-4">
          <div className="max-w-md">
            <Input
              aria-label="Search CVE"
              placeholder="Search CVE (at least 3 characters)"
              value={search}
              onChange={(event) => { setSearch(event.target.value); setOffset(0); }}
            />
          </div>
          {catalog.loading && !catalog.data ? <LoadingState label="Loading vulnerability intelligence…" /> : catalog.error ? <ErrorState message={catalog.error} onRetry={catalog.refetch} /> : !catalog.data?.items.length ? <EmptyState title="No synchronized CVEs" description="The intelligence worker adds entries as canonical findings with CVE identifiers are processed." /> : (
            <>
              <Table>
                <THead><TR><TH>CVE</TH><TH>CVSS</TH><TH>EPSS</TH><TH>Observed exploitation</TH><TH>Exploit evidence</TH><TH>Freshness</TH></TR></THead>
                <TBody>{catalog.data.items.map((item) => {
                  const intel = item.snapshot;
                  const stale = Array.isArray(intel.stale_providers) && intel.stale_providers.length > 0;
                  return <TR key={item.cve_id}>
                    <TD className="font-mono font-medium text-fg">{item.cve_id}</TD>
                    <TD>{typeof intel.cvss_score === "number" ? intel.cvss_score.toFixed(1) : "—"}</TD>
                    <TD>{typeof intel.epss_score === "number" ? `${(intel.epss_score * 100).toFixed(1)}%` : "—"}</TD>
                    <TD><div className="flex flex-wrap gap-1">{intel.in_kev === true && <Badge tone="danger">CISA KEV</Badge>}{intel.ransomware_use === true && <Badge tone="danger">Ransomware</Badge>}{intel.in_kev !== true && intel.ransomware_use !== true && <span className="text-muted">Not observed</span>}</div></TD>
                    <TD>{intel.exploit_available === true ? <Badge tone="warn">Available</Badge> : <span className="text-muted">None recorded</span>}</TD>
                    <TD><div className="text-xs"><Badge tone={stale ? "warn" : "ok"}>{stale ? "Partial" : "Current"}</Badge><div className="mt-1 text-muted">{formatDateTime(item.refreshed_at)}</div></div></TD>
                  </TR>;
                })}</TBody>
              </Table>
              <Pagination meta={catalog.data.meta} onOffsetChange={setOffset} />
            </>
          )}
        </CardBody>
      </Card>
      {showWatch && <Modal title="Add threat watch" onClose={() => setShowWatch(false)}>
        <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void createWatch.run(watchForm); }}>
          <Field label="Type" htmlFor="watch-type"><select id="watch-type" className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm" value={watchForm.entity_type} onChange={(event) => setWatchForm((value) => ({ ...value, entity_type: event.target.value as ThreatEntityType }))}>{["cve", "product", "actor", "domain", "brand"].map((type) => <option key={type} value={type}>{humanize(type)}</option>)}</select></Field>
          <Field label="Identifier" htmlFor="watch-key"><Input id="watch-key" required maxLength={512} value={watchForm.entity_key} onChange={(event) => setWatchForm((value) => ({ ...value, entity_key: event.target.value }))} placeholder={watchForm.entity_type === "cve" ? "CVE-2026-1234" : "Exact value to monitor"} /></Field>
          <Field label="Label (optional)" htmlFor="watch-label"><Input id="watch-label" maxLength={255} value={watchForm.label ?? ""} onChange={(event) => setWatchForm((value) => ({ ...value, label: event.target.value }))} /></Field>
          {createWatch.errorMessage && <p role="alert" className="text-sm text-danger">{createWatch.errorMessage}</p>}
          <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setShowWatch(false)}>Cancel</Button><Button type="submit" loading={createWatch.loading}>Add watch</Button></div>
        </form>
      </Modal>}
    </div>
  );
}
