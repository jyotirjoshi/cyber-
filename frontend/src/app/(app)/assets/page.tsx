"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { AssetStatusBadge, Badge, CriticalityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { Pagination } from "@/components/ui/Pagination";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { useApiResource } from "@/hooks/useApi";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { api } from "@/lib/api";
import { canApplyCmdbPreview } from "@/lib/asset-cmdb";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { humanize } from "@/lib/format";
import type { AssetEnvironment, AssetOut, AssetStatus, CmdbImportOut, Criticality } from "@/lib/types";

const CRITICALITIES: Criticality[] = ["critical", "high", "normal", "low", "unknown"];
const ASSET_STATUSES: AssetStatus[] = ["active", "inactive", "unreachable", "out_of_scope"];
const ENVIRONMENTS: AssetEnvironment[] = ["unknown", "production", "staging", "development", "test"];

/** AssetOut carries ip/port rather than a single endpoint field — derive a locator for display. */
function assetEndpoint(asset: AssetOut): string | null {
  if (!asset.ip_address) return null;
  return asset.port != null ? `${asset.ip_address}:${asset.port}` : asset.ip_address;
}

export default function AssetsPage() {
  const { can } = useAuth();
  const router = useRouter();
  const canRead = can("asset:read");
  const canReadFindings = can("finding:read");
  const canTag = can("asset:tag");

  const [q, setQ] = React.useState("");
  const [criticality, setCriticality] = React.useState<Criticality | "">("");
  const [environment, setEnvironment] = React.useState<AssetEnvironment | "">("");
  const [status, setStatus] = React.useState<AssetStatus | "">("");
  const [exposedOnly, setExposedOnly] = React.useState(false);
  const [selectedOnly, setSelectedOnly] = React.useState(false);
  const [offset, setOffset] = React.useState(0);
  const [changeOffset, setChangeOffset] = React.useState(0);
  const [cmdbFile, setCmdbFile] = React.useState<File | null>(null);
  const [previewedFile, setPreviewedFile] = React.useState<File | null>(null);
  const [cmdbPreview, setCmdbPreview] = React.useState<CmdbImportOut | null>(null);
  const [cmdbApplied, setCmdbApplied] = React.useState<CmdbImportOut | null>(null);
  const [cmdbBusy, setCmdbBusy] = React.useState(false);
  const [cmdbError, setCmdbError] = React.useState<string | null>(null);
  const [selectedApplication, setSelectedApplication] = React.useState<string | null>(null);

  const debouncedQ = useDebouncedValue(q);

  const { data, error, loading, refetch } = useApiResource(
    () =>
      api.assets.list({
        limit: 25,
        offset,
        q: debouncedQ || undefined,
        criticality: criticality || undefined,
        environment: environment || undefined,
        status: status || undefined,
        internet_exposed: exposedOnly || undefined,
        selected: selectedOnly || undefined,
      }),
    [debouncedQ, criticality, environment, status, exposedOnly, selectedOnly, offset],
    { enabled: canRead },
  );
  const applicationRisks = useApiResource(
    () => api.applications.risks({ limit: 25, offset: 0 }),
    [],
    { enabled: canRead && canReadFindings },
  );
  const applicationPatterns = useApiResource(
    () => api.applications.patterns(selectedApplication!),
    [selectedApplication],
    { enabled: canRead && canReadFindings && selectedApplication !== null },
  );
  const assetChanges = useApiResource(
    () => api.assets.changes({ limit: 20, offset: changeOffset }),
    [changeOffset],
    { enabled: canRead },
  );

  const previewCmdb = async () => {
    if (!cmdbFile || cmdbBusy) return;
    setCmdbBusy(true);
    setCmdbError(null);
    setCmdbPreview(null);
    try {
      const preview = await api.assets.importCmdb(cmdbFile, true);
      setPreviewedFile(cmdbFile);
      setCmdbPreview(preview);
    } catch (cause) {
      setCmdbError(getErrorMessage(cause));
    } finally {
      setCmdbBusy(false);
    }
  };

  const applyCmdb = async () => {
    if (!canApplyCmdbPreview(cmdbFile, previewedFile, cmdbPreview) || cmdbBusy || !cmdbFile) return;
    setCmdbBusy(true);
    setCmdbError(null);
    try {
      const applied = await api.assets.importCmdb(cmdbFile, false);
      setCmdbApplied(applied);
      setCmdbPreview(null);
      setPreviewedFile(null);
      refetch();
    } catch (cause) {
      setCmdbError(getErrorMessage(cause));
    } finally {
      setCmdbBusy(false);
    }
  };

  if (!canRead) {
    return (
      <EmptyState title="No access" description="You don't have permission to view this." />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Assets"
        description="Hosts, services, and applications discovered across your assessments."
      />

      <Card>
        <CardBody className="space-y-3">
          <div>
            <h2 className="text-sm font-semibold text-fg">Discovery and drift</h2>
            <p className="text-xs text-muted">First observations and material changes from assessments, including scheduled passive reconnaissance.</p>
          </div>
          {assetChanges.loading ? (
            <LoadingState label="Loading inventory changes…" />
          ) : assetChanges.error ? (
            <ErrorState message={assetChanges.error} onRetry={assetChanges.refetch} />
          ) : !assetChanges.data?.items.length ? (
            <p className="text-sm text-muted">No asset changes recorded yet.</p>
          ) : (
            <>
              <Table>
                <THead><TR><TH>Asset</TH><TH>Observation</TH><TH>Changed fields</TH><TH>When</TH></TR></THead>
                <TBody>
                  {assetChanges.data.items.map((change) => (
                    <TR key={change.id} clickable onClick={() => router.push(`/assets/${change.asset_id}`)}>
                      <TD className="font-medium text-fg">{change.asset_name}</TD>
                      <TD>{change.change_type === "discovered" ? "New asset" : "Changed"}</TD>
                      <TD className="text-muted">{Object.keys(change.changes).join(", ") || "—"}</TD>
                      <TD className="text-muted">{new Date(change.created_at).toLocaleString()}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <div className="flex items-center justify-between gap-2 text-xs text-muted">
                <span>{changeOffset + 1}–{changeOffset + assetChanges.data.items.length} of {assetChanges.data.total}</span>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" disabled={changeOffset === 0} onClick={() => setChangeOffset(Math.max(0, changeOffset - 20))}>Previous</Button>
                  <Button size="sm" variant="outline" disabled={changeOffset + 20 >= assetChanges.data.total} onClick={() => setChangeOffset(changeOffset + 20)}>Next</Button>
                </div>
              </div>
            </>
          )}
        </CardBody>
      </Card>

      {canReadFindings && (
        <Card>
          <CardBody className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold text-fg">Application exposure</h2>
              <p className="text-xs text-muted">Active canonical findings grouped by the application field on assets.</p>
            </div>
            {applicationRisks.loading && !applicationRisks.data ? (
              <LoadingState label="Loading application exposure…" />
            ) : applicationRisks.error ? (
              <ErrorState message={applicationRisks.error} onRetry={applicationRisks.refetch} />
            ) : !applicationRisks.data?.items.length ? (
              <p className="text-sm text-muted">No assets have an application field yet. Set one in an asset’s business context to start the rollup.</p>
            ) : (
              <div className="space-y-3">
                <Table>
                  <THead><TR><TH>Application</TH><TH>Assets</TH><TH>Active findings</TH><TH>Critical</TH><TH>High</TH><TH>Top risk</TH></TR></THead>
                  <TBody>
                    {applicationRisks.data.items.map((item) => (
                      <TR key={item.application} clickable onClick={() => setSelectedApplication(item.application)}>
                        <TD><button type="button" className="font-medium text-primary hover:underline" onClick={() => setSelectedApplication(item.application)}>{item.application}</button></TD>
                        <TD>{item.asset_count}</TD><TD>{item.active_findings}</TD><TD>{item.critical}</TD><TD>{item.high}</TD>
                        <TD>{item.max_risk_score.toFixed(0)}/100</TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
                {applicationRisks.data.total > applicationRisks.data.items.length && (
                  <p className="text-xs text-muted">Showing the top {applicationRisks.data.items.length} of {applicationRisks.data.total} applications.</p>
                )}
              </div>
            )}
            {selectedApplication && (
              <div className="space-y-2 border-t border-line pt-3">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-fg">Cross-repository patterns: {selectedApplication}</h3>
                  <Button size="sm" variant="outline" onClick={() => setSelectedApplication(null)}>Close</Button>
                </div>
                {applicationPatterns.loading && !applicationPatterns.data ? (
                  <LoadingState label="Checking repositories…" />
                ) : applicationPatterns.error ? (
                  <ErrorState message={applicationPatterns.error} onRetry={applicationPatterns.refetch} />
                ) : applicationPatterns.data?.application !== selectedApplication ? (
                  <LoadingState label="Checking repositories…" />
                ) : !applicationPatterns.data.patterns.length ? (
                  <p className="text-sm text-muted">No repeated CVE or rule evidence across different repositories was found.</p>
                ) : (
                  <div className="space-y-2">
                    {applicationPatterns.data.patterns.map((pattern) => (
                      <div key={pattern.key} className="rounded border border-line p-3 text-sm">
                        <div className="font-medium text-fg">{pattern.key} · {pattern.repository_count} repositories · risk {pattern.max_risk_score.toFixed(0)}/100</div>
                        <div className="text-xs text-muted">{pattern.repositories.join(", ")}</div>
                      </div>
                    ))}
                    {applicationPatterns.data.truncated && <p className="text-xs text-muted">Results were capped; narrow the application or inspect canonical findings for the full evidence.</p>}
                  </div>
                )}
              </div>
            )}
          </CardBody>
        </Card>
      )}

      {canTag && (
        <Card>
          <CardBody className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold text-fg">Import CMDB business context</h2>
              <p className="text-xs text-muted">Update existing assets by type and identity. CSV columns: asset_type, asset_value, and any of tier, owner_team, environment. Tier accepts tier0–tier3. Unmatched assets are not created.</p>
            </div>
            <input
              aria-label="CMDB CSV file"
              type="file"
              accept=".csv,text/csv"
              className="block w-full text-sm text-muted"
              onChange={(event) => {
                setCmdbFile(event.target.files?.[0] ?? null);
                setPreviewedFile(null);
                setCmdbPreview(null);
                setCmdbApplied(null);
                setCmdbError(null);
              }}
            />
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={!cmdbFile || cmdbBusy} loading={cmdbBusy} onClick={() => void previewCmdb()}>Preview import</Button>
              <Button size="sm" disabled={!canApplyCmdbPreview(cmdbFile, previewedFile, cmdbPreview) || cmdbBusy} onClick={() => void applyCmdb()}>Apply previewed changes</Button>
            </div>
            {cmdbError && <p role="alert" className="text-xs text-danger">{cmdbError}</p>}
            {cmdbPreview && (
              <p className="text-xs text-muted">Preview: {cmdbPreview.matched} matched, {cmdbPreview.updated} would change, {cmdbPreview.unmatched.length} unmatched.</p>
            )}
            {cmdbApplied && (
              <p className="text-xs text-muted">Applied: {cmdbApplied.updated} assets updated; {cmdbApplied.unmatched.length} unmatched.</p>
            )}
            {(cmdbPreview ?? cmdbApplied)?.unmatched.length ? (
              <p className="text-xs text-muted">Unmatched: {(cmdbPreview ?? cmdbApplied)!.unmatched.slice(0, 10).join(", ")}{(cmdbPreview ?? cmdbApplied)!.unmatched.length > 10 ? "…" : ""}</p>
            ) : null}
          </CardBody>
        </Card>
      )}

      <Card>
        <CardBody className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Search" htmlFor="asset-q">
            <Input
              id="asset-q"
              placeholder="Name, IP, or service…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setOffset(0);
              }}
            />
          </Field>

          <Field label="Criticality" htmlFor="asset-criticality">
            <Select
              id="asset-criticality"
              value={criticality}
              onChange={(e) => {
                setCriticality(e.target.value as Criticality | "");
                setOffset(0);
              }}
            >
              <option value="">All criticalities</option>
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {humanize(c)}
                </option>
              ))}
            </Select>
          </Field>

          <Field label="Status" htmlFor="asset-status">
            <Select
              id="asset-status"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value as AssetStatus | "");
                setOffset(0);
              }}
            >
              <option value="">All statuses</option>
              {ASSET_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {humanize(s)}
                </option>
              ))}
            </Select>
          </Field>

          <Field label="Environment" htmlFor="asset-environment">
            <Select id="asset-environment" value={environment} onChange={(e) => {
              setEnvironment(e.target.value as AssetEnvironment | "");
              setOffset(0);
            }}>
              <option value="">All environments</option>
              {ENVIRONMENTS.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </Select>
          </Field>

          <div className="flex flex-wrap items-end gap-x-5 gap-y-2">
            <label className="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-line bg-surface-2 accent-primary"
                checked={exposedOnly}
                onChange={(e) => {
                  setExposedOnly(e.target.checked);
                  setOffset(0);
                }}
              />
              Internet-exposed
            </label>
            <label className="flex items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-line bg-surface-2 accent-primary"
                checked={selectedOnly}
                onChange={(e) => {
                  setSelectedOnly(e.target.checked);
                  setOffset(0);
                }}
              />
              Selected for scanning
            </label>
          </div>
        </CardBody>
      </Card>

      {loading && !data ? (
        <LoadingState label="Loading assets…" />
      ) : error ? (
        <ErrorState message={error} onRetry={refetch} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No assets found"
          description="No assets match the current filters. Adjust the filters or run an assessment to discover assets."
        />
      ) : (
        <div className="space-y-4">
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Type</TH>
                <TH>Criticality</TH>
                <TH>Status</TH>
                <TH>Exposed</TH>
                <TH className="text-right">Risk</TH>
                <TH>Selected</TH>
              </TR>
            </THead>
            <TBody>
              {data.items.map((asset) => {
                const endpoint = assetEndpoint(asset);
                return (
                  <TR
                    key={asset.id}
                    clickable
                    onClick={() => router.push(`/assets/${asset.id}`)}
                  >
                    <TD>
                      <div className="font-medium text-fg">{asset.name}</div>
                      {endpoint && <div className="text-xs text-muted">{endpoint}</div>}
                    </TD>
                    <TD className="text-muted">{asset.asset_type}</TD>
                    <TD>
                      <CriticalityBadge criticality={asset.criticality} />
                    </TD>
                    <TD>
                      <AssetStatusBadge status={asset.status} />
                    </TD>
                    <TD>
                      {asset.internet_exposed ? (
                        <Badge tone="warn">Internet</Badge>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </TD>
                    <TD className="text-right tabular-nums">
                      {(asset.risk_score * 100).toFixed(0)}%
                    </TD>
                    <TD className="text-muted">
                      {asset.selected_for_scanning ? "Yes" : "No"}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>

          <Pagination meta={data.meta} onOffsetChange={setOffset} />
        </div>
      )}
    </div>
  );
}
