"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { AssetStatusBadge, Badge, CriticalityBadge } from "@/components/ui/Badge";
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
import { useAuth } from "@/lib/auth";
import { humanize } from "@/lib/format";
import type { AssetOut, AssetStatus, Criticality } from "@/lib/types";

const CRITICALITIES: Criticality[] = ["critical", "high", "normal", "low", "unknown"];
const ASSET_STATUSES: AssetStatus[] = ["active", "inactive", "unreachable", "out_of_scope"];

/** AssetOut carries ip/port rather than a single endpoint field — derive a locator for display. */
function assetEndpoint(asset: AssetOut): string | null {
  if (!asset.ip_address) return null;
  return asset.port != null ? `${asset.ip_address}:${asset.port}` : asset.ip_address;
}

export default function AssetsPage() {
  const { can } = useAuth();
  const router = useRouter();
  const canRead = can("asset:read");

  const [q, setQ] = React.useState("");
  const [criticality, setCriticality] = React.useState<Criticality | "">("");
  const [status, setStatus] = React.useState<AssetStatus | "">("");
  const [exposedOnly, setExposedOnly] = React.useState(false);
  const [selectedOnly, setSelectedOnly] = React.useState(false);
  const [offset, setOffset] = React.useState(0);

  const debouncedQ = useDebouncedValue(q);

  const { data, error, loading, refetch } = useApiResource(
    () =>
      api.assets.list({
        limit: 25,
        offset,
        q: debouncedQ || undefined,
        criticality: criticality || undefined,
        status: status || undefined,
        internet_exposed: exposedOnly || undefined,
        selected: selectedOnly || undefined,
      }),
    [debouncedQ, criticality, status, exposedOnly, selectedOnly, offset],
    { enabled: canRead },
  );

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
