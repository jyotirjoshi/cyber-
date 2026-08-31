"use client";

import * as React from "react";

import { Badge, CriticalityBadge, RiskBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { Textarea } from "@/components/ui/Input";
import { InlineError } from "@/components/ui/States";
import { cn } from "@/lib/cn";
import { formatDateTime, formatRelative, humanize } from "@/lib/format";
import type { ApprovalOut, ApproveIn, ScannerName } from "@/lib/types";

/**
 * FR-011 approval gate — the single, authoritative control that lets a human approve, narrow, or
 * reject the agent's proposed scan scope before any active scanning runs. Rendered both inline in
 * the agent conversation and on the assessment detail screen; the resolved decision (its
 * `approved_payload`) is what actually drives scanning, so this is deliberately one component.
 *
 * The parent owns the network call — it passes `onResolve(body)` and reflects `busy`. When
 * `canApprove` is false the controls are replaced with a permission notice (the card still shows
 * the full proposal, read-only).
 */
export function ApprovalCard({
  approval,
  canApprove,
  busy,
  onResolve,
  className,
}: {
  approval: ApprovalOut;
  canApprove: boolean;
  busy: boolean;
  onResolve: (body: ApproveIn) => void;
  className?: string;
}) {
  const [customizing, setCustomizing] = React.useState(false);
  const [selectedAssets, setSelectedAssets] = React.useState<Set<string>>(
    () => new Set(approval.proposed_assets.map((asset) => asset.asset_id)),
  );
  const [selectedScanners, setSelectedScanners] = React.useState<Set<ScannerName>>(
    () => new Set(approval.proposed_scanners),
  );
  const [note, setNote] = React.useState("");

  const toggleAsset = (id: string) =>
    setSelectedAssets((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const toggleScanner = (scanner: ScannerName) =>
    setSelectedScanners((prev) => {
      const next = new Set(prev);
      if (next.has(scanner)) next.delete(scanner);
      else next.add(scanner);
      return next;
    });

  const noteOrNull = note.trim() ? note.trim() : null;

  return (
    <Card className={cn("border-warn/40 bg-warn/5", className)}>
      <CardHeader className="border-warn/20">
        <CardTitle className="flex items-center gap-2">
          <span className="flex h-5 w-5 items-center justify-center rounded-full bg-warn/20 text-warn">
            !
          </span>
          Approval required
        </CardTitle>
        <RiskBadge risk={approval.risk_level} />
      </CardHeader>
      <CardBody className="space-y-4">
        <div>
          <p className="text-sm font-medium text-fg">{approval.prompt}</p>
          {approval.rationale && <p className="mt-1 text-sm text-muted">{approval.rationale}</p>}
        </div>

        {approval.proposed_assets.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-faint">
              Proposed targets ({approval.proposed_assets.length})
            </p>
            <ul className="divide-y divide-line/60 rounded-lg border border-line">
              {approval.proposed_assets.map((asset) => (
                <li key={asset.asset_id} className="flex items-start gap-3 px-3 py-2.5">
                  {customizing && (
                    <input
                      type="checkbox"
                      className="mt-1 h-4 w-4 shrink-0 accent-primary"
                      checked={selectedAssets.has(asset.asset_id)}
                      onChange={() => toggleAsset(asset.asset_id)}
                      aria-label={`Include ${asset.name}`}
                    />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-medium text-fg">{asset.name}</span>
                      <CriticalityBadge criticality={asset.criticality} />
                      {asset.internet_exposed && <Badge tone="warn">Internet-exposed</Badge>}
                    </div>
                    {asset.endpoint && (
                      <p className="truncate font-mono text-xs text-muted">{asset.endpoint}</p>
                    )}
                    {asset.rationale && <p className="mt-0.5 text-xs text-muted">{asset.rationale}</p>}
                    <div className="mt-1 flex flex-wrap gap-1">
                      {asset.scanners.map((scanner) => (
                        <span
                          key={scanner}
                          className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted"
                        >
                          {scanner}
                        </span>
                      ))}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}

        {customizing && approval.proposed_scanners.length > 0 && (
          <div>
            <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-faint">Scanners</p>
            <div className="flex flex-wrap gap-2">
              {approval.proposed_scanners.map((scanner) => (
                <label
                  key={scanner}
                  className={cn(
                    "flex cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs",
                    selectedScanners.has(scanner)
                      ? "border-primary/40 bg-primary/10 text-fg"
                      : "border-line bg-surface-2 text-muted",
                  )}
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-primary"
                    checked={selectedScanners.has(scanner)}
                    onChange={() => toggleScanner(scanner)}
                  />
                  {humanize(scanner)}
                </label>
              ))}
            </div>
          </div>
        )}

        {!canApprove ? (
          <InlineError message="You don't have permission to resolve this approval." />
        ) : (
          <div className="space-y-3">
            <Textarea
              aria-label="Note (optional)"
              placeholder="Optional note recorded with your decision…"
              rows={2}
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
            {customizing ? (
              <div className="flex flex-wrap gap-2">
                <Button
                  loading={busy}
                  disabled={selectedAssets.size === 0}
                  onClick={() =>
                    onResolve({
                      decision: "customized",
                      asset_ids: [...selectedAssets],
                      scanners: selectedScanners.size > 0 ? [...selectedScanners] : null,
                      note: noteOrNull,
                    })
                  }
                >
                  Apply selection ({selectedAssets.size})
                </Button>
                <Button variant="ghost" disabled={busy} onClick={() => setCustomizing(false)}>
                  Cancel
                </Button>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2">
                <Button
                  loading={busy}
                  onClick={() => onResolve({ decision: "approved", note: noteOrNull })}
                >
                  Approve
                </Button>
                <Button
                  variant="secondary"
                  disabled={busy}
                  onClick={() => onResolve({ decision: "approved_all", note: noteOrNull })}
                >
                  Approve all
                </Button>
                <Button variant="outline" disabled={busy} onClick={() => setCustomizing(true)}>
                  Customize
                </Button>
                <Button
                  variant="danger"
                  disabled={busy}
                  onClick={() => onResolve({ decision: "rejected", note: noteOrNull })}
                >
                  Reject
                </Button>
              </div>
            )}
          </div>
        )}

        <p className="text-xs text-faint">
          Requested {formatRelative(approval.created_at)}
          {approval.expires_at ? ` · expires ${formatDateTime(approval.expires_at)}` : ""}
        </p>
      </CardBody>
    </Card>
  );
}
