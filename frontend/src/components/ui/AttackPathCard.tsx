"use client";

/**
 * AttackPathCard — renders one multi-hop kill-chain attack path.
 *
 * Shows entry point → steps (ATT&CK techniques) → crown jewel.
 * Color-coded by likelihood: red = high, orange = medium, yellow = low.
 */

import * as React from "react";
import { clsx } from "clsx";

export interface AttackStep {
  technique_id: string;
  technique_name: string;
  description: string;
  asset_id?: string | null;
  finding_id?: string | null;
}

export interface AttackPathData {
  entry_point: string;
  entry_finding_id?: string | null;
  steps: AttackStep[];
  crown_jewel: string;
  likelihood: "low" | "medium" | "high" | string;
  blast_radius: string;
  chokepoints: string[];
  confidence: "low" | "medium" | "high" | string;
  confidence_reason?: string;
}

interface AttackPathCardProps {
  path: AttackPathData;
  index: number;
  onFindingClick?: (findingId: string) => void;
}

const LIKELIHOOD_STYLES: Record<string, { border: string; badge: string; label: string }> = {
  high:    { border: "border-red-500",    badge: "bg-red-100 text-red-700",    label: "High likelihood" },
  medium:  { border: "border-orange-400", badge: "bg-orange-100 text-orange-700", label: "Medium likelihood" },
  low:     { border: "border-yellow-400", badge: "bg-yellow-100 text-yellow-700", label: "Low likelihood" },
  unknown: { border: "border-line",       badge: "bg-surface-2 text-muted",    label: "Unknown" },
};

function LikelihoodBadge({ likelihood }: { likelihood: string }) {
  const style = LIKELIHOOD_STYLES[likelihood] ?? LIKELIHOOD_STYLES.unknown;
  return (
    <span className={clsx("rounded-full px-2 py-0.5 text-xs font-medium", style.badge)}>
      {style.label}
    </span>
  );
}

function ArrowRight() {
  return (
    <svg
      aria-hidden="true"
      className="mx-1 h-4 w-4 shrink-0 text-muted"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path d="M3 8h10M9 4l4 4-4 4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4 text-red-500" viewBox="0 0 16 16" fill="currentColor">
      <path
        fillRule="evenodd"
        d="M8 1.5L2 4v4c0 3 2.5 5.5 6 7 3.5-1.5 6-4 6-7V4L8 1.5zM8 13C5.5 11.5 4 9.5 4 8V5.4l4-1.8 4 1.8V8c0 1.5-1.5 3.5-4 5z"
      />
    </svg>
  );
}

export function AttackPathCard({ path, index, onFindingClick }: AttackPathCardProps) {
  const [expanded, setExpanded] = React.useState(false);
  const style = LIKELIHOOD_STYLES[path.likelihood] ?? LIKELIHOOD_STYLES.unknown;

  return (
    <div className={clsx("rounded-xl border-2 bg-surface p-4 space-y-3", style.border)}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldIcon />
          <span className="text-sm font-semibold text-fg">Attack Path {index + 1}</span>
        </div>
        <div className="flex items-center gap-2">
          <LikelihoodBadge likelihood={path.likelihood} />
          <span className="text-xs text-muted">Confidence: {path.confidence}</span>
        </div>
      </div>

      {/* Kill-chain flow */}
      <div className="flex flex-wrap items-center gap-1 rounded-lg bg-surface-2 px-3 py-2">
        {/* Entry */}
        <div className="rounded bg-red-50 border border-red-200 px-2 py-1 text-xs text-red-700 font-medium max-w-[160px] truncate"
          title={path.entry_point}>
          🎯 {path.entry_point || "Entry point"}
        </div>

        {path.steps.slice(0, expanded ? undefined : 3).map((step, i) => (
          <React.Fragment key={i}>
            <ArrowRight />
            <div
              className={clsx(
                "rounded border px-2 py-1 text-xs font-medium max-w-[140px] truncate",
                step.finding_id
                  ? "border-primary/30 bg-primary/5 text-primary cursor-pointer hover:bg-primary/10"
                  : "border-line bg-surface text-muted"
              )}
              title={`${step.technique_id}: ${step.technique_name}\n${step.description}`}
              onClick={() => step.finding_id && onFindingClick?.(step.finding_id)}
            >
              {step.technique_id ? (
                <span className="font-mono mr-1 text-[10px] opacity-70">{step.technique_id}</span>
              ) : null}
              {step.technique_name || step.description.slice(0, 30)}
            </div>
          </React.Fragment>
        ))}

        {!expanded && path.steps.length > 3 && (
          <>
            <ArrowRight />
            <button
              type="button"
              onClick={() => setExpanded(true)}
              className="rounded border border-dashed border-muted px-2 py-1 text-xs text-muted hover:text-fg hover:border-fg transition-colors"
            >
              +{path.steps.length - 3} more
            </button>
          </>
        )}

        <ArrowRight />
        {/* Crown jewel */}
        <div className="rounded bg-purple-50 border border-purple-200 px-2 py-1 text-xs text-purple-700 font-medium max-w-[160px] truncate"
          title={path.crown_jewel}>
          👑 {path.crown_jewel || "Crown jewel"}
        </div>
      </div>

      {/* Blast radius */}
      {path.blast_radius && (
        <p className="text-xs text-muted">
          <span className="font-medium text-fg">Blast radius:</span> {path.blast_radius}
        </p>
      )}

      {/* Chokepoints */}
      {path.chokepoints.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-fg">Break the chain here:</p>
          <ul className="space-y-0.5">
            {path.chokepoints.map((cp, i) => (
              <li key={i} className="flex items-start gap-1.5 text-xs text-muted">
                <span className="mt-0.5 text-green-500">✓</span>
                {cp}
              </li>
            ))}
          </ul>
        </div>
      )}

      {expanded && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="text-xs text-muted hover:text-fg"
        >
          Show less
        </button>
      )}
    </div>
  );
}
