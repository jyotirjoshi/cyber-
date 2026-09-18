"use client";

/**
 * SSVCBadge — renders the SSVC triage outcome with full tooltip context.
 *
 * Outcomes: track | track* | attend | act
 * Color-coded from green (track) to red (act).
 */

import * as React from "react";
import { clsx } from "clsx";

export type SSVCOutcome = "track" | "track*" | "attend" | "act" | string;

interface SSVCBadgeProps {
  outcome: SSVCOutcome | null | undefined;
  exploitation?: string | null;
  automatable?: string | null;
  showTooltip?: boolean;
  className?: string;
}

const OUTCOME_STYLES: Record<string, { bg: string; text: string; border: string; label: string; description: string }> = {
  act: {
    bg: "bg-red-600",
    text: "text-white",
    border: "border-red-700",
    label: "ACT",
    description: "Immediate action required. Actively exploited, high impact.",
  },
  attend: {
    bg: "bg-orange-500",
    text: "text-white",
    border: "border-orange-600",
    label: "ATTEND",
    description: "Address within 1 week. Significant exploitation risk.",
  },
  "track*": {
    bg: "bg-yellow-400",
    text: "text-gray-900",
    border: "border-yellow-500",
    label: "TRACK★",
    description: "Monitor closely. Prepare to act quickly if exploitation is confirmed.",
  },
  track: {
    bg: "bg-green-500",
    text: "text-white",
    border: "border-green-600",
    label: "TRACK",
    description: "Monitor. No immediate action required.",
  },
};

export function SSVCBadge({ outcome, exploitation, automatable, showTooltip = true, className }: SSVCBadgeProps) {
  if (!outcome) return null;

  const key = outcome.toLowerCase().replace("*", "*");
  const style = OUTCOME_STYLES[key] ?? {
    bg: "bg-surface-2",
    text: "text-muted",
    border: "border-line",
    label: outcome.toUpperCase(),
    description: "SSVC triage result",
  };

  const tooltipParts = [
    style.description,
    exploitation ? `Exploitation: ${exploitation}` : null,
    automatable ? `Automatable: ${automatable}` : null,
  ].filter(Boolean);

  return (
    <span
      className={clsx(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold tracking-wide uppercase",
        style.bg,
        style.text,
        style.border,
        className,
      )}
      title={showTooltip ? tooltipParts.join(" · ") : undefined}
      aria-label={`SSVC: ${style.label}`}
    >
      {style.label}
    </span>
  );
}

/**
 * SSVCMatrix — a compact 2×2 matrix showing where the finding sits on
 * the exploitation × technical-impact axes.
 */
interface SSVCMatrixProps {
  exploitation: string | null | undefined;
  automatable: string | null | undefined;
  technicalImpact: string | null | undefined;
  missionPrevalence: string | null | undefined;
  outcome: SSVCOutcome | null | undefined;
}

export function SSVCMatrix({ exploitation, automatable, technicalImpact, missionPrevalence, outcome }: SSVCMatrixProps) {
  const rows = [
    { label: "Exploitation",       value: exploitation },
    { label: "Automatable",        value: automatable },
    { label: "Technical Impact",   value: technicalImpact },
    { label: "Mission Prevalence", value: missionPrevalence },
  ];

  return (
    <div className="rounded-lg border border-line bg-surface-2 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted">SSVC Triage</p>
        <SSVCBadge outcome={outcome} exploitation={exploitation} automatable={automatable} />
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        {rows.map(({ label, value }) => (
          <div key={label} className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted">{label}</span>
            <span className={clsx(
              "text-xs font-medium capitalize",
              value === "active"  ? "text-red-600" :
              value === "poc"     ? "text-orange-500" :
              value === "yes"     ? "text-orange-500" :
              value === "total"   ? "text-red-600" :
              value === "critical"? "text-red-600" :
              "text-fg"
            )}>
              {value ?? "—"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
