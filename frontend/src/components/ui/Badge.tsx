import * as React from "react";

import { cn } from "@/lib/cn";
import type {
  AssessmentStatus,
  AssetStatus,
  Criticality,
  EnrichmentStatus,
  FindingStatus,
  JobStatus,
  Priority,
  RiskLevel,
  Severity,
} from "@/lib/types";

/**
 * Status vocabulary — the one place enum values become colored pills. Screens import these
 * badges rather than re-mapping enums to Tailwind classes, so a severity is the same red
 * everywhere. Class strings are written out in full (never interpolated) so Tailwind's JIT
 * keeps them.
 */

export type BadgeTone =
  | "neutral"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "ok"
  | "warn"
  | "danger"
  | "primary";

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: "bg-surface-2 text-muted border-line",
  critical: "bg-sev-critical/10 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/10 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/10 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/10 text-sev-low border-sev-low/30",
  info: "bg-sev-info/10 text-sev-info border-sev-info/30",
  ok: "bg-ok/10 text-ok border-ok/30",
  warn: "bg-warn/10 text-warn border-warn/30",
  danger: "bg-danger/10 text-danger border-danger/30",
  primary: "bg-primary/10 text-primary border-primary/30",
};

const DOT_CLASSES: Record<BadgeTone, string> = {
  neutral: "bg-faint",
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
  ok: "bg-ok",
  warn: "bg-warn",
  danger: "bg-danger",
  primary: "bg-primary",
};

export function Badge({
  tone = "neutral",
  dot = false,
  pulse = false,
  className,
  children,
}: {
  tone?: BadgeTone;
  dot?: boolean;
  pulse?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium",
        TONE_CLASSES[tone],
        className,
      )}
    >
      {dot && (
        <span
          className={cn("h-1.5 w-1.5 rounded-full", DOT_CLASSES[tone], pulse && "animate-pulse")}
          aria-hidden="true"
        />
      )}
      {children}
    </span>
  );
}

// --- Severity ---------------------------------------------------------------

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge tone={SEVERITY_TONE[severity]} className={className}>
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}

// --- Priority ---------------------------------------------------------------

const PRIORITY_TONE: Record<Priority, BadgeTone> = {
  P1: "critical",
  P2: "high",
  P3: "medium",
  P4: "low",
  P5: "neutral",
};

export function PriorityBadge({ priority, className }: { priority: Priority; className?: string }) {
  return (
    <Badge tone={PRIORITY_TONE[priority]} className={className}>
      {priority}
    </Badge>
  );
}

// --- Risk level (agent tool risk) -------------------------------------------

const RISK_TONE: Record<RiskLevel, BadgeTone> = {
  low: "low",
  medium: "medium",
  high: "high",
  forbidden: "danger",
};

const RISK_LABEL: Record<RiskLevel, string> = {
  low: "Low risk",
  medium: "Medium risk",
  high: "High risk",
  forbidden: "Forbidden",
};

export function RiskBadge({ risk, className }: { risk: RiskLevel; className?: string }) {
  return (
    <Badge tone={RISK_TONE[risk]} className={className}>
      {RISK_LABEL[risk]}
    </Badge>
  );
}

// --- Assessment status ------------------------------------------------------

interface StatusMeta {
  tone: BadgeTone;
  label: string;
  active?: boolean;
}

const ASSESSMENT_STATUS: Record<AssessmentStatus, StatusMeta> = {
  CREATED: { tone: "neutral", label: "Created" },
  PLANNING: { tone: "primary", label: "Planning", active: true },
  DISCOVERY: { tone: "primary", label: "Discovery", active: true },
  WAITING_FOR_APPROVAL: { tone: "warn", label: "Awaiting approval", active: true },
  SCANNING: { tone: "primary", label: "Scanning", active: true },
  ANALYZING: { tone: "primary", label: "Analyzing", active: true },
  REMEDIATING: { tone: "primary", label: "Remediating", active: true },
  COMPLETED: { tone: "ok", label: "Completed" },
  FAILED: { tone: "danger", label: "Failed" },
  CANCELLING: { tone: "warn", label: "Cancelling", active: true },
  CANCELLED: { tone: "neutral", label: "Cancelled" },
};

export function AssessmentStatusBadge({
  status,
  className,
}: {
  status: AssessmentStatus;
  className?: string;
}) {
  const meta = ASSESSMENT_STATUS[status];
  return (
    <Badge tone={meta.tone} dot={meta.active} pulse={meta.active} className={className}>
      {meta.label}
    </Badge>
  );
}

// --- Scanner job status -----------------------------------------------------

const JOB_STATUS: Record<JobStatus, StatusMeta> = {
  QUEUED: { tone: "neutral", label: "Queued" },
  RUNNING: { tone: "primary", label: "Running", active: true },
  COMPLETED: { tone: "ok", label: "Completed" },
  FAILED: { tone: "danger", label: "Failed" },
  CANCELLED: { tone: "neutral", label: "Cancelled" },
  TIMEOUT: { tone: "warn", label: "Timed out" },
};

export function JobStatusBadge({ status, className }: { status: JobStatus; className?: string }) {
  const meta = JOB_STATUS[status];
  return (
    <Badge tone={meta.tone} dot={meta.active} pulse={meta.active} className={className}>
      {meta.label}
    </Badge>
  );
}

// --- Finding status ---------------------------------------------------------

const FINDING_STATUS: Record<FindingStatus, StatusMeta> = {
  active: { tone: "primary", label: "Active" },
  verified: { tone: "warn", label: "Verified" },
  false_positive: { tone: "neutral", label: "False positive" },
  risk_accepted: { tone: "info", label: "Risk accepted" },
  out_of_scope: { tone: "neutral", label: "Out of scope" },
  mitigated: { tone: "ok", label: "Mitigated" },
  duplicate: { tone: "neutral", label: "Duplicate" },
};

export function FindingStatusBadge({
  status,
  className,
}: {
  status: FindingStatus;
  className?: string;
}) {
  const meta = FINDING_STATUS[status];
  return (
    <Badge tone={meta.tone} className={className}>
      {meta.label}
    </Badge>
  );
}

// --- Asset criticality + status ---------------------------------------------

const CRITICALITY_TONE: Record<Criticality, BadgeTone> = {
  critical: "critical",
  high: "high",
  normal: "neutral",
  low: "low",
  unknown: "neutral",
};

const CRITICALITY_LABEL: Record<Criticality, string> = {
  critical: "Critical",
  high: "High",
  normal: "Normal",
  low: "Low",
  unknown: "Unknown",
};

export function CriticalityBadge({
  criticality,
  className,
}: {
  criticality: Criticality;
  className?: string;
}) {
  return (
    <Badge tone={CRITICALITY_TONE[criticality]} className={className}>
      {CRITICALITY_LABEL[criticality]}
    </Badge>
  );
}

const ASSET_STATUS: Record<AssetStatus, StatusMeta> = {
  active: { tone: "ok", label: "Active" },
  inactive: { tone: "neutral", label: "Inactive" },
  unreachable: { tone: "warn", label: "Unreachable" },
  out_of_scope: { tone: "neutral", label: "Out of scope" },
};

export function AssetStatusBadge({
  status,
  className,
}: {
  status: AssetStatus;
  className?: string;
}) {
  const meta = ASSET_STATUS[status];
  return (
    <Badge tone={meta.tone} className={className}>
      {meta.label}
    </Badge>
  );
}

// --- KEV (tri-state) --------------------------------------------------------

/**
 * FR-020: `in_kev` is tri-state. `true` → confirmed exploited (danger). `null` → intel was
 * unavailable and we must NOT imply "safe" — render an explicit "unknown". `false` is only shown
 * when asked, and never dressed up as reassurance.
 */
export function KevBadge({
  inKev,
  showNegative = false,
  className,
}: {
  inKev: boolean | null;
  showNegative?: boolean;
  className?: string;
}) {
  if (inKev === true) {
    return (
      <Badge tone="danger" className={className}>
        KEV — known exploited
      </Badge>
    );
  }
  if (inKev === null) {
    return (
      <Badge tone="neutral" className={className}>
        KEV status unknown
      </Badge>
    );
  }
  if (!showNegative) return null;
  return (
    <Badge tone="neutral" className={className}>
      Not in KEV
    </Badge>
  );
}

// --- Threat-intel enrichment status -----------------------------------------

const ENRICHMENT: Record<EnrichmentStatus, StatusMeta> = {
  pending: { tone: "neutral", label: "Pending" },
  complete: { tone: "ok", label: "Complete" },
  partial: { tone: "warn", label: "Partial" },
  unavailable: { tone: "neutral", label: "Unavailable" },
  not_applicable: { tone: "neutral", label: "N/A" },
};

export function EnrichmentBadge({
  status,
  className,
}: {
  status: EnrichmentStatus;
  className?: string;
}) {
  const meta = ENRICHMENT[status];
  return (
    <Badge tone={meta.tone} className={className}>
      {meta.label}
    </Badge>
  );
}
