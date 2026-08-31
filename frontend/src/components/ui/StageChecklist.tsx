import * as React from "react";

import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/cn";
import { formatDateTime } from "@/lib/format";
import type { StageOut, StepStatus } from "@/lib/types";

/**
 * FR-038 progress tracker — the ordered stage checklist for an assessment. Fed the
 * `AssessmentDetailOut.stages` array (already ordered by the backend); renders one row per stage
 * with a status glyph, so an operator can see exactly where a run is and what degraded.
 */

const STATUS_GLYPH: Record<StepStatus, React.ReactNode> = {
  completed: <CheckIcon className="text-ok" />,
  running: <Spinner className="h-3.5 w-3.5 text-primary" />,
  failed: <CrossIcon className="text-danger" />,
  degraded: <WarnIcon className="text-warn" />,
  skipped: <DashIcon className="text-faint" />,
  pending: <CircleIcon className="text-faint" />,
};

const STATUS_TEXT: Record<StepStatus, string> = {
  completed: "text-fg",
  running: "text-fg font-medium",
  failed: "text-danger",
  degraded: "text-warn",
  skipped: "text-faint line-through",
  pending: "text-muted",
};

export function StageChecklist({
  stages,
  className,
}: {
  stages: StageOut[];
  className?: string;
}) {
  if (stages.length === 0) return null;
  return (
    <ol className={cn("space-y-0", className)}>
      {stages.map((stage, index) => {
        const timestamp = stage.completed_at ?? stage.started_at;
        return (
          <li
            key={`${stage.stage}-${index}`}
            className="flex items-start gap-3 border-b border-line/60 py-2.5 last:border-0"
          >
            <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center">
              {STATUS_GLYPH[stage.status]}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-3">
                <span className={cn("truncate text-sm", STATUS_TEXT[stage.status])}>
                  {stage.label}
                </span>
                {timestamp && (
                  <span className="shrink-0 text-xs text-faint">{formatDateTime(timestamp)}</span>
                )}
              </div>
              {stage.detail && <p className="mt-0.5 text-xs text-muted">{stage.detail}</p>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

// --- Inline glyphs ----------------------------------------------------------

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={cn("h-4 w-4", className)} fill="none" aria-hidden="true">
      <path
        d="M13 4.5 6.5 11 3 7.5"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CrossIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={cn("h-3.5 w-3.5", className)} fill="none" aria-hidden="true">
      <path
        d="M4 4l8 8M12 4l-8 8"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
      />
    </svg>
  );
}

function WarnIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={cn("h-4 w-4", className)} fill="currentColor" aria-hidden="true">
      <path d="M8 1.5 15 14H1L8 1.5Z" opacity="0.9" />
      <rect x="7.25" y="6" width="1.5" height="4" rx="0.75" fill="#171f30" />
      <circle cx="8" cy="11.75" r="0.85" fill="#171f30" />
    </svg>
  );
}

function DashIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={cn("h-4 w-4", className)} fill="none" aria-hidden="true">
      <path d="M3.5 8h9" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

function CircleIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={cn("h-3.5 w-3.5", className)} fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="5" stroke="currentColor" strokeWidth="1.5" strokeDasharray="2 2" />
    </svg>
  );
}
