"use client";

/**
 * Risk Heatmap — 5x5 likelihood × impact matrix.
 *
 * Cells are colored by combined risk score. Each cell shows the count of findings
 * that fall into that quadrant. Click a cell to filter the findings list.
 */

import * as React from "react";
import { clsx } from "clsx";

export interface HeatmapCell {
  likelihood: 1 | 2 | 3 | 4 | 5;
  impact: 1 | 2 | 3 | 4 | 5;
  count: number;
  findingIds?: string[];
}

interface RiskHeatmapProps {
  cells: HeatmapCell[];
  onCellClick?: (cell: HeatmapCell) => void;
  className?: string;
}

const LIKELIHOOD_LABELS = ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"];
const IMPACT_LABELS = ["Negligible", "Minor", "Moderate", "Major", "Critical"];

function riskScore(likelihood: number, impact: number): number {
  return likelihood * impact;
}

function cellColor(score: number): string {
  if (score >= 20) return "bg-red-600 text-white";
  if (score >= 15) return "bg-orange-500 text-white";
  if (score >= 10) return "bg-yellow-400 text-gray-900";
  if (score >= 5)  return "bg-green-400 text-gray-900";
  return "bg-green-200 text-gray-700";
}

function cellLabel(score: number): string {
  if (score >= 20) return "Critical";
  if (score >= 15) return "High";
  if (score >= 10) return "Medium";
  if (score >= 5)  return "Low";
  return "Minimal";
}

export function RiskHeatmap({ cells, onCellClick, className }: RiskHeatmapProps) {
  // Build a lookup map: (likelihood, impact) → count
  const cellMap = React.useMemo(() => {
    const map = new Map<string, HeatmapCell>();
    for (const cell of cells) {
      map.set(`${cell.likelihood},${cell.impact}`, cell);
    }
    return map;
  }, [cells]);

  return (
    <div className={clsx("space-y-2", className)}>
      <div className="flex items-center gap-2">
        <div
          className="flex flex-col items-center justify-center"
          style={{ writingMode: "vertical-lr", transform: "rotate(180deg)", height: 200 }}
        >
          <span className="text-xs font-medium uppercase tracking-wide text-muted">Impact →</span>
        </div>

        <div className="flex-1">
          {/* Grid: impact rows (5 down to 1), likelihood cols (1 to 5) */}
          <div className="grid gap-1" style={{ gridTemplateColumns: "auto repeat(5, 1fr)" }}>
            {/* Top-left corner label */}
            <div />
            {LIKELIHOOD_LABELS.map((l, i) => (
              <div key={i} className="text-center text-xs text-muted pb-1 truncate">
                {l}
              </div>
            ))}

            {/* Rows: impact high → low */}
            {[5, 4, 3, 2, 1].map((impact) => (
              <React.Fragment key={impact}>
                {/* Row label */}
                <div className="flex items-center justify-end pr-2 text-xs text-muted">
                  {IMPACT_LABELS[impact - 1]}
                </div>
                {/* Cells */}
                {[1, 2, 3, 4, 5].map((likelihood) => {
                  const score = riskScore(likelihood, impact as 1 | 2 | 3 | 4 | 5);
                  const cell = cellMap.get(`${likelihood},${impact}`);
                  const count = cell?.count ?? 0;

                  return (
                    <button
                      key={likelihood}
                      type="button"
                      onClick={() => cell && onCellClick?.(cell)}
                      className={clsx(
                        "rounded p-2 min-h-[48px] flex flex-col items-center justify-center",
                        "text-xs font-medium transition-opacity",
                        cellColor(score),
                        count > 0 ? "opacity-100" : "opacity-30",
                        count > 0 && onCellClick ? "cursor-pointer hover:opacity-80" : "cursor-default",
                      )}
                      title={`${cellLabel(score)} risk (${likelihood}×${impact}): ${count} finding${count !== 1 ? "s" : ""}`}
                      aria-label={`${cellLabel(score)} risk quadrant, ${count} findings`}
                    >
                      {count > 0 && (
                        <span className="text-sm font-bold tabular-nums">{count}</span>
                      )}
                      <span className="text-[10px] opacity-75">{score}</span>
                    </button>
                  );
                })}
              </React.Fragment>
            ))}
          </div>

          {/* X-axis label */}
          <div className="mt-1 text-center text-xs font-medium uppercase tracking-wide text-muted">
            Likelihood →
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 pt-1">
        {[
          { label: "Critical (20–25)", color: "bg-red-600" },
          { label: "High (15–19)",     color: "bg-orange-500" },
          { label: "Medium (10–14)",   color: "bg-yellow-400" },
          { label: "Low (5–9)",        color: "bg-green-400" },
          { label: "Minimal (1–4)",    color: "bg-green-200" },
        ].map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5 text-xs text-muted">
            <span className={clsx("inline-block h-3 w-3 rounded", color)} />
            {label}
          </div>
        ))}
      </div>
    </div>
  );
}
