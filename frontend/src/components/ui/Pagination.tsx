"use client";

import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";
import { formatNumber } from "@/lib/format";
import type { PageMeta } from "@/lib/types";

/**
 * Offset/limit pager driven by a {@link PageMeta}. Emits the next `offset`; the parent owns the
 * query state and refetches. Hidden entirely when a single page covers everything.
 */
export function Pagination({
  meta,
  onOffsetChange,
  className,
}: {
  meta: PageMeta;
  onOffsetChange: (offset: number) => void;
  className?: string;
}) {
  const { total, limit, offset, has_more } = meta;
  const hasPrev = offset > 0;
  if (!hasPrev && !has_more) return null;

  const first = total === 0 ? 0 : offset + 1;
  const last = offset + Math.min(limit, Math.max(total - offset, 0));

  return (
    <div className={cn("flex items-center justify-between gap-4 text-sm text-muted", className)}>
      <span>
        {formatNumber(first)}–{formatNumber(last)} of {formatNumber(total)}
      </span>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={!hasPrev}
          onClick={() => onOffsetChange(Math.max(0, offset - limit))}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={!has_more}
          onClick={() => onOffsetChange(offset + limit)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
