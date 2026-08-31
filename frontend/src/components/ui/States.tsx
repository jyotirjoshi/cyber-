"use client";

import * as React from "react";

import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/cn";

/**
 * Shared async-state views so every screen renders "loading" and "failed" identically. Pair with
 * {@link import("@/hooks/useApi").useApiResource}: spinner while `loading`, {@link ErrorState}
 * when `error`, then the screen's own content (or {@link import("./EmptyState").EmptyState}).
 */

export function LoadingState({ label, className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center justify-center gap-3 py-16 text-muted", className)}>
      <Spinner className="h-5 w-5 text-primary" />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-xl border border-danger/30 bg-danger/5 px-6 py-12 text-center",
        className,
      )}
    >
      <p className="text-sm font-medium text-danger">{message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

/** Compact form/action error line. Nothing renders when `message` is falsy. */
export function InlineError({ message, className }: { message?: string | null; className?: string }) {
  if (!message) return null;
  return (
    <p className={cn("rounded-lg border border-danger/30 bg-danger/5 px-3 py-2 text-sm text-danger", className)}>
      {message}
    </p>
  );
}
