import * as React from "react";

import { cn } from "@/lib/cn";

/**
 * Table primitives — thin styled wrappers over native table elements so list screens (findings,
 * assets, jobs, members, audit) share one look. The Table wrapper adds the border + horizontal
 * scroll; the rest map 1:1 to their HTML tags.
 */

export function Table({
  className,
  children,
  ...props
}: React.TableHTMLAttributes<HTMLTableElement>) {
  return (
    <div className="overflow-x-auto rounded-xl border border-line">
      <table className={cn("w-full border-collapse text-sm", className)} {...props}>
        {children}
      </table>
    </div>
  );
}

export function THead({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      className={cn(
        "border-b border-line bg-surface-2 text-left text-xs font-medium uppercase tracking-wide text-muted",
        className,
      )}
      {...props}
    >
      {children}
    </thead>
  );
}

export function TBody({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tbody className={className} {...props}>
      {children}
    </tbody>
  );
}

export function TR({
  className,
  clickable,
  children,
  ...props
}: React.HTMLAttributes<HTMLTableRowElement> & { clickable?: boolean }) {
  return (
    <tr
      className={cn(
        "border-b border-line last:border-0",
        clickable && "cursor-pointer transition-colors hover:bg-surface-2/60",
        className,
      )}
      {...props}
    >
      {children}
    </tr>
  );
}

export function TH({
  className,
  children,
  ...props
}: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={cn("whitespace-nowrap px-4 py-2.5", className)} {...props}>
      {children}
    </th>
  );
}

export function TD({
  className,
  children,
  ...props
}: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={cn("px-4 py-3 align-middle text-fg", className)} {...props}>
      {children}
    </td>
  );
}
