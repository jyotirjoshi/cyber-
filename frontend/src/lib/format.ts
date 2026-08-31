/**
 * Presentation helpers — pure formatting only. No wire types are declared here; these turn the
 * strings/numbers that come off `types.ts` into display text. Every function null-guards to an
 * em-dash so a screen never has to.
 */

const EMPTY = "—";

const DATE_TIME = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const DATE_ONLY = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "numeric",
});

function parse(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parse(value);
  return date ? DATE_TIME.format(date) : EMPTY;
}

export function formatDate(value: string | null | undefined): string {
  const date = parse(value);
  return date ? DATE_ONLY.format(date) : EMPTY;
}

/** "just now" / "3m ago" / "2h ago" / "5d ago", falling back to an absolute date past a week. */
export function formatRelative(value: string | null | undefined): string {
  const date = parse(value);
  if (!date) return EMPTY;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days}d ago`;
  return DATE_ONLY.format(date);
}

/** Compact human duration from a second count: "2h 5m", "5m 30s", "45s". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return EMPTY;
  if (seconds < 1) return "<1s";
  const total = Math.floor(seconds);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return EMPTY;
  return value.toLocaleString("en-US");
}

/** Turn an enum wire value ("false_positive") into sentence case ("False positive"). */
export function humanize(value: string | null | undefined): string {
  if (!value) return EMPTY;
  const spaced = value.replace(/[_-]+/g, " ").trim().toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}

/** "3 findings", "1 asset" — count + correctly pluralized noun. */
export function countLabel(count: number, singular: string, plural?: string): string {
  return `${formatNumber(count)} ${pluralize(count, singular, plural)}`;
}
