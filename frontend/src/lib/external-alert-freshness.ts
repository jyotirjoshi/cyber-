export function externalAlertFreshnessWarning(
  alert: { status: string; missing_sync_count: number },
): string | null {
  if (alert.status !== "open" || alert.missing_sync_count <= 0) return null;
  const count = alert.missing_sync_count;
  return `Not observed in ${count} recent complete sync${count === 1 ? "" : "s"}; confirm in the source before closing.`;
}
