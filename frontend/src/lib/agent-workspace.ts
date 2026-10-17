export function workspaceQuotaPercent(usedBytes: number, maxBytes: number): number {
  if (!Number.isFinite(usedBytes) || !Number.isFinite(maxBytes) || maxBytes <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((usedBytes / maxBytes) * 100)));
}

export function workspaceManifestFilename(name: string): string {
  const safe = name.trim().replace(/[^a-zA-Z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "");
  return `${safe || "agent-workspace"}-evidence.json`;
}
