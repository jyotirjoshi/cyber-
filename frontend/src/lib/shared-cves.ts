export function sharedCves(left: string[], right: string[]): string[] {
  const known = new Set(left.map((cve) => cve.trim().toUpperCase()));
  return [...new Set(right.map((cve) => cve.trim().toUpperCase()))]
    .filter((cve) => cve && known.has(cve));
}
