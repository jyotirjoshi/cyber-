/** Permit only browser-safe links supplied by external security tools. */
export function safeExternalUrl(value: string | null): string | null {
  if (!value || value !== value.trim() || /[\u0000-\u001f\\]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname) return null;
    if (url.username || url.password) return null;
    return value;
  } catch {
    return null;
  }
}
