/**
 * Token store — the single owner of the access/refresh token pair.
 *
 * Persisted to localStorage so a reload keeps the session. `api.ts` reads the access token to
 * attach `Authorization: Bearer`, rotates the pair on a 401 refresh, and clears it when refresh
 * fails; the WS hook reads the access token for its auth frame; the auth context subscribes to
 * broadcast changes so a clear (logout, or a refresh that failed in another tab) tears the UI
 * down everywhere. Kept deliberately separate from `api.ts` to avoid an import cycle.
 */

import type { TokenPairOut } from "./types";

const ACCESS_KEY = "cynux.access_token";
const REFRESH_KEY = "cynux.refresh_token";

export interface StoredTokens {
  accessToken: string;
  refreshToken: string;
}

type Listener = (tokens: StoredTokens | null) => void;

const listeners = new Set<Listener>();

/** Guard every access — this module is imported by code that runs during SSR. */
function hasWindow(): boolean {
  return typeof window !== "undefined";
}

export function getTokens(): StoredTokens | null {
  if (!hasWindow()) return null;
  const accessToken = window.localStorage.getItem(ACCESS_KEY);
  const refreshToken = window.localStorage.getItem(REFRESH_KEY);
  if (!accessToken || !refreshToken) return null;
  return { accessToken, refreshToken };
}

export function getAccessToken(): string | null {
  return getTokens()?.accessToken ?? null;
}

export function getRefreshToken(): string | null {
  return getTokens()?.refreshToken ?? null;
}

function emit(tokens: StoredTokens | null): void {
  for (const listener of listeners) listener(tokens);
}

/** Persist a fresh pair from any endpoint that returns `TokenPairOut`. */
export function setTokens(pair: Pick<TokenPairOut, "access_token" | "refresh_token">): void {
  if (!hasWindow()) return;
  window.localStorage.setItem(ACCESS_KEY, pair.access_token);
  window.localStorage.setItem(REFRESH_KEY, pair.refresh_token);
  emit({ accessToken: pair.access_token, refreshToken: pair.refresh_token });
}

export function clearTokens(): void {
  if (!hasWindow()) return;
  window.localStorage.removeItem(ACCESS_KEY);
  window.localStorage.removeItem(REFRESH_KEY);
  emit(null);
}

/**
 * Subscribe to token changes in this tab, plus cross-tab `storage` events so a logout or
 * refresh in one tab propagates to the others. Returns an unsubscribe function.
 */
export function subscribeTokens(listener: Listener): () => void {
  listeners.add(listener);

  const onStorage = (event: StorageEvent) => {
    if (event.key === ACCESS_KEY || event.key === REFRESH_KEY || event.key === null) {
      listener(getTokens());
    }
  };
  if (hasWindow()) window.addEventListener("storage", onStorage);

  return () => {
    listeners.delete(listener);
    if (hasWindow()) window.removeEventListener("storage", onStorage);
  };
}
