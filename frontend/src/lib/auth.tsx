"use client";

/**
 * Auth context — holds the authenticated identity ({@link MeOut}) and the session lifecycle.
 *
 * Sign-in endpoints return only a token pair; identity/role/permissions come from a follow-up
 * `GET /auth/me`. So every credential mutation here is "store the pair, then reload me". The
 * token store is the source of truth for *being* logged in; this context is the source of truth
 * for *who* — and it subscribes to the store so a token clear anywhere (an explicit logout, or a
 * refresh that failed inside `api.ts`) tears the session down.
 */

import * as React from "react";

import { api } from "./api";
import { clearTokens, getRefreshToken, getTokens, setTokens, subscribeTokens } from "./tokens";
import type {
  LoginIn,
  MeOut,
  MembershipOut,
  Permission,
  RegisterIn,
  Role,
  UserOut,
} from "./types";

export type AuthStatus = "loading" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  status: AuthStatus;
  me: MeOut | null;
  user: UserOut | null;
  organizations: MembershipOut[];
  activeOrganizationId: string | null;
  activeRole: Role | null;
  permissions: Permission[];
  login: (body: LoginIn) => Promise<void>;
  register: (body: RegisterIn) => Promise<void>;
  logout: () => Promise<void>;
  switchOrganization: (organizationId: string) => Promise<void>;
  reload: () => Promise<void>;
  can: (permission: Permission) => boolean;
}

const AuthContext = React.createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = React.useState<AuthStatus>("loading");
  const [me, setMe] = React.useState<MeOut | null>(null);

  const reload = React.useCallback(async () => {
    if (!getTokens()) {
      setMe(null);
      setStatus("unauthenticated");
      return;
    }
    try {
      const next = await api.auth.me();
      setMe(next);
      setStatus("authenticated");
    } catch {
      // A failed /auth/me (after the built-in refresh attempt) means the session is dead.
      setMe(null);
      setStatus("unauthenticated");
    }
  }, []);

  // Initial bootstrap from any persisted tokens.
  React.useEffect(() => {
    void reload();
  }, [reload]);

  // Tear down when the token store is cleared (logout elsewhere, or refresh failure in api.ts).
  React.useEffect(
    () =>
      subscribeTokens((tokens) => {
        if (!tokens) {
          setMe(null);
          setStatus("unauthenticated");
        }
      }),
    [],
  );

  const login = React.useCallback(
    async (body: LoginIn) => {
      const pair = await api.auth.login(body);
      setTokens(pair);
      await reload();
    },
    [reload],
  );

  const register = React.useCallback(
    async (body: RegisterIn) => {
      const pair = await api.auth.register(body);
      setTokens(pair);
      await reload();
    },
    [reload],
  );

  const logout = React.useCallback(async () => {
    try {
      await api.auth.logout({ refresh_token: getRefreshToken() ?? undefined });
    } catch {
      // Best effort — the local clear below is what actually ends the session.
    }
    clearTokens();
    setMe(null);
    setStatus("unauthenticated");
  }, []);

  const switchOrganization = React.useCallback(
    async (organizationId: string) => {
      const pair = await api.auth.switchOrganization({ organization_id: organizationId });
      setTokens(pair);
      await reload();
    },
    [reload],
  );

  const can = React.useCallback(
    (permission: Permission) => me?.permissions.includes(permission) ?? false,
    [me],
  );

  const value = React.useMemo<AuthContextValue>(
    () => ({
      status,
      me,
      user: me?.user ?? null,
      organizations: me?.organizations ?? [],
      activeOrganizationId: me?.active_organization_id ?? null,
      activeRole: me?.active_role ?? null,
      permissions: me?.permissions ?? [],
      login,
      register,
      logout,
      switchOrganization,
      reload,
      can,
    }),
    [status, me, login, register, logout, switchOrganization, reload, can],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = React.useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an <AuthProvider>");
  return ctx;
}
