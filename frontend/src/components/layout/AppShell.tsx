"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/cn";
import { useAuth } from "@/lib/auth";
import { humanize } from "@/lib/format";
import type { Permission } from "@/lib/types";

/**
 * App shell — the persistent frame (sidebar nav + topbar) around every authenticated screen.
 * Nav entries are filtered by the caller's permissions so the sidebar only shows what the role
 * can reach; the topbar carries the org switcher and sign-out.
 */

interface NavItem {
  href: string;
  label: string;
  icon: React.ReactNode;
  permission?: Permission;
}

const NAV: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: <IconDashboard /> },
  { href: "/agent", label: "Agent", icon: <IconAgent />, permission: "agent:chat" },
  { href: "/assessments", label: "Assessments", icon: <IconAssessments />, permission: "assessment:read" },
  { href: "/findings", label: "Findings", icon: <IconFindings />, permission: "finding:read" },
  { href: "/assets", label: "Assets", icon: <IconAssets />, permission: "asset:read" },
  { href: "/jobs", label: "Scanner jobs", icon: <IconJobs />, permission: "assessment:read" },
  { href: "/integrations", label: "Integrations", icon: <IconIntegrations />, permission: "integration:read" },
  { href: "/audit", label: "Audit log", icon: <IconAudit />, permission: "audit:read" },
  { href: "/settings/organization", label: "Organization", icon: <IconSettings />, permission: "org:read" },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const { can } = useAuth();
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const pathname = usePathname();

  // Close the mobile drawer on navigation.
  React.useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  const items = NAV.filter((item) => !item.permission || can(item.permission));

  return (
    <div className="min-h-screen">
      {/* Sidebar (fixed on lg; drawer on mobile) */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-line bg-surface transition-transform lg:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-14 items-center gap-2 border-b border-line px-5">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/15 text-primary">
            <IconLogo />
          </span>
          <span className="text-sm font-semibold tracking-wide text-fg">CYNUX</span>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
          {items.map((item) => {
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-primary/10 font-medium text-primary"
                    : "text-muted hover:bg-surface-2 hover:text-fg",
                )}
              >
                <span className="flex h-4 w-4 items-center justify-center">{item.icon}</span>
                {item.label}
              </Link>
            );
          })}
        </nav>

        <IdentityCard />
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Content column */}
      <div className="flex min-h-screen flex-col lg:pl-60">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-bg/80 px-4 backdrop-blur sm:px-6">
          <button
            type="button"
            className="text-muted hover:text-fg lg:hidden"
            onClick={() => setMobileOpen((open) => !open)}
            aria-label="Toggle navigation"
          >
            <IconMenu />
          </button>
          <div className="flex-1" />
          <OrgSwitcher />
          <SignOutButton />
        </header>

        <main className="flex-1">
          <div className="container-app py-6">{children}</div>
        </main>
      </div>
    </div>
  );
}

function IdentityCard() {
  const { user, activeRole } = useAuth();
  if (!user) return null;
  return (
    <div className="border-t border-line px-4 py-3">
      <p className="truncate text-sm font-medium text-fg" title={user.email}>
        {user.full_name || user.email}
      </p>
      <div className="mt-1 flex items-center gap-2">
        {activeRole && <Badge tone="neutral">{humanize(activeRole)}</Badge>}
      </div>
    </div>
  );
}

function OrgSwitcher() {
  const { organizations, activeOrganizationId, switchOrganization } = useAuth();
  const [busy, setBusy] = React.useState(false);

  if (organizations.length <= 1) {
    const only = organizations[0];
    return only ? (
      <span className="hidden max-w-[12rem] truncate text-sm text-muted sm:block">
        {only.organization_name}
      </span>
    ) : null;
  }

  return (
    <select
      value={activeOrganizationId ?? ""}
      disabled={busy}
      onChange={async (event) => {
        setBusy(true);
        try {
          await switchOrganization(event.target.value);
        } finally {
          setBusy(false);
        }
      }}
      className="h-9 rounded-lg border border-line bg-surface-2 px-2 text-sm text-fg disabled:opacity-60"
      aria-label="Active organization"
    >
      {organizations.map((org) => (
        <option key={org.organization_id} value={org.organization_id}>
          {org.organization_name}
        </option>
      ))}
    </select>
  );
}

function SignOutButton() {
  const { logout } = useAuth();
  const [busy, setBusy] = React.useState(false);
  return (
    <button
      type="button"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        await logout();
      }}
      className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-muted transition-colors hover:bg-surface-2 hover:text-fg disabled:opacity-60"
    >
      <IconSignOut />
      <span className="hidden sm:inline">Sign out</span>
    </button>
  );
}

// --- Icons (16px line set) --------------------------------------------------

function svg(path: React.ReactNode) {
  return (
    <svg viewBox="0 0 20 20" className="h-full w-full" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {path}
    </svg>
  );
}

function IconLogo() {
  return (
    <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <path d="M10 2 3 5v5c0 4 3 6.5 7 8 4-1.5 7-4 7-8V5l-7-3Z" strokeLinejoin="round" />
    </svg>
  );
}
function IconDashboard() {
  return svg(<><rect x="3" y="3" width="6" height="6" rx="1" /><rect x="11" y="3" width="6" height="6" rx="1" /><rect x="3" y="11" width="6" height="6" rx="1" /><rect x="11" y="11" width="6" height="6" rx="1" /></>);
}
function IconAgent() {
  return svg(<><rect x="4" y="6" width="12" height="9" rx="2" /><path d="M10 3v3M7 10h.01M13 10h.01" /></>);
}
function IconAssessments() {
  return svg(<><path d="M5 3h7l3 3v11H5V3Z" /><path d="M12 3v3h3M8 11h4M8 14h4" /></>);
}
function IconFindings() {
  return svg(<><path d="M10 2 3 5v5c0 4 3 6.5 7 8 4-1.5 7-4 7-8V5l-7-3Z" /><path d="M10 8v3M10 13h.01" /></>);
}
function IconAssets() {
  return svg(<><rect x="3" y="4" width="14" height="5" rx="1" /><rect x="3" y="11" width="14" height="5" rx="1" /><path d="M6 6.5h.01M6 13.5h.01" /></>);
}
function IconJobs() {
  return svg(<><circle cx="10" cy="10" r="3" /><path d="M10 3v2M10 15v2M3 10h2M15 10h2M5 5l1.5 1.5M13.5 13.5 15 15M15 5l-1.5 1.5M6.5 13.5 5 15" /></>);
}
function IconIntegrations() {
  return svg(<><path d="M8 4 4 8l4 4M12 8l4 4-4 4" /><path d="M11 5l-2 10" /></>);
}
function IconAudit() {
  return svg(<><path d="M4 4h12v12H4z" /><path d="M7 8h6M7 11h6M7 14h3" /></>);
}
function IconSettings() {
  return svg(<><circle cx="10" cy="10" r="2.5" /><path d="M10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.6 4.6l1.4 1.4M14 14l1.4 1.4M15.4 4.6 14 6M6 14l-1.4 1.4" /></>);
}
function IconMenu() {
  return <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true"><path d="M3 6h14M3 10h14M3 14h14" /></svg>;
}
function IconSignOut() {
  return <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M8 4H5v12h3M13 7l3 3-3 3M16 10H8" /></svg>;
}
