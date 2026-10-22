import { AuthGate } from "@/components/auth/AuthGate";
import { AppShell } from "@/components/layout/AppShell";

// Authenticated HTML must always come from the active Cloud Run revision. Caching a
// prerendered shell across deployments leaves it pointing at chunks from an old image.
export const dynamic = "force-dynamic";

/** Layout for every authenticated screen: guard the session, then frame it in the app shell. */
export default function AppGroupLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGate>
      <AppShell>{children}</AppShell>
    </AuthGate>
  );
}
