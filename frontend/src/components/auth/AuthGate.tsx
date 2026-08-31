"use client";

import { usePathname, useRouter } from "next/navigation";
import * as React from "react";

import { Spinner } from "@/components/ui/Spinner";
import { useAuth } from "@/lib/auth";

/**
 * Client-side route guard for the authenticated app group. While the session bootstraps it shows
 * a full-screen spinner; once resolved it either renders the app or bounces to `/login`,
 * preserving the intended path in `?next=` so sign-in can return the user there.
 */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  React.useEffect(() => {
    if (status === "unauthenticated") {
      const next =
        pathname && pathname !== "/" ? `?next=${encodeURIComponent(pathname)}` : "";
      router.replace(`/login${next}`);
    }
  }, [status, router, pathname]);

  if (status !== "authenticated") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner className="h-6 w-6 text-primary" />
      </div>
    );
  }

  return <>{children}</>;
}
