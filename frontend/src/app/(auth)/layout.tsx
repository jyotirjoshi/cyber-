"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { Spinner } from "@/components/ui/Spinner";
import { useAuth } from "@/lib/auth";

/**
 * Public auth layout — centers the sign-in / register card and bounces already-authenticated
 * visitors to the dashboard so `/login` is never shown to a live session.
 */
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const router = useRouter();

  React.useEffect(() => {
    if (status === "authenticated") router.replace("/dashboard");
  }, [status, router]);

  if (status === "loading" || status === "authenticated") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner className="h-6 w-6 text-primary" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-12">
      <div className="mb-6 flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
          <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
            <path d="M10 2 3 5v5c0 4 3 6.5 7 8 4-1.5 7-4 7-8V5l-7-3Z" strokeLinejoin="round" />
          </svg>
        </span>
        <span className="text-lg font-semibold tracking-wide text-fg">CYNUX</span>
      </div>
      <div className="w-full max-w-sm">{children}</div>
    </div>
  );
}
