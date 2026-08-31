"use client";

import * as React from "react";

import { ToastProvider } from "@/components/ui/Toast";
import { AuthProvider } from "@/lib/auth";

/** Client provider stack mounted once at the root: auth session + toast surface. */
export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <ToastProvider>{children}</ToastProvider>
    </AuthProvider>
  );
}
