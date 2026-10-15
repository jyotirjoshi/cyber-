"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { Card, CardBody } from "@/components/ui/Card";
import { InlineError } from "@/components/ui/States";
import { api } from "@/lib/api";
import { setTokens } from "@/lib/tokens";

/** Complete the short-lived opaque handoff from the backend OIDC callback. */
export default function SsoCallbackPage() {
  const router = useRouter();
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const handoff = new URLSearchParams(window.location.hash.slice(1)).get("ticket");
    if (!handoff) {
      setError("The SSO handoff is missing. Start sign-in again from your organization login.");
      return;
    }
    void api.auth.exchangeSso(handoff)
      .then((tokens) => {
        setTokens(tokens);
        // Remove the opaque handoff from browser history before entering the workspace.
        window.history.replaceState(null, "", "/sso/callback");
        router.replace("/dashboard");
      })
      .catch(() => setError("The SSO handoff expired or was already used. Start sign-in again."));
  }, [router]);

  return <main className="mx-auto flex min-h-screen max-w-md items-center px-5"><Card className="w-full"><CardBody className="space-y-3"><h1 className="text-lg font-semibold text-fg">Completing secure sign-in</h1>{error ? <InlineError message={error} /> : <p className="text-sm text-muted">Verifying your identity and opening your workspace…</p>}</CardBody></Card></main>;
}
