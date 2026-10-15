"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { Field, Input } from "@/components/ui/Input";
import { InlineError } from "@/components/ui/States";
import { useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fieldError } from "@/lib/errors";

function LoginForm() {
  const { login } = useAuth();
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/dashboard";

  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [organizationSlug, setOrganizationSlug] = React.useState("");

  const { run, loading, error, errorMessage } = useMutation(
    (body: { email: string; password: string }) => login(body),
    { onSuccess: () => router.replace(next) },
  );

  return (
    <Card>
      <CardBody className="space-y-5">
        <div>
          <h1 className="text-lg font-semibold text-fg">Sign in</h1>
          <p className="mt-1 text-sm text-muted">Access your security assessments.</p>
        </div>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            void run({ email, password });
          }}
        >
          <InlineError message={fieldError(error, "email") ? null : errorMessage} />

          <Field label="Email" htmlFor="email" required error={fieldError(error, "email")}>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>

          <Field label="Password" htmlFor="password" required error={fieldError(error, "password")}>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>

          <Button type="submit" className="w-full" loading={loading}>
            Sign in
          </Button>
        </form>

        <div className="border-t border-line pt-5">
          <p className="text-sm font-medium text-fg">Sign in with your organization identity provider</p>
          <p className="mt-1 text-xs text-muted">Enter the organization slug configured by your administrator.</p>
          <div className="mt-3 grid gap-2 sm:grid-cols-[1fr_auto_auto]">
            <Input aria-label="Organization slug" value={organizationSlug} onChange={(event) => setOrganizationSlug(event.target.value)} placeholder="acme-security" />
            <Button type="button" variant="outline" disabled={!organizationSlug.trim()} onClick={() => window.location.assign(api.auth.ssoStartUrl(organizationSlug.trim()))}>OIDC SSO</Button>
            <Button type="button" variant="outline" disabled={!organizationSlug.trim()} onClick={() => window.location.assign(api.auth.samlSsoStartUrl(organizationSlug.trim()))}>SAML SSO</Button>
          </div>
        </div>

        <p className="text-center text-sm text-muted">
          No account?{" "}
          <Link href="/register" className="text-primary hover:underline">
            Create one
          </Link>
        </p>
      </CardBody>
    </Card>
  );
}

export default function LoginPage() {
  // useSearchParams requires a Suspense boundary during prerender in the App Router.
  return (
    <React.Suspense fallback={null}>
      <LoginForm />
    </React.Suspense>
  );
}
