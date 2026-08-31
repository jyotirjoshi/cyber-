"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import * as React from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardBody } from "@/components/ui/Card";
import { Field, Input } from "@/components/ui/Input";
import { InlineError } from "@/components/ui/States";
import { useMutation } from "@/hooks/useApi";
import { useAuth } from "@/lib/auth";
import { fieldError } from "@/lib/errors";
import type { RegisterIn } from "@/lib/types";

export default function RegisterPage() {
  const { register } = useAuth();
  const router = useRouter();

  const [fullName, setFullName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [organizationName, setOrganizationName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [mismatch, setMismatch] = React.useState<string | null>(null);

  const { run, loading, error, errorMessage } = useMutation(
    (body: RegisterIn) => register(body),
    { onSuccess: () => router.replace("/dashboard") },
  );

  return (
    <Card>
      <CardBody className="space-y-5">
        <div>
          <h1 className="text-lg font-semibold text-fg">Create your account</h1>
          <p className="mt-1 text-sm text-muted">Sets up your organization and first user.</p>
        </div>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (password !== confirm) {
              setMismatch("Passwords do not match.");
              return;
            }
            setMismatch(null);
            void run({
              email,
              password,
              organization_name: organizationName,
              full_name: fullName || null,
            });
          }}
        >
          <InlineError message={errorMessage} />

          <Field label="Full name" htmlFor="full_name" error={fieldError(error, "full_name")}>
            <Input
              id="full_name"
              autoComplete="name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
            />
          </Field>

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

          <Field
            label="Organization name"
            htmlFor="organization_name"
            required
            error={fieldError(error, "organization_name")}
          >
            <Input
              id="organization_name"
              required
              minLength={2}
              value={organizationName}
              onChange={(e) => setOrganizationName(e.target.value)}
            />
          </Field>

          <Field
            label="Password"
            htmlFor="password"
            required
            hint="At least 12 characters."
            error={fieldError(error, "password")}
          >
            <Input
              id="password"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>

          <Field label="Confirm password" htmlFor="confirm" required error={mismatch ?? undefined}>
            <Input
              id="confirm"
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </Field>

          <Button type="submit" className="w-full" loading={loading}>
            Create account
          </Button>
        </form>

        <p className="text-center text-sm text-muted">
          Already have an account?{" "}
          <Link href="/login" className="text-primary hover:underline">
            Sign in
          </Link>
        </p>
      </CardBody>
    </Card>
  );
}
