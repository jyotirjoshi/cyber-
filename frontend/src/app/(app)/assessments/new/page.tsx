"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { InlineError } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/cn";
import { fieldError } from "@/lib/errors";
import { MAX_TARGETS } from "@/lib/types";
import type { AssessmentCreateIn, AssessmentDepth, Scope } from "@/lib/types";

const OBJECTIVE_MAX = 4000;
const ATTESTATION_MAX = 4000;

/** Split raw text on the given delimiter, trim, drop empties, and dedupe preserving order. */
function parseList(raw: string, delimiter: RegExp): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of raw.split(delimiter)) {
    const value = part.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function NewAssessmentForm() {
  const router = useRouter();
  const { toast } = useToast();

  const [targetsRaw, setTargetsRaw] = React.useState("");
  const [title, setTitle] = React.useState("");
  const [scope, setScope] = React.useState<Scope>("external");
  const [depth, setDepth] = React.useState<AssessmentDepth>("standard");
  const [objective, setObjective] = React.useState("");
  const [notifyRaw, setNotifyRaw] = React.useState("");
  const [attestationText, setAttestationText] = React.useState("");
  const [evidenceReference, setEvidenceReference] = React.useState("");
  const [confirmed, setConfirmed] = React.useState(false);

  const targets = React.useMemo(() => parseList(targetsRaw, /[\n,]/), [targetsRaw]);
  const notify = React.useMemo(() => parseList(notifyRaw, /[\s,]+/), [notifyRaw]);

  const targetCount = targets.length;
  const targetsOverLimit = targetCount > MAX_TARGETS;
  const targetsValid = targetCount >= 1 && !targetsOverLimit;
  const attestationTrimmed = attestationText.trim();
  const attestationValid =
    attestationTrimmed.length >= 1 && attestationTrimmed.length <= ATTESTATION_MAX;

  const m = useMutation((body: AssessmentCreateIn) => api.assessments.create(body), {
    onSuccess: (result) => {
      toast({ title: "Assessment created", tone: "ok" });
      router.push(`/assessments/${result.id}`);
    },
  });

  const canSubmit = targetsValid && attestationValid && confirmed && !m.loading;

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;

    const body: AssessmentCreateIn = {
      targets,
      title: title.trim() ? title.trim() : null,
      scope,
      depth,
      objective: objective.trim() ? objective.trim() : null,
      authorization: {
        confirmed,
        attestation_text: attestationTrimmed,
        evidence_reference: evidenceReference.trim() ? evidenceReference.trim() : null,
      },
    };
    if (notify.length > 0) body.notify = notify;

    void m.run(body);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="New assessment"
        description="Define the targets and confirm authorization to launch an AI-driven security assessment."
      />

      <form className="space-y-6" onSubmit={onSubmit}>
        <InlineError message={m.errorMessage} />

        <Card>
          <CardBody className="space-y-5">
            <Field label="Targets" htmlFor="targets" required error={fieldError(m.error, "targets")}>
              <Textarea
                id="targets"
                className="min-h-28 font-mono"
                placeholder={"api.example.com\n203.0.113.10\nhttps://app.example.com"}
                value={targetsRaw}
                onChange={(e) => setTargetsRaw(e.target.value)}
                aria-invalid={targetsOverLimit}
              />
              <div className="mt-1.5 flex items-center justify-between gap-3">
                <span className="text-xs text-faint">
                  One target per line or comma-separated. Duplicates are removed.
                </span>
                <span
                  className={cn(
                    "shrink-0 text-xs tabular-nums",
                    targetsOverLimit ? "text-danger" : "text-muted",
                  )}
                >
                  {targetCount} / {MAX_TARGETS}
                </span>
              </div>
              {targetsOverLimit && (
                <p className="mt-1 text-xs text-danger">
                  Too many targets — remove {targetCount - MAX_TARGETS} to continue.
                </p>
              )}
            </Field>

            <Field label="Title" htmlFor="title" hint="Optional — a short label for this assessment.">
              <Input
                id="title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Q3 external perimeter review"
              />
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Scope" htmlFor="scope">
                <Select
                  id="scope"
                  value={scope}
                  onChange={(e) => setScope(e.target.value as Scope)}
                >
                  <option value="external">External</option>
                  <option value="internal">Internal</option>
                  <option value="application">Application</option>
                  <option value="code">Code</option>
                </Select>
              </Field>

              <Field
                label="Depth"
                htmlFor="depth"
                hint="Passive runs reconnaissance only — no active scanning."
              >
                <Select
                  id="depth"
                  value={depth}
                  onChange={(e) => setDepth(e.target.value as AssessmentDepth)}
                >
                  <option value="passive">Passive</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                </Select>
              </Field>
            </div>

            <Field
              label="Objective"
              htmlFor="objective"
              hint="Describe the goal in plain language (optional)."
              error={fieldError(m.error, "objective")}
            >
              <Textarea
                id="objective"
                maxLength={OBJECTIVE_MAX}
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                placeholder="e.g. Check our public marketing site for exposed admin panels and known CVEs."
              />
            </Field>

            <Field
              label="Notify"
              htmlFor="notify"
              hint="Optional — email addresses to notify, comma or space separated."
            >
              <Input
                id="notify"
                value={notifyRaw}
                onChange={(e) => setNotifyRaw(e.target.value)}
                placeholder="alice@example.com, bob@example.com"
              />
            </Field>
          </CardBody>
        </Card>

        <Card className="border-warn/40 bg-warn/5">
          <CardHeader className="border-warn/30">
            <CardTitle className="text-warn">Authorization required</CardTitle>
          </CardHeader>
          <CardBody className="space-y-4">
            <p className="text-sm text-muted">
              CYNUX will not begin any testing without an explicit authorization attestation. The
              server rejects this request (403) unless you confirm below.
            </p>

            <Field
              label="Authorization attestation"
              htmlFor="attestation"
              required
              error={fieldError(m.error, "authorization.attestation_text")}
            >
              <Textarea
                id="attestation"
                maxLength={ATTESTATION_MAX}
                value={attestationText}
                onChange={(e) => setAttestationText(e.target.value)}
                placeholder="I confirm I am authorized to assess these targets on behalf of Acme Inc."
              />
            </Field>

            <Field
              label="Evidence reference"
              htmlFor="evidence"
              hint="Optional — ticket ID or URL recording the authorization."
            >
              <Input
                id="evidence"
                value={evidenceReference}
                onChange={(e) => setEvidenceReference(e.target.value)}
                placeholder="AUTH-1234 or https://tracker.example.com/AUTH-1234"
              />
            </Field>

            <label className="flex cursor-pointer items-start gap-2.5">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 h-4 w-4 shrink-0 cursor-pointer rounded border-line bg-surface-2 accent-primary"
              />
              <span className="text-sm text-fg">
                I am authorized to perform security testing against these targets.
              </span>
            </label>
          </CardBody>
        </Card>

        <div className="flex items-center justify-end gap-3">
          <Button
            type="button"
            variant="ghost"
            onClick={() => router.push("/assessments")}
            disabled={m.loading}
          >
            Cancel
          </Button>
          <Button type="submit" loading={m.loading} disabled={!canSubmit}>
            Create assessment
          </Button>
        </div>
      </form>
    </div>
  );
}

export default function NewAssessmentPage() {
  const { can } = useAuth();

  if (!can("assessment:create")) {
    return (
      <EmptyState title="No access" description="You don't have permission to view this." />
    );
  }

  return <NewAssessmentForm />;
}
