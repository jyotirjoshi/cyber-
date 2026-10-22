"use client";

import Link from "next/link";

import { Badge } from "@/components/ui/Badge";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useApiResource } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { onboardingSummary, onboardingTone } from "@/lib/onboarding";

const STEP_TONE = {
  complete: "ok",
  ready: "warn",
  blocked: "neutral",
} as const;

export default function OnboardingPage() {
  const resource = useApiResource(() => api.platform.onboarding(), []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Operational onboarding"
        description="A first-value path backed by real tenant evidence. Steps complete only when Cynux observes the required outcome."
      />
      {resource.loading && !resource.data ? (
        <LoadingState label="Evaluating onboarding progress…" />
      ) : resource.error || !resource.data ? (
        <ErrorState message={resource.error ?? "Onboarding status is unavailable."} onRetry={resource.refetch} />
      ) : (
        <>
          <Card>
            <CardBody className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-3xl font-semibold text-fg">{resource.data.percent}%</p>
                  <p className="text-sm text-muted">{onboardingSummary(resource.data)}</p>
                </div>
                <Badge tone={onboardingTone(resource.data)}>
                  {resource.data.complete ? "Operating baseline complete" : "Next action available"}
                </Badge>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-surface-2" aria-label={`${resource.data.percent}% complete`}>
                <div className="h-full bg-primary transition-all" style={{ width: `${resource.data.percent}%` }} />
              </div>
            </CardBody>
          </Card>

          <div className="space-y-3">
            {resource.data.steps.map((step, index) => (
              <Card key={step.key}>
                <CardHeader>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="text-xs font-medium uppercase tracking-wide text-muted">Milestone {index + 1}</p>
                      <CardTitle>{step.title}</CardTitle>
                    </div>
                    <Badge tone={STEP_TONE[step.status]}>{step.status}</Badge>
                  </div>
                </CardHeader>
                <CardBody className="space-y-3">
                  <p className="text-sm text-muted">{step.description}</p>
                  <p className="rounded-md border border-line bg-surface-2 px-3 py-2 text-xs text-muted">
                    Evidence: {step.evidence}
                  </p>
                  {step.status !== "blocked" && (
                    <Link className="inline-flex rounded-md bg-primary px-3 py-2 text-sm font-medium text-white hover:opacity-90" href={step.action_path}>
                      {step.status === "complete" ? "Review" : step.action_label}
                    </Link>
                  )}
                </CardBody>
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
