"use client";

import Link from "next/link";
import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { useApiResource } from "@/hooks/useApi";
import { useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { onboardingSummary, onboardingTone } from "@/lib/onboarding";
import { useToast } from "@/components/ui/Toast";
import type { DemoWorkspaceOut } from "@/lib/types";

const STEP_TONE = {
  complete: "ok",
  ready: "warn",
  blocked: "neutral",
} as const;

export default function OnboardingPage() {
  const { can } = useAuth();
  const { toast } = useToast();
  const [demoResult, setDemoResult] = React.useState<DemoWorkspaceOut | null>(null);
  const resource = useApiResource(() => api.platform.onboarding(), []);
  const demo = useMutation(() => api.platform.createDemoWorkspace(), {
    onSuccess: (result) => {
      setDemoResult(result);
      toast({ title: result.reused ? "Demo company already available" : "Demo company created", description: `${result.assets} assets · ${result.findings} findings · ${result.incidents} incident`, tone: "ok" });
      void resource.refetch();
    },
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Operational onboarding"
        description="A first-value path backed by real tenant evidence. Steps complete only when Cynux observes the required outcome."
        action={can("assessment:create") && can("report:generate") ? <Button loading={demo.loading} onClick={() => void demo.run()}>Create sample company</Button> : undefined}
      />
      {demo.errorMessage && <p role="alert" className="text-sm text-danger">{demo.errorMessage}</p>}
      {demoResult && <Card><CardBody className="flex flex-wrap items-center justify-between gap-3"><div><p className="font-medium text-fg">Cynux Demo Company is ready</p><p className="text-sm text-muted">{demoResult.assets} assets · {demoResult.findings} findings · {demoResult.tickets} ticket · {demoResult.attack_paths} attack path · {demoResult.ai_resources} AI resources</p></div><div className="flex gap-2"><Link className="text-sm font-medium text-primary hover:underline" href={`/assessments/${demoResult.assessment_id}`}>Open assessment</Link><Link className="text-sm font-medium text-primary hover:underline" href="/control-plane">Open incident</Link></div></CardBody></Card>}
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

          <Card>
            <CardHeader><CardTitle>First-value coverage · {resource.data.first_value_score}%</CardTitle></CardHeader>
            <CardBody>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {resource.data.first_value_areas.map((area) => <div key={area.key} className="rounded-lg border border-line p-3">
                  <div className="flex items-center justify-between gap-2"><span className="font-medium text-fg">{area.label}</span><Badge tone={area.achieved ? "ok" : "warn"}>{area.achieved ? "Covered" : "Gap"}</Badge></div>
                  <p className="mt-2 text-xs text-muted">{area.evidence}</p>
                  {!area.achieved && <><p className="mt-2 text-xs font-medium text-warn">{area.gap}</p><Link href={area.action_path} className="mt-3 inline-flex text-xs font-medium text-primary hover:underline">Resolve gap →</Link></>}
                </div>)}
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
