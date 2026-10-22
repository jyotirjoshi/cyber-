import type { BadgeTone } from "@/components/ui/Badge";

export function onboardingTone(value: { complete: boolean; percent: number }): BadgeTone {
  if (value.complete) return "ok";
  return value.percent >= 50 ? "warn" : "danger";
}

export function onboardingSummary(value: { completed: number; total: number }): string {
  return value.completed === value.total
    ? `All ${value.total} milestones complete`
    : `${value.completed} of ${value.total} milestones complete`;
}
