import type { BadgeTone } from "@/components/ui/Badge";

export function readinessTone(value: { ready: boolean; score: number }): BadgeTone {
  if (value.ready) return "ok";
  return value.score >= 70 ? "warn" : "danger";
}

export function readinessProgress(value: { passed: number; total: number }): string {
  return `${value.passed} of ${value.total} controls ready`;
}
