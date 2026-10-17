import type { EngagementStatus } from "./types";

const TRANSITIONS: Record<EngagementStatus, readonly EngagementStatus[]> = {
  draft: ["scoping", "cancelled"],
  scoping: ["draft", "active", "cancelled"],
  active: ["retesting", "completed", "cancelled"],
  retesting: ["active", "completed", "cancelled"],
  completed: [],
  cancelled: [],
};

const PROGRESS: Record<EngagementStatus, number> = {
  draft: 5,
  scoping: 20,
  active: 55,
  retesting: 80,
  completed: 100,
  cancelled: 0,
};

export function allowedEngagementStatuses(
  status: EngagementStatus,
): readonly EngagementStatus[] {
  return TRANSITIONS[status];
}

export function engagementProgress(status: EngagementStatus): number {
  return PROGRESS[status];
}
