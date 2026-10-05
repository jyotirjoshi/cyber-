import type { CanonicalWorkIn } from "./types";

interface CurrentWork {
  assignee_user_id: string | null;
  due_at: string | null;
  remediation_plan: string | null;
  status_version: number;
}

interface EditedWork {
  assignee: string;
  dueLocal: string;
  plan: string;
}

export function toLocalDateTimeInput(value: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (number: number) => String(number).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function buildCanonicalWorkUpdate(
  current: CurrentWork, edited: EditedWork,
): CanonicalWorkIn | null {
  const body: CanonicalWorkIn = { expected_version: current.status_version };
  if (edited.assignee !== (current.assignee_user_id ?? "")) {
    body.assignee_user_id = edited.assignee || null;
  }
  if (edited.dueLocal !== toLocalDateTimeInput(current.due_at)) {
    if (edited.dueLocal && Number.isNaN(new Date(edited.dueLocal).getTime())) return null;
    body.due_at = edited.dueLocal ? new Date(edited.dueLocal).toISOString() : null;
  }
  const plan = edited.plan.trim();
  if (plan !== (current.remediation_plan ?? "")) {
    body.remediation_plan = plan || null;
  }
  return Object.keys(body).length > 1 ? body : null;
}
