import type { AgentTaskOut } from "./types";

export interface AgentDagLayout {
  lanes: string[][];
  tasks: ReadonlyMap<string, AgentTaskOut>;
  errors: string[];
}

export function layoutDag(input: AgentTaskOut[]): AgentDagLayout {
  const ordered = [...input].sort(
    (left, right) => left.plan_index - right.plan_index || left.task_key.localeCompare(right.task_key),
  );
  const tasks = new Map(ordered.map((task) => [task.task_key, task]));
  const errors: string[] = [];
  for (const task of ordered) {
    for (const dependency of task.depends_on) {
      if (!tasks.has(dependency)) {
        errors.push(`${task.task_key} depends on missing task ${dependency}`);
      }
    }
  }
  if (errors.length > 0) return { lanes: [], tasks, errors };

  const remaining = new Set(ordered.map((task) => task.task_key));
  const completed = new Set<string>();
  const lanes: string[][] = [];
  while (remaining.size > 0) {
    const lane = ordered
      .filter((task) => remaining.has(task.task_key))
      .filter((task) => task.depends_on.every((dependency) => completed.has(dependency)))
      .map((task) => task.task_key);
    if (lane.length === 0) {
      errors.push(`task graph contains a cycle involving ${[...remaining].join(", ")}`);
      return { lanes: [], tasks, errors };
    }
    lanes.push(lane);
    lane.forEach((key) => {
      remaining.delete(key);
      completed.add(key);
    });
  }
  return { lanes, tasks, errors };
}
