export type WorkflowNodeType =
  | "trigger"
  | "condition"
  | "enrichment"
  | "action"
  | "branch"
  | "delay"
  | "approval";

export interface WorkflowNode {
  id: string;
  type: WorkflowNodeType;
  config: Record<string, unknown>;
}

export interface WorkflowEdge {
  source: string;
  target: string;
  branch?: "true" | "false" | "always";
}

export interface WorkflowDocument {
  name: string;
  description?: string | null;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  is_enabled?: boolean;
  dry_run?: boolean;
}

export function validateWorkflow(workflow: WorkflowDocument): string[] {
  const errors: string[] = [];
  const ids = new Set(workflow.nodes.map((node) => node.id));
  if (ids.size !== workflow.nodes.length) errors.push("Node IDs must be unique.");

  const triggers = workflow.nodes.filter((node) => node.type === "trigger");
  if (triggers.length !== 1) errors.push("Workflow must have exactly one trigger.");

  const outgoing = new Map<string, string[]>();
  const indegree = new Map<string, number>();
  for (const id of ids) {
    outgoing.set(id, []);
    indegree.set(id, 0);
  }
  for (const edge of workflow.edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target)) {
      errors.push("Edge references an unknown node.");
      continue;
    }
    outgoing.get(edge.source)?.push(edge.target);
    indegree.set(edge.target, (indegree.get(edge.target) ?? 0) + 1);
  }

  const queue = [...indegree.entries()]
    .filter(([, count]) => count === 0)
    .map(([id]) => id)
    .sort();
  let visited = 0;
  while (queue.length > 0) {
    const id = queue.shift()!;
    visited += 1;
    for (const target of (outgoing.get(id) ?? []).sort()) {
      const next = (indegree.get(target) ?? 0) - 1;
      indegree.set(target, next);
      if (next === 0) {
        queue.push(target);
        queue.sort();
      }
    }
  }
  if (visited !== workflow.nodes.length) errors.push("Workflow must be acyclic.");
  return [...new Set(errors)];
}

export function serializeWorkflow(workflow: WorkflowDocument): WorkflowDocument {
  return {
    ...workflow,
    name: workflow.name.trim(),
    description: workflow.description?.trim() || null,
    nodes: [...workflow.nodes]
      .map((node) => ({ ...node, config: sortObject(node.config) }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    edges: [...workflow.edges]
      .map((edge) => ({ ...edge }))
      .sort((left, right) =>
        `${left.source}\u0000${left.target}\u0000${left.branch ?? ""}`.localeCompare(
          `${right.source}\u0000${right.target}\u0000${right.branch ?? ""}`,
        ),
      ),
  };
}

function sortObject(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
}
