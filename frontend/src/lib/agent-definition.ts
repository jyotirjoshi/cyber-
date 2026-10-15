export type AgentAutonomy = "manual" | "supervised" | "bounded";
export interface AgentConfiguration {
  role: string; instructions: string; provider: "openai" | "google" | "anthropic" | "openrouter";
  model: string; autonomy_mode: AgentAutonomy; temperature: number; max_output_tokens: number;
  max_parallel_tasks: number; max_runtime_seconds: number; max_tool_calls: number;
  max_input_tokens: number; max_estimated_spend_micros: number;
  scope_policy: Record<string, unknown>; retrieval_policy: Record<string, unknown>;
  tool_names: string[]; collection_ids: string[];
}
export interface AgentDefinition {
  id: string; name: string; description: string | null; avatar_reference: string | null;
  active_version_id: string | null; is_enabled: boolean; version_count: number;
  created_at: string; updated_at: string;
}
export interface AgentVersion extends AgentConfiguration {
  id: string; agent_definition_id: string; version: number; configuration_digest: string; created_at: string;
}
export interface AgentTool {
  name: string; version: number; permission: string; side_effect: string; approval: string;
  timeout_seconds: number; permitted: boolean; input_schema: Record<string, unknown>;
}
export interface AgentPolicyPreview {
  tools: { name: string; approval: string; timeout_seconds: number; per_run_call_limit: number }[];
  rejected: Record<string, string>; max_tool_calls: number;
}
export interface MemoryCandidate {
  id: string; key: string; category: string; content: string; confidence: number;
  evidence: { kind: "run" | "knowledge_chunk"; id: string }[];
  agent_version_id: string | null; expires_at: string | null;
  status: "pending" | "approved" | "rejected" | "expired";
  reviewed_by_id: string | null; decision_rationale: string | null;
  approved_memory_id: string | null; created_at: string;
}
export interface MemoryApproval { content?: string; expires_at?: string | null; rationale?: string }

export function defaultAgentConfiguration(): AgentConfiguration {
  return { role: "Security analyst", instructions: "Use cited evidence. Explain uncertainty and verify outcomes before reporting success.",
    provider: "openai", model: "", autonomy_mode: "supervised", temperature: 0,
    max_output_tokens: 4096, max_parallel_tasks: 1, max_runtime_seconds: 900, max_tool_calls: 20,
    max_input_tokens: 100000, max_estimated_spend_micros: 1000000,
    scope_policy: {}, retrieval_policy: {}, tool_names: [], collection_ids: [] };
}

export function configurationFromVersion<T extends AgentConfiguration>(version: T): AgentConfiguration {
  const output = defaultAgentConfiguration();
  for (const key of Object.keys(output) as (keyof AgentConfiguration)[]) {
    Object.assign(output, { [key]: structuredClone(version[key]) });
  }
  return output;
}

export function approvalLabel(mode: AgentAutonomy, tool: Pick<AgentTool, "side_effect" | "approval">): string {
  if (tool.side_effect === "read") return "Read access";
  if (mode === "manual") return "Unavailable in manual mode";
  if (mode === "supervised" || tool.approval === "always") return "Approval required";
  return "Subject to execution policy";
}
