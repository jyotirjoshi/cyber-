"use client";
import * as React from "react";
import { Button } from "@/components/ui/Button";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { AgentConfiguration, AgentTool, approvalLabel } from "@/lib/agent-definition";
import { KnowledgeCollection } from "@/lib/knowledge";

export function AgentEditor({ initial, tools, collections, disabled, saving, onSave }: {
  initial: AgentConfiguration; tools: AgentTool[]; collections: KnowledgeCollection[];
  disabled?: boolean; saving: boolean; onSave: (value: AgentConfiguration) => void;
}) {
  const [value, setValue] = React.useState(initial);
  const [scope, setScope] = React.useState(JSON.stringify(initial.scope_policy, null, 2));
  const [retrieval, setRetrieval] = React.useState(JSON.stringify(initial.retrieval_policy, null, 2));
  const initialCosts = initial.scope_policy.cost_estimate as Record<string, unknown> | undefined;
  const [inputPrice, setInputPrice] = React.useState(String(initialCosts?.input_usd_per_million ?? ""));
  const [outputPrice, setOutputPrice] = React.useState(String(initialCosts?.output_usd_per_million ?? ""));
  const [error, setError] = React.useState<string | null>(null);
  const [previewResult, setPreviewResult] = React.useState<Awaited<ReturnType<typeof api.customAgents.preview>> | null>(null);
  const preview = useMutation(api.customAgents.preview, { onSuccess: setPreviewResult });
  function update<K extends keyof AgentConfiguration>(key: K, next: AgentConfiguration[K]) {
    setValue((current) => ({ ...current, [key]: next })); setPreviewResult(null);
  }
  function payload(): AgentConfiguration | null {
    try {
      const scopePolicy = JSON.parse(scope), retrievalPolicy = JSON.parse(retrieval);
      if (!scopePolicy || Array.isArray(scopePolicy) || typeof scopePolicy !== "object" || !retrievalPolicy || Array.isArray(retrievalPolicy) || typeof retrievalPolicy !== "object") throw new Error("Policies must be JSON objects.");
      const input = Number(inputPrice), output = Number(outputPrice);
      if (!inputPrice.trim() || !outputPrice.trim() || !Number.isFinite(input) || !Number.isFinite(output) || input < 0 || output < 0) throw new Error("Model prices are required.");
      setError(null); return { ...value, scope_policy: { ...scopePolicy,
        cost_estimate: { input_usd_per_million: input, output_usd_per_million: output } },
        retrieval_policy: retrievalPolicy };
    } catch { setError("Enter valid JSON policies and non-negative model prices."); return null; }
  }
  return <form className="space-y-5" onSubmit={(event) => { event.preventDefault(); const body = payload(); if (body) onSave(body); }}>
    {error && <p role="alert" className="text-danger">{error}</p>}
    {preview.errorMessage && <p role="alert" className="text-danger">{preview.errorMessage}</p>}
    <fieldset disabled={disabled || saving} className="space-y-5 disabled:opacity-70">
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="Role" htmlFor="agent-role"><Input id="agent-role" required maxLength={160} value={value.role} onChange={(e) => update("role", e.target.value)} /></Field>
        <Field label="Provider" htmlFor="agent-provider" hint="Uses credentials configured in Integrations; keys are not saved with agent versions."><Select id="agent-provider" value={value.provider} onChange={(e) => update("provider", e.target.value as AgentConfiguration["provider"])}><option value="openai">OpenAI / compatible provider</option><option value="google">Google Gemini</option><option value="anthropic">Anthropic</option><option value="openrouter">OpenRouter</option></Select></Field>
        <Field label="Exact model ID" htmlFor="agent-model"><Input id="agent-model" required maxLength={160} pattern="[A-Za-z0-9._:/-]+" placeholder="Model available from your provider" value={value.model} onChange={(e) => update("model", e.target.value)} /></Field>
        <Field label="Autonomy" htmlFor="agent-autonomy"><Select id="agent-autonomy" value={value.autonomy_mode} onChange={(e) => update("autonomy_mode", e.target.value as AgentConfiguration["autonomy_mode"])}><option value="manual">Manual — reads only</option><option value="supervised">Supervised — approve mutations</option><option value="bounded">Bounded — subject to execution limits</option></Select></Field>
      </div>
      <Field label="Instructions" htmlFor="agent-instructions"><Textarea id="agent-instructions" required rows={7} maxLength={50000} value={value.instructions} onChange={(e) => update("instructions", e.target.value)} /></Field>
      <div className="grid gap-4 md:grid-cols-3">{([
        ["max_output_tokens", "Output tokens", 1, 200000], ["max_input_tokens", "Input token budget", 1, 2000000],
        ["max_runtime_seconds", "Runtime (seconds)", 1, 86400], ["max_tool_calls", "Total tool calls", 0, 1000],
        ["max_parallel_tasks", "Parallel tasks", 1, 30],
      ] as const).map(([key, label, min, max]) => <Field key={key} label={label} htmlFor={key}><Input id={key} type="number" required min={min} max={max} value={value[key]} onChange={(e) => update(key, Number(e.target.value))} /></Field>)}
        <Field label="Estimated spend ceiling (USD)" htmlFor="agent-spend" hint="Agent-run configuration, not a cloud billing cutoff."><Input id="agent-spend" type="number" min={0} max={10000} step={0.01} value={value.max_estimated_spend_micros / 1000000} onChange={(e) => update("max_estimated_spend_micros", Math.round(Number(e.target.value) * 1000000))} /></Field>
      </div>
      <section><h3 className="mb-3 font-medium">Selected tools</h3><p className="mb-3 text-xs text-muted">Selecting a tool never grants permissions your account lacks. External writes and active security operations retain mandatory approval.</p><div className="grid max-h-80 gap-2 overflow-auto rounded-lg border border-line p-3 md:grid-cols-2">{tools.map((tool) => <label key={tool.name} className="flex items-start gap-2 p-2 text-sm"><input type="checkbox" className="mt-1" disabled={!tool.permitted} checked={value.tool_names.includes(tool.name)} onChange={(event) => update("tool_names", event.target.checked ? [...value.tool_names, tool.name] : value.tool_names.filter((name) => name !== tool.name))} /><span>{tool.name.replaceAll("_", " ")}<span className="block text-xs text-muted">{tool.permitted ? approvalLabel(value.autonomy_mode, tool) : "Your role cannot use this tool"}</span></span></label>)}</div></section>
      <section><h3 className="mb-3 font-medium">Knowledge collections</h3><div className="space-y-2">{collections.filter((item) => item.is_enabled).map((item) => <label key={item.id} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={value.collection_ids.includes(item.id)} onChange={(e) => update("collection_ids", e.target.checked ? [...value.collection_ids, item.id] : value.collection_ids.filter((id) => id !== item.id))} />{item.name}</label>)}{collections.length === 0 && <p className="text-sm text-muted">Create a collection in Knowledge to attach runbooks.</p>}</div></section>
      <div className="grid gap-4 md:grid-cols-2"><Field label="Provider input price (USD / 1M tokens)" htmlFor="agent-input-price" hint="Used for the agent's hard pre-call spend estimate. Copy the current rate from your provider."><Input id="agent-input-price" type="number" required min={0} step="any" value={inputPrice} onChange={(e) => { setInputPrice(e.target.value); setPreviewResult(null); }} /></Field><Field label="Provider output price (USD / 1M tokens)" htmlFor="agent-output-price"><Input id="agent-output-price" type="number" required min={0} step="any" value={outputPrice} onChange={(e) => { setOutputPrice(e.target.value); setPreviewResult(null); }} /></Field></div>
      <details className="rounded-lg border border-line p-4"><summary className="cursor-pointer text-sm">Advanced configuration</summary><div className="mt-4 grid gap-4 md:grid-cols-2"><Field label="Scope policy (JSON)" htmlFor="agent-scope" hint="The editor stores cost estimates into this policy automatically."><Textarea id="agent-scope" rows={5} value={scope} onChange={(e) => { setScope(e.target.value); setPreviewResult(null); }} /></Field><Field label="Retrieval policy (JSON)" htmlFor="agent-retrieval"><Textarea id="agent-retrieval" rows={5} value={retrieval} onChange={(e) => { setRetrieval(e.target.value); setPreviewResult(null); }} /></Field><Field label="Temperature" htmlFor="agent-temperature"><Input id="agent-temperature" type="number" min={0} max={2} step={0.1} value={value.temperature} onChange={(e) => update("temperature", Number(e.target.value))} /></Field></div></details>
      <div className="flex gap-3"><Button type="submit" loading={saving}>Save version</Button><Button type="button" variant="secondary" loading={preview.loading} onClick={() => { const body = payload(); if (body) void preview.run(body); }}>Preview tool policy</Button></div>
    </fieldset>
    {previewResult && <section aria-live="polite" className="rounded-lg border border-line p-4"><h3 className="font-medium">Effective tool policy for your account</h3><ul className="mt-3 space-y-2 text-sm">{previewResult.tools.map((tool) => <li key={tool.name}>{tool.name}: {tool.approval} approval · {tool.per_run_call_limit} calls · {tool.timeout_seconds}s timeout</li>)}{Object.entries(previewResult.rejected).map(([name, reason]) => <li key={name} className="text-warning">{name}: unavailable ({reason.replaceAll("_", " ")})</li>)}</ul></section>}
  </form>;
}
