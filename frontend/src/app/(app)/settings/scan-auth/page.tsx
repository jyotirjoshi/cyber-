"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select } from "@/components/ui/Input";
import { Modal } from "@/components/ui/Modal";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { humanize } from "@/lib/format";
import type { ScanAuthProfileIn } from "@/lib/types";

const MODES: ScanAuthProfileIn["auth_type"][] = ["bearer", "openapi_token", "basic", "header", "cookie", "aws_static", "aws_role", "azure_service_principal", "gcp_service_account"];

function secretFields(mode: ScanAuthProfileIn["auth_type"]): string[] {
  if (mode === "basic") return ["username", "password"];
  if (mode === "aws_static") return ["access_key_id", "secret_access_key", "session_token"];
  if (mode === "aws_role") return ["role_arn", "external_id"];
  if (mode === "header") return ["header_name", "header_value"];
  if (mode === "cookie") return ["cookie"];
  if (mode === "azure_service_principal") return ["tenant_id", "client_id", "client_secret"];
  if (mode === "gcp_service_account") return ["service_account_json"];
  return ["token"];
}

export default function ScanAuthPage() {
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [mode, setMode] = React.useState<ScanAuthProfileIn["auth_type"]>("bearer");
  const [targets, setTargets] = React.useState("");
  const [scanner, setScanner] = React.useState("nuclei");
  const [secrets, setSecrets] = React.useState<Record<string, string>>({});
  const profiles = useApiResource(() => api.scanAuth.list(), []);
  const create = useMutation((body: ScanAuthProfileIn) => api.scanAuth.create(body), {
    onSuccess: () => { toast({ title: "Scan credential saved", tone: "ok" }); setOpen(false); void profiles.refetch(); },
  });
  const remove = useMutation((id: string) => api.scanAuth.delete(id), {
    onSuccess: () => { toast({ title: "Scan credential deleted", tone: "ok" }); void profiles.refetch(); },
  });

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const required = Object.fromEntries(secretFields(mode).filter((key) => secrets[key]).map((key) => [key, secrets[key]]));
    void create.run({ name, auth_type: mode, target_patterns: targets.split(",").map((item) => item.trim()).filter(Boolean), permitted_scanners: [scanner], secrets: required });
  }

  return <div className="space-y-6">
    <PageHeader title="Authenticated scans" description="Write-only, target-scoped credentials injected only into the selected sandboxed scanner." action={<Button onClick={() => setOpen(true)}>Add profile</Button>} />
    {profiles.loading ? <LoadingState label="Loading profiles…" /> : profiles.error ? <ErrorState message={profiles.error} onRetry={profiles.refetch} /> : !profiles.data?.length ? <EmptyState title="No scan credentials" description="Add a credential to run authenticated API or cloud assessments." action={<Button onClick={() => setOpen(true)}>Add profile</Button>} /> : <Table><THead><TR><TH>Name</TH><TH>Authentication</TH><TH>Scanners</TH><TH>Scope</TH><TH>Credential</TH><TH /></TR></THead><TBody>{profiles.data.map((profile) => <TR key={profile.id}><TD className="font-medium">{profile.name}</TD><TD><Badge tone="neutral">{humanize(profile.auth_type)}</Badge></TD><TD>{profile.permitted_scanners.map(humanize).join(", ")}</TD><TD className="font-mono text-xs">{profile.target_patterns.join(", ")}</TD><TD className="font-mono text-xs">••••{profile.hint} · {profile.fingerprint}</TD><TD><button className="text-xs text-danger hover:underline" onClick={() => void remove.run(profile.id)}>Delete</button></TD></TR>)}</TBody></Table>}
    {open && <Modal title="Add scan credential" onClose={() => setOpen(false)}><form className="space-y-4" onSubmit={submit}><Field label="Name" htmlFor="sa-name"><Input id="sa-name" required value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Authentication type" htmlFor="sa-type"><Select id="sa-type" value={mode} onChange={(event) => { setMode(event.target.value as typeof mode); setSecrets({}); }}>{MODES.map((item) => <option key={item} value={item}>{humanize(item)}</option>)}</Select></Field><Field label="Allowed target patterns" htmlFor="sa-targets" hint="Comma-separated exact targets or leading wildcard domains, for example *.example.com"><Input id="sa-targets" required value={targets} onChange={(event) => setTargets(event.target.value)} /></Field><Field label="Permitted scanner" htmlFor="sa-scanner"><Select id="sa-scanner" value={scanner} onChange={(event) => setScanner(event.target.value)}><option value="nuclei">Nuclei</option><option value="zap">ZAP</option><option value="prowler_aws">Prowler AWS</option><option value="prowler_azure">Prowler Azure</option><option value="prowler_gcp">Prowler GCP</option></Select></Field>{secretFields(mode).map((field) => <Field key={field} label={humanize(field)} htmlFor={`sa-${field}`}><Input id={`sa-${field}`} type={field === "username" || field.endsWith("_id") ? "text" : "password"} required={field !== "session_token"} autoComplete="new-password" value={secrets[field] ?? ""} onChange={(event) => setSecrets((current) => ({ ...current, [field]: event.target.value }))} /></Field>)}<div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" loading={create.loading}>Save encrypted profile</Button></div></form></Modal>}
  </div>;
}
