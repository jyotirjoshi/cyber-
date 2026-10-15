"use client";

import * as React from "react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/Table";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fieldError } from "@/lib/errors";
import { formatDateTime, formatNumber, humanize } from "@/lib/format";
import { RISK_WEIGHT_KEYS, totalRiskWeights } from "@/lib/risk-weights";
import type {
  ClientOrganizationCreateIn,
  ClientOrganizationPortfolioOut,
  MemberInviteIn,
  MemberOut,
  AgentMemoryOut,
  OrganizationOut,
  OrganizationUpdateIn,
  OidcConnectionUpsertIn,
  Role,
  RiskWeights,
  SamlConnectionUpsertIn,
  ScimProvisioningTokenIssuedOut,
} from "@/lib/types";

const ROLES: readonly Role[] = [
  "owner",
  "admin",
  "security_engineer",
  "developer",
  "viewer",
];

// --- Organization profile ---------------------------------------------------

function OrgSummary({ org }: { org: OrganizationOut }) {
  return (
    <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div>
        <dt className="text-xs font-medium text-muted">Name</dt>
        <dd className="mt-1 text-sm text-fg">{org.name}</dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Slug</dt>
        <dd className="mt-1 font-mono text-sm text-fg">{org.slug}</dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Status</dt>
        <dd className="mt-1">
          <Badge tone={org.is_active ? "ok" : "neutral"}>
            {org.is_active ? "Active" : "Inactive"}
          </Badge>
        </dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Max concurrent scanner jobs</dt>
        <dd className="mt-1 text-sm text-fg">
          {formatNumber(org.max_concurrent_scanner_jobs)}
        </dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Asset capacity</dt>
        <dd className="mt-1 text-sm text-fg">{formatNumber(org.entitlements.max_assets)}</dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Member capacity</dt>
        <dd className="mt-1 text-sm text-fg">{formatNumber(org.entitlements.max_members)}</dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Integration capacity</dt>
        <dd className="mt-1 text-sm text-fg">
          {formatNumber(org.entitlements.max_integrations)}
        </dd>
      </div>
      <div>
        <dt className="text-xs font-medium text-muted">Active validation</dt>
        <dd className="mt-1">
          <Badge tone={org.entitlements.allow_active_validation ? "warn" : "neutral"}>
            {org.entitlements.allow_active_validation ? "Enabled" : "Disabled"}
          </Badge>
        </dd>
      </div>
    </dl>
  );
}

function OrgEditForm({
  org,
  onUpdated,
}: {
  org: OrganizationOut;
  onUpdated: (next: OrganizationOut) => void;
}) {
  const { toast } = useToast();
  const [name, setName] = React.useState(org.name);
  const [maxJobs, setMaxJobs] = React.useState(String(org.max_concurrent_scanner_jobs));
  const [policyText, setPolicyText] = React.useState(JSON.stringify(org.policy, null, 2));
  const [policyError, setPolicyError] = React.useState<string | null>(null);
  const [pagerDutyEnabled, setPagerDutyEnabled] = React.useState(Boolean(org.policy.pagerduty_enabled));

  React.useEffect(() => {
    setPolicyText(JSON.stringify(org.policy, null, 2));
    setPagerDutyEnabled(Boolean(org.policy.pagerduty_enabled));
  }, [org.policy]);

  const mutation = useMutation(
    (body: OrganizationUpdateIn) => api.organization.update(body),
    {
      onSuccess: (next) => {
        onUpdated(next);
        toast({ title: "Organization updated", tone: "ok" });
      },
    },
  );

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setPolicyError(null);

    const body: OrganizationUpdateIn = { name: name.trim() };

    const maxNum = maxJobs.trim() === "" ? Number.NaN : Number(maxJobs);
    if (!Number.isNaN(maxNum)) body.max_concurrent_scanner_jobs = maxNum;

    const trimmedPolicy = policyText.trim();
    if (trimmedPolicy) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmedPolicy);
      } catch {
        setPolicyError("Enter valid JSON, or leave blank.");
        return;
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setPolicyError("Policy must be a JSON object.");
        return;
      }
      body.policy = { ...(parsed as Record<string, unknown>), pagerduty_enabled: pagerDutyEnabled };
    } else if (pagerDutyEnabled !== Boolean(org.policy.pagerduty_enabled)) {
      body.policy = { ...org.policy, pagerduty_enabled: pagerDutyEnabled };
    }

    void mutation.run(body);
  };

  const generalError =
    fieldError(mutation.error, "name") ||
    fieldError(mutation.error, "max_concurrent_scanner_jobs")
      ? null
      : mutation.errorMessage;

  return (
    <form onSubmit={onSubmit} className="space-y-4 border-t border-line pt-6">
      <h3 className="text-sm font-semibold text-fg">Edit profile</h3>
      <InlineError message={generalError} />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field
          label="Name"
          htmlFor="org-name"
          required
          error={fieldError(mutation.error, "name")}
        >
          <Input
            id="org-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </Field>
        <Field
          label="Max concurrent scanner jobs"
          htmlFor="org-max-jobs"
          hint="Between 1 and 64."
          error={fieldError(mutation.error, "max_concurrent_scanner_jobs")}
        >
          <Input
            id="org-max-jobs"
            type="number"
            min={1}
            max={64}
            value={maxJobs}
            onChange={(e) => setMaxJobs(e.target.value)}
          />
        </Field>
      </div>
      <Field
        label="Policy (JSON)"
        htmlFor="org-policy"
        hint="Optional. Leave blank to keep the current policy."
        error={policyError}
      >
        <Textarea
          id="org-policy"
          rows={5}
          value={policyText}
          onChange={(e) => setPolicyText(e.target.value)}
          className="font-mono text-xs"
          placeholder={'{ "key": "value" }'}
        />
      </Field>
      <label className="flex items-start gap-3 rounded-lg border border-line p-3 text-sm">
        <input
          type="checkbox"
          className="mt-0.5 h-4 w-4 rounded border border-line bg-surface-2 accent-primary"
          checked={pagerDutyEnabled}
          onChange={(event) => setPagerDutyEnabled(event.target.checked)}
        />
        <span>
          <span className="font-medium text-fg">Page on-call for critical exposure</span>
          <span className="mt-1 block text-xs text-muted">
            Sends PagerDuty events for critical findings and SLA breaches after a PagerDuty integration is configured.
          </span>
        </span>
      </label>
      <div className="flex justify-end">
        <Button type="submit" loading={mutation.loading}>
          Save changes
        </Button>
      </div>
    </form>
  );
}

function RiskWeightsEditor({
  org,
  onUpdated,
}: {
  org: OrganizationOut;
  onUpdated: (next: OrganizationOut) => void;
}) {
  const { toast } = useToast();
  const [weights, setWeights] = React.useState<RiskWeights>(org.policy.risk_weights);
  const [validationError, setValidationError] = React.useState<string | null>(null);
  React.useEffect(() => setWeights(org.policy.risk_weights), [org.policy.risk_weights]);
  const mutation = useMutation(
    () => api.organization.update({
      policy: { ...org.policy, risk_weights: weights },
    }),
    {
      onSuccess: (next) => {
        onUpdated(next);
        setValidationError(null);
        toast({ title: "Risk weights updated", tone: "ok" });
      },
    },
  );
  const total = totalRiskWeights(weights);
  return (
    <Card>
      <CardHeader><CardTitle>Risk scoring weights</CardTitle></CardHeader>
      <CardBody>
        <form className="space-y-4" onSubmit={(event) => {
          event.preventDefault();
          if (RISK_WEIGHT_KEYS.some((key) => !Number.isFinite(weights[key]) || weights[key] < 0 || weights[key] > 100)
            || Math.abs(total - 100) > 0.000001) {
            setValidationError("Each weight must be between 0 and 100, and the total must equal 100.");
            return;
          }
          setValidationError(null);
          void mutation.run();
        }}>
          <p className="text-sm text-muted">Tune how the canonical queue balances severity, confirmed exploitation, EPSS, exposure, asset criticality, and ransomware evidence. Unknown intelligence is shown as unknown.</p>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {RISK_WEIGHT_KEYS.map((key) => (
              <Field key={key} label={humanize(key)} htmlFor={`risk-weight-${key}`}>
                <Input id={`risk-weight-${key}`} type="number" min={0} max={100} step="0.01"
                  value={weights[key]} onChange={(event) => setWeights((current) => ({ ...current, [key]: Number(event.target.value) }))} />
              </Field>
            ))}
          </div>
          <p className="text-sm text-muted">Total: {Number.isFinite(total) ? total.toFixed(2) : "invalid"} / 100</p>
          <InlineError message={validationError ?? mutation.errorMessage} />
          <Button type="submit" loading={mutation.loading}>Save risk weights</Button>
        </form>
      </CardBody>
    </Card>
  );
}

function AgentMemoryEditor() {
  const { toast } = useToast();
  const memories = useApiResource(() => api.agent.memories(), []);
  const [key, setKey] = React.useState("");
  const [category, setCategory] = React.useState<AgentMemoryOut["category"]>("operational");
  const [content, setContent] = React.useState("");
  const [expiresAt, setExpiresAt] = React.useState("");
  const upsert = useMutation(
    () => api.agent.upsertMemory({ key: key.trim().toLowerCase(), category, content: content.trim(), expires_at: expiresAt ? new Date(expiresAt).toISOString() : null }),
    { onSuccess: () => { setKey(""); setContent(""); setExpiresAt(""); void memories.refetch(); toast({ title: "Agent memory saved", tone: "ok" }); } },
  );
  const disable = useMutation(
    (id: string) => api.agent.disableMemory(id),
    { onSuccess: () => { void memories.refetch(); toast({ title: "Agent memory disabled", tone: "ok" }); } },
  );
  return <Card>
    <CardHeader><CardTitle>AI worker memory</CardTitle></CardHeader>
    <CardBody className="space-y-4">
      <p className="text-sm text-muted">Curated tenant facts are available in future AI conversations as reference data, never as executable instructions. Do not add credentials or raw scan output.</p>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={(event) => { event.preventDefault(); if (key.trim() && content.trim()) void upsert.run(); }}>
        <Field label="Memory key" htmlFor="agent-memory-key"><Input id="agent-memory-key" value={key} maxLength={120} onChange={(event) => setKey(event.target.value)} placeholder="production-change-window" /></Field>
        <Field label="Category" htmlFor="agent-memory-category"><Select id="agent-memory-category" value={category} onChange={(event) => setCategory(event.target.value as AgentMemoryOut["category"])}><option value="operational">Operational</option><option value="architecture">Architecture</option><option value="remediation">Remediation</option><option value="scope">Scope</option><option value="preference">Preference</option></Select></Field>
        <Field label="Expires at (optional)" htmlFor="agent-memory-expires" hint="Expired memory is automatically excluded from future agent context."><Input id="agent-memory-expires" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></Field>
        <Field label="Curated fact" htmlFor="agent-memory-content" className="sm:col-span-2"><Textarea id="agent-memory-content" value={content} maxLength={2000} onChange={(event) => setContent(event.target.value)} placeholder="Production changes require CAB approval on Wednesdays." /></Field>
        {upsert.errorMessage && <p role="alert" className="sm:col-span-2 text-sm text-danger">{upsert.errorMessage}</p>}
        <div className="sm:col-span-2"><Button type="submit" loading={upsert.loading} disabled={!key.trim() || !content.trim()}>Save memory</Button></div>
      </form>
      {memories.loading && !memories.data ? <LoadingState label="Loading AI worker memory…" /> : memories.error ? <ErrorState message={memories.error} onRetry={memories.refetch} /> : memories.data?.length ? <Table><THead><TR><TH>Key</TH><TH>Category</TH><TH>Fact</TH><TH>Expires</TH><TH>Status</TH><TH /></TR></THead><TBody>{memories.data.map((memory) => <TR key={memory.id}><TD className="font-mono text-xs">{memory.key}</TD><TD>{humanize(memory.category)}</TD><TD className="max-w-lg whitespace-pre-wrap text-sm">{memory.content}</TD><TD className="text-xs text-muted">{memory.expires_at ? formatDateTime(memory.expires_at) : "Never"}</TD><TD><Badge tone={memory.is_active ? "ok" : "neutral"}>{memory.is_active ? "Active" : "Disabled"}</Badge></TD><TD className="text-right">{memory.is_active && <Button size="sm" variant="secondary" loading={disable.loading} onClick={() => void disable.run(memory.id)}>Disable</Button>}</TD></TR>)}</TBody></Table> : <p className="text-sm text-muted">No curated AI worker memory yet.</p>}
    </CardBody>
  </Card>;
}

// --- Members ----------------------------------------------------------------

function InviteForm({ onInvited }: { onInvited: () => void }) {
  const { toast } = useToast();
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<Role>("viewer");
  const [fullName, setFullName] = React.useState("");

  const mutation = useMutation(
    (body: MemberInviteIn) => api.organization.inviteMember(body),
    {
      onSuccess: (member) => {
        onInvited();
        toast({ title: "Invitation sent", description: member.email, tone: "ok" });
        setEmail("");
        setFullName("");
        setRole("viewer");
      },
    },
  );

  const onSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    void mutation.run({
      email: email.trim(),
      role,
      full_name: fullName.trim() || null,
    });
  };

  const generalError =
    fieldError(mutation.error, "email") ||
    fieldError(mutation.error, "full_name") ||
    fieldError(mutation.error, "role")
      ? null
      : mutation.errorMessage;

  return (
    <form
      onSubmit={onSubmit}
      className="space-y-4 rounded-lg border border-line bg-surface-2/40 p-4"
    >
      <h3 className="text-sm font-semibold text-fg">Invite a member</h3>
      <InlineError message={generalError} />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Field
          label="Email"
          htmlFor="invite-email"
          required
          error={fieldError(mutation.error, "email")}
          className="lg:col-span-2"
        >
          <Input
            id="invite-email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="person@example.com"
          />
        </Field>
        <Field
          label="Full name"
          htmlFor="invite-name"
          error={fieldError(mutation.error, "full_name")}
        >
          <Input
            id="invite-name"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            placeholder="Optional"
          />
        </Field>
        <Field
          label="Role"
          htmlFor="invite-role"
          error={fieldError(mutation.error, "role")}
        >
          <Select
            id="invite-role"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {humanize(r)}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <div className="flex justify-end">
        <Button type="submit" loading={mutation.loading}>
          Send invitation
        </Button>
      </div>
    </form>
  );
}

function MemberRow({
  member,
  canManage,
  onChanged,
}: {
  member: MemberOut;
  canManage: boolean;
  onChanged: () => void;
}) {
  const { toast } = useToast();
  const [pendingRole, setPendingRole] = React.useState<Role | null>(null);

  const roleMutation = useMutation(
    (role: Role) => api.organization.updateMemberRole(member.membership_id, { role }),
    {
      onSuccess: () => {
        setPendingRole(null);
        onChanged();
        toast({ title: "Role updated", description: member.email, tone: "ok" });
      },
      onError: () => {
        setPendingRole(null);
        toast({ title: "Couldn't update role", description: member.email, tone: "danger" });
      },
    },
  );

  const removeMutation = useMutation(
    () => api.organization.removeMember(member.membership_id),
    {
      onSuccess: () => {
        onChanged();
        toast({ title: "Member removed", description: member.email, tone: "ok" });
      },
      onError: () => {
        toast({ title: "Couldn't remove member", description: member.email, tone: "danger" });
      },
    },
  );

  const onRemove = () => {
    if (!window.confirm(`Remove ${member.email} from the organization?`)) return;
    void removeMutation.run();
  };

  return (
    <TR>
      <TD><div>{member.email}</div><div className="font-mono text-[10px] text-faint">{member.user_id}</div></TD>
      <TD>{member.full_name || "—"}</TD>
      <TD>
        {canManage ? (
          <Select
            value={pendingRole ?? member.role}
            disabled={roleMutation.loading}
            aria-label={`Role for ${member.email}`}
            className="h-8 py-1 text-xs"
            onChange={(e) => {
              const next = e.target.value as Role;
              setPendingRole(next);
              void roleMutation.run(next);
            }}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {humanize(r)}
              </option>
            ))}
          </Select>
        ) : (
          humanize(member.role)
        )}
      </TD>
      <TD>
        <Badge tone={member.is_active ? "ok" : "neutral"}>
          {member.is_active ? "Active" : "Inactive"}
        </Badge>
      </TD>
      <TD className="text-muted">{formatDateTime(member.last_login_at)}</TD>
      {canManage && (
        <TD className="text-right">
          <Button
            variant="danger"
            size="sm"
            loading={removeMutation.loading}
            onClick={onRemove}
          >
            Remove
          </Button>
        </TD>
      )}
    </TR>
  );
}

// --- Page -------------------------------------------------------------------

function IdentityProvisioning({ organizationSlug }: { organizationSlug: string }) {
  const { toast } = useToast();
  const [oidc, setOidc] = React.useState<OidcConnectionUpsertIn>({ issuer_url: "", client_id: "", client_secret: "", redirect_uri: "", allowed_email_domains: [], is_enabled: true });
  const [saml, setSaml] = React.useState<SamlConnectionUpsertIn>({ sp_entity_id: "", idp_entity_id: "", idp_sso_url: "", idp_certificate_pem: "", acs_url: "", allowed_email_domains: [], is_enabled: true });
  const [scimName, setScimName] = React.useState("");
  const [issuedScim, setIssuedScim] = React.useState<ScimProvisioningTokenIssuedOut | null>(null);
  const oidcConnection = useApiResource(() => api.organization.oidcConnection(), []);
  const samlConnection = useApiResource(() => api.organization.samlConnection(), []);
  const scimTokens = useApiResource(() => api.organization.scimTokens(), []);
  const saveOidc = useMutation(api.organization.configureOidc, { onSuccess: () => { void oidcConnection.refetch(); toast({ title: "OIDC SSO configuration saved", tone: "ok" }); } });
  const saveSaml = useMutation(api.organization.configureSaml, { onSuccess: () => { void samlConnection.refetch(); toast({ title: "SAML SSO configuration saved", tone: "ok" }); } });
  const issueScim = useMutation(api.organization.createScimToken, { onSuccess: (token) => { setIssuedScim(token); setScimName(""); void scimTokens.refetch(); toast({ title: "SCIM provisioning token created", tone: "ok" }); } });
  const revokeScim = useMutation(api.organization.revokeScimToken, { onSuccess: () => { void scimTokens.refetch(); toast({ title: "SCIM provisioning token revoked", tone: "ok" }); } });
  const domains = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);

  return <Card>
    <CardHeader><CardTitle>Enterprise identity and provisioning</CardTitle></CardHeader>
    <CardBody className="space-y-6">
      <p className="text-xs text-muted">SAML service-provider metadata: <a className="text-primary hover:underline" href={api.auth.samlMetadataUrl(organizationSlug)} target="_blank" rel="noopener noreferrer">Open metadata ↗</a></p>
      <p className="text-sm text-muted">Configure one identity-provider trust path and create revocable SCIM credentials for your directory. Client secrets and certificate material are not returned after submission.</p>
      <details className="rounded-lg border border-line p-3"><summary className="cursor-pointer text-sm font-medium text-fg">OIDC SSO</summary>{oidcConnection.data && <p className="mt-3 text-xs text-muted">Configured for {oidcConnection.data.issuer_url} · {oidcConnection.data.is_enabled ? "enabled" : "disabled"}. Enter all values below to rotate the client secret.</p>}<form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={(event) => { event.preventDefault(); void saveOidc.run(oidc); }}><Field label="Issuer URL" htmlFor="oidc-issuer"><Input id="oidc-issuer" required type="url" value={oidc.issuer_url} onChange={(event) => setOidc((current) => ({ ...current, issuer_url: event.target.value }))} /></Field><Field label="Client ID" htmlFor="oidc-client-id"><Input id="oidc-client-id" required value={oidc.client_id} onChange={(event) => setOidc((current) => ({ ...current, client_id: event.target.value }))} /></Field><Field label="Client secret" htmlFor="oidc-client-secret"><Input id="oidc-client-secret" required type="password" value={oidc.client_secret} onChange={(event) => setOidc((current) => ({ ...current, client_secret: event.target.value }))} /></Field><Field label="Redirect URI" htmlFor="oidc-redirect"><Input id="oidc-redirect" required type="url" value={oidc.redirect_uri} onChange={(event) => setOidc((current) => ({ ...current, redirect_uri: event.target.value }))} /></Field><Field label="Allowed domains (comma-separated)" htmlFor="oidc-domains" className="sm:col-span-2"><Input id="oidc-domains" onChange={(event) => setOidc((current) => ({ ...current, allowed_email_domains: domains(event.target.value) }))} /></Field>{saveOidc.errorMessage && <p role="alert" className="sm:col-span-2 text-sm text-danger">{saveOidc.errorMessage}</p>}<div className="sm:col-span-2"><Button type="submit" loading={saveOidc.loading}>Save OIDC connection</Button></div></form></details>
      <details className="rounded-lg border border-line p-3"><summary className="cursor-pointer text-sm font-medium text-fg">SAML 2.0 SSO</summary>{samlConnection.data && <p className="mt-3 text-xs text-muted">Configured for {samlConnection.data.idp_entity_id} · {samlConnection.data.is_enabled ? "enabled" : "disabled"}. Enter all values below to replace the trust material.</p>}<form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={(event) => { event.preventDefault(); void saveSaml.run(saml); }}><Field label="Service provider entity ID" htmlFor="saml-sp"><Input id="saml-sp" required type="url" value={saml.sp_entity_id} onChange={(event) => setSaml((current) => ({ ...current, sp_entity_id: event.target.value }))} /></Field><Field label="ACS URL" htmlFor="saml-acs"><Input id="saml-acs" required type="url" value={saml.acs_url} onChange={(event) => setSaml((current) => ({ ...current, acs_url: event.target.value }))} /></Field><Field label="Identity provider entity ID" htmlFor="saml-idp"><Input id="saml-idp" required type="url" value={saml.idp_entity_id} onChange={(event) => setSaml((current) => ({ ...current, idp_entity_id: event.target.value }))} /></Field><Field label="Identity provider SSO URL" htmlFor="saml-sso"><Input id="saml-sso" required type="url" value={saml.idp_sso_url} onChange={(event) => setSaml((current) => ({ ...current, idp_sso_url: event.target.value }))} /></Field><Field label="Identity provider certificate PEM" htmlFor="saml-cert" className="sm:col-span-2"><Textarea id="saml-cert" required value={saml.idp_certificate_pem} onChange={(event) => setSaml((current) => ({ ...current, idp_certificate_pem: event.target.value }))} /></Field><Field label="Allowed domains (comma-separated)" htmlFor="saml-domains" className="sm:col-span-2"><Input id="saml-domains" onChange={(event) => setSaml((current) => ({ ...current, allowed_email_domains: domains(event.target.value) }))} /></Field>{saveSaml.errorMessage && <p role="alert" className="sm:col-span-2 text-sm text-danger">{saveSaml.errorMessage}</p>}<div className="sm:col-span-2"><Button type="submit" loading={saveSaml.loading}>Save SAML connection</Button></div></form></details>
      <div className="border-t border-line pt-4"><h3 className="text-sm font-medium text-fg">SCIM 2.0 provisioning</h3><form className="mt-3 flex flex-wrap gap-2" onSubmit={(event) => { event.preventDefault(); void issueScim.run({ name: scimName }); }}><Input required maxLength={160} value={scimName} onChange={(event) => setScimName(event.target.value)} placeholder="Okta production provisioner" className="max-w-sm" /><Button type="submit" loading={issueScim.loading}>Create SCIM token</Button></form>{issuedScim && <div className="mt-3 rounded border border-ok/40 bg-ok/10 p-3 text-sm"><p className="text-muted">Copy this SCIM bearer token now. It will not be shown again.</p><code className="mt-2 block break-all text-fg">{issuedScim.secret}</code></div>}{scimTokens.loading && !scimTokens.data ? <LoadingState label="Loading SCIM tokens…" /> : scimTokens.error ? <InlineError message={scimTokens.error} /> : <ul className="mt-3 space-y-2">{scimTokens.data?.map((token) => <li key={token.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-line p-2 text-sm"><span className="font-medium text-fg">{token.name} <span className="font-mono text-muted">{token.key_prefix}…</span></span>{token.revoked_at ? <Badge tone="neutral">Revoked</Badge> : <Button size="sm" variant="outline" loading={revokeScim.loading} onClick={() => void revokeScim.run(token.id)}>Revoke</Button>}</li>)}</ul>}</div>
    </CardBody>
  </Card>;
}

function ClientOrganizations() {
  const { toast } = useToast();
  const { reload } = useAuth();
  const clients = useApiResource(() => api.organization.clients(), []);
  const parentMembers = useApiResource(
    () => api.organization.members({ limit: 200, offset: 0 }),
    [],
  );
  const [name, setName] = React.useState("");
  const [slug, setSlug] = React.useState("");
  const [delegates, setDelegates] = React.useState<Record<string, string>>({});
  const createClient = useMutation(
    (body: ClientOrganizationCreateIn) => api.organization.createClient(body),
    {
      onSuccess: (organization) => {
        setName("");
        setSlug("");
        void clients.refetch();
        void reload();
        toast({ title: `${organization.name} client organization created`, tone: "ok" });
      },
    },
  );
  const delegateClient = useMutation(
    ({ clientOrganizationId, userId }: { clientOrganizationId: string; userId: string }) =>
      api.organization.delegateClient(clientOrganizationId, {
        user_id: userId,
        role: "security_engineer",
      }),
    {
      onSuccess: () => {
        setDelegates({});
        toast({ title: "Client access granted", tone: "ok" });
      },
    },
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>MSSP client organizations</CardTitle>
      </CardHeader>
      <CardBody className="space-y-5">
        <p className="text-sm text-muted">
          Create isolated customer tenants. Portfolio counters are visible here, while each
          client&apos;s assets, findings, integrations, and credentials remain separated.
        </p>
        <form
          className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]"
          onSubmit={(event) => {
            event.preventDefault();
            void createClient.run({ name, ...(slug.trim() ? { slug: slug.trim() } : {}) });
          }}
        >
          <Field label="Client organization" htmlFor="client-org-name">
            <Input id="client-org-name" required value={name} onChange={(event) => setName(event.target.value)} placeholder="Acme Security" />
          </Field>
          <Field label="Slug (optional)" htmlFor="client-org-slug">
            <Input id="client-org-slug" value={slug} onChange={(event) => setSlug(event.target.value)} placeholder="acme-security" />
          </Field>
          <div className="flex items-end"><Button type="submit" loading={createClient.loading}>Create client</Button></div>
          {createClient.errorMessage && <InlineError className="sm:col-span-3" message={createClient.errorMessage} />}
        </form>
        {clients.loading && !clients.data ? <LoadingState label="Loading client portfolio…" /> : clients.error ? <InlineError message={clients.error} /> : !clients.data?.length ? <EmptyState title="No client organizations" description="Create a client tenant to begin building a managed portfolio." /> : (
          <Table>
            <THead><TR><TH>Client</TH><TH>Assets</TH><TH>Open findings</TH><TH>Critical</TH><TH>Open risk</TH><TH>Delegate analyst</TH></TR></THead>
            <TBody>{clients.data.map((client: ClientOrganizationPortfolioOut) => {
              const selectedUserId = delegates[client.organization.id] ?? "";
              return <TR key={client.organization.id}><TD><div className="font-medium text-fg">{client.organization.name}</div><div className="font-mono text-xs text-muted">{client.organization.slug}</div></TD><TD>{formatNumber(client.asset_count)}</TD><TD>{formatNumber(client.open_finding_count)}</TD><TD>{formatNumber(client.critical_open_finding_count)}</TD><TD>{client.open_risk_score.toFixed(1)}</TD><TD><div className="flex min-w-64 gap-2"><Select aria-label={`Delegate analyst to ${client.organization.name}`} value={selectedUserId} onChange={(event) => setDelegates((current) => ({ ...current, [client.organization.id]: event.target.value }))}><option value="">Select a parent-team member…</option>{(parentMembers.data?.items ?? []).filter((member: MemberOut) => member.is_active).map((member: MemberOut) => <option key={member.user_id} value={member.user_id}>{member.full_name || member.email}</option>)}</Select><Button size="sm" variant="outline" disabled={!selectedUserId} loading={delegateClient.loading} onClick={() => void delegateClient.run({ clientOrganizationId: client.organization.id, userId: selectedUserId })}>Grant</Button></div></TD></TR>;
            })}</TBody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}

function CodeownersRouting({ org, onUpdated }: { org: OrganizationOut; onUpdated: (next: OrganizationOut) => void }) {
  const { toast } = useToast();
  const [source, setSource] = React.useState(org.policy.codeowners ?? "");
  const [mapping, setMapping] = React.useState(() => JSON.stringify(org.policy.codeowner_members ?? {}, null, 2));
  React.useEffect(() => {
    setSource(org.policy.codeowners ?? "");
    setMapping(JSON.stringify(org.policy.codeowner_members ?? {}, null, 2));
  }, [org.policy.codeowners, org.policy.codeowner_members]);
  const save = useMutation(api.organization.update, {
    onSuccess: (next) => {
      onUpdated(next);
      toast({ title: "CODEOWNERS routing saved", tone: "ok" });
    },
  });
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    let codeownerMembers: Record<string, string>;
    try {
      const parsed: unknown = JSON.parse(mapping || "{}");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object" || Object.entries(parsed).some(([key, value]) => !key.trim() || typeof value !== "string")) throw new Error("invalid mapping");
      codeownerMembers = parsed as Record<string, string>;
    } catch {
      toast({ title: "CODEOWNERS mapping must be a JSON object of owner token to member UUID", tone: "danger" });
      return;
    }
    void save.run({ policy: { ...org.policy, codeowners: source || null, codeowner_members: codeownerMembers } });
  };
  return <Card><CardHeader><CardTitle>CODEOWNERS remediation routing</CardTitle></CardHeader><CardBody className="space-y-3"><p className="text-sm text-muted">Automation rules using “Assign codeowner” match a finding&apos;s <code>repository_path</code> or <code>path</code> custom field and assign the mapped tenant member.</p><form className="space-y-3" onSubmit={submit}><Field label="CODEOWNERS rules" htmlFor="org-codeowners" hint="Use standard path and owner-token lines, such as /services/payments/ @payments-team."><Textarea id="org-codeowners" rows={7} value={source} onChange={(event) => setSource(event.target.value)} maxLength={50000} /></Field><Field label="Owner-token to Cynux member mapping" htmlFor="org-codeowner-members" hint="JSON mapping; each value is a member UUID from the Members table."><Textarea id="org-codeowner-members" rows={5} value={mapping} onChange={(event) => setMapping(event.target.value)} maxLength={30000} /></Field><InlineError message={save.errorMessage} /><Button type="submit" loading={save.loading}>Save routing</Button></form></CardBody></Card>;
}

export default function OrganizationPage() {
  const { can } = useAuth();
  const canRead = can("org:read");
  const canManageOrg = can("org:manage");
  const canManageMembers = can("member:manage");

  const org = useApiResource(() => api.organization.get(), [canRead], {
    enabled: canRead,
  });
  const members = useApiResource(
    () => api.organization.members({ limit: 100, offset: 0 }),
    [canRead],
    { enabled: canRead },
  );

  if (!canRead) {
    return (
      <div className="space-y-6">
        <PageHeader title="Organization" />
        <EmptyState
          title="No access"
          description="You don't have permission to view this."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organization"
        description="Manage your organization profile and team members."
      />

      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
        <CardBody className="space-y-6">
          {org.loading && !org.data ? (
            <LoadingState />
          ) : org.error ? (
            <ErrorState message={org.error} onRetry={org.refetch} />
          ) : org.data ? (
            <>
              <OrgSummary org={org.data} />
              {canManageOrg && <OrgEditForm org={org.data} onUpdated={org.setData} />}
            </>
          ) : null}
        </CardBody>
      </Card>

      {canManageOrg && org.data && <RiskWeightsEditor org={org.data} onUpdated={org.setData} />}
      {canManageOrg && org.data && <CodeownersRouting org={org.data} onUpdated={org.setData} />}
      {canManageOrg && <AgentMemoryEditor />}
      {canManageOrg && org.data && <IdentityProvisioning organizationSlug={org.data.slug} />}
      {canManageOrg && <ClientOrganizations />}

      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
        </CardHeader>
        <CardBody className="space-y-6">
          {canManageMembers && <InviteForm onInvited={members.refetch} />}

          {members.loading && !members.data ? (
            <LoadingState />
          ) : members.error ? (
            <ErrorState message={members.error} onRetry={members.refetch} />
          ) : !members.data || members.data.items.length === 0 ? (
            <EmptyState
              title="No members"
              description="No members found for this organization."
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Email</TH>
                  <TH>Name</TH>
                  <TH>Role</TH>
                  <TH>Active</TH>
                  <TH>Last login</TH>
                  {canManageMembers && <TH className="text-right">Actions</TH>}
                </TR>
              </THead>
              <TBody>
                {members.data.items.map((m) => (
                  <MemberRow
                    key={m.membership_id}
                    member={m}
                    canManage={canManageMembers}
                    onChanged={members.refetch}
                  />
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
