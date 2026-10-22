"use client";

import * as React from "react";

import { Badge, type BadgeTone } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardFooter, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Field, Input, Label, Select, Textarea } from "@/components/ui/Input";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { fieldError } from "@/lib/errors";
import { formatDate, formatRelative, humanize } from "@/lib/format";
import { configuredTenableScanIds, handleIntegrationSyncSuccess, handleIntegrationTestSuccess } from "@/lib/integration-actions";
import { certificationTone, summarizeCertification } from "@/lib/integration-certification";
import { ADDABLE_INTEGRATIONS, BYOK_PROVIDERS, INTEGRATION_SETUP_HINTS } from "@/lib/integration-catalog";
import type {
  ConnectorCertificationOut,
  IntegrationKind,
  IntegrationOut,
  IntegrationSyncOut,
  IntegrationSyncRunOut,
  IntegrationStatus,
  IntegrationTestOut,
  IntegrationUpsertIn,
  TenableScanLaunchOut,
  TenableScanStatusOut,
} from "@/lib/types";

/** Integration status → shared badge tone. Static map so Tailwind classes stay literal. */
const STATUS_TONE: Record<IntegrationStatus, BadgeTone> = {
  configured: "ok",
  unverified: "warn",
  error: "danger",
  disabled: "neutral",
};

interface CredRow {
  key: string;
  value: string;
}

type BYOKProvider = (typeof BYOK_PROVIDERS)[number]["kind"];

function ByokSetupCard({ onChanged }: { onChanged: () => void }) {
  const { toast } = useToast();
  const [provider, setProvider] = React.useState<BYOKProvider>("openai");
  const [model, setModel] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [formError, setFormError] = React.useState<string | null>(null);

  const upsert = useMutation((body: IntegrationUpsertIn) => api.integrations.upsert(body), {
    onSuccess: () => {
      setApiKey("");
      onChanged();
      toast({ title: "AI provider saved", tone: "ok" });
    },
  });

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!model.trim() || !apiKey.trim()) {
      setFormError("Choose a model and enter your provider API key.");
      return;
    }
    setFormError(null);
    const credentialName = `${provider}_api_key`;
    void upsert.run({
      kind: "llm",
      name: "Bring your own AI provider",
      is_enabled: true,
      config: { provider, default_model: model.trim() },
      credentials: { [credentialName]: apiKey.trim() },
    });
  };

  return (
    <Card className="border-primary/30">
      <CardHeader>
        <div>
          <CardTitle>Bring your own AI provider</CardTitle>
          <p className="mt-0.5 text-xs text-muted">Required for AI analysis, remediation and reports.</p>
        </div>
        <Badge tone="primary">BYOK</Badge>
      </CardHeader>
      <CardBody>
        <form className="space-y-4" onSubmit={submit}>
          <InlineError message={formError ?? upsert.errorMessage} />
          <Field label="Provider" htmlFor="byok-provider">
            <Select
              id="byok-provider"
              value={provider}
              onChange={(event) => setProvider(event.target.value as BYOKProvider)}
            >
              {BYOK_PROVIDERS.map((item) => (
                <option key={item.kind} value={item.kind}>{item.label}</option>
              ))}
            </Select>
          </Field>
          <Field label="Model" htmlFor="byok-model" hint="Use the exact model ID enabled for your key.">
            <Input
              id="byok-model"
              value={model}
              onChange={(event) => setModel(event.target.value)}
              placeholder={provider === "openai" ? "gpt-4.1-mini" : "your-model-id"}
            />
          </Field>
          <Field
            label="API key"
            htmlFor="byok-key"
            hint="Encrypted on save and never shown again."
          >
            <Input
              id="byok-key"
              type="password"
              autoComplete="new-password"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              placeholder="Paste your key"
            />
          </Field>
          <Button type="submit" loading={upsert.loading}>Save AI provider</Button>
        </form>
      </CardBody>
    </Card>
  );
}

function AddIntegrationCard({ existing, onChanged }: { existing: IntegrationOut[]; onChanged: () => void }) {
  const { toast } = useToast();
  const available = ADDABLE_INTEGRATIONS.filter(
    ({ kind }) => !existing.some((integration) => integration.kind === kind),
  );
  const [kind, setKind] = React.useState<IntegrationKind>(available[0]?.kind ?? "defectdojo");
  React.useEffect(() => {
    if (!available.some((item) => item.kind === kind)) setKind(available[0]?.kind ?? "defectdojo");
  }, [available, kind]);
  const create = useMutation((body: IntegrationUpsertIn) => api.integrations.upsert(body), {
    onSuccess: () => {
      onChanged();
      toast({ title: "Integration added", tone: "ok" });
    },
  });

  if (available.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Add integration</CardTitle>
          <p className="mt-0.5 text-xs text-muted">Add a service, then configure its endpoint and credentials.</p>
        </div>
      </CardHeader>
      <CardBody className="space-y-3">
        <InlineError message={create.errorMessage} />
        <Field label="Service" htmlFor="new-integration-kind">
          <Select
            id="new-integration-kind"
            value={kind}
            onChange={(event) => setKind(event.target.value as IntegrationKind)}
          >
            {available.map((item) => (
              <option key={item.kind} value={item.kind}>{item.label}</option>
            ))}
          </Select>
        </Field>
        <Button
          size="sm"
          loading={create.loading}
          onClick={() => void create.run({ kind, config: {}, credentials: {} })}
        >
          Add service
        </Button>
      </CardBody>
    </Card>
  );
}

const SCAN_IMPORT_FORMATS = [
  ["sarif", "SARIF"], ["nuclei_jsonl", "Nuclei JSONL"],
  ["nessus_xml", "Nessus XML"], ["burp_xml", "Burp XML"],
  ["qualys_host_detection_xml", "Qualys VM host-detection XML"],
  ["rapid7_csv", "Rapid7 InsightVM CSV"],
  ["aws_inspector_csv", "AWS Inspector CSV (account:resource cloud asset)"],
  ["azure_defender_json", "Azure Defender API JSON (full ARM resource ID)"],
  ["gcp_scc_json", "Google SCC API JSON (full cloud resource)"],
  ["prowler_ocsf", "Prowler JSON-OCSF (AWS, Azure, GCP account)"],
  ["hackerone_json", "HackerOne report detail JSON (structured scope required)"],
  ["bugcrowd_json", "Bugcrowd submissions API JSON (include=target)"],
  ["wiz_json", "Wiz issues JSON"],
  ["prisma_cloud_json", "Prisma Cloud alerts JSON"],
  ["sonarqube_json", "SonarQube issues JSON"],
  ["defectdojo_json", "DefectDojo findings JSON"],
  ["checkmarx_xml", "Checkmarx XML"],
  ["fortify_fvdl", "OpenText Fortify FVDL"],
  ["fortify_fpr", "OpenText Fortify FPR"],
  ["trivy", "Trivy JSON"], ["gitleaks", "Gitleaks JSON"],
  ["cyclonedx", "CycloneDX JSON"], ["spdx", "SPDX JSON"],
  ["generic_csv", "Mapped CSV"], ["generic_json", "Mapped JSON"],
] as const;

type ScanImportFormat = (typeof SCAN_IMPORT_FORMATS)[number][0];

function ScanImportCard() {
  const { toast } = useToast();
  const [file, setFile] = React.useState<File | null>(null);
  const [formatName, setFormatName] = React.useState<ScanImportFormat>("sarif");
  const [provider, setProvider] = React.useState("manual");
  const [assetType, setAssetType] = React.useState("repo");
  const [assetValue, setAssetValue] = React.useState("");
  const [mappingText, setMappingText] = React.useState(
    '{"id":"id","title":"title","severity":"severity","cve":"cve"}',
  );
  const [formError, setFormError] = React.useState<string | null>(null);
  const upload = useMutation(api.integrations.importScanExport, {
    onSuccess: (result) => toast({
      title: "Scanner findings imported",
      description: `${result.findings_staged} records staged in the canonical findings flow.`,
      tone: "ok",
    }),
  });
  const isGeneric = formatName === "generic_csv" || formatName === "generic_json";

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!file || file.size === 0 || file.size > 10 * 1024 * 1024) {
      setFormError("Choose a non-empty scanner export no larger than 10 MB.");
      return;
    }
    if (!/^[a-z][a-z0-9_-]{1,39}$/.test(provider.trim())) {
      setFormError("Provider must be 2–40 lowercase letters, digits, hyphens or underscores.");
      return;
    }
    if (!assetValue.trim()) {
      setFormError("Enter the asset this export belongs to.");
      return;
    }
    let fieldMapping: Record<string, string> | undefined;
    if (isGeneric) {
      try {
        const parsed: unknown = JSON.parse(mappingText);
        if (!parsed || Array.isArray(parsed) || typeof parsed !== "object" ||
            Object.values(parsed).some((value) => typeof value !== "string")) {
          throw new Error("invalid mapping");
        }
        fieldMapping = parsed as Record<string, string>;
      } catch {
        setFormError("Field mapping must be a JSON object of destination fields to source column names.");
        return;
      }
    }
    setFormError(null);
    void upload.run({
      file, formatName, provider: provider.trim(), assetType,
      assetValue: assetValue.trim(), fieldMapping,
    });
  };

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Import scanner findings or SBOM</CardTitle>
          <p className="mt-0.5 text-xs text-muted">Import code, cloud, vulnerability-management, DAST, bug-bounty and SBOM exports. Supported formats include SARIF, Nessus, Burp, Qualys, Rapid7, cloud-security feeds, Wiz, Prisma Cloud, SonarQube, DefectDojo, Checkmarx, Fortify, Trivy, Gitleaks, CycloneDX, SPDX and mapped CSV/JSON. Findings join the unified exposure model.</p>
        </div>
      </CardHeader>
      <CardBody>
        <form className="grid gap-4 sm:grid-cols-2" onSubmit={submit}>
          <div className="sm:col-span-2"><InlineError message={formError ?? upload.errorMessage} /></div>
          <Field label="Format" htmlFor="scan-import-format">
            <Select id="scan-import-format" value={formatName} onChange={(event) => setFormatName(event.target.value as ScanImportFormat)}>
              {SCAN_IMPORT_FORMATS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </Select>
          </Field>
          <Field label="Source name" htmlFor="scan-import-provider" hint="Lowercase identifier used to attribute findings to this scanner.">
            <Input id="scan-import-provider" value={provider} onChange={(event) => setProvider(event.target.value)} maxLength={40} />
          </Field>
          <Field label="Asset type" htmlFor="scan-import-asset-type">
            <Select id="scan-import-asset-type" value={assetType} onChange={(event) => setAssetType(event.target.value)}>
              <option value="repo">Repository</option><option value="container">Container</option>
              <option value="domain">Domain</option><option value="ip">IP address</option>
              <option value="url">URL</option><option value="cloud">Cloud resource</option>
              <option value="cloud_account">Cloud account (Prowler)</option>
            </Select>
          </Field>
          <Field label="Asset identity" htmlFor="scan-import-asset" hint={formatName === "prowler_ocsf" ? "Use aws:123456789012, azure:subscription-id, or gcp:project-id. Only findings from that account are imported." : "Select the exact asset in the export: host, URL, repository owner/name, full cloud resource ID, or HackerOne structured-scope identifier."}>
            <Input id="scan-import-asset" value={assetValue} onChange={(event) => setAssetValue(event.target.value)} maxLength={900} placeholder="acme/api" />
          </Field>
          {isGeneric && (
            <Field className="sm:col-span-2" label="Field mapping (JSON)" htmlFor="scan-import-mapping" hint="Required: id and title. Optional: severity, status, cve, package, location.">
              <Textarea id="scan-import-mapping" value={mappingText} onChange={(event) => setMappingText(event.target.value)} rows={3} maxLength={4096} />
            </Field>
          )}
          <Field className="sm:col-span-2" label="Export file" htmlFor="scan-import-file" hint="Maximum 10 MB. Matched secrets and unmapped fields are not retained.">
            <Input id="scan-import-file" type="file" accept=".json,.jsonl,.sarif,.csv,.nessus,.xml,application/json,text/csv,application/xml,text/xml" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
          </Field>
          <Button className="sm:col-span-2" type="submit" loading={upload.loading}>Import findings</Button>
        </form>
      </CardBody>
    </Card>
  );
}

function IntegrationCard({
  integration,
  canManage,
  onChanged,
}: {
  integration: IntegrationOut;
  canManage: boolean;
  onChanged: () => void;
}) {
  const { toast } = useToast();

  const [open, setOpen] = React.useState(false);
  const [baseUrl, setBaseUrl] = React.useState(integration.base_url ?? "");
  const [enabled, setEnabled] = React.useState(integration.is_enabled);
  const [syncInterval, setSyncInterval] = React.useState(
    integration.sync_interval_minutes === null
      ? ""
      : String(integration.sync_interval_minutes),
  );
  const [configText, setConfigText] = React.useState(() =>
    Object.keys(integration.config).length > 0
      ? JSON.stringify(integration.config, null, 2)
      : "",
  );
  const [credRows, setCredRows] = React.useState<CredRow[]>(() =>
    integration.credentials.length > 0
      ? integration.credentials.map((c) => ({ key: c.name, value: "" }))
      : [{ key: "", value: "" }],
  );
  const [formError, setFormError] = React.useState<string | null>(null);
  const [scanChoice, setScanChoice] = React.useState("");
  const [scanStatus, setScanStatus] = React.useState<TenableScanStatusOut | null>(null);
  const [lastLaunch, setLastLaunch] = React.useState<TenableScanLaunchOut | null>(null);

  const test = useMutation((kind: IntegrationKind) => api.integrations.test(kind), {
    onSuccess: (r: IntegrationTestOut) =>
      handleIntegrationTestSuccess(r, { refresh: onChanged, toast }),
  });
  const contractTest = useMutation((kind: IntegrationKind) => api.integrations.contractTest(kind), {
    onSuccess: (result) => {
      toast({ title: result.passed ? "Connector contract passed" : "Connector contract blocked", description: `${result.score}% · ${result.checks.filter((check) => check.passed).length}/${result.checks.length} checks passed`, tone: result.passed ? "ok" : "danger" });
      onChanged();
    },
  });

  const sync = useMutation((kind: "github" | "gitlab" | "wazuh" | "sonarqube" | "snyk" | "tenable" | "qualys" | "rapid7" | "wiz" | "prisma_cloud" | "crowdstrike" | "aws_security_hub" | "aws_inspector" | "hackerone" | "bugcrowd" | "checkmarx" | "fortify" | "azure_defender" | "gcp_scc" | "burp_dast") => api.integrations.sync(kind), {
    onSuccess: (result: IntegrationSyncOut) => {
      handleIntegrationSyncSuccess(result, { toast });
      onChanged();
    },
  });

  const checkScan = useMutation((scanId: string) => api.integrations.tenableStatus(scanId), {
    onSuccess: (result) => setScanStatus(result),
  });
  const launchScan = useMutation((scanId: string) => api.integrations.launchTenable(scanId), {
    onSuccess: (result) => {
      setLastLaunch(result);
      setScanStatus(null);
      toast({ title: "Tenable scan launched", description: result.run_uuid ? `Run ${result.run_uuid}. Check status before syncing findings.` : "Check status before syncing findings.", tone: "ok" });
    },
  });

  const remove = useMutation((kind: IntegrationKind) => api.integrations.remove(kind), {
    onSuccess: () => {
      onChanged();
      toast({ title: "Integration removed", tone: "ok" });
    },
  });

  const upsert = useMutation((body: IntegrationUpsertIn) => api.integrations.upsert(body), {
    onSuccess: () => {
      onChanged();
      toast({ title: "Integration saved", tone: "ok" });
      setOpen(false);
    },
  });

  const idBase = integration.kind;
  const tenableScans = integration.kind === "tenable" ? configuredTenableScanIds(integration.config) : [];
  const selectedScan = tenableScans.includes(scanChoice) ? scanChoice : (tenableScans[0] ?? "");
  const setupHint = integration.kind === "sonarqube" || integration.kind === "snyk" || integration.kind === "tenable" || integration.kind === "qualys" || integration.kind === "rapid7" || integration.kind === "wiz" || integration.kind === "prisma_cloud" || integration.kind === "crowdstrike" || integration.kind === "aws_security_hub" || integration.kind === "aws_inspector" || integration.kind === "hackerone" || integration.kind === "bugcrowd" || integration.kind === "checkmarx" || integration.kind === "fortify" || integration.kind === "azure_defender" || integration.kind === "gcp_scc" || integration.kind === "burp_dast" || integration.kind === "prowler_aws" || integration.kind === "prowler_azure" || integration.kind === "prowler_gcp" || integration.kind === "zscaler"
    ? INTEGRATION_SETUP_HINTS[integration.kind] : null;
  const syncKind =
    integration.kind === "github" ||
    integration.kind === "gitlab" ||
    integration.kind === "wazuh" ||
    integration.kind === "sonarqube" ||
    integration.kind === "snyk" ||
    integration.kind === "tenable" ||
    integration.kind === "qualys" ||
    integration.kind === "rapid7" ||
    integration.kind === "wiz" ||
    integration.kind === "prisma_cloud" ||
    integration.kind === "crowdstrike" ||
    integration.kind === "aws_security_hub"
    || integration.kind === "aws_inspector"
    || integration.kind === "hackerone"
    || integration.kind === "bugcrowd"
    || integration.kind === "checkmarx"
    || integration.kind === "fortify"
    || integration.kind === "azure_defender"
    || integration.kind === "gcp_scc"
    || integration.kind === "burp_dast"
      ? integration.kind
      : null;

  const updateRow = (idx: number, patch: Partial<CredRow>) =>
    setCredRows((rows) => rows.map((r, i) => (i === idx ? { ...r, ...patch } : r)));

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();

    let parsedConfig: Record<string, unknown> = {};
    const raw = configText.trim();
    if (raw) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        setFormError("Config must be valid JSON.");
        return;
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setFormError("Config must be a JSON object.");
        return;
      }
      parsedConfig = parsed as Record<string, unknown>;
    }
    setFormError(null);

    const parsedSyncInterval = syncInterval ? Number(syncInterval) : null;
    if (
      parsedSyncInterval !== null &&
      (!Number.isInteger(parsedSyncInterval) || parsedSyncInterval < 5 || parsedSyncInterval > 10080)
    ) {
      setFormError("Continuous sync interval must be a whole number from 5 to 10,080 minutes.");
      return;
    }

    const creds: Record<string, string> = {};
    for (const row of credRows) {
      const key = row.key.trim();
      if (key && row.value) creds[key] = row.value;
    }

    void upsert.run({
      kind: integration.kind,
      base_url: baseUrl.trim() || null,
      is_enabled: enabled,
      sync_interval_minutes: syncKind ? parsedSyncInterval : null,
      config: parsedConfig,
      credentials: creds,
    });
  };

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="min-w-0">
          <CardTitle className="truncate">{humanize(integration.kind)}</CardTitle>
          <p className="mt-0.5 truncate text-xs text-muted">{integration.name}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Badge tone={STATUS_TONE[integration.status]}>{humanize(integration.status)}</Badge>
          <Badge tone={integration.is_enabled ? "ok" : "neutral"}>
            {integration.is_enabled ? "Enabled" : "Disabled"}
          </Badge>
        </div>
      </CardHeader>

      <CardBody className="flex-1 space-y-3">
        <dl className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <dt className="text-xs text-faint">Endpoint</dt>
            <dd className="min-w-0 truncate font-mono text-xs text-muted">
              {integration.base_url ?? "—"}
            </dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-xs text-faint">Last verified</dt>
            <dd className="text-xs text-muted">{formatRelative(integration.last_verified_at)}</dd>
          </div>
          {syncKind && (
            <>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-xs text-faint">Continuous sync</dt>
                <dd className="text-xs text-muted">
                  {integration.sync_interval_minutes
                    ? `Every ${integration.sync_interval_minutes} min`
                    : "Off"}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-xs text-faint">Last sync</dt>
                <dd className="flex items-center gap-2 text-xs text-muted">
                  {integration.last_sync_status && (
                    <Badge tone={integration.last_sync_status === "succeeded" ? "ok" : "danger"}>
                      {humanize(integration.last_sync_status)}
                    </Badge>
                  )}
                  {formatRelative(integration.last_sync_at)}
                </dd>
              </div>
              {integration.sync_interval_minutes && (
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-xs text-faint">Next sync</dt>
                  <dd className="text-xs text-muted">{formatRelative(integration.next_sync_at)}</dd>
                </div>
              )}
            </>
          )}
          {integration.failure_count > 0 && (
            <div className="flex items-center justify-between gap-3">
              <dt className="text-xs text-faint">Recent failures</dt>
              <dd className="text-xs font-medium text-danger">{integration.failure_count}</dd>
            </div>
          )}
        </dl>

        {integration.last_error && (
          <p className="rounded-lg border border-danger/30 bg-danger/5 px-2.5 py-1.5 text-xs text-danger">
            {integration.last_error}
          </p>
        )}
        {integration.last_sync_error && (
          <p className="rounded-lg border border-danger/30 bg-danger/5 px-2.5 py-1.5 text-xs text-danger">
            Continuous sync: {integration.last_sync_error}
          </p>
        )}

        <div className="space-y-1.5">
          <p className="text-xs text-faint">Credentials</p>
          {integration.credentials.length > 0 ? (
            <ul className="space-y-1.5">
              {integration.credentials.map((c) => (
                <li
                  key={c.name}
                  className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted"
                >
                  <span className="font-medium text-fg">{c.name}</span>
                  {c.hint && <span>{c.hint}</span>}
                  <Badge tone="neutral">v{c.key_version}</Badge>
                  {c.expires_at && (
                    <span className="text-faint">expires {formatDate(c.expires_at)}</span>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-faint">No credentials stored.</p>
          )}
        </div>

        {integration.kind === "tenable" && (
          <div className="space-y-2 border-t border-line pt-3">
            <Field label="Configured scan" htmlFor={`${idBase}-scan`}>
              <Select id={`${idBase}-scan`} value={selectedScan}
                onChange={(event) => { setScanChoice(event.target.value); setScanStatus(null); setLastLaunch(null); }}>
                {tenableScans.length === 0 && <option value="">Configure a scan UUID first</option>}
                {tenableScans.map((scanId) => <option key={scanId} value={scanId}>{scanId}</option>)}
              </Select>
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" disabled={!selectedScan || checkScan.loading}
                loading={checkScan.loading} onClick={() => void checkScan.run(selectedScan)}>
                Check status
              </Button>
              {canManage && <Button size="sm" variant="primary" disabled={!selectedScan || launchScan.loading || !integration.is_enabled}
                loading={launchScan.loading} onClick={() => {
                  if (window.confirm(`Launch Tenable scan ${selectedScan} against its saved targets?`)) {
                    void launchScan.run(selectedScan);
                  }
                }}>
                Launch scan
              </Button>}
            </div>
            {scanStatus?.scan_id === selectedScan && <p className="text-xs text-muted">Tenable status: {scanStatus.status}</p>}
            {lastLaunch?.scan_id === selectedScan && <p className="break-all text-xs text-muted">Last launch accepted{lastLaunch.run_uuid ? `: ${lastLaunch.run_uuid}` : "."}</p>}
            <InlineError message={checkScan.errorMessage ?? launchScan.errorMessage} />
          </div>
        )}
        <InlineError message={contractTest.errorMessage ?? test.errorMessage ?? sync.errorMessage ?? remove.errorMessage} />
      </CardBody>

      {canManage && (
        <CardFooter className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            loading={test.loading}
            onClick={() => void test.run(integration.kind)}
          >
            Test
          </Button>
          <Button size="sm" variant="secondary" loading={contractTest.loading} onClick={() => void contractTest.run(integration.kind)}>
            Contract test
          </Button>
          {syncKind && (
            <Button
              size="sm"
              variant="secondary"
              loading={sync.loading}
              onClick={() => void sync.run(syncKind)}
            >
              Sync findings
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => setOpen((o) => !o)}>
            {open ? "Close" : "Configure"}
          </Button>
          <Button
            size="sm"
            variant="danger"
            loading={remove.loading}
            onClick={() => {
              if (window.confirm(`Remove the ${humanize(integration.kind)} integration?`)) {
                void remove.run(integration.kind);
              }
            }}
          >
            Remove
          </Button>
        </CardFooter>
      )}

      {canManage && open && (
        <form onSubmit={handleSubmit} className="space-y-4 border-t border-line px-5 py-4">
          <InlineError
            message={
              formError ?? (fieldError(upsert.error, "base_url") ? null : upsert.errorMessage)
            }
          />

          <Field
            label="Base URL"
            htmlFor={`${idBase}-base_url`}
            hint={integration.kind === "sonarqube" ? "SonarQube Server root URL, without /api. Leave blank to clear." : integration.kind === "snyk" ? "Optional regional Snyk API URL. Leave blank for api.snyk.io." : integration.kind === "tenable" ? "Tenable VM cloud URL is fixed at cloud.tenable.com." : integration.kind === "qualys" ? "A supported Qualys regional API URL. Leave blank for qualysapi.qualys.com." : integration.kind === "rapid7" ? "Your HTTPS InsightVM Security Console origin, without /api/3." : integration.kind === "wiz" ? "Wiz derives its authenticated GraphQL endpoint from region; no base URL is needed." : integration.kind === "prisma_cloud" ? "Your regional Prisma Cloud API origin, such as https://api.eu.prismacloud.io." : integration.kind === "crowdstrike" ? "CrowdStrike Falcon cloud origin, such as https://api.crowdstrike.com." : "Leave blank to clear."}
            error={fieldError(upsert.error, "base_url")}
          >
            <Input
              id={`${idBase}-base_url`}
              type="url"
              placeholder="https://…"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </Field>

          <label className="flex items-center gap-2 text-sm text-fg">
            <input
              type="checkbox"
              className="h-4 w-4 accent-primary"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled
          </label>

          {syncKind && (
            <Field
              label="Continuous sync interval"
              htmlFor={`${idBase}-sync-interval`}
              hint="Minutes between automatic provider pulls. Leave blank to sync manually."
            >
              <Input
                id={`${idBase}-sync-interval`}
                type="number"
                min={5}
                max={10080}
                step={1}
                placeholder="60"
                value={syncInterval}
                onChange={(event) => setSyncInterval(event.target.value)}
              />
            </Field>
          )}

          <Field
            label="Config (JSON)"
            htmlFor={`${idBase}-config`}
            hint={integration.kind === "sonarqube" ? "Enter the SonarQube project keys to sync; no secrets here." : integration.kind === "snyk" ? "Enter your Snyk organization UUID; no secrets here." : integration.kind === "tenable" ? "Enter up to 20 Tenable scan UUIDs; access and secret keys go in credentials." : integration.kind === "qualys" ? "Enter one explicit asset_ip. The connector only reads host detections for this IP." : integration.kind === "rapid7" ? "Enter 1-20 InsightVM numeric asset IDs. The connector only reads these assets' service vulnerabilities." : integration.kind === "wiz" ? "Enter the Wiz data-center region plus 1-100 explicit project IDs. The connector only reads Issues attached to these projects." : integration.kind === "prisma_cloud" ? "Enter 1-100 explicit cloud account IDs. Access-key credentials are stored encrypted and the connector is read-only." : integration.kind === "crowdstrike" ? "No non-secret scope is required; use a Falcon client with Vulnerabilities: READ." : integration.kind === "aws_security_hub" ? "Enter one AWS region and up to 20 account IDs; use credentials limited to securityhub:GetFindings." : integration.kind === "azure_defender" ? "Enter the subscription UUID and a service principal with read access to Microsoft.Security alerts." : integration.kind === "gcp_scc" ? "Enter a GCP project and SCC location; add a read-only service-account JSON key below." : integration.kind === "burp_dast" ? "Enter 1-100 numeric Burp DAST site IDs; add an API-user key below. Only the latest successful scan for each site is ingested." : integration.kind === "prowler_aws" ? "Enter the 12-digit AWS account ID; add read-only access_key_id and secret_access_key below." : integration.kind === "prowler_azure" ? "Enter the Azure subscription UUID; add the service-principal client_id, tenant_id, and client_secret below." : integration.kind === "prowler_gcp" ? "Enter the GCP project ID; add its service_account_json below as an encrypted credential." : "A JSON object of non-secret settings."}
            error={fieldError(upsert.error, "config")}
          >
            <Textarea
              id={`${idBase}-config`}
              className="font-mono text-xs"
              spellCheck={false}
              rows={4}
              placeholder={setupHint?.config ?? "{}"}
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
            />
          </Field>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Credentials</Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setCredRows((rows) => [...rows, { key: "", value: "" }])}
              >
                Add
              </Button>
            </div>
            {credRows.map((row, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <Input
                  placeholder={setupHint?.credential ?? "key"}
                  aria-label="Credential key"
                  className="flex-1"
                  value={row.key}
                  onChange={(e) => updateRow(idx, { key: e.target.value })}
                />
                <Input
                  type="password"
                  placeholder="value"
                  aria-label="Credential value"
                  autoComplete="new-password"
                  className="flex-1"
                  value={row.value}
                  onChange={(e) => updateRow(idx, { value: e.target.value })}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label="Remove credential"
                  onClick={() =>
                    setCredRows((rows) =>
                      rows.length > 1 ? rows.filter((_, i) => i !== idx) : rows,
                    )
                  }
                >
                  ✕
                </Button>
              </div>
            ))}
            <p className="text-xs text-faint">
              Write-only. Secrets are encrypted on save and never displayed. Blank rows are ignored.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button type="submit" size="sm" loading={upsert.loading}>
              Save
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </Card>
  );
}

export default function IntegrationsPage() {
  const { can } = useAuth();
  const canRead = can("integration:read");
  const canManage = can("integration:manage");

  const { data, error, loading, refetch } = useApiResource(
    () => api.integrations.list(),
    [],
    { enabled: canRead },
  );
  const coverage = useApiResource(
    () => api.integrations.coverage(),
    [],
    { enabled: canRead && can("finding:read") },
  );
  const certifications = useApiResource(
    () => api.integrations.certifications(),
    [],
    { enabled: canRead },
  );
  const syncRuns = useApiResource(
    () => api.integrations.syncRuns(30),
    [],
    { enabled: canRead },
  );
  const refresh = React.useCallback(() => {
    refetch();
    coverage.refetch();
    certifications.refetch();
    syncRuns.refetch();
  }, [refetch, coverage, certifications, syncRuns]);

  if (!canRead) {
    return (
      <EmptyState
        title="No access"
        description="You don't have permission to view this."
      />
    );
  }

  let body: React.ReactNode;
  if (loading && !data) {
    body = <LoadingState />;
  } else if (error) {
    body = <ErrorState message={error} onRetry={refetch} />;
  } else if (!data || data.length === 0) {
    body = (
      <EmptyState
        title="No integrations configured"
        description="Connect DefectDojo, Jira, Slack, threat-intel and other services to enrich and route assessment results."
      />
    );
  } else {
    body = (
      <div className="grid gap-4 sm:grid-cols-2">
        {data.map((integration) => (
          <IntegrationCard
            key={integration.kind}
            integration={integration}
            canManage={canManage}
            onChanged={refresh}
          />
        ))}
      </div>
    );
  }

  const hasByok = data?.some((integration) => integration.kind === "llm") ?? false;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Integrations"
        description="Connected AI, security, ticketing, notification and threat-intelligence services."
      />
      {canManage && !hasByok && <ByokSetupCard onChanged={refresh} />}
      {canManage && data && <AddIntegrationCard existing={data} onChanged={refresh} />}
      {can("assessment:create") && <ScanImportCard />}
      <Card>
        <CardHeader><div><CardTitle>Connector operational assurance</CardTitle><p className="mt-0.5 text-xs text-muted">Certification combines enabled state, required credentials, a recent live authentication test, circuit health, and current scheduled coverage.</p></div></CardHeader>
        <CardBody>
          {certifications.loading && !certifications.data ? <LoadingState label="Evaluating connector assurance…" /> : certifications.error ? <ErrorState message={certifications.error} onRetry={certifications.refetch} /> : certifications.data?.length ? (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{certifications.data.map((item: ConnectorCertificationOut) => <div key={item.kind} className="rounded-lg border border-line p-3">
              <div className="flex items-center justify-between gap-2"><span className="font-medium text-fg">{item.name}</span><Badge tone={certificationTone(item.grade)}>{item.score}% · {humanize(item.grade)}</Badge></div>
              <p className="mt-2 text-xs text-muted">{summarizeCertification(item.blockers)}</p>
              <div className="mt-3 flex flex-wrap gap-1">{item.capabilities.map((capability) => <Badge key={capability} tone="neutral">{humanize(capability)}</Badge>)}</div>
              <p className="mt-3 text-xs text-faint">{item.checks.filter((check) => check.passed).length}/{item.checks.length} operational checks passed</p>
            </div>)}</div>
          ) : <p className="text-sm text-muted">Configure a connector to begin operational certification.</p>}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><div><CardTitle>Source coverage and sync confidence</CardTitle><p className="mt-0.5 text-xs text-muted">Confidence combines connector health, schedule freshness, failed pulls, circuit state, and the source observations actually contributing to canonical findings.</p></div></CardHeader>
        <CardBody>
          {coverage.loading && !coverage.data ? <LoadingState label="Loading source coverage…" /> : coverage.error ? <ErrorState message={coverage.error} onRetry={coverage.refetch} /> : coverage.data?.length ? (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{coverage.data.map((source) => <div key={source.provider} className="rounded-lg border border-line p-3">
              <div className="flex items-center justify-between gap-2"><span className="font-medium text-fg">{humanize(source.provider)}</span><Badge tone={source.sync_confidence >= 0.8 ? "ok" : source.sync_confidence >= 0.4 ? "warn" : "danger"}>{Math.round(source.sync_confidence * 100)}%</Badge></div>
              <p className="mt-2 text-xs text-muted">{source.canonical_findings} unified findings · {source.active_observations} active observations</p>
              <p className="mt-1 text-xs text-faint">{humanize(source.coverage_state)} · {source.missing_observations} missing/stale source records</p>
              <p className="mt-2 text-xs text-muted">{source.coverage_reason}</p>
            </div>)}</div>
          ) : <p className="text-sm text-muted">No connector coverage has been recorded yet.</p>}
        </CardBody>
      </Card>
      <Card>
        <CardHeader><div><CardTitle>Connector execution history</CardTitle><p className="mt-0.5 text-xs text-muted">Append-only scheduled-sync receipts show timing, bounded checkpoints, staged records, absence candidates and safe failure classifications.</p></div></CardHeader>
        <CardBody>
          {syncRuns.loading && !syncRuns.data ? <LoadingState label="Loading connector execution history…" /> : syncRuns.error ? <ErrorState message={syncRuns.error} onRetry={syncRuns.refetch} /> : syncRuns.data?.length ? (
            <div className="space-y-2">{syncRuns.data.map((run: IntegrationSyncRunOut) => <div key={run.id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line p-3">
              <div><div className="flex flex-wrap items-center gap-2"><span className="font-medium text-fg">{run.name}</span><Badge tone={run.status === "succeeded" ? "ok" : run.status === "failed" ? "danger" : "warn"}>{humanize(run.status)}</Badge><Badge tone="neutral">{run.mode}</Badge></div><p className="mt-1 text-xs text-muted">{formatRelative(run.started_at)} · {run.duration_ms === null ? "in progress" : `${(run.duration_ms / 1000).toFixed(1)}s`} · {run.items_staged} staged · {run.absence_candidates} absence candidates</p>{run.error_summary && <p className="mt-1 text-xs text-danger">{run.error_code ? `${humanize(run.error_code)}: ` : ""}{run.error_summary}</p>}</div>
              <p className="text-xs text-faint">{humanize(run.kind)}</p>
            </div>)}</div>
          ) : <p className="text-sm text-muted">No scheduled connector execution has completed since run receipts were enabled.</p>}
        </CardBody>
      </Card>
      {body}
    </div>
  );
}
