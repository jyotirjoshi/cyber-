"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import * as React from "react";

import {
  Badge,
  CriticalityBadge,
  EnrichmentBadge,
  FindingStatusBadge,
  KevBadge,
  PriorityBadge,
  SeverityBadge,
} from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { PageHeader } from "@/components/ui/PageHeader";
import { ErrorState, InlineError, LoadingState } from "@/components/ui/States";
import { useToast } from "@/components/ui/Toast";
import { useApiResource, useMutation } from "@/hooks/useApi";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { getErrorMessage } from "@/lib/errors";
import { formatDate, formatDateTime, humanize } from "@/lib/format";
import type { EnrichmentStatus } from "@/lib/types";

/**
 * FR-024: the exact, verbatim string shown when an AI claim has no backing evidence. It must read
 * as "unverified", never as reassurance. Kept as a constant so it is impossible to paraphrase.
 */
const UNVERIFIABLE = "Unable to verify from available security intelligence.";

/** Pull the first non-empty string among `keys` off a loosely-typed record (evidence/references). */
function readStr(obj: Record<string, unknown>, ...keys: string[]): string | null {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return null;
}

/**
 * SEC-005 / FR-024: evidence URLs come from untrusted AI output (indirectly influenced by scanned
 * content), so a citation could carry a `javascript:`/`data:` scheme — which React does NOT strip
 * from an href and which executes on click. Only allow http(s) absolute URLs to become links;
 * anything else falls back to plain-text rendering of the label.
 */
function safeHttpUrl(value: string | null): string | null {
  if (!value) return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? value : null;
  } catch {
    return null;
  }
}

function Detail({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-muted">{label}</dt>
      <dd className="mt-0.5 break-words text-sm text-fg">{value ?? "—"}</dd>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FR-024 evidence — always rendered alongside the AI claims. When empty, the exact unverifiable
// sentinel is shown instead of citations, so a claim is never presented as verified without proof.
// ---------------------------------------------------------------------------

function EvidenceBlock({ evidence }: { evidence: Array<Record<string, unknown>> }) {
  if (evidence.length === 0) {
    return (
      <div className="rounded-lg border border-warn/30 bg-warn/5 px-3 py-2">
        <p className="text-xs font-semibold uppercase tracking-wide text-warn">Evidence</p>
        <p className="mt-1 text-sm text-warn">{UNVERIFIABLE}</p>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-line bg-surface-2/40 px-3 py-2">
      <p className="text-xs font-semibold uppercase tracking-wide text-faint">
        Evidence ({evidence.length})
      </p>
      <ul className="mt-1.5 space-y-1.5">
        {evidence.map((item, index) => {
          const source = readStr(item, "source", "provider", "type", "kind");
          const label =
            readStr(item, "title", "label", "name", "reference", "ref", "id") ??
            readStr(item, "detail", "description", "text", "value", "quote") ??
            "Evidence";
          const detail = readStr(item, "detail", "description", "text", "value", "quote");
          const url = safeHttpUrl(readStr(item, "url", "link", "href"));
          return (
            <li key={index} className="text-sm text-fg">
              <div className="flex flex-wrap items-baseline gap-2">
                {source && (
                  <span className="rounded border border-line bg-surface px-1.5 py-0.5 text-[11px] uppercase text-muted">
                    {source}
                  </span>
                )}
                {url ? (
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="break-all text-primary hover:underline"
                  >
                    {label}
                  </a>
                ) : (
                  <span className="break-words">{label}</span>
                )}
              </div>
              {detail && detail !== label && (
                <p className="mt-0.5 text-xs text-muted">{detail}</p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** A single threat-intel provider row: the status badge is ALWAYS shown so "unavailable" ≠ absent. */
function ProviderRow({
  label,
  status,
  children,
}: {
  label: string;
  status: EnrichmentStatus;
  children?: React.ReactNode;
}) {
  const hasData = status === "complete" || status === "partial";
  return (
    <div className="border-t border-line py-3 first:border-0 first:pt-0">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-fg">{label}</span>
        <EnrichmentBadge status={status} />
      </div>
      {hasData && children ? (
        <div className="mt-2 space-y-1 text-sm text-muted">{children}</div>
      ) : null}
    </div>
  );
}

export default function FindingDetailPage() {
  const params = useParams();
  const rawId = params.id;
  const id = (Array.isArray(rawId) ? rawId[0] : rawId) ?? "";
  const { toast } = useToast();
  const { can } = useAuth();

  const canRead = can("finding:read");
  const canAnalyze = can("finding:analyze");
  const canRemediate = can("finding:remediate");
  const canTicket = can("ticket:create");

  const { data, error, loading, refetch, setData } = useApiResource(
    () => api.findings.get(id),
    [id],
    { enabled: canRead && !!id },
  );

  const analyzeMut = useMutation((force: boolean) => api.findings.analyze(id, { force }), {
    onSuccess: (next) => {
      setData(next);
      toast({ title: "Analysis complete", tone: "ok" });
    },
    onError: (e) =>
      toast({ title: "Analysis failed", description: getErrorMessage(e), tone: "danger" }),
  });

  const remediateMut = useMutation(() => api.findings.remediate(id, {}), {
    onSuccess: () => {
      refetch();
      toast({ title: "Remediation guidance generated", tone: "ok" });
    },
    onError: (e) =>
      toast({ title: "Couldn't generate remediation", description: getErrorMessage(e), tone: "danger" }),
  });

  const ticketMut = useMutation(() => api.findings.createTicket(id, {}), {
    onSuccess: (ticket) => {
      refetch();
      toast({ title: "Ticket created", description: ticket.external_key, tone: "ok" });
    },
    onError: (e) =>
      toast({ title: "Couldn't create ticket", description: getErrorMessage(e), tone: "danger" }),
  });

  if (!canRead) {
    return <EmptyState title="No access" description="You don't have permission to view this." />;
  }
  if (loading && !data) return <LoadingState label="Loading finding…" />;
  if (error && !data) return <ErrorState message={error} onRetry={refetch} />;
  if (!data) {
    return <EmptyState title="Finding not found" description="This finding may have been removed." />;
  }

  const f = data;
  const enr = f.enrichment;
  const hasAnalysis =
    f.ai_analyzed_at != null &&
    Boolean(f.ai_explanation || f.ai_business_impact || f.ai_attack_scenario);

  return (
    <div className="space-y-6">
      <PageHeader
        title={f.title}
        description={
          [f.scanner ? humanize(f.scanner) : null, f.endpoint]
            .filter(Boolean)
            .join(" · ") || undefined
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main column */}
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                {f.priority && <PriorityBadge priority={f.priority} />}
                <FindingStatusBadge status={f.status} />
                <KevBadge inKev={f.in_kev} showNegative />
              </div>
            </CardHeader>
            <CardBody className="space-y-5">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
                <Detail label="Scanner" value={humanize(f.scanner)} />
                <Detail label="Endpoint" value={f.endpoint} />
                <Detail label="Component" value={f.component} />
                <Detail label="Version" value={f.component_version} />
                <Detail
                  label="CVSS"
                  value={
                    f.cvss_score != null
                      ? `${f.cvss_score.toFixed(1)}${f.cvss_vector ? ` · ${f.cvss_vector}` : ""}`
                      : null
                  }
                />
                <Detail label="CWE" value={f.cwe != null ? `CWE-${f.cwe}` : null} />
                <Detail
                  label="Risk score"
                  value={f.risk_score != null ? `${(f.risk_score * 100).toFixed(0)}%` : null}
                />
                <Detail
                  label="Asset criticality"
                  value={
                    f.asset_criticality ? <CriticalityBadge criticality={f.asset_criticality} /> : null
                  }
                />
                <Detail label="DefectDojo ID" value={String(f.defectdojo_finding_id)} />
                <Detail label="First seen" value={formatDateTime(f.first_seen_at)} />
                <Detail label="Last seen" value={formatDateTime(f.last_seen_at)} />
              </dl>

              {f.cve_ids.length > 0 && (
                <div>
                  <p className="mb-2 text-xs font-medium text-muted">CVEs</p>
                  <div className="flex flex-wrap gap-2">
                    {f.cve_ids.map((cve) => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="rounded border border-line bg-surface-2 px-2 py-0.5 font-mono text-xs text-primary hover:underline"
                      >
                        {cve}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {f.asset && (
                <div className="border-t border-line pt-4">
                  <Link
                    href={`/assets/${f.asset.id}`}
                    className="text-sm text-primary hover:underline"
                  >
                    View affected asset: {f.asset.name} →
                  </Link>
                </div>
              )}
            </CardBody>
          </Card>

          {/* AI analysis — FR-024: claims are only ever shown together with their evidence. */}
          <Card>
            <CardHeader>
              <CardTitle>AI analysis</CardTitle>
              <div className="flex items-center gap-2">
                <Badge tone="info">Advisory</Badge>
                {canAnalyze && hasAnalysis && (
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={analyzeMut.loading}
                    onClick={() => void analyzeMut.run(true)}
                  >
                    Re-analyze
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardBody className="space-y-4">
              {!hasAnalysis ? (
                <div className="space-y-3">
                  <p className="text-sm text-muted">
                    {f.ai_skipped_reason
                      ? `AI analysis was not performed: ${f.ai_skipped_reason}`
                      : "This finding has not been analyzed by the AI yet."}
                  </p>
                  {canAnalyze && (
                    <Button
                      size="sm"
                      loading={analyzeMut.loading}
                      onClick={() => void analyzeMut.run(false)}
                    >
                      Run AI analysis
                    </Button>
                  )}
                  <InlineError message={analyzeMut.errorMessage} />
                </div>
              ) : (
                <>
                  {f.ai_explanation && (
                    <section>
                      <h4 className="text-xs font-semibold uppercase tracking-wide text-faint">
                        Explanation
                      </h4>
                      <p className="mt-1 whitespace-pre-wrap text-sm text-fg">{f.ai_explanation}</p>
                    </section>
                  )}
                  {f.ai_business_impact && (
                    <section>
                      <h4 className="text-xs font-semibold uppercase tracking-wide text-faint">
                        Business impact
                      </h4>
                      <p className="mt-1 whitespace-pre-wrap text-sm text-fg">
                        {f.ai_business_impact}
                      </p>
                    </section>
                  )}
                  {f.ai_attack_scenario && (
                    <section>
                      <h4 className="text-xs font-semibold uppercase tracking-wide text-faint">
                        Attack scenario
                      </h4>
                      <p className="mt-1 whitespace-pre-wrap text-sm text-fg">
                        {f.ai_attack_scenario}
                      </p>
                    </section>
                  )}

                  {/* The evidence (or the explicit unverifiable notice) is mandatory (FR-024). */}
                  <EvidenceBlock evidence={f.ai_evidence} />

                  <p className="text-xs text-faint">
                    {f.ai_model ? `Model: ${f.ai_model} · ` : ""}
                    Analyzed {formatDateTime(f.ai_analyzed_at)}
                  </p>
                </>
              )}
            </CardBody>
          </Card>

          {/* Remediation — FR-025 / FR-034: advisory only, never auto-applied. */}
          <Card>
            <CardHeader>
              <CardTitle>Remediation</CardTitle>
              {canRemediate && (
                <Button
                  size="sm"
                  variant="secondary"
                  loading={remediateMut.loading}
                  onClick={() => void remediateMut.run()}
                >
                  {f.remediations.length > 0 ? "Generate another" : "Generate guidance"}
                </Button>
              )}
            </CardHeader>
            <CardBody className="space-y-4">
              <div className="rounded-lg border border-info/30 bg-info/5 px-3 py-2 text-xs text-muted">
                Advisory guidance only. Review before applying — CYNUX never changes your systems
                automatically.
              </div>
              <InlineError message={remediateMut.errorMessage} />
              {f.remediations.length === 0 ? (
                <p className="text-sm text-muted">No remediation guidance yet.</p>
              ) : (
                <ul className="space-y-5">
                  {f.remediations.map((r) => (
                    <li key={r.id} className="space-y-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-fg">{humanize(r.approach)}</span>
                        {r.effort && <Badge tone="neutral">{humanize(r.effort)} effort</Badge>}
                      </div>
                      <p className="text-sm text-muted">{r.summary}</p>
                      {r.steps.length > 0 && (
                        <ol className="list-decimal space-y-1 pl-5 text-sm text-fg">
                          {r.steps.map((step, index) => (
                            <li key={index}>{step}</li>
                          ))}
                        </ol>
                      )}
                      {r.code_patch && (
                        <div>
                          {r.patch_language && (
                            <p className="mb-1 text-xs text-faint">{r.patch_language}</p>
                          )}
                          <pre className="overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 text-xs text-fg">
                            <code>{r.code_patch}</code>
                          </pre>
                        </div>
                      )}
                      {r.configuration_change && (
                        <div>
                          <p className="text-xs font-medium text-muted">Configuration change</p>
                          <p className="mt-0.5 whitespace-pre-wrap text-sm text-fg">
                            {r.configuration_change}
                          </p>
                        </div>
                      )}
                      {r.verification && (
                        <div>
                          <p className="text-xs font-medium text-muted">Verification</p>
                          <p className="mt-0.5 text-sm text-fg">{r.verification}</p>
                        </div>
                      )}
                      {r.side_effects && (
                        <div>
                          <p className="text-xs font-medium text-muted">Side effects</p>
                          <p className="mt-0.5 text-sm text-fg">{r.side_effects}</p>
                        </div>
                      )}
                      <p className="text-xs text-faint">
                        {r.ai_model ? `Model: ${r.ai_model} · ` : ""}
                        {r.generated_at ? `Generated ${formatDateTime(r.generated_at)}` : ""}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Threat intelligence — FR-020: every provider's status is shown; unavailable ≠ safe. */}
          <Card>
            <CardHeader>
              <CardTitle>Threat intelligence</CardTitle>
              {enr && <EnrichmentBadge status={enr.status} />}
            </CardHeader>
            <CardBody>
              {!enr ? (
                <p className="text-sm text-muted">
                  No threat intelligence available for this finding.
                </p>
              ) : (
                <div>
                  <ProviderRow label="CISA KEV" status={enr.kev_status}>
                    <div className="flex flex-wrap items-center gap-2">
                      <KevBadge inKev={enr.in_kev} showNegative />
                    </div>
                    {enr.in_kev === true && (
                      <>
                        {enr.kev_date_added && <p>Added: {formatDate(enr.kev_date_added)}</p>}
                        {enr.kev_due_date && <p>Remediation due: {formatDate(enr.kev_due_date)}</p>}
                        {enr.kev_ransomware_use && <p>Ransomware use: {enr.kev_ransomware_use}</p>}
                        {enr.kev_required_action && (
                          <p className="text-fg">{enr.kev_required_action}</p>
                        )}
                      </>
                    )}
                  </ProviderRow>

                  <ProviderRow label="NVD" status={enr.nvd_status}>
                    {enr.nvd_cvss_v31_score != null && (
                      <p>
                        CVSS v3.1: {enr.nvd_cvss_v31_score.toFixed(1)}
                        {enr.nvd_cvss_v31_vector ? ` · ${enr.nvd_cvss_v31_vector}` : ""}
                      </p>
                    )}
                    {enr.nvd_published_at && <p>Published: {formatDate(enr.nvd_published_at)}</p>}
                    {enr.nvd_cwe_ids.length > 0 && <p>CWE: {enr.nvd_cwe_ids.join(", ")}</p>}
                    {enr.nvd_description && (
                      <p className="line-clamp-4 text-fg">{enr.nvd_description}</p>
                    )}
                    {enr.nvd_references.length > 0 && (
                      <p className="text-faint">{enr.nvd_references.length} reference(s)</p>
                    )}
                  </ProviderRow>

                  <ProviderRow label="EPSS" status={enr.epss_status}>
                    {enr.epss_score != null && (
                      <p>
                        Exploit probability: {(enr.epss_score * 100).toFixed(1)}%
                        {enr.epss_percentile != null
                          ? ` (${(enr.epss_percentile * 100).toFixed(0)}th pct)`
                          : ""}
                      </p>
                    )}
                  </ProviderRow>

                  <ProviderRow label="MISP" status={enr.misp_status}>
                    {enr.misp_event_count != null && <p>{enr.misp_event_count} related event(s)</p>}
                  </ProviderRow>

                  {Object.keys(enr.provider_errors).length > 0 && (
                    <div className="mt-3 space-y-1 border-t border-line pt-3">
                      {Object.entries(enr.provider_errors).map(([provider, message]) => (
                        <p key={provider} className="text-xs text-faint">
                          {humanize(provider)}: {message}
                        </p>
                      ))}
                    </div>
                  )}

                  {enr.enriched_at && (
                    <p className="mt-3 text-xs text-faint">
                      Enriched {formatDateTime(enr.enriched_at)}
                    </p>
                  )}
                </div>
              )}
            </CardBody>
          </Card>

          {/* Tickets */}
          <Card>
            <CardHeader>
              <CardTitle>Tickets</CardTitle>
              {canTicket && (
                <Button
                  size="sm"
                  variant="secondary"
                  loading={ticketMut.loading}
                  onClick={() => void ticketMut.run()}
                >
                  Create Jira ticket
                </Button>
              )}
            </CardHeader>
            <CardBody className="space-y-3">
              <InlineError message={ticketMut.errorMessage} />
              {f.tickets.length === 0 ? (
                <p className="text-sm text-muted">No tickets linked to this finding.</p>
              ) : (
                <ul className="space-y-2">
                  {f.tickets.map((t) => (
                    <li
                      key={t.id}
                      className="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2"
                    >
                      <div className="min-w-0">
                        {t.url ? (
                          <a
                            href={t.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sm font-medium text-primary hover:underline"
                          >
                            {t.external_key}
                          </a>
                        ) : (
                          <span className="text-sm font-medium text-fg">{t.external_key}</span>
                        )}
                        <p className="mt-0.5 text-xs text-muted">
                          {humanize(t.provider)}
                          {t.created_by_agent ? " · created by agent" : ""}
                        </p>
                      </div>
                      {t.external_status && <Badge tone="neutral">{t.external_status}</Badge>}
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  );
}
