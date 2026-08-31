/**
 * Wire types — the single TypeScript mirror of the backend's `app/schemas/*` and
 * `app/db/enums.py`. INTERFACES §14: `types.ts` mirrors the schema layer exactly; nothing
 * else in the frontend redeclares a server shape.
 *
 * Conventions:
 * - UUIDs and datetimes cross the wire as strings (`Uuid` / `IsoDateTime` aliases below).
 * - A backend `X | None` becomes `X | null`: FastAPI serializes response models with their
 *   null fields present, so the value is `null`, not absent. `?:` is reserved for request
 *   bodies where omitting a key is meaningful.
 * - Enums are string-literal unions carrying the exact wire value (lowercase or UPPER as the
 *   backend declares). `null` is never coerced to a boolean — `in_kev`, KEV status and MTTR
 *   preserve "unknown" as `null` per FR-020.
 */

export type Uuid = string;
export type IsoDateTime = string;
export type IsoDate = string;

// ---------------------------------------------------------------------------
// Enumerations (app/db/enums.py) — exact wire strings.
// ---------------------------------------------------------------------------

export type Role = "owner" | "admin" | "security_engineer" | "developer" | "viewer";

export type Permission =
  | "org:read"
  | "org:manage"
  | "member:manage"
  | "integration:read"
  | "integration:manage"
  | "assessment:read"
  | "assessment:create"
  | "assessment:approve"
  | "assessment:cancel"
  | "asset:read"
  | "asset:tag"
  | "finding:read"
  | "finding:analyze"
  | "finding:remediate"
  | "ticket:create"
  | "report:read"
  | "report:generate"
  | "audit:read"
  | "agent:chat";

export type AssessmentStatus =
  | "CREATED"
  | "PLANNING"
  | "DISCOVERY"
  | "WAITING_FOR_APPROVAL"
  | "SCANNING"
  | "ANALYZING"
  | "REMEDIATING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLING"
  | "CANCELLED";

export type AssessmentStage =
  | "queued"
  | "understanding_request"
  | "validating_target"
  | "checking_authorization"
  | "planning"
  | "reconnaissance"
  | "asset_analysis"
  | "awaiting_approval"
  | "scanning_nmap"
  | "scanning_nuclei"
  | "scanning_zap"
  | "importing_findings"
  | "threat_intelligence"
  | "ai_analysis"
  | "risk_prioritization"
  | "remediation"
  | "creating_actions"
  | "report"
  | "done";

/** Ordered checklist the FR-038 progress tracker renders. Mirrors `STAGE_ORDER`. */
export const STAGE_ORDER: readonly AssessmentStage[] = [
  "understanding_request",
  "validating_target",
  "checking_authorization",
  "planning",
  "reconnaissance",
  "asset_analysis",
  "awaiting_approval",
  "scanning_nmap",
  "scanning_nuclei",
  "scanning_zap",
  "importing_findings",
  "threat_intelligence",
  "ai_analysis",
  "risk_prioritization",
  "remediation",
  "creating_actions",
  "report",
];

/** Human labels for stages, for the checklist and stage pills. */
export const STAGE_LABELS: Record<AssessmentStage, string> = {
  queued: "Queued",
  understanding_request: "Understanding request",
  validating_target: "Validating target",
  checking_authorization: "Checking authorization",
  planning: "Planning",
  reconnaissance: "Reconnaissance",
  asset_analysis: "Asset analysis",
  awaiting_approval: "Awaiting approval",
  scanning_nmap: "Scanning — Nmap",
  scanning_nuclei: "Scanning — Nuclei",
  scanning_zap: "Scanning — ZAP",
  importing_findings: "Importing findings",
  threat_intelligence: "Threat intelligence",
  ai_analysis: "AI analysis",
  risk_prioritization: "Risk prioritization",
  remediation: "Remediation",
  creating_actions: "Creating actions",
  report: "Report",
  done: "Done",
};

export type AssessmentDepth = "passive" | "standard" | "deep";

export type Scope = "external" | "internal" | "application" | "code";

export type AssetStatus = "active" | "inactive" | "unreachable" | "out_of_scope";

export type Criticality = "critical" | "high" | "normal" | "low" | "unknown";

export type CriticalitySource =
  | "operator_tag"
  | "inferred_keyword"
  | "inferred_exposure"
  | "default";

export type ScannerName = "reconftw" | "nmap" | "nuclei" | "zap";

export type JobStatus =
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "TIMEOUT";

export type ArtifactKind = "raw_output" | "stdout" | "stderr" | "report";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Higher is worse — ordering + severity floor. Mirrors `Severity.rank`. */
export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type FindingStatus =
  | "active"
  | "verified"
  | "false_positive"
  | "risk_accepted"
  | "out_of_scope"
  | "mitigated"
  | "duplicate";

export type Priority = "P1" | "P2" | "P3" | "P4" | "P5";

export type EnrichmentStatus =
  | "pending"
  | "complete"
  | "partial"
  | "unavailable"
  | "not_applicable";

export type RiskLevel = "low" | "medium" | "high" | "forbidden";

export type AgentRunStatus =
  | "queued"
  | "running"
  | "interrupted"
  | "completed"
  | "failed"
  | "cancelled";

export type StepStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "skipped"
  | "degraded";

export type MessageRole = "user" | "assistant" | "system" | "tool";

export type ApprovalDecision =
  | "pending"
  | "approved"
  | "approved_all"
  | "customized"
  | "rejected"
  | "expired";

export type ApprovalKind =
  | "scan_scope"
  | "high_risk_tool"
  | "remediation_apply"
  | "ticket_bulk_create";

export type IntegrationKind =
  | "defectdojo"
  | "jira"
  | "slack"
  | "email"
  | "dify"
  | "misp"
  | "nvd"
  | "github"
  | "gitlab";

export type IntegrationStatus = "configured" | "unverified" | "error" | "disabled";

export type AuditOutcome = "success" | "failure" | "denied";

export type ReportFormat = "html" | "pdf" | "json";

export type ReportStatus = "pending" | "generating" | "ready" | "failed";

// ---------------------------------------------------------------------------
// Common envelopes (app/schemas/common.py) + errors.py.
// ---------------------------------------------------------------------------

/** RFC 9457 problem document. `title` is the only user-safe field to render verbatim. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  code: string;
  category: string;
  retryable: boolean;
  detail?: string | null;
  instance?: string | null;
  request_id?: string | null;
  /** Field-level validation errors: `{ "field.path": ["message", ...] }`. */
  errors?: Record<string, string[]> | null;
}

export interface PageMeta {
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

/** Envelope for every list endpoint, e.g. `Page<FindingOut>`. */
export interface Page<T> {
  items: T[];
  meta: PageMeta;
}

export interface DependencyHealth {
  name: string;
  healthy: boolean;
  detail: string | null;
  latency_ms: number | null;
}

export interface HealthOut {
  status: "ok" | "degraded" | "unhealthy";
  version: string;
  environment: string;
  dependencies: DependencyHealth[];
  warnings: string[];
}

export interface OkOut {
  ok: boolean;
}

// ---------------------------------------------------------------------------
// Auth + identity (app/schemas/auth.py, organization.py).
// ---------------------------------------------------------------------------

export interface RegisterIn {
  email: string;
  password: string;
  full_name?: string | null;
  organization_name: string;
}

export interface LoginIn {
  email: string;
  password: string;
}

export interface TokenPairOut {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface RefreshIn {
  refresh_token: string;
}

export interface UserOut {
  id: Uuid;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_email_verified: boolean;
  created_at: IsoDateTime;
  last_login_at: IsoDateTime | null;
}

export interface MembershipOut {
  organization_id: Uuid;
  organization_name: string;
  organization_slug: string;
  role: Role;
  is_default: boolean;
  joined_at: IsoDateTime | null;
}

export interface MeOut {
  user: UserOut;
  organizations: MembershipOut[];
  active_organization_id: Uuid | null;
  active_role: Role | null;
  permissions: Permission[];
}

export interface ChangePasswordIn {
  current_password: string;
  new_password: string;
}

export interface PasswordResetRequestIn {
  email: string;
}

export interface PasswordResetConfirmIn {
  token: string;
  new_password: string;
}

export interface LogoutIn {
  refresh_token?: string | null;
}

export interface SwitchOrganizationIn {
  organization_id: Uuid;
}

export interface OrganizationOut {
  id: Uuid;
  name: string;
  slug: string;
  is_active: boolean;
  max_concurrent_scanner_jobs: number;
  created_at: IsoDateTime;
}

export interface OrganizationUpdateIn {
  name?: string | null;
  max_concurrent_scanner_jobs?: number | null;
  policy?: Record<string, unknown> | null;
}

export interface MemberOut {
  membership_id: Uuid;
  user_id: Uuid;
  email: string;
  full_name: string | null;
  role: Role;
  is_active: boolean;
  accepted_at: IsoDateTime | null;
  last_login_at: IsoDateTime | null;
}

export interface MemberInviteIn {
  email: string;
  role?: Role;
  full_name?: string | null;
}

export interface MemberRoleIn {
  role: Role;
}

// ---------------------------------------------------------------------------
// Assessments (app/schemas/assessment.py).
// ---------------------------------------------------------------------------

export const MAX_TARGETS = 50;

/** FR-006 operator attestation. Required, and `confirmed` must be true. */
export interface AuthorizationIn {
  confirmed: boolean;
  attestation_text: string;
  evidence_reference?: string | null;
}

export interface AssessmentCreateIn {
  targets: string[];
  title?: string | null;
  scope?: Scope;
  depth?: AssessmentDepth;
  objective?: string | null;
  authorization: AuthorizationIn;
  notify?: string[];
}

export interface TargetOut {
  id: Uuid;
  raw_value: string;
  canonical_value: string;
  target_type: string;
  host: string;
  port: number | null;
  host_count: number;
}

export interface PlanStepOut {
  index: number;
  stage: AssessmentStage;
  title: string;
  tool: string | null;
  rationale: string | null;
  requires_approval: boolean;
  status: StepStatus;
}

/** One row of the FR-038 progress checklist, ordered by STAGE_ORDER. */
export interface StageOut {
  stage: AssessmentStage;
  label: string;
  status: StepStatus;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  detail: string | null;
}

/** A dependency that failed without failing the assessment (FR-020, FR-039). */
export interface DegradationOut {
  stage: string;
  component: string;
  reason: string;
  impact: string;
  occurred_at: IsoDateTime | null;
}

/** An asset the agent proposes to scan — the FR-011 approval card renders these. */
export interface ProposedAssetOut {
  asset_id: Uuid;
  name: string;
  endpoint: string | null;
  criticality: Criticality;
  risk_score: number;
  internet_exposed: boolean;
  scanners: ScannerName[];
  rationale: string | null;
}

export interface ApprovalOut {
  id: Uuid;
  assessment_id: Uuid;
  agent_run_id: Uuid | null;
  kind: ApprovalKind;
  decision: ApprovalDecision;
  prompt: string;
  rationale: string | null;
  risk_level: RiskLevel;
  requested_payload: Record<string, unknown>;
  approved_payload: Record<string, unknown>;
  expires_at: IsoDateTime | null;
  resolved_at: IsoDateTime | null;
  resolved_by: string | null;
  resolution_note: string | null;
  proposed_assets: ProposedAssetOut[];
  proposed_scanners: ScannerName[];
  created_at: IsoDateTime;
}

/** Resolution of a pending approval (FR-011). `customized` requires `asset_ids`. */
export interface ApproveIn {
  decision: "approved" | "approved_all" | "customized" | "rejected";
  asset_ids?: Uuid[] | null;
  scanners?: ScannerName[] | null;
  note?: string | null;
}

export interface CancelIn {
  reason?: string | null;
}

/** Assessment list row. */
export interface AssessmentOut {
  id: Uuid;
  reference: number;
  title: string;
  status: AssessmentStatus;
  current_stage: AssessmentStage;
  progress_percent: number;
  scope: Scope;
  depth: AssessmentDepth;
  findings_total: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_info: number;
  assets_discovered: number;
  assets_in_scope: number;
  created_at: IsoDateTime;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  duration_seconds: number | null;
  targets: TargetOut[];
  created_by: string | null;
}

export interface AssessmentDetailOut extends AssessmentOut {
  plan: PlanStepOut[];
  request_interpretation: Record<string, unknown>;
  stages: StageOut[];
  degradations: DegradationOut[];
  pending_approval: ApprovalOut | null;
  failure_reason: string | null;
  failure_category: string | null;
  agent_session_id: Uuid | null;
  defectdojo_engagement_id: number | null;
  defectdojo_product_id: number | null;
}

/** Query params for `GET /assessments`. */
export interface AssessmentFilter {
  status?: AssessmentStatus;
  scope?: Scope;
  active?: boolean;
  awaiting_approval?: boolean;
  q?: string;
}

// ---------------------------------------------------------------------------
// Assets (app/schemas/asset.py).
// ---------------------------------------------------------------------------

export interface AssetTagOut {
  id: Uuid;
  key: string;
  value: string | null;
  is_operator_applied: boolean;
  applied_by_id: Uuid | null;
  created_at: IsoDateTime;
}

export interface AssetTagIn {
  key: string;
  value?: string | null;
}

export interface AssetOut {
  id: Uuid;
  assessment_id: Uuid | null;
  name: string;
  asset_type: string;
  ip_address: string | null;
  port: number | null;
  protocol: string | null;
  service: string | null;
  technology: string[];
  status: AssetStatus;
  internet_exposed: boolean;
  http_title: string | null;
  http_status_code: number | null;
  tls_subject: string | null;
  criticality: Criticality;
  criticality_source: CriticalitySource;
  criticality_rationale: string | null;
  risk_score: number;
  selected_for_scanning: boolean;
  selection_rationale: string | null;
  evidence: Record<string, unknown>;
  first_seen_at: IsoDateTime | null;
  last_seen_at: IsoDateTime | null;
  seen_in_assessments: string[];
  tags: AssetTagOut[];
  created_at: IsoDateTime;
}

export interface AssetCriticalityIn {
  criticality: Criticality;
  rationale?: string | null;
}

export interface AssetFilter {
  criticality?: Criticality;
  selected?: boolean;
  internet_exposed?: boolean;
  status?: AssetStatus;
  assessment_id?: Uuid;
  q?: string;
}

// ---------------------------------------------------------------------------
// Findings, enrichment, remediation, tickets (app/schemas/finding.py).
// ---------------------------------------------------------------------------

/** Threat-intel overlay. Every `*_status` is reported so partial ≠ absent (FR-020). */
export interface EnrichmentOut {
  status: EnrichmentStatus;
  nvd_status: EnrichmentStatus;
  nvd_published_at: IsoDateTime | null;
  nvd_last_modified_at: IsoDateTime | null;
  nvd_description: string | null;
  nvd_cvss_v31_score: number | null;
  nvd_cvss_v31_vector: string | null;
  nvd_cwe_ids: string[];
  nvd_references: Array<Record<string, unknown>>;
  kev_status: EnrichmentStatus;
  /** `null` = KEV not determined (outage). Never coerce to false (FR-020). */
  in_kev: boolean | null;
  kev_date_added: IsoDate | null;
  kev_due_date: IsoDate | null;
  kev_ransomware_use: string | null;
  kev_required_action: string | null;
  epss_status: EnrichmentStatus;
  epss_score: number | null;
  epss_percentile: number | null;
  misp_status: EnrichmentStatus;
  misp_event_count: number | null;
  misp_attributes: Array<Record<string, unknown>>;
  provider_errors: Record<string, string>;
  enriched_at: IsoDateTime | null;
}

export interface RemediationOut {
  id: Uuid;
  finding_id: Uuid;
  approach: string;
  summary: string;
  steps: string[];
  code_patch: string | null;
  patch_language: string | null;
  configuration_change: string | null;
  verification: string | null;
  side_effects: string | null;
  effort: string | null;
  references: Array<Record<string, unknown>>;
  ai_model: string | null;
  generated_at: IsoDateTime | null;
  reviewed_at: IsoDateTime | null;
  reviewed_by: string | null;
}

export interface TicketLinkOut {
  id: Uuid;
  provider: string;
  external_key: string;
  external_id: string | null;
  url: string | null;
  project_key: string | null;
  issue_type: string | null;
  external_status: string | null;
  created_by_agent: boolean;
  created_at: IsoDateTime;
}

/** Finding list row. */
export interface FindingOut {
  id: Uuid;
  assessment_id: Uuid | null;
  asset_id: Uuid | null;
  defectdojo_finding_id: number;
  title: string;
  severity: Severity;
  status: FindingStatus;
  scanner: ScannerName | null;
  endpoint: string | null;
  component: string | null;
  component_version: string | null;
  cve_ids: string[];
  cwe: number | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  is_duplicate: boolean;
  is_false_positive: boolean;
  priority: Priority | null;
  risk_score: number | null;
  risk_factors: Record<string, unknown>;
  asset_criticality: Criticality | null;
  in_kev: boolean | null;
  first_seen_at: IsoDateTime | null;
  last_seen_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface FindingDetailOut extends FindingOut {
  ai_explanation: string | null;
  ai_business_impact: string | null;
  ai_attack_scenario: string | null;
  /** Citations backing every AI claim above (FR-024). Never render a claim without these. */
  ai_evidence: Array<Record<string, unknown>>;
  ai_model: string | null;
  ai_analyzed_at: IsoDateTime | null;
  ai_skipped_reason: string | null;
  severity_raw: string | null;
  defectdojo_test_id: number | null;
  synced_at: IsoDateTime | null;
  enrichment: EnrichmentOut | null;
  remediations: RemediationOut[];
  tickets: TicketLinkOut[];
  asset: AssetOut | null;
}

export interface FindingFilter {
  severity?: Severity;
  priority?: Priority;
  status?: FindingStatus;
  scanner?: ScannerName;
  assessment_id?: Uuid;
  asset_id?: Uuid;
  in_kev?: boolean;
  cve?: string;
  include_duplicates?: boolean;
  include_false_positives?: boolean;
  q?: string;
}

export interface AnalyzeIn {
  force?: boolean;
}

export interface RemediateIn {
  approach?: string | null;
  force?: boolean;
}

export interface JiraTicketIn {
  project_key?: string | null;
  issue_type?: string | null;
  assignee?: string | null;
  include_remediation?: boolean;
}

// ---------------------------------------------------------------------------
// Scanner jobs (app/schemas/job.py).
// ---------------------------------------------------------------------------

export interface ArtifactOut {
  id: Uuid;
  kind: ArtifactKind;
  filename: string;
  size_bytes: number | null;
  sha256: string | null;
  content_type: string | null;
  download_url: string | null;
  created_at: IsoDateTime;
}

export interface SandboxOut {
  image: string | null;
  cpu_limit: number | null;
  memory_limit_mb: number | null;
  pids_limit: number | null;
  network_mode: string | null;
  read_only_rootfs: boolean | null;
  user: string | null;
  cap_drop: string[];
  security_opt: string[];
  tmpfs: string[];
  timeout_seconds: number | null;
}

export interface ScannerJobOut {
  id: Uuid;
  assessment_id: Uuid;
  scanner: ScannerName;
  status: JobStatus;
  targets: string[];
  image: string | null;
  started_at: IsoDateTime | null;
  finished_at: IsoDateTime | null;
  exit_code: number | null;
  duration_seconds: number | null;
  imported_finding_count: number;
  sandbox: Record<string, unknown>;
  artifacts: ArtifactOut[];
  error_message: string | null;
  failure_code: string | null;
  retry_count: number;
  timeout_seconds: number | null;
  cancel_requested: boolean;
  defectdojo_test_id: number | null;
  created_at: IsoDateTime;
}

export interface JobFilter {
  assessment_id?: Uuid;
  scanner?: ScannerName;
  status?: JobStatus;
  active?: boolean;
}

// ---------------------------------------------------------------------------
// Reports (app/schemas/report.py).
// ---------------------------------------------------------------------------

export interface ReportOut {
  id: Uuid;
  assessment_id: Uuid;
  title: string;
  format: ReportFormat;
  audience: string;
  status: ReportStatus;
  size_bytes: number | null;
  sha256: string | null;
  generated_at: IsoDateTime | null;
  download_url: string | null;
  failure_reason: string | null;
  created_at: IsoDateTime;
}

export interface ReportDetailOut extends ReportOut {
  executive_summary: string | null;
  summary_ai_generated: boolean;
  ai_model: string | null;
  content_digest: Record<string, unknown>;
  degradations: DegradationOut[];
}

export interface ReportGenerateIn {
  format?: ReportFormat;
  audience?: "executive" | "technical";
  title?: string | null;
  force?: boolean;
}

// ---------------------------------------------------------------------------
// Integrations (app/schemas/integration.py).
// ---------------------------------------------------------------------------

export interface CredentialOut {
  name: string;
  fingerprint: string | null;
  hint: string | null;
  key_version: number;
  expires_at: IsoDateTime | null;
  last_used_at: IsoDateTime | null;
  rotated_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface IntegrationOut {
  id: Uuid;
  kind: IntegrationKind;
  name: string;
  status: IntegrationStatus;
  is_enabled: boolean;
  base_url: string | null;
  config: Record<string, unknown>;
  credentials: CredentialOut[];
  last_verified_at: IsoDateTime | null;
  last_error: string | null;
  last_error_at: IsoDateTime | null;
  failure_count: number;
  created_at: IsoDateTime;
}

export interface IntegrationUpsertIn {
  kind: IntegrationKind;
  name?: string | null;
  base_url?: string | null;
  is_enabled?: boolean;
  config?: Record<string, unknown>;
  /** Write-only; encrypted on receipt, never returned. */
  credentials?: Record<string, string>;
}

export interface IntegrationTestOut {
  kind: IntegrationKind;
  healthy: boolean;
  detail: string | null;
  latency_ms: number | null;
  version: string | null;
  checked_at: IsoDateTime | null;
}

export interface IntegrationHealthOut {
  kind: IntegrationKind;
  name: string;
  status: IntegrationStatus;
  is_enabled: boolean;
  last_verified_at: IsoDateTime | null;
  failure_count: number;
  circuit_open: boolean;
}

// ---------------------------------------------------------------------------
// Audit (app/schemas/audit.py).
// ---------------------------------------------------------------------------

export interface AuditEventOut {
  id: Uuid;
  organization_id: Uuid | null;
  actor_id: Uuid | null;
  actor_email: string | null;
  actor_type: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: AuditOutcome;
  detail: Record<string, unknown>;
  reason: string | null;
  source_ip: string | null;
  user_agent: string | null;
  request_id: string | null;
  trace_id: string | null;
  created_at: IsoDateTime;
}

export interface AuditFilter {
  actor_id?: Uuid;
  actor_type?: "user" | "agent" | "worker" | "system";
  action?: string;
  resource_type?: string;
  resource_id?: string;
  outcome?: AuditOutcome;
  since?: IsoDateTime;
  until?: IsoDateTime;
  q?: string;
}

// ---------------------------------------------------------------------------
// Dashboard (app/schemas/dashboard.py).
// ---------------------------------------------------------------------------

export interface ActivityOut {
  id: Uuid;
  at: IsoDateTime;
  actor: string | null;
  actor_type: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: AuditOutcome;
  summary: string | null;
}

export interface DashboardOut {
  assessments_total: number;
  assessments_active: number;
  assessments_awaiting_approval: number;
  findings_open: number;
  /** Keyed by Severity value; every severity present even at zero. */
  severity_breakdown: Record<string, number>;
  priority_breakdown: Record<string, number>;
  assets_total: number;
  assets_critical: number;
  /** Confirmed KEV only (FR-020). */
  kev_findings: number;
  /** `null` when nothing has been remediated. Never coerce to zero. */
  mean_time_to_remediate_days: number | null;
  recent_assessments: AssessmentOut[];
  top_findings: FindingOut[];
  activity: ActivityOut[];
  integration_health: IntegrationHealthOut[];
  generated_at: IsoDateTime | null;
}

// ---------------------------------------------------------------------------
// Agent conversation + runs (app/schemas/agent.py).
// ---------------------------------------------------------------------------

export const MAX_MESSAGE_LENGTH = 8000;

export interface AgentMessageIn {
  session_id?: Uuid | null;
  content: string;
  assessment_id?: Uuid | null;
}

export interface AgentMessageOut {
  id: Uuid;
  session_id: Uuid;
  run_id: Uuid | null;
  seq: number;
  role: MessageRole;
  content: string;
  tool_calls: Array<Record<string, unknown>>;
  tool_name: string | null;
  tool_status: string | null;
  citations: Array<Record<string, unknown>>;
  model: string | null;
  guardrail_applied: string | null;
  created_at: IsoDateTime;
}

export interface AgentStepOut {
  id: Uuid;
  run_id: Uuid;
  seq: number;
  node: string;
  stage: AssessmentStage | null;
  tool_name: string | null;
  status: StepStatus;
  label: string | null;
  output_truncated: boolean;
  failure_code: string | null;
  degradation_note: string | null;
  retry_count: number;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  duration_ms: number | null;
}

export interface AgentRunOut {
  id: Uuid;
  session_id: Uuid | null;
  assessment_id: Uuid | null;
  thread_id: string;
  graph: string;
  status: AgentRunStatus;
  current_node: string | null;
  interrupt_kind: string | null;
  pending_approval_id: Uuid | null;
  resumed_count: number;
  failure_reason: string | null;
  failure_category: string | null;
  trace_url: string | null;
  total_input_tokens: number;
  total_output_tokens: number;
  tool_call_count: number;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  steps: AgentStepOut[];
}

export interface AgentSessionOut {
  id: Uuid;
  title: string;
  is_archived: boolean;
  message_count: number;
  last_activity_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface AgentSessionDetailOut extends AgentSessionOut {
  messages: AgentMessageOut[];
  runs: AgentRunOut[];
  context_summary: string | null;
  summarized_through_seq: number;
}

// ---------------------------------------------------------------------------
// WebSocket event stream (app/schemas/agent.py — WS /ws/agent/{session_id}).
// ---------------------------------------------------------------------------

export type AgentEventType =
  | "agent_thinking"
  | "agent_plan_step"
  | "agent_tool_call"
  | "agent_approval_required"
  | "agent_findings_update"
  | "agent_error"
  | "agent_complete"
  | "agent_message"
  | "agent_progress"
  | "pong";

/** The single server→client envelope. `type` selects which payload `data` conforms to. */
export interface AgentEvent<T = Record<string, unknown>> {
  type: AgentEventType;
  session_id: Uuid;
  assessment_id: Uuid | null;
  run_id: Uuid | null;
  seq: number;
  at: IsoDateTime;
  data: T;
}

export interface ThinkingData {
  text: string;
  node?: string | null;
}

export interface PlanStepData {
  step_index: number;
  total_steps: number;
  stage?: AssessmentStage | null;
  title: string;
  status: StepStatus;
  detail?: string | null;
}

/** `summary` is a one-liner; arguments are deliberately absent (SEC-002/SEC-006). */
export interface ToolCallData {
  tool: string;
  status: "started" | "succeeded" | "failed";
  risk_level?: RiskLevel | null;
  summary?: string | null;
  duration_ms?: number | null;
}

export interface FindingsUpdateData {
  assessment_id: Uuid;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  new_since_last: number;
}

/** `user_message` only — never a raw exception (SEC-002). */
export interface ErrorData {
  code: string;
  category: string;
  user_message: string;
  retryable: boolean;
  degradable: boolean;
  stage?: AssessmentStage | null;
}

export interface CompleteData {
  assessment_id?: Uuid | null;
  status?: AssessmentStatus | null;
  findings_total: number;
  report_id?: Uuid | null;
  duration_seconds?: number | null;
}

export interface ProgressData {
  stage: AssessmentStage;
  progress_percent: number;
  stages: StageOut[];
}

/** Client→server frame. Only auth + keepalive; the socket cannot start work. */
export interface ClientFrame {
  type: "auth" | "ping";
  token?: string | null;
}

/**
 * Discriminated view of an AgentEvent, so a consumer can `switch (ev.type)` and get the
 * right `data` shape without casting at every call site.
 */
export type TypedAgentEvent =
  | (AgentEvent<ThinkingData> & { type: "agent_thinking" })
  | (AgentEvent<PlanStepData> & { type: "agent_plan_step" })
  | (AgentEvent<ToolCallData> & { type: "agent_tool_call" })
  | (AgentEvent<ApprovalOut> & { type: "agent_approval_required" })
  | (AgentEvent<FindingsUpdateData> & { type: "agent_findings_update" })
  | (AgentEvent<ErrorData> & { type: "agent_error" })
  | (AgentEvent<CompleteData> & { type: "agent_complete" })
  | (AgentEvent<AgentMessageOut> & { type: "agent_message" })
  | (AgentEvent<ProgressData> & { type: "agent_progress" })
  | (AgentEvent<Record<string, never>> & { type: "pong" });
