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
  | "finding:validate"
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
  | "scanning_trivy_repo"
  | "scanning_semgrep_repo"
  | "scanning_gitleaks_repo"
  | "scanning_trivy_image"
  | "scanning_syft_image"
  | "scanning_prowler_aws"
  | "scanning_prowler_azure"
  | "scanning_prowler_gcp"
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
  "scanning_trivy_repo",
  "scanning_semgrep_repo",
  "scanning_gitleaks_repo",
  "scanning_trivy_image",
  "scanning_syft_image",
  "scanning_prowler_aws",
  "scanning_prowler_azure",
  "scanning_prowler_gcp",
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
  scanning_trivy_repo: "Scanning — Trivy repository",
  scanning_semgrep_repo: "Scanning — Semgrep source code",
  scanning_gitleaks_repo: "Scanning — Gitleaks secrets",
  scanning_trivy_image: "Scanning — Trivy image",
  scanning_syft_image: "Inventorying — Syft image SBOM",
  scanning_prowler_aws: "Scanning — Prowler AWS",
  scanning_prowler_azure: "Scanning — Prowler Azure",
  scanning_prowler_gcp: "Scanning — Prowler GCP",
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

export type EngagementType =
  | "web_application"
  | "api_security"
  | "mobile_application"
  | "llm_agentic_application"
  | "network_external"
  | "network_internal"
  | "active_directory"
  | "cloud_security"
  | "code_review"
  | "threat_modeling"
  | "attack_surface_monitoring"
  | "devsecops_pipeline"
  | "threat_hunting"
  | "code_remediation"
  | "red_team"
  | "supply_chain";

export type ExecutionMode = "supervised" | "background" | "interactive";
export type ValidationStatus = "unvalidated" | "confirmed" | "rejected" | "recheck_required";

export type AssetStatus = "active" | "inactive" | "unreachable" | "out_of_scope";

export type Criticality = "critical" | "high" | "normal" | "low" | "unknown";

export type CriticalitySource =
  | "operator_tag"
  | "cmdb"
  | "inferred_keyword"
  | "inferred_exposure"
  | "default";

export type ScannerName = "reconftw" | "nmap" | "nuclei" | "zap" | "trivy_repo" | "semgrep_repo" | "gitleaks_repo" | "trivy_image" | "syft_image";

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
  | "llm"
  | "defectdojo"
  | "jira"
  | "servicenow"
  | "azure_devops"
  | "linear"
  | "pagerduty"
  | "splunk"
  | "slack"
  | "email"
  | "dify"
  | "misp"
  | "nvd"
  | "github"
  | "gitlab"
  | "bitbucket"
  | "wazuh"
  | "sonarqube"
  | "snyk"
  | "tenable"
  | "qualys"
  | "rapid7"
  | "wiz"
  | "prisma_cloud"
  | "crowdstrike"
  | "aws_security_hub"
  | "aws_inspector"
  | "hackerone"
  | "bugcrowd"
  | "checkmarx"
  | "fortify"
  | "azure_defender"
  | "gcp_scc"
  | "burp_dast"
  | "prowler_aws"
  | "prowler_azure"
  | "prowler_gcp"
  | "zscaler";

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
  parent_organization_id: Uuid | null;
  is_active: boolean;
  max_concurrent_scanner_jobs: number;
  entitlements: OrganizationEntitlements;
  policy: OrgPolicyOut;
  created_at: IsoDateTime;
}

export interface ClientOrganizationCreateIn {
  name: string;
  slug?: string | null;
}

/** Portfolio-only counters. Client assets and findings remain in their own tenant. */
export interface ClientOrganizationPortfolioOut {
  organization: OrganizationOut;
  asset_count: number;
  open_finding_count: number;
  critical_open_finding_count: number;
  open_risk_score: number;
}

export interface ClientOrganizationDelegateIn {
  user_id: Uuid;
  role?: Exclude<Role, "owner">;
}

export interface RiskWeights {
  severity: number;
  exploitation: number;
  exploit_probability: number;
  exposure: number;
  asset_criticality: number;
  ransomware: number;
}

export interface OrgPolicyOut {
  risk_weights: RiskWeights;
  pagerduty_enabled?: boolean;
  codeowners?: string | null;
  codeowner_members?: Record<string, Uuid>;
  [key: string]: unknown;
}

/** Self-service capability snapshot returned by the organization API. */
export interface OrganizationEntitlements {
  max_assets: number;
  max_members: number;
  max_integrations: number;
  max_active_assessments: number;
  allow_active_validation: boolean;
  allow_agentic_pentest: boolean;
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
  engagement_type?: EngagementType;
  execution_mode?: ExecutionMode;
  objective?: string | null;
  api_spec?: Record<string, unknown>;
  api_target?: string;
  api_auth_token?: string;
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

export interface EngagementChecklistItemOut {
  key: string;
  title: string;
  required: boolean;
  evidence_reference: string | null;
  completed: boolean;
  completed_by_id: Uuid | null;
  completed_at: IsoDateTime | null;
}

export interface EngagementChecklistUpdateIn {
  completed: boolean;
  evidence_reference?: string | null;
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
  engagement_type: EngagementType;
  execution_mode: ExecutionMode;
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
  engagement_checklist: EngagementChecklistItemOut[];
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
  version: number;
  merged_into_id: Uuid | null;
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
  owner_user_id: Uuid | null;
  owner_team: string | null;
  environment: AssetEnvironment;
  groups: string[];
  custom_fields: Record<string, string | number | boolean>;
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

export interface CmdbImportOut {
  dry_run: boolean;
  matched: number;
  updated: number;
  unmatched: string[];
}

export interface AssetChangeOut {
  id: Uuid;
  asset_id: Uuid;
  assessment_id: Uuid | null;
  asset_name: string;
  change_type: "discovered" | "changed" | "unreachable";
  changes: Record<string, { old: unknown; new: unknown }>;
  created_at: IsoDateTime;
}

export interface AssetChangePageOut {
  items: AssetChangeOut[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApplicationRiskOut {
  application: string;
  asset_count: number;
  active_findings: number;
  critical: number;
  high: number;
  max_risk_score: number;
  aggregate_risk_score: number;
}

export interface ApplicationRiskPageOut {
  items: ApplicationRiskOut[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApplicationPatternOut {
  key: string;
  confidence: "cve" | "rule";
  repository_count: number;
  repositories: string[];
  finding_ids: Uuid[];
  max_risk_score: number;
}

export interface ApplicationPatternsOut {
  application: string;
  patterns: ApplicationPatternOut[];
  findings_sampled: number;
  truncated: boolean;
}

export type AssetEnvironment = "unknown" | "production" | "staging" | "development" | "test";

export interface AssetContextIn {
  owner_user_id?: Uuid | null;
  owner_team?: string | null;
  environment?: AssetEnvironment;
  groups?: string[];
  custom_fields?: Record<string, string | number | boolean>;
}

export interface AssetCriticalityIn {
  criticality: Criticality;
  rationale?: string | null;
}

export interface AssetCreateIn {
  name: string;
  asset_type: string;
  port?: number | null;
  protocol?: string | null;
  service?: string | null;
  internet_exposed?: boolean;
  context?: AssetContextIn | null;
}

export interface AssetBulkUpdateIn {
  items: Array<{
    asset_id: Uuid;
    expected_version: number;
    context?: AssetContextIn | null;
    status?: AssetStatus | null;
  }>;
}

export interface AssetMergeIn {
  source_asset_id: Uuid;
  target_asset_id: Uuid;
  source_expected_version: number;
  target_expected_version: number;
  reason: string;
}

export interface AssetMergeOut {
  event_id: Uuid;
  source_asset_id: Uuid;
  target_asset_id: Uuid;
  moved_counts: Record<string, number>;
}

export interface AssetRelationshipOut {
  id: Uuid;
  source_asset_id: Uuid;
  target_asset_id: Uuid;
  relationship_type: "depends_on" | "contains" | "hosts" | "connects_to" | "owned_by";
  evidence: Record<string, unknown>;
  created_by_id: Uuid | null;
  created_at: IsoDateTime;
}

export interface AssetCsvImportOut {
  dry_run: boolean;
  accepted: number;
  created: number;
  existing: number;
  errors: string[];
}

export interface PolicyGateOut {
  asset_id: Uuid;
  decision: "pass" | "warn" | "block" | "unknown";
  allow_deploy: boolean;
  reason_code: string;
  counts: Record<Severity, number>;
  blockers: Array<{
    id: Uuid;
    title: string;
    severity: "critical" | "high";
    risk_score: number;
  }>;
  scan_imported_at: IsoDateTime | null;
  evaluated_at: IsoDateTime;
}

export interface AssetFilter {
  criticality?: Criticality;
  environment?: AssetEnvironment;
  selected?: boolean;
  internet_exposed?: boolean;
  status?: AssetStatus;
  assessment_id?: Uuid;
  group?: string;
  q?: string;
  query?: string;
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
  external_updated_at: IsoDateTime | null;
  closure_generation: number;
  created_by_agent: boolean;
  created_at: IsoDateTime;
}

/** Finding list row. */
export interface ExternalAlertOut {
  id: Uuid;
  provider: string;
  category: string;
  title: string;
  severity: Severity;
  status: "open" | "resolved" | "dismissed" | "fixed";
  resource: string | null;
  cve_ids: string[];
  first_seen_at: IsoDateTime | null;
  last_seen_at: IsoDateTime | null;
  missing_sync_count: number;
  triage_status: TriageStatus;
}

export interface ExposureOut {
  id: string;
  source: string;
  title: string;
  severity: Severity;
  status: string;
  resource: string | null;
  seen_at: string | null;
}

export type CanonicalFindingStatus = "new" | "open" | "reopened" | "mitigated" | "accepted_risk" | "false_positive" | "closed";

export interface CanonicalFindingOut {
  id: Uuid;
  asset_id: Uuid;
  title: string;
  severity: Severity;
  status: CanonicalFindingStatus;
  cve_ids: string[];
  risk_score: number;
  risk_factors: {
    components?: Record<string, number>;
    weights?: Record<string, number>;
    inputs?: Record<string, unknown>;
    unavailable?: string[];
  };
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime;
  closed_at: IsoDateTime | null;
  status_version: number;
  assignee_user_id: Uuid | null;
  due_at: IsoDateTime | null;
  remediation_plan: string | null;
  remediation_group: string | null;
  custom_fields: Record<string, string | number | boolean>;
}

export interface CanonicalObservationOut {
  id: Uuid;
  provider: string;
  external_id: string;
  source_record_id: Uuid | null;
  cve_id: string;
  title: string;
  severity: Severity;
  source_status: string;
  source_url: string | null;
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime;
}

export interface CanonicalHistoryOut {
  id: Uuid;
  previous_status: CanonicalFindingStatus | null;
  new_status: CanonicalFindingStatus;
  reason: string;
  actor_user_id: Uuid | null;
  occurred_at: IsoDateTime;
}

export interface FieldProvenanceOut {
  field: string;
  value: unknown;
  sources: string[];
  observation_ids: Uuid[];
  confidence: number;
  conflicts: boolean;
}

export interface FindingCollaborationCommentOut {
  id: Uuid;
  canonical_finding_id: Uuid;
  author_user_id: Uuid | null;
  kind: "note" | "evidence" | "remediation" | "retest" | "status_update";
  body: string;
  evidence_reference: string | null;
  visible_to_client: boolean;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface FindingCollaborationCommentCreateIn {
  body: string;
  kind?: FindingCollaborationCommentOut["kind"];
  evidence_reference?: string | null;
  visible_to_client?: boolean;
}

export interface CanonicalFindingDetailOut extends CanonicalFindingOut {
  observations: CanonicalObservationOut[];
  history: CanonicalHistoryOut[];
  tickets: TicketLinkOut[];
  field_provenance: FieldProvenanceOut[];
}

export interface RiskAcceptanceOut {
  id: Uuid;
  canonical_finding_id: Uuid;
  requested_by_id: Uuid;
  approved_by_id: Uuid | null;
  rationale: string;
  status: "pending" | "approved" | "rejected" | "revoked" | "expired";
  expires_at: IsoDateTime;
  approved_at: IsoDateTime | null;
}

export interface RiskAcceptanceIn {
  rationale: string;
  expires_at: IsoDateTime;
}

export interface RetestRequestOut {
  id: Uuid;
  canonical_finding_id: Uuid;
  assessment_id: Uuid | null;
  status: "requested" | "scheduled" | "running" | "confirmed" | "not_confirmed" | "failed" | "cancelled";
  request_note: string | null;
  evidence: Record<string, unknown>;
  completed_at: IsoDateTime | null;
}

export interface RetestRequestIn {
  note?: string | null;
}

export interface CanonicalRemediationOperationOut {
  finding: CanonicalFindingOut;
  tickets: TicketLinkOut[];
  latest_risk_acceptance: RiskAcceptanceOut | null;
  latest_retest: RetestRequestOut | null;
  next_action: string;
  priority_reasons: string[];
  source_observations: number;
  sla_escalation_level: number;
}

export interface RiskTrendPointOut {
  assessment_id: Uuid;
  assessment_reference: number | null;
  measured_at: IsoDateTime;
  exposure_score: number;
  findings_total: number;
  assets_total: number;
  new_findings: number;
  resolved_findings: number;
}

export interface RiskTrendOut {
  points: RiskTrendPointOut[];
  source: "completed_assessment_reports";
}

export interface DashboardLayoutOut {
  id: Uuid;
  name: string;
  audience: "executive" | "technical" | "team";
  widgets: Array<{ key: string }>;
  is_default: boolean;
}

export interface DashboardLayoutIn {
  name: string;
  audience?: DashboardLayoutOut["audience"];
  widgets: string[];
  is_default?: boolean;
}

export interface ReportShareLinkOut {
  id: Uuid;
  report_id: Uuid;
  token_prefix: string;
  expires_at: IsoDateTime;
  revoked_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface ReportShareCreateIn {
  expires_at: IsoDateTime;
}

/** The opaque token is returned once when a link is issued and is never stored client-side. */
export interface ReportShareIssuedOut {
  id: Uuid;
  token: string;
  expires_at: IsoDateTime;
}

export interface ReportScheduleCreateIn {
  name: string;
  assessment_id: Uuid;
  title?: string | null;
  format?: "html" | "pdf" | "json";
  audience?: "executive" | "technical";
  cron_expression: string;
  timezone?: string;
  recipients?: string[];
  template_id?: Uuid | null;
}

export interface ReportScheduleOut {
  id: Uuid;
  assessment_id: Uuid;
  name: string;
  title: string | null;
  format: "html" | "pdf" | "json";
  audience: "executive" | "technical";
  cron_expression: string;
  timezone: string;
  recipients: string[];
  is_enabled: boolean;
  next_run_at: IsoDateTime;
  last_run_at: IsoDateTime | null;
  last_report_id: Uuid | null;
  created_at: IsoDateTime;
  template_id: Uuid | null;
}

export interface ReportTemplateOut {
  id: Uuid;
  name: string;
  version: number;
  description: string | null;
  definition: { blocks: Array<Record<string, unknown>>; theme?: Record<string, unknown> };
  is_active: boolean;
  created_at: IsoDateTime;
}

export interface ReportTemplateCreateIn {
  name: string;
  description?: string | null;
  definition: { blocks: Array<Record<string, unknown>>; theme?: Record<string, unknown> };
}

export interface ScanProfileOut {
  id: Uuid;
  name: string;
  config: Record<string, unknown>;
  is_active: boolean;
  created_at: IsoDateTime;
}

export interface ScanProfileCreateIn {
  name: string;
  scope?: Scope;
  depth?: AssessmentDepth;
  engagement_type?: EngagementType;
  execution_mode?: ExecutionMode;
  objective?: string | null;
  notify?: string[];
}

export interface RecurringScanOut {
  id: Uuid;
  name: string;
  profile_id: Uuid;
  targets: string[];
  cron_expression: string;
  timezone: string;
  authorization_expires_at: IsoDateTime;
  enabled: boolean;
  next_run_at: IsoDateTime;
  last_run_at: IsoDateTime | null;
  last_assessment_id: Uuid | null;
  last_error_code: string | null;
  created_at: IsoDateTime;
}

export interface RecurringScanCreateIn {
  name: string;
  profile_id: Uuid;
  targets: string[];
  cron_expression: string;
  timezone?: string;
  authorization: AuthorizationIn;
  authorization_expires_at: IsoDateTime;
}

export interface WorkerMetricsOut {
  runs: Record<string, number>;
  pending_dispatches: number;
  scanner_jobs: Record<string, number>;
  notification_deliveries: Record<string, number>;
  notification_retries_due: number;
}

export interface OidcConnectionUpsertIn {
  issuer_url: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  allowed_email_domains?: string[];
  is_enabled?: boolean;
}

export interface OidcConnectionOut {
  id: Uuid;
  issuer_url: string;
  client_id: string;
  redirect_uri: string;
  allowed_email_domains: string[];
  is_enabled: boolean;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface SamlConnectionUpsertIn {
  sp_entity_id: string;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_certificate_pem: string;
  acs_url: string;
  allowed_email_domains?: string[];
  is_enabled?: boolean;
}

export interface SamlConnectionOut {
  id: Uuid;
  sp_entity_id: string;
  idp_entity_id: string;
  idp_sso_url: string;
  acs_url: string;
  allowed_email_domains: string[];
  is_enabled: boolean;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface ScimProvisioningTokenCreateIn {
  name: string;
  expires_at?: IsoDateTime | null;
}

export interface ScimProvisioningTokenOut {
  id: Uuid;
  name: string;
  key_prefix: string;
  expires_at: IsoDateTime | null;
  revoked_at: IsoDateTime | null;
  last_used_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface ScimProvisioningTokenIssuedOut extends ScimProvisioningTokenOut {
  secret: string;
}

export interface CanonicalStatusDecisionIn {
  status: "open" | "false_positive";
  reason: string;
  expected_version: number;
}

export interface CanonicalWorkIn {
  expected_version: number;
  assignee_user_id?: Uuid | null;
  due_at?: IsoDateTime | null;
  remediation_plan?: string | null;
  remediation_group?: string | null;
  custom_fields?: Record<string, string | number | boolean>;
}

export interface BulkCanonicalWorkIn {
  items: Array<CanonicalWorkIn & { finding_id: Uuid }>;
}

export interface RemediationGroupOut {
  name: string;
  active_findings: number;
  overdue_findings: number;
  highest_risk_score: number;
  last_seen_at: IsoDateTime;
}

export interface ExposureFilter {
  source?: ExposureOut["source"];
  severity?: Severity;
}

export type TriageStatus = "new" | "investigating" | "risk_accepted" | "false_positive" | "closed";

export interface ExternalAlertDetailOut extends ExternalAlertOut {
  external_id: string;
  source_url: string | null;
  triage_note: string | null;
  triage_version: number;
  triaged_at: IsoDateTime | null;
}

export interface ExternalAlertSourceActionIn {
  decision: "dismiss" | "reopen";
  reason?: string | null;
  comment?: string | null;
}

export interface ExternalAlertTriageIn {
  status: TriageStatus;
  note: string | null;
  expected_version: number;
}

export interface RelatedFindingOut {
  id: Uuid;
  title: string;
  severity: Severity;
  status: FindingStatus;
  cve_ids: string[];
  priority: Priority | null;
  risk_score: number | null;
}

export interface ExternalAlertFilter {
  provider?: ExternalAlertOut["provider"];
  severity?: Severity;
  status?: ExternalAlertOut["status"];
  triage_status?: TriageStatus;
  q?: string;
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
  validation_status: ValidationStatus;
  validation_checked_at: IsoDateTime | null;
  first_seen_at: IsoDateTime | null;
  last_seen_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface FindingDetailOut extends FindingOut {
  validation_proof: Record<string, unknown>;
  ai_explanation: string | null;
  ai_business_impact: string | null;
  ai_attack_scenario: string | null;
  /** New elite-analysis fields from ELITE_FINDING_ANALYSIS_SYSTEM */
  ai_adversary_profile: string | null;
  ai_mitre_tactics: string[] | null;
  ai_detection_hint: string | null;
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

export interface ValidateFindingIn {
  status: Exclude<ValidationStatus, "unvalidated">;
  summary?: string | null;
  evidence_references?: string[];
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
  provider?: "jira" | "github" | "gitlab" | "servicenow" | "azure_devops" | "linear";
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
  template_id?: Uuid | null;
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
  sync_interval_minutes: number | null;
  next_sync_at: IsoDateTime | null;
  last_sync_at: IsoDateTime | null;
  last_sync_status: "succeeded" | "failed" | null;
  last_sync_error: string | null;
  sync_failure_count: number;
  created_at: IsoDateTime;
}

export interface IntegrationUpsertIn {
  kind: IntegrationKind;
  name?: string | null;
  base_url?: string | null;
  is_enabled?: boolean;
  /** Null disables continuous finding ingestion. */
  sync_interval_minutes?: number | null;
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

export interface IntegrationSyncOut {
  kind: IntegrationKind;
  alerts_staged: number;
  absence_candidates: number;
  missing_source_records: number;
}

export interface TenableScanStatusOut {
  scan_id: string;
  status: string;
}

export interface TenableScanLaunchOut {
  scan_id: string;
  run_uuid: string | null;
}

export interface IntegrationHealthOut {
  kind: IntegrationKind;
  name: string;
  status: IntegrationStatus;
  is_enabled: boolean;
  last_verified_at: IsoDateTime | null;
  failure_count: number;
  sync_interval_minutes: number | null;
  last_sync_at: IsoDateTime | null;
  last_sync_status: "succeeded" | "failed" | null;
  sync_failure_count: number;
  freshness_seconds: number | null;
  coverage_state: string;
  sync_confidence: number;
  coverage_reason: string;
  circuit_open: boolean;
}

export interface ConnectorAssuranceCheckOut {
  key: string;
  passed: boolean;
  weight: number;
  detail: string;
}

export interface ConnectorCertificationOut {
  kind: IntegrationKind;
  name: string;
  grade: "certified" | "operational" | "degraded" | "failed";
  score: number;
  capabilities: string[];
  checks: ConnectorAssuranceCheckOut[];
  blockers: string[];
  checked_at: IsoDateTime;
}

export interface SourceCoverageOut {
  provider: string;
  observations_total: number;
  canonical_findings: number;
  active_observations: number;
  missing_observations: number;
  last_observed_at: IsoDateTime | null;
  coverage_state: string;
  sync_confidence: number;
  coverage_reason: string;
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
  actor_type?: "user" | "agent" | "worker" | "system" | "api_key";
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

export interface DashboardFindingOut {
  id: Uuid;
  source_kind: "canonical" | "legacy";
  title: string;
  severity: Severity;
  priority: Priority | null;
  risk_score: number | null;
  risk_factors: Record<string, unknown>;
  in_kev: boolean | null;
  first_seen_at: IsoDateTime;
}

export interface DashboardOut {
  assessments_total: number;
  assessments_active: number;
  assessments_awaiting_approval: number;
  findings_open: number;
  external_alerts_actionable: number;
  external_alerts_awaiting_triage: number;
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
  top_findings: DashboardFindingOut[];
  activity: ActivityOut[];
  integration_health: IntegrationHealthOut[];
  generated_at: IsoDateTime | null;
}

export interface TeamDashboardOut {
  team_name: string;
  assets_total: number;
  assets_critical: number;
  findings_open: number;
  kev_findings: number;
  highest_risk_score: number | null;
  severity_breakdown: Record<string, number>;
  priority_breakdown: Record<string, number>;
}

export interface AssetGroupRiskOut {
  group_name: string;
  assets_total: number;
  internet_exposed_assets: number;
  findings_open: number;
  critical_or_high_findings: number;
  highest_risk_score: number | null;
  aggregate_risk_score: number;
}

// ---------------------------------------------------------------------------
// Compliance (app/schemas/compliance.py).
// ---------------------------------------------------------------------------

export type ComplianceFramework =
  | "pci_dss"
  | "iso_27001"
  | "soc_2"
  | "hipaa"
  | "nist_csf"
  | "cis_controls";

export type ComplianceControlStatus =
  | "not_assessed"
  | "satisfied"
  | "partially_satisfied"
  | "at_risk"
  | "not_applicable";

export interface ComplianceControlOut {
  id: Uuid;
  framework: ComplianceFramework;
  control_id: string;
  title: string;
  family: string | null;
  description: string | null;
  owner_user_id: Uuid | null;
  assessment_status: ComplianceControlStatus;
  evidence: Record<string, unknown>;
  mapped_finding_count: number;
  active_finding_count: number;
  highest_risk_score: number | null;
  effective_status: ComplianceControlStatus;
}

export interface ComplianceFrameworkSummaryOut {
  framework: ComplianceFramework;
  control_count: number;
  mapped_control_count: number;
  at_risk_control_count: number;
  partially_satisfied_control_count: number;
  satisfied_control_count: number;
  active_finding_count: number;
  coverage_percent: number;
}

export interface ComplianceOverviewOut {
  frameworks: ComplianceFrameworkSummaryOut[];
}

export interface ComplianceAuditWorkspaceOut {
  id: string;
  name: string;
  framework: ComplianceFramework;
  status: "draft" | "open" | "in_review" | "completed" | "archived";
  control_ids: string[];
  auditor_emails: string[];
  starts_at: string | null;
  due_at: string | null;
  evidence_cutoff_at: string | null;
  created_by_id: string | null;
  created_at: string;
}

export interface ComplianceEvidenceOut {
  id: string;
  control_id: string;
  title: string;
  evidence_type: "artifact" | "report" | "screenshot" | "log" | "ticket" | "attestation" | "external_link";
  source_reference: string;
  content_sha256: string | null;
  collection_status: "requested" | "collected" | "verified" | "rejected" | "expired";
  collected_at: string | null;
  valid_until: string | null;
  collected_by_id: string | null;
  verified_by_id: string | null;
  review_note: string | null;
  created_at: string;
}

export type ComplianceEvidenceRequestStatus =
  | "open"
  | "collecting"
  | "submitted"
  | "accepted"
  | "rejected"
  | "cancelled";

export interface ComplianceEvidenceRequestOut {
  id: string;
  workspace_id: string;
  control_id: string;
  request_key: string;
  title: string;
  description: string;
  assignee_user_id: string | null;
  requested_by_id: string | null;
  submitted_by_id: string | null;
  reviewed_by_id: string | null;
  status: ComplianceEvidenceRequestStatus;
  freshness_days: number;
  due_at: string | null;
  fulfilled_evidence_ids: string[];
  review_note: string | null;
  status_changed_at: string;
  submitted_at: string | null;
  fulfilled_at: string | null;
  created_at: string;
}

export interface ComplianceInheritanceOut {
  id: string;
  control_id: string;
  parent_control_id: string;
  source_system: string;
  responsibility: "inherited" | "shared" | "customer";
  inherited_percentage: string;
  evidence_refs: string[];
  created_at: string;
}

// ---------------------------------------------------------------------------
// Agent conversation + runs (app/schemas/agent.py).
// ---------------------------------------------------------------------------

export const MAX_MESSAGE_LENGTH = 8000;

export interface AgentMessageIn {
  session_id?: Uuid | null;
  content: string;
  assessment_id?: Uuid | null;
  agent_definition_id?: Uuid | null;
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

export interface AgentMemoryOut {
  id: Uuid;
  key: string;
  category: "operational" | "architecture" | "remediation" | "scope" | "preference";
  content: string;
  source: "manual" | "approved_agent";
  created_by_id: Uuid | null;
  expires_at: IsoDateTime | null;
  is_active: boolean;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface AgentMemoryUpsertIn {
  key: string;
  category?: AgentMemoryOut["category"];
  content: string;
  expires_at?: IsoDateTime | null;
}

export type AgentActionName =
  | "sync_github_alerts"
  | "sync_gitlab_alerts"
  | "sync_wazuh_alerts"
  | "sync_sonarqube_alerts"
  | "sync_snyk_issues"
  | "sync_tenable_vulnerabilities"
  | "sync_qualys_host_detections"
  | "sync_rapid7_vulnerabilities"
  | "sync_wiz_issues"
  | "sync_prisma_cloud_alerts"
  | "sync_crowdstrike_vulnerabilities"
  | "sync_aws_security_hub_findings"
  | "sync_aws_inspector_findings"
  | "sync_hackerone_reports"
  | "sync_bugcrowd_submissions"
  | "sync_checkmarx_results"
  | "sync_fortify_issues"
  | "sync_azure_defender_alerts"
  | "sync_gcp_scc_findings"
  | "sync_burp_dast_findings"
  | "update_github_alert"
  | "create_jira_ticket"
  | "create_ticket"
  | "refresh_ticket_status"
  | "update_canonical_work"
  | "bulk_update_canonical_work"
  | "request_retest"
  | "request_remediation_group_retests"
  | "request_risk_acceptance"
  | "start_assessment";

export interface AssessmentWorkOut {
  id: Uuid;
  status: string;
  current_stage: string;
  progress_percent: number;
  findings_total: number;
  findings_critical: number;
  findings_high: number;
  assets_discovered: number;
  coverage_gap_count: number;
  failure_reason: string;
}

export interface AgentActionOut {
  id: Uuid;
  session_id: Uuid;
  run_id: Uuid | null;
  depends_on_action_id: Uuid | null;
  run_status: string | null;
  assessment: AssessmentWorkOut | null;
  action: AgentActionName;
  label: string;
  rationale: string | null;
  payload: Record<string, unknown>;
  payload_digest: string;
  status: "pending" | "approved" | "rejected" | "executed" | "failed";
  resolution_note: string | null;
  resolved_at: IsoDateTime | null;
  executed_at: IsoDateTime | null;
  result_summary: string | null;
  execution_evidence: Record<string, unknown>;
  created_at: IsoDateTime;
}

export interface AgentActionProposeIn {
  session_id: Uuid;
  action: AgentActionName;
  label: string;
  rationale?: string | null;
  payload?: Record<string, unknown>;
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

export interface AgentSpecialistTaskOut {
  id: Uuid;
  plan_index: number;
  specialist: "network" | "web" | "code" | "secrets" | "supply_chain" | "container" | "cloud";
  scanner: string;
  target_count: number;
  status: "pending" | "running" | "completed" | "degraded" | "failed";
  attempts: number;
  max_attempts: number;
  scanner_job_id: Uuid | null;
  evidence: Record<string, unknown>;
  failure_code: string | null;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
}

export type AgentTaskStatus =
  | "pending"
  | "blocked"
  | "ready"
  | "queued"
  | "running"
  | "awaiting_approval"
  | "completed"
  | "degraded"
  | "skipped"
  | "failed"
  | "rejected"
  | "cancelled";

export interface AgentEvidenceOut {
  id: Uuid;
  evidence_key: string;
  kind: "observation" | "artifact" | "provider_receipt" | "approval" | "report" | "metric";
  artifact_reference: string;
  content_digest: string;
  content_type: string | null;
  summary: Record<string, unknown>;
  verified: boolean;
  produced_at: IsoDateTime;
}

export interface AgentTaskOut {
  id: Uuid;
  task_key: string;
  kind: "agent" | "tool" | "approval" | "join" | "decision" | "finalize";
  status: AgentTaskStatus;
  depends_on: string[];
  required: boolean;
  plan_index: number;
  priority: number;
  attempt_count: number;
  max_attempts: number;
  tool_name: string | null;
  provider: string | null;
  output_summary: Record<string, unknown>;
  failure_code: string | null;
  failure_detail: string | null;
  started_at: IsoDateTime | null;
  settled_at: IsoDateTime | null;
  cancellation_requested_at: IsoDateTime | null;
  evidence: AgentEvidenceOut[];
}

export interface AgentRunOut {
  id: Uuid;
  session_id: Uuid | null;
  assessment_id: Uuid | null;
  thread_id: string;
  graph: string;
  objective: string | null;
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
  total_spend_micros: number;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  steps: AgentStepOut[];
  specialist_tasks: AgentSpecialistTaskOut[];
  tasks?: AgentTaskOut[];
  stop_reason?: string | null;
}

export interface AgentRunCreateIn {
  session_id: Uuid;
  objective: string;
}

export interface AgentSessionOut {
  id: Uuid;
  title: string;
  is_archived: boolean;
  message_count: number;
  autonomy_mode: "supervised" | "monitored";
  agent_version_id: Uuid | null;
  last_activity_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface AgentSessionAutonomyIn {
  autonomy_mode: AgentSessionOut["autonomy_mode"];
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

// ---------------------------------------------------------------------------
// Attack Surface Management surfaces (app/schemas/asm.py).
// ---------------------------------------------------------------------------

export interface AsmSurfaceOut {
  id: Uuid;
  organization_id: Uuid;
  name: string;
  seeds: string[];
  cron_expression: string;
  timezone: string;
  authorization_expires_at: IsoDateTime;
  enabled: boolean;
  next_run_at: IsoDateTime;
  last_run_at: IsoDateTime | null;
  last_asset_count: number;
  last_new_count: number;
  last_error_code: string | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface AsmSurfaceCreateIn {
  name: string;
  seeds: string[];
  cron_expression: string;
  timezone?: string;
  authorization_text: string;
  authorization_confirmed: boolean;
  authorization_expires_at: IsoDateTime;
}

export interface AsmSurfaceUpdateIn {
  name?: string;
  seeds?: string[];
  cron_expression?: string;
  enabled?: boolean;
  authorization_text?: string;
  authorization_expires_at?: IsoDateTime;
}

// ---------------------------------------------------------------------------
// Automation rules (app/schemas/automation.py).
// ---------------------------------------------------------------------------

export type AutomationTrigger =
  | "finding.created"
  | "finding.updated"
  | "ticket.closed"
  | "retest.confirmed"
  | "retest.cleared"
  | "sla.breached"
  | "asset.created"
  | "asset.updated"
  | "assessment.started"
  | "assessment.completed"
  | "engagement.created"
  | "engagement.status_changed"
  | "scan.failed"
  | "integration.error"
  | "webhook.received"
  | "manual";

export interface AutomationCondition {
  field: string;
  op: string;
  value: unknown;
}

export interface AutomationAction {
  type: string;
  provider?: string;
  channels?: string[];
  assignee_user_id?: Uuid;
  remediation_group?: string;
  authorization_reference?: string;
  key?: string;
  value?: unknown;
  field?: string;
  assessment_id?: Uuid;
  format?: "html" | "pdf" | "json";
  audience?: "executive" | "technical";
  title?: string;
  session_id?: Uuid;
  objective?: string;
}

export interface AutomationTemplateOut {
  id: string;
  name: string;
  description: string;
  definition: Pick<AutomationRuleCreateIn, "trigger" | "conditions" | "actions">;
}

export interface AutomationCatalogOut {
  triggers: AutomationTrigger[];
  conditions: string[];
  actions: string[];
  templates: AutomationTemplateOut[];
}

export interface AutomationRuleOut {
  id: Uuid;
  name: string;
  trigger: AutomationTrigger;
  conditions: Record<string, unknown>;
  actions: AutomationAction[];
  cron_expression: string | null;
  timezone: string;
  next_run_at: IsoDateTime | null;
  is_enabled: boolean;
  dry_run: boolean;
  created_at: IsoDateTime;
}

export interface AutomationRuleCreateIn {
  name: string;
  trigger: AutomationTrigger;
  conditions?: Record<string, unknown>;
  actions: AutomationAction[];
  cron_expression?: string | null;
  timezone?: string;
  is_enabled?: boolean;
  dry_run?: boolean;
}

export interface AutomationExecutionOut {
  id: Uuid;
  rule_id: Uuid;
  canonical_finding_id: Uuid | null;
  event_key: string;
  status: "pending" | "skipped" | "dry_run" | "executed" | "failed";
  dry_run: boolean;
  attempts: number;
  next_retry_at: IsoDateTime | null;
  result: Record<string, unknown>;
  created_at: IsoDateTime;
}

export type WorkflowNodeType = "trigger" | "condition" | "enrichment" | "action" | "branch" | "delay" | "approval";

export interface WorkflowNodeIn {
  id: string;
  type: WorkflowNodeType;
  config: Record<string, unknown>;
}

export interface WorkflowEdgeIn {
  source: string;
  target: string;
  branch?: "true" | "false" | "always";
}

export interface WorkflowDefinitionIn {
  name: string;
  description?: string | null;
  nodes: WorkflowNodeIn[];
  edges: WorkflowEdgeIn[];
  is_enabled?: boolean;
  dry_run?: boolean;
}

export interface WorkflowDefinitionOut extends WorkflowDefinitionIn {
  id: Uuid;
  organization_id: Uuid;
  version: number;
  next_run_at: IsoDateTime | null;
  created_by_id: Uuid | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface WorkflowRunOut {
  id: Uuid;
  workflow_id: Uuid;
  organization_id: Uuid;
  definition_version: number;
  event_key: string;
  trigger: string;
  context: Record<string, unknown>;
  status: "pending" | "running" | "waiting" | "succeeded" | "failed" | "cancelled" | "dry_run";
  dry_run: boolean;
  attempts: number;
  next_resume_at: IsoDateTime | null;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  error_code: string | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface ScanAuthProfileIn {
  name: string;
  auth_type: "basic" | "bearer" | "header" | "cookie" | "openapi_token" | "aws_static" | "aws_role" | "azure_service_principal" | "gcp_service_account";
  target_patterns: string[];
  permitted_scanners: string[];
  metadata?: Record<string, unknown>;
  secrets: Record<string, string>;
  is_active?: boolean;
}

export interface ScanAuthProfileOut extends Omit<ScanAuthProfileIn, "secrets"> {
  id: Uuid;
  fingerprint: string;
  hint: string | null;
  last_validated_at: IsoDateTime | null;
  rotated_at: IsoDateTime | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

// ---------------------------------------------------------------------------
// Attack Simulation campaigns (app/schemas/attack_simulation.py).
// ---------------------------------------------------------------------------

export type AttackSimulationStatus = "draft" | "active" | "paused" | "completed" | "failed";

export interface AttackSimulationCampaignOut {
  id: Uuid;
  name: string;
  authorization_reference: string;
  authorization_expires_at: IsoDateTime;
  scenarios: string[];
  targets: string[];
  cron_expression: string | null;
  timezone: string;
  next_run_at: IsoDateTime | null;
  last_run_at: IsoDateTime | null;
  last_assessment_id: Uuid | null;
  status: AttackSimulationStatus;
  last_error_code: string | null;
  created_at: IsoDateTime;
}

export interface AttackSimulationTechniqueCatalogOut {
  key: string;
  scenario: string;
  title: string;
  mitre_technique: string;
  target_types: string[];
  adapter: string;
  risk_class: "low" | "medium" | "high";
  approval_required: boolean;
  timeout_seconds: number;
  expected_evidence: string[];
  cleanup: string;
  catalog_version: string;
}

export interface AttackSimulationTechniqueRunOut {
  id: Uuid;
  technique_key: string;
  scenario: string;
  mitre_technique: string;
  adapter: string;
  target: string;
  risk_class: "low" | "medium" | "high";
  status: "queued" | "awaiting_approval" | "running" | "completed" | "failed" | "cancelled";
  control_result: "detected" | "prevented" | "inconclusive" | "error" | null;
  approval_id: Uuid | null;
  scanner_job_id: Uuid | null;
  expected_evidence: string[];
  evidence_artifact_ids: string[];
  evidence_summary: Record<string, unknown>;
  error_code: string | null;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
}

export interface AttackSimulationRunOut {
  id: Uuid;
  campaign_id: Uuid;
  assessment_id: Uuid;
  baseline_run_id: Uuid | null;
  status: "pending" | "awaiting_approval" | "running" | "completed" | "failed" | "cancelled";
  catalog_version: string;
  scenarios_snapshot: string[];
  targets_snapshot: string[];
  summary: Record<string, unknown>;
  started_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface AttackSimulationRunDetailOut extends AttackSimulationRunOut {
  techniques: AttackSimulationTechniqueRunOut[];
}

export interface AttackSimulationCampaignCreateIn {
  name: string;
  authorization_text: string;
  authorization_reference: string;
  authorization_expires_at: IsoDateTime;
  scenarios: string[];
  targets: string[];
  cron_expression?: string | null;
  timezone?: string;
}

// ---------------------------------------------------------------------------
// Platform API keys (app/schemas/platform.py).
// ---------------------------------------------------------------------------

export interface PlatformApiKeyOut {
  id: Uuid;
  name: string;
  key_prefix: string;
  scopes: string[];
  expires_at: IsoDateTime | null;
  revoked_at: IsoDateTime | null;
  last_used_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface PlatformApiKeyCreateIn {
  name: string;
  scopes?: string[];
  expires_at?: IsoDateTime | null;
}

export interface PlatformApiKeyCreatedOut extends PlatformApiKeyOut {
  /** Shown once; never stored in plaintext. */
  secret: string;
}

// ---------------------------------------------------------------------------
// Saved views (app/schemas/saved_view.py).
// ---------------------------------------------------------------------------

export type SavedViewResource = "findings" | "assets";

export interface SavedViewOut {
  id: Uuid;
  name: string;
  resource: SavedViewResource;
  filters: Record<string, unknown>;
  created_at: IsoDateTime;
}

export interface SavedViewCreateIn {
  name: string;
  resource: SavedViewResource;
  filters: Record<string, unknown>;
}

export interface SavedViewUpdateIn {
  name?: string;
  filters?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Webhooks (app/schemas/webhook.py).
// ---------------------------------------------------------------------------

export interface WebhookSubscriptionOut {
  id: Uuid;
  name: string;
  url: string;
  event_types: string[];
  is_enabled: boolean;
  created_at: IsoDateTime;
}

export interface WebhookSubscriptionCreateIn {
  name: string;
  url: string;
  event_types: string[];
}

export interface WebhookSubscriptionIssuedOut extends WebhookSubscriptionOut {
  /** Returned exactly once after creation or signing-secret rotation. */
  secret: string;
}

export interface WebhookDeliveryOut {
  id: Uuid;
  event: string;
  status: string;
  subject: string | null;
  resource_type: string | null;
  resource_id: string | null;
  attempts: number;
  sent_at: IsoDateTime | null;
  next_retry_at: IsoDateTime | null;
  last_error: string | null;
  created_at: IsoDateTime;
}

export interface ExternalDeliveryOut {
  id: Uuid;
  event: string;
  channel: "slack" | "email" | "pagerduty" | "webhook" | "splunk";
  status: "pending" | "sent" | "failed";
  recipient: string;
  subject: string | null;
  resource_type: string | null;
  resource_id: string | null;
  attempts: number;
  sent_at: IsoDateTime | null;
  next_retry_at: IsoDateTime | null;
  last_error: string | null;
  created_at: IsoDateTime;
}

// ---------------------------------------------------------------------------
// Shared vulnerability intelligence catalog.
// ---------------------------------------------------------------------------

export interface VulnerabilityIntelligenceOut {
  cve_id: string;
  snapshot: {
    cvss_score?: number;
    epss_score?: number;
    in_kev?: boolean;
    ransomware_use?: boolean;
    exploit_available?: boolean;
    exploit_references?: string[];
    nvd_status?: string;
    kev_status?: string;
    epss_status?: string;
    stale_providers?: string[];
    [key: string]: unknown;
  };
  refreshed_at: IsoDateTime;
  expires_at: IsoDateTime;
}

export type ThreatEntityType = "cve" | "product" | "actor" | "domain" | "brand";

export interface ThreatWatchlistOut {
  id: Uuid;
  entity_type: ThreatEntityType;
  entity_key: string;
  label: string | null;
  is_active: boolean;
  last_matched_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface ThreatWatchlistCreateIn {
  entity_type: ThreatEntityType;
  entity_key: string;
  label?: string | null;
}

export interface ThreatWatchlistMatchOut {
  id: Uuid;
  watchlist_id: Uuid;
  observation_id: Uuid;
  canonical_finding_id: Uuid | null;
  asset_id: Uuid | null;
  match_key: string;
  matched_at: IsoDateTime;
}

// ---------------------------------------------------------------------------
// PTaaS engagements.
// ---------------------------------------------------------------------------

export type EngagementStatus =
  | "draft"
  | "scoping"
  | "active"
  | "retesting"
  | "completed"
  | "cancelled";

export interface EngagementCreateIn {
  title: string;
  description?: string | null;
  assessment_id?: Uuid | null;
  scope?: Record<string, unknown>;
  starts_at?: IsoDateTime | null;
  ends_at?: IsoDateTime | null;
  client_visible?: boolean;
}

export interface EngagementOut {
  id: Uuid;
  assessment_id: Uuid | null;
  title: string;
  description: string | null;
  status: EngagementStatus;
  scope: Record<string, unknown>;
  starts_at: IsoDateTime | null;
  ends_at: IsoDateTime | null;
  client_visible: boolean;
  created_by_id: Uuid | null;
  version: number;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface EngagementParticipantOut {
  id: Uuid;
  engagement_id: Uuid;
  user_id: Uuid | null;
  email: string;
  display_name: string | null;
  role: "lead_tester" | "tester" | "client_manager" | "client_observer";
  status: "invited" | "active" | "removed";
  created_at: IsoDateTime;
}

export interface EngagementMilestoneOut {
  id: Uuid;
  engagement_id: Uuid;
  title: string;
  description: string | null;
  status: "pending" | "in_progress" | "completed" | "blocked" | "cancelled";
  due_at: IsoDateTime | null;
  completed_at: IsoDateTime | null;
  sort_order: number;
  created_at: IsoDateTime;
}

export interface EngagementRetestRoundOut {
  id: Uuid;
  engagement_id: Uuid;
  assessment_id: Uuid | null;
  ordinal: number;
  status: "requested" | "scheduled" | "running" | "completed" | "cancelled" | "failed";
  requested_by_id: Uuid | null;
  note: string | null;
  requested_at: IsoDateTime;
  completed_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface EngagementTimeEntryOut {
  id: Uuid;
  engagement_id: Uuid;
  user_id: Uuid | null;
  minutes: number;
  work_date: string;
  note: string | null;
  billable: boolean;
  created_at: IsoDateTime;
}

export interface EngagementDocumentOut {
  id: Uuid;
  engagement_id: Uuid;
  uploaded_by_id: Uuid | null;
  title: string;
  kind: "scope" | "authorization" | "evidence" | "report" | "deliverable" | "other";
  content_type: string;
  size_bytes: number;
  sha256: string;
  client_visible: boolean;
  created_at: IsoDateTime;
}

// ---------------------------------------------------------------------------
// Durable agent execution workspaces.
// ---------------------------------------------------------------------------

export type AgentWorkspaceStatus = "active" | "suspended" | "closed" | "expired";

export interface AgentWorkspaceCreateIn {
  run_id: Uuid;
  name: string;
  max_bytes?: number;
  ttl_hours?: number;
}

export interface AgentWorkspaceOut {
  id: Uuid;
  run_id: Uuid;
  status: AgentWorkspaceStatus;
  name: string;
  max_bytes: number;
  used_bytes: number;
  manifest: Record<string, unknown>;
  expires_at: IsoDateTime;
  closed_at: IsoDateTime | null;
  version: number;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface WorkspaceArtifactOut {
  id: Uuid;
  workspace_id: Uuid;
  task_id: Uuid | null;
  kind: "input" | "output" | "screenshot" | "har" | "console" | "report" | "evidence" | "archive";
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  summary: Record<string, unknown>;
  is_evidence: boolean;
  created_at: IsoDateTime;
}

export interface WorkspaceRecordOut {
  id: Uuid;
  workspace_id: Uuid;
  namespace: string;
  key: string;
  value: Record<string, unknown>;
  version: number;
  updated_by_task_id: Uuid | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface WorkspaceEvidenceManifest {
  schema_version: "v1";
  workspace: {
    id: Uuid;
    run_id: Uuid;
    name: string;
    status: AgentWorkspaceStatus;
    used_bytes: number;
    max_bytes: number;
    expires_at: IsoDateTime;
  };
  artifacts: Array<{
    id: Uuid;
    task_id: Uuid | null;
    kind: WorkspaceArtifactOut["kind"];
    filename: string;
    content_type: string;
    size_bytes: number;
    sha256: string;
    is_evidence: boolean;
  }>;
  records: Array<{
    namespace: string;
    key: string;
    value: Record<string, unknown>;
    version: number;
  }>;
  executions: Array<{
    id: Uuid;
    task_id: Uuid;
    approval_id: Uuid;
    kind: "shell" | "browser" | "scanner";
    status: string;
    executable: string;
    argument_names: string[];
    environment_names: string[];
    command_digest: string;
    result_summary: Record<string, unknown>;
  }>;
}

// ---------------------------------------------------------------------------
// Unified security control plane.
// ---------------------------------------------------------------------------

export type SecurityResourceKind =
  | "asset" | "data_store" | "dataset" | "saas_application" | "ai_application"
  | "ai_model" | "ai_agent" | "mcp_server" | "ai_tool" | "identity" | "endpoint" | "browser";

export interface SecurityResource {
  id: Uuid;
  resource_key: string;
  kind: SecurityResourceKind;
  name: string;
  provider: string | null;
  external_id: string | null;
  asset_id: Uuid | null;
  owner_team: string | null;
  environment: string;
  internet_exposed: boolean;
  approved: boolean | null;
  posture_status: "unknown" | "healthy" | "at_risk" | "non_compliant" | "inactive";
  risk_score: string;
  sensitivity: string;
  classifications: string[];
  permissions: Record<string, unknown>;
  attributes: Record<string, unknown>;
  provenance: Record<string, unknown>;
  source_count: number;
  identity_confidence: string;
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime;
}

export interface SecurityPosture {
  total_resources: number;
  active_sources: number;
  stale_resources: number;
  unknown_owner: number;
  internet_exposed: number;
  non_compliant: number;
  at_risk: number;
  approved_ai: number;
  unapproved_ai: number;
  source_coverage: Record<string, number>;
  kind_coverage: Record<string, number>;
  average_identity_confidence: string;
}

export interface NativeAIPostureAssessment {
  policy_id: Uuid;
  assessed_resources: number;
  compliant_resources: number;
  at_risk_resources: number;
  critical_resources: number;
  recommendations_created: number;
  evaluation_ids: Uuid[];
  recommendation_ids: Uuid[];
  finding_counts: Record<string, number>;
  external_connector_required: false;
}

export type SecurityPolicyKind =
  | "ztna" | "secure_web_gateway" | "firewall" | "tls_inspection" | "dlp" | "casb"
  | "sspm" | "ai_gateway" | "ai_guard" | "endpoint_isolation" | "browser_isolation";

export interface SecurityPolicy {
  id: Uuid;
  name: string;
  kind: SecurityPolicyKind;
  mode: "monitor" | "recommend" | "enforce";
  status: "draft" | "active" | "disabled";
  version: number;
  rules: Record<string, unknown>;
  integration_id: Uuid | null;
  created_at: IsoDateTime;
}

export interface SecurityPolicyEvaluation {
  id: Uuid;
  policy_id: Uuid;
  resource_id: Uuid | null;
  event_id: Uuid | null;
  decision: "allow" | "block" | "redact" | "require_approval" | "recommend" | "not_applicable";
  severity: Severity;
  score: string;
  findings: Array<Record<string, unknown>>;
  evidence: Record<string, unknown>;
  content_digest: string | null;
  evaluated_at: IsoDateTime;
}

export interface PrivateAccessEvaluateInput {
  policy_id: Uuid;
  request_id: string;
  identity_ref: string;
  groups?: string[];
  application_ref: string;
  application_tags?: string[];
  device_posture?: string[];
  mfa?: boolean;
  source_country?: string | null;
  identity_risk_score?: number;
  requested_session_minutes?: number;
}

export interface PrivateAccessDecision {
  policy_id: Uuid;
  policy_version: number;
  event_id: Uuid;
  decision: "allow" | "deny";
  enforced: boolean;
  would_block: boolean;
  session_minutes: number;
  reason_codes: string[];
}

export interface CasbEvaluateInput {
  action: "upload" | "download" | "share" | "external_share" | "copy" | "paste" | "print";
  content: string;
  policy_id?: Uuid | null;
  identity_ref: string;
  groups?: string[];
  application_key: string;
  device_managed: boolean;
  mfa: boolean;
  destination_domain?: string | null;
}

export interface CasbDecision {
  decision: "allow" | "block" | "redact" | "require_approval";
  severity: Severity;
  score: string;
  reasons: string[];
  content_digest: string;
  redacted_content: string | null;
  approval_required: boolean;
}

export type SecurityRecommendationStatus =
  | "proposed" | "approved" | "applying" | "applied" | "rejected" | "failed" | "superseded";

export interface SecurityRecommendation {
  id: Uuid;
  policy_id: Uuid | null;
  resource_id: Uuid | null;
  asset_id: Uuid | null;
  integration_id: Uuid | null;
  domain: string;
  title: string;
  rationale: string;
  action: string;
  severity: Severity;
  status: SecurityRecommendationStatus;
  current_state: Record<string, unknown>;
  desired_state: Record<string, unknown>;
  idempotency_key: string;
  provider_receipt: Record<string, unknown>;
  applied_by_id: Uuid | null;
  applied_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface SecurityThreatStory {
  id: Uuid;
  correlation_key: string;
  title: string;
  status: "open" | "investigating" | "contained" | "resolved" | "dismissed";
  severity: Severity;
  confidence: string;
  summary: string;
  event_ids: string[];
  asset_ids: string[];
  finding_ids: string[];
  identity_refs: string[];
  timeline: Array<Record<string, unknown>>;
  first_seen_at: IsoDateTime;
  last_seen_at: IsoDateTime;
  assigned_user_id: Uuid | null;
  resolution: string | null;
}

export interface SecurityEvent {
  id: Uuid;
  event_key: string;
  category: string;
  event_type: string;
  source_kind: string;
  occurred_at: IsoDateTime;
  severity: Severity;
  summary: string;
  content_digest: string | null;
  asset_id: Uuid | null;
  resource_id: Uuid | null;
  identity_ref: string | null;
  metrics: Record<string, unknown>;
  evidence: Record<string, unknown>;
}

export interface NativeEndpointEventInput {
  event_key: string;
  endpoint_key: string;
  hostname: string;
  operating_system: "windows" | "linux" | "macos" | "other";
  occurred_at: IsoDateTime;
  event_type: "process_start" | "network_connection" | "file_change" | "identity_activity" | "persistence" | "autorun_change" | "scheduled_task_created" | "security_control_disabled" | "sensor_tamper" | "defense_evasion" | "ransomware_activity" | "malware";
  process_name?: string | null;
  parent_process_name?: string | null;
  executable_path?: string | null;
  command_line?: string | null;
  signature_status?: "signed" | "unsigned" | "invalid" | "unknown";
  destination_host?: string | null;
  destination_port?: number | null;
  file_activity_count?: number;
  identity_ref?: string | null;
  attack_techniques?: string[];
  asset_id?: Uuid | null;
  environment?: "production" | "staging" | "development" | "test" | "unknown";
  internet_exposed?: boolean;
}

export interface NativeEndpointEventResult {
  endpoint: SecurityResource;
  event: SecurityEvent;
  story: SecurityThreatStory | null;
  decision: {
    verdict: "observe" | "detect";
    severity: Severity;
    score: number;
    detections: Array<{ code: string; score: number; technique_id: string; rationale: string }>;
    attack_techniques: string[];
    command_digest: string | null;
    destination_digest: string | null;
  };
}

export interface SecurityExperienceSummary {
  event_count: number;
  monitored_journeys: number;
  degraded_journeys: number;
  average_score: string;
  business_impact: "unknown" | "low" | "moderate" | "high" | "critical";
  latest_at: IsoDateTime | null;
}

export interface SecurityCanary {
  id: Uuid;
  name: string;
  kind: "credential" | "dns" | "http" | "file" | "cloud_resource" | "identity";
  token_digest: string;
  asset_id: Uuid | null;
  status: "active" | "disabled" | "triggered" | "retired";
  placement: Record<string, unknown>;
  last_triggered_at: IsoDateTime | null;
  created_at: IsoDateTime;
}

export interface SecurityRiskSimulation {
  id: Uuid;
  name: string;
  business_service_id: Uuid | null;
  scenario_id: Uuid | null;
  status: string;
  annual_probability: string;
  loss_min: string;
  loss_likely: string;
  loss_max: string;
  control_effectiveness: string;
  acceptance_status: string;
  expected_loss: string;
  inherent_annual_loss: string;
  residual_annual_loss: string;
  assumptions: Record<string, unknown>;
  evidence: Record<string, unknown>;
  narrative: string | null;
}

export interface AIGatewayDecision {
  decision: "allow" | "block" | "redact" | "require_approval";
  severity: Severity;
  score: string;
  reasons: string[];
  content_digest: string;
  redacted_content: string | null;
  approval_required: boolean;
}

export interface DataClassification {
  labels: string[];
  highest_sensitivity: "public" | "internal" | "confidential" | "restricted";
  redacted_content: string;
  content_digest: string;
  match_counts: Record<string, number>;
}

export interface AssuranceSummary {
  transactions: Array<{
    id: Uuid;
    provider: string;
    operation: string;
    status: string;
    diff_digest: string;
    blast_radius: Record<string, unknown>;
    created_at: IsoDateTime;
  }>;
  ai: {
    receipts: Array<{
      id: Uuid;
      provider: string;
      model: string;
      decision: "allow" | "block" | "redact" | "require_approval";
      reason_codes: string[];
      created_at: IsoDateTime;
    }>;
    manifests: Array<{
      id: Uuid;
      server_key: string;
      tool_name: string;
      version: string;
      status: string;
      approved: boolean;
      schema_digest: string;
    }>;
  };
  agent_assurance: Array<{
    id: Uuid;
    run_id: Uuid;
    verifier_status: string;
    confidence: string;
    metrics: Record<string, unknown>;
    finalized_at: IsoDateTime | null;
  }>;
  agent_evaluations: {
    suites: Array<{
      id: Uuid;
      suite_key: string;
      name: string;
      task_kind: string;
      version: number;
      case_count: number;
      active: boolean;
    }>;
    runs: Array<{
      id: Uuid;
      suite_id: Uuid;
      agent_version_id: Uuid;
      status: string;
      metrics: Record<string, string | number | boolean | null>;
      failed_thresholds: string[];
      passed: boolean;
      completed_at: IsoDateTime;
    }>;
  };
  validation_recipes: Array<{
    id: Uuid;
    recipe_key: string;
    status: string;
    exploitation_verdict: string;
    reproducibility_score: string;
  }>;
  data_security: Array<{
    id: Uuid;
    provider: string;
    service: string;
    scan_mode: string;
    posture_score: string;
    findings: Array<Record<string, unknown>>;
    observed_at: IsoDateTime;
  }>;
  response_actions: Array<{
    id: Uuid;
    action_type: string;
    target_ref: string;
    status: string;
    predicted_impact: Record<string, unknown>;
  }>;
  risk_trials: Array<{
    id: Uuid;
    simulation_id: Uuid;
    p05: string;
    p50: string;
    p95: string;
    mean_annual_loss: string;
    iterations: number;
    seed: number;
  }>;
  compliance_exports: Array<{
    id: Uuid;
    package_key: string;
    model: string;
    status: string;
    content_digest: string;
    generated_at: IsoDateTime;
  }>;
}
