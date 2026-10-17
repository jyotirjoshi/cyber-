/**
 * API client — INTERFACES §14: the ONLY module in the frontend that talks HTTP. Every screen
 * and hook calls through `api.*`; nothing else constructs a fetch to the backend.
 *
 * Responsibilities:
 * - Attach `Authorization: Bearer <access>` (auth model: HTTPBearer).
 * - On 401, refresh once via `POST /auth/refresh`, then replay the original request. Concurrent
 *   401s share a single in-flight refresh. A failed refresh clears the token store (→ logout).
 * - Turn a non-2xx `application/problem+json` body into a typed {@link ApiError} carrying the
 *   RFC 9457 {@link Problem}; synthesize one for network/parse failures.
 * - Mount everything under `/api/v1` except health (root) and the WS URL (root, unversioned).
 */

import { clearTokens, getAccessToken, getRefreshToken, setTokens } from "./tokens";
import { knowledgeFileType } from "./knowledge";
import type { AgentConfiguration, AgentDefinition, AgentVersion, AgentTool, AgentPolicyPreview, MemoryCandidate, MemoryApproval } from "./agent-definition";
import type { CollectionCreateInput, KnowledgeCollection, KnowledgeHit, KnowledgeSource } from "./knowledge";
import type {
  AgentActionOut,
  AgentActionProposeIn,
  AgentEvent,
  AgentMessageIn,
  AgentMessageOut,
  AgentMemoryOut,
  AgentMemoryUpsertIn,
  AgentRunOut,
  AgentRunCreateIn,
  AgentSessionDetailOut,
  AgentSessionAutonomyIn,
  AgentSessionOut,
  AgentWorkspaceCreateIn,
  AgentWorkspaceOut,
  AgentWorkspaceStatus,
  AnalyzeIn,
  ApplicationPatternsOut,
  ApplicationRiskPageOut,
  ApprovalOut,
  ApproveIn,
  AsmSurfaceCreateIn,
  AsmSurfaceOut,
  AsmSurfaceUpdateIn,
  AssessmentCreateIn,
  AssessmentDetailOut,
  AssessmentFilter,
  AssessmentOut,
  EngagementChecklistUpdateIn,
  AssetCriticalityIn,
  AssetChangePageOut,
  AssetContextIn,
  CmdbImportOut,
  AssetFilter,
  AssetOut,
  AssetTagIn,
  BulkCanonicalWorkIn,
  AttackSimulationCampaignCreateIn,
  AttackSimulationCampaignOut,
  AttackSimulationRunDetailOut,
  AttackSimulationRunOut,
  AttackSimulationTechniqueCatalogOut,
  AuditEventOut,
  AuditFilter,
  AutomationCatalogOut,
  AutomationExecutionOut,
  AutomationRuleCreateIn,
  AutomationRuleOut,
  CancelIn,
  ClientOrganizationCreateIn,
  ClientOrganizationDelegateIn,
  ClientOrganizationPortfolioOut,
  CanonicalFindingDetailOut,
  CanonicalFindingOut,
  CanonicalRemediationOperationOut,
  FindingCollaborationCommentCreateIn,
  FindingCollaborationCommentOut,
  CanonicalStatusDecisionIn,
  CanonicalWorkIn,
  ComplianceControlOut,
  ComplianceFramework,
  ComplianceOverviewOut,
  ChangePasswordIn,
  DashboardOut,
  DashboardLayoutIn,
  DashboardLayoutOut,
  EngagementCreateIn,
  EngagementDocumentOut,
  EngagementMilestoneOut,
  EngagementOut,
  EngagementParticipantOut,
  EngagementRetestRoundOut,
  EngagementStatus,
  EngagementTimeEntryOut,
  AssetGroupRiskOut,
  TeamDashboardOut,
  ExternalAlertFilter,
  ExternalAlertDetailOut,
  ExternalAlertTriageIn,
  ExternalAlertSourceActionIn,
  RelatedFindingOut,
  ExternalAlertOut,
  ExternalDeliveryOut,
  ExposureFilter,
  ExposureOut,
  FindingDetailOut,
  FindingFilter,
  FindingOut,
  HealthOut,
  IntegrationHealthOut,
  IntegrationKind,
  IntegrationOut,
  IntegrationSyncOut,
  TenableScanLaunchOut,
  TenableScanStatusOut,
  IntegrationTestOut,
  IntegrationUpsertIn,
  JiraTicketIn,
  JobFilter,
  LoginIn,
  LogoutIn,
  MeOut,
  MemberInviteIn,
  MemberOut,
  MemberRoleIn,
  OkOut,
  OrganizationOut,
  OrganizationUpdateIn,
  OidcConnectionOut,
  OidcConnectionUpsertIn,
  Page,
  PasswordResetConfirmIn,
  PasswordResetRequestIn,
  PlatformApiKeyCreateIn,
  PlatformApiKeyCreatedOut,
  PlatformApiKeyOut,
  PolicyGateOut,
  Problem,
  RegisterIn,
  RemediateIn,
  RemediationGroupOut,
  RemediationOut,
  ReportDetailOut,
  ReportGenerateIn,
  ReportOut,
  ReportScheduleCreateIn,
  ReportScheduleOut,
  RecurringScanOut,
  RecurringScanCreateIn,
  RetestRequestIn,
  RetestRequestOut,
  RiskAcceptanceIn,
  RiskAcceptanceOut,
  ScanProfileOut,
  ScanProfileCreateIn,
  SamlConnectionOut,
  SamlConnectionUpsertIn,
  ScimProvisioningTokenCreateIn,
  ScimProvisioningTokenIssuedOut,
  ScimProvisioningTokenOut,
  ReportShareCreateIn,
  ReportShareIssuedOut,
  ReportShareLinkOut,
  ReportTemplateCreateIn,
  ReportTemplateOut,
  RiskTrendOut,
  SavedViewCreateIn,
  SavedViewOut,
  SavedViewUpdateIn,
  ScannerJobOut,
  SwitchOrganizationIn,
  TicketLinkOut,
  ThreatWatchlistCreateIn,
  ThreatWatchlistMatchOut,
  ThreatWatchlistOut,
  TokenPairOut,
  ValidateFindingIn,
  VulnerabilityIntelligenceOut,
  WebhookSubscriptionCreateIn,
  WebhookDeliveryOut,
  WebhookSubscriptionIssuedOut,
  WebhookSubscriptionOut,
  WorkerMetricsOut,
  WorkflowDefinitionIn,
  WorkflowDefinitionOut,
  WorkflowRunOut,
  WorkspaceArtifactOut,
  WorkspaceEvidenceManifest,
  WorkspaceRecordOut,
  ScanAuthProfileIn,
  ScanAuthProfileOut,
} from "./types";

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

const stripTrailingSlash = (value: string): string => value.replace(/\/+$/, "");

type LocationLike = Pick<Location, "protocol" | "host">;

/** Empty in production means Firebase Hosting's current origin. */
export function apiOrigin(
  configured = process.env.NEXT_PUBLIC_API_BASE_URL ??
    (process.env.NODE_ENV === "development" ? "http://localhost:8000" : ""),
): string {
  return stripTrailingSlash(configured);
}

/** Derive WS/WSS from the browser origin unless an explicit development endpoint is set. */
export function websocketOrigin(
  locationLike: LocationLike = globalThis.location,
  configured = process.env.NEXT_PUBLIC_WS_BASE_URL ??
    (process.env.NODE_ENV === "development" ? "ws://localhost:8000" : ""),
): string {
  const override = stripTrailingSlash(configured);
  if (override) return override;
  return `${locationLike.protocol === "https:" ? "wss" : "ws"}://${locationLike.host}`;
}

const API_BASE = apiOrigin();

const API_PREFIX = "/api/v1";

/** Public, unauthenticated download URL for a one-time-issued opaque report grant. */
export function reportShareUrl(token: string): string {
  return `${API_BASE}${API_PREFIX}/shared/reports/${encodeURIComponent(token)}`;
}

// ---------------------------------------------------------------------------
// Typed error.
// ---------------------------------------------------------------------------

/** A non-2xx response, or a transport/parse failure, wrapped around a {@link Problem}. */
export class ApiError extends Error {
  readonly problem: Problem;
  readonly status: number;

  constructor(problem: Problem) {
    super(problem.title || problem.code || "Request failed");
    this.name = "ApiError";
    this.problem = problem;
    this.status = problem.status;
  }

  get code(): string {
    return this.problem.code;
  }

  get retryable(): boolean {
    return this.problem.retryable;
  }

  /** Field-level validation errors from a 422, keyed by field path. */
  get fieldErrors(): Record<string, string[]> {
    return this.problem.errors ?? {};
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

function syntheticProblem(status: number, code: string, title: string): Problem {
  return {
    type: "about:blank",
    title,
    status,
    code,
    category: code,
    retryable: status === 0 || status >= 500,
  };
}

async function toApiError(res: Response): Promise<ApiError> {
  try {
    const data = (await res.json()) as Partial<Problem>;
    if (data && typeof data === "object" && typeof data.title === "string") {
      return new ApiError({
        type: data.type ?? "about:blank",
        title: data.title,
        status: typeof data.status === "number" ? data.status : res.status,
        code: data.code ?? "error",
        category: data.category ?? "error",
        retryable: data.retryable ?? false,
        detail: data.detail ?? null,
        instance: data.instance ?? null,
        request_id: data.request_id ?? null,
        errors: data.errors ?? null,
      });
    }
  } catch {
    // Body was not JSON — fall through to a synthetic problem.
  }
  return new ApiError(
    syntheticProblem(res.status, "http_error", res.statusText || "Request failed"),
  );
}

// ---------------------------------------------------------------------------
// Query-string helpers.
// ---------------------------------------------------------------------------

/**
 * Pagination + sort options every list endpoint accepts, merged with its filter. The default is
 * `unknown` (not `Record<string, never>`, whose `never`-valued index rejects even `{ limit }`) so a
 * bare `ListParams` — the no-filter endpoints like `organization.members` — accepts the pagination
 * fields on their own: `unknown & T` reduces to `T`.
 */
export type ListParams<F = unknown> = F & {
  limit?: number;
  offset?: number;
  sort_by?: string;
  sort_dir?: "asc" | "desc";
};

/**
 * Serialize a params object to a query string. Typed as `unknown` because the concrete filter
 * interfaces (which lack an index signature) are not assignable to `Record<string, unknown>`;
 * the public api methods type their params, so safety is enforced at the call boundary. Null and
 * undefined are dropped, arrays repeat the key, everything else is stringified.
 */
function buildQuery(params?: unknown): string {
  if (!params || typeof params !== "object") return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) search.append(key, String(item));
      }
    } else {
      search.append(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

// ---------------------------------------------------------------------------
// Core request pipeline with single-flight token refresh.
// ---------------------------------------------------------------------------

interface RequestOptions {
  query?: unknown;
  body?: unknown;
  /** Attach the bearer token and enable 401→refresh→retry. Default true. */
  auth?: boolean;
  /** Mount at the server root instead of `/api/v1` (health checks). Default false. */
  root?: boolean;
}

let refreshInFlight: Promise<void> | null = null;

/** Refresh the token pair exactly once for concurrent callers. Clears tokens on failure. */
async function refreshTokens(): Promise<void> {
  if (refreshInFlight) return refreshInFlight;

  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    throw new ApiError(syntheticProblem(401, "unauthenticated", "Your session has expired."));
  }

  refreshInFlight = (async () => {
    let res: Response;
    try {
      res = await fetch(`${API_BASE}${API_PREFIX}/auth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch {
      clearTokens();
      throw new ApiError(syntheticProblem(0, "network_error", "Unable to reach the server."));
    }
    if (!res.ok) {
      clearTokens();
      throw await toApiError(res);
    }
    const pair = (await res.json()) as TokenPairOut;
    setTokens(pair);
  })();

  try {
    await refreshInFlight;
  } finally {
    refreshInFlight = null;
  }
}

async function rawFetch(
  method: string,
  path: string,
  options: RequestOptions,
): Promise<Response> {
  const base = options.root ? API_BASE : `${API_BASE}${API_PREFIX}`;
  const url = `${base}${path}${buildQuery(options.query)}`;

  const headers: Record<string, string> = { accept: "application/json" };
  const isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;
  if (options.body !== undefined && !isFormData) headers["content-type"] = "application/json";
  if (options.auth !== false) {
    const token = getAccessToken();
    if (token) headers.authorization = `Bearer ${token}`;
  }

  try {
    return await fetch(url, {
      method,
      headers,
      body: isFormData
        ? options.body as FormData
        : options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });
  } catch {
    throw new ApiError(syntheticProblem(0, "network_error", "Unable to reach the server."));
  }
}

async function parse<T>(res: Response): Promise<T> {
  if (!res.ok) throw await toApiError(res);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

async function request<T>(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const res = await rawFetch(method, path, options);

  if (res.status === 401 && options.auth !== false && getRefreshToken()) {
    await refreshTokens();
    const retry = await rawFetch(method, path, options);
    return parse<T>(retry);
  }

  return parse<T>(res);
}

// ---------------------------------------------------------------------------
// Binary downloads (authenticated fetch → Blob + filename).
// ---------------------------------------------------------------------------

export interface DownloadedFile {
  blob: Blob;
  filename: string;
}

function filenameFromDisposition(header: string | null, fallback: string): string {
  if (!header) return fallback;
  const star = /filename\*=(?:UTF-8'')?([^;]+)/i.exec(header);
  if (star?.[1]) {
    try {
      return decodeURIComponent(star[1].replace(/^"|"$/g, ""));
    } catch {
      /* fall through */
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(header);
  return plain?.[1] ?? fallback;
}

/** GET a binary endpoint with auth (following any 307 to presigned storage) → blob + filename. */
async function download(
  path: string,
  fallbackName: string,
  query?: unknown,
): Promise<DownloadedFile> {
  const doFetch = () => {
    const headers: Record<string, string> = {};
    const token = getAccessToken();
    if (token) headers.authorization = `Bearer ${token}`;
    return fetch(`${API_BASE}${API_PREFIX}${path}${buildQuery(query)}`, { headers });
  };

  let res: Response;
  try {
    res = await doFetch();
    if (res.status === 401 && getRefreshToken()) {
      await refreshTokens();
      res = await doFetch();
    }
  } catch {
    throw new ApiError(syntheticProblem(0, "network_error", "Unable to reach the server."));
  }
  if (!res.ok) throw await toApiError(res);

  const blob = await res.blob();
  const filename = filenameFromDisposition(
    res.headers.get("content-disposition"),
    fallbackName,
  );
  return { blob, filename };
}

/** Trigger a browser save for an already-fetched blob. */
export function saveBlob(file: DownloadedFile): void {
  if (typeof window === "undefined") return;
  const url = URL.createObjectURL(file.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// The client. Grouped to mirror the router namespaces.
// ---------------------------------------------------------------------------

export const api = {
  customAgents: {
    list: (offset = 0) => request<AgentDefinition[]>("GET", `/agents/definitions?limit=50&offset=${offset}`),
    get: (id: string) => request<AgentDefinition>("GET", `/agents/definitions/${id}`),
    create: (body: AgentConfiguration & { name: string; description?: string }) => request<AgentDefinition>("POST", "/agents/definitions", { body }),
    versions: (id: string, offset = 0) => request<AgentVersion[]>("GET", `/agents/definitions/${id}/versions?limit=50&offset=${offset}`),
    version: (id: string, body: AgentConfiguration & { expected_active_version_id: string }) => request<AgentVersion>("POST", `/agents/definitions/${id}/versions`, { body }),
    disable: (id: string) => request<AgentDefinition>("POST", `/agents/definitions/${id}/disable`),
    tools: () => request<AgentTool[]>("GET", "/agents/tools"),
    preview: (body: AgentConfiguration) => request<AgentPolicyPreview>("POST", "/agents/policy-preview", { body }),
    candidates: (status: MemoryCandidate["status"], offset = 0) => request<MemoryCandidate[]>("GET", `/agents/memory-candidates?status=${status}&limit=50&offset=${offset}`),
    approveMemory: (id: string, body: MemoryApproval) => request<MemoryCandidate>("POST", `/agents/memory-candidates/${id}/approve`, { body }),
    rejectMemory: (id: string, rationale: string) => request<MemoryCandidate>("POST", `/agents/memory-candidates/${id}/reject`, { body: { rationale } }),
  },
  knowledge: {
    collections: () => request<KnowledgeCollection[]>("GET", "/knowledge/collections"),
    createCollection: (body: CollectionCreateInput) => request<KnowledgeCollection>("POST", "/knowledge/collections", { body }),
    sources: (collectionId: string, offset = 0) => request<KnowledgeSource[]>("GET", `/knowledge/collections/${collectionId}/sources`, { query: { limit: 100, offset } }),
    upload: (collectionId: string, file: File) => {
      const body = new FormData();
      body.append("file", new Blob([file], { type: knowledgeFileType(file.name) }), file.name);
      return request<KnowledgeSource>("POST", `/knowledge/collections/${collectionId}/sources`, { body });
    },
    deleteSource: (sourceId: string) => request<KnowledgeSource>("DELETE", `/knowledge/sources/${sourceId}`),
    restoreSource: (sourceId: string) => request<KnowledgeSource>("POST", `/knowledge/sources/${sourceId}/restore`),
    retrySource: (sourceId: string) => request<KnowledgeSource>("POST", `/knowledge/sources/${sourceId}/retry`),
    search: (collectionIds: string[], query: string) => request<KnowledgeHit[]>("POST", "/knowledge/search", { body: { collection_ids: collectionIds, query } }),
    feedback: (chunkId: string, query: string, isUseful: boolean) => request<{ id: string }>("POST", "/knowledge/feedback", { body: { chunk_id: chunkId, query, is_useful: isUseful } }),
  },
  auth: {
    register: (body: RegisterIn) =>
      request<TokenPairOut>("POST", "/auth/register", { body, auth: false }),
    login: (body: LoginIn) =>
      request<TokenPairOut>("POST", "/auth/login", { body, auth: false }),
    ssoStartUrl: (organizationSlug: string) =>
      `${API_BASE}${API_PREFIX}/auth/sso/${encodeURIComponent(organizationSlug)}/start`,
    samlSsoStartUrl: (organizationSlug: string) =>
      `${API_BASE}${API_PREFIX}/auth/sso/saml/${encodeURIComponent(organizationSlug)}/start`,
    samlMetadataUrl: (organizationSlug: string) =>
      `${API_BASE}${API_PREFIX}/auth/sso/saml/${encodeURIComponent(organizationSlug)}/metadata`,
    exchangeSso: (handoffToken: string) =>
      request<TokenPairOut>("POST", "/auth/sso/exchange", { body: { handoff_token: handoffToken }, auth: false }),
    me: () => request<MeOut>("GET", "/auth/me"),
    switchOrganization: (body: SwitchOrganizationIn) =>
      request<TokenPairOut>("POST", "/auth/switch-organization", { body }),
    logout: (body?: LogoutIn) =>
      request<OkOut>("POST", "/auth/logout", { body: body ?? {} }),
    passwordResetRequest: (body: PasswordResetRequestIn) =>
      request<OkOut>("POST", "/auth/password/reset-request", { body, auth: false }),
    passwordResetConfirm: (body: PasswordResetConfirmIn) =>
      request<OkOut>("POST", "/auth/password/reset-confirm", { body, auth: false }),
    changePassword: (body: ChangePasswordIn) =>
      request<OkOut>("POST", "/auth/password/change", { body }),
  },

  dashboard: {
    get: () => request<DashboardOut>("GET", "/dashboard"),
    teams: () => request<TeamDashboardOut[]>("GET", "/dashboard/teams"),
    assetGroups: (limit = 100) => request<AssetGroupRiskOut[]>("GET", "/dashboard/asset-groups", { query: { limit } }),
    riskTrend: (limit = 24) => request<RiskTrendOut>("GET", "/dashboard/risk-trend", { query: { limit } }),
    layouts: () => request<DashboardLayoutOut[]>("GET", "/dashboard/layouts"),
    createLayout: (body: DashboardLayoutIn) => request<DashboardLayoutOut>("POST", "/dashboard/layouts", { body }),
    updateLayout: (id: string, body: DashboardLayoutIn) => request<DashboardLayoutOut>("PUT", `/dashboard/layouts/${id}`, { body }),
    deleteLayout: (id: string) => request<void>("DELETE", `/dashboard/layouts/${id}`),
  },

  assessments: {
    list: (params?: ListParams<AssessmentFilter>) =>
      request<Page<AssessmentOut>>("GET", "/assessments", { query: params }),
    create: (body: AssessmentCreateIn) =>
      request<AssessmentDetailOut>("POST", "/assessments", { body }),
    updateEngagementChecklist: (assessmentId: string, key: string, body: EngagementChecklistUpdateIn) =>
      request<AssessmentDetailOut>("PATCH", `/assessments/${assessmentId}/engagement-checklist/${encodeURIComponent(key)}`, { body }),
    workerMetrics: () => request<WorkerMetricsOut>("GET", "/assessments/worker/metrics"),
    profiles: () => request<ScanProfileOut[]>("GET", "/assessments/profiles"),
    createProfile: (body: ScanProfileCreateIn) => request<ScanProfileOut>("POST", "/assessments/profiles", { body }),
    deactivateProfile: (id: string) =>
      request<ScanProfileOut>("POST", `/assessments/profiles/${id}/deactivate`),
    schedules: () => request<RecurringScanOut[]>("GET", "/assessments/schedules"),
    createSchedule: (body: RecurringScanCreateIn) => request<RecurringScanOut>("POST", "/assessments/schedules", { body }),
    pauseSchedule: (id: string) => request<RecurringScanOut>("POST", `/assessments/schedules/${id}/pause`),
    resumeSchedule: (id: string) => request<RecurringScanOut>("POST", `/assessments/schedules/${id}/resume`),
    get: (id: string) => request<AssessmentDetailOut>("GET", `/assessments/${id}`),
    cancel: (id: string, body: CancelIn = {}) =>
      request<AssessmentDetailOut>("POST", `/assessments/${id}/cancel`, { body }),
    reports: (id: string) => request<ReportOut[]>("GET", `/assessments/${id}/reports`),
    generateReport: (id: string, body: ReportGenerateIn = {}) =>
      request<ReportDetailOut>("POST", `/assessments/${id}/reports`, { body }),
  },

  engagements: {
    list: (params?: { limit?: number; offset?: number }) =>
      request<Page<EngagementOut>>("GET", "/engagements", { query: params }),
    create: (body: EngagementCreateIn) =>
      request<EngagementOut>("POST", "/engagements", { body }),
    get: (id: string) => request<EngagementOut>("GET", `/engagements/${id}`),
    updateStatus: (id: string, status: EngagementStatus, expectedVersion: number) =>
      request<EngagementOut>("PATCH", `/engagements/${id}/status`, {
        body: { status, expected_version: expectedVersion },
      }),
    participants: (id: string) =>
      request<EngagementParticipantOut[]>("GET", `/engagements/${id}/participants`),
    addParticipant: (
      id: string,
      body: {
        user_id?: string | null;
        email: string;
        display_name?: string | null;
        role: EngagementParticipantOut["role"];
      },
    ) => request<EngagementParticipantOut>("POST", `/engagements/${id}/participants`, { body }),
    milestones: (id: string) =>
      request<EngagementMilestoneOut[]>("GET", `/engagements/${id}/milestones`),
    addMilestone: (
      id: string,
      body: { title: string; description?: string | null; due_at?: string | null; sort_order?: number },
    ) => request<EngagementMilestoneOut>("POST", `/engagements/${id}/milestones`, { body }),
    retestRounds: (id: string) =>
      request<EngagementRetestRoundOut[]>("GET", `/engagements/${id}/retest-rounds`),
    createRetestRound: (id: string, body: { assessment_id?: string | null; note?: string | null }) =>
      request<EngagementRetestRoundOut>("POST", `/engagements/${id}/retest-rounds`, { body }),
    timeEntries: (id: string) =>
      request<EngagementTimeEntryOut[]>("GET", `/engagements/${id}/time-entries`),
    addTimeEntry: (
      id: string,
      body: { minutes: number; work_date: string; note?: string | null; billable?: boolean },
    ) => request<EngagementTimeEntryOut>("POST", `/engagements/${id}/time-entries`, { body }),
    documents: (id: string) =>
      request<EngagementDocumentOut[]>("GET", `/engagements/${id}/documents`),
    uploadDocument: (
      id: string,
      input: { file: File; title: string; kind: EngagementDocumentOut["kind"]; clientVisible: boolean },
    ) => {
      const form = new FormData();
      form.append("file", input.file);
      form.append("title", input.title);
      form.append("kind", input.kind);
      form.append("client_visible", String(input.clientVisible));
      return request<EngagementDocumentOut>("POST", `/engagements/${id}/documents/upload`, { body: form });
    },
  },

  agentWorkspaces: {
    list: (params?: { limit?: number; offset?: number }) =>
      request<Page<AgentWorkspaceOut>>("GET", "/agent-workspaces", { query: params }),
    create: (body: AgentWorkspaceCreateIn) =>
      request<AgentWorkspaceOut>("POST", "/agent-workspaces", { body }),
    get: (id: string) => request<AgentWorkspaceOut>("GET", `/agent-workspaces/${id}`),
    updateStatus: (
      id: string,
      status: Extract<AgentWorkspaceStatus, "active" | "suspended" | "closed">,
      expectedVersion: number,
    ) => request<AgentWorkspaceOut>("PATCH", `/agent-workspaces/${id}/status`, {
      body: { status, expected_version: expectedVersion },
    }),
    putRecord: (
      id: string,
      body: { namespace: string; key: string; value: Record<string, unknown>; expected_version?: number },
    ) => request<WorkspaceRecordOut>("PUT", `/agent-workspaces/${id}/records`, { body }),
    uploadArtifact: (
      id: string,
      input: { file: File; kind: WorkspaceArtifactOut["kind"]; taskId?: string; isEvidence: boolean },
    ) => {
      const form = new FormData();
      form.append("file", input.file);
      form.append("kind", input.kind);
      form.append("is_evidence", String(input.isEvidence));
      if (input.taskId) form.append("task_id", input.taskId);
      return request<WorkspaceArtifactOut>("POST", `/agent-workspaces/${id}/artifacts/upload`, { body: form });
    },
    evidenceExport: (id: string) =>
      request<WorkspaceEvidenceManifest>("GET", `/agent-workspaces/${id}/evidence-export`),
  },

  approvals: {
    get: (id: string) => request<ApprovalOut>("GET", `/approvals/${id}`),
    resolve: (id: string, body: ApproveIn) =>
      request<ApprovalOut>("POST", `/approvals/${id}/resolve`, { body }),
  },

  findings: {
    list: (params?: ListParams<FindingFilter>) =>
      request<Page<FindingOut>>("GET", "/findings", { query: params }),
    get: (id: string) => request<FindingDetailOut>("GET", `/findings/${id}`),
    remediations: (id: string) =>
      request<RemediationOut[]>("GET", `/findings/${id}/remediations`),
    tickets: (id: string) => request<TicketLinkOut[]>("GET", `/findings/${id}/tickets`),
    analyze: (id: string, body: AnalyzeIn = {}) =>
      request<FindingDetailOut>("POST", `/findings/${id}/analyze`, { body }),
    remediate: (id: string, body: RemediateIn = {}) =>
      request<RemediationOut>("POST", `/findings/${id}/remediate`, { body }),
    validate: (id: string, body: ValidateFindingIn) =>
      request<FindingDetailOut>("POST", `/findings/${id}/validate`, { body }),
    createTicket: (id: string, body: JiraTicketIn = {}) =>
      request<TicketLinkOut>("POST", `/findings/${id}/tickets`, { body }),
    refreshTicket: (ticketId: string) =>
      request<TicketLinkOut>("POST", `/findings/tickets/${ticketId}/refresh`),
  },

  externalAlerts: {
    list: (params?: ListParams<ExternalAlertFilter>) =>
      request<Page<ExternalAlertOut>>("GET", "/external-alerts", { query: params }),
    get: (id: string) => request<ExternalAlertDetailOut>("GET", `/external-alerts/${id}`),
    triage: (id: string, body: ExternalAlertTriageIn) =>
      request<ExternalAlertDetailOut>("PATCH", `/external-alerts/${id}/triage`, { body }),
    githubAction: (id: string, body: ExternalAlertSourceActionIn) =>
      request<ExternalAlertDetailOut>("PATCH", `/external-alerts/${id}/github`, { body }),
    relatedFindings: (id: string) =>
      request<RelatedFindingOut[]>("GET", `/external-alerts/${id}/related-findings`),
    canonicalFindings: (id: string) =>
      request<CanonicalFindingOut[]>("GET", `/external-alerts/${id}/canonical-findings`),
    relatedAlerts: (id: string) =>
      request<ExternalAlertOut[]>("GET", `/external-alerts/${id}/related-alerts`),
  },

  exposures: {
    list: (params?: ListParams<ExposureFilter>) =>
      request<Page<ExposureOut>>("GET", "/exposures", { query: params }),
  },

  canonicalFindings: {
    list: (params?: { limit?: number; offset?: number; mine?: boolean; overdue?: boolean; severity?: string; status?: string; q?: string; query?: string }) =>
      request<Page<CanonicalFindingOut>>("GET", "/canonical-findings", { query: params }),
    operations: (params?: { limit?: number; offset?: number; mine?: boolean; overdue?: boolean; attention_only?: boolean; asset_group?: string; remediation_group?: string }) =>
      request<Page<CanonicalRemediationOperationOut>>("GET", "/canonical-findings/operations", { query: params }),
    remediationGroups: () =>
      request<RemediationGroupOut[]>("GET", "/canonical-findings/remediation-groups"),
    bulkUpdateWork: (body: BulkCanonicalWorkIn) =>
      request<CanonicalFindingOut[]>("PATCH", "/canonical-findings/work/bulk", { body }),
    requestRiskAcceptance: (id: string, body: RiskAcceptanceIn) =>
      request<RiskAcceptanceOut>("POST", `/canonical-findings/${id}/risk-acceptances`, { body }),
    approveRiskAcceptance: (acceptanceId: string) =>
      request<RiskAcceptanceOut>("POST", `/canonical-findings/risk-acceptances/${acceptanceId}/approve`),
    requestRetest: (id: string, body: RetestRequestIn) =>
      request<RetestRequestOut>("POST", `/canonical-findings/${id}/retests`, { body }),
    requestRemediationGroupRetests: (remediationGroup: string, body: RetestRequestIn) =>
      request<RetestRequestOut[]>("POST", `/canonical-findings/remediation-groups/${encodeURIComponent(remediationGroup)}/retests`, { body }),
    get: (id: string) =>
      request<CanonicalFindingDetailOut>("GET", `/canonical-findings/${id}`),
    decide: (id: string, body: CanonicalStatusDecisionIn) =>
      request<CanonicalFindingOut>("PATCH", `/canonical-findings/${id}/status`, { body }),
    updateWork: (id: string, body: CanonicalWorkIn) =>
      request<CanonicalFindingOut>("PATCH", `/canonical-findings/${id}/work`, { body }),
    comments: (id: string) =>
      request<FindingCollaborationCommentOut[]>("GET", `/canonical-findings/${id}/comments`),
    addComment: (id: string, body: FindingCollaborationCommentCreateIn) =>
      request<FindingCollaborationCommentOut>("POST", `/canonical-findings/${id}/comments`, { body }),
    createTicket: (id: string, body: JiraTicketIn = {}) =>
      request<TicketLinkOut>("POST", `/canonical-findings/${id}/tickets`, { body }),
  },

  compliance: {
    overview: () => request<ComplianceOverviewOut>("GET", "/compliance/overview"),
    controls: (framework?: ComplianceFramework) =>
      request<ComplianceControlOut[]>("GET", "/compliance/controls", {
        query: framework ? { framework } : undefined,
      }),
    seed: (framework: ComplianceFramework) =>
      request<ComplianceControlOut[]>("POST", `/compliance/frameworks/${framework}/seed`),
  },

  assets: {
    list: (params?: ListParams<AssetFilter>) =>
      request<Page<AssetOut>>("GET", "/assets", { query: params }),
    changes: (params?: { limit?: number; offset?: number }) =>
      request<AssetChangePageOut>("GET", "/assets/changes", { query: params }),
    get: (id: string) => request<AssetOut>("GET", `/assets/${id}`),
    importCmdb: (file: File, dryRun: boolean) => {
      const form = new FormData();
      form.append("file", file);
      form.append("dry_run", String(dryRun));
      return request<CmdbImportOut>("POST", "/assets/cmdb-import", { body: form });
    },
    addTag: (id: string, body: AssetTagIn) =>
      request<AssetOut>("POST", `/assets/${id}/tags`, { body }),
    setCriticality: (id: string, body: AssetCriticalityIn) =>
      request<AssetOut>("POST", `/assets/${id}/criticality`, { body }),
    setContext: (id: string, body: AssetContextIn) =>
      request<AssetOut>("PATCH", `/assets/${id}/context`, { body }),
    policyGate: (id: string) =>
      request<PolicyGateOut>("GET", `/assets/${id}/policy-gate`),
    markOutOfScope: (id: string) =>
      request<AssetOut>("POST", `/assets/${id}/out-of-scope`),
  },

  applications: {
    risks: (params?: { limit?: number; offset?: number }) =>
      request<ApplicationRiskPageOut>("GET", "/applications/risks", { query: params }),
    patterns: (application: string) =>
      request<ApplicationPatternsOut>(
        "GET", "/applications/patterns", { query: { application } },
      ),
  },

  jobs: {
    list: (params?: ListParams<JobFilter>) =>
      request<Page<ScannerJobOut>>("GET", "/jobs", { query: params }),
    get: (id: string) => request<ScannerJobOut>("GET", `/jobs/${id}`),
    cancel: (id: string) => request<ScannerJobOut>("POST", `/jobs/${id}/cancel`),
    downloadArtifact: (jobId: string, artifactId: string) =>
      download(`/jobs/${jobId}/artifacts/${artifactId}/download`, "artifact"),
  },

  reports: {
    list: (params?: ListParams) => request<Page<ReportOut>>("GET", "/reports", { query: params }),
    get: (id: string) => request<ReportDetailOut>("GET", `/reports/${id}`),
    download: (id: string) => download(`/reports/${id}/download`, `report-${id}`),
    schedules: () => request<ReportScheduleOut[]>("GET", "/report-schedules"),
    createSchedule: (body: ReportScheduleCreateIn) => request<ReportScheduleOut>("POST", "/report-schedules", { body }),
    pauseSchedule: (id: string) => request<ReportScheduleOut>("POST", `/report-schedules/${id}/pause`),
    resumeSchedule: (id: string) => request<ReportScheduleOut>("POST", `/report-schedules/${id}/resume`),
    createShareLink: (id: string, body: ReportShareCreateIn) => request<ReportShareIssuedOut>("POST", `/reports/${id}/share-links`, { body }),
    shareLinks: (id: string) => request<ReportShareLinkOut[]>("GET", `/reports/${id}/share-links`),
    revokeShareLink: (id: string) => request<void>("POST", `/reports/share-links/${id}/revoke`),
    templates: () => request<ReportTemplateOut[]>("GET", "/report-templates"),
    createTemplate: (body: ReportTemplateCreateIn) =>
      request<ReportTemplateOut>("POST", "/report-templates", { body }),
    portfolio: () => request<ClientOrganizationPortfolioOut[]>("GET", "/reports/portfolio"),
  },

  organization: {
    get: () => request<OrganizationOut>("GET", "/organization"),
    update: (body: OrganizationUpdateIn) =>
      request<OrganizationOut>("PATCH", "/organization", { body }),
    clients: () =>
      request<ClientOrganizationPortfolioOut[]>("GET", "/organization/clients"),
    createClient: (body: ClientOrganizationCreateIn) =>
      request<OrganizationOut>("POST", "/organization/clients", { body }),
    delegateClient: (clientOrganizationId: string, body: ClientOrganizationDelegateIn) =>
      request<MemberOut>("POST", `/organization/clients/${clientOrganizationId}/delegates`, { body }),
    members: (params?: ListParams) =>
      request<Page<MemberOut>>("GET", "/organization/members", { query: params }),
    inviteMember: (body: MemberInviteIn) =>
      request<MemberOut>("POST", "/organization/members", { body }),
    updateMemberRole: (membershipId: string, body: MemberRoleIn) =>
      request<MemberOut>("PATCH", `/organization/members/${membershipId}`, { body }),
    removeMember: (membershipId: string) =>
      request<OkOut>("DELETE", `/organization/members/${membershipId}`),
    configureOidc: (body: OidcConnectionUpsertIn) =>
      request<OidcConnectionOut>("PUT", "/organization/sso/oidc", { body }),
    oidcConnection: () => request<OidcConnectionOut | null>("GET", "/organization/sso/oidc"),
    configureSaml: (body: SamlConnectionUpsertIn) =>
      request<SamlConnectionOut>("PUT", "/organization/sso/saml", { body }),
    samlConnection: () => request<SamlConnectionOut | null>("GET", "/organization/sso/saml"),
    scimTokens: () => request<ScimProvisioningTokenOut[]>("GET", "/organization/scim/tokens"),
    createScimToken: (body: ScimProvisioningTokenCreateIn) =>
      request<ScimProvisioningTokenIssuedOut>("POST", "/organization/scim/tokens", { body }),
    revokeScimToken: (id: string) =>
      request<ScimProvisioningTokenOut>("POST", `/organization/scim/tokens/${id}/revoke`),
  },

  integrations: {
    list: () => request<IntegrationOut[]>("GET", "/integrations"),
    health: () => request<IntegrationHealthOut[]>("GET", "/integrations/health"),
    upsert: (body: IntegrationUpsertIn) =>
      request<IntegrationOut>("POST", "/integrations", { body }),
    get: (kind: IntegrationKind) => request<IntegrationOut>("GET", `/integrations/${kind}`),
    remove: (kind: IntegrationKind) =>
      request<IntegrationOut>("DELETE", `/integrations/${kind}`),
    test: (kind: IntegrationKind) =>
      request<IntegrationTestOut>("POST", `/integrations/${kind}/test`),
    sync: (kind: "github" | "gitlab" | "wazuh" | "sonarqube" | "snyk" | "tenable" | "qualys" | "rapid7" | "wiz" | "prisma_cloud" | "crowdstrike" | "aws_security_hub" | "aws_inspector" | "hackerone" | "bugcrowd" | "checkmarx" | "fortify" | "azure_defender" | "gcp_scc" | "burp_dast") =>
      request<IntegrationSyncOut>("POST", `/integrations/${kind}/sync`),
    importScanExport: (input: {
      file: File;
      formatName: "sarif" | "nuclei_jsonl" | "nessus_xml" | "burp_xml" | "qualys_host_detection_xml" | "rapid7_csv" | "aws_inspector_csv" | "azure_defender_json" | "gcp_scc_json" | "prowler_ocsf" | "hackerone_json" | "bugcrowd_json" | "trivy" | "gitleaks" | "cyclonedx" | "spdx" | "generic_csv" | "generic_json" | "wiz_json" | "prisma_cloud_json" | "sonarqube_json" | "defectdojo_json" | "checkmarx_xml" | "fortify_fvdl" | "fortify_fpr";
      provider: string;
      assetType: string;
      assetValue: string;
      fieldMapping?: Record<string, string>;
    }) => {
      const form = new FormData();
      form.append("file", input.file);
      form.append("format_name", input.formatName);
      form.append("provider", input.provider);
      form.append("asset_type", input.assetType);
      form.append("asset_value", input.assetValue);
      if (input.fieldMapping) form.append("mapping_json", JSON.stringify(input.fieldMapping));
      return request<{ findings_staged: number }>("POST", "/integrations/imports/scan", { body: form });
    },
    tenableStatus: (scanId: string) =>
      request<TenableScanStatusOut>("GET", `/integrations/tenable/scans/${encodeURIComponent(scanId)}/status`),
    launchTenable: (scanId: string) =>
      request<TenableScanLaunchOut>("POST", `/integrations/tenable/scans/${encodeURIComponent(scanId)}/launch`),
  },

  audit: {
    list: (params?: ListParams<AuditFilter>) =>
      request<Page<AuditEventOut>>("GET", "/audit", { query: params }),
    forResource: (resourceType: string, resourceId: string) =>
      request<AuditEventOut[]>("GET", `/audit/resource/${resourceType}/${resourceId}`),
    exportCsv: (params?: AuditFilter) =>
      download("/audit/export", "cynux-audit-events.csv", params),
  },

  agent: {
    memories: () => request<AgentMemoryOut[]>("GET", "/agent/memories"),
    upsertMemory: (body: AgentMemoryUpsertIn) => request<AgentMemoryOut>("PUT", "/agent/memories", { body }),
    disableMemory: (id: string) => request<AgentMemoryOut>("POST", `/agent/memories/${id}/disable`),
    actions: (sessionId: string) =>
      request<AgentActionOut[]>("GET", "/agent/actions", { query: { session_id: sessionId } }),
    proposeAction: (body: AgentActionProposeIn) =>
      request<AgentActionOut>("POST", "/agent/actions", { body }),
    resolveAction: (id: string, approve: boolean, note?: string) =>
      request<AgentActionOut>("POST", `/agent/actions/${id}/resolve`, { body: { approve, note } }),
    executeAction: (id: string) =>
      request<AgentActionOut>("POST", `/agent/actions/${id}/execute`),
    sessions: (params?: ListParams<{ include_archived?: boolean }>) =>
      request<Page<AgentSessionOut>>("GET", "/agent/sessions", { query: params }),
    session: (id: string) =>
      request<AgentSessionDetailOut>("GET", `/agent/sessions/${id}`),
    setAutonomy: (id: string, body: AgentSessionAutonomyIn) =>
      request<AgentSessionOut>("PUT", `/agent/sessions/${id}/autonomy`, { body }),
    events: (id: string, afterSeq = 0) =>
      request<AgentEvent[]>("GET", `/agent/sessions/${id}/events`, {
        query: { after_seq: afterSeq },
      }),
    run: (id: string) => request<AgentRunOut>("GET", `/agent/runs/${id}`),
    createRun: (body: AgentRunCreateIn) =>
      request<AgentRunOut>("POST", "/agent/runs", { body }),
    runEvents: (id: string, afterSeq = 0) =>
      request<AgentEvent[]>("GET", `/agent/runs/${id}/events`, {
        query: { after_seq: afterSeq },
      }),
    cancelRun: (id: string) =>
      request<AgentRunOut>("POST", `/agent/runs/${id}/cancel`),
    retryRunTask: (runId: string, taskId: string) =>
      request<AgentRunOut>("POST", `/agent/runs/${runId}/tasks/${taskId}/retry`),
    approveRunTask: (runId: string, taskId: string, note?: string) =>
      request<AgentRunOut>("POST", `/agent/runs/${runId}/tasks/${taskId}/approve`, {
        body: { note },
      }),
    sendMessage: (body: AgentMessageIn) =>
      request<AgentMessageOut>("POST", "/agent/messages", { body }),
  },

  health: {
    healthz: () => request<OkOut>("GET", "/healthz", { root: true, auth: false }),
    health: () => request<HealthOut>("GET", "/health", { root: true, auth: false }),
    readyz: () => request<HealthOut>("GET", "/readyz", { root: true, auth: false }),
  },

  asm: {
    list: () => request<AsmSurfaceOut[]>("GET", "/asm/surfaces"),
    create: (body: AsmSurfaceCreateIn) =>
      request<AsmSurfaceOut>("POST", "/asm/surfaces", { body }),
    get: (id: string) => request<AsmSurfaceOut>("GET", `/asm/surfaces/${id}`),
    update: (id: string, body: AsmSurfaceUpdateIn) =>
      request<AsmSurfaceOut>("PATCH", `/asm/surfaces/${id}`, { body }),
    delete: (id: string) => request<void>("DELETE", `/asm/surfaces/${id}`),
  },

  automation: {
    catalog: () => request<AutomationCatalogOut>("GET", "/automation/catalog"),
    listRules: (params?: { limit?: number; offset?: number }) =>
      request<Page<AutomationRuleOut>>("GET", "/automation/rules", { query: params }),
    createRule: (body: AutomationRuleCreateIn) =>
      request<AutomationRuleOut>("POST", "/automation/rules", { body }),
    getRule: (id: string) => request<AutomationRuleOut>("GET", `/automation/rules/${id}`),
    updateRule: (id: string, body: Partial<AutomationRuleCreateIn>) =>
      request<AutomationRuleOut>("PATCH", `/automation/rules/${id}`, { body }),
    deleteRule: (id: string) => request<void>("DELETE", `/automation/rules/${id}`),
    executions: (ruleId: string, params?: { limit?: number; offset?: number }) =>
      request<Page<AutomationExecutionOut>>("GET", `/automation/rules/${ruleId}/executions`, { query: params }),
    run: (ruleId: string, body: { idempotency_key: string; context?: Record<string, unknown> }) =>
      request<AutomationExecutionOut>("POST", `/automation/rules/${ruleId}/run`, { body }),
    rotateInboundSecret: (ruleId: string) =>
      request<{ rule_id: string; secret: string; rotated_at: string }>("POST", `/automation/rules/${ruleId}/inbound-secret/rotate`),
  },

  workflows: {
    list: (params?: { limit?: number; offset?: number }) =>
      request<Page<WorkflowDefinitionOut>>("GET", "/workflows", { query: params }),
    create: (body: WorkflowDefinitionIn) =>
      request<WorkflowDefinitionOut>("POST", "/workflows", { body }),
    update: (id: string, body: WorkflowDefinitionIn) =>
      request<WorkflowDefinitionOut>("PUT", `/workflows/${id}`, { body }),
    delete: (id: string) => request<void>("DELETE", `/workflows/${id}`),
    runs: (id: string, params?: { limit?: number; offset?: number }) =>
      request<Page<WorkflowRunOut>>("GET", `/workflows/${id}/runs`, { query: params }),
    start: (id: string, body: { event_key: string; context: Record<string, unknown>; dry_run?: boolean }) =>
      request<WorkflowRunOut>("POST", `/workflows/${id}/runs`, { body }),
    resume: (runId: string) => request<WorkflowRunOut>("POST", `/workflows/runs/${runId}/resume`),
  },

  scanAuth: {
    list: () => request<ScanAuthProfileOut[]>("GET", "/scan-auth"),
    create: (body: ScanAuthProfileIn) => request<ScanAuthProfileOut>("POST", "/scan-auth", { body }),
    delete: (id: string) => request<void>("DELETE", `/scan-auth/${id}`),
  },

  attackSimulations: {
    list: (params?: { limit?: number; offset?: number }) =>
      request<Page<AttackSimulationCampaignOut>>("GET", "/attack-simulations", { query: params }),
    create: (body: AttackSimulationCampaignCreateIn) =>
      request<AttackSimulationCampaignOut>("POST", "/attack-simulations", {
        body: {
          name: body.name,
          scenarios: body.scenarios,
          targets: body.targets,
          cron_expression: body.cron_expression || null,
          timezone: body.timezone || "UTC",
          authorization_expires_at: body.authorization_expires_at,
          authorization: {
            confirmed: true,
            attestation_text: body.authorization_text,
            evidence_reference: body.authorization_reference,
          },
        },
      }),
    get: (id: string) =>
      request<AttackSimulationCampaignOut>("GET", `/attack-simulations/${id}`),
    update: (id: string, body: Partial<AttackSimulationCampaignCreateIn>) =>
      request<AttackSimulationCampaignOut>("PATCH", `/attack-simulations/${id}`, { body }),
    delete: (id: string) => request<void>("DELETE", `/attack-simulations/${id}`),
    run: (id: string) =>
      request<AttackSimulationCampaignOut>("POST", `/attack-simulations/${id}/run`),
    catalog: () =>
      request<AttackSimulationTechniqueCatalogOut[]>("GET", "/attack-simulations/catalog"),
    runs: (id: string) =>
      request<AttackSimulationRunOut[]>("GET", `/attack-simulations/${id}/runs`),
    runDetail: (id: string) =>
      request<AttackSimulationRunDetailOut>("GET", `/attack-simulations/runs/${id}`),
  },

  platform: {
    listApiKeys: () => request<PlatformApiKeyOut[]>("GET", "/platform/api-keys"),
    createApiKey: (body: PlatformApiKeyCreateIn) =>
      request<PlatformApiKeyCreatedOut>("POST", "/platform/api-keys", { body }),
    revokeApiKey: (id: string) =>
      request<PlatformApiKeyOut>("POST", `/platform/api-keys/${id}/revoke`),
    listSavedViews: (resource?: string) =>
      request<SavedViewOut[]>("GET", "/saved-views", { query: resource ? { resource } : undefined }),
    createSavedView: (body: SavedViewCreateIn) =>
      request<SavedViewOut>("POST", "/saved-views", { body }),
    updateSavedView: (id: string, body: SavedViewUpdateIn) =>
      request<SavedViewOut>("PUT", `/saved-views/${id}`, { body }),
    deleteSavedView: (id: string) => request<void>("DELETE", `/saved-views/${id}`),
    listWebhooks: () => request<WebhookSubscriptionOut[]>("GET", "/webhooks"),
    listWebhookDeliveries: (id: string) =>
      request<WebhookDeliveryOut[]>("GET", `/webhooks/${id}/deliveries`),
    retryWebhookDelivery: (subscriptionId: string, deliveryId: string) =>
      request<WebhookDeliveryOut>(
        "POST",
        `/webhooks/${subscriptionId}/deliveries/${deliveryId}/retry`,
      ),
    createWebhook: (body: WebhookSubscriptionCreateIn) =>
      request<WebhookSubscriptionIssuedOut>("POST", "/webhooks", { body }),
    disableWebhook: (id: string) => request<WebhookSubscriptionOut>("POST", `/webhooks/${id}/disable`),
    rotateWebhookSecret: (id: string) =>
      request<WebhookSubscriptionIssuedOut>("POST", `/webhooks/${id}/rotate-secret`),
  },

  threatIntelligence: {
    list: (params?: { q?: string; limit?: number; offset?: number }) =>
      request<Page<VulnerabilityIntelligenceOut>>("GET", "/threat-intelligence", { query: params }),
    get: (cveId: string) =>
      request<VulnerabilityIntelligenceOut>("GET", `/threat-intelligence/${encodeURIComponent(cveId)}`),
    watchlists: () => request<ThreatWatchlistOut[]>("GET", "/threat-intelligence/watchlists"),
    createWatchlist: (body: ThreatWatchlistCreateIn) =>
      request<ThreatWatchlistOut>("POST", "/threat-intelligence/watchlists", { body }),
    deleteWatchlist: (id: string) =>
      request<void>("DELETE", `/threat-intelligence/watchlists/${id}`),
    watchlistMatches: (id: string) =>
      request<ThreatWatchlistMatchOut[]>("GET", `/threat-intelligence/watchlists/${id}/matches`),
  },

  notifications: {
    listDeliveries: (status?: "pending" | "sent" | "failed") =>
      request<ExternalDeliveryOut[]>("GET", "/notifications/deliveries", {
        query: status ? { status } : undefined,
      }),
    retryDelivery: (id: string) =>
      request<ExternalDeliveryOut>("POST", `/notifications/deliveries/${id}/retry`),
  },
};

// ---------------------------------------------------------------------------
// WebSocket URL builder (root, unversioned). The JWT is sent as the first frame, NOT here.
// ---------------------------------------------------------------------------

export function agentSocketUrl(sessionId: string, afterSeq?: number): string {
  const suffix =
    afterSeq !== undefined && afterSeq > 0 ? `?after_seq=${afterSeq}` : "";
  return `${websocketOrigin()}/ws/agent/${sessionId}${suffix}`;
}
