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
import type {
  AgentEvent,
  AgentMessageIn,
  AgentMessageOut,
  AgentRunOut,
  AgentSessionDetailOut,
  AgentSessionOut,
  AnalyzeIn,
  ApprovalOut,
  ApproveIn,
  AssessmentCreateIn,
  AssessmentDetailOut,
  AssessmentFilter,
  AssessmentOut,
  AssetCriticalityIn,
  AssetFilter,
  AssetOut,
  AssetTagIn,
  AuditEventOut,
  AuditFilter,
  CancelIn,
  ChangePasswordIn,
  DashboardOut,
  FindingDetailOut,
  FindingFilter,
  FindingOut,
  HealthOut,
  IntegrationHealthOut,
  IntegrationKind,
  IntegrationOut,
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
  Page,
  PasswordResetConfirmIn,
  PasswordResetRequestIn,
  Problem,
  RegisterIn,
  RemediateIn,
  RemediationOut,
  ReportDetailOut,
  ReportGenerateIn,
  ReportOut,
  ScannerJobOut,
  SwitchOrganizationIn,
  TicketLinkOut,
  TokenPairOut,
} from "./types";

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

const stripTrailingSlash = (value: string): string => value.replace(/\/+$/, "");

const API_BASE = stripTrailingSlash(
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "https://cynux-api.onrender.com",
);
const WS_BASE = stripTrailingSlash(
  process.env.NEXT_PUBLIC_WS_BASE_URL ?? "wss://cynux-api.onrender.com",
);

const API_PREFIX = "/api/v1";

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
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.auth !== false) {
    const token = getAccessToken();
    if (token) headers.authorization = `Bearer ${token}`;
  }

  try {
    return await fetch(url, {
      method,
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
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
async function download(path: string, fallbackName: string): Promise<DownloadedFile> {
  const doFetch = () => {
    const headers: Record<string, string> = {};
    const token = getAccessToken();
    if (token) headers.authorization = `Bearer ${token}`;
    return fetch(`${API_BASE}${API_PREFIX}${path}`, { headers });
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
  auth: {
    register: (body: RegisterIn) =>
      request<TokenPairOut>("POST", "/auth/register", { body, auth: false }),
    login: (body: LoginIn) =>
      request<TokenPairOut>("POST", "/auth/login", { body, auth: false }),
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
  },

  assessments: {
    list: (params?: ListParams<AssessmentFilter>) =>
      request<Page<AssessmentOut>>("GET", "/assessments", { query: params }),
    create: (body: AssessmentCreateIn) =>
      request<AssessmentDetailOut>("POST", "/assessments", { body }),
    get: (id: string) => request<AssessmentDetailOut>("GET", `/assessments/${id}`),
    cancel: (id: string, body: CancelIn = {}) =>
      request<AssessmentDetailOut>("POST", `/assessments/${id}/cancel`, { body }),
    reports: (id: string) => request<ReportOut[]>("GET", `/assessments/${id}/reports`),
    generateReport: (id: string, body: ReportGenerateIn = {}) =>
      request<ReportDetailOut>("POST", `/assessments/${id}/reports`, { body }),
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
    createTicket: (id: string, body: JiraTicketIn = {}) =>
      request<TicketLinkOut>("POST", `/findings/${id}/tickets`, { body }),
  },

  assets: {
    list: (params?: ListParams<AssetFilter>) =>
      request<Page<AssetOut>>("GET", "/assets", { query: params }),
    get: (id: string) => request<AssetOut>("GET", `/assets/${id}`),
    addTag: (id: string, body: AssetTagIn) =>
      request<AssetOut>("POST", `/assets/${id}/tags`, { body }),
    setCriticality: (id: string, body: AssetCriticalityIn) =>
      request<AssetOut>("POST", `/assets/${id}/criticality`, { body }),
    markOutOfScope: (id: string) =>
      request<AssetOut>("POST", `/assets/${id}/out-of-scope`),
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
    get: (id: string) => request<ReportDetailOut>("GET", `/reports/${id}`),
    download: (id: string) => download(`/reports/${id}/download`, `report-${id}`),
  },

  organization: {
    get: () => request<OrganizationOut>("GET", "/organization"),
    update: (body: OrganizationUpdateIn) =>
      request<OrganizationOut>("PATCH", "/organization", { body }),
    members: (params?: ListParams) =>
      request<Page<MemberOut>>("GET", "/organization/members", { query: params }),
    inviteMember: (body: MemberInviteIn) =>
      request<MemberOut>("POST", "/organization/members", { body }),
    updateMemberRole: (membershipId: string, body: MemberRoleIn) =>
      request<MemberOut>("PATCH", `/organization/members/${membershipId}`, { body }),
    removeMember: (membershipId: string) =>
      request<OkOut>("DELETE", `/organization/members/${membershipId}`),
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
  },

  audit: {
    list: (params?: ListParams<AuditFilter>) =>
      request<Page<AuditEventOut>>("GET", "/audit", { query: params }),
    forResource: (resourceType: string, resourceId: string) =>
      request<AuditEventOut[]>("GET", `/audit/resource/${resourceType}/${resourceId}`),
  },

  agent: {
    sessions: (params?: ListParams<{ include_archived?: boolean }>) =>
      request<Page<AgentSessionOut>>("GET", "/agent/sessions", { query: params }),
    session: (id: string) =>
      request<AgentSessionDetailOut>("GET", `/agent/sessions/${id}`),
    events: (id: string, afterSeq = 0) =>
      request<AgentEvent[]>("GET", `/agent/sessions/${id}/events`, {
        query: { after_seq: afterSeq },
      }),
    run: (id: string) => request<AgentRunOut>("GET", `/agent/runs/${id}`),
    sendMessage: (body: AgentMessageIn) =>
      request<AgentMessageOut>("POST", "/agent/messages", { body }),
  },

  health: {
    healthz: () => request<OkOut>("GET", "/healthz", { root: true, auth: false }),
    health: () => request<HealthOut>("GET", "/health", { root: true, auth: false }),
    readyz: () => request<HealthOut>("GET", "/readyz", { root: true, auth: false }),
  },
};

// ---------------------------------------------------------------------------
// WebSocket URL builder (root, unversioned). The JWT is sent as the first frame, NOT here.
// ---------------------------------------------------------------------------

export function agentSocketUrl(sessionId: string, afterSeq?: number): string {
  const suffix =
    afterSeq !== undefined && afterSeq > 0 ? `?after_seq=${afterSeq}` : "";
  return `${WS_BASE}/ws/agent/${sessionId}${suffix}`;
}
