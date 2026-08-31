# Cynux — Internal Interface Contract

This file is **normative**. Every module in the build is written against it so that
work done independently composes without rework. If you are implementing a slice,
read the sections for *your* files and for anything you import.

Two rules override everything else in here:

1. **Do not edit files you do not own.** Ownership is listed in §2. If you need a
   change in someone else's file, note it in your summary instead of making it.
2. **`python tools/verify.py` must pass** before you report done. It is an offline AST
   gate: it resolves every `from app.… import …` against real modules and symbols,
   checks every `__all__` entry exists, and rejects `subprocess`/`eval`/`exec`/
   `shell=True` and secret-revealing calls inside log statements.

---

## 1. Conventions (mandatory — the existing code already follows these)

**Module docstring.** Every module opens with a docstring that names the requirement
it implements and explains *why the design is the way it is*, not what the code does.
Look at `app/db/repository.py` or `app/core/targets.py` for the register to match.

```python
"""Scanner sandbox construction (FR-014).

Every constraint here exists because a scanner runs attacker-influenced input …
"""
```

**Imports.** `from __future__ import annotations` first, always. Import from leaf
modules (`from app.core.errors import ScannerError`), never from a package
`__init__`. Package `__init__.py` files stay docstring-only — the one exception is
the pre-existing `app/db/models/__init__.py`, which must keep re-exporting because
Alembic relies on it to register mappers.

**`__all__`.** Every module ends with a sorted `__all__`. `verify.py` checks each
entry resolves.

**Typing.** `from __future__ import annotations` + PEP 604 (`str | None`). Public
functions are fully annotated. `mypy` runs with `check_untyped_defs=true` and
`disallow_untyped_defs=false`.

**Errors.** Never raise bare `Exception`/`ValueError` across a module boundary. Use
`app/core/errors.py`. Pick the class whose `category`, `retryable` and `degradable`
flags already say what you mean — that metadata is what FR-040 routes on. Add a new
subclass only if nothing fits, and give it a `default_user_message` that is safe to
show a user (SEC-002: no hostnames of internal services, no credentials, no stack
detail).

**Logging.** `log = structlog.get_logger(__name__)` at module top. Structured kwargs,
never f-strings: `log.info("scanner.started", job_id=str(job.id), scanner=name)`.
Never pass a secret, and never call `.reveal()` or `.get_secret_value()` inside a log
call — `verify.py` fails the build on that.

**Async.** Everything I/O-bound is `async`. Blocking libraries (`docker`, `boto3`,
`weasyprint`, `psycopg` sync) are wrapped in `await asyncio.to_thread(...)`.

**SQLAlchemy.** Relationships use `lazy="raise_on_sql"` (module constant
`LAZY = "raise_on_sql"`). That means **you must eager-load explicitly** —
`selectinload`/`joinedload` passed as options — or you get a loud error instead of a
silent N+1. Do not change it to `"selectin"` to make an error go away.

**Tenancy.** Any query touching a `TenantMixin` table goes through
`tenant_select(Model, organization_id)` or a `TenantRepository`. Never write a bare
`select(Asset)`. Cross-tenant misses raise `TenantIsolationError`, which renders 404.

**Naming.** `snake_case` modules/functions, `PascalCase` classes, verbs for services
(`create_assessment`, not `assessment_create`).

**Comments.** Sparse and load-bearing. Explain the non-obvious constraint, not the
syntax. Match the density of `app/db/models/asset.py`.

---

## 2. File ownership

Each row is owned by exactly one implementer. Nothing outside your row is yours.

| Slice | Files |
|---|---|
| **schemas** | `app/schemas/*.py` |
| **llm** | `app/llm/*.py` |
| **integrations** | `app/integrations/*.py` |
| **scanners** | `app/scanners/*.py` |
| **services** | `app/services/*.py` |
| **agent** | `app/agent/*.py`, `app/agent/nodes/*.py`, `app/agent/tools/*.py` |
| **api** | `app/api/*.py`, `app/api/v1/*.py`, `app/api/ws/*.py` |
| **worker** | `app/worker/*.py` |
| **reporting** | `app/reporting/*.py`, `app/reporting/templates/*` |
| **migration** | `alembic/versions/*.py` |
| **tests** | `tests/**` |
| **infra** | `docker/**`, `docker-compose.yml`, `.env.example`, `Makefile`, `README.md` |
| **frontend** | `frontend/**` |
| **docs** | `docs/*.md`, `docs/adr/*.md` (except this file) |

Already written and **frozen** — read them, import them, do not modify:
`app/core/{config,errors,targets,security,crypto,redis_client,logging_conf,telemetry}.py`,
`app/db/{base,enums,session,repository}.py`, `app/db/models/*.py`, `tools/verify.py`,
`pyproject.toml`, `alembic/env.py`, `alembic.ini`.

---

## 3. What already exists

Full signatures are in the source; this is the index so you know what not to rebuild.

**`app/core/config.py`** — `get_settings() -> Settings`. Groups are reached as
`settings.db`, `.redis`, `.security`, `.scanner`, `.targets`, `.llm`, `.langsmith`,
`.defectdojo`, `.intel`, `.dify`, `.storage`, `.jira`, `.notify`, `.otel`, `.agent`.
Note `settings.db` — **not** `settings.database`. Also
`validate_runtime_configuration(settings, *, role="api"|"worker") -> list[str]` (raises
`ConfigurationError`, returns warnings) and `REQUIRED_LLM_ROLES`.

**`app/core/errors.py`** — `CynuxError` with `.category`, `.http_status`, `.retryable`,
`.degradable`, `.code`, `.to_problem()` (RFC 9457), `.to_log_fields()`. Subclasses cover
user / authz / scanner / integration / AI / config failures. Notable: `TenantIsolationError`
is 404 by design; `ApprovalRequiredError` is 428; `UnverifiableClaimError`'s user message
is exactly the FR-024 sentence.

**`app/core/targets.py`** — `validate_target(raw, settings.targets) -> ValidatedTarget`.
This is the **only** sanctioned way to turn user text into something a scanner may
receive. Also `expand_cidr(target, limit)`, `is_public_hostname(host)` (re-check
recon-discovered hosts — DNS rebinding), `classify(raw)`.

**`app/core/security.py`** — `hash_password`, `verify_password`, `needs_rehash`,
`validate_password_strength`, `create_token(settings, *, subject, token_type, …) ->
(str, TokenClaims)`, `decode_token(settings, token, *, expect)`, `generate_api_key()`.

**`app/core/crypto.py`** — `get_cipher(settings) -> CredentialCipher` with
`.encrypt/.decrypt/.rotate`, and `Secret` (repr-safe wrapper; `.reveal()`).

**`app/core/redis_client.py`** — `get_redis(settings)`, `TokenDenyList`,
`FixedWindowLimiter.hit(key) -> (allowed, remaining, reset)`,
`TokenBucket.acquire(cost) -> (allowed, wait_seconds)`, `ResponseCache.get/set/invalidate`.

**`app/core/telemetry.py`** — `setup_telemetry`, `instrument_app`, `configure_langsmith`,
`get_tracer(name)` (returns a no-op tracer when OTel is off, so `with
tracer.start_as_current_span(...)` is always safe).

**`app/db/enums.py`** — the whole domain vocabulary. `Role`, `Permission`,
`PERMISSIONS: dict[Role, frozenset[Permission]]`, `role_has()`, `AssessmentStatus` +
`ALLOWED_TRANSITIONS`, `AssessmentStage` + `STAGE_ORDER`, `Severity.parse()`,
`Criticality.weight`, `Priority`, `RiskLevel`, `JobStatus`, `EnrichmentStatus`,
`ApprovalDecision`, `NotificationEvent`, and more. **Use these; never re-declare a
string literal that already has an enum member.**

**`app/db/repository.py`** — `tenant_select`, `assert_tenant_owned`, `TenantRepository`.

**`app/db/models/`** — 24 models. Read the docstrings: several carry design
constraints you must honour (e.g. `Approval.approved_payload` is what drives the
scanner layer, not `requested_payload`; `FindingEnrichment.in_kev` is tri-state).

---

## 4. `app/schemas/` — wire format

Pydantic v2. `model_config = ConfigDict(from_attributes=True)` on every `*Out`.
`extra="forbid"` on every `*In`/`*Request` so a typo'd field is a 422 rather than a
silently ignored instruction. UUIDs serialize as strings, datetimes as ISO-8601 UTC.

Files and the types each must export:

- **`common.py`** — `Problem` (RFC 9457: `type`, `title`, `status`, `detail`,
  `code`, `category`, `retryable`, `instance`, `errors`), `PageMeta` (`total`,
  `limit`, `offset`, `has_more`), `Page[T]` (generic, `items: list[T]`, `meta`),
  `PaginationParams` (`limit` 1–200 default 50, `offset` ≥0), `HealthOut`,
  `OkOut` (`{"ok": true}`).
- **`auth.py`** — `RegisterIn` (email, password, full_name, organization_name),
  `LoginIn`, `TokenPairOut` (`access_token`, `refresh_token`, `token_type="bearer"`,
  `expires_in`), `RefreshIn`, `UserOut`, `MeOut` (user + `organizations:
  list[MembershipOut]` + `active_organization_id` + `permissions: list[str]`),
  `PasswordResetRequestIn`, `PasswordResetConfirmIn`, `ChangePasswordIn`.
- **`organization.py`** — `OrganizationOut`, `OrganizationCreateIn`,
  `OrganizationUpdateIn`, `MembershipOut` (`organization_id`, `organization_name`,
  `role`, `joined_at`), `MemberOut` (user + role), `MemberInviteIn`, `MemberRoleIn`.
- **`assessment.py`** — the important ones:
  - `AssessmentCreateIn`: `targets: list[str]` (1–50), `title: str | None`,
    `scope: Scope = external`, `depth: AssessmentDepth = standard`,
    `objective: str | None` (free text, FR-004), `authorization: AuthorizationIn`,
    `notify: list[str] = []`.
  - `AuthorizationIn`: `confirmed: bool`, `attestation_text: str`,
    `evidence_reference: str | None`. `confirmed=False` ⇒ 403
    `UnauthorizedTargetError`; there is no implicit authorization anywhere.
  - `AssessmentOut` (list row): `id`, `reference`, `title`, `status`,
    `current_stage`, `progress_percent`, `scope`, `depth`, `findings_total` and the
    five severity counters, `assets_discovered`, `assets_in_scope`, `created_at`,
    `started_at`, `completed_at`, `duration_seconds`, `targets: list[TargetOut]`.
  - `AssessmentDetailOut`: `AssessmentOut` + `plan: list[PlanStepOut]`,
    `request_interpretation: dict`, `stages: list[StageOut]`, `degradations:
    list[DegradationOut]`, `pending_approval: ApprovalOut | None`,
    `failure_reason`, `failure_category`, `agent_session_id`,
    `defectdojo_engagement_id`.
  - `StageOut`: `stage`, `label`, `status` (`StepStatus`), `started_at`,
    `completed_at`, `detail: str | None`. Ordered by `STAGE_ORDER` — this is the
    FR-038 checklist the UI renders.
  - `DegradationOut`: `stage`, `component`, `reason`, `impact`, `occurred_at`.
  - `ApprovalOut`: `id`, `kind`, `decision`, `prompt`, `rationale`, `risk_level`,
    `requested_payload`, `approved_payload`, `expires_at`, `resolved_at`,
    `resolved_by`, and `proposed_assets: list[ProposedAssetOut]` projected from
    `requested_payload` so the UI does not parse raw JSON.
  - `ApproveIn`: `decision: Literal["approved","approved_all","customized","rejected"]`,
    `asset_ids: list[UUID] | None` (required when `customized`),
    `scanners: list[ScannerName] | None`, `note: str | None`.
  - `CancelIn`: `reason: str | None`.
- **`asset.py`** — `AssetOut` (incl. `criticality`, `criticality_source`,
  `criticality_rationale`, `risk_score`, `selected_for_scanning`,
  `selection_rationale`, `internet_exposed`, `technology`, `evidence`,
  `tags: list[AssetTagOut]`), `AssetTagOut`, `AssetTagIn` (`key`, `value`),
  `AssetCriticalityIn` (`criticality: Criticality`, `rationale: str | None`),
  `AssetFilter` (`criticality`, `selected`, `internet_exposed`, `q`).
- **`finding.py`** — `FindingOut`, `FindingDetailOut` (+ `enrichment`,
  `remediations`, `tickets`, `asset`), `EnrichmentOut` (per-provider status +
  `in_kev: bool | None` — serialize the null, never coerce to false),
  `RemediationOut`, `TicketLinkOut`, `FindingFilter` (`severity`, `priority`,
  `status`, `scanner`, `assessment_id`, `asset_id`, `in_kev`, `q`),
  `AnalyzeIn` (`force: bool = False`), `RemediateIn` (`approach: str | None`,
  `force: bool = False`), `JiraTicketIn` (`project_key: str | None`,
  `issue_type: str | None`, `assignee: str | None`).
- **`agent.py`** — `AgentMessageIn` (`session_id: UUID | None`, `content: str`
  1–8000, `assessment_id: UUID | None`), `AgentMessageOut`, `AgentSessionOut`,
  `AgentSessionDetailOut` (+ `messages`, `runs`), `AgentRunOut`, `AgentStepOut`,
  and the WebSocket envelope + 7 payloads — see §8.
- **`job.py`** — `ScannerJobOut` (`scanner`, `status`, `targets`, `image`,
  `started_at`, `finished_at`, `exit_code`, `duration_seconds`,
  `imported_finding_count`, `sandbox`, `artifacts: list[ArtifactOut]`,
  `error_message`), `ArtifactOut` (`kind`, `filename`, `size_bytes`, `sha256`,
  `download_url: str | None`).
- **`report.py`** — `ReportOut` (`id`, `format`, `audience`, `status`, `sha256`,
  `generated_at`, `download_url`), `ReportGenerateIn` (`format: ReportFormat`,
  `audience: Literal["executive","technical"]`).
- **`dashboard.py`** — `DashboardOut`: `assessments_total`,
  `assessments_active`, `assessments_awaiting_approval`, `findings_open`,
  `severity_breakdown: dict[str,int]`, `priority_breakdown: dict[str,int]`,
  `assets_total`, `assets_critical`, `kev_findings`, `mean_time_to_remediate_days:
  float | None`, `recent_assessments: list[AssessmentOut]`,
  `top_findings: list[FindingOut]`, `activity: list[ActivityOut]`,
  `integration_health: list[IntegrationHealthOut]`.
- **`integration.py`** — `IntegrationOut` (never includes a credential; exposes
  `fingerprint` and `hint` only), `IntegrationUpsertIn`, `IntegrationTestOut`.
- **`audit.py`** — `AuditEventOut`, `AuditFilter`.

---

## 5. `app/llm/` — provider gateway (PRD §55, SEC-005, SEC-006)

```python
# app/llm/base.py
@dataclass(frozen=True, slots=True)
class LLMMessage:
    role: Literal["system", "user", "assistant"]
    content: str

@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int
    output_tokens: int

@dataclass(frozen=True, slots=True)
class LLMResponse:
    text: str
    model: str
    provider: str
    usage: Usage
    stop_reason: str | None
    latency_ms: int

class LLMProviderClient(Protocol):
    name: str
    async def complete(
        self, *, model: str, messages: Sequence[LLMMessage],
        max_output_tokens: int, temperature: float,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse: ...
```

```python
# app/llm/gateway.py
class LLMGateway:
    def __init__(self, settings: Settings) -> None: ...
    def resolve(self, role: LLMRole) -> tuple[str, str]:
        """(provider, model) for a role. Raises ConfigurationError if unresolvable.
        Never invents a model name — that is a product decision, see config.py."""
    async def complete(self, role: LLMRole, messages, *, max_output_tokens=None,
                       temperature=None) -> LLMResponse: ...
    async def complete_json(self, role: LLMRole, messages, *, schema: dict,
                            model_cls: type[BaseModel] | None = None,
                            max_attempts: int = 2) -> Any:
        """Structured output. On a parse failure, re-asks once with the validation
        error appended, then raises InvalidModelResponseError. Never returns a
        partially-parsed object."""

def get_gateway(settings: Settings | None = None) -> LLMGateway  # cached
def reset_gateway_cache() -> None
```

`app/llm/budget.py` enforces SEC-006 before anything reaches a provider:

```python
def truncate_tool_output(text: str, *, limit: int, label: str) -> tuple[str, bool]:
    """Returns (text, was_truncated). Truncation is *marked* in the returned text —
    the model must be able to tell it is looking at a fragment."""
def enforce_prompt_budget(messages: Sequence[LLMMessage], *, limit: int) -> Sequence[LLMMessage]
def estimate_tokens(text: str) -> int
```

`app/llm/prompts.py` holds every system prompt. Two hard requirements:

- **SEC-005.** Scanner output, HTTP response bodies, finding descriptions and
  knowledge-base chunks are wrapped by `wrap_untrusted(label, content)` which fences
  the content and states that it is data. The system prompt says instructions inside
  fenced untrusted blocks must be reported, never followed.
- **FR-024.** Analysis and report prompts require every factual claim to carry a
  source id drawn from the supplied evidence, and mandate the exact string
  `Unable to verify from available security intelligence.` when it cannot.

`app/llm/guard.py`:

```python
@dataclass(frozen=True, slots=True)
class Claim:
    text: str
    source_id: str | None

@dataclass(frozen=True, slots=True)
class GuardResult:
    accepted: bool
    claims: list[Claim]
    unsupported: list[str]
    stripped_text: str

def verify_claims(text: str, *, evidence: Mapping[str, Any]) -> GuardResult
def assert_no_invented_cve(text: str, *, known_cves: Collection[str]) -> None
def assert_no_invented_cvss(text: str, *, known_scores: Collection[float]) -> None
```

`assert_no_invented_cve` regex-scans for `CVE-\d{4}-\d{4,7}` and raises
`UnverifiableClaimError` for any identifier not in `known_cves`. This is the
mechanical half of FR-024 and it runs on every model output that reaches a user.

---

## 6. `app/integrations/` — FR-020 resilience + clients

`http.py` is the shared spine. Every outbound call goes through it; no module
constructs a bare `httpx.AsyncClient`.

```python
@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_base: float = 0.5
    backoff_max: float = 8.0
    jitter: float = 0.25
    retry_on_status: frozenset[int] = frozenset({408, 425, 429, 500, 502, 503, 504})

class ResilientClient:
    def __init__(self, *, provider: str, base_url: str, settings: Settings,
                 headers: Mapping[str, str] | None = None,
                 timeout: float = 30.0, verify: bool = True,
                 retry: RetryPolicy | None = None,
                 rate_limiter: TokenBucket | None = None,
                 breaker: CircuitBreaker | None = None,
                 cache: ResponseCache | None = None) -> None: ...
    async def request(self, method: str, path: str, *, json=None, params=None,
                      data=None, files=None, headers=None,
                      cache_ttl: int | None = None,
                      idempotency_key: str | None = None) -> httpx.Response
    async def get_json(...) -> Any
    async def post_json(...) -> Any
    async def aclose(self) -> None
    async def __aenter__ / __aexit__
```

Behaviour that is not negotiable:

- Retries only on `retry_on_status` and on transport errors, and **only for
  idempotent methods** unless an `idempotency_key` is supplied. A POST that creates a
  Jira ticket must not be silently retried into two tickets.
- `429` honours `Retry-After` and raises `IntegrationRateLimitError(retry_after=…)`
  once attempts are exhausted.
- Non-2xx maps to `IntegrationAuthError` (401/403), `IntegrationRateLimitError` (429),
  `IntegrationTimeoutError` (timeout), else `IntegrationError`, each carrying
  `provider`. Response bodies are **never** put in the user-facing message.
- The circuit breaker is Redis-backed (`circuit.py`) so it is shared across API and
  worker processes: N consecutive failures ⇒ open for a cooldown ⇒ half-open probe.
  Open raises `CircuitOpenError`.
- Read-only GETs may be cached through `ResponseCache` with an explicit `cache_ttl`.

Clients — each exposes exactly the operations Cynux needs and returns typed
dataclasses, not raw dicts:

| File | Class | Key operations |
|---|---|---|
| `defectdojo.py` | `DefectDojoClient` | `ensure_product`, `ensure_engagement`, `import_scan(engagement_id, scan_type, file, …)`, `reimport_scan`, `list_findings(test_id=…, engagement_id=…)`, `get_finding`, `update_finding`, `close_engagement`. `scan_type` strings are the exact DefectDojo parser names — `"Nmap Scan"`, `"Nuclei Scan"`, `"ZAP Scan"`. Deduplication is DefectDojo's job (FR-018); we set the engagement flag and never dedupe locally. Failures raise `DefectDojoError` (`degradable=False` — an assessment that cannot record findings has not succeeded). |
| `nvd.py` | `NVDClient` | `get_cve(cve_id) -> NVDRecord | None`. Rate limit via `TokenBucket` sized 5/30s without a key, 50/30s with one. Cached `settings.intel.nvd_cache_ttl_seconds`. |
| `kev.py` | `KEVClient` | `refresh() -> KEVCatalog`, `lookup(cve_id) -> KEVEntry | None`. Whole catalogue cached in Redis for `kev_refresh_seconds`. On failure the caller records `EnrichmentStatus.UNAVAILABLE` — never `in_kev=False`. |
| `epss.py` | `EPSSClient` | `scores(cve_ids) -> dict[str, EPSSScore]` (batched). |
| `misp.py` | `MISPClient` | `search_attribute(value) -> list[MISPHit]`. Optional integration: unconfigured ⇒ `IntegrationNotConfiguredError`, caller degrades. |
| `dify.py` | `DifyClient` | `retrieve(query, *, top_k, score_threshold) -> list[KnowledgeChunk]` (`content`, `score`, `document_name`, `document_id`). FR-021: unconfigured or failing ⇒ the caller reports "knowledge base unavailable" and the model is **not** allowed to answer from memory. |
| `jira.py` | `JiraClient` | `create_issue(...) -> JiraIssue`, `get_issue`, `add_comment`, `search`. Idempotency: callers pass a key derived from the finding id, and `TicketLink`'s unique constraint is the real guard. |
| `slack.py` | `SlackClient` | `post_message(channel, text, blocks=None)`, `post_webhook(text, blocks=None)`. |
| `email.py` | `EmailSender` | `send(to, subject, html, text=None)` over `aiosmtplib`. |
| `storage.py` | `ObjectStorage` | `put_bytes(key, data, content_type) -> StoredObject`, `put_file(key, path, …)`, `get_bytes(key)`, `presign_get(key, ttl) -> str`, `delete(key)`, `ensure_bucket()`. `boto3` wrapped in `asyncio.to_thread`. Keys are namespaced `org/{organization_id}/…` so a bug cannot cross tenants. Raises `StorageError`. |

Every client takes `settings` and exposes `configured: bool`. An unconfigured
integration raises `IntegrationNotConfiguredError` on use — it never no-ops silently,
because a silent no-op looks like success to the agent.

---

## 7. `app/scanners/` — FR-012 / FR-014

```python
# app/scanners/base.py
@dataclass(frozen=True, slots=True)
class ScannerRequest:
    scanner: ScannerName
    targets: tuple[str, ...]          # already canonical, from validate_target()
    workdir: Path                     # host dir bind-mounted at the adapter's work_mount
    timeout_seconds: int
    options: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class ScannerResult:
    scanner: ScannerName
    exit_code: int
    duration_seconds: float
    argv: tuple[str, ...]
    image: str
    container_id: str | None
    sandbox: Mapping[str, Any]        # persisted as FR-014 evidence
    artifacts: tuple[ArtifactFile, ...]
    stdout_tail: str
    stderr_tail: str
    timed_out: bool
    cancelled: bool

@dataclass(frozen=True, slots=True)
class ArtifactFile:
    kind: ArtifactKind
    filename: str
    path: Path
    size_bytes: int
    sha256: str
    defectdojo_scan_type: str | None   # set on the report artifact DefectDojo ingests

class ScannerAdapter(ABC):
    name: ScannerName
    image_setting: str                 # attribute name on ScannerSettings
    defectdojo_scan_type: str | None
    entrypoint_is_tool: bool = True    # False when the image's CMD is a shell (ZAP)

    # Per-adapter sandbox dials. Each is bounded by a check in sandbox.py rather than
    # trusted, and each is recorded in sandbox_evidence() on the job row.
    work_mount: str = WORK_MOUNT               # must be in ALLOWED_WORK_MOUNTS
    read_only_root: bool = True
    run_as_user: str | None = None             # never root; see _assert_unprivileged
    container_env: Mapping[str, str] = MappingProxyType({})   # ALLOWED_ENV_NAMES only
    success_exit_codes: frozenset[int] = frozenset({0})

    @abstractmethod
    def build_argv(self, request: ScannerRequest) -> tuple[str, ...]: ...
    @abstractmethod
    def collect(self, request: ScannerRequest) -> tuple[ArtifactFile, ...]: ...
    def validate(self, request: ScannerRequest) -> None: ...
    def prepare(self, request: ScannerRequest) -> None: ...   # stage input files
    def container_path(self, *parts: str) -> str              # joins on self.work_mount
```

Four of those fields are **deviations from v1 of this document**, added because the
upstream scanner images cannot all run under one set of maximally strict defaults. The
rule applied in each case was: never loosen the sandbox globally, add a narrow dial and
bound it with an allow-list, so a fifth scanner cannot weaken the isolation the other
four run under.

- `work_mount` — ZAP's report writer concatenates onto a hard-coded `/zap/wrk/`.
- `run_as_user` — the ZAP image pre-creates `/home/zap` owned by uid 1000.
- `container_env` — Nuclei and ReconFTW abort if they cannot resolve `$HOME`.
- `success_exit_codes` — ZAP baseline reports findings *through* its exit code.

`container_path()` lives on the adapter, not on `ScannerRequest`: the request does not
know where it will be mounted, so a request-level helper would hard-code `/work` and
silently return paths that resolve nowhere inside a ZAP container.

`sandbox.py` builds the container kwargs, and this is the security core of FR-014 /
SEC-004:

```python
def build_sandbox(settings: ScannerSettings, *, workdir: Path, image: str,
                  read_only_root: bool = True) -> dict[str, Any]
```

It must set, at minimum: `network=settings.scanner.network` (egress-only; it cannot
reach postgres/redis/minio), `read_only=True`, `tmpfs={"/tmp": f"size={tmpfs_size_mb}m"}`,
`user=settings.scanner.run_as_user`, `nano_cpus=int(cpu_quota_cores * 1e9)`,
`mem_limit=f"{memory_limit_mb}m"`, `pids_limit`, `cap_drop=["ALL"]`,
`security_opt=["no-new-privileges:true"]`, `privileged=False`,
`environment={}` (**no host env inheritance — that is how API secrets would leak**),
and a single bind of `workdir` at `/work`. The returned dict is stored verbatim on
`ScannerJob.sandbox` as evidence.

`runner.py`:

```python
class DockerRunner:
    def __init__(self, settings: Settings) -> None: ...
    async def preflight(self) -> None                       # DockerUnavailableError
    async def run(self, adapter: ScannerAdapter, request: ScannerRequest, *,
                  on_log: Callable[[str], Awaitable[None]] | None = None,
                  cancel: Callable[[], Awaitable[bool]] | None = None,
                  ) -> ScannerResult
    async def cancel(self, container_id: str) -> None
```

Non-negotiable in `run()`:

- **argv only.** `container.create(command=[...])` with a list. Never a shell string,
  never `shell=True`, never string interpolation into a command. If any argv element
  fails `_ARGV_SAFE` validation, raise `UnsafeScannerInvocationError` — that class is
  deliberately not `degradable`, so it fails the assessment instead of being retried.
- **Image allow-list.** `if image not in settings.scanner.allowed_images: raise
  UnsafeScannerInvocationError`. A model-supplied image string can therefore never
  reach the Docker API.
- **Timeout.** `min(request.timeout_seconds, settings.scanner.max_timeout_seconds)`,
  enforced by the runner (not the container), then `kill()` and
  `ScannerTimeoutError` — but still collect whatever artifacts exist.
- **Cooperative cancellation.** Poll `cancel()` while waiting; on True, kill the
  container and return `ScannerResult(cancelled=True)`.
- `finally: container.remove(force=True)` always.

Adapters:

- **`reconftw.py`** — passive only. argv is `["-d", domain, "-r", "-o", "/work/out"]`
  (or `-l` for a target list). **FR-008 hard constraint:** the module must assert that
  no active flag (`-a`, `-w`, `-n`, `-c`, `-v`, `--deep`) is ever present, and must
  never let ReconFTW fire Nmap or Nuclei internally. Put the reason in the docstring.
  `defectdojo_scan_type = None` — recon output is asset discovery, not findings.
- **`nmap.py`** — `["-sV", "-Pn", "--top-ports", "1000", "-oX", "/work/nmap.xml", *hosts]`.
  Scan-type `"Nmap Scan"`. No `-sS` (needs `NET_RAW`, which we drop), no NSE scripts
  in MVP.
- **`nuclei.py`** — `["-target"…|"-list", "/work/targets.txt", "-jsonl", "-o",
  "/work/nuclei.jsonl", "-severity", "critical,high,medium,low", "-rate-limit", …,
  "-no-interactsh"]`. Scan-type `"Nuclei Scan"`. `-no-interactsh` because OAST
  callbacks to a third-party server are not acceptable default behaviour.
- **`zap.py`** — baseline passive spider + `-J /work/zap.json`. Scan-type `"ZAP Scan"`.
  Active attack mode is out of MVP scope.

`recon_assets.py` extracts **assets** from recon output (subdomains, live hosts,
ports, tech, titles). It is explicitly *not* a vulnerability parser — §8 of the PRD
puts custom scanner parsers out of scope; vulnerability parsing is DefectDojo's.

`registry.py` — `get_adapter(name: ScannerName) -> ScannerAdapter`,
`ALL_ADAPTERS: Mapping[ScannerName, ScannerAdapter]`.

`artifacts.py` — `hash_file(path)`, `collect_dir(workdir, …)`,
`upload_artifacts(storage, organization_id, job_id, artifacts) -> list[StoredArtifact]`,
`purge_workdir(path)`. Artifacts are uploaded, hashed, then the host workdir is wiped.

---

## 8. Events, WebSocket and progress

One envelope on the wire (`app/schemas/agent.py`), fanned out over Redis pub/sub
(`app/services/events.py`) so any API replica can serve any socket.

```python
class AgentEventType(StrEnum):
    AGENT_THINKING     = "agent_thinking"
    AGENT_PLAN_STEP    = "agent_plan_step"
    AGENT_TOOL_CALL    = "agent_tool_call"
    AGENT_APPROVAL_REQUIRED = "agent_approval_required"
    AGENT_FINDINGS_UPDATE   = "agent_findings_update"
    AGENT_ERROR        = "agent_error"
    AGENT_COMPLETE     = "agent_complete"
    # transport-level, not in PRD §53's list but required for a usable socket:
    AGENT_MESSAGE      = "agent_message"
    AGENT_PROGRESS     = "agent_progress"
    PONG               = "pong"

class AgentEvent(BaseModel):
    type: AgentEventType
    session_id: UUID
    assessment_id: UUID | None = None
    run_id: UUID | None = None
    seq: int                       # monotonic per session; lets a client detect gaps
    at: datetime
    data: dict[str, Any]
```

Payload shape per type:

| type | `data` |
|---|---|
| `agent_thinking` | `{text, node}` |
| `agent_plan_step` | `{step_index, total_steps, stage, title, status, detail}` |
| `agent_tool_call` | `{tool, status: "started"\|"succeeded"\|"failed", risk_level, summary, duration_ms}` — **arguments are summarized, never dumped** (SEC-002/SEC-006) |
| `agent_approval_required` | `ApprovalOut` |
| `agent_findings_update` | `{assessment_id, total, critical, high, medium, low, info, new_since_last}` |
| `agent_error` | `{code, category, user_message, retryable, degradable, stage}` — `user_message` only |
| `agent_complete` | `{assessment_id, status, findings_total, report_id, duration_seconds}` |
| `agent_message` | `AgentMessageOut` |
| `agent_progress` | `{stage, progress_percent, stages: [StageOut]}` |

```python
# app/services/events.py
class EventBus:
    def __init__(self, redis: Redis, settings: Settings) -> None: ...
    async def publish(self, event: AgentEvent) -> None
    async def subscribe(self, session_id: UUID) -> AsyncIterator[AgentEvent]
    async def next_seq(self, session_id: UUID) -> int
def channel_for(settings: Settings, session_id: UUID) -> str
```

Channel name is `f"{settings.redis.event_channel_prefix}:session:{session_id}"`.
`WS /ws/agent/{session_id}` authenticates with the access token (query param or
first-frame `{"type":"auth","token":…}`), verifies the session belongs to the
caller's organization, then relays. Client may send `{"type":"ping"}`.

Progress (FR-038) is derived, never guessed:

```python
# app/services/progress.py
def percent_for(stage: AssessmentStage) -> int          # position in STAGE_ORDER
def stage_checklist(assessment, steps) -> list[StageOut]
```

---

## 9. `app/services/` — signatures other slices depend on

Every service function takes `session: AsyncSession` first and a `Principal` where
authorization matters. Services own transactions only when invoked from the worker;
API routes commit.

```python
# app/services/context.py
@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID | None
    organization_id: uuid.UUID
    role: Role
    email: str | None = None
    actor_type: str = "user"            # user | agent | worker | system
    source_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    trace_id: str | None = None

    @property
    def permissions(self) -> frozenset[Permission]: ...
    def has(self, permission: Permission) -> bool: ...
    def require(self, permission: Permission) -> None: ...   # PermissionDeniedError
    @classmethod
    def for_agent(cls, *, organization_id, on_behalf_of=None) -> "Principal": ...
```

The agent's principal is **never** more privileged than the user who started the run.
`Principal.for_agent` copies the initiating user's role.

Selected signatures (each service exports more; these are the cross-slice ones):

```python
# assessment.py
async def create_assessment(session, principal, payload: AssessmentCreateIn,
                            settings: Settings) -> Assessment
async def get_assessment(session, principal, assessment_id, *, detail=False) -> Assessment
async def list_assessments(session, principal, *, filters, pagination) -> tuple[Sequence[Assessment], int]
async def transition(session, assessment, to: AssessmentStatus, *,
                     stage: AssessmentStage | None = None,
                     reason: str | None = None) -> None
    """Enforces ALLOWED_TRANSITIONS. An illegal transition raises ConflictError —
    it is never applied 'best effort'."""
async def record_degradation(session, assessment, *, stage, component, reason, impact) -> None
async def cancel_assessment(session, principal, assessment_id, payload: CancelIn) -> Assessment
async def refresh_counters(session, assessment) -> None

# approval.py
async def open_approval(session, assessment, *, kind, prompt, rationale,
                        requested_payload, risk_level, agent_run_id, settings) -> Approval
async def resolve_approval(session, principal, approval_id, payload: ApproveIn) -> Approval
    """Writes approved_payload from the human's choice. Requires
    Permission.ASSESSMENT_APPROVE. Expired ⇒ ConflictError."""
async def pending_approval(session, assessment_id) -> Approval | None
async def expire_stale(session, settings) -> int

# asset.py
async def upsert_assets(session, assessment, records: Sequence[DiscoveredAsset]) -> list[Asset]
async def score_and_select(session, assessment, *, budget: int, settings) -> list[Asset]
async def infer_criticality(asset, settings) -> tuple[Criticality, CriticalitySource, str]
async def tag_asset(session, principal, asset_id, payload: AssetTagIn) -> AssetTag

# job.py
async def enqueue_job(session, assessment, *, scanner, targets, timeout_seconds) -> ScannerJob
async def claim_slot(redis, settings, organization_id) -> bool     # FR-013 concurrency
async def release_slot(redis, settings, organization_id) -> None
async def execute_job(session, job, *, runner, storage, settings, on_log=None) -> ScannerJob
async def request_cancel(session, principal, job_id) -> ScannerJob

# finding.py
async def import_from_defectdojo(session, assessment, *, client, test_id) -> list[Finding]
async def list_findings(session, principal, *, filters, pagination) -> tuple[Sequence[Finding], int]
async def analyze_finding(session, principal, finding_id, *, gateway, dify, settings) -> Finding
async def prioritize(session, assessment, *, settings) -> None

# enrichment.py
async def enrich_finding(session, finding, *, nvd, kev, epss, misp, settings) -> FindingEnrichment
    """Each provider independently sets its own *_status. A provider outage records
    UNAVAILABLE; it never records a negative result (FR-020)."""

# audit.py
async def record(session, *, principal=None, action: str, resource_type=None,
                 resource_id=None, outcome=AuditOutcome.SUCCESS, detail=None,
                 reason=None, organization_id=None) -> AuditEvent
```

FR-032 requires an audit row for: auth events (including failures), assessment
create/approve/cancel, scanner start/stop, integration config change, finding status
change, ticket creation, report generation, permission denials, and every agent tool
invocation.

---

## 10. `app/agent/` — LangGraph (PRD §54)

```python
# app/agent/state.py
class AssessmentState(TypedDict, total=False):
    organization_id: str
    assessment_id: str
    session_id: str
    run_id: str
    principal: dict[str, Any]
    objective: str
    raw_targets: list[str]
    targets: list[dict[str, Any]]
    interpretation: dict[str, Any]
    plan: list[dict[str, Any]]
    discovered_assets: list[dict[str, Any]]
    selected_asset_ids: list[str]
    approval_id: str | None
    approved_payload: dict[str, Any]
    scanner_jobs: list[dict[str, Any]]
    defectdojo: dict[str, Any]
    finding_ids: list[str]
    analysis: dict[str, Any]
    report_id: str | None
    stage: str
    degradations: list[dict[str, Any]]
    error: dict[str, Any] | None
    messages: Annotated[list[dict[str, Any]], operator.add]
```

Node modules in `app/agent/nodes/`, each exporting one
`async def run(state: AssessmentState, ctx: NodeContext) -> dict[str, Any]` that
returns a **partial** state update:

`understand.py` → `validate.py` → `plan.py` → `recon.py` → `assets.py` →
`approval.py` (interrupt) → `scan.py` → `import_findings.py` → `enrich.py` →
`analyze.py` → `remediate.py` → `actions.py` → `report.py`, plus `error.py`.

`graph.py` wires them with `StateGraph(AssessmentState)`, a conditional edge from
every node to `error` when `state["error"]` is set, and
`interrupt_before=["execute_scanners"]` for FR-011. Checkpointer is
`AsyncPostgresSaver` over `settings.db.sync_dsn`, `thread_id = str(AgentRun.thread_id)`.

**The approval gate is structural.** `scan.py` must re-read the `Approval` row from
the database and refuse to run unless `approval.is_granted` and
`approval.resolved_by_id is not None`; it drives scanning from `approved_payload`
only. State alone is never sufficient authority — a resumed or replayed checkpoint
must not be able to carry a forged approval. Raise `ApprovalRequiredError` otherwise.

Tool registry (FR-034 / FR-035):

```python
# app/agent/registry.py
@dataclass(frozen=True, slots=True)
class ToolContract:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: RiskLevel
    required_permission: Permission
    idempotent: bool
    timeout_seconds: int
    failure_mode: Literal["fail", "degrade"]

class ToolRegistry:
    def register(self, contract: ToolContract, fn: ToolFn) -> None
    def get(self, name: str) -> tuple[ToolContract, ToolFn]
    def specs_for(self, principal: Principal) -> list[dict[str, Any]]
    async def invoke(self, name: str, args: dict, *, ctx: NodeContext) -> Any
```

`invoke` must, in order: look up the contract (unknown ⇒ `InvalidToolCallError`);
validate args against `input_schema` (⇒ `InvalidToolCallError`); check
`principal.has(required_permission)` (⇒ `ToolPermissionError`); if
`risk_level` is in `settings.agent.approval_required_risk_levels` and no granted
approval covers it, raise `ApprovalRequiredError`; refuse `RiskLevel.FORBIDDEN`
outright; write an audit row; run with timeout; truncate output through
`app/llm/budget.py` before it can reach a prompt.

---

## 11. `app/api/` — REST (PRD §53)

`main.py` — `create_app()` returning `FastAPI`. Lifespan: `configure_logging`,
`validate_runtime_configuration(role="api")` (log the returned warnings),
`setup_telemetry`, `configure_langsmith`, `instrument_app`, redis ping, then
`dispose_engine()` + `close_redis()` on shutdown. Middleware: request-id, structlog
context binding, `CORSMiddleware` from `settings.cors_origins`,
`TrustedHostMiddleware` from `settings.allowed_hosts`, `GZipMiddleware`.
Exception handlers convert `CynuxError` → `err.to_problem()` with
`media_type="application/problem+json"`, `RequestValidationError` → 422 problem, and
a catch-all that logs `exc_info` but returns a generic problem (SEC-002).

`deps.py` — `get_settings_dep`, `get_redis_dep`, `get_db` (re-exported),
`current_claims`, `current_user`, `current_principal`,
`require(*permissions)` factory, `rate_limit` dependency using `FixedWindowLimiter`,
`get_event_bus`, `get_llm_gateway`, `get_storage`, `get_defectdojo`.
`current_principal` resolves the active organization from the token's
`organization_id` claim and returns the §9 `Principal`.

Routers under `app/api/v1/`, mounted at `settings.api_prefix`. Exactly the PRD §53
surface, plus what a usable product needs (auth, orgs, integrations, audit, reports,
dashboard, health):

```
POST   /auth/register            POST /auth/login          POST /auth/refresh
POST   /auth/logout              GET  /auth/me             POST /auth/password/reset
POST   /assessments              GET  /assessments         GET  /assessments/{id}
POST   /assessments/{id}/approve POST /assessments/{id}/cancel
GET    /assessments/{id}/assets  GET  /assessments/{id}/findings
GET    /assessments/{id}/jobs    GET  /assessments/{id}/report
POST   /assessments/{id}/report
GET    /agent/sessions           GET  /agent/sessions/{id} POST /agent/messages
GET    /findings                 GET  /findings/{id}
POST   /findings/{id}/analyze    POST /findings/{id}/remediate
POST   /findings/{id}/jira
GET    /assets                   POST /assets/{id}/tags    PUT  /assets/{id}/criticality
GET    /jobs/{id}                GET  /jobs/{id}/artifacts/{artifact_id}
GET    /dashboard                GET  /audit               GET  /integrations
PUT    /integrations/{kind}      POST /integrations/{kind}/test
GET    /organizations/current    GET  /organizations/current/members
GET    /health                   GET  /health/ready
```

Every mutating route: `require(...)` permission dependency, `rate_limit`, an audit
row, and an explicit `await session.commit()`.

---

## 12. `app/worker/` — FR-033 / FR-037

Redis Streams consumer on `settings.redis.stream`, group
`settings.redis.consumer_group`. Loop: `XAUTOCLAIM` messages idle longer than
`claim_idle_ms` **first** (that is how a crashed worker's assessment resumes), then
`XREADGROUP` for new ones. For each message: build a `Principal`, load or create the
`AgentRun`, run the graph via `app/agent/runner.py`, heartbeat `AgentRun.heartbeat_at`
on a background task, `XACK` on terminal outcome. A run that hits an approval
interrupt is acked and left `INTERRUPTED` — resuming is a *new* message published by
the approve endpoint. `graceful shutdown` on SIGTERM: stop claiming, finish in-flight,
release concurrency slots.

---

## 13. `app/reporting/` — FR-030

```python
async def build_report_context(session, assessment, *, settings) -> dict[str, Any]
async def render_html(context) -> str
async def render_pdf(html: str) -> bytes          # weasyprint in a thread
async def generate(session, assessment, *, format, audience, storage, settings) -> Report
```

Sections, in order: executive summary (AI-generated, flagged as such via
`Report.summary_ai_generated`), scope and authorization, methodology and tools with
versions, asset inventory, findings by priority, remediation guidance, and an
appendix that lists **degradations and unavailable intelligence**. A reader must be
able to tell what was not covered rather than assume full coverage. Jinja2 with
`autoescape=True`; every finding field is untrusted scanner text.

---

## 14. Frontend

Next.js 15 App Router, TypeScript strict, Tailwind. `frontend/src/lib/api.ts` is the
only place that talks HTTP; `frontend/src/lib/types.ts` mirrors §4 exactly.
Three MVP screens (PRD §59): dashboard, agent chat, findings. The chat screen
consumes the §8 socket, renders plan steps and tool calls as they arrive, and
presents Approve / Reject / Customize inline when `agent_approval_required` lands.
Findings always show whether intelligence was verified or unavailable, and never
render an AI claim without its evidence.

---

## 15. Build gate

```bash
cd backend
python tools/verify.py          # must print OK
ruff check app tests tools
ruff format --check app tests tools
mypy app
pytest -q
```

`verify.py` is authoritative for import correctness and runs without any packages
installed. Run it after every file you add.
