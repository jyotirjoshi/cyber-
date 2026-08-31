"""Cynux configuration.

Everything is driven by environment variables with the ``CYNUX_`` prefix, and each
settings group owns its own prefix, e.g. ``CYNUX_LLM__PROVIDER``,
``CYNUX_SCANNER__MEMORY_LIMIT_MB``.

Two rules shaped this module:

1. **No fabricated defaults.**  Anything whose wrong value would be a security
   problem (signing keys, encryption keys, allowed origins) has *no* default, and
   startup fails with a message naming the variable.  Nothing in Cynux invents a
   credential, a demo tenant, or a placeholder endpoint.
2. **No default LLM provider.**  Per the product decision, the gateway refuses to
   guess which model vendor to send security data to.

:func:`validate_runtime_configuration` runs during API and worker startup, so a
misconfigured deployment fails immediately and visibly rather than halfway through
a customer's assessment.
"""

from __future__ import annotations

import functools
from typing import Annotated, Literal
from urllib.parse import quote_plus

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.errors import ConfigurationError, NoLLMProviderError

Environment = Literal["development", "staging", "production"]
LLMProvider = Literal["anthropic", "openai", "google"]

#: Roles the gateway routes independently (PRD section 55).
LLMRole = Literal["planning", "reasoning", "classification", "code_remediation", "report"]


def _cfg(prefix: str) -> SettingsConfigDict:
    """Build a settings config for one group. Each group reads its own prefix so
    ``CYNUX_DB__PASSWORD`` and ``CYNUX_JIRA__API_TOKEN`` cannot collide."""
    return SettingsConfigDict(
        env_prefix=prefix,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


#: List fields are annotated with ``NoDecode`` so pydantic-settings hands us the raw
#: string instead of insisting on JSON. Operators write
#: ``CYNUX_CORS_ORIGINS=https://a.com,https://b.com`` far more often than a JSON array,
#: and without this the JSON form would be the only accepted syntax.
StrList = Annotated[list[str], NoDecode]
SecretList = Annotated[list[SecretStr], NoDecode]


def _csv(value: object) -> object:
    """Accept a JSON array or a comma-separated string for list fields."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            import json

            try:
                return json.loads(stripped)
            except ValueError:
                pass
        return [part.strip() for part in stripped.split(",") if part.strip()]
    return value


# ---------------------------------------------------------------------------


class DatabaseSettings(BaseSettings):
    model_config = _cfg("CYNUX_DB__")

    host: str = "postgres"
    port: int = 5432
    name: str = "cynux"
    user: str = "cynux"
    password: SecretStr = SecretStr("")
    pool_size: int = 10
    max_overflow: int = 20
    pool_recycle_seconds: int = 1800
    pool_timeout_seconds: int = 30
    #: Tests set this so no pooled connection outlives its event loop.
    use_null_pool: bool = False
    echo: bool = False

    @property
    def _credentials(self) -> str:
        """User:password, percent-encoded.

        Without quoting, a password containing ``@``, ``/`` or ``:`` -- all legal, and
        common in generated secrets -- produces a DSN that parses into the wrong host.
        """
        user = quote_plus(self.user)
        password = quote_plus(self.password.get_secret_value())
        return f"{user}:{password}" if password else user

    @property
    def async_dsn(self) -> str:
        """asyncpg DSN used by the API and worker."""
        return f"postgresql+asyncpg://{self._credentials}@{self.host}:{self.port}/{self.name}"

    @property
    def sync_dsn(self) -> str:
        """psycopg DSN. Alembic and the LangGraph Postgres checkpointer need this."""
        return f"postgresql://{self._credentials}@{self.host}:{self.port}/{self.name}"


class RedisSettings(BaseSettings):
    model_config = _cfg("CYNUX_REDIS__")

    url: str = "redis://redis:6379/0"
    #: Stream carrying agent run requests to the worker pool.
    stream: str = "cynux:agent:runs"
    consumer_group: str = "cynux-workers"
    #: A pending message idle longer than this is reclaimed by another worker,
    #: which is how an assessment survives a worker crash (FR-033).
    claim_idle_ms: int = 120_000
    max_stream_length: int = 100_000
    #: Prefix for WebSocket fan-out pub/sub channels.
    event_channel_prefix: str = "cynux:events"
    #: Prefix for cached external-intelligence responses.
    cache_prefix: str = "cynux:cache"


class SecuritySettings(BaseSettings):
    model_config = _cfg("CYNUX_SECURITY__")

    #: Signs access/refresh tokens. No default: a shared default would be a backdoor.
    jwt_secret: SecretStr = SecretStr("")
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_ttl_minutes: int = 30
    refresh_token_ttl_days: int = 14
    password_reset_ttl_minutes: int = 30

    #: 32-byte url-safe base64 Fernet key encrypting integration credentials at rest
    #: (SEC-001). Generate with:
    #:   python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
    credential_encryption_key: SecretStr = SecretStr("")
    #: Retired keys, newest first. Enables rotation without downtime.
    credential_encryption_previous_keys: SecretList = Field(default_factory=list)

    min_password_length: int = 12
    login_max_attempts: int = 8
    login_lockout_seconds: int = 900

    @field_validator("credential_encryption_previous_keys", mode="before")
    @classmethod
    def _parse_keys(cls, value: object) -> object:
        return _csv(value)


class ScannerSettings(BaseSettings):
    """FR-012 / FR-014 sandbox parameters."""

    model_config = _cfg("CYNUX_SCANNER__")

    #: None -> docker.from_env(). Set to e.g. tcp://docker-proxy:2375 to run scanners
    #: through a socket proxy instead of mounting the raw Docker socket.
    docker_host: str | None = None
    #: Network the scanner containers join. It must NOT be able to reach postgres,
    #: redis or minio (SEC-004); docker-compose defines it as egress-only.
    network: str = "cynux_scanner_net"

    cpu_quota_cores: float = 1.0
    memory_limit_mb: int = 2048
    #: Guards against a fork bomb in a compromised scanner image.
    pids_limit: int = 512
    #: Writable scratch; the container root filesystem stays read-only.
    tmpfs_size_mb: int = 1024
    default_timeout_seconds: int = 1800
    max_timeout_seconds: int = 21_600  # 6h ceiling for one scanner job
    #: UID:GID the scanner process runs as inside the container (nobody:nogroup).
    run_as_user: str = "65534:65534"
    #: Concurrent scanner containers per organization (PRD section 57).
    max_concurrent_jobs_per_org: int = 4
    #: Cynux-wide ceiling so one tenant cannot exhaust the host.
    max_concurrent_jobs_global: int = 16
    #: Host directory bind-mounted per job for artifact hand-off. Cleared after upload.
    artifact_workdir: str = "/var/lib/cynux/artifacts"

    image_reconftw: str = "six2dez/reconftw:main"
    image_nmap: str = "instrumentisto/nmap:7.95"
    image_nuclei: str = "projectdiscovery/nuclei:v3.3.7"
    image_zap: str = "zaproxy/zap-stable:2.15.0"

    @property
    def allowed_images(self) -> frozenset[str]:
        """Only these images may ever be started. A model-supplied image name can
        therefore never reach the Docker API."""
        return frozenset({self.image_reconftw, self.image_nmap, self.image_nuclei, self.image_zap})


class TargetPolicySettings(BaseSettings):
    """FR-006 target validation policy."""

    model_config = _cfg("CYNUX_TARGETS__")

    #: Refuse RFC1918 / loopback / link-local / CGNAT targets. Disabling this is a
    #: deliberate act for internal deployments and is recorded in the audit log.
    block_private_ranges: bool = True
    #: Cloud metadata endpoints and similar SSRF magnets are always blocked.
    block_metadata_endpoints: bool = True
    deny_list: StrList = Field(default_factory=list)
    #: If non-empty, only these suffixes/CIDRs may ever be scanned.
    allow_list: StrList = Field(default_factory=list)
    max_cidr_hosts: int = 4096

    @field_validator("deny_list", "allow_list", mode="before")
    @classmethod
    def _parse_lists(cls, value: object) -> object:
        parsed = _csv(value)
        if isinstance(parsed, list):
            return [str(item).strip().lower() for item in parsed if str(item).strip()]
        return parsed


class LLMSettings(BaseSettings):
    """PRD section 55. Deliberately has *no* default provider."""

    model_config = _cfg("CYNUX_LLM__")

    provider: LLMProvider | None = None

    anthropic_api_key: SecretStr | None = None
    anthropic_base_url: str | None = None
    openai_api_key: SecretStr | None = None
    openai_base_url: str | None = None
    google_api_key: SecretStr | None = None

    #: Model used for roles without an explicit override. Still requires ``provider``.
    default_model: str | None = None
    #: e.g. CYNUX_LLM__ROLE_MODELS='{"planning":"claude-opus-4-1","report":"gpt-4.1-mini"}'
    role_models: dict[str, str] = Field(default_factory=dict)
    #: e.g. CYNUX_LLM__ROLE_PROVIDERS='{"report":"openai"}'
    role_providers: dict[str, str] = Field(default_factory=dict)

    max_output_tokens: int = 4096
    temperature: float = 0.0
    request_timeout_seconds: int = 120
    max_retries: int = 3

    #: SEC-006 -- hard ceiling on characters of tool output handed to the model in one
    #: turn. The agent summarizes before this is reached.
    max_tool_output_chars: int = 60_000
    #: Ceiling on a whole prompt, in characters, as a cheap proxy for tokens.
    max_prompt_chars: int = 400_000

    def key_for(self, provider: str) -> SecretStr | None:
        return {
            "anthropic": self.anthropic_api_key,
            "openai": self.openai_api_key,
            "google": self.google_api_key,
        }.get(provider)


class LangSmithSettings(BaseSettings):
    """Agent tracing. Section 58 makes this effectively mandatory for debuggability."""

    model_config = _cfg("CYNUX_LANGSMITH__")

    enabled: bool = False
    api_key: SecretStr | None = None
    project: str = "cynux"
    endpoint: str = "https://api.smith.langchain.com"

    @model_validator(mode="after")
    def _need_key(self) -> LangSmithSettings:
        if self.enabled and not self.api_key:
            raise ValueError(
                "CYNUX_LANGSMITH__ENABLED is true but CYNUX_LANGSMITH__API_KEY is unset."
            )
        return self


class DefectDojoSettings(BaseSettings):
    """FR-016. The vulnerability-management source of truth."""

    model_config = _cfg("CYNUX_DEFECTDOJO__")

    base_url: str | None = None
    api_token: SecretStr | None = None
    verify_tls: bool = True
    timeout_seconds: int = 120
    product_type_name: str = "Cynux"
    #: DefectDojo owns deduplication (FR-018); we only ask it to do so.
    deduplication_on_engagement: bool = True
    close_old_findings: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_token)


class IntelSettings(BaseSettings):
    """FR-019 vulnerability + threat intelligence sources."""

    model_config = _cfg("CYNUX_INTEL__")

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"
    #: Optional but recommended: raises NVD's limit from 5/30s to 50/30s.
    nvd_api_key: SecretStr | None = None
    nvd_cache_ttl_seconds: int = 86_400

    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    kev_refresh_seconds: int = 21_600

    epss_base_url: str = "https://api.first.org/data/v1/epss"
    epss_cache_ttl_seconds: int = 86_400

    misp_base_url: str | None = None
    misp_api_key: SecretStr | None = None
    misp_verify_tls: bool = True

    @property
    def misp_configured(self) -> bool:
        return bool(self.misp_base_url and self.misp_api_key)


class DifySettings(BaseSettings):
    """FR-021 knowledge base / RAG."""

    model_config = _cfg("CYNUX_DIFY__")

    base_url: str | None = None
    dataset_api_key: SecretStr | None = None
    dataset_id: str | None = None
    top_k: int = 6
    score_threshold: float = 0.35
    timeout_seconds: int = 30

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.dataset_api_key and self.dataset_id)


class StorageSettings(BaseSettings):
    """FR-015 raw artifact storage."""

    model_config = _cfg("CYNUX_STORAGE__")

    endpoint_url: str | None = None  # None -> real AWS S3
    region: str = "us-east-1"
    bucket: str = "cynux-artifacts"
    access_key_id: SecretStr | None = None
    secret_access_key: SecretStr | None = None
    #: Path-style addressing is required by MinIO.
    force_path_style: bool = True
    sse: str | None = "AES256"
    presign_ttl_seconds: int = 900

    @property
    def configured(self) -> bool:
        return bool(self.access_key_id and self.secret_access_key and self.bucket)


class JiraSettings(BaseSettings):
    model_config = _cfg("CYNUX_JIRA__")

    base_url: str | None = None
    user_email: str | None = None
    api_token: SecretStr | None = None
    project_key: str | None = None
    issue_type: str = "Bug"
    timeout_seconds: int = 45

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.user_email and self.api_token and self.project_key)


class NotificationSettings(BaseSettings):
    """FR-029."""

    model_config = _cfg("CYNUX_NOTIFY__")

    slack_bot_token: SecretStr | None = None
    slack_default_channel: str | None = None
    slack_webhook_url: SecretStr | None = None

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_use_tls: bool = True
    smtp_from: str | None = None

    @property
    def slack_configured(self) -> bool:
        return bool(self.slack_bot_token or self.slack_webhook_url)

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)


class ObservabilitySettings(BaseSettings):
    model_config = _cfg("CYNUX_OTEL__")

    enabled: bool = False
    endpoint: str = "http://otel-collector:4318"
    service_name: str = "cynux-api"
    sample_ratio: float = 1.0
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    #: JSON logs in containers, key=value in a terminal.
    json_logs: bool = True


class AgentSettings(BaseSettings):
    model_config = _cfg("CYNUX_AGENT__")

    #: FR-010: how many assets the agent may recommend for deep scanning by default.
    default_scope_budget: int = 50
    #: Hard cap regardless of what the model asks for.
    max_scope_budget: int = 500
    #: FR-011: tool risk levels that always require a human before execution.
    approval_required_risk_levels: StrList = Field(default_factory=lambda: ["high", "medium"])
    #: An assessment interrupted for approval expires after this long.
    approval_ttl_hours: int = 72
    #: FR-022: findings at or above this severity get full enrichment + AI analysis.
    analysis_severity_floor: Literal["critical", "high", "medium", "low", "info"] = "high"
    #: Cap on findings analyzed per assessment, to bound LLM spend.
    max_findings_analyzed: int = 200
    #: Keywords used to infer asset criticality when no operator tag exists (FR-022).
    criticality_keywords: StrList = Field(
        default_factory=lambda: [
            "auth",
            "sso",
            "login",
            "admin",
            "api",
            "payment",
            "pay",
            "billing",
            "checkout",
            "identity",
            "vault",
            "secret",
            "keycloak",
            "db",
            "database",
            "internal",
            "vpn",
            "jenkins",
            "gitlab",
            "prod",
            "production",
        ]
    )
    #: Wall-clock ceiling for one agent run before the graph aborts.
    max_run_seconds: int = 43_200  # 12h

    @field_validator("approval_required_risk_levels", "criticality_keywords", mode="before")
    @classmethod
    def _parse_lists(cls, value: object) -> object:
        parsed = _csv(value)
        if isinstance(parsed, list):
            return [str(item).strip().lower() for item in parsed if str(item).strip()]
        return parsed


# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    model_config = _cfg("CYNUX_")

    environment: Environment = "development"
    debug: bool = False
    api_prefix: str = "/api/v1"
    public_base_url: str = "http://localhost:3000"

    #: No wildcard default: an ordinary misconfiguration should not become a CORS hole.
    cors_origins: StrList = Field(default_factory=lambda: ["http://localhost:3000"])
    allowed_hosts: StrList = Field(default_factory=lambda: ["*"])

    #: Requests per minute per authenticated principal on mutating endpoints.
    rate_limit_per_minute: int = 120

    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    targets: TargetPolicySettings = Field(default_factory=TargetPolicySettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    langsmith: LangSmithSettings = Field(default_factory=LangSmithSettings)
    defectdojo: DefectDojoSettings = Field(default_factory=DefectDojoSettings)
    intel: IntelSettings = Field(default_factory=IntelSettings)
    dify: DifySettings = Field(default_factory=DifySettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    jira: JiraSettings = Field(default_factory=JiraSettings)
    notify: NotificationSettings = Field(default_factory=NotificationSettings)
    otel: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)

    @field_validator("cors_origins", "allowed_hosts", mode="before")
    @classmethod
    def _parse_lists(cls, value: object) -> object:
        return _csv(value)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook -- lets a test change the environment and rebuild settings."""
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------

#: Roles the gateway must resolve for the agent to function at all.
REQUIRED_LLM_ROLES: tuple[str, ...] = (
    "planning",
    "reasoning",
    "classification",
    "code_remediation",
    "report",
)


def validate_runtime_configuration(settings: Settings, *, role: str = "api") -> list[str]:
    """Fail fast on anything that would break correctness or security.

    Returns non-fatal warnings; raises :class:`ConfigurationError` for anything
    fatal.  ``role`` is ``"api"`` or ``"worker"`` -- only the worker needs the
    container runtime, object storage and DefectDojo.
    """
    fatal: list[str] = []
    warnings: list[str] = []

    # --- secrets that must never have a default ------------------------------
    jwt_secret = settings.security.jwt_secret.get_secret_value()
    if not jwt_secret:
        fatal.append(
            "CYNUX_SECURITY__JWT_SECRET is unset. Generate one with `openssl rand -hex 32`."
        )
    elif len(jwt_secret) < 32:
        fatal.append("CYNUX_SECURITY__JWT_SECRET must be at least 32 characters.")

    if not settings.security.credential_encryption_key.get_secret_value():
        fatal.append(
            "CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY is unset. Integration "
            "credentials cannot be stored without it. Generate one with: python -c "
            '"from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"'
        )

    if not settings.db.password.get_secret_value():
        fatal.append("CYNUX_DB__PASSWORD is unset.")

    # --- LLM: no default provider, by design --------------------------------
    if settings.llm.provider is None and not settings.llm.role_providers:
        raise NoLLMProviderError()

    providers_in_use = {settings.llm.provider, *settings.llm.role_providers.values()}
    for provider in sorted(p for p in providers_in_use if p):
        if provider not in ("anthropic", "openai", "google"):
            fatal.append(
                f"Unknown LLM provider '{provider}'. Supported: anthropic, openai, google."
            )
        elif not settings.llm.key_for(provider):
            fatal.append(
                f"LLM provider '{provider}' is selected but "
                f"CYNUX_LLM__{provider.upper()}_API_KEY is unset."
            )

    missing_roles = sorted(set(REQUIRED_LLM_ROLES) - set(settings.llm.role_models))
    if not settings.llm.default_model and missing_roles:
        fatal.append(
            "CYNUX_LLM__DEFAULT_MODEL is unset and these roles have no explicit model: "
            f"{', '.join(missing_roles)}. Cynux will not guess a model name."
        )

    # --- production hardening -----------------------------------------------
    if settings.is_production:
        if settings.debug:
            fatal.append("CYNUX_DEBUG must be false in production.")
        if "*" in settings.cors_origins:
            fatal.append("CYNUX_CORS_ORIGINS must not contain '*' in production.")
        if "*" in settings.allowed_hosts:
            fatal.append("CYNUX_ALLOWED_HOSTS must not contain '*' in production.")
        if not settings.public_base_url.startswith("https://"):
            fatal.append("CYNUX_PUBLIC_BASE_URL must be https:// in production (SEC-001).")
        if not settings.defectdojo.verify_tls:
            fatal.append("CYNUX_DEFECTDOJO__VERIFY_TLS must be true in production.")
        if not settings.langsmith.enabled:
            warnings.append(
                "LangSmith tracing is disabled. Agent decisions will be much harder "
                "to explain after the fact (PRD section 58)."
            )
        if not settings.targets.block_private_ranges:
            warnings.append(
                "Private-range scanning is enabled. Confirm this deployment is "
                "authorized to test internal networks."
            )
        if not settings.otel.enabled:
            warnings.append("OpenTelemetry is disabled; request traces will not be exported.")

    # --- capabilities the worker cannot do without --------------------------
    if role == "worker":
        if not settings.storage.configured:
            fatal.append(
                "Object storage is not configured (CYNUX_STORAGE__*). Scanner "
                "artifacts must be retained (FR-015)."
            )
        if not settings.defectdojo.configured:
            fatal.append(
                "DefectDojo is not configured (CYNUX_DEFECTDOJO__BASE_URL and "
                "CYNUX_DEFECTDOJO__API_TOKEN). It is the vulnerability-management "
                "source of truth (FR-016); Cynux will not substitute its own store."
            )

    # --- optional integrations: warn, never silently substitute -------------
    if not settings.dify.configured:
        warnings.append(
            "Dify is not configured; security-knowledge retrieval will report "
            "'knowledge base unavailable' rather than answering from model memory."
        )
    if not settings.jira.configured:
        warnings.append("Jira is not configured; ticket creation will be rejected.")
    if not (settings.notify.slack_configured or settings.notify.email_configured):
        warnings.append("No notification channel is configured (Slack or SMTP).")
    if not settings.intel.nvd_api_key:
        warnings.append(
            "No NVD API key: requests are limited to 5 per 30s, which will slow "
            "enrichment of large assessments."
        )
    if not settings.intel.misp_configured:
        warnings.append("MISP is not configured; threat-intelligence lookups will be skipped.")

    if fatal:
        raise ConfigurationError(
            "Cynux cannot start. Fix these configuration problems:\n  - " + "\n  - ".join(fatal)
        )
    return warnings


__all__ = [
    "REQUIRED_LLM_ROLES",
    "AgentSettings",
    "DatabaseSettings",
    "DefectDojoSettings",
    "DifySettings",
    "Environment",
    "IntelSettings",
    "JiraSettings",
    "LLMProvider",
    "LLMRole",
    "LLMSettings",
    "LangSmithSettings",
    "NotificationSettings",
    "ObservabilitySettings",
    "RedisSettings",
    "ScannerSettings",
    "SecuritySettings",
    "Settings",
    "StorageSettings",
    "TargetPolicySettings",
    "get_settings",
    "reset_settings_cache",
    "validate_runtime_configuration",
]
