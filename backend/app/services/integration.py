"""Per-organization integration configuration and credential custody (FR-020, SEC-001,
SEC-002).

The central design question this module answers is: *where does a provider client get its
configuration from?*  Every client in :mod:`app.integrations` is constructed from
:class:`~app.core.config.Settings` — deliberately, because that keeps them usable from a
CLI, a test, or the worker without a database.  But Cynux is multi-tenant, and two
organizations legitimately point at two different Jira instances.

Rather than rewrite eight frozen clients to accept a different configuration source, this
module **projects a database row onto a copy of Settings** (:func:`resolve_settings`).
Deployment-wide environment configuration remains the default; an ``integrations`` row
overlays whatever it specifies on top.  A caller that needs an organization-scoped client
therefore writes::

    scoped = await resolve_settings(session, principal, IntegrationKind.JIRA,
                                    settings=settings)
    client = JiraClient(scoped, redis)

and every existing client works per-tenant with no change.  The alternative — threading a
credential dict through every client constructor — would have spread secret handling across
eight modules instead of confining it to this one.

Three rules about credentials, all of which the type system cannot enforce for us:

**Credentials are write-only across the API boundary.**  They arrive on
:class:`~app.schemas.integration.IntegrationUpsertIn`, are encrypted before the row is
flushed, and no read path in this module returns plaintext to a caller other than
:func:`resolve_settings`, which hands it straight to a client constructor.  What the API
returns is a fingerprint and a four-character hint.

**Omitting a credential on update keeps the stored one.**  A settings form that submits
only the fields a human edited must not de-provision the ones it left blank.  Clearing a
credential is an explicit empty string, which is why :func:`_apply_credentials`
distinguishes "absent" from "present and empty".

**``config`` is scanned for secret-shaped keys and they are refused.**  ``config`` is
returned to the API in plaintext, so a token smuggled into it would be a disclosure. The
schema documents that the service strips such keys; this module is where that happens, and
it rejects rather than strips, because silently dropping the field an operator just typed
looks like the save failed.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import structlog
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.crypto import CredentialDecryptionError, Secret, get_cipher
from app.core.errors import (
    CynuxError,
    IntegrationError,
    IntegrationNotConfiguredError,
    InvalidConfigurationError,
    ResourceNotFoundError,
)
from app.db.base import utcnow
from app.db.enums import AuditOutcome, IntegrationKind, IntegrationStatus, Permission
from app.db.models.integration import Integration, IntegrationCredential
from app.db.repository import tenant_select
from app.integrations.circuit import CircuitBreaker
from app.integrations.defectdojo import DefectDojoClient
from app.integrations.dify import DifyClient
from app.integrations.email import EmailSender
from app.integrations.jira import JiraClient
from app.integrations.misp import MISPClient
from app.integrations.slack import SlackClient
from app.schemas.integration import (
    CredentialOut,
    IntegrationHealthOut,
    IntegrationOut,
    IntegrationTestOut,
    IntegrationUpsertIn,
)
from app.services import audit as audit_service
from app.services.audit import AuditAction
from app.services.context import Principal

log = structlog.get_logger(__name__)

#: Substrings that make a ``config`` key look like a credential. Matched against the
#: lowercased key, so ``apiToken`` and ``API_TOKEN`` are both caught.
_SECRET_KEY_MARKERS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "passphrase",
)


@dataclass(frozen=True, slots=True)
class _KindSpec:
    """How one integration kind maps onto a section of :class:`Settings`.

    ``credentials`` and ``config`` are ``{stored name: settings field}``. The indirection
    exists because the stored names are the operator's vocabulary ("api_token") while the
    settings fields are the deployment's ("slack_bot_token"), and forcing either to match
    the other would make one of the two confusing.
    """

    section: str
    base_url_field: str | None = None
    credentials: Mapping[str, str] = field(default_factory=dict)
    config: Mapping[str, str] = field(default_factory=dict)
    #: Credential slots without which the integration cannot work at all.
    required: tuple[str, ...] = ()


_SPECS: dict[IntegrationKind, _KindSpec] = {
    IntegrationKind.DEFECTDOJO: _KindSpec(
        section="defectdojo",
        base_url_field="base_url",
        credentials={"api_token": "api_token"},
        config={
            "verify_tls": "verify_tls",
            "product_type_name": "product_type_name",
            "deduplication_on_engagement": "deduplication_on_engagement",
            "close_old_findings": "close_old_findings",
        },
        required=("api_token",),
    ),
    IntegrationKind.JIRA: _KindSpec(
        section="jira",
        base_url_field="base_url",
        credentials={"api_token": "api_token"},
        # ``user_email`` is the account the token belongs to, not a secret: Jira's API
        # needs both halves and the address is visible on every issue the bot files.
        config={
            "user_email": "user_email",
            "project_key": "project_key",
            "issue_type": "issue_type",
        },
        required=("api_token",),
    ),
    IntegrationKind.SLACK: _KindSpec(
        section="notify",
        credentials={"bot_token": "slack_bot_token", "webhook_url": "slack_webhook_url"},
        config={"default_channel": "slack_default_channel"},
        # Neither is individually required: a bot token and an incoming webhook are two
        # valid ways to post, and demanding both would reject a working setup.
    ),
    IntegrationKind.EMAIL: _KindSpec(
        section="notify",
        credentials={"smtp_password": "smtp_password"},
        config={
            "smtp_host": "smtp_host",
            "smtp_port": "smtp_port",
            "smtp_username": "smtp_username",
            "smtp_use_tls": "smtp_use_tls",
            "smtp_from": "smtp_from",
        },
    ),
    IntegrationKind.DIFY: _KindSpec(
        section="dify",
        base_url_field="base_url",
        credentials={"dataset_api_key": "dataset_api_key"},
        config={
            "dataset_id": "dataset_id",
            "top_k": "top_k",
            "score_threshold": "score_threshold",
        },
        required=("dataset_api_key",),
    ),
    IntegrationKind.MISP: _KindSpec(
        section="intel",
        base_url_field="misp_base_url",
        credentials={"api_key": "misp_api_key"},
        config={"verify_tls": "misp_verify_tls"},
        required=("api_key",),
    ),
    IntegrationKind.NVD: _KindSpec(
        section="intel",
        base_url_field="nvd_base_url",
        credentials={"api_key": "nvd_api_key"},
        # NVD serves unauthenticated callers at a lower rate limit, so a key is optional.
    ),
}

#: Kinds the MVP can store configuration for but cannot yet talk to (FR-028). Kept in the
#: table so the schema and UI can be built against them, and so an operator who configures
#: one is told plainly rather than seeing a silent no-op.
_UNIMPLEMENTED: frozenset[IntegrationKind] = frozenset(
    {IntegrationKind.GITHUB, IntegrationKind.GITLAB}
)

_DEFAULT_NAMES: dict[IntegrationKind, str] = {
    IntegrationKind.DEFECTDOJO: "DefectDojo",
    IntegrationKind.JIRA: "Jira",
    IntegrationKind.SLACK: "Slack",
    IntegrationKind.EMAIL: "Email",
    IntegrationKind.DIFY: "Dify Knowledge Base",
    IntegrationKind.MISP: "MISP",
    IntegrationKind.NVD: "NVD",
    IntegrationKind.GITHUB: "GitHub",
    IntegrationKind.GITLAB: "GitLab",
}


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------


def _fingerprint(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()[:8]


def _hint(plaintext: str) -> str:
    """Last four characters, or fewer for a short value.

    A three-character secret would otherwise be fully disclosed by its own hint.
    """
    return plaintext[-4:] if len(plaintext) >= 8 else ""


def _reject_secret_shaped_config(config: Mapping[str, Any]) -> None:
    offenders = sorted(
        key for key in config if any(marker in key.lower() for marker in _SECRET_KEY_MARKERS)
    )
    if offenders:
        raise InvalidConfigurationError(
            "secret-shaped key in integration config",
            user_message=(
                "These settings look like credentials and must be sent as credentials, "
                f"not configuration: {', '.join(offenders)}."
            ),
            context={"keys": offenders},
        )


def _spec_for(kind: IntegrationKind) -> _KindSpec:
    spec = _SPECS.get(kind)
    if spec is None:
        raise IntegrationNotConfiguredError(
            kind.value,
            hint=f"{kind.value} integrations are not available in this release.",
        )
    return spec


def _decrypt(credential: IntegrationCredential, *, settings: Settings) -> Secret | None:
    """Reveal one stored credential, or ``None`` if it cannot be decrypted.

    A row sealed with a key that is no longer configured is a real operational state (a
    key was rotated out without re-encrypting). It degrades to "this credential is
    missing", which surfaces as an honest ``IntegrationNotConfiguredError`` at the point
    of use, rather than propagating a decryption traceback out of a settings page.
    """
    cipher = get_cipher(settings)
    try:
        return cipher.decrypt(credential.ciphertext.decode("utf-8"))
    except (CredentialDecryptionError, UnicodeDecodeError):
        log.error(
            "integration.credential_undecryptable",
            credential_id=str(credential.id),
            name=credential.name,
            key_version=credential.key_version,
        )
        return None


def _apply_credentials(
    integration: Integration,
    submitted: Mapping[str, str],
    *,
    settings: Settings,
    actor_id: uuid.UUID | None,
    now: dt.datetime,
) -> list[str]:
    """Encrypt and store submitted credentials. Returns the slot names that changed.

    ``integration.credentials`` must already be loaded. An absent key keeps its stored
    value; a present-but-empty key deletes it. See the module docstring.
    """
    spec = _spec_for(integration.kind_enum)
    unknown = sorted(set(submitted) - set(spec.credentials))
    if unknown:
        raise InvalidConfigurationError(
            "unknown credential slot",
            user_message=(
                f"{integration.name} does not use these credentials: {', '.join(unknown)}. "
                f"Expected: {', '.join(sorted(spec.credentials))}."
            ),
            context={"unknown": unknown},
        )

    cipher = get_cipher(settings)
    existing = {credential.name: credential for credential in integration.credentials}
    changed: list[str] = []

    for name, plaintext in submitted.items():
        current = existing.get(name)
        if not plaintext:
            if current is not None:
                integration.credentials.remove(current)
                changed.append(name)
            continue
        fingerprint = _fingerprint(plaintext)
        if current is not None and current.fingerprint == fingerprint:
            continue  # Same value resubmitted; rewriting it would only churn ``rotated_at``.
        ciphertext = cipher.encrypt(plaintext).encode("utf-8")
        if current is None:
            integration.credentials.append(
                IntegrationCredential(
                    organization_id=integration.organization_id,
                    name=name,
                    ciphertext=ciphertext,
                    key_version=1,
                    fingerprint=fingerprint,
                    hint=_hint(plaintext),
                    created_by_id=actor_id,
                )
            )
        else:
            current.ciphertext = ciphertext
            current.fingerprint = fingerprint
            current.hint = _hint(plaintext)
            current.rotated_at = now
            current.key_version = 1
        changed.append(name)

    return changed


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def list_integrations(session: AsyncSession, principal: Principal) -> Sequence[Integration]:
    """Every configured integration for the principal's organization, credentials loaded."""
    principal.require(Permission.INTEGRATION_READ)
    stmt = tenant_select(
        Integration,
        principal.organization_id,
        selectinload(Integration.credentials),
    ).order_by(Integration.kind)
    return (await session.execute(stmt)).scalars().all()


async def find_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
) -> Integration | None:
    """The organization's integration of this kind, or ``None``.

    Returns the first when several rows share a kind. The unique constraint is on
    ``(organization_id, kind, name)``, so two named Jira instances are legal; MVP flows
    address integrations by kind alone and take the oldest deterministically.
    """
    stmt = (
        tenant_select(
            Integration,
            principal.organization_id,
            selectinload(Integration.credentials),
        )
        .where(Integration.kind == kind.value)
        .order_by(Integration.created_at)
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def get_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
) -> Integration:
    principal.require(Permission.INTEGRATION_READ)
    integration = await find_integration(session, principal, kind)
    if integration is None:
        raise ResourceNotFoundError(
            "integration not configured",
            user_message=f"No {kind.value} integration has been configured.",
            context={"kind": kind.value},
        )
    return integration


def integration_out(integration: Integration) -> IntegrationOut:
    """Serialize for the API. Requires ``credentials`` to be eager-loaded."""
    return IntegrationOut(
        id=integration.id,
        kind=integration.kind_enum,
        name=integration.name,
        status=integration.status_enum,
        is_enabled=integration.is_enabled,
        base_url=integration.base_url,
        config=dict(integration.config or {}),
        credentials=[
            CredentialOut(
                name=credential.name,
                fingerprint=credential.fingerprint,
                hint=credential.hint,
                key_version=credential.key_version,
                expires_at=credential.expires_at,
                last_used_at=credential.last_used_at,
                rotated_at=credential.rotated_at,
                created_at=credential.created_at,
            )
            for credential in sorted(integration.credentials, key=lambda c: c.name)
        ],
        last_verified_at=integration.last_verified_at,
        last_error=integration.last_error,
        last_error_at=integration.last_error_at,
        failure_count=integration.failure_count,
        created_at=integration.created_at,
    )


async def integration_health(
    session: AsyncSession,
    principal: Principal,
    *,
    redis: Redis | None = None,
) -> list[IntegrationHealthOut]:
    """Dashboard rows (FR-031), including live circuit-breaker state.

    The breaker lives in Redis and is keyed per provider, so it is deployment-wide rather
    than per-organization -- an open circuit means Cynux is not calling that provider for
    anyone. Reported here anyway because "why are my tickets not being created" is
    answered by exactly that fact.
    """
    principal.require(Permission.INTEGRATION_READ)
    rows = await list_integrations(session, principal)
    out: list[IntegrationHealthOut] = []
    for integration in rows:
        circuit_open = False
        if redis is not None:
            status = await CircuitBreaker(redis, provider=integration.kind).status()
            circuit_open = status.is_open
        out.append(
            IntegrationHealthOut(
                kind=integration.kind_enum,
                name=integration.name,
                status=integration.status_enum,
                is_enabled=integration.is_enabled,
                last_verified_at=integration.last_verified_at,
                failure_count=integration.failure_count,
                circuit_open=circuit_open,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Settings projection
# ---------------------------------------------------------------------------


def _overlay(
    base: Settings,
    integration: Integration,
    credentials: Mapping[str, Secret],
) -> Settings:
    spec = _spec_for(integration.kind_enum)
    scoped = base.model_copy(deep=True)
    section = getattr(scoped, spec.section)

    if spec.base_url_field and integration.base_url:
        setattr(section, spec.base_url_field, integration.base_url)

    stored_config = integration.config or {}
    for key, target in spec.config.items():
        if key in stored_config and stored_config[key] is not None:
            setattr(section, target, stored_config[key])

    for name, target in spec.credentials.items():
        secret = credentials.get(name)
        if secret is not None:
            # Every credential-bearing settings field is a ``SecretStr``; wrapping here
            # keeps the plaintext inside a type that will not render itself into a log.
            setattr(section, target, SecretStr(secret.reveal()))

    return scoped


def credentials_for(
    integration: Integration,
    *,
    settings: Settings,
    mark_used: bool = True,
) -> dict[str, Secret]:
    """Decrypt every credential on an already-loaded integration.

    Synchronous, and takes no session: it only reads bytes already in memory and mutates
    loaded objects. ``mark_used`` stamps ``last_used_at``, which is how an operator
    distinguishes a credential that is actually in the request path from one left over
    from a half-finished setup. That is a write, so the caller still owns the transaction.
    """
    now = utcnow()
    resolved: dict[str, Secret] = {}
    for credential in integration.credentials:
        secret = _decrypt(credential, settings=settings)
        if secret is None:
            continue
        resolved[credential.name] = secret
        if mark_used:
            credential.last_used_at = now
    return resolved


async def resolve_settings(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    *,
    settings: Settings,
    require: bool = False,
) -> Settings:
    """Deployment settings with this organization's integration row overlaid.

    This is the function every organization-scoped provider call should go through. With
    no row configured it returns ``settings`` unchanged, so a single-tenant deployment
    that configures everything through the environment keeps working with no rows at all.

    ``require=True`` raises :class:`IntegrationNotConfiguredError` when the resulting
    configuration still lacks a required credential -- use it at the point of a real
    outbound call, so the error names the provider the user was waiting on.
    """
    integration = await find_integration(session, principal, kind)
    if integration is None:
        if require:
            _assert_env_configured(settings, kind)
        return settings
    if not integration.is_usable:
        raise IntegrationNotConfiguredError(
            kind.value,
            hint=f"The {integration.name} integration is disabled.",
        )

    credentials = credentials_for(integration, settings=settings)
    if require:
        spec = _spec_for(kind)
        missing = [name for name in spec.required if name not in credentials]
        if missing:
            raise IntegrationNotConfiguredError(
                kind.value,
                hint=f"Missing credential(s): {', '.join(missing)}.",
            )
    return _overlay(settings, integration, credentials)


def _assert_env_configured(settings: Settings, kind: IntegrationKind) -> None:
    """Check the deployment-wide fallback before reporting a provider unusable."""
    spec = _spec_for(kind)
    section = getattr(settings, spec.section)
    for name in spec.required:
        value = getattr(section, spec.credentials[name], None)
        if not value:
            raise IntegrationNotConfiguredError(
                kind.value,
                hint=f"Configure the {kind.value} integration, or set it in the environment.",
            )


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


async def upsert_integration(
    session: AsyncSession,
    principal: Principal,
    payload: IntegrationUpsertIn,
    *,
    settings: Settings,
) -> Integration:
    """Create or update one integration, encrypting any submitted credentials (FR-032).

    Configuration and credential changes are audited as two separate actions even though
    they arrive in one request: ``INTEGRATION_CONFIGURE`` is routine and
    ``INTEGRATION_CREDENTIAL_UPDATE`` is the one an incident responder greps for. Only the
    *names* of the changed credential slots are recorded -- never a value, not even a
    fingerprint, since a fingerprint over a low-entropy secret is guessable.
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    kind = payload.kind
    if kind in _UNIMPLEMENTED:
        raise InvalidConfigurationError(
            "integration kind not implemented",
            user_message=(
                f"{kind.value} integrations are not available in this release. "
                "Configuration for them cannot be saved yet."
            ),
            context={"kind": kind.value},
        )
    spec = _spec_for(kind)
    _reject_secret_shaped_config(payload.config)

    unknown_config = sorted(set(payload.config) - set(spec.config))
    if unknown_config:
        raise InvalidConfigurationError(
            "unknown integration config key",
            user_message=(
                f"Unrecognized settings for {kind.value}: {', '.join(unknown_config)}. "
                f"Expected: {', '.join(sorted(spec.config)) or 'none'}."
            ),
            context={"unknown": unknown_config},
        )

    now = utcnow()
    integration = await find_integration(session, principal, kind)
    created = integration is None
    if integration is None:
        integration = Integration(
            organization_id=principal.organization_id,
            kind=kind.value,
            name=payload.name or _DEFAULT_NAMES[kind],
            status=IntegrationStatus.UNVERIFIED.value,
            is_enabled=payload.is_enabled,
            base_url=payload.base_url,
            config=dict(payload.config),
            created_by_id=principal.user_id,
        )
        session.add(integration)
        # Flushed before credentials are attached so the child rows have a parent id and
        # so a unique-constraint violation surfaces here rather than at the route's commit.
        await session.flush()
        await session.refresh(integration, ["credentials"])
    else:
        if payload.name:
            integration.name = payload.name
        if payload.base_url is not None:
            integration.base_url = payload.base_url
        integration.is_enabled = payload.is_enabled
        # Merged, not replaced: a form that submits one field must not blank the rest.
        integration.config = {**(integration.config or {}), **payload.config}

    changed = _apply_credentials(
        integration,
        payload.credentials,
        settings=settings,
        actor_id=principal.user_id,
        now=now,
    )

    # Any change invalidates the previous verdict: the old one described a configuration
    # that no longer exists. Re-verification is an explicit test call.
    integration.status = (
        IntegrationStatus.DISABLED.value
        if not integration.is_enabled
        else IntegrationStatus.UNVERIFIED.value
    )
    integration.last_verified_at = None
    integration.last_error = None
    integration.last_error_at = None
    integration.failure_count = 0
    await session.flush()

    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_CONFIGURE,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id,
        detail={
            "kind": kind.value,
            "created": created,
            "is_enabled": integration.is_enabled,
            "config_keys": sorted(payload.config),
        },
    )
    if changed:
        await audit_service.record(
            session,
            action=AuditAction.INTEGRATION_CREDENTIAL_UPDATE,
            principal=principal,
            resource_type="integration",
            resource_id=integration.id,
            detail={"kind": kind.value, "slots": sorted(changed)},
        )
    log.info(
        "integration.configured",
        kind=kind.value,
        integration_id=str(integration.id),
        created=created,
        credential_slots=len(changed),
    )
    return integration


async def disable_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
) -> Integration:
    """Stop using an integration without discarding its credentials.

    Deliberately not a delete. Turning an integration off during an incident and back on
    afterwards should not require an operator to find the API token again.
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    integration = await get_integration(session, principal, kind)
    integration.is_enabled = False
    integration.status = IntegrationStatus.DISABLED.value
    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_DISABLE,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id,
        detail={"kind": kind.value},
    )
    log.info("integration.disabled", kind=kind.value, integration_id=str(integration.id))
    return integration


# ---------------------------------------------------------------------------
# Connectivity probe
# ---------------------------------------------------------------------------


async def _ping(kind: IntegrationKind, scoped: Settings, redis: Redis | None) -> bool:
    if kind is IntegrationKind.DEFECTDOJO:
        return await DefectDojoClient(scoped, redis).ping()
    if kind is IntegrationKind.JIRA:
        return await JiraClient(scoped, redis).ping()
    if kind is IntegrationKind.SLACK:
        return await SlackClient(scoped, redis).ping()
    if kind is IntegrationKind.DIFY:
        return await DifyClient(scoped, redis).ping()
    if kind is IntegrationKind.MISP:
        return await MISPClient(scoped, redis).ping()
    if kind is IntegrationKind.EMAIL:
        return await EmailSender(scoped).ping()
    # NVD needs no credential and has no cheap authenticated endpoint to probe; reporting
    # it healthy on the strength of its configuration is more honest than an unrelated
    # request that would count against the shared rate limit.
    if kind is IntegrationKind.NVD:
        return True
    raise IntegrationNotConfiguredError(
        kind.value, hint=f"{kind.value} cannot be tested in this release."
    )


async def test_integration(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    *,
    settings: Settings,
    redis: Redis | None = None,
) -> IntegrationTestOut:
    """Probe a provider live and record the verdict on the row (FR-028, FR-032).

    Never raises for a provider-side failure: an unreachable Jira is the *answer* to
    "test this integration", not an error in answering. Only a caller-side problem
    (missing permission, no such integration) raises. The recorded ``last_error`` is the
    user-safe message from the error taxonomy -- never a provider response body, which
    can echo back a credential (SEC-002).
    """
    principal.require(Permission.INTEGRATION_MANAGE)
    integration = await find_integration(session, principal, kind)
    now = utcnow()
    started = time.monotonic()

    healthy = False
    detail: str | None = None
    try:
        scoped = await resolve_settings(session, principal, kind, settings=settings, require=True)
        healthy = await _ping(kind, scoped, redis)
        detail = "Reachable and authenticated." if healthy else "Provider rejected the probe."
    except CynuxError as exc:
        detail = exc.user_message
        log.warning(
            "integration.test_failed",
            kind=kind.value,
            code=exc.code,
            **exc.to_log_fields(),
        )
    except Exception as exc:  # - an unexpected client bug is still a test result
        detail = "The connectivity test failed unexpectedly. See the server logs."
        log.error("integration.test_error", kind=kind.value, error=type(exc).__name__)

    latency_ms = int((time.monotonic() - started) * 1000)

    if integration is not None:
        if healthy:
            integration.status = IntegrationStatus.CONFIGURED.value
            integration.last_verified_at = now
            integration.last_error = None
            integration.last_error_at = None
            integration.failure_count = 0
        else:
            integration.status = IntegrationStatus.ERROR.value
            integration.last_error = detail
            integration.last_error_at = now
            integration.failure_count += 1

    await audit_service.record(
        session,
        action=AuditAction.INTEGRATION_TEST,
        principal=principal,
        resource_type="integration",
        resource_id=integration.id if integration is not None else None,
        outcome=AuditOutcome.SUCCESS if healthy else AuditOutcome.FAILURE,
        detail={"kind": kind.value, "latency_ms": latency_ms},
        reason=None if healthy else detail,
    )
    return IntegrationTestOut(
        kind=kind,
        healthy=healthy,
        detail=detail,
        latency_ms=latency_ms,
        checked_at=now,
    )


async def record_failure(
    session: AsyncSession,
    principal: Principal,
    kind: IntegrationKind,
    error: IntegrationError,
) -> None:
    """Note a provider failure observed during normal work, not during a test.

    Best-effort and silent: it is called from an exception path, and a bookkeeping failure
    must not replace the original provider error with a less useful one.
    """
    try:
        integration = await find_integration(session, principal, kind)
        if integration is None:
            return
        integration.failure_count += 1
        integration.last_error = error.user_message
        integration.last_error_at = utcnow()
        if integration.status == IntegrationStatus.CONFIGURED.value:
            integration.status = IntegrationStatus.ERROR.value
    except Exception:  # - see docstring
        log.warning("integration.failure_not_recorded", kind=kind.value, exc_info=True)


__all__ = [
    "credentials_for",
    "disable_integration",
    "find_integration",
    "get_integration",
    "integration_health",
    "integration_out",
    "list_integrations",
    "record_failure",
    "resolve_settings",
    "test_integration",
    "upsert_integration",
]
