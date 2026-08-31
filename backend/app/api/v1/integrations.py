"""Integration configuration endpoints (FR-028, FR-032, SEC-002).

WHY the service stages writes and the router commits: :mod:`app.services.integration` follows
the house rule that a service flushes and audits but never commits, so a handler that raises
before its commit persists nothing. Every mutating endpoint here therefore ends its success
path with ``await session.commit()`` -- including ``test``, which never raises for a provider
failure (an unreachable Jira is the *answer*, not an error) but does record the verdict on the
row, so without the commit the probe result would be discarded.

WHY the upsert reloads before projecting: ``created_at``/``updated_at`` are ``server_default``
columns with no client-side default (:class:`app.db.base.TimestampMixin`). A freshly-inserted
integration or credential row therefore has those attributes *expired* after flush, and reading
one on the async session would trigger implicit IO -- a ``MissingGreenlet`` crash inside the
synchronous :func:`app.services.integration.integration_out`. The row is re-read with
:func:`app.services.integration.find_integration` (which carries no permission check, so a
``INTEGRATION_MANAGE`` principal need not also hold ``INTEGRATION_READ``) after the commit,
which repopulates every column from the database.

No endpoint here returns a secret: :func:`integration_out` exposes only a fingerprint and a
four-character hint, and the connectivity probe returns a user-safe summary -- provider response
bodies are logged, never echoed (SEC-002).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import DbSession, PrincipalDep, RedisDep, SettingsDep
from app.db.enums import IntegrationKind
from app.schemas.integration import (
    IntegrationHealthOut,
    IntegrationOut,
    IntegrationTestOut,
    IntegrationUpsertIn,
)
from app.services import integration as integration_service

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=list[IntegrationOut])
async def list_integrations(
    principal: PrincipalDep,
    session: DbSession,
) -> list[IntegrationOut]:
    """Every configured integration for the organization, secrets redacted (FR-028)."""
    rows = await integration_service.list_integrations(session, principal)
    return [integration_service.integration_out(row) for row in rows]


@router.get("/health", response_model=list[IntegrationHealthOut])
async def integration_health(
    principal: PrincipalDep,
    session: DbSession,
    redis: RedisDep,
) -> list[IntegrationHealthOut]:
    """One health row per integration, including live circuit-breaker state (FR-031, FR-020).

    Declared before ``/{kind}`` so ``GET /integrations/health`` is not swallowed as a ``kind``
    path parameter. ``redis`` is passed so the breaker state is real rather than assumed closed.
    """
    return await integration_service.integration_health(session, principal, redis=redis)


@router.post("", response_model=IntegrationOut)
async def upsert_integration(
    payload: IntegrationUpsertIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> IntegrationOut:
    """Create or update one integration, encrypting any submitted credentials (FR-028, FR-032).

    Credentials are write-only: they are encrypted on receipt and never returned. Omitting a
    credential slot keeps its stored value; sending an empty string clears it (enforced in the
    service). The row is re-read after the commit before projecting, because a freshly-inserted
    row's ``server_default`` timestamps are expired until reloaded (see the module docstring).
    """
    await integration_service.upsert_integration(session, principal, payload, settings=settings)
    await session.commit()
    reloaded = await integration_service.find_integration(session, principal, payload.kind)
    assert reloaded is not None  # noqa: S101 - just upserted under this tenant and kind
    return integration_service.integration_out(reloaded)


@router.get("/{kind}", response_model=IntegrationOut)
async def get_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
) -> IntegrationOut:
    """One integration by kind. A kind that is not configured is a 404."""
    integration = await integration_service.get_integration(session, principal, kind)
    return integration_service.integration_out(integration)


@router.delete("/{kind}", response_model=IntegrationOut)
async def disable_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
) -> IntegrationOut:
    """Disable an integration without discarding its credentials (FR-032).

    Deliberately not a hard delete: turning an integration off during an incident and back on
    afterwards must not force an operator to re-enter the API token. The returned row is the
    now-disabled integration, so the UI can update in place. The row was fully loaded by the
    service (via ``get_integration``), so it is projected directly after the commit -- no
    freshly-inserted columns are in play.
    """
    integration = await integration_service.disable_integration(session, principal, kind)
    await session.commit()
    return integration_service.integration_out(integration)


@router.post("/{kind}/test", response_model=IntegrationTestOut)
async def test_integration(
    kind: IntegrationKind,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> IntegrationTestOut:
    """Probe a provider live and persist the verdict on the row (FR-028, FR-032).

    Never fails for a provider-side problem -- an unreachable or rejecting provider is the
    result of the test, not an error in running it. The commit is required: the service stages
    the ``configured``/``error`` status, ``last_verified_at`` and the failure counter without
    committing, so omitting it here would return a verdict that was never saved.
    """
    result = await integration_service.test_integration(
        session, principal, kind, settings=settings, redis=redis
    )
    await session.commit()
    return result


__all__ = ["router"]
