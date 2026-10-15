"""Public platform API credential storage contracts."""

from __future__ import annotations


def test_platform_api_key_never_persists_plaintext_secret() -> None:
    from app.db.models.platform import PlatformApiKey

    columns = PlatformApiKey.__table__.c
    assert "secret_hash" in columns
    assert "secret" not in columns
    assert columns.organization_id.nullable is False


async def test_create_platform_api_key_returns_secret_once_and_stores_only_hash() -> None:
    import uuid

    from app.db.enums import Role
    from app.schemas.platform import PlatformApiKeyCreateIn
    from app.services.context import Principal
    from app.services.platform_api_key import create_platform_api_key

    class Session:
        def __init__(self) -> None:
            self.added = []

        def add(self, row) -> None:
            self.added.append(row)

        async def flush(self) -> None:
            return None

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    issued = await create_platform_api_key(
        Session(), principal, PlatformApiKeyCreateIn(name="CI", scopes=["finding:read"])
    )

    assert issued.secret.startswith("cynux_")
    assert issued.key.secret_hash != issued.secret
    assert issued.key.organization_id == principal.organization_id


def test_platform_api_key_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/platform/api-keys" in {route.path for route in api_router.routes}


def test_platform_api_key_api_exposes_safe_list() -> None:
    from app.api.v1.platform import router

    methods = {
        method
        for route in router.routes
        if route.path == "/platform/api-keys"
        for method in route.methods
    }
    assert "GET" in methods


def test_platform_api_key_api_exposes_revocation() -> None:
    from app.api.v1.platform import router

    assert "/platform/api-keys/{key_id}/revoke" in {route.path for route in router.routes}


def test_platform_api_key_lifecycle_has_dedicated_audit_actions() -> None:
    from app.services.audit import AuditAction

    assert AuditAction.PLATFORM_API_KEY_CREATE == "platform_api_key.create"
    assert AuditAction.PLATFORM_API_KEY_REVOKE == "platform_api_key.revoke"


async def test_platform_api_key_authentication_rejects_revoked_key() -> None:
    import datetime as dt
    from types import SimpleNamespace

    from app.core.errors import AuthenticationError
    from app.services.platform_api_key import authenticate_platform_api_key

    key = SimpleNamespace(
        key_prefix="cynux_example123",
        secret_hash="unused",
        revoked_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        expires_at=None,
    )

    class Session:
        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: key)

    try:
        await authenticate_platform_api_key(Session(), "cynux_example123_secret")
    except AuthenticationError:
        return
    raise AssertionError("revoked API key must be rejected")


def test_machine_principal_enforces_key_scopes_not_role_permissions() -> None:
    import uuid

    import pytest

    from app.core.errors import PermissionDeniedError
    from app.db.enums import Permission, Role
    from app.services.context import Principal

    principal = Principal(
        user_id=None,
        organization_id=uuid.uuid4(),
        role=Role.OWNER,
        permission_override=frozenset({Permission.FINDING_READ}),
    )
    principal.require(Permission.FINDING_READ)
    with pytest.raises(PermissionDeniedError):
        principal.require(Permission.ORG_MANAGE)


async def test_current_principal_accepts_scoped_machine_key(monkeypatch) -> None:
    import uuid
    from types import SimpleNamespace

    from app.api import deps
    from app.db.enums import Permission

    organization_id = uuid.uuid4()
    key = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        scopes=[Permission.FINDING_READ.value],
    )

    async def authenticate(session, secret):
        assert secret.startswith("cynux_")
        return key

    monkeypatch.setattr(deps, "authenticate_platform_api_key", authenticate)
    principal = await deps.current_principal(
        SimpleNamespace(
            client=SimpleNamespace(host="203.0.113.10"),
            headers={"user-agent": "platform-ci"},
            state=SimpleNamespace(request_id="req-1", trace_id="trace-1"),
        ),
        object(),
        object(),
        object(),
        SimpleNamespace(credentials="cynux_example_machine_key"),
    )

    assert principal.organization_id == organization_id
    assert principal.credential_id == key.id
    assert principal.permissions == frozenset({Permission.FINDING_READ})
    assert principal.source_ip == "203.0.113.10"
    assert principal.request_id == "req-1"


def test_machine_principal_scope_survives_agent_derivation_and_serialization() -> None:
    import uuid

    from app.db.enums import Permission, Role
    from app.services.context import Principal

    original = Principal(
        user_id=None,
        organization_id=uuid.uuid4(),
        role=Role.OWNER,
        permission_override=frozenset({Permission.FINDING_READ}),
    )
    assert original.for_agent(organization_id=original.organization_id, on_behalf_of=original).permissions == original.permissions
    assert Principal.from_dict(original.to_dict()).permissions == original.permissions


def test_machine_principal_has_distinct_audit_actor_type() -> None:
    import uuid

    from app.db.enums import Role
    from app.services.context import ACTOR_API_KEY, Principal

    principal = Principal.for_api_key(organization_id=uuid.uuid4(), scopes=frozenset())
    assert principal.actor_type == ACTOR_API_KEY
    assert principal.role is Role.OWNER
