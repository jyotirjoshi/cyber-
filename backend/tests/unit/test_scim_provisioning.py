"""SCIM provisioning credentials are tenant-scoped and never stored in plaintext."""

from __future__ import annotations

import uuid


def test_scim_provisioning_token_never_persists_plaintext_secret() -> None:
    from app.db.models.identity import ScimProvisioningToken

    columns = ScimProvisioningToken.__table__.c
    assert "secret_hash" in columns
    assert "secret" not in columns
    assert ScimProvisioningToken.organization_id.nullable is False


async def test_issue_scim_provisioning_token_returns_secret_once_and_stores_only_hash() -> None:
    from app.db.enums import Role
    from app.schemas.scim import ScimProvisioningTokenCreateIn
    from app.services.context import Principal
    from app.services.scim import issue_provisioning_token

    class Session:
        def __init__(self) -> None:
            self.added = []

        def add(self, row) -> None:
            self.added.append(row)

        async def flush(self) -> None:
            return None

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    issued = await issue_provisioning_token(
        Session(), principal, ScimProvisioningTokenCreateIn(name="Okta production")
    )

    assert issued.secret.startswith("cynux_scim_")
    assert issued.token.secret_hash != issued.secret
    assert issued.token.organization_id == principal.organization_id


async def test_authenticate_scim_provisioning_token_rejects_revoked_or_expired_tokens() -> None:
    import datetime as dt
    from types import SimpleNamespace

    import pytest

    from app.core.errors import AuthenticationError
    from app.core.security import hash_password
    from app.services.scim import authenticate_provisioning_token

    secret = "cynux_scim_test-provisioner-secret"
    token = SimpleNamespace(
        key_prefix=secret[:24],
        secret_hash=hash_password(secret),
        revoked_at=dt.datetime.now(dt.UTC),
        expires_at=None,
    )

    class Session:
        async def execute(self, statement):
            return SimpleNamespace(scalar_one_or_none=lambda: token)

    with pytest.raises(AuthenticationError):
        await authenticate_provisioning_token(Session(), secret)


def test_scim_provisioning_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/organization/scim/tokens" in {route.path for route in api_router.routes}


def test_scim_user_protocol_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/scim/v2/Users" in {route.path for route in api_router.routes}


def test_scim_supports_individual_user_lookup() -> None:
    from app.api.v1.scim import router

    methods = {
        method
        for route in router.routes
        if route.path == "/scim/v2/Users/{membership_id}"
        for method in route.methods
    }
    assert "GET" in methods
    assert "PATCH" in methods


def test_scim_create_rejects_inactive_user_payload() -> None:
    import pytest
    from pydantic import ValidationError

    from app.api.v1.scim import ScimUserIn

    with pytest.raises(ValidationError, match="active users"):
        ScimUserIn(userName="person@example.com", active=False)


def test_scim_user_filter_only_accepts_exact_username_equality() -> None:
    import pytest

    from app.api.v1.scim import parse_user_name_filter

    assert parse_user_name_filter('userName eq "Alice@example.com"') == "alice@example.com"
    with pytest.raises(ValueError, match="userName eq"):
        parse_user_name_filter('displayName co "alice"')

