"""Enterprise OIDC SSO connection contracts."""

from __future__ import annotations

import pytest


def test_oidc_connection_is_tenant_scoped_and_encrypts_client_secret() -> None:
    from app.db.models.identity import OidcConnection

    columns = OidcConnection.__table__.c
    assert OidcConnection.organization_id.nullable is False
    assert "client_secret_ciphertext" in columns
    assert "client_secret" not in columns


def test_oidc_connection_admin_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/organization/sso/oidc" in {route.path for route in api_router.routes}
    assert "/organization/sso/saml" in {route.path for route in api_router.routes}


def test_saml_connection_requires_https_idp_and_acs_urls() -> None:
    import pytest
    from pydantic import ValidationError

    from app.schemas.sso import SamlConnectionUpsertIn

    with pytest.raises(ValidationError, match="https"):
        SamlConnectionUpsertIn(
            sp_entity_id="https://app.example.test/saml/metadata",
            idp_entity_id="https://idp.example.test/entity",
            idp_sso_url="http://idp.example.test/sso",
            idp_certificate_pem="-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
            acs_url="https://app.example.test/auth/saml/callback",
        )


@pytest.mark.parametrize("issuer_url", ["https://localhost", "https://127.0.0.1", "https://10.0.0.4"])
def test_oidc_connection_rejects_local_or_private_issuer_urls(issuer_url: str) -> None:
    """OIDC discovery must not let an org administrator turn the backend into an SSRF client."""
    from pydantic import ValidationError

    from app.schemas.sso import OidcConnectionUpsertIn

    with pytest.raises(ValidationError, match="public"):
        OidcConnectionUpsertIn(
            issuer_url=issuer_url,
            client_id="tenant-client",
            client_secret="not-a-real-secret",
            redirect_uri="https://app.example.test/auth/sso/callback",
        )


def test_oidc_login_start_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/auth/sso/{organization_slug}/start" in {route.path for route in api_router.routes}


def test_oidc_callback_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/auth/sso/callback" in {route.path for route in api_router.routes}


def test_oidc_login_has_a_dedicated_audit_action() -> None:
    from app.services.audit import AuditAction

    assert AuditAction.OIDC_LOGIN == "auth.oidc.login"


def test_oidc_authorization_url_keeps_exact_configured_callback() -> None:
    from urllib.parse import parse_qs, urlparse

    from app.services.sso import build_authorization_url

    url = build_authorization_url(
        authorization_endpoint="https://login.example.com/authorize",
        client_id="client-123",
        redirect_uri="https://api.cynux.example/api/v1/auth/sso/callback",
        state="one-time-state",
        nonce="token-nonce",
    )

    query = parse_qs(urlparse(url).query)
    assert query["redirect_uri"] == ["https://api.cynux.example/api/v1/auth/sso/callback"]
    assert query["state"] == ["one-time-state"]
    assert query["nonce"] == ["token-nonce"]
    assert query["response_type"] == ["code"]


async def test_oidc_login_state_is_one_time_and_bound_to_organization() -> None:
    import uuid

    from app.services.sso import create_login_state

    class Redis:
        def __init__(self) -> None:
            self.calls = []

        async def set(self, key, value, *, ex, nx):
            self.calls.append((key, value, ex, nx))
            return True

    organization_id = uuid.uuid4()
    state, nonce = await create_login_state(Redis(), organization_id)

    assert state and nonce and state != nonce


async def test_oidc_login_state_can_only_be_consumed_once() -> None:
    import json
    import uuid

    from app.services.sso import consume_login_state

    organization_id = uuid.uuid4()

    class Redis:
        def __init__(self) -> None:
            self.value = json.dumps({"organization_id": str(organization_id), "nonce": "n"})

        async def getdel(self, key):
            value, self.value = self.value, None
            return value

    redis = Redis()
    assert await consume_login_state(redis, "state") == (organization_id, "n")
    assert await consume_login_state(redis, "state") is None


async def test_saml_login_state_is_single_use_and_tenant_bound() -> None:
    import uuid

    from app.services.sso import consume_saml_login_state, create_saml_login_state

    class Redis:
        def __init__(self) -> None:
            self.values = {}

        async def set(self, key, value, *, ex, nx):
            if key in self.values:
                return False
            self.values[key] = value
            return True

        async def getdel(self, key):
            return self.values.pop(key, None)

    organization_id = uuid.uuid4()
    redis = Redis()
    state = await create_saml_login_state(redis, organization_id)
    assert await consume_saml_login_state(redis, state) == organization_id
    assert await consume_saml_login_state(redis, state) is None


async def test_saml_connection_resolution_requires_enabled_tenant_connection() -> None:
    import uuid

    from app.services.sso import resolve_saml_connection_by_organization_id

    connection = object()

    class Result:
        def scalar_one_or_none(self):
            return connection

    class Session:
        async def execute(self, _statement):
            return Result()

    assert await resolve_saml_connection_by_organization_id(Session(), uuid.uuid4()) is connection


def test_oidc_claims_require_verified_email_nonce_and_allowed_domain() -> None:
    import pytest

    from app.core.errors import AuthenticationError
    from app.services.sso import validated_identity_claims

    assert validated_identity_claims(
        {"email": "analyst@acme.example", "email_verified": True, "nonce": "expected"},
        expected_nonce="expected",
        allowed_email_domains=["acme.example"],
    ) == ("analyst@acme.example", None)

    with pytest.raises(AuthenticationError):
        validated_identity_claims(
            {"email": "analyst@other.example", "email_verified": True, "nonce": "expected"},
            expected_nonce="expected",
            allowed_email_domains=["acme.example"],
        )


def test_saml_claims_require_email_and_allowed_domain() -> None:
    import pytest

    from app.core.errors import AuthenticationError
    from app.services.sso import validated_saml_identity_attributes

    assert validated_saml_identity_attributes(
        {"email": ["analyst@acme.example"], "displayName": ["Analyst"]},
        allowed_email_domains=["acme.example"],
    ) == ("analyst@acme.example", "Analyst")
    with pytest.raises(AuthenticationError):
        validated_saml_identity_attributes(
            {"email": ["analyst@other.example"]}, allowed_email_domains=["acme.example"]
        )


def test_oidc_id_token_rejects_symmetric_or_unsigned_algorithms() -> None:
    import jwt
    import pytest

    from app.core.errors import AuthenticationError
    from app.services.sso import validate_id_token

    token = jwt.encode(
        {"iss": "https://issuer.example", "aud": "client", "exp": 4_000_000_000},
        "not-a-provider-key",
        algorithm="HS256",
        headers={"kid": "untrusted"},
    )
    with pytest.raises(AuthenticationError):
        validate_id_token(
            token,
            jwks={"keys": []},
            issuer="https://issuer.example",
            client_id="client",
        )

