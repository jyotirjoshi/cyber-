"""OIDC connection administration with encrypted client credentials."""

from __future__ import annotations

import json
import secrets
import uuid
from urllib.parse import urlencode, urlparse
from xml.sax.saxutils import escape as xml_escape

import httpx
import jwt
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, SAMLError
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from sqlalchemy import select

from app.core.config import Settings
from app.core.crypto import get_cipher
from app.core.errors import AuthenticationError, IntegrationError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.identity import OidcConnection, Organization, SamlConnection
from app.db.repository import tenant_select
from app.schemas.sso import OidcConnectionUpsertIn, SamlConnectionUpsertIn
from app.services.context import Principal

_STATE_TTL_SECONDS = 600
_HANDOFF_TTL_SECONDS = 60


def saml_service_provider_metadata(connection: SamlConnection) -> str:
    """Produce minimal SP metadata from administrator-controlled SAML connection fields.

    It intentionally advertises only the signed-response ACS endpoint; keys and IdP trust
    material never appear in a public metadata response.
    """
    entity_id = xml_escape(connection.sp_entity_id, {'"': "&quot;"})
    acs_url = xml_escape(connection.acs_url, {'"': "&quot;"})
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}"><SPSSODescriptor '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
        'WantAssertionsSigned="true"><AssertionConsumerService '
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs_url}" index="0" isDefault="true"/>'
        '</SPSSODescriptor></EntityDescriptor>'
    )


async def create_login_state(redis, organization_id: uuid.UUID) -> tuple[str, str]:
    """Store a single-use OIDC login state and its nonce for at most ten minutes."""
    for _ in range(3):
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        created = await redis.set(
            f"cynux:oidc:state:{state}",
            json.dumps({"organization_id": str(organization_id), "nonce": nonce}),
            ex=_STATE_TTL_SECONDS,
            nx=True,
        )
        if created:
            return state, nonce
    raise RuntimeError("unable to allocate OIDC login state")


async def consume_login_state(redis, state: str) -> tuple[uuid.UUID, str] | None:
    """Atomically consume login state, returning its tenant and expected nonce once."""
    raw = await redis.getdel(f"cynux:oidc:state:{state}")
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
        return uuid.UUID(payload["organization_id"]), str(payload["nonce"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


async def create_frontend_handoff(redis, tokens) -> str:
    """Store a session pair briefly and return an opaque one-time browser handoff token.

    The token pair is intentionally never placed in a query string or fragment: browser
    history, referer headers, and third-party scripts must not receive bearer credentials.
    """
    for _ in range(3):
        handoff = f"cynux_sso_{secrets.token_urlsafe(32)}"
        saved = await redis.set(
            f"cynux:oidc:handoff:{handoff}",
            tokens.model_dump_json(),
            ex=_HANDOFF_TTL_SECONDS,
            nx=True,
        )
        if saved:
            return handoff
    raise RuntimeError("unable to allocate SSO browser handoff")


async def consume_frontend_handoff(redis, handoff: str) -> dict[str, object] | None:
    """Atomically consume an opaque SSO handoff exactly once."""
    if not handoff.startswith("cynux_sso_"):
        return None
    raw = await redis.getdel(f"cynux:oidc:handoff:{handoff}")
    if raw is None:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def create_saml_login_state(
    redis, organization_id: uuid.UUID, *, request_id: str | None = None
) -> str:
    """Store an opaque one-time SAML request state bound to one tenant and request."""
    for _ in range(3):
        state = secrets.token_urlsafe(32)
        if await redis.set(
            f"cynux:saml:state:{state}",
            json.dumps(
                {"organization_id": str(organization_id), "request_id": request_id}
            ),
            ex=_STATE_TTL_SECONDS,
            nx=True,
        ):
            return state
    raise RuntimeError("unable to allocate SAML login state")


async def consume_saml_login_state(redis, state: str) -> uuid.UUID | None:
    """Atomically consume a SAML request state, returning its tenant only once."""
    consumed = await consume_saml_login_context(redis, state)
    return consumed[0] if consumed is not None else None


async def consume_saml_login_context(
    redis, state: str
) -> tuple[uuid.UUID, str | None] | None:
    """Consume the tenant and AuthnRequest identifier carried by RelayState."""
    raw = await redis.getdel(f"cynux:saml:state:{state}")
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
        request_id = payload.get("request_id")
        if request_id is not None and not isinstance(request_id, str):
            return None
        return uuid.UUID(payload["organization_id"]), request_id
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _saml_idp_metadata(connection: SamlConnection) -> str:
    """Build the smallest trusted IdP metadata document from tenant configuration."""
    certificate = "".join(
        line.strip()
        for line in connection.idp_certificate_pem.splitlines()
        if line.strip() and not line.startswith("-----")
    )
    entity_id = xml_escape(connection.idp_entity_id, {'"': "&quot;"})
    sso_url = xml_escape(connection.idp_sso_url, {'"': "&quot;"})
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id}"><IDPSSODescriptor '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><ds:KeyInfo '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>'
        f'<ds:X509Certificate>{certificate}</ds:X509Certificate>'
        '</ds:X509Data></ds:KeyInfo></KeyDescriptor>'
        '<SingleSignOnService '
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{sso_url}"/></IDPSSODescriptor></EntityDescriptor>'
    )


def build_saml_client(connection: SamlConnection) -> Saml2Client:
    """Create a tenant-local SAML client that trusts only its configured IdP key."""
    config = Saml2Config()
    config.load(
        {
            "entityid": connection.sp_entity_id,
            "metadata": {"inline": [_saml_idp_metadata(connection)]},
            "service": {
                "sp": {
                    "allow_unsolicited": False,
                    "authn_requests_signed": False,
                    "want_assertions_or_response_signed": True,
                    "want_assertions_signed": False,
                    "want_response_signed": False,
                    "endpoints": {
                        "assertion_consumer_service": [
                            (connection.acs_url, BINDING_HTTP_POST)
                        ]
                    },
                }
            },
        }
    )
    return Saml2Client(config=config)


def build_saml_authorization_redirect(
    connection: SamlConnection, *, relay_state: str, request_id: str
) -> str:
    """Create a Redirect-binding AuthnRequest and return its IdP location."""
    client = build_saml_client(connection)
    generated_id, info = client.prepare_for_authenticate(
        entityid=connection.idp_entity_id,
        relay_state=relay_state,
        binding=BINDING_HTTP_REDIRECT,
        response_binding=BINDING_HTTP_POST,
        message_id=request_id,
    )
    if generated_id != request_id:
        raise IntegrationError("SAML request identifier mismatch", provider="SAML")
    location = next(
        (value for name, value in info.get("headers", []) if name.lower() == "location"),
        None,
    )
    if not isinstance(location, str) or not location.startswith("https://"):
        raise IntegrationError("SAML identity provider redirect is invalid", provider="SAML")
    return location


def parse_saml_authentication_response(
    connection: SamlConnection, *, saml_response: str, request_id: str
) -> dict[str, object]:
    """Verify a POSTed SAML response and return its normalized attribute map."""
    try:
        response = build_saml_client(connection).parse_authn_request_response(
            saml_response,
            BINDING_HTTP_POST,
            outstanding={request_id: connection.acs_url},
        )
        if response is None:
            raise AuthenticationError("SAML response is empty or malformed")
        session_info = response.session_info()
        attributes = session_info.get("ava")
        if not isinstance(attributes, dict):
            raise AuthenticationError("SAML response contains no identity attributes")
        return dict(attributes)
    except AuthenticationError:
        raise
    except (SAMLError, KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError("SAML response validation failed") from exc


def validated_identity_claims(
    claims: dict[str, object], *, expected_nonce: str, allowed_email_domains: list[str]
) -> tuple[str, str | None]:
    """Extract an authorized, verified identity from a signature-checked ID token."""
    email = claims.get("email")
    if (
        not isinstance(email, str)
        or not email
        or claims.get("email_verified") is not True
        or claims.get("nonce") != expected_nonce
    ):
        raise AuthenticationError("invalid OIDC identity claims")
    normalized_email = email.strip().lower()
    domain = normalized_email.rpartition("@")[2]
    if allowed_email_domains and domain not in allowed_email_domains:
        raise AuthenticationError("OIDC email domain is not allowed")
    name = claims.get("name")
    return normalized_email, name.strip() if isinstance(name, str) and name.strip() else None


def validated_saml_identity_attributes(
    attributes: dict[str, object], *, allowed_email_domains: list[str]
) -> tuple[str, str | None]:
    """Extract a tenant-authorized identity from an already signature-verified SAML response."""
    def first_text(*names: str) -> str | None:
        for name in names:
            values = attributes.get(name)
            if isinstance(values, list) and values and isinstance(values[0], str) and values[0].strip():
                return values[0].strip()
        return None

    email = first_text("email", "emailAddress", "Email", "mail")
    if not email or "@" not in email:
        raise AuthenticationError("SAML assertion has no usable email attribute")
    normalized_email = email.lower()
    domain = normalized_email.rpartition("@")[2]
    if allowed_email_domains and domain not in allowed_email_domains:
        raise AuthenticationError("SAML email domain is not allowed")
    return normalized_email, first_text("displayName", "name", "cn")


def validate_id_token(
    id_token: str, *, jwks: dict[str, object], issuer: str, client_id: str
) -> dict[str, object]:
    """Verify an asymmetric OIDC ID token against the provider's JWKS.

    HMAC algorithms are intentionally forbidden: accepting them would let a client
    secret be confused with a signing key.  The provider selects a key with ``kid``;
    its advertised JWK algorithm must also match the compact-token header.
    """
    try:
        header = jwt.get_unverified_header(id_token)
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if algorithm not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"} or not key_id:
            raise AuthenticationError("OIDC ID token uses an unsupported signing algorithm")
        candidates = jwks.get("keys")
        if not isinstance(candidates, list):
            raise AuthenticationError("OIDC JWKS is malformed")
        jwk_data = next(
            (key for key in candidates if isinstance(key, dict) and key.get("kid") == key_id), None
        )
        if not isinstance(jwk_data, dict) or jwk_data.get("alg") not in (None, algorithm):
            raise AuthenticationError("OIDC signing key is not available")
        key = jwt.PyJWK.from_dict(jwk_data, algorithm=algorithm).key
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=[algorithm],
            audience=client_id,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        return dict(claims)
    except AuthenticationError:
        raise
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError("OIDC ID token validation failed") from exc


async def resolve_login_connection(session, organization_slug: str) -> OidcConnection:
    """Find the enabled OIDC connection without exposing another tenant's settings."""
    connection = (
        await session.execute(
            select(OidcConnection)
            .join(Organization, Organization.id == OidcConnection.organization_id)
            .where(
                Organization.slug == organization_slug,
                Organization.is_active.is_(True),
                OidcConnection.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise ResourceNotFoundError("SSO connection not found")
    return connection


async def resolve_connection_by_organization_id(
    session, organization_id: uuid.UUID
) -> OidcConnection:
    """Resolve only an enabled OIDC connection for a state-bound tenant."""
    connection = (
        await session.execute(
            select(OidcConnection).where(
                OidcConnection.organization_id == organization_id,
                OidcConnection.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise AuthenticationError("OIDC connection is no longer available")
    return connection


async def resolve_saml_login_connection(session, organization_slug: str) -> SamlConnection:
    """Find an enabled SAML connection without exposing another tenant's IdP settings."""
    connection = (
        await session.execute(
            select(SamlConnection)
            .join(Organization, Organization.id == SamlConnection.organization_id)
            .where(
                Organization.slug == organization_slug,
                Organization.is_active.is_(True),
                SamlConnection.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise ResourceNotFoundError("SAML SSO connection not found")
    return connection


async def resolve_saml_connection_by_organization_id(
    session, organization_id: uuid.UUID
) -> SamlConnection:
    """Resolve the enabled SAML connection selected by an already consumed login state."""
    connection = (
        await session.execute(
            select(SamlConnection).where(
                SamlConnection.organization_id == organization_id,
                SamlConnection.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise AuthenticationError("SAML connection is no longer available")
    return connection


async def discover_authorization_endpoint(connection: OidcConnection) -> str:
    """Fetch and validate OIDC discovery metadata for one configured issuer."""
    discovery_url = f"{connection.issuer_url}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise IntegrationError("OIDC discovery failed", provider="OIDC") from exc
    if document.get("issuer") != connection.issuer_url:
        raise IntegrationError("OIDC discovery issuer mismatch", provider="OIDC")
    endpoint = document.get("authorization_endpoint")
    if not isinstance(endpoint, str):
        raise IntegrationError("OIDC discovery has no authorization endpoint", provider="OIDC")
    endpoint_url = urlparse(endpoint)
    if endpoint_url.scheme != "https" or not endpoint_url.netloc:
        raise IntegrationError("OIDC discovery returned an unsafe authorization endpoint", provider="OIDC")
    return endpoint


async def exchange_authorization_code(
    connection: OidcConnection, code: str, *, settings: Settings
) -> dict[str, object]:
    """Exchange one authorization code and signature-verify its ID token."""
    discovery_url = f"{connection.issuer_url}/.well-known/openid-configuration"
    secret = get_cipher(settings).decrypt(connection.client_secret_ciphertext).reveal()
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            discovery_response = await client.get(discovery_url)
            discovery_response.raise_for_status()
            document = discovery_response.json()
            if document.get("issuer") != connection.issuer_url:
                raise AuthenticationError("OIDC discovery issuer mismatch")
            token_endpoint = document.get("token_endpoint")
            jwks_uri = document.get("jwks_uri")
            if not isinstance(token_endpoint, str) or not isinstance(jwks_uri, str):
                raise AuthenticationError("OIDC discovery is incomplete")
            if urlparse(token_endpoint).scheme != "https" or urlparse(jwks_uri).scheme != "https":
                raise AuthenticationError("OIDC discovery returned unsafe endpoints")
            token_response = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": connection.redirect_uri,
                },
                auth=(connection.client_id, secret),
            )
            token_response.raise_for_status()
            token_payload = token_response.json()
            id_token = token_payload.get("id_token")
            if not isinstance(id_token, str):
                raise AuthenticationError("OIDC token response has no ID token")
            jwks_response = await client.get(jwks_uri)
            jwks_response.raise_for_status()
            jwks = jwks_response.json()
    except AuthenticationError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise AuthenticationError("OIDC authorization-code exchange failed") from exc
    if not isinstance(jwks, dict):
        raise AuthenticationError("OIDC JWKS is malformed")
    return validate_id_token(
        id_token,
        jwks=jwks,
        issuer=connection.issuer_url,
        client_id=connection.client_id,
    )


def build_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
) -> str:
    """Build a standards-compliant OIDC authorization-code redirect.

    This intentionally accepts a discovered authorization endpoint rather than an
    admin-supplied value.  The caller validates discovery first, so an organization
    cannot accidentally turn its SSO configuration into an open redirect.
    """
    endpoint = urlparse(authorization_endpoint)
    if endpoint.scheme != "https" or not endpoint.netloc:
        raise ValueError("OIDC authorization endpoint must be an https URL")
    return f"{authorization_endpoint}?{urlencode({
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': redirect_uri,
        'state': state,
        'nonce': nonce,
    })}"


async def configure_oidc_connection(
    session, principal: Principal, payload: OidcConnectionUpsertIn, *, settings: Settings
) -> OidcConnection:
    """Create or replace the active tenant's confidential OIDC client settings."""
    principal.require(Permission.ORG_MANAGE)
    connection = (
        await session.execute(
            tenant_select(OidcConnection, principal.organization_id).with_for_update()
        )
    ).scalar_one_or_none()
    encrypted_secret = get_cipher(settings).encrypt(payload.client_secret)
    if connection is None:
        connection = OidcConnection(
            organization_id=principal.organization_id,
            created_by_id=principal.user_id,
            issuer_url=payload.issuer_url,
            client_id=payload.client_id,
            client_secret_ciphertext=encrypted_secret,
            redirect_uri=payload.redirect_uri,
            allowed_email_domains=payload.allowed_email_domains,
            is_enabled=payload.is_enabled,
        )
        session.add(connection)
    else:
        connection.issuer_url = payload.issuer_url
        connection.client_id = payload.client_id
        connection.client_secret_ciphertext = encrypted_secret
        connection.redirect_uri = payload.redirect_uri
        connection.allowed_email_domains = payload.allowed_email_domains
        connection.is_enabled = payload.is_enabled
    await session.flush()
    return connection


async def configure_saml_connection(
    session, principal: Principal, payload: SamlConnectionUpsertIn
) -> SamlConnection:
    """Create or replace one tenant's trusted SAML identity-provider settings."""
    principal.require(Permission.ORG_MANAGE)
    connection = (
        await session.execute(
            tenant_select(SamlConnection, principal.organization_id).with_for_update()
        )
    ).scalar_one_or_none()
    fields = {
        "sp_entity_id": payload.sp_entity_id,
        "idp_entity_id": payload.idp_entity_id,
        "idp_sso_url": payload.idp_sso_url,
        "idp_certificate_pem": payload.idp_certificate_pem,
        "acs_url": payload.acs_url,
        "allowed_email_domains": payload.allowed_email_domains,
        "is_enabled": payload.is_enabled,
    }
    if connection is None:
        connection = SamlConnection(
            organization_id=principal.organization_id, created_by_id=principal.user_id, **fields
        )
        session.add(connection)
    else:
        for name, value in fields.items():
            setattr(connection, name, value)
    await session.flush()
    return connection


__all__ = [
    "build_authorization_url",
    "build_saml_authorization_redirect",
    "build_saml_client",
    "configure_oidc_connection",
    "configure_saml_connection",
    "consume_frontend_handoff",
    "consume_login_state",
    "consume_saml_login_context",
    "consume_saml_login_state",
    "create_login_state",
    "create_frontend_handoff",
    "create_saml_login_state",
    "discover_authorization_endpoint",
    "exchange_authorization_code",
    "parse_saml_authentication_response",
    "resolve_login_connection",
    "resolve_connection_by_organization_id",
    "resolve_saml_login_connection",
    "resolve_saml_connection_by_organization_id",
    "saml_service_provider_metadata",
    "validate_id_token",
    "validated_identity_claims",
    "validated_saml_identity_attributes",
]
