"""Authentication and session endpoints (FR-001, FR-002, FR-032, SEC-002).

Thin by design: every security decision -- password custody, lockout, deny-list
revocation, tenant resolution -- lives in :mod:`app.services.auth`, and these handlers
only adapt HTTP to those calls and commit the unit of work. Two conventions are load-bearing.

**Routes commit; the session dependency does not.** ``get_db`` leaves committing to the
handler so a partial write cannot be persisted by a teardown after a raise. Each mutating
endpoint therefore ends its success path with ``await session.commit()``; the failed-login
counter and independent audit rows manage their own transactions and survive a rollback.

**Tokens and identity are separate responses.** Sign-in style endpoints return only a
:class:`TokenPairOut`; the client then reads ``GET /auth/me`` for the identity, role and
flattened permission set. The dev-only password-reset link the service may return is
discarded here and never placed in a response body -- it is a credential (SEC-002).
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response, status
from starlette.responses import RedirectResponse

from app.api.deps import CurrentClaims, CurrentUser, DbSession, DenyListDep, RedisDep, SettingsDep
from app.schemas.auth import (
    ChangePasswordIn,
    LoginIn,
    LogoutIn,
    MeOut,
    PasswordResetConfirmIn,
    PasswordResetRequestIn,
    RefreshIn,
    RegisterIn,
    SsoHandoffIn,
    SwitchOrganizationIn,
    TokenPairOut,
)
from app.schemas.common import OkOut
from app.services import auth as auth_service
from app.services import sso as sso_service
from app.services.audit import AuditAction, record
from app.services.context import Principal
from app.services.scim import provision_user

router = APIRouter(prefix="/auth", tags=["auth"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _ua(request: Request) -> str | None:
    return request.headers.get("user-agent")


@router.get("/sso/saml/{organization_slug}/metadata", include_in_schema=False)
async def saml_service_provider_metadata(
    organization_slug: str, session: DbSession
) -> Response:
    """Publish non-secret, tenant-specific SAML SP metadata for an IdP administrator."""
    connection = await sso_service.resolve_saml_login_connection(session, organization_slug)
    return Response(
        content=sso_service.saml_service_provider_metadata(connection),
        media_type="application/samlmetadata+xml",
    )


@router.get("/sso/saml/{organization_slug}/start", include_in_schema=False)
async def start_saml_sso_login(
    organization_slug: str,
    session: DbSession,
    redis: RedisDep,
) -> RedirectResponse:
    """Begin a tenant-bound SAML 2.0 Web Browser SSO flow."""
    connection = await sso_service.resolve_saml_login_connection(session, organization_slug)
    request_id = f"cynux_{secrets.token_urlsafe(24)}"
    relay_state = await sso_service.create_saml_login_state(
        redis,
        connection.organization_id,
        request_id=request_id,
    )
    location = sso_service.build_saml_authorization_redirect(
        connection,
        relay_state=relay_state,
        request_id=request_id,
    )
    return RedirectResponse(location, status_code=status.HTTP_302_FOUND)


@router.post("/sso/saml/callback", include_in_schema=False)
async def complete_saml_sso_login(
    saml_response: Annotated[
        str,
        Form(alias="SAMLResponse", min_length=1, max_length=2_000_000),
    ],
    relay_state: Annotated[
        str,
        Form(alias="RelayState", min_length=16, max_length=512),
    ],
    session: DbSession,
    redis: RedisDep,
    settings: SettingsDep,
) -> RedirectResponse:
    """Verify a signed SAML response, provision membership, and issue a session."""
    consumed = await sso_service.consume_saml_login_context(redis, relay_state)
    if consumed is None or consumed[1] is None:
        from app.core.errors import AuthenticationError

        raise AuthenticationError("SAML state is missing, expired, or already used")
    organization_id, request_id = consumed
    connection = await sso_service.resolve_saml_connection_by_organization_id(
        session, organization_id
    )
    attributes = sso_service.parse_saml_authentication_response(
        connection,
        saml_response=saml_response,
        request_id=request_id,
    )
    email, full_name = sso_service.validated_saml_identity_attributes(
        attributes,
        allowed_email_domains=connection.allowed_email_domains,
    )
    membership, user = await provision_user(
        session,
        connection,
        email=email,
        full_name=full_name,
        active=True,
    )
    tokens = auth_service.issue_sso_session(settings, user=user, membership=membership)
    await record(
        session,
        action=AuditAction.SAML_LOGIN,
        principal=Principal(
            user_id=user.id,
            organization_id=membership.organization_id,
            role=membership.role_enum,
            email=user.email,
        ),
        resource_type="saml_connection",
        resource_id=connection.id,
        detail={"idp_entity_id": connection.idp_entity_id},
    )
    await session.commit()
    handoff = await sso_service.create_frontend_handoff(redis, tokens)
    return RedirectResponse(
        f"{settings.public_base_url.rstrip('/')}/sso/callback#ticket={handoff}",
        status_code=status.HTTP_302_FOUND,
    )


@router.post("/register", response_model=TokenPairOut, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterIn, request: Request, session: DbSession, settings: SettingsDep
) -> TokenPairOut:
    """Create an account, its first organization, and an owner membership (FR-001)."""
    result = await auth_service.register(
        session, payload, settings=settings, source_ip=_ip(request), user_agent=_ua(request)
    )
    await session.commit()
    return result.tokens


@router.post("/login", response_model=TokenPairOut)
async def login(
    payload: LoginIn, request: Request, session: DbSession, settings: SettingsDep
) -> TokenPairOut:
    """Verify credentials and issue an access/refresh pair (FR-001, FR-032)."""
    result = await auth_service.login(
        session, payload, settings=settings, source_ip=_ip(request), user_agent=_ua(request)
    )
    await session.commit()
    return result.tokens


@router.get("/sso/{organization_slug}/start", include_in_schema=False)
async def start_oidc_sso_login(
    organization_slug: str,
    session: DbSession,
    redis: RedisDep,
) -> RedirectResponse:
    """Begin a tenant-specific OIDC authorization-code login.

    The callback URI is selected by the organization administrator during setup,
    never from a browser query parameter, preventing attacker-directed callbacks.
    """
    connection = await sso_service.resolve_login_connection(session, organization_slug)
    state, nonce = await sso_service.create_login_state(redis, connection.organization_id)
    endpoint = await sso_service.discover_authorization_endpoint(connection)
    return RedirectResponse(
        sso_service.build_authorization_url(
            authorization_endpoint=endpoint,
            client_id=connection.client_id,
            redirect_uri=connection.redirect_uri,
            state=state,
            nonce=nonce,
        ),
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/sso/callback", include_in_schema=False)
async def complete_oidc_sso_login(
    code: str = Query(min_length=1, max_length=8192),
    state: str = Query(min_length=16, max_length=512),
    *,
    session: DbSession,
    redis: RedisDep,
    settings: SettingsDep,
) -> RedirectResponse:
    """Complete OIDC, then redirect with a short-lived opaque token handoff only."""
    consumed = await sso_service.consume_login_state(redis, state)
    if consumed is None:
        from app.core.errors import AuthenticationError

        raise AuthenticationError("OIDC state is missing, expired, or already used")
    organization_id, nonce = consumed
    connection = await sso_service.resolve_connection_by_organization_id(session, organization_id)
    claims = await sso_service.exchange_authorization_code(connection, code, settings=settings)
    email, full_name = sso_service.validated_identity_claims(
        claims,
        expected_nonce=nonce,
        allowed_email_domains=connection.allowed_email_domains,
    )
    membership, user = await provision_user(
        session,
        connection,
        email=email,
        full_name=full_name,
        active=True,
    )
    tokens = auth_service.issue_sso_session(settings, user=user, membership=membership)
    await record(
        session,
        action=AuditAction.OIDC_LOGIN,
        principal=Principal(
            user_id=user.id,
            organization_id=membership.organization_id,
            role=membership.role_enum,
            email=user.email,
        ),
        resource_type="oidc_connection",
        resource_id=connection.id,
        detail={"issuer_url": connection.issuer_url},
    )
    await session.commit()
    handoff = await sso_service.create_frontend_handoff(redis, tokens)
    return RedirectResponse(
        f"{settings.public_base_url.rstrip('/')}/sso/callback#ticket={handoff}",
        status_code=status.HTTP_302_FOUND,
    )


@router.post("/sso/exchange", response_model=TokenPairOut)
async def exchange_oidc_sso_handoff(payload: SsoHandoffIn, redis: RedisDep) -> TokenPairOut:
    """Redeem the browser's one-time OIDC handoff and return the normal token pair."""
    handoff = await sso_service.consume_frontend_handoff(redis, payload.handoff_token)
    if handoff is None:
        from app.core.errors import AuthenticationError

        raise AuthenticationError("SSO handoff is missing, expired, or already used")
    return TokenPairOut.model_validate(handoff)


@router.post("/refresh", response_model=TokenPairOut)
async def refresh(
    payload: RefreshIn, session: DbSession, deny_list: DenyListDep, settings: SettingsDep
) -> TokenPairOut:
    """Rotate a refresh token for a new pair, retiring the one presented."""
    result = await auth_service.refresh(session, deny_list, payload, settings=settings)
    await session.commit()
    return result.tokens


@router.get("/me", response_model=MeOut)
async def me(user: CurrentUser, claims: CurrentClaims, session: DbSession) -> MeOut:
    """The bootstrap payload for a signed-in shell: identity, memberships, permissions."""
    return await auth_service.build_me(session, user, active_organization_id=claims.organization_id)


@router.post("/switch-organization", response_model=TokenPairOut)
async def switch_organization(
    payload: SwitchOrganizationIn, user: CurrentUser, session: DbSession, settings: SettingsDep
) -> TokenPairOut:
    """Re-issue tokens scoped to another organization the user belongs to (SEC-003: 404 if not)."""
    result = await auth_service.switch_organization(session, user, payload, settings=settings)
    return result.tokens


@router.post("/logout", response_model=OkOut)
async def logout(
    user: CurrentUser,
    claims: CurrentClaims,
    session: DbSession,
    deny_list: DenyListDep,
    settings: SettingsDep,
    payload: LogoutIn | None = None,
) -> OkOut:
    """Revoke the presented access token (and the refresh token if one is supplied)."""
    await auth_service.logout(session, deny_list, claims=claims, payload=payload, settings=settings)
    await session.commit()
    return OkOut()


@router.post("/password/reset-request", response_model=OkOut, status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset(
    payload: PasswordResetRequestIn, request: Request, session: DbSession, settings: SettingsDep
) -> OkOut:
    """Issue a single-use reset link if the address belongs to an account.

    Always answers 202 with the same body -- an unknown address does the same amount of
    nothing -- so the endpoint is not a user-enumeration oracle. The link the service may
    return in development is intentionally discarded here (SEC-002).
    """
    await auth_service.request_password_reset(
        session, payload, settings=settings, source_ip=_ip(request)
    )
    await session.commit()
    return OkOut()


@router.post("/password/reset-confirm", response_model=OkOut)
async def confirm_password_reset(
    payload: PasswordResetConfirmIn,
    session: DbSession,
    deny_list: DenyListDep,
    settings: SettingsDep,
) -> OkOut:
    """Spend a reset token, set a new password, and end every existing session."""
    await auth_service.confirm_password_reset(session, deny_list, payload, settings=settings)
    await session.commit()
    return OkOut()


@router.post("/password/change", response_model=OkOut)
async def change_password(
    payload: ChangePasswordIn,
    user: CurrentUser,
    session: DbSession,
    deny_list: DenyListDep,
    settings: SettingsDep,
) -> OkOut:
    """Change a signed-in user's password, ending every other session."""
    await auth_service.change_password(session, deny_list, user, payload, settings=settings)
    await session.commit()
    return OkOut()


__all__ = ["router"]
