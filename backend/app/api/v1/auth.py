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

from fastapi import APIRouter, Request, status

from app.api.deps import CurrentClaims, CurrentUser, DbSession, DenyListDep, SettingsDep
from app.schemas.auth import (
    ChangePasswordIn,
    LoginIn,
    LogoutIn,
    MeOut,
    PasswordResetConfirmIn,
    PasswordResetRequestIn,
    RefreshIn,
    RegisterIn,
    SwitchOrganizationIn,
    TokenPairOut,
)
from app.schemas.common import OkOut
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _ua(request: Request) -> str | None:
    return request.headers.get("user-agent")


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
