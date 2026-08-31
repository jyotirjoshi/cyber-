"""Authentication, session issuance and password custody (FR-001, FR-002, SEC-002).

Five decisions are worth recording, because each of them looks like unnecessary work
until the thing it prevents happens.

**Tokens are stateless; revocation is not.**  A JWT is verified without touching the
database, which is what makes the authenticated request path cheap.  The cost is that an
unexpired token has no idea it was retired -- so sign-out, password change and refresh
rotation would all take up to ``access_token_ttl_minutes`` to bite.  The deny list in
:mod:`app.core.redis_client` supplies immediate revocation, keyed both by ``jti`` (one
token) and by a per-user cutoff timestamp (every token issued before now).  One Redis
read per authenticated request is the price, paid deliberately.

**Authority is re-read from the membership, never trusted from the token.**  The access
token carries a ``role`` claim, and :func:`resolve_principal` ignores it.  A token is
proof of *identity*; the ``memberships`` row is the authority.  Trusting the claim would
mean demoting someone had no effect until their token expired, which is exactly the
window an incident responder cannot afford.

**Failed-login bookkeeping runs in its own transaction.**  A rejected login raises, the
route never commits, and a naive ``failed_login_count += 1`` rolls back with it -- so the
counter would sit at zero forever and the lockout would never fire.  This is the same
problem :func:`app.services.audit.record_independently` exists to solve, and it gets the
same solution: a separate short transaction that survives the caller's rollback.

**Password reset needs both a signed token and a stored row.**  The signature lets the
endpoint reject garbage without a query, so it is not a database oracle for an
unauthenticated caller.  The row supplies single use, which a stateless token cannot --
without it a reset link works repeatedly until it expires.  Only the hash of the token is
stored, so a database read does not hand an attacker a working link.

**Login does not distinguish an unknown address from a wrong password**, including in the
time it takes: an absent user still pays for one Argon2 verification.  Registration
necessarily leaks whether an address is taken -- it has to, to be usable -- which is why
that path is rate limited at the route rather than made falsely quiet here.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import uuid
from dataclasses import dataclass

import structlog
from sqlalchemy import case, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidConfigurationError,
    PermissionDeniedError,
    ResourceNotFoundError,
)
from app.core.redis_client import TokenDenyList
from app.core.security import (
    TokenClaims,
    TokenType,
    create_token,
    decode_token,
    hash_password,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from app.db.base import utcnow
from app.db.enums import PERMISSIONS, AuditOutcome, Role
from app.db.models.identity import Membership, Organization, PasswordResetToken, User
from app.db.session import session_scope
from app.integrations.email import EmailSender
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
    UserOut,
)
from app.services import audit as audit_service
from app.services.audit import AuditAction
from app.services.context import ACTOR_USER, Principal
from app.services.organization import (
    create_organization,
    default_membership,
    membership_out,
    memberships_for_user,
    resolve_membership,
)

log = structlog.get_logger(__name__)

#: Paths on the *frontend*, appended to ``settings.public_base_url``. The API never
#: renders these pages; it only has to produce a link a human can click.
_RESET_PATH = "/reset-password"
_INVITE_PATH = "/accept-invite"

#: Cached Argon2 hash of a value nobody holds, used to equalize login timing. Built
#: lazily: hashing at import would make ``tools/verify.py`` and every test collection
#: pay ~80ms for something only the login path needs.
_DUMMY_HASH: str | None = None


@dataclass(frozen=True, slots=True)
class AuthResult:
    """What a successful issuance produced.

    Deliberately holds the resolved ``organization_id`` and ``role`` as plain values
    rather than the ``Membership`` row.  Relationships in this codebase are
    ``lazy="raise_on_sql"``, so handing an ORM object to a caller means handing it an
    eager-load requirement it cannot see in the type.  A value object has no such trap.
    """

    user: User
    tokens: TokenPairOut
    organization_id: uuid.UUID | None
    role: Role | None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _dummy_password_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


def _hash_token(token: str) -> str:
    """Digest a reset/invite token for storage.

    SHA-256 rather than Argon2, and that is not an oversight.  Argon2 exists to make
    *guessing* expensive, which matters for passwords because humans choose them.  This
    token is a JWT whose signature is 32 bytes of HMAC output an attacker cannot compute
    without ``jwt_secret``; there is nothing to guess, so a slow hash would only make
    every redemption slower.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def _load_user_by_email(session: AsyncSession, email: str) -> User | None:
    stmt = select(User).where(User.email == email.strip().lower())
    return (await session.execute(stmt)).scalar_one_or_none()


async def _load_user(session: AsyncSession, user_id: uuid.UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        # Reached when a token outlives the account it names. Presented as an auth
        # failure, not a 404: the caller is holding a credential, and "that user is
        # gone" is more than an unauthenticated party needs to be told.
        raise AuthenticationError("token subject no longer exists")
    return user


def _assert_active(user: User) -> None:
    if not user.is_active:
        raise AuthenticationError(
            "account disabled",
            user_message="This account has been disabled. Contact your administrator.",
            context={"user_id": str(user.id)},
        )


def _lockout_remaining(user: User, *, now: dt.datetime) -> int:
    """Seconds left on an active lockout, or 0 if the account is not locked."""
    if user.locked_until is None:
        return 0
    remaining = (user.locked_until - now).total_seconds()
    return int(remaining) if remaining > 0 else 0


async def _register_failed_login(user_id: uuid.UUID, *, settings: Settings) -> None:
    """Increment the failure counter and lock the account if it crossed the threshold.

    Runs in its own transaction because the caller is about to raise. See the module
    docstring. Failures here are logged, never re-raised: losing the increment degrades
    brute-force protection, but turning it into a 500 would tell an attacker that their
    guess was interesting.
    """
    threshold = max(settings.security.login_max_attempts, 1)
    locked_until = utcnow() + dt.timedelta(seconds=settings.security.login_lockout_seconds)
    next_count = User.failed_login_count + 1
    stmt = (
        update(User)
        .where(User.id == user_id)
        .values(
            failed_login_count=next_count,
            # Only *extends* the lock when the threshold is crossed; an already-locked
            # account keeps its original expiry rather than being pushed further out by
            # continued guessing, which would otherwise let an attacker lock a real user
            # out indefinitely.
            locked_until=case(
                (next_count >= threshold, locked_until),
                else_=User.locked_until,
            ),
        )
    )
    try:
        async with session_scope(settings) as own:
            await own.execute(stmt)
    except Exception:  # - see docstring; this must not mask the auth failure
        log.critical("auth.lockout_not_recorded", user_id=str(user_id), exc_info=True)


def _clear_failed_logins(user: User, *, now: dt.datetime) -> None:
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now


def _issue_pair(
    settings: Settings,
    *,
    user: User,
    organization_id: uuid.UUID | None,
    role: Role | None,
) -> TokenPairOut:
    """Mint an access/refresh pair.

    The ``org`` and ``role`` claims are carried for convenience -- they let the API log a
    request's tenant before touching the database -- but they are *not* authority. See
    :func:`resolve_principal`.
    """
    access, _ = create_token(
        settings,
        subject=user.id,
        token_type="access",  # noqa: S106 - a token *type* discriminator, not a credential
        organization_id=organization_id,
        role=role.value if role else None,
    )
    # The refresh token carries the organization too, so a refresh lands the client back
    # in the tenant they were working in rather than silently in their default one.
    refresh_token, _ = create_token(
        settings,
        subject=user.id,
        token_type="refresh",  # noqa: S106 - a token *type* discriminator, not a credential
        organization_id=organization_id,
    )
    return TokenPairOut(
        access_token=access,
        refresh_token=refresh_token,
        expires_in=settings.security.access_token_ttl_minutes * 60,
    )


async def _active_membership(
    session: AsyncSession,
    user_id: uuid.UUID,
    requested_organization_id: uuid.UUID | None,
) -> Membership | None:
    """The membership a session should operate under.

    An explicitly requested organization is honoured only if the user is actually a
    member of it; a request for one they are not in falls back to their default rather
    than raising, because the common cause is a stale token from before they were removed
    and the useful outcome is "you are now somewhere you do belong", not a hard failure.
    Cross-tenant *reads* are still refused downstream by ``tenant_select`` (SEC-003) --
    this only chooses which tenant the principal is built for.
    """
    if requested_organization_id is not None:
        membership = await resolve_membership(session, user_id, requested_organization_id)
        if membership is not None:
            return membership
        log.info(
            "auth.organization_claim_stale",
            user_id=str(user_id),
            organization_id=str(requested_organization_id),
        )
    return await default_membership(session, user_id)


async def _revoke(deny_list: TokenDenyList, claims: TokenClaims, *, now: dt.datetime) -> None:
    """Deny-list one token for exactly as long as it would otherwise remain valid.

    An already-expired token is skipped: signature verification rejects it anyway, so
    storing it would only occupy Redis.
    """
    ttl = int((claims.expires_at - now).total_seconds())
    if ttl <= 0:
        return
    await deny_list.revoke_token(claims.jti, ttl)


async def _store_single_use_token(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    token: str,
    expires_at: dt.datetime,
    requested_ip: str | None,
) -> PasswordResetToken:
    """Persist the *hash* of a reset/invite token so it can be spent exactly once.

    ``PasswordResetToken`` has no ``TimestampMixin``, so ``created_at`` is set here rather
    than by a default.
    """
    row = PasswordResetToken(
        user_id=user_id,
        token_hash=_hash_token(token),
        expires_at=expires_at,
        requested_ip=requested_ip[:64] if requested_ip else None,
        created_at=utcnow(),
    )
    session.add(row)
    await session.flush()
    return row


async def _spend_single_use_token(
    session: AsyncSession, token: str, *, now: dt.datetime
) -> PasswordResetToken:
    """Look up, validate and consume a stored reset/invite token.

    Every rejection reason collapses to the same :class:`AuthenticationError` message. A
    caller holding a link cannot learn whether it was never issued, already spent or
    merely late -- distinctions that only help someone probing for a reusable link.
    """
    stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == _hash_token(token))
    row = (await session.execute(stmt)).scalar_one_or_none()
    invalid = AuthenticationError(
        "reset token not redeemable",
        user_message="That link is no longer valid. Request a new one.",
    )
    if row is None or row.used_at is not None or row.expires_at <= now:
        raise invalid
    row.used_at = now
    await session.flush()
    return row


def _link(settings: Settings, path: str, token: str, **params: str) -> str:
    base = settings.public_base_url.rstrip("/")
    query = "".join(f"&{key}={value}" for key, value in params.items() if value)
    return f"{base}{path}?token={token}{query}"


# ---------------------------------------------------------------------------
# Request authentication
# ---------------------------------------------------------------------------


async def authenticate_token(
    session: AsyncSession,
    deny_list: TokenDenyList,
    token: str,
    *,
    settings: Settings,
    expect: TokenType = "access",
) -> tuple[User, TokenClaims]:
    """Verify a bearer token and load the account it names.

    Returns the claims alongside the user because the caller needs the ``jti`` (to revoke
    on sign-out) and the ``org`` claim (to choose the active tenant) -- re-decoding the
    token in the route to recover them would be wasteful and easy to get subtly wrong.
    """
    claims = decode_token(settings, token, expect=expect)
    issued_at = int(claims.raw.get("iat") or 0)
    if await deny_list.is_revoked(claims.jti, str(claims.subject), issued_at):
        raise AuthenticationError(
            "token revoked",
            user_message="Your session has ended. Sign in again.",
        )
    user = await _load_user(session, claims.subject)
    _assert_active(user)
    return user, claims


async def resolve_principal(
    session: AsyncSession,
    user: User,
    claims: TokenClaims,
    *,
    source_ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
) -> Principal:
    """Build the tenant-scoped authority for a request.

    A user with no membership authenticates fine and can read nothing -- that is the
    documented contract on :class:`~app.db.models.identity.User`. That case raises
    :class:`PermissionDeniedError` (403) and not :class:`AuthenticationError` (401),
    because retrying with a fresh credential cannot help: the credential is already
    valid, the *authorization* is missing. This is why the API exposes both a
    ``current_user`` dependency and a ``current_principal`` one.
    """
    membership = await _active_membership(session, user.id, claims.organization_id)
    if membership is None:
        raise PermissionDeniedError(
            "user has no organization membership",
            user_message="Your account is not a member of any organization yet.",
            context={"user_id": str(user.id)},
        )
    return Principal(
        user_id=user.id,
        organization_id=membership.organization_id,
        role=membership.role_enum,
        email=user.email,
        actor_type=ACTOR_USER,
        source_ip=source_ip,
        user_agent=user_agent,
        request_id=request_id,
        trace_id=trace_id,
    )


async def build_me(
    session: AsyncSession,
    user: User,
    *,
    active_organization_id: uuid.UUID | None = None,
) -> MeOut:
    """Everything the client needs to render a signed-in shell.

    Serves users with no membership too, returning empty ``organizations`` and a null
    ``active_role`` rather than failing -- the frontend uses exactly that state to show
    "ask an administrator to invite you" instead of bouncing to the login page.
    """
    memberships = await memberships_for_user(session, user.id)
    active: Membership | None = None
    if active_organization_id is not None:
        active = next(
            (m for m in memberships if m.organization_id == active_organization_id),
            None,
        )
    if active is None:
        # Deliberately delegated rather than re-deriving "prefer is_default, then oldest":
        # duplicating that rule here would let the two definitions drift apart.
        active = await default_membership(session, user.id)
    role = active.role_enum if active is not None else None
    return MeOut(
        user=UserOut.model_validate(user),
        organizations=[membership_out(m) for m in memberships],
        active_organization_id=active.organization_id if active is not None else None,
        active_role=role,
        permissions=sorted(p.value for p in PERMISSIONS[role]) if role is not None else [],
    )


# ---------------------------------------------------------------------------
# Registration and sign-in
# ---------------------------------------------------------------------------


async def register(
    session: AsyncSession,
    payload: RegisterIn,
    *,
    settings: Settings,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> AuthResult:
    """Create a user, their first organization, and an owner membership (FR-001, FR-002).

    Self-service registration always creates an organization: a user with no membership
    can read nothing, so registering without one would produce an account that appears
    broken. Joining an existing organization is the invitation flow instead.
    """
    validate_password_strength(payload.password, settings)
    email = payload.email.strip().lower()

    if await _load_user_by_email(session, email) is not None:
        raise ConflictError(
            "email already registered",
            user_message="An account with that email already exists.",
        )

    now = utcnow()
    user = User(
        email=email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        is_active=True,
        is_email_verified=False,
        password_changed_at=now,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        # Two registrations for the same address interleaved between the check above and
        # this flush. Not rolled back here: this function does not own the transaction.
        raise ConflictError(
            "email already registered",
            user_message="An account with that email already exists.",
        ) from exc

    organization, membership = await create_organization(
        session, name=payload.organization_name, owner=user
    )
    principal = Principal(
        user_id=user.id,
        organization_id=organization.id,
        role=membership.role_enum,
        email=user.email,
        actor_type=ACTOR_USER,
        source_ip=source_ip,
        user_agent=user_agent,
    )
    await audit_service.record(
        session,
        action=AuditAction.REGISTER,
        principal=principal,
        resource_type="user",
        resource_id=user.id,
        detail={"organization_slug": organization.slug},
    )
    user.last_login_at = now
    log.info("auth.registered", user_id=str(user.id), organization_id=str(organization.id))
    return AuthResult(
        user=user,
        tokens=_issue_pair(
            settings, user=user, organization_id=organization.id, role=membership.role_enum
        ),
        organization_id=organization.id,
        role=membership.role_enum,
    )


async def login(
    session: AsyncSession,
    payload: LoginIn,
    *,
    settings: Settings,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> AuthResult:
    """Verify credentials and issue a token pair (FR-001, FR-032).

    Lockout state *is* disclosed to the user, which is a deliberate trade. It leaks that
    an address exists -- but only after eight failures against that one address, by which
    point the attacker has already been audited and rate limited, and the alternative is
    a user who cannot tell a wrong password from a locked account and keeps guessing.
    """
    email = payload.email.strip().lower()
    now = utcnow()
    user = await _load_user_by_email(session, email)

    if user is None:
        # An unknown address still pays for one Argon2 verification so that response time
        # does not become a user-enumeration oracle.
        verify_password(_dummy_password_hash(), payload.password)
        await audit_service.record_independently(
            action=AuditAction.LOGIN_FAILED,
            outcome=AuditOutcome.FAILURE,
            reason="unknown email",
            detail={"email": email, "source_ip": source_ip},
            settings=settings,
        )
        raise _invalid_credentials()

    locked_for = _lockout_remaining(user, now=now)
    if locked_for > 0:
        await audit_service.record_independently(
            action=AuditAction.LOGIN_LOCKED,
            outcome=AuditOutcome.DENIED,
            reason="account locked",
            resource_type="user",
            resource_id=user.id,
            detail={"email": email, "source_ip": source_ip, "retry_after": locked_for},
            settings=settings,
        )
        raise AuthenticationError(
            "account locked",
            user_message=(
                "Too many failed sign-in attempts. Try again in "
                f"{max(locked_for // 60, 1)} minute(s)."
            ),
            context={"user_id": str(user.id), "retry_after": locked_for},
        )

    if not verify_password(user.password_hash, payload.password):
        await _register_failed_login(user.id, settings=settings)
        await audit_service.record_independently(
            action=AuditAction.LOGIN_FAILED,
            outcome=AuditOutcome.FAILURE,
            reason="bad password",
            resource_type="user",
            resource_id=user.id,
            detail={"email": email, "source_ip": source_ip},
            settings=settings,
        )
        raise _invalid_credentials()

    _assert_active(user)

    if needs_rehash(user.password_hash):
        # Argon2 parameters were raised since this hash was written. Upgrading now is the
        # only moment the plaintext is available to do it.
        user.password_hash = hash_password(payload.password)

    _clear_failed_logins(user, now=now)
    membership = await _active_membership(session, user.id, None)
    organization_id = membership.organization_id if membership is not None else None
    role = membership.role_enum if membership is not None else None

    if membership is not None:
        principal = Principal(
            user_id=user.id,
            organization_id=membership.organization_id,
            role=membership.role_enum,
            email=user.email,
            actor_type=ACTOR_USER,
            source_ip=source_ip,
            user_agent=user_agent,
        )
        await audit_service.record(
            session,
            action=AuditAction.LOGIN,
            principal=principal,
            resource_type="user",
            resource_id=user.id,
        )
    else:
        # No membership means no tenant to attribute the row to, and ``audit_events`` is
        # tenant-scoped. Recorded independently with no organization so the sign-in is
        # still visible rather than dropped.
        await audit_service.record_independently(
            action=AuditAction.LOGIN,
            outcome=AuditOutcome.SUCCESS,
            resource_type="user",
            resource_id=user.id,
            reason="no organization membership",
            detail={"email": email, "source_ip": source_ip},
            settings=settings,
        )

    log.info("auth.login", user_id=str(user.id), organization_id=str(organization_id or ""))
    return AuthResult(
        user=user,
        tokens=_issue_pair(settings, user=user, organization_id=organization_id, role=role),
        organization_id=organization_id,
        role=role,
    )


def _invalid_credentials() -> AuthenticationError:
    return AuthenticationError(
        "invalid credentials",
        user_message="That email or password is incorrect.",
    )


async def refresh(
    session: AsyncSession,
    deny_list: TokenDenyList,
    payload: RefreshIn,
    *,
    settings: Settings,
) -> AuthResult:
    """Exchange a refresh token for a new pair, retiring the one presented.

    Rotation is the point: a refresh token is usable exactly once, so a stolen one is
    worth a single exchange and the theft becomes detectable when the legitimate client's
    next refresh is rejected. Role is re-read from the membership on every refresh, which
    is what makes a demotion take effect within one access-token lifetime.
    """
    now = utcnow()
    user, claims = await authenticate_token(
        session, deny_list, payload.refresh_token, settings=settings, expect="refresh"
    )
    await _revoke(deny_list, claims, now=now)

    membership = await _active_membership(session, user.id, claims.organization_id)
    organization_id = membership.organization_id if membership is not None else None
    role = membership.role_enum if membership is not None else None

    if membership is not None:
        await audit_service.record(
            session,
            action=AuditAction.TOKEN_REFRESH,
            principal=Principal(
                user_id=user.id,
                organization_id=membership.organization_id,
                role=membership.role_enum,
                email=user.email,
                actor_type=ACTOR_USER,
            ),
            resource_type="user",
            resource_id=user.id,
        )
    return AuthResult(
        user=user,
        tokens=_issue_pair(settings, user=user, organization_id=organization_id, role=role),
        organization_id=organization_id,
        role=role,
    )


async def logout(
    session: AsyncSession,
    deny_list: TokenDenyList,
    *,
    claims: TokenClaims,
    payload: LogoutIn | None = None,
    settings: Settings,
    principal: Principal | None = None,
) -> None:
    """Retire the presented access token, and the refresh token if one was supplied.

    A malformed or already-expired refresh token does not fail the request. The user
    asked to sign out; refusing to do so because the second half of their credential was
    unusable would leave a working access token in place -- the opposite of the intent.
    """
    now = utcnow()
    await _revoke(deny_list, claims, now=now)

    if payload is not None and payload.refresh_token:
        try:
            refresh_claims = decode_token(settings, payload.refresh_token, expect="refresh")
        except AuthenticationError:
            log.info("auth.logout_refresh_unusable", user_id=str(claims.subject))
        else:
            if refresh_claims.subject == claims.subject:
                await _revoke(deny_list, refresh_claims, now=now)

    if principal is not None:
        await audit_service.record(
            session,
            action=AuditAction.LOGOUT,
            principal=principal,
            resource_type="user",
            resource_id=claims.subject,
        )
    log.info("auth.logout", user_id=str(claims.subject))


async def switch_organization(
    session: AsyncSession,
    user: User,
    payload: SwitchOrganizationIn,
    *,
    settings: Settings,
) -> AuthResult:
    """Re-issue tokens scoped to another organization the user belongs to.

    An organization the user is not a member of raises
    :class:`ResourceNotFoundError` -- a 404, not a 403. Per SEC-003 a tenant the caller
    has no relationship with must be indistinguishable from one that does not exist,
    otherwise the error code itself confirms that a given organization id is real.
    """
    membership = await resolve_membership(session, user.id, payload.organization_id)
    if membership is None:
        raise ResourceNotFoundError(
            "organization not found",
            user_message="That organization was not found.",
            context={"organization_id": str(payload.organization_id)},
        )
    log.info(
        "auth.organization_switched",
        user_id=str(user.id),
        organization_id=str(membership.organization_id),
    )
    return AuthResult(
        user=user,
        tokens=_issue_pair(
            settings,
            user=user,
            organization_id=membership.organization_id,
            role=membership.role_enum,
        ),
        organization_id=membership.organization_id,
        role=membership.role_enum,
    )


# ---------------------------------------------------------------------------
# Password custody
# ---------------------------------------------------------------------------


async def request_password_reset(
    session: AsyncSession,
    payload: PasswordResetRequestIn,
    *,
    settings: Settings,
    sender: EmailSender | None = None,
    source_ip: str | None = None,
) -> str | None:
    """Issue a single-use reset link, if the address belongs to an account.

    Always succeeds from the caller's point of view -- an unknown address does the same
    amount of nothing, quietly, so the endpoint is not a user-enumeration oracle.

    The return value is the reset link, and it is returned **only** when
    ``settings.environment == "development"``; production always returns ``None``. It
    exists so a developer without SMTP configured can still complete the flow and so
    tests can assert it. A route must never place it in a response body. Returning it
    rather than logging it is the deliberate choice: a reset link is a credential, and
    SEC-002 keeps credentials out of the log pipeline entirely.
    """
    email = payload.email.strip().lower()
    user = await _load_user_by_email(session, email)
    if user is None or not user.is_active:
        log.info("auth.password_reset_ignored", reason="no active account")
        return None

    token, claims = create_token(
        settings,
        subject=user.id,
        token_type="password_reset",  # noqa: S106 - a token *type* discriminator, not a credential
        extra={"purpose": "reset"},
    )
    await _store_single_use_token(
        session,
        user_id=user.id,
        token=token,
        expires_at=claims.expires_at,
        requested_ip=source_ip,
    )
    await audit_service.record_independently(
        action=AuditAction.PASSWORD_RESET_REQUESTED,
        outcome=AuditOutcome.SUCCESS,
        resource_type="user",
        resource_id=user.id,
        detail={"email": email, "source_ip": source_ip},
        settings=settings,
    )

    url = _link(settings, _RESET_PATH, token)
    if sender is not None and sender.configured:
        try:
            await sender.send(
                user.email,
                "Reset your Cynux password",
                _reset_email_html(user.display_name, url, settings),
            )
        except Exception:  # - delivery must not reveal whether the account exists
            log.warning("auth.password_reset_email_failed", user_id=str(user.id), exc_info=True)

    log.info("auth.password_reset_issued", user_id=str(user.id))
    return url if settings.environment == "development" else None


async def confirm_password_reset(
    session: AsyncSession,
    deny_list: TokenDenyList,
    payload: PasswordResetConfirmIn,
    *,
    settings: Settings,
) -> User:
    """Spend a reset token and set a new password.

    Both halves are checked: the signature first, so a forged or tampered token is
    rejected without a query, then the stored row, which is what makes the link
    single-use.
    """
    validate_password_strength(payload.new_password, settings)
    now = utcnow()

    try:
        claims = decode_token(settings, payload.token, expect="password_reset")
    except AuthenticationError as exc:
        raise AuthenticationError(
            "reset token not redeemable",
            user_message="That link is no longer valid. Request a new one.",
            cause=exc,
        ) from exc

    row = await _spend_single_use_token(session, payload.token, now=now)
    if row.user_id != claims.subject:
        # Signature and stored row disagree about who this is for. Impossible without
        # either a key compromise or a bug, and not something to paper over.
        log.error(
            "auth.reset_token_subject_mismatch",
            row_user_id=str(row.user_id),
            claim_user_id=str(claims.subject),
        )
        raise AuthenticationError(
            "reset token subject mismatch",
            user_message="That link is no longer valid. Request a new one.",
        )

    user = await _load_user(session, claims.subject)
    _assert_active(user)
    if verify_password(user.password_hash, payload.new_password):
        raise InvalidConfigurationError(
            "password reuse",
            user_message="Choose a password you have not used before.",
        )

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = now
    user.failed_login_count = 0
    user.locked_until = None
    await _revoke_all_sessions(deny_list, user, settings=settings)
    await audit_service.record_independently(
        action=AuditAction.PASSWORD_RESET_COMPLETED,
        outcome=AuditOutcome.SUCCESS,
        resource_type="user",
        resource_id=user.id,
        settings=settings,
    )
    log.info("auth.password_reset_completed", user_id=str(user.id))
    return user


async def change_password(
    session: AsyncSession,
    deny_list: TokenDenyList,
    user: User,
    payload: ChangePasswordIn,
    *,
    settings: Settings,
    principal: Principal | None = None,
) -> None:
    """Change a signed-in user's password, ending every other session."""
    if not verify_password(user.password_hash, payload.current_password):
        raise AuthenticationError(
            "current password incorrect",
            user_message="Your current password is incorrect.",
        )
    validate_password_strength(payload.new_password, settings)
    if verify_password(user.password_hash, payload.new_password):
        raise InvalidConfigurationError(
            "password reuse",
            user_message="Choose a password you have not used before.",
        )

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = utcnow()
    await _revoke_all_sessions(deny_list, user, settings=settings)
    if principal is not None:
        await audit_service.record(
            session,
            action=AuditAction.TOKEN_REVOKED,
            principal=principal,
            resource_type="user",
            resource_id=user.id,
            reason="password changed",
        )
    log.info("auth.password_changed", user_id=str(user.id))


async def _revoke_all_sessions(deny_list: TokenDenyList, user: User, *, settings: Settings) -> None:
    """Invalidate every token issued to this user before now.

    The window is the longest-lived credential type -- a refresh token -- because a
    shorter one would let a refresh token issued before the cutoff outlive the marker
    that is supposed to kill it.
    """
    ttl = settings.security.refresh_token_ttl_days * 86_400
    await deny_list.revoke_all_for_user(str(user.id), ttl)


async def issue_invite_token(
    session: AsyncSession,
    *,
    user: User,
    organization: Organization,
    settings: Settings,
    ttl: dt.timedelta | None = None,
) -> str:
    """Mint the credential an invited user needs to set their first password.

    :mod:`app.services.organization` deliberately stops after creating the ``User`` and
    ``Membership``: password material is owned by this module, so ``invite_member`` has no
    business minting it. The route calls that, then this.

    Reuses the ``password_reset`` machinery because "set a password you do not have yet"
    and "replace a password you cannot remember" are the same operation on the same
    column, redeemed by the same endpoint. The default lifetime is a week rather than the
    30 minutes a reset gets -- an invitation waits on a human reading their inbox.
    """
    token, claims = create_token(
        settings,
        subject=user.id,
        token_type="password_reset",  # noqa: S106 - a token *type* discriminator, not a credential
        organization_id=organization.id,
        ttl=ttl or dt.timedelta(days=7),
        extra={"purpose": "invite"},
    )
    await _store_single_use_token(
        session,
        user_id=user.id,
        token=token,
        expires_at=claims.expires_at,
        requested_ip=None,
    )
    log.info(
        "auth.invite_token_issued",
        user_id=str(user.id),
        organization_id=str(organization.id),
    )
    return _link(settings, _INVITE_PATH, token, org=organization.slug)


def _reset_email_html(name: str, url: str, settings: Settings) -> str:
    minutes = settings.security.password_reset_ttl_minutes
    return (
        f"<p>Hello {name},</p>"
        f"<p>Use the link below to choose a new Cynux password. It expires in {minutes} "
        f"minutes and can be used once.</p>"
        f'<p><a href="{url}">Reset your password</a></p>'
        f"<p>If you did not request this, no action is needed.</p>"
    )


__all__ = [
    "AuthResult",
    "authenticate_token",
    "build_me",
    "change_password",
    "confirm_password_reset",
    "issue_invite_token",
    "login",
    "logout",
    "refresh",
    "register",
    "request_password_reset",
    "resolve_principal",
    "switch_organization",
]
