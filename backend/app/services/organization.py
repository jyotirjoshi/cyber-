"""Organizations, membership and per-organization policy (FR-002).

Three things in here are load-bearing and none of them are obvious from the schema:

* **An organization always has at least one owner.**  Every write that could remove the
  last one -- demotion and removal -- counts owners first and refuses.  An organization
  with no owner cannot grant roles, configure integrations or delete itself; it is
  unrecoverable without direct database access, so the guard has to live below the API.
* **Nobody can grant a role above their own, or change their own role.**  ``MEMBER_MANAGE``
  is held by ``admin``, which means without these two rules an admin could set their own
  membership to ``owner`` and acquire ``ORG_MANAGE`` -- the one permission the role table
  deliberately withholds from them (:data:`~app.db.enums.PERMISSIONS`).
* **``memberships`` is queried explicitly, not through
  :func:`~app.db.repository.tenant_select`.**  The table carries ``organization_id`` but
  does not use :class:`~app.db.base.TenantMixin`, because membership *is* the mechanism
  tenancy is derived from -- scoping it with the helper that reads the resolved tenant
  would be circular.  Every query below therefore names the filter itself, the same way
  :mod:`app.services.audit` does.

Invitations create the ``User`` and the ``Membership`` but deliberately do **not** mint
the credential the invitee needs.  Password material is owned by
:mod:`app.services.auth`; having this module reach for it would make the two import each
other, and more importantly would put token minting in two places.  The route calls
:func:`invite_member` and then ``auth.issue_invite_token``.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
import uuid
from collections.abc import Sequence
from typing import Any

import structlog
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import (
    ConflictError,
    InvalidConfigurationError,
    PermissionDeniedError,
    ResourceNotFoundError,
    TenantIsolationError,
)
from app.core.security import hash_password
from app.db.base import utcnow
from app.db.enums import Permission, Role
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.db.models.identity import Membership, Organization, User
from app.schemas.common import PaginationParams
from app.schemas.organization import (
    ClientOrganizationCreateIn,
    ClientOrganizationDelegateIn,
    ClientOrganizationPortfolioOut,
    MemberInviteIn,
    MembershipOut,
    OrganizationUpdateIn,
    OrgPolicy,
)
from app.services import audit
from app.services.audit import AuditAction
from app.services.context import Principal
from app.services.entitlements import (
    DEFAULT_ENTITLEMENTS,
    assert_member_capacity,
    load_entitlements,
)

log = structlog.get_logger(__name__)

#: Column width of ``organizations.slug``.
_SLUG_MAX = 80
#: Room for the ``-<n>`` disambiguator appended by :func:`allocate_slug`.
_SLUG_BASE_MAX = _SLUG_MAX - 5
_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


# ---------------------------------------------------------------------------
# Slugs
# ---------------------------------------------------------------------------


def slugify(name: str, *, fallback: str = "org") -> str:
    """URL-safe form of an organization name.

    Non-ASCII characters are transliterated rather than dropped, so "Sécurité" becomes
    ``securite`` instead of ``scurit``.  A name that is *entirely* non-transliterable --
    a CJK or emoji-only name, which the 2-character minimum on
    ``OrganizationCreateIn.name`` happily allows -- would otherwise slugify to the empty
    string and violate the NOT NULL, so it falls back instead.
    """
    decomposed = unicodedata.normalize("NFKD", name)
    ascii_only = decomposed.encode("ascii", "ignore").decode("ascii")
    slug = _SLUG_STRIP.sub("-", ascii_only.lower()).strip("-")
    if not slug:
        return f"{fallback}-{secrets.token_hex(4)}"
    return slug[:_SLUG_BASE_MAX].rstrip("-")


async def allocate_slug(session: AsyncSession, base: str) -> str:
    """Return ``base``, or ``base-2``, ``base-3``, ... if it is taken.

    Two organizations may legitimately be called "Acme"; the slug is a URL, not an
    identity.  The loop is bounded and then falls back to a random suffix rather than
    spinning: at ``-50`` the name is contested enough that a readable slug is no longer
    achievable, and an unbounded scan is a way for one caller to make the endpoint slow
    for everyone.

    Racy by nature -- two concurrent registrations can both see ``acme`` as free.  The
    unique index is the actual guarantee; :func:`create_organization` catches the
    violation and retries.
    """
    taken = set(
        (await session.execute(select(Organization.slug).where(Organization.slug.like(f"{base}%"))))
        .scalars()
        .all()
    )
    if base not in taken:
        return base
    for suffix in range(2, 50):
        candidate = f"{base}-{suffix}"
        if candidate not in taken:
            return candidate
    return f"{base}-{secrets.token_hex(3)}"[:_SLUG_MAX]


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------


async def create_organization(
    session: AsyncSession,
    *,
    name: str,
    owner: User,
    slug: str | None = None,
    principal: Principal | None = None,
    parent_organization_id: uuid.UUID | None = None,
) -> tuple[Organization, Membership]:
    """Create an organization and its first owner membership.

    Returns both rows because the caller almost always needs the membership too -- to
    build a :class:`~app.services.context.Principal`, or to report the new default
    organization back to the client.

    ``is_default`` is set only when the owner has no other membership.  A user creating a
    second organization should not have their existing default silently moved out from
    under them.

    The audit row is written with ``organization_id`` pointing at the new organization
    even when ``principal`` is ``None`` (self-service registration, where no principal
    exists yet), so the event is filed under the tenant it created rather than nowhere.
    """
    candidate = slugify(slug or name)
    if slug is not None and candidate != slug:
        # An explicit slug is part of the caller's URL contract. Silently rewriting it
        # would mean the organization is reachable at an address the caller never chose.
        raise InvalidConfigurationError(
            f"slug {slug!r} is not URL-safe",
            user_message="That slug contains characters that are not allowed.",
            context={"slug": slug, "normalized": candidate},
        )

    organization = Organization(
        name=name.strip(),
        slug=await allocate_slug(session, candidate),
        policy={},
        entitlements=DEFAULT_ENTITLEMENTS.model_dump(),
        parent_organization_id=parent_organization_id,
        is_active=True,
    )
    session.add(organization)
    try:
        await session.flush()
    except IntegrityError as exc:
        # Lost the slug race: :func:`allocate_slug` read a free slug that another
        # registration took before this flush. Surfaced as 409 rather than retried --
        # Postgres has already aborted the transaction, so a retry here would need a
        # savepoint, and re-POSTing is both cheaper and correct for the caller.
        #
        # No ``session.rollback()``: this function does not own the transaction, and
        # rolling back would silently discard whatever the caller staged before it (the
        # ``User`` row, during registration). The route's error handler and the session
        # dependency's teardown both roll back on the way out.
        raise ConflictError(
            "organization slug collision",
            user_message="That organization name is already in use. Try another.",
            context={"slug": candidate},
            cause=exc,
        ) from exc

    is_first = not await _has_any_membership(session, owner.id)
    membership = Membership(
        organization_id=organization.id,
        user_id=owner.id,
        role=Role.OWNER.value,
        is_default=is_first,
        accepted_at=utcnow(),
    )
    session.add(membership)
    await session.flush()

    await audit.record(
        session,
        action=AuditAction.ORG_CREATE,
        principal=principal,
        organization_id=organization.id,
        resource_type="organization",
        resource_id=organization.id,
        detail={"slug": organization.slug, "owner_id": str(owner.id)},
    )
    log.info(
        "organization.created",
        organization_id=str(organization.id),
        slug=organization.slug,
        owner_id=str(owner.id),
    )
    return organization, membership


async def create_client_organization(
    session: AsyncSession,
    principal: Principal,
    payload: ClientOrganizationCreateIn,
) -> Organization:
    """Create an isolated customer tenant below an MSSP tenant.

    The creator becomes the client tenant's owner.  That is intentional: existing
    organization switching continues to be the sole way a user enters a tenant, and
    prevents a parent token from reading a customer tenant without an explicit
    membership.
    """
    principal.require(Permission.ORG_MANAGE)
    parent = await get_organization(session, principal)
    client, _membership = await create_organization(
        session,
        name=payload.name,
        slug=payload.slug,
        owner=await _user_for_principal(session, principal),
        principal=principal,
        parent_organization_id=parent.id,
    )
    await audit.record(
        session,
        action=AuditAction.MSSP_CLIENT_CREATE,
        principal=principal,
        resource_type="organization",
        resource_id=client.id,
        detail={"client_organization_id": str(client.id), "client_slug": client.slug},
    )
    return client


async def list_client_portfolio(
    session: AsyncSession,
    principal: Principal,
) -> list[ClientOrganizationPortfolioOut]:
    """Return direct client tenants and aggregate counters, never their raw records."""
    principal.require(Permission.ORG_MANAGE)
    clients = list(
        (
            await session.scalars(
                select(Organization)
                .where(Organization.parent_organization_id == principal.organization_id)
                .order_by(Organization.name.asc(), Organization.id.asc())
            )
        ).all()
    )
    if not clients:
        return []

    client_ids = [client.id for client in clients]
    asset_counts = dict(
        (
            await session.execute(
                select(Asset.organization_id, func.count(Asset.id))
                .where(Asset.organization_id.in_(client_ids))
                .group_by(Asset.organization_id)
            )
        ).all()
    )
    open_statuses = ("new", "open", "reopened")
    finding_rows = (
        await session.execute(
            select(
                CanonicalFinding.organization_id,
                func.count(CanonicalFinding.id),
                func.count(CanonicalFinding.id).filter(CanonicalFinding.severity == "critical"),
                func.coalesce(func.sum(CanonicalFinding.risk_score), 0.0),
            )
            .where(
                CanonicalFinding.organization_id.in_(client_ids),
                CanonicalFinding.status.in_(open_statuses),
            )
            .group_by(CanonicalFinding.organization_id)
        )
    ).all()
    finding_counts = {row[0]: row[1:] for row in finding_rows}
    return [
        ClientOrganizationPortfolioOut(
            organization=client,
            asset_count=int(asset_counts.get(client.id, 0)),
            open_finding_count=int(finding_counts.get(client.id, (0, 0, 0.0))[0]),
            critical_open_finding_count=int(finding_counts.get(client.id, (0, 0, 0.0))[1]),
            open_risk_score=float(finding_counts.get(client.id, (0, 0, 0.0))[2]),
        )
        for client in clients
    ]


async def delegate_client_access(
    session: AsyncSession,
    principal: Principal,
    client_organization_id: uuid.UUID,
    payload: ClientOrganizationDelegateIn,
) -> tuple[Membership, User]:
    """Grant a parent-team member a least-privilege role in one direct client tenant.

    A delegate must already belong to the parent organization.  This gives an MSSP a
    practical staffing model while preventing a parent administrator from using an
    arbitrary global account id as an invisible cross-tenant grant mechanism.
    """
    principal.require(Permission.ORG_MANAGE)
    client = (
        await session.execute(
            select(Organization).where(
                Organization.id == client_organization_id,
                Organization.parent_organization_id == principal.organization_id,
            )
        )
    ).scalar_one_or_none()
    if client is None:
        raise ResourceNotFoundError(
            "client organization not found",
            user_message="That client organization is not in your managed portfolio.",
            context={"client_organization_id": str(client_organization_id)},
        )
    parent_membership = (
        await session.execute(
            select(Membership).where(
                Membership.organization_id == principal.organization_id,
                Membership.user_id == payload.user_id,
            )
        )
    ).scalar_one_or_none()
    if parent_membership is None:
        raise ResourceNotFoundError(
            "parent team member not found",
            user_message="Choose an active member of this organization to delegate.",
            context={"user_id": str(payload.user_id)},
        )
    user = await session.get(User, payload.user_id)
    if user is None or not user.is_active:
        raise ConflictError(
            "delegate user inactive",
            user_message="That team member is not active.",
            context={"user_id": str(payload.user_id)},
        )
    membership = (
        await session.execute(
            select(Membership).where(
                Membership.organization_id == client.id,
                Membership.user_id == payload.user_id,
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        membership = Membership(
            organization_id=client.id,
            user_id=user.id,
            role=payload.role.value,
            is_default=False,
            invited_by_id=principal.user_id,
            accepted_at=utcnow(),
        )
        session.add(membership)
    else:
        membership.role = payload.role.value
    await session.flush()
    await audit.record(
        session,
        action=AuditAction.MEMBER_ROLE_CHANGE,
        principal=principal,
        resource_type="membership",
        resource_id=membership.id,
        detail={
            "client_organization_id": str(client.id),
            "target_user_id": str(user.id),
            "delegated_role": payload.role.value,
        },
    )
    return membership, user


async def get_organization(session: AsyncSession, principal: Principal) -> Organization:
    """The caller's own organization.

    Takes no id: there is exactly one organization a principal can read, and accepting an
    id would create an endpoint whose whole job is to reject most of its inputs.
    """
    principal.require(Permission.ORG_READ)
    organization = await session.get(Organization, principal.organization_id)
    if organization is None:
        # The principal came from a validated token, so this means the organization was
        # deleted mid-session. A 404 rather than a 500: from the caller's side the tenant
        # genuinely no longer exists.
        raise TenantIsolationError(
            "organization not found",
            context={"organization_id": str(principal.organization_id)},
        )
    return organization


async def update_organization(
    session: AsyncSession,
    principal: Principal,
    payload: OrganizationUpdateIn,
) -> Organization:
    """Rename, re-cap concurrency, or replace policy.

    ``policy`` is validated through :class:`~app.schemas.organization.OrgPolicy` here
    rather than at the wire boundary, so adding a policy key does not require a schema
    release -- but an *unknown* key is still rejected, because ``OrgPolicy`` forbids
    extras.  A silently-ignored policy key is the failure mode this guards against: an
    operator who believes they have restricted something.

    The slug is intentionally immutable.  It appears in URLs and in DefectDojo product
    names; renaming it would orphan both.
    """
    principal.require(Permission.ORG_MANAGE)
    organization = await get_organization(session, principal)

    changes: dict[str, Any] = {}
    if payload.name is not None and payload.name.strip() != organization.name:
        changes["name"] = payload.name.strip()
        organization.name = payload.name.strip()
    if (
        payload.max_concurrent_scanner_jobs is not None
        and payload.max_concurrent_scanner_jobs != organization.max_concurrent_scanner_jobs
    ):
        changes["max_concurrent_scanner_jobs"] = payload.max_concurrent_scanner_jobs
        organization.max_concurrent_scanner_jobs = payload.max_concurrent_scanner_jobs
    if payload.policy is not None:
        previous_risk_weights = load_policy(organization).risk_weights.model_dump(mode="json")
        validated = _validate_policy(payload.policy)
        changes["policy_keys"] = sorted(validated.keys())
        organization.policy = validated
        if validated["risk_weights"] != previous_risk_weights:
            organization.risk_policy_version += 1
            changes["risk_policy_version"] = organization.risk_policy_version

    if not changes:
        return organization

    await session.flush()
    await audit.record(
        session,
        action=AuditAction.ORG_UPDATE,
        principal=principal,
        resource_type="organization",
        resource_id=organization.id,
        detail=changes,
    )
    return organization


def load_policy(organization: Organization) -> OrgPolicy:
    """Parse ``organizations.policy``, falling back to defaults on a bad row.

    A policy written by an older build -- or by a migration that has since changed the
    key names -- must not break every assessment in the organization.  The failure is
    logged at WARNING and the defaults apply, which is the *more* restrictive outcome for
    every field except ``denied_targets`` (whose global list is unaffected either way).
    """
    if not organization.policy:
        return OrgPolicy()
    try:
        return OrgPolicy.model_validate(organization.policy)
    except ValueError as exc:
        log.warning(
            "organization.policy_invalid",
            organization_id=str(organization.id),
            error=str(exc)[:400],
        )
        return OrgPolicy()


def _validate_policy(raw: dict[str, Any]) -> dict[str, Any]:
    try:
        policy = OrgPolicy.model_validate(raw)
    except ValueError as exc:
        raise InvalidConfigurationError(
            "invalid organization policy",
            user_message="That policy contains unknown or invalid settings.",
            context={"errors": str(exc)[:1000]},
            cause=exc,
        ) from exc
    # ``mode="json"`` so the JSONB column receives plain strings for the enum members
    # rather than ``Severity`` instances, which asyncpg cannot adapt.
    return policy.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Membership reads
# ---------------------------------------------------------------------------


#: Sorts owners first, viewers last, in SQL. A Python-side sort would only order the
#: *current page*, which is worse than no ordering at all -- it looks sorted. Built from
#: ``Role.rank`` so the two cannot drift, and negated because ORDER BY ascends.
_ROLE_RANK_ORDER = case(
    {role.value: -role.rank for role in Role},
    value=Membership.role,
    # Unreachable while the ``valid_role`` CHECK holds; sorts an impossible value last
    # rather than making the whole query fail.
    else_=1,
)


async def list_members(
    session: AsyncSession,
    principal: Principal,
    *,
    pagination: PaginationParams | None = None,
) -> tuple[Sequence[Membership], int]:
    """The organization's members, owners first, each with its ``user`` loaded.

    Ordering by role rank rather than by name puts the people who can act on an escalation
    at the top of the page.  ``id`` breaks ties so paging is stable.
    """
    principal.require(Permission.ORG_READ)
    page = pagination or PaginationParams()

    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Membership)
                .where(Membership.organization_id == principal.organization_id)
            )
        ).scalar_one()
    )
    stmt = (
        select(Membership)
        .where(Membership.organization_id == principal.organization_id)
        .options(selectinload(Membership.user))
        .order_by(_ROLE_RANK_ORDER, Membership.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return rows, total


async def memberships_for_user(session: AsyncSession, user_id: uuid.UUID) -> Sequence[Membership]:
    """Every organization a user belongs to, with ``organization`` loaded.

    Backs ``MeOut.organizations``, so the eager load is required rather than an
    optimization: :data:`~app.db.base.LAZY` makes the later attribute access raise.
    """
    stmt = (
        select(Membership)
        .where(Membership.user_id == user_id)
        .options(selectinload(Membership.organization))
        .order_by(Membership.is_default.desc(), Membership.created_at)
    )
    return (await session.execute(stmt)).scalars().all()


async def resolve_membership(
    session: AsyncSession,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> Membership | None:
    """The membership binding one user to one organization, or ``None``.

    Returns ``None`` rather than raising because both callers -- token validation and
    organization switching -- need to turn the miss into their own error: an expired
    authority in one case, a bad request in the other.
    """
    stmt = select(Membership).where(
        Membership.user_id == user_id,
        Membership.organization_id == organization_id,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def default_membership(session: AsyncSession, user_id: uuid.UUID) -> Membership | None:
    """The organization a fresh sign-in lands in.

    Prefers the one flagged ``is_default``, then the oldest.  Falling back to *oldest*
    rather than to an arbitrary row means a user whose default flag was lost still lands
    somewhere predictable.
    """
    stmt = (
        select(Membership)
        .where(Membership.user_id == user_id)
        .options(selectinload(Membership.organization))
        .order_by(Membership.is_default.desc(), Membership.created_at)
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


def membership_out(membership: Membership) -> MembershipOut:
    """Project a membership for ``MeOut``.

    Requires ``membership.organization`` to be loaded; see :func:`memberships_for_user`.
    """
    return MembershipOut(
        organization_id=membership.organization_id,
        organization_name=membership.organization.name,
        organization_slug=membership.organization.slug,
        role=membership.role_enum,
        is_default=membership.is_default,
        joined_at=membership.accepted_at,
    )


# ---------------------------------------------------------------------------
# Membership writes
# ---------------------------------------------------------------------------


async def invite_member(
    session: AsyncSession,
    principal: Principal,
    payload: MemberInviteIn,
) -> tuple[Membership, User, bool]:
    """Add someone to the caller's organization.

    Returns ``(membership, user, user_was_created)``.  The third element tells the route
    whether to mint an invite credential: an existing Cynux user already has a password
    and must not be sent a reset link they did not ask for, which would otherwise be an
    account-takeover primitive available to any admin of any organization.

    A brand-new user is created with a random password nobody holds -- not with a blank or
    well-known one -- so the account is unusable until the invite token is redeemed even
    if the email never arrives.
    """
    principal.require(Permission.MEMBER_MANAGE)
    _assert_can_grant(principal, payload.role)

    email = payload.email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()

    # Memberships are the paid-capacity unit, so serialize the duplicate check, quota check
    # and insert per organization.  A user may still be invited to a different organization
    # concurrently; that is intentionally independent and handled by the user-email unique
    # constraint below.
    organization = (
        await session.execute(
            select(Organization)
            .where(Organization.id == principal.organization_id)
            .with_for_update()
        )
    ).scalar_one()
    if user is not None:
        existing = await resolve_membership(session, user.id, principal.organization_id)
        if existing is not None:
            raise ConflictError(
                "already a member",
                user_message="That person is already a member of this organization.",
                context={"role": existing.role},
            )
    assert_member_capacity(
        current_members=await _count_organization_members(session, principal.organization_id),
        new_members=1,
        entitlements=load_entitlements(organization.entitlements),
    )

    created = user is None
    if user is None:
        user = User(
            email=email,
            full_name=payload.full_name,
            # 32 bytes of urlsafe entropy, hashed and discarded. Unusable by construction.
            password_hash=hash_password(secrets.token_urlsafe(32)),
            is_active=True,
            is_email_verified=False,
        )
        session.add(user)
        try:
            await session.flush()
        except IntegrityError as exc:
            # Two admins invited the same new address at once. See the note in
            # :func:`create_organization` for why this does not roll back.
            raise ConflictError(
                "user created concurrently",
                user_message="That user was just added. Refresh and try again.",
                cause=exc,
            ) from exc

    membership = Membership(
        organization_id=principal.organization_id,
        user_id=user.id,
        role=payload.role.value,
        is_default=not await _has_any_membership(session, user.id),
        invited_by_id=principal.user_id,
        # ``accepted_at`` stays NULL until the invitee signs in. It is the field that
        # distinguishes "invited" from "joined" on the members table.
        accepted_at=None,
    )
    session.add(membership)
    await session.flush()

    await audit.record(
        session,
        action=AuditAction.MEMBER_INVITE,
        principal=principal,
        resource_type="membership",
        resource_id=membership.id,
        detail={"invited_email": email, "role": payload.role.value, "new_user": created},
    )
    return membership, user, created


async def change_member_role(
    session: AsyncSession,
    principal: Principal,
    membership_id: uuid.UUID,
    role: Role,
) -> Membership:
    """Change one member's role.

    Refuses three things, each for a distinct reason:

    * granting a role above the caller's own -- privilege escalation;
    * changing the caller's *own* role -- the same escalation by a different route, since
      an admin holds ``MEMBER_MANAGE`` and could otherwise promote themselves to owner;
    * demoting the last owner -- leaves the organization unadministrable.
    """
    principal.require(Permission.MEMBER_MANAGE)
    _assert_can_grant(principal, role)

    membership = await _get_membership(session, principal, membership_id)
    if membership.user_id == principal.user_id:
        raise PermissionDeniedError(
            "cannot change your own role",
            user_message="You cannot change your own role. Ask another owner.",
            context={"membership_id": str(membership_id)},
        )
    if membership.role == role.value:
        return membership
    if membership.role == Role.OWNER.value and await _owner_count(session, principal) <= 1:
        raise ConflictError(
            "last owner",
            user_message="An organization must keep at least one owner.",
            context={"membership_id": str(membership_id)},
        )

    previous = membership.role
    membership.role = role.value
    await session.flush()
    await audit.record(
        session,
        action=AuditAction.MEMBER_ROLE_CHANGE,
        principal=principal,
        resource_type="membership",
        resource_id=membership.id,
        detail={
            "target_user_id": str(membership.user_id),
            "from_role": previous,
            "to_role": role.value,
        },
    )
    log.info(
        "membership.role_changed",
        membership_id=str(membership.id),
        from_role=previous,
        to_role=role.value,
        **principal.to_log_fields(),
    )
    return membership


async def remove_member(
    session: AsyncSession,
    principal: Principal,
    membership_id: uuid.UUID,
) -> None:
    """Revoke someone's access to the caller's organization.

    Deletes the membership, never the ``User``: the person may belong to other
    organizations, and their id is referenced by assessments and audit rows that must stay
    attributable (FR-032).

    Self-removal is allowed -- leaving an organization is legitimate -- but not for the
    last owner, and the caller's tokens keep working until they expire or they sign out.
    Immediate revocation is the deny list's job; wiring it here would make this function
    depend on Redis for a case the API layer already handles.
    """
    principal.require(Permission.MEMBER_MANAGE)
    membership = await _get_membership(session, principal, membership_id)

    if membership.role == Role.OWNER.value and await _owner_count(session, principal) <= 1:
        raise ConflictError(
            "last owner",
            user_message="An organization must keep at least one owner.",
            context={"membership_id": str(membership_id)},
        )

    detail = {"target_user_id": str(membership.user_id), "role": membership.role}
    await session.delete(membership)
    await session.flush()
    await audit.record(
        session,
        action=AuditAction.MEMBER_REMOVE,
        principal=principal,
        resource_type="membership",
        resource_id=membership_id,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _assert_can_grant(principal: Principal, role: Role) -> None:
    """Refuse to hand out authority the caller does not hold.

    Rank comparison rather than a permission check: ``MEMBER_MANAGE`` says *whether* the
    caller may assign roles, not *which* ones.  Without this an admin -- who deliberately
    lacks ``ORG_MANAGE`` -- could mint an owner and inherit it on the next login.
    """
    if role.rank > principal.role.rank:
        raise PermissionDeniedError(
            f"{principal.role.value} cannot grant {role.value}",
            user_message="You cannot assign a role higher than your own.",
            context={"caller_role": principal.role.value, "requested_role": role.value},
        )


async def _get_membership(
    session: AsyncSession,
    principal: Principal,
    membership_id: uuid.UUID,
) -> Membership:
    """Load a membership, scoped to the caller's organization.

    The organization filter is in the ``where`` rather than checked afterwards, so a
    membership id from another tenant is indistinguishable from one that does not exist
    (SEC-003).
    """
    stmt = select(Membership).where(
        Membership.id == membership_id,
        Membership.organization_id == principal.organization_id,
    )
    membership = (await session.execute(stmt)).scalar_one_or_none()
    if membership is None:
        raise ResourceNotFoundError(
            "membership not found",
            user_message="That member does not exist in this organization.",
            context={"membership_id": str(membership_id)},
        )
    return membership


async def _owner_count(session: AsyncSession, principal: Principal) -> int:
    stmt = (
        select(func.count())
        .select_from(Membership)
        .where(
            Membership.organization_id == principal.organization_id,
            Membership.role == Role.OWNER.value,
        )
    )
    return int((await session.execute(stmt)).scalar_one())


async def _count_organization_members(session: AsyncSession, organization_id: uuid.UUID) -> int:
    """Count invited and accepted memberships occupying organization capacity."""
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Membership)
                .where(Membership.organization_id == organization_id)
            )
        ).scalar_one()
    )


async def _has_any_membership(session: AsyncSession, user_id: uuid.UUID) -> bool:
    stmt = select(func.count()).select_from(Membership).where(Membership.user_id == user_id)
    return int((await session.execute(stmt)).scalar_one()) > 0


async def _user_for_principal(session: AsyncSession, principal: Principal) -> User:
    """Load the actor behind a membership-backed principal for tenant creation."""
    user = await session.get(User, principal.user_id)
    if user is None:
        raise TenantIsolationError(
            "principal user not found",
            context={"user_id": str(principal.user_id)},
        )
    return user


__all__ = [
    "allocate_slug",
    "change_member_role",
    "create_client_organization",
    "create_organization",
    "default_membership",
    "delegate_client_access",
    "get_organization",
    "invite_member",
    "list_members",
    "list_client_portfolio",
    "load_policy",
    "membership_out",
    "memberships_for_user",
    "remove_member",
    "resolve_membership",
    "slugify",
    "update_organization",
]
