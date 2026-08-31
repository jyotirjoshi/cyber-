"""Organization settings and membership administration (FR-002, SEC-002, SEC-003).

Thin over :mod:`app.services.organization`, which owns every rule that matters here -- the
last-owner guard, the "no granting a role above your own" escalation check, and
tenant-scoped membership lookups that turn a foreign id into a 404 rather than a 403
(SEC-003).  These handlers adapt HTTP to those calls and commit the unit of work.

Two projections are built here by hand, and both are deliberate:

*   **The members list is :class:`MemberOut`, which spans two rows.**  A member is a
    ``Membership`` (the role, when they joined) plus the ``User`` it points at (their email,
    whether the account is active, last sign-in).  :func:`~app.services.organization.
    list_members` eager-loads the ``user`` relationship for exactly this reason; no service
    projector exists because the shape is a join the presentation layer owns.  ``PATCH`` on
    a role returns the same shape, but :func:`~app.services.organization.change_member_role`
    loads only the membership -- so the user is fetched by id before projecting, never off
    the ``user`` relationship, which is ``lazy="raise_on_sql"`` and unloaded there.

*   **An invite mints a credential the response never carries.**  ``invite_member`` creates
    the ``User`` and ``Membership`` but not the password material -- that is
    :func:`app.services.auth.issue_invite_token`'s job, called here only when the invitee is
    a brand-new account (an existing Cynux user already has a password and must not be handed
    a reset link they never asked for).  The link it returns is a single-use credential, so
    it is discarded exactly as the password-reset link is (SEC-002): delivery is the email
    integration's concern, never a response body.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import DbSession, PaginationDep, PrincipalDep, SettingsDep
from app.db.models.identity import Membership, User
from app.schemas.common import OkOut, Page
from app.schemas.organization import (
    MemberInviteIn,
    MemberOut,
    MemberRoleIn,
    OrganizationOut,
    OrganizationUpdateIn,
)
from app.services import auth as auth_service
from app.services import organization as organization_service

router = APIRouter(prefix="/organization", tags=["organization"])


def _member_out(membership: Membership, user: User) -> MemberOut:
    """Join a membership and its user into the members-table row (SEC-002).

    Built by hand because :class:`MemberOut` spans two rows: the role and join time come
    from the ``Membership``, the identity and account state from the ``User``.  Only the
    user's email is carried outward, never the ``User`` object itself.
    """
    return MemberOut(
        membership_id=membership.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role_enum,
        is_active=user.is_active,
        accepted_at=membership.accepted_at,
        last_login_at=user.last_login_at,
    )


@router.get("", response_model=OrganizationOut)
async def get_organization(principal: PrincipalDep, session: DbSession) -> OrganizationOut:
    """The caller's own organization (FR-002).

    Takes no id: a principal can read exactly one organization, and an id parameter would
    only exist to be rejected.  A tenant deleted mid-session is a 404 (SEC-003).
    """
    organization = await organization_service.get_organization(session, principal)
    return OrganizationOut.model_validate(organization)


@router.patch("", response_model=OrganizationOut)
async def update_organization(
    payload: OrganizationUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> OrganizationOut:
    """Rename, re-cap scanner concurrency, or replace policy (FR-002, ORG_MANAGE).

    The policy shape is validated in the service, not at the wire boundary, so an unknown
    key is a loud 422 rather than a silently-ignored setting.  The slug is immutable -- it
    names DefectDojo products and lives in URLs.
    """
    organization = await organization_service.update_organization(session, principal, payload)
    await session.commit()
    return OrganizationOut.model_validate(organization)


@router.get("/members", response_model=Page[MemberOut])
async def list_members(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
) -> Page[MemberOut]:
    """A page of the organization's members, owners first (FR-002, ORG_READ).

    Each row is projected from the membership and its eager-loaded ``user``; owners sort
    to the top so the people who can act on an escalation are the first thing seen.
    """
    rows, total = await organization_service.list_members(session, principal, pagination=pagination)
    return Page.build(
        [_member_out(membership, membership.user) for membership in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def invite_member(
    payload: MemberInviteIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> MemberOut:
    """Invite someone into the organization (FR-002, MEMBER_MANAGE, SEC-002).

    The service creates the ``User`` and ``Membership`` and reports whether the user was
    newly created.  Only then, and only for a brand-new account, is an invite credential
    minted -- an existing Cynux user already has a password.  That credential is a single-use
    link; it is deliberately discarded here rather than returned or logged (SEC-002), the
    same way the password-reset link is.
    """
    membership, user, created = await organization_service.invite_member(
        session, principal, payload
    )
    if created:
        organization = await organization_service.get_organization(session, principal)
        await auth_service.issue_invite_token(
            session, user=user, organization=organization, settings=settings
        )
    await session.commit()
    return _member_out(membership, user)


@router.patch("/members/{membership_id}", response_model=MemberOut)
async def change_member_role(
    membership_id: uuid.UUID,
    payload: MemberRoleIn,
    principal: PrincipalDep,
    session: DbSession,
) -> MemberOut:
    """Change one member's role (FR-002, MEMBER_MANAGE).

    The service refuses to grant a role above the caller's own, to change the caller's own
    role, or to demote the last owner.  The membership it returns has no ``user`` loaded, so
    the user is fetched by id for the projection rather than off the unloaded relationship.
    """
    membership = await organization_service.change_member_role(
        session, principal, membership_id, payload.role
    )
    user = await session.get(User, membership.user_id)
    assert user is not None  # membership.user_id is a NOT NULL FK to users.id  # noqa: S101
    await session.commit()
    return _member_out(membership, user)


@router.delete("/members/{membership_id}", response_model=OkOut)
async def remove_member(
    membership_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> OkOut:
    """Revoke a member's access (FR-002, MEMBER_MANAGE).

    Deletes the membership, never the ``User`` -- the person may belong to other
    organizations, and their id is referenced by assessments and audit rows that must stay
    attributable (FR-032).  The last owner cannot be removed.  Tokens already issued keep
    working until they expire or the user signs out; immediate revocation is the deny list's
    job, not this endpoint's.
    """
    await organization_service.remove_member(session, principal, membership_id)
    await session.commit()
    return OkOut()


__all__ = ["router"]
