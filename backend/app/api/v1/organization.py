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
from app.db.enums import Permission
from app.db.models.identity import Membership, OidcConnection, SamlConnection, ScimProvisioningToken, User
from app.db.repository import tenant_select
from app.schemas.common import OkOut, Page
from app.schemas.organization import (
    ClientOrganizationCreateIn,
    ClientOrganizationDelegateIn,
    ClientOrganizationPortfolioOut,
    MemberInviteIn,
    MemberOut,
    MemberRoleIn,
    OrganizationOut,
    OrganizationUpdateIn,
)
from app.schemas.scim import (
    ScimProvisioningTokenCreateIn,
    ScimProvisioningTokenIssuedOut,
    ScimProvisioningTokenOut,
)
from app.schemas.sso import (
    OidcConnectionOut,
    OidcConnectionUpsertIn,
    SamlConnectionOut,
    SamlConnectionUpsertIn,
)
from app.services import auth as auth_service
from app.services import organization as organization_service
from app.services import scim as scim_service
from app.services import sso as sso_service
from app.services.audit import AuditAction, record

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


@router.get("/clients", response_model=list[ClientOrganizationPortfolioOut])
async def list_client_organizations(
    principal: PrincipalDep, session: DbSession
) -> list[ClientOrganizationPortfolioOut]:
    """List direct MSSP customer tenants with portfolio-only risk counters."""
    return await organization_service.list_client_portfolio(session, principal)


@router.post(
    "/clients",
    response_model=OrganizationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_client_organization(
    payload: ClientOrganizationCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> OrganizationOut:
    """Create an isolated client tenant and grant the creator owner access to it."""
    organization = await organization_service.create_client_organization(session, principal, payload)
    await session.commit()
    return OrganizationOut.model_validate(organization)


@router.post("/clients/{client_organization_id}/delegates", response_model=MemberOut)
async def delegate_client_organization_access(
    client_organization_id: uuid.UUID,
    payload: ClientOrganizationDelegateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> MemberOut:
    """Delegate one parent-team member into a direct customer tenant."""
    membership, user = await organization_service.delegate_client_access(
        session, principal, client_organization_id, payload
    )
    await session.commit()
    return _member_out(membership, user)


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


@router.get("/scim/tokens", response_model=list[ScimProvisioningTokenOut])
async def list_scim_provisioning_tokens(
    principal: PrincipalDep, session: DbSession
) -> list[ScimProvisioningToken]:
    """List non-secret provisioning credential metadata for the active tenant."""
    principal.require(Permission.ORG_MANAGE)
    return list(
        (
            await session.scalars(
                tenant_select(ScimProvisioningToken, principal.organization_id)
                .order_by(ScimProvisioningToken.created_at.desc())
                .limit(200)
            )
        ).all()
    )


@router.post(
    "/scim/tokens",
    response_model=ScimProvisioningTokenIssuedOut,
    status_code=status.HTTP_201_CREATED,
)
async def issue_scim_provisioning_token(
    payload: ScimProvisioningTokenCreateIn, principal: PrincipalDep, session: DbSession
) -> ScimProvisioningTokenIssuedOut:
    """Issue a SCIM bearer secret once; only its verifier remains in storage."""
    issued = await scim_service.issue_provisioning_token(session, principal, payload)
    await record(
        session,
        action=AuditAction.SCIM_TOKEN_CREATE,
        principal=principal,
        resource_type="scim_provisioning_token",
        resource_id=issued.token.id,
        detail={"key_prefix": issued.token.key_prefix},
    )
    await session.commit()
    return ScimProvisioningTokenIssuedOut(
        **ScimProvisioningTokenOut.model_validate(issued.token).model_dump(), secret=issued.secret
    )


@router.post("/scim/tokens/{token_id}/revoke", response_model=ScimProvisioningTokenOut)
async def revoke_scim_provisioning_token(
    token_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> ScimProvisioningTokenOut:
    """Revoke a provisioner without deleting forensic metadata."""
    token = await scim_service.revoke_provisioning_token(session, principal, token_id)
    await record(
        session,
        action=AuditAction.SCIM_TOKEN_REVOKE,
        principal=principal,
        resource_type="scim_provisioning_token",
        resource_id=token.id,
        detail={"key_prefix": token.key_prefix},
    )
    await session.commit()
    return ScimProvisioningTokenOut.model_validate(token)


@router.put("/sso/oidc", response_model=OidcConnectionOut)
async def configure_oidc_sso(
    payload: OidcConnectionUpsertIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> OidcConnectionOut:
    """Configure the active organization's encrypted OIDC client connection."""
    connection = await sso_service.configure_oidc_connection(
        session, principal, payload, settings=settings
    )
    await record(
        session,
        action=AuditAction.OIDC_CONNECTION_UPSERT,
        principal=principal,
        resource_type="oidc_connection",
        resource_id=connection.id,
        detail={"issuer_url": connection.issuer_url, "client_id": connection.client_id},
    )
    await session.commit()
    return OidcConnectionOut.model_validate(connection)


@router.get("/sso/oidc", response_model=OidcConnectionOut | None)
async def get_oidc_sso(principal: PrincipalDep, session: DbSession) -> OidcConnection | None:
    """Return non-secret OIDC metadata for the active tenant's administrator."""
    principal.require(Permission.ORG_MANAGE)
    return (
        await session.execute(
            tenant_select(OidcConnection, principal.organization_id).limit(1)
        )
    ).scalar_one_or_none()


@router.put("/sso/saml", response_model=SamlConnectionOut)
async def configure_saml_sso(
    payload: SamlConnectionUpsertIn, principal: PrincipalDep, session: DbSession
) -> SamlConnectionOut:
    """Configure the active organization's SAML identity-provider trust material."""
    connection = await sso_service.configure_saml_connection(session, principal, payload)
    await record(
        session,
        action=AuditAction.SAML_CONNECTION_UPSERT,
        principal=principal,
        resource_type="saml_connection",
        resource_id=connection.id,
        detail={"idp_entity_id": connection.idp_entity_id, "idp_sso_url": connection.idp_sso_url},
    )
    await session.commit()
    return SamlConnectionOut.model_validate(connection)


@router.get("/sso/saml", response_model=SamlConnectionOut | None)
async def get_saml_sso(principal: PrincipalDep, session: DbSession) -> SamlConnection | None:
    """Return non-secret SAML trust metadata for the active tenant's administrator."""
    principal.require(Permission.ORG_MANAGE)
    return (
        await session.execute(
            tenant_select(SamlConnection, principal.organization_id).limit(1)
        )
    ).scalar_one_or_none()


__all__ = ["router"]
