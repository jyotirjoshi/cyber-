"""Organization and membership wire types (FR-001, FR-002).

A user is global; *access* is granted by a membership carrying exactly one role.  Every
one of these types therefore names its ``organization_id`` explicitly rather than
letting it be implied by the session, because the same user may hold different roles in
different organizations and the UI has to be able to say which one it is showing
(SEC-003).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.db.enums import Role, Severity
from app.services.entitlements import OrganizationEntitlements, load_entitlements

#: Roles that can be assigned when inviting a member. ``owner`` is excluded:
#: ownership is granted only by an existing owner promoting a member via PATCH,
#: never by minting it on a fresh invite. This prevents the invite endpoint from
#: being used to bootstrap a second owner without going through the normal flow.
_INVITABLE_ROLES = frozenset(
    {
        Role.VIEWER,
        Role.DEVELOPER,
        Role.SECURITY_ENGINEER,
        Role.ADMIN,
    }
)


class RiskWeights(BaseModel):
    """Tenant-owned 0-100 contribution ceilings for canonical risk scoring."""

    model_config = ConfigDict(extra="forbid")

    severity: float = Field(default=45.0, ge=0, le=100)
    exploitation: float = Field(default=20.0, ge=0, le=100)
    exploit_probability: float = Field(default=12.0, ge=0, le=100)
    exposure: float = Field(default=10.0, ge=0, le=100)
    asset_criticality: float = Field(default=10.0, ge=0, le=100)
    ransomware: float = Field(default=3.0, ge=0, le=100)

    @model_validator(mode="after")
    def require_full_scale(self) -> RiskWeights:
        if abs(sum(self.model_dump().values()) - 100.0) > 0.000001:
            raise ValueError("risk weights must add up to 100")
        return self


class OrgPolicy(BaseModel):
    """Per-organization overrides, stored in ``organizations.policy`` as JSONB.

    Security-control fields can only make Cynux **more** restrictive or change where output is
    routed; risk weights change ranking but never authorization. There is deliberately no key that switches off the approval interrupt: FR-011
    makes human approval mandatory before any active scanning, and a policy flag able to
    waive it would turn the one hard guardrail in the system into a configuration setting.
    Widening the target policy is likewise impossible -- ``denied_targets`` is additive on
    top of the global deny list and there is no allow-list counterpart (FR-006).

    ``extra="forbid"`` matters more than usual: this model is loaded from a JSONB column
    that an earlier build may have written.  A typo'd or retired key surfaces as a loud
    validation error naming the organization, rather than as a policy that reads as
    "default" because nothing matched.
    """

    model_config = ConfigDict(extra="forbid")

    #: Extra host / CIDR / domain patterns this organization refuses to scan.
    denied_targets: list[str] = Field(default_factory=list, max_length=500)
    #: Severity at or above which a finding raises an immediate notification (FR-029).
    notify_min_severity: Severity = Severity.HIGH
    #: Overrides the global Slack channel for this organization's notifications.
    slack_channel: str | None = Field(default=None, max_length=120)
    #: Copied on every assessment-completed email, in addition to the requester.
    email_recipients: list[EmailStr] = Field(default_factory=list, max_length=50)
    #: Require approval even for a passive-only assessment. Active scanning always
    #: requires it; this only closes the passive exception.
    require_approval_for_passive: bool = False
    #: Overrides ``CYNUX_AGENT__APPROVAL_TTL_HOURS`` for this organization. Bounded at a
    #: week: an approval that outlives the assessment context it was granted in is no
    #: longer informed consent.
    approval_ttl_hours: int | None = Field(default=None, ge=1, le=168)
    #: Skip Jira ticket creation for findings below ``notify_min_severity`` even when the
    #: integration is configured (FR-027). Reduces ticket noise without disabling it.
    ticket_min_severity: Severity | None = None
    risk_weights: RiskWeights = Field(default_factory=RiskWeights)


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    max_concurrent_scanner_jobs: int
    created_at: dt.datetime
    entitlements: OrganizationEntitlements
    policy: OrgPolicy = Field(default_factory=OrgPolicy)

    @field_validator("entitlements", mode="before")
    @classmethod
    def _resolve_legacy_entitlements(cls, value: dict[str, Any] | None) -> OrganizationEntitlements:
        return load_entitlements(value)

    @field_validator("policy", mode="before")
    @classmethod
    def _resolve_policy(cls, value: dict[str, Any] | None) -> OrgPolicy:
        try:
            return OrgPolicy.model_validate(value or {})
        except ValueError:
            return OrgPolicy()


class OrganizationCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=200)
    #: Optional; derived from ``name`` when omitted.
    slug: str | None = Field(
        default=None, min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"
    )


class OrganizationUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=2, max_length=200)
    max_concurrent_scanner_jobs: int | None = Field(default=None, ge=1, le=64)
    #: Free-form policy overrides (extra denied targets, approval thresholds,
    #: notification routing). Shape is validated by the organization service, not here,
    #: so adding a policy key does not require a schema release.
    policy: dict[str, Any] | None = None


class MembershipOut(BaseModel):
    """One organization as seen from a user's perspective (used by ``MeOut``)."""

    model_config = ConfigDict(from_attributes=True)

    organization_id: uuid.UUID
    organization_name: str
    organization_slug: str
    role: Role
    is_default: bool = False
    joined_at: dt.datetime | None = None


class MemberOut(BaseModel):
    """One user as seen from an organization's perspective (the members table)."""

    model_config = ConfigDict(from_attributes=True)

    membership_id: uuid.UUID
    user_id: uuid.UUID
    email: EmailStr
    full_name: str | None = None
    role: Role
    is_active: bool
    accepted_at: dt.datetime | None = None
    last_login_at: dt.datetime | None = None


class MemberInviteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    role: Role = Role.VIEWER
    full_name: str | None = Field(default=None, max_length=200)


class MemberRoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role


__all__ = [
    "MemberInviteIn",
    "MemberOut",
    "MemberRoleIn",
    "MembershipOut",
    "OrgPolicy",
    "RiskWeights",
    "OrganizationCreateIn",
    "OrganizationOut",
    "OrganizationUpdateIn",
]
