"""Organization capability limits for self-service SaaS onboarding.

This is intentionally separate from organization security policy. Policy decides
what a customer is allowed to scan; entitlements decide what product capacity is
available to that customer. Missing or malformed stored values resolve to the
safe community defaults so a legacy tenant can never acquire unlimited capacity.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.core.errors import QuotaExceededError


class OrganizationEntitlements(BaseModel):
    """The internal plan snapshot attached to one organization.

    Billing is deliberately outside this model. Platform operators can change the
    snapshot later without coupling product authorization to a payment provider.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_assets: int = Field(ge=1, le=100_000)
    max_members: int = Field(ge=1, le=10_000)
    max_integrations: int = Field(ge=0, le=10_000)
    max_active_assessments: int = Field(ge=0, le=1_000)
    allow_active_validation: bool = False
    allow_agentic_pentest: bool = False

    @model_validator(mode="after")
    def _agentic_execution_requires_validation(self) -> OrganizationEntitlements:
        if self.allow_agentic_pentest and not self.allow_active_validation:
            return self.model_copy(update={"allow_agentic_pentest": False})
        return self


DEFAULT_ENTITLEMENTS = OrganizationEntitlements(
    max_assets=100,
    max_members=5,
    max_integrations=5,
    max_active_assessments=1,
)


def load_entitlements(value: dict[str, Any] | None) -> OrganizationEntitlements:
    """Load an organization's stored limits, failing closed on invalid data."""
    if not value:
        return DEFAULT_ENTITLEMENTS
    try:
        return OrganizationEntitlements.model_validate(value)
    except ValidationError:
        return DEFAULT_ENTITLEMENTS


def assert_asset_capacity(
    *,
    current_assets: int,
    new_assets: int,
    entitlements: OrganizationEntitlements,
) -> None:
    """Refuse inventory growth above the organization's assigned asset limit."""
    if current_assets + new_assets <= entitlements.max_assets:
        return
    raise QuotaExceededError(
        "organization asset capacity reached",
        user_message=(
            "This organization has reached its asset limit. Remove inactive assets or ask an "
            "administrator to increase the organization's capacity."
        ),
        context={
            "current_assets": current_assets,
            "new_assets": new_assets,
            "max_assets": entitlements.max_assets,
        },
    )


def assert_integration_capacity(
    *,
    current_integrations: int,
    new_integrations: int,
    entitlements: OrganizationEntitlements,
) -> None:
    """Raise a clear quota error when a new connector would exceed the plan."""
    if current_integrations + new_integrations <= entitlements.max_integrations:
        return
    raise QuotaExceededError(
        "organization integration capacity reached",
        user_message=(
            "This organization has reached its integration limit. Remove an unused integration "
            "or ask an administrator to increase the organization's capacity."
        ),
        context={
            "current_integrations": current_integrations,
            "new_integrations": new_integrations,
            "max_integrations": entitlements.max_integrations,
        },
    )


def assert_active_assessment_capacity(
    *,
    current_active_assessments: int,
    new_active_assessments: int,
    entitlements: OrganizationEntitlements,
) -> None:
    """Prevent an organization from queueing more live engagements than its plan allows."""
    if (
        current_active_assessments + new_active_assessments
        <= entitlements.max_active_assessments
    ):
        return
    raise QuotaExceededError(
        "organization active assessment capacity reached",
        user_message=(
            "This organization has reached its active assessment limit. Complete or cancel an "
            "existing assessment, or ask an administrator to increase the organization's capacity."
        ),
        context={
            "current_active_assessments": current_active_assessments,
            "new_active_assessments": new_active_assessments,
            "max_active_assessments": entitlements.max_active_assessments,
        },
    )


def assert_member_capacity(
    *,
    current_members: int,
    new_members: int,
    entitlements: OrganizationEntitlements,
) -> None:
    """Refuse invitations that would exceed the organization's member capacity."""
    if current_members + new_members <= entitlements.max_members:
        return
    raise QuotaExceededError(
        "organization member capacity reached",
        user_message=(
            "This organization has reached its member limit. Remove an inactive member or ask an "
            "administrator to increase the organization's capacity."
        ),
        context={
            "current_members": current_members,
            "new_members": new_members,
            "max_members": entitlements.max_members,
        },
    )


__all__ = [
    "DEFAULT_ENTITLEMENTS",
    "OrganizationEntitlements",
    "assert_active_assessment_capacity",
    "assert_asset_capacity",
    "assert_integration_capacity",
    "assert_member_capacity",
    "load_entitlements",
]
