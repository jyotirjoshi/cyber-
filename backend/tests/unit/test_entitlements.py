"""Self-service organization entitlements.

Entitlements are a commercial-control boundary, not an authorization boundary:
they constrain expensive SaaS capabilities while the RBAC and target-approval
guards remain mandatory for every organization.
"""

from __future__ import annotations

import pytest

from app.core.errors import QuotaExceededError
from app.db.models.identity import Organization
from app.schemas.organization import OrganizationOut
from app.services.entitlements import (
    DEFAULT_ENTITLEMENTS,
    assert_active_assessment_capacity,
    assert_asset_capacity,
    assert_integration_capacity,
    assert_member_capacity,
    load_entitlements,
)


def test_empty_stored_entitlements_use_the_safe_community_defaults() -> None:
    """Legacy organizations do not become unlimited when the feature is introduced."""
    entitlements = load_entitlements({})

    assert entitlements == DEFAULT_ENTITLEMENTS
    assert entitlements.max_assets == 100
    assert entitlements.max_members == 5
    assert entitlements.allow_active_validation is False


def test_stored_entitlements_cannot_enable_agentic_pentest_without_validation() -> None:
    """Risky autonomous execution must fail closed when its prerequisite is disabled."""
    entitlements = load_entitlements(
        {
            "max_assets": 250,
            "max_members": 10,
            "max_integrations": 20,
            "max_active_assessments": 3,
            "allow_active_validation": False,
            "allow_agentic_pentest": True,
        }
    )

    assert entitlements.allow_agentic_pentest is False


def test_organization_persists_and_projects_its_entitlement_snapshot() -> None:
    """Self-service organizations expose limits without exposing billing data."""
    assert "entitlements" in Organization.__table__.c

    payload = OrganizationOut.model_validate(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Acme Security",
            "slug": "acme-security",
            "is_active": True,
            "max_concurrent_scanner_jobs": 1,
            "created_at": "2026-09-30T00:00:00Z",
            "entitlements": DEFAULT_ENTITLEMENTS.model_dump(),
        }
    )

    assert payload.entitlements.max_integrations == 5


def test_asset_capacity_blocks_only_new_assets_beyond_the_organization_limit() -> None:
    """Rediscovery must not fail merely because the inventory is already full."""
    assert_asset_capacity(current_assets=100, new_assets=0, entitlements=DEFAULT_ENTITLEMENTS)

    with pytest.raises(QuotaExceededError) as excinfo:
        assert_asset_capacity(current_assets=99, new_assets=2, entitlements=DEFAULT_ENTITLEMENTS)

    assert "asset limit" in excinfo.value.user_message.lower()


def test_integration_capacity_allows_updates_but_blocks_new_connections_over_limit() -> None:
    """Editing an existing connector must remain possible at the plan limit."""
    assert_integration_capacity(
        current_integrations=DEFAULT_ENTITLEMENTS.max_integrations,
        new_integrations=0,
        entitlements=DEFAULT_ENTITLEMENTS,
    )

    with pytest.raises(QuotaExceededError) as excinfo:
        assert_integration_capacity(
            current_integrations=DEFAULT_ENTITLEMENTS.max_integrations,
            new_integrations=1,
            entitlements=DEFAULT_ENTITLEMENTS,
        )

    assert "integration limit" in excinfo.value.user_message.lower()


def test_active_assessment_capacity_fails_before_a_new_engagement_is_created() -> None:
    """An organization may not queue more assessments than its plan permits."""
    assert_active_assessment_capacity(
        current_active_assessments=0,
        new_active_assessments=1,
        entitlements=DEFAULT_ENTITLEMENTS,
    )

    with pytest.raises(QuotaExceededError) as excinfo:
        assert_active_assessment_capacity(
            current_active_assessments=1,
            new_active_assessments=1,
            entitlements=DEFAULT_ENTITLEMENTS,
        )

    assert "active assessment limit" in excinfo.value.user_message.lower()


def test_member_capacity_reserves_the_owner_and_blocks_only_additional_members() -> None:
    """A self-service organization cannot invite over its member limit."""
    assert_member_capacity(
        current_members=DEFAULT_ENTITLEMENTS.max_members,
        new_members=0,
        entitlements=DEFAULT_ENTITLEMENTS,
    )

    with pytest.raises(QuotaExceededError) as excinfo:
        assert_member_capacity(
            current_members=DEFAULT_ENTITLEMENTS.max_members,
            new_members=1,
            entitlements=DEFAULT_ENTITLEMENTS,
        )

    assert "member limit" in excinfo.value.user_message.lower()
