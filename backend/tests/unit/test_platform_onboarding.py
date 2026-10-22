from __future__ import annotations

import datetime as dt
import uuid
from types import SimpleNamespace

import pytest

from app.db.enums import Role
from app.services.context import Principal


def test_onboarding_progress_uses_real_completion_and_one_next_action() -> None:
    from app.services.platform_onboarding import build_onboarding

    result = build_onboarding(
        member_count=2,
        verified_integrations=1,
        asset_count=4,
        completed_assessments=0,
        completed_agent_runs=0,
        remediation_tickets=0,
        active_detection_rules=1,
        scheduled_reports=1,
        backup_ready=False,
        restore_ready=False,
        now=dt.datetime(2026, 10, 22, tzinfo=dt.UTC),
    )

    assert result.completed == 4
    assert result.total == 8
    assert result.percent == 50
    assert result.next_step == "first_assessment"
    assert [step.status for step in result.steps[:3]] == ["complete"] * 3
    assert result.steps[3].status == "ready"
    assert [step.status for step in result.steps[4:6]] == ["blocked", "blocked"]
    assert result.steps[6].status == "complete"
    assert result.steps[7].status == "blocked"
    assert result.first_value_score == 50
    assert [area.key for area in result.first_value_areas if area.achieved] == [
        "sources",
        "inventory",
        "continuous_operations",
    ]
    assert (
        next(area for area in result.first_value_areas if area.key == "exposure").gap
        == "Complete an authorized assessment"
    )


def test_onboarding_is_complete_only_with_operational_and_recovery_evidence() -> None:
    from app.services.platform_onboarding import build_onboarding

    result = build_onboarding(
        member_count=3,
        verified_integrations=2,
        asset_count=20,
        completed_assessments=2,
        completed_agent_runs=3,
        remediation_tickets=1,
        active_detection_rules=2,
        scheduled_reports=1,
        backup_ready=True,
        restore_ready=True,
        now=dt.datetime(2026, 10, 22, tzinfo=dt.UTC),
    )

    assert result.complete is True
    assert result.percent == 100
    assert result.next_step is None
    assert all(step.status == "complete" for step in result.steps)


def test_platform_onboarding_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/platform/onboarding" in {route.path for route in api_router.routes}


@pytest.mark.asyncio
async def test_onboarding_counts_memberships_without_tenant_repository(monkeypatch) -> None:
    """Membership has an organization FK, but intentionally is not a TenantMixin model."""
    from app.services import platform_onboarding

    async def readiness(*_args, **_kwargs):
        return SimpleNamespace(checks=[])

    class Session:
        def __init__(self) -> None:
            self.statements: list[object] = []

        async def scalar(self, statement):
            self.statements.append(statement)
            return 0

    monkeypatch.setattr(platform_onboarding, "get_readiness", readiness)
    session = Session()
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER
    )

    result = await platform_onboarding.get_onboarding(session, principal)  # type: ignore[arg-type]

    assert result.total == 8
    assert len(session.statements) == 8
    membership_sql = str(session.statements[0])
    assert "memberships.organization_id" in membership_sql
    assert "memberships.accepted_at IS NOT NULL" in membership_sql
