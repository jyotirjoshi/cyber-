from __future__ import annotations

import datetime as dt


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
