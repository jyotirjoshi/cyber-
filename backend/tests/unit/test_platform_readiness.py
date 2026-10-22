from __future__ import annotations

import datetime as dt


def test_readiness_requires_recent_backup_and_restore_evidence() -> None:
    from app.services.platform_readiness import build_readiness

    now = dt.datetime(2026, 10, 22, tzinfo=dt.UTC)
    result = build_readiness(
        organization_active=True,
        member_count=2,
        asset_count=12,
        configured_integrations=1,
        verified_integrations=1,
        active_api_keys=1,
        active_detection_rules=1,
        scheduled_reports=1,
        backup_verified_at=now - dt.timedelta(hours=26),
        restore_tested_at=now - dt.timedelta(days=91),
        recovery_point_minutes=60,
        recovery_time_minutes=240,
        backup_evidence_ref="gcp-backup:123",
        restore_evidence_ref="drill:2026-q2",
        now=now,
    )

    checks = {check.key: check for check in result.checks}
    assert checks["backup_freshness"].status == "blocked"
    assert checks["restore_drill"].status == "blocked"
    assert result.ready is False
    assert result.score < 100


def test_readiness_is_ready_only_when_all_required_controls_pass() -> None:
    from app.services.platform_readiness import build_readiness

    now = dt.datetime(2026, 10, 22, tzinfo=dt.UTC)
    result = build_readiness(
        organization_active=True,
        member_count=2,
        asset_count=12,
        configured_integrations=1,
        verified_integrations=1,
        active_api_keys=1,
        active_detection_rules=1,
        scheduled_reports=1,
        backup_verified_at=now - dt.timedelta(hours=2),
        restore_tested_at=now - dt.timedelta(days=10),
        recovery_point_minutes=60,
        recovery_time_minutes=240,
        backup_evidence_ref="gcp-backup:456",
        restore_evidence_ref="drill:2026-q3",
        now=now,
    )

    assert result.ready is True
    assert result.score == 100
    assert all(check.status == "passed" for check in result.checks)


def test_platform_readiness_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/platform/readiness" in {route.path for route in api_router.routes}


def test_org_policy_accepts_bounded_recovery_evidence() -> None:
    from app.schemas.organization import OrgPolicy

    policy = OrgPolicy.model_validate(
        {
            "recovery_point_minutes": 60,
            "recovery_time_minutes": 240,
            "dr_backup_verified_at": "2026-10-22T10:00:00Z",
            "dr_backup_evidence_ref": "gcp:backup/2026-10-22",
            "dr_restore_tested_at": "2026-10-01T10:00:00Z",
            "dr_restore_evidence_ref": "runbook:restore-drill-17",
        }
    )

    assert policy.recovery_point_minutes == 60
    assert policy.recovery_time_minutes == 240
    assert policy.dr_backup_evidence_ref == "gcp:backup/2026-10-22"
