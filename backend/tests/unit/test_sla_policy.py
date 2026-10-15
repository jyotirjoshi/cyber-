"""SLA due-date policy contracts for canonical remediation work."""

from __future__ import annotations

import datetime as dt

import pytest

from app.db.enums import Severity


def test_sla_due_at_uses_severity_and_asset_criticality() -> None:
    from app.services.sla import calculate_due_at

    opened_at = dt.datetime(2026, 10, 8, 9, tzinfo=dt.UTC)

    assert calculate_due_at(
        Severity.CRITICAL, "critical", opened_at=opened_at
    ) == opened_at + dt.timedelta(days=1)
    assert calculate_due_at(
        Severity.HIGH, "medium", opened_at=opened_at
    ) == opened_at + dt.timedelta(days=14)


def test_sla_due_at_allows_tenant_override_without_widening_validation() -> None:
    from app.services.sla import calculate_due_at, validate_sla_targets

    opened_at = dt.datetime(2026, 10, 8, 9, tzinfo=dt.UTC)
    policy = validate_sla_targets({"critical": 2, "high": 5, "medium": 30, "low": 90})

    assert calculate_due_at(Severity.CRITICAL, "low", opened_at=opened_at, targets=policy) == (
        opened_at + dt.timedelta(days=2)
    )


def test_organization_policy_validates_sla_targets() -> None:
    from app.schemas.organization import OrgPolicy

    assert OrgPolicy(sla_targets_days={"critical": 2}).sla_targets_days == {"critical": 2}
    with pytest.raises(ValueError):
        OrgPolicy(sla_targets_days={"unknown": 2})
