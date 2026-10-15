"""Durable tenant-bound remediation governance service contracts."""

from __future__ import annotations

import datetime as dt
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.errors import TenantIsolationError
from app.db.enums import Role
from app.services.context import Principal


@pytest.mark.asyncio
async def test_complete_retest_records_verified_outcome_without_closing_finding() -> None:
    from app.services.remediation_governance import complete_retest

    request = SimpleNamespace(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), assessment_id=uuid.uuid4(),
        status="running", evidence={}, completed_at=None,
    )
    session = AsyncMock()
    session.add = MagicMock()
    rows = MagicMock()
    rows.scalar_one_or_none.return_value = request
    session.execute.return_value = rows

    result = await complete_retest(
        session, organization_id=request.organization_id, assessment_id=request.assessment_id,
        outcome="not_confirmed", evidence={"findings_total": 0},
    )
    assert result is request
    assert request.status == "not_confirmed"
    assert request.evidence == {"findings_total": 0}


@pytest.mark.asyncio
async def test_verified_absent_retest_closes_only_its_tenant_finding() -> None:
    """The change that would break this is closing a finding from an unverified or cross-tenant result."""
    from app.services.remediation_governance import complete_retest

    organization_id, assessment_id, finding_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    request = SimpleNamespace(
        id=uuid.uuid4(), organization_id=organization_id, assessment_id=assessment_id,
        canonical_finding_id=finding_id, status="running", evidence={}, completed_at=None,
    )
    finding = SimpleNamespace(
        id=finding_id, organization_id=organization_id, status="open", status_version=3, closed_at=None
    )
    session = AsyncMock()
    session.add = MagicMock()
    request_rows = MagicMock()
    request_rows.scalar_one_or_none.return_value = request
    finding_rows = MagicMock()
    finding_rows.scalar_one_or_none.return_value = finding
    session.execute.side_effect = [request_rows, finding_rows]

    result = await complete_retest(
        session,
        organization_id=organization_id,
        assessment_id=assessment_id,
        outcome="not_confirmed",
        evidence={"verification": {"assessment_complete": True, "finding_present": False}},
    )

    assert result is request
    assert request.status == "not_confirmed"
    assert finding.status == "closed"
    assert finding.status_version == 4
    assert finding.closed_at is not None


@pytest.mark.asyncio
async def test_completed_assessment_retest_derives_absence_from_its_own_membership() -> None:
    """The change that would break this is using another assessment's results to close a finding."""
    from app.services.remediation_governance import complete_assessment_retest

    organization_id, assessment_id, finding_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    request = SimpleNamespace(
        id=uuid.uuid4(), organization_id=organization_id, assessment_id=assessment_id,
        canonical_finding_id=finding_id, status="scheduled", evidence={}, completed_at=None,
    )
    finding = SimpleNamespace(
        id=finding_id, organization_id=organization_id, status="open", status_version=0, closed_at=None
    )
    session = AsyncMock()
    session.add = MagicMock()
    request_rows = MagicMock()
    request_rows.scalar_one_or_none.return_value = request
    no_membership_rows = MagicMock()
    no_membership_rows.scalar_one_or_none.return_value = None
    finding_rows = MagicMock()
    finding_rows.scalar_one_or_none.return_value = finding
    session.execute.side_effect = [request_rows, no_membership_rows, request_rows, finding_rows]

    result = await complete_assessment_retest(
        session,
        organization_id=organization_id,
        assessment_id=assessment_id,
        run_id=uuid.uuid4(),
    )

    assert result is request
    assert request.status == "not_confirmed"
    assert request.evidence["verification"] == {
        "assessment_complete": True,
        "finding_present": False,
    }
    assert finding.status == "closed"


@pytest.mark.asyncio
async def test_request_risk_acceptance_rejects_cross_tenant_finding() -> None:
    from app.services.remediation_governance import request_risk_acceptance

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4(), status="open")

    class Session:
        async def execute(self, _statement):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [finding]))

    with pytest.raises(TenantIsolationError):
        await request_risk_acceptance(
            Session(),
            principal,
            finding.id,
            rationale="Compensating control is in place.",
            expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
        )


@pytest.mark.asyncio
async def test_worker_maintenance_expires_risk_acceptances(monkeypatch) -> None:
    """An approved exception must expire without a manual API request."""
    pytest.importorskip("croniter")
    from app.worker import worker as worker_module

    worker = object.__new__(worker_module.AgentWorker)
    worker._stopping, worker._settings, worker._redis = False, object(), object()
    session, calls = object(), []

    async def one_tick(seconds):
        worker._stopping = True

    @asynccontextmanager
    async def scoped(settings):
        yield session

    async def no_op(*args, **kwargs):
        return 0

    async def expire(actual_session):
        calls.append(actual_session)
        return 1

    monkeypatch.setattr(worker_module.asyncio, "sleep", one_tick)
    monkeypatch.setattr(worker_module, "session_scope", scoped)
    for name in (
        "reclaim_orphans", "run_due_scans", "deliver_pending_dispatches", "deliver_pending",
        "execute_approved_batch", "execute_pending_automations", "emit_overdue_sla_escalations",
        "refresh_stale_risk_batch", "refresh_stale_intel_batch",
    ):
        monkeypatch.setattr(worker_module, name, no_op, raising=False)
    monkeypatch.setattr(worker_module, "expire_risk_acceptances", expire, raising=False)

    await worker._maintenance_loop()
    assert calls == [session]
