import datetime as dt
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import UniqueConstraint


def test_breach_level_escalates_only_at_defined_overdue_thresholds() -> None:
    """A late finding must escalate predictably instead of re-alerting every sweep."""
    from app.services.sla_escalation import breach_level

    due_at = dt.datetime(2026, 10, 1, 9, 0, tzinfo=dt.UTC)

    assert breach_level(due_at, due_at) == 1
    assert breach_level(due_at + dt.timedelta(days=6, hours=23), due_at) == 1
    assert breach_level(due_at + dt.timedelta(days=7), due_at) == 2
    assert breach_level(due_at + dt.timedelta(days=14), due_at) == 3
    assert breach_level(due_at + dt.timedelta(days=30), due_at) == 3


def test_sla_escalation_model_deduplicates_each_finding_level() -> None:
    """A concurrent sweep must not produce a second escalation for the same level."""
    from app.db.models.canonical import SlaEscalation

    unique_constraints = [
        constraint
        for constraint in SlaEscalation.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    ]
    assert any(
        tuple(column.name for column in constraint.columns)
        == ("organization_id", "canonical_finding_id", "level")
        for constraint in unique_constraints
    )


@pytest.mark.asyncio
async def test_worker_maintenance_emits_overdue_sla_escalations(monkeypatch) -> None:
    """An overdue finding is actively processed by the worker, not just shown in a list."""
    pytest.importorskip("croniter")
    from app.worker import worker as worker_module

    worker = object.__new__(worker_module.AgentWorker)
    worker._stopping = False
    worker._settings = object()
    worker._redis = object()
    session = object()
    calls = []

    async def one_tick(seconds):
        worker._stopping = True

    @asynccontextmanager
    async def scoped(settings):
        yield session

    async def no_op(*args, **kwargs):
        return 0

    async def emit(actual_session, *, settings, redis):
        calls.append((actual_session, settings, redis))
        return 1

    monkeypatch.setattr(worker_module.asyncio, "sleep", one_tick)
    monkeypatch.setattr(worker_module, "session_scope", scoped)
    for name in (
        "reclaim_orphans", "run_due_scans", "deliver_pending_dispatches",
        "deliver_pending", "execute_approved_batch", "execute_pending_automations",
        "refresh_stale_risk_batch", "refresh_stale_intel_batch",
    ):
        monkeypatch.setattr(worker_module, name, no_op)
    monkeypatch.setattr(worker_module, "emit_overdue_sla_escalations", emit, raising=False)

    await worker._maintenance_loop()

    assert calls == [(session, worker._settings, worker._redis)]
