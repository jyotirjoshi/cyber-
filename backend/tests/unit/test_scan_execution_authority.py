"""A scanner starts only under the latest current approval and target policy."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from app.agent.nodes.scan import _enqueue_and_execute
from app.db.enums import ApprovalDecision, AssessmentStatus, JobStatus, ScannerName
from app.services.approval import granted_approval


@pytest.mark.asyncio
async def test_latest_rejected_decision_revokes_older_grant() -> None:
    rejected = SimpleNamespace(
        decision=ApprovalDecision.REJECTED.value, resolved_by_id=uuid.uuid4(),
        is_granted=False,
    )

    class Session:
        async def execute(self, stmt):
            compiled = str(stmt.compile())
            assert "ORDER BY approvals.created_at DESC" in compiled
            assert "approvals.decision IN" not in compiled
            return SimpleNamespace(scalars=lambda: SimpleNamespace(first=lambda: rejected))

    assert await granted_approval(Session(), uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_unresolved_latest_approval_does_not_authorize() -> None:
    pending = SimpleNamespace(
        decision=ApprovalDecision.PENDING.value, resolved_by_id=None,
        is_granted=False,
    )

    class Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(first=lambda: pending))

    assert await granted_approval(Session(), uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_latest_resolved_grant_still_authorizes() -> None:
    granted = SimpleNamespace(
        decision=ApprovalDecision.APPROVED.value,
        resolved_by_id=uuid.uuid4(), is_granted=True,
    )

    class Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(first=lambda: granted))

    assert await granted_approval(Session(), uuid.uuid4()) is granted


@pytest.mark.asyncio
async def test_authority_revoked_after_enqueue_prevents_container_start(monkeypatch) -> None:
    import app.agent.nodes.scan as scan

    org_id, assessment_id, run_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    state = {
        "organization_id": str(org_id), "assessment_id": str(assessment_id),
        "run_id": str(run_id),
    }
    assessment = SimpleNamespace(
        id=assessment_id, organization_id=org_id,
        status_enum=AssessmentStatus.SCANNING,
    )
    job = SimpleNamespace(
        id=uuid.uuid4(), organization_id=org_id,
        status=JobStatus.QUEUED.value, targets=["example.com"],
    )

    class Session:
        async def get(self, model, key):
            assert key == job.id
            return job

    @asynccontextmanager
    async def scope(settings):
        yield Session()

    async def load(session, state, *args):
        return assessment

    async def enqueue(session, assessment, **kwargs):
        assert kwargs["idempotency_key"] == f"agent:{run_id}:nmap"
        return job

    async def denied(session, assessment_id):
        return None

    async def empty_scope(session, state, approval, settings):
        return [], [], "Approval revoked"

    async def unexpected_execute(*args, **kwargs):
        raise AssertionError("a revoked job must never start a container")

    audits = []

    async def record(*args, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(scan, "session_scope", scope)
    monkeypatch.setattr(scan, "load_assessment", load)
    monkeypatch.setattr(scan, "enqueue_job", enqueue)
    monkeypatch.setattr(scan, "granted_approval", denied)
    monkeypatch.setattr(scan, "_resolve_scope", empty_scope)
    monkeypatch.setattr(scan, "execute_job", unexpected_execute)
    monkeypatch.setattr(scan.audit_service, "record", record)

    status, duration = await _enqueue_and_execute(
        SimpleNamespace(settings=SimpleNamespace()), state,
        ScannerName.NMAP, ["example.com"],
    )
    assert (status, duration) == (JobStatus.CANCELLED.value, None)
    assert job.status == JobStatus.CANCELLED.value
    assert job.failure_code == "scan_authorization_changed"
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_current_grant_starts_one_scanner_job(monkeypatch) -> None:
    import app.agent.nodes.scan as scan

    org_id, assessment_id, run_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    state = {
        "organization_id": str(org_id), "assessment_id": str(assessment_id),
        "run_id": str(run_id),
    }
    assessment = SimpleNamespace(
        id=assessment_id, organization_id=org_id,
        status_enum=AssessmentStatus.SCANNING,
    )
    job = SimpleNamespace(
        id=uuid.uuid4(), organization_id=org_id,
        status=JobStatus.QUEUED.value, targets=["example.com"],
    )
    executed = []

    class Session:
        async def get(self, model, key):
            return job

    @asynccontextmanager
    async def scope(settings):
        yield Session()

    async def load(session, state, *args):
        return assessment

    async def enqueue(session, assessment, **kwargs):
        return job

    async def grant(session, assessment_id):
        return SimpleNamespace(is_granted=True)

    async def allowed_scope(session, state, approval, settings):
        return ["example.com"], [ScannerName.NMAP], ""

    async def execute(session, row, **kwargs):
        executed.append(row.id)
        row.status = JobStatus.COMPLETED.value
        row.duration_seconds = 2
        return row

    monkeypatch.setattr(scan, "session_scope", scope)
    monkeypatch.setattr(scan, "load_assessment", load)
    monkeypatch.setattr(scan, "enqueue_job", enqueue)
    monkeypatch.setattr(scan, "granted_approval", grant)
    monkeypatch.setattr(scan, "_resolve_scope", allowed_scope)
    monkeypatch.setattr(scan, "execute_job", execute)

    status, duration = await _enqueue_and_execute(
        SimpleNamespace(settings=SimpleNamespace(), runner=object(), storage=object()),
        state, ScannerName.NMAP, ["example.com"],
    )
    assert (status, duration) == (JobStatus.COMPLETED.value, 2_000)
    assert executed == [job.id]
