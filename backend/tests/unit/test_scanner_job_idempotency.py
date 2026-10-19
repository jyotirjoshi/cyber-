"""A replayed graph node must not create or execute duplicate scanner work."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.core.errors import ConflictError
from app.db.enums import ScannerName
from app.db.models.scanner import ScannerJob
from app.services.job import enqueue_job


@pytest.mark.asyncio
async def test_enqueue_reuses_existing_job_for_same_run_step(monkeypatch) -> None:
    import app.services.job as service

    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4())
    existing = ScannerJob(
        id=uuid.uuid4(),
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        scanner=ScannerName.NMAP.value,
        idempotency_key="agent:run-1:nmap",
        targets=["example.com"],
        timeout_seconds=30,
    )
    calls = []

    class Session:
        async def execute(self, stmt):
            calls.append(stmt)
            return SimpleNamespace(scalar_one_or_none=lambda: None)

        async def scalar(self, stmt):
            calls.append(stmt)
            return existing

    async def unexpected_audit(*args, **kwargs):
        raise AssertionError("replay must not create a second audit event")

    monkeypatch.setattr(service.audit_service, "record", unexpected_audit)
    result = await enqueue_job(
        Session(),
        assessment,
        scanner=ScannerName.NMAP,
        targets=["example.com"],
        idempotency_key="agent:run-1:nmap",
    )
    assert result is existing
    assert len(calls) == 2


def test_scanner_job_has_tenant_scoped_unique_idempotency_key() -> None:
    assert "idempotency_key" in ScannerJob.__table__.columns
    constraints = ScannerJob.__table__.constraints
    assert any(
        {column.name for column in constraint.columns} == {"organization_id", "idempotency_key"}
        for constraint in constraints
        if hasattr(constraint, "columns")
    )


@pytest.mark.asyncio
async def test_enqueue_rejects_reuse_of_key_for_different_targets(monkeypatch) -> None:
    import app.services.job as service

    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4())
    existing = ScannerJob(
        id=uuid.uuid4(),
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        scanner=ScannerName.NMAP.value,
        idempotency_key="agent:run-1:nmap",
        targets=["different.example"],
        timeout_seconds=30,
    )

    class Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalar_one_or_none=lambda: None)

        async def scalar(self, stmt):
            return existing

    async def unexpected_audit(*args, **kwargs):
        raise AssertionError("conflicting replay must not create an audit event")

    monkeypatch.setattr(service.audit_service, "record", unexpected_audit)
    with pytest.raises(ConflictError):
        await enqueue_job(
            Session(),
            assessment,
            scanner=ScannerName.NMAP,
            targets=["example.com"],
            idempotency_key="agent:run-1:nmap",
        )


@pytest.mark.asyncio
async def test_enqueue_records_one_audit_for_new_idempotent_job(monkeypatch) -> None:
    import app.services.job as service

    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4())
    job_id = uuid.uuid4()
    job = ScannerJob(
        id=job_id,
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        scanner=ScannerName.NMAP.value,
        idempotency_key="agent:run-1:nmap",
        targets=["example.com"],
        timeout_seconds=30,
    )
    audits = []

    class Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalar_one_or_none=lambda: job_id)

        async def get(self, model, key):
            assert model is ScannerJob and key == job_id
            return job

    async def record(*args, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(service.audit_service, "record", record)
    result = await enqueue_job(
        Session(),
        assessment,
        scanner=ScannerName.NMAP,
        targets=["example.com"],
        idempotency_key="agent:run-1:nmap",
    )
    assert result is job
    assert len(audits) == 1
    assert audits[0]["resource_id"] == job_id


@pytest.mark.asyncio
async def test_replay_accepts_same_target_set_in_different_order(monkeypatch) -> None:
    import app.services.job as service

    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4())
    existing = ScannerJob(
        id=uuid.uuid4(),
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        scanner=ScannerName.NMAP.value,
        idempotency_key="agent:run-2:nmap",
        targets=["a.example.com", "b.example.com"],
        timeout_seconds=30,
    )

    class Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalar_one_or_none=lambda: None)

        async def scalar(self, stmt):
            return existing

    async def unexpected_audit(*args, **kwargs):
        raise AssertionError("replay must not be audited twice")

    monkeypatch.setattr(service.audit_service, "record", unexpected_audit)
    result = await enqueue_job(
        Session(),
        assessment,
        scanner=ScannerName.NMAP,
        targets=["b.example.com", "a.example.com"],
        idempotency_key="agent:run-2:nmap",
    )
    assert result is existing


@pytest.mark.asyncio
async def test_replay_rejects_a_different_credential_reference(monkeypatch) -> None:
    import app.services.job as service

    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=uuid.uuid4())
    existing = ScannerJob(
        id=uuid.uuid4(),
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        auth_profile_id=uuid.uuid4(),
        scanner=ScannerName.NMAP.value,
        idempotency_key="agent:run-3:nmap",
        targets=["example.com"],
        timeout_seconds=30,
    )

    class Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalar_one_or_none=lambda: None)

        async def scalar(self, stmt):
            return existing

    monkeypatch.setattr(service.audit_service, "record", lambda *args, **kwargs: None)
    with pytest.raises(ConflictError):
        await enqueue_job(
            Session(),
            assessment,
            scanner=ScannerName.NMAP,
            targets=["example.com"],
            idempotency_key="agent:run-3:nmap",
            auth_profile_id=uuid.uuid4(),
        )
