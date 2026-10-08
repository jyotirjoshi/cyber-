"""The terminal worker stage must not erase canonical scan counts."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("receipt_failure", [False, True])
def test_completion_keeps_cloud_severity_counts_in_record_and_notification(monkeypatch, receipt_failure) -> None:
    from app.agent.nodes import report
    from app.services import assessment as assessment_service

    tenant = uuid.uuid4()
    assessment = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=tenant,
        reference="SCAN-1",
        targets=[SimpleNamespace(canonical_value="aws:123456789012")],
        degradations=[],
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        findings_info=0,
    )
    notices = []
    run_id = uuid.uuid4()
    completed_receipts = []

    class Session:
        @asynccontextmanager
        async def begin_nested(self):
            yield

    @asynccontextmanager
    async def scope(settings):
        yield Session()

    async def load(session, state, *options):
        return assessment

    async def transition(session, row, status, *, stage):
        return None

    async def unified_counts(session, organization_id, assessment_id):
        assert (organization_id, assessment_id) == (tenant, assessment.id)
        return {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}

    async def notify(session, principal, *, counts, **kwargs):
        notices.append(counts)

    async def complete_receipt(session, row, linked_run_id):
        completed_receipts.append((row, linked_run_id))
        if receipt_failure:
            raise RuntimeError("receipt temporarily unavailable")
        return True

    class Step:
        async def thinking(self, text):
            return None

    monkeypatch.setattr(report, "session_scope", scope)
    monkeypatch.setattr(report, "load_assessment", load)
    monkeypatch.setattr(report, "transition", transition)
    monkeypatch.setattr(assessment_service, "assessment_finding_counts", unified_counts)
    monkeypatch.setattr(report, "notify_assessment_completed", notify)
    monkeypatch.setattr(report, "complete_assessment_action_receipt", complete_receipt)

    completion = report._complete(
        {"run_id": str(run_id)},
        deps=SimpleNamespace(settings=object(), redis=None),
        principal=SimpleNamespace(organization_id=tenant),
        step=Step(),
    )
    with pytest.raises(StopIteration) as finished:
        completion.send(None)
    result = finished.value.value
    assert result.findings_total == 1
    assert assessment.findings_total == 1
    assert assessment.findings_high == 1
    assert notices == [{"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}]
    assert completed_receipts == [(assessment, run_id)]
