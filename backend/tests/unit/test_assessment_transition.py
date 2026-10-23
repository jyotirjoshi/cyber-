from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from app.db.enums import AssessmentStage, AssessmentStatus
from app.services import automation
from app.services.assessment import transition


class _AssessmentStub:
    def __init__(self) -> None:
        self.id = uuid.UUID("11111111-1111-4111-8111-111111111111")
        self.organization_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
        self.status = AssessmentStatus.CREATED.value
        self.current_stage = AssessmentStage.QUEUED.value
        self.started_at = None
        self.completed_at = None
        self.progress_percent = 0
        self.failure_reason = None

    @property
    def status_enum(self) -> AssessmentStatus:
        return AssessmentStatus(self.status)


@pytest.mark.asyncio
async def test_created_assessment_enters_planning_and_queues_started_automation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queued = AsyncMock()
    monkeypatch.setattr(automation, "queue_rule_event", queued)
    row = _AssessmentStub()
    session = object()

    await transition(
        session, row, AssessmentStatus.PLANNING, stage=AssessmentStage.UNDERSTANDING
    )

    assert row.status == AssessmentStatus.PLANNING.value
    assert row.current_stage == AssessmentStage.UNDERSTANDING.value
    assert row.started_at is not None
    queued.assert_awaited_once_with(
        session,
        organization_id=row.organization_id,
        trigger="assessment.started",
        event_key=f"assessment.started:{row.id}",
        context={
            "assessment_id": str(row.id),
            "status": AssessmentStatus.PLANNING.value,
            "source": "assessment",
        },
    )


@pytest.mark.asyncio
async def test_created_assessment_can_settle_failed_without_automation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queued = AsyncMock()
    monkeypatch.setattr(automation, "queue_rule_event", queued)
    row = _AssessmentStub()

    await transition(object(), row, AssessmentStatus.FAILED, reason="worker failed")

    assert row.status == AssessmentStatus.FAILED.value
    assert row.completed_at is not None
    assert row.failure_reason == "worker failed"
    queued.assert_not_awaited()
