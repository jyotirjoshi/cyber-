"""Assessment API projection contracts."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace
from uuid import uuid4

from app.db.enums import (
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    EngagementType,
    ExecutionMode,
    Scope,
)


def test_assessment_projection_includes_authorized_engagement_mode() -> None:
    """A regression must not hide whether a run is a red-team or supervised engagement."""
    from app.api.v1.projections import assessment_out

    assessment = SimpleNamespace(
        id=uuid4(),
        reference=7,
        title="Authorized red-team exercise",
        status=AssessmentStatus.CREATED.value,
        current_stage=AssessmentStage.QUEUED.value,
        progress_percent=0,
        scope=Scope.EXTERNAL.value,
        depth=AssessmentDepth.STANDARD.value,
        engagement_type=EngagementType.RED_TEAM.value,
        execution_mode=ExecutionMode.SUPERVISED.value,
        findings_total=0,
        findings_critical=0,
        findings_high=0,
        findings_medium=0,
        findings_low=0,
        findings_info=0,
        assets_discovered=0,
        assets_in_scope=0,
        created_at=dt.datetime(2026, 10, 10, tzinfo=dt.UTC),
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        targets=[],
        created_by=None,
    )

    result = assessment_out(assessment)

    assert result.engagement_type is EngagementType.RED_TEAM
    assert result.execution_mode is ExecutionMode.SUPERVISED
