"""AI correlation candidates remain advisory and tenant-bound."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.services.correlation import FalsePositiveCandidate


@pytest.mark.asyncio
async def test_correlation_candidate_keeps_analysis_enabled_and_cannot_mark_other_tenant() -> None:
    from app.agent.nodes.attack_path import record_false_positive_candidates

    organization_id, assessment_id = uuid.uuid4(), uuid.uuid4()
    valid = SimpleNamespace(
        id=uuid.uuid4(), organization_id=organization_id,
        assessment_id=assessment_id, risk_factors={"ssvc": {"outcome": "act"}},
        ai_skipped_reason=None,
    )
    foreign = SimpleNamespace(
        id=uuid.uuid4(), organization_id=uuid.uuid4(),
        assessment_id=uuid.uuid4(), risk_factors={}, ai_skipped_reason=None,
    )

    class _Session:
        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [valid, foreign]))

    session = _Session()
    count = await record_false_positive_candidates(
        session,
        organization_id=organization_id,
        assessment_id=assessment_id,
        candidates=[
            FalsePositiveCandidate(valid.id, "Scanner version could be stale", "high"),
            FalsePositiveCandidate(foreign.id, "Untrusted model suggestion", "high"),
        ],
    )
    assert count == 1
    assert valid.risk_factors == {
        "ssvc": {"outcome": "act"},
        "false_positive_candidate": {
            "confidence": "high",
            "reason": "Scanner version could be stale",
            "source": "ai_correlation",
        },
    }
    assert valid.ai_skipped_reason is None
    assert foreign.risk_factors == {}
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert organization_id in compiled.params.values()
    assert assessment_id in compiled.params.values()


@pytest.mark.asyncio
async def test_legacy_correlation_skip_is_removed_without_erasing_other_skip_reasons() -> None:
    from app.agent.nodes.attack_path import record_false_positive_candidates

    organization_id, assessment_id = uuid.uuid4(), uuid.uuid4()
    legacy = SimpleNamespace(
        id=uuid.uuid4(), organization_id=organization_id,
        assessment_id=assessment_id, risk_factors={},
        ai_skipped_reason="Flagged as likely false positive by cross-scanner correlation analysis.",
    )
    unrelated = SimpleNamespace(
        id=uuid.uuid4(), organization_id=organization_id,
        assessment_id=assessment_id, risk_factors={},
        ai_skipped_reason="Analysis provider unavailable",
    )

    class _Session:
        async def execute(self, _statement):
            return SimpleNamespace(
                scalars=lambda: SimpleNamespace(all=lambda: [legacy, unrelated])
            )

    await record_false_positive_candidates(
        _Session(), organization_id=organization_id, assessment_id=assessment_id,
        candidates=[
            FalsePositiveCandidate(legacy.id, "Needs review", "high"),
            FalsePositiveCandidate(unrelated.id, "Needs review", "high"),
        ],
    )
    assert legacy.ai_skipped_reason is None
    assert unrelated.ai_skipped_reason == "Analysis provider unavailable"
