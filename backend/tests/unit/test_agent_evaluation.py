"""Deterministic, privacy-bounded evaluation for production AI workers."""

from __future__ import annotations

import pytest


def _cases() -> list[dict[str, object]]:
    return [
        {
            "case_key": "dedupe-1",
            "input_evidence_refs": ["artifact://eval/finding-1"],
            "expected_digest": "a" * 64,
            "tags": ["finding_deduplication"],
        },
        {
            "case_key": "routing-1",
            "input_evidence_refs": ["artifact://eval/ticket-1"],
            "expected_digest": "b" * 64,
            "tags": ["ticket_routing"],
        },
    ]


def test_evaluation_manifest_is_digest_bound_and_rejects_duplicate_cases() -> None:
    from app.services.agent_evaluation import build_suite_manifest

    manifest = build_suite_manifest(_cases())
    assert len(manifest.dataset_digest) == 64
    assert manifest.case_count == 2
    assert "raw_prompt" not in repr(manifest)

    with pytest.raises(ValueError, match="unique"):
        build_suite_manifest([_cases()[0], _cases()[0]])


def test_evaluation_scores_verified_outcomes_not_answer_style() -> None:
    from app.services.agent_evaluation import evaluate_agent_outcomes

    report = evaluate_agent_outcomes(
        case_manifest=_cases(),
        results=[
            {
                "case_key": "dedupe-1",
                "outcome_digest": "a" * 64,
                "task_completed": True,
                "evidence_grounded": True,
                "unsafe_actions": 0,
                "human_corrections": 0,
                "unsupported_claims": 0,
                "verified_outcomes": 1,
                "cost_usd": "0.08",
                "closure_seconds": 120,
            },
            {
                "case_key": "routing-1",
                "outcome_digest": "0" * 64,
                "task_completed": False,
                "evidence_grounded": False,
                "unsafe_actions": 1,
                "human_corrections": 1,
                "unsupported_claims": 2,
                "verified_outcomes": 0,
                "cost_usd": "0.04",
                "closure_seconds": None,
            },
        ],
        thresholds={
            "task_completion_rate": 0.8,
            "evidence_grounding_rate": 0.8,
            "unsafe_action_rate": 0,
            "unsupported_claim_rate": 0.1,
        },
    )
    assert report.metrics["task_completion_rate"] == 0.5
    assert report.metrics["evidence_grounding_rate"] == 0.5
    assert report.metrics["unsafe_action_rate"] == 0.5
    assert report.metrics["cost_per_verified_outcome_usd"] == "0.12"
    assert report.passed is False
    assert set(report.failed_thresholds) >= {
        "task_completion_rate",
        "evidence_grounding_rate",
        "unsafe_action_rate",
    }
    assert "answer_quality" not in report.metrics


def test_evaluation_rejects_unknown_missing_or_duplicate_results() -> None:
    from app.services.agent_evaluation import evaluate_agent_outcomes

    base = {
        "outcome_digest": "a" * 64,
        "task_completed": True,
        "evidence_grounded": True,
        "unsafe_actions": 0,
        "human_corrections": 0,
        "unsupported_claims": 0,
        "verified_outcomes": 1,
        "cost_usd": "0",
        "closure_seconds": 1,
    }
    with pytest.raises(ValueError, match="exactly one result"):
        evaluate_agent_outcomes(
            case_manifest=_cases(),
            results=[{"case_key": "dedupe-1", **base}],
            thresholds={},
        )
    with pytest.raises(ValueError, match="exactly one result"):
        evaluate_agent_outcomes(
            case_manifest=_cases(),
            results=[
                {"case_key": "dedupe-1", **base},
                {"case_key": "dedupe-1", **base},
            ],
            thresholds={},
        )
