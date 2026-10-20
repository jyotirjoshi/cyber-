"""Tests for immutable agent work records and governed validation recipes."""

from __future__ import annotations

import pytest

from app.core.errors import ConflictError


def test_agent_record_is_digest_bound_and_finalizes_once() -> None:
    from app.services.assurance_work import create_agent_record, finalize_agent_record

    record = create_agent_record(
        plan={"version": 2, "steps": ["collect", "correlate", "verify"]},
        input_evidence_refs=["artifact://finding/7"],
        budgets={"max_tool_calls": 20, "max_seconds": 900, "max_cost_usd": "1.50"},
        success_criteria=[{"metric": "verified_findings", "operator": ">=", "value": 1}],
    )
    assert len(record.plan_digest) == 64
    assert not hasattr(record, "plan")
    finalize_agent_record(
        record,
        tool_receipts=[{"tool": "finding.read", "status": "ok", "digest": "a" * 64}],
        artifact_refs=["artifact://report/9"],
        contradictory_evidence=[],
        verifier_result={"status": "passed", "checks": 3, "passed": 3},
        outcome_labels=["true_positive", "true_positive", "false_positive"],
        elapsed_seconds=120,
        cost_usd="0.25",
    )
    assert record.verifier_status == "passed"
    assert record.metrics["precision"] == pytest.approx(2 / 3)
    assert record.replay_digest
    with pytest.raises(ConflictError, match="finalized"):
        finalize_agent_record(
            record,
            tool_receipts=[],
            artifact_refs=[],
            contradictory_evidence=[],
            verifier_result={"status": "failed"},
            outcome_labels=[],
            elapsed_seconds=1,
            cost_usd="0",
        )


def test_agent_budgets_and_receipts_are_bounded() -> None:
    from app.services.assurance_work import create_agent_record, finalize_agent_record

    with pytest.raises(ValueError, match="max_tool_calls"):
        create_agent_record(
            plan={"version": 1},
            input_evidence_refs=[],
            budgets={"max_tool_calls": 0, "max_seconds": 10, "max_cost_usd": "1"},
            success_criteria=[{"metric": "done"}],
        )
    record = create_agent_record(
        plan={"version": 1},
        input_evidence_refs=[],
        budgets={"max_tool_calls": 1, "max_seconds": 10, "max_cost_usd": "1"},
        success_criteria=[{"metric": "done"}],
    )
    with pytest.raises(ConflictError, match="tool-call budget"):
        finalize_agent_record(
            record,
            tool_receipts=[{"tool": "a"}, {"tool": "b"}],
            artifact_refs=[],
            contradictory_evidence=[],
            verifier_result={"status": "passed"},
            outcome_labels=[],
            elapsed_seconds=1,
            cost_usd="0",
        )


def test_validation_recipe_rejects_shell_and_out_of_scope_targets() -> None:
    from app.services.assurance_work import build_validation_recipe

    with pytest.raises(ValueError, match="allow-listed"):
        build_validation_recipe(
            recipe_key="r-1",
            authorized_targets=["https://app.example.test"],
            requested_targets=["https://app.example.test"],
            actions=[{"kind": "shell", "command": "curl example.test"}],
            budgets={"max_actions": 2, "max_requests": 20, "max_seconds": 60},
            approval_refs=["approval://7"],
        )
    with pytest.raises(ConflictError, match="outside the approved scope"):
        build_validation_recipe(
            recipe_key="r-2",
            authorized_targets=["https://app.example.test"],
            requested_targets=["https://other.example.test"],
            actions=[{"kind": "http_request", "method": "GET", "path": "/health"}],
            budgets={"max_actions": 2, "max_requests": 20, "max_seconds": 60},
            approval_refs=["approval://7"],
        )


def test_validation_evidence_has_chain_of_custody_and_reproducibility() -> None:
    from app.services.assurance_work import (
        append_validation_evidence,
        build_validation_recipe,
        verify_validation_recipe,
    )

    recipe = build_validation_recipe(
        recipe_key="r-3",
        authorized_targets=["https://app.example.test"],
        requested_targets=["https://app.example.test"],
        actions=[
            {"kind": "http_request", "method": "GET", "path": "/version"},
            {"kind": "assert_response", "status": 200, "contains": "version"},
        ],
        budgets={"max_actions": 3, "max_requests": 5, "max_seconds": 60},
        approval_refs=["approval://7"],
    )
    first = append_validation_evidence(recipe, artifact_ref="artifact://http/1", content=b"one")
    second = append_validation_evidence(recipe, artifact_ref="artifact://http/2", content=b"two")
    assert first != second
    assert len(recipe.evidence_hashes) == 2
    verify_validation_recipe(
        recipe,
        action_results=[{"passed": True}, {"passed": True}],
        exploitation_verdict="proved_exploitable",
    )
    assert recipe.status == "verified"
    assert recipe.reproducibility_score == 100.0
    assert recipe.verification["chain_head"] == second


def test_validation_evidence_digest_chain_rejects_stale_heads() -> None:
    from app.services.assurance_work import (
        append_validation_evidence_digest,
        build_validation_recipe,
    )

    recipe = build_validation_recipe(
        recipe_key="r-digest",
        authorized_targets=["https://app.example.test"],
        requested_targets=["https://app.example.test"],
        actions=[{"kind": "http_request", "method": "GET", "path": "/health"}],
        budgets={"max_actions": 2, "max_requests": 5, "max_seconds": 60},
        approval_refs=["approval://7"],
    )
    first = append_validation_evidence_digest(
        recipe,
        artifact_ref="artifact://exchange-1",
        content_digest="1" * 64,
        previous_chain_head="0" * 64,
    )
    assert recipe.evidence_hashes == [first]
    with pytest.raises(ConflictError, match="chain head"):
        append_validation_evidence_digest(
            recipe,
            artifact_ref="artifact://exchange-2",
            content_digest="2" * 64,
            previous_chain_head="0" * 64,
        )


def test_verifier_requires_balanced_evidence_for_high_confidence() -> None:
    from app.services.assurance_work import confidence_from_evidence

    result = confidence_from_evidence(
        supporting=[{"weight": 0.9}, {"weight": 0.8}],
        contradicting=[{"weight": 0.7}],
    )
    assert 0 < result["confidence"] < 0.8
    assert result["reason_codes"] == ["contradictory_evidence_present"]

