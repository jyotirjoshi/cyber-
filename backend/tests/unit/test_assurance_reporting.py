"""Reproducible quantitative-risk and OSCAL evidence-package tests."""

from __future__ import annotations

import datetime as dt

import pytest


def _assumptions() -> dict[str, object]:
    return {
        "iterations": 10_000,
        "seed": 42,
        "frequency": (0.05, 0.2, 0.6),
        "primary_loss": (10_000, 50_000, 500_000),
        "secondary_loss": (0, 25_000, 250_000),
        "control_effectiveness": (0.1, 0.4, 0.8),
        "assumptions_version": 3,
    }


def test_monte_carlo_is_seeded_and_reports_intervals_not_false_precision() -> None:
    from app.services.assurance_reporting import run_monte_carlo

    first = run_monte_carlo(**_assumptions())
    second = run_monte_carlo(**_assumptions())
    assert first == second
    assert 0 <= first.percentile_05 <= first.percentile_50 <= first.percentile_95
    assert first.mean_annual_loss >= 0
    assert first.iterations == 10_000
    assert first.seed == 42
    assert first.assumptions_version == 3


def test_monte_carlo_rejects_invalid_ranges_and_comparison_reuses_seed() -> None:
    from app.services.assurance_reporting import compare_risk_scenarios, run_monte_carlo

    invalid = _assumptions()
    invalid["frequency"] = (0.8, 0.2, 0.1)
    with pytest.raises(ValueError, match="ordered"):
        run_monte_carlo(**invalid)

    before = _assumptions()
    after = {**before, "control_effectiveness": (0.6, 0.8, 0.95)}
    comparison = compare_risk_scenarios(before=before, after=after)
    assert comparison["seed"] == 42
    assert comparison["after"].mean_annual_loss < comparison["before"].mean_annual_loss
    assert comparison["risk_reduction"] > 0


def test_calibration_reports_coverage_and_error() -> None:
    from app.services.assurance_reporting import calibrate_risk_model

    result = calibrate_risk_model(
        [
            {"p05": 10, "p50": 50, "p95": 100, "actual": 70},
            {"p05": 20, "p50": 60, "p95": 120, "actual": 150},
        ]
    )
    assert result["interval_coverage"] == 0.5
    assert result["median_absolute_error"] == 55.0
    assert result["sample_size"] == 2


def test_inheritance_detects_cycles_and_effective_responsibility() -> None:
    from app.services.assurance_reporting import resolve_control_inheritance

    resolved = resolve_control_inheritance(
        [
            {"control_id": "child", "parent_control_id": "parent", "percentage": 80},
            {"control_id": "leaf", "parent_control_id": "child", "percentage": 50},
        ],
        "leaf",
    )
    assert resolved["effective_inherited_percentage"] == 40.0
    assert resolved["path"] == ["leaf", "child", "parent"]
    with pytest.raises(ValueError, match="cycle"):
        resolve_control_inheritance(
            [
                {"control_id": "a", "parent_control_id": "b", "percentage": 100},
                {"control_id": "b", "parent_control_id": "a", "percentage": 100},
            ],
            "a",
        )


def test_oscal_package_filters_stale_evidence_and_has_verifiable_signature() -> None:
    from app.services.assurance_reporting import build_oscal_package, verify_oscal_package

    now = dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    package = build_oscal_package(
        model="assessment-results",
        package_key="audit-2026-q4",
        workspace_id="workspace-7",
        controls=[{"id": "ac-2", "title": "Account Management", "status": "satisfied"}],
        evidence=[
            {
                "id": "fresh-1",
                "control_id": "ac-2",
                "captured_at": "2026-10-19T00:00:00+00:00",
                "freshness_days": 30,
                "artifact_ref": "artifact://evidence/1",
                "asset_refs": ["asset-7"],
                "finding_refs": ["finding-9"],
            },
            {
                "id": "stale-1",
                "control_id": "ac-2",
                "captured_at": "2025-01-01T00:00:00+00:00",
                "freshness_days": 30,
                "artifact_ref": "artifact://evidence/2",
            },
        ],
        findings=[{"id": "finding-9", "title": "Dormant account", "status": "open"}],
        signing_secret=b"test-signing-secret-with-sufficient-length",
        signing_key_id="key-2026-01",
        generated_at=now,
    )
    assert package["oscal-version"] == "1.1.2"
    assert package["manifest"]["included_evidence_ids"] == ["fresh-1"]
    assert package["manifest"]["stale_evidence_ids"] == ["stale-1"]
    assert verify_oscal_package(package, b"test-signing-secret-with-sufficient-length") is True
    package["document"]["assessment-results"]["results"][0]["title"] = "tampered"
    assert verify_oscal_package(package, b"test-signing-secret-with-sufficient-length") is False

