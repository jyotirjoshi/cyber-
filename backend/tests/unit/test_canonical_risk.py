"""Canonical risk ranking must be explainable and tenant-configurable."""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.schemas.organization import OrganizationOut, OrgPolicy, RiskWeights
from app.services.canonical_risk import score_canonical


def test_default_score_uses_severity_and_curated_asset_context() -> None:
    asset = SimpleNamespace(criticality="high", internet_exposed=True)

    score, factors = score_canonical("high", asset, [], OrgPolicy().risk_weights)

    assert score == 46.5
    assert factors["components"] == {
        "severity": 29.0,
        "exploitation": 0.0,
        "exploit_probability": 0.0,
        "exposure": 10.0,
        "asset_criticality": 7.5,
        "ransomware": 0.0,
    }
    assert factors["inputs"]["in_kev"] is None
    assert factors["inputs"]["epss_score"] is None


def test_verified_threat_signals_increase_score_without_inventing_unknowns() -> None:
    asset = SimpleNamespace(criticality="high", internet_exposed=True)
    evidence = [{"in_kev": True, "epss_score": 0.5, "ransomware_use": True}]

    score, factors = score_canonical("high", asset, evidence, OrgPolicy().risk_weights)

    assert score == 75.5
    assert factors["inputs"]["in_kev"] is True
    assert factors["inputs"]["epss_score"] == 0.5


def test_tenant_weights_change_score_and_invalid_totals_are_rejected() -> None:
    weights = RiskWeights(
        severity=30,
        exploitation=35,
        exploit_probability=10,
        exposure=15,
        asset_criticality=5,
        ransomware=5,
    )
    asset = SimpleNamespace(criticality="high", internet_exposed=True)

    score, factors = score_canonical(
        "high",
        asset,
        [{"in_kev": True, "epss_score": 0.5, "ransomware_use": True}],
        weights,
    )

    assert score == 83.08
    assert factors["weights"]["exploitation"] == 35
    with pytest.raises(ValidationError):
        RiskWeights(severity=80)


def test_untrusted_out_of_range_scores_do_not_inflate_risk() -> None:
    asset = SimpleNamespace(criticality="unknown", internet_exposed=False)

    score, factors = score_canonical(
        "low",
        asset,
        [{"cvss_score": 100, "epss_score": 30, "in_kev": "true"}],
        OrgPolicy().risk_weights,
    )

    assert score == 11.0
    assert factors["inputs"]["cvss_score"] is None
    assert factors["inputs"]["in_kev"] is None


def test_cloud_exploit_signals_raise_risk_without_equating_poc_to_active_exploitation() -> None:
    asset = SimpleNamespace(criticality="unknown", internet_exposed=False)
    weights = OrgPolicy().risk_weights

    poc_score, poc_factors = score_canonical(
        "low",
        asset,
        [{"exploit_available": True}],
        weights,
    )
    active_score, active_factors = score_canonical(
        "low",
        asset,
        [{"observed_in_the_wild": True}],
        weights,
    )
    unknown_score, unknown_factors = score_canonical(
        "low",
        asset,
        [{"exploit_available": "true"}],
        weights,
    )

    assert poc_score == 21.0
    assert poc_factors["components"]["exploitation"] == 10.0
    assert poc_factors["inputs"]["exploit_available"] is True
    assert active_score == 31.0
    assert active_factors["components"]["exploitation"] == 20.0
    assert active_factors["inputs"]["observed_in_the_wild"] is True
    assert unknown_score == 11.0
    assert unknown_factors["inputs"]["exploit_available"] is None


def test_organization_response_exposes_validated_current_weights() -> None:
    import datetime as dt
    import uuid

    organization = SimpleNamespace(
        id=uuid.uuid4(),
        name="Acme",
        slug="acme",
        is_active=True,
        max_concurrent_scanner_jobs=4,
        entitlements={},
        created_at=dt.datetime.now(dt.UTC),
        policy={
            "risk_weights": {
                "severity": 30,
                "exploitation": 35,
                "exploit_probability": 10,
                "exposure": 15,
                "asset_criticality": 5,
                "ransomware": 5,
            }
        },
    )

    payload = OrganizationOut.model_validate(organization)

    assert payload.policy.risk_weights.exploitation == 35
