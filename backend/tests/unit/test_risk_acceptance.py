"""Risk-acceptance lifecycle guards."""

from __future__ import annotations

import datetime as dt

import pytest


def test_risk_acceptance_requires_future_bounded_expiry() -> None:
    from app.services.risk_acceptance import validate_expiry

    now = dt.datetime(2026, 10, 8, 9, tzinfo=dt.UTC)
    assert validate_expiry(now + dt.timedelta(days=30), now=now) == now + dt.timedelta(days=30)
    with pytest.raises(ValueError):
        validate_expiry(now, now=now)
    with pytest.raises(ValueError):
        validate_expiry(now + dt.timedelta(days=366), now=now)


def test_risk_acceptance_and_retest_records_are_tenant_scoped_models() -> None:
    from app.db.models.canonical import RetestRequest, RiskAcceptance

    assert RiskAcceptance.__tablename__ == "risk_acceptances"
    assert RetestRequest.__tablename__ == "retest_requests"
    assert "organization_id" in RiskAcceptance.__table__.c
    assert "organization_id" in RetestRequest.__table__.c


def test_acceptance_and_retest_wire_inputs_reject_unbounded_data() -> None:
    from app.schemas.canonical import RetestRequestIn, RiskAcceptanceIn

    expiry = dt.datetime.now(dt.UTC) + dt.timedelta(days=30)
    assert RiskAcceptanceIn(rationale="Temporary compensating control", expires_at=expiry).expires_at == expiry
    assert RetestRequestIn(note="Verify patched deployment").note == "Verify patched deployment"
    with pytest.raises(ValueError):
        RetestRequestIn(note=" ")
