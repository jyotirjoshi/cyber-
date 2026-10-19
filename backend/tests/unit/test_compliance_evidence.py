from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from app.schemas.compliance import ComplianceExceptionCreateIn


def test_compliance_exception_requires_a_reason_and_compensating_control() -> None:
    with pytest.raises(ValidationError):
        ComplianceExceptionCreateIn(
            rationale="short",
            compensating_controls="",
            expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=30),
        )


def test_compliance_models_enforce_one_active_exception_per_control() -> None:
    from app.db.models.compliance import ComplianceControlException

    indexes = {index.name: index for index in ComplianceControlException.__table__.indexes}
    index = indexes["uq_compliance_control_active_exception"]
    assert index.unique is True
    assert index.dialect_options["postgresql"]["where"] is not None


def test_compliance_evidence_routes_are_mounted() -> None:
    from app.api.v1.compliance import router

    paths = {route.path for route in router.routes}
    assert "/compliance/audit-workspaces" in paths
    assert "/compliance/controls/{control_id}/evidence" in paths
    assert "/compliance/evidence/{evidence_id}/review" in paths
    assert "/compliance/exceptions/{exception_id}/decision" in paths


def test_worker_expires_compliance_records() -> None:
    import inspect

    from app.worker.worker import AgentWorker

    source = inspect.getsource(AgentWorker._maintenance_loop)
    assert "expire_compliance_records" in source
    assert "compliance-expiry" in source
