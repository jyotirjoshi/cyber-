"""PTaaS engagement checklist contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from uuid import uuid4


def test_engagement_checklist_item_requires_safe_evidence_reference() -> None:
    """A regression must not persist an unbounded or control-character evidence reference."""
    from app.schemas.assessment import EngagementChecklistItemIn

    item = EngagementChecklistItemIn.model_validate(
        {
            "key": "authentication-tested",
            "title": "Authentication controls tested",
            "required": True,
            "evidence_reference": "artifact://assessment/evidence/authentication",
        }
    )

    assert item.key == "authentication-tested"
    assert item.evidence_reference == "artifact://assessment/evidence/authentication"
    with pytest.raises(ValidationError):
        EngagementChecklistItemIn.model_validate(
            {"key": "unsafe", "title": "Unsafe", "evidence_reference": "proof\nspoofed"}
        )


@pytest.mark.asyncio
async def test_checklist_update_changes_only_matching_tenant_item(monkeypatch) -> None:
    from app.db.enums import Role
    from app.services import assessment as service
    from app.services.context import Principal

    principal = Principal(user_id=uuid4(), organization_id=uuid4(), role=Role.OWNER)
    assessment = type("Assessment", (), {"id": uuid4(), "extra_data": {"engagement": {"checklist": [{"key": "auth", "title": "Auth", "required": True}]}}})()

    async def load(*args, **kwargs): return assessment
    async def audit(*args, **kwargs): return None
    monkeypatch.setattr(service, "get_assessment", load)
    monkeypatch.setattr(service.audit_service, "record", audit)
    result = await service.update_engagement_checklist(None, principal, assessment.id, "auth", completed=True, evidence_reference="artifact://auth")
    assert result.extra_data["engagement"]["checklist"][0]["completed"] is True
