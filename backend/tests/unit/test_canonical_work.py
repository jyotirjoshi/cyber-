"""Canonical findings need actionable, tenant-safe remediation ownership."""

import datetime as dt
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from app.api.v1.router import api_router
from app.core.errors import ConflictError, InvalidConfigurationError
from app.db.enums import Role
from app.db.models.canonical import CanonicalFinding, FindingHistory
from app.schemas.canonical import CanonicalWorkIn
from app.services.canonical_work import update_work
from app.services.context import Principal


def test_work_api_and_payload_require_a_real_change() -> None:
    app = FastAPI()
    app.include_router(api_router, prefix="/api/v1")
    assert "patch" in app.openapi()["paths"]["/api/v1/canonical-findings/{finding_id}/work"]
    assert "patch" in app.openapi()["paths"]["/api/v1/canonical-findings/work/bulk"]
    with pytest.raises(ValidationError):
        CanonicalWorkIn(expected_version=0)
    with pytest.raises(ValidationError):
        CanonicalWorkIn(expected_version=0, remediation_plan="   ")


def test_bulk_work_requires_unique_bounded_versioned_items() -> None:
    from app.schemas.canonical import BulkCanonicalWorkIn, BulkCanonicalWorkItemIn

    finding_id = uuid.uuid4()
    item = BulkCanonicalWorkItemIn(
        finding_id=finding_id,
        expected_version=2,
        remediation_plan="Upgrade the affected dependency and verify the deployed version.",
    )
    assert BulkCanonicalWorkIn(items=[item]).items == [item]
    with pytest.raises(ValidationError, match="unique"):
        BulkCanonicalWorkIn(items=[item, item])


@pytest.mark.asyncio
async def test_work_assignment_sets_owner_due_plan_and_records_history() -> None:
    org_id = uuid.uuid4()
    owner_id = uuid.uuid4()
    finding = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=uuid.uuid4(),
        fingerprint="a" * 64,
        title="Risk",
        severity="high",
        status="open",
        cve_ids=[],
        risk_score=40.0,
        risk_factors={},
        status_version=2,
    )
    due_at = dt.datetime.now(dt.UTC) + dt.timedelta(days=7)
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    session = AsyncMock()
    session.add = MagicMock()
    finding_rows = MagicMock()
    finding_rows.scalars.return_value.all.return_value = [finding]
    member_rows = MagicMock()
    member_rows.scalar_one_or_none.return_value = owner_id
    session.execute.side_effect = [finding_rows, member_rows]

    with patch("app.services.canonical_work.audit_service.record", new_callable=AsyncMock):
        result = await update_work(
            session,
            principal,
            finding.id,
            CanonicalWorkIn(
                expected_version=2,
                assignee_user_id=owner_id,
                due_at=due_at,
                remediation_plan="Upgrade affected package",
            ),
        )

    assert result is finding
    assert finding.assignee_user_id == owner_id
    assert finding.due_at == due_at
    assert finding.remediation_plan == "Upgrade affected package"
    assert finding.status_version == 3
    assert [row for row in session.add.call_args_list if isinstance(row.args[0], FindingHistory)]


@pytest.mark.asyncio
async def test_bulk_work_rejects_a_stale_item_before_mutating_any_finding() -> None:
    from app.schemas.canonical import BulkCanonicalWorkIn, BulkCanonicalWorkItemIn
    from app.services.canonical_work import bulk_update_work

    org_id = uuid.uuid4()
    first = CanonicalFinding(
        id=uuid.uuid4(), organization_id=org_id, asset_id=uuid.uuid4(), fingerprint="c" * 64,
        title="First", severity="high", status="open", status_version=2,
    )
    stale = CanonicalFinding(
        id=uuid.uuid4(), organization_id=org_id, asset_id=uuid.uuid4(), fingerprint="d" * 64,
        title="Second", severity="high", status="open", status_version=3,
    )
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    session = AsyncMock()
    session.add = MagicMock()
    rows = MagicMock()
    rows.scalars.return_value.all.return_value = [first, stale]
    session.execute.return_value = rows
    request = BulkCanonicalWorkIn(
        items=[
            BulkCanonicalWorkItemIn(
                finding_id=first.id, expected_version=2, remediation_plan="Upgrade and verify.",
            ),
            BulkCanonicalWorkItemIn(
                finding_id=stale.id, expected_version=2, remediation_plan="Upgrade and verify.",
            ),
        ]
    )

    with pytest.raises(ConflictError, match="changed"):
        await bulk_update_work(session, principal, request)

    assert first.status_version == 2
    assert first.remediation_plan is None
    assert not session.add.called


@pytest.mark.asyncio
async def test_assignment_rejects_nonmember_and_stale_edit() -> None:
    org_id = uuid.uuid4()
    finding = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=uuid.uuid4(),
        fingerprint="b" * 64,
        title="Risk",
        severity="high",
        status="open",
        status_version=4,
    )
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    session = AsyncMock()
    finding_rows = MagicMock()
    finding_rows.scalars.return_value.all.return_value = [finding]
    missing_member = MagicMock()
    missing_member.scalar_one_or_none.return_value = None
    session.execute.side_effect = [finding_rows, missing_member]
    with pytest.raises(InvalidConfigurationError):
        await update_work(
            session,
            principal,
            finding.id,
            CanonicalWorkIn(expected_version=4, assignee_user_id=uuid.uuid4()),
        )
    assert finding.status_version == 4

    session.execute.side_effect = [finding_rows]
    with pytest.raises(ConflictError):
        await update_work(
            session,
            principal,
            finding.id,
            CanonicalWorkIn(expected_version=3, remediation_plan="Patch"),
        )
