"""Historical source records can be projected without asking providers to resync."""

import asyncio
import sys
import uuid

import pytest

from app.db.models.canonical import CanonicalFinding
from app.db.models.external_alert import ExternalSecurityAlert
from app.services.canonical_backfill import backfill_organization_page
from tests.unit.test_canonical_ingest import _Rows, _Session


class _BackfillSession(_Session):
    def __init__(self, organization_id: uuid.UUID, alerts: list[ExternalSecurityAlert]):
        super().__init__(organization_id)
        self.alerts = alerts

    async def execute(self, statement):
        if statement.column_descriptions[0]["entity"] is ExternalSecurityAlert:
            return _Rows(self.alerts)
        return await super().execute(statement)


@pytest.mark.asyncio
async def test_existing_external_alert_projects_to_canonical_ledger() -> None:
    org_id = uuid.uuid4()
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(),
        organization_id=org_id,
        provider="github",
        external_id="dependabot:acme/api:7",
        category="dependabot",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable library",
        severity="high",
        status="open",
        source_url=None,
    )
    session = _BackfillSession(org_id, [alert])

    cursor, processed, projected = await backfill_organization_page(
        session, org_id, source="external", after_id=None, limit=100
    )

    assert cursor == alert.id
    assert processed == projected == 1
    assert len([row for row in session.added if isinstance(row, CanonicalFinding)]) == 1


def test_cli_disposes_database_in_the_same_event_loop(monkeypatch) -> None:
    from app.commands import backfill_canonical

    loops = []

    async def fake_backfill(*, batch_size: int) -> None:
        assert batch_size == 25
        loops.append(asyncio.get_running_loop())

    async def fake_dispose() -> None:
        loops.append(asyncio.get_running_loop())

    monkeypatch.setattr(backfill_canonical, "backfill_all", fake_backfill)
    monkeypatch.setattr(backfill_canonical, "dispose_engine", fake_dispose)
    monkeypatch.setattr(sys, "argv", ["backfill_canonical", "--batch-size", "25"])
    backfill_canonical.main()

    assert len(loops) == 2
    assert loops[0] is loops[1]
