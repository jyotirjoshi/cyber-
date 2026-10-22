from __future__ import annotations

import hashlib
import uuid
from types import SimpleNamespace

import pytest

from app.db.enums import Role
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.services.context import Principal


class _Result:
    def scalar_one_or_none(self):
        return None


class _FkCheckingSession:
    """Models PostgreSQL's requirement that referenced assets already exist."""

    def __init__(self) -> None:
        self.pending: list[object] = []
        self.persisted_assets: set[uuid.UUID] = set()
        self.flushes = 0

    async def execute(self, _statement):
        return _Result()

    async def scalar(self, _statement):
        return 0

    def add(self, row) -> None:
        self.pending.append(row)

    async def flush(self) -> None:
        self.flushes += 1
        for row in self.pending:
            if isinstance(row, CanonicalFinding) and row.asset_id not in self.persisted_assets:
                raise RuntimeError("canonical finding flushed before its asset")
        self.persisted_assets.update(
            row.id for row in self.pending if isinstance(row, Asset)
        )
        self.pending.clear()


@pytest.mark.asyncio
async def test_demo_workspace_flushes_fk_parents_before_findings(monkeypatch) -> None:
    from app.services import demo_workspace

    async def no_audit(*_args, **_kwargs):
        return None

    async def complete(*_args, **_kwargs):
        return None

    class Storage:
        async def put_bytes(self, _key, data, **_kwargs):
            return SimpleNamespace(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

    monkeypatch.setattr(demo_workspace.audit_service, "record", no_audit)
    monkeypatch.setattr(demo_workspace.report_service, "complete_generation", complete)
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER
    )
    session = _FkCheckingSession()

    result = await demo_workspace.create_demo_workspace(
        session, principal, storage=Storage()  # type: ignore[arg-type]
    )

    assert result.assets == 3
    assert result.findings == 3
    assert session.flushes >= 3
