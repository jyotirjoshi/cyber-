"""Large recon batches must use bounded tenant-filtered inventory queries."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.services.asset import _load_by_keys


@pytest.mark.asyncio
async def test_bulk_inventory_lookup_chunks_large_name_sets() -> None:
    organization_id = uuid.uuid4()
    keys = {(f"host-{index}.example.com", None, None) for index in range(2_101)}
    calls = []

    class Session:
        async def execute(self, stmt):
            assert "assets.organization_id" in str(stmt)
            names = next(
                value for value in stmt.compile().params.values()
                if isinstance(value, list)
            )
            calls.append(names)
            assert len(names) <= 1_000
            rows = [
                SimpleNamespace(name=name, port=None, protocol=None)
                for name in names
            ]
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    found = await _load_by_keys(Session(), organization_id, keys)
    assert len(found) == len(keys)
    assert len(calls) == 3
