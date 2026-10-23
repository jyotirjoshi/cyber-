"""Regression coverage for durable specialist task timestamp defaults."""

from __future__ import annotations

import importlib.util
from pathlib import Path


VERSIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"


def _load(filename: str):
    path = VERSIONS / filename
    spec = importlib.util.spec_from_file_location(f"_migration_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_specialist_timestamp_repair_sets_database_defaults(monkeypatch) -> None:
    migration = _load("0112_agent_specialist_timestamp_defaults.py")
    operations: list[tuple[str, str, object]] = []
    monkeypatch.setattr(
        migration.op,
        "alter_column",
        lambda table, column, **kwargs: operations.append(
            (table, column, kwargs["server_default"])
        ),
    )

    migration.upgrade()

    assert [(table, column) for table, column, _ in operations] == [
        ("agent_specialist_tasks", "created_at"),
        ("agent_specialist_tasks", "updated_at"),
    ]
    assert [str(default) for _, _, default in operations] == ["now()", "now()"]


def test_specialist_timestamp_repair_is_reversible(monkeypatch) -> None:
    migration = _load("0112_agent_specialist_timestamp_defaults.py")
    operations: list[tuple[str, str, object]] = []
    monkeypatch.setattr(
        migration.op,
        "alter_column",
        lambda table, column, **kwargs: operations.append(
            (table, column, kwargs["server_default"])
        ),
    )

    migration.downgrade()

    assert operations == [
        ("agent_specialist_tasks", "updated_at", None),
        ("agent_specialist_tasks", "created_at", None),
    ]
