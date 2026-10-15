"""Database connection setup for the pgvector extension."""

from __future__ import annotations

from typing import Any

from pgvector.asyncpg import register_vector

from app.db import session as session_module


class _AdaptedAsyncpgConnection:
    def __init__(self) -> None:
        self.callback: Any | None = None

    def run_async(self, callback: Any) -> None:
        self.callback = callback


def test_pgvector_registration_delegates_to_asyncpg_adapter() -> None:
    """Removing the connect hook would make VECTOR values decode as raw strings."""
    connection = _AdaptedAsyncpgConnection()

    session_module._register_pgvector_connection(connection, None)

    assert connection.callback is register_vector
