"""Alembic environment.

Runs synchronously on psycopg rather than asyncpg.  Migrations are a one-shot
startup step, they gain nothing from an event loop, and the sync path avoids the
``asyncio.run`` wrapper that makes Alembic tracebacks hard to read.  The application
still uses asyncpg -- see :mod:`app.db.session`.

The DSN comes from settings, never from ``alembic.ini``, so a database password is
never written to a tracked file.
"""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.core.config import get_settings

# Importing the models package is what registers every mapper on the metadata.
# Without it autogenerate would cheerfully emit a migration that drops every table.
from app.db import models
from app.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.db.sync_dsn)

target_metadata = Base.metadata


def include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    """Keep LangGraph's own checkpoint tables out of our autogenerate diffs.

    ``langgraph-checkpoint-postgres`` creates and migrates ``checkpoints``,
    ``checkpoint_blobs`` and ``checkpoint_writes`` itself.  They live in the same
    database, so without this filter every autogenerate run would try to drop them.
    """
    if type_ == "table" and name is not None:
        return not name.startswith(("checkpoint", "checkpoint_"))
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
            # Serializes concurrent upgrades: two API replicas starting at once would
            # otherwise both try to create the same tables.
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
