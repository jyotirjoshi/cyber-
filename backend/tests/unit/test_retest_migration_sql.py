"""Retest cleanup SQL must not interpret JSON booleans as bind parameters."""
import importlib.util
import io
from pathlib import Path
import pytest
from app.db.base import Base

from alembic.migration import MigrationContext
from alembic.operations import Operations


def test_retest_cleanup_emits_true_without_unbound_sql_parameters():
    path = Path(__file__).resolve().parents[2] / "alembic/versions/0051_retest_active_request_uniqueness.py"
    spec = importlib.util.spec_from_file_location("retest_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = io.StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output})
    with Operations.context(context):
        module.upgrade()
    sql = output.getvalue()
    assert "%(" not in sql
    assert "NULL" not in sql
    assert "deduplicated_by_migration" in sql
    assert "true" in sql


@pytest.mark.parametrize("number", [65, 66, 67, 68, 69, 74])
def test_connector_migrations_preserve_existing_constraint_names(number):
    path = next((Path(__file__).resolve().parents[2] / "alembic/versions").glob(f"{number:04d}_*.py"))
    spec = importlib.util.spec_from_file_location("connector_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = io.StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output, "target_metadata": Base.metadata})
    with Operations.context(context):
        module.upgrade()
    sql = output.getvalue()
    assert "DROP CONSTRAINT ck_integrations_valid_integration_kind;" in sql
    assert "ck_integrations_ck_" not in sql
    assert "ck_notifications_ck_" not in sql
