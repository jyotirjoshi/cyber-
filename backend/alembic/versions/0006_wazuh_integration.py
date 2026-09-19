"""Add tenant-scoped Wazuh integration support.

Revision ID: 0006_wazuh_integration
Revises: 0005_llm_byok_integration
Create Date: 2026-09-20
"""

from __future__ import annotations

from alembic import op


revision = "0006_wazuh_integration"
down_revision = "0005_llm_byok_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab')",
    )
