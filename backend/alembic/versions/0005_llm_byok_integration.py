"""Allow tenant-scoped bring-your-own-key LLM integrations.

Revision ID: 0005_llm_byok_integration
Revises: 0004_ctem_foundation
Create Date: 2026-09-19
"""

from __future__ import annotations

from alembic import op


revision = "0005_llm_byok_integration"
down_revision = "0004_ctem_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        "kind IN ('defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab')",
    )
