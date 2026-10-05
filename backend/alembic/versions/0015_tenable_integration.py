"""Allow tenant-owned Tenable VM scan connections.

Revision ID: 0015_tenable_integration
Revises: 0014_snyk_integration
"""

from __future__ import annotations

from alembic import op

revision = "0015_tenable_integration"
down_revision = "0014_snyk_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk')",
    )
