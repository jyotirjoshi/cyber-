"""Add the tenant-scoped Rapid7 InsightVM integration kind.

Revision ID: 0058_rapid7_direct_integration
Revises: 0057_agent_qualys_sync
"""

from __future__ import annotations

from alembic import op


revision = "0058_rapid7_direct_integration"
down_revision = "0057_agent_qualys_sync"
branch_labels = None
depends_on = None

_NEW_KINDS = (
    "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty',"
    "'slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk',"
    "'tenable','qualys','rapid7','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
)
_OLD_KINDS = _NEW_KINDS.replace(",'rapid7'", "")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW_KINDS)


def downgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD_KINDS)
