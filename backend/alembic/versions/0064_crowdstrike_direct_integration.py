"""Add the CrowdStrike Falcon Spotlight integration kind.

Revision ID: 0064_crowdstrike_direct_integration
Revises: 0063_vulnerability_intelligence_cache
"""

from __future__ import annotations

from alembic import op

revision = "0064_crowdstrike_direct_integration"
down_revision = "0063_vulnerability_intelligence_cache"
branch_labels = None
depends_on = None

_NEW_KINDS = (
    "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty',"
    "'slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk',"
    "'tenable','qualys','rapid7','wiz','crowdstrike','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
)
_OLD_KINDS = _NEW_KINDS.replace(",'crowdstrike'", "")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW_KINDS)


def downgrade() -> None:
    op.execute("DELETE FROM integrations WHERE kind = 'crowdstrike'")
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD_KINDS)
