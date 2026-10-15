"""Add the read-only Qualys VM connector kind.

Revision ID: 0056_qualys_direct_integration
Revises: 0055_canonical_remediation_group_keys
"""

from __future__ import annotations

from alembic import op


revision = "0056_qualys_direct_integration"
down_revision = "0055_canonical_remediation_group_keys"
branch_labels = None
depends_on = None


_NEW_KINDS = (
    "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty',"
    "'slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk',"
    "'tenable','qualys','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
)
_OLD_KINDS = _NEW_KINDS.replace(",'qualys'", "")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW_KINDS
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD_KINDS
    )
