"""Add the Prisma Cloud direct integration kind.

Revision ID: 0074_prisma_cloud_direct_integration
Revises: 0073_tenant_model_indexes
"""

from alembic import op

revision = "0074_prisma_cloud_direct_integration"
down_revision = "0073_tenant_model_indexes"
branch_labels = None
depends_on = None

_OLD = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','burp_dast','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_NEW = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','burp_dast','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','prisma_cloud','crowdstrike','aws_security_hub','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW)


def downgrade() -> None:
    op.execute("DELETE FROM integrations WHERE kind = 'prisma_cloud'")
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD)
