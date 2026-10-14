"""Add the Microsoft Defender for Cloud direct integration kind."""

from alembic import op

revision = "0066_azure_defender_direct_integration"
down_revision = "0065_aws_security_hub_direct_integration"
branch_labels = None
depends_on = None

_OLD = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_NEW = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','azure_defender','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW)


def downgrade() -> None:
    op.execute("DELETE FROM integrations WHERE kind = 'azure_defender'")
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD)
