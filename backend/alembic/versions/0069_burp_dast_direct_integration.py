"""Add the Burp Suite DAST direct integration kind."""

from alembic import op

revision = "0069_burp_dast_direct_integration"
down_revision = "0068_splunk_hec_delivery"
branch_labels = None
depends_on = None

_OLD = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_NEW = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','burp_dast','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW)


def downgrade() -> None:
    op.execute("DELETE FROM integrations WHERE kind = 'burp_dast'")
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD)
