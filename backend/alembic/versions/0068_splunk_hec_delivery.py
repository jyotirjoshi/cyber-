"""Add tenant Splunk HEC integration and durable delivery channel."""

from alembic import op

revision = "0068_splunk_hec_delivery"
down_revision = "0067_gcp_scc_direct_integration"
branch_labels = None
depends_on = None

_OLD_KINDS = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_NEW_KINDS = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','crowdstrike','aws_security_hub','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_OLD_CHANNELS = "channel IN ('slack','email','websocket','pagerduty','webhook')"
_NEW_CHANNELS = "channel IN ('slack','email','websocket','pagerduty','webhook','splunk')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW_KINDS)
    op.drop_constraint(op.f("ck_notifications_valid_notification_channel"), "notifications", type_="check")
    op.create_check_constraint(op.f("ck_notifications_valid_notification_channel"), "notifications", _NEW_CHANNELS)


def downgrade() -> None:
    op.execute("DELETE FROM notifications WHERE channel = 'splunk'")
    op.execute("DELETE FROM integrations WHERE kind = 'splunk'")
    op.drop_constraint(op.f("ck_notifications_valid_notification_channel"), "notifications", type_="check")
    op.create_check_constraint(op.f("ck_notifications_valid_notification_channel"), "notifications", _OLD_CHANNELS)
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD_KINDS)
