"""Add Fortify SSC direct integration and sync action."""

from alembic import op

revision = "0080_fortify_direct_integration"
down_revision = "0079_checkmarx_direct_integration"
branch_labels = None
depends_on = None

_OLD_KINDS = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','burp_dast','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','prisma_cloud','crowdstrike','aws_security_hub','aws_inspector','hackerone','bugcrowd','checkmarx','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_NEW_KINDS = _OLD_KINDS.replace("'checkmarx'", "'checkmarx','fortify'")
_OLD_ACTIONS = "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','sync_qualys_host_detections','sync_rapid7_vulnerabilities','sync_wiz_issues','sync_prisma_cloud_alerts','sync_crowdstrike_vulnerabilities','sync_aws_security_hub_findings','sync_aws_inspector_findings','sync_hackerone_reports','sync_bugcrowd_submissions','sync_checkmarx_results','sync_azure_defender_alerts','sync_gcp_scc_findings','sync_burp_dast_findings','update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work','bulk_update_canonical_work','request_retest','request_remediation_group_retests','request_risk_acceptance','start_assessment')"
_NEW_ACTIONS = _OLD_ACTIONS.replace("'sync_checkmarx_results'", "'sync_checkmarx_results','sync_fortify_issues'")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _NEW_KINDS)
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _NEW_ACTIONS)


def downgrade() -> None:
    op.execute("DELETE FROM agent_actions WHERE action = 'sync_fortify_issues'")
    op.execute("DELETE FROM integrations WHERE kind = 'fortify'")
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _OLD_ACTIONS)
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", _OLD_KINDS)
