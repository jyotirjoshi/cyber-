"""Allow agent-triggered syncs for every implemented direct connector."""

from alembic import op

revision = "0070_direct_connector_agent_actions"
down_revision = "0069_burp_dast_direct_integration"
branch_labels = None
depends_on = None

_OLD = "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','sync_qualys_host_detections','sync_rapid7_vulnerabilities','sync_wiz_issues','update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work','bulk_update_canonical_work','request_retest','request_remediation_group_retests','request_risk_acceptance','start_assessment')"
_NEW = "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','sync_qualys_host_detections','sync_rapid7_vulnerabilities','sync_wiz_issues','sync_crowdstrike_vulnerabilities','sync_aws_security_hub_findings','sync_azure_defender_alerts','sync_gcp_scc_findings','sync_burp_dast_findings','update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work','bulk_update_canonical_work','request_retest','request_remediation_group_retests','request_risk_acceptance','start_assessment')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _NEW)


def downgrade() -> None:
    op.execute("DELETE FROM agent_actions WHERE action IN ('sync_crowdstrike_vulnerabilities','sync_aws_security_hub_findings','sync_azure_defender_alerts','sync_gcp_scc_findings','sync_burp_dast_findings')")
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _OLD)
