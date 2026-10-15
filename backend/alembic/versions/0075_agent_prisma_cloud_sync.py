"""Allow monitored AI actions to synchronize Prisma Cloud alerts.

Revision ID: 0075_agent_prisma_cloud_sync
Revises: 0074_prisma_cloud_direct_integration
"""

from alembic import op

revision = "0075_agent_prisma_cloud_sync"
down_revision = "0074_prisma_cloud_direct_integration"
branch_labels = None
depends_on = None

_OLD = "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','sync_qualys_host_detections','sync_rapid7_vulnerabilities','sync_wiz_issues','sync_crowdstrike_vulnerabilities','sync_aws_security_hub_findings','sync_azure_defender_alerts','sync_gcp_scc_findings','sync_burp_dast_findings','update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work','bulk_update_canonical_work','request_retest','request_remediation_group_retests','request_risk_acceptance','start_assessment')"
_NEW = _OLD.replace("'sync_wiz_issues'", "'sync_wiz_issues','sync_prisma_cloud_alerts'")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _NEW)


def downgrade() -> None:
    op.execute("DELETE FROM agent_actions WHERE action = 'sync_prisma_cloud_alerts'")
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _OLD)
