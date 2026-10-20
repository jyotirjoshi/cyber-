"""Allow the governed native AI posture agent action.

Revision ID: 0108_native_ai_posture_action
Revises: 0107_compliance_evidence_workflow
"""

from __future__ import annotations

from alembic import op

revision = "0108_native_ai_posture_action"
down_revision = "0107_compliance_evidence_workflow"
branch_labels = None
depends_on = None

_OLD = (
    "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts',"
    "'sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities',"
    "'sync_qualys_host_detections','sync_rapid7_vulnerabilities','sync_wiz_issues',"
    "'sync_prisma_cloud_alerts','sync_crowdstrike_vulnerabilities',"
    "'sync_aws_security_hub_findings','sync_aws_inspector_findings',"
    "'sync_hackerone_reports','sync_bugcrowd_submissions','sync_checkmarx_results',"
    "'sync_fortify_issues','sync_azure_defender_alerts','sync_gcp_scc_findings',"
    "'sync_burp_dast_findings','update_github_alert','create_jira_ticket','create_ticket',"
    "'refresh_ticket_status','update_canonical_work','bulk_update_canonical_work',"
    "'request_retest','request_remediation_group_retests','request_risk_acceptance',"
    "'start_assessment')"
)
_NEW = _OLD[:-1] + ",'run_native_ai_posture')"


def upgrade() -> None:
    op.drop_constraint("ck_agent_actions_valid_agent_action", "agent_actions", type_="check")
    op.create_check_constraint("valid_agent_action", "agent_actions", _NEW)


def downgrade() -> None:
    op.drop_constraint("ck_agent_actions_valid_agent_action", "agent_actions", type_="check")
    op.create_check_constraint("valid_agent_action", "agent_actions", _OLD)
