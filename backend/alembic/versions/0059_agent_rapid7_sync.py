"""Allow the monitored agent to synchronize Rapid7 InsightVM findings.

Revision ID: 0059_agent_rapid7_sync
Revises: 0058_rapid7_direct_integration
"""

from __future__ import annotations

from alembic import op


revision = "0059_agent_rapid7_sync"
down_revision = "0058_rapid7_direct_integration"
branch_labels = None
depends_on = None

_NEW_ACTIONS = (
    "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts',"
    "'sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities',"
    "'sync_qualys_host_detections','sync_rapid7_vulnerabilities','update_github_alert',"
    "'create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work',"
    "'bulk_update_canonical_work','request_retest','request_remediation_group_retests',"
    "'request_risk_acceptance','start_assessment')"
)
_OLD_ACTIONS = _NEW_ACTIONS.replace(",'sync_rapid7_vulnerabilities'", "")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _NEW_ACTIONS)


def downgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _OLD_ACTIONS)
