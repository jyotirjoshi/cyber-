"""Allow approved AI actions to request remediation group verification.

Revision ID: 0054_agent_remediation_group_retests
Revises: 0053_canonical_remediation_groups
"""

from __future__ import annotations

from alembic import op


revision = "0054_agent_remediation_group_retests"
down_revision = "0053_canonical_remediation_groups"
branch_labels = None
depends_on = None


_NEW_ACTIONS = (
    "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts',"
    "'sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities',"
    "'update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status',"
    "'update_canonical_work','bulk_update_canonical_work','request_retest',"
    "'request_remediation_group_retests','request_risk_acceptance','start_assessment')"
)
_OLD_ACTIONS = _NEW_ACTIONS.replace(",'request_remediation_group_retests'", "")


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _NEW_ACTIONS)


def downgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _OLD_ACTIONS)
