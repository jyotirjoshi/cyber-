"""Allow approved GitHub alert source actions in agent conversations.

Revision ID: 0016_github_alert_agent_action
Revises: 0015_tenable_integration
"""

from __future__ import annotations

from alembic import op

revision = "0016_github_alert_agent_action"
down_revision = "0015_tenable_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','update_github_alert','create_jira_ticket')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','create_jira_ticket')",
    )
