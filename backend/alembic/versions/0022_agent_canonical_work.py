"""Allow approved agent remediation-work updates.

Revision ID: 0022_agent_canonical_work
Revises: 0021_canonical_work
"""

from __future__ import annotations

from alembic import op

revision = "0022_agent_canonical_work"
down_revision = "0021_canonical_work"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','update_github_alert','create_jira_ticket','update_canonical_work')",
    )


def downgrade() -> None:
    # An existing update_canonical_work action makes the old constraint fail; the
    # transaction rolls back instead of silently deleting its audit history.
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','update_github_alert','create_jira_ticket')",
    )
