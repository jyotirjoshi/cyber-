"""Allow approval-bound agent ticket actions for every supported tracker.

Revision ID: 0043_agent_multi_provider_tickets
Revises: 0042_dashboard_layouts
"""

from __future__ import annotations

from alembic import op

revision = "0043_agent_multi_provider_tickets"
down_revision = "0042_dashboard_layouts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work','bulk_update_canonical_work','request_retest','request_risk_acceptance','start_assessment')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','update_github_alert','create_jira_ticket','update_canonical_work','bulk_update_canonical_work','request_retest','request_risk_acceptance','start_assessment')",
    )
