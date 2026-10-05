"""Allow tenant-scoped SonarQube connections and approved sync actions.

Revision ID: 0011_sonarqube_integration
Revises: 0010_agent_actions
"""

from __future__ import annotations

from alembic import op

revision = "0011_sonarqube_integration"
down_revision = "0010_agent_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube')",
    )
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','create_jira_ticket')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','create_jira_ticket')",
    )
    op.drop_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh')",
    )
