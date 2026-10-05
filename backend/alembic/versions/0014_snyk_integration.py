"""Allow tenant-owned Snyk issue connections.

Revision ID: 0014_snyk_integration
Revises: 0013_github_repo_identity
"""

from __future__ import annotations

from alembic import op

revision = "0014_snyk_integration"
down_revision = "0013_github_repo_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk')",
    )
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','create_jira_ticket')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','create_jira_ticket')",
    )
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations",
        "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube')",
    )
