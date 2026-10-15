"""Add durable remediation exception and retest governance.

Revision ID: 0026_m3_remediation_governance
Revises: 0025_m2_scanner_targets
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0026_m3_remediation_governance"
down_revision = "0025_m2_scanner_targets"
branch_labels = None
depends_on = None

_M2_ACTIONS = (
    "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts',"
    "'sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities',"
    "'update_github_alert','create_jira_ticket','update_canonical_work','start_assessment')"
)
_M3_ACTIONS = _M2_ACTIONS.replace(
    "'update_canonical_work','start_assessment')",
    "'update_canonical_work','bulk_update_canonical_work','request_retest','request_risk_acceptance','start_assessment')",
)
_M2_NOTIFICATION_EVENTS = (
    "event IN ('assessment_started','approval_required','critical_finding',"
    "'assessment_completed','assessment_failed','ticket_created','new_asset')"
)
_M3_NOTIFICATION_EVENTS = _M2_NOTIFICATION_EVENTS.replace(
    "'new_asset')", "'new_asset','sla_breach','automation_notification')"
)


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','bitbucket','prowler_aws','prowler_azure','prowler_gcp')")
    op.drop_constraint(op.f("ck_ticket_links_valid_ticket_provider"), "ticket_links", type_="check")
    op.create_check_constraint(op.f("ck_ticket_links_valid_ticket_provider"), "ticket_links", "provider IN ('jira','github','gitlab','servicenow','azure_devops','linear')")
    op.add_column(
        "agent_actions",
        sa.Column(
            "execution_evidence",
            pg.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _M3_ACTIONS
    )
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_event"), "notifications", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        _M3_NOTIFICATION_EVENTS,
    )
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_channel"), "notifications", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_channel"),
        "notifications",
        "channel IN ('slack','email','websocket','pagerduty')",
    )
    op.create_table(
        "risk_acceptances",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by_id", pg.UUID(as_uuid=True)),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('pending','approved','rejected','revoked','expired')", name=op.f("ck_risk_acceptances_valid_risk_acceptance_status")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_risk_acceptances_organization_id"), "risk_acceptances", ["organization_id"])
    op.create_index(op.f("ix_risk_acceptances_created_at"), "risk_acceptances", ["created_at"])
    op.create_index("ix_risk_acceptances_org_finding_status", "risk_acceptances", ["organization_id", "canonical_finding_id", "status"])
    op.create_index("ix_risk_acceptances_org_expiry", "risk_acceptances", ["organization_id", "expires_at"])
    op.create_table(
        "retest_requests",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by_id", pg.UUID(as_uuid=True)),
        sa.Column("assessment_id", pg.UUID(as_uuid=True)),
        sa.Column("status", sa.String(20), nullable=False, server_default="requested"),
        sa.Column("request_note", sa.Text()),
        sa.Column("evidence", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('requested','scheduled','running','confirmed','not_confirmed','failed','cancelled')", name=op.f("ck_retest_requests_valid_retest_request_status")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_retest_requests_organization_id"), "retest_requests", ["organization_id"])
    op.create_index(op.f("ix_retest_requests_created_at"), "retest_requests", ["created_at"])
    op.create_index("ix_retest_requests_org_finding_status", "retest_requests", ["organization_id", "canonical_finding_id", "status"])
    op.create_table(
        "sla_escalations",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("level IN (1,2,3)", name=op.f("ck_sla_escalations_valid_sla_escalation_level")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "canonical_finding_id", "level", name="unique_sla_escalation_level"),
    )
    op.create_index(op.f("ix_sla_escalations_organization_id"), "sla_escalations", ["organization_id"])
    op.create_index(op.f("ix_sla_escalations_created_at"), "sla_escalations", ["created_at"])
    op.create_index("ix_sla_escalations_org_finding_time", "sla_escalations", ["organization_id", "canonical_finding_id", "escalated_at"])
    op.create_table(
        "automation_rules",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("trigger", sa.String(40), nullable=False),
        sa.Column("conditions", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("actions", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cron_expression", sa.String(120)),
        sa.Column("timezone", sa.String(100), nullable=False, server_default="UTC"),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "trigger IN ('finding.created','finding.updated','ticket.closed','sla.breached')",
            name=op.f("ck_automation_rules_valid_automation_rule_trigger"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="unique_automation_rule_name"),
    )
    op.create_index(op.f("ix_automation_rules_organization_id"), "automation_rules", ["organization_id"])
    op.create_index(op.f("ix_automation_rules_created_at"), "automation_rules", ["created_at"])
    op.create_index("ix_automation_rules_org_trigger_enabled", "automation_rules", ["organization_id", "trigger", "is_enabled"])
    op.create_index("ix_automation_rules_due", "automation_rules", ["is_enabled", "next_run_at"])
    op.create_table(
        "automation_executions",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True)),
        sa.Column("event_key", sa.String(160), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('pending','skipped','dry_run','executed','failed')",
            name=op.f("ck_automation_executions_valid_automation_execution_status"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rule_id"], ["automation_rules.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id", "event_key", name="unique_automation_execution_event"),
    )
    op.create_index(op.f("ix_automation_executions_organization_id"), "automation_executions", ["organization_id"])
    op.create_index(op.f("ix_automation_executions_created_at"), "automation_executions", ["created_at"])
    op.create_index("ix_automation_executions_org_rule_time", "automation_executions", ["organization_id", "rule_id", "created_at"])
    op.create_table(
        "attack_simulation_campaigns",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("authorization_text", sa.Text(), nullable=False),
        sa.Column("authorization_reference", sa.String(1024), nullable=False),
        sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scenarios", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("targets", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cron_expression", sa.String(120)),
        sa.Column("timezone", sa.String(100), nullable=False, server_default="UTC"),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_assessment_id", pg.UUID(as_uuid=True)),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("last_error_code", sa.String(80)),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('draft','active','paused','completed','failed')", name=op.f("ck_attack_simulation_campaigns_valid_attack_simulation_campaign_status")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_assessment_id"], ["assessments.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="unique_attack_simulation_campaign_name"),
    )
    op.create_index(op.f("ix_attack_simulation_campaigns_organization_id"), "attack_simulation_campaigns", ["organization_id"])
    op.create_index(op.f("ix_attack_simulation_campaigns_created_at"), "attack_simulation_campaigns", ["created_at"])
    op.create_index("ix_attack_simulation_campaigns_due", "attack_simulation_campaigns", ["status", "next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_attack_simulation_campaigns_due", table_name="attack_simulation_campaigns")
    op.drop_index(op.f("ix_attack_simulation_campaigns_created_at"), table_name="attack_simulation_campaigns")
    op.drop_index(op.f("ix_attack_simulation_campaigns_organization_id"), table_name="attack_simulation_campaigns")
    op.drop_table("attack_simulation_campaigns")
    op.drop_constraint(op.f("ck_ticket_links_valid_ticket_provider"), "ticket_links", type_="check")
    op.create_check_constraint(op.f("ck_ticket_links_valid_ticket_provider"), "ticket_links", "provider IN ('jira','github','gitlab')")
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','bitbucket','prowler_aws','prowler_azure','prowler_gcp')")
    op.drop_index("ix_sla_escalations_org_finding_time", table_name="sla_escalations")
    op.drop_index(op.f("ix_sla_escalations_created_at"), table_name="sla_escalations")
    op.drop_index(op.f("ix_sla_escalations_organization_id"), table_name="sla_escalations")
    op.drop_table("sla_escalations")
    op.drop_index("ix_automation_executions_org_rule_time", table_name="automation_executions")
    op.drop_index(op.f("ix_automation_executions_created_at"), table_name="automation_executions")
    op.drop_index(op.f("ix_automation_executions_organization_id"), table_name="automation_executions")
    op.drop_table("automation_executions")
    op.drop_index("ix_automation_rules_due", table_name="automation_rules")
    op.drop_index("ix_automation_rules_org_trigger_enabled", table_name="automation_rules")
    op.drop_index(op.f("ix_automation_rules_created_at"), table_name="automation_rules")
    op.drop_index(op.f("ix_automation_rules_organization_id"), table_name="automation_rules")
    op.drop_table("automation_rules")
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions", _M2_ACTIONS
    )
    op.drop_index("ix_retest_requests_org_finding_status", table_name="retest_requests")
    op.drop_index(op.f("ix_retest_requests_created_at"), table_name="retest_requests")
    op.drop_index(op.f("ix_retest_requests_organization_id"), table_name="retest_requests")
    op.drop_table("retest_requests")
    op.drop_index("ix_risk_acceptances_org_expiry", table_name="risk_acceptances")
    op.drop_index("ix_risk_acceptances_org_finding_status", table_name="risk_acceptances")
    op.drop_index(op.f("ix_risk_acceptances_created_at"), table_name="risk_acceptances")
    op.drop_index(op.f("ix_risk_acceptances_organization_id"), table_name="risk_acceptances")
    op.drop_table("risk_acceptances")
    op.execute("DELETE FROM notifications WHERE event = 'sla_breach'")
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_event"), "notifications", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        _M2_NOTIFICATION_EVENTS,
    )
    op.execute("DELETE FROM notifications WHERE channel = 'pagerduty'")
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_channel"), "notifications", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_channel"),
        "notifications",
        "channel IN ('slack','email','websocket')",
    )
    op.drop_column("agent_actions", "execution_evidence")
