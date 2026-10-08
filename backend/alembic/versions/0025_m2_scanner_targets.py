"""Allow repository and container-image scanning in the assessment pipeline.

Revision ID: 0025_m2_scanner_targets
Revises: 0024_m1_worker_core
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0025_m2_scanner_targets"
down_revision = "0024_m1_worker_core"
branch_labels = None
depends_on = None

_OLD_STAGES = (
    "current_stage IN ('queued','understanding_request','validating_target',"
    "'checking_authorization','planning','reconnaissance','asset_analysis',"
    "'awaiting_approval','scanning_nmap','scanning_nuclei','scanning_zap',"
    "'importing_findings','threat_intelligence','ai_analysis','risk_prioritization',"
    "'remediation','creating_actions','report','done')"
)
_NEW_STAGES = _OLD_STAGES.replace(
    "'scanning_zap',",
    "'scanning_zap','scanning_trivy_repo','scanning_semgrep_repo','scanning_gitleaks_repo','scanning_trivy_image','scanning_syft_image','scanning_prowler_aws','scanning_prowler_azure','scanning_prowler_gcp',",
)
_OLD_SCANNERS = "scanner IN ('reconftw','nmap','nuclei','zap')"
_NEW_SCANNERS = "scanner IN ('reconftw','nmap','nuclei','zap','trivy_repo','semgrep_repo','gitleaks_repo','trivy_image','syft_image','prowler_aws','prowler_azure','prowler_gcp')"
_OLD_INTEGRATIONS = "kind IN ('llm','defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable')"
_NEW_INTEGRATIONS = _OLD_INTEGRATIONS[:-1] + ",'bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_OLD_ACTIONS = (
    "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts',"
    "'sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities',"
    "'update_github_alert','create_jira_ticket','update_canonical_work')"
)
_NEW_ACTIONS = _OLD_ACTIONS.replace(
    "'update_canonical_work')",
    "'update_canonical_work','start_assessment')",
)
_OLD_CRITICALITY_SOURCES = (
    "criticality_source IN ('operator_tag','inferred_keyword','inferred_exposure','default')"
)
_NEW_CRITICALITY_SOURCES = (
    "criticality_source IN ('operator_tag','cmdb','inferred_keyword',"
    "'inferred_exposure','default')"
)
_OLD_NOTIFICATION_EVENTS = (
    "event IN ('assessment_started','approval_required','critical_finding',"
    "'assessment_completed','assessment_failed','ticket_created')"
)
_NEW_NOTIFICATION_EVENTS = _OLD_NOTIFICATION_EVENTS.replace(
    "'ticket_created')",
    "'ticket_created','new_asset')",
)


def upgrade() -> None:
    op.add_column("assessments", sa.Column("api_auth_ciphertext", sa.Text(), nullable=True))
    op.add_column(
        "canonical_findings",
        sa.Column("intel_evidence", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "canonical_findings", sa.Column("intel_refreshed_at", sa.DateTime(timezone=True)),
    )
    op.create_index(
        op.f("ix_canonical_findings_org_intel_refresh"), "canonical_findings",
        ["organization_id", "intel_refreshed_at"],
    )
    op.add_column(
        "agent_actions", sa.Column("depends_on_action_id", pg.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_agent_actions_depends_on_action_id", "agent_actions", "agent_actions",
        ["depends_on_action_id"], ["id"], ondelete="CASCADE",
    )
    op.create_index(
        op.f("ix_agent_actions_depends_on_action_id"), "agent_actions", ["depends_on_action_id"],
    )
    op.add_column(
        "agent_messages",
        sa.Column("source_action_id", pg.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_agent_messages_source_action_id_agent_actions",
        "agent_messages", "agent_actions", ["source_action_id"], ["id"],
        ondelete="SET NULL",
    )
    op.create_unique_constraint(
        "unique_action_receipt", "agent_messages", ["source_action_id"],
    )
    op.drop_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        _NEW_INTEGRATIONS,
    )
    op.create_table(
        "assessment_canonical_findings",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("scanner_job_id", pg.UUID(as_uuid=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["canonical_finding_id"],
            ["canonical_findings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["scanner_job_id"], ["scanner_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "assessment_id",
            "canonical_finding_id",
            name="unique_assessment_canonical_finding",
        ),
    )
    op.create_index(
        op.f("ix_assessment_canonical_findings_organization_id"),
        "assessment_canonical_findings",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_assessment_canonical_findings_org_assessment"),
        "assessment_canonical_findings",
        ["organization_id", "assessment_id"],
    )
    op.create_table(
        "asset_changes",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", pg.UUID(as_uuid=True)),
        sa.Column("asset_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("change_type", sa.String(20), nullable=False),
        sa.Column("changes", pg.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "change_type IN ('discovered','changed')",
            name=op.f("ck_asset_changes_valid_asset_change_type"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "assessment_id",
            "asset_id",
            name="unique_asset_change_per_assessment",
        ),
    )
    op.create_index(op.f("ix_asset_changes_organization_id"), "asset_changes", ["organization_id"])
    op.create_index(op.f("ix_asset_changes_created_at"), "asset_changes", ["created_at"])
    op.create_index(op.f("ix_asset_changes_updated_at"), "asset_changes", ["updated_at"])
    op.create_index(
        op.f("ix_asset_changes_org_time"), "asset_changes", ["organization_id", "created_at"]
    )
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_event"), "notifications", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        _NEW_NOTIFICATION_EVENTS,
    )
    op.add_column("scanner_jobs", sa.Column("imported_at", sa.DateTime(timezone=True)))
    op.add_column(
        "assets",
        sa.Column(
            "custom_fields", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.add_column(
        "canonical_findings",
        sa.Column(
            "custom_fields", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.drop_constraint(op.f("ck_assets_valid_criticality_source"), "assets", type_="check")
    op.create_check_constraint(
        op.f("ck_assets_valid_criticality_source"),
        "assets",
        _NEW_CRITICALITY_SOURCES,
    )
    op.drop_constraint(op.f("ck_assessments_valid_assessment_stage"), "assessments", type_="check")
    op.create_check_constraint(
        op.f("ck_assessments_valid_assessment_stage"),
        "assessments",
        _NEW_STAGES,
    )
    op.drop_constraint(op.f("ck_scanner_jobs_valid_scanner_name"), "scanner_jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_scanner_jobs_valid_scanner_name"),
        "scanner_jobs",
        _NEW_SCANNERS,
    )
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        _NEW_ACTIONS,
    )


def downgrade() -> None:
    op.drop_column("assessments", "api_auth_ciphertext")
    op.drop_index(
        op.f("ix_canonical_findings_org_intel_refresh"), table_name="canonical_findings",
    )
    op.drop_column("canonical_findings", "intel_refreshed_at")
    op.drop_column("canonical_findings", "intel_evidence")
    op.drop_index(op.f("ix_agent_actions_depends_on_action_id"), table_name="agent_actions")
    op.drop_constraint(
        "fk_agent_actions_depends_on_action_id", "agent_actions", type_="foreignkey",
    )
    op.drop_column("agent_actions", "depends_on_action_id")
    op.drop_constraint(
        "unique_action_receipt", "agent_messages", type_="unique",
    )
    op.drop_constraint(
        "fk_agent_messages_source_action_id_agent_actions", "agent_messages", type_="foreignkey",
    )
    op.drop_column("agent_messages", "source_action_id")
    op.drop_index(
        op.f("ix_assessment_canonical_findings_org_assessment"),
        table_name="assessment_canonical_findings",
    )
    op.drop_index(
        op.f("ix_assessment_canonical_findings_organization_id"),
        table_name="assessment_canonical_findings",
    )
    op.drop_table("assessment_canonical_findings")
    op.execute(
        "DELETE FROM integrations WHERE kind IN ('bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
    )
    op.drop_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"),
        "integrations",
        _OLD_INTEGRATIONS,
    )
    op.execute("DELETE FROM notifications WHERE event = 'new_asset'")
    op.drop_constraint(
        op.f("ck_notifications_valid_notification_event"), "notifications", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_notifications_valid_notification_event"),
        "notifications",
        _OLD_NOTIFICATION_EVENTS,
    )
    op.drop_index(op.f("ix_asset_changes_org_time"), table_name="asset_changes")
    op.drop_index(op.f("ix_asset_changes_created_at"), table_name="asset_changes")
    op.drop_index(op.f("ix_asset_changes_updated_at"), table_name="asset_changes")
    op.drop_index(op.f("ix_asset_changes_organization_id"), table_name="asset_changes")
    op.drop_table("asset_changes")
    op.drop_column("canonical_findings", "custom_fields")
    op.drop_column("assets", "custom_fields")
    op.execute(
        "UPDATE assets SET criticality_source = 'operator_tag' WHERE criticality_source = 'cmdb'"
    )
    op.drop_constraint(op.f("ck_assets_valid_criticality_source"), "assets", type_="check")
    op.create_check_constraint(
        op.f("ck_assets_valid_criticality_source"),
        "assets",
        _OLD_CRITICALITY_SOURCES,
    )
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"),
        "agent_actions",
        _OLD_ACTIONS,
    )
    op.drop_column("scanner_jobs", "imported_at")
    op.drop_constraint(op.f("ck_scanner_jobs_valid_scanner_name"), "scanner_jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_scanner_jobs_valid_scanner_name"),
        "scanner_jobs",
        _OLD_SCANNERS,
    )
    op.drop_constraint(op.f("ck_assessments_valid_assessment_stage"), "assessments", type_="check")
    op.create_check_constraint(
        op.f("ck_assessments_valid_assessment_stage"),
        "assessments",
        _OLD_STAGES,
    )
