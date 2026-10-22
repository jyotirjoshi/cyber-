"""Add durable SOC cases and detection engineering.

Revision ID: 0109_soc_case_detection
Revises: 0108_native_ai_posture_action
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0109_soc_case_detection"
down_revision = "0108_native_ai_posture_action"
branch_labels = None
depends_on = None


def _tenant_columns() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def _tenant_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["organization_id"],
        ["organizations.id"],
        ondelete="CASCADE",
        name=op.f(f"fk_{table}_organization_id_organizations"),
    )


def _base_indexes(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def upgrade() -> None:
    op.create_table(
        "soc_incident_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("case_key", sa.String(200), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("threat_story_id", postgresql.UUID(as_uuid=True)),
        sa.Column("assigned_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("owner_team", sa.String(120)),
        sa.Column("event_ids", postgresql.JSONB(), nullable=False),
        sa.Column("asset_ids", postgresql.JSONB(), nullable=False),
        sa.Column("finding_ids", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False),
        sa.Column("timeline", postgresql.JSONB(), nullable=False),
        sa.Column("resolution", sa.Text()),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("contained_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        *_tenant_columns(),
        sa.CheckConstraint("severity IN ('info','low','medium','high','critical')", name=op.f("ck_soc_incident_cases_valid_soc_case_severity")),
        sa.CheckConstraint("status IN ('open','investigating','contained','resolved','dismissed')", name=op.f("ck_soc_incident_cases_valid_soc_case_status")),
        sa.CheckConstraint("priority BETWEEN 0 AND 100", name=op.f("ck_soc_incident_cases_valid_soc_case_priority")),
        sa.ForeignKeyConstraint(["threat_story_id"], ["security_threat_stories.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"], ondelete="SET NULL"),
        _tenant_fk("soc_incident_cases"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_soc_incident_cases")),
        sa.UniqueConstraint("organization_id", "case_key", name="unique_soc_incident_case_key"),
    )
    _base_indexes("soc_incident_cases")
    op.create_index("ix_soc_cases_org_status", "soc_incident_cases", ["organization_id", "status"])
    op.create_index("ix_soc_cases_org_assignee", "soc_incident_cases", ["organization_id", "assigned_user_id"])

    op.create_table(
        "soc_case_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("assigned_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False),
        *_tenant_columns(),
        sa.CheckConstraint("status IN ('open','in_progress','blocked','completed','cancelled')", name=op.f("ck_soc_case_tasks_valid_soc_case_task_status")),
        sa.ForeignKeyConstraint(["case_id"], ["soc_incident_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"], ondelete="SET NULL"),
        _tenant_fk("soc_case_tasks"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_soc_case_tasks")),
    )
    _base_indexes("soc_case_tasks")
    op.create_index("ix_soc_case_tasks_org_case", "soc_case_tasks", ["organization_id", "case_id"])
    op.create_index("ix_soc_case_tasks_org_status", "soc_case_tasks", ["organization_id", "status"])

    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_key", sa.String(160), nullable=False),
        sa.Column("name", sa.String(240), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("minimum_event_severity", sa.String(16), nullable=False),
        sa.Column("categories", postgresql.JSONB(), nullable=False),
        sa.Column("event_types", postgresql.JSONB(), nullable=False),
        sa.Column("conditions", postgresql.JSONB(), nullable=False),
        sa.Column("group_by", postgresql.JSONB(), nullable=False),
        sa.Column("auto_create_case", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("last_matched_at", sa.DateTime(timezone=True)),
        *_tenant_columns(),
        sa.CheckConstraint("status IN ('draft','active','disabled')", name=op.f("ck_detection_rules_valid_detection_rule_status")),
        sa.CheckConstraint("severity IN ('info','low','medium','high','critical')", name=op.f("ck_detection_rules_valid_detection_rule_severity")),
        sa.CheckConstraint("minimum_event_severity IN ('info','low','medium','high','critical')", name=op.f("ck_detection_rules_valid_detection_rule_minimum_severity")),
        sa.CheckConstraint("version > 0", name=op.f("ck_detection_rules_valid_detection_rule_version")),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        _tenant_fk("detection_rules"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_rules")),
        sa.UniqueConstraint("organization_id", "rule_key", name="unique_detection_rule_key"),
    )
    _base_indexes("detection_rules")
    op.create_index("ix_detection_rules_org_status", "detection_rules", ["organization_id", "status"])

    op.create_table(
        "detection_rule_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("case_id", postgresql.UUID(as_uuid=True)),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        *_tenant_columns(),
        sa.ForeignKeyConstraint(["rule_id"], ["detection_rules.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["case_id"], ["soc_incident_cases.id"], ondelete="SET NULL"),
        _tenant_fk("detection_rule_matches"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_rule_matches")),
        sa.UniqueConstraint("organization_id", "rule_id", "event_id", name="unique_detection_rule_event_match"),
    )
    _base_indexes("detection_rule_matches")
    op.create_index("ix_detection_matches_org_rule", "detection_rule_matches", ["organization_id", "rule_id"])
    op.create_index("ix_detection_matches_org_case", "detection_rule_matches", ["organization_id", "case_id"])


def downgrade() -> None:
    op.drop_index("ix_detection_matches_org_case", table_name="detection_rule_matches")
    op.drop_index("ix_detection_matches_org_rule", table_name="detection_rule_matches")
    op.drop_index(op.f("ix_detection_rule_matches_created_at"), table_name="detection_rule_matches")
    op.drop_index(op.f("ix_detection_rule_matches_organization_id"), table_name="detection_rule_matches")
    op.drop_table("detection_rule_matches")
    op.drop_index("ix_detection_rules_org_status", table_name="detection_rules")
    op.drop_index(op.f("ix_detection_rules_created_at"), table_name="detection_rules")
    op.drop_index(op.f("ix_detection_rules_organization_id"), table_name="detection_rules")
    op.drop_table("detection_rules")
    op.drop_index("ix_soc_case_tasks_org_status", table_name="soc_case_tasks")
    op.drop_index("ix_soc_case_tasks_org_case", table_name="soc_case_tasks")
    op.drop_index(op.f("ix_soc_case_tasks_created_at"), table_name="soc_case_tasks")
    op.drop_index(op.f("ix_soc_case_tasks_organization_id"), table_name="soc_case_tasks")
    op.drop_table("soc_case_tasks")
    op.drop_index("ix_soc_cases_org_assignee", table_name="soc_incident_cases")
    op.drop_index("ix_soc_cases_org_status", table_name="soc_incident_cases")
    op.drop_index(op.f("ix_soc_incident_cases_created_at"), table_name="soc_incident_cases")
    op.drop_index(op.f("ix_soc_incident_cases_organization_id"), table_name="soc_incident_cases")
    op.drop_table("soc_incident_cases")
