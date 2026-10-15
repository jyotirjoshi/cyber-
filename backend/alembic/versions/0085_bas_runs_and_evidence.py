"""Add durable breach-and-attack simulation runs and evidence outcomes."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0085_bas_runs_and_evidence"
down_revision = "0084_scan_auth_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_simulation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("baseline_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=20), server_default="pending", nullable=False),
        sa.Column("catalog_version", sa.String(length=40), nullable=False),
        sa.Column("scenarios_snapshot", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("targets_snapshot", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("summary", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("triggered_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('pending','awaiting_approval','running','completed','failed','cancelled')", name=op.f("ck_attack_simulation_runs_valid_attack_simulation_run_status")),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["baseline_run_id"], ["attack_simulation_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["campaign_id"], ["attack_simulation_campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["triggered_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_simulation_runs")),
        sa.UniqueConstraint("assessment_id", name="unique_attack_simulation_run_assessment"),
    )
    op.create_index("ix_attack_simulation_runs_org_campaign_time", "attack_simulation_runs", ["organization_id", "campaign_id", "created_at"])
    op.create_index("ix_attack_simulation_runs_org_status", "attack_simulation_runs", ["organization_id", "status"])
    op.create_index(op.f("ix_attack_simulation_runs_organization_id"), "attack_simulation_runs", ["organization_id"])
    op.create_index(op.f("ix_attack_simulation_runs_created_at"), "attack_simulation_runs", ["created_at"])

    op.create_table(
        "attack_simulation_technique_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scanner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("technique_key", sa.String(length=120), nullable=False),
        sa.Column("scenario", sa.String(length=80), nullable=False),
        sa.Column("mitre_technique", sa.String(length=32), nullable=False),
        sa.Column("adapter", sa.String(length=40), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("risk_class", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=24), server_default="queued", nullable=False),
        sa.Column("control_result", sa.String(length=24), nullable=True),
        sa.Column("expected_evidence", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence_artifact_ids", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence_summary", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("risk_class IN ('low','medium','high')", name=op.f("ck_attack_simulation_technique_runs_valid_bas_technique_risk")),
        sa.CheckConstraint("status IN ('queued','awaiting_approval','running','completed','failed','cancelled')", name=op.f("ck_attack_simulation_technique_runs_valid_bas_technique_status")),
        sa.CheckConstraint("control_result IS NULL OR control_result IN ('detected','prevented','inconclusive','error')", name=op.f("ck_attack_simulation_technique_runs_valid_bas_control_result")),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["attack_simulation_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scanner_job_id"], ["scanner_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_simulation_technique_runs")),
        sa.UniqueConstraint("run_id", "scenario", "target", name="unique_bas_run_scenario_target"),
    )
    op.create_index("ix_bas_technique_runs_org_status", "attack_simulation_technique_runs", ["organization_id", "status"])
    op.create_index("ix_bas_technique_runs_job", "attack_simulation_technique_runs", ["scanner_job_id"])
    op.create_index(op.f("ix_attack_simulation_technique_runs_organization_id"), "attack_simulation_technique_runs", ["organization_id"])
    op.create_index(op.f("ix_attack_simulation_technique_runs_created_at"), "attack_simulation_technique_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_attack_simulation_technique_runs_created_at"), table_name="attack_simulation_technique_runs")
    op.drop_index(op.f("ix_attack_simulation_technique_runs_organization_id"), table_name="attack_simulation_technique_runs")
    op.drop_index("ix_bas_technique_runs_job", table_name="attack_simulation_technique_runs")
    op.drop_index("ix_bas_technique_runs_org_status", table_name="attack_simulation_technique_runs")
    op.drop_table("attack_simulation_technique_runs")
    op.drop_index(op.f("ix_attack_simulation_runs_created_at"), table_name="attack_simulation_runs")
    op.drop_index(op.f("ix_attack_simulation_runs_organization_id"), table_name="attack_simulation_runs")
    op.drop_index("ix_attack_simulation_runs_org_status", table_name="attack_simulation_runs")
    op.drop_index("ix_attack_simulation_runs_org_campaign_time", table_name="attack_simulation_runs")
    op.drop_table("attack_simulation_runs")
