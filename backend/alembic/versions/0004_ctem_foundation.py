"""Persist engagement controls and finding-validation evidence.

Revision ID: 0004_ctem_foundation
Revises: 0003_finding_elite_ai_fields
Create Date: 2026-09-19
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0004_ctem_foundation"
down_revision = "0003_finding_elite_ai_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assessments",
        sa.Column(
            "engagement_type",
            sa.String(length=60),
            nullable=False,
            server_default=sa.text("'web_application'"),
        ),
    )
    op.add_column(
        "assessments",
        sa.Column(
            "execution_mode",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'supervised'"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_assessments_valid_engagement_type"),
        "assessments",
        "engagement_type IN ('web_application','api_security','mobile_application',"
        "'llm_agentic_application','network_external','network_internal',"
        "'active_directory','cloud_security','code_review','threat_modeling',"
        "'attack_surface_monitoring','devsecops_pipeline','threat_hunting',"
        "'code_remediation','red_team','supply_chain')",
    )
    op.create_check_constraint(
        op.f("ck_assessments_valid_execution_mode"),
        "assessments",
        "execution_mode IN ('supervised','background','interactive')",
    )
    op.add_column(
        "findings",
        sa.Column(
            "validation_status",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'unvalidated'"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column(
            "validation_proof",
            JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column("findings", sa.Column("validation_checked_at", sa.DateTime(timezone=True)))
    op.create_check_constraint(
        op.f("ck_findings_valid_validation_status"),
        "findings",
        "validation_status IN ('unvalidated','confirmed','rejected','recheck_required')",
    )
    op.create_index(
        "ix_findings_organization_id_validation_status",
        "findings",
        ["organization_id", "validation_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_findings_organization_id_validation_status", table_name="findings")
    op.drop_constraint(op.f("ck_findings_valid_validation_status"), "findings", type_="check")
    op.drop_column("findings", "validation_checked_at")
    op.drop_column("findings", "validation_proof")
    op.drop_column("findings", "validation_status")
    op.drop_constraint(op.f("ck_assessments_valid_execution_mode"), "assessments", type_="check")
    op.drop_constraint(op.f("ck_assessments_valid_engagement_type"), "assessments", type_="check")
    op.drop_column("assessments", "execution_mode")
    op.drop_column("assessments", "engagement_type")
