"""Add elite AI analysis fields to findings table.

Revision ID: 0003_finding_elite_ai_fields
Revises: 0002_assessment_metadata_ssvc
Create Date: 2026-09-18

New columns:
  findings.ai_adversary_profile  - threat actor profile from ELITE_FINDING_ANALYSIS_SYSTEM
  findings.ai_mitre_tactics      - MITRE ATT&CK tactic array
  findings.ai_detection_hint     - specific log/SIEM detection hint
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003_finding_elite_ai_fields"
down_revision = "0002_assessment_metadata_ssvc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("ai_adversary_profile", sa.Text(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "ai_mitre_tactics",
            JSONB(),
            nullable=False,
            server_default="'[]'::jsonb",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("ai_detection_hint", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "ai_detection_hint")
    op.drop_column("findings", "ai_mitre_tactics")
    op.drop_column("findings", "ai_adversary_profile")
