"""Add assessment.extra_data column for attack paths / SSVC / compound risks.

Revision ID: 0002_assessment_metadata_ssvc
Revises: 0001_initial_schema
Create Date: 2026-09-18

"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002_assessment_metadata_ssvc"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # assessment.extra_data — stores attack_paths, compound_risks, coverage_gaps
    op.add_column(
        "assessments",
        sa.Column(
            "extra_data",
            JSONB(),
            nullable=False,
            # A SQL expression, not a quoted Python string.  Passing the string
            # directly makes SQLAlchemy quote it again as text.
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("assessments", "extra_data")
