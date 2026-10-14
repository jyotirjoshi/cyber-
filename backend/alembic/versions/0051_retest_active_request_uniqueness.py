"""Enforce one active retest request per canonical finding.

Revision ID: 0051_retest_active_request_uniqueness
Revises: 0050_asm_unreachable_drift
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0051_retest_active_request_uniqueness"
down_revision = "0050_asm_unreachable_drift"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older releases relied on service-level locking only.  Retain the newest request in
    # each active set and make superseded rows terminal before adding the invariant, so an
    # upgrade succeeds even if a prior multi-worker race left duplicate requests behind.
    op.execute(
        sa.text(
            """
            WITH ranked AS (
                SELECT
                    id,
                    row_number() OVER (
                        PARTITION BY organization_id, canonical_finding_id
                        ORDER BY created_at DESC, id DESC
                    ) AS position
                FROM retest_requests
                WHERE status IN ('requested', 'scheduled', 'running')
            )
            UPDATE retest_requests AS request
            SET
                status = 'cancelled',
                completed_at = COALESCE(request.completed_at, now()),
                evidence = COALESCE(request.evidence, '{}'::jsonb)
                    || jsonb_build_object('deduplicated_by_migration', true)
            FROM ranked
            WHERE request.id = ranked.id
              AND ranked.position > 1
            """
        )
    )
    op.create_index(
        "uq_retest_requests_one_active_per_finding",
        "retest_requests",
        ["organization_id", "canonical_finding_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('requested','scheduled','running')"),
    )


def downgrade() -> None:
    op.drop_index("uq_retest_requests_one_active_per_finding", table_name="retest_requests")
