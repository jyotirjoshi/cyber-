"""Scope existing GitHub alert identities to their repositories.

Revision ID: 0013_github_repo_identity
Revises: 0012_external_alert_absence
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0013_github_repo_identity"
down_revision = "0012_external_alert_absence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Legacy rows were keyed only by feed and number, which can collide across
    # repositories. Only rewrite rows with a trustworthy stored full_name.
    op.execute(sa.text("""
        UPDATE external_security_alerts
        SET external_id = category || ':' || resource || ':' ||
            substring(external_id FROM char_length(category) + 2)
        WHERE provider = 'github'
          AND category IN ('dependabot', 'code_scanning', 'secret_scanning')
          AND resource IS NOT NULL
          AND position('/' IN resource) > 0
          AND external_id LIKE category || ':%'
          AND external_id NOT LIKE category || ':' || resource || ':%'
          AND char_length(category || ':' || resource || ':' ||
              substring(external_id FROM char_length(category) + 2)) <= 300
    """))


def downgrade() -> None:
    # There is no schema change to undo. Stripping repository identity from data
    # would reintroduce collisions, so a schema downgrade preserves corrected rows.
    pass
