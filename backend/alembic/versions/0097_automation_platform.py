"""Expand automation triggers and add encrypted inbound webhook secrets."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0097_automation_platform"
down_revision = "0096_agent_workspaces"
branch_labels = None
depends_on = None

_EXPANDED_TRIGGERS = (
    "trigger IN ('finding.created','finding.updated','ticket.closed','retest.confirmed',"
    "'retest.cleared','sla.breached','asset.created','asset.updated','assessment.started',"
    "'assessment.completed','engagement.created','engagement.status_changed','scan.failed',"
    "'integration.error','webhook.received','manual')"
)
_LEGACY_TRIGGERS = (
    "trigger IN ('finding.created','finding.updated','ticket.closed','retest.confirmed',"
    "'retest.cleared','sla.breached')"
)


def upgrade() -> None:
    op.add_column("automation_rules", sa.Column("inbound_secret_ciphertext", sa.Text()))
    op.add_column(
        "automation_rules",
        sa.Column("inbound_secret_rotated_at", sa.DateTime(timezone=True)),
    )
    op.drop_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        _EXPANDED_TRIGGERS,
    )


def downgrade() -> None:
    op.execute(
        "UPDATE automation_rules SET is_enabled = false, trigger = 'finding.updated' "
        "WHERE trigger NOT IN ('finding.created','finding.updated','ticket.closed',"
        "'retest.confirmed','retest.cleared','sla.breached')"
    )
    op.drop_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        _LEGACY_TRIGGERS,
    )
    op.drop_column("automation_rules", "inbound_secret_rotated_at")
    op.drop_column("automation_rules", "inbound_secret_ciphertext")
