"""Allow automation rules to react to evidence-based retest outcomes.

Revision ID: 0052_retest_automation_triggers
Revises: 0051_retest_active_request_uniqueness
"""

from __future__ import annotations

from alembic import op


revision = "0052_retest_automation_triggers"
down_revision = "0051_retest_active_request_uniqueness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        "trigger IN ('finding.created','finding.updated','ticket.closed','retest.confirmed','retest.cleared','sla.breached')",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_automation_rules_valid_automation_rule_trigger"),
        "automation_rules",
        "trigger IN ('finding.created','finding.updated','ticket.closed','sla.breached')",
    )
