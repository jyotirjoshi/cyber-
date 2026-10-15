"""Enforce tenant ownership for ASM surfaces.

Revision ID: 0072_asm_surface_tenant_fk
Revises: 0071_usage_meter_tenant_fk
"""

from __future__ import annotations

from alembic import op

revision = "0072_asm_surface_tenant_fk"
down_revision = "0071_usage_meter_tenant_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_foreign_key(
        op.f("fk_asm_surfaces_organization_id_organizations"),
        "asm_surfaces",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_asm_surfaces_organization_id_organizations"),
        "asm_surfaces",
        type_="foreignkey",
    )
