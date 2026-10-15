"""Add normalized threat-feed provenance, actors, ransomware tags and watchlists."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0086_threat_feed_provenance"
down_revision = "0085_bas_runs_and_evidence"
branch_labels = None
depends_on = None


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "threat_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_key", sa.String(512), nullable=False),
        sa.Column("source", sa.String(80), nullable=False),
        sa.Column("source_reference", sa.String(1024), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("facts", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("freshness", sa.String(20), server_default="fresh", nullable=False),
        sa.Column("license_reference", sa.String(1024)),
        *_timestamps(),
        sa.CheckConstraint("entity_type IN ('cve','product','actor','domain','brand')", name=op.f("ck_threat_observations_valid_threat_entity_type")),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name=op.f("ck_threat_observations_valid_threat_observation_confidence")),
        sa.CheckConstraint("freshness IN ('fresh','stale')", name=op.f("ck_threat_observations_valid_threat_observation_freshness")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_observations")),
        sa.UniqueConstraint("source", "source_reference", name="unique_threat_observation_source_reference"),
    )
    op.create_index("ix_threat_observations_entity_time", "threat_observations", ["entity_type", "entity_key", "observed_at"])
    op.create_index(op.f("ix_threat_observations_created_at"), "threat_observations", ["created_at"])

    op.create_table(
        "threat_actors",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(160), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("aliases", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("references", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_actors")),
        sa.UniqueConstraint("slug", name=op.f("uq_threat_actors_slug")),
    )
    op.create_index(op.f("ix_threat_actors_created_at"), "threat_actors", ["created_at"])

    op.create_table(
        "ransomware_associations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("threat_actor_id", postgresql.UUID(as_uuid=True)),
        sa.Column("family", sa.String(255)),
        sa.Column("source_observation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["source_observation_id"], ["threat_observations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["threat_actor_id"], ["threat_actors.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ransomware_associations")),
        sa.UniqueConstraint("cve_id", "source_observation_id", name="unique_ransomware_observation"),
    )
    op.create_index("ix_ransomware_associations_cve", "ransomware_associations", ["cve_id", "active"])
    op.create_index(op.f("ix_ransomware_associations_created_at"), "ransomware_associations", ["created_at"])

    op.create_table(
        "threat_watchlists",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_key", sa.String(512), nullable=False),
        sa.Column("label", sa.String(255)),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("last_matched_at", sa.DateTime(timezone=True)),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        *_timestamps(),
        sa.CheckConstraint("entity_type IN ('cve','product','actor','domain','brand')", name=op.f("ck_threat_watchlists_valid_watchlist_entity_type")),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_watchlists")),
        sa.UniqueConstraint("organization_id", "entity_type", "entity_key", name="unique_tenant_threat_watch"),
    )
    op.create_index("ix_threat_watchlists_org_active", "threat_watchlists", ["organization_id", "is_active"])
    op.create_index(op.f("ix_threat_watchlists_organization_id"), "threat_watchlists", ["organization_id"])
    op.create_index(op.f("ix_threat_watchlists_created_at"), "threat_watchlists", ["created_at"])

    op.create_table(
        "threat_watchlist_matches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("watchlist_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("observation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_finding_id", postgresql.UUID(as_uuid=True)),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("match_key", sa.String(1024), nullable=False),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["canonical_finding_id"], ["canonical_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["observation_id"], ["threat_observations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["watchlist_id"], ["threat_watchlists.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_watchlist_matches")),
        sa.UniqueConstraint("watchlist_id", "observation_id", "match_key", name="unique_threat_watchlist_match"),
    )
    op.create_index("ix_threat_watchlist_matches_org_time", "threat_watchlist_matches", ["organization_id", "matched_at"])
    op.create_index(op.f("ix_threat_watchlist_matches_organization_id"), "threat_watchlist_matches", ["organization_id"])
    op.create_index(op.f("ix_threat_watchlist_matches_created_at"), "threat_watchlist_matches", ["created_at"])


def downgrade() -> None:
    for name in (op.f("ix_threat_watchlist_matches_created_at"), op.f("ix_threat_watchlist_matches_organization_id"), "ix_threat_watchlist_matches_org_time"):
        op.drop_index(name, table_name="threat_watchlist_matches")
    op.drop_table("threat_watchlist_matches")
    for name in (op.f("ix_threat_watchlists_created_at"), op.f("ix_threat_watchlists_organization_id"), "ix_threat_watchlists_org_active"):
        op.drop_index(name, table_name="threat_watchlists")
    op.drop_table("threat_watchlists")
    for name in (op.f("ix_ransomware_associations_created_at"), "ix_ransomware_associations_cve"):
        op.drop_index(name, table_name="ransomware_associations")
    op.drop_table("ransomware_associations")
    op.drop_index(op.f("ix_threat_actors_created_at"), table_name="threat_actors")
    op.drop_table("threat_actors")
    op.drop_index(op.f("ix_threat_observations_created_at"), table_name="threat_observations")
    op.drop_index("ix_threat_observations_entity_time", table_name="threat_observations")
    op.drop_table("threat_observations")
