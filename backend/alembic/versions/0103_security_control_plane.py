"""Add the unified security control plane.

Revision ID: 0103_security_control_plane
Revises: 0102_compliance_evidence_workspaces
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0103_security_control_plane"
down_revision = "0102_compliance_evidence_workspaces"
branch_labels = None
depends_on = None

_INTEGRATION_KINDS_OLD = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','burp_dast','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','prisma_cloud','crowdstrike','aws_security_hub','aws_inspector','hackerone','bugcrowd','checkmarx','fortify','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp')"
_INTEGRATION_KINDS_NEW = "kind IN ('llm','defectdojo','jira','servicenow','azure_devops','linear','pagerduty','splunk','burp_dast','slack','email','dify','misp','nvd','github','gitlab','wazuh','sonarqube','snyk','tenable','qualys','rapid7','wiz','prisma_cloud','crowdstrike','aws_security_hub','aws_inspector','hackerone','bugcrowd','checkmarx','fortify','azure_defender','gcp_scc','bitbucket','prowler_aws','prowler_azure','prowler_gcp','zscaler')"


def _tenant_timestamps() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def _tenant_constraints(table: str) -> tuple[sa.ForeignKeyConstraint, ...]:
    return (
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE",
            name=op.f(f"fk_{table}_organization_id_organizations"),
        ),
    )


def _base_indexes(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def upgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", _INTEGRATION_KINDS_NEW
    )
    op.create_table(
        "security_resources",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_key", sa.String(512), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("provider", sa.String(80)),
        sa.Column("external_id", sa.String(512)),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("owner_team", sa.String(120)),
        sa.Column("environment", sa.String(24), nullable=False),
        sa.Column("internet_exposed", sa.Boolean(), nullable=False),
        sa.Column("approved", sa.Boolean()),
        sa.Column("posture_status", sa.String(24), nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("sensitivity", sa.String(24), nullable=False),
        sa.Column("classifications", postgresql.JSONB(), nullable=False),
        sa.Column("permissions", postgresql.JSONB(), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False),
        sa.Column("provenance", postgresql.JSONB(), nullable=False),
        sa.Column("source_count", sa.Integer(), nullable=False),
        sa.Column("identity_confidence", sa.Numeric(4, 3), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "kind IN ('asset','data_store','dataset','saas_application','ai_application','ai_model','ai_agent','mcp_server','ai_tool','identity','endpoint','browser')",
            name="ck_security_resources_valid_security_resource_kind",
        ),
        sa.CheckConstraint(
            "environment IN ('production','staging','development','test','unknown')",
            name="ck_security_resources_valid_security_resource_environment",
        ),
        sa.CheckConstraint(
            "posture_status IN ('unknown','healthy','at_risk','non_compliant','inactive')",
            name="ck_security_resources_valid_security_resource_posture",
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_security_resources_valid_security_resource_risk"),
        sa.CheckConstraint(
            "sensitivity IN ('unknown','public','internal','confidential','restricted')",
            name="ck_security_resources_valid_security_resource_sensitivity",
        ),
        sa.CheckConstraint("source_count >= 0", name="ck_security_resources_valid_security_resource_source_count"),
        sa.CheckConstraint(
            "identity_confidence BETWEEN 0 AND 1",
            name="ck_security_resources_valid_security_resource_identity_confidence",
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_resources"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_resources")),
        sa.UniqueConstraint("organization_id", "resource_key", name="unique_security_resource_key"),
    )
    _base_indexes("security_resources")
    op.create_index("ix_security_resources_org_kind", "security_resources", ["organization_id", "kind"])
    op.create_index("ix_security_resources_org_posture", "security_resources", ["organization_id", "posture_status"])
    op.create_index("ix_security_resources_org_asset", "security_resources", ["organization_id", "asset_id"])

    op.create_table(
        "security_resource_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True)),
        sa.Column("source_kind", sa.String(80), nullable=False),
        sa.Column("source_key", sa.String(512), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False),
        sa.Column("provenance", postgresql.JSONB(), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_security_resource_observations_valid_security_observation_confidence"),
        sa.ForeignKeyConstraint(["resource_id"], ["security_resources.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_resource_observations"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_resource_observations")),
        sa.UniqueConstraint(
            "organization_id", "source_kind", "source_key", "fingerprint",
            name="unique_security_resource_observation",
        ),
    )
    _base_indexes("security_resource_observations")
    op.create_index("ix_security_observations_org_resource", "security_resource_observations", ["organization_id", "resource_id"])
    op.create_index("ix_security_observations_org_expiry", "security_resource_observations", ["organization_id", "expires_at"])

    op.create_table(
        "security_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("rules", postgresql.JSONB(), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "kind IN ('ztna','secure_web_gateway','firewall','tls_inspection','dlp','casb','sspm','ai_gateway','ai_guard','endpoint_isolation','browser_isolation')",
            name="ck_security_policies_valid_security_policy_kind",
        ),
        sa.CheckConstraint("mode IN ('monitor','recommend','enforce')", name="ck_security_policies_valid_security_policy_mode"),
        sa.CheckConstraint("status IN ('draft','active','disabled')", name="ck_security_policies_valid_security_policy_status"),
        sa.CheckConstraint("version > 0", name="ck_security_policies_valid_security_policy_version"),
        sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_policies"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_policies")),
        sa.UniqueConstraint("organization_id", "name", name="unique_security_policy_name"),
    )
    _base_indexes("security_policies")
    op.create_index("ix_security_policies_org_kind", "security_policies", ["organization_id", "kind"])
    op.create_index("ix_security_policies_org_status", "security_policies", ["organization_id", "status"])

    op.create_table(
        "security_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_key", sa.String(512), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("source_kind", sa.String(80), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("content_digest", sa.String(64)),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True)),
        sa.Column("identity_ref", sa.String(512)),
        sa.Column("metrics", postgresql.JSONB(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "category IN ('experience','incident','identity','deception','access','dlp','ai_gateway','endpoint','browser')",
            name="ck_security_events_valid_security_event_category",
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_security_events_valid_security_event_severity",
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["resource_id"], ["security_resources.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_events"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
        sa.UniqueConstraint("organization_id", "event_key", name="unique_security_event_key"),
    )
    _base_indexes("security_events")
    op.create_index("ix_security_events_org_category_time", "security_events", ["organization_id", "category", "occurred_at"])
    op.create_index("ix_security_events_org_asset", "security_events", ["organization_id", "asset_id"])

    op.create_table(
        "security_policy_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True)),
        sa.Column("event_id", postgresql.UUID(as_uuid=True)),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("score", sa.Numeric(5, 2), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("content_digest", sa.String(64)),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "decision IN ('allow','block','redact','require_approval','recommend','not_applicable')",
            name="ck_security_policy_evaluations_valid_security_evaluation_decision",
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_security_policy_evaluations_valid_security_evaluation_severity",
        ),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name="ck_security_policy_evaluations_valid_security_evaluation_score"),
        sa.ForeignKeyConstraint(["policy_id"], ["security_policies.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["resource_id"], ["security_resources.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_policy_evaluations"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_policy_evaluations")),
    )
    _base_indexes("security_policy_evaluations")
    op.create_index("ix_security_evaluations_org_policy", "security_policy_evaluations", ["organization_id", "policy_id"])
    op.create_index("ix_security_evaluations_org_time", "security_policy_evaluations", ["organization_id", "evaluated_at"])

    op.create_table(
        "security_recommendations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True)),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True)),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True)),
        sa.Column("domain", sa.String(40), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("current_state", postgresql.JSONB(), nullable=False),
        sa.Column("desired_state", postgresql.JSONB(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("provider_receipt", postgresql.JSONB(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("applied_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "domain IN ('ztna','secure_web_gateway','firewall','data_security','ai_security','endpoint','browser','soc')",
            name="ck_security_recommendations_valid_security_recommendation_domain",
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_security_recommendations_valid_security_recommendation_severity",
        ),
        sa.CheckConstraint(
            "status IN ('proposed','approved','applying','applied','rejected','failed','superseded')",
            name="ck_security_recommendations_valid_security_recommendation_status",
        ),
        sa.ForeignKeyConstraint(["policy_id"], ["security_policies.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["resource_id"], ["security_resources.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["applied_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_recommendations"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_recommendations")),
        sa.UniqueConstraint("organization_id", "idempotency_key", name="unique_security_recommendation_key"),
    )
    _base_indexes("security_recommendations")
    op.create_index("ix_security_recommendations_org_status", "security_recommendations", ["organization_id", "status"])
    op.create_index("ix_security_recommendations_org_domain", "security_recommendations", ["organization_id", "domain"])

    op.create_table(
        "security_threat_stories",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("correlation_key", sa.String(256), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("event_ids", postgresql.JSONB(), nullable=False),
        sa.Column("asset_ids", postgresql.JSONB(), nullable=False),
        sa.Column("finding_ids", postgresql.JSONB(), nullable=False),
        sa.Column("identity_refs", postgresql.JSONB(), nullable=False),
        sa.Column("timeline", postgresql.JSONB(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("resolution", sa.Text()),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "status IN ('open','investigating','contained','resolved','dismissed')",
            name="ck_security_threat_stories_valid_security_threat_story_status",
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_security_threat_stories_valid_security_threat_story_severity",
        ),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_security_threat_stories_valid_security_threat_story_confidence"),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_threat_stories"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_threat_stories")),
        sa.UniqueConstraint("organization_id", "correlation_key", name="unique_security_threat_story_key"),
    )
    _base_indexes("security_threat_stories")
    op.create_index("ix_security_stories_org_status", "security_threat_stories", ["organization_id", "status"])
    op.create_index("ix_security_stories_org_last_seen", "security_threat_stories", ["organization_id", "last_seen_at"])

    op.create_table(
        "security_canaries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("token_digest", sa.String(64), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("placement", postgresql.JSONB(), nullable=False),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "kind IN ('credential','dns','http','file','cloud_resource','identity')",
            name="ck_security_canaries_valid_security_canary_kind",
        ),
        sa.CheckConstraint(
            "status IN ('active','disabled','triggered','retired')",
            name="ck_security_canaries_valid_security_canary_status",
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_canaries"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_canaries")),
        sa.UniqueConstraint("organization_id", "name", name="unique_security_canary_name"),
        sa.UniqueConstraint("organization_id", "token_digest", name="unique_security_canary_digest"),
    )
    _base_indexes("security_canaries")
    op.create_index("ix_security_canaries_org_status", "security_canaries", ["organization_id", "status"])

    op.create_table(
        "security_canary_interactions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canary_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True)),
        sa.Column("interaction_key", sa.String(256), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip_digest", sa.String(64)),
        sa.Column("identity_ref", sa.String(512)),
        sa.Column("protocol", sa.String(40)),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_security_canary_interactions_valid_security_canary_interaction_severity",
        ),
        sa.ForeignKeyConstraint(["canary_id"], ["security_canaries.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_canary_interactions"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_canary_interactions")),
        sa.UniqueConstraint("organization_id", "interaction_key", name="unique_security_canary_interaction_key"),
    )
    _base_indexes("security_canary_interactions")
    op.create_index("ix_security_canary_interactions_org_canary", "security_canary_interactions", ["organization_id", "canary_id"])
    op.create_index("ix_security_canary_interactions_org_time", "security_canary_interactions", ["organization_id", "occurred_at"])

    op.create_table(
        "security_risk_simulations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("business_service_id", postgresql.UUID(as_uuid=True)),
        sa.Column("scenario_id", postgresql.UUID(as_uuid=True)),
        sa.Column("name", sa.String(240), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("annual_probability", sa.Numeric(6, 5), nullable=False),
        sa.Column("loss_min", sa.Numeric(16, 2), nullable=False),
        sa.Column("loss_likely", sa.Numeric(16, 2), nullable=False),
        sa.Column("loss_max", sa.Numeric(16, 2), nullable=False),
        sa.Column("control_effectiveness", sa.Numeric(6, 5), nullable=False),
        sa.Column("acceptance_status", sa.String(20), nullable=False),
        sa.Column("assumptions", postgresql.JSONB(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("narrative", sa.Text()),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint("annual_probability BETWEEN 0 AND 1", name="ck_security_risk_simulations_valid_security_risk_probability"),
        sa.CheckConstraint("control_effectiveness BETWEEN 0 AND 1", name="ck_security_risk_simulations_valid_security_risk_control_effectiveness"),
        sa.CheckConstraint(
            "loss_min >= 0 AND loss_likely >= loss_min AND loss_max >= loss_likely",
            name="ck_security_risk_simulations_valid_security_risk_loss_range",
        ),
        sa.CheckConstraint("status IN ('draft','completed','archived')", name="ck_security_risk_simulations_valid_security_risk_status"),
        sa.CheckConstraint(
            "acceptance_status IN ('unreviewed','accepted','mitigating','rejected','expired')",
            name="ck_security_risk_simulations_valid_security_risk_acceptance_status",
        ),
        sa.ForeignKeyConstraint(["business_service_id"], ["business_services.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scenario_id"], ["business_risk_scenarios.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        *_tenant_constraints("security_risk_simulations"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_risk_simulations")),
    )
    _base_indexes("security_risk_simulations")
    op.create_index("ix_security_risk_org_service", "security_risk_simulations", ["organization_id", "business_service_id"])
    op.create_index("ix_security_risk_org_status", "security_risk_simulations", ["organization_id", "status"])


_INDEXES = {
    "security_resources": ["ix_security_resources_organization_id", "ix_security_resources_created_at", "ix_security_resources_org_kind", "ix_security_resources_org_posture", "ix_security_resources_org_asset"],
    "security_resource_observations": ["ix_security_resource_observations_organization_id", "ix_security_resource_observations_created_at", "ix_security_observations_org_resource", "ix_security_observations_org_expiry"],
    "security_policies": ["ix_security_policies_organization_id", "ix_security_policies_created_at", "ix_security_policies_org_kind", "ix_security_policies_org_status"],
    "security_events": ["ix_security_events_organization_id", "ix_security_events_created_at", "ix_security_events_org_category_time", "ix_security_events_org_asset"],
    "security_policy_evaluations": ["ix_security_policy_evaluations_organization_id", "ix_security_policy_evaluations_created_at", "ix_security_evaluations_org_policy", "ix_security_evaluations_org_time"],
    "security_recommendations": ["ix_security_recommendations_organization_id", "ix_security_recommendations_created_at", "ix_security_recommendations_org_status", "ix_security_recommendations_org_domain"],
    "security_threat_stories": ["ix_security_threat_stories_organization_id", "ix_security_threat_stories_created_at", "ix_security_stories_org_status", "ix_security_stories_org_last_seen"],
    "security_canaries": ["ix_security_canaries_organization_id", "ix_security_canaries_created_at", "ix_security_canaries_org_status"],
    "security_canary_interactions": ["ix_security_canary_interactions_organization_id", "ix_security_canary_interactions_created_at", "ix_security_canary_interactions_org_canary", "ix_security_canary_interactions_org_time"],
    "security_risk_simulations": ["ix_security_risk_simulations_organization_id", "ix_security_risk_simulations_created_at", "ix_security_risk_org_service", "ix_security_risk_org_status"],
}


def downgrade() -> None:
    op.drop_constraint(op.f("ck_integrations_valid_integration_kind"), "integrations", type_="check")
    op.create_check_constraint(
        op.f("ck_integrations_valid_integration_kind"), "integrations", _INTEGRATION_KINDS_OLD
    )
    table_order = [
        "security_risk_simulations",
        "security_canary_interactions",
        "security_canaries",
        "security_threat_stories",
        "security_recommendations",
        "security_policy_evaluations",
        "security_events",
        "security_policies",
        "security_resource_observations",
        "security_resources",
    ]
    for table in table_order:
        for index_name in _INDEXES[table]:
            op.drop_index(index_name, table_name=table)
        op.drop_table(table)
