"""Add the evidence-backed assurance runtime.

Revision ID: 0104_assurance_runtime
Revises: 0103_security_control_plane
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0104_assurance_runtime"
down_revision = "0103_security_control_plane"
branch_labels = None
depends_on = None


def _tenant_timestamps() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def _tenant_constraint(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["organization_id"],
        ["organizations.id"],
        ondelete="CASCADE",
        name=op.f(f"fk_{table}_organization_id_organizations"),
    )


def _base(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def upgrade() -> None:
    op.create_table(
        "enforcement_transactions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recommendation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True)),
        sa.Column("provider", sa.String(80), nullable=False),
        sa.Column("operation", sa.String(120), nullable=False),
        sa.Column("transaction_key", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("provider_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("snapshot_digest", sa.String(64), nullable=False),
        sa.Column("desired_state", postgresql.JSONB(), nullable=False),
        sa.Column("diff", postgresql.JSONB(), nullable=False),
        sa.Column("diff_digest", sa.String(64), nullable=False),
        sa.Column("blast_radius", postgresql.JSONB(), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True)),
        sa.Column("approved_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("mutation_receipt", postgresql.JSONB(), nullable=False),
        sa.Column("confirmation", postgresql.JSONB(), nullable=False),
        sa.Column("verification", postgresql.JSONB(), nullable=False),
        sa.Column("rollback_plan", postgresql.JSONB(), nullable=False),
        sa.Column("observation_seconds", sa.Integer(), nullable=False),
        sa.Column("observation_ends_at", sa.DateTime(timezone=True)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "status IN ('draft','simulated','pending_approval','approved','applying','observing','verifying','succeeded','rollback_pending','rolling_back','rolled_back','failed','cancelled')",
            name=op.f("ck_enforcement_transactions_valid_enforcement_transaction_status"),
        ),
        sa.CheckConstraint(
            "observation_seconds BETWEEN 0 AND 604800",
            name=op.f("ck_enforcement_transactions_valid_enforcement_observation_seconds"),
        ),
        sa.ForeignKeyConstraint(
            ["recommendation_id"], ["security_recommendations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["approved_by_id"], ["users.id"], ondelete="SET NULL"),
        _tenant_constraint("enforcement_transactions"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enforcement_transactions")),
        sa.UniqueConstraint(
            "organization_id", "transaction_key", name="unique_enforcement_transaction_key"
        ),
        sa.UniqueConstraint(
            "organization_id", "idempotency_key", name="unique_enforcement_idempotency_key"
        ),
    )
    _base("enforcement_transactions")
    op.create_index(
        "ix_enforcement_transactions_org_status",
        "enforcement_transactions",
        ["organization_id", "status"],
    )
    op.create_index(
        "ix_enforcement_transactions_org_recommendation",
        "enforcement_transactions",
        ["organization_id", "recommendation_id"],
    )

    op.create_table(
        "ai_interaction_receipts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_key", sa.String(128), nullable=False),
        sa.Column("application_key", sa.String(512)),
        sa.Column("agent_key", sa.String(512)),
        sa.Column("model_key", sa.String(512), nullable=False),
        sa.Column("provider", sa.String(80), nullable=False),
        sa.Column("region", sa.String(80)),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("prompt_digest", sa.String(64), nullable=False),
        sa.Column("output_digest", sa.String(64)),
        sa.Column("tool_keys", postgresql.JSONB(), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(14, 6), nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("retention_mode", sa.String(20), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "decision IN ('allow','block','redact','require_approval')",
            name=op.f("ck_ai_interaction_receipts_valid_ai_interaction_decision"),
        ),
        sa.CheckConstraint(
            "input_tokens >= 0 AND output_tokens >= 0",
            name=op.f("ck_ai_interaction_receipts_valid_ai_interaction_tokens"),
        ),
        sa.CheckConstraint(
            "cost_usd >= 0", name=op.f("ck_ai_interaction_receipts_valid_ai_interaction_cost")
        ),
        sa.CheckConstraint(
            "retention_mode IN ('none','digest_only','metadata')",
            name=op.f("ck_ai_interaction_receipts_valid_ai_interaction_retention"),
        ),
        _tenant_constraint("ai_interaction_receipts"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_interaction_receipts")),
        sa.UniqueConstraint("organization_id", "request_key", name="unique_ai_interaction_request"),
    )
    _base("ai_interaction_receipts")
    op.create_index(
        "ix_ai_interactions_org_time", "ai_interaction_receipts", ["organization_id", "occurred_at"]
    )
    op.create_index(
        "ix_ai_interactions_org_agent", "ai_interaction_receipts", ["organization_id", "agent_key"]
    )

    op.create_table(
        "ai_tool_manifests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_key", sa.String(512), nullable=False),
        sa.Column("tool_name", sa.String(240), nullable=False),
        sa.Column("version", sa.String(80), nullable=False),
        sa.Column("schema_digest", sa.String(64), nullable=False),
        sa.Column("argument_schema", postgresql.JSONB(), nullable=False),
        sa.Column("result_schema", postgresql.JSONB(), nullable=False),
        sa.Column("permissions", postgresql.JSONB(), nullable=False),
        sa.Column("owner_team", sa.String(120)),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "status IN ('pending_review','approved','changed','revoked','disabled')",
            name=op.f("ck_ai_tool_manifests_valid_ai_tool_manifest_status"),
        ),
        _tenant_constraint("ai_tool_manifests"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_tool_manifests")),
        sa.UniqueConstraint(
            "organization_id",
            "server_key",
            "tool_name",
            "version",
            name="unique_ai_tool_manifest_version",
        ),
    )
    _base("ai_tool_manifests")
    op.create_index(
        "ix_ai_tool_manifests_org_status", "ai_tool_manifests", ["organization_id", "status"]
    )
    op.create_index(
        "ix_ai_tool_manifests_org_server", "ai_tool_manifests", ["organization_id", "server_key"]
    )

    op.create_table(
        "ai_access_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("relation", sa.String(40), nullable=False),
        sa.Column("privileges", postgresql.JSONB(), nullable=False),
        sa.Column("approved", sa.Boolean(), nullable=False),
        sa.Column("source_kind", sa.String(80), nullable=False),
        sa.Column("provenance", postgresql.JSONB(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "relation IN ('uses','calls','assumes_identity','reads','writes','administers','contains_sensitive_data')",
            name=op.f("ck_ai_access_edges_valid_ai_access_edge_relation"),
        ),
        sa.CheckConstraint(
            "source_resource_id <> target_resource_id",
            name=op.f("ck_ai_access_edges_valid_ai_access_edge_distinct_nodes"),
        ),
        sa.ForeignKeyConstraint(
            ["source_resource_id"], ["security_resources.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["target_resource_id"], ["security_resources.id"], ondelete="CASCADE"
        ),
        _tenant_constraint("ai_access_edges"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_access_edges")),
        sa.UniqueConstraint(
            "organization_id",
            "source_resource_id",
            "target_resource_id",
            "relation",
            name="unique_ai_access_edge",
        ),
    )
    _base("ai_access_edges")
    op.create_index(
        "ix_ai_access_edges_org_source",
        "ai_access_edges",
        ["organization_id", "source_resource_id"],
    )
    op.create_index(
        "ix_ai_access_edges_org_target",
        "ai_access_edges",
        ["organization_id", "target_resource_id"],
    )

    op.create_table(
        "agent_run_assurance",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("plan_digest", sa.String(64), nullable=False),
        sa.Column("input_evidence_refs", postgresql.JSONB(), nullable=False),
        sa.Column("tool_receipts", postgresql.JSONB(), nullable=False),
        sa.Column("budgets", postgresql.JSONB(), nullable=False),
        sa.Column("approval_refs", postgresql.JSONB(), nullable=False),
        sa.Column("artifact_refs", postgresql.JSONB(), nullable=False),
        sa.Column("contradictory_evidence", postgresql.JSONB(), nullable=False),
        sa.Column("confidence", sa.Numeric(4, 3), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(), nullable=False),
        sa.Column("success_criteria", postgresql.JSONB(), nullable=False),
        sa.Column("verifier_status", sa.String(24), nullable=False),
        sa.Column("verifier_result", postgresql.JSONB(), nullable=False),
        sa.Column("replay_digest", sa.String(64)),
        sa.Column("metrics", postgresql.JSONB(), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "plan_version > 0",
            name=op.f("ck_agent_run_assurance_valid_agent_assurance_plan_version"),
        ),
        sa.CheckConstraint(
            "confidence BETWEEN 0 AND 1",
            name=op.f("ck_agent_run_assurance_valid_agent_assurance_confidence"),
        ),
        sa.CheckConstraint(
            "verifier_status IN ('pending','passed','failed','inconclusive')",
            name=op.f("ck_agent_run_assurance_valid_agent_assurance_verifier_status"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="CASCADE"),
        _tenant_constraint("agent_run_assurance"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_run_assurance")),
        sa.UniqueConstraint("organization_id", "run_id", name="unique_agent_run_assurance"),
    )
    _base("agent_run_assurance")
    op.create_index(
        "ix_agent_run_assurance_org_verifier",
        "agent_run_assurance",
        ["organization_id", "verifier_status"],
    )

    op.create_table(
        "validation_recipes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recipe_key", sa.String(128), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True)),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True)),
        sa.Column("run_id", postgresql.UUID(as_uuid=True)),
        sa.Column("original_recipe_id", postgresql.UUID(as_uuid=True)),
        sa.Column("target_digest", sa.String(64), nullable=False),
        sa.Column("authorized_target_refs", postgresql.JSONB(), nullable=False),
        sa.Column("actions", postgresql.JSONB(), nullable=False),
        sa.Column("credential_refs", postgresql.JSONB(), nullable=False),
        sa.Column("artifact_refs", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_hashes", postgresql.JSONB(), nullable=False),
        sa.Column("budgets", postgresql.JSONB(), nullable=False),
        sa.Column("approval_refs", postgresql.JSONB(), nullable=False),
        sa.Column("exploitation_verdict", sa.String(30), nullable=False),
        sa.Column("reproducibility_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("verification", postgresql.JSONB(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "exploitation_verdict IN ('observed','likely_exploitable','proved_exploitable','not_exploitable')",
            name=op.f("ck_validation_recipes_valid_validation_recipe_verdict"),
        ),
        sa.CheckConstraint(
            "reproducibility_score BETWEEN 0 AND 100",
            name=op.f("ck_validation_recipes_valid_validation_reproducibility"),
        ),
        sa.CheckConstraint(
            "status IN ('recorded','approved','executing','verified','failed','superseded')",
            name=op.f("ck_validation_recipes_valid_validation_recipe_status"),
        ),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["campaign_id"], ["attack_simulation_campaigns.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["run_id"], ["attack_simulation_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["original_recipe_id"], ["validation_recipes.id"], ondelete="SET NULL"
        ),
        _tenant_constraint("validation_recipes"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_validation_recipes")),
        sa.UniqueConstraint("organization_id", "recipe_key", name="unique_validation_recipe_key"),
    )
    _base("validation_recipes")
    op.create_index(
        "ix_validation_recipes_org_status", "validation_recipes", ["organization_id", "status"]
    )

    op.create_table(
        "data_security_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_key", sa.String(128), nullable=False),
        sa.Column("provider", sa.String(80), nullable=False),
        sa.Column("service", sa.String(80), nullable=False),
        sa.Column("scan_mode", sa.String(24), nullable=False),
        sa.Column("sample_policy", postgresql.JSONB(), nullable=False),
        sa.Column("classifications", postgresql.JSONB(), nullable=False),
        sa.Column("lineage", postgresql.JSONB(), nullable=False),
        sa.Column("duplicate_group", sa.String(128)),
        sa.Column("sharing", postgresql.JSONB(), nullable=False),
        sa.Column("identity_access", postgresql.JSONB(), nullable=False),
        sa.Column("encryption", postgresql.JSONB(), nullable=False),
        sa.Column("key_posture", postgresql.JSONB(), nullable=False),
        sa.Column("retention", postgresql.JSONB(), nullable=False),
        sa.Column("residency", postgresql.JSONB(), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("recommendations", postgresql.JSONB(), nullable=False),
        sa.Column("posture_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "scan_mode IN ('metadata_only','controlled_sample','full_authorized')",
            name=op.f("ck_data_security_assessments_valid_data_security_scan_mode"),
        ),
        sa.CheckConstraint(
            "posture_score BETWEEN 0 AND 100",
            name=op.f("ck_data_security_assessments_valid_data_security_posture_score"),
        ),
        sa.ForeignKeyConstraint(["resource_id"], ["security_resources.id"], ondelete="CASCADE"),
        _tenant_constraint("data_security_assessments"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_data_security_assessments")),
        sa.UniqueConstraint(
            "organization_id", "assessment_key", name="unique_data_security_assessment_key"
        ),
    )
    _base("data_security_assessments")
    op.create_index(
        "ix_data_security_assessments_org_resource",
        "data_security_assessments",
        ["organization_id", "resource_id"],
    )
    op.create_index(
        "ix_data_security_assessments_org_observed",
        "data_security_assessments",
        ["organization_id", "observed_at"],
    )

    op.create_table(
        "threat_response_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("story_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type", sa.String(40), nullable=False),
        sa.Column("target_ref", sa.String(512), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("predicted_impact", postgresql.JSONB(), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True)),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("provider_receipt", postgresql.JSONB(), nullable=False),
        sa.Column("verification", postgresql.JSONB(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "action_type IN ('isolate_endpoint','revoke_credential','restrict_access','disable_identity','create_ticket','notify')",
            name=op.f("ck_threat_response_actions_valid_threat_response_action_type"),
        ),
        sa.CheckConstraint(
            "status IN ('proposed','approved','executing','executed','verified','failed','rolled_back')",
            name=op.f("ck_threat_response_actions_valid_threat_response_action_status"),
        ),
        sa.ForeignKeyConstraint(["story_id"], ["security_threat_stories.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], ondelete="SET NULL"),
        _tenant_constraint("threat_response_actions"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_response_actions")),
        sa.UniqueConstraint(
            "organization_id", "idempotency_key", name="unique_threat_response_action_key"
        ),
    )
    _base("threat_response_actions")
    op.create_index(
        "ix_threat_response_actions_org_story",
        "threat_response_actions",
        ["organization_id", "story_id"],
    )

    op.create_table(
        "risk_simulation_trials",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("simulation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("comparison_trial_id", postgresql.UUID(as_uuid=True)),
        sa.Column("run_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("iterations", sa.Integer(), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("assumptions_version", sa.Integer(), nullable=False),
        sa.Column("distributions", postgresql.JSONB(), nullable=False),
        sa.Column("percentile_05", sa.Numeric(16, 2), nullable=False),
        sa.Column("percentile_50", sa.Numeric(16, 2), nullable=False),
        sa.Column("percentile_95", sa.Numeric(16, 2), nullable=False),
        sa.Column("mean_annual_loss", sa.Numeric(16, 2), nullable=False),
        sa.Column("standard_deviation", sa.Numeric(16, 2), nullable=False),
        sa.Column("confidence_level", sa.Numeric(4, 3), nullable=False),
        sa.Column("calibration", postgresql.JSONB(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "status IN ('completed','failed','superseded')",
            name=op.f("ck_risk_simulation_trials_valid_risk_simulation_trial_status"),
        ),
        sa.CheckConstraint(
            "iterations BETWEEN 1000 AND 1000000",
            name=op.f("ck_risk_simulation_trials_valid_risk_simulation_iterations"),
        ),
        sa.CheckConstraint(
            "assumptions_version > 0",
            name=op.f("ck_risk_simulation_trials_valid_risk_simulation_assumptions_version"),
        ),
        sa.CheckConstraint(
            "confidence_level > 0 AND confidence_level < 1",
            name=op.f("ck_risk_simulation_trials_valid_risk_simulation_confidence"),
        ),
        sa.CheckConstraint(
            "percentile_05 <= percentile_50 AND percentile_50 <= percentile_95",
            name=op.f("ck_risk_simulation_trials_valid_risk_simulation_percentiles"),
        ),
        sa.ForeignKeyConstraint(
            ["simulation_id"], ["security_risk_simulations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["comparison_trial_id"], ["risk_simulation_trials.id"], ondelete="SET NULL"
        ),
        _tenant_constraint("risk_simulation_trials"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_simulation_trials")),
        sa.UniqueConstraint("organization_id", "run_key", name="unique_risk_simulation_trial_key"),
    )
    _base("risk_simulation_trials")
    op.create_index(
        "ix_risk_simulation_trials_org_simulation",
        "risk_simulation_trials",
        ["organization_id", "simulation_id"],
    )

    op.create_table(
        "compliance_control_inheritances",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("parent_control_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_system", sa.String(240), nullable=False),
        sa.Column("responsibility", sa.String(24), nullable=False),
        sa.Column("inherited_percentage", sa.Numeric(5, 2), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "control_id <> parent_control_id",
            name=op.f(
                "ck_compliance_control_inheritances_valid_compliance_inheritance_distinct_controls"
            ),
        ),
        sa.CheckConstraint(
            "responsibility IN ('inherited','shared','customer')",
            name=op.f(
                "ck_compliance_control_inheritances_valid_compliance_inheritance_responsibility"
            ),
        ),
        sa.CheckConstraint(
            "inherited_percentage BETWEEN 0 AND 100",
            name=op.f("ck_compliance_control_inheritances_valid_compliance_inherited_percentage"),
        ),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["parent_control_id"], ["compliance_controls.id"], ondelete="CASCADE"
        ),
        _tenant_constraint("compliance_control_inheritances"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_control_inheritances")),
        sa.UniqueConstraint(
            "organization_id",
            "control_id",
            "parent_control_id",
            name="unique_compliance_control_inheritance",
        ),
    )
    _base("compliance_control_inheritances")
    op.create_index(
        "ix_compliance_inheritance_org_control",
        "compliance_control_inheritances",
        ["organization_id", "control_id"],
    )

    op.create_table(
        "compliance_evidence_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_key", sa.String(128), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("assignee_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("freshness_days", sa.Integer(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.Column("fulfilled_evidence_ids", postgresql.JSONB(), nullable=False),
        sa.Column("fulfilled_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "status IN ('open','collecting','submitted','accepted','rejected','cancelled')",
            name=op.f("ck_compliance_evidence_requests_valid_compliance_evidence_request_status"),
        ),
        sa.CheckConstraint(
            "freshness_days BETWEEN 1 AND 3650",
            name=op.f("ck_compliance_evidence_requests_valid_compliance_evidence_freshness"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["compliance_audit_workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assignee_user_id"], ["users.id"], ondelete="SET NULL"),
        _tenant_constraint("compliance_evidence_requests"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_evidence_requests")),
        sa.UniqueConstraint(
            "organization_id", "request_key", name="unique_compliance_evidence_request_key"
        ),
    )
    _base("compliance_evidence_requests")
    op.create_index(
        "ix_compliance_evidence_requests_org_workspace",
        "compliance_evidence_requests",
        ["organization_id", "workspace_id"],
    )
    op.create_index(
        "ix_compliance_evidence_requests_org_status",
        "compliance_evidence_requests",
        ["organization_id", "status"],
    )

    op.create_table(
        "compliance_export_packages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("package_key", sa.String(128), nullable=False),
        sa.Column("oscal_model", sa.String(40), nullable=False),
        sa.Column("oscal_version", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("artifact_reference", sa.String(2048)),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signing_key_id", sa.String(80), nullable=False),
        sa.Column("manifest", postgresql.JSONB(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "oscal_model IN ('assessment-results','poam','component-definition','ssp')",
            name=op.f("ck_compliance_export_packages_valid_compliance_export_oscal_model"),
        ),
        sa.CheckConstraint(
            "status IN ('generated','published','revoked')",
            name=op.f("ck_compliance_export_packages_valid_compliance_export_status"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["compliance_audit_workspaces.id"], ondelete="CASCADE"
        ),
        _tenant_constraint("compliance_export_packages"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compliance_export_packages")),
        sa.UniqueConstraint(
            "organization_id", "package_key", name="unique_compliance_export_package_key"
        ),
    )
    _base("compliance_export_packages")
    op.create_index(
        "ix_compliance_export_packages_org_workspace",
        "compliance_export_packages",
        ["organization_id", "workspace_id"],
    )


def downgrade() -> None:
    indexes = {
        "compliance_export_packages": ["ix_compliance_export_packages_org_workspace"],
        "compliance_evidence_requests": [
            "ix_compliance_evidence_requests_org_workspace",
            "ix_compliance_evidence_requests_org_status",
        ],
        "compliance_control_inheritances": ["ix_compliance_inheritance_org_control"],
        "risk_simulation_trials": ["ix_risk_simulation_trials_org_simulation"],
        "threat_response_actions": ["ix_threat_response_actions_org_story"],
        "data_security_assessments": [
            "ix_data_security_assessments_org_resource",
            "ix_data_security_assessments_org_observed",
        ],
        "validation_recipes": ["ix_validation_recipes_org_status"],
        "agent_run_assurance": ["ix_agent_run_assurance_org_verifier"],
        "ai_access_edges": ["ix_ai_access_edges_org_source", "ix_ai_access_edges_org_target"],
        "ai_tool_manifests": ["ix_ai_tool_manifests_org_status", "ix_ai_tool_manifests_org_server"],
        "ai_interaction_receipts": ["ix_ai_interactions_org_time", "ix_ai_interactions_org_agent"],
        "enforcement_transactions": [
            "ix_enforcement_transactions_org_status",
            "ix_enforcement_transactions_org_recommendation",
        ],
    }
    for table, custom_indexes in indexes.items():
        for index in custom_indexes:
            op.drop_index(index, table_name=table)
        op.drop_index(op.f(f"ix_{table}_created_at"), table_name=table)
        op.drop_index(op.f(f"ix_{table}_organization_id"), table_name=table)
        op.drop_table(table)
