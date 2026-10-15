# Deployed Workspace Baseline — 2026-10-16

This manifest identifies the source snapshot deployed before the market-parity expansion. It contains no credential values.

## Git baseline

- Planning baseline commit: `39aa6ed334d1ea3ad9fb714123b31535cb61cb00`
- Branch: `codex/ctem-parity`
- Deployed source commit: `6af099ea41b856bfeecb7d1c43bbe4a76c72c72c`
- Deployed snapshot tag: `6af099ea41b856bfeecb7d1c43bbe4a76c72c72c-dirty-0fabc7804934`
- Snapshot captured from the existing dirty checkout without resetting or replacing any file.
- `backend/tests/unit/test_runtime_configuration.py`, this manifest, and the root ignore entry are Task 1 verification additions made after the deployed snapshot.

## Alembic heads

1. `0092_graphql_mutation_receipts`

## Images

- Backend: `asia-south1-docker.pkg.dev/cynux-security-prod/cynux/api:6af099ea41b856bfeecb7d1c43bbe4a76c72c72c-dirty-0fabc7804934`
- Frontend: `asia-south1-docker.pkg.dev/cynux-security-prod/cynux/frontend:6af099ea41b856bfeecb7d1c43bbe4a76c72c72c-dirty-0fabc7804934`
- Firebase edge: `https://cynux-security-prod.web.app`
- API service: `https://cynux-api-q4p5v4ufgq-el.a.run.app`
- Web service: `https://cynux-web-q4p5v4ufgq-el.a.run.app`

## Verification

- `cd backend && pytest -q tests/unit/test_migration_matches_models.py tests/unit/test_runtime_configuration.py`
  - RED before this manifest: 539 passed, one expected missing-manifest failure.
- `npm --prefix frontend test -- --run firebase-routing.test.ts`
  - Baseline: 3 passed.
- `npm --prefix frontend test -- --run`
  - Full frontend baseline: 24 files and 55 tests passed.
- `cd backend && pytest -q --tb=no`
  - Full backend baseline: 2,242 passed, 1 skipped, and the 76 failures listed below.
- Final verification must make the backend manifest suite green and keep the frontend routing suite green.

## Known baseline failures

The focused migration/runtime suite is green. The complete backend suite has these inherited
failures in the deployed dirty snapshot; they predate the manifest and are not waived for later
slice tasks:

```text
tests/unit/test_agent_actions.py::test_approved_canonical_jira_action_calls_canonical_ticket_service
tests/unit/test_agent_actions.py::test_execute_approved_sync_records_result
tests/unit/test_agent_actions.py::test_execute_jira_uses_the_approved_finding_and_options
tests/unit/test_agent_chat.py::test_reply_uses_read_tool_result_in_final_model_prompt
tests/unit/test_agent_chat.py::test_completed_work_is_reported_when_model_is_unavailable
tests/unit/test_agent_chat.py::test_work_status_reply_does_not_adopt_a_false_model_completion
tests/unit/test_agent_chat_actions.py::test_jira_request_requires_one_explicit_finding_id
tests/unit/test_agent_chat_actions.py::test_jira_request_can_select_one_highest_risk_finding
tests/unit/test_agent_chat_actions.py::test_jira_request_can_select_at_most_five_ranked_findings
tests/unit/test_agent_chat_actions.py::test_combined_triage_and_ticket_request_plans_both_bounded_actions
tests/unit/test_agent_chat_actions.py::test_highest_risk_jira_request_resolves_tenant_finding_before_approval
tests/unit/test_agent_chat_actions.py::test_application_scoped_jira_ticket_resolves_only_tenant_application
tests/unit/test_agent_chat_actions.py::test_highest_risk_jira_request_without_open_finding_does_not_queue
tests/unit/test_agent_chat_actions.py::test_top_three_jira_requests_bind_distinct_tenant_findings
tests/unit/test_agent_chat_actions.py::test_my_highest_risk_jira_request_filters_to_assignee
tests/unit/test_agent_chat_actions.py::test_application_scoped_triage_never_falls_back_to_global_queue
tests/unit/test_agent_chat_actions.py::test_chat_queues_canonical_only_jira_target_for_approval
tests/unit/test_agent_read_tools.py::test_canonical_lookup_is_tenant_scoped_and_grounded_in_remediation_queue
tests/unit/test_application_risk.py::test_application_rollup_uses_tenant_filters_and_active_finding_counts
tests/unit/test_assessment_canonical_link.py::test_cloud_observations_link_distinct_findings_only_to_own_tenant
tests/unit/test_automation_rules.py::test_ticket_close_retest_schedule_creates_authorized_assessment_and_links_request
tests/unit/test_automation_rules.py::test_ticket_refresh_queues_closed_event_for_its_canonical_finding
tests/unit/test_automation_rules.py::test_automation_api_exposes_rule_management_routes
tests/unit/test_canonical_backfill.py::test_existing_external_alert_projects_to_canonical_ledger
tests/unit/test_canonical_ingest.py::test_two_providers_one_repo_cve_create_one_finding_two_observations
tests/unit/test_canonical_ingest.py::test_integration_reuses_scanned_repository_asset_for_same_exposure
tests/unit/test_canonical_ingest.py::test_matching_asset_from_other_tenant_is_never_reused
tests/unit/test_canonical_ingest.py::test_ambiguous_same_named_repositories_do_not_guess_an_asset
tests/unit/test_canonical_ingest.py::test_existing_canonical_exposure_moves_from_legacy_alias_to_scanned_asset
tests/unit/test_canonical_ingest.py::test_enterprise_git_repository_import_reuses_its_scanned_asset
tests/unit/test_canonical_ingest.py::test_source_asset_reassignment_closes_orphaned_canonical_finding
tests/unit/test_canonical_ingest.py::test_source_cve_replacement_supersedes_old_observation
tests/unit/test_canonical_ingest.py::test_github_staging_populates_canonical_ledger_in_same_transaction
tests/unit/test_canonical_ingest.py::test_multi_cve_alert_projects_one_finding_per_cve
tests/unit/test_canonical_ingest.py::test_defectdojo_finding_links_existing_inventory_asset
tests/unit/test_canonical_ingest.py::test_defectdojo_finding_without_inventory_match_uses_endpoint_host
tests/unit/test_canonical_ingest.py::test_analyst_risk_acceptance_requires_reason_and_records_history
tests/unit/test_canonical_intel_refresh.py::test_worker_maintenance_runs_intelligence_refresh
tests/unit/test_canonical_intel_refresh.py::test_worker_maintenance_executes_pending_automation
tests/unit/test_canonical_work.py::test_work_assignment_sets_owner_due_plan_and_records_history
tests/unit/test_cloud_report_context.py::test_cloud_only_assessment_snapshot_has_finding_and_asset
tests/unit/test_custom_fields.py::test_finding_custom_fields_update_is_tenant_scoped_and_versioned
tests/unit/test_defectdojo_streaming.py::test_trivy_import_projects_to_canonical_with_approved_repository_asset
tests/unit/test_exposure_feed.py::test_exposure_route_is_mounted_and_has_bounded_filters
tests/unit/test_external_alert_freshness.py::test_github_sync_marks_missing_only_after_successful_complete_fetch
tests/unit/test_external_alert_freshness.py::test_gitlab_sync_marks_only_selected_project_after_complete_fetch
tests/unit/test_external_alert_inbox.py::test_external_alert_provider_filter_includes_sonarqube
tests/unit/test_external_alerts.py::test_github_staging_keeps_same_number_from_two_repositories
tests/unit/test_external_alerts.py::test_github_sync_stages_a_tenant_scoped_conflict_safe_upsert
tests/unit/test_external_alerts.py::test_gitlab_sync_stages_project_findings_in_the_same_tenant_ledger
tests/unit/test_external_alerts.py::test_wazuh_sync_stages_indexer_hits_in_the_same_tenant_ledger
tests/unit/test_external_alerts.py::test_integration_sync_output_exposes_counts_but_never_provider_evidence
tests/unit/test_github_alert_actions.py::test_github_alert_service_updates_local_state_only_after_provider_confirmation
tests/unit/test_notification_outbox.py::test_worker_maintenance_drains_notification_outbox
tests/unit/test_notification_outbox.py::test_production_notification_never_uses_global_slack_credential_for_unconfigured_tenant
tests/unit/test_policy_gate.py::test_gate_uses_open_canonical_severity_and_recent_imported_scan[counts0-None-block-False]
tests/unit/test_policy_gate.py::test_gate_uses_open_canonical_severity_and_recent_imported_scan[counts1-1-warn-True]
tests/unit/test_policy_gate.py::test_gate_uses_open_canonical_severity_and_recent_imported_scan[counts4-10-unknown-False]
tests/unit/test_policy_gate.py::test_gate_counts_critical_finding_on_legacy_source_alias
tests/unit/test_remediation_governance.py::test_complete_retest_records_verified_outcome_without_closing_finding
tests/unit/test_remediation_governance.py::test_verified_absent_retest_closes_only_its_tenant_finding
tests/unit/test_remediation_governance.py::test_completed_assessment_retest_derives_absence_from_its_own_membership
tests/unit/test_remediation_governance.py::test_worker_maintenance_expires_risk_acceptances
tests/unit/test_scanner_adapters.py::test_every_adapter_builds_argv_that_passes_validation[trivy_repo]
tests/unit/test_scanner_adapters.py::test_every_adapter_writes_only_under_its_work_mount[trivy_repo]
tests/unit/test_sla_escalation.py::test_worker_maintenance_emits_overdue_sla_escalations
tests/unit/test_snyk_integration.py::test_snyk_sync_stages_tenant_scoped_issue
tests/unit/test_sonarqube_integration.py::test_sonarqube_sync_stages_tenant_scoped_idempotent_alerts
tests/unit/test_sonarqube_integration.py::test_sonarqube_sync_uses_tenant_settings_and_closes_client
tests/unit/test_sonarqube_integration.py::test_sonarqube_sync_endpoint_commits_only_after_success
tests/unit/test_tenable_integration.py::test_tenable_stages_in_tenant_ledger
tests/unit/test_ticket_providers.py::test_azure_devops_work_item_creation_uses_project_scoped_tag_lookup
tests/unit/test_wazuh_integration.py::test_wazuh_sync_accepts_indexer_only_tenant_connection
tests/unit/test_worker_queue.py::test_worker_maintenance_recovers_committed_unpublished_runs
tests/unit/test_worker_queue.py::test_assessment_creation_stamps_tenant_on_targets_and_append_only_authorizations
tests/unit/test_worker_queue.py::test_worker_metrics_report_only_requesting_tenants_jobs
```

## Changed-file inventory

The following is the exact `git status --short` inventory immediately before this manifest was added. The task's test and ignore entry are explicitly identified above.

```text
 M .gitignore
 M Dockerfile
 M backend/alembic/versions/0089_custom_agents_knowledge.py
 M backend/app/agent/graph.py
 M backend/app/agent/nodes/attack_path.py
 M backend/app/agent/nodes/plan.py
 M backend/app/agent/nodes/recon.py
 M backend/app/agent/nodes/report.py
 M backend/app/agent/nodes/scan.py
 M backend/app/agent/state.py
 M backend/app/api/deps.py
 M backend/app/api/v1/agent.py
 M backend/app/api/v1/assessments.py
 M backend/app/api/v1/audit.py
 M backend/app/api/v1/auth.py
 M backend/app/api/v1/canonical.py
 M backend/app/api/v1/dashboard.py
 M backend/app/api/v1/exposures.py
 M backend/app/api/v1/external_alerts.py
 M backend/app/api/v1/findings.py
 M backend/app/api/v1/integrations.py
 M backend/app/api/v1/organization.py
 M backend/app/api/v1/projections.py
 M backend/app/api/v1/reports.py
 M backend/app/api/v1/router.py
 M backend/app/core/config.py
 M backend/app/db/enums.py
 M backend/app/db/models/__init__.py
 M backend/app/db/models/agent.py
 M backend/app/db/models/agent_definition.py
 M backend/app/db/models/asset.py
 M backend/app/db/models/audit.py
 M backend/app/db/models/canonical.py
 M backend/app/db/models/finding.py
 M backend/app/db/models/identity.py
 M backend/app/db/models/integration.py
 M backend/app/db/models/knowledge.py
 M backend/app/db/models/notification.py
 M backend/app/db/models/report.py
 M backend/app/integrations/github.py
 M backend/app/integrations/gitlab.py
 M backend/app/reporting/context.py
 M backend/app/reporting/generate.py
 M backend/app/reporting/templates/report.html
 M backend/app/scanners/nuclei.py
 M backend/app/scanners/runner.py
 M backend/app/schemas/agent.py
 M backend/app/schemas/application_risk.py
 M backend/app/schemas/assessment.py
 M backend/app/schemas/asset.py
 M backend/app/schemas/asset_change.py
 M backend/app/schemas/audit.py
 M backend/app/schemas/auth.py
 M backend/app/schemas/canonical.py
 M backend/app/schemas/dashboard.py
 M backend/app/schemas/finding.py
 M backend/app/schemas/integration.py
 M backend/app/schemas/organization.py
 M backend/app/schemas/policy_gate.py
 M backend/app/schemas/report.py
 M backend/app/services/agent_action.py
 M backend/app/services/agent_chat.py
 M backend/app/services/agent_chat_actions.py
 M backend/app/services/agent_read_tools.py
 M backend/app/services/application_risk.py
 M backend/app/services/assessment.py
 M backend/app/services/asset.py
 M backend/app/services/asset_cmdb.py
 M backend/app/services/audit.py
 M backend/app/services/auth.py
 M backend/app/services/canonical_decision.py
 M backend/app/services/canonical_ingest.py
 M backend/app/services/canonical_intel_refresh.py
 M backend/app/services/canonical_query.py
 M backend/app/services/canonical_risk_refresh.py
 M backend/app/services/canonical_work.py
 M backend/app/services/context.py
 M backend/app/services/correlation.py
 M backend/app/services/dashboard.py
 M backend/app/services/external_alert.py
 M backend/app/services/file_intake.py
 M backend/app/services/finding.py
 M backend/app/services/integration.py
 M backend/app/services/job.py
 M backend/app/services/notification.py
 M backend/app/services/organization.py
 M backend/app/services/policy_gate.py
 M backend/app/services/recurring_scan.py
 M backend/app/services/report.py
 M backend/app/services/ticket.py
 M backend/app/worker/dispatch.py
 M backend/app/worker/worker.py
 M backend/pyproject.toml
 M backend/requirements.txt
 M backend/tests/unit/test_agent_actions.py
 M backend/tests/unit/test_agent_chat_actions.py
 M backend/tests/unit/test_canonical_ingest.py
 M backend/tests/unit/test_canonical_intel_refresh.py
 M backend/tests/unit/test_canonical_ticket.py
 M backend/tests/unit/test_canonical_work.py
 M backend/tests/unit/test_gitleaks_adapter.py
 M backend/tests/unit/test_integration_selection.py
 M backend/tests/unit/test_migration_matches_models.py
 M backend/tests/unit/test_notification_outbox.py
 M backend/tests/unit/test_orm_models.py
 M backend/tests/unit/test_runtime_configuration.py
 M backend/tests/unit/test_semgrep_adapter.py
 M backend/tests/unit/test_worker_queue.py
 M docker/backend.Dockerfile
 M frontend/src/app/(app)/agent/[sessionId]/page.tsx
 M frontend/src/app/(app)/assessments/[id]/page.tsx
 M frontend/src/app/(app)/assessments/page.tsx
 M frontend/src/app/(app)/assets/[id]/page.tsx
 M frontend/src/app/(app)/assets/page.tsx
 M frontend/src/app/(app)/audit/page.tsx
 M frontend/src/app/(app)/dashboard/page.tsx
 M frontend/src/app/(app)/findings/[id]/page.tsx
 M frontend/src/app/(app)/findings/all-exposures.tsx
 M frontend/src/app/(app)/findings/canonical-findings.tsx
 M frontend/src/app/(app)/findings/canonical/[id]/page.tsx
 M frontend/src/app/(app)/findings/external-alerts.tsx
 M frontend/src/app/(app)/findings/external/[id]/page.tsx
 M frontend/src/app/(app)/findings/page.tsx
 M frontend/src/app/(app)/integrations/page.tsx
 M frontend/src/app/(app)/jobs/page.tsx
 M frontend/src/app/(app)/settings/organization/page.tsx
 M frontend/src/app/(auth)/login/page.tsx
 M frontend/src/components/layout/AppShell.tsx
 M frontend/src/components/ui/PageHeader.tsx
 M frontend/src/lib/agent-action-workflow.ts
 M frontend/src/lib/api.ts
 M frontend/src/lib/canonical-ticket.ts
 M frontend/src/lib/canonical-work.ts
 M frontend/src/lib/format.ts
 M frontend/src/lib/integration-actions.ts
 M frontend/src/lib/integration-catalog.ts
 M frontend/src/lib/types.ts
?? backend/alembic/versions/0026_m3_remediation_governance.py
?? backend/alembic/versions/0027_m4_platform_api_keys.py
?? backend/alembic/versions/0028_m4_platform_api_key_audit_actor.py
?? backend/alembic/versions/0029_m4_saved_views.py
?? backend/alembic/versions/0030_m4_webhook_subscriptions.py
?? backend/alembic/versions/0031_m4_webhook_notification_channel.py
?? backend/alembic/versions/0032_m4_scim_provisioning_tokens.py
?? backend/alembic/versions/0033_m4_oidc_connections.py
?? backend/alembic/versions/0034_m4_report_schedules.py
?? backend/alembic/versions/0035_m4_report_share_links.py
?? backend/alembic/versions/0036_m4_saml_connections.py
?? backend/alembic/versions/0037_compliance_controls.py
?? backend/alembic/versions/0038_ptaas_finding_collaboration.py
?? backend/alembic/versions/0039_agent_memory.py
?? backend/alembic/versions/0040_asm_surfaces.py
?? backend/alembic/versions/0041_usage_metering.py
?? backend/alembic/versions/0042_dashboard_layouts.py
?? backend/alembic/versions/0043_agent_multi_provider_tickets.py
?? backend/alembic/versions/0044_mssp_client_organizations.py
?? backend/alembic/versions/0045_agent_session_autonomy.py
?? backend/alembic/versions/0046_notification_delivery_retries.py
?? backend/alembic/versions/0047_ticket_closure_generations.py
?? backend/alembic/versions/0048_automation_execution_retries.py
?? backend/alembic/versions/0049_ticket_closed_notification.py
?? backend/alembic/versions/0050_asm_unreachable_drift.py
?? backend/alembic/versions/0052_retest_automation_triggers.py
?? backend/alembic/versions/0053_canonical_remediation_groups.py
?? backend/alembic/versions/0054_agent_remediation_group_retests.py
?? backend/alembic/versions/0055_canonical_remediation_group_keys.py
?? backend/alembic/versions/0056_qualys_direct_integration.py
?? backend/alembic/versions/0057_agent_qualys_sync.py
?? backend/alembic/versions/0058_rapid7_direct_integration.py
?? backend/alembic/versions/0059_agent_rapid7_sync.py
?? backend/alembic/versions/0060_wiz_direct_integration.py
?? backend/alembic/versions/0061_agent_wiz_sync.py
?? backend/alembic/versions/0062_integration_sync_schedules.py
?? backend/alembic/versions/0063_vulnerability_intelligence_cache.py
?? backend/alembic/versions/0064_crowdstrike_direct_integration.py
?? backend/alembic/versions/0070_direct_connector_agent_actions.py
?? backend/alembic/versions/0071_usage_meter_tenant_fk.py
?? backend/alembic/versions/0072_asm_surface_tenant_fk.py
?? backend/alembic/versions/0073_tenant_model_indexes.py
?? backend/alembic/versions/0075_agent_prisma_cloud_sync.py
?? backend/alembic/versions/0076_aws_inspector_direct_integration.py
?? backend/alembic/versions/0077_hackerone_direct_integration.py
?? backend/alembic/versions/0078_bugcrowd_direct_integration.py
?? backend/alembic/versions/0079_checkmarx_direct_integration.py
?? backend/alembic/versions/0080_fortify_direct_integration.py
?? backend/alembic/versions/0081_agent_specialist_tasks.py
?? backend/alembic/versions/0082_agent_decisions.py
?? backend/alembic/versions/0083_durable_workflows.py
?? backend/alembic/versions/0084_scan_auth_profiles.py
?? backend/alembic/versions/0085_bas_runs_and_evidence.py
?? backend/alembic/versions/0086_threat_feed_provenance.py
?? backend/alembic/versions/0087_report_templates.py
?? backend/alembic/versions/0088_custom_connectors.py
?? backend/app/agent/nodes/decide_next.py
?? backend/app/agent/nodes/verify_specialists.py
?? backend/app/api/v1/asm.py
?? backend/app/api/v1/attack_simulations.py
?? backend/app/api/v1/automation.py
?? backend/app/api/v1/compliance.py
?? backend/app/api/v1/custom_connectors.py
?? backend/app/api/v1/metering.py
?? backend/app/api/v1/notifications.py
?? backend/app/api/v1/platform.py
?? backend/app/api/v1/postquantum.py
?? backend/app/api/v1/saved_views.py
?? backend/app/api/v1/scan_auth.py
?? backend/app/api/v1/scim.py
?? backend/app/api/v1/threat_intelligence.py
?? backend/app/api/v1/webhooks.py
?? backend/app/api/v1/workflows.py
?? backend/app/db/models/asm.py
?? backend/app/db/models/compliance.py
?? backend/app/db/models/custom_connector.py
?? backend/app/db/models/platform.py
?? backend/app/db/models/scan_auth.py
?? backend/app/db/models/threat_intelligence.py
?? backend/app/db/models/workflow.py
?? backend/app/db/queries.py
?? backend/app/integrations/aws_inspector.py
?? backend/app/integrations/aws_security_hub.py
?? backend/app/integrations/azure_defender.py
?? backend/app/integrations/azure_devops.py
?? backend/app/integrations/bugcrowd.py
?? backend/app/integrations/burp_dast.py
?? backend/app/integrations/checkmarx.py
?? backend/app/integrations/crowdstrike.py
?? backend/app/integrations/fortify.py
?? backend/app/integrations/gcp_scc.py
?? backend/app/integrations/hackerone.py
?? backend/app/integrations/linear.py
?? backend/app/integrations/pagerduty.py
?? backend/app/integrations/prisma_cloud.py
?? backend/app/integrations/qualys.py
?? backend/app/integrations/rapid7.py
?? backend/app/integrations/servicenow.py
?? backend/app/integrations/splunk.py
?? backend/app/integrations/wiz.py
?? backend/app/schemas/agent_memory.py
?? backend/app/schemas/asm.py
?? backend/app/schemas/attack_simulation.py
?? backend/app/schemas/automation.py
?? backend/app/schemas/collaboration.py
?? backend/app/schemas/compliance.py
?? backend/app/schemas/custom_connector.py
?? backend/app/schemas/dashboard_layout.py
?? backend/app/schemas/notification.py
?? backend/app/schemas/platform.py
?? backend/app/schemas/saved_view.py
?? backend/app/schemas/scan_auth.py
?? backend/app/schemas/scim.py
?? backend/app/schemas/sso.py
?? backend/app/schemas/threat_intelligence.py
?? backend/app/schemas/webhook.py
?? backend/app/schemas/workflow.py
?? backend/app/services/agent_memory.py
?? backend/app/services/agent_planner.py
?? backend/app/services/agent_specialist.py
?? backend/app/services/asm_discovery.py
?? backend/app/services/attack_simulation.py
?? backend/app/services/automation.py
?? backend/app/services/bas_techniques.py
?? backend/app/services/canonical_metrics.py
?? backend/app/services/codeowners.py
?? backend/app/services/compliance.py
?? backend/app/services/custom_connector.py
?? backend/app/services/finding_collaboration.py
?? backend/app/services/integration_sync.py
?? backend/app/services/platform_api_key.py
?? backend/app/services/postquantum.py
?? backend/app/services/query_language.py
?? backend/app/services/remediation_governance.py
?? backend/app/services/report_sharing.py
?? backend/app/services/report_template.py
?? backend/app/services/risk_acceptance.py
?? backend/app/services/scan_auth.py
?? backend/app/services/scheduling.py
?? backend/app/services/scim.py
?? backend/app/services/sla.py
?? backend/app/services/sla_escalation.py
?? backend/app/services/sso.py
?? backend/app/services/threat_feed.py
?? backend/app/services/usage_metering.py
?? backend/app/services/webhook.py
?? backend/app/services/workflow.py
?? backend/tests/unit/test_agent_adaptive_loop.py
?? backend/tests/unit/test_agent_specialists.py
?? backend/tests/unit/test_assessment_projection.py
?? backend/tests/unit/test_attack_simulation_campaigns.py
?? backend/tests/unit/test_authenticated_scans.py
?? backend/tests/unit/test_automation_rules.py
?? backend/tests/unit/test_aws_inspector_connector.py
?? backend/tests/unit/test_aws_security_hub_connector.py
?? backend/tests/unit/test_azure_defender_connector.py
?? backend/tests/unit/test_bas_execution.py
?? backend/tests/unit/test_bugcrowd_connector.py
?? backend/tests/unit/test_burp_dast_connector.py
?? backend/tests/unit/test_checkmarx_connector.py
?? backend/tests/unit/test_codeowners.py
?? backend/tests/unit/test_crowdstrike_connector.py
?? backend/tests/unit/test_custom_connector_runtime.py
?? backend/tests/unit/test_demo_pack.py
?? backend/tests/unit/test_engagement_checklist.py
?? backend/tests/unit/test_fortify_connector.py
?? backend/tests/unit/test_gcp_scc_connector.py
?? backend/tests/unit/test_hackerone_connector.py
?? backend/tests/unit/test_oidc_sso.py
?? backend/tests/unit/test_pagerduty.py
?? backend/tests/unit/test_platform_api_keys.py
?? backend/tests/unit/test_prisma_cloud_connector.py
?? backend/tests/unit/test_remediation_governance.py
?? backend/tests/unit/test_report_download_media_type.py
?? backend/tests/unit/test_report_schedules.py
?? backend/tests/unit/test_report_shares.py
?? backend/tests/unit/test_report_templates.py
?? backend/tests/unit/test_risk_acceptance.py
?? backend/tests/unit/test_saml_dependency.py
?? backend/tests/unit/test_saved_views.py
?? backend/tests/unit/test_scim_provisioning.py
?? backend/tests/unit/test_sla_escalation.py
?? backend/tests/unit/test_sla_policy.py
?? backend/tests/unit/test_splunk.py
?? backend/tests/unit/test_threat_feed_aggregation.py
?? backend/tests/unit/test_ticket_providers.py
?? backend/tests/unit/test_webhooks.py
?? backend/tests/unit/test_workflow_runtime.py
?? demo/
?? docs/superpowers/plans/2026-09-19-integrated-ctem-foundation.md
?? docs/superpowers/plans/2026-09-19-railway-full-stack-recovery.md
?? docs/superpowers/plans/2026-10-13-product-depth-and-operations.md
?? docs/superpowers/plans/2026-10-14-api-only-integrations.md
?? docs/superpowers/plans/2026-10-14-monthly-budget-cutoff.md
?? docs/superpowers/specs/2026-09-19-integrated-ctem-platform-design.md
?? docs/superpowers/specs/2026-09-19-railway-full-stack-recovery-design.md
?? frontend/src/app/(app)/asm/
?? frontend/src/app/(app)/attack-simulations/
?? frontend/src/app/(app)/automation/
?? frontend/src/app/(app)/compliance/
?? frontend/src/app/(app)/remediation/
?? frontend/src/app/(app)/reports/
?? frontend/src/app/(app)/settings/api-keys/
?? frontend/src/app/(app)/settings/deliveries/
?? frontend/src/app/(app)/settings/saved-views/
?? frontend/src/app/(app)/settings/scan-auth/
?? frontend/src/app/(app)/settings/webhooks/
?? frontend/src/app/(app)/threat-intelligence/
?? frontend/src/app/(app)/workflows/
?? frontend/src/app/(auth)/sso/
?? frontend/src/components/ui/Modal.tsx
?? frontend/src/lib/duplicate-candidate.ts
?? frontend/src/lib/workflow-builder.test.ts
?? frontend/src/lib/workflow-builder.ts
?? infra/defectdojo/
```

