# Market-Parity Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement every recommended market-parity capability except adding new named connector families.

**Architecture:** Build tenant-owned aggregates behind existing permission, audit, outbox, worker, canonical-ingest, and approval primitives. Ship each slice independently with migrations, REST/GraphQL contracts, SDK support, UI, and regression tests.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy 2, PostgreSQL, Redis workers, Strawberry GraphQL, Next.js/TypeScript, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-17-market-parity-platform-design.md`

## Global Constraints

- Preserve organization scoping and current RBAC on every query and mutation.
- Never expose credentials, secrets, provider response bodies, or unrestricted execution.
- Require idempotency for external writes and durable jobs.
- Preserve approval gates for active security and external side effects.
- Do not add new named connector families.
- Introduce migrations in monotonic order after `0093`.

## Review Focus

- Connector redirects or DNS rebinding must not reach private or link-local destinations.
- Replayed webhook, GraphQL, and worker requests must not duplicate side effects.
- Cross-tenant identifiers must return not-found without revealing resource existence.
- Retention must never delete legal-hold, active-engagement, or audit evidence prematurely.
- Asset merge and provider reconciliation must preserve source provenance and lifecycle history.

---

### Task 1: Executable custom connectors and governed transformations

**Files:**
- Modify: `backend/app/services/custom_connector.py`
- Modify: `backend/app/api/v1/custom_connectors.py`
- Modify: `backend/app/schemas/custom_connector.py`
- Test: `backend/tests/unit/test_custom_connector_runtime.py`

**Interfaces:**
- Produces: `execute_connector(...) -> CustomConnectorRun`, bounded pagination helpers, normalization contracts, and `POST /custom-connectors/{id}/runs`.

- [x] Write failing tests for pagination, mapping, ingestion, checkpoints, idempotency, safe redirects, and durable worker settlement.
- [x] Run the focused tests and confirm feature-missing failures.
- [x] Implement the smallest runtime using the hardened HTTP transport and canonical ingestion services.
- [x] Run focused, migration, worker, canonical-ingest, and external-alert suites; focused checks pass, while the broader compatibility run records 18 unrelated baseline failures.
- [x] Commit the independently deployable connector runtime (`6718592`).

### Task 2: Full-platform GraphQL and Python SDK

**Files:**
- Modify: `backend/app/graphql/queries.py`
- Modify: `backend/app/graphql/mutations.py`
- Modify: `backend/app/graphql/types.py`
- Modify: `sdk/python/cynux/client.py`
- Modify: `sdk/python/cynux/async_client.py`
- Test: `backend/tests/unit/test_graphql_queries.py`
- Test: `backend/tests/unit/test_graphql_agent_mutations.py`

**Interfaces:**
- Produces: cursor-paginated asset/finding/assessment/report/automation queries and idempotent core mutations.

- [ ] Add failing authorization, pagination, filtering, bulk-mutation, and idempotency tests (core asset/finding/assessment query coverage complete; mutation coverage remains).
- [ ] Implement tenant-scoped query nodes and service-backed mutations (asset, finding, assessment, report, and automation read connections complete; write mutations remain).
- [x] Add typed sync/async SDK methods and pagination helpers for asset, canonical-finding, assessment, report, and automation connections.
- [x] Run the complete GraphQL and Python SDK suites for the completed query slice.

### Task 3: PTaaS engagement aggregate and portals

**Files:**
- Create: `backend/app/db/models/engagement.py`
- Create: `backend/app/schemas/engagement.py`
- Create: `backend/app/services/engagement.py`
- Create: `backend/app/api/v1/engagements.py`
- Create: `backend/alembic/versions/0095_ptaas_engagements.py`
- Create: `frontend/src/app/(app)/engagements/page.tsx`
- Create: `frontend/src/app/(app)/engagements/[id]/page.tsx`
- Test: `backend/tests/unit/test_engagements.py`

**Interfaces:**
- Produces: engagement, participant, scope, milestone, time-entry, document, and retest-round operations.

- [x] Add failing lifecycle, role-boundary, time-entry, document, and retest tests.
- [x] Implement models, migration, contracts, service, routes, and navigation.
- [x] Implement client/tester projections without parallel finding storage.
- [x] Run migration, API, ORM, OpenAPI, frontend unit, typecheck, and production-build suites.

### Task 4: Durable agentic pentest workspaces

**Files:**
- Create: `backend/app/db/models/agent_workspace.py`
- Create: `backend/app/services/agent_workspace.py`
- Create: `backend/app/api/v1/agent_workspaces.py`
- Create: `backend/alembic/versions/0096_agent_workspaces.py`
- Create: `frontend/src/app/(app)/agent/workspaces/page.tsx`
- Test: `backend/tests/unit/test_agent_workspaces.py`

**Interfaces:**
- Produces: durable workspace, artifact, shared-table, credential-reference, browser-task, and shell-task contracts linked to AgentRun.

- [x] Add failing isolation, artifact, approval, quota, and reproducibility tests.
- [x] Implement workspace persistence and object-storage artifacts.
- [x] Bind active tasks to existing approval and scanner dispatch systems.
- [x] Add evidence export and UI.
- [x] Run agent and frontend suites.

### Task 5: Automation platform expansion

**Files:**
- Modify: `backend/app/services/automation.py`
- Modify: `backend/app/schemas/automation.py`
- Modify: `backend/app/api/v1/automation.py`
- Create: `backend/app/services/automation_expression.py`
- Create: `backend/alembic/versions/0097_automation_platform.py`
- Modify: `frontend/src/app/(app)/automation/page.tsx`
- Test: `backend/tests/unit/test_automation_rules.py`

**Interfaces:**
- Produces: entity triggers, manual/signed-webhook starts, bounded expressions, agent-run action, templates, and execution trace.

- [x] Add failing parser, trigger, template, signature, replay, and agent-action tests.
- [x] Implement the expression evaluator without `eval` or arbitrary code.
- [x] Add asset, assessment, engagement, scan-log, integration, webhook, and manual triggers.
- [x] Add enrichment, field mutation, tag, webhook, report, and agent actions.
- [x] Run automation and frontend suites.

### Task 6: Asset inventory operations

**Files:**
- Modify: `backend/app/db/models/asset.py`
- Modify: `backend/app/services/asset.py`
- Modify: `backend/app/api/v1/assets.py`
- Create: `backend/app/services/asset_merge.py`
- Create: `backend/alembic/versions/0098_asset_inventory_operations.py`
- Modify: `frontend/src/app/(app)/assets/page.tsx`
- Test: `backend/tests/unit/test_asset_inventory_operations.py`

**Interfaces:**
- Produces: create, CSV import/export, bulk update, merge, relationship, custom-field, and cloud-inventory projection operations.

- [x] Add failing provenance, merge, bulk, CSV, cycle, and cross-tenant tests.
- [x] Implement persistence and service operations with immutable merge history.
- [x] Add API/SDK/UI surfaces with bounded CSV preview/apply imports.
- [ ] Add durable asynchronous processing for imports above the interactive limit.
- [x] Run asset, SDK, and frontend suites.

### Task 7: Event-driven bidirectional ticket synchronization

**Files:**
- Modify: `backend/app/services/ticket.py`
- Create: `backend/app/api/v1/inbound_integrations.py`
- Create: `backend/app/services/inbound_ticket_event.py`
- Test: `backend/tests/unit/test_ticket_webhooks.py`

**Interfaces:**
- Produces: signed provider webhook ingestion, replay protection, normalized transitions, and provider-side update commands.

- [ ] Add failing signature, replay, stale-event, transition, and tenant-resolution tests.
- [ ] Implement Jira, GitHub, GitLab, ServiceNow, and Azure DevOps event normalization using existing integrations only.
- [ ] Implement idempotent outbound comment/state updates where provider clients support them.
- [ ] Run ticket, webhook, and automation suites.

### Task 8: Exploit, product, patch, and compensating-control intelligence

**Files:**
- Create: `backend/app/db/models/exploit_intelligence.py`
- Create: `backend/app/services/exploit_intelligence.py`
- Modify: `backend/app/services/canonical_risk.py`
- Create: `backend/alembic/versions/0099_exploit_intelligence.py`
- Modify: `frontend/src/app/(app)/threat-intelligence/page.tsx`
- Test: `backend/tests/unit/test_exploit_intelligence.py`

**Interfaces:**
- Produces: exploit references, PoC maturity, affected products, fixes, campaigns, controls, and risk-score provenance.

- [ ] Add failing freshness, conflict, product-range, patch, control-effectiveness, and scoring tests.
- [ ] Implement normalized intelligence aggregates and bounded feed ingestion.
- [ ] Extend risk scoring while preserving explicit unknown signals.
- [ ] Add REST/GraphQL/SDK/UI projections.
- [ ] Run intelligence and risk suites.

### Task 9: Enterprise administration, workbooks, and AI budget controls

**Files:**
- Create: `backend/app/services/mfa.py`
- Create: `backend/app/services/retention.py`
- Create: `backend/app/db/models/workbook.py`
- Create: `backend/alembic/versions/0100_enterprise_controls.py`
- Modify: `backend/app/api/v1/organization.py`
- Create: `backend/app/api/v1/workbooks.py`
- Create: `frontend/src/app/(app)/reports/workbooks/page.tsx`
- Test: `backend/tests/unit/test_enterprise_controls.py`

**Interfaces:**
- Produces: TOTP enrolment/challenge/recovery, legal-hold-aware retention, tenant branding, workbook definitions, dashboard sharing, and AI spend alerts.

- [ ] Add failing MFA, recovery, retention, legal-hold, workbook query-budget, and spend-alert tests.
- [ ] Implement encrypted TOTP state and one-time recovery codes.
- [ ] Implement auditable retention sweeps and tenant branding.
- [ ] Implement governed workbooks and budget-threshold notifications.
- [ ] Run authentication, reporting, metering, migration, and frontend suites.

### Task 10: Release integration

**Files:**
- Modify: deployment manifests and environment examples only as required by Tasks 1-9.

**Interfaces:**
- Consumes: all prior task contracts.
- Produces: one migration-safe deployable release.

- [ ] Run full backend, frontend, SDK, migration, lint, and type-check suites.
- [ ] Review upgrade/downgrade paths and worker compatibility.
- [ ] Commit and push the release branch.
- [ ] Deploy API, worker, scheduler, and frontend; run smoke checks against production URLs.

