# Product Depth and Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing adaptive-agent, automation, scanner, BAS, intelligence, reporting, API, and deployment foundations into integrated production capabilities without introducing parallel tenant, finding, assessment, approval, or credential models.

**Architecture:** The existing `Assessment`, `AgentRun`, `AutomationRule`, `ScannerJob`, `AttackSimulationCampaign`, `VulnerabilityIntelligence`, `Report`, and platform API models remain authoritative. New durable child records add decisions, workflow steps, scan-auth bindings, BAS evidence, feed provenance, templates, and custom connector executions. All active operations use the existing tenant principal, authorization record, approval gate, queue, encrypted integration credentials, evidence archive, audit events, and notification outbox.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Redis Streams, LangGraph, Pydantic 2, Next.js 15, TypeScript, Docker.

**Spec:** `docs/superpowers/specs/2026-09-19-integrated-ctem-platform-design.md`

## Global Constraints

- Active testing requires explicit authorization and existing approval gates.
- All additions are additive migrations with safe defaults for existing rows.
- API keys are encrypted per organization and write-only at the API boundary.
- No implementation may weaken tenant filtering, audit logging, or host validation.
- Do not introduce a parallel assessment, finding, or integration model.
- Every external side effect requires an idempotency key and an auditable durable execution record.
- LLM output may propose bounded actions but may not bypass deterministic scope, approval, credential, or evidence checks.

## Review Focus

- A resumed worker must not repeat a completed external side effect; each owning task tests crash recovery with an existing idempotency record.
- Cross-tenant IDs in agent, workflow, scanner-auth, BAS, report-template, and connector requests must return not-found/forbidden without exposing existence.
- Secrets contained in provider errors, scanner logs, report context, or connector responses must be redacted before persistence.
- A model-generated plan containing an unknown tool, out-of-scope target, or forbidden technique must fail closed and preserve an audit explanation.
- A slow or unavailable external provider must produce bounded retries and a terminal degraded result instead of leaving runs permanently active.

---

### Task 1: Adaptive, evidence-driven agent loop

**Files:**
- Create: `backend/app/services/agent_planner.py`
- Create: `backend/app/agent/nodes/decide_next.py`
- Modify: `backend/app/db/models/agent.py`
- Modify: `backend/app/agent/state.py`
- Modify: `backend/app/agent/graph.py`
- Modify: `backend/app/services/agent_specialist.py`
- Modify: `backend/app/worker/worker.py`
- Create: `backend/alembic/versions/0082_agent_decisions.py`
- Test: `backend/tests/unit/test_agent_adaptive_loop.py`

**Interfaces:**
- Consumes: `AgentRun`, completed `AgentSpecialistTask` rows, archived scanner artifacts, the assessment authorization record, and current autonomy mode.
- Produces: `AgentDecision`, `propose_next_actions(session, principal, run_id) -> DecisionBatch`, and a bounded graph loop `verify_specialists -> decide_next -> scan|enrich_intelligence`.

- [ ] **Step 1: Write failing decision-policy tests**

```python
def test_unknown_or_out_of_scope_tool_is_rejected():
    result = validate_decision(candidate={"tool": "shell", "targets": ["other.example"]}, allowed_tools={"nuclei"}, allowed_targets={"app.example"})
    assert result.accepted is False
    assert result.reason_code == "policy_rejected"

def test_completed_fingerprint_is_not_dispatched_twice():
    batch = choose_actions(candidates=[candidate("nuclei", "app.example")], completed_fingerprints={fingerprint("nuclei", ["app.example"])})
    assert batch.actions == []
```

- [ ] **Step 2: Run the new tests and verify RED**

Run: `pytest -q backend/tests/unit/test_agent_adaptive_loop.py`

Expected: FAIL because `agent_planner`, `AgentDecision`, and the decision node do not exist.

- [ ] **Step 3: Add durable decisions and deterministic validation**

Implement `AgentDecision` with `organization_id`, `run_id`, `sequence`, `hypothesis`, `candidate_actions`, `accepted_actions`, `rejections`, `input_evidence_ids`, `status`, and timestamps. Parse model output through a strict Pydantic schema, then intersect tools and targets with the server-built allowlists. Hash `(run_id, tool, normalized targets, parameters)` for dispatch idempotency. Stop on configured step/time budgets, no new evidence, or terminal coverage.

- [ ] **Step 4: Wire a bounded graph loop and recovery**

The node may enqueue only existing scanner adapters and must reuse `ensure_tasks`. On resume it loads the latest decision and specialist state, dispatches only missing fingerprints, and records a terminal degraded explanation after bounded provider/scanner retries.

- [ ] **Step 5: Verify focused and graph tests**

Run: `pytest -q backend/tests/unit/test_agent_adaptive_loop.py backend/tests/unit/test_agent_specialists.py backend/tests/unit/test_agent_graph.py`

Expected: PASS, including the unknown-tool, cross-tenant, duplicate-dispatch, stale-worker, and provider-timeout cases.

### Task 2: Durable visual automation workflows

**Files:**
- Create: `backend/app/db/models/workflow.py`
- Create: `backend/app/schemas/workflow.py`
- Create: `backend/app/services/workflow.py`
- Create: `backend/app/api/v1/workflows.py`
- Modify: `backend/app/services/automation.py`
- Modify: `backend/app/api/v1/router.py`
- Create: `backend/alembic/versions/0083_durable_workflows.py`
- Create: `frontend/src/app/(app)/automation/workflows/page.tsx`
- Create: `frontend/src/lib/workflow-builder.ts`
- Test: `backend/tests/unit/test_workflow_runtime.py`
- Test: `frontend/src/lib/workflow-builder.test.ts`

**Interfaces:**
- Consumes: existing `AutomationRule` triggers and conditions, canonical finding events, ticket/retest/notification services, and cron scheduler.
- Produces: `WorkflowDefinition`, `WorkflowRun`, `WorkflowStepRun`, `validate_workflow_graph(definition)`, `start_workflow(...)`, and `resume_workflow(...)`.

- [ ] **Step 1: Write failing DAG and recovery tests**

```python
def test_cycle_is_rejected():
    with pytest.raises(ValueError, match="acyclic"):
        validate_workflow_graph(graph_with_edges(("a", "b"), ("b", "a")))

async def test_resume_skips_succeeded_side_effect(session):
    run = await seeded_run(step_status="succeeded", idempotency_key="ticket:42")
    await resume_workflow(session, run.id)
    assert ticket_provider.create_calls == 0
```

- [ ] **Step 2: Run backend/frontend tests and verify RED**

Run: `pytest -q backend/tests/unit/test_workflow_runtime.py` and `npm --prefix frontend test -- --run src/lib/workflow-builder.test.ts`

Expected: FAIL because the workflow runtime and builder serializer do not exist.

- [ ] **Step 3: Implement validated workflow definitions**

Support trigger nodes (`finding.created`, `finding.updated`, `ticket.closed`, `retest.cleared`, `sla.breached`, `cron`), condition nodes, approved enrichment nodes, action nodes already supported by `automation.py`, branch nodes, delay nodes, and approval nodes. Reject arbitrary code, arbitrary URLs, cycles, orphan steps, and unknown input references.

- [ ] **Step 4: Implement resumable execution and visual builder**

Claim steps with row locks, persist input/output/error/redacted logs, use deterministic per-step idempotency keys, retry only retryable failures, and resume downstream steps after delays or approvals. The UI edits typed nodes/edges, validates locally, supports dry-run, and renders execution history.

- [ ] **Step 5: Verify automation compatibility**

Run: `pytest -q backend/tests/unit/test_workflow_runtime.py backend/tests/unit/test_automation_rules.py` and `npm --prefix frontend run typecheck`

Expected: PASS; existing single-rule automation remains functional and can be represented as a one-action workflow.

### Task 3: Tenant-safe authenticated scan profiles

**Files:**
- Create: `backend/app/db/models/scan_auth.py`
- Create: `backend/app/schemas/scan_auth.py`
- Create: `backend/app/services/scan_auth.py`
- Create: `backend/app/api/v1/scan_auth.py`
- Modify: `backend/app/scanners/base.py`
- Modify: `backend/app/scanners/runner.py`
- Modify: `backend/app/scanners/zap.py`
- Modify: `backend/app/scanners/nuclei.py`
- Modify: `backend/app/scanners/prowler.py`
- Modify: `backend/app/api/v1/router.py`
- Create: `backend/alembic/versions/0084_scan_auth_profiles.py`
- Create: `frontend/src/app/(app)/settings/scan-auth/page.tsx`
- Test: `backend/tests/unit/test_authenticated_scans.py`

**Interfaces:**
- Consumes: encrypted `IntegrationCredential` rows, scanner credential allowlists, scan profiles, authorized targets, and sandbox execution.
- Produces: `ScanAuthProfile`, write-only profile APIs, and `resolve_scanner_credentials(session, principal, profile_id, scanner, target) -> ResolvedScannerAuth`.

- [ ] **Step 1: Write failing auth-resolution tests**

```python
async def test_profile_secret_is_write_only(client):
    issued = await client.post("/api/v1/scan-auth", json=basic_profile("user", "pass"))
    assert "pass" not in issued.text

async def test_profile_cannot_cross_tenant_or_host_scope(session):
    with pytest.raises(NotFoundError):
        await resolve_scanner_credentials(session, other_principal, profile.id, ScannerName.ZAP, "https://app.example")
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `pytest -q backend/tests/unit/test_authenticated_scans.py`

Expected: FAIL because scan-auth profiles and credential resolution do not exist.

- [ ] **Step 3: Implement write-only profiles and adapter contracts**

Support HTTP basic, bearer/header, cookie/session, OpenAPI token, AWS role/static, Azure service principal, and GCP service-account modes. Persist only encrypted secrets through the existing credential vault; profiles store target patterns, permitted scanners, non-secret metadata, and rotation/validation timestamps.

- [ ] **Step 4: Pass credentials only to the sandboxed process**

Resolve immediately before execution, re-check tenant and target scope, map only adapter-declared environment names or mounted temporary files, disable captured command environments, redact provider output, delete temporary files after completion, and never place secret values in queue payloads.

- [ ] **Step 5: Verify scanner and isolation behavior**

Run: `pytest -q backend/tests/unit/test_authenticated_scans.py backend/tests/unit/test_scanner_runner.py backend/tests/unit/test_scanner_sandbox.py`

Expected: PASS for each auth mode, disallowed scanner, target mismatch, rotation, provider error redaction, and cleanup.

### Task 4: Executable breach-and-attack simulation

**Files:**
- Modify: `backend/app/db/models/canonical.py`
- Modify: `backend/app/schemas/attack_simulation.py`
- Modify: `backend/app/services/attack_simulation.py`
- Modify: `backend/app/api/v1/attack_simulations.py`
- Create: `backend/app/services/bas_techniques.py`
- Create: `backend/alembic/versions/0085_bas_runs_and_evidence.py`
- Modify: `frontend/src/app/(app)/attack-simulations/page.tsx`
- Test: `backend/tests/unit/test_bas_execution.py`

**Interfaces:**
- Consumes: existing campaigns, authorization/approval services, scanner jobs, agent decisions, and evidence artifacts.
- Produces: `AttackSimulationRun`, `AttackSimulationTechniqueRun`, a versioned safe technique catalog, control-effectiveness results, and rerun comparisons.

- [ ] **Step 1: Write failing policy/evidence tests**

```python
async def test_active_technique_requires_current_approval(session):
    with pytest.raises(ApprovalRequiredError):
        await execute_technique(session, principal, campaign, technique("T1190"))

def test_control_result_requires_archived_evidence():
    assert classify_control_result(exit_code=0, artifact_ids=[]) == "inconclusive"
```

- [ ] **Step 2: Run and verify RED**

Run: `pytest -q backend/tests/unit/test_bas_execution.py`

Expected: FAIL because technique runs and evidence-backed classification do not exist.

- [ ] **Step 3: Add a bounded technique catalog and executor**

Begin with non-destructive discovery, exposure validation, web-template validation, cloud-control checks, and credential-exposure checks. Each catalog item declares MITRE technique, required target type, risk class, adapter, approval requirement, timeout, expected evidence, and cleanup behavior. The executor can invoke only registered adapters.

- [ ] **Step 4: Persist evidence and comparisons**

Archive artifacts, record detected/prevented/inconclusive/error, correlate available integration telemetry, compute per-control effectiveness, and compare a rerun with its baseline. Never label a control effective or ineffective without evidence.

- [ ] **Step 5: Verify campaign lifecycle**

Run: `pytest -q backend/tests/unit/test_bas_execution.py backend/tests/unit/test_attack_simulation_campaigns.py`

Expected: PASS for approval, scope, recovery, evidence, pause, schedule, and rerun-delta cases.

### Task 5: Multi-source threat intelligence and watchlists

**Files:**
- Modify: `backend/app/db/models/threat_intelligence.py`
- Modify: `backend/app/schemas/threat_intelligence.py`
- Create: `backend/app/services/threat_feed.py`
- Modify: `backend/app/services/canonical_intel_refresh.py`
- Modify: `backend/app/api/v1/threat_intelligence.py`
- Create: `backend/alembic/versions/0086_threat_feed_provenance.py`
- Modify: `frontend/src/app/(app)/threat-intelligence/page.tsx`
- Test: `backend/tests/unit/test_threat_feed_aggregation.py`

**Interfaces:**
- Consumes: cached NVD/KEV/EPSS/exploit data, tenant asset/product inventory, canonical findings, and configurable feed integrations.
- Produces: normalized `ThreatObservation`, `ThreatActor`, `RansomwareAssociation`, `ThreatWatchlist`, provenance/confidence, and risk-refresh events.

- [ ] **Step 1: Write failing merge/provenance tests**

```python
def test_conflicting_observations_preserve_sources_and_confidence():
    merged = merge_observations([obs("kev", exploited=True, confidence=1.0), obs("community", exploited=False, confidence=.3)])
    assert merged.exploited is True
    assert {p.source for p in merged.provenance} == {"kev", "community"}
```

- [ ] **Step 2: Run and verify RED**

Run: `pytest -q backend/tests/unit/test_threat_feed_aggregation.py`

Expected: FAIL because multi-source observations and watchlists do not exist.

- [ ] **Step 3: Implement feed adapters and normalized merge**

Add first-party adapters for CISA KEV, NVD, EPSS, GitHub advisory/exploit references, and ransomware/actor tagging feeds whose license permits storage. Normalize timestamps and identifiers, retain immutable provenance, select facts by deterministic source priority/confidence, and retain stale data with a visible freshness state when refresh fails.

- [ ] **Step 4: Add tenant watchlists and risk refresh**

Watch CVEs, products, actors, domains, and brands. Match only tenant inventory and findings, emit deduplicated change events, and enqueue canonical risk recalculation without making live provider calls in read endpoints.

- [ ] **Step 5: Verify aggregation and tenant matching**

Run: `pytest -q backend/tests/unit/test_threat_feed_aggregation.py backend/tests/unit/test_canonical_intel_refresh.py`

Expected: PASS for conflicts, stale feeds, malformed records, duplicate refresh, tenant separation, and provider timeout.

### Task 6: Enterprise report templates and MSSP portfolio reporting

**Files:**
- Modify: `backend/app/db/models/report.py`
- Modify: `backend/app/schemas/report.py`
- Create: `backend/app/services/report_template.py`
- Modify: `backend/app/services/report.py`
- Modify: `backend/app/reporting/context.py`
- Modify: `backend/app/reporting/generate.py`
- Modify: `backend/app/api/v1/reports.py`
- Create: `backend/alembic/versions/0087_report_templates.py`
- Create: `frontend/src/app/(app)/reports/templates/page.tsx`
- Create: `frontend/src/app/(app)/reports/portfolio/page.tsx`
- Test: `backend/tests/unit/test_report_templates.py`

**Interfaces:**
- Consumes: existing report generation/storage/schedule/share services, dashboard layouts, compliance mappings, and MSSP client organization relationships.
- Produces: versioned `ReportTemplate`, `ReportDistribution`, safe block-based template rendering, and parent-organization portfolio context.

- [ ] **Step 1: Write failing template-safety and tenant tests**

```python
def test_template_rejects_arbitrary_html_or_unknown_query():
    with pytest.raises(ValueError):
        validate_template({"blocks": [{"type": "html", "value": "<script>alert(1)</script>"}]})

async def test_parent_portfolio_includes_only_managed_children(session):
    context = await build_portfolio_context(session, parent_principal)
    assert unrelated_org.id not in {row.organization_id for row in context.organizations}
```

- [ ] **Step 2: Run and verify RED**

Run: `pytest -q backend/tests/unit/test_report_templates.py`

Expected: FAIL because templates and portfolio context do not exist.

- [ ] **Step 3: Implement safe versioned templates**

Use an allowlisted block schema for title, narrative, metric, trend, table, chart, compliance, page-break, and branding blocks. Snapshot the template version on each report, resolve only saved tenant queries, sanitize text/URLs, and preserve deterministic HTML/PDF/JSON rendering.

- [ ] **Step 4: Add distributions and MSSP portfolio views**

Allow scheduled email/webhook delivery with recipient/domain policies and per-delivery status. Parent organizations can aggregate managed clients only, with drill-down preserving child tenant authorization and no shared raw finding query.

- [ ] **Step 5: Verify rendering and schedules**

Run: `pytest -q backend/tests/unit/test_report_templates.py backend/tests/unit/test_report_schedules.py backend/tests/unit/test_report_shares.py` and `npm --prefix frontend run typecheck`

Expected: PASS for template versioning, unsafe content, child removal, failed delivery retry, and deterministic output.

### Task 7: Public SDK, GraphQL read API, and declarative custom connectors

**Files:**
- Create: `backend/app/api/graphql/schema.py`
- Create: `backend/app/api/graphql/context.py`
- Modify: `backend/app/api/app.py`
- Create: `backend/app/db/models/custom_connector.py`
- Create: `backend/app/schemas/custom_connector.py`
- Create: `backend/app/services/custom_connector.py`
- Create: `backend/app/api/v1/custom_connectors.py`
- Create: `backend/alembic/versions/0088_custom_connectors.py`
- Create: `sdk/python/pyproject.toml`
- Create: `sdk/python/cynux/client.py`
- Create: `sdk/python/cynux/models.py`
- Create: `sdk/python/tests/test_client.py`
- Test: `backend/tests/unit/test_graphql_api.py`
- Test: `backend/tests/unit/test_custom_connector_runtime.py`

**Interfaces:**
- Consumes: scoped platform API keys, existing REST services/schemas, integration credentials, external-alert normalization, webhook delivery protections, and canonical ingest.
- Produces: tenant-scoped read-only GraphQL queries, `CynuxClient`, and a declarative HTTP connector runtime with test/sync/health/history APIs.

- [ ] **Step 1: Write failing authorization and SSRF tests**

```python
async def test_graphql_enforces_api_key_scope(graphql_client):
    response = await graphql_client.query("{ findings { id } }", key=assets_only_key)
    assert response.errors[0]["extensions"]["code"] == "FORBIDDEN"

async def test_connector_rejects_private_or_rebound_destination(session):
    with pytest.raises(UnsafeDestinationError):
        await execute_connector(session, connector(base_url="http://127.0.0.1"))
```

- [ ] **Step 2: Run and verify RED**

Run: `pytest -q backend/tests/unit/test_graphql_api.py backend/tests/unit/test_custom_connector_runtime.py sdk/python/tests/test_client.py`

Expected: FAIL because these public extension surfaces do not exist.

- [ ] **Step 3: Implement GraphQL as a thin service layer**

Expose paginated assets, canonical findings, assessments, reports, integrations, and aggregate metrics. Resolvers must call existing tenant-aware services, use request-scoped batching, enforce API-key scopes before lookup, cap depth/complexity/page size, disable introspection outside configured development environments, and expose no mutations initially.

- [ ] **Step 4: Implement declarative connectors and SDK**

Connector definitions allow fixed HTTPS base URL, allowlisted relative paths/methods, typed pagination, JSON field mapping, credential references, rate limits, and canonical/external-alert output mapping. Reuse DNS pinning and public-address validation from webhooks, redact configured secret fields, checkpoint pagination, and record every execution. The Python SDK wraps REST pagination, retries retryable responses, typed errors, idempotency keys, and webhook signature verification.

- [ ] **Step 5: Verify contracts**

Run: `pytest -q backend/tests/unit/test_graphql_api.py backend/tests/unit/test_custom_connector_runtime.py sdk/python/tests/test_client.py backend/tests/unit/test_platform_api_keys.py backend/tests/unit/test_webhooks.py`

Expected: PASS for scope denial, cross-tenant IDs, depth limits, rebinding, pagination resume, secret redaction, retry limits, and signature verification.

### Task 8: Production topology, observability, backup, and recovery

**Files:**
- Create: `compose.production.yml`
- Create: `infra/production/README.md`
- Create: `infra/production/env.example`
- Create: `infra/production/backup-postgres.ps1`
- Create: `infra/production/restore-postgres.ps1`
- Create: `infra/production/verify-backup.ps1`
- Create: `infra/production/run-migrations.ps1`
- Create: `infra/production/smoke-test.ps1`
- Modify: `backend/app/core/config.py`
- Modify: `backend/app/api/app.py`
- Modify: `backend/app/worker/worker.py`
- Modify: `Dockerfile`
- Modify: `docker/backend.Dockerfile`
- Modify: `docker/frontend.Dockerfile`
- Test: `backend/tests/unit/test_production_config.py`
- Test: `backend/tests/unit/test_health_readiness.py`

**Interfaces:**
- Consumes: API, worker, Redis, PostgreSQL, object storage, scanner runtime, migrations, and existing metrics endpoints.
- Produces: separate API/worker/scanner services, startup validation, liveness/readiness, graceful shutdown, backup/restore verification, retention jobs, and deployment smoke checks.

- [ ] **Step 1: Write failing production-config/readiness tests**

```python
def test_production_refuses_ephemeral_secrets():
    with pytest.raises(SettingsError, match="stable secret"):
        Settings(environment="production", secret_key="change-me")

async def test_readiness_fails_when_queue_or_database_is_unavailable(client):
    response = await client.get("/readyz")
    assert response.status_code == 503
    assert set(response.json()["unavailable"]) == {"database", "queue"}
```

- [ ] **Step 2: Run and verify RED**

Run: `pytest -q backend/tests/unit/test_production_config.py backend/tests/unit/test_health_readiness.py`

Expected: FAIL because strict production validation and dependency readiness do not exist.

- [ ] **Step 3: Implement deployable topology and startup contracts**

Define separate API, scheduler/worker, constrained scanner worker, frontend, PostgreSQL, Redis, and S3-compatible object-storage services. Use immutable images, non-root users, read-only filesystems where compatible, health checks, restart policies, explicit resource limits, named volumes, and no secret values in the compose file. API startup validates migrations and configuration but never runs destructive schema operations concurrently.

- [ ] **Step 4: Implement operational recovery**

Add liveness/readiness/dependency status, queue-depth and run-latency metrics, correlation IDs, graceful drain, database and artifact retention, encrypted PostgreSQL backups, restore into a separate target database, checksum verification, and smoke checks for registration/login, tenant isolation, assessment creation, queue processing, report storage, and webhook delivery.

- [ ] **Step 5: Run full verification**

Run: `pytest -q backend/tests`, `ruff check backend/app backend/tests`, `npm --prefix frontend test -- --run`, `npm --prefix frontend run typecheck`, and `npm --prefix frontend run build`.

Expected: all commands PASS. Then build the production images, apply migrations to an empty PostgreSQL database and a copied legacy database, run `infra/production/smoke-test.ps1`, restore the newest backup into an isolated database, and verify its checksum and row counts.

