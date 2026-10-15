# Expanded Automation Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand Cynux automation into a versioned, simulatable, durable rule platform with broad triggers, nested conditions, branching, delays, approvals, reusable templates, and complete execution lineage.

**Architecture:** Keep automation as a policy-oriented layer over the shared durable workflow runtime. Published rules are immutable versions; normalized domain events enter through the transactional outbox; a pure evaluator selects typed action requests; durable steps execute admitted effects with the same authorization, idempotency, budget, and audit services as direct actions.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Redis, Pydantic, Next.js, React Flow or existing workflow builder primitives, pytest, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-16-market-parity-platform-design.md`

## Global Constraints

- Simulation is pure and cannot produce external or persistent side effects.
- Published rule versions and event envelopes are immutable.
- Every action uses the same domain service, permission, approval, and idempotency contract as a direct request.
- Delays and retries are durable and do not depend on an in-process timer.
- Rule budgets and deployment cutoffs are checked before dispatching paid or external work.

## Review Focus

- An event replayed after a rule edit must use the version selected for that replay, not silently switch versions; covered by Task 1.
- Missing condition fields and explicit null values must be distinct; covered by Task 2.
- Two matching rules attempting the same provider mutation must deduplicate at the operation ledger; covered by Task 4.
- Delayed work whose authorization expires must fail before action dispatch; covered by Task 5.
- Disabling a rule must stop new events while allowing committed execution settlement; covered by Task 5.

---

### Task 1: Immutable rule versions, templates, and event schemas

**Files:**
- Create: `backend/alembic/versions/0105_automation_versions.py`
- Modify: `backend/app/db/models/canonical.py`
- Create: `backend/app/services/automation_versions.py`
- Create: `backend/app/services/automation_events.py`
- Modify: `backend/app/schemas/automation.py`
- Test: `backend/tests/unit/test_automation_versions.py`
- Test: `backend/tests/unit/test_automation_event_schema.py`

**Interfaces:**
- Consumes: current `AutomationRule`, workflow models, and domain outbox events.
- Produces: `AutomationRuleVersion`, `AutomationTemplate`, `AutomationEventEnvelope`, `publish_rule()`, and `normalize_automation_event()`.

- [ ] **Step 1: Write failing immutability and version-selection tests**

```python
async def test_published_rule_version_cannot_be_edited(service):
    version = await service.publish(rule_definition())
    with pytest.raises(ImmutableRuleVersion):
        await service.update_version(version.id, name="changed")

async def test_replay_pins_selected_rule_version(service):
    v1 = await service.publish(rule_with_action("notify"))
    v2 = await service.publish(rule_with_action("create_ticket"))
    replay = await service.replay(EVENT_ID, rule_version_id=v1.id)
    assert replay.rule_version_id == v1.id
    assert replay.planned_actions == ["notify"]
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_automation_versions.py tests/unit/test_automation_event_schema.py`

Expected: FAIL on missing version and event-schema services.

- [ ] **Step 3: Implement immutable definitions and normalized events**

Published versions store canonical definition JSON, digest, event schema version, creator, and publication time. Templates are versioned definitions with parameters and minimum permissions. Event envelopes store organization, event ID, type, schema version, resource identity, occurred/received times, correlation/causation IDs, and a bounded normalized payload.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_automation_versions.py tests/unit/test_automation_event_schema.py tests/unit/test_migration_matches_models.py tests/unit/test_orm_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0105_automation_versions.py backend/app/db/models/canonical.py backend/app/services/automation_versions.py backend/app/services/automation_events.py backend/app/schemas/automation.py backend/tests/unit/test_automation_versions.py backend/tests/unit/test_automation_event_schema.py
git commit -m "feat: version automation rules and events"
```

### Task 2: Nested condition tree and side-effect-free simulator

**Files:**
- Create: `backend/app/services/automation_conditions.py`
- Create: `backend/app/services/automation_simulation.py`
- Modify: `backend/app/services/query_language.py`
- Test: `backend/tests/unit/test_automation_conditions.py`
- Test: `backend/tests/unit/test_automation_simulation.py`

**Interfaces:**
- Consumes: Task 1 event envelopes and rule versions.
- Produces: `ConditionNode`, `EvaluationTrace`, `evaluate_condition()`, and `simulate_rule()`.

- [ ] **Step 1: Write failing null, nesting, and purity tests**

```python
@pytest.mark.parametrize("payload,operator,expected", [
    ({}, "is_missing", True),
    ({"owner": None}, "is_missing", False),
    ({"owner": None}, "is_null", True),
])
def test_missing_and_null_are_distinct(payload, operator, expected):
    assert evaluate_condition(condition("owner", operator), payload).matched is expected

def test_nested_all_any_not_returns_complete_trace():
    result = evaluate_condition(
        {"all": [{"field": "severity", "op": "eq", "value": "critical"},
                 {"not": {"field": "asset.environment", "op": "eq", "value": "dev"}}]},
        {"severity": "critical", "asset": {"environment": "prod"}},
    )
    assert result.matched and len(result.trace.children) == 2

async def test_simulation_never_calls_action_executor(simulator, action_executor):
    await simulator.simulate(rule_with_action("create_ticket"), sample_event())
    action_executor.assert_not_called()
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_automation_conditions.py tests/unit/test_automation_simulation.py`

Expected: FAIL because the condition tree and simulator are absent.

- [ ] **Step 3: Implement pure evaluation and typed traces**

Support `all`, `any`, `not`, equality, inequality, set membership, contains, prefix/suffix, regex with bounded input/pattern, numeric/date comparisons, changed-from/to, missing, null, and existence. Resolve only allowlisted event fields. Simulation returns condition trace, branches, planned actions, approvals, estimated cost, and validation errors without creating execution rows or outbox messages.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_automation_conditions.py tests/unit/test_automation_simulation.py tests/unit/test_automation_rules.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/automation_conditions.py backend/app/services/automation_simulation.py backend/app/services/query_language.py backend/tests/unit/test_automation_conditions.py backend/tests/unit/test_automation_simulation.py
git commit -m "feat: evaluate and simulate automation rules"
```

### Task 3: Broad trigger intake and transactional fan-out

**Files:**
- Create: `backend/app/services/automation_triggers.py`
- Modify: `backend/app/services/automation.py`
- Modify: `backend/app/services/workflow.py`
- Modify: `backend/app/worker/dispatch.py`
- Test: `backend/tests/unit/test_automation_triggers.py`
- Test: `backend/tests/integration/test_automation_event_recovery.py`

**Interfaces:**
- Consumes: lifecycle, asset, sync, ticket, SLA, retest, assessment, engagement, agent, pipeline, intelligence, webhook, and cron domain events.
- Produces: `route_automation_event()`, idempotent rule execution rows, and transactional execution dispatch.

- [ ] **Step 1: Write failing trigger coverage and recovery tests**

```python
EXPECTED_TRIGGERS = {
    "finding.created", "finding.updated", "finding.closed", "asset.changed",
    "integration.sync.completed", "ticket.updated", "sla.warning", "sla.breached",
    "retest.updated", "assessment.completed", "engagement.milestone",
    "agent.run.completed", "pipeline.run.completed", "threat.changed",
    "webhook.received", "cron.fired",
}

def test_trigger_catalog_is_complete():
    assert set(trigger_catalog()) == EXPECTED_TRIGGERS

async def test_restart_after_execution_commit_before_publish_dispatches_once(stack):
    await stack.crash_after_execution_commit()
    await stack.restart_dispatcher()
    assert await stack.dispatch_count() == 1
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_automation_triggers.py tests/integration/test_automation_event_recovery.py`

Expected: FAIL on missing trigger catalog and durable fan-out.

- [ ] **Step 3: Implement trigger adapters and outbox fan-out**

Each domain adapter produces a Task 1 envelope. Routing selects enabled published versions by organization and trigger, evaluates conditions, and commits execution plus outbox in one transaction. Unique `(rule_version_id, event_id)` prevents duplicate logical runs.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_automation_triggers.py tests/integration/test_automation_event_recovery.py tests/unit/test_events.py tests/unit/test_automation_rules.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/automation_triggers.py backend/app/services/automation.py backend/app/services/workflow.py backend/app/worker/dispatch.py backend/tests/unit/test_automation_triggers.py backend/tests/integration/test_automation_event_recovery.py
git commit -m "feat: route expanded automation triggers"
```

### Task 4: Typed action catalog, approvals, and deduplicated effects

**Files:**
- Create: `backend/app/services/automation_actions.py`
- Modify: `backend/app/services/automation.py`
- Modify: `backend/app/services/integration_operations.py`
- Modify: `backend/app/services/agent_action.py`
- Test: `backend/tests/unit/test_automation_actions.py`
- Test: `backend/tests/integration/test_automation_effect_dedup.py`

**Interfaces:**
- Consumes: domain services, connector operations, agent/pipeline runtimes, notifications, reports, compliance, and approvals.
- Produces: typed `AutomationActionSpec`, action catalog, policy/approval planning, and idempotent effect dispatch.

- [ ] **Step 1: Write failing catalog, approval, and cross-rule dedup tests**

```python
EXPECTED_ACTIONS = {
    "assign", "tag", "transition_finding", "request_risk_acceptance", "create_ticket",
    "sync_comment", "notify", "escalate", "request_retest", "start_assessment",
    "generate_report", "run_agent", "run_pipeline", "send_webhook", "attach_compliance_evidence",
}

def test_action_catalog_is_complete_and_schema_bound():
    assert set(action_catalog()) == EXPECTED_ACTIONS
    assert all(spec.input_schema for spec in action_catalog().values())

async def test_two_rules_same_provider_effect_mutate_remote_once(stack):
    await stack.fire_two_matching_rules_same_ticket_transition()
    assert await stack.provider_mutation_count() == 1
    assert await stack.execution_count() == 2

async def test_material_action_requires_exact_payload_approval(stack):
    action = await stack.plan_action("start_assessment", {"target": "app.example"})
    approval = await stack.approve(action)
    await stack.change_payload(action, {"target": "other.example"})
    assert (await stack.dispatch(action, approval)).code == "approval_payload_changed"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_automation_actions.py tests/integration/test_automation_effect_dedup.py`

Expected: FAIL because the typed catalog is absent.

- [ ] **Step 3: Implement action adapters over existing domain services**

Each spec declares input/output schema versions, permission, side-effect class, approval rule, cost estimate, idempotency scope, and executor. External mutations use the connector operation ledger, so separate rules can settle independently while sharing one remote mutation.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_automation_actions.py tests/integration/test_automation_effect_dedup.py tests/unit/test_agent_actions.py tests/unit/test_webhooks.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/automation_actions.py backend/app/services/automation.py backend/app/services/integration_operations.py backend/app/services/agent_action.py backend/tests/unit/test_automation_actions.py backend/tests/integration/test_automation_effect_dedup.py
git commit -m "feat: execute typed automation actions"
```

### Task 5: Branch, delay, throttle, join, stop, budgets, and cancellation

**Files:**
- Modify: `backend/app/db/models/workflow.py`
- Modify: `backend/app/services/workflow.py`
- Create: `backend/app/services/automation_runtime.py`
- Test: `backend/tests/unit/test_automation_runtime.py`
- Test: `backend/tests/integration/test_automation_delay_authority.py`

**Interfaces:**
- Consumes: Tasks 2-4 evaluator, triggers, and action catalog plus shared durable task runtime.
- Produces: branch/delay/throttle/deduplicate/join/stop nodes, budget admission, cancellation, pause-and-settle behavior.

- [ ] **Step 1: Write failing delay, authorization, and disable tests**

```python
async def test_delayed_action_rechecks_expired_authorization(stack):
    run = await stack.start_rule_with_delay(authorization_expires_in=timedelta(minutes=5))
    await stack.advance_clock(minutes=10)
    result = await stack.resume(run.id)
    assert result.code == "authorization_expired"
    assert await stack.external_effect_count(run.id) == 0

async def test_disabling_rule_stops_new_runs_but_settles_committed_run(stack):
    committed = await stack.commit_run_before_disable()
    await stack.disable_rule()
    await stack.fire_new_event()
    assert (await stack.wait_terminal(committed.id)).status == "succeeded"
    assert await stack.new_run_count() == 0

async def test_throttle_window_is_tenant_and_rule_scoped(stack):
    assert await stack.emit_burst(count=100, window="5m") == {"executed": 1, "throttled": 99}
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_automation_runtime.py tests/integration/test_automation_delay_authority.py`

Expected: FAIL on missing expanded runtime nodes.

- [ ] **Step 3: Implement durable control nodes and admission**

Delay stores resume time; throttle and dedup use PostgreSQL uniqueness/locking rather than Redis-only state; join declares all/quorum/best-effort policy; stop records an explicit terminal reason. Revalidate feature state, rule state, permission, authorization, approval, budget, and connector capability immediately before every effect.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_automation_runtime.py tests/integration/test_automation_delay_authority.py tests/unit/test_workflow_runtime.py tests/unit/test_usage_metering.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/db/models/workflow.py backend/app/services/workflow.py backend/app/services/automation_runtime.py backend/tests/unit/test_automation_runtime.py backend/tests/integration/test_automation_delay_authority.py
git commit -m "feat: add durable automation control flow"
```

### Task 6: Versioned API, visual builder, simulation, and operations

**Files:**
- Modify: `backend/app/api/v1/automation.py`
- Modify: `backend/app/graphql/queries.py`
- Modify: `backend/app/graphql/mutations.py`
- Create: `frontend/src/lib/automation-v2.ts`
- Modify: `frontend/src/app/(app)/automation/page.tsx`
- Create: `frontend/src/app/(app)/automation/[id]/page.tsx`
- Create: `frontend/src/components/automation/ConditionTreeEditor.tsx`
- Create: `frontend/src/components/automation/AutomationCanvas.tsx`
- Create: `frontend/src/components/automation/SimulationPanel.tsx`
- Test: `backend/tests/unit/test_automation_v2_api.py`
- Test: `frontend/src/lib/automation-v2.test.ts`

**Interfaces:**
- Consumes: Tasks 1-5 services.
- Produces: draft/validate/simulate/publish/version/enable/pause/replay/cancel/query APIs and accessible visual plus ordered editors.

- [ ] **Step 1: Write failing API and canonicalization tests**

```python
async def test_simulate_endpoint_creates_no_execution_or_outbox_rows(api, db_counts):
    before = await db_counts("automation_executions", "dispatch_outbox")
    response = await api.simulate(rule_definition(), sample_event())
    after = await db_counts("automation_executions", "dispatch_outbox")
    assert response.status_code == 200 and before == after
```

```typescript
it("round-trips canvas and ordered editor through one canonical definition", () => {
  expect(canonicalize(fromOrdered(toOrdered(sampleRule)))).toEqual(canonicalize(sampleRule))
})

it("renders every condition decision and action outcome", () => {
  expect(executionView(sampleExecution).unexplainedSteps).toHaveLength(0)
})
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_automation_v2_api.py`

Run: `npm --prefix frontend test -- automation-v2.test.ts`

Expected: FAIL on missing v2 APIs and builder state.

- [ ] **Step 3: Implement thin APIs and dual-mode builder**

Both editors modify one canonical typed definition. UI exposes validation, effective permissions, required approvals, worst-case cost, sample/historical simulation, immutable version comparison, run trace, attempts, evidence, dead letters, replay, and cancellation. Server responses drive supported actions.

- [ ] **Step 4: Run tests and build**

Run: `cd backend && pytest -q tests/unit/test_automation_v2_api.py tests/unit/test_graphql_schema.py`

Run: `npm --prefix frontend test -- automation-v2.test.ts && npm --prefix frontend run build`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/automation.py backend/app/graphql frontend/src/lib/automation-v2.ts frontend/src/lib/automation-v2.test.ts frontend/src/app/\(app\)/automation frontend/src/components/automation backend/tests/unit/test_automation_v2_api.py
git commit -m "feat: operate expanded automation rules"
```

### Task 7: Production acceptance, templates, and staged rollout

**Files:**
- Create: `backend/tests/integration/test_automation_v2_flow.py`
- Create: `frontend/e2e/automation-builder.spec.ts`
- Create: `infra/gcp/verify-automation.ps1`
- Modify: `backend/app/core/config.py`
- Modify: `infra/gcp/main.tf`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: complete automation slice and all shared domain events/actions.
- Produces: production templates, feature gate, metrics, alerts, canary verification, and rollback exercise.

- [ ] **Step 1: Write failing multi-step production flow**

```python
@pytest.mark.integration
async def test_critical_prod_finding_escalation_and_retest_flow(stack):
    rule = await stack.publish_template("critical-production-remediation")
    run = await stack.emit_finding(severity="critical", environment="prod")
    await stack.approve_material_actions(run)
    await stack.close_created_ticket(run)
    await stack.run_due_work()
    result = await stack.wait_terminal(run.id)
    assert result.status == "succeeded"
    assert result.actions == ["assign", "create_ticket", "notify", "request_retest"]
    assert await stack.condition_and_effect_lineage_complete(run.id)
```

- [ ] **Step 2: Run acceptance**

Run: `cd backend && pytest -q tests/integration/test_automation_v2_flow.py`

Expected: FAIL before template and rollout wiring exist.

- [ ] **Step 3: Add templates, controls, metrics, and alerts**

Ship reviewed templates for critical production remediation, SLA escalation, ticket-closed retest, new internet-facing asset, exploited CVE, engagement milestone, failed integration sync, and report distribution. Add `CYNUX_FEATURES__AUTOMATION_V2`, organization allowlist, stop-new-runs kill switch, and metrics for evaluation, match, branch, action, approval wait, delay, retry, dead letter, budget, and terminal outcome.

- [ ] **Step 4: Run complete verification**

Run: `cd backend && pytest -q tests/unit/test_automation_*.py tests/integration/test_automation_*.py tests/unit/test_workflow_runtime.py`

Run: `npm --prefix frontend run e2e -- automation-builder.spec.ts && terraform -chdir=infra/gcp validate`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_automation_v2_flow.py frontend/e2e/automation-builder.spec.ts infra/gcp/verify-automation.ps1 backend/app/core/config.py infra/gcp/main.tf .github/workflows/ci.yml
git commit -m "ops: roll out expanded automation platform"
```

