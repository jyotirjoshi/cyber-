# Durable Parallel Multi-Agent Orchestrator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute tenant-configured supervisor and specialist agents as durable parallel task graphs with recovery, approvals, evidence, cancellation, and hard budgets.

**Architecture:** Generalize the existing `AgentRun`, specialist task, decision, dispatch outbox, Redis Streams worker, and LangGraph checkpointing. Plans are typed DAGs validated deterministically; each ready task is leased and executed independently with a fresh database session; joins consume bounded structured outputs and evidence references.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy/PostgreSQL, Redis Streams, LangGraph, existing tool registry and usage metering, Next.js/WebSocket events.

**Spec:** `docs/superpowers/specs/2026-10-15-multi-agent-orchestrator-design.md`

## Global Constraints

- Maximum default graph depth is 3, tasks per run 30, and parallel tasks 3.
- Redis messages are acknowledged only after durable terminal settlement.
- Every task attempt has a lease generation; stale results cannot overwrite a newer attempt.
- Each concurrently executing task owns a fresh SQLAlchemy session.
- Model plans cannot bypass schemas, permissions, tool policy, approvals, or budgets.
- Canonical payload digests and idempotency keys protect every external mutation.
- Final output explicitly distinguishes completed, degraded, skipped, failed, rejected, and unverified work.

## Review Focus

- A worker dying after an external provider succeeds but before local commit must retry without duplicating the mutation; Task 4 adds the idempotency recovery test.
- Cancelling a run while children are queued/running must prevent new dispatch and ignore late results; Task 6 adds cancellation tests.
- Two ready tasks sharing a target conflict key must serialize while unrelated tasks remain parallel; Task 5 adds the conflict test.
- Membership or permission revocation while awaiting approval must prevent execution after approval; Task 7 adds revalidation tests.
- A planner that repeatedly proposes rejected or duplicate work must stop within depth/task/token budgets; Task 8 adds the loop-bound test.

---

## File Structure

- `backend/app/db/models/agent_task.py`: generic tasks, dependencies, attempts, evidence, budget reservations.
- `backend/app/schemas/agent_plan.py`: typed plan/task/condition/join contracts.
- `backend/app/services/agent_plan_validator.py`: cycle/schema/policy/budget validation.
- `backend/app/services/agent_scheduler.py`: readiness, dispatch outbox, cancellation, joins.
- `backend/app/services/agent_task_executor.py`: lease, tool/agent execution, settlement.
- `backend/app/services/agent_concurrency.py`: global/tenant/run/provider/target admission.
- `backend/app/services/agent_budget.py`: reservation and metering.
- `backend/app/services/agent_supervisor.py`: bounded planning and decision waves.
- `frontend/src/app/(app)/agent/runs/[runId]/page.tsx`: live DAG and operations.

### Task 1: Generic task persistence and migration

**Files:**
- Create: `backend/alembic/versions/0090_generic_agent_tasks.py`
- Create: `backend/app/db/models/agent_task.py`
- Modify: `backend/app/db/models/agent.py`
- Modify: `backend/app/db/models/__init__.py`
- Test: `backend/tests/unit/test_agent_task_models.py`

**Interfaces:**
- Produces: `AgentTask`, `AgentTaskDependency`, `AgentTaskAttempt`, `AgentEvidence`, `AgentBudgetReservation`.
- Consumes: existing `AgentRun`, tenant and timestamp mixins.

- [ ] **Step 1: Write failing invariants tests**

```python
def test_task_has_unique_run_idempotency_key():
    assert "unique_agent_task_idempotency" in constraint_names(AgentTask)

def test_attempt_lease_generation_is_positive():
    assert "valid_agent_task_attempt_lease" in constraint_names(AgentTaskAttempt)
```

- [ ] **Step 2: Run focused tests**

Run: `cd backend && pytest -q tests/unit/test_agent_task_models.py`
Expected: FAIL on missing models.

- [ ] **Step 3: Implement tables and migration**

Use states `pending`, `blocked`, `ready`, `queued`, `running`, `awaiting_approval`, `completed`, `degraded`, `skipped`, `failed`, `rejected`, `cancelled`; task kinds `agent`, `tool`, `approval`, `join`, `decision`, `finalize`. Dependencies use composite tenant/run validation and unique parent/child pairs.

- [ ] **Step 4: Run model and migration tests**

Run: `cd backend && pytest -q tests/unit/test_agent_task_models.py tests/unit/test_migration_matches_models.py tests/unit/test_orm_models.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0090_generic_agent_tasks.py backend/app/db/models/agent_task.py backend/app/db/models/agent.py backend/app/db/models/__init__.py backend/tests/unit/test_agent_task_models.py
git commit -m "feat: persist generic agent task graphs"
```

### Task 2: Typed DAG plan and deterministic validator

**Files:**
- Create: `backend/app/schemas/agent_plan.py`
- Create: `backend/app/services/agent_plan_validator.py`
- Test: `backend/tests/unit/test_agent_plan_validator.py`

**Interfaces:**
- Produces: `AgentPlan`, `AgentPlanTask`, `ValidatedAgentPlan`, `validate_plan(plan, context)`.
- Consumes: tool registry, agent definitions, asset scope, budgets.

- [ ] **Step 1: Write failing table-driven validator tests**

```python
@pytest.mark.parametrize("plan,code", [
    (cyclic_plan(), "plan_cycle"),
    (unknown_tool_plan(), "unknown_tool"),
    (depth_four_plan(), "plan_depth_exceeded"),
    (thirty_one_task_plan(), "task_limit_exceeded"),
    (foreign_asset_plan(), "resource_not_found"),
])
def test_invalid_plans_are_rejected(plan, code, context):
    with pytest.raises(PlanValidationError) as exc:
        validate_plan(plan, context)
    assert exc.value.code == code
```

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_plan_validator.py`
Expected: FAIL on missing validator.

- [ ] **Step 3: Implement schemas, topological sort, depth/count/schema/policy validation**

```python
class AgentPlanTask(BaseModel):
    key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")]
    kind: TaskKind
    depends_on: list[str] = Field(default_factory=list, max_length=30)
    input: dict[str, JsonValue] = Field(default_factory=dict)
    required: bool = True

def validate_plan(plan: AgentPlan, context: PlanValidationContext) -> ValidatedAgentPlan:
    order = stable_topological_sort(plan.tasks)
    enforce_depth(order, maximum=3)
    return validate_authority_and_budgets(plan, order, context)
```

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_agent_plan_validator.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/schemas/agent_plan.py backend/app/services/agent_plan_validator.py backend/tests/unit/test_agent_plan_validator.py
git commit -m "feat: validate bounded agent task plans"
```

### Task 3: Plan materialization and readiness scheduler

**Files:**
- Create: `backend/app/services/agent_scheduler.py`
- Modify: `backend/app/worker/dispatch.py`
- Test: `backend/tests/unit/test_agent_scheduler.py`

**Interfaces:**
- Produces: `materialize_plan`, `release_ready_tasks`, `settle_join`, `cancel_run_tasks`.
- Consumes: `ValidatedAgentPlan`, dispatch outbox, task models.

- [ ] **Step 1: Write failing scheduling tests**

```python
@pytest.mark.asyncio
async def test_only_dependency_free_tasks_are_released(session):
    run = await materialize_plan(session, validated_fanout_plan())
    released = await release_ready_tasks(session, run.id)
    assert [task.key for task in released] == ["triage", "intel", "asset"]
    assert await task_status(session, run.id, "join") == "blocked"
```

Test all/quorum/best-effort joins, conditions, duplicate scheduler invocations, and tenant scope.

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_scheduler.py`
Expected: FAIL on missing scheduler.

- [ ] **Step 3: Implement idempotent materialization and `FOR UPDATE SKIP LOCKED` readiness**

```python
async def release_ready_tasks(session, run_id):
    tasks = await lock_pending_tasks(session, run_id)
    ready = [task for task in tasks if dependencies_satisfied(task)]
    for task in ready:
        task.status = "ready"
        ensure_task_dispatch(session, task)
    return ready
```

- [ ] **Step 4: Run scheduler/outbox tests**

Run: `cd backend && pytest -q tests/unit/test_agent_scheduler.py tests/unit/test_worker_queue.py -k dispatch`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/agent_scheduler.py backend/app/worker/dispatch.py backend/tests/unit/test_agent_scheduler.py
git commit -m "feat: schedule durable agent DAG tasks"
```

### Task 4: Task leases, execution, settlement, and crash recovery

**Files:**
- Create: `backend/app/services/agent_task_executor.py`
- Modify: `backend/app/worker/protocol.py`
- Modify: `backend/app/worker/worker.py`
- Test: `backend/tests/unit/test_agent_task_executor.py`

**Interfaces:**
- Produces: `claim_task`, `heartbeat_task`, `execute_task`, `settle_task`, `recover_stale_tasks`.
- Consumes: tool registry, agent runtime, fresh session factory, scheduler.

- [ ] **Step 1: Write failing recovery/idempotency tests**

```python
@pytest.mark.asyncio
async def test_provider_success_before_crash_is_not_duplicated(executor, idempotent_provider):
    await executor.execute_then_crash(task_id, after="provider_success")
    await executor.recover_and_execute(task_id)
    assert idempotent_provider.mutation_count == 1
    assert await terminal_status(task_id) == "completed"

async def test_old_lease_cannot_settle_after_reclaim(session, reclaimed_task, late_result):
    assert await settle_task(task_id, lease=1, result=late_result) is False
```

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_task_executor.py`
Expected: FAIL on missing executor.

- [ ] **Step 3: Implement lease-generation protocol and fresh-session execution**

```python
async def execute_task(task_id: UUID, session_factory: async_sessionmaker):
    async with session_factory() as claim_session:
        claim = await claim_task(claim_session, task_id)
        await claim_session.commit()
    result = await execute_with_idempotency(claim)
    async with session_factory() as settle_session:
        await settle_task(settle_session, claim, result)
        await settle_session.commit()
```

- [ ] **Step 4: Run executor and worker tests**

Run: `cd backend && pytest -q tests/unit/test_agent_task_executor.py tests/unit/test_worker_queue.py -k "lease or recover or ack"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/agent_task_executor.py backend/app/worker/protocol.py backend/app/worker/worker.py backend/tests/unit/test_agent_task_executor.py
git commit -m "feat: execute recoverable agent tasks"
```

### Task 5: Multi-dimensional concurrency admission

**Files:**
- Create: `backend/app/services/agent_concurrency.py`
- Modify: `backend/app/core/redis_client.py`
- Test: `backend/tests/unit/test_agent_concurrency.py`

**Interfaces:**
- Produces: `ConcurrencyRequest`, `ConcurrencyLease`, `admit_task`, `release_task`.
- Consumes: Redis Lua execution and organization entitlements.

- [ ] **Step 1: Write failing atomic admission tests**

```python
@pytest.mark.asyncio
async def test_same_conflict_key_serializes_but_other_targets_run(admission):
    first = await admission.acquire(req(target="asset:1"))
    assert not await admission.try_acquire(req(target="asset:1"))
    assert await admission.try_acquire(req(target="asset:2"))
    await first.release()
```

Test global, tenant, run, provider and TTL recovery under concurrent callers.

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_concurrency.py`
Expected: FAIL on missing admission service.

- [ ] **Step 3: Implement one atomic Redis Lua admission/release operation**

```python
@dataclass(frozen=True)
class ConcurrencyRequest:
    organization_id: UUID
    run_id: UUID
    provider: str | None
    conflict_key: str | None
    ttl_seconds: int
```

The Lua script increments all counters only if every ceiling and conflict lock can be acquired; release validates a random lease token.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_agent_concurrency.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/agent_concurrency.py backend/app/core/redis_client.py backend/tests/unit/test_agent_concurrency.py
git commit -m "feat: bound parallel agent execution"
```

### Task 6: Cancellation propagation

**Files:**
- Modify: `backend/app/services/agent_scheduler.py`
- Modify: `backend/app/services/agent_task_executor.py`
- Modify: `backend/app/api/v1/agent.py`
- Test: `backend/tests/unit/test_agent_cancellation.py`

**Interfaces:**
- Produces: `cancel_agent_run`, cancellation checks and provider/scanner cancellation adapters.
- Consumes: current run/task leases and existing job cancellation.

- [ ] **Step 1: Write failing cancellation race tests**

```python
@pytest.mark.asyncio
async def test_cancel_prevents_new_dispatch_and_late_settlement(session):
    await cancel_agent_run(session, owner, run.id)
    assert await release_ready_tasks(session, run.id) == []
    assert not await settle_task(session, old_claim, successful_result())
    assert await all_nonterminal_tasks_are_cancelled(session, run.id)
```

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_cancellation.py`
Expected: FAIL because generic cancellation is absent.

- [ ] **Step 3: Implement locked parent cancellation and cooperative executor checks**

Use one transaction to mark run cancellation, cancel undispatched tasks, set cancellation requests on running tasks, invalidate pending approvals, and enqueue provider/scanner cancellation after commit.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_agent_cancellation.py tests/unit/test_worker_queue.py -k cancel`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/agent_scheduler.py backend/app/services/agent_task_executor.py backend/app/api/v1/agent.py backend/tests/unit/test_agent_cancellation.py
git commit -m "feat: propagate agent run cancellation"
```

### Task 7: Approval and authority revalidation

**Files:**
- Modify: `backend/app/services/agent_action.py`
- Modify: `backend/app/services/approval.py`
- Modify: `backend/app/services/agent_task_executor.py`
- Test: `backend/tests/unit/test_agent_task_approvals.py`

**Interfaces:**
- Produces: approval-task creation and exact-payload execution revalidation.
- Consumes: effective tool policy and existing approval/action digests.

- [ ] **Step 1: Write failing revocation and payload tests**

```python
@pytest.mark.asyncio
async def test_permission_revoked_after_approval_prevents_execution(session):
    approval = await approve_task_action(session, owner, task)
    await demote_user(session, owner.user_id, Role.READER)
    with pytest.raises(AuthorizationError):
        await execute_approved_task(session, approval.id)
    assert provider.calls == 0
```

Also test expired approval, changed organization policy, changed payload digest, and bounded autonomy mandatory classes.

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_task_approvals.py`
Expected: FAIL on missing task approval binding.

- [ ] **Step 3: Bind approvals to run/task/agent/tool/payload and revalidate current authority**

```python
assert approval.payload_digest == task.payload_digest
effective = resolve_effective_tools(current_principal, task.agent_version, current_org_policy)
effective.require(task.tool_name, payload=task.input)
```

- [ ] **Step 4: Run approval suites**

Run: `cd backend && pytest -q tests/unit/test_agent_task_approvals.py tests/unit/test_agent_actions.py tests/unit/test_approval.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/agent_action.py backend/app/services/approval.py backend/app/services/agent_task_executor.py backend/tests/unit/test_agent_task_approvals.py
git commit -m "feat: enforce agent task approvals"
```

### Task 8: Budgets, supervisor planning, and bounded decision waves

**Files:**
- Create: `backend/app/services/agent_budget.py`
- Create: `backend/app/services/agent_supervisor.py`
- Modify: `backend/app/services/agent_planner.py`
- Modify: `backend/app/services/usage_metering.py`
- Test: `backend/tests/unit/test_agent_supervisor.py`

**Interfaces:**
- Produces: `reserve_budget`, `settle_usage`, `plan_objective`, `decide_next_wave`, deterministic stop reasons.
- Consumes: LLM gateway, plan validator, evidence summaries, usage meter.

- [ ] **Step 1: Write failing budget/loop tests**

```python
@pytest.mark.asyncio
async def test_duplicate_rejected_proposals_stop_within_budget(supervisor):
    result = await supervisor.run(model=repeating_model(), budget=budget(tasks=5, depth=2))
    assert result.stop_reason == "no_valid_next_action"
    assert result.task_count <= 5

async def test_exhausted_budget_cancels_undispatched_and_finalizes_partial(supervisor, exhausted_budget):
    assert result.stop_reason == "budget_exhausted"
    assert result.evidence_summary
```

- [ ] **Step 2: Verify failure**

Run: `cd backend && pytest -q tests/unit/test_agent_supervisor.py`
Expected: FAIL on missing budget/supervisor services.

- [ ] **Step 3: Implement atomic reservations and schema-bound supervisor output**

```python
class SupervisorDecision(BaseModel):
    hypothesis: Annotated[str | None, Field(max_length=2000)] = None
    tasks: list[AgentPlanTask] = Field(default_factory=list, max_length=10)
    stop_reason: StopReason | None = None
```

Subtract reservations before dispatch, reconcile actual usage at settlement, and never let the model raise limits.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_agent_supervisor.py tests/unit/test_usage_metering.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/agent_budget.py backend/app/services/agent_supervisor.py backend/app/services/agent_planner.py backend/app/services/usage_metering.py backend/tests/unit/test_agent_supervisor.py
git commit -m "feat: add budgeted multi-agent supervisor"
```

### Task 9: Run APIs, live events, and DAG interface

**Files:**
- Modify: `backend/app/api/v1/agent.py`
- Modify: `backend/app/api/ws/agent.py`
- Modify: `backend/app/services/events.py`
- Create: `frontend/src/app/(app)/agent/runs/[runId]/page.tsx`
- Create: `frontend/src/components/agent/RunDag.tsx`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`
- Test: `frontend/src/lib/agent-run-dag.test.ts`
- Test: `backend/tests/unit/test_agent_run_events.py`

**Interfaces:**
- Produces: create/get/cancel/retry/approve run endpoints and resumable sequenced events.
- Consumes: scheduler/supervisor/task state.

- [ ] **Step 1: Write failing replay and DAG view-model tests**

```python
async def test_reconnect_replays_only_events_after_cursor(events):
    assert [e.seq for e in await events.after(run.id, 2)] == [3, 4]
```

```typescript
it("orders tasks topologically and preserves parallel lanes", () => {
  expect(layoutDag(fanoutRun).lanes).toEqual([["triage", "intel", "asset"], ["join"], ["finalize"]]);
});
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_agent_run_events.py` and `npm --prefix frontend test -- agent-run-dag.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement thin APIs, durable replay, live subscription, and run UI**

The UI displays every outcome/degradation, evidence link, retry, approval, cost/token counter, cancellation status, and final stop reason; it never infers success from missing events.

- [ ] **Step 4: Run backend/frontend tests and build**

Run: `cd backend && pytest -q tests/unit/test_agent_run_events.py`

Run: `npm --prefix frontend test -- agent-run-dag.test.ts && npm --prefix frontend run build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/agent.py backend/app/api/ws/agent.py backend/app/services/events.py frontend/src/app/\(app\)/agent/runs frontend/src/components/agent/RunDag.tsx frontend/src/lib/api.ts frontend/src/lib/types.ts frontend/src/lib/agent-run-dag.test.ts backend/tests/unit/test_agent_run_events.py
git commit -m "feat: expose live multi-agent runs"
```

### Task 10: Recovery, load, and production rollout

**Files:**
- Modify: `backend/app/core/config.py`
- Modify: `infra/gcp/main.tf`
- Modify: `infra/gcp/verify.ps1`
- Create: `backend/tests/integration/test_multi_agent_recovery.py`
- Create: `frontend/e2e/multi-agent-run.spec.ts`

**Interfaces:**
- Produces: feature flag, capacity settings, production acceptance probe.
- Consumes: all prior tasks.

- [ ] **Step 1: Write failing restart/load acceptance tests**

```python
@pytest.mark.integration
async def test_parallel_run_survives_worker_restart(stack):
    run = await stack.start_run(fanout_objective())
    await stack.kill_worker_during("intel")
    await stack.restart_worker()
    result = await stack.wait_terminal(run.id)
    assert result.status == "completed"
    assert stack.external_mutations == expected_unique_mutations
```

- [ ] **Step 2: Run and confirm rollout wiring is absent**

Run: `cd backend && pytest -q tests/integration/test_multi_agent_recovery.py`
Expected: FAIL before flags/capacity/recovery verification exist.

- [ ] **Step 3: Add configuration, metrics, alerts, and staged rollout**

Add `CYNUX_FEATURES__MULTI_AGENT`, task/depth/parallel/default runtime ceilings, Redis admission TTLs, provider ceilings, worker max concurrency, stale lease alerts, queue latency alert, cost meter linkage, and a canary organization allowlist.

- [ ] **Step 4: Run complete verification**

Run: `cd backend && pytest -q tests/unit/test_agent_task_models.py tests/unit/test_agent_plan_validator.py tests/unit/test_agent_scheduler.py tests/unit/test_agent_task_executor.py tests/unit/test_agent_concurrency.py tests/unit/test_agent_cancellation.py tests/unit/test_agent_task_approvals.py tests/unit/test_agent_supervisor.py tests/unit/test_agent_run_events.py tests/integration/test_multi_agent_recovery.py`

Run: `npm --prefix frontend test && npm --prefix frontend run build && npm --prefix frontend run e2e -- multi-agent-run.spec.ts`

Expected: selected suites pass. Run the full suites and report all baseline failures before canary enablement.

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/config.py infra/gcp backend/tests/integration/test_multi_agent_recovery.py frontend/e2e/multi-agent-run.spec.ts
git commit -m "ops: roll out durable multi-agent execution"
```
