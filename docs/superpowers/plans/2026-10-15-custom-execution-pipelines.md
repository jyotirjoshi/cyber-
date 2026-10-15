# Custom Execution Pipelines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let tenants build, publish, trigger, observe, and safely operate durable typed execution pipelines combining queries, conditions, agents, tools, approvals, integrations, and isolated Python transformations.

**Architecture:** Store organization-scoped pipeline identities and immutable versions in PostgreSQL. Validate definitions into acyclic typed DAGs, ingest triggers through the transactional outbox, and reuse the generic leased-task scheduler from the multi-agent phase. Run customer Python only in a scale-to-zero Cloud Run Job with KMS-bound one-time inputs/secrets and strict network, runtime, resource, and cost policy.

**Tech Stack:** FastAPI, SQLAlchemy 2, PostgreSQL, Alembic, Redis, JSON Schema 2020-12, Cloud Run Jobs, Cloud KMS, Artifact Registry, GCS, Terraform, Next.js/React.

**Spec:** `docs/superpowers/specs/2026-10-15-custom-execution-pipelines-design.md`

## Global Constraints

- Pipeline drafts are mutable; published versions referenced by runs are immutable.
- Every model, query, join, event, object key, KMS context, and task carries `organization_id`.
- First release DAGs are acyclic, maximum 25 nodes, four parallel branches, ten minutes per code step, and one hour per run unless a lower entitlement applies.
- Trigger delivery and every externally visible mutation use stable idempotency keys.
- Built-in integration operations use the tool registry; customer code receives no direct platform credentials.
- Customer Python never runs in the API, general worker, scheduler, or migration process.
- Custom code has no network by default and cannot access metadata, private, loopback, link-local, or undeclared destinations.
- Cost cutoff, tenant budget, and pipeline budget are enforced before dispatch and reconciled after settlement.

## Review Focus

- Redirects, DNS rebinding, mixed public/private answers, and alternate numeric IP formats must not bypass destination policy; Task 8 adds network-policy tests.
- Duplicate event or API delivery must create one logical run and one external mutation; Tasks 3 and 4 add idempotency tests.
- Invalid node input/output must fail before downstream steps are released; Task 5 adds schema-boundary tests.
- A crashed or cancelled code job must not leave a readable secret envelope; Task 8 adds cleanup/reaper tests.
- Deployment or tenant cost exhaustion must reject new jobs before Cloud Run launch; Task 9 adds hard-cutoff tests.

---

## File Structure

- `backend/app/db/models/pipeline.py`: identities, immutable versions, triggers, code artifacts, runs, steps, events, and usage.
- `backend/app/schemas/pipeline.py`: typed draft/version/node/edge/trigger/run contracts.
- `backend/app/services/pipeline_definition.py`: draft, validate, test, publish, version, pause.
- `backend/app/services/pipeline_validator.py`: deterministic DAG/schema/authority/budget validation.
- `backend/app/services/pipeline_trigger.py`: outbox/manual/cron/webhook intake and deduplication.
- `backend/app/services/pipeline_runtime.py`: materialization, scheduling, settlement, recovery.
- `backend/app/services/pipeline_nodes.py`: declarative node executors.
- `backend/app/services/pipeline_code.py`: artifact validation/build lifecycle.
- `backend/app/services/pipeline_network.py`: exact destination resolution and revalidation.
- `backend/app/services/pipeline_cloud_run.py`: job launch/cancel/settle adapter.
- `frontend/src/app/(app)/pipelines/*`: catalog, builder, versions, tests, and live run operations.

### Task 1: Pipeline persistence, immutable versions, and migration

**Files:**
- Create: `backend/alembic/versions/0092_custom_execution_pipelines.py`
- Create: `backend/app/db/models/pipeline.py`
- Modify: `backend/app/db/models/__init__.py`
- Create: `backend/app/schemas/pipeline.py`
- Test: `backend/tests/unit/test_pipeline_models.py`
- Test: `backend/tests/unit/test_migration_matches_models.py`

**Interfaces:**
- Produces: `Pipeline`, `PipelineDraft`, `PipelineVersion`, `PipelineTrigger`, `PipelineRun`, `PipelineStep`, `PipelineStepAttempt`, `PipelineCodeArtifact`, `PipelineUsage`.
- Consumes: tenant/timestamp mixins, generic task protocol identifiers, audit IDs.

- [ ] **Step 1: Write failing persistence invariant tests**

```python
def test_published_version_digest_is_unique_per_pipeline():
    assert "unique_pipeline_version_number" in constraint_names(PipelineVersion)
    assert "unique_pipeline_configuration_digest" in constraint_names(PipelineVersion)

def test_event_deduplication_is_scoped_to_version():
    assert "unique_pipeline_version_event" in constraint_names(PipelineRun)
```

- [ ] **Step 2: Run focused tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_models.py tests/unit/test_migration_matches_models.py`
Expected: FAIL because models and revision `0092` are absent.

- [ ] **Step 3: Implement tables, constraints, retention references, and typed schemas**

```python
class PipelineNode(BaseModel):
    key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,79}$")]
    kind: PipelineNodeKind
    input_schema: dict[str, JsonValue]
    output_schema: dict[str, JsonValue]
    config: dict[str, JsonValue]
    failure_policy: FailurePolicy
```

Use unique organization-qualified foreign keys and indexes for active triggers, recent runs, ready steps, and artifact hashes. Published versions cannot cascade-delete while runs reference them.

- [ ] **Step 4: Run model/migration tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_models.py tests/unit/test_migration_matches_models.py tests/unit/test_orm_models.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0092_custom_execution_pipelines.py backend/app/db/models/pipeline.py backend/app/db/models/__init__.py backend/app/schemas/pipeline.py backend/tests/unit/test_pipeline_models.py backend/tests/unit/test_migration_matches_models.py
git commit -m "feat: persist versioned execution pipelines"
```

### Task 2: Deterministic definition and publish validator

**Files:**
- Create: `backend/app/services/pipeline_validator.py`
- Create: `backend/app/services/pipeline_definition.py`
- Test: `backend/tests/unit/test_pipeline_validator.py`
- Test: `backend/tests/unit/test_pipeline_definition.py`

**Interfaces:**
- Produces: `validate_pipeline`, `save_draft`, `test_draft`, `publish_version`, `pause_triggers`.
- Consumes: JSON Schema validator, tool/agent registry, persisted operation registry, tenant entitlements.

- [ ] **Step 1: Write failing table-driven validation tests**

```python
@pytest.mark.parametrize("definition,code", [
    (cyclic_definition(), "pipeline_cycle"),
    (twenty_six_nodes(), "node_limit_exceeded"),
    (five_parallel_branches(), "parallel_limit_exceeded"),
    (unknown_tool(), "unknown_tool"),
    (foreign_agent_version(), "resource_not_found"),
    (incompatible_edge_schemas(), "schema_incompatible"),
])
def test_invalid_pipeline_cannot_publish(definition, code, context):
    with pytest.raises(PipelineValidationError) as exc:
        validate_pipeline(definition, context)
    assert exc.value.code == code
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_validator.py tests/unit/test_pipeline_definition.py`
Expected: FAIL on missing validator/services.

- [ ] **Step 3: Implement stable topological validation and immutable publishing**

```python
async def publish_version(session, principal, pipeline_id, expected_draft_revision):
    draft = await locked_tenant_draft(session, principal.organization_id, pipeline_id)
    require_revision(draft, expected_draft_revision)
    validated = validate_pipeline(draft.definition, build_context(principal))
    version = PipelineVersion.from_validated(validated, digest=canonical_digest(validated))
    session.add(version)
    return version
```

Validate node configuration and JSON Schemas, stable graph ordering, authority, worst-case nodes/branches/duration/cost, trigger schema, referenced immutable versions, and failure branches.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_validator.py tests/unit/test_pipeline_definition.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_validator.py backend/app/services/pipeline_definition.py backend/tests/unit/test_pipeline_validator.py backend/tests/unit/test_pipeline_definition.py
git commit -m "feat: validate and publish pipeline definitions"
```

### Task 3: Trigger intake, transactional outbox, cron, and webhook events

**Files:**
- Create: `backend/app/services/pipeline_trigger.py`
- Create: `backend/app/services/pipeline_cron.py`
- Modify: `backend/app/services/outbox.py`
- Modify: `backend/app/api/v1/webhooks.py`
- Test: `backend/tests/unit/test_pipeline_triggers.py`
- Test: `backend/tests/unit/test_pipeline_cron.py`

**Interfaces:**
- Produces: manual/API, cron, domain-event, sync, ticket, SLA, retest, assessment, agent, and webhook trigger envelopes.
- Consumes: transactional outbox, organization timezone, event schema registry, idempotency store.

- [ ] **Step 1: Write failing duplicate/DST/filter tests**

```python
@pytest.mark.asyncio
async def test_duplicate_domain_event_creates_one_logical_run(session):
    await ingest_pipeline_event(session, event(id="evt-1"))
    await ingest_pipeline_event(session, event(id="evt-1"))
    assert await run_count_for_event(session, "evt-1") == 1

def test_fall_back_cron_has_deterministic_single_fire(cron):
    fires = cron.between("2026-11-01T00:00Z", "2026-11-02T00:00Z", timezone="America/New_York")
    assert unique_utc(fires)
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_triggers.py tests/unit/test_pipeline_cron.py`
Expected: FAIL because trigger intake is absent.

- [ ] **Step 3: Implement typed event registry and deduplicated run creation**

```python
class TriggerEnvelope(BaseModel):
    event_id: str
    event_type: TriggerEventType
    schema_version: int
    occurred_at: AwareDatetime
    organization_id: UUID
    payload: dict[str, JsonValue]
```

Evaluate declarative filters against the versioned event schema. Store timezone and UTC fire key; define spring-forward skip and fall-back de-duplication explicitly. Manual starts bind organization, version, actor, and input digest to the idempotency key.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_triggers.py tests/unit/test_pipeline_cron.py tests/unit/test_outbox.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_trigger.py backend/app/services/pipeline_cron.py backend/app/services/outbox.py backend/app/api/v1/webhooks.py backend/tests/unit/test_pipeline_triggers.py backend/tests/unit/test_pipeline_cron.py
git commit -m "feat: trigger pipelines idempotently"
```

### Task 4: Durable run materialization, scheduling, and recovery

**Files:**
- Create: `backend/app/services/pipeline_runtime.py`
- Modify: `backend/app/services/agent_scheduler.py`
- Modify: `backend/app/services/agent_task_executor.py`
- Modify: `backend/app/worker/protocol.py`
- Modify: `backend/app/worker/worker.py`
- Test: `backend/tests/unit/test_pipeline_runtime.py`
- Test: `backend/tests/integration/test_pipeline_recovery.py`

**Interfaces:**
- Produces: `materialize_pipeline_run`, `release_pipeline_steps`, `execute_pipeline_step`, `settle_pipeline_step`, `recover_pipeline_steps`.
- Consumes: immutable version, generic task lease/attempt protocol, concurrency admission, outbox.

- [ ] **Step 1: Write failing recovery and exactly-once-effect tests**

```python
@pytest.mark.integration
async def test_duplicate_delivery_and_worker_crash_produce_one_external_mutation(stack):
    await stack.deliver_twice("evt-1")
    await stack.crash_worker_after_provider_success()
    await stack.recover()
    assert stack.external_mutations == 1
    assert await stack.logical_run_count("evt-1") == 1
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_runtime.py tests/integration/test_pipeline_recovery.py`
Expected: FAIL on absent pipeline runtime.

- [ ] **Step 3: Adapt the generic leased-task protocol without forking semantics**

```python
async def execute_pipeline_step(step_id: UUID, session_factory):
    claim = await claim_generic_task(step_id, task_type="pipeline_step")
    result = await pipeline_node_registry.execute(claim.kind, claim.input, claim.idempotency_key)
    await settle_generic_task(claim, result)
```

Materialization must be idempotent. Every provider/tool mutation gets a stable key derived from run/version/node/attempt policy. A stale lease cannot settle or release successors.

- [ ] **Step 4: Run runtime/recovery tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_runtime.py tests/integration/test_pipeline_recovery.py tests/unit/test_agent_task_executor.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_runtime.py backend/app/services/agent_scheduler.py backend/app/services/agent_task_executor.py backend/app/worker/protocol.py backend/app/worker/worker.py backend/tests/unit/test_pipeline_runtime.py backend/tests/integration/test_pipeline_recovery.py
git commit -m "feat: execute recoverable pipeline runs"
```

### Task 5: Typed query, filter, mapping, parallel, join, delay, and emit nodes

**Files:**
- Create: `backend/app/services/pipeline_nodes.py`
- Create: `backend/app/services/pipeline_mapping.py`
- Create: `backend/app/services/pipeline_schema.py`
- Test: `backend/tests/unit/test_pipeline_nodes.py`
- Test: `backend/tests/unit/test_pipeline_schema_boundaries.py`

**Interfaces:**
- Produces: built-in declarative node executors and JSON-schema boundary validation.
- Consumes: persisted GraphQL/domain queries, notification/webhook/report services, scheduler.

- [ ] **Step 1: Write failing schema-boundary and mapping tests**

```python
@pytest.mark.asyncio
async def test_invalid_output_stops_before_downstream_release(runtime):
    await runtime.execute_node(produces={"risk": "not-a-number"}, output_schema=number_schema())
    assert await runtime.node_status("producer") == "failed"
    assert await runtime.node_status("consumer") == "blocked"

def test_mapping_cannot_read_undeclared_context(mapping):
    with pytest.raises(PipelineMappingError, match="unknown_path"):
        mapping.evaluate("$.platform.secrets.api_key", declared_input())
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_nodes.py tests/unit/test_pipeline_schema_boundaries.py`
Expected: FAIL on missing node registry and validators.

- [ ] **Step 3: Implement bounded declarative executors**

```python
@node_registry.register("filter")
async def filter_node(context: NodeContext, config: FilterConfig, value: JsonValue) -> NodeResult:
    validate_json(value, context.input_schema)
    matched = evaluate_condition(config.condition, value, max_operations=100)
    return NodeResult(output={"matched": matched, "value": value})
```

Use a small allowlisted mapping expression set with bounded recursion and operations. Validate input before execution and output before persistence/release. Delay stores `resume_at`; it never sleeps a worker.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_nodes.py tests/unit/test_pipeline_schema_boundaries.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_nodes.py backend/app/services/pipeline_mapping.py backend/app/services/pipeline_schema.py backend/tests/unit/test_pipeline_nodes.py backend/tests/unit/test_pipeline_schema_boundaries.py
git commit -m "feat: add typed declarative pipeline nodes"
```

### Task 6: Agent, tool, and exact-payload approval nodes

**Files:**
- Modify: `backend/app/services/pipeline_nodes.py`
- Modify: `backend/app/services/approval.py`
- Modify: `backend/app/services/agent_task_executor.py`
- Test: `backend/tests/unit/test_pipeline_agent_tool_nodes.py`
- Test: `backend/tests/unit/test_pipeline_approvals.py`

**Interfaces:**
- Produces: immutable agent invocation, registry tool execution, approval-gated continuation.
- Consumes: custom agent versions, generic orchestrator, tool policy, approval service.

- [ ] **Step 1: Write failing authority/payload tests**

```python
async def test_approval_cannot_authorize_changed_downstream_payload(runtime):
    approval = await runtime.request_approval(payload={"ticket": "A"})
    await runtime.approve(approval.id)
    await runtime.replace_step_input({"ticket": "B"})
    with pytest.raises(ApprovalInvalid, match="payload_digest_changed"):
        await runtime.resume()

async def test_agent_version_is_pinned_for_run(runtime):
    run = await runtime.start(agent_version=1)
    await publish_agent_version(2)
    assert (await run.agent_result()).agent_version == 1
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_agent_tool_nodes.py tests/unit/test_pipeline_approvals.py`
Expected: FAIL on missing adapters/binding.

- [ ] **Step 3: Implement immutable references and execution-time reauthorization**

Bind approvals to organization, pipeline version, run, step, tool/agent version, input digest, expiry, approver, and current policy revision. Recheck permission and organization policy immediately before dispatch.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_agent_tool_nodes.py tests/unit/test_pipeline_approvals.py tests/unit/test_agent_task_approvals.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_nodes.py backend/app/services/approval.py backend/app/services/agent_task_executor.py backend/tests/unit/test_pipeline_agent_tool_nodes.py backend/tests/unit/test_pipeline_approvals.py
git commit -m "feat: compose agents tools and approvals in pipelines"
```

### Task 7: Code upload, validation, deterministic artifact, and test-run gate

**Files:**
- Create: `backend/app/services/pipeline_code.py`
- Create: `backend/app/services/pipeline_dependency_catalog.py`
- Create: `backend/executor/runner.py`
- Create: `backend/executor/Dockerfile`
- Create: `backend/executor/requirements.lock`
- Test: `backend/tests/unit/test_pipeline_code.py`
- Test: `backend/executor/tests/test_runner.py`

**Interfaces:**
- Produces: validated `run(context, input)` packages, immutable artifact/lock hashes, private artifact objects, mandatory test-run result.
- Consumes: object storage, malware/secret scanners, approved dependency catalog, Artifact Registry build service.

- [ ] **Step 1: Write failing package and runner tests**

```python
@pytest.mark.parametrize("source,code", [
    ("import subprocess", "forbidden_import"),
    ("eval(input['x'])", "forbidden_call"),
    ("def nope(): pass", "missing_entrypoint"),
])
def test_unsafe_package_is_rejected(source, code):
    with pytest.raises(CodeValidationError) as exc:
        validate_source(source, approved_lock())
    assert exc.value.code == code

def test_runner_rejects_oversized_output(tmp_path):
    assert run_package(large_output_package(), output_limit=1_000_000).code == "output_limit_exceeded"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_code.py executor/tests/test_runner.py`
Expected: FAIL because code lifecycle/executor image are absent.

- [ ] **Step 3: Implement deterministic artifact lifecycle and minimal runner**

```python
def execute(package: Path, input_path: Path, output_path: Path, context: dict) -> None:
    module = load_verified_module(package)
    result = module.run(read_json(context), read_json(input_path))
    validate_json(result, read_output_schema(package))
    write_json_bounded(output_path, result, MAX_OUTPUT_BYTES)
```

Reject dynamic imports, undeclared files, native extensions, installation hooks, and dependencies outside the approved pinned catalog. Scan source and lockfile, hash canonical package/lock, build or reuse by hash, store privately, and require a passing isolated test run before publish.

- [ ] **Step 4: Run tests and build executor image locally**

Run: `cd backend && pytest -q tests/unit/test_pipeline_code.py executor/tests/test_runner.py`

Run: `docker build -f backend/executor/Dockerfile backend/executor`
Expected: tests PASS and image runs as a non-root user with read-only root filesystem expectations.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_code.py backend/app/services/pipeline_dependency_catalog.py backend/executor backend/tests/unit/test_pipeline_code.py
git commit -m "feat: package isolated pipeline transformations"
```

### Task 8: Destination policy, KMS secret envelopes, and Cloud Run Job adapter

**Files:**
- Create: `backend/app/services/pipeline_network.py`
- Create: `backend/app/services/pipeline_secret_envelope.py`
- Create: `backend/app/services/pipeline_cloud_run.py`
- Create: `backend/app/services/pipeline_envelope_reaper.py`
- Modify: `infra/gcp/main.tf`
- Modify: `infra/gcp/variables.tf`
- Test: `backend/tests/unit/test_pipeline_network.py`
- Test: `backend/tests/unit/test_pipeline_secret_envelope.py`
- Test: `backend/tests/unit/test_pipeline_cloud_run.py`

**Interfaces:**
- Produces: verified exact HTTPS destinations, one-time step envelopes, least-privilege Cloud Run launches/cancellation/settlement, cleanup reaper.
- Consumes: Cloud DNS resolution, KMS, private GCS, Cloud Run Jobs, credential slot resolver.

- [ ] **Step 1: Write failing SSRF/rebinding and cleanup tests**

```python
@pytest.mark.parametrize("target", [
    "https://127.0.0.1", "https://169.254.169.254", "https://[::1]",
    "https://2130706433", "https://0177.0.0.1", "https://user@allowed.example@evil.example",
])
async def test_private_or_ambiguous_destination_is_rejected(target, policy):
    with pytest.raises(DestinationDenied):
        await policy.resolve(target)

async def test_redirect_or_dns_rebinding_is_revalidated(policy, rebinding_dns):
    with pytest.raises(DestinationDenied):
        await policy.follow(rebinding_dns.public_then_private())

async def test_crashed_job_envelope_is_deleted_by_reaper(stack):
    envelope = await stack.launch_then_crash()
    await stack.run_reaper(after_expiry=True)
    assert not await stack.envelope_exists(envelope.id)
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_network.py tests/unit/test_pipeline_secret_envelope.py tests/unit/test_pipeline_cloud_run.py`
Expected: FAIL on missing isolation adapters.

- [ ] **Step 3: Implement validation, envelope lifecycle, and least-privilege job launch**

```python
@dataclass(frozen=True)
class ResolvedDestination:
    scheme: Literal["https"]
    hostname: str
    port: Literal[443]
    addresses: Sequence[ipaddress.IPv4Address | ipaddress.IPv6Address]

async def launch_step(claim: CodeStepClaim) -> CloudRunExecution:
    destination = await destination_policy.resolve_and_pin(claim.destination)
    envelope = await create_envelope(claim, expires_in=timedelta(minutes=15))
    return await cloud_run_jobs.run(job_name, args=[claim.input_uri, envelope.uri], labels=claim.labels)
```

Reject any non-global address, mixed answer, redirect outside exact allowlist, non-443 port, credentials in URLs, and hostname change. Re-resolve before each connection. Terraform creates a dedicated service account without metadata/API access beyond exact artifact/envelope objects and KMS decrypt context.

- [ ] **Step 4: Run tests and Terraform validation**

Run: `cd backend && pytest -q tests/unit/test_pipeline_network.py tests/unit/test_pipeline_secret_envelope.py tests/unit/test_pipeline_cloud_run.py`

Run: `terraform -chdir=infra/gcp validate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_network.py backend/app/services/pipeline_secret_envelope.py backend/app/services/pipeline_cloud_run.py backend/app/services/pipeline_envelope_reaper.py infra/gcp backend/tests/unit/test_pipeline_network.py backend/tests/unit/test_pipeline_secret_envelope.py backend/tests/unit/test_pipeline_cloud_run.py
git commit -m "feat: isolate custom pipeline execution"
```

### Task 9: Hard budgets, cost cutoff, concurrency, cancellation, and metering

**Files:**
- Create: `backend/app/services/pipeline_budget.py`
- Modify: `backend/app/services/pipeline_runtime.py`
- Modify: `backend/app/services/agent_concurrency.py`
- Modify: `backend/app/services/usage_metering.py`
- Modify: `backend/app/core/config.py`
- Test: `backend/tests/unit/test_pipeline_budget.py`
- Test: `backend/tests/unit/test_pipeline_cancellation.py`

**Interfaces:**
- Produces: atomic budget reservation/reconciliation, deployment cost cutoff admission, job/task cancellation, usage records.
- Consumes: tenant entitlements, platform budget state, Cloud Run job adapter, generic admission service.

- [ ] **Step 1: Write failing hard-cutoff and cancellation tests**

```python
@pytest.mark.parametrize("exhausted", ["deployment", "tenant", "pipeline"])
async def test_exhausted_budget_rejects_before_cloud_run_launch(runtime, cloud_run, exhausted):
    runtime.exhaust(exhausted)
    with pytest.raises(BudgetExceeded):
        await runtime.dispatch_code_step()
    assert cloud_run.launch_count == 0

async def test_cancel_stops_jobs_and_prevents_successor_release(runtime):
    await runtime.cancel_run()
    assert runtime.cloud_run.cancelled
    assert await runtime.ready_successors() == []
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_budget.py tests/unit/test_pipeline_cancellation.py`
Expected: FAIL on missing budget/cancel integration.

- [ ] **Step 3: Implement atomic pre-dispatch reservations and reconciliation**

```python
async def admit_code_step(session, step, estimate):
    await lock_budget_rows(session, step.organization_id, step.pipeline_run_id)
    enforce_deployment_cutoff(current_deployment_spend(), estimate)
    reservation = reserve_all_dimensions(step, estimate)
    return reservation
```

Meter job seconds, CPU/memory class, object storage, tool calls, model tokens, and external calls. Cancellation invalidates lease generation, cancels the Cloud Run execution, schedules envelope cleanup, and cannot convert a late result to success.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_budget.py tests/unit/test_pipeline_cancellation.py tests/unit/test_usage_metering.py tests/unit/test_agent_concurrency.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/pipeline_budget.py backend/app/services/pipeline_runtime.py backend/app/services/agent_concurrency.py backend/app/services/usage_metering.py backend/app/core/config.py backend/tests/unit/test_pipeline_budget.py backend/tests/unit/test_pipeline_cancellation.py
git commit -m "feat: enforce pipeline cost and runtime limits"
```

### Task 10: REST/GraphQL APIs, audit, and replay operations

**Files:**
- Create: `backend/app/api/v1/pipelines.py`
- Modify: `backend/app/api/v1/router.py`
- Create: `backend/app/graphql/types/pipelines.py`
- Create: `backend/app/graphql/queries/pipelines.py`
- Create: `backend/app/graphql/mutations/pipelines.py`
- Modify: `backend/app/graphql/subscriptions.py`
- Test: `backend/tests/unit/test_pipeline_api.py`
- Test: `backend/tests/unit/test_pipeline_graphql.py`

**Interfaces:**
- Produces: draft/validate/test/publish/version/pause/start/cancel/retry/replay/query/log APIs and live run events.
- Consumes: Tasks 1-9 services, audit service, GraphQL conventions.

- [ ] **Step 1: Write failing authority and immutable-history API tests**

```python
async def test_retry_creates_new_attempt_without_rewriting_history(api):
    before = await api.step_attempts(run_id, step_id)
    await api.retry_step(run_id, step_id)
    after = await api.step_attempts(run_id, step_id)
    assert len(after) == len(before) + 1
    assert after[:len(before)] == before

async def test_replay_creates_new_run_with_source_link(api):
    replay = await api.replay_event(old_run_id, target_version_id)
    assert replay.id != old_run_id
    assert replay.replayed_from_run_id == old_run_id
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_pipeline_api.py tests/unit/test_pipeline_graphql.py`
Expected: FAIL on missing API surfaces.

- [ ] **Step 3: Implement thin tenant-scoped APIs and sequenced events**

Every mutation calls one service transaction, emits an audit event, accepts idempotency where retryable, and returns safe error codes. Logs redact secrets and have bounded size; artifact access uses short-lived tenant-authorized download handles.

- [ ] **Step 4: Run API tests**

Run: `cd backend && pytest -q tests/unit/test_pipeline_api.py tests/unit/test_pipeline_graphql.py tests/unit/test_graphql_subscriptions.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/pipelines.py backend/app/api/v1/router.py backend/app/graphql/types/pipelines.py backend/app/graphql/queries/pipelines.py backend/app/graphql/mutations/pipelines.py backend/app/graphql/subscriptions.py backend/tests/unit/test_pipeline_api.py backend/tests/unit/test_pipeline_graphql.py
git commit -m "feat: expose pipeline control APIs"
```

### Task 11: Visual builder, ordered editor, test console, and run operations

**Files:**
- Create: `frontend/src/app/(app)/pipelines/page.tsx`
- Create: `frontend/src/app/(app)/pipelines/[pipelineId]/page.tsx`
- Create: `frontend/src/app/(app)/pipelines/[pipelineId]/runs/[runId]/page.tsx`
- Create: `frontend/src/components/pipelines/PipelineBuilder.tsx`
- Create: `frontend/src/components/pipelines/OrderedStepEditor.tsx`
- Create: `frontend/src/components/pipelines/PipelineRunDag.tsx`
- Create: `frontend/src/lib/pipelines.ts`
- Modify: `frontend/src/lib/api.ts`
- Test: `frontend/src/lib/pipelines.test.ts`
- Create: `frontend/e2e/pipeline-builder.spec.ts`

**Interfaces:**
- Produces: catalog, accessible dual-mode editor, schema mapper, test/publish/version compare, pause, live operations.
- Consumes: Task 10 APIs and subscription events.

- [ ] **Step 1: Write failing builder state and accessibility tests**

```typescript
it("round-trips graph and ordered editor to the same canonical definition", () => {
  expect(canonicalize(fromOrderedEditor(toOrderedEditor(samplePipeline)))).toEqual(canonicalize(samplePipeline));
});

it("shows degraded and failed branches without inferring success", () => {
  expect(runView(partialRun).terminalLabel).toBe("Completed with degradation");
});
```

- [ ] **Step 2: Verify failures**

Run: `npm --prefix frontend test -- pipelines.test.ts`
Expected: FAIL on missing pipeline UI/view models.

- [ ] **Step 3: Implement builder and operations UI**

Both editors modify the same typed canonical definition. Expose node catalogs, mappings, schema errors, sample-event test output, effective authority, worst-case cost, immutable version comparison, trigger pause, DAG state, retries, approvals, evidence, usage, logs, and terminal reason.

- [ ] **Step 4: Run tests, E2E, and build**

Run: `npm --prefix frontend test -- pipelines.test.ts`

Run: `npm --prefix frontend run e2e -- pipeline-builder.spec.ts && npm --prefix frontend run build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/\(app\)/pipelines frontend/src/components/pipelines frontend/src/lib/pipelines.ts frontend/src/lib/pipelines.test.ts frontend/src/lib/api.ts frontend/e2e/pipeline-builder.spec.ts
git commit -m "feat: add execution pipeline builder"
```

### Task 12: Production acceptance, observability, and staged rollout

**Files:**
- Create: `backend/tests/integration/test_pipeline_production_flow.py`
- Create: `backend/tests/integration/test_pipeline_isolation.py`
- Create: `infra/gcp/verify-pipeline.ps1`
- Modify: `infra/gcp/verify.ps1`
- Modify: `backend/app/core/config.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: canary feature control, dashboards/alerts, executor isolation probe, full acceptance gate.
- Consumes: all prior tasks and deployed GCP resources.

- [ ] **Step 1: Write failing production acceptance tests**

```python
@pytest.mark.integration
async def test_full_pipeline_survives_restart_and_records_lineage(stack):
    run = await stack.start(query_agent_approval_code_emit_pipeline())
    await stack.restart_api_and_worker_mid_run()
    result = await stack.wait_terminal(run.id)
    assert result.status == "completed"
    assert result.lineage.has("trigger", "version", "code_hash", "agent_version", "approval", "usage")

@pytest.mark.integration
async def test_executor_cannot_reach_metadata_or_other_tenant(stack):
    result = await stack.execute_isolation_probe()
    assert result.metadata_access is False
    assert result.cross_tenant_access is False
```

- [ ] **Step 2: Run and confirm rollout wiring is absent**

Run: `cd backend && pytest -q tests/integration/test_pipeline_production_flow.py tests/integration/test_pipeline_isolation.py`
Expected: FAIL before flags, probes, metrics, and deployed executor resources exist.

- [ ] **Step 3: Add flags, metrics, alerts, retention, and canary controls**

Add `CYNUX_FEATURES__CUSTOM_PIPELINES`, organization allowlist, queue/lease/retry/error/job/cost metrics, stale-step and envelope alerts, artifact/envelope lifecycle policies, audit retention, Cloud Run maximum instances `2`, executor disabled-by-default egress, and a kill switch that stops new code jobs without corrupting in-flight state.

- [ ] **Step 4: Run complete verification**

Run: `cd backend && pytest -q tests/unit/test_pipeline_models.py tests/unit/test_pipeline_validator.py tests/unit/test_pipeline_definition.py tests/unit/test_pipeline_triggers.py tests/unit/test_pipeline_cron.py tests/unit/test_pipeline_runtime.py tests/unit/test_pipeline_nodes.py tests/unit/test_pipeline_schema_boundaries.py tests/unit/test_pipeline_agent_tool_nodes.py tests/unit/test_pipeline_approvals.py tests/unit/test_pipeline_code.py executor/tests/test_runner.py tests/unit/test_pipeline_network.py tests/unit/test_pipeline_secret_envelope.py tests/unit/test_pipeline_cloud_run.py tests/unit/test_pipeline_budget.py tests/unit/test_pipeline_cancellation.py tests/unit/test_pipeline_api.py tests/unit/test_pipeline_graphql.py tests/integration/test_pipeline_recovery.py tests/integration/test_pipeline_production_flow.py tests/integration/test_pipeline_isolation.py`

Run: `npm --prefix frontend test -- pipelines.test.ts && npm --prefix frontend run build && npm --prefix frontend run e2e -- pipeline-builder.spec.ts`

Run: `terraform -chdir=infra/gcp validate` and `powershell -ExecutionPolicy Bypass -File infra/gcp/verify-pipeline.ps1`
Expected: selected suites and infrastructure probes pass. Run the full suites and report known baseline failures before enabling the first canary organization.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_pipeline_production_flow.py backend/tests/integration/test_pipeline_isolation.py infra/gcp/verify-pipeline.ps1 infra/gcp/verify.ps1 backend/app/core/config.py .github/workflows/ci.yml
git commit -m "ops: roll out isolated execution pipelines"
```
