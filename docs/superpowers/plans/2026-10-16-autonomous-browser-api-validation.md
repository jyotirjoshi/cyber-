# Autonomous Browser and API Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let authorized Cynux agents execute durable, evidence-backed browser and API validation workflows without uncontrolled or destructive exploitation.

**Architecture:** Add typed validation techniques and immutable runs on top of the durable multi-agent task runtime. Browser and API work executes in isolated workers using scoped one-time credential envelopes; evidence is content-addressed and findings are emitted only when technique-specific verification contracts pass.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Playwright, httpx, PostgreSQL, Redis, Cloud Run Jobs, GCS, KMS, Next.js, pytest, Playwright Test.

**Spec:** `docs/superpowers/specs/2026-10-16-market-parity-platform-design.md`

## Global Constraints

- Every active request must match a current authorization, target scope, technique allowlist, and approval policy.
- Denial of service, persistence, destructive mutation, credential theft, and uncontrolled fuzzing are unavailable techniques.
- Credentials use one-time envelopes and never appear in prompts, logs, screenshots, traces, or evidence previews.
- Findings require a versioned verification contract; uncertain results remain inconclusive.
- Browser/API runs obey wall-time, request, task, token, cost, and parallelism budgets.

## Review Focus

- Redirects and DNS changes must not escape authorized origins; covered by Task 3.
- Secrets in headers, forms, URLs, storage, and screenshots must be redacted before persistence; covered by Task 4.
- Approval of one HTTP payload must not authorize a changed method, URL, body, or account; covered by Task 2.
- Expired authentication during a run must produce an explicit blocked result rather than a false finding; covered by Task 5.
- Concurrent specialists sharing a target must respect target conflict keys for state-changing checks; covered by Task 5.

---

### Task 1: Validation techniques, runs, steps, and evidence persistence

**Files:**
- Create: `backend/alembic/versions/0096_validation_runs.py`
- Create: `backend/app/db/models/validation.py`
- Create: `backend/app/schemas/validation.py`
- Modify: `backend/app/db/models/__init__.py`
- Create: `backend/app/services/validation_techniques.py`
- Test: `backend/tests/unit/test_validation_models.py`
- Test: `backend/tests/unit/test_validation_techniques.py`

**Interfaces:**
- Consumes: generic agent tasks, assessment authorizations, assets, canonical findings, and artifacts.
- Produces: `ValidationTechnique`, `ValidationRun`, `ValidationStep`, `ValidationEvidence`, `VerificationContract`, and `get_validation_technique()`.

- [ ] **Step 1: Write failing technique and immutable-evidence tests**

```python
def test_forbidden_technique_classes_cannot_be_registered():
    for category in ("denial_of_service", "persistence", "credential_theft", "destructive"):
        with pytest.raises(TechniquePolicyError):
            register_technique(technique(category=category))

def test_evidence_digest_is_immutable():
    evidence = ValidationEvidence.from_bytes(b"original", media_type="application/json")
    with pytest.raises(ImmutableEvidence):
        evidence.digest = sha256(b"changed").hexdigest()
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_validation_models.py tests/unit/test_validation_techniques.py`

Expected: FAIL on missing validation domain.

- [ ] **Step 3: Implement typed persistence and technique registry**

Runs pin organization, objective, authorization, scope digest, agent/tool/technique versions, budgets, approval policy, and terminal reason. Steps pin input/output schema and payload digest. Evidence stores object reference, digest, classification, redaction version, source step, capture time, and verification role.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_validation_models.py tests/unit/test_validation_techniques.py tests/unit/test_migration_matches_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0096_validation_runs.py backend/app/db/models/validation.py backend/app/db/models/__init__.py backend/app/schemas/validation.py backend/app/services/validation_techniques.py backend/tests/unit/test_validation_models.py backend/tests/unit/test_validation_techniques.py
git commit -m "feat: model authorized validation runs"
```

### Task 2: Scope, authorization, approval, and budget admission

**Files:**
- Create: `backend/app/services/validation_policy.py`
- Create: `backend/app/services/validation_budget.py`
- Modify: `backend/app/services/scan_auth.py`
- Modify: `backend/app/services/agent_action.py`
- Test: `backend/tests/unit/test_validation_policy.py`
- Test: `backend/tests/unit/test_validation_budget.py`

**Interfaces:**
- Consumes: Task 1 techniques, scan-auth profiles, agent tool policy, exact-payload approvals, and usage metering.
- Produces: `ValidationAdmission`, `admit_validation_step()`, atomic budget reservations, and execution-time reauthorization.

- [ ] **Step 1: Write failing exact-payload and cutoff tests**

```python
async def test_changed_request_invalidates_approval(policy):
    approved = await policy.approve(method="GET", url="https://app.example/me", body=None, account="user-a")
    for changed in (
        {"method": "POST"}, {"url": "https://app.example/admin"},
        {"body": {"role": "admin"}}, {"account": "user-b"},
    ):
        with pytest.raises(ApprovalInvalid):
            await policy.admit(approved=approved, **changed)

async def test_budget_is_reserved_before_worker_launch(runtime):
    runtime.exhaust_requests()
    with pytest.raises(ValidationBudgetExceeded):
        await runtime.dispatch()
    assert runtime.launch_count == 0
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_validation_policy.py tests/unit/test_validation_budget.py`

Expected: FAIL on missing validation admission.

- [ ] **Step 3: Implement deterministic policy intersection**

Intersect user permission, organization policy, agent version, tool policy, assessment authorization, technique policy, scope, approval, feature flag, and remaining budgets. Canonicalize request method, origin, path, query, headers classification, body digest, account, and intended assertion into the approval digest.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_validation_policy.py tests/unit/test_validation_budget.py tests/unit/test_scan_execution_authority.py tests/unit/test_agent_actions.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/validation_policy.py backend/app/services/validation_budget.py backend/app/services/scan_auth.py backend/app/services/agent_action.py backend/tests/unit/test_validation_policy.py backend/tests/unit/test_validation_budget.py
git commit -m "feat: admit bounded validation work"
```

### Task 3: Isolated browser worker and authenticated sessions

**Files:**
- Create: `backend/validation_worker/browser_runner.py`
- Create: `backend/validation_worker/navigation_policy.py`
- Create: `backend/validation_worker/Dockerfile`
- Create: `backend/app/services/validation_browser_job.py`
- Test: `backend/validation_worker/tests/test_browser_runner.py`
- Test: `backend/tests/unit/test_validation_navigation_policy.py`
- Test: `backend/tests/unit/test_validation_browser_job.py`

**Interfaces:**
- Consumes: admitted browser steps, scan-auth profiles, one-time credential envelopes, Cloud Run Jobs.
- Produces: bounded browser execution, scoped session state, DOM/screenshot/network evidence, and structured assertions.

- [ ] **Step 1: Write failing origin, redirect, and isolation tests**

```python
@pytest.mark.parametrize("url", [
    "http://127.0.0.1", "http://169.254.169.254", "https://[::1]", "https://10.0.0.5"
])
async def test_private_or_metadata_navigation_is_denied(policy, url):
    with pytest.raises(NavigationDenied):
        await policy.authorize(url)

async def test_redirect_and_dns_rebinding_are_revalidated(policy, browser_fixture):
    with pytest.raises(NavigationDenied):
        await browser_fixture.navigate_public_then_redirect_private(policy)

def test_browser_image_runs_non_root_and_without_metadata_access(container_probe):
    assert container_probe.uid != 0
    assert not container_probe.metadata_reachable
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q validation_worker/tests/test_browser_runner.py tests/unit/test_validation_navigation_policy.py tests/unit/test_validation_browser_job.py`

Expected: FAIL because the browser worker is absent.

- [ ] **Step 3: Implement the isolated runner**

Use Playwright with one fresh context per task, bounded pages, downloads disabled unless a technique allows an evidence attachment, service workers disabled, proxy-level origin enforcement, response size/time limits, and navigation revalidation. Inject authentication through fields/cookies/headers from a one-time envelope without exposing values to the model.

- [ ] **Step 4: Run tests and build image**

Run: `cd backend && pytest -q validation_worker/tests/test_browser_runner.py tests/unit/test_validation_navigation_policy.py tests/unit/test_validation_browser_job.py`

Run: `docker build -f backend/validation_worker/Dockerfile backend/validation_worker`

Expected: PASS and image probe confirms non-root, read-only root filesystem compatibility, and blocked metadata access.

- [ ] **Step 5: Commit**

```bash
git add backend/validation_worker backend/app/services/validation_browser_job.py backend/tests/unit/test_validation_navigation_policy.py backend/tests/unit/test_validation_browser_job.py
git commit -m "feat: isolate authenticated browser validation"
```

### Task 4: API and GraphQL validation engine with evidence redaction

**Files:**
- Create: `backend/app/services/validation_api.py`
- Create: `backend/app/services/validation_redaction.py`
- Create: `backend/app/services/validation_evidence.py`
- Test: `backend/tests/unit/test_validation_api.py`
- Test: `backend/tests/unit/test_validation_redaction.py`
- Test: `backend/tests/unit/test_validation_evidence.py`

**Interfaces:**
- Consumes: OpenAPI/GraphQL descriptions, admitted API steps, auth profiles, object storage.
- Produces: bounded REST/GraphQL requests, authorization-matrix checks, schema assertions, redacted evidence, and verification outcomes.

- [ ] **Step 1: Write failing redaction and inconclusive tests**

```python
def test_headers_urls_forms_storage_and_screenshots_are_redacted(redactor):
    artifact = redactor.redact(sample_artifact_with_secrets())
    serialized = artifact.bytes + artifact.metadata_json.encode()
    for secret in (b"Bearer abc", b"session=xyz", b"password123"):
        assert secret not in serialized

async def test_authentication_failure_is_inconclusive_not_vulnerable(engine):
    result = await engine.run(authenticated_authorization_check(response_status=401))
    assert result.outcome == "inconclusive"
    assert result.reason == "authentication_failed"

async def test_graphql_query_cost_is_bounded_before_request(engine):
    with pytest.raises(TechniqueBudgetExceeded):
        await engine.run(graphql_query(depth=50, aliases=500))
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_validation_api.py tests/unit/test_validation_redaction.py tests/unit/test_validation_evidence.py`

Expected: FAIL on missing engine and redactor.

- [ ] **Step 3: Implement bounded API execution and evidence pipeline**

Support spec discovery, operation selection, schema validation, identity/role authorization matrices, safe parameter boundary checks, response assertions, and GraphQL complexity limits. Redact before hashing or persistence; store original only when an explicit evidence policy permits encrypted restricted storage unavailable to normal UI and prompts.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_validation_api.py tests/unit/test_validation_redaction.py tests/unit/test_validation_evidence.py tests/unit/test_openapi_scope.py tests/unit/test_logging_redaction.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/validation_api.py backend/app/services/validation_redaction.py backend/app/services/validation_evidence.py backend/tests/unit/test_validation_api.py backend/tests/unit/test_validation_redaction.py backend/tests/unit/test_validation_evidence.py
git commit -m "feat: validate APIs with redacted evidence"
```

### Task 5: Parallel validation specialists, joins, and finding verification

**Files:**
- Create: `backend/app/services/validation_orchestrator.py`
- Create: `backend/app/services/validation_verifier.py`
- Modify: `backend/app/services/agent_specialist.py`
- Modify: `backend/app/services/canonical_ingest.py`
- Test: `backend/tests/unit/test_validation_orchestrator.py`
- Test: `backend/tests/integration/test_validation_parallelism.py`

**Interfaces:**
- Consumes: durable agent tasks, browser/API engines, verification contracts, canonical ingestion.
- Produces: parallel technique DAGs, target conflict keys, deterministic joins, verified/inconclusive results, and canonical finding observations.

- [ ] **Step 1: Write failing parallelism, conflict, and verification tests**

```python
async def test_three_read_only_specialists_execute_in_parallel(stack):
    run = await stack.start_specialists(["headers", "authorization", "schema"])
    await stack.wait_terminal(run.id)
    assert stack.maximum_parallel_tasks(run.id) == 3

async def test_state_changing_checks_share_target_conflict_key(stack):
    run = await stack.start_two_stateful_checks(target="account:user-a")
    assert not await stack.overlapped(run.task_ids)

async def test_finding_requires_verification_contract(stack):
    inconclusive = await stack.finish_without_required_evidence()
    assert inconclusive.outcome == "inconclusive"
    assert await stack.canonical_finding_count(inconclusive.run_id) == 0
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_validation_orchestrator.py tests/integration/test_validation_parallelism.py`

Expected: FAIL on missing validation orchestration.

- [ ] **Step 3: Implement scheduling and verification**

Release independent read-only tasks concurrently; serialize tasks sharing conflict keys. Joins consume bounded structured outputs and evidence references. Verification contracts declare required observations, negative controls, identity context, reproducibility, and confidence thresholds. Verified results enter canonical ingestion with technique/run/evidence provenance.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_validation_orchestrator.py tests/integration/test_validation_parallelism.py tests/unit/test_agent_specialists.py tests/unit/test_canonical_ingest.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/validation_orchestrator.py backend/app/services/validation_verifier.py backend/app/services/agent_specialist.py backend/app/services/canonical_ingest.py backend/tests/unit/test_validation_orchestrator.py backend/tests/integration/test_validation_parallelism.py
git commit -m "feat: orchestrate evidence-backed validation"
```

### Task 6: Validation APIs and live operations UI

**Files:**
- Create: `backend/app/api/v1/validations.py`
- Modify: `backend/app/api/v1/router.py`
- Modify: `backend/app/graphql/queries.py`
- Modify: `backend/app/graphql/mutations.py`
- Create: `frontend/src/app/(app)/validations/page.tsx`
- Create: `frontend/src/app/(app)/validations/[id]/page.tsx`
- Create: `frontend/src/lib/validations.ts`
- Test: `backend/tests/unit/test_validation_api_routes.py`
- Test: `frontend/src/lib/validations.test.ts`

**Interfaces:**
- Consumes: Tasks 1-5 services and replayable run events.
- Produces: plan/start/approve/cancel/retry/query/evidence APIs and a live DAG/evidence/budget interface.

- [ ] **Step 1: Write failing authority and terminal-label tests**

```python
async def test_start_rejects_asset_outside_authorization(api, unauthorized_asset):
    response = await api.post("/validations", json={"asset_id": str(unauthorized_asset.id)})
    assert response.status_code == 403
    assert response.json()["code"] == "validation_scope_denied"
```

```typescript
it("does not label inconclusive evidence as a finding", () => {
  expect(validationResult({ outcome: "inconclusive" }).findingLabel).toBeNull()
})
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_validation_api_routes.py`

Run: `npm --prefix frontend test -- validations.test.ts`

Expected: FAIL on missing interfaces.

- [ ] **Step 3: Implement service-backed APIs and operations views**

Expose immutable plan, tasks, dependencies, approvals, authorization expiry, budgets, attempts, evidence previews, redaction classification, verification trace, and terminal reasons. Artifact downloads use tenant-authorized short-lived handles.

- [ ] **Step 4: Run tests and build**

Run: `cd backend && pytest -q tests/unit/test_validation_api_routes.py tests/unit/test_graphql_schema.py`

Run: `npm --prefix frontend test -- validations.test.ts && npm --prefix frontend run build`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/validations.py backend/app/api/v1/router.py backend/app/graphql frontend/src/app/\(app\)/validations frontend/src/lib/validations.ts frontend/src/lib/validations.test.ts backend/tests/unit/test_validation_api_routes.py
git commit -m "feat: operate autonomous validation runs"
```

### Task 7: Isolation, recovery, and canary rollout

**Files:**
- Create: `backend/tests/integration/test_validation_production_flow.py`
- Create: `backend/tests/integration/test_validation_isolation.py`
- Create: `infra/gcp/verify-validation.ps1`
- Modify: `infra/gcp/main.tf`
- Modify: `infra/gcp/variables.tf`
- Modify: `backend/app/core/config.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: complete validation slice.
- Produces: Cloud Run worker resources, feature gate, kill switch, metrics, alerts, isolation probe, and production acceptance.

- [ ] **Step 1: Write failing recovery and isolation tests**

```python
@pytest.mark.integration
async def test_browser_api_run_survives_worker_restart_without_duplicate_requests(stack):
    run = await stack.start_browser_api_validation()
    await stack.restart_worker_mid_step(run.id)
    result = await stack.wait_terminal(run.id)
    assert result.status in {"completed", "completed_with_degradation"}
    assert await stack.mutating_request_count(run.id) <= 1
    assert result.evidence_ids

@pytest.mark.integration
async def test_worker_cannot_reach_metadata_database_or_other_tenant(stack):
    probe = await stack.run_isolation_probe()
    assert not probe.metadata
    assert not probe.database
    assert not probe.other_tenant_artifact
```

- [ ] **Step 2: Run acceptance**

Run: `cd backend && pytest -q tests/integration/test_validation_production_flow.py tests/integration/test_validation_isolation.py`

Expected: FAIL before deployed worker and rollout controls exist.

- [ ] **Step 3: Add least-privilege infrastructure and observability**

Create browser worker and API worker jobs with separate service accounts, exact artifact/KMS permissions, no metadata/database/Redis access, default-deny egress policy, maximum instances, and hard deadlines. Add `CYNUX_FEATURES__BROWSER_VALIDATION`, organization allowlist, stop-new-runs kill switch, and metrics for admission, queue, step result, request count, redaction, evidence completeness, authorization expiry, budget, and isolation probes.

- [ ] **Step 4: Run complete verification**

Run: `cd backend && pytest -q tests/unit/test_validation_*.py tests/integration/test_validation_*.py`

Run: `terraform -chdir=infra/gcp validate && powershell -ExecutionPolicy Bypass -File infra/gcp/verify-validation.ps1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_validation_production_flow.py backend/tests/integration/test_validation_isolation.py infra/gcp/verify-validation.ps1 infra/gcp/main.tf infra/gcp/variables.tf backend/app/core/config.py .github/workflows/ci.yml
git commit -m "ops: roll out isolated autonomous validation"
```

