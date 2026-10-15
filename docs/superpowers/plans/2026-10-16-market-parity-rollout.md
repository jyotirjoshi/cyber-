# Market-Parity Platform Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the seven approved Cynux capability slices as compatible, tenant-safe production increments and deploy them through a controlled canary rollout.

**Architecture:** Preserve the current modular monolith and reuse one durable execution substrate across GraphQL, integrations, agents, PTaaS, pipelines, ASM, threat intelligence, and automation. Each slice has its own implementation plan and feature gate; this controller establishes the baseline, interface order, cross-slice acceptance, and production rollout.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Redis, Strawberry GraphQL, Next.js, TypeScript, Cloud Run, Cloud Run Jobs, Firebase Hosting, Terraform, pytest, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-16-market-parity-platform-design.md`

## Global Constraints

- PostgreSQL is authoritative; Redis is never the sole business-state store.
- Every database query, event, task, and artifact is organization-scoped.
- Existing REST endpoints and canonical identifiers remain backward-compatible.
- External mutations are capability-declared, idempotent, auditable, and replay-safe.
- Active validation requires current target authorization and remains non-destructive by default.
- Customer code never executes in the API or general worker process.
- New capabilities remain feature-gated through internal and canary rollout.
- Preserve all existing workspace changes; never reset or discard the deployed snapshot.

## Review Focus

- A rolling deployment where old and new workers overlap must not duplicate an external mutation; covered by Task 3 cross-version recovery acceptance.
- An MSSP principal switching between delegated clients must not reuse tenant-scoped loader or cache data; covered by Task 3 tenant-switch acceptance.
- An authorization expiring while an active validation task is queued must prevent dispatch; covered by Task 3 expiry acceptance.
- A deployment budget cutoff reached between reservation and launch must release the reservation without starting work; covered by Task 3 budget-race acceptance.
- Feature rollback must stop new work without corrupting or silently abandoning committed runs; covered by Task 4 rollback acceptance.

---

### Task 1: Capture and verify the deployed workspace baseline

**Files:**
- Create: `docs/superpowers/baselines/2026-10-16-deployed-snapshot.md`
- Modify: `.gitignore`
- Test: `backend/tests/unit/test_migration_matches_models.py`
- Test: `backend/tests/unit/test_runtime_configuration.py`
- Test: `frontend/src/lib/firebase-routing.test.ts`

**Interfaces:**
- Consumes: current dirty `codex/ctem-parity` workspace and deployed image tag recorded by operations.
- Produces: commit `market-parity-baseline`, exact changed-file inventory, migration heads, test evidence, and known-baseline failures for every slice plan.

- [ ] **Step 1: Write the baseline manifest checker**

Add a test to `backend/tests/unit/test_runtime_configuration.py` that loads
`docs/superpowers/baselines/2026-10-16-deployed-snapshot.md`, asserts it contains the Git commit,
the ordered Alembic heads, frontend/backend image identifiers, and no credential-like value:

```python
def test_deployed_baseline_manifest_is_complete_and_secret_free():
    text = Path("../docs/superpowers/baselines/2026-10-16-deployed-snapshot.md").read_text()
    for heading in ("Git baseline", "Alembic heads", "Images", "Verification"):
        assert f"## {heading}" in text
    assert not re.search(r"(?:sk-|api[_-]?key\s*[:=]|password\s*[:=])\S+", text, re.I)
```

- [ ] **Step 2: Run baseline tests and record failures before editing production code**

Run: `cd backend && pytest -q tests/unit/test_migration_matches_models.py tests/unit/test_runtime_configuration.py`

Run: `npm --prefix frontend test -- firebase-routing.test.ts`

Expected: the new manifest test fails because the manifest is absent; all pre-existing tests either pass or are copied verbatim into the manifest's `Known baseline failures` section.

- [ ] **Step 3: Create the manifest and protect execution scratch state**

Record `git status --short`, `git rev-parse HEAD`, Alembic heads, deployed image tags, and exact test commands. Add only `.superpowers/sdd/` to `.gitignore`. Never place environment values or secrets in the manifest.

- [ ] **Step 4: Run the baseline verification**

Run: `cd backend && pytest -q tests/unit/test_migration_matches_models.py tests/unit/test_runtime_configuration.py`

Run: `npm --prefix frontend test -- firebase-routing.test.ts`

Expected: PASS except failures already proven to predate the manifest test and recorded with full test names.

- [ ] **Step 5: Commit the complete current snapshot without altering its contents**

```bash
git add -A
gitleaks protect --staged --redact
git commit -m "chore: capture deployed market parity baseline"
```

If `gitleaks` reports a credential, unstage that file, replace the credential with a secret
reference through the existing settings/credential store, rerun the relevant baseline test, and
repeat the staged scan. Never waive a live credential finding merely to create the baseline.

### Task 2: Execute the seven slice plans in dependency order

**Files:**
- Consume: `docs/superpowers/plans/2026-10-15-multi-agent-orchestrator.md`
- Consume: `docs/superpowers/plans/2026-10-15-graphql-sdk.md`
- Consume: `docs/superpowers/plans/2026-10-16-bidirectional-connectors.md`
- Consume: `docs/superpowers/plans/2026-10-16-autonomous-browser-api-validation.md`
- Consume: `docs/superpowers/plans/2026-10-16-ptaas-operations.md`
- Consume: `docs/superpowers/plans/2026-10-15-custom-execution-pipelines.md`
- Consume: `docs/superpowers/plans/2026-10-16-asm-threat-intelligence.md`
- Consume: `docs/superpowers/plans/2026-10-16-automation-platform.md`
- Create: `docs/superpowers/baselines/2026-10-16-slice-contracts.json`
- Test: `backend/tests/integration/test_market_parity_slice_contracts.py`

**Interfaces:**
- Consumes: Task 1 baseline; each named plan's completed, reviewed commits.
- Produces: published interface versions for durable tasks, GraphQL, connector manifests, engagements, pipelines, ASM observations, intelligence assertions, and automation events.

- [ ] **Step 1: Write a failing slice-contract registry test**

```python
def test_every_slice_publishes_a_versioned_contract():
    contracts = json.loads(Path("../docs/superpowers/baselines/2026-10-16-slice-contracts.json").read_text())
    assert set(contracts) == {
        "execution", "graphql", "connectors", "ptaas", "pipelines", "asm_intel", "automation"
    }
    assert all(re.fullmatch(r"v[1-9][0-9]*", item["version"]) for item in contracts.values())
    assert all(Path("..", item["schema"]).is_file() for item in contracts.values())
```

- [ ] **Step 2: Run the contract test**

Run: `cd backend && pytest -q tests/integration/test_market_parity_slice_contracts.py`

Expected: FAIL because the slice contract registry does not exist.

- [ ] **Step 3: Execute each child plan completely**

Use the plan executor separately for each plan, in the listed order. Execute autonomous browser/API validation after bidirectional connectors and before PTaaS. Resume the GraphQL and custom-agent work from existing commits by proving completed task acceptance tests before marking those tasks complete; do not reimplement code solely because its earlier ledger is absent. Record each published JSON Schema or GraphQL SDL path and version in `2026-10-16-slice-contracts.json`.

- [ ] **Step 4: Run the slice-contract test and each child plan's final acceptance command**

Run: `cd backend && pytest -q tests/integration/test_market_parity_slice_contracts.py`

Expected: PASS and every child plan final suite passes or has a baseline failure documented in Task 1 that is unrelated to changed code.

- [ ] **Step 5: Commit the registry**

```bash
git add docs/superpowers/baselines/2026-10-16-slice-contracts.json backend/tests/integration/test_market_parity_slice_contracts.py
git commit -m "chore: publish market parity slice contracts"
```

### Task 3: Cross-slice recovery, isolation, authority, and budget acceptance

**Files:**
- Create: `backend/tests/integration/test_market_parity_end_to_end.py`
- Create: `backend/tests/integration/test_market_parity_recovery.py`
- Create: `backend/tests/integration/test_market_parity_tenant_isolation.py`
- Create: `backend/tests/integration/test_market_parity_budget.py`
- Modify: `backend/tools/verify.py`

**Interfaces:**
- Consumes: all published slice contracts from Task 2.
- Produces: one production-like acceptance gate proving the slices compose safely.

- [ ] **Step 1: Write failing cross-slice acceptance tests**

```python
@pytest.mark.integration
async def test_connector_finding_drives_agent_ptaas_pipeline_and_automation(stack):
    finding = await stack.ingest_provider_finding(status="open")
    engagement = await stack.attach_to_engagement(finding)
    run = await stack.launch_authorized_validation(engagement)
    await stack.approve_exact_payload(run.pending_approval)
    result = await stack.wait_terminal(run.id)
    await stack.run_due_work()
    assert result.evidence_ids
    assert await stack.provider_status(finding) == "resolved"
    assert await stack.audit_lineage(finding) == [
        "connector.ingested", "canonical.updated", "agent.validated",
        "ptaas.retest_passed", "automation.executed", "connector.exported",
    ]

@pytest.mark.integration
async def test_expired_authorization_blocks_queued_validation(stack):
    task = await stack.queue_validation(authorization_expires_in=timedelta(seconds=1))
    await stack.advance_clock(seconds=2)
    assert (await stack.dispatch(task)).code == "authorization_expired"

@pytest.mark.integration
async def test_mssp_tenant_switch_never_reuses_loader_cache(stack):
    first, second = await stack.query_two_delegated_clients_same_global_id()
    assert first.organization_id != second.organization_id

@pytest.mark.integration
async def test_cutoff_race_releases_reservation_without_launch(stack):
    reservation = await stack.reserve_pipeline_budget()
    await stack.exhaust_deployment_budget()
    result = await stack.launch_reserved_step(reservation)
    assert result.code == "deployment_budget_exhausted"
    assert await stack.reservation_released(reservation.id)
```

- [ ] **Step 2: Run the new acceptance files**

Run: `cd backend && pytest -q tests/integration/test_market_parity_end_to_end.py tests/integration/test_market_parity_recovery.py tests/integration/test_market_parity_tenant_isolation.py tests/integration/test_market_parity_budget.py`

Expected: FAIL at the first missing cross-slice adapter or fixture.

- [ ] **Step 3: Add only cross-slice adapters and verifier wiring**

Extend `backend/tools/verify.py` with a `market-parity` suite that composes existing public services. Do not add alternate business logic in test helpers. Add old/new worker overlap to the recovery test and assert a provider operation ID settles once.

- [ ] **Step 4: Run acceptance twice, including randomized order**

Run: `cd backend && pytest -q tests/integration/test_market_parity_*.py`

Run: `cd backend && pytest -q --random-order tests/integration/test_market_parity_*.py`

Expected: PASS with no ordering dependency or duplicated external mutation.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_market_parity_*.py backend/tools/verify.py
git commit -m "test: prove market parity slices compose safely"
```

### Task 4: Canary deployment, rollback, and production verification

**Files:**
- Create: `infra/gcp/verify-market-parity.ps1`
- Modify: `infra/gcp/main.tf`
- Modify: `infra/gcp/variables.tf`
- Modify: `infra/gcp/verify.ps1`
- Modify: `.github/workflows/ci.yml`
- Test: `backend/tests/unit/test_gcp_terraform_contract.py`
- Test: `backend/tests/unit/test_gcp_deployment_config.py`

**Interfaces:**
- Consumes: Task 3 green acceptance and all feature flags.
- Produces: disabled-by-default deployment, internal/canary/GA controls, stop-new-work rollback, metrics, alerts, and production smoke evidence.

- [ ] **Step 1: Write failing rollout and rollback contract tests**

```python
def test_every_market_parity_feature_has_default_off_canary_and_kill_switch(terraform_text):
    for feature in ("graphql_full", "connector_writeback", "browser_validation", "ptaas",
                    "custom_pipelines", "asm_intel_v2", "automation_v2"):
        assert f'CYNUX_FEATURES__{feature.upper()}' in terraform_text
        assert f'CYNUX_KILL_SWITCH__{feature.upper()}' in terraform_text

def test_rollback_stops_new_work_but_preserves_settlement(deployment_config):
    assert deployment_config.rollback_mode == "stop_new_and_settle_committed"
```

- [ ] **Step 2: Run infrastructure contract tests**

Run: `cd backend && pytest -q tests/unit/test_gcp_terraform_contract.py tests/unit/test_gcp_deployment_config.py`

Expected: FAIL for missing per-slice rollout controls.

- [ ] **Step 3: Implement flags, canary allowlists, kill switches, metrics, and alerts**

Add explicit environment variables and Terraform variables for all seven features. `verify-market-parity.ps1` must check health, migration head, schema version, queue settlement, executor/browser isolation, feature state, event replay, and budget admission without invoking paid scans or third-party writes.

- [ ] **Step 4: Validate rollback and deploy progressively**

Run: `terraform -chdir=infra/gcp validate`

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/verify-market-parity.ps1 -Mode PreDeploy`

Deploy with every new feature disabled, enable the internal organization, run the verification script in `Canary` mode, then enable selected canary organizations. Exercise each kill switch in `DryRunRollback` mode and assert committed runs settle while new runs return `feature_paused`.

Expected: every command succeeds before general availability.

- [ ] **Step 5: Commit deployment controls**

```bash
git add infra/gcp .github/workflows/ci.yml backend/tests/unit/test_gcp_terraform_contract.py backend/tests/unit/test_gcp_deployment_config.py
git commit -m "ops: stage market parity platform rollout"
```

