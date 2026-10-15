# Bidirectional Connector Synchronization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every Cynux connector capability-explicit and provide durable, conflict-aware bidirectional synchronization for providers that support writes.

**Architecture:** Replace provider-name branching at the orchestration boundary with a typed connector manifest and adapter registry. Persist inbound cursors, webhook receipts, outbound operations, attempts, mappings, conflicts, and dead letters so retries and restarts cannot duplicate or regress remote state.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Redis, httpx, Pydantic, Next.js, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-16-market-parity-platform-design.md`

## Global Constraints

- Existing integration configuration and credential storage remain compatible.
- Secret values never enter manifests, operation payload logs, API responses, or audit details.
- Every provider write has a stable operation ID and idempotency behavior.
- Stale inbound state cannot overwrite a newer canonical decision.
- Unsupported write capabilities are explicit and never simulated as success.

## Review Focus

- Webhook delivery arriving before the corresponding poll page must deduplicate to one observation; covered by Task 4.
- A provider returning success without the expected state must remain unconfirmed and retry safely; covered by Task 2.
- Status vocabulary changes in a provider mapping version must not reinterpret historical operations; covered by Task 2.
- Credential rotation during a retry must use the current slot without changing operation identity; covered by Task 4.
- Disabling an integration with queued outbound work must pause rather than discard operations; covered by Task 4.

---

### Task 1: Connector capability manifests and registry

**Files:**
- Create: `backend/app/integrations/capabilities.py`
- Create: `backend/app/integrations/registry.py`
- Modify: `backend/app/integrations/base.py`
- Modify: `backend/app/services/integration.py`
- Modify: `backend/app/schemas/integration.py`
- Test: `backend/tests/unit/test_connector_capabilities.py`
- Test: `backend/tests/unit/test_connector_registry.py`

**Interfaces:**
- Consumes: `IntegrationKind`, current provider clients, and encrypted credential slots.
- Produces: `ConnectorCapability`, `ConnectorManifest`, `ConnectorAdapter`, `get_connector(kind)`, and API-safe manifest output.

- [ ] **Step 1: Write failing manifest and registry tests**

```python
def test_every_integration_kind_has_a_manifest():
    assert set(connector_registry.kinds()) == set(IntegrationKind)

def test_read_only_connector_rejects_status_write():
    adapter = connector_registry.get(IntegrationKind.NVD)
    assert ConnectorCapability.STATUS_WRITE not in adapter.manifest.capabilities
    with pytest.raises(UnsupportedCapability, match="status_write"):
        adapter.require(ConnectorCapability.STATUS_WRITE)

def test_manifest_serialization_contains_no_credentials(configured_jira):
    body = ConnectorManifestOut.model_validate(configured_jira.manifest).model_dump_json()
    assert configured_jira.secret not in body
```

- [ ] **Step 2: Verify the tests fail**

Run: `cd backend && pytest -q tests/unit/test_connector_capabilities.py tests/unit/test_connector_registry.py`

Expected: FAIL because the manifest and registry types are absent.

- [ ] **Step 3: Implement the typed contract and register every current kind**

```python
class ConnectorCapability(StrEnum):
    ASSET_READ = "asset_read"
    FINDING_READ = "finding_read"
    STATUS_WRITE = "status_write"
    COMMENT_WRITE = "comment_write"
    ASSIGNMENT_WRITE = "assignment_write"
    TICKET_WRITE = "ticket_write"
    EVIDENCE_READ = "evidence_read"
    EVIDENCE_WRITE = "evidence_write"
    WEBHOOK_INTAKE = "webhook_intake"
    INCREMENTAL_CURSOR = "incremental_cursor"
    ABSENCE_CLOSE = "absence_close"

@dataclass(frozen=True)
class ConnectorManifest:
    kind: IntegrationKind
    version: str
    capabilities: frozenset[ConnectorCapability]
    credential_slots: tuple[str, ...]
    status_mapping_version: str | None = None
```

Define `ConnectorAdapter.require(capability) -> None` and `get_connector(kind) -> ConnectorAdapter`. Adapt existing connectors without changing provider request behavior.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_connector_capabilities.py tests/unit/test_connector_registry.py tests/unit/test_integration_selection.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/integrations backend/app/services/integration.py backend/app/schemas/integration.py backend/tests/unit/test_connector_capabilities.py backend/tests/unit/test_connector_registry.py
git commit -m "feat: declare connector capabilities"
```

### Task 2: Durable mappings, outbound operations, attempts, and conflicts

**Files:**
- Create: `backend/alembic/versions/0095_bidirectional_connector_sync.py`
- Create: `backend/app/db/models/integration_operation.py`
- Create: `backend/app/services/integration_mapping.py`
- Create: `backend/app/services/integration_operations.py`
- Modify: `backend/app/db/models/__init__.py`
- Test: `backend/tests/unit/test_integration_mapping.py`
- Test: `backend/tests/unit/test_integration_operations.py`
- Test: `backend/tests/unit/test_migration_matches_models.py`

**Interfaces:**
- Consumes: Task 1 manifests and canonical lifecycle events.
- Produces: `StatusMapping`, `IntegrationOperation`, `IntegrationOperationAttempt`, `IntegrationConflict`, `plan_outbound_operation()`, and `settle_outbound_attempt()`.

- [ ] **Step 1: Write failing mapping and idempotency tests**

```python
def test_mapping_version_is_pinned_to_operation(mapping_v1, mapping_v2):
    operation = plan_outbound_operation(event("closed"), mapping_v1)
    assert operation.mapping_version == "v1"
    assert operation.provider_payload["status"] == "Done"
    assert replay_payload(operation, mapping_v2)["status"] == "Done"

async def test_duplicate_event_returns_same_operation(session, canonical_event):
    first = await plan_outbound_operation(session, canonical_event, provider="jira")
    second = await plan_outbound_operation(session, canonical_event, provider="jira")
    assert first.id == second.id

def test_success_without_state_confirmation_is_not_settled(operation):
    result = settle_outbound_attempt(operation, http_status=200, remote_state="Open")
    assert result.status == "pending_confirmation"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_integration_mapping.py tests/unit/test_integration_operations.py`

Expected: FAIL on missing operation persistence and mapping services.

- [ ] **Step 3: Implement immutable mappings and operation ledger**

Persist organization, integration, capability, canonical resource/event, operation ID, payload digest, mapping version, remote identity, status, next attempt, and confirmation state. Attempts are append-only. A unique `(integration_id, capability, canonical_event_id)` constraint returns the existing operation on replay. Conflict rows preserve both values, timestamps, policy, and resolution.

- [ ] **Step 4: Run model, migration, and service tests**

Run: `cd backend && pytest -q tests/unit/test_integration_mapping.py tests/unit/test_integration_operations.py tests/unit/test_migration_matches_models.py tests/unit/test_orm_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0095_bidirectional_connector_sync.py backend/app/db/models backend/app/services/integration_mapping.py backend/app/services/integration_operations.py backend/tests/unit/test_integration_mapping.py backend/tests/unit/test_integration_operations.py backend/tests/unit/test_migration_matches_models.py
git commit -m "feat: persist connector synchronization operations"
```

### Task 3: Certified provider write adapters

**Files:**
- Create: `backend/app/integrations/writeback.py`
- Modify: `backend/app/integrations/defectdojo.py`
- Modify: `backend/app/integrations/jira.py`
- Modify: `backend/app/integrations/servicenow.py`
- Modify: `backend/app/integrations/azure_devops.py`
- Modify: `backend/app/integrations/github.py`
- Modify: `backend/app/integrations/gitlab.py`
- Modify: `backend/app/integrations/linear.py`
- Test: `backend/tests/unit/test_connector_writeback_contract.py`
- Test: `backend/tests/unit/test_connector_status_roundtrip.py`

**Interfaces:**
- Consumes: `IntegrationOperation` and each provider's current HTTP client.
- Produces: `WritebackResult`, `execute_writeback(adapter, operation)`, remote confirmation reads, and normalized provider errors.

- [ ] **Step 1: Write failing provider contract tests**

```python
@pytest.mark.parametrize("kind", [
    "defectdojo", "jira", "servicenow", "azure_devops", "github", "gitlab", "linear"
])
async def test_certified_provider_round_trips_status_comment_and_owner(kind, provider_harness):
    adapter = provider_harness.adapter(kind)
    result = await adapter.write_status_comment_owner(
        remote_id="R-1", status="closed", comment="Verified by Cynux", owner="team-security",
        idempotency_key="op-123",
    )
    confirmed = await adapter.confirm(result.remote_id)
    assert confirmed.status == "closed"
    assert confirmed.comment_present
    assert confirmed.owner == "team-security"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_connector_writeback_contract.py tests/unit/test_connector_status_roundtrip.py`

Expected: FAIL because the common writeback protocol is absent.

- [ ] **Step 3: Implement provider-specific requests behind one protocol**

```python
class ConnectorWriteback(Protocol):
    async def write(self, operation: IntegrationOperationView) -> WritebackResult: ...
    async def confirm(self, operation: IntegrationOperationView) -> RemoteState: ...
```

Use provider request IDs or idempotency headers where available. Where unavailable, search for the operation marker before retry. Normalize retryable rate-limit/provider failures separately from terminal authorization, mapping, and missing-resource failures.

- [ ] **Step 4: Run connector regression suites**

Run: `cd backend && pytest -q tests/unit/test_connector_writeback_contract.py tests/unit/test_connector_status_roundtrip.py tests/unit/test_ticket_providers.py tests/unit/test_github_integration.py tests/unit/test_gitlab_integration.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/integrations backend/tests/unit/test_connector_writeback_contract.py backend/tests/unit/test_connector_status_roundtrip.py
git commit -m "feat: certify bidirectional provider adapters"
```

### Task 4: Inbound cursors, webhook receipts, outbound worker, and dead letters

**Files:**
- Create: `backend/app/services/integration_webhooks.py`
- Create: `backend/app/services/integration_outbound.py`
- Modify: `backend/app/services/integration_sync.py`
- Modify: `backend/app/worker/dispatch.py`
- Modify: `backend/app/worker/worker.py`
- Test: `backend/tests/unit/test_integration_webhook_dedup.py`
- Test: `backend/tests/unit/test_integration_outbound_worker.py`
- Test: `backend/tests/integration/test_integration_sync_recovery.py`

**Interfaces:**
- Consumes: Task 2 operations and Task 3 adapters.
- Produces: `accept_provider_webhook()`, `run_due_outbound_operations()`, cursor settlement, dead-letter review, pause/resume behavior.

- [ ] **Step 1: Write failing race, rotation, and pause tests**

```python
async def test_webhook_before_poll_deduplicates_to_one_observation(stack):
    await stack.webhook("provider-event-1")
    await stack.poll(page_contains="provider-event-1")
    assert await stack.observation_count("provider-event-1") == 1

async def test_disabled_integration_pauses_queued_write(stack):
    op = await stack.queue_write()
    await stack.disable_integration()
    await stack.run_worker()
    assert (await stack.operation(op.id)).status == "paused"

async def test_retry_after_rotation_keeps_operation_identity(stack):
    op = await stack.fail_once_then_rotate_credentials()
    await stack.retry(op.id)
    assert await stack.remote_mutation_count(op.operation_id) == 1
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_integration_webhook_dedup.py tests/unit/test_integration_outbound_worker.py tests/integration/test_integration_sync_recovery.py`

Expected: FAIL on missing durable receipt and outbound worker.

- [ ] **Step 3: Implement intake and execution**

Webhook receipts have a provider delivery key and body digest. Poll cursors settle only after canonical ingestion commits. Outbound claims use `FOR UPDATE SKIP LOCKED`, generation leases, bounded retries, provider rate limits, and circuit state. Disabling an integration pauses work; deleting one moves pending operations to review rather than dropping them.

- [ ] **Step 4: Run recovery tests**

Run: `cd backend && pytest -q tests/unit/test_integration_webhook_dedup.py tests/unit/test_integration_outbound_worker.py tests/integration/test_integration_sync_recovery.py tests/unit/test_worker_queue.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/integration_webhooks.py backend/app/services/integration_outbound.py backend/app/services/integration_sync.py backend/app/worker backend/tests/unit/test_integration_webhook_dedup.py backend/tests/unit/test_integration_outbound_worker.py backend/tests/integration/test_integration_sync_recovery.py
git commit -m "feat: run durable bidirectional synchronization"
```

### Task 5: Connector operations API and UI

**Files:**
- Modify: `backend/app/api/v1/integrations.py`
- Modify: `backend/app/graphql/types.py`
- Modify: `backend/app/graphql/queries.py`
- Modify: `backend/app/graphql/mutations.py`
- Modify: `frontend/src/app/(app)/integrations/page.tsx`
- Create: `frontend/src/app/(app)/integrations/[id]/operations/page.tsx`
- Create: `frontend/src/lib/integration-sync.ts`
- Test: `backend/tests/unit/test_integration_operations_api.py`
- Test: `frontend/src/lib/integration-sync.test.ts`

**Interfaces:**
- Consumes: Tasks 1-4 service APIs.
- Produces: capability display, operation/conflict/dead-letter queries, retry/resolve/pause mutations, and safe provider diagnostics.

- [ ] **Step 1: Write failing authorization and view-model tests**

```python
async def test_cross_tenant_operation_is_not_found(api, tenant_b_operation):
    response = await api.get(f"/integrations/operations/{tenant_b_operation.id}")
    assert response.status_code == 404
```

```typescript
it("never offers unsupported connector actions", () => {
  expect(actionsFor({ capabilities: ["finding_read"] })).toEqual(["Sync now"])
})
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_integration_operations_api.py`

Run: `npm --prefix frontend test -- integration-sync.test.ts`

Expected: FAIL on missing API and view model.

- [ ] **Step 3: Implement thin tenant-scoped endpoints and operations UI**

Expose manifests, health, cursors, operations, attempts, conflicts, and dead letters without credentials or unredacted provider bodies. Mutations call one domain service and require manage-integrations permission.

- [ ] **Step 4: Run tests and build**

Run: `cd backend && pytest -q tests/unit/test_integration_operations_api.py tests/unit/test_graphql_schema.py`

Run: `npm --prefix frontend test -- integration-sync.test.ts && npm --prefix frontend run build`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/integrations.py backend/app/graphql frontend/src/app/\(app\)/integrations frontend/src/lib/integration-sync.ts frontend/src/lib/integration-sync.test.ts backend/tests/unit/test_integration_operations_api.py
git commit -m "feat: operate connector synchronization"
```

### Task 6: End-to-end certification and rollout

**Files:**
- Create: `backend/tests/integration/test_connector_certification.py`
- Create: `infra/gcp/verify-connectors.ps1`
- Modify: `backend/app/core/config.py`
- Modify: `infra/gcp/main.tf`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: complete connector slice.
- Produces: provider contract fixtures, feature flag, canary verification, sync-lag/conflict/dead-letter metrics and alerts.

- [ ] **Step 1: Write failing certification test**

```python
@pytest.mark.integration
@pytest.mark.parametrize("provider", CERTIFIED_PROVIDERS)
async def test_full_bidirectional_round_trip_survives_worker_restart(provider, stack):
    local = await stack.ingest(provider, remote_status="open")
    await stack.update_local(local, status="closed", owner="security", comment="fixed")
    await stack.restart_worker_mid_write()
    await stack.wait_settled()
    assert await stack.remote_state(provider, local) == {
        "status": "closed", "owner": "security", "comment": "fixed"
    }
    assert await stack.remote_mutation_count(provider, local.operation_id) == 1
```

- [ ] **Step 2: Run certification test**

Run: `cd backend && pytest -q tests/integration/test_connector_certification.py`

Expected: FAIL before rollout fixtures and controls exist.

- [ ] **Step 3: Add feature gate, metrics, alerts, and verification script**

Add `CYNUX_FEATURES__CONNECTOR_WRITEBACK`, organization allowlist, stop-new-writes kill switch, and metrics for inbound/outbound lag, attempt result, rate limiting, conflicts, paused operations, and dead letters. The script uses provider sandboxes or deterministic mocks unless explicit certification credentials are supplied.

- [ ] **Step 4: Run complete connector verification**

Run: `cd backend && pytest -q tests/unit/test_connector_*.py tests/unit/test_integration_*.py tests/integration/test_connector_certification.py tests/integration/test_integration_sync_recovery.py`

Run: `terraform -chdir=infra/gcp validate`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_connector_certification.py infra/gcp/verify-connectors.ps1 backend/app/core/config.py infra/gcp/main.tf .github/workflows/ci.yml
git commit -m "ops: certify bidirectional connectors"
```

