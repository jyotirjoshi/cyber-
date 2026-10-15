# Public GraphQL API and Python SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose Cynux's supported tenant business surface through a secure, bounded GraphQL API and a stable synchronous/asynchronous Python SDK without duplicating domain logic.

**Architecture:** Mount Strawberry on the existing FastAPI service. Resolvers create short-lived request-scoped loaders and call current application services with the authenticated principal. PostgreSQL is authoritative for replay; Redis only signals live events. The SDK provides handwritten stable facades over checked-in GraphQL operations and shared sync/async transport policy.

**Tech Stack:** FastAPI, Strawberry GraphQL `0.327.7`, SQLAlchemy 2, PostgreSQL, Redis Streams, Pydantic 2, httpx, websockets, Python packaging, Next.js.

**Spec:** `docs/superpowers/specs/2026-10-15-graphql-sdk-design.md`

## Global Constraints

- REST remains supported; GraphQL resolvers call the same services and authorization paths.
- Every decoded ID, cursor, loader key, query, mutation, and subscription reapplies organization scope.
- Never expose credential material, reset/SCIM tokens, webhook secrets, raw scanner payloads, internal object keys, or provider exception text.
- Connection defaults are 25 and hard maximums are 100; bulk input maximum is 100.
- Retried mutations require both a client mutation ID and an idempotency key.
- Subscriptions use PostgreSQL for durable replay and Redis only for wake-up notifications.
- SDK secrets are redacted from representations, errors, logs, traces, and telemetry.

## Review Focus

- A valid opaque ID for another tenant must be indistinguishable from a missing node; Task 2 adds the non-disclosure test.
- Alias/fragment expansion must count every executable field and cannot bypass depth or cost limits; Task 8 adds adversarial tests.
- Forged, malformed, stale, or cross-connection cursors must fail safely; Task 3 adds cursor tests.
- Membership or scope revocation must terminate an already-open subscription before the next event; Task 9 adds the revocation test.
- SDK retry policy must never repeat a non-idempotent mutation and must never expose its API key; Task 10 adds retry/redaction tests.

---

## File Structure

- `backend/app/graphql/schema.py`: composed schema and FastAPI router.
- `backend/app/graphql/context.py`: authenticated request/subscription context and request-local loaders.
- `backend/app/graphql/ids.py`: opaque global IDs.
- `backend/app/graphql/pagination.py`: signed stable cursors and connections.
- `backend/app/graphql/errors.py`: public error mapping.
- `backend/app/graphql/loaders.py`: tenant-keyed request-local loaders.
- `backend/app/graphql/types/*`: public object/input/payload types.
- `backend/app/graphql/queries/*`: thin query resolvers grouped by domain.
- `backend/app/graphql/mutations/*`: thin mutation resolvers grouped by domain.
- `backend/app/graphql/subscriptions.py`: replayable event subscriptions.
- `backend/app/graphql/validation.py`: query depth/node/cost/alias/fragment controls.
- `sdk/python/cynux/*`: shared models, transports, operation documents, sync/async facades.

### Task 1: GraphQL package, schema mount, and database indexes

**Files:**
- Modify: `backend/pyproject.toml`
- Modify: `backend/requirements.txt`
- Create: `backend/alembic/versions/0094_graphql_query_indexes.py`
- Create: `backend/app/graphql/__init__.py`
- Create: `backend/app/graphql/schema.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/unit/test_graphql_schema.py`
- Test: `backend/tests/unit/test_migration_matches_models.py`

**Interfaces:**
- Produces: `/api/graphql`, generated schema artifact, indexes for stable connection sorts.
- Consumes: existing FastAPI app, REST dependencies, canonical models.

- [ ] **Step 1: Write failing schema and migration tests**

```python
def test_schema_exposes_health_and_version_fields(graphql_client):
    result = graphql_client.execute("{ system { apiVersion capabilities } }")
    assert result.errors is None
    assert "graphql" in result.data["system"]["capabilities"]

def test_graphql_index_revision_matches_models():
    assert migration_has_index("ix_findings_org_updated_id")
```

- [ ] **Step 2: Run focused tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_schema.py tests/unit/test_migration_matches_models.py`
Expected: FAIL because Strawberry, schema, route, and revision are absent.

- [ ] **Step 3: Add dependency, package, mount, and composite indexes**

```toml
"strawberry-graphql[fastapi]==0.327.7",
```

```python
graphql_router = GraphQLRouter(schema, context_getter=build_graphql_context)
app.include_router(graphql_router, prefix="/api/graphql")
```

Index `(organization_id, updated_at DESC, id)` and equivalent documented sort paths for assets, findings, assessments, runs, integrations, and pipeline runs. Do not create per-request schemas.

- [ ] **Step 4: Run tests and export the schema**

Run: `cd backend && pytest -q tests/unit/test_graphql_schema.py tests/unit/test_migration_matches_models.py`
Expected: PASS and deterministic schema output.

- [ ] **Step 5: Commit**

```bash
git add backend/pyproject.toml backend/requirements.txt backend/alembic/versions/0094_graphql_query_indexes.py backend/app/graphql backend/app/main.py backend/tests/unit/test_graphql_schema.py backend/tests/unit/test_migration_matches_models.py
git commit -m "feat: mount public graphql schema"
```

### Task 2: Authentication context, public errors, and opaque IDs

**Files:**
- Create: `backend/app/graphql/context.py`
- Create: `backend/app/graphql/errors.py`
- Create: `backend/app/graphql/ids.py`
- Create: `backend/app/graphql/scalars.py`
- Modify: `backend/app/graphql/schema.py`
- Test: `backend/tests/unit/test_graphql_auth.py`

**Interfaces:**
- Produces: `GraphQLContext`, `GlobalID`, UTC/money scalars, stable error extensions.
- Consumes: JWT/API-key authentication, `Principal`, request ID, session factory.

- [ ] **Step 1: Write failing authorization and disclosure tests**

```python
def test_foreign_global_id_looks_missing(graphql_client_org_a, asset_org_b):
    node_id = encode_global_id("Asset", asset_org_b.id)
    result = graphql_client_org_a.execute("query($id: ID!){ node(id:$id){ id } }", {"id": node_id})
    assert result.data["node"] is None
    assert result.errors is None

def test_provider_exception_is_not_exposed(graphql_client, broken_service):
    result = graphql_client.execute("{ assets(first: 1) { nodes { id } } }")
    assert "postgres" not in str(result.errors).lower()
```

- [ ] **Step 2: Verify tests fail**

Run: `cd backend && pytest -q tests/unit/test_graphql_auth.py`
Expected: FAIL on missing context/ID/error behavior.

- [ ] **Step 3: Implement authentication, ID decoding, and sanitized errors**

```python
@dataclass
class GraphQLContext:
    principal: Principal
    request_id: str
    session_factory: async_sessionmaker[AsyncSession]
    loaders: RequestLoaders

def decode_global_id(value: str, expected_type: str) -> UUID:
    decoded = verify_and_decode(value)
    if decoded.type_name != expected_type:
        raise PublicGraphQLError("NOT_FOUND")
    return decoded.uuid
```

Resolvers must translate absent and foreign resources to the same nullable result or `NOT_FOUND` payload. Error extensions include only `code`, `requestId`, `retryable`, and safe field paths.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_auth.py tests/unit/test_auth.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql backend/tests/unit/test_graphql_auth.py
git commit -m "feat: secure graphql request context"
```

### Task 3: Signed cursor connections and tenant-safe DataLoaders

**Files:**
- Create: `backend/app/graphql/pagination.py`
- Create: `backend/app/graphql/loaders.py`
- Create: `backend/app/graphql/types/common.py`
- Test: `backend/tests/unit/test_graphql_pagination.py`
- Test: `backend/tests/unit/test_graphql_loaders.py`

**Interfaces:**
- Produces: stable signed cursor codec, connection builders, per-request tenant loaders.
- Consumes: principal organization ID, deployment cursor signing key, projections.

- [ ] **Step 1: Write failing cursor and batching tests**

```python
@pytest.mark.parametrize("cursor", ["", "not-base64", forged_cursor(), cursor_for_other_sort()])
def test_invalid_cursor_is_rejected(cursor, connection):
    with pytest.raises(PublicGraphQLError, match="INVALID_CURSOR"):
        connection.decode(cursor)

async def test_loader_never_batches_two_organizations(loader_factory):
    a = loader_factory(principal_org_a)
    assert await a.asset.load(asset_org_b.id) is None
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_pagination.py tests/unit/test_graphql_loaders.py`
Expected: FAIL because pagination/loaders are absent.

- [ ] **Step 3: Implement signed sort/id cursors and request-local loaders**

```python
class CursorPayload(BaseModel):
    connection: str
    sort_value: datetime | str | int
    id: UUID
    version: Literal[1] = 1

async def load_assets(keys: list[UUID], organization_id: UUID) -> list[Asset | None]:
    rows = await tenant_asset_projection(organization_id, keys)
    return [rows.get(key) for key in keys]
```

Verify signature, connection name, sort type, and bounded age before using cursor fields in parameterized SQL.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_pagination.py tests/unit/test_graphql_loaders.py`
Expected: PASS, including constant query-count assertions.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/pagination.py backend/app/graphql/loaders.py backend/app/graphql/types/common.py backend/tests/unit/test_graphql_pagination.py backend/tests/unit/test_graphql_loaders.py
git commit -m "feat: add safe graphql connections and loaders"
```

### Task 4: Assets, applications, findings, and remediation queries

**Files:**
- Create: `backend/app/graphql/types/assets.py`
- Create: `backend/app/graphql/types/findings.py`
- Create: `backend/app/graphql/queries/exposure.py`
- Modify: `backend/app/graphql/schema.py`
- Test: `backend/tests/unit/test_graphql_exposure_queries.py`

**Interfaces:**
- Produces: node/connection queries for assets, applications, findings, observations, history, work, comments, tickets, risk acceptances, and retests.
- Consumes: canonical exposure services and loaders.

- [ ] **Step 1: Write failing parity and N+1 tests**

```python
async def test_findings_query_matches_rest_service(graphql, principal, finding_service):
    gql = await graphql.findings(first=20, severity=["CRITICAL"])
    domain = await finding_service.list(principal, severity=[Severity.CRITICAL], limit=20)
    assert [n.raw_id for n in gql.nodes] == [n.id for n in domain.items]

async def test_nested_assets_and_owners_have_bounded_queries(query_counter):
    await execute_deep_but_valid_exposure_query()
    assert query_counter.count <= 8
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_exposure_queries.py`
Expected: FAIL on absent exposure types/resolvers.

- [ ] **Step 3: Implement projection-backed thin resolvers**

```python
@strawberry.field
async def findings(self, info: Info[GraphQLContext], first: int = 25, after: str | None = None,
                   filter: FindingFilter | None = None) -> FindingConnection:
    page = await finding_service.list_connection(info.context.principal, bounded(first), after, filter)
    return FindingConnection.from_page(page)
```

Expose evidence metadata but not raw provider payloads or object-storage keys.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_exposure_queries.py tests/unit/test_findings.py tests/unit/test_assets.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/types/assets.py backend/app/graphql/types/findings.py backend/app/graphql/queries/exposure.py backend/app/graphql/schema.py backend/tests/unit/test_graphql_exposure_queries.py
git commit -m "feat: query exposure graph through graphql"
```

### Task 5: Remaining supported domain queries

**Files:**
- Create: `backend/app/graphql/types/operations.py`
- Create: `backend/app/graphql/types/platform.py`
- Create: `backend/app/graphql/queries/operations.py`
- Create: `backend/app/graphql/queries/platform.py`
- Modify: `backend/app/graphql/schema.py`
- Test: `backend/tests/unit/test_graphql_domain_queries.py`

**Interfaces:**
- Produces: organization/member metadata, assessments/jobs/artifacts/reports, integrations/sync, compliance, threat intelligence, ASM, notifications, automation/workflow, agent/knowledge, and pipeline queries.
- Consumes: existing domain services plus phase-one/two/four services when their feature flags are enabled.

- [ ] **Step 1: Write failing domain inventory tests**

```python
def test_public_domain_inventory_is_classified(schema_inventory):
    assert schema_inventory.unclassified_rest_operations == set()
    assert schema_inventory.rest_only_binary == {"download_report", "download_artifact"}

def test_sensitive_fields_do_not_exist(schema):
    text = str(schema)
    assert not {"credentialValue", "webhookSecret", "objectKey", "scimToken"} & schema_field_names(text)
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_domain_queries.py`
Expected: FAIL because inventory and domain types are incomplete.

- [ ] **Step 3: Add typed projections and feature-aware fields**

Every resolver calls a domain service. For unimplemented phase dependencies, the schema remains stable and returns a typed `FEATURE_DISABLED` error until its feature flag is enabled; it must not fabricate data.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_domain_queries.py`
Expected: PASS with no unclassified REST business operation.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/types backend/app/graphql/queries backend/app/graphql/schema.py backend/tests/unit/test_graphql_domain_queries.py
git commit -m "feat: expose supported graphql query domains"
```

### Task 6: Service-backed mutations, idempotency, and bulk limits

**Files:**
- Create: `backend/app/graphql/types/mutations.py`
- Create: `backend/app/graphql/mutations/exposure.py`
- Create: `backend/app/graphql/mutations/operations.py`
- Create: `backend/app/graphql/mutations/agents.py`
- Create: `backend/app/graphql/mutations/pipelines.py`
- Modify: `backend/app/graphql/schema.py`
- Test: `backend/tests/unit/test_graphql_mutations.py`

**Interfaces:**
- Produces: typed mutation payloads with resource, item errors, audit event ID, and client mutation ID.
- Consumes: domain services, idempotency store, audit service, permissions.

- [ ] **Step 1: Write failing parity/idempotency tests**

```python
async def test_retrying_idempotent_mutation_returns_one_effect(graphql, jira):
    first = await graphql.create_ticket(input=ticket_input(), key="same-key")
    second = await graphql.create_ticket(input=ticket_input(), key="same-key")
    assert first.ticket.id == second.ticket.id
    assert jira.created_count == 1

def test_bulk_over_limit_fails_before_any_write(graphql):
    result = graphql.bulk_assign(items=[assignment() for _ in range(101)])
    assert result.code == "BULK_LIMIT_EXCEEDED"
    assert assigned_count() == 0
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_mutations.py`
Expected: FAIL on missing mutations.

- [ ] **Step 3: Implement thin mutations and stable payloads**

```python
@strawberry.type
class MutationPayload(Generic[T]):
    resource: T | None
    errors: list[UserError]
    audit_event_id: strawberry.ID | None
    client_mutation_id: str | None
```

Bind idempotency entries to organization, actor, operation, and canonical input digest. Reject key reuse with different input.

- [ ] **Step 4: Run mutation and service parity tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_mutations.py tests/unit/test_idempotency.py tests/unit/test_authorization.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/types/mutations.py backend/app/graphql/mutations backend/app/graphql/schema.py backend/tests/unit/test_graphql_mutations.py
git commit -m "feat: add idempotent graphql mutations"
```

### Task 7: Persisted operations for the web application

**Files:**
- Create: `backend/app/graphql/persisted.py`
- Create: `frontend/src/lib/graphql/client.ts`
- Create: `frontend/src/lib/graphql/operations.graphql`
- Create: `frontend/scripts/build-graphql-manifest.mjs`
- Modify: `frontend/package.json`
- Test: `backend/tests/unit/test_graphql_persisted.py`
- Test: `frontend/src/lib/graphql/client.test.ts`

**Interfaces:**
- Produces: checked-in operation manifest, hash-only production requests, typed web client.
- Consumes: generated schema artifact, frontend authentication transport.

- [ ] **Step 1: Write failing manifest/hash tests**

```python
def test_unknown_hash_is_rejected_in_manifest_only_mode(client):
    result = client.post("/api/graphql", json={"extensions": {"persistedQuery": {"sha256Hash": "0" * 64}}})
    assert result.json()["errors"][0]["extensions"]["code"] == "UNKNOWN_OPERATION"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_persisted.py` and `npm --prefix frontend test -- graphql/client.test.ts`
Expected: FAIL on absent registry/client.

- [ ] **Step 3: Build deterministic manifest and web transport**

```typescript
export async function executePersisted<T>(operation: Operation<T>, variables: object): Promise<T> {
  return graphqlFetch({ operationName: operation.name, variables, extensions: { persistedQuery: { version: 1, sha256Hash: operation.hash } } });
}
```

Validate every manifest operation against the checked-in schema in CI; never treat persisted operations as an authorization boundary.

- [ ] **Step 4: Run tests and frontend build**

Run: `cd backend && pytest -q tests/unit/test_graphql_persisted.py`

Run: `npm --prefix frontend test -- graphql/client.test.ts && npm --prefix frontend run build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/persisted.py frontend/src/lib/graphql frontend/scripts/build-graphql-manifest.mjs frontend/package.json backend/tests/unit/test_graphql_persisted.py
git commit -m "feat: add persisted graphql web operations"
```

### Task 8: Depth, alias, fragment, cost, rate, and introspection controls

**Files:**
- Create: `backend/app/graphql/validation.py`
- Create: `backend/app/graphql/rate_limit.py`
- Modify: `backend/app/graphql/schema.py`
- Modify: `backend/app/core/config.py`
- Test: `backend/tests/unit/test_graphql_validation.py`

**Interfaces:**
- Produces: normalized executable selection graph, query cost, rate decision, scoped introspection policy.
- Consumes: parsed GraphQL document, operation variables, principal/scopes, Redis limiter.

- [ ] **Step 1: Write failing adversarial query tests**

```python
@pytest.mark.parametrize("document", [alias_bomb(200), recursive_fragment_bomb(), wide_fragment_bomb(500)])
def test_aliases_and_fragments_cannot_hide_cost(document, validator):
    with pytest.raises(QueryRejected) as exc:
        validator.validate(document, variables={"first": 100})
    assert exc.value.code in {"QUERY_TOO_COMPLEX", "QUERY_TOO_DEEP", "QUERY_TOO_LARGE"}

def test_api_key_without_schema_scope_cannot_introspect(prod_graphql):
    assert error_code(prod_graphql.execute(INTROSPECTION_QUERY)) == "INTROSPECTION_DISABLED"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_validation.py`
Expected: FAIL because validation controls are absent.

- [ ] **Step 3: Implement expanded-selection validation and atomic rate charging**

```python
@dataclass(frozen=True)
class QueryBudget:
    max_depth: int = 12
    max_nodes: int = 1000
    max_cost: int = 5000
    max_aliases: int = 100
```

Resolve fragment spreads with cycle detection, count aliases separately, multiply connection field cost by bounded `first`, and rate charge user/key and organization in one Redis operation.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_validation.py tests/unit/test_rate_limits.py`
Expected: PASS under adversarial documents.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/validation.py backend/app/graphql/rate_limit.py backend/app/graphql/schema.py backend/app/core/config.py backend/tests/unit/test_graphql_validation.py
git commit -m "feat: bound graphql query execution"
```

### Task 9: Durable replayable subscriptions

**Files:**
- Create: `backend/app/graphql/subscriptions.py`
- Create: `backend/app/services/subscription_events.py`
- Modify: `backend/app/graphql/schema.py`
- Modify: `backend/app/services/events.py`
- Test: `backend/tests/unit/test_graphql_subscriptions.py`

**Interfaces:**
- Produces: `graphql-transport-ws` subscriptions for runs, jobs, findings, approvals, pipelines, and notifications.
- Consumes: PostgreSQL event log, Redis notifications, current membership/role checks.

- [ ] **Step 1: Write failing replay/revocation/backpressure tests**

```python
async def test_membership_revocation_terminates_open_stream(subscription, revoke_member):
    stream = await subscription.open(after=0)
    await stream.__anext__()
    await revoke_member()
    with pytest.raises(SubscriptionClosed, match="AUTHORITY_REVOKED"):
        await stream.__anext__()

async def test_reconnect_replays_postgres_events_after_cursor(subscription):
    assert [e.sequence for e in await subscription.collect(after=2, count=2)] == [3, 4]
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_graphql_subscriptions.py`
Expected: FAIL on missing subscription transport.

- [ ] **Step 3: Implement replay-then-live stream with per-event authorization**

```python
async def authorized_events(context, topic, after):
    async for event in replay_then_subscribe(topic, after, queue_size=100):
        principal = await refresh_principal(context)
        authorize_event(principal, event)
        yield event
```

On slow-client overflow, close with a safe reconnect cursor rather than dropping silently or growing memory.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_graphql_subscriptions.py tests/unit/test_events.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/graphql/subscriptions.py backend/app/services/subscription_events.py backend/app/graphql/schema.py backend/app/services/events.py backend/tests/unit/test_graphql_subscriptions.py
git commit -m "feat: stream durable graphql subscriptions"
```

### Task 10: Shared Python SDK transports, models, and retry policy

**Files:**
- Modify: `sdk/python/pyproject.toml`
- Create: `sdk/python/cynux/transport.py`
- Create: `sdk/python/cynux/auth.py`
- Create: `sdk/python/cynux/errors.py`
- Create: `sdk/python/cynux/models.py`
- Create: `sdk/python/cynux/graphql.py`
- Test: `sdk/python/tests/test_transport.py`
- Test: `sdk/python/tests/test_secrets.py`

**Interfaces:**
- Produces: shared serializers, auth, sync/async HTTP/WS transports, public exceptions, typed models.
- Consumes: API key or callback token provider, checked-in operation documents.

- [ ] **Step 1: Write failing retry and secret-redaction tests**

```python
def test_non_idempotent_mutation_is_never_retried(fake_http):
    fake_http.fail_transport_then_succeed()
    with pytest.raises(CynuxTransportError):
        transport.execute(MUTATION, {}, idempotency_key=None)
    assert fake_http.calls == 1

def test_api_key_is_absent_from_repr_exception_and_logs(caplog):
    client = CynuxClient(api_key="cx_live_secret")
    assert "cx_live_secret" not in repr(client)
    assert "cx_live_secret" not in captured_failure(client, caplog)
```

- [ ] **Step 2: Verify failures**

Run: `cd sdk/python && pytest -q tests/test_transport.py tests/test_secrets.py`
Expected: FAIL because shared transport policy is absent.

- [ ] **Step 3: Implement shared policy and sync/async adapters**

```python
@dataclass(frozen=True, repr=False)
class ApiKeyAuth:
    value: SecretStr
    def __repr__(self) -> str:
        return "ApiKeyAuth(***)"

def may_retry(operation: Operation, idempotency_key: str | None, error: Exception) -> bool:
    return operation.kind == "query" or (operation.retryable and idempotency_key is not None)
```

Bound exponential backoff by caller deadline and honor `Retry-After`; preserve request IDs on typed exceptions.

- [ ] **Step 4: Run SDK transport tests**

Run: `cd sdk/python && pytest -q tests/test_transport.py tests/test_secrets.py`
Expected: PASS for sync and async parameterized transports.

- [ ] **Step 5: Commit**

```bash
git add sdk/python/pyproject.toml sdk/python/cynux sdk/python/tests/test_transport.py sdk/python/tests/test_secrets.py
git commit -m "feat: harden cynux python sdk transports"
```

### Task 11: Ergonomic sync/async SDK domains and streaming

**Files:**
- Modify: `sdk/python/cynux/client.py`
- Create: `sdk/python/cynux/async_client.py`
- Create: `sdk/python/cynux/operations.py`
- Create: `sdk/python/cynux/resources/agents.py`
- Create: `sdk/python/cynux/resources/exposure.py`
- Create: `sdk/python/cynux/resources/operations.py`
- Create: `sdk/python/cynux/resources/pipelines.py`
- Modify: `sdk/python/cynux/__init__.py`
- Test: `sdk/python/tests/test_clients.py`
- Test: `sdk/python/tests/test_agent_stream.py`

**Interfaces:**
- Produces: `CynuxClient`, `AsyncCynuxClient`, cursor iterators, agent submit/approve/cancel/stream, knowledge, exposure, assessments, integrations, reports, automation, and pipeline facades.
- Consumes: Task 10 transports and checked-in GraphQL operations.

- [ ] **Step 1: Write failing facade tests**

```python
async def test_async_agent_flow(async_client):
    run = await async_client.agents.submit_objective("triage critical findings")
    events = [event async for event in async_client.agents.events(run.id)]
    assert events[-1].terminal

def test_cursor_iterator_fetches_lazily(client, fake_transport):
    assert [x.id for x in client.findings.iter(limit=3)] == expected_ids
    assert fake_transport.calls == 2
```

- [ ] **Step 2: Verify failures**

Run: `cd sdk/python && pytest -q tests/test_clients.py tests/test_agent_stream.py`
Expected: FAIL on missing facades/streaming.

- [ ] **Step 3: Implement stable resource facades and bounded streaming uploads**

```python
class AsyncCynuxClient:
    async def __aenter__(self) -> "AsyncCynuxClient":
        return self
    async def __aexit__(self, *_exc) -> None: await self.close()

    @property
    def agents(self) -> AsyncAgentResource:
        return AsyncAgentResource(self._transport)
```

REST-only binary upload/download uses the same auth, timeout, request-ID, retry, and redaction policy.

- [ ] **Step 4: Run all SDK tests**

Run: `cd sdk/python && pytest -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sdk/python/cynux sdk/python/tests
git commit -m "feat: expand cynux python sdk domains"
```

### Task 12: Contracts, compatibility, load, and staged rollout

**Files:**
- Create: `backend/tests/contracts/test_graphql_schema_compatibility.py`
- Create: `backend/tests/integration/test_graphql_rest_parity.py`
- Create: `backend/tests/integration/test_graphql_load.py`
- Create: `sdk/python/tests/integration/test_production_flows.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `backend/app/core/config.py`
- Modify: `infra/gcp/verify.ps1`

**Interfaces:**
- Produces: checked schema contract, REST parity matrix, SDK compatibility gate, canary feature controls.
- Consumes: all prior tasks.

- [ ] **Step 1: Write failing compatibility and production-flow tests**

```python
def test_schema_has_no_unapproved_breaking_changes(released_schema, current_schema):
    assert diff_breaking(released_schema, current_schema) == []

async def test_sdk_complete_scoped_key_flow(production_stack):
    result = await production_stack.sdk.create_query_approve_stream()
    assert result.audit_event_id
```

- [ ] **Step 2: Run and confirm rollout gates are absent**

Run: `cd backend && pytest -q tests/contracts/test_graphql_schema_compatibility.py tests/integration/test_graphql_rest_parity.py tests/integration/test_graphql_load.py`

Run: `cd sdk/python && pytest -q tests/integration/test_production_flows.py`
Expected: FAIL before CI artifacts, flags, and production-like fixtures exist.

- [ ] **Step 3: Add contract generation, metrics, alerts, and canary flags**

Add `CYNUX_FEATURES__GRAPHQL`, per-operation cost/latency/error metrics, subscription queue/replay metrics, SDK compatibility headers, schema diff gate, and organization allowlist. Preserve REST fallback during rollout.

- [ ] **Step 4: Run complete verification**

Run: `cd backend && pytest -q tests/unit/test_graphql_schema.py tests/unit/test_graphql_auth.py tests/unit/test_graphql_pagination.py tests/unit/test_graphql_loaders.py tests/unit/test_graphql_exposure_queries.py tests/unit/test_graphql_domain_queries.py tests/unit/test_graphql_mutations.py tests/unit/test_graphql_persisted.py tests/unit/test_graphql_validation.py tests/unit/test_graphql_subscriptions.py tests/contracts/test_graphql_schema_compatibility.py tests/integration/test_graphql_rest_parity.py tests/integration/test_graphql_load.py`

Run: `cd sdk/python && pytest -q`

Run: `npm --prefix frontend test -- graphql/client.test.ts && npm --prefix frontend run build`
Expected: selected suites pass. Run the full backend/frontend suites and report the known baseline failures before enabling the canary.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/contracts backend/tests/integration/test_graphql_rest_parity.py backend/tests/integration/test_graphql_load.py sdk/python/tests/integration .github/workflows/ci.yml backend/app/core/config.py infra/gcp/verify.ps1
git commit -m "ops: gate graphql and sdk production rollout"
```
