# ASM and Threat Intelligence Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Cynux ASM and threat feeds into continuously observed, provenance-rich asset and vulnerability intelligence that drives deterministic risk updates.

**Architecture:** Store immutable source observations separately from current asset and intelligence projections. Collectors emit normalized observations; correlation and reconciliation update canonical assets, relationships, certificate/DNS/service state, brand candidates, credential-exposure events, CVE/advisory assertions, and risk inputs without destroying conflicting evidence.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Redis, httpx, dnspython, cryptography, public/vendor feeds, Next.js, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-16-market-parity-platform-design.md`

## Global Constraints

- Active probes require a current ASM authorization and allowed target scope.
- Observations retain provider, reference, observed time, confidence, license, and digest.
- Feed reconciliation supersedes assertions but never deletes historical provenance.
- Leaked-credential evidence never contains plaintext passwords or recoverable secrets.
- Risk changes are deterministic from versioned inputs and scoring configuration.

## Review Focus

- A wildcard certificate covering an unrelated delegated namespace must not claim ownership automatically; covered by Task 2.
- DNS rebinding and split-horizon answers must not allow active probing outside authorized scope; covered by Task 2.
- Unicode/confusable brand candidates must be normalized without collapsing distinct domains; covered by Task 3.
- A feed retracting an assertion must preserve history while removing it from current risk; covered by Task 5.
- Conflicting actor/ransomware claims with different confidence must remain independently inspectable; covered by Task 5.

---

### Task 1: Versioned ASM observation and relationship model

**Files:**
- Create: `backend/alembic/versions/0102_asm_observations.py`
- Modify: `backend/app/db/models/asm.py`
- Modify: `backend/app/db/models/__init__.py`
- Create: `backend/app/services/asm_observations.py`
- Test: `backend/tests/unit/test_asm_observations.py`
- Test: `backend/tests/unit/test_migration_matches_models.py`

**Interfaces:**
- Consumes: `AsmSurface`, assets, source integrations, and object storage evidence.
- Produces: `AsmObservation`, `AssetRelationship`, `CertificateState`, `DnsState`, `ServiceState`, `record_observation()`, and `project_surface_state()`.

- [ ] **Step 1: Write failing idempotency and provenance tests**

```python
async def test_same_source_fact_is_idempotent_but_new_observation_time_is_history(service):
    first = await service.record(source="ct", reference="log:1", observed_at=t1, fact=cert_fact())
    duplicate = await service.record(source="ct", reference="log:1", observed_at=t1, fact=cert_fact())
    later = await service.record(source="ct", reference="log:2", observed_at=t2, fact=cert_fact())
    assert first.id == duplicate.id
    assert later.id != first.id

async def test_projection_keeps_conflicting_provenance(service):
    await service.record(source="dns-a", fact={"a": "203.0.113.1"}, confidence=.9)
    await service.record(source="dns-b", fact={"a": "203.0.113.2"}, confidence=.7)
    projection = await service.project()
    assert len(projection.assertions) == 2
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_asm_observations.py tests/unit/test_migration_matches_models.py`

Expected: FAIL on missing observation persistence.

- [ ] **Step 3: Implement immutable observations and projections**

Observation identity is `(organization_id, source, source_reference, fact_digest)`. Relationships include `resolves_to`, `serves`, `certifies`, `hosted_by`, `depends_on`, `owned_by`, and `discovered_from`, each with confidence and evidence. Current-state tables point to the observations used for projection.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_asm_observations.py tests/unit/test_migration_matches_models.py tests/unit/test_orm_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0102_asm_observations.py backend/app/db/models/asm.py backend/app/db/models/__init__.py backend/app/services/asm_observations.py backend/tests/unit/test_asm_observations.py backend/tests/unit/test_migration_matches_models.py
git commit -m "feat: persist ASM observations and relationships"
```

### Task 2: Certificate, DNS, and authorized service monitoring

**Files:**
- Create: `backend/app/services/asm_certificates.py`
- Create: `backend/app/services/asm_dns.py`
- Create: `backend/app/services/asm_services.py`
- Modify: `backend/app/services/asm_discovery.py`
- Test: `backend/tests/unit/test_asm_certificates.py`
- Test: `backend/tests/unit/test_asm_dns.py`
- Test: `backend/tests/unit/test_asm_service_scope.py`

**Interfaces:**
- Consumes: Task 1 observation writer and `AsmSurface` authorization.
- Produces: CT/certificate collector, DNS snapshot collector, scoped active service probe, expiry and drift events.

- [ ] **Step 1: Write failing ownership, rebinding, and expiry tests**

```python
def test_wildcard_certificate_does_not_auto_claim_unapproved_namespace(correlator):
    result = correlator.correlate("*.vendor.example", tenant_roots={"customer.example"})
    assert result.ownership == "candidate"

async def test_split_horizon_or_rebinding_target_is_not_probed(prober, dns):
    dns.answers = [["203.0.113.10"], ["10.0.0.5"]]
    with pytest.raises(ScopeDenied, match="dns_answer_changed"):
        await prober.probe("app.customer.example")

def test_certificate_expiry_events_are_bucketed_once(projector):
    events = projector.events_for(expiry_in_days=7)
    assert [event.kind for event in events] == ["certificate.expiring_7d"]
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_asm_certificates.py tests/unit/test_asm_dns.py tests/unit/test_asm_service_scope.py`

Expected: FAIL because the collectors are absent.

- [ ] **Step 3: Implement collectors and scoped probes**

Normalize IDNA hostnames, SANs, issuers, serials, validity, DNS RRsets, TTLs, resolved addresses, ports, TLS metadata, HTTP metadata, and technology evidence. Active probes revalidate authorization, exact hostname/IP scope, and DNS answers immediately before connecting; private destinations require an explicitly configured private runner.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_asm_certificates.py tests/unit/test_asm_dns.py tests/unit/test_asm_service_scope.py tests/unit/test_scan_execution_authority.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/asm_certificates.py backend/app/services/asm_dns.py backend/app/services/asm_services.py backend/app/services/asm_discovery.py backend/tests/unit/test_asm_certificates.py backend/tests/unit/test_asm_dns.py backend/tests/unit/test_asm_service_scope.py
git commit -m "feat: monitor certificates DNS and services"
```

### Task 3: Cloud, repository, third-party, and brand discovery

**Files:**
- Create: `backend/app/services/asm_cloud.py`
- Create: `backend/app/services/asm_repositories.py`
- Create: `backend/app/services/asm_third_party.py`
- Create: `backend/app/services/asm_brand.py`
- Test: `backend/tests/unit/test_asm_cloud.py`
- Test: `backend/tests/unit/test_asm_third_party.py`
- Test: `backend/tests/unit/test_asm_brand.py`

**Interfaces:**
- Consumes: connector manifests, cloud/repository integrations, Task 1 observations.
- Produces: cloud/repository asset observations, third-party relationships, reviewed brand/typosquat candidates.

- [ ] **Step 1: Write failing correlation and Unicode tests**

```python
async def test_cloud_resource_and_dns_name_link_through_evidence(service):
    relation = await service.correlate(cloud_lb("lb-1", "app.example"), dns_a("app.example"))
    assert relation.kind == "served_by"
    assert len(relation.evidence_ids) == 2

def test_unicode_brand_candidates_preserve_distinct_domains(detector):
    candidates = detector.candidates("cynux.example", ["cynuх.example", "cynux-example.com"])
    assert len({item.ascii_domain for item in candidates}) == 2
    assert all(item.state == "candidate" for item in candidates)

def test_dependency_domain_creates_third_party_not_owned_asset(correlator):
    result = correlator.from_csp("script-src https://cdn.vendor.example")
    assert result.relationship == "depends_on"
    assert result.asset.ownership == "third_party"
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_asm_cloud.py tests/unit/test_asm_third_party.py tests/unit/test_asm_brand.py`

Expected: FAIL on missing discovery services.

- [ ] **Step 3: Implement evidence-based correlations**

Cloud and repository collectors consume read capabilities only. Third-party inference uses DNS delegation, certificate organization, HTTP dependencies, CSP, repository manifests, and cloud relationships with explainable confidence. Brand candidates use IDNA, confusable skeleton, edit distance, token insertion, and certificate/DNS observations; all begin in review state.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_asm_cloud.py tests/unit/test_asm_third_party.py tests/unit/test_asm_brand.py tests/unit/test_asset_cmdb.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/asm_cloud.py backend/app/services/asm_repositories.py backend/app/services/asm_third_party.py backend/app/services/asm_brand.py backend/tests/unit/test_asm_cloud.py backend/tests/unit/test_asm_third_party.py backend/tests/unit/test_asm_brand.py
git commit -m "feat: discover cloud third-party and brand exposure"
```

### Task 4: Privacy-preserving credential exposure events

**Files:**
- Create: `backend/alembic/versions/0103_credential_exposure_events.py`
- Modify: `backend/app/db/models/asm.py`
- Create: `backend/app/services/credential_exposure.py`
- Test: `backend/tests/unit/test_credential_exposure.py`
- Test: `backend/tests/unit/test_logging_redaction.py`

**Interfaces:**
- Consumes: authorized external feed records and organization verified-domain policy.
- Produces: `CredentialExposureEvent`, minimized identity hash, provider evidence, review/notify/resolve lifecycle.

- [ ] **Step 1: Write failing minimization and scope tests**

```python
def test_plaintext_secret_is_never_persisted_or_logged(service, caplog):
    event = service.normalize({"email": "alice@example.com", "password": "hunter2", "breach": "x"})
    serialized = event.model_dump_json() + caplog.text
    assert "hunter2" not in serialized
    assert event.identity_hint == "a***@example.com"
    assert event.identity_hash

def test_unverified_domain_event_is_rejected(service):
    with pytest.raises(ExposureScopeDenied):
        service.normalize({"email": "person@other.example", "breach": "x"})
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_credential_exposure.py tests/unit/test_logging_redaction.py`

Expected: FAIL because exposure events are absent.

- [ ] **Step 3: Implement minimized ingestion**

Persist HMAC identity hash, masked hint, verified domain, breach/provider identifiers, dates, categories, confidence, provider reference, and status. Drop plaintext password, full credential, provider raw body, and unnecessary personal attributes before constructing ORM objects or log context.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_credential_exposure.py tests/unit/test_logging_redaction.py tests/unit/test_migration_matches_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0103_credential_exposure_events.py backend/app/db/models/asm.py backend/app/services/credential_exposure.py backend/tests/unit/test_credential_exposure.py backend/tests/unit/test_logging_redaction.py
git commit -m "feat: ingest minimized credential exposure events"
```

### Task 5: Versioned vulnerability and threat assertion graph

**Files:**
- Create: `backend/alembic/versions/0104_threat_assertion_graph.py`
- Modify: `backend/app/db/models/threat_intelligence.py`
- Create: `backend/app/services/threat_assertions.py`
- Modify: `backend/app/services/threat_feed.py`
- Test: `backend/tests/unit/test_threat_assertions.py`
- Test: `backend/tests/unit/test_threat_feed_retractions.py`

**Interfaces:**
- Consumes: NVD, KEV, EPSS, MISP, vendor advisories, and licensed provider observations.
- Produces: versioned assertions for CVE/CWE/CPE/advisory/patch/exploit/malware/ransomware/campaign/actor relationships and current projections.

- [ ] **Step 1: Write failing retraction and conflict tests**

```python
async def test_retracted_assertion_leaves_history_but_exits_current_projection(service):
    assertion = await service.assert_fact(source="feed-a", subject="CVE-1", predicate="exploited", value=True)
    await service.retract(assertion.id, provider_reference="feed-a:retraction")
    assert await service.historical(assertion.id)
    assert not await service.current_contains(assertion.id)

async def test_conflicting_actor_claims_remain_visible(service):
    await service.assert_fact(source="a", subject="CVE-1", predicate="used_by", value="Actor-X", confidence=.8)
    await service.assert_fact(source="b", subject="CVE-1", predicate="used_by", value="Actor-Y", confidence=.6)
    assert len(await service.current_claims("CVE-1", "used_by")) == 2
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_threat_assertions.py tests/unit/test_threat_feed_retractions.py`

Expected: FAIL on missing versioned assertion service.

- [ ] **Step 3: Implement append-only assertions and feed checkpoints**

Assertions store normalized subject/predicate/object, confidence, source, source reference, published/observed/retrieved times, license, digest, supersedes/retracts link, and current flag. Feed checkpoints settle only after batch commit and allow resumption by cursor or conditional request metadata.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_threat_assertions.py tests/unit/test_threat_feed_retractions.py tests/unit/test_threat_feed_aggregation.py tests/unit/test_migration_matches_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0104_threat_assertion_graph.py backend/app/db/models/threat_intelligence.py backend/app/services/threat_assertions.py backend/app/services/threat_feed.py backend/tests/unit/test_threat_assertions.py backend/tests/unit/test_threat_feed_retractions.py
git commit -m "feat: add versioned threat assertion graph"
```

### Task 6: Risk integration, APIs, and operations UI

**Files:**
- Modify: `backend/app/services/canonical_intel_refresh.py`
- Modify: `backend/app/services/canonical_risk_refresh.py`
- Modify: `backend/app/api/v1/asm.py`
- Modify: `backend/app/api/v1/threat_intelligence.py`
- Modify: `backend/app/graphql/queries.py`
- Create: `frontend/src/lib/asm-intelligence.ts`
- Modify: `frontend/src/app/(app)/asm/page.tsx`
- Modify: `frontend/src/app/(app)/threat-intelligence/page.tsx`
- Test: `backend/tests/unit/test_intelligence_risk_projection.py`
- Test: `frontend/src/lib/asm-intelligence.test.ts`

**Interfaces:**
- Consumes: Tasks 1-5 projections.
- Produces: deterministic risk-input snapshots, timelines, review actions, freshness/coverage dashboards, and GraphQL/REST queries.

- [ ] **Step 1: Write failing deterministic risk and view tests**

```python
async def test_same_assertion_version_produces_same_risk_snapshot(service):
    first = await service.refresh(finding_id=FINDING_ID, as_of=NOW)
    second = await service.refresh(finding_id=FINDING_ID, as_of=NOW)
    assert first.input_digest == second.input_digest
    assert first.score == second.score

def test_retraction_removes_current_actor_weight_but_not_timeline(projector):
    before, after = projector.timeline_with_retraction()
    assert before.actor_weight > 0 and after.actor_weight == 0
    assert after.previous_snapshot_id == before.id
```

```typescript
it("labels stale and conflicting intelligence instead of hiding it", () => {
  expect(intelBadge({ freshness: "stale", conflicts: 2 })).toBe("Stale · 2 conflicts")
})
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_intelligence_risk_projection.py`

Run: `npm --prefix frontend test -- asm-intelligence.test.ts`

Expected: FAIL on missing projection and view model.

- [ ] **Step 3: Implement service-backed risk refresh and UI**

Risk snapshots pin assertion IDs and scoring version. UI exposes asset change timelines, certificate/DNS/service state, brand and credential review queues, intelligence provenance, conflicts, retractions, freshness, and coverage without rendering raw secrets.

- [ ] **Step 4: Run tests and build**

Run: `cd backend && pytest -q tests/unit/test_intelligence_risk_projection.py tests/unit/test_canonical_intel_refresh.py tests/unit/test_canonical_risk_refresh.py`

Run: `npm --prefix frontend test -- asm-intelligence.test.ts && npm --prefix frontend run build`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/canonical_intel_refresh.py backend/app/services/canonical_risk_refresh.py backend/app/api/v1/asm.py backend/app/api/v1/threat_intelligence.py backend/app/graphql/queries.py frontend/src/lib/asm-intelligence.ts frontend/src/lib/asm-intelligence.test.ts frontend/src/app/\(app\)/asm/page.tsx frontend/src/app/\(app\)/threat-intelligence/page.tsx backend/tests/unit/test_intelligence_risk_projection.py
git commit -m "feat: operationalize ASM and threat intelligence"
```

### Task 7: Production acceptance and feed rollout

**Files:**
- Create: `backend/tests/integration/test_asm_intel_flow.py`
- Create: `backend/tests/integration/test_asm_scope_isolation.py`
- Create: `infra/gcp/verify-asm-intel.ps1`
- Modify: `backend/app/core/config.py`
- Modify: `infra/gcp/main.tf`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: complete ASM/intelligence slice.
- Produces: feature gate, collector schedules, feed freshness alerts, scope probe, and canary verification.

- [ ] **Step 1: Write failing production flow**

```python
@pytest.mark.integration
async def test_discovery_to_risk_with_retraction(stack):
    asset = await stack.discover_domain_certificate_dns_and_service()
    finding = await stack.attach_cve_finding(asset)
    assertion = await stack.ingest_actor_ransomware_patch_assertions(finding.cve)
    raised = await stack.refresh_risk(finding)
    await stack.retract(assertion.actor_link)
    lowered = await stack.refresh_risk(finding)
    assert raised.score > lowered.score
    assert lowered.previous_snapshot_id == raised.id
    assert await stack.provenance_complete(finding)
```

- [ ] **Step 2: Run acceptance**

Run: `cd backend && pytest -q tests/integration/test_asm_intel_flow.py tests/integration/test_asm_scope_isolation.py`

Expected: FAIL before rollout wiring exists.

- [ ] **Step 3: Add flags, schedules, metrics, alerts, and safe verifier**

Add `CYNUX_FEATURES__ASM_INTEL_V2`, organization allowlist, collector/feed kill switches, bounded concurrency, conditional-fetch caches, and metrics for source freshness, collector outcome, new/change counts, scope denials, assertion conflicts, retractions, and risk refresh lag. Verification uses owned test domains and fixture feeds only.

- [ ] **Step 4: Run complete verification**

Run: `cd backend && pytest -q tests/unit/test_asm_*.py tests/unit/test_credential_exposure.py tests/unit/test_threat_*.py tests/unit/test_intelligence_risk_projection.py tests/integration/test_asm_*.py`

Run: `terraform -chdir=infra/gcp validate`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_asm_intel_flow.py backend/tests/integration/test_asm_scope_isolation.py infra/gcp/verify-asm-intel.ps1 backend/app/core/config.py infra/gcp/main.tf .github/workflows/ci.yml
git commit -m "ops: roll out ASM and intelligence expansion"
```

