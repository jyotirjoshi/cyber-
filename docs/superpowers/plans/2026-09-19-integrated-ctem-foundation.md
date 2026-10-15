# Integrated CTEM Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the shared, tenant-safe data and API contracts for integrated CTEM engagement profiles, BYOK setup, and proof validation.

**Architecture:** Existing assessments and findings are extended with additive columns and typed schemas. The existing encrypted integration vault receives the LLM provider contract; no key ever leaves the backend. Existing approval and authorization models remain the policy authority for all future execution features.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic, Pydantic 2, PostgreSQL JSONB, Next.js 15.

**Spec:** `docs/superpowers/specs/2026-09-19-integrated-ctem-platform-design.md`

## Global Constraints

- Active testing requires explicit authorization and existing approval gates.
- All additions are additive migrations with safe defaults for existing rows.
- API keys are encrypted per organization and write-only at the API boundary.
- No implementation may weaken tenant filtering, audit logging, or host validation.
- Do not introduce a parallel assessment, finding, or integration model.

---

### Task 1: Add engagement profile and validation-proof vocabulary

**Files:**
- Modify: `backend/app/db/enums.py`
- Modify: `backend/app/db/models/assessment.py`
- Modify: `backend/app/db/models/finding.py`
- Create: `backend/alembic/versions/0004_ctem_foundation.py`
- Test: `backend/tests/unit/test_ctem_foundation.py`

**Interfaces:**
- Produces `EngagementType`, `ExecutionMode`, and `ValidationStatus` enums for existing schemas and services.
- Produces additive `Assessment` and `Finding` fields used by later API/UI slices.

- [ ] **Step 1: Write failing migration/model tests**

Assert that a legacy assessment defaults to `web_application` and `supervised`, and a legacy finding defaults to `unvalidated` with an empty proof object.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `pytest tests/unit/test_ctem_foundation.py -q`

Expected: FAIL because the enum values and mapped fields do not yet exist.

- [ ] **Step 3: Add the minimal model, enum, and migration changes**

Add check-constrained, defaulted engagement and validation fields. The migration uses `sa.text` for all PostgreSQL JSONB defaults.

- [ ] **Step 4: Re-run focused and migration tests**

Run: `pytest tests/unit/test_ctem_foundation.py tests/unit/test_migration_matches_models.py -q`

Expected: PASS.

### Task 2: Implement tenant-scoped BYOK LLM configuration

**Files:**
- Modify: `backend/app/db/enums.py`
- Modify: `backend/app/services/integration.py`
- Modify: `backend/app/llm/gateway.py`
- Modify: `backend/app/api/deps.py`
- Modify: `backend/app/schemas/integration.py`
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/app/(app)/integrations/page.tsx`
- Test: `backend/tests/unit/test_byok_llm.py`

**Interfaces:**
- Consumes an authenticated `Principal`, organization-scoped `Integration`, and write-only provider key.
- Produces an LLM gateway configured only for the caller's organization and a setup-required response when absent.

- [ ] **Step 1: Write failing tenant-isolation tests**

Assert that one organization's LLM credential cannot resolve for another organization, and that the credential never appears in an integration response.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `pytest tests/unit/test_byok_llm.py -q`

Expected: FAIL because no LLM integration kind or tenant resolver exists.

- [ ] **Step 3: Add the smallest resolver and UI configuration contract**

Add `llm` as an encrypted integration kind with `provider` and `default_model` as non-secret configuration and exactly one provider API key as a credential. Resolve it per request instead of using a global deployment key.

- [ ] **Step 4: Verify security and API behavior**

Run: `pytest tests/unit/test_byok_llm.py tests/unit/test_tenant_isolation.py -q` and `npm --prefix frontend run typecheck`.

Expected: PASS; no client type exposes a key.

### Task 3: Expose proof-validation state through existing finding APIs

**Files:**
- Modify: `backend/app/schemas/finding.py`
- Modify: `backend/app/services/finding.py`
- Modify: `backend/app/api/v1/findings.py`
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/app/(app)/findings/[id]/page.tsx`
- Test: `backend/tests/unit/test_validation_proofs.py`

**Interfaces:**
- Consumes a finding's normalized type and evidence.
- Produces immutable validation evidence and state: `unvalidated`, `confirmed`, `rejected`, or `recheck_required`.

- [ ] **Step 1: Write failing proof-transition tests**

Assert an unvalidated finding cannot transition to `confirmed` without a non-empty proof payload and that a proof update is tenant-scoped and audited.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `pytest tests/unit/test_validation_proofs.py -q`

Expected: FAIL because the validation state API does not yet exist.

- [ ] **Step 3: Implement minimal proof transition service and endpoint**

Add a typed transition endpoint that accepts evidence metadata, records an audit event, and never permits a caller to overwrite a prior proof silently.

- [ ] **Step 4: Verify focused, tenant, and frontend checks**

Run: `pytest tests/unit/test_validation_proofs.py tests/unit/test_tenant_isolation.py -q` and `npm --prefix frontend run typecheck`.

Expected: PASS.
