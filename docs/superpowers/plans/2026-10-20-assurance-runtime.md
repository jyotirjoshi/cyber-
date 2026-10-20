# Assurance Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert cyber-ai's control-plane recommendations, AI policies, agent work, validation, DSPM, SOC, risk, and compliance records into one evidence-backed assurance runtime.

**Architecture:** Add tenant-scoped assurance records and deterministic services around existing domain objects. External effects remain adapter-owned and approval-bound; raw sensitive payloads remain transient while durable state consists of canonical digests, bounded metadata, artifact references, and verification receipts.

**Tech Stack:** Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2, PostgreSQL 16, Redis workers, Next.js 15, TypeScript, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-20-assurance-runtime-design.md`

## Global Constraints

- Preserve tenant isolation and current RBAC on every query and mutation.
- Never store raw prompts, outputs, secrets, sampled customer content, or provider bodies.
- External mutations require exact-scope approval, idempotency, provider confirmation, verification, and an explicit rollback definition.
- No arbitrary URLs, commands, executable images, or unbounded model/tool arguments.
- OCSF is an event-normalization contract, not a log-retention system.
- OSCAL exports are canonical JSON projections signed with the configured platform secret.
- Add one reversible linear migration after `0103_security_control_plane`.

## Review Focus

- Replayed transaction execution must return the original receipt without a second provider call.
- Approval must be invalid after the diff, tool manifest, target, or argument digest changes.
- Cross-tenant IDs must resolve as not found in transactions, graph, recipes, DSPM, SOC, risk, and compliance.
- Sensitive input must be absent from model representations, audit details, receipts, errors, and logs.
- Monte Carlo output must be reproducible for a seed and reject invalid or misleading ranges.

---

### Task 1: Assurance persistence and contracts

**Files:**
- Create: `backend/app/db/models/assurance.py`
- Create: `backend/app/schemas/assurance.py`
- Create: `backend/alembic/versions/0104_assurance_runtime.py`
- Modify: `backend/app/db/models/__init__.py`
- Test: `backend/tests/unit/test_assurance_models.py`

**Interfaces:**
- Produces transaction, AI receipt/manifest/edge, agent assurance, validation recipe, DSPM assessment, response action, risk trial, and compliance automation records.

- [x] Write failing metadata, constraint, privacy, and schema tests.
- [x] Verify failures are feature-absence failures.
- [x] Implement models, strict Pydantic contracts, and reversible migration.
- [x] Run model/migration parity and focused tests.
- [x] Commit the persistence slice.

### Task 2: Universal enforcement transaction engine

**Files:**
- Create: `backend/app/services/assurance_transactions.py`
- Modify: `backend/app/integrations/control_enforcement.py`
- Modify: `backend/app/api/v1/control_plane.py`
- Test: `backend/tests/unit/test_assurance_transactions.py`

**Interfaces:**
- Consumes: recommendations and allow-listed enforcement adapters.
- Produces: canonical diff/blast simulation, exact-digest approval, execute/observe/verify/rollback state transitions.

- [x] Write failing state, replay, approval-binding, verification, and rollback tests.
- [x] Verify the tests fail for missing transaction behavior.
- [x] Implement deterministic transaction services and REST routes.
- [x] Run focused integration and audit tests.
- [ ] Commit the transaction slice.

### Task 3: AI runtime and access graph

**Files:**
- Create: `backend/app/services/ai_runtime.py`
- Modify: `backend/app/llm/gateway.py`
- Modify: `backend/app/api/v1/control_plane.py`
- Test: `backend/tests/unit/test_ai_runtime.py`

**Interfaces:**
- Produces OpenAI-compatible policy requests, digest-only receipts, pinned manifests, schema-bound tool authorization, delegation validation, graph reachability, and blast-radius answers.

- [ ] Write failing provider/model/region/budget/retention and raw-content tests.
- [ ] Write failing manifest-change, strict-schema, delegation, approval, revocation, and graph tests.
- [ ] Implement pure policy/graph functions and persistence adapters.
- [ ] Run focused gateway and tenant-isolation tests.
- [ ] Commit the AI runtime slice.

### Task 4: Verifiable agent work and governed validation

**Files:**
- Create: `backend/app/services/assurance_work.py`
- Modify: agent-run and attack-simulation APIs to expose assurance projections.
- Test: `backend/tests/unit/test_assurance_work.py`

**Interfaces:**
- Produces immutable plan/receipt/evidence/verifier records, evaluation metrics, non-destructive recipes, chain-of-custody hashes, exploitation verdicts, and reproducibility scores.

- [ ] Write failing immutability, budget, evidence, verifier, recipe, and verdict tests.
- [ ] Verify feature-absence failures.
- [ ] Implement recording/finalization and recipe verification services.
- [ ] Run focused agent, approval, and scanner-sandbox tests.
- [ ] Commit the work-assurance slice.

### Task 5: DSPM and Agentic SOC

**Files:**
- Create: `backend/app/services/security_operations.py`
- Modify: `backend/app/api/v1/control_plane.py`
- Test: `backend/tests/unit/test_security_operations.py`

**Interfaces:**
- Produces provider-neutral data-store posture, OCSF normalization, enriched stories, identity compromise scores, evidence-balanced verdicts, response previews/actions, and post-response verification.

- [ ] Write failing metadata-first, sharing, encryption, residency, OCSF, correlation, evidence, response, and replay tests.
- [ ] Verify feature-absence failures.
- [ ] Implement deterministic services and routes.
- [ ] Run focused CAASM, threat-story, and enforcement tests.
- [ ] Commit the operations slice.

### Task 6: Defensible risk and OSCAL evidence automation

**Files:**
- Create: `backend/app/services/assurance_reporting.py`
- Modify: `backend/app/api/v1/control_plane.py`
- Test: `backend/tests/unit/test_assurance_reporting.py`

**Interfaces:**
- Produces seeded Monte Carlo intervals/comparisons/calibration and signed OSCAL assessment-results/POA&M packages with inheritance, freshness, requests, and asset/finding relationships.

- [ ] Write failing reproducibility, range, comparison, calibration, freshness, inheritance, canonicalization, and signature tests.
- [ ] Verify feature-absence failures.
- [ ] Implement deterministic simulations and OSCAL package services/routes.
- [ ] Run focused business-risk and compliance tests.
- [ ] Commit the reporting slice.

### Task 7: Operator workspace

**Files:**
- Modify: `frontend/src/app/(app)/control-plane/page.tsx`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`
- Test: `frontend/src/lib/assurance-runtime.test.ts`

**Interfaces:**
- Consumes Tasks 2-6 REST projections and exposes exact-scope approval/verification UX.

- [ ] Write failing projection/state/interval/privacy tests.
- [ ] Implement typed transaction, AI graph, assurance, DSPM, SOC, risk, and compliance panels.
- [ ] Run frontend tests, typecheck, and production build.
- [ ] Commit the workspace slice.

### Task 8: Release verification

- [ ] Run focused backend suites, migration parity, ORM integrity, Ruff, and isolated mypy.
- [ ] Run worker/approval/integration compatibility suites.
- [ ] Run frontend tests, typecheck, and production build.
- [ ] Commit the release candidate; do not push or deploy unless explicitly requested.

