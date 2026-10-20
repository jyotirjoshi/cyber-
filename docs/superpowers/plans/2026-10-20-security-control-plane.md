# Security Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tenant-safe control plane covering CAASM reconciliation, data and AI posture, policy recommendations, AI gateway protection, experience telemetry, threat stories, deception, and quantitative risk.

**Architecture:** Add one normalized control-plane domain linked to existing assets, findings, business services, integrations, and audit records. Deterministic evaluators create evidence-backed decisions; explicit operator actions can route approved changes to provider adapters.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2, PostgreSQL 16, Redis workers, Next.js 15, TypeScript, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-20-security-control-plane-design.md`

## Global Constraints

- Preserve tenant isolation and existing RBAC for every query and mutation.
- Never persist raw prompts, outputs, secrets, or customer data samples.
- Deterministic policy evaluation only; LLM output is explanatory and non-authoritative.
- External writes require explicit operator action, idempotency, audit, and provider receipts.
- Do not build proxy, TLS interception, packet-forwarding, or browser-rendering infrastructure.
- Introduce one linear migration after `0102_compliance_evidence_workspaces`.

## Review Focus

- Malicious prompt text must be detected without being logged or persisted verbatim.
- Replayed resource observations, events, and recommendation applies must not duplicate state or external writes.
- Cross-tenant asset, integration, policy, and story identifiers must return not-found.
- Stale source observations must lower confidence without deleting curated ownership or business context.
- Risk simulations must reject invalid probability/loss/control-effectiveness ranges.

---

### Task 1: Control-plane persistence and contracts

**Files:**
- Create: `backend/app/db/models/control_plane.py`
- Create: `backend/app/schemas/control_plane.py`
- Create: `backend/alembic/versions/0103_security_control_plane.py`
- Modify: `backend/app/db/models/__init__.py`
- Test: `backend/tests/unit/test_control_plane_models.py`

**Interfaces:**
- Produces: tenant-owned resources, observations, policies, evaluations, recommendations, events, stories, canaries, interactions, and risk simulations.

- [x] Write failing metadata, constraint, and schema-validation tests.
- [x] Run focused tests and confirm the new domain is absent.
- [x] Implement models, wire contracts, and the reversible migration.
- [x] Run focused and migration/model parity tests.
- [x] Commit the persistence slice.

### Task 2: CAASM reconciliation, policy recommendations, and posture summaries

**Files:**
- Create: `backend/app/services/control_plane.py`
- Create: `backend/app/api/v1/control_plane.py`
- Modify: `backend/app/api/v1/router.py`
- Test: `backend/tests/unit/test_control_plane_service.py`

**Interfaces:**
- Consumes: Task 1 aggregates.
- Produces: idempotent resource/source upsert, confidence scoring, stale-source/coverage summaries, policies, evaluations, and recommendation lifecycle APIs.

- [x] Write failing tenant, replay, confidence, stale-source, policy, and recommendation tests.
- [x] Run focused tests and confirm feature-missing failures.
- [x] Implement services and REST routes using permission and audit primitives.
- [x] Run focused, tenant-isolation, OpenAPI, and migration tests.
- [x] Commit the CAASM and policy slice.

### Task 3: Data security and inline AI gateway

**Files:**
- Create: `backend/app/services/ai_security.py`
- Modify: `backend/app/api/v1/control_plane.py`
- Test: `backend/tests/unit/test_ai_security.py`

**Interfaces:**
- Produces: bounded deterministic prompt/output evaluation, sensitive-data classification, prompt-injection detection, redaction, approval decisions, and hashed audit events.

- [x] Write failing injection, sensitive-data, redaction, no-raw-storage, and policy tests.
- [x] Run tests and confirm evaluator is absent.
- [x] Implement pure evaluator and persistence adapter.
- [x] Run focused security, logging-redaction, and API tests.
- [x] Commit the data/AI protection slice.

### Task 4: Experience, threat stories, deception, and risk simulation

**Files:**
- Modify: `backend/app/services/control_plane.py`
- Modify: `backend/app/api/v1/control_plane.py`
- Test: `backend/tests/unit/test_control_plane_operations.py`

**Interfaces:**
- Produces: idempotent telemetry ingestion, deterministic incident correlation, threat-story timelines, canary interaction escalation, and residual-loss simulations.

- [x] Write failing replay, correlation, canary, telemetry, and risk-math tests.
- [x] Run tests and confirm operations are absent.
- [x] Implement deterministic services and routes.
- [x] Run focused, audit, automation, and business-risk tests.
- [x] Commit the operations slice.

### Task 5: Enforcement adapters and Zscaler integration contracts

**Files:**
- Create: `backend/app/integrations/control_enforcement.py`
- Create: `backend/app/integrations/zscaler.py`
- Modify: integration enum, configuration, service, model constraint, and catalogue files.
- Modify: `backend/app/services/control_plane.py`
- Test: `backend/tests/unit/test_control_enforcement.py`

**Interfaces:**
- Produces: provider-neutral dry-run/apply contracts, ZPA/ZIA inventory adapters, explicit policy-change application, idempotency, and redacted provider receipts.

- [x] Write failing connector-auth, dry-run, replay, unsupported-action, and receipt-redaction tests.
- [x] Run tests and confirm adapters are absent.
- [x] Implement hardened clients and explicit-apply service path.
- [x] Run integration, SSRF, retry, circuit-breaker, and control-plane tests.
- [x] Commit the connector slice.

### Task 6: Control-plane product UI

**Files:**
- Create: `frontend/src/app/(app)/control-plane/page.tsx`
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`
- Modify: the existing application navigation component.
- Test: `frontend/src/lib/control-plane.test.ts`

**Interfaces:**
- Consumes: Tasks 2-5 REST contracts.
- Produces: posture, data, AI, recommendations, experience, SOC stories, deception, and risk workspaces.

- [x] Write failing client projection and decision-label tests.
- [x] Implement typed API methods and operator UI.
- [x] Run frontend tests, typecheck, and production build.
- [x] Commit the UI slice.

### Task 7: Release verification

**Files:**
- Modify deployment configuration only if a new runtime input is required.

**Interfaces:**
- Consumes: all prior task contracts.
- Produces: one migration-safe release candidate.

- [x] Run backend focused/full relevant suites, migration parity, lint, frontend tests, typecheck, and production build.
- [x] Review upgrade/downgrade behavior and worker compatibility.
- [x] Commit the release verification fixes; push only when explicitly requested.
- [ ] Deploy only when explicitly requested in this turn.

