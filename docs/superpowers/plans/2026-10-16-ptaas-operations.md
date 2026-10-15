# PTaaS Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide complete engagement, tester, client-collaboration, retest, report-approval, and attestation operations on top of Cynux assessments and canonical findings.

**Architecture:** Introduce a first-class engagement aggregate that references existing assessments and canonical findings without duplicating them. Append-only authorization, scope, assignment, time, submission, review, report, and attestation records preserve history while role-specific projections enforce tester, client, reviewer, and internal visibility.

**Tech Stack:** FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Strawberry GraphQL, Next.js, object storage, pytest, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-16-market-parity-platform-design.md`

## Global Constraints

- Existing assessment and canonical-finding IDs remain authoritative and backward-compatible.
- Historical scope and authorization versions are immutable after testing starts.
- Internal notes and draft evidence never appear in client projections.
- Attestations reference an approved immutable report artifact and never claim external certification.
- Every tester action is limited by organization membership, assignment, scope, and authorization window.

## Review Focus

- Removing a tester after submission must preserve attribution but remove future access; covered by Task 2.
- A scope change while testing is active must create a new version and block unapproved targets; covered by Task 2.
- Client-visible comments that quote internal content must be rejected or sanitized; covered by Task 3.
- A retest of a merged canonical finding must preserve source submissions and target the canonical identity; covered by Task 4.
- Revoking report approval must invalidate future attestation downloads without altering issued audit history; covered by Task 4.

---

### Task 1: Engagement persistence and migration

**Files:**
- Create: `backend/alembic/versions/0097_ptaas_engagements.py`
- Create: `backend/app/db/models/engagement.py`
- Modify: `backend/app/db/models/__init__.py`
- Modify: `backend/app/db/enums.py`
- Test: `backend/tests/unit/test_engagement_models.py`
- Test: `backend/tests/unit/test_migration_matches_models.py`

**Interfaces:**
- Consumes: organizations, users, assessments, assets, canonical findings, report artifacts.
- Produces: `Engagement`, `EngagementScopeVersion`, `EngagementAuthorization`, `EngagementAssessment`, `EngagementMilestone`, and `EngagementDocument`.

- [ ] **Step 1: Write failing model tests**

```python
def test_started_engagement_scope_versions_are_immutable():
    scope = EngagementScopeVersion(version=1, state="active", targets=[{"type": "domain", "value": "app.example"}])
    with pytest.raises(ImmutableEngagementVersion):
        scope.targets.append({"type": "domain", "value": "new.example"})

def test_engagement_requires_current_authorization_to_enter_testing():
    engagement = engagement_factory(status="scheduled", authorization=None)
    with pytest.raises(EngagementTransitionDenied, match="authorization_required"):
        transition_engagement(engagement, "testing")
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_engagement_models.py tests/unit/test_migration_matches_models.py`

Expected: FAIL because engagement persistence is absent.

- [ ] **Step 3: Implement aggregate and constraints**

Statuses are `draft`, `scheduled`, `testing`, `review`, `retest`, `completed`, `cancelled`, and `archived`. Scope versions store canonical JSON and digest. Authorizations store signer, attestation, start/end, allowed technique categories, scope digest, and revocation. Documents store private object references, classification, digest, uploader, and retention state.

- [ ] **Step 4: Run model and migration tests**

Run: `cd backend && pytest -q tests/unit/test_engagement_models.py tests/unit/test_migration_matches_models.py tests/unit/test_orm_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0097_ptaas_engagements.py backend/app/db/models backend/app/db/enums.py backend/tests/unit/test_engagement_models.py backend/tests/unit/test_migration_matches_models.py
git commit -m "feat: add PTaaS engagement aggregate"
```

### Task 2: Tester profiles, assignments, capacity, and time

**Files:**
- Create: `backend/alembic/versions/0098_ptaas_testers_assignments.py`
- Modify: `backend/app/db/models/engagement.py`
- Create: `backend/app/services/engagement_assignment.py`
- Create: `backend/app/schemas/engagement.py`
- Test: `backend/tests/unit/test_engagement_assignments.py`
- Test: `backend/tests/unit/test_engagement_time_entries.py`

**Interfaces:**
- Consumes: Task 1 engagement, memberships, roles, and organization delegation.
- Produces: `TesterProfile`, `EngagementAssignment`, `EngagementTimeEntry`, `assign_tester()`, `remove_tester()`, and `record_time()`.

- [ ] **Step 1: Write failing authority and capacity tests**

```python
async def test_assignment_rejects_skill_or_capacity_mismatch(service):
    tester = tester_factory(skills={"web"}, weekly_capacity_minutes=60)
    engagement = engagement_factory(required_skills={"mobile"}, planned_minutes=120)
    with pytest.raises(AssignmentDenied, match="skill_and_capacity"):
        await service.assign_tester(engagement, tester)

async def test_removed_tester_keeps_attribution_without_future_access(service):
    assignment = await service.assign_then_remove()
    assert await service.submission_author(assignment.submission_id) == assignment.user_id
    assert not await service.can_view_engagement(assignment.user_id, assignment.engagement_id)

def test_time_entry_correction_is_append_only(time_service):
    original = time_service.record(minutes=60)
    correction = time_service.correct(original.id, minutes=-15)
    assert time_service.total() == 45
    assert original.minutes == 60 and correction.corrects_id == original.id
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_engagement_assignments.py tests/unit/test_engagement_time_entries.py`

Expected: FAIL on missing assignment services.

- [ ] **Step 3: Implement profiles and append-only operations**

Assignment validates active membership, tester role, engagement organization, required skills, authorization, date overlap, and planned capacity. Removal closes the assignment without modifying authored records. Time corrections reference prior rows; totals are projections.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_engagement_assignments.py tests/unit/test_engagement_time_entries.py tests/unit/test_tenant_isolation.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0098_ptaas_testers_assignments.py backend/app/db/models/engagement.py backend/app/services/engagement_assignment.py backend/app/schemas/engagement.py backend/tests/unit/test_engagement_assignments.py backend/tests/unit/test_engagement_time_entries.py
git commit -m "feat: manage PTaaS tester assignments"
```

### Task 3: Finding submissions, review, evidence, and role-safe collaboration

**Files:**
- Create: `backend/alembic/versions/0099_ptaas_submissions.py`
- Modify: `backend/app/db/models/engagement.py`
- Create: `backend/app/services/engagement_submission.py`
- Modify: `backend/app/services/finding_collaboration.py`
- Test: `backend/tests/unit/test_engagement_submissions.py`
- Test: `backend/tests/unit/test_ptaas_visibility.py`

**Interfaces:**
- Consumes: assignments, canonical findings, evidence storage, current collaboration service.
- Produces: `FindingSubmission`, `SubmissionReview`, `EngagementThread`, `submit_finding()`, `review_submission()`, and `client_projection()`.

- [ ] **Step 1: Write failing lifecycle and leakage tests**

```python
async def test_approved_submission_links_canonical_finding_without_copying_it(service):
    submission = await service.submit(valid_submission())
    approved = await service.approve(submission.id)
    assert approved.canonical_finding_id
    assert await service.canonical_title(approved) == submission.title

async def test_client_projection_excludes_internal_notes_and_draft_evidence(service):
    thread = await service.thread(internal_note="secret reasoning", client_message="Please retest")
    projection = await service.client_projection(thread.engagement_id)
    assert "Please retest" in projection.text
    assert "secret reasoning" not in projection.text
    assert all(item.state == "published" for item in projection.evidence)

async def test_client_message_cannot_quote_internal_comment(service):
    with pytest.raises(VisibilityViolation):
        await service.publish_client_message(quoted_comment_id=service.internal_comment_id)
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_engagement_submissions.py tests/unit/test_ptaas_visibility.py`

Expected: FAIL because submission and projection boundaries are absent.

- [ ] **Step 3: Implement submission review and visibility projections**

Submissions transition `draft -> submitted -> changes_requested|approved|rejected`; approved rows reference one canonical finding. Evidence has `internal`, `reviewer`, or `client` classification and `draft` or `published` state. Projection queries select allowed classifications in SQL rather than filtering loaded secret content in Python.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_engagement_submissions.py tests/unit/test_ptaas_visibility.py tests/unit/test_engagement_checklist.py tests/unit/test_canonical_ingest.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0099_ptaas_submissions.py backend/app/db/models/engagement.py backend/app/services/engagement_submission.py backend/app/services/finding_collaboration.py backend/tests/unit/test_engagement_submissions.py backend/tests/unit/test_ptaas_visibility.py
git commit -m "feat: add PTaaS finding review and collaboration"
```

### Task 4: Retests, report approval, and attestations

**Files:**
- Create: `backend/alembic/versions/0100_ptaas_deliverables.py`
- Modify: `backend/app/db/models/engagement.py`
- Create: `backend/app/services/engagement_retest.py`
- Create: `backend/app/services/report_approval.py`
- Create: `backend/app/services/attestation.py`
- Test: `backend/tests/unit/test_engagement_retests.py`
- Test: `backend/tests/unit/test_report_approval.py`
- Test: `backend/tests/unit/test_attestations.py`

**Interfaces:**
- Consumes: canonical remediation/retest services and immutable report artifacts.
- Produces: engagement retest requests/results, `ReportApproval`, `Attestation`, approval revocation, and authorized download state.

- [ ] **Step 1: Write failing canonical identity and artifact tests**

```python
async def test_retest_targets_canonical_identity_after_source_merge(service):
    request = await service.request_for_source_finding(service.merged_source_id)
    assert request.canonical_finding_id == service.surviving_canonical_id

async def test_attestation_requires_approved_immutable_report(service):
    with pytest.raises(AttestationDenied, match="approved_report_required"):
        await service.issue(report_version="draft")

async def test_revoked_approval_blocks_future_download_but_keeps_history(service):
    issued = await service.issue_approved()
    await service.revoke_report_approval(issued.report_approval_id)
    assert not await service.can_download(issued.id)
    assert await service.audit_record_exists(issued.id)
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_engagement_retests.py tests/unit/test_report_approval.py tests/unit/test_attestations.py`

Expected: FAIL on missing engagement deliverables.

- [ ] **Step 3: Implement lifecycle and immutable digests**

Retests reference canonical findings and authorization versions. Report approval pins artifact ID and SHA-256 digest. Attestation text states tested scope, period, methodology, result summary, report digest, issuer, and platform disclaimer; it never claims a third-party certification.

- [ ] **Step 4: Run tests**

Run: `cd backend && pytest -q tests/unit/test_engagement_retests.py tests/unit/test_report_approval.py tests/unit/test_attestations.py tests/unit/test_report_templates.py tests/unit/test_risk_acceptance.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/0100_ptaas_deliverables.py backend/app/db/models/engagement.py backend/app/services/engagement_retest.py backend/app/services/report_approval.py backend/app/services/attestation.py backend/tests/unit/test_engagement_retests.py backend/tests/unit/test_report_approval.py backend/tests/unit/test_attestations.py
git commit -m "feat: complete PTaaS deliverables"
```

### Task 5: REST, GraphQL, SDK, and role-specific workspaces

**Files:**
- Create: `backend/app/api/v1/engagements.py`
- Modify: `backend/app/api/v1/router.py`
- Modify: `backend/app/graphql/types.py`
- Modify: `backend/app/graphql/queries.py`
- Modify: `backend/app/graphql/mutations.py`
- Create: `sdk/python/cynux/engagements.py`
- Modify: `sdk/python/cynux/client.py`
- Modify: `sdk/python/cynux/async_client.py`
- Create: `frontend/src/app/(app)/engagements/page.tsx`
- Create: `frontend/src/app/(app)/engagements/[id]/page.tsx`
- Create: `frontend/src/lib/engagements.ts`
- Test: `backend/tests/unit/test_engagement_api.py`
- Test: `sdk/python/tests/test_engagements.py`
- Test: `frontend/src/lib/engagements.test.ts`

**Interfaces:**
- Consumes: Tasks 1-4 domain services.
- Produces: complete engagement operations and tester/client/reviewer projections across REST, GraphQL, SDK, and UI.

- [ ] **Step 1: Write failing projection and client tests**

```python
@pytest.mark.parametrize("role,visible", [
    ("tester", {"scope", "submissions", "internal_threads"}),
    ("client", {"scope", "published_findings", "client_threads", "reports"}),
    ("reviewer", {"scope", "submissions", "internal_threads", "approvals"}),
])
async def test_engagement_projection_is_role_specific(api, role, visible):
    body = await api.engagement(role=role)
    assert set(body["sections"]) == visible
```

```typescript
it("does not render internal evidence for the client workspace", () => {
  expect(clientSections(sampleEngagement)).not.toContain("internalEvidence")
})
```

- [ ] **Step 2: Verify failures**

Run: `cd backend && pytest -q tests/unit/test_engagement_api.py && cd ../sdk/python && pytest -q tests/test_engagements.py`

Run: `npm --prefix frontend test -- engagements.test.ts`

Expected: FAIL on missing public interfaces.

- [ ] **Step 3: Implement service-backed APIs and workspaces**

Every mutation calls one engagement service transaction, emits an audit event, and returns a stable error code. UI tabs and actions derive from server permissions and projection, not locally inferred roles.

- [ ] **Step 4: Run tests and frontend build**

Run: `cd backend && pytest -q tests/unit/test_engagement_api.py tests/unit/test_graphql_schema.py && cd ../sdk/python && pytest -q tests/test_engagements.py`

Run: `npm --prefix frontend test -- engagements.test.ts && npm --prefix frontend run build`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/v1/engagements.py backend/app/api/v1/router.py backend/app/graphql sdk/python/cynux sdk/python/tests/test_engagements.py frontend/src/app/\(app\)/engagements frontend/src/lib/engagements.ts frontend/src/lib/engagements.test.ts backend/tests/unit/test_engagement_api.py
git commit -m "feat: expose PTaaS engagement workspaces"
```

### Task 6: Production acceptance and staged rollout

**Files:**
- Create: `backend/tests/integration/test_ptaas_engagement_flow.py`
- Create: `backend/tests/integration/test_ptaas_visibility.py`
- Create: `frontend/e2e/ptaas-engagement.spec.ts`
- Create: `infra/gcp/verify-ptaas.ps1`
- Modify: `backend/app/core/config.py`
- Modify: `infra/gcp/main.tf`

**Interfaces:**
- Consumes: complete PTaaS slice.
- Produces: feature flag, visibility isolation probe, lifecycle metrics, alerts, and canary acceptance.

- [ ] **Step 1: Write failing full-lifecycle test**

```python
@pytest.mark.integration
async def test_engagement_scope_to_attestation(stack):
    engagement = await stack.create_authorized_engagement()
    await stack.assign_tester(engagement)
    submission = await stack.submit_and_approve_finding(engagement)
    await stack.client_add_remediation_evidence(submission)
    await stack.request_and_pass_retest(submission)
    report = await stack.generate_and_approve_report(engagement)
    attestation = await stack.issue_attestation(report)
    assert attestation.report_digest == report.digest
    assert await stack.client_can_download(attestation)
    assert not await stack.client_can_see_internal_notes(engagement)
```

- [ ] **Step 2: Run acceptance**

Run: `cd backend && pytest -q tests/integration/test_ptaas_engagement_flow.py tests/integration/test_ptaas_visibility.py`

Expected: FAIL before rollout wiring exists.

- [ ] **Step 3: Add controls and observability**

Add `CYNUX_FEATURES__PTAAS`, organization allowlist, stop-new-engagements kill switch, audit retention, and metrics for engagement status age, assignment capacity, submission review time, client response time, retest result, report approval, and visibility denials.

- [ ] **Step 4: Run full acceptance**

Run: `cd backend && pytest -q tests/unit/test_engagement_*.py tests/unit/test_ptaas_visibility.py tests/unit/test_report_approval.py tests/unit/test_attestations.py tests/integration/test_ptaas_*.py`

Run: `npm --prefix frontend run e2e -- ptaas-engagement.spec.ts && terraform -chdir=infra/gcp validate`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_ptaas_engagement_flow.py backend/tests/integration/test_ptaas_visibility.py frontend/e2e/ptaas-engagement.spec.ts infra/gcp/verify-ptaas.ps1 backend/app/core/config.py infra/gcp/main.tf
git commit -m "ops: roll out PTaaS operations"
```

