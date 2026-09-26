# Cynux Execution Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make authorized Cynux assessments execute reliably through a private Railway worker, artifact storage, DefectDojo, and an isolated native-scanner runner.

**Architecture:** The public API stays a control plane. A private Redis consumer drives durable runs and uses a private S3-compatible artifact store plus DefectDojo; scanner binaries run only behind a signed, private runner API. The API reports dependency health without exposing credentials or scanner infrastructure.

**Tech Stack:** FastAPI, SQLAlchemy async, Redis Streams, PostgreSQL, boto3/S3-compatible MinIO, httpx, Docker multi-stage images, Railway private networking, pytest.

**Spec:** `docs/superpowers/specs/2026-09-26-execution-platform-design.md`

## Global Constraints

- Keep API, worker, storage, and runner non-public except for the existing API domain.
- Never log credentials, target details, raw scanner output, or untrusted integration responses.
- Require existing assessment authorization and approval gates before scanner work is submitted.
- Store artifacts only under the existing organization-scoped key format.
- Do not install scanner binaries in the API or generic worker image.
- Treat unavailable storage, DefectDojo, or runner as visible failures; never create a false successful assessment.
- Use Railway reference variables for shared service configuration and keep concrete secrets out of repository files.
- Rotate credentials previously pasted into chat before acceptance testing.

## Review Focus

- Storage credentials are missing or the bucket is unavailable: worker must refuse startup before consuming Redis jobs.
- DefectDojo returns an authentication or rate-limit error: assessment must become visibly failed/degraded, never completed.
- A replayed Redis entry must not submit a second active scanner job for the same durable scanner-job id.
- A request with an invalid runner signature or an unapproved target must be rejected before any binary runs.
- A runner timeout/cancellation must retain the job terminal state and artifact metadata without leaking raw output in events.

---

### Task 1: Runtime dependency probe contract

**Files:**
- Create: `backend/app/services/runtime_checks.py`
- Modify: `backend/app/api/v1/health.py`
- Modify: `backend/app/worker/__main__.py`
- Test: `backend/tests/unit/test_runtime_checks.py`

**Interfaces:**
- Produces `async def probe_worker_dependencies(settings: Settings) -> list[DependencyHealth]`.
- Produces `async def assert_worker_dependencies(settings: Settings) -> None` that raises `ConfigurationError` when storage or DefectDojo is unusable.
- Consumes `ObjectStorage`, `DefectDojoClient`, and `DependencyHealth`.

- [ ] **Step 1: Write failing dependency-probe tests**

```python
@pytest.mark.asyncio
async def test_worker_probe_marks_storage_unhealthy_when_head_bucket_fails(monkeypatch):
    settings = configured_worker_settings()
    monkeypatch.setattr(runtime_checks, "_head_storage_bucket", raises_storage_error)
    dependencies = await runtime_checks.probe_worker_dependencies(settings)
    assert next(item for item in dependencies if item.name == "storage").healthy is False

@pytest.mark.asyncio
async def test_worker_probe_marks_defectdojo_unhealthy_when_auth_fails(monkeypatch):
    settings = configured_worker_settings()
    monkeypatch.setattr(runtime_checks, "_probe_defectdojo", raises_auth_error)
    dependencies = await runtime_checks.probe_worker_dependencies(settings)
    assert next(item for item in dependencies if item.name == "defectdojo").healthy is False
```

- [ ] **Step 2: Run the new tests and verify red**

Run: `pytest -q tests/unit/test_runtime_checks.py`

Expected: failure because `runtime_checks` does not yet expose the probe contract.

- [ ] **Step 3: Implement bounded probes**

```python
async def probe_worker_dependencies(settings: Settings) -> list[DependencyHealth]:
    return [
        await _probe_storage(settings),
        await _probe_defectdojo(settings),
    ]

async def assert_worker_dependencies(settings: Settings) -> None:
    unhealthy = [item.name for item in await probe_worker_dependencies(settings) if not item.healthy]
    if unhealthy:
        raise ConfigurationError(
            f"Worker dependencies are unavailable: {', '.join(unhealthy)}.",
            setting="CYNUX_STORAGE__ENDPOINT_URL",
        )
```

Use a bucket `head_bucket` call and a minimal authenticated DefectDojo `GET /api/v2/system_settings/` request. Map all transport/provider bodies to short dependency details only.

- [ ] **Step 4: Wire the contract into health and worker startup**

Add storage/DefectDojo dependencies to `/health` and `/readyz` only when configured. In `app.worker.__main__`, call `assert_worker_dependencies(settings)` after static validation and before Redis consumer creation.

- [ ] **Step 5: Verify green**

Run: `pytest -q tests/unit/test_runtime_checks.py tests/unit/test_runtime_configuration.py`

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add backend/app/services/runtime_checks.py backend/app/api/v1/health.py backend/app/worker/__main__.py backend/tests/unit/test_runtime_checks.py
git commit -m "feat: verify worker runtime dependencies"
```

### Task 2: Signed scanner-runner protocol and client

**Files:**
- Create: `backend/app/scanners/remote.py`
- Modify: `backend/app/core/config.py`
- Modify: `backend/app/agent/registry.py`
- Modify: `backend/app/scanners/runner.py`
- Test: `backend/tests/unit/test_remote_scanner_runner.py`

**Interfaces:**
- Produces `RemoteScannerRunner(settings: ScannerSettings)`, implementing the existing scanner-runner `run(command: ScannerCommand) -> ScannerResult` contract.
- Adds `ScannerSettings.runner_url: str | None`, `runner_shared_secret: SecretStr | None`, and `runner_timeout_seconds: int`.
- Uses `POST {runner_url}/v1/jobs` with `X-Cynux-Timestamp` and `X-Cynux-Signature` HMAC-SHA256 headers.

- [ ] **Step 1: Write failing client tests**

```python
@pytest.mark.asyncio
async def test_remote_runner_signs_canonical_job_payload(httpx_mock):
    runner = RemoteScannerRunner(scanner_settings(runner_url="http://runner", runner_shared_secret="secret"))
    await runner.run(command_for_authorized_job())
    request = httpx_mock.get_request()
    assert request.headers["X-Cynux-Signature"] == expected_hmac(request.content, "secret")

@pytest.mark.asyncio
async def test_remote_runner_maps_timeout_to_scanner_timeout(httpx_mock):
    httpx_mock.add_exception(httpx.TimeoutException("timeout"))
    with pytest.raises(ScannerTimeoutError):
        await RemoteScannerRunner(scanner_settings()).run(command_for_authorized_job())
```

- [ ] **Step 2: Run tests and verify red**

Run: `pytest -q tests/unit/test_remote_scanner_runner.py`

Expected: failure because `RemoteScannerRunner` does not exist.

- [ ] **Step 3: Implement signed, idempotent client**

```python
class RemoteScannerRunner:
    async def run(self, command: ScannerCommand) -> ScannerResult:
        payload = command.to_runner_payload()
        encoded = canonical_json(payload)
        headers = signed_headers(encoded, self._secret)
        response = await self._client.post("/v1/jobs", content=encoded, headers=headers)
        return ScannerResult.model_validate(response.json())
```

Use `scanner_job_id` as the runner idempotency key. Reject missing runner URL/secret in production worker settings. Preserve the local subprocess runner for explicit development-only configuration.

- [ ] **Step 4: Verify green**

Run: `pytest -q tests/unit/test_remote_scanner_runner.py tests/unit/test_scanner_adapters.py tests/unit/test_scanner_sandbox.py`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add backend/app/scanners/remote.py backend/app/core/config.py backend/app/agent/registry.py backend/app/scanners/runner.py backend/tests/unit/test_remote_scanner_runner.py
git commit -m "feat: add signed remote scanner runner"
```

### Task 3: Private scanner-runner service

**Files:**
- Create: `infra/scanner-runner/Dockerfile`
- Create: `infra/scanner-runner/app/main.py`
- Create: `infra/scanner-runner/app/auth.py`
- Create: `infra/scanner-runner/app/models.py`
- Create: `infra/scanner-runner/requirements.txt`
- Test: `infra/scanner-runner/tests/test_jobs.py`

**Interfaces:**
- Exposes `POST /v1/jobs` and `GET /healthz` on Railway private networking only.
- Consumes the signed payload from `RemoteScannerRunner` and returns the `ScannerResult` schema.
- Produces an idempotent result keyed by `scanner_job_id`.

- [ ] **Step 1: Write failing runner authorization tests**

```python
def test_rejects_missing_or_invalid_signature(client):
    response = client.post("/v1/jobs", json=authorized_payload())
    assert response.status_code == 401

def test_reuses_completed_job_result(client, signed_headers):
    first = client.post("/v1/jobs", json=authorized_payload(), headers=signed_headers)
    second = client.post("/v1/jobs", json=authorized_payload(), headers=signed_headers)
    assert second.json()["job_id"] == first.json()["job_id"]
    assert run_binary.call_count == 1
```

- [ ] **Step 2: Run tests and verify red**

Run: `pytest -q infra/scanner-runner/tests/test_jobs.py`

Expected: failure because the runner application is absent.

- [ ] **Step 3: Implement runner safety boundary**

```python
@app.post("/v1/jobs", response_model=ScannerResult)
async def submit_job(job: ScannerJobRequest, request: Request) -> ScannerResult:
    verify_hmac(request, job)
    validate_allowlisted_binary(job.scanner)
    validate_authorization_claim(job.authorization_id)
    return await jobs.run_once(job.scanner_job_id, job)
```

Install only pinned `nmap`, `nuclei`, and the selected approved scanner binaries in this image. Run as a non-root user, use an empty writable work directory, impose subprocess timeout/resource limits, and return summaries/artifact file descriptors only.

- [ ] **Step 4: Verify green**

Run: `pytest -q infra/scanner-runner/tests/test_jobs.py`

Expected: all authorization, idempotency, and timeout tests pass.

- [ ] **Step 5: Commit**

```bash
git add infra/scanner-runner
git commit -m "feat: add isolated scanner runner service"
```

### Task 4: Railway worker and private storage provisioning

**Files:**
- Create: `infra/railway/worker-variables.md`
- Create: `infra/railway/minio-variables.md`
- Modify: `railway.toml`
- Test: `backend/tests/unit/test_runtime_configuration.py`

**Interfaces:**
- Railway service `cynux-worker` starts `sh start_worker.sh` and has no public domain.
- Railway service `cynux-storage` runs MinIO with a persistent volume and private bucket `cynux-artifacts`.
- All worker variables reference `cynux-api`, `Postgres`, `Redis`, and `cynux-storage`; no concrete secrets are committed.

- [ ] **Step 1: Write failing static configuration tests**

```python
def test_worker_production_requires_remote_runner_when_scanning_enabled():
    settings = production_settings(storage=valid_storage(), defectdojo=valid_defectdojo())
    with pytest.raises(ConfigurationError, match="CYNUX_SCANNER__RUNNER_URL"):
        validate_runtime_configuration(settings, role="worker")
```

- [ ] **Step 2: Run test and verify red**

Run: `pytest -q tests/unit/test_runtime_configuration.py -k remote_runner`

Expected: failure because runtime validation does not yet require the private runner.

- [ ] **Step 3: Add Railway-safe manifests and validation**

Add only variable names/reference expressions to the checked-in files. Configure deployment manually with Railway CLI:

```text
cynux-worker start command: sh start_worker.sh
CYNUX_DB__HOST=${{Postgres.PGHOST}}
CYNUX_REDIS__URL=${{Redis.REDIS_URL}}
CYNUX_STORAGE__ENDPOINT_URL=http://${{cynux-storage.RAILWAY_PRIVATE_DOMAIN}}
CYNUX_STORAGE__BUCKET=cynux-artifacts
CYNUX_SCANNER__RUNNER_URL=http://${{cynux-scanner-runner.RAILWAY_PRIVATE_DOMAIN}}
```

Set generated MinIO root credentials, bucket access key/secret, runner shared secret, and DefectDojo token only through Railway variables. Attach persistent volumes to MinIO and any runner work directory that requires durable temporary state; do not attach a public domain to either service.

- [ ] **Step 4: Verify green**

Run: `pytest -q tests/unit/test_runtime_configuration.py`

Expected: all runtime-configuration tests pass.

- [ ] **Step 5: Commit**

```bash
git add railway.toml infra/railway backend/app/core/config.py backend/tests/unit/test_runtime_configuration.py
git commit -m "feat: configure private assessment execution services"
```

### Task 5: End-to-end worker and integration acceptance tests

**Files:**
- Create: `backend/tests/integration/test_assessment_execution.py`
- Modify: `backend/tests/conftest.py`
- Modify: `frontend/src/app/(app)/assessments/[assessmentId]/page.tsx`

**Interfaces:**
- Consumes an authorized assessment fixture and a private test runner/DefectDojo fixture.
- Produces an assessment timeline with queued, running, terminal, artifact, and DefectDojo synchronization evidence.

- [ ] **Step 1: Write failing end-to-end test**

```python
@pytest.mark.asyncio
async def test_authorized_assessment_persists_artifact_and_syncs_finding(client, worker, defectdojo):
    assessment = await create_authorized_assessment(client)
    await worker.drain_once()
    detail = await get_assessment(client, assessment.id)
    assert detail.status == "completed"
    assert detail.artifacts[0].storage_key.startswith(f"org/{detail.organization_id}/")
    assert defectdojo.has_finding_for(assessment.id)
```

- [ ] **Step 2: Run test and verify red**

Run: `pytest -q tests/integration/test_assessment_execution.py`

Expected: failure until the worker, storage, runner, and DefectDojo fixtures are connected.

- [ ] **Step 3: Implement only missing observability/UI wiring**

Render durable assessment terminal errors and artifact links in the existing assessment detail page. Do not show an assessment as complete until the API has returned the persisted terminal status.

- [ ] **Step 4: Verify green locally and in Railway**

Run: `pytest -q tests/integration/test_assessment_execution.py`

Then run one explicitly authorized, non-production target assessment in Railway. Confirm worker logs show one queue consumer, private storage contains an organization-prefixed artifact, DefectDojo contains the normalized test finding, and the Vercel UI shows the same terminal status.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/integration/test_assessment_execution.py backend/tests/conftest.py frontend/src/app/(app)/assessments/[assessmentId]/page.tsx
git commit -m "test: verify end-to-end assessment execution"
```

## Plan self-review

- Spec coverage: worker runtime, private storage, DefectDojo, runner isolation, failure behavior, tenant artifacts, and acceptance verification map to Tasks 1–5.
- Placeholder scan: no deferred implementation markers are present; concrete interfaces, commands, and expected test outcomes are stated for each task.
- Type consistency: `RemoteScannerRunner`, `ScannerSettings.runner_url`, and `ScannerResult` are defined in Task 2 and consumed by Tasks 3–5.
- Review-focus coverage: storage and DefectDojo are tested in Task 1; replay/idempotency and runner auth/timeout are tested in Tasks 2–3; terminal UI state is tested in Task 5.
