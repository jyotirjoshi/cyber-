# API-Only Integrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every production third-party connection tenant-owned, keep Wazuh API-only, and retire the shared DefectDojo runtime without breaking native assessment ingestion.

**Architecture:** Production connector resolution clears every deployment-level third-party endpoint and secret except public unauthenticated intelligence defaults. Assessment imports select a configured tenant DefectDojo API when present and otherwise normalize scanner artifacts directly into Cynux's canonical ingestion pipeline. The existing DefectDojo VM is stopped but its protected disks and snapshots remain recoverable.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async ORM, Pydantic settings, pytest, Next.js/TypeScript, Terraform, PowerShell, Google Compute Engine.

**Spec:** `docs/superpowers/specs/2026-10-14-api-only-integrations-budget-cutoff-design.md`

## Global Constraints

- Production tenants must never inherit a deployment endpoint, account scope, or credential.
- Wazuh and all customer platforms remain API connections; no new third-party server is provisioned.
- Keep the Cynux scanner worker and its isolated tool containers.
- Do not delete the current DefectDojo persistent disk, snapshot schedule, or snapshots.
- A configured tenant DefectDojo remains authoritative for its own imports and Smart Close behavior.
- A missing tenant DefectDojo uses native canonical ingestion only for explicitly supported formats.
- Invalid or unreachable configured integrations fail visibly; never silently fall back.
- Credentials remain encrypted and write-only across API responses and logs.

## Review Focus

- A production tenant with deployment-level LLM, DefectDojo, Slack, or SMTP settings must still receive an unconfigured tenant result; Task 1 pins this.
- A multi-target Nmap/Nuclei/ZAP job must not discard findings for targets after the first; Task 2 pins target-by-target parsing and one batched projection.
- A saved but disabled or invalid DefectDojo connection must fail rather than silently use native import; Task 3 pins this.
- A crash after native staging must not create duplicate canonical observations on retry; Task 3 pins job import idempotency.
- Deployment must stop the shared DefectDojo VM without planning destruction of its data disk; Task 5 pins Terraform and production verification behavior.

## File Structure

- `backend/app/services/integration.py`: production tenant-only settings resolution.
- `backend/app/services/file_intake.py`: bounded native scanner artifact parsing and staging.
- `backend/app/agent/nodes/importer.py`: choose tenant DefectDojo or native import per assessment.
- `frontend/src/lib/integration-catalog.ts`: API-only setup guidance shown to operators.
- `infra/gcp/terraform/compute.tf`: archived/stopped DefectDojo compute state.
- `infra/gcp/templates/scanner-cloud-init.yaml.tftpl`: worker environment without a shared DefectDojo fallback.
- `infra/gcp/deploy.ps1`: bootstrap only active private runtimes.
- `infra/gcp/verify.ps1`: API-only policy and archived-disk production checks.

---

### Task 1: Enforce production tenant-only connector resolution

**Files:**
- Modify: `backend/app/services/integration.py:499-533,1156-1205`
- Modify: `backend/tests/unit/test_integration_tenant_isolation.py`

**Interfaces:**
- Consumes: `resolve_settings(session, principal, kind, *, settings, require=False, mark_used=True) -> Settings`
- Produces: `TENANT_OWNED_KINDS: frozenset[IntegrationKind]` containing every credential-bearing production connector.

- [ ] **Step 1: Write failing isolation tests**

Add a parameterized test that supplies deployment credentials for `LLM`, `DEFECTDOJO`, `SLACK`, `EMAIL`, and `WAZUH`, calls `resolve_settings` in production with `_Rows([])`, and asserts each returned credential and customer endpoint is `None`. Add a second test asserting `require=True` raises `IntegrationNotConfiguredError` for each kind.

```python
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "settings", "read_secret"),
    [
        (IntegrationKind.LLM, Settings(environment="production", llm={"provider": "openai", "default_model": "model", "openai_api_key": "platform"}), lambda value: value.llm.openai_api_key),
        (IntegrationKind.DEFECTDOJO, Settings(environment="production", defectdojo={"base_url": "https://dojo.platform", "api_token": "platform"}), lambda value: value.defectdojo.api_token),
        (IntegrationKind.WAZUH, Settings(environment="production", wazuh={"base_url": "https://wazuh.platform", "api_username": "u", "api_password": "p"}), lambda value: value.wazuh.api_password),
    ],
)
async def test_production_shared_provider_credentials_are_never_tenant_fallback(kind, settings, read_secret):
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    scoped = await resolve_settings(_Rows([]), principal, kind, settings=settings)
    assert read_secret(scoped) is None
```

- [ ] **Step 2: Run the tests and confirm the current shared fallbacks fail**

Run: `pytest -q backend/tests/unit/test_integration_tenant_isolation.py`

Expected: the new LLM and DefectDojo cases fail because the deployment credentials remain visible.

- [ ] **Step 3: Replace the exception list with an explicit tenant-owned policy**

Rename `_TENANT_PRIVATE_KINDS` to `_TENANT_OWNED_KINDS` and include every `IntegrationKind` except `NVD`. Keep development fallback behavior, but in production always call `_without_deployment_provider_config` for a member of this set. Update the `resolve_settings` docstring to state that only public unauthenticated intelligence defaults may remain shared.

```python
_TENANT_OWNED_KINDS = frozenset(kind for kind in IntegrationKind if kind is not IntegrationKind.NVD)

tenant_private = settings.is_production and kind in _TENANT_OWNED_KINDS
base = _without_deployment_provider_config(settings, kind) if tenant_private else settings
```

- [ ] **Step 4: Run isolation and integration-selection tests**

Run: `pytest -q backend/tests/unit/test_integration_tenant_isolation.py backend/tests/unit/test_integration_selection.py backend/tests/unit/test_worker_byok_isolation.py`

Expected: all pass.

- [ ] **Step 5: Commit the tenant boundary**

```bash
git add backend/app/services/integration.py backend/tests/unit/test_integration_tenant_isolation.py
git commit -m "fix: require tenant-owned production integrations"
```

---

### Task 2: Normalize native scanner artifacts without DefectDojo

**Files:**
- Modify: `backend/app/services/file_intake.py`
- Modify: `backend/tests/unit/test_scan_import.py`

**Interfaces:**
- Produces: `NATIVE_SCANNER_FORMATS: Mapping[ScannerName, str]`
- Produces: `import_native_scanner_artifact(session, principal, job, storage) -> int`
- Consumes later: Task 3 calls `import_native_scanner_artifact` for completed non-cloud scanner jobs.

- [ ] **Step 1: Add failing parser tests for Nmap XML and ZAP JSON**

Add bounded fixtures containing two in-scope targets and one out-of-scope target. Assert Nmap emits stable `network_service` observations only for open ports and ZAP emits stable `dast` observations without retaining request/response bodies.

```python
def test_nmap_xml_keeps_only_open_services_for_selected_asset():
    alerts = parse_scan_export(
        NMAP_TWO_HOSTS,
        format_name="nmap_xml",
        provider="nmap",
        asset_type="ip",
        asset_value="192.0.2.10",
    )
    assert [(row.category, row.resource) for row in alerts] == [("network_service", "192.0.2.10")]
    assert alerts[0].raw_payload == {}

def test_zap_json_drops_http_bodies_and_out_of_scope_sites():
    alerts = parse_scan_export(
        ZAP_TWO_SITES,
        format_name="zap_json",
        provider="zap",
        asset_type="url",
        asset_value="https://app.example",
    )
    assert {row.evidence["plugin_id"] for row in alerts} == {"10021"}
    assert "request" not in str(alerts[0].evidence).lower()
```

- [ ] **Step 2: Run the parser tests and confirm unsupported-format failures**

Run: `pytest -q backend/tests/unit/test_scan_import.py -k "nmap_xml or zap_json"`

Expected: FAIL with `unsupported scanner export format`.

- [ ] **Step 3: Implement bounded Nmap and ZAP parsers**

Use `SafeET.fromstring` for Nmap, reject DTDs/entities, cap at `MAX_IMPORT_FINDINGS`, accept only `open` ports, and build IDs from provider, normalized asset, protocol, port, and service product/name. Parse ZAP's `site[].alerts[]` structure, validate site host/port against the requested URL, map `riskcode` 0-3 to info/low/medium/high, retain only plugin ID, CWE/WASC IDs, path, parameter, and safe description text, and set `raw_payload={}`.

Extend `parse_scan_export` dispatch:

```python
if format_name == "nmap_xml":
    return _nmap_xml(data, provider=provider, kind=kind, asset=asset)
...
if format_name == "zap_json":
    return _zap_json(document, provider=provider, kind=kind, asset=asset)
```

- [ ] **Step 4: Add failing multi-target import and retry-idempotency tests**

Construct a completed `ScannerJob` with two targets and one raw artifact. Stub storage and `_stage_normalized_alerts`; assert the service parses both targets, stages once, links every external ID to the assessment/job, and sets `job.imported_at`. Call it again and assert it returns zero without reading storage.

```python
count = await import_native_scanner_artifact(session, principal, job, storage)
assert count == 2
assert stage_calls == [2]
assert job.imported_at is not None
assert await import_native_scanner_artifact(session, principal, job, storage) == 0
assert storage.read_count == 1
```

- [ ] **Step 5: Implement the native scanner mapping and import service**

Map `NMAP -> nmap_xml`, `NUCLEI -> nuclei_jsonl`, `ZAP -> zap_json`, both Trivy modes to `trivy`, Semgrep to `sarif`, Gitleaks to `gitleaks`, and Syft to `cyclonedx`. Validate job ownership/status, require exactly one bounded raw artifact, derive a normalized asset type for every target, parse each target, deduplicate by `external_id`, stage the combined observations once, call `link_scan_observations`, and set `job.imported_at=utcnow()` only after staging succeeds.

- [ ] **Step 6: Run the complete scanner-import suite**

Run: `pytest -q backend/tests/unit/test_scan_import.py`

Expected: all pass.

- [ ] **Step 7: Commit native scanner ingestion**

```bash
git add backend/app/services/file_intake.py backend/tests/unit/test_scan_import.py
git commit -m "feat: ingest native scanner artifacts without defectdojo"
```

---

### Task 3: Select tenant DefectDojo or native canonical import

**Files:**
- Modify: `backend/app/agent/nodes/importer.py`
- Modify: `backend/tests/unit/test_cloud_import_node.py`
- Create: `backend/tests/unit/test_native_import_node.py`

**Interfaces:**
- Consumes: `find_integration(session, principal, IntegrationKind.DEFECTDOJO) -> Integration | None`
- Consumes: `import_native_scanner_artifact(session, principal, job, storage) -> int`
- Produces: `_tenant_defectdojo_enabled(state, deps) -> bool`

- [ ] **Step 1: Write failing branch-selection tests**

Test these exact cases: no tenant row selects native import; enabled tenant row selects DefectDojo; disabled tenant row raises `IntegrationNotConfiguredError`; configured DefectDojo transport failure propagates and never calls native import.

```python
@pytest.mark.asyncio
async def test_missing_defectdojo_uses_native_import(monkeypatch):
    monkeypatch.setattr(importer, "_tenant_defectdojo_enabled", AsyncMock(return_value=False))
    native = AsyncMock(return_value=3)
    monkeypatch.setattr(importer, "_import_native_job", native)
    await importer.import_findings(state, deps=deps)
    assert native.await_count == 1
```

- [ ] **Step 2: Run the new node tests and confirm the current mandatory `_prepare` path fails**

Run: `pytest -q backend/tests/unit/test_native_import_node.py backend/tests/unit/test_cloud_import_node.py`

Expected: the missing-DefectDojo case fails by calling `_prepare`.

- [ ] **Step 3: Implement explicit tenant selection**

Read the integration row without falling back to settings. If absent, use native import for every non-cloud plan. If present but disabled or incomplete, allow `resolve_settings(require=True)` to raise. Preserve the current DefectDojo import/reimport path unchanged for a valid tenant row. Rename summaries and `_EMPTY_NOTE` so they describe canonical ingestion rather than always naming DefectDojo.

The native branch loads the `ScannerJob` tenant-scoped with artifacts, calls `import_native_scanner_artifact`, commits, emits counts only, and records a visible degradation for a format that the native map does not support.

- [ ] **Step 4: Add and pass crash-resume tests**

Test a staged native job with `imported_at` already set and assert the resumed node does not restage it, does advance the assessment, and reports the final canonical total.

Run: `pytest -q backend/tests/unit/test_native_import_node.py backend/tests/unit/test_cloud_import_node.py backend/tests/unit/test_defectdojo_streaming.py`

Expected: all pass.

- [ ] **Step 5: Commit importer selection**

```bash
git add backend/app/agent/nodes/importer.py backend/tests/unit/test_native_import_node.py backend/tests/unit/test_cloud_import_node.py
git commit -m "feat: make defectdojo an optional tenant integration"
```

---

### Task 4: Make the integration UI explicitly API-only

**Files:**
- Modify: `frontend/src/lib/integration-catalog.ts`
- Modify: `frontend/src/lib/integration-catalog.test.ts`
- Modify: `frontend/src/app/(app)/integrations/page.tsx`

**Interfaces:**
- Produces: setup hints that list required endpoint, scope, and credential fields for DefectDojo, Wazuh, and other API connectors.

- [ ] **Step 1: Write failing catalog tests**

Assert Wazuh names both manager and indexer endpoints, DefectDojo says the tenant must provide an API URL/token, and no hint promises Cynux-hosted vendor infrastructure.

- [ ] **Step 2: Run the catalog tests**

Run: `npm --prefix frontend test -- integration-catalog.test.ts`

Expected: FAIL on the new API-only copy assertions.

- [ ] **Step 3: Update API-only setup guidance**

Change the integration card heading to `Connect provider API`, add a persistent note that Cynux encrypts credentials but does not host the selected vendor, and specify Wazuh's manager/indexer fields and DefectDojo's URL/token fields. Do not expose secrets or add provider-specific defaults that could point one tenant at another.

- [ ] **Step 4: Run frontend tests and build**

Run: `npm --prefix frontend test -- integration-catalog.test.ts`

Run: `npm --prefix frontend run build`

Expected: both pass.

- [ ] **Step 5: Commit UI guidance**

```bash
git add frontend/src/lib/integration-catalog.ts frontend/src/lib/integration-catalog.test.ts frontend/src/app/\(app\)/integrations/page.tsx
git commit -m "feat: clarify api-only provider connections"
```

---

### Task 5: Archive the shared DefectDojo runtime safely

**Files:**
- Modify: `infra/gcp/terraform/variables.tf`
- Modify: `infra/gcp/terraform/compute.tf`
- Modify: `infra/gcp/templates/scanner-cloud-init.yaml.tftpl`
- Modify: `infra/gcp/deploy.ps1`
- Modify: `infra/gcp/verify.ps1`
- Modify: `infra/gcp/tests/deploy.Tests.ps1`
- Modify: `infra/gcp/terraform/tests/production.tftest.hcl`

**Interfaces:**
- Produces: Terraform variable `shared_defectdojo_enabled: bool = false`.
- Produces: production checks `api-only-integration-policy` and `defectdojo-archive`.

- [ ] **Step 1: Write failing infrastructure tests**

Assert the scanner template contains no `CYNUX_DEFECTDOJO__BASE_URL` or token secret, the deployment script never starts `cynux-defectdojo-01`, Terraform defaults the instance to `TERMINATED`, and the protected data disk plus snapshot attachment remain declared with `prevent_destroy=true`.

- [ ] **Step 2: Run PowerShell and Terraform tests**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/tests/run.ps1`

Run: `.tools/terraform/terraform.exe -chdir=infra/gcp/terraform test`

Expected: the new archive-policy assertions fail.

- [ ] **Step 3: Remove worker fallback injection and active VM bootstrap**

Remove the DefectDojo URL/token inputs from `scanner_bootstrap` and its template. Add `shared_defectdojo_enabled` and set the VM `desired_status` from it without deleting the VM, boot disk, attached data disk, address, or snapshot policy. Remove DefectDojo startup/SSH bootstrap from the release pipeline and from the normal cleanup list.

- [ ] **Step 4: Replace production verification**

Delete `defectdojo-private-health`. Add a check that the DefectDojo VM status is `TERMINATED`, the `cynux-defectdojo-data` disk exists and has `users` referencing the archived instance, and the worker environment contains no deployment DefectDojo URL. Add an API-only policy check that a new tenant's integration list contains no configured DefectDojo/Wazuh row.

- [ ] **Step 5: Run infrastructure tests and inspect the plan for deletion**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/tests/run.ps1`

Run: `.tools/terraform/terraform.exe -chdir=infra/gcp/terraform plan -var=project_id=cynux-security-prod -var=region=asia-south1 -var=zone=asia-south1-a -var=image_tag=verification-only`

Expected: tests pass; the plan contains a VM stop/update and no destroy action for the DefectDojo data disk or snapshot resources.

- [ ] **Step 6: Commit reversible archival**

```bash
git add infra/gcp/terraform/variables.tf infra/gcp/terraform/compute.tf infra/gcp/templates/scanner-cloud-init.yaml.tftpl infra/gcp/deploy.ps1 infra/gcp/verify.ps1 infra/gcp/tests/deploy.Tests.ps1 infra/gcp/terraform/tests/production.tftest.hcl
git commit -m "infra: retire shared defectdojo runtime safely"
```

---

### Task 6: Deploy and verify the API-only migration

**Files:**
- Modify only if a verified deployment defect requires repair.

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: a production release whose shared DefectDojo VM is stopped and recoverable.

- [ ] **Step 1: Run targeted backend and frontend verification**

Run: `pytest -q backend/tests/unit/test_integration_tenant_isolation.py backend/tests/unit/test_scan_import.py backend/tests/unit/test_native_import_node.py backend/tests/unit/test_cloud_import_node.py backend/tests/unit/test_defectdojo_streaming.py`

Run: `ruff check backend/app/services/integration.py backend/app/services/file_intake.py backend/app/agent/nodes/importer.py`

Run: `npm --prefix frontend test -- integration-catalog.test.ts`

- [ ] **Step 2: Deploy while preserving dirty-snapshot safeguards**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/deploy.ps1 -ApproveApply -AllowDirtySnapshot`

Expected: migrations, Cloud Run readiness, Firebase publish, worker bootstrap, and revised smoke tests pass.

- [ ] **Step 3: Run live tenant probes**

Create a disposable organization. Verify an assessment without DefectDojo stages a supported scanner artifact natively, a Wazuh integration with intentionally invalid credentials returns a user-safe authentication failure, and no API response exposes a credential.

- [ ] **Step 4: Confirm archived infrastructure**

Run read-only GCP checks proving `cynux-defectdojo-01` is terminated, `cynux-defectdojo-data` exists, snapshots remain scheduled, and the scanner worker is active.

- [ ] **Step 5: Commit only deployment repairs, then push the branch**

```bash
git push origin codex/ctem-parity
```

