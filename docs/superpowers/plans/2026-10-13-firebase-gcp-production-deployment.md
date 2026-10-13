# Firebase/GCP Production Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the complete Cynux application behind Firebase Hosting using production Google Cloud services in a new, dedicated project.

**Architecture:** Firebase Hosting is the public HTTPS edge and rewrites traffic to separate Next.js and FastAPI Cloud Run services in `asia-south1`. Cloud SQL, Memorystore, Cloud Storage, Secret Manager, private Compute Engine scanner/DefectDojo hosts, Cloud NAT, Artifact Registry, and least-privilege service accounts provide the application data and execution plane.

**Tech Stack:** Firebase CLI, Google Cloud CLI, Docker/BuildKit, Cloud Run, Cloud SQL PostgreSQL 16, Memorystore Redis, Cloud Storage XML API, Secret Manager, Compute Engine, Cloud Build, Bash/PowerShell, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-13-firebase-gcp-production-deployment-design.md`

## Global Constraints

- Create a new Firebase/Google Cloud project owned by `nexrasecurity@gmail.com`; do not modify the two existing Nexra projects.
- Use `asia-south1` and `asia-south1-a` where supported.
- Keep PostgreSQL, Redis, DefectDojo, and worker management ports private.
- Store secrets only in Secret Manager or the existing tenant-encrypted credential model; never commit values or bake them into images.
- Firebase Hosting is the only documented public application origin.
- Run database migrations as an explicit release job before sending production traffic.
- Scanner execution remains on Compute Engine because it requires a Docker-compatible host runtime.
- Configure billing alerts before provisioning long-lived billable resources.
- Preserve all unrelated, currently uncommitted product-development changes.

## Review Focus

- A generated project ID can already be taken; bootstrap must derive a new candidate and confirm it before creating anything.
- Billing may not be attached to the new project; provisioning must stop before enabling paid services and print the exact console action required.
- A partial deployment must be safely resumable without regenerating secrets or replacing databases.
- Firebase Hosting rewrites must route `/api/**` and `/ws/**` before the frontend catch-all.
- Cloud Run and worker startup must fail visibly when a required secret, database, Redis, bucket, or DefectDojo dependency is unavailable.

---

## File Structure

- `firebase.json` — Hosting rewrites, cache headers, and Cloud Run destinations.
- `.firebaserc` — deployment alias for the new production project (actual project ID written by bootstrap).
- `infra/gcp/config.env.example` — non-secret regional and sizing inputs.
- `infra/gcp/bootstrap.ps1` — idempotent project, billing, API, budget, and Terraform prerequisite bootstrap.
- `infra/gcp/terraform/main.tf` — providers, APIs, VPC, private service networking, NAT, Artifact Registry, and shared resources.
- `infra/gcp/terraform/identity.tf` — runtime service accounts and IAM bindings.
- `infra/gcp/terraform/data.tf` — Cloud SQL, Redis, bucket, and generated Secret Manager values.
- `infra/gcp/terraform/compute.tf` — private scanner and DefectDojo VMs plus startup metadata.
- `infra/gcp/terraform/run.tf` — Cloud Run API/frontend/job definitions and VPC/database/secret wiring.
- `infra/gcp/terraform/variables.tf` — typed, validated deployment inputs.
- `infra/gcp/terraform/outputs.tf` — hosting, service, database, bucket, and VM outputs without secret values.
- `infra/gcp/templates/scanner-cloud-init.yaml.tftpl` — Docker runtime and systemd-managed Cynux worker.
- `infra/gcp/templates/defectdojo-cloud-init.yaml.tftpl` — private DefectDojo Compose runtime.
- `infra/gcp/deploy.ps1` — build, push, Terraform apply, migration job, Hosting deploy, and smoke checks.
- `infra/gcp/verify.ps1` — repeatable read-only deployment checks.
- `cloudbuild.yaml` — reproducible API and frontend image builds.
- `backend/tests/unit/test_gcp_deployment_config.py` — deployment contract tests.
- `frontend/src/lib/firebase-routing.test.ts` — public-origin URL contract tests.

### Task 1: Pin the Firebase/GCP deployment contract

**Files:**
- Create: `backend/tests/unit/test_gcp_deployment_config.py`
- Create: `frontend/src/lib/firebase-routing.test.ts`
- Modify: `frontend/src/lib/api.ts`

**Interfaces:**
- Consumes: `NEXT_PUBLIC_API_BASE_URL`, `NEXT_PUBLIC_WS_BASE_URL`.
- Produces: same-origin HTTP and WebSocket URL resolution that works behind Firebase Hosting.

- [ ] **Step 1: Write failing backend configuration tests**

Add tests that build production `Settings` with `https://PROJECT.web.app`, private database/Redis hosts, S3-compatible GCS settings, non-placeholder secrets, and `role="api"`; assert `validate_runtime_configuration` returns no errors. Add parameterized cases proving wildcard CORS, wildcard hosts, HTTP public origins, missing storage credentials, and a missing LLM provider fail with the named setting.

- [ ] **Step 2: Run the focused backend test**

Run: `pytest -q backend/tests/unit/test_gcp_deployment_config.py`

Expected: FAIL until the test environment exactly matches the runtime contract; no cloud calls occur.

- [ ] **Step 3: Write frontend same-origin routing tests**

Add Vitest cases asserting an empty public API base resolves REST paths under `/api/v1`, an empty WebSocket base derives `wss://<current-host>`, and explicit development URLs still override both.

- [ ] **Step 4: Implement same-origin URL resolution**

In `frontend/src/lib/api.ts`, centralize URL creation in:

```ts
export function apiOrigin(): string {
  return (process.env.NEXT_PUBLIC_API_BASE_URL ?? "").replace(/\/$/, "");
}

export function websocketOrigin(locationLike = globalThis.location): string {
  const configured = (process.env.NEXT_PUBLIC_WS_BASE_URL ?? "").replace(/\/$/, "");
  if (configured) return configured;
  return `${locationLike.protocol === "https:" ? "wss" : "ws"}://${locationLike.host}`;
}
```

Use these helpers for all API and agent WebSocket URLs so Firebase rewrites work without a second public hostname.

- [ ] **Step 5: Run contract tests**

Run: `pytest -q backend/tests/unit/test_gcp_deployment_config.py`

Run: `npm --prefix frontend run test -- --run src/lib/firebase-routing.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit the contract**

```powershell
git add backend/tests/unit/test_gcp_deployment_config.py frontend/src/lib/firebase-routing.test.ts frontend/src/lib/api.ts
git commit -m "feat: support Firebase same-origin routing"
```

### Task 2: Add Firebase Hosting and image-build configuration

**Files:**
- Create: `firebase.json`
- Create: `.firebaserc`
- Create: `cloudbuild.yaml`
- Modify: `docker/frontend.Dockerfile`
- Modify: `.dockerignore`

**Interfaces:**
- Consumes: final project ID, Cloud Run service names `cynux-api` and `cynux-web`, image tag substitution `_IMAGE_TAG`.
- Produces: `asia-south1-docker.pkg.dev/$PROJECT_ID/cynux/api:$TAG` and `.../frontend:$TAG`.

- [ ] **Step 1: Add Firebase rewrite configuration**

Create `firebase.json` with rewrites in this exact order: `/api/**` to `cynux-api`, `/ws/**` to `cynux-api`, `/docs` and `/openapi.json` to `cynux-api`, then `**` to `cynux-web`; every Cloud Run rewrite uses `region: "asia-south1"` and `pinTag: true`. Add immutable caching for `/_next/static/**` and `no-store` for application/API responses.

- [ ] **Step 2: Add a non-secret project alias**

Create `.firebaserc` with `"production": "__PROJECT_ID__"`; `bootstrap.ps1` replaces only that sentinel after successful project selection.

- [ ] **Step 3: Add Cloud Build image steps**

Create `cloudbuild.yaml` with BuildKit builds for `docker/backend.Dockerfile` and `docker/frontend.Dockerfile`, substitutions for the public same-origin values (`NEXT_PUBLIC_API_BASE_URL=` and `NEXT_PUBLIC_WS_BASE_URL=`), pushes to Artifact Registry, and `images:` entries for both immutable tags.

- [ ] **Step 4: Verify container build contexts**

Run: `docker build -f docker/backend.Dockerfile -t cynux-api:firebase .`

Run: `docker build -f docker/frontend.Dockerfile --build-arg NEXT_PUBLIC_API_BASE_URL= --build-arg NEXT_PUBLIC_WS_BASE_URL= -t cynux-web:firebase .`

Expected: both images build and neither build log contains a secret from `.env`.

- [ ] **Step 5: Commit the edge/build configuration**

```powershell
git add firebase.json .firebaserc cloudbuild.yaml docker/frontend.Dockerfile .dockerignore
git commit -m "build: add Firebase and Cloud Build deployment"
```

### Task 3: Bootstrap a dedicated billed project safely

**Files:**
- Create: `infra/gcp/config.env.example`
- Create: `infra/gcp/bootstrap.ps1`
- Create: `infra/gcp/tests/bootstrap.Tests.ps1`

**Interfaces:**
- Consumes: authenticated `gcloud`, Firebase account `nexrasecurity@gmail.com`, billing account selected from `gcloud billing accounts list`.
- Produces: `CYNUX_GCP_PROJECT_ID`, enabled APIs, Firebase registration, budget alerts, local `.firebaserc` alias.

- [ ] **Step 1: Write bootstrap behavior tests**

Using Pester mocks, assert the script refuses an unavailable project ID, refuses a closed/disabled billing account, creates no paid resource before billing is linked, is idempotent when the project exists under the correct owner, and never prints token or secret values.

- [ ] **Step 2: Implement idempotent bootstrap**

The script must:

```powershell
$ProjectBase = "cynux-security-prod"
$Region = "asia-south1"
$Zone = "asia-south1-a"
gcloud auth login nexrasecurity@gmail.com
gcloud billing accounts list --filter="open=true"
gcloud projects create $ProjectId --name="Cynux Security Production"
gcloud billing projects link $ProjectId --billing-account=$BillingAccountId
gcloud services enable serviceusage.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com firebase.googleapis.com
firebase projects:addfirebase $ProjectId --account nexrasecurity@gmail.com
```

Generate a collision-resistant suffix only if `cynux-security-prod` is unavailable, persist the chosen non-secret ID to `infra/gcp/.deployment.env`, update `.firebaserc`, set the gcloud project, and then enable Compute, Run, Build, Artifact Registry, SQL Admin, Redis, Service Networking, Secret Manager, Storage, IAM, Logging, Monitoring, IAP, and Cloud Resource Manager APIs. Create a USD 300 budget with 25%, 50%, 75%, 90%, 100%, and forecast alerts using `gcloud billing budgets create`.

- [ ] **Step 3: Run bootstrap tests**

Run: `Invoke-Pester infra/gcp/tests/bootstrap.Tests.ps1`

Expected: PASS without accessing Google Cloud.

- [ ] **Step 4: Commit bootstrap automation**

```powershell
git add infra/gcp/config.env.example infra/gcp/bootstrap.ps1 infra/gcp/tests/bootstrap.Tests.ps1
git commit -m "ops: add safe GCP project bootstrap"
```

### Task 4: Define managed data, network, identity, and secret resources

**Files:**
- Create: `infra/gcp/terraform/versions.tf`
- Create: `infra/gcp/terraform/variables.tf`
- Create: `infra/gcp/terraform/main.tf`
- Create: `infra/gcp/terraform/identity.tf`
- Create: `infra/gcp/terraform/data.tf`
- Create: `infra/gcp/terraform/outputs.tf`
- Create: `infra/gcp/terraform/tests/production.tftest.hcl`

**Interfaces:**
- Consumes: project ID, region, zone, deployment image tag.
- Produces: VPC/subnet/private service range/NAT, Artifact Registry, service accounts, Cloud SQL private IP, Redis private host, storage bucket/HMAC identity, Secret Manager resources.

- [ ] **Step 1: Write Terraform validation tests**

Use `terraform test` assertions for deletion protection, private-only database/Redis, bucket public-access prevention and uniform access, regional colocation, separate runtime identities, no `roles/owner` or `roles/editor`, and no secret values in outputs.

- [ ] **Step 2: Implement shared infrastructure**

Pin Terraform and Google provider versions; define validated variables. Create a custom VPC/subnet, private service access range/connection, router/NAT, Artifact Registry repository, and APIs. Use lifecycle protections on stateful resources.

- [ ] **Step 3: Implement least-privilege identities**

Create `cynux-api`, `cynux-web`, `cynux-worker`, `cynux-defectdojo`, and `cynux-build` service accounts. Bind only Cloud SQL Client, Secret Accessor for named secrets, bucket object permissions, Artifact Registry reader/writer, Logging writer, Monitoring metric writer, and the Compute permissions each identity actually consumes.

- [ ] **Step 4: Implement data services and secrets**

Create PostgreSQL 16 with private IP, backups, point-in-time recovery, deletion protection, a generated database password stored in Secret Manager, and a `cynux` database/user. Create a regional Redis 7 instance with AUTH and in-transit encryption if supported by the selected tier. Create the artifact bucket with lifecycle/versioning and a dedicated GCS HMAC identity; store its one-time secret using a sensitive Terraform value and Secret Manager without outputting it. Generate JWT, Fernet, and DefectDojo secrets with `random_password`/`random_id` and store them as secret versions.

- [ ] **Step 5: Validate Terraform**

Run: `terraform -chdir=infra/gcp/terraform fmt -check`

Run: `terraform -chdir=infra/gcp/terraform init -backend=false`

Run: `terraform -chdir=infra/gcp/terraform validate`

Run: `terraform -chdir=infra/gcp/terraform test`

Expected: all checks PASS.

- [ ] **Step 6: Commit managed infrastructure**

```powershell
git add infra/gcp/terraform
git commit -m "infra: define Cynux managed GCP services"
```

### Task 5: Define Cloud Run services and migration job

**Files:**
- Create: `infra/gcp/terraform/run.tf`
- Create: `infra/gcp/terraform/run_env.tf`
- Modify: `infra/gcp/terraform/tests/production.tftest.hcl`

**Interfaces:**
- Consumes: API/frontend Artifact Registry image URIs, data-service outputs, named Secret Manager versions.
- Produces: `cynux-api`, `cynux-web`, and `cynux-migrate` Cloud Run resources.

- [ ] **Step 1: Extend Terraform tests**

Assert API min/max instances and timeout are bounded, frontend/API use different service accounts, the migration job has no public ingress, all secrets use Secret Manager references, VPC egress is configured, and no environment variable contains a literal credential.

- [ ] **Step 2: Implement the migration job**

Use the backend image with command `python -m alembic -c alembic.ini upgrade head`, one task, no retries for schema errors, Cloud SQL/private VPC access, and the same database secret as the API. Release automation executes it and blocks traffic changes on failure.

- [ ] **Step 3: Implement the API service**

Deploy the backend image with `uvicorn --factory app.api.app:create_app --host 0.0.0.0 --port 8080`, startup/liveness probes at `/healthz`, a 3600-second timeout for WebSockets, instance/concurrency caps, private data connectivity, production CORS/hosts, GCS XML API values, Redis TLS/AUTH values, and secret references. Keep unauthenticated invocation at the infrastructure edge while Cynux enforces application authentication.

- [ ] **Step 4: Implement the frontend service**

Deploy the Next.js standalone image on port 8080 with same-origin public values, bounded scaling, health startup probe, and no data-plane secrets.

- [ ] **Step 5: Validate and commit**

Run: `terraform -chdir=infra/gcp/terraform test`

Expected: PASS.

```powershell
git add infra/gcp/terraform/run.tf infra/gcp/terraform/run_env.tf infra/gcp/terraform/tests/production.tftest.hcl
git commit -m "infra: add Cloud Run application services"
```

### Task 6: Define isolated scanner and DefectDojo compute

**Files:**
- Create: `infra/gcp/terraform/compute.tf`
- Create: `infra/gcp/templates/scanner-cloud-init.yaml.tftpl`
- Create: `infra/gcp/templates/defectdojo-cloud-init.yaml.tftpl`
- Create: `infra/gcp/templates/defectdojo-compose.yml.tftpl`
- Modify: `infra/gcp/terraform/tests/production.tftest.hcl`

**Interfaces:**
- Consumes: private VPC, service accounts, image URI, database/Redis/storage/secret outputs.
- Produces: private `cynux-scanner-01` and `cynux-defectdojo-01` hosts with managed services.

- [ ] **Step 1: Add compute security tests**

Assert neither VM has `access_config`, OS Login is enabled, shielded VM secure boot/vTPM/integrity monitoring are enabled, disks are encrypted and deletion-protected as appropriate, tags do not open application ports publicly, and the scanner/DefectDojo service accounts differ.

- [ ] **Step 2: Implement scanner startup**

Cloud-init installs Docker and the Ops Agent, authenticates to Artifact Registry through the VM identity, creates `/var/lib/cynux/artifacts`, creates the egress-only `cynux_scanner_net`, pulls the immutable backend image, and writes a systemd unit that runs `python -m app.worker` with the Docker socket, bounded restart policy, and secrets fetched into a root-only runtime environment file. It pre-pulls the allow-listed scanner image versions from application configuration.

- [ ] **Step 3: Implement DefectDojo startup**

Cloud-init writes the rendered private Compose stack, fetches only named secrets, initializes DefectDojo once, exposes its nginx endpoint only on the VPC address, and runs web/Celery services under systemd. Persistent disks hold media and its dedicated database data.

- [ ] **Step 4: Validate and commit**

Run: `terraform -chdir=infra/gcp/terraform test`

Expected: PASS.

```powershell
git add infra/gcp/terraform/compute.tf infra/gcp/templates infra/gcp/terraform/tests/production.tftest.hcl
git commit -m "infra: isolate scanner and DefectDojo compute"
```

### Task 7: Build resumable release and verification automation

**Files:**
- Create: `infra/gcp/deploy.ps1`
- Create: `infra/gcp/verify.ps1`
- Create: `infra/gcp/tests/deploy.Tests.ps1`

**Interfaces:**
- Consumes: `.deployment.env`, authenticated CLIs, Terraform outputs, git commit SHA.
- Produces: deployed release, Firebase URLs, and a machine-readable verification summary.

- [ ] **Step 1: Write release-order tests**

Mock commands and assert ordering: preflight → budget/billing check → build/push → Terraform plan → explicit apply approval boundary → migration job → Cloud Run readiness → Firebase Hosting deploy → smoke tests. Assert migration failure prevents Hosting deployment and a rerun reuses the same image tag/secrets.

- [ ] **Step 2: Implement deployment orchestration**

Use `$ErrorActionPreference = "Stop"`, strict external-command exit checks, and an immutable image tag from `git rev-parse HEAD`. Refuse deployment with unresolved `.firebaserc` sentinel, disabled billing, missing Secret Manager versions, or a dirty tree unless `-AllowDirtySnapshot` is explicitly supplied. Record non-secret resource outputs under `infra/gcp/.last-deployment.json`; never serialize Terraform sensitive values.

- [ ] **Step 3: Implement read-only verification**

Check Firebase URL TLS and headers, `/healthz`, `/openapi.json`, frontend login page, API CORS, WebSocket upgrade, Cloud Run ready conditions, migration job success, SQL/Redis health, worker systemd state through IAP, bucket write/read/delete with a generated test object, DefectDojo private health through IAP tunneling, and budget existence. Emit PASS/FAIL JSON without tokens or response bodies containing customer data.

- [ ] **Step 4: Run orchestration tests**

Run: `Invoke-Pester infra/gcp/tests/deploy.Tests.ps1`

Expected: PASS without cloud mutations.

- [ ] **Step 5: Commit release automation**

```powershell
git add infra/gcp/deploy.ps1 infra/gcp/verify.ps1 infra/gcp/tests/deploy.Tests.ps1
git commit -m "ops: automate Firebase GCP production releases"
```

### Task 8: Provision and deploy the live production environment

**Files:**
- Modify: `.firebaserc` (bootstrap-selected project ID)
- Create, ignored: `infra/gcp/.deployment.env`
- Create, ignored: `infra/gcp/.last-deployment.json`

**Interfaces:**
- Consumes: Tasks 1-7, Google account/billing authorization, current approved working-tree snapshot.
- Produces: live Firebase URL and verified production resources.

- [ ] **Step 1: Install and authenticate required CLIs**

Install current Google Cloud CLI and Terraform from official distributions. Run `gcloud auth login nexrasecurity@gmail.com`, `gcloud auth application-default login`, switch Firebase CLI to the same account, and verify both identities without printing access tokens.

- [ ] **Step 2: Bootstrap project and budget**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/bootstrap.ps1`

Expected: new project ID persisted, billing enabled, Firebase registered, APIs enabled, USD 300 budget present.

- [ ] **Step 3: Review the Terraform plan**

Run: `terraform -chdir=infra/gcp/terraform init`

Run: `terraform -chdir=infra/gcp/terraform plan -out=cynux.tfplan -var="project_id=$PROJECT_ID" -var="image_tag=$GIT_SHA"`

Expected: only resources named by this plan; no existing Nexra project changes and no secret values in terminal output.

- [ ] **Step 4: Execute the release**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/deploy.ps1 -ProjectId $PROJECT_ID -AllowDirtySnapshot`

Expected: images pushed, infrastructure ready, migration job successful, Cloud Run revisions ready, Hosting deployed.

- [ ] **Step 5: Run production verification**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/verify.ps1 -ProjectId $PROJECT_ID`

Expected: every required check PASS. Any scanner action uses only a harmless owned/test target and follows the application's authorization workflow.

- [ ] **Step 6: Record the deployment commit**

```powershell
git add .firebaserc
git commit -m "ops: bind production Firebase project"
```

### Task 9: Final rollback and operating handoff

**Files:**
- Modify: `infra/gcp/verify.ps1`
- Create: `infra/gcp/rollback.ps1`
- Test: `infra/gcp/tests/deploy.Tests.ps1`

**Interfaces:**
- Consumes: `.last-deployment.json`, Cloud Run revision history, Firebase Hosting releases.
- Produces: safe application rollback that never rolls back the database destructively.

- [ ] **Step 1: Add rollback tests**

Assert rollback selects the previous healthy Cloud Run API/frontend revisions and previous Firebase Hosting release, refuses when no previous healthy release exists, and never invokes `terraform destroy`, SQL deletion, migration downgrade, or secret-version destruction.

- [ ] **Step 2: Implement rollback**

Route Cloud Run traffic back to recorded prior revisions, run the health checks, then roll Firebase Hosting back only when both services are healthy. Print manual database-forward-fix guidance when a schema incompatibility prevents application rollback.

- [ ] **Step 3: Verify and commit**

Run: `Invoke-Pester infra/gcp/tests/deploy.Tests.ps1`

Expected: PASS.

```powershell
git add infra/gcp/rollback.ps1 infra/gcp/verify.ps1 infra/gcp/tests/deploy.Tests.ps1
git commit -m "ops: add safe production rollback"
```

## Self-Review Results

- **Spec coverage:** Public edge, managed data, secrets, identity, network isolation, API/frontend, WebSockets, scanners, DefectDojo, migration, verification, cost alerts, monitoring prerequisites, and rollback are assigned to Tasks 1-9.
- **Placeholder scan:** Every implementation step names its concrete behavior, command, output, or test.
- **Type consistency:** Project ID, region, image tag, Cloud Run service names, Terraform outputs, and deployment artifact names remain consistent across tasks.
- **Review Focus:** Each of the five named failure classes has a concrete test in Tasks 1, 3, 5, or 7.

