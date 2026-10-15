# Monthly USD 200 Budget Cutoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a monthly USD 200-equivalent project budget with an automated optional-compute shutdown near USD 170 and project billing unlink near USD 190.

**Architecture:** The existing project-scoped budget publishes periodic spend updates to Pub/Sub. A dedicated Cloud Run function validates each notification and executes an idempotent staged policy: stop optional VMs at 85%, then unlink project billing at 95%, leaving a reporting-delay buffer below the requested ceiling. The function and its narrowly scoped identity are managed with Terraform; budget synchronization remains in the guarded deployment script because the budget already exists outside Terraform state.

**Tech Stack:** Python 3.12 Cloud Run functions, Functions Framework CloudEvents, Google Cloud Billing/Compute clients, Pub/Sub, Terraform Google providers, PowerShell/Pester, pytest.

**Spec:** `docs/superpowers/specs/2026-10-14-api-only-integrations-budget-cutoff-design.md`

## Global Constraints

- Budget period is monthly and scoped only to `cynux-security-prod`.
- Policy value is USD 200; billing-account amount starts at INR 19,000 and remains configurable.
- Stop optional compute at 85% and unlink billing at 95%.
- Never act on another billing account, budget, project, or malformed message.
- Pub/Sub delivery is duplicate-prone and out of order; every action must be idempotent.
- Dry-run validation must not stop a VM or unlink billing.
- Project billing unlink is the final cutoff and requires manual owner recovery.
- Logs contain project/action/ratio only, never credentials or raw messages.

## Review Focus

- A stale out-of-order notification below the highest observed spend must not reverse or repeat actions incorrectly; Task 1 pins monotonic policy behavior.
- A notification with `budgetAmount=0`, NaN, negative cost, wrong currency, account, or budget ID must be rejected; Task 1 pins validation.
- Duplicate 95% notifications must observe already-unlinked billing and return success without another mutation; Task 2 pins idempotency.
- Partial VM-stop failure must not prevent the later billing cutoff, but must be logged; Task 2 pins independent action handling.
- A deployment verification must prove Pub/Sub linkage and dry-run function health without sending a real cutoff event; Task 4 pins this.

## File Structure

- `infra/gcp/budget_cutoff/policy.py`: pure notification validation and action selection.
- `infra/gcp/budget_cutoff/main.py`: CloudEvent handler and Google API adapters.
- `infra/gcp/budget_cutoff/requirements.txt`: pinned runtime dependencies.
- `infra/gcp/budget_cutoff/tests/test_policy.py`: pure policy tests.
- `infra/gcp/budget_cutoff/tests/test_main.py`: handler/idempotency tests with fake clients.
- `infra/gcp/terraform/budget_cutoff.tf`: topic, function, identity, IAM, and source package.
- `infra/gcp/bootstrap.ps1`: configurable monthly amount and update-capable budget sync.
- `infra/gcp/deploy.ps1`: synchronize budget after Terraform creates the topic.
- `infra/gcp/verify.ps1`: verify amount, period, topic, function readiness, and dry-run endpoint.

---

### Task 1: Implement the pure cutoff policy

**Files:**
- Create: `infra/gcp/budget_cutoff/policy.py`
- Create: `infra/gcp/budget_cutoff/tests/test_policy.py`

**Interfaces:**
- Produces: `BudgetNotice.from_pubsub(cloud_event, expected: ExpectedBudget) -> BudgetNotice`
- Produces: `select_action(notice: BudgetNotice) -> Literal["none", "stop_optional", "unlink_billing"]`
- Produces: `ExpectedBudget(project_id, billing_account_id, budget_id, currency_code, stop_ratio=Decimal("0.85"), unlink_ratio=Decimal("0.95"))`

- [ ] **Step 1: Write validation and threshold tests**

Cover 0.84/0.85/0.949/0.95 ratios, malformed base64/JSON, zero budget, negative cost, non-finite decimals, wrong account/budget/currency, duplicates, and a stale lower-cost event arriving after a higher one.

```python
@pytest.mark.parametrize(
    ("cost", "expected"),
    [("15959", "none"), ("16150", "stop_optional"), ("18049", "stop_optional"), ("18050", "unlink_billing")],
)
def test_thresholds(cost, expected):
    notice = BudgetNotice(cost=Decimal(cost), budget=Decimal("19000"), currency="INR")
    assert select_action(notice) == expected
```

- [ ] **Step 2: Run tests and confirm missing module failure**

Run: `pytest -q infra/gcp/budget_cutoff/tests/test_policy.py`

Expected: FAIL because `policy.py` does not exist.

- [ ] **Step 3: Implement strict immutable policy types**

Use frozen dataclasses and `Decimal`, reject booleans/floats/non-finite values, decode only the Pub/Sub `message.data` object, and validate event attributes against the configured billing account and budget. `select_action` compares `cost/budget` and returns the highest applicable action. Do not perform network IO in this module.

- [ ] **Step 4: Pass policy tests**

Run: `pytest -q infra/gcp/budget_cutoff/tests/test_policy.py`

Expected: all pass.

- [ ] **Step 5: Commit the policy**

```bash
git add infra/gcp/budget_cutoff/policy.py infra/gcp/budget_cutoff/tests/test_policy.py
git commit -m "feat: define staged cloud budget cutoff policy"
```

---

### Task 2: Implement an idempotent Cloud Run function

**Files:**
- Create: `infra/gcp/budget_cutoff/main.py`
- Create: `infra/gcp/budget_cutoff/requirements.txt`
- Create: `infra/gcp/budget_cutoff/tests/test_main.py`

**Interfaces:**
- Consumes: `BudgetNotice.from_pubsub` and `select_action` from Task 1.
- Produces: `handle_budget_event(cloud_event) -> None` CloudEvent entry point.
- Produces: `CutoffActions.stop_optional_instances() -> ActionResult`
- Produces: `CutoffActions.unlink_project_billing() -> ActionResult`

- [ ] **Step 1: Write handler tests with fake Compute and Billing clients**

Assert `none` makes no API calls, `stop_optional` stops only configured optional instances that are running, `unlink_billing` first attempts optional stops and then clears `billing_account_name`, duplicate events are no-ops against already stopped/unlinked state, dry run never mutates, and one failed VM stop does not block unlinking.

- [ ] **Step 2: Run handler tests and confirm failure**

Run: `pytest -q infra/gcp/budget_cutoff/tests/test_main.py`

Expected: FAIL because the handler does not exist.

- [ ] **Step 3: Implement the CloudEvent adapter**

Read only these environment variables: `PROJECT_ID`, `ZONE`, `OPTIONAL_INSTANCES`, `BILLING_ACCOUNT_ID`, `BUDGET_ID`, `BUDGET_CURRENCY`, `DRY_RUN`. Use `compute_v1.InstancesClient.get/stop` and `billing_v1.CloudBillingClient.get_project_billing_info/update_project_billing_info`. Treat `TERMINATED` and an empty billing association as successful existing state. Log structured action, ratio, and outcome; never log the raw event.

Pin runtime dependencies:

```text
functions-framework==3.9.2
google-cloud-billing==1.16.3
google-cloud-compute==1.39.0
google-cloud-logging==3.12.1
cloudevents==1.12.0
```

- [ ] **Step 4: Run unit tests and lint**

Run: `pytest -q infra/gcp/budget_cutoff/tests`

Run: `ruff check infra/gcp/budget_cutoff`

Expected: all pass.

- [ ] **Step 5: Commit the function**

```bash
git add infra/gcp/budget_cutoff
git commit -m "feat: add idempotent budget cutoff function"
```

---

### Task 3: Provision the cutoff transport and least-privilege identity

**Files:**
- Modify: `infra/gcp/terraform/versions.tf`
- Modify: `infra/gcp/terraform/main.tf`
- Modify: `infra/gcp/terraform/variables.tf`
- Modify: `infra/gcp/terraform/identity.tf`
- Create: `infra/gcp/terraform/budget_cutoff.tf`
- Modify: `infra/gcp/terraform/outputs.tf`
- Modify: `infra/gcp/terraform/tests/production.tftest.hcl`

**Interfaces:**
- Produces: topic `cynux-budget-events`.
- Produces: function `cynux-budget-cutoff` with entry point `handle_budget_event`.
- Produces: outputs `budget_topic_id`, `budget_cutoff_function_name`, `budget_cutoff_service_account`.

- [ ] **Step 1: Add failing Terraform assertions**

Assert required APIs include Pub/Sub, Cloud Functions, Eventarc, Cloud Billing, and Billing Budgets; the topic denies public access; the runtime service account is distinct; the function has `DRY_RUN=true` by default; and IAM contains no project Owner/Editor or Billing Account Administrator grant.

- [ ] **Step 2: Run Terraform tests**

Run: `.tools/terraform/terraform.exe -chdir=infra/gcp/terraform test`

Expected: the new resource assertions fail.

- [ ] **Step 3: Package and provision the function**

Add the `hashicorp/archive ~> 2.7` provider. Archive only `main.py`, `policy.py`, and `requirements.txt`; upload the content-hashed zip to the existing private artifact bucket; create the Pub/Sub topic; grant `roles/pubsub.publisher` to the Cloud Billing notification service agent; deploy a second-generation Python 3.12 function triggered by the topic; and set max instances to 1.

Create a dedicated service account. Grant project permissions through a custom role containing `compute.instances.get`, `compute.instances.stop`, `logging.logEntries.create`, and `resourcemanager.projects.get`. Grant `roles/billing.projectManager` only on the linked billing account, passed as a non-secret Terraform variable. Do not grant `roles/billing.admin`.

- [ ] **Step 4: Pass Terraform tests and inspect the plan**

Run: `.tools/terraform/terraform.exe -chdir=infra/gcp/terraform test`

Run: `.tools/terraform/terraform.exe -chdir=infra/gcp/terraform validate`

Expected: pass; the plan creates only the topic/function/package/IAM resources described above.

- [ ] **Step 5: Commit infrastructure**

```bash
git add infra/gcp/terraform
git commit -m "infra: provision budget cutoff automation"
```

---

### Task 4: Synchronize the existing budget safely

**Files:**
- Modify: `infra/gcp/bootstrap.ps1`
- Modify: `infra/gcp/deploy.ps1`
- Modify: `infra/gcp/config.env.example`
- Modify: `infra/gcp/tests/bootstrap.Tests.ps1`
- Modify: `infra/gcp/tests/deploy.Tests.ps1`

**Interfaces:**
- Produces: `Sync-CynuxBudget(BillingAccountId, ProjectId, Amount, TopicResourceName) -> string` returning the budget resource ID.
- Produces deployment keys `CYNUX_GCP_BUDGET_AMOUNT=19000INR` and `CYNUX_GCP_BUDGET_POLICY_USD=200`.

- [ ] **Step 1: Write failing Pester tests**

Assert the amount is configurable, period is `month`, thresholds are 0.50/0.75/0.85/0.95 plus forecast 0.90, existing budgets are updated rather than duplicated, Pub/Sub topic is linked, and unsupported/mismatched currency values are rejected.

- [ ] **Step 2: Run Pester tests**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/tests/run.ps1`

Expected: the current annual INR 28,500 assertions fail.

- [ ] **Step 3: Implement create-or-update budget synchronization**

Replace `Get-CynuxBudgetAmount` hardcoding with validated deployment config. `Sync-CynuxBudget` lists the stable display name, creates it when absent, and otherwise calls `gcloud billing budgets update <resource-id>` with the monthly amount, project filter, thresholds, project-owner email notification, and `--notifications-rule-pubsub-topic`. Return exactly one resource ID and reject duplicates.

Move synchronization to a new deployment stage immediately after `terraform-apply`, because the Pub/Sub topic must exist first. Keep the early `billing-budget` stage as a read-only billing-enabled check.

- [ ] **Step 4: Pass Pester tests**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/tests/run.ps1`

Expected: all pass.

- [ ] **Step 5: Commit budget synchronization**

```bash
git add infra/gcp/bootstrap.ps1 infra/gcp/deploy.ps1 infra/gcp/config.env.example infra/gcp/tests/bootstrap.Tests.ps1 infra/gcp/tests/deploy.Tests.ps1
git commit -m "infra: synchronize monthly usd 200 budget policy"
```

---

### Task 5: Verify safely without triggering the cutoff

**Files:**
- Modify: `infra/gcp/verify.ps1`
- Modify: `infra/gcp/tests/deploy.Tests.ps1`
- Create: `infra/gcp/budget_cutoff/tests/fixtures/below-threshold.json`

**Interfaces:**
- Produces verification checks `budget-monthly-policy`, `budget-pubsub-link`, and `budget-cutoff-function`.

- [ ] **Step 1: Write failing verification-source tests**

Assert verification reads the budget JSON and checks INR 19,000, monthly period, exact thresholds, Pub/Sub topic, and ready function. Assert it invokes only a below-threshold fixture while `DRY_RUN=true` and never publishes an 85% or 95% message.

- [ ] **Step 2: Implement safe production checks**

Query the budget resource as JSON, compare every required field, describe the function readiness state, and publish a signed below-threshold synthetic event to a dedicated test subscription or call the pure handler test path. Confirm logs contain `action=none`. Do not exercise real stop/unlink actions during deployment.

- [ ] **Step 3: Run all cutoff tests**

Run: `pytest -q infra/gcp/budget_cutoff/tests`

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/tests/run.ps1`

Run: `.tools/terraform/terraform.exe -chdir=infra/gcp/terraform test`

Expected: all pass.

- [ ] **Step 4: Commit verification**

```bash
git add infra/gcp/verify.ps1 infra/gcp/tests/deploy.Tests.ps1 infra/gcp/budget_cutoff/tests/fixtures/below-threshold.json
git commit -m "test: verify production budget cutoff controls"
```

---

### Task 6: Deploy in dry-run, then arm the cutoff

**Files:**
- Modify only if deployment verification reveals a defect.

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: armed project cutoff policy and a verified monthly budget.

- [ ] **Step 1: Deploy with `DRY_RUN=true`**

Run: `powershell -ExecutionPolicy Bypass -File infra/gcp/deploy.ps1 -ApproveApply -AllowDirtySnapshot`

Expected: Terraform creates the topic/function/IAM, the existing budget updates to monthly INR 19,000, and all smoke checks pass without stopping resources.

- [ ] **Step 2: Inspect IAM and budget read-only**

Verify the cutoff identity has no Owner/Editor/Billing Admin role, the budget is scoped only to project `262677283916`, and the Pub/Sub notification rule names `cynux-budget-events`.

- [ ] **Step 3: Publish below-threshold and duplicate dry-run fixtures**

Publish only 10% and duplicate 10% test events. Confirm `action=none`, no Compute stop operations, and billing remains linked.

- [ ] **Step 4: Arm the function**

Change `DRY_RUN` to `false` through Terraform, apply the reviewed one-field plan, and re-run readiness. Do not publish synthetic 85% or 95% events against the armed function.

- [ ] **Step 5: Record and push the release**

Update the non-secret deployment record with the budget resource ID, cutoff function name, thresholds, and armed timestamp, then push:

```bash
git push origin codex/ctem-parity
```

