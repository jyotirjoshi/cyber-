# API-Only Integrations and USD 200 Cost Cutoff

Date: 2026-10-14
Status: approved in chat; awaiting written-spec review

## Intent

Cynux remains a multi-tenant SaaS application with its own API, database, Redis, object
storage, web frontend, scanner worker, and native scanner containers. Customer-owned or
third-party platforms are connected through tenant-scoped APIs; Cynux does not operate those
platforms on behalf of every tenant. The Google Cloud project must also have an automated
monthly cost circuit breaker intended to keep spend below USD 200.

## Scope

- Convert DefectDojo from a shared deployment fallback to a tenant-owned API integration.
- Keep Wazuh and every other customer platform API-only. No Wazuh infrastructure is added.
- Preserve the native scanner worker and its isolated scanner containers; these are Cynux
  execution capabilities, not shared customer systems of record.
- Replace the current annual credit-alert budget with a monthly INR-denominated equivalent
  of USD 200.
- Add programmatic budget responses that reduce optional compute before the final cutoff.
- Do not destroy the existing DefectDojo data disk or snapshots during this migration.

## API-only connector boundary

In production, every connector except public unauthenticated intelligence sources must resolve
its endpoint, account scope, and credentials from the calling organization. Deployment-level
credentials may still be used in development, but never as a production tenant fallback.
This includes DefectDojo, Wazuh, Jira, ServiceNow, Azure DevOps, GitHub, GitLab, Bitbucket,
Tenable, Qualys, Rapid7, Wiz, Prisma Cloud, CrowdStrike, Snyk, SonarQube, Burp, Checkmarx,
Fortify, Splunk, Slack, PagerDuty, MISP, Dify, and the cloud security connectors.

Secrets remain write-only at the API boundary, encrypted at rest, and are exposed only to the
outbound client selected for the same organization. Each connector retains its live `test`
action and continuous-sync schedule where supported. An unconfigured connector must return a
clear configuration error; it must not silently use another tenant's or the deployment's key.

## DefectDojo transition

DefectDojo becomes optional and tenant-scoped. When an organization configures a DefectDojo
base URL and token, assessment artifacts use that API and preserve the existing reimport and
Smart Close behavior. When an organization does not configure DefectDojo, supported native
scanner exports are parsed through the canonical Cynux ingestion path so an assessment can
still complete. Unsupported formats fail visibly with a configuration error rather than
producing an empty successful assessment.

The production deployment stops injecting the private DefectDojo URL/token into the worker.
After the API-only worker revision is verified, the `cynux-defectdojo-01` VM is stopped. Its
protected persistent data disk and recent snapshots are retained for rollback. Terraform must
model this as a reversible archived resource or remove it from active management without
issuing a disk destroy. Permanent deletion is outside this change.

## Wazuh and other providers

Wazuh remains an outbound API integration. A tenant supplies the manager API URL and manager
credentials, plus the indexer URL and credentials when alert ingestion is enabled. Cynux tests
the connection, stores the credentials encrypted, and performs scheduled ingestion through the
existing worker. No Wazuh manager, indexer, dashboard, or agent is provisioned by Cynux.

The same rule applies to all other third-party providers: Cynux provisions connector code and
scheduling, not the vendor service. Providers that need an externally hosted endpoint cannot be
used until the tenant supplies that endpoint and valid credentials.

## Monthly budget circuit breaker

The billing account uses INR, so the deployment config records both the policy value
(`USD 200 monthly`) and the reviewed INR amount used by Google Cloud. The initial amount is
INR 19,000, matching the conversion already used by the project's USD 300 credit guardrail.
It remains an explicit deployment input so it can be changed later without editing scripts.

The budget is scoped only to `cynux-security-prod`, resets monthly, and publishes spend updates
to a dedicated Pub/Sub topic. Alerts are emitted at 50%, 75%, 85%, and 95% of the budget, with
a 90% forecast alert.

A dedicated Cloud Run function performs idempotent responses:

1. Below 85% it records the notification and takes no action.
2. At or above 85% (about USD 170), it stops the optional scanner worker and the archived
   DefectDojo VM if still running. Core API, web, database, Redis, and storage remain online.
3. At or above 95% (about USD 190), it verifies the notification belongs to the configured
   billing account, budget, and project, then unlinks the project's billing account. This stops
   billable services and leaves a reporting-delay buffer below USD 200.

The function uses a dedicated service account with only the project billing-association and VM
stop permissions needed for these actions. It rejects messages for any other project or budget,
handles duplicate/out-of-order Pub/Sub delivery, and writes structured audit logs without
secrets. Re-enabling billing is a manual owner action; services are then restored through the
normal deployment pipeline.

Google Cloud cost reporting is delayed, so no implementation can mathematically guarantee an
exact USD amount. The USD 170/190 staged response is the guard band intended to keep final
reported spend below USD 200 under the current workload.

## Rollout

1. Add tests for production tenant isolation, native import fallback, budget payload validation,
   idempotent VM shutdown, and billing unlink thresholds.
2. Deploy the API-only application revision while the current DefectDojo VM is still available.
3. Verify an organization without DefectDojo can complete native canonical ingestion and an
   organization with an API-configured DefectDojo uses only its own endpoint.
4. Provision the Pub/Sub topic, cutoff function, service account, IAM, and monthly budget.
5. Send synthetic notifications below and above each threshold using a non-destructive dry-run
   mode, then verify IAM and logs.
6. Stop the shared DefectDojo VM, retain its protected disks/snapshots, and run the full production
   readiness suite with the verification check changed from `defectdojo-private-health` to
   `api-only-integration-policy` and `budget-cutoff-health`.

## Success criteria

- No production tenant can inherit a deployment-level third-party endpoint or credential.
- Wazuh and all listed third-party services are configured only through tenant API connections.
- Assessments without DefectDojo do not fail when their scanner format is supported natively.
- The shared DefectDojo VM is stopped without deleting its recoverable data.
- The monthly project budget is INR 19,000 with programmatic notifications.
- Synthetic tests prove the USD 170 optional shutdown and USD 190 billing unlink paths are
  correctly scoped and idempotent without triggering a real cutoff during deployment.
- The public application, database, Redis, worker, WebSocket path, and API remain healthy after
  the migration.

