# Cynux Market-Parity Platform Expansion Design

Date: 2026-10-16  
Status: Approved architecture; specification awaiting review

## Purpose

Close the seven largest functional gaps between Cynux and mature CTEM platforms without replacing
the working platform. The result is one tenant-safe system in which APIs, connectors, autonomous
validation, PTaaS operations, custom pipelines, attack-surface intelligence, and automations share
the same canonical assets, findings, identity, authorization, evidence, audit, and job runtime.

The work extends the current FastAPI, PostgreSQL, Redis, Cloud Run, Firebase, Next.js, GraphQL, and
Python SDK architecture. Existing REST contracts and deployed tenant data remain compatible.

## Product Boundaries

This program includes production code, migrations, user interfaces, SDK support, worker/runtime
integration, observability, deployment configuration, and automated verification for all seven
capability groups.

It does not include payment processing, staffing a human penetration-testing marketplace,
unrestricted exploitation, destructive testing, covert credential collection, or a claim of
formal certification. Active validation must be explicitly authorized, scoped, time-bounded,
audited, and non-destructive by default.

## Architectural Principles

1. PostgreSQL is the authoritative state store; Redis carries notifications and queued work but
   is never the sole source of business state.
2. Every resource and background task is organization-scoped. Parent MSSP access is resolved
   through explicit delegation rather than inferred ownership.
3. REST, GraphQL, SDK, agents, workflows, and integrations call the same domain services and
   therefore produce identical authorization and lifecycle outcomes.
4. External writes are capability-declared, idempotent, replay-safe, observable, and auditable.
5. Plans, agent versions, pipeline versions, connector mappings, evidence, and execution attempts
   are immutable once used by a run.
6. Secrets are stored only through encrypted credential references. They are never copied into
   plans, prompts, events, GraphQL responses, pipeline definitions, or audit payloads.
7. New capabilities use organization feature flags and staged rollout. Existing REST behavior is
   backward-compatible.

## Shared Runtime

The seven slices share a durable execution substrate instead of creating separate job engines.
An execution consists of a versioned definition, a run, typed tasks, immutable attempts, evidence
references, monotonic events, budget reservations, approvals, and a terminal outcome. A
transactional outbox commits work and state together. Workers claim tasks with generation-based
leases; late results from stale generations cannot settle a task.

Admission applies deployment, organization, run, provider, target-conflict, and tool concurrency
limits. Retriable failures use bounded exponential backoff. Schema, authorization, policy,
approval, and hard-budget failures are terminal unless a user creates a new run. Cancellation
prevents successor dispatch and propagates to cancellable provider or Cloud Run jobs.

## Slice 1: Full GraphQL API and Python SDK

The public GraphQL API will cover organizations, assets, applications, canonical findings,
assessments, jobs, reports, integrations, compliance, threat intelligence, ASM, PTaaS,
automations, agents, and pipelines. Binary artifact transfer may remain REST-only, but GraphQL
must expose authorized metadata and short-lived transfer handles.

GraphQL uses opaque global IDs, stable cursor connections, typed filters, explicit ordering,
bounded bulk mutations, idempotency keys, and typed mutation errors. Every resolver reapplies
tenant scope and application permissions. DataLoaders are request-local and include tenant scope
in their keys. Validation enforces depth, aliases, fragments, node count, connection limits,
calculated cost, and rate limits.

Subscriptions use `graphql-transport-ws` for findings, jobs, approvals, agent runs, pipeline runs,
and integration synchronization. PostgreSQL retains replayable events; Redis wakes subscribers.
Reconnect uses a tenant-scoped cursor, and authority is rechecked for each event.

The Python SDK provides synchronous and asynchronous clients, typed models, pagination iterators,
stream reconnection, upload/download streaming, webhook verification, idempotency, bounded retries,
request IDs, and stable operation modules for every supported GraphQL domain. Generated schema
details remain private behind a handwritten compatibility facade.

Acceptance requires parity between REST and GraphQL business outcomes, cross-tenant isolation,
bounded adversarial queries, replayable subscriptions, and complete SDK create/query/update/
approve/stream workflows.

## Slice 2: Bidirectional Connector Synchronization

Every connector implements a capability manifest rather than relying on provider-name branching.
Capabilities include asset read, finding read, status write, comment write, assignment write,
ticket create/update, evidence read/write, webhook intake, incremental cursor, and deletion or
absence semantics. The UI displays the effective manifest and does not offer unsupported actions.

Incoming records map into canonical assets, findings, observations, tickets, and evidence with a
provider mapping version. Outbound changes are generated from canonical lifecycle events through
a normalized status and priority mapping. Each mutation has a provider-neutral operation ID,
payload digest, provider request ID, attempt history, and confirmed remote result.

The sync engine maintains independent inbound and outbound cursors, webhook deduplication, rate
limits, circuit state, retry schedules, and dead-letter review. Conflict policy is configurable by
field: Cynux-authoritative, provider-authoritative, newest-wins, or manual review. A newer local
decision cannot be silently overwritten by a stale provider poll.

All existing catalog connectors adopt the manifest. Full bidirectional behavior is required for
providers whose APIs permit the relevant write; ingestion-only providers explicitly report that
constraint. DefectDojo, Jira, ServiceNow, Azure DevOps, GitHub, GitLab, and Linear are the first
certification set for status, comments, ownership, and closure round trips.

## Slice 3: Autonomous Browser and API Validation

The agent supervisor produces a validated typed DAG of agent, tool, approval, join, decision, and
finalization tasks. Independent specialists execute in parallel under tenant and deployment
limits. A bounded second planning wave is permitted, but recursive unbounded agent creation is
not. Every task pins the agent, prompt, tool, policy, input schema, and output schema versions.

Browser validation runs in an isolated ephemeral browser worker. It supports authenticated session
profiles, navigation, form workflows, API observation, screenshots, DOM snapshots, request traces,
and assertions. API validation supports OpenAPI/GraphQL discovery, tenant-provided credentials,
authorization-matrix checks, schema and response assertions, safe input variation, and evidence
capture. Credentials are injected through one-time scoped envelopes and redacted from artifacts.

The validator will not autonomously perform denial of service, persistence, destructive mutation,
credential theft, uncontrolled fuzzing, or exploitation outside approved techniques. Material
actions bind approval to the exact payload digest and current authorization window. Findings are
created only when evidence meets the technique's verification contract; otherwise the result is
recorded as unverified or inconclusive.

Runs enforce wall-time, token, cost, task, parallelism, request, and scanner budgets. Terminal
results distinguish completed, degraded, skipped, rejected, failed, cancelled, expired,
budget-exhausted, and evidence-insufficient work.

## Slice 4: PTaaS Operations

Introduce a first-class engagement above assessments. An engagement contains customer scope,
rules of engagement, authorization windows, delivery milestones, tester assignments, planned and
recorded hours, documents, assessments, submissions, findings, retests, reports, approvals, and
attestations. Historical scope and authorization versions are immutable once testing begins.

Tester profiles contain organization membership, skills, certifications, availability, and
permitted test categories. Assignment validates conflicts, scope permissions, and capacity. Hours
are append-only entries with approval state rather than mutable totals.

Tester and client experiences use the same application with role-specific workspaces. Testers can
submit structured findings and evidence, collaborate, request review, and respond to retests.
Clients can follow progress, discuss client-visible findings, submit remediation evidence,
request retests, approve deliverables, and download finalized reports. Internal notes and draft
evidence never leak into client views.

Report approval records reviewer, version, decision, timestamp, and immutable artifact digest.
Attestations are generated only from approved report versions and completed engagement criteria;
the platform does not claim an external certification it did not receive.

## Slice 5: Sandboxed Custom Execution Pipelines

Pipelines are organization-scoped identities with immutable published versions. A version is a
typed acyclic DAG containing manual/API, cron, lifecycle, asset, integration, ticket, SLA, retest,
assessment, agent, and webhook triggers. Nodes include query, filter, declarative transform,
isolated Python transform, agent, tool, approval, parallel, join, delay, and emit.

The runtime reuses the shared durable task protocol. Publishing validates schemas, graph shape,
permissions, worst-case task count, destinations, budgets, referenced versions, and secret slots.
Runs preserve complete lineage and never rewrite attempts during retry or replay.

Customer Python executes only in a pinned Cloud Run Job image as a non-root process with a
read-only root filesystem, bounded temporary storage, no network by default, CPU/memory/process/
output/time limits, and one validated JSON input and output. Source is statically checked;
dependencies come from a pinned allowlist; artifacts and lockfiles are content-addressed. A passing
isolated test run is required before publication.

Optional outbound HTTPS uses exact destination policies with redirect and DNS-rebinding checks.
Step-scoped credentials are delivered through short-lived KMS-encrypted envelopes. The executor
cannot access the metadata server, database, Redis, unrelated artifacts, or other tenants.

## Slice 6: ASM and Threat Intelligence Depth

ASM continuously discovers and correlates domains, subdomains, IPs, URLs, certificates, cloud
resources, repositories, containers, applications, and third-party relationships. Discovery
sources include certificate transparency, DNS, permitted active probes, archives, cloud account
connectors, repository providers, and imported inventory. Every observation preserves source,
first/last seen time, confidence, and evidence.

Monitoring detects new or removed services, certificate issuance and expiry, DNS and hosting
changes, technology drift, ownership drift, cloud exposure, and new third-party dependencies.
Brand monitoring generates candidate typosquats and lookalike domains with confidence and review
state. Leaked-credential monitoring accepts authorized provider feeds and stores only minimized,
non-secret evidence; it never stores plaintext passwords.

Threat intelligence maintains local versioned CVE, CWE, CPE, advisory, KEV, EPSS, exploit
reference, patch, malware, ransomware, campaign, and threat-actor associations with provenance,
confidence, timestamps, and license metadata. Feed reconciliation never deletes prior evidence;
superseded assertions remain auditable. Enrichment updates canonical risk through deterministic
versioned scoring inputs.

## Slice 7: Expanded Automation Platform

Automation rules use a versioned event schema and a typed condition tree supporting nested all,
any, and not groups. Triggers cover finding lifecycle, asset changes, integration synchronization,
ticket state, SLA warning/breach, retest state, assessment and engagement milestones, agent and
pipeline completion, threat-intelligence changes, webhook intake, and cron schedules.

Actions include assignment, tags, lifecycle decisions, risk acceptance workflows, ticket and
comment synchronization, notification, escalation, retest, assessment, report, agent, pipeline,
webhook, and compliance evidence operations. Branch, delay, throttle, deduplicate, join, and
stop nodes enable multi-step flows. Side-effect capabilities inherit the same approval and
authorization rules as direct user actions.

Rules support drafts, immutable published versions, simulation against historical or sample
events, templates, enable/pause, execution history, retries, dead-letter review, cancellation,
and per-rule budgets. Simulation cannot produce external effects. Runtime records every evaluated
condition, selected branch, action request, remote result, evidence link, and terminal reason.

## Cross-Slice Data Flow

1. Connectors, ASM, scanners, PTaaS submissions, or APIs create versioned source observations.
2. Canonical services resolve assets and findings, deduplicate evidence, and update risk.
3. Lifecycle events enter the transactional outbox.
4. Automation rules and pipelines evaluate the versioned event under current tenant policy.
5. Agents or workers execute admitted tasks, pausing for exact-payload approval where required.
6. External mutations settle through the bidirectional sync operation ledger.
7. GraphQL, REST, SDK, subscriptions, dashboards, and reports expose the same durable state.

## Security, Reliability, and Tenant Isolation

- Every database query and loader includes organization scope; opaque IDs never confer access.
- Parent organizations require explicit active delegation for client data.
- Active scanning and validation require current target authorization and allowed technique scope.
- SSRF defenses reject private, loopback, link-local, metadata, ambiguous, and rebinding targets
  unless a dedicated private runner and explicit policy authorize them.
- Logs, traces, evidence previews, provider errors, and task outputs pass secret redaction and
  bounded-size controls.
- Mutation idempotency, attempt history, outbox publication, lease generations, and provider
  request IDs prevent duplicate external effects during retries or worker restarts.
- Feature flags, organization allowlists, kill switches, migrations compatible with rolling
  deployment, and staged rollout protect existing production traffic.

## Observability

Metrics cover API latency and cost, GraphQL complexity, queue delay, task execution, retries,
leases, provider errors, sync lag, conflicts, browser/API validation outcomes, engagement SLA,
pipeline duration, ASM discovery changes, feed freshness, automation decisions, usage, and spend.

Every run has a correlation ID and immutable lineage. Health checks distinguish database, Redis,
object storage, queue, browser worker, pipeline executor, and provider dependencies. Alerts target
stuck leases, growing dead letters, stale feeds, failed webhook delivery, sustained sync lag,
budget saturation, isolation-probe failure, and migration mismatch.

## Delivery Sequence

The implementation order is:

1. stabilize and capture the currently deployed code baseline;
2. shared execution contracts and event schemas;
3. GraphQL and SDK expansion;
4. connector capability manifests and bidirectional sync;
5. durable autonomous browser/API validation;
6. PTaaS engagement operations;
7. isolated custom pipelines;
8. ASM and threat-intelligence expansion;
9. automation expansion;
10. cross-slice acceptance, rollout, and production deployment.

Each stage is independently migratable and feature-flagged. A later stage may consume only a
published interface from an earlier stage, not its internal implementation.

## Program Acceptance Criteria

- Every supported public business operation has REST or GraphQL coverage and typed SDK access;
  GraphQL and REST enforce identical tenant and role outcomes.
- Certified bidirectional connectors round-trip status, ownership, comments, and closure without
  loops or stale-write regression; unsupported provider capabilities are explicit.
- A three-specialist validation run executes concurrently, survives worker interruption, captures
  browser/API evidence, pauses for material approval, and settles once.
- A PTaaS engagement completes scope authorization, assignment, submission, client collaboration,
  remediation, retest, report approval, and attestation with correct visibility boundaries.
- A pipeline combining query, branch, agent, approval, isolated Python, and emit nodes survives a
  restart, preserves lineage, obeys budgets, and cannot access another tenant or metadata service.
- ASM produces reviewed change events for certificates, DNS, services, cloud resources, brand
  candidates, and third parties; threat enrichment has provenance and deterministically updates
  risk.
- Automation simulation is side-effect free, while a published rule performs an idempotent
  multi-step escalation and records every decision and external result.
- Unit, integration, migration, contract, tenant-isolation, recovery, frontend, SDK, and production
  smoke suites pass before global enablement.

## Compatibility and Rollout

Existing REST endpoints, database identities, canonical fingerprints, connector configuration,
and report URLs remain valid. New nullable fields and tables are deployed before code that writes
them; backfills are resumable and bounded. Destructive schema cleanup is outside this program.

Capabilities ship disabled by default, then enable for an internal organization, selected canary
organizations, and finally general availability. Each stage has a rollback flag that stops new
work while allowing already-committed state to settle safely.
