# Custom Execution Pipelines Design

Date: 2026-10-15
Status: Approved design, pending implementation planning

## Purpose

Provide versioned event-driven and scheduled pipelines that combine Cynux queries, conditions,
agent tasks, approval gates, platform tools, external integrations, and optional customer Python
transformations. Execution must be durable, observable, idempotent, tenant-isolated, and safe on
Cloud Run.

## Definition Model

Add organization-scoped pipeline identities and immutable versions. A version contains a JSON
DAG with typed nodes, edges, input/output schemas, trigger definitions, budgets, failure policy,
and configuration digest. Drafts may be edited; publishing validates and freezes a version.
Running versions cannot be mutated or deleted while retention references exist.

Node types:

- `query`: bounded GraphQL persisted operation or domain-service query.
- `filter`: declarative conditions over typed input.
- `transform`: declarative mapping or isolated Python step.
- `agent`: invoke an immutable agent version with selected input.
- `tool`: invoke one registry tool.
- `approval`: require resolution of the exact downstream payload.
- `parallel`: release bounded independent branches.
- `join`: combine branch results through a declared schema and policy.
- `delay`: resume at a timestamp within the maximum workflow lifetime.
- `emit`: create a notification, webhook event, report, or typed pipeline output.

Cycles are prohibited in the first release. Repetition uses bounded event/cron invocations rather
than in-run loops.

## Triggers

Supported triggers are manual/API, cron, canonical finding lifecycle, asset change, integration
sync completion, ticket state, SLA warning/breach, retest state, assessment completion, agent run
completion, and webhook intake. Trigger filters are declarative, bounded, and evaluated against a
versioned event schema.

Events enter through a transactional outbox with stable IDs. A unique `(pipeline_version,
event_id)` constraint provides at-most-one logical run. Manual/API starts accept idempotency keys.
Cron uses the organization's configured timezone but stores UTC fire times and handles daylight
saving deterministically.

## Runtime

Reuse the generic durable task protocol from the multi-agent orchestrator. A pipeline run stores
the immutable version, trigger envelope, current state, budgets, terminal outcome, and audit
links. Each step stores attempts, lease, typed input/output, evidence, usage, and error taxonomy.

The scheduler releases ready nodes only after dependency settlement and condition evaluation.
Parallel branches follow tenant/run/global admission limits. Failure policy is explicit per node:
fail run, retry, continue degraded, or route to a declared failure branch. No failure is silently
converted to success.

## Isolated Python Executor

Python transformations never execute in the API or general worker process. A dedicated pinned
executor image runs as a Cloud Run Job with:

- non-root user and read-only application filesystem;
- writable bounded temporary directory only;
- no network by default;
- optional exact HTTPS destination allowlist resolved and revalidated by the platform;
- no Docker socket, metadata-server access, broad service-account permissions, or shell access;
- fixed CPU, memory, process, output, and runtime ceilings;
- one input JSON document and one output JSON document validated against schemas;
- stdout/stderr capture with size limits and secret redaction;
- immutable code artifact hash and dependency-lock hash;
- cancellation and hard deadline.

Customer code is a small `run(context, input)` function packaged with a lockfile from an approved
dependency catalog. Arbitrary dependency installation during execution is prohibited. An
organization uploads source, Cynux scans and validates it, builds or selects a deterministic
artifact, stores it privately, and requires a test run before publishing.

## Secrets and Connectivity

Pipeline versions reference integration credential slots by opaque ID and name; they never copy
secret values. A run produces a one-time, step-scoped secret envelope encrypted with Cloud KMS,
stored in the private artifact bucket, and readable only by the executor service account for the
bounded job lifetime. The job deletes its local copy on exit and the platform deletes the
envelope after settlement. Audit records expose slot names, not values.

External access requires a connector or an explicit pipeline destination policy. URL redirects,
DNS rebinding, private/link-local IP ranges, unexpected ports, and destinations outside the
allowlist are rejected. Built-in integration calls should use registry tools rather than custom
network code.

## Builder and Operations Interface

The UI provides a graph builder and an accessible ordered-step editor backed by the same typed
definition. Users select triggers and nodes from catalogs, map fields, validate schemas, test with
sample events, inspect effective permissions/cost, publish, pause triggers, and compare versions.

Run views show the DAG, current steps, retries, approvals, logs, evidence, usage, and output.
Operators can cancel a run, retry an eligible failed step, or replay an event into a new run/version;
they cannot rewrite history.

## Budgets and Efficiency

- Validate the worst-case branch/task count before publish.
- Default maximum is 25 nodes, four parallel branches, ten minutes per Python step, and one hour
  per pipeline run; entitlements may lower or deliberately raise bounded values.
- Cloud Run Job maximum instances starts at two and scales from zero.
- Reject new custom-code work when the deployment cost cutoff, tenant budget, or pipeline budget
  is exhausted.
- Cache immutable code artifacts by hash and reuse the pinned executor image.
- Meter job seconds, CPU/memory class, storage, tool calls, model tokens, and external calls.

## Acceptance Criteria

- A user can draft, validate, test, publish, version, pause, and run a pipeline.
- Duplicate event delivery produces one logical pipeline run and one external mutation.
- Parallel branches and joins survive worker/API restart without lost or duplicated steps.
- Python cannot access another tenant, platform metadata, unbound secrets, private networks, or
  undeclared destinations.
- Inputs and outputs that violate schemas fail before downstream execution.
- Approval binds the exact version and payload and is revalidated immediately before execution.
- Cost, concurrency, duration, output, and network limits are enforced, not advisory.
- Run history links triggers, versions, code hashes, agent versions, tool calls, approvals,
  evidence, usage, logs, and terminal outcomes.

