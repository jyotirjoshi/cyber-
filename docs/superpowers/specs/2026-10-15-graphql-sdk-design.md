# Public GraphQL API and Python SDK Design

Date: 2026-10-15
Status: Approved design, pending implementation planning

## Purpose

Expose Cynux's complete supported business surface through a tenant-safe GraphQL API and provide
an ergonomic synchronous and asynchronous Python SDK. REST remains supported. Both interfaces
call the same domain services and enforce identical authorization and audit behavior.

## GraphQL Architecture

Add Strawberry GraphQL to the existing FastAPI application at `/api/graphql`. Use the existing
JWT and scoped platform API-key authentication. Request context contains the validated principal,
request metadata, service dependencies, and DataLoaders; it never contains a globally reusable
database session.

Public schema domains:

- organizations, client organizations, members, roles, SSO and SCIM metadata;
- assets, applications, changes, groups, ownership, policy gates, and risk history;
- canonical findings, observations, decisions, work, comments, remediation groups, tickets,
  risk acceptances, and retests;
- assessments, authorizations, profiles, schedules, jobs, artifacts, and reports;
- integrations, synchronization state, notifications, and webhook deliveries;
- compliance frameworks and controls, threat intelligence, ASM, automations, and workflows;
- agent definitions, versions, tools, knowledge, runs, tasks, actions, approvals, decisions,
  citations, and evaluations;
- pipeline definitions, versions, triggers, runs, steps, artifacts, and approvals.

Sensitive values such as credential material, reset tokens, SCIM tokens, webhook secrets, raw
scanner payloads, and internal storage keys are never fields in the schema.

## Schema Conventions

- Relay-style opaque global IDs encode type and UUID, but resolvers always reapply organization
  scope rather than trusting the decoded ID.
- Connections use cursor pagination with stable `(sort_value, id)` cursors. Offset pagination is
  not exposed for large collections.
- Filters and ordering are explicit typed inputs; arbitrary SQL-like expressions are rejected.
- Mutations return a typed payload with resource, user-safe errors, audit event ID, and client
  mutation ID.
- Mutations that can be retried accept an idempotency key and use the existing idempotency store.
- Bulk mutations have explicit maximum item counts and per-item results.
- Dates are UTC ISO-8601, money uses integer micros plus currency, and severity/status use enums.

## Authorization and Query Controls

Resolvers call application services using the current principal. Schema visibility is not relied
upon for security. Every loader includes organization scope in its key and query.

Before execution, validate maximum depth, aliases, fragments, node count, and calculated cost.
Cost incorporates connection limits and expensive fields. Apply per-key/user/organization rate
limits and reject introspection for production API keys unless their scope permits schema access.
Persisted queries are supported for the web application but do not replace these controls.

GraphQL errors use stable extension codes, request IDs, retryability, and field paths without
leaking exception strings, SQL, provider responses, or tenant existence.

## Subscriptions

Support the `graphql-transport-ws` protocol for agent run events, assessment/job progress,
finding changes, approval state, pipeline runs, and notification delivery. Redis carries event
notifications; PostgreSQL remains the source for replay. Each domain stream has a tenant-scoped
monotonic sequence or durable cursor. Clients reconnect with a cursor and receive missed bounded
events before switching to live delivery.

Subscription authorization is checked at connection and for every event. Membership or role
changes terminate streams whose authority is no longer valid. Slow clients have bounded queues
and receive an explicit reconnect cursor rather than consuming unbounded memory.

## Performance

- DataLoaders batch only within one request and include tenant scope.
- Resolvers select projections rather than hydrating full ORM graphs.
- Connection limits have conservative defaults and hard maxima.
- Common filtering/sorting paths receive composite indexes during migration.
- N+1 and query-cost budgets are asserted in integration tests.
- Introspection and schema artifacts are generated during CI, not per request.

## Python SDK

Publish `cynux` as a versioned package containing:

- `CynuxClient` and `AsyncCynuxClient` with context-manager support;
- typed Pydantic models and enums;
- GraphQL transport plus stable operation modules for common queries/mutations;
- cursor iterators and asynchronous iterators;
- agent objective submission, event streaming, approvals, cancellation, and result retrieval;
- knowledge upload/indexing/retrieval preview;
- findings, assets, assessments, integrations, reports, automations, and pipelines;
- bounded file upload/download streaming;
- webhook signature verification;
- idempotency, retry, timeout, rate-limit, and request-ID handling;
- structured exceptions matching public error codes.

The SDK facade is handwritten for ergonomic stability. GraphQL documents and response models may
be generated from the checked-in schema, but generated implementation details remain private.
Synchronous and asynchronous transports share serialization, auth, retry policy, and models.

Authentication accepts API keys directly or a callback token provider. Secrets are never included
in `repr`, exceptions, logs, traces, or telemetry. Automatic retries are limited to transport
errors, explicit retryable responses, and idempotent operations.

## Versioning and Compatibility

GraphQL additions are backward-compatible. Deprecated fields include a reason and removal date
and remain for at least two minor releases. Breaking changes require a new schema contract or
major SDK version. CI compares the generated schema against the previous release and fails on
unapproved breaking changes.

SDK support follows the current and previous minor backend API versions. Package metadata states
the compatible server range, and the client checks server capabilities before optional features.

## Acceptance Criteria

- Every documented public REST domain has an equivalent supported GraphQL query or mutation, or
  is explicitly classified as REST-only binary transport.
- GraphQL and REST produce identical authorization and business outcomes for shared operations.
- Cross-tenant node IDs, cursors, loader keys, subscriptions, and mutations disclose nothing.
- Complexity, pagination, bulk, and rate limits hold under adversarial queries.
- Subscriptions replay missed events after reconnect without cross-tenant delivery.
- The sync and async SDK complete create/query/update/approve/stream flows against production-like
  services using scoped API keys.
- Schema compatibility and SDK contract tests run in CI.

