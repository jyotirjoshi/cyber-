# Cynux Agent Platform Expansion

Date: 2026-10-15
Status: Approved design, pending implementation planning

## Objective

Turn Cynux's existing AI chat, assessment graph, specialist scan tasks, curated tenant memory,
Dify retrieval, REST API keys, SDK skeleton, and custom connector definitions into a cohesive
agent platform with four production capabilities:

1. Tenant-configurable AI agents with explicit tools and knowledge collections.
2. Durable parallel multi-agent execution with evidence, approvals, recovery, and budgets.
3. A complete public GraphQL surface and production Python SDK.
4. Versioned custom execution pipelines with isolated code execution.

The result must preserve organization isolation, reuse existing domain services instead of
duplicating business rules, remain operable on the current Google Cloud deployment, and respect
the deployment-wide cost cutoff.

## Delivery Units

This program is intentionally split into four independently releasable units:

1. [Custom agents and knowledge](2026-10-15-custom-agents-and-knowledge-design.md)
2. [Parallel multi-agent orchestration](2026-10-15-multi-agent-orchestrator-design.md)
3. [GraphQL and Python SDK](2026-10-15-graphql-sdk-design.md)
4. [Custom execution pipelines](2026-10-15-custom-execution-pipelines-design.md)

Each unit receives a separate implementation plan and can be deployed behind its own feature
flag. Their required order is 1, 2, 3, 4. GraphQL development may begin after the Phase 1 public
service contracts settle, but it must not block the agent runtime.

## Architectural Principles

- PostgreSQL remains the system of record; Redis carries ephemeral queue, event, lease, and
  concurrency state; object storage carries source documents and bounded run artifacts.
- All public interfaces call existing application services. GraphQL, REST, agents, and pipelines
  must not contain competing implementations of authorization, finding lifecycle, ticketing, or
  integration logic.
- Every persistent row is organization-scoped. Cross-tenant identifiers are rejected at service
  boundaries and composite tenant foreign keys are used where practical.
- Model output is untrusted. It may propose typed operations but cannot bypass schemas,
  permission checks, tool policy, approval policy, idempotency, or evidence requirements.
- Parallelism is admitted through global, tenant, run, and provider limits. Unbounded
  `asyncio.gather`, unbounded Redis fan-out, and concurrent use of one SQLAlchemy session are
  prohibited.
- Agent configuration, pipeline configuration, and knowledge revisions are immutable once used
  by a run. Edits create versions.
- A completed task means its structured output and evidence were durably committed. A model's
  natural-language claim is never completion evidence.
- Cost and token accounting are first-class. New work is rejected when tenant, run, or
  deployment budgets are exhausted.

## Shared Runtime Boundaries

The platform will expose one tool registry. A tool entry declares its input/output JSON schema,
required Cynux permission, side-effect class, approval default, timeout, retry behavior, and
executor. Custom agents select entries from this registry; orchestration and pipelines execute
the same entries. This prevents a tool from being safe in chat but unsafe in a workflow.

Knowledge retrieval has one interface. The internal hybrid retriever is the default; Dify is an
optional adapter. Both return the same bounded, cited `KnowledgeHit` objects. Prompt construction
does not depend on the provider.

Events use a durable transactional outbox before Redis publication. GraphQL subscriptions,
webhooks, automation, and agent progress consume the same event envelope without sharing mutable
state.

## Cost and Efficiency

- Reuse Cloud SQL, Redis, the existing private object bucket, API service, worker service, and
  Cloud Run Jobs. Do not provision a standalone vector database or message broker.
- Use PostgreSQL hybrid search with an HNSW vector index and full-text index. Retrieve a small
  candidate set before reranking.
- Hash documents and chunks so identical content is neither stored nor embedded twice within an
  organization.
- Batch embeddings, cache retrieval results briefly per organization/query/revision, and cancel
  obsolete indexing jobs.
- Default agent fan-out is three tasks, hard-bounded by organization entitlement and deployment
  capacity.
- Cloud Run pipeline jobs default to zero idle instances, maximum two concurrent instances,
  bounded CPU/memory, and a short runtime ceiling.
- Usage meters record model tokens, embedding tokens, task runtime, pipeline runtime, GraphQL
  cost units, storage bytes, and external tool calls.

## Program Acceptance

The program is complete only when a fresh tenant can:

1. Create and version an agent, select tools, attach a knowledge collection, and test retrieval
   with citations.
2. Submit one objective that produces at least three parallel durable specialist tasks, survives
   a worker restart, pauses for a material action, resumes after approval, and records evidence.
3. Query and mutate the resulting assets/findings/runs through GraphQL and perform the same flow
   through the Python SDK using a scoped API key.
4. Publish a versioned pipeline that reacts to a finding event, runs a bounded transformation in
   an isolated Cloud Run Job, pauses for approval, and invokes a typed Cynux tool exactly once.
5. Export an audit trail linking the objective, agent and pipeline versions, knowledge citations,
   tool calls, approvals, usage, and terminal outcome.

