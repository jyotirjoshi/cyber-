# Custom Agents and Internal Knowledge Design

Date: 2026-10-15
Status: Approved design, pending implementation planning

## Purpose

Allow each organization to create reusable AI workers with a defined role, model, instructions,
tools, knowledge, scope, autonomy, and budget. Replace the current combination of one generic
chat persona, manually curated short memories, and optional Dify retrieval with a first-party,
tenant-isolated knowledge system. Dify remains an optional retriever.

## Existing Foundations

Cynux already has agent sessions, messages, runs, steps, actions, immutable action payload
digests, approval execution, organization memory, BYOK LLM selection, integration credentials,
object storage, and Dify retrieval. This phase extends those foundations rather than replacing
them.

## Agent Domain Model

Add these organization-scoped records:

- `agent_definitions`: stable identity, display name, description, avatar reference, active
  version, enabled state, creator.
- `agent_definition_versions`: immutable role, instructions, provider/model selection, autonomy
  mode, budgets, concurrency, scope policy, and configuration digest.
- `agent_version_tools`: allowed registry tool, optional stricter approval mode, timeout, and
  per-run call limit.
- `agent_version_collections`: attached knowledge collection and optional metadata filter.
- `agent_templates`: system templates plus tenant-owned templates. Creating from a template
  copies into a tenant definition; later template changes never mutate an existing agent.
- `agent_evaluations`: test case, expected criteria, actual run, grader results, cost, latency,
  and reviewer decision.

An existing version is never updated after a session or run references it. Editing creates a
new version under a row lock and atomically changes `active_version_id`. Sessions record the
selected version so historical behavior is reproducible.

## Agent Configuration

The create/edit flow contains four sections:

1. Identity: name, description, avatar, and role.
2. Instructions and model: system instructions, BYOK provider, exact model identifier,
   temperature, and output-token ceiling.
3. Capabilities: tool selection, per-tool approval override, target/asset scope, autonomy mode,
   maximum parallel tasks, runtime, tool calls, tokens, and estimated spend.
4. Knowledge: one or more collections plus retrieval count, score threshold, and metadata
   filters.

Autonomy modes are `manual`, `supervised`, and `bounded`. `manual` permits reads only.
`supervised` permits reads and proposed mutations but requires approval for each mutation.
`bounded` permits only administrator-selected mutation tools within explicit asset, quantity,
time, and cost limits. Destructive, credential, identity, SSO, SCIM, role, and billing actions
always require approval and cannot be made autonomous.

At execution time the effective authority is the intersection of:

- the requesting principal's permissions;
- the agent version's tool allowlist and scope;
- the organization policy and entitlement;
- the tool registry's mandatory requirements;
- the run's remaining budgets.

## Tool Registry

Every callable tool has a stable name and version, human label, input/output JSON schema,
required permission, side-effect class (`read`, `tenant_write`, `external_write`,
`active_security`), default approval policy, timeout, retry policy, idempotency support, and
executor reference. Registry entries are code-owned; tenants cannot replace built-in executors.

Tool results contain a bounded summary and durable evidence references. Raw scanner output,
credentials, unrestricted HTML, and provider payloads are not placed in model context.

## Knowledge Domain Model

Add:

- `knowledge_collections`: name, description, retrieval policy, enabled state, revision.
- `knowledge_sources`: collection, source type, filename/title, object key, MIME type, content
  hash, size, status, error taxonomy, document metadata, creator, and current revision.
- `knowledge_source_versions`: immutable object and extraction provenance.
- `knowledge_chunks`: normalized text, ordinal, token count, page/section metadata, text-search
  vector, content hash, source version.
- `knowledge_embeddings`: chunk, embedding profile, fixed 1536-dimension vector, generation
  status, and embedding content hash.
- `knowledge_feedback`: query, cited hit, usefulness decision, run, and reviewer.
- `agent_memory_candidates`: bounded proposed organizational facts with source evidence,
  confidence, expiry, status, reviewer, and decision rationale.

All tables carry `organization_id`; joins validate matching organization identifiers. Object keys
are namespaced by organization and opaque IDs.

## Ingestion

Supported first release formats are plain text, Markdown, PDF, JSON, SARIF, CycloneDX, and SPDX.
Uploads are content-type checked, size bounded, hashed, and stored before an indexing job is
published transactionally. Extraction runs outside the API request. Unsupported encrypted PDFs,
archives, executables, macros, and malformed documents fail with a stable user-visible reason.

Extraction normalizes Unicode, preserves page/heading provenance, removes repeated page furniture,
and creates semantic chunks with a bounded overlap. Chunk hashes provide tenant-local
deduplication. Indexing batches embedding requests, records usage, and can resume from the first
unfinished batch. Deleting a source tombstones it immediately for retrieval, then asynchronously
removes objects, chunks, embeddings, caches, and derived citations subject to audit-retention
requirements.

## Embeddings and Retrieval

Use PostgreSQL `pgvector` in Cloud SQL with `vector(1536)` and an HNSW cosine index. Embedding
profiles are organization-selectable from supported OpenAI or Gemini embedding adapters, but all
profiles must emit exactly 1536 dimensions. An organization may use a deployment-managed profile
or its own encrypted BYOK credential. Anthropic is still valid for generation but is not an
embedding provider.

Retrieval:

1. Normalize and embed the query.
2. Apply organization, collection, enabled-source, revision, and metadata filters.
3. Retrieve bounded vector and PostgreSQL full-text candidate sets.
4. Fuse rankings with reciprocal-rank fusion.
5. Deduplicate adjacent chunks and enforce per-source diversity.
6. Return at most the configured hit count with collection, source, page/section, chunk ID,
   score, content hash, and bounded text.

Dify implements the same retriever interface and is selected per collection. Results from both
providers use identical citations and untrusted-content fencing.

## Persistent Learning

Conversation transcripts are not automatically treated as truth. An agent may propose a memory
candidate only when it cites durable Cynux evidence or knowledge chunks. The candidate is visible
to organization managers, who approve, edit, reject, or set an expiry. Approval creates or
versions an `AgentMemory` entry with source `approved_agent`; rejection is retained for evaluation
but never injected into prompts.

Feedback changes retrieval evaluation metrics, not stored knowledge. Promotion rules may suggest
frequently useful passages or memories, but may not auto-approve them.

## API and Interface

REST endpoints cover agent definitions, versions, templates, tool catalog, test runs,
evaluations, collections, sources, upload, indexing status, retrieval preview, feedback, and
memory candidate decisions. GraphQL exposes the same services in Phase 3.

Add navigation under **AI** for Agents, Knowledge, Runs, and Evaluations. The agent editor shows
effective permissions and approval behavior before save. Knowledge search preview displays the
exact citations that would enter a prompt.

## Failure, Safety, and Efficiency

- Retrieval failure degrades with an explicit `knowledge_unavailable` status; the model must not
  claim it searched unavailable knowledge.
- Provider keys are selected through integration records and are never stored on agent versions.
- Prompt injection in documents is fenced as reference data and cannot change tool policy.
- Per-tenant indexing concurrency, token budgets, file size, document count, and storage quotas
  are enforced before work is queued.
- Query and embedding caches include organization, knowledge revision, provider, model, and
  policy digest in their keys.

## Acceptance Criteria

- An owner can create, clone, version, disable, and test an agent.
- A tool removed in a new version remains visible in old run history but cannot be called by new
  runs.
- Cross-tenant agent, collection, source, chunk, embedding, citation, and memory access fails.
- A document upload progresses through stored, extracting, chunking, embedding, ready states and
  can recover after worker termination without duplicate chunks.
- Hybrid retrieval returns cited tenant-scoped passages and no disabled or deleted source.
- A model-proposed organizational fact is unavailable to later sessions until approved.
- Usage, latency, failure reason, citations, tool selection, and configuration version are
  auditable for every test and production run.

