# Assurance Runtime Design

## Intent

Turn the existing control-plane recommendations, AI policy evaluator, agent runs,
validation campaigns, threat stories, risk simulations, and compliance evidence into
one production control loop. Every operation must be bounded, tenant-owned, replay-safe,
and independently verifiable. The product remains an analysis and orchestration layer;
it does not become a global proxy, SIEM archive, access network, or arbitrary shell
executor.

## Architecture

The runtime is split into seven cohesive capabilities that share the existing asset,
resource, identity, finding, business-service, integration, approval, and audit records.

1. **Enforcement transactions** snapshot sanitized provider state, produce a canonical
   deterministic diff, simulate blast radius, bind approval to the exact diff digest,
   perform one idempotent mutation, confirm provider state, observe, verify, and either
   close or execute an explicitly defined rollback. A strict state machine prevents phase
   skipping and replay.
2. **AI security runtime** exposes an OpenAI-compatible, non-streaming completion contract
   over tenant BYOK providers. Pre- and post-flight policies classify/redact content,
   enforce model/region/token/cost/retention limits, and write digest-only receipts.
   Tool manifests are pinned by hash; access edges form the user-to-data authorization
   graph. Tool calls require schema-valid arguments and action-bound approvals.
3. **Verifiable agent work** adds an immutable assurance record to each run: plan version,
   evidence references, bounded tool receipts, budgets, contradictory evidence, reason
   codes, success criteria, independent verifier result, replay digest, and outcome metrics.
4. **Governed validation** stores immutable reproduction recipes with explicit target,
   action/request budgets, artifact hashes, approval boundaries, exploitation verdict, and
   reproducibility score. Recipes never contain arbitrary shell commands or raw secrets.
5. **DSPM** projects provider inventory into the shared resource graph and records
   metadata-first assessments for cloud/SaaS data stores: classifications, controlled
   sampling policy, lineage, duplicate groups, sharing, identities, encryption/key posture,
   retention/residency, posture findings, and remediation actions.
6. **Agentic SOC and quantitative risk** normalize high-value events into OCSF-compatible
   classifications, enrich threat stories with ATT&CK progression and supporting/
   contradicting evidence, approval-bound response actions, and post-response verification.
   Risk simulation uses reproducible Monte Carlo trials and always reports assumptions and
   confidence intervals rather than a single false-precision number.
7. **Compliance automation** adds control inheritance, freshness policies, collector runs,
   asset/finding relationships, evidence requests, and signed OSCAL JSON export receipts.
   OSCAL exports cover assessment-results and POA&M-shaped remediation data without
   inventing unsupported catalog content.

## Shared invariants

- Every durable row carries `organization_id`; every lookup uses tenant filtering.
- Raw prompts, model outputs, credentials, provider bodies, samples, and HTTP exchanges are
  never stored in these tables. Durable evidence uses digests and artifact references.
- Canonical JSON uses sorted keys and compact separators before SHA-256 hashing.
- External writes require an approved, unexpired, exact action/diff digest and a unique
  idempotency key. Preview and verification never mutate providers.
- State transitions are explicit and reject skipped, repeated, or terminal transitions.
- Provider and connector adapters remain allow-listed; no request can supply an arbitrary
  URL, method, command, image, or executable.
- Tool schemas require object roots and `additionalProperties: false`; schema changes revoke
  prior approval until reviewed.
- Risk output includes seed, iterations, distribution assumptions, P05/P50/P95 and expected
  annual loss. Comparisons reuse the same seed for defensible before/after analysis.
- OCSF input is normalized to the platform event projection, not retained as a raw-log lake.
- OSCAL packages are canonicalized, SHA-256 digested, HMAC-signed with the configured
  platform signing secret, and accompanied by a key identifier and generation timestamp.

## Product surfaces

- REST APIs live under `/control-plane` to preserve the existing operator workspace.
- The existing `/control-plane` UI gains Transactions, AI Access, DSPM, SOC, Risk, Agent
  Assurance, Validation, and Compliance views. Dangerous mutations always show their exact
  scope and require a separate approval action.
- Worker execution may advance only already-approved transactions or recipes; API requests
  create/approve records and enqueue bounded work rather than running arbitrary payloads.

## Non-goals

- Building ZPA/ZIA data planes, TLS interception, browser isolation infrastructure, or VPN.
- Storing every SIEM event or full packet/body capture in PostgreSQL.
- Allowing an LLM to execute arbitrary shell commands, choose unrestricted targets, or
  authorize its own dangerous action.
- Claiming full OSCAL validation against every NIST catalog; exports are versioned platform
  projections with source provenance.

## Success criteria

- A recommendation can complete or roll back through the complete enforcement lifecycle
  with deterministic receipts and no duplicate provider mutation.
- AI interactions and tool calls are rejected when model, region, budget, schema, manifest,
  delegation, or approval policies fail, and no raw content appears in durable records.
- Agent and validation outcomes are independently verifiable and replayable from immutable
  evidence references.
- DSPM findings, OCSF events, threat stories, risk intervals, and OSCAL exports all link to
  the same canonical resources and business context.

