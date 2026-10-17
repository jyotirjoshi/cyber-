# Market-Parity Platform Design

## Intent

Close the highest-impact capability gaps found in the clean-room Strobes comparison while preserving Cynux's existing tenant isolation, approval gates, canonical finding model, FastAPI/PostgreSQL backend, Next.js frontend, and BYOK model.

## Scope

This programme includes:

1. An executable declarative custom-connector runtime and governed transformation pipelines.
2. Full-platform GraphQL and corresponding typed Python SDK coverage.
3. A first-class PTaaS engagement domain with participants, scope, milestones, documents, time entries, retest rounds, and client/tester views.
4. Durable agentic pentest workspaces with artifacts, shared tables, shell/browser task contracts, and approval-bound active work.
5. Broader automation triggers, expressions, manual/webhook starts, AI-agent actions, and reusable templates.
6. Asset create/import/export/bulk/merge/relationship/custom-field operations and cloud inventory projections.
7. Event-driven inbound ticket synchronization and provider-side status transitions.
8. Exploit, proof-of-concept, affected-product, patch, and control-effectiveness intelligence.
9. Enterprise MFA, retention, tenant branding, AI budget alerts, workbooks, and richer dashboards.

Adding new named third-party connector families is explicitly out of scope. Existing connector implementations may be deepened where required for bidirectional lifecycle behavior.

## Architecture

Each capability is implemented as a tenant-owned database aggregate, Pydantic contract, permission-checked service, versioned REST/GraphQL surface, worker-safe execution primitive, and focused frontend page. Long-running or external operations use durable run rows and the existing outbox/worker patterns. User-supplied code is never executed inside the API process; transformation pipelines use a bounded declarative expression language first, with any later code runner isolated behind a separate worker contract.

All cross-system writes are idempotent, audited, and approval-aware. Existing canonical findings and assets remain the source of truth; PTaaS, automation, connectors, agents, and intelligence link to them rather than creating parallel exposure stores.

## Product behavior

- A manager can define a connector, run it, observe progress, and ingest normalized data with checkpoints and reconciliation.
- API consumers can query and mutate core platform resources through GraphQL and the SDK.
- PTaaS users can manage an engagement from scope through retest and evidence delivery.
- Agents work inside durable workspaces and can produce evidence without bypassing active-security approvals.
- Automations can react to platform entities, schedules, manual requests, and signed inbound webhooks.
- Asset managers can curate inventory at scale without destroying source provenance.
- Ticket state changes can enter Cynux immediately and verified fixes can transition provider records.
- Risk scoring can consume exploit, patch, product, threat, and compensating-control evidence.
- Organizations can require MFA, enforce retention, brand tenant surfaces, and alert on AI spend.

## Constraints

- PostgreSQL remains the authoritative store and every new row is organization-scoped.
- No raw credentials or customer data may be included in logs, run results, model prompts, or webhook responses.
- External requests must use the existing hardened HTTP client, bounded pagination, rate limits, timeouts, response-size limits, and SSRF protections.
- Active security and external writes remain permission- and policy-gated.
- New behavior is introduced test-first and in independently deployable migrations.
- No new third-party connector catalogue entries are added in this programme.

