# Integrated CTEM Platform Design

## Goal

Extend Cynux's existing assessment, finding, agent, integration, dashboard, and API surfaces into an authorization-bound CTEM platform without introducing a parallel product model.

## Product Boundaries

Only targets with an immutable, explicit authorization record may enter active testing. Every action classified medium or high risk requires a durable approval record; forbidden actions remain impossible to approve. Customer-supplied keys are encrypted in the existing per-organization credential vault, never returned by APIs, and never logged.

## Integrated Architecture

`Assessment` becomes the common engagement record. It retains its existing lifecycle and gains an engagement profile, execution mode, retention policy, and validation linkage. `Finding` remains the Cynux projection of the vulnerability source of truth while gaining normalized-source metadata, proof-of-validation state, risk/ownership/SLA fields, and remediation recheck history.

The existing `Integration` and `IntegrationCredential` tables are extended with a tenant-scoped LLM integration. The API and agent graph resolve the current organization's provider/model/key at the time an AI capability is invoked; an organization without a configured key receives a typed setup-required response rather than causing application startup to fail.

Existing Redis Streams agent runs remain the execution backbone. Specialist agent roles, progressive skill manifests, bridge execution, workflows, and background validation become typed capabilities on the existing agent run/event protocol. They must preserve current authorization and approval behavior.

## Delivery Slices

1. **Shared foundation:** engagement profiles; tenant BYOK; validation-proof state; workflow/SLA data contracts; migration safety; UI setup paths.
2. **Assess and pentest:** normalized ingestion, deterministic deduplication and risk scoring, specialist orchestration, evidence gates, durable context memory.
3. **Validate and mobilize:** recheck runs, workflow rules, ticket lifecycle hooks, ownership/SLA escalation, verified remediation reporting.
4. **Platform and scale:** GraphQL, scoped API tokens, connector/pipeline runtime, Intel API, advanced bridge/sandbox execution, reporting schedules.

## First Slice

The first slice delivers the shared contract needed by all later slices: a typed engagement profile on existing assessments; a provider/model/key configuration contract using the existing encrypted integration store; and proof-validation lifecycle fields on findings. No active scanner, exploit, shell, bridge, or connector is added until the authorization, approval, and evidence contract is implemented and tested.

## Testing and Rollout

Each migration must be forward-safe on the Railway Postgres database and preserve existing rows through server defaults/backfills. Unit tests cover authorization, tenant isolation, credential redaction, LLM resolution, and proof state transitions. End-to-end checks cover registration, organization configuration, assessment creation, approval, and health endpoints before every production deployment.
