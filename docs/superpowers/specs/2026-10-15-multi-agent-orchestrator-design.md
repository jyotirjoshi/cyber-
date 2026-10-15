# Durable Parallel Multi-Agent Orchestrator Design

Date: 2026-10-15
Status: Approved design, pending implementation planning

## Purpose

Generalize the existing assessment graph and scanner-specific specialist tasks into a durable
orchestrator that can plan and run multiple tenant-configured agents in parallel, aggregate
evidence, pause for approvals, recover from process failure, and stop at explicit budgets.

## Execution Model

An objective creates one `AgentRun` referencing an immutable agent version. A supervisor produces
a typed plan, not executable prose. The plan is a directed acyclic graph of bounded tasks. A
deterministic validator rejects cycles, unknown tools, invalid schemas, inaccessible assets,
permission violations, impossible dependencies, and plans exceeding run budgets before any task
is dispatched.

Task types are:

- `agent`: invoke a configured specialist with bounded context and selected tools.
- `tool`: execute one registry tool with a validated payload.
- `approval`: pause until an authorized principal resolves the exact payload digest.
- `join`: aggregate dependency outputs through a deterministic schema.
- `decision`: ask the supervisor to choose from policy-generated candidates.
- `finalize`: verify evidence and produce the terminal answer/report.

The supervisor can add a bounded second wave of tasks after a decision node. It cannot create
unbounded recursive agents. Default maximum depth is three, maximum tasks per run is 30, and
maximum parallel tasks is three unless a lower tenant/deployment limit applies.

## Persistence

Extend existing run, step, specialist-task, decision, dispatch, and event records instead of
building a second run system. Add generic task kind, parent task, agent version, tool version,
input/output schema versions, dependency records, lease generation, idempotency key, budget
reservation, result summary, evidence references, cancellation state, and terminal taxonomy.

Plans and task payloads receive canonical JSON digests. A unique run/idempotency constraint
prevents duplicate task creation. Attempts are append-only; the current task row points to the
successful or latest attempt. Evidence artifacts are immutable.

## Queue and Worker Protocol

Use Redis Streams with consumer groups and the existing transactional dispatch outbox:

1. Commit task and outbox entry together.
2. Publish only committed entries.
3. Claim one task under tenant/run/global concurrency admission.
4. Atomically acquire a database lease generation and record the worker.
5. Heartbeat both lease and progress without sharing the execution transaction.
6. Execute with a fresh SQLAlchemy session for each task.
7. Commit structured output, evidence, usage, and terminal status.
8. Publish the task event and acknowledge Redis only after durable settlement.

Stale tasks are reclaimed only when their lease and underlying provider/scanner job are stale.
Late results from an older lease generation are rejected. Retryable failures use bounded
exponential backoff with jitter; policy, permission, schema, budget, and approval rejections are
terminal.

## Parallelism and Joins

The scheduler releases a task only when every required dependency is complete and its condition
is true. Independent ready tasks may run in parallel, subject to:

- deployment worker capacity;
- tenant entitlement and budget;
- run maximum parallelism;
- LLM provider concurrency and rate limits;
- tool/provider-specific concurrency;
- target conflict keys for actions that must serialize.

Joins consume bounded structured outputs and evidence references, never raw unbounded logs. Join
policy may require all, quorum, or best-effort dependencies. A failed mandatory dependency fails
the join; an optional failure is represented as a degradation and cannot be hidden.

## Planning and Specialists

Built-in templates include exposure triage, threat-intelligence review, attack-path analysis,
remediation planning, compliance evidence, report generation, and authorized assessment. Tenant
agents may fill these roles when their tool and knowledge policies satisfy the template.

The planner receives the objective, asset scope, effective permissions, tool catalog summaries,
knowledge citations, prior approved organization memory, and budgets. It does not receive
credentials or raw third-party payloads. The policy validator, not the model, selects which
candidate actions are executable.

## Approvals and Autonomy

Every task derives an approval requirement from its side-effect class, agent mode, organization
policy, tool policy, and payload scope. Approval rows bind the canonical payload digest, agent
version, run, task, requester, expiration, and effective permission. Execution revalidates all of
them and current organization policy; approval is not a permanent capability grant.

Changing a pending action creates a new action and invalidates the old approval. Bounded autonomy
still requires approval for destructive, credential, identity, role, SSO/SCIM, billing, broad
external-write, and active-security actions outside an already authorized assessment scope.

## Budgets and Stop Conditions

Runs reserve and meter input/output tokens, estimated LLM cost, wall time, tool calls, task count,
parallelism, scanner time, and pipeline time. The supervisor receives remaining budget but cannot
raise it. When a hard limit is reached, undispatched tasks are cancelled and the run finalizes
with a partial, evidence-backed result and `budget_exhausted` reason.

Other deterministic stop reasons include objective satisfied, no valid next action, awaiting
approval, user cancellation, authorization expiry, deadline reached, provider unavailable, and
evidence insufficiency.

## Observability and Interface

The run UI shows the plan DAG, live task states, specialists, dependencies, evidence, approvals,
cost/tokens, degradations, decisions, retries, and final result. Users can cancel a run, reject or
approve actions, and retry only failed retryable tasks. WebSocket/GraphQL events use monotonically
increasing per-run sequence numbers so reconnects can resume without loss or duplication.

Metrics cover queue latency, execution latency, provider latency, task outcome, retry count,
approval wait, tokens, estimated spend, concurrency saturation, stale leases, recovery, and
evidence completeness.

## Acceptance Criteria

- One run executes at least three independent specialists concurrently and joins their typed
  results deterministically.
- Killing a worker during each task phase results in safe recovery without duplicated external
  mutation.
- A cancelled parent prevents new child dispatch and propagates cancellation to cancellable
  provider/scanner jobs.
- A task cannot call a tool outside the agent, user, organization, or run policy intersection.
- Approval is required and revalidated for material actions; identical re-delivery executes at
  most once.
- Tenant, run, provider, target-conflict, and deployment concurrency ceilings are enforced under
  load.
- Final output distinguishes completed, degraded, skipped, failed, rejected, and unverified work
  and cites durable evidence.

