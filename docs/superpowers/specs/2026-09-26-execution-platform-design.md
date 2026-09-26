# Cynux execution platform design

## Intent and success criteria

Turn the deployed Cynux API from a read/write control plane into a working CTEM
execution platform. A signed-in organization with valid BYOK and integration credentials
must be able to start an authorized assessment, observe progress, retain artifacts,
receive normalized findings in DefectDojo, and receive actionable failure states when an
external dependency is unavailable. Chat remains a model-only, BYOK conversation and
must never claim that a scan or integration action was performed without durable evidence.

## Scope

This increment provisions the missing runtime dependencies for the existing assessment
code: a queue consumer, S3-compatible private artifact storage, a default DefectDojo
connection, and health/readiness checks. It does not run active scanners inside the API or
worker container. The existing adapters invoke native scanner binaries, which require a
dedicated runner image with an explicit network policy and target-authorization boundary;
Railway application containers are not the scanner isolation boundary.

## Architecture

```text
Vercel UI -> Railway API -> Postgres
                  |          ^
                  v          |
                Redis queue --+-- Railway worker
                                    |        |
                                    v        v
                              S3 artifacts  DefectDojo
                                    |
                                    v
                         isolated scanner runner (approved jobs only)
```

### API service

The existing `cynux-api` remains the only public application service. It handles
authentication, tenant authorization, integration configuration, assessment creation,
event replay, chat completions, and health endpoints. It never runs scans in its request
process.

### Worker service

A second Railway service, built from the same repository image, starts with
`sh start_worker.sh`. It consumes the existing Redis queue and uses the same Postgres,
Redis, credential-encryption, and public-runtime configuration as the API through
Railway reference variables. It has no public domain. Worker readiness must fail closed
when private storage or the default DefectDojo connection is unavailable.

### Artifact storage

An S3-compatible private storage service retains raw tool output and reports. The API and
worker use only internal networking and scoped access credentials. Buckets are private;
artifacts are exposed only through tenant-authorized application endpoints or short-lived
signed links. Storage configuration must survive restarts and be included in readiness.

### DefectDojo

The worker is configured with a server-side DefectDojo base URL and token for the existing
self-hosted DefectDojo deployment. Organization-specific integrations continue to take
precedence where the code already supports BYOK. Finding synchronization is retried with
bounded backoff, and an integration failure produces a visible assessment error rather
than silently reporting success.

### Scanner execution boundary

The current scanner adapters invoke native scanner binaries. They require a dedicated
runner image that contains the selected tools and can receive only authorized, approved job
payloads. The worker must use a narrow runner client instead of installing high-risk scanner
tools into an internet-facing API or generic Railway worker. The runner is reachable only
over private networking, validates job signatures/authorization, records artifact
references, and returns summarized results. This boundary is a prerequisite to calling a
scan workflow fully operational.

## Data and event flow

1. An authorized user creates an assessment and attests authority for the target.
2. The API creates the durable run and enqueues a Redis job.
3. The worker resolves the organization-scoped BYOK/integration settings, emits progress
   events, and requests only approved scanner jobs from the runner.
4. Scanner evidence is retained in private storage; summaries and normalized findings are
   persisted in Postgres.
5. Findings are synchronized to DefectDojo and displayed through the API/UI. Every
   terminal state emits `agent_complete` or a user-safe `agent_error` event.

## Failure handling

- Missing BYOK/provider credentials: chat or AI analysis returns an explicit configuration
  error without losing the user's message.
- Redis/Postgres/storage/DefectDojo unavailable: the worker fails readiness and jobs remain
  observable instead of being marked complete.
- Scanner runner unavailable: the affected job fails with a retryable, user-safe status;
  no finding or evidence is fabricated.
- Duplicate queue delivery: existing durable run IDs and idempotent integration writes are
  used to prevent duplicate execution.

## Security requirements

- All credentials remain encrypted at rest through the existing application mechanism and
  are never sent to browser clients or logs.
- The worker and storage use Railway private networking/reference variables; no storage or
  worker public domain is created.
- Active targets require existing authorization and approval gates. Private ranges remain
  blocked unless the configured policy explicitly permits them.
- Previously pasted credentials must be rotated before production acceptance testing.

## Verification

1. API and worker readiness report Postgres, Redis, storage, and DefectDojo availability.
2. A BYOK chat reply is persisted and displayed after a browser refresh.
3. A permitted assessment moves from queued to a visible terminal state, with a timeline
   event sequence and retained artifact reference.
4. A test finding appears in the configured DefectDojo product/engagement.
5. An unavailable runner or integration returns an explicit error and does not create a
   false success state.

## Explicit constraint

This spec does not label active scanner execution complete until an isolated runner exists
and passes the end-to-end authorized test. Provisioning a worker plus storage alone makes
the assessment orchestration executable, but it cannot safely replace the runner boundary.
