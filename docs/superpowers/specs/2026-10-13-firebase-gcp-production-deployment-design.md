# Cynux Firebase/GCP Production Deployment Design

**Date:** 2026-10-13  
**Status:** Approved by user  
**Target:** New Firebase project owned by `nexrasecurity@gmail.com`

## Goals

- Publish the complete Cynux web product behind a Firebase-managed HTTPS origin.
- Preserve the FastAPI API, Next.js SSR frontend, WebSockets, background work, native/container scanners, and optional DefectDojo services.
- Use managed Google Cloud services for stateful production dependencies.
- Keep tenant data and credentials isolated from the existing unrelated Firebase projects.
- Establish predictable spending controls while the account uses its introductory credit.

## Chosen Architecture

Create a dedicated Firebase/Google Cloud project with a globally unique project ID derived from `cynux-security-prod`. Use `asia-south1` as the primary region and `asia-south1-a` as the initial compute zone where the product supports it.

Firebase Hosting is the public edge and TLS endpoint. It routes `/api/**`, `/ws/**`, and API documentation paths to the FastAPI Cloud Run service, and all remaining requests to the Next.js Cloud Run service. Both services use immutable images in Artifact Registry. Hosting pins deployed Cloud Run revisions so application and edge configuration roll back together.

The FastAPI service connects to Cloud SQL for PostgreSQL using the Cloud SQL connector and to Memorystore for Redis through Direct VPC egress. WebSocket clients reconnect on Cloud Run timeout; Redis carries shared state across API instances. Cloud Run has explicit minimum, maximum, concurrency, CPU, memory, timeout, health check, and service-account settings.

The existing worker requires scanner binaries and, for containerized tools, control of a Docker-compatible host runtime. It therefore runs on a hardened Compute Engine instance rather than Cloud Run. The worker uses the same application image, pulls jobs from private Redis, writes evidence to Cloud Storage, and reaches Cloud SQL privately. The VM has no public application ports and is managed through OS Login/IAP. A separate Compute Engine deployment hosts the optional DefectDojo stack so its resource demand and lifecycle do not interfere with scanner execution.

## Data and Secrets

- Cloud SQL PostgreSQL 16 is the system database, with automated backups, point-in-time recovery, deletion protection, private networking, and encrypted connections.
- Memorystore for Redis supplies streams, queues, locks, and WebSocket coordination on the private VPC.
- Cloud Storage replaces MinIO for evidence and report artifacts, with uniform bucket-level access, lifecycle rules, versioning where appropriate, and CORS restricted to the product origin.
- Secret Manager stores database credentials, JWT signing material, credential-encryption keys, DefectDojo credentials, and deployment-level provider configuration.
- Tenant BYOK integration and LLM credentials continue to use Cynux's encrypted credential model; provider keys are not baked into images or Firebase configuration.

## Identity and Network Boundaries

Use separate least-privilege service accounts for build, frontend, API, worker, and DefectDojo. Cloud Run ingress is reachable through Firebase Hosting; API authorization remains enforced by Cynux. Data services have no public endpoint. Direct VPC egress connects Cloud Run to private Redis and internal services. Firewall rules permit only the exact internal service flows. Artifact Registry and Secret Manager access is granted per runtime identity.

The scanner worker retains product target-policy enforcement. Cloud egress, concurrency, resource limits, and audit logging provide an additional boundary around active security tooling.

## Deployment Flow

1. Create a dedicated Firebase project and link the billing account containing the credit.
2. Set a billing budget and threshold alerts before provisioning billable resources.
3. Enable required APIs and create Artifact Registry, VPC/private service access, service accounts, and secrets.
4. Provision Cloud SQL, Memorystore, and Cloud Storage.
5. Build and push API/frontend images, run Alembic as a one-off Cloud Run Job, and deploy Cloud Run services.
6. Provision scanner and DefectDojo compute from reproducible startup configuration.
7. Configure Firebase Hosting rewrites and deploy the public site.
8. Validate health, authentication, database migration level, WebSockets, queue execution, object uploads, and scanner isolation before declaring the deployment ready.

## Failure Handling and Operations

Cloud Run revisions retain rollback capability. Database migrations run as an explicit pre-release job and must succeed before traffic moves. Failed worker jobs remain durable in Redis/application state and are observable through Cloud Logging. Compute instances restart managed services automatically and preserve only the minimum required persistent data; product evidence remains in Cloud Storage.

Monitoring covers API latency/errors, Cloud Run instances, Cloud SQL capacity/connections, Redis memory, worker queue depth, VM health, and failed jobs. Budget alerts fire at multiple thresholds; maximum Cloud Run instances and worker concurrency limit unexpected cost acceleration. Budget alerts are notifications, not hard spending caps.

## Deliberate Trade-offs

- Firebase Hosting is the public product surface, but the full application cannot run inside Firebase Hosting itself. Every Firebase project is also a Google Cloud project, so the backend remains within one project and billing boundary.
- A privileged scanner runtime is intentionally isolated on Compute Engine because Cloud Run cannot provide a host Docker socket.
- DefectDojo is separated from the main API and worker because it has its own PostgreSQL, Redis, web, and Celery topology.
- The first deployment uses production controls but conservative initial capacity. Scaling can be increased after observed load; the $300 credit is not treated as a permanent production budget.

