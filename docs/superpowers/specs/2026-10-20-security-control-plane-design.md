# Security Control Plane Design

## Intent

Extend Cynux from exposure management into an evidence-backed security control plane without pretending to be a replacement for Zscaler's globally distributed proxy, ZTNA, or browser-isolation network.

## Product behavior

- Reconcile assets, SaaS applications, data stores, AI applications, models, agents, MCP servers, tools, identities, endpoints, and browsers into tenant-owned resources with source observations, confidence, freshness, ownership, and coverage gaps.
- Represent ZTNA, SWG, firewall, DLP, CASB, SSPM, AI-gateway, AI-guard, endpoint, and browser controls as policies that can evaluate resources and produce explainable recommendations.
- Apply a recommendation only through an enabled integration, an explicit authenticated operator action, idempotency, an audit record, and a durable provider receipt.
- Classify data posture without storing raw customer data. Persist classifications, sharing/access facts, hashes, redacted evidence, and remediation state.
- Inventory AI systems and enforce prompt/output policy through a synchronous decision API that detects prompt injection and sensitive data, redacts output, records hashes rather than raw content, and can require per-agent approval.
- Ingest experience, incident, identity, deception, access, DLP, and AI events; correlate deterministic threat stories across assets, identities, findings, and time.
- Register decoys/canaries and turn interactions into high-confidence security events.
- Quantify scenario risk using probability, loss distributions, control effectiveness, residual risk, acceptance state, and board-facing narratives.

## Architecture

One tenant-scoped control-plane domain owns resources, source observations, policies, evaluations, recommendations, normalized events, threat stories, deception objects, and risk simulations. Existing assets, business services, canonical findings, integrations, approvals, automation, audit, and agent workspaces remain authoritative and are linked rather than copied.

Policy evaluation is deterministic. LLMs may explain results but never decide enforcement. External policy changes are explicit operator-triggered writes routed through provider adapters and recorded with idempotency keys and provider receipts.

## Constraints

- PostgreSQL is authoritative; every row is organization-scoped.
- Raw prompts, outputs, secrets, data samples, session cookies, and provider response bodies are never persisted.
- Cross-tenant identifiers return not-found.
- External writes require `integration:manage`, an enabled verified connector, explicit apply, and an audit trail.
- Inline policy evaluation is bounded and does not call an LLM.
- ZTNA/SWG proxying, TLS interception, packet forwarding, and remote-browser rendering are out of scope; Cynux integrates and governs those enforcement planes.

