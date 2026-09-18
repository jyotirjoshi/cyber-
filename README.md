# Cynux — AI-Powered Security Assessment Platform

> **God-tier cybersecurity AI.** Cynux is a full-stack, agentic security assessment platform that
> combines automated scanning, multi-source threat intelligence, SSVC triage, kill-chain attack
> path simulation, and adversarial-framing AI analysis into a single operator-controlled pipeline.

---

## What It Does

Cynux runs a deterministic, human-gated assessment pipeline driven by a LangGraph AI agent:

```
Understand → Plan → Recon → Discover Assets
    ↓ (human approval gate)
Execute Scanners → Import Findings → Enrich Intelligence
    ↓ (NEW)
Attack Path + SSVC + Correlation → AI Analysis → Prioritize
    ↓
Remediate → Create Actions → Generate Report
```

At every stage the operator sees exactly what the agent proposes, and nothing runs against a target
without an authorization record and a granted approval. The pipeline degrades gracefully when a
scanner fails or an intelligence provider is unreachable — it never reports "unknown" as safe.

---

## Architecture

```
frontend/          Next.js 15 (App Router, TypeScript, Tailwind)
backend/app/
  agent/           LangGraph pipeline (nodes, graph, prompts, state)
  api/             FastAPI REST + WebSocket
  db/              SQLAlchemy models + Alembic migrations
  integrations/    DefectDojo · NVD · CISA KEV · EPSS · MISP · Jira · Slack · MinIO
  llm/             Multi-provider gateway (Anthropic · OpenAI · Google)
  reporting/       Jinja2 HTML + WeasyPrint PDF reports
  scanners/        Nmap · Nuclei · ZAP · ReconFTW adapters (subprocess, no Docker)
  services/        Business logic layer
  worker/          Redis Streams consumer (crash-safe, checkpointed)
```

**Infrastructure (run natively — no Docker required):**
- PostgreSQL 16
- Redis 7
- MinIO (or real AWS S3)
- DefectDojo (vulnerability management source of truth)

---

## New Capabilities (September 2026)

### 1. Kill-Chain Attack Path Simulation

The new `attack_path` agent node runs after threat intelligence enrichment. It:

- **Generates up to 3 realistic multi-hop attack paths** from the most exploitable entry
  point to the highest-criticality crown jewel, grounded in actual scanner findings.
- **Identifies chokepoints** — the 1-2 remediations that break all discovered paths.
- **Quantifies blast radius** in business terms.
- Stores paths in `assessment.extra_data["attack_paths"]` for the report and dashboard.

```python
# backend/app/services/attack_path.py
paths = await generate_attack_paths(session, assessment, gateway=gateway, settings=settings)
# Returns: List[AttackPath] ordered by likelihood (high → low)
```

### 2. SSVC Triage (CISA Framework)

Every finding now gets an SSVC (Stakeholder-Specific Vulnerability Categorization) decision
stored in `finding.risk_factors["ssvc"]`:

| Outcome | Meaning |
|---------|---------|
| **ACT** | Immediate action — actively exploited, high impact |
| **ATTEND** | Address within 1 week |
| **TRACK★** | Monitor closely, ready to act |
| **TRACK** | Monitor, no immediate action needed |

SSVC is **fully deterministic** — the same enrichment data always produces the same outcome.
It weighs: exploitation evidence (KEV + EPSS), automatability (CVSS vector + CWE), technical
impact (scope change, confidentiality/integrity/availability), and mission prevalence
(asset criticality).

```python
# backend/app/services/ssvc.py
result = evaluate_ssvc(finding, enrichment)  # → SSVCResult(outcome=SSVCOutcome.ACT, ...)
```

### 3. Cross-Finding Correlation Engine

The correlation service detects three things scanners cannot:

- **False positives** — version-detection mismatches, WAF-protected endpoints, scanner artifacts
- **Duplicate groupings** — same weakness reported under different names by different scanners
- **Compound risks** — SSRF + IMDSv1 = cloud credential theft; two medium findings → critical chain

Phase 1 is deterministic (SHA-256 fingerprint on CWE + endpoint + asset). Phase 2 uses the AI
only for genuinely ambiguous cases, keeping token cost bounded.

### 4. Elite Adversarial Finding Analysis

The AI analysis prompt was upgraded from "explain this to a developer" to a senior red-team
operator's framing. Each finding analysis now includes:

| Field | Content |
|-------|---------|
| `explanation` | Root cause, not just symptom — why the code pattern creates the exposure |
| `business_impact` | Regulatory exposure, revenue risk, specific regulation (GDPR, PCI DSS, etc.) |
| `attack_scenario` | Concrete kill-chain: the exact request an attacker sends, the tool they use, where they land |
| `adversary_profile` | Nation-state / organized crime / opportunistic — grounded in KEV/EPSS evidence |
| `mitre_tactics` | ATT&CK tactic categories this finding directly enables |
| `detection_hint` | The specific SIEM query or log source that catches exploitation |

All fields are guarded by FR-024: every factual claim must cite a source from the evidence
block. Unsupported claims are replaced by "Unable to verify from available security intelligence."

### 5. Dashboard Upgrades

The dashboard now shows:

- **Risk Heat Map** — 5×5 likelihood × impact matrix built from severity and priority
- **SSVC Triage Strip** — counts of ACT / ATTEND / TRACK★ / TRACK across all findings  
- **Kill-Chain Panel** — attack paths from the most recent completed assessment
- **Severity/Priority progress bars** — proportional bars instead of plain counts

### 6. Report Upgrades

The PDF/HTML report now includes:

- **Attack Paths appendix** — each kill chain with steps, blast radius, chokepoints
- **Compound Risks appendix** — multi-finding attack chains
- **Coverage Gaps** — attack surface not covered by the configured scanners
- **SSVC badge** next to every finding's priority pill
- **Detection hint box** (technical audience) — the specific detection logic
- **Adversary profile** — threat actor context per finding

---

## Getting Started

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | ≥ 3.11 | Backend |
| Node.js | ≥ 22 | Frontend |
| PostgreSQL | 16 | Primary database |
| Redis | 7 | Job queue, pubsub, caching |
| MinIO *(optional)* | latest | Artifact storage (or use real S3) |
| DefectDojo *(optional)* | latest | Vulnerability management |

### 1. Environment

```bash
cp .env.example .env
# Fill in required secrets:
#   CYNUX_SECURITY__JWT_SECRET       (openssl rand -hex 32)
#   CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY  (python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
#   CYNUX_DB__PASSWORD
#   CYNUX_LLM__PROVIDER + API key
```

### 2. Install dependencies

```bash
# Backend
cd backend
pip install -e ".[dev]"

# Frontend
cd frontend
npm install
```

### 3. Database migrations

```bash
cd backend
alembic upgrade head
```

This runs all three migrations:
- `0001_initial_schema` — full schema
- `0002_assessment_metadata_ssvc` — `assessments.extra_data` (attack paths, compound risks)
- `0003_finding_elite_ai_fields` — `ai_adversary_profile`, `ai_mitre_tactics`, `ai_detection_hint`

### 4. Run

**Linux/macOS:**
```bash
bash start.sh
```

**Windows (PowerShell):**
```powershell
.\start.ps1
```

**Or start services individually:**
```bash
# Terminal 1 — API
cd backend && uvicorn --factory app.api.app:create_app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — Worker
cd backend && python -m app.worker

# Terminal 3 — Frontend
cd frontend && npm run dev
```

Open: http://localhost:3000

---

## Configuration Reference

### Required

| Variable | Description |
|----------|-------------|
| `CYNUX_SECURITY__JWT_SECRET` | JWT signing key, ≥ 32 chars |
| `CYNUX_SECURITY__CREDENTIAL_ENCRYPTION_KEY` | Fernet key for integration credentials |
| `CYNUX_DB__PASSWORD` | PostgreSQL password |
| `CYNUX_LLM__PROVIDER` | `anthropic` \| `openai` \| `google` |
| `CYNUX_LLM__ANTHROPIC_API_KEY` *(or openai/google)* | Provider API key |
| `CYNUX_LLM__DEFAULT_MODEL` | e.g. `claude-sonnet-4-5` |

### Scanner binaries (native mode)

Cynux runs scanners as local processes. Install the tools and optionally override paths:

```env
CYNUX_SCANNER__BIN_NMAP=nmap
CYNUX_SCANNER__BIN_NUCLEI=nuclei
CYNUX_SCANNER__BIN_ZAP=zap.sh
CYNUX_SCANNER__BIN_RECONFTW=reconftw.sh
```

Nmap and Nuclei work out of the box on Linux. On Windows, use WSL or adjust the binary paths.

### LLM roles

Each pipeline role can use a different model:

```env
CYNUX_LLM__DEFAULT_MODEL=claude-sonnet-4-5
CYNUX_LLM__ROLE_MODELS={"planning":"claude-haiku-4-5","code_remediation":"claude-opus-4-5"}
```

---

## Pipeline Deep Dive

### Agent Graph

```
START
  └─ understand          Parse objective, detect prompt injection
  └─ plan                Deterministic plan skeleton + AI rationale
  └─ recon               ReconFTW passive recon
  └─ discover_assets     Score + select assets for scanning
  └─ [route]
       ├─ (passive depth / no assets selected)
       │    └─ analyze_findings ──────────────────────────────────────┐
       └─ (active depth + assets selected)                            │
            └─ request_approval    ← human gate (FR-011)              │
            └─ execute_scanners    ← interrupt_before                 │
            └─ import_findings     DefectDojo import                  │
            └─ enrich_intelligence NVD + KEV + EPSS + MISP            │
            └─ attack_path  ← NEW  SSVC + paths + correlation         │
            └─ analyze_findings ◄──────────────────────────────────────┘
  └─ prioritize_findings  Deterministic risk score (0-100)
  └─ remediate_findings   Advisory fix guidance
  └─ create_actions       Jira tickets + Slack notifications
  └─ generate_report      HTML + PDF report
END
```

### Risk Scoring Formula

```
score = severity(45) + kev(20) + epss(12) + exposure(10) + criticality(10) + ransomware(3)
```

Bands: P1 ≥ 75 · P2 ≥ 55 · P3 ≥ 38 · P4 ≥ 18 · P5 < 18

### SSVC Decision Tree

```
Exploitation=Active + TechnicalImpact=Total           → ACT
Exploitation=Active + MissionPrevalence=Critical      → ACT
Exploitation=Active                                   → ATTEND
Exploitation=PoC + Auto=Yes + Impact=Total + Mission≥Support → ATTEND
Exploitation=None + Auto=Yes + Impact=Total + Mission=Critical → ATTEND
Exploitation=PoC                                      → TRACK*
Exploitation=None + Auto=Yes + Impact=Total           → TRACK*
(default)                                             → TRACK
```

---

## Security Design

| Requirement | Implementation |
|-------------|----------------|
| **No default provider** | `CYNUX_LLM__PROVIDER` has no default; startup fails without it |
| **Prompt injection** | Every untrusted value is fenced with `<<<UNTRUSTED label id=NONCE>>>` |
| **No hallucination** | FR-024: every factual claim requires a cited source; invented CVEs/CVSS raise `UnverifiableClaimError` |
| **Human approval gate** | `interrupt_before=["execute_scanners"]`; no scan runs without a granted `ScanApproval` row |
| **Tenant isolation** | Every query includes `organization_id` filter; cross-tenant IDs return 404 |
| **No secrets in logs** | `str(exc)` is never logged; only `type(exc).__name__` and `user_message` |
| **No auto-apply** | Remediation patches are stored, never applied; FR-034 enforces this architecturally |
| **Scanner sandbox** | Argv validated against `ARGV_SAFE` regex; no shell involved in subprocess execution |

---

## Development

```bash
# Lint + type check
cd backend
ruff check app && ruff format --check app && mypy app

# Tests
pytest --tb=short -q

# Full gate
python tools/verify.py && ruff check app && mypy app
```

```bash
# Frontend
cd frontend
npm run lint
npm run typecheck
```

---

## New Files Added

### Backend

| File | Purpose |
|------|---------|
| `app/services/ssvc.py` | CISA SSVC v2.0 deterministic triage |
| `app/services/attack_path.py` | Multi-hop kill-chain path generation |
| `app/services/correlation.py` | False positive detection + compound risk synthesis |
| `app/agent/nodes/attack_path.py` | Agent node wiring all three services |
| `app/llm/prompts_enhanced.py` | 8 elite-level security AI prompts |
| `alembic/versions/0002_*` | `assessments.extra_data` column |
| `alembic/versions/0003_*` | `findings.ai_adversary_profile/mitre_tactics/detection_hint` |

### Frontend

| File | Purpose |
|------|---------|
| `components/ui/RiskHeatmap.tsx` | 5×5 likelihood × impact heat map |
| `components/ui/AttackPathCard.tsx` | Kill-chain visualizer with chokepoints |
| `components/ui/SSVCBadge.tsx` | SSVC outcome badge + decision matrix |
| `app/(app)/dashboard/page.tsx` | Upgraded dashboard with all new panels |

---

## Credits & References

- [CISA SSVC v2.0](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%200.2.pdf) — triage framework
- [Spring et al. 2021](https://arxiv.org/abs/1904.04965) — SSVC research paper
- [FIRST EPSS](https://www.first.org/epss/) — exploit prediction scoring
- [MITRE ATT&CK](https://attack.mitre.org/) — adversary tactic taxonomy
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — known exploited vulnerabilities
- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) — vulnerability management
- [LangGraph](https://github.com/langchain-ai/langgraph) — agent state machine
- [Nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability scanner
- [Nmap](https://nmap.org/) — network scanner
- [OWASP ZAP](https://www.zaproxy.org/) — web app scanner
- [ReconFTW](https://github.com/six2dez/reconftw) — recon framework
