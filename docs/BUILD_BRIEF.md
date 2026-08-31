# Cynux build brief — read this before writing a single line

You are one of several agents building Cynux concurrently. This file is the shared
briefing. `docs/INTERFACES.md` is the **normative** contract; this file tells you how to
work inside it without colliding with the other agents.

---

## 0. Non-negotiables

1. **`docs/INTERFACES.md` §1 (Conventions) and §2 (File ownership) are mandatory.** Read
   both, in full, before writing anything.
2. **Do not edit a file you do not own.** Your prompt names your files. If you need a
   change in someone else's file, put it in your final report instead of making it.
   Silently editing a shared file will be reverted and your work will be redone.
3. **Never modify a frozen file.** See §2 below.
4. **Your own files must pass the gate.** See §4 below.

---

## 1. What Cynux is

An AI-powered security assessment platform. A user states an objective in natural
language ("assess our staging environment"); a LangGraph agent interprets it, plans,
runs passive recon, discovers assets, **stops for human approval**, runs scanners in
locked-down Docker sandboxes, pushes results into DefectDojo, enriches them with public
threat intelligence, analyses and prioritises them, and produces a report.

Product principles that decide arguments:

- **P1** Do not reinvent security infrastructure. DefectDojo owns vulnerabilities. Nmap,
  Nuclei, ZAP, ReconFTW do the scanning. NVD/KEV/EPSS supply intelligence.
- **P2** The AI controls orchestration, not truth. Every factual security claim is
  traceable to a source.
- **P3** Risky actions need human approval.
- **P4** Everything is auditable.
- **P5** Security tools run in isolation.
- **P6** Assessments are asynchronous.
- **P7** Provider independence — no hardcoded LLM vendor, and **no default provider**.
  Cynux refuses to guess (`NoLLMProviderError`).

Security requirements you will be judged against:

- **SEC-002** No secret in source, logs, LLM prompts, or user-facing errors. Ever.
- **SEC-003** Tenant isolation. A cross-tenant read is a **404**, never a 403 — see
  `TenantIsolationError`. Query through `tenant_select` / `TenantRepository`, never a
  bare `select(Model)`.
- **SEC-005** Untrusted content (scanner output, page titles, finding descriptions) is
  fenced with `app.llm.prompts.wrap_untrusted` before it reaches a prompt.
- **SEC-006** The LLM never receives raw scanner logs or DefectDojo dumps. Parse, filter
  and summarise first; truncate through `app/llm/budget.py`.
- **FR-020** A provider outage records `EnrichmentStatus.UNAVAILABLE`. It **never**
  records a negative result. "Not in KEV" and "we could not reach KEV" are different
  answers, which is why `in_kev` is `bool | None`.
- **FR-024** Every factual claim carries a source id. When a claim cannot be supported,
  the exact string is `Unable to verify from available security intelligence.`
  (`app.llm.guard.UNVERIFIABLE_STATEMENT`).
- **FR-032** An audit row for: auth events *including failures*, assessment
  create/approve/cancel, scanner start/stop, integration config change, finding status
  change, ticket creation, report generation, permission denials, and **every** agent
  tool invocation.

---

## 2. Frozen files — read them, import them, never change them

```
app/core/config.py        app/core/errors.py       app/core/targets.py
app/core/security.py      app/core/crypto.py       app/core/redis_client.py
app/core/logging_conf.py  app/core/telemetry.py
app/db/base.py            app/db/enums.py          app/db/session.py
app/db/repository.py      app/db/models/*.py
tools/verify.py           pyproject.toml           alembic/env.py    alembic.ini
alembic/versions/0001_initial_schema.py
```

Already built and equally off-limits unless your prompt says otherwise — treat as
read-only inputs whose signatures you must match exactly:

```
app/schemas/*.py          app/llm/*.py             app/integrations/*.py
app/scanners/*.py
app/services/{audit,context,events,progress,organization,assessment,approval,
               asset,job,enrichment,finding,auth}.py
tests/conftest.py
```

If a frozen file seems wrong, say so in your report. Do not work around it by editing it.

---

## 3. Conventions, condensed

These are already followed by ~90 existing modules. Match them or your file will look
foreign.

- **Module docstring** naming the FR it implements and, more importantly, *why* the
  design is the way it is. Record the decisions a reader would otherwise re-litigate.
  Look at `app/services/finding.py` or `app/services/job.py` for the register.
- `from __future__ import annotations` is always the first statement after the docstring.
- **Import from leaf modules, never from a package `__init__`.** `from app.db.enums
  import Severity`, not `from app.db import Severity`.
- Package `__init__.py` files stay **docstring-only**. The single exception that already
  exists is `app/db/models/__init__.py`.
- Every module ends with a **sorted** `__all__`.
- PEP 604 typing (`str | None`). Public functions fully annotated.
- **Never raise bare `Exception` / `ValueError` / `RuntimeError` across a module
  boundary.** Use the taxonomy in `app/core/errors.py`. A bare raise inside one function
  that the same module catches is fine.
- `log = structlog.get_logger(__name__)`. Structured kwargs, never f-strings:
  `log.info("job.started", job_id=str(job.id))`. Never log a secret.
- Async everywhere for I/O. Blocking libraries go through
  `await asyncio.to_thread(...)`.
- ORM relationships are `lazy="raise_on_sql"` (`app.db.base.LAZY`). **Eager-load
  explicitly** with `selectinload`. Do **not** switch a relationship to `selectin` to
  make an error go away — the error is telling you a query is missing a load option.
  Note the corollary: any helper that touches a relationship silently imposes an
  eager-load requirement on all of its callers.
- Tenancy through `tenant_select(Model, organization_id, *options)` or
  `TenantRepository`.
- Service functions are **verbs**: `create_assessment`, not `assessment_create`.
- Services do **not** commit. The caller owns the transaction. (Exception: audit's
  `record_independently`, which deliberately uses its own.)
- Comments are sparse and load-bearing. Explain *why*, never *what*. No section banners
  full of nothing.

Two traps that have already cost time:

- `app/db/base.py` maps `list[str] → JSONB`, **not** a Postgres `ARRAY`. So
  `Finding.cve_ids.any("CVE-…")` is invalid; use
  `Finding.cve_ids.contains(["CVE-…"])`.
- `AuditOutcome` has exactly three members: `SUCCESS`, `FAILURE`, `DENIED`. There is no
  `SKIPPED`. A skipped-but-correct operation is `SUCCESS` with a `reason` and
  `detail={"skipped": True}`.

---

## 4. The gate

Other agents are writing other files **at the same time as you**. That changes how you
verify.

Run this after every file you write, from `backend/`:

```bash
ruff format app/<your_file>.py && ruff check --fix app/<your_file>.py && python -m mypy app/<your_file>.py
```

Then confirm it actually imports:

```bash
python -c "import app.<your.module>"
```

`python tools/verify.py` parses and imports **every** module in the tree. It is the
authoritative gate, but while other agents are mid-write it may report errors in files
you do not own. **Fix only errors in your own files.** Report any error you see in
someone else's file; do not touch it.

`tools/verify.py` only parses and imports. It cannot catch a malformed SQL construct or
a miscalibrated constant. If you write non-trivial query or scoring logic, prove it
separately — compile statements against `postgresql.dialect()`, or exercise pure
functions against synthetic inputs. This has caught real defects that ruff and mypy
missed.

---

## 5. Your report

When you finish, report:

1. Files created, with line counts.
2. Gate status per file — the actual command output, not a claim.
3. **Any change you need in a file you do not own**, with the exact reason.
4. Anything in `INTERFACES.md` you found ambiguous and how you resolved it.
5. Anything you deliberately left undone, and why.

Do not report success unless the commands in §4 actually passed. If something is broken
and you cannot fix it inside your ownership boundary, say so plainly — that is far more
useful than a green claim that falls over in the next agent's build.
