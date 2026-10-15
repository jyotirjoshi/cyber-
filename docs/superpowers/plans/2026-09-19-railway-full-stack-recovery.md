# Railway Full-Stack Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover and deploy the Cynux backend and frontend as connected Railway services.

**Architecture:** The API uses the root Dockerfile so its nested Python project is built deterministically. The frontend is a separate Railway service based on `frontend/`; environment variables connect browser HTTP/WebSocket calls to the public API service.

**Tech Stack:** Railway CLI, Docker, Python 3.12, FastAPI/Uvicorn/Alembic, Next.js 15.

**Spec:** `docs/superpowers/specs/2026-09-19-railway-full-stack-recovery-design.md`

## Global Constraints

- Retain all current Railway environment variables and database data.
- Do not expose or print secret values.
- Use `Dockerfile` for the backend; do not force Nixpacks for a nested Python manifest.
- Deploy the frontend and backend as separate Railway services.
- Confirm `/healthz` and frontend-to-API connectivity after deployment.

---

### Task 1: Make the backend Railway build deterministic

**Files:**
- Modify: `railway.toml`
- Modify: `Dockerfile`
- Test: local Docker build and `backend` unit suite

**Interfaces:**
- Consumes: Railway-provided `PORT` and configured `CYNUX_*` variables.
- Produces: An API image that runs `alembic upgrade head` then Uvicorn on `0.0.0.0:$PORT`.

- [ ] **Step 1: Write a failing deployment assertion**

Record that `railway.toml` selects Nixpacks while the Python package is in `backend/`, so a root Railway build cannot reliably discover the package.

- [ ] **Step 2: Verify the failure condition**

Run: `railway status`

Expected: The checkout is not linked and the existing config reports `builder = "nixpacks"`.

- [ ] **Step 3: Implement the minimal build correction**

Remove the Nixpacks builder directive from `railway.toml`, retain the health check and startup command, and update the Dockerfile to copy and execute `start_api.sh` consistently with the runtime paths it uses.

- [ ] **Step 4: Verify image and backend behavior**

Run: `docker build -t cynux-api:railway-recovery .` then `pytest -q` from `backend/`.

Expected: Docker build succeeds and backend tests pass.

### Task 2: Deploy and validate the API service

**Files:**
- Modify: Railway project metadata created by `railway link` (not committed)
- Test: Railway deployment logs and `GET /healthz`

**Interfaces:**
- Consumes: Existing `cynux-backend` Railway project, service secrets, and database.
- Produces: A public API domain responding successfully to `/healthz`.

- [ ] **Step 1: Link the checkout to the existing service**

Run: `railway link` and choose the `cynux-backend` project and API service.

- [ ] **Step 2: Inspect non-secret deployment configuration**

Run: `railway status`, `railway variables`, and `railway logs --lines 120`.

Expected: Confirm service selection and identify missing required variable *names* without printing their values.

- [ ] **Step 3: Deploy the verified API image**

Run: `railway up --detach` from the repository root.

- [ ] **Step 4: Verify the public API**

Run: `railway domain` followed by `curl.exe -fsS https://<api-domain>/healthz`.

Expected: Deployment logs show migrations and Uvicorn startup; health returns HTTP 200.

### Task 3: Deploy and connect the frontend service

**Files:**
- Create: `frontend/Dockerfile`
- Modify: `frontend/src/lib/api.ts`
- Test: `npm run typecheck`, `npm run build`, public frontend smoke test

**Interfaces:**
- Consumes: `NEXT_PUBLIC_API_BASE_URL` and `NEXT_PUBLIC_WS_BASE_URL` passed at frontend build time.
- Produces: A frontend whose browser API and WebSocket requests target the deployed Railway API, without a stale Render fallback.

- [ ] **Step 1: Write a failing configuration assertion**

Record that `frontend/src/lib/api.ts` defaults to `https://cynux-api.onrender.com`, which makes a Railway deployment call the obsolete host when build variables are absent.

- [ ] **Step 2: Verify the failure condition**

Run: `rg "onrender.com" frontend/src/lib/api.ts`.

Expected: The obsolete Render host is found in both HTTP and WebSocket fallback values.

- [ ] **Step 3: Implement the minimal frontend deployment contract**

Add a multi-stage `frontend/Dockerfile` that runs `npm ci`, builds standalone Next.js output, and starts `node server.js` on `$PORT`. Replace stale Render fallbacks with same-origin-safe configuration handling that fails loudly in production when build variables are missing.

- [ ] **Step 4: Verify frontend build behavior**

Run: `npm run typecheck` and `npm run build` from `frontend/` with Railway API URLs supplied.

Expected: Type checking and standalone build succeed.

- [ ] **Step 5: Create and configure the frontend Railway service**

Run: `railway add --service cynux-frontend` and set its root directory to `frontend`; set build-time public API/WS URLs to the API domain; add the frontend domain to `CYNUX_CORS_ORIGINS` on the API.

- [ ] **Step 6: Deploy and smoke-test the frontend**

Run: `railway up --service cynux-frontend --detach`, then request the frontend domain and inspect the browser's health/API request path.

Expected: The landing page returns HTTP 200 and browser calls target the Railway API domain.
