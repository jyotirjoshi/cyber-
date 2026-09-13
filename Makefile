# Cynux — native (no-Docker) development entrypoint. `make help` lists everything.
#
# Prerequisites:
#   * Python 3.11+  (cd backend && pip install -e ".[dev]")
#   * Node.js 22+   (cd frontend && npm install)
#   * PostgreSQL 16 running on localhost:5432
#   * Redis 7       running on localhost:6379
#   * MinIO (optional, for artifact storage) on localhost:9000
#
# Copy .env.example to .env and fill in secrets before running anything.

PYTHON  ?= python
NPM     ?= npm

.DEFAULT_GOAL := help

.PHONY: help env secrets install install-backend install-frontend \
        migrate api worker frontend dev \
        lint typecheck test backend-gate clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Setup ──────────────────────────────────────────────────────────────────

env: ## Create .env from .env.example if it does not exist
	@if [ ! -f .env ]; then cp .env.example .env && echo "created .env — edit it and fill in secrets"; else echo ".env already exists"; fi

secrets: ## Regenerate the CHANGE-ME secrets in .env in place (keeps your LLM key)
	$(PYTHON) docker/gen-secrets.py .env

install: install-backend install-frontend ## Install all dependencies

install-backend: ## Install Python dependencies (editable, with dev extras)
	cd backend && pip install -e ".[dev]"

install-frontend: ## Install Node dependencies
	cd frontend && $(NPM) install

# ── Database ───────────────────────────────────────────────────────────────

migrate: ## Run database migrations (alembic upgrade head)
	cd backend && alembic upgrade head

# ── Run services (each in its own terminal) ────────────────────────────────

api: ## Start the FastAPI server on :8000
	cd backend && uvicorn --factory app.api.app:create_app --host 0.0.0.0 --port 8000 --reload

worker: ## Start the background worker
	cd backend && $(PYTHON) -m app.worker

frontend: ## Start the Next.js dev server on :3000
	cd frontend && $(NPM) run dev

# ── Code quality ───────────────────────────────────────────────────────────

lint: ## Run ruff linter + formatter check
	cd backend && ruff check app && ruff format --check app

typecheck: ## Run mypy type checks
	cd backend && mypy app

test: ## Run pytest (single pass, no watch)
	cd backend && pytest --tb=short -q

backend-gate: ## Run the full offline gate (verify + ruff + mypy)
	cd backend && $(PYTHON) tools/verify.py && ruff check app && ruff format --check app && mypy app

# ── Misc ───────────────────────────────────────────────────────────────────

clean: ## Remove Python bytecode, build artefacts and Next.js cache
	find backend -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find backend -name "*.pyc" -delete 2>/dev/null || true
	rm -rf backend/.mypy_cache backend/dist backend/cynux_backend.egg-info
	rm -rf frontend/.next frontend/node_modules/.cache
