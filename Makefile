# Cynux — operator entrypoint. `make help` lists everything.
#
# Requires Docker + the Compose v2 plugin. On Windows run these from Git Bash
# (or run the underlying `docker compose ...` commands from the README directly).

COMPOSE ?= docker compose
PYTHON  ?= python

.DEFAULT_GOAL := help

.PHONY: help env secrets build up up-backend up-defectdojo defectdojo-up down down-v restart logs ps \
        migrate defectdojo-token shell-api shell-worker psql redis-cli \
        backend-gate clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from .env.example if it does not exist
	@if [ ! -f .env ]; then cp .env.example .env && echo "created .env — edit it, then run 'make secrets'"; else echo ".env already exists"; fi

secrets: ## Regenerate the CHANGE-ME secrets in .env in place (keeps your LLM key)
	$(PYTHON) docker/gen-secrets.py .env

build: ## Build the api/worker and frontend images
	$(COMPOSE) build

up: ## Start the core stack (postgres, redis, minio, api, worker, frontend)
	$(COMPOSE) up -d --build

up-backend: ## Start the backend only (data plane + api + worker, no frontend)
	$(COMPOSE) up -d --build postgres redis minio minio-init migrate api worker

up-defectdojo: ## Start the core stack plus the bundled DefectDojo
	$(COMPOSE) --profile defectdojo up -d --build

defectdojo-up: ## Start ONLY DefectDojo (do this before 'make defectdojo-token')
	$(COMPOSE) --profile defectdojo up -d \
		defectdojo-postgres defectdojo-redis defectdojo-initializer \
		defectdojo-uwsgi defectdojo-celeryworker defectdojo-celerybeat defectdojo-nginx

down: ## Stop the stack (keep volumes)
	$(COMPOSE) --profile defectdojo down

down-v: ## Stop the stack and delete all volumes (DESTRUCTIVE)
	$(COMPOSE) --profile defectdojo down -v

restart: ## Restart api and worker (after a code or .env change)
	$(COMPOSE) up -d --build api worker

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=100

ps: ## Show service status
	$(COMPOSE) --profile defectdojo ps

migrate: ## Run database migrations once (alembic upgrade head)
	$(COMPOSE) run --rm migrate

defectdojo-token: ## Mint a DefectDojo API token and write it into .env
	$(PYTHON) docker/defectdojo-token.py .env

shell-api: ## Open a shell in a throwaway api container
	$(COMPOSE) run --rm --no-deps api /bin/bash

shell-worker: ## Open a shell in a throwaway worker container (root)
	$(COMPOSE) run --rm --no-deps --user 0:0 worker /bin/bash

psql: ## Open psql against the Cynux database
	$(COMPOSE) exec postgres psql -U $${CYNUX_DB__USER:-cynux} -d $${CYNUX_DB__NAME:-cynux}

redis-cli: ## Open redis-cli
	$(COMPOSE) exec redis redis-cli

backend-gate: ## Run the offline backend gate (verify + ruff + mypy)
	cd backend && $(PYTHON) tools/verify.py && ruff check app && ruff format --check app && mypy app

clean: ## Remove built images and dangling build cache
	-$(COMPOSE) --profile defectdojo down
	-docker image rm cynux-backend:local cynux-frontend:local 2>/dev/null || true
