#!/usr/bin/env bash
# Cynux — Linux/macOS startup helper (no Docker required).
#
# Prerequisites:
#   - Python 3.11+  (pip install in backend)
#   - Node.js 22+   (npm install in frontend)
#   - PostgreSQL 16 running on localhost:5432
#   - Redis 7 running on localhost:6379
#   - MinIO (optional) running on localhost:9000  — or use real AWS S3
#
# Usage:  bash start.sh

set -euo pipefail

step() { echo -e "\n\033[36m==> $*\033[0m"; }

ROOT="$(cd "$(dirname "$0")" && pwd)"

# ── 1. Ensure .env exists ──────────────────────────────────────────────────
if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "Created .env from .env.example — fill in secrets before continuing."
  echo "Edit .env, then run this script again."
  exit 0
fi

# ── 2. Install Python deps ─────────────────────────────────────────────────
step "Installing Python dependencies"
cd "$ROOT/backend"
pip install -e ".[dev]"

# ── 3. Install Node deps ───────────────────────────────────────────────────
step "Installing frontend dependencies"
cd "$ROOT/frontend"
npm install

# ── 4. Run database migrations ─────────────────────────────────────────────
step "Running database migrations"
cd "$ROOT/backend"
alembic upgrade head

# ── 5. Launch services in background ─────────────────────────────────────
step "Starting API server (port 8000)"
cd "$ROOT/backend"
uvicorn --factory app.api.app:create_app --host 0.0.0.0 --port 8000 &
API_PID=$!

step "Starting worker"
python -m app.worker &
WORKER_PID=$!

step "Starting frontend dev server (port 3000)"
cd "$ROOT/frontend"
npm run dev &
FRONTEND_PID=$!

echo -e "\n\033[32mAll services started.\033[0m"
echo "  API:      http://localhost:8000"
echo "  Frontend: http://localhost:3000"
echo "  API docs: http://localhost:8000/docs"
echo ""
echo "PIDs: api=$API_PID  worker=$WORKER_PID  frontend=$FRONTEND_PID"
echo "Press Ctrl-C to stop all."

# Wait for any of the processes to exit
trap "kill $API_PID $WORKER_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
