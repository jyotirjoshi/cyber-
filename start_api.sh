#!/bin/sh
# Railway entrypoint — run migrations then start the API server.
# Uses `python -m` so the installed venv path is not needed.
set -e

echo "[cynux] Running database migrations..."
python -m alembic -c backend/alembic.ini upgrade head

echo "[cynux] Starting API server on port ${PORT:-8000}..."
exec python -m uvicorn app.api.app:create_app \
  --factory \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers 2 \
  --app-dir backend
