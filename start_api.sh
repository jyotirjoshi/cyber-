#!/bin/sh
# Railway entrypoint — run migrations then start the API server.
set -e

# Find python executable
PYTHON=$(which python3 || which python)
echo "[cynux] Python: $PYTHON"
echo "[cynux] PATH: $PATH"
$PYTHON --version

# Find where pip installed the scripts
SCRIPTS=$($PYTHON -c "import sysconfig; print(sysconfig.get_path('scripts'))")
echo "[cynux] Scripts dir: $SCRIPTS"
export PATH="$SCRIPTS:$PATH"

# Run migrations
echo "[cynux] Running database migrations..."
$PYTHON -m alembic -c backend/alembic.ini upgrade head

# Start server
echo "[cynux] Starting API server on port ${PORT:-8000}..."
exec $PYTHON -m uvicorn app.api.app:create_app \
  --factory \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers 2 \
  --app-dir backend
