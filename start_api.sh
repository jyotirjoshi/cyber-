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

# A Docker image installs the package and copies Alembic files to /app.  The
# source-tree fallback keeps this entrypoint usable with Railway's earlier build.
if [ -f "alembic.ini" ]; then
  ALEMBIC_CONFIG="alembic.ini"
  APP_DIR=""
else
  ALEMBIC_CONFIG="backend/alembic.ini"
  APP_DIR="--app-dir backend"
fi

# Run migrations
echo "[cynux] Running database migrations..."
MIGRATION_ATTEMPT=1
MIGRATION_MAX_ATTEMPTS=12
until $PYTHON -m alembic -c "$ALEMBIC_CONFIG" upgrade head; do
  if [ "$MIGRATION_ATTEMPT" -ge "$MIGRATION_MAX_ATTEMPTS" ]; then
    echo "[cynux] Database migrations failed after ${MIGRATION_ATTEMPT} attempts."
    exit 1
  fi
  echo "[cynux] Database is not ready; retrying migrations in 5 seconds (attempt ${MIGRATION_ATTEMPT}/${MIGRATION_MAX_ATTEMPTS})..."
  sleep 5
  MIGRATION_ATTEMPT=$((MIGRATION_ATTEMPT + 1))
done

# Start server
echo "[cynux] Starting API server on port ${PORT:-8000}..."
exec $PYTHON -m uvicorn app.api.app:create_app \
  --factory \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers 2 \
  $APP_DIR
