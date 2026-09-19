#!/bin/sh
# Background worker entrypoint. The API service owns migrations; this process
# only consumes approved assessment runs from the shared Redis stream.
set -e

PYTHON=$(which python3 || which python)
echo "[cynux] Starting assessment worker with $PYTHON"
exec "$PYTHON" -m app.worker
