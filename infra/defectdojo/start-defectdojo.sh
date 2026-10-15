#!/bin/bash
set -euo pipefail

# complete_initialization is idempotent: it applies migrations and only creates
# the administrator during the first boot.
/entrypoint-initializer.sh /bin/true

pids=()

/entrypoint-celery-worker.sh &
pids+=("$!")

/entrypoint-celery-beat.sh &
pids+=("$!")

/entrypoint-uwsgi.sh &
pids+=("$!")

shutdown() {
  kill -TERM "${pids[@]}" 2>/dev/null || true
  wait "${pids[@]}" 2>/dev/null || true
}

trap 'shutdown; exit 0' TERM INT

set +e
wait -n "${pids[@]}"
status=$?
set -e

shutdown
exit "$status"
