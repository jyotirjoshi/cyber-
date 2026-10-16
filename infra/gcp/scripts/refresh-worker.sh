#!/usr/bin/env bash
set -euo pipefail

METADATA_ROOT='http://metadata.google.internal/computeMetadata/v1'
METADATA_HEADER='Metadata-Flavor: Google'
ENV_FILE='/etc/cynux/worker.env'
SERVICE_DROP_IN='/etc/systemd/system/cynux-worker.service.d/10-cynux-release.conf'

metadata() {
  curl -fsS -H "$METADATA_HEADER" "$METADATA_ROOT/instance/attributes/$1"
}

backend_image="$(metadata cynux-backend-image)"
multi_agent_enabled="$(metadata cynux-multi-agent-enabled)"
multi_agent_canary_org_ids="$(metadata cynux-multi-agent-canary-org-ids)"
worker_concurrency="$(metadata cynux-multi-agent-worker-concurrency)"
provider_parallelism="$(metadata cynux-multi-agent-provider-parallelism)"

if [[ "$backend_image" != *-docker.pkg.dev/*/cynux/api:* ]]; then
  echo "Invalid Cynux backend image in instance metadata." >&2
  exit 1
fi
if [[ ! "$multi_agent_enabled" =~ ^(true|false)$ ]]; then
  echo "Invalid multi-agent feature flag in instance metadata." >&2
  exit 1
fi
if [[ ! "$worker_concurrency" =~ ^([1-9]|1[0-6])$ ]]; then
  echo "Invalid worker concurrency in instance metadata." >&2
  exit 1
fi

tmp_env="$(mktemp)"
trap 'rm -f "$tmp_env"' EXIT
awk '!/^(CYNUX_FEATURES__MULTI_AGENT|CYNUX_FEATURES__MULTI_AGENT_CANARY_ORG_IDS|CYNUX_AGENT__WORKER_MAX_CONCURRENCY|CYNUX_AGENT__PROVIDER_MAX_PARALLEL_TASKS)=/' "$ENV_FILE" > "$tmp_env"
{
  printf 'CYNUX_FEATURES__MULTI_AGENT=%s\n' "$multi_agent_enabled"
  printf 'CYNUX_FEATURES__MULTI_AGENT_CANARY_ORG_IDS=%s\n' "$multi_agent_canary_org_ids"
  printf 'CYNUX_AGENT__WORKER_MAX_CONCURRENCY=%s\n' "$worker_concurrency"
  printf 'CYNUX_AGENT__PROVIDER_MAX_PARALLEL_TASKS=%s\n' "$provider_parallelism"
} >> "$tmp_env"
install -o root -g root -m 0600 "$tmp_env" "$ENV_FILE"

region="${backend_image%%-docker.pkg.dev/*}"
access_token="$(curl -fsS -H "$METADATA_HEADER" "$METADATA_ROOT/instance/service-accounts/default/token" | jq -r .access_token)"
printf '%s' "$access_token" | docker login -u oauth2accesstoken --password-stdin "https://$region-docker.pkg.dev"
docker pull "$backend_image"

install -d -o root -g root -m 0755 "$(dirname "$SERVICE_DROP_IN")"
cat > "$SERVICE_DROP_IN" <<UNIT
[Service]
ExecStart=
ExecStart=/usr/bin/docker run --name cynux-worker --rm --user 0:0 --env-file /etc/cynux/worker.env --network bridge -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/cynux/artifacts:/var/lib/cynux/artifacts $backend_image python -m app.worker
UNIT
chmod 0644 "$SERVICE_DROP_IN"

systemctl daemon-reload
systemctl restart cynux-worker.service
systemctl is-active --quiet cynux-worker.service
docker image prune -f --filter 'until=168h' >/dev/null
