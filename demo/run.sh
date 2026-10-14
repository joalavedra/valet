#!/usr/bin/env bash
# Bring up the Valet agent-commerce demo behind a public Cloudflare tunnel.
# The tunnel URL becomes DEMO_PUBLIC_URL; VALET_PUBLIC_URL is <URL>/valet so the
# phone can reach /capture/<token> and Collect.js through the demo's proxy.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] && set -a && . ./.env && set +a

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared not found. Install: https://github.com/cloudflare/cloudflared/releases" >&2
  exit 1
fi

LOG=$(mktemp /tmp/cloudflared.XXXX.log)
cloudflared tunnel --url http://localhost:8080 --no-autoupdate >"$LOG" 2>&1 &
CF_PID=$!
trap 'kill $CF_PID 2>/dev/null || true' EXIT

echo "waiting for tunnel URL…"
URL=""
for i in $(seq 1 30); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG" | head -1 || true)
  [ -n "$URL" ] && break
  sleep 1
done
if [ -z "$URL" ]; then
  echo "no tunnel URL; cloudflared log:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

export DEMO_PUBLIC_URL="$URL"
export VALET_PUBLIC_URL="$URL/valet"

# Passkeys are bound to the tunnel hostname (the WebAuthn RP ID) while
# valet-data persists across runs — remember this run's host so a changed
# one can be detected next time.
OLD_URL="${DEMO_LAST_PUBLIC_URL:-}"
touch .env
{ grep -v '^DEMO_LAST_PUBLIC_URL=' .env || true; echo "DEMO_LAST_PUBLIC_URL=$URL"; } > .env.tmp && mv .env.tmp .env

# Generate secrets once and persist them in .env — the compose DB survives
# relaunches, so re-generating the master password would break decryption.
persist() { # NAME=value → export + append to .env if unset
  local name="$1" value="$2"
  if [ -z "${!name:-}" ]; then
    export "$name=$value"
    grep -q "^$name=" .env || echo "$name=$value" >> .env
  fi
}
persist VALET_MASTER_PASSWORD "valet-demo-master-$(date +%s | sha256sum | cut -c1-16)"
persist VALET_OWNER_TOKEN "vlt_owner_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
persist DEMO_PASSWORD "$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# If the tunnel host changed and passkeys exist, they can never match the
# new RP ID — approvals would 403 forever. Runs whenever the host differs,
# including the first run after upgrade (OLD_URL empty), but only when a
# valet-data volume already exists — a fresh clone has nothing to warn
# about and shouldn't build an image just for the check. Best-effort.
if [ "$OLD_URL" != "$URL" ] && docker volume inspect "$(basename "$PWD")_valet-data" >/dev/null 2>&1; then
  docker compose build -q valet-init >/dev/null 2>&1 || true # ensure the init image has the passkey CLI
  PKJSON=$(docker compose run --rm --no-deps -T --entrypoint /valet -e VALET_DB=/data/valet.db valet-init passkey list --json 2>/dev/null || true)
  if [ -n "$PKJSON" ] && [ "$PKJSON" != "[]" ]; then
    echo "warning: passkeys were enrolled at ${OLD_URL:-a previous hostname}; they will not work at $URL and approvals will be stuck" >&2
    if [ -t 0 ]; then
      read -r -p "Remove them now? [y/N] " ans || ans=""
      if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
        docker compose run --rm --no-deps -T --entrypoint /valet -e VALET_DB=/data/valet.db valet-init passkey reset --yes || true
      fi
    else
      echo "  to remove: docker compose run --rm --no-deps -T --entrypoint /valet -e VALET_DB=/data/valet.db valet-init passkey reset --yes" >&2
    fi
  fi
fi

if [ -n "${VGS_CLIENT_ID:-}" ] && [ -n "${VGS_CLIENT_SECRET:-}" ] && [ -n "${VGS_VAULT_ID:-}" ]; then
  DEMO_PUBLIC_URL="$URL" ./vgs-route.sh || echo "warning: vgs-route.sh failed — purchases will be declined" >&2
else
  echo "warning: VGS_* not set — skipping reveal route; purchases will fail" >&2
fi

echo "DEMO_PUBLIC_URL=$DEMO_PUBLIC_URL"
echo "login: demo / $DEMO_PASSWORD"
echo "VALET_PUBLIC_URL=$VALET_PUBLIC_URL"

docker compose up --build
