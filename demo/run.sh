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

# Generate secrets once and persist them in .env — the compose DB survives
# relaunches, so re-generating the master password would break decryption.
touch .env
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

if [ -n "${VGS_CLIENT_ID:-}" ] && [ -n "${VGS_CLIENT_SECRET:-}" ] && [ -n "${VGS_VAULT_ID:-}" ]; then
  DEMO_PUBLIC_URL="$URL" ./vgs-route.sh || echo "warning: vgs-route.sh failed — purchases will be declined" >&2
else
  echo "warning: VGS_* not set — skipping reveal route; purchases will fail" >&2
fi

echo "DEMO_PUBLIC_URL=$DEMO_PUBLIC_URL"
echo "login: demo / $DEMO_PASSWORD"
echo "VALET_PUBLIC_URL=$VALET_PUBLIC_URL"

docker compose up --build
