#!/usr/bin/env bash
# login-demo: fill the-internet.herokuapp.com/login via Valet's browser edge.
set -euo pipefail

cd "$(dirname "$0")/../.."
VALET=${VALET_BIN:-./valet}
export VALET_MASTER_PASSWORD=${VALET_MASTER_PASSWORD:-demo-password}
DB=${VALET_DB:-/tmp/valet-demo.db}
SITE=the-internet.herokuapp.com
DEBUG_PORT=9222
CHROME=${CHROME:-google-chrome}

cleanup() {
  [ -n "${CHROME_PID:-}" ] && kill "$CHROME_PID" 2>/dev/null || true
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -f "$DB"

"$VALET" server --db "$DB" &
SERVER_PID=$!
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:14400/healthz >/dev/null && break
  sleep 0.3
done

# Store the login credential; secrets go via stdin, never argv.
printf 'tomsmith\nSuperSecretPassword!\nJBSWY3DPEHPK3PXP\n' | \
  "$VALET" cred add --db "$DB" --type login --label demo --site "$SITE"
"$VALET" cred list --db "$DB"

TOKEN=$("$VALET" agent create --db "$DB" demo-agent)
echo "agent token: ${TOKEN:0:12}…"

"$CHROME" --headless=new --disable-gpu --no-sandbox \
  --remote-debugging-port=$DEBUG_PORT --user-data-dir=/tmp/valet-demo-profile \
  "https://$SITE/login" \
  >/tmp/valet-demo-chrome.log 2>&1 &
CHROME_PID=$!
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:$DEBUG_PORT/json >/dev/null && break
  sleep 0.5
done
WS=$(curl -s http://127.0.0.1:$DEBUG_PORT/json/version | grep -o '"webSocketDebuggerUrl": *"[^"]*"' | head -1 | cut -d'"' -f4)
echo "cdp ws: $WS"

GRANT=$(curl -sf -X POST http://127.0.0.1:14400/v1/grants \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"handle\":\"cred://$SITE/demo\",\"policy\":{\"hosts\":[\"$SITE\"]},\"ttl\":600}" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "grant: ${GRANT:0:20}…"

curl -s -X POST http://127.0.0.1:14400/v1/edge/browser/fill \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"grant_token\":\"$GRANT\",\"cdp_ws_url\":\"$WS\",\"mapping\":{\"username\":\"#username\",\"password\":\"#password\"},\"submit\":\"button[type=submit]\"}"
echo

curl -s http://127.0.0.1:14400/v1/audit -H "Authorization: Bearer $VALET_MASTER_PASSWORD"
echo
