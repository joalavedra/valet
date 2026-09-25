#!/usr/bin/env bash
# valet-start.sh — start the valet server inside a hotdesk desktop, or run a
# one-off valet CLI command with the same environment ("cli" subcommand).
set -euo pipefail

STATE=/home/cua/.valet
mkdir -p "$STATE"
chmod 700 "$STATE"

cli_mode=0
if [ "${1:-}" = "cli" ]; then
  cli_mode=1
  shift
fi

if [ "$cli_mode" = "1" ]; then
  # CLI mode rides on the server-supervised state: wait up to 30s for the
  # server to have created master.key and to be serving /healthz.
  ready=0
  for _ in $(seq 1 60); do
    if [ -f "$STATE/master.key" ] && curl -fs http://127.0.0.1:14400/healthz >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.5
  done
  if [ "$ready" != "1" ]; then
    echo "valet server not ready" >&2
    exit 1
  fi
elif [ ! -f "$STATE/master.key" ]; then
  # Write to a temp file and mv -n so a racing second start can't clobber it.
  tmp="$STATE/.master.key.$$"
  (umask 077 && head -c 32 /dev/urandom | base64 -w0 > "$tmp")
  mv -n "$tmp" "$STATE/master.key" 2>/dev/null || rm -f "$tmp"
fi

export VALET_MASTER_PASSWORD
VALET_MASTER_PASSWORD="$(cat "$STATE/master.key")"
export VALET_DB="$STATE/valet.db"
export VALET_CDP_URL="http://127.0.0.1:9222"
export VALET_LISTEN="127.0.0.1:14400"

if [ "$cli_mode" = "1" ]; then
  exec /usr/local/bin/valet "$@"
fi
exec /usr/local/bin/valet server
