#!/usr/bin/env bash
# valet-start.sh — start the valet server inside a hotdesk desktop, or run a
# one-off valet CLI command with the same environment ("cli" subcommand).
set -euo pipefail

STATE=/home/cua/.valet
mkdir -p "$STATE"
chmod 700 "$STATE"

if [ ! -f "$STATE/master.key" ]; then
  (umask 077 && head -c 32 /dev/urandom | base64 -w0 > "$STATE/master.key")
fi

export VALET_MASTER_PASSWORD
VALET_MASTER_PASSWORD="$(cat "$STATE/master.key")"
export VALET_DB="$STATE/valet.db"
export VALET_CDP_URL="http://127.0.0.1:9222"
export VALET_LISTEN="127.0.0.1:14400"

if [ "${1:-}" = "cli" ]; then
  shift
  exec /usr/local/bin/valet "$@"
fi
exec /usr/local/bin/valet server
