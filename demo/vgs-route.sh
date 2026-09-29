#!/usr/bin/env bash
# Create/update the VGS outbound route that reveals card aliases for the demo
# store's /store/checkout endpoint (REQUEST ENRICH JSON_PATH on $.card.number
# and $.card.cvc). Idempotent by route name "valet-demo-store".
# Env: VGS_CLIENT_ID, VGS_CLIENT_SECRET (service account OAuth2),
#      VGS_VAULT_ID (tnt… vault alias), DEMO_PUBLIC_URL (or $1).
set -euo pipefail

PUBLIC_URL="${1:-${DEMO_PUBLIC_URL:?set DEMO_PUBLIC_URL or pass it as \$1}}"
HOST=$(echo "$PUBLIC_URL" | sed -E 's#^https?://([^/]+).*#\1#')
: "${VGS_CLIENT_ID:?}" "${VGS_CLIENT_SECRET:?}" "${VGS_VAULT_ID:?}"
NAME="valet-demo-store"
API="https://api.sandbox.verygoodsecurity.com"

TOK=$(curl -fsS -X POST https://auth.verygoodsecurity.com/auth/realms/vgs/protocol/openid-connect/token \
  -d "grant_type=client_credentials&client_id=$VGS_CLIENT_ID&client_secret=$VGS_CLIENT_SECRET" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

# JSON:API rule-chain for an outbound ENRICH reveal, mirrors
# deploy/vgs/routes/httpbin-echo.yaml.
PAYLOAD=$(python3 - "$HOST" <<'EOF'
import json, sys
host = sys.argv[1]
print(json.dumps({"data": {
  "type": "rule_chain",
  "attributes": {
    "tags": {"name": "valet-demo-store", "source": "RouteService"},
    "destination_override_endpoint": "https://" + host,
    "host_endpoint": host,
    "port": 443,
    "protocol": "http",
    "source_endpoint": "*",
    "entries": [{
      "phase": "REQUEST",
      "operation": "ENRICH",
      "token_manager": "PERSISTENT",
      "public_token_generator": "UUID",
      "transformer": "JSON_PATH",
      "transformer_config": ["$.card.number", "$.card.cvc"],
      "targets": ["body"],
      "classifiers": {},
      "config": {
        "condition": "AND",
        "rules": [
          {"expression": {"field": "PathInfo", "type": "string",
                          "operator": "matches", "values": ["/store/checkout"]}},
          {"expression": {"field": "ContentType", "type": "string",
                          "operator": "equals", "values": ["application/json"]}}
        ]
      }
    }]
  }
}}))
EOF
)

AUTHZ=(-H "Authorization: Bearer $TOK" -H "VGS-Tenant: $VGS_VAULT_ID" -H 'Content-Type: application/vnd.api+json')
LIST=$(curl -fsS "${AUTHZ[@]}" "$API/rule-chains")
ID=$(printf '%s' "$LIST" | python3 -c "import json,sys
for r in json.load(sys.stdin).get('data',[]):
    t=(r.get('attributes',{}).get('tags') or {})
    if t.get('name')=='$NAME': print(r['id']); break")

if [ -n "$ID" ]; then
  curl -fsS "${AUTHZ[@]}" -X PUT "$API/rule-chains/$ID" --data-binary "$PAYLOAD" >/dev/null
  echo "updated outbound route $NAME ($ID) -> $HOST /store/checkout"
else
  curl -fsS "${AUTHZ[@]}" -X POST "$API/rule-chains" --data-binary "$PAYLOAD" >/dev/null
  echo "created outbound route $NAME -> $HOST /store/checkout"
fi
