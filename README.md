# Valet

> Agents get **handles**, never secrets. Valet holds a user's logins, API keys and cards, and swaps the real values in **at the edge** (HTTP egress proxy, browser field, or card-vault outbound route) — so no LLM, prompt, log or agent process ever sees a password or a PAN.

**Status: pre-alpha.** Design doc: [docs/DESIGN.md](docs/DESIGN.md).

## Demo

A Gemini shopping agent buys from a demo store with a card it never sees — VGS-vaulted card, human approval on the phone, PAN swapped in only on the outbound request.

![Valet demo: chat → approval → receipt](docs/media/demo-checkout.webp)

Run it yourself: [demo/README.md](demo/README.md).

## Architecture

```
                 ┌────────────────────────── Agent side ──────────────────────────┐
                 │  LLM / agent framework  ──MCP──▶  valet-mcp (tools:          │
                 │  sees only handles               list_handles, request_grant,  │
                 │                                  http_call, browser_fill,      │
                 │                                  pay)                          │
                 └────────────────────────────────┬───────────────────────────────┘
                                                  │ grant token + handle
┌─────────────────────────────────── Valet (self-hosted) ────────────────────────┐
│                                                  ▼                              │
│   ┌──────────────┐   ┌──────────────┐   ┌────────────────────┐                  │
│   │ Control plane│   │ Policy engine│   │ Audit log (append- │                  │
│   │ users/agents │──▶│ (grant eval, │──▶│ only, hash-chained)│                  │
│   │ consent UI   │   │ spend, HITL) │   └────────────────────┘                  │
│   └──────────────┘   └──────┬───────┘                                           │
│                             │ approved                                          │
│   ┌─────────────────────────▼─────────────────────────────────────────┐         │
│   │  EDGES (plaintext only here, only in memory)                       │         │
│   │  ① Egress HTTP proxy      ② Browser injector      ③ Card route     │         │
│   │  inject header/body/      CDP: type into field    alias ──▶ PAN    │         │
│   │  query, redact response   never returned to LLM   swap in outbound │         │
│   └──────┬─────────────────────────┬──────────────────────┬───────────┘         │
│          │                         │                      │                     │
│   ┌──────▼──────────────────────────▼──────┐    ┌─────────▼──────────────────┐  │
│   │ Secret store (pluggable)               │    │ Card vault provider        │  │
│   │ built-in (AES-GCM, Argon2id-wrapped)   │    │ (pluggable): VGS │ Basis   │  │
│   │ Vaultwarden │ Infisical │ OpenBao      │    │ Theory │ Evervault         │  │
│   └────────────────────────────────────────┘    └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
        │ ①/② real creds                                  │ ③ real PAN
        ▼                                                 ▼
   Third-party API / website                         Merchant checkout / PSP
```

## Install

Prebuilt binaries for Linux, macOS, and Windows are on the
[GitHub Releases](https://github.com/joalavedra/valet/releases) page.

```bash
# Homebrew (tap populated on the next release)
brew install joalavedra/valet/valet
# The binary is unsigned — the cask clears the macOS quarantine bit on install.

export VALET_MASTER_PASSWORD="$(openssl rand -base64 24)"  # keep this; it is the owner credential

# Docker (server on 127.0.0.1:14400, data in a named volume)
docker run -d -v valet-data:/data -p 127.0.0.1:14400:14400 \
  -e VALET_MASTER_PASSWORD="$VALET_MASTER_PASSWORD" ghcr.io/joalavedra/valet:latest

# or build from source with Go ≥ 1.26
go install github.com/joalavedra/valet@latest
```

The master password is also the owner bearer token — never expose the
listen port publicly without a TLS/auth proxy in front.

## Quickstart

```bash
make build

export VALET_MASTER_PASSWORD="$(openssl rand -base64 24)"  # keep this; it is the owner credential

./valet cred add --type login --label joan --site github.com   # secrets via prompt/stdin
./valet cred list                                             # handles + metadata only
./valet agent create my-bot                                   # prints agent token once
./valet server                                                # HTTP API on :14400

export VALET_ADDR=http://127.0.0.1:14400                      # optional, this is the default
export VALET_AGENT_TOKEN=<token from agent create>
./valet mcp                                                   # MCP tools over stdio
```

Working browser-fill demo: [examples/login-demo](examples/login-demo).

Browser-fill accepts a page-level CDP websocket URL such as
`ws://127.0.0.1:9222/devtools/page/<target-id>`; browser-level URLs are only
accepted when exactly one page target exists. The server only allows CDP hosts
from `VALET_CDP_ALLOW` (default `127.0.0.1,localhost,::1`). Fill statuses are
`ok`, `need_otp`, `wrong_password`, `captcha`, `host_mismatch`, or `unknown`.

## API credentials via Infisical Agent Vault

`http_call` delegates to an Infisical Agent Vault forward proxy, which
injects the real credential upstream — the agent (and Valet) never see it.

```bash
export VALET_AGENTVAULT_PROXY=http://TOKEN:VAULT@127.0.0.1:14322  # forward proxy, token:vault userinfo
export VALET_AGENTVAULT_ADDR=http://127.0.0.1:14321               # Agent Vault API (for /discover)
export VALET_AGENTVAULT_TOKEN=<agent-token>
export VALET_AGENTVAULT_VAULT=<vault-name>                        # optional X-Vault header
export VALET_AGENTVAULT_CA=/path/to/agent-vault-ca.pem            # optional, for HTTPS upstreams (GET {ADDR}/v1/mitm/ca.pem)
```

Each Agent Vault service becomes a virtual handle `api://<name>`. Grant it,
then call:

```bash
curl -X POST localhost:14400/v1/grants -H "Authorization: Bearer $AGENT" \
  -d '{"handle":"api://stripe","policy":{"hosts":["api.stripe.com"]},"ttl":600}'

curl -X POST localhost:14400/v1/edge/http/call -H "Authorization: Bearer $AGENT" \
  -d '{"grant_token":"'$GRANT'","method":"GET","url":"https://api.stripe.com/v1/charges"}'
```

The request URL host must match the discovered service host; hop-by-hop and
`Proxy-*` agent headers are stripped, and `Set-Cookie` is never returned.
The response body is redacted best-effort (`redacted: true` when applied):
Valet can't see the injected credential value, so it masks common secret
shapes (`sk_live_…`, `ghp_…`, `AKIA…`, `Bearer …`, etc.) and quoted JSON
fields with credential-looking names (`"api_key"`, `"access_token"`,
`"password"`, `"secret"`, `"token"`, …, values ≥ 8 chars) — this catches
echoed credentials in responses like httpbin's, it is not a guarantee.

## Card payments via VGS

`POST /v1/edge/card/pay` sends the merchant's payment API call through VGS's
outbound proxy — Valet substitutes `{{card.*}}` placeholders with the stored
aliases, and VGS detokenizes them to real PAN/CVC in transit for hosts that
have an **Outbound Route** configured in the VGS dashboard.

Env vars: `VGS_VAULT_ID` (the `tnt…` id — required, otherwise the provider
isn't registered), `VGS_ENV` (default `sandbox`), `VGS_USERNAME`,
`VGS_PASSWORD` (vault Access Credentials), `VGS_CA_FILE` (path to VGS's
`sandbox.pem`/`live.pem` — the proxy is reached over TLS on
`<vault>.<env>.verygoodproxy.com:8443`). The sandbox CA is bundled in the
binary (and at `deploy/vgs/sandbox.pem`), so `VGS_CA_FILE` is only needed
for `VGS_ENV=live`.

Operator-side tokenization (no Collect.js needed): `cred add --type card
--tokenize` prompts for the raw PAN and sends it through the VGS Vault API,
storing only the returned aliases (CVC, if given, is stored as a 1-hour
VOLATILE alias). Requires a VGS service account:
`VGS_CLIENT_ID`/`VGS_CLIENT_SECRET` (Dashboard → Organization settings →
Service Accounts → Create New, scopes `aliases:write`). Prints only the
alias's last4. Example outbound route for httpbin.org (reveals
`$.card.number` in the JSON body): `deploy/vgs/routes/httpbin-echo.yaml` —
import via the dashboard or `vgs apply`.

Placeholders (stored as credential fields by `cred add --type card`):

| Placeholder | Card field |
|---|---|
| `{{card.number}}` | PAN alias |
| `{{card.exp_month}}` / `{{card.exp_year}}` | expiry |
| `{{card.holder}}` | cardholder name |
| `{{card.cvc}}` | CVC alias (VOLATILE, optional — 409 `{"error":"cvc_required","status":"need_cvc"}` if referenced but absent) |

Card grants must be scoped — the policy needs `hosts` or `spend.merchants`
(otherwise 403 `card grant must restrict merchants`); a `spend` policy also
requires a positive `amount` (403 `amount required`). Policy:
`spend.merchants` (glob on the request host), `spend.per_tx` cap;
`amount`/`currency` are recorded in the audit row.

Response: `{"status","http_status","headers","body","truncated"}` where
`status` is `ok` (upstream 2xx), `declined` (4xx) or `upstream_error`
(3xx/5xx). Hop-by-hop and `Proxy-*` request headers are dropped, redirects
are never followed, the body is capped at 256 KiB, and the response body is
redacted — stored secret values (number/cvc), Luhn-valid PANs and
CVC-shaped JSON values never reach the agent.

Verified flow: `--tokenize` a card, give the merchant's host an outbound
ENRICH route revealing `$.card.number`, then `pay` echoes the real PAN
upstream and returns `****1111` to the agent. If the route's filters include
`ContentType`, the agent must pass a matching `Content-Type` in `headers` —
otherwise the payload bypasses the filter and the alias crosses the proxy
unrevealed.

## Capturing a card from the cardholder (Collect.js)

For a PAN that never touches the operator or the CLI, generate a one-time
capture link:

```
valet card capture --label visa-4242 --ttl 15m
# → Open in the cardholder's browser: http://localhost:14400/capture/<token>
```

Prerequisite: one **Inbound Route** in the vault whose upstream is
`https://api.<env>.verygoodvault.com` (the Vault API **v1** upstream that
Collect's `tokenize()` targets — *not* `vault-api.verygoodvault.com`,
which is v2/`createAliases` and rejects the CORS preflight) — Collect.js
`tokenize()` posts through the vault's inbound proxy and fails with
"Network Error" if no inbound route covers it. No `setRouteId` needed —
a single inbound route is matched by host. If preflights still fail,
enable **Intercept CORS** in Vault Settings → Advanced.

`GET /capture/<token>` renders an embedded page that loads VGS Collect.js
3.4.0 (hosted iframes for number + CVC; expiry/holder are plain inputs) and
calls `form.tokenize()` — the PAN goes straight to the VGS vault. The page
posts only aliases to `POST /capture/<token>/complete`. The number must be
a **UUID-format** alias (`tok_…`) — the server rejects anything else,
including format-preserving aliases which are themselves Luhn-valid PANs.
The CVC alias VGS returns is **numeric length-preserving** (3–4 digits —
VGS forces this for VOLATILE card-security-code storage regardless of the
requested format), so the server accepts `tok_…` or `\d{3,4}` for `cvc`.
Collect's field state also supplies `last4`/`bin` (stored in metadata —
BIN is the non-sensitive first 6–8 digits). Rejections return
`raw card data rejected`; completion claims
the capture atomically, and stores a `card://<label>` credential identical
to `cred add --type card`, so `pay` works unchanged. Links are single-use
and expire; the base URL comes from `VALET_PUBLIC_URL` (default
`http://<VALET_LISTEN>`). Audit rows carry edge `card`, target `capture`.

## Use from browser-use

`sdks/python` ships a `valet-agent` package with a browser-use adapter:

```bash
pip install -e 'sdks/python[browser-use]'
```

```python
from browser_use import Agent, BrowserSession, ChatOpenAI, Tools
from valet.browser_use import register_valet_tools
from valet.client import ValetClient

client = ValetClient()                      # VALET_ADDR + VALET_AGENT_TOKEN
session = BrowserSession(cdp_url="http://127.0.0.1:9222")
tools = register_valet_tools(Tools(), client, cdp_url=session.cdp_url)
agent = Agent(task="Log in via valet_login ...", llm=ChatOpenAI(model="gpt-4o-mini"),
              browser_session=session, tools=tools)
```

`valet_login` fills credentials via the browser-fill edge — the agent sees
only a status string, never the password. See
`sdks/python/examples/browser-use/login.py`.

## Running under hotdesk / remote-CDP hosts

Agents behind an MCP-over-HTTP proxy or a shared CDP browser (e.g. hotdesk)
never see devtools websocket URLs. Valet can own both ends:

```bash
VALET_CDP_URL=http://127.0.0.1:9222 valet server   # default CDP endpoint
valet mcp --http 127.0.0.1:14401                    # streamable HTTP on /mcp
```

With `VALET_CDP_URL` set, `browser_fill` may omit `cdp_ws_url`. Agents can
also pass `page_url` — the URL of the tab to fill — and Valet picks the
matching page target (exact match, then host+path ignoring query, then a
unique-host fallback; ambiguous → error). The default endpoint's host must
still satisfy `VALET_CDP_ALLOW` (loopback by default).

`--http` auth: set `VALET_MCP_TOKEN` and clients must send `Authorization:
Bearer <token>` (401 + `Cache-Control: no-store` otherwise). Without a
token, only loopback binds are allowed — `valet mcp --http` refuses to
start on `0.0.0.0`/non-loopback addresses.

See [deploy/hotdesk](deploy/hotdesk) for a drop-in hotdesk desktop image that
bundles Valet into `hotdesk-desktop` (supervisor-managed server, credentials
encrypted in the persistent `/home/cua` volume, MCP via `docker exec`).

## Wallets (x402 / Openfort)

Agents can pay for HTTP resources that answer `402 Payment Required`
([x402](https://x402.org), USDC on Base) from an
[Openfort](https://openfort.io) backend wallet — without ever holding the
Openfort secret key, wallet secret, or being able to sign arbitrary
transactions. The agent holds a `wallet://` handle; Valet signs only
x402 `exact`-scheme EIP-3009 authorizations at the edge and returns a
payment receipt.

```bash
valet cred add --type wallet --label agent
# prompts: secret_key, wallet_secret, account_id (optional),
#          svm_account_id (optional), svm_address (optional)
# leave account_id empty to create a new backend account, or pass
# --address 0x.. --network eip155:84532 for an existing one
```

The same `wallet://` label can also pay on Solana: create a second
backend wallet with `chainType=SVM` in Openfort, then pass
`--svm-account-id` + `--svm-address` and list the Solana CAIP-2 network:

```bash
valet cred add --type wallet --label agent --address 0x.. \
  --svm-account-id acc_... --svm-address <base58> \
  --network eip155:84532,solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1
```

For Solana the edge signs the transaction message via the SVM account
and the facilitator's `feePayer` co-signs, so the wallet needs no SOL —
only devnet USDC (https://faucet.circle.com). A credential that lists a
`solana:` network without an SVM account is denied before any request.

Grant it like a card (host scope is required):

```json
{"hosts":["api.example.com"],"ttl":3600,"spend":{"per_tx":100000,"total":1000000,"currency":"USDC"}}
```

`per_tx` and `total` are USDC minor units (6dp); `total` is cumulative
over the grant's life. The MCP tool:

```
x402_fetch(grant, url, method, headers, body, max_amount)
```

returns `{status:"ok"|"paid", http_status, headers, body, payment:
{network, asset, pay_to, amount, transaction}}`. The edge only pays when
the server's offer matches the wallet's configured network and USDC (the
network's default x402 asset) and is
within `min(per_tx, total-spent, max_amount)`; otherwise the call is
denied and nothing is signed. Set `VALET_REQUIRE_APPROVAL=card,wallet`
to require owner approval for wallet grants too.

### MPP (Tempo)

The same `wallet://` credential also answers MPP
([Machine Payments Protocol](https://paymentauth.org)) challenges —
`WWW-Authenticate: Payment` with the `tempo`/`charge` method — via
`POST /v1/edge/wallet/mpp` or the MCP tool:

```
mpp_fetch(grant, url, method, headers, body, max_amount)
```

Valet signs a Tempo pull-mode transaction (TIP-20 transfer with
attribution memo; zero-amount challenges get a proof credential) with the
same Openfort digest signer — push mode and arbitrary signing are not
exposed. Only chains listed in the credential's `network` metadata are
paid; `asset` resolves per chain (on Tempo chains the default
stablecoins: pathUSD/OUSD on Moderato `eip155:42431`, USDC.e/OUSD on
mainnet `eip155:4217`).

Configure both protocols on one credential with a comma-separated
network list:

```bash
valet cred add --type wallet --label agent --address 0x.. \
  --network eip155:84532,eip155:42431
```

For the Tempo Moderato testnet (chain 42431), fund the wallet with
pathUSD `0x20c0000000000000000000000000000000000000` via the
`tempo_fundAddress` RPC method on the Moderato RPC.

## Human approvals & wallet

Grant requests can require a human decision before a token is issued. An
agent's `request_grant` returns `202 pending_approval` with a `request_id`;
it then polls `GET /v1/grants/requests/<id>` (optionally `?wait=<seconds>`
for a long poll) until the owner decides.

Configuration (environment):

| Variable | Meaning |
|---|---|
| `VALET_REQUIRE_APPROVAL` | `card` (default: any `card://` handle needs approval), `all`, `none`, or a comma list like `card,wallet`. `policy.require_human` on a request always forces approval. |
| `VALET_APPROVAL_TTL` | How long a pending request stays live (Go duration, default `10m`). |
| `VALET_APPROVAL_WEBHOOK` | Optional URL POSTed a JSON notification (`request_id`, `agent`, `handle`, `label`, `purpose`, `policy`, `approve_url`) for each new request. |
| `VALET_OWNER_TOKEN` | Extra bearer token accepted for owner endpoints (alongside `VALET_MASTER_PASSWORD`). |
| `VALET_PUBLIC_URL` | Public base URL used to build `approve_url` links; relative when unset. |
| `VALET_CAPTURE_RETURN_ORIGINS` | Comma-separated origins allowed as capture `return_url` targets. Defaults to the `VALET_PUBLIC_URL` origin; when neither is set, any non-empty `return_url` is rejected. |

Pages: `GET /wallet` (all pending requests + active grants) and
`GET /approve/<id>` serve the bundled `wallet.html` SPA.

Owner API (bearer = master password or `VALET_OWNER_TOKEN`):

- `GET /v1/owner/handles` — same handle list agents see
- `DELETE /v1/owner/handles/{handle}` — remove a stored credential (audited as edge `owner`, target `delete`)
- `GET /v1/owner/approvals?status=pending` — pending/decided requests
- `POST /v1/owner/approvals/{id}/approve` — issue the grant
- `POST /v1/owner/approvals/{id}/deny`
- `GET /v1/owner/grants` — all grants with `active` flag
- `POST /v1/owner/grants/{id}/revoke` — revoke (edge calls then get `403 grant revoked`)
- `GET /v1/owner/audit` — alias of `GET /v1/audit`

MCP: `request_grant` accepts `purpose` and `wait`; `wait_grant(request_id,
wait)` long-polls for the decision.

## Dev

```bash
make build   # build ./valet
make test    # go test ./...
make lint    # go vet + gofmt check
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
