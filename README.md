# Valet

> Agents get **handles**, never secrets. Valet holds a user's logins, API keys and cards, and swaps the real values in **at the edge** (HTTP egress proxy, browser field, or card-vault outbound route) — so no LLM, prompt, log or agent process ever sees a password or a PAN.

**Status: pre-alpha.** Design doc: [docs/DESIGN.md](docs/DESIGN.md).

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

## Quickstart

```bash
make build

export VALET_MASTER_PASSWORD=changeme

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

## Dev

```bash
make build   # build ./valet
make test    # go test ./...
make lint    # go vet + gofmt check
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
