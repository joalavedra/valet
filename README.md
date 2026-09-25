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
./valet mcp                                                   # MCP tools over stdio
```

## Dev

```bash
make build   # build ./valet
make test    # go test ./...
make lint    # go vet + gofmt check
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
