# Valet — Design Draft v0.2

*Open-source (Apache-2.0), self-hostable credential + payment broker for AI agents: it holds the user's keys and card and acts on their behalf, never handing them over. Companion to `ai_vault_landscape.md` (Sept 2026 survey).*

**Decisions locked (v0.2):** Go core + TS/Python SDKs · Apache-2.0 · card rail = PAN replay via VGS first (Basis Theory as second driver), virtual cards later · x402/Openfort wallet as a later plugin, core reads as neutral infra · no own PCI/TEE card vault · builds on top of `Infisical/agent-vault` for the API-credential edge (see §10b).

---

## 1. One-liner

> Agents get **handles**, never secrets. Valet holds a user's logins, API keys and cards, and swaps the real values in **at the edge** (HTTP egress proxy, browser field, or card-vault outbound route) — so no LLM, prompt, log or agent process ever sees a password or a PAN.

## 2. Why build it (from the landscape)

| Gap in the OSS market | Who almost does it | Valet stance |
|---|---|---|
| Self-hostable broker for **non-API logins** (email/pw, sessions, TOTP) | Skyvern (only inside its own browser agent), Anon (closed) | Core module, exposed to *any* agent via MCP |
| Password-manager MCPs that **don't leak** plaintext to the model | Bitwarden MCP (admits it leaks), hobby projects | Opaque-by-default handles; reveal is impossible by design, not by policy |
| **Card payments by agents** without merchant-scoped tokens | Fewsats/SimpleCheckout (closed, VGS-backed) | Open implementation of the "neutral alias vault + outbound proxy" pattern, provider-pluggable |
| **TEE-attested** injection | Phala dstack / Oasis ROFL (wallet keys only) | Optional deployment mode; same API |
| Response-side redaction, scoped/ephemeral grants, audit | AgentSecrets (180★), Scalekit (SaaS) | Built-in, self-hosted |

Positioning: **"OpenBao for agents"** — permissive license, boring infra, pluggable backends. Not a hosted SaaS first. Valet does not re-implement API-key brokering; it composes with Infisical Agent Vault (edge ①) and adds the login edge, the card edge, policy/spend and attestation.

## 3. Threat model (what we defend against)

1. **Prompt/context leakage** — secret ends up in LLM input/output, traces, evals, logs.
2. **Compromised or prompt-injected agent** — agent tries to read/exfiltrate secrets or use them off-task (pay the wrong merchant, log in to the wrong site).
3. **Compromised Valet host** (TEE mode only) — operator/cloud can't read plaintext.
4. **Card data breach** — PAN/CVC must never be at rest or in memory on our infra (PCI scope stays SAQ A-ish).

Out of scope v1: malicious user, compromised end-user device, side channels on TEE.

## 4. Core concepts

```
User ──grants──▶ Credential (login | api_key | oauth | card)
                     │ referenced by
                     ▼
                  Handle  e.g. cred://github/joan  card://visa-4242
                     │ usable only under a
                     ▼
                  Grant   { agent_id, handle, scope, ttl, policy }
                     │ exercised through an
                     ▼
                  Edge    (egress proxy | browser injector | card route)
```

- **Handle** — opaque URI. Safe to put in prompts, code, logs. Has no read endpoint that returns plaintext.
- **Grant** — signed, short-lived (minutes–hours), bound to an agent identity and a **policy**: host allowlist, method/path patterns, spend cap, merchant allowlist, max uses, human-approval threshold.
- **Edge** — the only place plaintext exists transiently. Three edge types (§6).

## 5. Architecture

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
│   │ built-in (age/AES-GCM, KMS-wrapped)    │    │ (pluggable): VGS │ Basis   │  │
│   │ Vaultwarden │ Infisical │ OpenBao      │    │ Theory │ Evervault │ own-   │  │
│   │ 1Password Connect                      │    │ TEE vault (later)          │  │
│   └────────────────────────────────────────┘    └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
        │ ①/② real creds                                  │ ③ real PAN
        ▼                                                 ▼
   Third-party API / website                         Merchant checkout / PSP
```

Deployment modes: (a) **local** — single binary next to the agent (like `op`/`bw` CLI); (b) **server** — team-shared, multi-user; (c) **TEE** — same binary inside Phala dstack / Oasis ROFL / AWS Nitro, keys derived in-enclave, attestation exposed at `/attest`.

## 6. Edges in detail

### ① Egress HTTP proxy (API keys, OAuth tokens, basic auth)
- Agent calls `http_call(handle, request)` or points `HTTP(S)_PROXY` at Valet with a grant token.
- Valet validates grant → policy (host allowlist, method, path glob, rate) → injects (`Authorization`, custom header, query param, body template, mTLS cert) → forwards.
- **Response redaction**: scan response for any secret value belonging to the user (and common token shapes) → replace with handle. Prevents "echo my key back" leaks.
- OAuth: refresh handled server-side; agent never sees refresh tokens. Reuse Nango-style provider templates for the 900+ OAuth configs rather than rewriting.

### ② Browser injector (email/password, sessions, TOTP)
- Agent runs a browser (Playwright/CDP — browser-use, Skyvern, Stagehand, own). Agent calls `browser_fill(handle, cdp_ws_url, {selector→field})`.
- Valet connects to the same CDP session and types the real values itself; the agent's screenshots/DOM diffs are post-processed to mask fields (Skyvern-style placeholders `{{cred://…}}`).
- TOTP generated in Valet from the stored seed. Session cookies can be captured **into** Valet after login and re-injected later (`session://` handles) so re-auth is rare.
- Status codes back to agent mirror SimpleCheckout's `connect` flow: `ok | need_otp | wrong_password | captcha | mfa_push` — agent gets *what to do*, never *why in plaintext*.

### ③ Card route (paying with a credit card) — the Fewsats/VGS pattern, opened up
Constraint (same as Fewsats): **we are not the merchant**. A Stripe `pm_xxx` is bound to our merchant account and is worthless at a third-party checkout. We need to *replay a real PAN* into someone else's form, from a bot, without ever holding it.

```
 Capture (once)                                  Spend (per purchase)
 ───────────────                                 ────────────────────
 User's browser                                  Agent
   │ card fields = provider-hosted iframes          │ pay(card://visa-4242, merchant, amount)
   ▼                                                ▼
 Card vault provider (VGS / Basis Theory / …)    Valet policy: merchant allowlist, spend cap,
   │ returns alias  tok_ab12…                    per-tx & daily limit, HITL above threshold
   ▼                                                │ approved
 Valet stores only the alias  ──────────▶  card://visa-4242
                                                    ▼
                                             Edge ③ picks a rail:
                                             (a) Merchant API / hosted checkout → outbound proxy
                                                 route swaps alias→PAN in the request body
                                             (b) Web checkout → browser injector, but the
                                                 typing happens from a provider "reveal" iframe /
                                                 outbound-proxied CDP so PAN never hits our RAM
                                             (c) Virtual card: provider issues a single-use /
                                                 merchant-locked VCN (Lithic, Stripe Issuing,
                                                 Privacy.com) funded from user's card or Openfort
                                                 wallet → agent gets a *disposable* number
```

Design decisions:
- **Provider-pluggable via `/v0/provider-config`-style indirection** (Fewsats hard-fails on anything but `vgs`; we ship ≥2 drivers so it's real). Interface: `capture_config()`, `outbound_route(alias→PAN)`, `reveal_iframe(alias)`, optional `issue_vcn()`.
- **CVC is never stored** (PCI forbids post-auth). Step-up `update_cvc` flow re-collects it from the human into the provider vault with a short TTL alias. HITL is natural here: "Confirm $84.20 at Amazon — enter CVC".
- **Virtual cards are the preferred rail** when available: merchant-locked, amount-capped, single-use numbers make prompt-injection-driven fraud mostly harmless and drop us from "replay a PAN" to "hand the agent a throwaway". Card-on-file replay (a/b) is the fallback for the long tail.
- **x402 / stablecoin rail** plugs into the same `pay()` tool as a fourth option (agent wallet, Openfort-managed). Same policy engine, same audit, no PAN. Row 3 is the bridge, row 4 is the destination — one API for both.
- PCI posture: aliases only at rest → target SAQ A / A-EP; PAN in memory only inside provider iframes/proxies (or, later, inside our TEE-mode own-vault driver — which is where a wallet-infra company could plausibly run its own PCI'd enclave vault).

## 7. Policy & consent

- Grants requested by agent → auto-approved if inside the user's standing policy for that agent, else pushed to the user (web UI / mobile / Slack) with plain-English intent: *"Agent `travel-bot` wants to log in to united.com and pay ≤ $600 at united.com, valid 30 min."*
- Policy language: small JSON/CEL — `hosts`, `methods`, `paths`, `max_uses`, `ttl`, `spend.per_tx`, `spend.daily`, `merchants`, `require_human_above`.
- Every edge action → audit event `{ts, agent, handle, edge, target, policy_decision, hash_prev}`; exportable, verifiable chain. TEE mode signs events with the enclave key.

## 8. Agent-facing surface

MCP server (primary) + REST + thin SDKs (TS/Python). Tools:

| Tool | Returns | Never returns |
|---|---|---|
| `list_handles()` | handles + metadata (site, label, last4, scopes) | secrets |
| `request_grant(handle, policy)` | grant_id, status `granted|pending_approval|denied` | — |
| `http_call(grant, req)` | redacted response | injected headers |
| `browser_fill(grant_token, cdp_ws_url, mapping{field→selector}, submit?)` | `ok|need_otp|wrong_password|captcha|host_mismatch|unknown` | typed values |
| `pay(grant, merchant, amount, rail?)` | receipt / `need_cvc` / `pending_approval` | PAN, VCN (unless rail=vcn and policy allows) |

Framework adapters: browser-use `sensitive_data` shim, OpenHands secrets provider, LangChain tool, OpenAI Agents SDK tool.

## 9. Storage & crypto

- Per-user envelope encryption: user root key (Argon2id from passphrase or passkey-PRF) → wraps data keys; server-mode adds KMS/HSM wrap; TEE mode derives root from enclave identity (dstack `getKey`).
- Backing stores behind one interface: built-in SQLite/Postgres blobs, Vaultwarden (via CLI/API), Infisical, OpenBao KV, 1Password Connect. Bring-your-own password manager = fastest adoption path.

## 10. MVP scope (v0.2 cut, post Agent Vault discovery)

**Phase 1 — core + login edge (≈ 3 sessions)**
- Go single binary `valet`, SQLite (Postgres later), envelope-encrypted built-in store.
- Handles, grants, policy (hosts/ttl/max_uses/require_human), hash-chained audit.
- Edge ①: delegate to Infisical Agent Vault — Valet mints/forwards Agent Vault sessions so agents get one token; `http_call` is a thin passthrough plus **response redaction** implemented Valet-side.
- Edge ②: CDP-based `browser_fill` (email/pw), TOTP, session-cookie capture/reinject, placeholder masking in screenshots/DOM. Adapter for browser-use.
- MCP server: `list_handles`, `request_grant`, `http_call`, `browser_fill`.
- Import from Bitwarden/Vaultwarden export & 1Password CLI.
- Demo: agent logs into a site with TOTP without seeing the password; asks for it → gets handle.

**Phase 2 — payments (≈ 3 sessions)**
- Edge ③: `CardProvider` interface; **VGS driver first** (Collect iframe capture, alias storage, outbound route alias→PAN, `update_cvc` step-up); Basis Theory driver second to prove the abstraction.
- `pay()` tool: merchant allowlist, per-tx/daily caps, HITL above threshold; rails (a) API/hosted-checkout via outbound route and (b) web checkout via browser edge with provider reveal.
- Consent UI (web) + Slack approvals.

**Phase 3 — later / plugins**
- Virtual-card driver (Lithic) as a safer rail once an issuing partner exists.
- x402 / Openfort wallet rail as an external plugin behind the same `pay()`.
- TEE deployment recipe (Phala dstack), `/attest`, enclave-signed audit. No own card vault / PCI scope.
- Security review, threat model doc, fuzzing of redaction.

## 10b. Addendum — Infisical Agent Vault (found after v0.1)

`github.com/Infisical/agent-vault` (MIT, Go, first commit 2026-07, ~50 commits, backed by Infisical) is essentially **Phase 1 of this doc, already shipped**: MITM egress proxy (`HTTPS_PROXY` + own CA), placeholder substitution (`__anthropic_api_key__` → real key), bearer/basic/api-key/custom header injection, OAuth PKCE connect + refresh, per-host/path service rules, deny-unmatched mode, agent tokens & short-lived sandbox sessions, GitHub-PR-style **proposals** for human approval of new creds, Docker container isolation with iptables egress lock, SQLite/Postgres, pluggable store (Infisical backend), TS SDK, web UI.

What it does **not** do (verified in repo): browser/CDP credential injection, TOTP/session handling, response-body secret redaction (only log redaction), spend/payment policies, cards, TEE/attestation. Commercial upsell is "Infisical Agent Vault" (hosted, access bundles).

**Revised recommendation:** don't rebuild the egress proxy. Either
- (A) **build on top**: Valet = browser edge ② + card edge ③ + policy/spend + TEE recipe, using Agent Vault as the API-credential edge (it's MIT; contribute upstream where sensible), or
- (B) **fork** if we need deep changes (response redaction, grants w/ spend caps, `pay()`), accepting divergence.

Either way the differentiators that remain open are unchanged: *website logins, card payments (VGS-pattern + virtual cards + x402), and attested execution*. That is a sharper, more defensible scope than "another vault", and it's exactly the part Infisical (a secrets company, not a payments/wallet company) is least likely to build.

**Status (implemented):** option (A). `http_call` is live via `internal/edge/egress`: requests go through the Agent Vault forward proxy (`VALET_AGENTVAULT_PROXY` with `token:vault` userinfo), services from `GET {VALET_AGENTVAULT_ADDR}/discover` become virtual `api://<name>` handles, and grants/policy/audit apply as on the other edges. The CA PEM is served by Agent Vault at `GET /v1/mitm/ca.pem` (`VALET_AGENTVAULT_CA`).

## 11. Decisions log

| # | Question | Decision (Joan, Sept 2026) |
|---|---|---|
| 1 | Stack | Go core + TS/Python SDKs |
| 2 | License | Apache-2.0 |
| 3 | Card rail priority | VGS PAN-replay first; virtual cards later |
| 4 | Openfort / x402 tie-in | Plugin later; core stays neutral |
| 5 | Own TEE card vault / PCI | No, not for now |
| 6 | Name | **Valet** (alternates: Sesame, Glovebox) |

## 12. Next step

Scaffold the `valet` repo: Go module, `valet server` / `valet mcp`, store + handles + grants + audit, CDP `browser_fill` PoC against a test site with TOTP, `CardProvider` interface with a VGS sandbox stub. Then iterate per Phase 1.
