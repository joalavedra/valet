# Valet agent-commerce demo

A mobile-first "agent buys things for you" demo in the Crossmint style. A Gemini
agent chats with you, and when you ask it to buy something it doesn't touch your
card: it asks Valet for a spend-capped, single-use grant, you approve it on your
phone, and Valet injects the aliased card into the demo store's checkout request.
The VGS outbound route reveals the aliases in flight, and the store's Luhn check
proving a real PAN arrived (`tok_…` aliases are declined with 402).

![Valet demo: chat → approval → receipt](../docs/media/demo-checkout.webp)

## Quickstart

```sh
cd demo
cp .env.example .env   # fill in GEMINI_API_KEY and VGS_*
./run.sh               # builds, starts cloudflared tunnel + compose stack
```

`run.sh` prints the public URL and the basic-auth password (`demo` / printed
value). Open the URL on your phone.

To enroll a test card without a browser (Collect.js requires a real page), use
the CLI path against the compose DB:

```sh
docker compose exec valet /valet cred add --type card --label personal --tokenize
# card: 4111111111111111, exp 12/2030, cvc 123  (VGS sandbox test Visa)
```

Multiple cards: the Wallet tab lists every `card://` handle — "Add card"
prompts for a label, tapping a card makes it the checkout default, and ✕
removes it (`DELETE /v1/owner/handles/{handle}`). Checkout always uses the
default card (`POST /api/card/default`); deleting the default falls back to
the first remaining card.

Or use the real flow: open the app → Wallet → "Add card" (the `/capture` page is
served by Valet through the demo's `/valet/*` proxy).

Then in chat: "Buy the coffee beans" → approve the bottom-sheet → receipt.

## Env

| Var | Purpose |
|---|---|
| `DEMO_LISTEN` | listen addr (default `:8080`) |
| `DEMO_PUBLIC_URL` | public base URL (set by run.sh to the tunnel) |
| `DEMO_PASSWORD` | basic-auth password, user `demo` (`/store/*` is open for VGS) |
| `VALET_URL` | internal valet base (default `http://valet:14400`) |
| `VALET_AGENT_TOKEN` / `_FILE` | demo agent token (written by `valet-init`) |
| `VALET_OWNER_TOKEN` | owner API token (approvals/captures) |
| `VALET_MASTER_PASSWORD` | valet DEK password |
| `VALET_PUBLIC_URL` | public valet base — `DEMO_PUBLIC_URL + /valet` |
| `VALET_REQUIRE_APPROVAL` | `card` (compose default) — makes `card://` grants human-approved |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | Gemini REST (default `gemini-2.5-flash`) |
| `DEMO_CARD_LABEL` | initial default card handle label (default `personal`) |
| `VALET_CAPTURE_RETURN_ORIGINS` | origins allowed as capture `return_url` (compose sets `DEMO_PUBLIC_URL`) |
| `VGS_CLIENT_ID`/`VGS_CLIENT_SECRET` | service-account OAuth for tokenize + `vgs-route.sh` |
| `VGS_USERNAME`/`VGS_PASSWORD` | vault access credentials — the outbound proxy auth Valet uses for payments |
| `VGS_VAULT_ID`/`VGS_ENV` | `tnt…` vault id; `sandbox` (default) or `live` |

## Money flow

1. Agent → `POST /v1/grants` `{handle:"card://personal", purpose, ttl:600, max_uses:1, spend:{per_tx, merchants:[demo host]}}` → `202 pending_approval` (because `VALET_REQUIRE_APPROVAL=card`).
2. Phone approves → `GET /v1/grants/requests/{id}?wait=60` returns the grant token.
3. Agent → `POST /v1/edge/card/pay` with `{{card.number}}`/`{{card.cvc}}` placeholders in the checkout body — Valet swaps in VGS aliases.
4. The request egresses through the VGS outbound proxy → `valet-demo-store` route reveals `$.card.number`/`$.card.cvc` → real PAN reaches the store.
5. Store Luhn-checks, records the order, returns `{order_id,status:"paid",last4}`.

## Limitations

Demo only: fixed catalog, in-memory orders, sandbox VGS vault, fake "store"
(psp-free). Approval webhook and 3DS are out of scope.
