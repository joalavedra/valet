package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
	"time"

	mppserver "github.com/tempoxyz/mpp-go/pkg/server"
	"github.com/tempoxyz/mpp-go/pkg/tempo"
	charge "github.com/tempoxyz/mpp-go/pkg/tempo/server"
	x402 "github.com/x402-foundation/x402/go"
	x402http "github.com/x402-foundation/x402/go/http"
	x402nethttp "github.com/x402-foundation/x402/go/http/nethttp"
	evmserver "github.com/x402-foundation/x402/go/mechanisms/evm/exact/server"
)

// Crypto-priced premium product: 0.01 in the rail's stablecoin
// (10000 base units at 6 decimals — USDC on Base Sepolia, pathUSD on
// Tempo Moderato).
const (
	tempoModeratoChainID = 42431
	x402Network          = "eip155:84532"
	x402Facilitator      = "https://x402.org/facilitator"
	reportPrice          = "$0.01"
	reportAmountMPP      = "0.01"
)

func reportBody() map[string]any {
	return map[string]any{
		"title": "Agent Commerce Market Report — Q3 2026",
		"summary": "Machine-to-machine payment volume grew 340% quarter over quarter, driven by per-request micropayments for API inference and metered data access. Card-rail checkouts still dominate order value, but wallet-native rails now carry the majority of agent-initiated transactions.\n\n" +
			"Adoption of programmatic payment challenges (HTTP 402 / MPP) spread beyond the early facilitator networks this quarter: merchants report sub-dollar digital goods as the fastest-growing category, with median settlement under two seconds on stablecoin rails.\n\n" +
			"Outlook: policy-scoped wallet grants are emerging as the default delegation pattern — owners cap spend per transaction and per grant lifetime, letting agents pay autonomously within tight bounds. We expect cross-rail interoperability (one product, multiple settlement methods) to become table stakes for agent-facing storefronts.",
		"unlocked_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func premiumReportHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, reportBody())
}

// x402Paywall gates a handler behind an x402 exact payment. The evm
// scheme server must be registered explicitly — SimpleX402Payment
// registers none, so requirements can't be built without it.
func x402Paywall(payTo, facilitatorURL string) func(http.Handler) http.Handler {
	return x402nethttp.X402Payment(x402nethttp.Config{
		Routes: x402http.RoutesConfig{
			"*": {Accepts: []x402http.PaymentOption{{
				Scheme:  "exact",
				PayTo:   payTo,
				Price:   x402.Price(reportPrice),
				Network: x402Network,
			}}},
		},
		Facilitator: x402http.NewHTTPFacilitatorClient(&x402http.FacilitatorConfig{URL: facilitatorURL}),
		Schemes: []x402nethttp.SchemeConfig{{
			Network: x402Network, Server: evmserver.NewExactEvmScheme(),
		}},
		SyncFacilitatorOnStart: true,
	})
}

// premiumHandlers builds the two paywalled report endpoints when a payout
// address is configured. The x402 gate wraps the handler at construction;
// the MPP gate needs a realm + HMAC secret and a Tempo RPC.
func (a *app) premiumHandlers() map[string]http.Handler {
	out := map[string]http.Handler{}
	payTo := a.cfg.PayTo
	out["GET /store/premium/report"] = x402Paywall(payTo, x402Facilitator)(
		http.HandlerFunc(premiumReportHandler))

	rpcURL, err := tempo.RPCURLForChain(tempoModeratoChainID)
	if err != nil {
		log.Printf("demo: tempo rpc for %d: %v", tempoModeratoChainID, err)
		return out
	}
	currencies := tempo.DefaultCurrenciesForChain(tempoModeratoChainID)
	method, err := charge.MethodFromConfig(charge.Config{
		RPCURL:     rpcURL,
		ChainID:    tempoModeratoChainID,
		Currencies: currencies,
		Recipient:  payTo,
		Store:      tempo.NewMemoryStore(),
	})
	if err != nil {
		log.Printf("demo: mpp method: %v", err)
		return out
	}
	realm := "valet-demo"
	if u, err := url.Parse(a.cfg.PublicURL); err == nil && u.Hostname() != "" {
		realm = u.Hostname()
	}
	mpp, err := mppserver.New(method, realm, a.cfg.MPPSecret)
	if err != nil {
		log.Printf("demo: mpp server: %v", err)
		return out
	}
	out["GET /store/premium/report/mpp"] = mppserver.ChargeMiddleware(mpp, mppserver.ChargeParams{
		Amount:      reportAmountMPP,
		Description: "Agent Commerce Market Report",
	})(http.HandlerFunc(premiumReportHandler))
	return out
}

// randomSecret returns a hex secret for the MPP realm when DEMO_MPP_SECRET
// is unset (a fresh realm secret per boot is fine for a demo).
func randomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "valet-demo-mpp-secret-key-32-bytes!"
	}
	return hex.EncodeToString(b)
}
