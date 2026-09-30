package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPremiumProductHiddenWithoutPayTo(t *testing.T) {
	a := testApp()
	a.cfg.PayTo = ""
	a.store = newDemoStore("")
	if p := a.store.byID("report"); p != nil {
		t.Fatal("report product visible without DEMO_PAY_TO")
	}
	a.store = newDemoStore("0xabc")
	p := a.store.byID("report")
	if p == nil || len(p.Rails) != 2 {
		t.Fatalf("report product missing with DEMO_PAY_TO: %+v", p)
	}
}

func TestX402PremiumReturns402WithoutPayment(t *testing.T) {
	// Fake facilitator: Initialize() may consult /supported.
	fac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"kinds": []any{}})
	}))
	defer fac.Close()

	h := x402Paywall("0xabc", fac.URL)(http.HandlerFunc(premiumReportHandler))
	r := httptest.NewRequest("GET", "/store/premium/report", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 402 {
		t.Fatalf("want 402, got %d (%s)", w.Code, w.Body)
	}
	if w.Header().Get("PAYMENT-REQUIRED") == "" {
		t.Fatalf("no PAYMENT-REQUIRED header: %v", w.Header())
	}
}

// fakeValetWallet stubs the valet calls agentWalletBuy makes:
// auto-approved grant, then a wallet edge reply shaped like the real one.
func fakeValetWallet(t *testing.T, pay any, code int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/grants":
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "token": "gtok"})
		case strings.HasPrefix(r.URL.Path, "/v1/edge/wallet/"):
			w.WriteHeader(code)
			if code >= 400 {
				json.NewEncoder(w).Encode(map[string]string{"error": "policy"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status": "paid", "http_status": 200,
				"body":    `{"title":"Report T","summary":"S"}`,
				"payment": pay,
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
		}
	}))
}

func TestAgentWalletBuyPaid(t *testing.T) {
	srv := fakeValetWallet(t, map[string]any{
		"protocol": "x402", "network": "eip155:84532",
		"transaction": "0xtxhash", "amount": "10000",
	}, 200)
	defer srv.Close()
	a := testApp()
	a.cfg.PayTo = "0xabc"
	a.cfg.PublicURL = "https://demo.example"
	a.store = newDemoStore("0xabc")
	a.valet = newValetClient(srv.URL, "agent", "owner")

	var events []map[string]any
	var mu sync.Mutex
	emit := func(ev string, d any) {
		mu.Lock()
		events = append(events, map[string]any{"ev": ev, "d": d})
		mu.Unlock()
	}
	res := a.agentWalletBuy(context.Background(), "conv1", "report", "x402", emit)
	if res["status"] != "paid" {
		t.Fatalf("want paid, got %v", res)
	}
	if res["tx"] != "0xtxhash" || res["explorer_url"] != "https://sepolia.basescan.org/tx/0xtxhash" {
		t.Fatalf("bad receipt: %v", res)
	}
	if res["title"] != "Report T" {
		t.Fatalf("report content not propagated: %v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(a.orders) != 1 || a.orders[0].Rail != "x402" || a.orders[0].ExplorerURL == "" {
		t.Fatalf("order not recorded: %+v", a.orders)
	}
}

func TestAgentWalletBuyDeclined(t *testing.T) {
	srv := fakeValetWallet(t, nil, 403)
	defer srv.Close()
	a := testApp()
	a.cfg.PayTo = "0xabc"
	a.cfg.PublicURL = "https://demo.example"
	a.store = newDemoStore("0xabc")
	a.valet = newValetClient(srv.URL, "agent", "owner")
	res := a.agentWalletBuy(context.Background(), "conv1", "report", "x402", func(string, any) {})
	if res["status"] != "declined" {
		t.Fatalf("want declined, got %v", res)
	}
	if len(a.orders) != 0 {
		t.Fatalf("order recorded on decline: %+v", a.orders)
	}
}

func TestAgentWalletBuyRailNotConfigured(t *testing.T) {
	a := testApp()
	a.cfg.PayTo = ""
	a.store = newDemoStore("")
	res := a.agentWalletBuy(context.Background(), "conv1", "report", "x402", func(string, any) {})
	if res["status"] != "error" {
		t.Fatalf("want error, got %v", res)
	}
}
