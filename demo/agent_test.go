package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAgentCheckoutDedupesPendingApproval(t *testing.T) {
	var grantCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/grants":
			grantCalls++
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"status": "pending_approval", "request_id": "rid_new"})
		default: // /v1/grants/requests/{id}
			json.NewEncoder(w).Encode(map[string]any{"status": "pending", "request_id": "rid1"})
		}
	}))
	defer srv.Close()

	a := testApp()
	a.cfg.PublicURL = "https://demo.example"
	a.valet = newValetClient(srv.URL, "agent", "owner")
	// The original approval was for coffee — a second buy of a different
	// product must re-emit the STORED purpose/amount, not the new item's.
	a.pending["conv1"] = &pendingApproval{
		id: "rid1", purpose: "Buy 1x Colombian coffee beans (250g) at Valet Demo Store",
		total: 1800, merchant: "demo.example", expiresAt: "2030-01-01T00:00:00Z",
	}

	var events []map[string]any
	var mu sync.Mutex
	emit := func(ev string, d any) {
		mu.Lock()
		events = append(events, map[string]any{"ev": ev, "d": d})
		mu.Unlock()
	}

	res := a.agentCheckout(context.Background(), "conv1", "sneakers", 1, emit)
	if res["status"] != "pending_approval" {
		t.Fatalf("want pending_approval, got %v", res)
	}
	if grantCalls != 0 {
		t.Fatalf("new grant request created despite pending approval (calls=%d)", grantCalls)
	}
	if len(events) != 1 || events[0]["ev"] != "approval_required" {
		t.Fatalf("approval_required not re-emitted for existing request: %v", events)
	}
	d, _ := events[0]["d"].(map[string]any)
	if d["request_id"] != "rid1" || d["amount_cents"] != 1800 ||
		!strings.Contains(d["purpose"].(string), "coffee beans") {
		t.Fatalf("re-emitted event should carry stored details, got %v", d)
	}
}

func TestAgentCheckoutConcurrentBuysMintOneGrant(t *testing.T) {
	var mu sync.Mutex
	var grantCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/owner/handles":
			json.NewEncoder(w).Encode(map[string]any{"handles": []map[string]any{
				{"handle": "card://personal", "metadata": `{"last4":"1111"}`},
			}})
		case "/v1/grants":
			mu.Lock()
			grantCalls++
			mu.Unlock()
			time.Sleep(100 * time.Millisecond) // widen the race window
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"status": "pending_approval", "request_id": "rid1"})
		default: // /v1/grants/requests/{id}
			if r.URL.Query().Get("wait") == "60" {
				json.NewEncoder(w).Encode(map[string]any{"status": "denied"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
		}
	}))
	defer srv.Close()

	a := testApp()
	a.cfg.PublicURL = "https://demo.example"
	a.valet = newValetClient(srv.URL, "agent", "owner")
	emit := func(string, any) {}

	var wg sync.WaitGroup
	results := make([]map[string]any, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = a.agentCheckout(context.Background(), "conv1", "coffee", 1, emit)
		}(i)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if grantCalls != 1 {
		t.Fatalf("want exactly one POST /v1/grants, got %d", grantCalls)
	}
}

func TestAgentCheckoutKeepsPendingOnClientDisconnect(t *testing.T) {
	grantCreated := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/owner/handles":
			json.NewEncoder(w).Encode(map[string]any{"handles": []map[string]any{
				{"handle": "card://personal", "metadata": `{"last4":"1111"}`},
			}})
		case "/v1/grants":
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"status": "pending_approval", "request_id": "rid1"})
			grantCreated <- struct{}{}
		default: // /v1/grants/requests/{id} — block until the client goes away
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	a := testApp()
	a.cfg.PublicURL = "https://demo.example"
	a.valet = newValetClient(srv.URL, "agent", "owner")
	emit := func(string, any) {}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan map[string]any, 1)
	go func() { done <- a.agentCheckout(ctx, "conv1", "coffee", 1, emit) }()
	<-grantCreated
	// Let the client finish requestGrant, store the entry, and enter the
	// blocking status poll — then kill its context to simulate disconnect.
	time.Sleep(100 * time.Millisecond)
	cancel()
	res := <-done
	if res["status"] != "error" {
		t.Fatalf("want error on canceled poll, got %v", res)
	}
	a.mu.Lock()
	pa := a.pending["conv1"]
	a.mu.Unlock()
	if pa == nil || pa.id != "rid1" {
		t.Fatalf("pending approval lost on client disconnect: %v", pa)
	}
}

func TestAgentCheckoutResolvesDefaultCard(t *testing.T) {
	// fake valet: handles endpoint returns the given cards; /v1/grants records
	// the handle and returns an auto-issued grant; pay replies paid.
	newFake := func(cards []map[string]any, gotHandle *string) *httptest.Server {
		var mu sync.Mutex
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/owner/handles":
				json.NewEncoder(w).Encode(map[string]any{"handles": cards})
			case "/v1/grants":
				var req map[string]any
				json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				*gotHandle, _ = req["handle"].(string)
				mu.Unlock()
				json.NewEncoder(w).Encode(map[string]any{"status": "ok", "token": "gtok"})
			case "/v1/edge/card/pay":
				json.NewEncoder(w).Encode(map[string]any{"status": "ok", "body": `{"status":"paid","last4":"1111"}`})
			default:
				json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			}
		}))
	}
	card := map[string]any{"handle": "card://personal", "metadata": `{"last4":"1111"}`}
	backup := map[string]any{"handle": "card://backup", "metadata": `{"last4":"9999"}`}

	// defaultCard "" + one card → grant for card://personal.
	var got string
	srv := newFake([]map[string]any{card}, &got)
	a := testApp()
	a.cfg.PublicURL = "https://demo.example"
	a.valet = newValetClient(srv.URL, "agent", "owner")
	a.defaultCard = ""
	res := a.agentCheckout(context.Background(), "conv1", "coffee", 1, func(string, any) {})
	srv.Close()
	if res["status"] != "paid" && res["status"] != "ok" {
		t.Fatalf("want paid, got %v", res)
	}
	if got != "card://personal" {
		t.Fatalf("grant handle: want card://personal, got %q", got)
	}

	// defaultCard "gone" + handles [backup] → uses backup.
	got = ""
	srv = newFake([]map[string]any{backup}, &got)
	a = testApp()
	a.cfg.PublicURL = "https://demo.example"
	a.valet = newValetClient(srv.URL, "agent", "owner")
	a.defaultCard = "gone"
	res = a.agentCheckout(context.Background(), "conv1", "coffee", 1, func(string, any) {})
	srv.Close()
	if got != "card://backup" {
		t.Fatalf("grant handle: want card://backup, got %q (res=%v)", got, res)
	}

	// No cards → no card saved, no grant request.
	got = ""
	srv = newFake(nil, &got)
	a = testApp()
	a.cfg.PublicURL = "https://demo.example"
	a.valet = newValetClient(srv.URL, "agent", "owner")
	a.defaultCard = ""
	res = a.agentCheckout(context.Background(), "conv1", "coffee", 1, func(string, any) {})
	srv.Close()
	if res["status"] != "error" || !strings.Contains(res["reason"].(string), "no card saved") {
		t.Fatalf("want no-card error, got %v", res)
	}
	if got != "" {
		t.Fatalf("grant request made with no card: %q", got)
	}
}
