package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
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
	a.pending["conv1"] = "rid1"

	var events []string
	var mu sync.Mutex
	emit := func(ev string, _ any) { mu.Lock(); events = append(events, ev); mu.Unlock() }

	res := a.agentCheckout(context.Background(), "conv1", "coffee", 1, emit)
	if res["status"] != "pending_approval" {
		t.Fatalf("want pending_approval, got %v", res)
	}
	if grantCalls != 0 {
		t.Fatalf("new grant request created despite pending approval (calls=%d)", grantCalls)
	}
	var sawApproval bool
	for _, e := range events {
		if e == "approval_required" {
			sawApproval = true
		}
	}
	if !sawApproval {
		t.Fatal("approval_required not re-emitted for existing request")
	}
}
