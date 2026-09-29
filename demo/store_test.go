package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func testApp() *app {
	return &app{cfg: config{CardLabel: "personal"}, store: newDemoStore(), convs: map[string][]geminiContent{}, pending: map[string]*pendingApproval{}}
}

func TestLuhn(t *testing.T) {
	if !luhn("4111111111111111") {
		t.Fatal("valid visa rejected")
	}
	if luhn("tok_sandbox_abc") || luhn("tok_abc") {
		t.Fatal("alias accepted")
	}
	if luhn("4111111111111112") {
		t.Fatal("bad check digit accepted")
	}
}

func TestStoreCheckout(t *testing.T) {
	a := testApp()
	body := `{"order":{"items":[{"id":"coffee","qty":1}]},"card":{"number":"4111111111111111","exp_month":"12","exp_year":"2030","cvc":"123","holder":"Test"}}`
	r := httptest.NewRequest("POST", "/store/checkout", strings.NewReader(body))
	w := httptest.NewRecorder()
	a.checkoutHandler(w, r)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body)
	}
	var out map[string]any
	json.NewDecoder(w.Body).Decode(&out)
	if out["status"] != "paid" || out["last4"] != "1111" || out["total_cents"] != float64(1800) {
		t.Fatalf("bad checkout: %v", out)
	}
	// A tok_ alias fails Luhn → 402.
	body = `{"order":{"items":[{"id":"coffee","qty":1}]},"card":{"number":"tok_sandbox_x","exp_month":"12","exp_year":"2030","cvc":"tok_y","holder":"T"}}`
	r = httptest.NewRequest("POST", "/store/checkout", strings.NewReader(body))
	w = httptest.NewRecorder()
	a.checkoutHandler(w, r)
	if w.Code != 402 {
		t.Fatalf("alias checkout: want 402, got %d", w.Code)
	}
	// Unknown product → 400.
	body = `{"order":{"items":[{"id":"nope","qty":1}]},"card":{"number":"4111111111111111"}}`
	r = httptest.NewRequest("POST", "/store/checkout", strings.NewReader(body))
	w = httptest.NewRecorder()
	a.checkoutHandler(w, r)
	if w.Code != 400 {
		t.Fatalf("unknown product: want 400, got %d", w.Code)
	}
	// Qty outside 1-10 → 400.
	for _, qty := range []int{0, 11} {
		body = fmt.Sprintf(`{"order":{"items":[{"id":"coffee","qty":%d}]},"card":{"number":"4111111111111111"}}`, qty)
		r = httptest.NewRequest("POST", "/store/checkout", strings.NewReader(body))
		w = httptest.NewRecorder()
		a.checkoutHandler(w, r)
		if w.Code != 400 {
			t.Fatalf("qty=%d: want 400, got %d", qty, w.Code)
		}
	}
}

func TestSSEEncoding(t *testing.T) {
	w := httptest.NewRecorder()
	f := &fakeFlusher{w}
	emitJSON(w, f, "receipt", map[string]any{"order_id": "o1", "total_cents": 1800})
	out := w.Body.String()
	if !strings.Contains(out, "event: receipt") || !strings.Contains(out, `"order_id":"o1"`) {
		t.Fatalf("bad SSE: %q", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Fatalf("SSE frame not terminated: %q", out)
	}
}

type fakeFlusher struct{ *httptest.ResponseRecorder }

func (f *fakeFlusher) Flush() {}

func TestProducts(t *testing.T) {
	a := testApp()
	r := httptest.NewRequest("GET", "/store/products", nil)
	w := httptest.NewRecorder()
	a.productsHandler(w, r)
	var out map[string]any
	json.NewDecoder(w.Body).Decode(&out)
	if n := len(out["products"].([]any)); n != 6 {
		t.Fatalf("want 6 products, got %d", n)
	}
}

func TestChatRequiresMessage(t *testing.T) {
	a := testApp()
	r := httptest.NewRequest("POST", "/api/chat", bytes.NewReader([]byte(`{"conversation_id":"c1"}`)))
	w := httptest.NewRecorder()
	a.chatHandler(w, r)
	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
}
