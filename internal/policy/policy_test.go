package policy

import (
	"testing"
	"time"
)

var now = time.Now()

func TestEvaluate(t *testing.T) {
	g := &GrantView{ExpiresAt: now.Add(time.Hour), Uses: 0, MaxUses: 0}
	tests := []struct {
		name string
		p    *Policy
		g    *GrantView
		req  Request
		want bool
	}{
		{"empty policy allows", &Policy{}, g, Request{Host: "x.com"}, true},
		{"expired denied", &Policy{}, &GrantView{ExpiresAt: now.Add(-time.Hour)}, Request{}, false},
		{"max uses", &Policy{}, &GrantView{ExpiresAt: now.Add(time.Hour), Uses: 2, MaxUses: 2}, Request{}, false},
		{"host allowed", &Policy{Hosts: []string{"*.github.com"}}, g, Request{Host: "api.github.com"}, true},
		{"host bare match", &Policy{Hosts: []string{"*.github.com"}}, g, Request{Host: "github.com"}, true},
		{"host denied", &Policy{Hosts: []string{"*.github.com"}}, g, Request{Host: "evil.com"}, false},
		{"method denied", &Policy{Methods: []string{"GET"}}, g, Request{Method: "POST"}, false},
		{"method ok", &Policy{Methods: []string{"GET"}}, g, Request{Method: "get"}, true},
		{"path glob", &Policy{Paths: []string{"/v1/*"}}, g, Request{Path: "/v1/charges"}, true},
		{"path denied", &Policy{Paths: []string{"/v1/*"}}, g, Request{Path: "/admin"}, false},
		{"spend per-tx", &Policy{Spend: &SpendPolicy{PerTx: 100}}, g, Request{Amount: 200, Merchant: "m"}, false},
		{"spend ok", &Policy{Spend: &SpendPolicy{PerTx: 100, Merchants: []string{"amazon.com"}, Currency: "USD"}}, g, Request{Amount: 50, Merchant: "amazon.com", Currency: "USD"}, true},
		{"merchant denied", &Policy{Spend: &SpendPolicy{Merchants: []string{"amazon.com"}}}, g, Request{Amount: 50, Merchant: "ebay.com"}, false},
		{"currency denied", &Policy{Spend: &SpendPolicy{Currency: "USD"}}, g, Request{Amount: 50, Currency: "EUR"}, false},
	}
	for _, tc := range tests {
		tc.req.Now = now
		got := Evaluate(tc.p, tc.g, tc.req)
		if got.Allow != tc.want {
			t.Errorf("%s: got allow=%v reason=%q, want %v", tc.name, got.Allow, got.Reason, tc.want)
		}
	}
}

func TestGlobMatchPathSubtree(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"/api/*", "/api/v1/charges", true},
		{"/api/*", "/api/x", true},
		{"/api/*", "/other/x", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.value); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.value, got, c.want)
		}
	}
}
