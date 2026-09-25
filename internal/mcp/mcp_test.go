package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "vlt_secret-token"

func newBackend(t *testing.T, handler http.HandlerFunc) *HTTPBackend {
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &HTTPBackend{Base: ts.URL, Token: testToken}
}

func TestListHandles(t *testing.T) {
	var gotAuth string
	b := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/handles" || r.Method != "GET" {
			t.Errorf("bad request %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"handles": []any{map[string]any{"handle": "cred://x/y"}}})
	})
	out, err := b.ListHandles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+testToken {
		t.Fatalf("auth header %q", gotAuth)
	}
	m := out.(map[string]any)
	if len(m["handles"].([]any)) != 1 {
		t.Fatalf("bad handles: %v", m)
	}
}

func TestRequestGrant(t *testing.T) {
	b := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["handle"] != "cred://x/y" || body["ttl"] != float64(1800) {
			t.Errorf("bad body %v", body)
		}
		json.NewEncoder(w).Encode(map[string]any{"grant_id": "g1", "token": "g1.sig"})
	})
	out, err := b.RequestGrant(context.Background(), "cred://x/y", `{"hosts":["x.com"]}`, "30m")
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["grant_id"] != "g1" {
		t.Fatalf("bad out %v", out)
	}
}

func TestBrowserFill(t *testing.T) {
	b := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edge/browser/fill" {
			t.Errorf("bad path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})
	out, err := b.BrowserFill(context.Background(), "g.sig", "ws://x", map[string]string{"username": "#u"}, "#submit")
	if err != nil || out.(map[string]any)["status"] != "ok" {
		t.Fatal(err, out)
	}
}

func TestErrorRedactsToken(t *testing.T) {
	b := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"invalid Authorization: Bearer ` + testToken + `"}`))
	})
	_, err := b.ListHandles(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("token leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("want redaction: %v", err)
	}
}

func TestPay(t *testing.T) {
	b := newBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"status":"not_implemented"}`))
	})
	_, err := b.Pay(context.Background(), "g.sig", "shop.com", 500, "USD", "")
	if err == nil || !strings.Contains(err.Error(), "501") {
		t.Fatalf("want 501 error, got %v", err)
	}
}
