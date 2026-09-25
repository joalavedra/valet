package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	out, err := b.BrowserFill(context.Background(), "g.sig", "ws://x", map[string]string{"username": "#u"}, "#submit", "https://example.com/login")
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
	_, err := b.Pay(context.Background(), "g.sig", "https://shop.com/charge", "POST", nil, `{"pan":"{{card.number}}"}`, 500, "USD")
	if err == nil || !strings.Contains(err.Error(), "501") {
		t.Fatalf("want 501 error, got %v", err)
	}
}

func TestHTTPCallRoundTrip(t *testing.T) {
	var got map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edge/http/call" {
			t.Errorf("path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Error("missing bearer")
		}
		json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"status":200,"headers":{},"body":"ok"}`)
	}))
	defer api.Close()
	b := &HTTPBackend{Base: api.URL, Token: "tok"}
	out, err := b.HTTPCall(context.Background(), "g1", "GET", "https://api.stripe.com/v1/x", `{"X-A":"1"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["status"] != float64(200) || m["body"] != "ok" {
		t.Fatalf("out %v", m)
	}
	if got["grant_token"] != "g1" || got["method"] != "GET" || got["url"] != "https://api.stripe.com/v1/x" {
		t.Fatalf("payload %v", got)
	}
	if h, ok := got["headers"].(map[string]any); !ok || h["X-A"] != "1" {
		t.Fatalf("headers %v", got["headers"])
	}
}

type stubBackend struct{}

func (stubBackend) ListHandles(ctx context.Context) (any, error) {
	return map[string]any{"handles": []any{map[string]any{"handle": "cred://x/y"}}}, nil
}
func (stubBackend) RequestGrant(ctx context.Context, handle, policyJSON, ttl string) (any, error) {
	return nil, nil
}
func (stubBackend) BrowserFill(ctx context.Context, grant, cdpWSURL string, mapping map[string]string, submit, pageURL string) (any, error) {
	return nil, nil
}
func (stubBackend) HTTPCall(ctx context.Context, grant, method, url, headersJSON, body string) (any, error) {
	return nil, nil
}
func (stubBackend) Pay(ctx context.Context, grant, url, method string, headers map[string]string, body string, amount int64, currency string) (any, error) {
	return nil, nil
}

func TestRunHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	go func() { _ = RunHTTP(ctx, stubBackend{}, addr, "") }()
	var client *mcp.Client
	var cs *mcp.ClientSession
	deadline := time.Now().Add(5 * time.Second)
	for {
		client = mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.1"}, nil)
		cs, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + addr + "/mcp"}, nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	if !names["list_handles"] {
		t.Fatalf("tools: %v", names)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_handles"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "cred://x/y") {
		t.Fatalf("result: %+v", res.Content[0])
	}
}

func TestHandlerAuth(t *testing.T) {
	h := Handler(stubBackend{}, "s3cret")
	for _, tc := range []struct {
		name string
		auth string
		want int
		noSt bool
	}{
		{"no header", "", 401, true},
		{"wrong token", "Bearer nope", 401, true},
		{"right token", "Bearer s3cret", 400, false}, // streamable handler rejects bare GET but auths pass
	} {
		r := httptest.NewRequest("GET", "/mcp", nil)
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if tc.want == 401 {
			if rec.Code != 401 {
				t.Fatalf("%s: got %d", tc.name, rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s: missing no-store", tc.name)
			}
		} else if rec.Code == 401 {
			t.Fatalf("%s: got 401", tc.name)
		}
	}
}

func TestLoopbackAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1", true}, {"localhost:1", true}, {"[::1]:1", true},
		{":1", false}, {"0.0.0.0:1", false}, {"10.0.0.1:1", false}, {"[::]:1", false},
	} {
		if got := loopbackAddr(tc.addr); got != tc.want {
			t.Errorf("loopbackAddr(%q)=%v want %v", tc.addr, got, tc.want)
		}
	}
}

func TestRunHTTPNonLoopbackNoToken(t *testing.T) {
	if err := RunHTTP(context.Background(), stubBackend{}, "0.0.0.0:1", ""); err == nil ||
		!strings.Contains(err.Error(), "VALET_MCP_TOKEN") {
		t.Fatalf("err=%v", err)
	}
}
