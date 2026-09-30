package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/edge/card"
	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/edge/wallet"
	mppedg "github.com/joalavedra/valet/internal/edge/wallet/mpp"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/handle"
	"github.com/joalavedra/valet/internal/store"
	"github.com/tempoxyz/mpp-go/pkg/tempo"
)

type fakeFiller struct {
	pageURL    string
	gotValues  map[string]string
	gotCDP     string
	fillErr    error
	fillStatus browser.Result
	resolveWS  string
	resolveErr error
}

func (f *fakeFiller) PageURL(ctx context.Context, ws string) (string, error) {
	return f.pageURL, nil
}

func (f *fakeFiller) ResolvePage(ctx context.Context, cdpURL, pageURL string) (string, error) {
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	return f.resolveWS, nil
}

func (f *fakeFiller) Fill(ctx context.Context, ws, expectedHost string, mapping map[string]string, submit string, values map[string]string) (browser.Result, error) {
	f.gotCDP = ws
	cp := map[string]string{}
	for k, v := range values {
		cp[k] = v
	}
	f.gotValues = cp
	if f.fillErr != nil {
		return f.fillStatus, f.fillErr
	}
	return browser.Result{Status: browser.StatusOK}, nil
}

func testServer(t *testing.T) (*Server, *store.SQLite, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dek, _ := crypto.GenerateDEK()
	srv := New(st, grant.NewIssuer(st, dek), audit.New(st), &fakeFiller{pageURL: "https://github.com/login"}, dek, nil)
	token := "tok-abc"
	if _, err := st.CreateAgent("bot", hashToken(token)); err != nil {
		t.Fatal(err)
	}
	pt, _ := json.Marshal(map[string]string{"username": "joan", "password": "SuperSecretPassword!", "totp_seed": "JBSWY3DPEHPK3PXP"})
	ct, _ := crypto.Encrypt(dek, pt)
	if err := st.AddCredential(&store.Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: "{}", Ciphertext: ct}); err != nil {
		t.Fatal(err)
	}
	return srv, st, token
}

func issueGrant(t *testing.T, srv *Server, st *store.SQLite, agentTok, policyJSON string, ttl time.Duration) string {
	t.Helper()
	return issueGrantHandle(t, srv, st, agentTok, "cred://github.com/joan", policyJSON, ttl)
}

func issueGrantHandle(t *testing.T, srv *Server, st *store.SQLite, agentTok, handleID, policyJSON string, ttl time.Duration) string {
	t.Helper()
	a, err := st.GetAgentByTokenHash(hashToken(agentTok))
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.issuer.Issue(a.ID, handleID, policyJSON, ttl, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func fillReq(t *testing.T, agentTok string, body map[string]any) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/edge/browser/fill", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	return httptest.NewRecorder(), req
}

func TestHealthz(t *testing.T) {
	srv, _, _ := testServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHandlesAuth(t *testing.T) {
	srv, _, tok := testServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/handles", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth: got %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/v1/handles", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	var body struct {
		Handles []map[string]any `json:"handles"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if len(body.Handles) != 1 || body.Handles[0]["handle"] != "cred://github.com/joan" {
		t.Fatalf("bad body: %v", body.Handles)
	}
	if _, has := body.Handles[0]["ciphertext"]; has {
		t.Fatal("ciphertext must not be exposed")
	}
}

func TestCreateGrant(t *testing.T) {
	srv, _, tok := testServer(t)
	payload, _ := json.Marshal(map[string]any{
		"handle":   "cred://github.com/joan",
		"policy":   map[string]any{"hosts": []string{"github.com"}},
		"ttl":      600,
		"max_uses": 3,
	})
	req := httptest.NewRequest("POST", "/v1/grants", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	var body struct {
		GrantID string `json:"grant_id"`
		Token   string `json:"token"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.Token == "" || body.GrantID == "" {
		t.Fatalf("missing grant fields: %v", body)
	}
}

func TestCreateGrantRequireHuman(t *testing.T) {
	srv, _, tok := testServer(t)
	payload, _ := json.Marshal(map[string]any{
		"handle": "cred://github.com/joan",
		"policy": map[string]any{"require_human": true},
	})
	req := httptest.NewRequest("POST", "/v1/grants", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestBrowserFillHappyPath(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Hour)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": gtok,
		"cdp_ws_url":  "ws://127.0.0.1:9222",
		"mapping":     map[string]string{"username": "#u", "password": "#p", "otp": "#otp"},
		"submit":      "#go",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("bad status %v", body)
	}
	if strings.Contains(rec.Body.String(), "SuperSecretPassword!") {
		t.Fatal("password leaked in response")
	}
	last, err := st.LastAudit()
	if err != nil {
		t.Fatal(err)
	}
	if last.Edge != "browser" || last.Target != "github.com" || last.Decision != "allow" {
		t.Fatalf("bad audit row %+v", last)
	}
	f := srv.filler.(*fakeFiller)
	if f.gotValues["password"] != "SuperSecretPassword!" {
		t.Fatal("filler did not get password")
	}
	if len(f.gotValues["otp"]) != 6 {
		t.Fatalf("want 6-digit totp, got %q", f.gotValues["otp"])
	}
	if _, ok := f.gotValues["totp_seed"]; ok {
		t.Fatal("totp_seed must not reach the filler")
	}
}

func TestBrowserFillHostDenied(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["allowed.com"]}`, time.Hour)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": gtok, "cdp_ws_url": "ws://127.0.0.1:9222",
		"mapping": map[string]string{"password": "#p"},
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	last, _ := st.LastAudit()
	if last.Decision != "deny" || last.Edge != "browser" {
		t.Fatalf("want deny audit row, got %+v", last)
	}
}

func TestBrowserFillCDPHostDenied(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Hour)
	rec, req := fillReq(t, tok, map[string]any{"grant_token": gtok, "cdp_ws_url": "ws://evil.example:9222", "mapping": map[string]string{"password": "#p"}})
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	last, _ := st.LastAudit()
	if !strings.Contains(last.Detail, "cdp_host_denied") {
		t.Fatalf("audit detail %q", last.Detail)
	}
}

func TestBrowserFillEmptyPageURL(t *testing.T) {
	srv, st, tok := testServer(t)
	srv.filler = &fakeFiller{}
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Hour)
	rec, req := fillReq(t, tok, map[string]any{"grant_token": gtok, "cdp_ws_url": "ws://127.0.0.1:9222", "mapping": map[string]string{"password": "#p"}})
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	last, _ := st.LastAudit()
	if !strings.Contains(last.Detail, "no_page_url") {
		t.Fatalf("audit detail %q", last.Detail)
	}
}

func TestBrowserFillExpiredGrant(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, -time.Hour)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": gtok, "cdp_ws_url": "ws://127.0.0.1:9222",
		"mapping": map[string]string{"password": "#p"},
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

// fakeProvider short-circuits card.Do to a local upstream (no real proxy).
type fakeProvider struct {
	upstream *httptest.Server
	err      error
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Transport() (http.RoundTripper, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.upstream != nil {
		// TLS test server: trust its cert.
		return f.upstream.Client().Transport, nil
	}
	return http.DefaultTransport, nil
}
func (f *fakeProvider) CaptureConfig() (card.CaptureConfig, error) {
	return card.CaptureConfig{Provider: "fake"}, nil
}

// inspectorProvider adds AliasInspector to fakeProvider.
type inspectorProvider struct {
	fakeProvider
	last4, bin string
	err        error
}

func (p *inspectorProvider) InspectAlias(_ context.Context, _ string) (string, string, error) {
	return p.last4, p.bin, p.err
}

func cardCred(t *testing.T, srv *Server, st *store.SQLite) {
	t.Helper()
	dek := srv.dek
	pt, _ := json.Marshal(map[string]string{
		"number": "tok_card_123", "exp_month": "12", "exp_year": "2030", "holder": "Joan",
	})
	ct, err := crypto.Encrypt(dek, pt)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddCredential(&store.Credential{
		Handle: "card://visa-4242", Type: "card", Label: "visa-4242",
		Metadata: `{"provider":"vgs"}`, Ciphertext: ct,
	}); err != nil {
		t.Fatal(err)
	}
}

func payReq(t *testing.T, tok string, body map[string]any) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/edge/card/pay", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	return httptest.NewRecorder(), req
}

func TestCardPayDeniedMerchant(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	srv.SetCardProvider(&fakeProvider{})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"per_tx":10000,"merchants":["shop.com"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://evil.com/charge", "amount": 50, "currency": "USD",
		"body": `{"amount":"{{card.number}}"}`, "method": "POST",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCardPayAmountOverLimit(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	srv.SetCardProvider(&fakeProvider{})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"per_tx":100,"merchants":["shop.com"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://shop.com/charge", "amount": 5000, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCardPayNonCardHandle(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://shop.com/charge", "amount": 1, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "not for a card handle") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCardPaySuccess(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "tok_card_123") {
			t.Error("placeholder not substituted")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"charged":true}`)
	}))
	defer upstream.Close()
	srv.SetCardProvider(&fakeProvider{upstream: upstream})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"merchants":["*"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": upstream.URL + "/charge", "method": "POST",
		"body":   `{"pan":"{{card.number}}","exp":"{{card.exp_month}}/{{card.exp_year}}","cvc":""}`,
		"amount": 50, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Status     string `json:"status"`
		HTTPStatus int    `json:"http_status"`
		Body       string `json:"body"`
	}
	json.NewDecoder(rec.Body).Decode(&out)
	if out.Status != "ok" || out.HTTPStatus != 200 || !strings.Contains(out.Body, "charged") {
		t.Fatalf("bad response: %v", out)
	}
}

func TestCardPayErrorNoLeak(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	srv.SetCardProvider(&fakeProvider{err: fmt.Errorf("dial tok_card_123 boom")})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"merchants":["*"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://shop.com/x", "amount": 1, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 502 || strings.Contains(rec.Body.String(), "tok_card_123") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

// egressFixture wires a fake Agent Vault: /discover advertising one
// service, and a forward proxy that injects X-Injected and forwards to the
// upstream.
func egressFixture(t *testing.T, upstream *httptest.Server) (*httptest.Server, *httptest.Server, *map[string]string) {
	t.Helper()
	saw := &map[string]string{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, upstream.URL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		req.Header.Set("X-Injected", "1")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		b := make([]byte, 8<<10)
		for {
			n, err := resp.Body.Read(b)
			w.Write(b[:n])
			if err != nil {
				break
			}
		}
	}))
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := upstream.URL[len("http://"):]
		fmt.Fprintf(w, `{"vault":"v","services":[{"name":"echo","host":%q}],"available_credentials":["K"]}`, host)
	}))
	t.Cleanup(func() { proxy.Close(); api.Close() })
	return proxy, api, saw
}

func httpCallServer(t *testing.T, proxy, api *httptest.Server) (*Server, *store.SQLite, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dek, _ := crypto.GenerateDEK()
	eg, err := egress.New(&egress.Config{ProxyURL: "http://u:v@" + proxy.URL[len("http://"):], Addr: api.URL, Token: "tok", Vault: "v"})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, grant.NewIssuer(st, dek), audit.New(st), nil, dek, eg)
	token := "tok-abc"
	if _, err := st.CreateAgent("bot", hashToken(token)); err != nil {
		t.Fatal(err)
	}
	return srv, st, token
}

func grantFor(t *testing.T, srv *Server, agentID int64, handle, policyJSON string) string {
	t.Helper()
	gtok, _, err := srv.issuer.Issue(agentID, handle, policyJSON, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	return gtok
}

func TestHTTPCallEndToEnd(t *testing.T) {
	var sawInjected bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawInjected = r.Header.Get("X-Injected") == "1"
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	proxy, api, _ := egressFixture(t, upstream)
	srv, st, tok := httpCallServer(t, proxy, api)
	a, _ := st.GetAgentByTokenHash(hashToken(tok))

	// handles must list api://echo.
	req := httptest.NewRequest("GET", "/v1/handles", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var hb struct {
		Handles []map[string]any `json:"handles"`
	}
	json.NewDecoder(rec.Body).Decode(&hb)
	found := false
	for _, h := range hb.Handles {
		if h["handle"] == "api://echo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("api://echo missing: %v", hb.Handles)
	}

	// grant for api://echo via POST /v1/grants.
	payload, _ := json.Marshal(map[string]any{"handle": "api://echo", "policy": map[string]any{}})
	req = httptest.NewRequest("POST", "/v1/grants", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("grant: %d %s", rec.Code, rec.Body)
	}
	var gb struct {
		Token string `json:"token"`
	}
	json.NewDecoder(rec.Body).Decode(&gb)

	call := func(grant, url string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"grant_token": grant, "method": "GET", "url": url})
		r := httptest.NewRequest("POST", "/v1/edge/http/call", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, r)
		return rr
	}
	rec = call(gb.Token, upstream.URL+"/v1/x")
	if rec.Code != 200 {
		t.Fatalf("call: %d %s", rec.Code, rec.Body)
	}
	if !sawInjected {
		t.Fatal("upstream did not see injected header")
	}
	var res map[string]any
	json.NewDecoder(rec.Body).Decode(&res)
	if res["status"] != float64(200) {
		t.Fatalf("res %v", res)
	}

	// different host -> service_mismatch, audited.
	rec = call(gb.Token, "http://example.org/x")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatch: %d", rec.Code)
	}
	entries, _ := st.ListAudit(10)
	denySeen := false
	for _, e := range entries {
		if e.Edge == "http" && e.Decision == "deny" && strings.Contains(e.Detail, "service_mismatch") {
			denySeen = true
		}
	}
	if !denySeen {
		t.Fatal("service_mismatch deny not audited")
	}
	_ = a
}

func TestHTTPCallUnknownAPIHandleGrant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	proxy, api, _ := egressFixture(t, upstream)
	srv, _, tok := httpCallServer(t, proxy, api)
	payload, _ := json.Marshal(map[string]any{"handle": "api://nope", "policy": map[string]any{}})
	req := httptest.NewRequest("POST", "/v1/grants", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHTTPCallExpiredGrant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	proxy, api, _ := egressFixture(t, upstream)
	srv, st, tok := httpCallServer(t, proxy, api)
	a, _ := st.GetAgentByTokenHash(hashToken(tok))
	gtok, _, err := srv.issuer.Issue(a.ID, "api://echo", `{}`, -time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"grant_token": gtok, "method": "GET", "url": upstream.URL})
	req := httptest.NewRequest("POST", "/v1/edge/http/call", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestFillPageURLResolves(t *testing.T) {
	srv, st, tok := testServer(t)
	srv.filler = &fakeFiller{pageURL: "https://github.com/login", resolveWS: "ws://127.0.0.1:9222/devtools/page/P1"}
	g := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Minute)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": g, "cdp_ws_url": "ws://127.0.0.1:9222/devtools/browser/x",
		"page_url": "https://github.com/login", "mapping": map[string]string{"u": "#u"},
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	ff := srv.filler.(*fakeFiller)
	if ff.gotCDP != "ws://127.0.0.1:9222/devtools/page/P1" {
		t.Fatalf("Fill used %q, want resolved ws", ff.gotCDP)
	}
}

func TestFillDefaultCDP(t *testing.T) {
	srv, st, tok := testServer(t)
	srv.filler = &fakeFiller{pageURL: "https://github.com/login"}
	srv.SetCDPDefault("http://127.0.0.1:9222")
	g := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Minute)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": g, "mapping": map[string]string{"u": "#u"},
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFillMissingCDP(t *testing.T) {
	srv, _, tok := testServer(t)
	rec, req := fillReq(t, tok, map[string]any{"grant_token": "x", "mapping": map[string]string{"u": "#u"}})
	srv.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "cdp_ws_url required") {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFillPageResolveError(t *testing.T) {
	srv, st, tok := testServer(t)
	srv.filler = &fakeFiller{resolveErr: fmt.Errorf("page not found")}
	srv.SetCDPDefault("http://127.0.0.1:9222")
	g := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, time.Minute)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": g, "page_url": "https://github.com/nope", "mapping": map[string]string{"u": "#u"},
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	audits, err := st.ListAudit(10)
	if err != nil || len(audits) == 0 || !strings.Contains(audits[len(audits)-1].Detail, "page_not_found") {
		t.Fatalf("audit: %v %v", audits, err)
	}
}

func TestCardPayCVCRequired(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st) // no cvc field stored
	srv.SetCardProvider(&fakeProvider{})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"merchants":["*"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://shop.com/charge", "amount": 50, "currency": "USD",
		"body": `{"cvc":"{{card.cvc}}"}`,
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "need_cvc") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	// Grant must not be consumed by the fill failure.
	if _, err := srv.issuer.Verify(gtok, agentID(t, st, tok)); err != nil {
		t.Fatalf("grant should still verify: %v", err)
	}
	audits, _ := st.ListAudit(10)
	if !strings.Contains(audits[len(audits)-1].Detail, "cvc_required") {
		t.Fatalf("audit: %v", audits[len(audits)-1].Detail)
	}
}

func TestCardPayAmountRequired(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	srv.SetCardProvider(&fakeProvider{})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"per_tx":100,"merchants":["*"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://shop.com/charge", "amount": 0, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "amount required") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCardPayUnscopedGrant(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	srv.SetCardProvider(&fakeProvider{})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": "https://shop.com/charge", "amount": 50, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "restrict merchants") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCardPayStatusMapping(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	code := 402
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	defer upstream.Close()
	srv.SetCardProvider(&fakeProvider{upstream: upstream})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242", `{"spend":{"merchants":["*"]}}`, time.Hour)
	rec, req := payReq(t, tok, map[string]any{
		"grant_token": gtok, "url": upstream.URL, "amount": 50, "currency": "USD",
	})
	srv.ServeHTTP(rec, req)
	var out struct {
		Status string `json:"status"`
	}
	json.NewDecoder(rec.Body).Decode(&out)
	if rec.Code != 200 || out.Status != "declined" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func agentID(t *testing.T, st *store.SQLite, tok string) int64 {
	t.Helper()
	a, err := st.GetAgentByTokenHash(hashToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// ---- capture endpoints ----

func newCapture(t *testing.T, st *store.SQLite, label string, ttl time.Duration) string {
	t.Helper()
	tok := "cap-" + randToken(8)
	if err := st.CreateCapture(&store.Capture{
		Token: tok, Label: label, Metadata: `{"provider":"vgs"}`, ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i%36]
	}
	return string(b)
}

func capReq(t *testing.T, srv *Server, method, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestCapturePageRenders(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-x", time.Hour)
	rec := capReq(t, srv, "GET", "/capture/"+tok, nil)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "vgs-collect") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bad page: %s", rec.Header())
	}
}

func TestCapturePageGone(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-x", -time.Hour) // expired
	rec := capReq(t, srv, "GET", "/capture/"+tok, nil)
	if rec.Code != 404 {
		t.Fatalf("got %d", rec.Code)
	}
	rec = capReq(t, srv, "GET", "/capture/nope", nil)
	if rec.Code != 404 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestCaptureCompleteHappy(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-live", time.Hour)
	body := map[string]any{
		"number": "tok_sandbox_pan1", "cvc": "tok_cvc1", "exp_month": "12",
		"exp_year": "2030", "holder": "Test", "last4": "1111",
	}
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "card://visa-live") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	cred, err := st.GetCredential("card://visa-live")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Type != "card" || !strings.Contains(cred.Metadata, `"source":"collect"`) {
		t.Fatalf("cred: %v %s", cred.Type, cred.Metadata)
	}
	// second POST → gone
	rec = capReq(t, srv, "POST", "/capture/"+tok+"/complete", body)
	if rec.Code != 404 && rec.Code != 410 {
		t.Fatalf("second POST got %d", rec.Code)
	}
	// audit has a capture allow
	audits, _ := st.ListAudit(10)
	found := false
	for _, a := range audits {
		if a.Edge == "card" && a.Target == "capture" {
			found = true
		}
	}
	if !found {
		t.Fatal("no capture audit")
	}
}

func TestCaptureCompleteRejectsPAN(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-x", time.Hour)
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "4111111111111111", "exp_month": "12", "exp_year": "2030", "holder": "T",
	})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "raw card data rejected") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	// capture must remain unused
	c, _ := st.GetCapture(tok)
	if c.UsedAt != nil {
		t.Fatal("capture consumed on reject")
	}
}

func TestCaptureCompleteRejectsBadExp(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-x", time.Hour)
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_x", "exp_month": "13", "exp_year": "2030",
	})
	if rec.Code != 400 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestCaptureCompleteRejectsNonTokAlias(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-x", time.Hour)
	// A FPE format-preserving alias is a Luhn-valid PAN — must be rejected.
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "4111112771441111", "exp_month": "12", "exp_year": "2030",
	})
	if rec.Code != 400 {
		t.Fatalf("FPE alias accepted: %d %s", rec.Code, rec.Body)
	}
	// A non-tok_ non-numeric string is rejected too.
	rec = capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "not-an-alias", "exp_month": "12", "exp_year": "2030",
	})
	if rec.Code != 400 {
		t.Fatalf("non-tok string accepted: %d %s", rec.Code, rec.Body)
	}
}

func TestCaptureCompleteNumericCVC(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-num", time.Hour)
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_sandbox_pan2", "cvc": "123", "exp_month": "12",
		"exp_year": "2030", "holder": "T", "bin": "411111",
	})
	if rec.Code != 200 {
		t.Fatalf("numeric cvc rejected: %d %s", rec.Code, rec.Body)
	}
	cred, err := st.GetCredential("card://visa-num")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cred.Metadata, `"bin":"411111"`) {
		t.Fatalf("metadata: %s", cred.Metadata)
	}
}

func TestCaptureCompleteRejectsLongCVC(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-x", time.Hour)
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_sandbox_pan1", "cvc": "4111111111111111",
		"exp_month": "12", "exp_year": "2030",
	})
	if rec.Code != 400 {
		t.Fatalf("16-digit cvc accepted: %d", rec.Code)
	}
}

func TestCaptureCompleteRejectsExpired(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-old", time.Hour)
	now := time.Now().UTC()
	// past year → expired
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_x", "exp_month": "12", "exp_year": "2020",
	})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "card expired") {
		t.Fatalf("past year: got %d %s", rec.Code, rec.Body)
	}
	// earlier month this year → expired
	if now.Month() > 1 {
		rec = capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
			"number": "tok_x", "exp_month": "1", "exp_year": strconv.Itoa(now.Year()),
		})
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "card expired") {
			t.Fatalf("past month: got %d %s", rec.Code, rec.Body)
		}
	}
	// far-future year → bad exp_year
	rec = capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_x", "exp_month": "12", "exp_year": strconv.Itoa(now.Year() + 31),
	})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad exp_year") {
		t.Fatalf("far year: got %d %s", rec.Code, rec.Body)
	}
	// capture must NOT be consumed — a valid completion still succeeds
	c, _ := st.GetCapture(tok)
	if c.UsedAt != nil {
		t.Fatal("capture consumed on reject")
	}
	rec = capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_x", "exp_month": strconv.Itoa(int(now.Month())), "exp_year": strconv.Itoa(now.Year()),
	})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "card://visa-old") {
		t.Fatalf("current month: got %d %s", rec.Code, rec.Body)
	}
}

// addCard stores a card credential and returns its handle.
func addCard(t *testing.T, st *store.SQLite, srv *Server, dek []byte, label string) string {
	t.Helper()
	h, err := handle.New("card", "", label)
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := json.Marshal(map[string]string{"number": "tok_123", "cvc": "123"})
	ct, _ := crypto.Encrypt(dek, pt)
	if err := st.AddCredential(&store.Credential{Handle: h.String(), Type: "card", Label: label, Metadata: `{"provider":"vgs"}`, Ciphertext: ct}); err != nil {
		t.Fatal(err)
	}
	return h.String()
}

// approvalServer builds a server with the given approval mode and a card
// credential; returns srv, store, dek, agent token, owner token.
func approvalServer(t *testing.T, mode string) (*Server, *store.SQLite, []byte, string, string) {
	t.Helper()
	t.Setenv("VALET_REQUIRE_APPROVAL", mode)
	t.Setenv("VALET_OWNER_TOKEN", "owner-tok")
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dek, _ := crypto.GenerateDEK()
	srv := New(st, grant.NewIssuer(st, dek), audit.New(st), &fakeFiller{pageURL: "https://github.com/login"}, dek, nil)
	token := "tok-abc"
	if _, err := st.CreateAgent("bot", hashToken(token)); err != nil {
		t.Fatal(err)
	}
	return srv, st, dek, token, "owner-tok"
}

func doJSON(t *testing.T, srv *Server, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	out := map[string]any{}
	json.NewDecoder(rec.Body).Decode(&out)
	return rec.Code, out
}

func TestCardGrantRequiresApproval(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	code, out := doJSON(t, srv, "POST", "/v1/grants", tok,
		map[string]any{"handle": h, "purpose": "coffee", "ttl": 600})
	if code != 202 || out["status"] != "pending_approval" {
		t.Fatalf("want 202 pending, got %d %v", code, out)
	}
	rid, _ := out["request_id"].(string)
	if rid == "" || out["approve_url"] != "/approve/"+rid {
		t.Fatalf("bad 202 body: %v", out)
	}
	// Agent poll: still pending.
	code, out = doJSON(t, srv, "GET", "/v1/grants/requests/"+rid, tok, nil)
	if code != 200 || out["status"] != "pending" {
		t.Fatalf("want pending, got %d %v", code, out)
	}
	// Owner sees it listed.
	code, out = doJSON(t, srv, "GET", "/v1/owner/approvals?status=pending", own, nil)
	if code != 200 {
		t.Fatalf("owner list: %d %v", code, out)
	}
	list := out["approvals"].([]any)
	if len(list) != 1 {
		t.Fatalf("want 1 approval, got %v", out)
	}
	a0 := list[0].(map[string]any)
	if a0["purpose"] != "coffee" || a0["agent"] != "bot" || a0["type"] != "card" || a0["label"] != "amex" {
		t.Fatalf("bad approval view: %v", a0)
	}
	// Approve.
	code, out = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	if code != 200 || out["status"] != "approved" || out["grant_id"] == nil {
		t.Fatalf("approve: %d %v", code, out)
	}
	// Agent poll now returns a usable token.
	code, out = doJSON(t, srv, "GET", "/v1/grants/requests/"+rid, tok, nil)
	if code != 200 || out["status"] != "approved" {
		t.Fatalf("want approved, got %d %v", code, out)
	}
	gtoken, _ := out["token"].(string)
	if _, err := srv.issuer.Verify(gtoken, 1); err != nil {
		t.Fatalf("issued token doesn't verify: %v", err)
	}
	// Approve twice → 409.
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	if code != 409 {
		t.Fatalf("second approve: want 409, got %d", code)
	}
	// Grant shows in owner grant list as active.
	code, out = doJSON(t, srv, "GET", "/v1/owner/grants", own, nil)
	glist := out["grants"].([]any)
	if len(glist) != 1 || glist[0].(map[string]any)["active"] != true {
		t.Fatalf("bad grants list: %v", glist)
	}
	gid := glist[0].(map[string]any)["id"].(string)
	// Revoke → token stops verifying, edge returns 403.
	code, _ = doJSON(t, srv, "POST", "/v1/owner/grants/"+gid+"/revoke", own, nil)
	if code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if _, err := srv.issuer.Verify(gtoken, 1); !errors.Is(err, grant.ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
	code, out = doJSON(t, srv, "POST", "/v1/edge/browser/fill", tok,
		map[string]any{"grant_token": gtoken, "cdp_ws_url": "ws://127.0.0.1:9222", "mapping": map[string]string{"u": "#u"}})
	if code != 403 || out["error"] != "grant revoked" {
		t.Fatalf("fill on revoked: %d %v", code, out)
	}
	code, _ = doJSON(t, srv, "POST", "/v1/owner/grants/"+gid+"/revoke", own, nil)
	if code != 404 {
		t.Fatalf("re-revoke: want 404, got %d", code)
	}
}

func TestDenyGrantRequest(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	code, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	if code != 202 {
		t.Fatalf("want 202, got %d", code)
	}
	rid := out["request_id"].(string)
	code, out = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/deny", own, nil)
	if code != 200 || out["status"] != "denied" {
		t.Fatalf("deny: %d %v", code, out)
	}
	code, out = doJSON(t, srv, "GET", "/v1/grants/requests/"+rid, tok, nil)
	if out["status"] != "denied" {
		t.Fatalf("agent sees %v", out)
	}
}

func TestApprovalLazyExpiry(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)
	// Insert a stale pending approval directly.
	if err := st.CreateApproval(&store.Approval{ID: "stale1", AgentID: 1, Handle: h,
		Policy: "{}", Status: "pending", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	code, out := doJSON(t, srv, "GET", "/v1/grants/requests/stale1", tok, nil)
	if code != 200 || out["status"] != "expired" {
		t.Fatalf("want expired, got %d %v", code, out)
	}
	// Stale request excluded from the pending owner list.
	code, out = doJSON(t, srv, "GET", "/v1/owner/approvals?status=pending", own, nil)
	list := out["approvals"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != rid {
		t.Fatalf("bad pending list: %v", list)
	}
}

func TestGrantRequestForeignAgent(t *testing.T) {
	srv, st, dek, tok, _ := approvalServer(t, "card")
	if _, err := st.CreateAgent("other", hashToken("tok-other")); err != nil {
		t.Fatal(err)
	}
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)
	code, _ := doJSON(t, srv, "GET", "/v1/grants/requests/"+rid, "tok-other", nil)
	if code != 404 {
		t.Fatalf("foreign agent: want 404, got %d", code)
	}
}

func TestApprovalModesNoneAndAll(t *testing.T) {
	srv, st, dek, tok, _ := approvalServer(t, "none")
	h := addCard(t, st, srv, dek, "amex")
	code, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	if code != 200 || out["token"] == nil {
		t.Fatalf("mode=none: want immediate grant, got %d %v", code, out)
	}

	srv, _, _, tok, _ = approvalServer(t, "all")
	code, out = doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": "cred://github.com/joan"})
	if code != 404 && code != 202 {
		t.Fatalf("mode=all: want 202 for login handle (missing cred ok to check separately), got %d", code)
	}
}

func TestApprovalModeAllLogin(t *testing.T) {
	srv, st, dek, tok, _ := approvalServer(t, "all")
	pt, _ := json.Marshal(map[string]string{"username": "u", "password": "p"})
	ct, _ := crypto.Encrypt(dek, pt)
	if err := st.AddCredential(&store.Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: "{}", Ciphertext: ct}); err != nil {
		t.Fatal(err)
	}
	code, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": "cred://github.com/joan"})
	if code != 202 || out["status"] != "pending_approval" {
		t.Fatalf("mode=all: want pending for login handle, got %d %v", code, out)
	}
}

func TestRequireHumanPolicyForcesApproval(t *testing.T) {
	srv, st, dek, tok, _ := approvalServer(t, "none")
	pt, _ := json.Marshal(map[string]string{"username": "u"})
	ct, _ := crypto.Encrypt(dek, pt)
	if err := st.AddCredential(&store.Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: "{}", Ciphertext: ct}); err != nil {
		t.Fatal(err)
	}
	code, out := doJSON(t, srv, "POST", "/v1/grants", tok,
		map[string]any{"handle": "cred://github.com/joan", "policy": map[string]any{"require_human": true}})
	if code != 202 {
		t.Fatalf("require_human: want 202, got %d %v", code, out)
	}
}

func TestLongPollWakesOnApprove(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)
	done := make(chan map[string]any, 1)
	go func() {
		_, o := doJSON(t, srv, "GET", "/v1/grants/requests/"+rid+"?wait=60", tok, nil)
		done <- o
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	select {
	case o := <-done:
		if o["status"] != "approved" || o["token"] == nil {
			t.Fatalf("bad wake response: %v", o)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll did not return promptly")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("long poll took too long: %v", time.Since(start))
	}
}

func TestOwnerAuthToken(t *testing.T) {
	srv, _, _, _, own := approvalServer(t, "card")
	code, _ := doJSON(t, srv, "GET", "/v1/owner/handles", own, nil)
	if code != 200 {
		t.Fatalf("owner token auth: %d", code)
	}
	code, _ = doJSON(t, srv, "GET", "/v1/owner/handles", "wrong", nil)
	if code != 401 {
		t.Fatalf("bad owner token: want 401, got %d", code)
	}
	code, _ = doJSON(t, srv, "GET", "/v1/owner/audit", own, nil)
	if code != 200 {
		t.Fatalf("owner audit alias: %d", code)
	}
}

func TestConcurrentPollersAllWake(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)
	var wg sync.WaitGroup
	res := make([]map[string]any, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, o := doJSON(t, srv, "GET", "/v1/grants/requests/"+rid+"?wait=10", tok, nil)
			res[i] = o
		}(i)
	}
	// Give all three pollers a moment to register before deciding.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pollers took %v", elapsed)
	}
	for i, o := range res {
		if o["status"] != "approved" || o["token"] == nil {
			t.Fatalf("poller %d bad response: %v", i, o)
		}
	}
}

func TestWaiterChannelsDoNotLeak(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)
	// wait=0 polls never register.
	for i := 0; i < 3; i++ {
		doJSON(t, srv, "GET", "/v1/grants/requests/"+rid, tok, nil)
	}
	// One completed wait>0 poll (woken by approve).
	done := make(chan struct{})
	go func() {
		doJSON(t, srv, "GET", "/v1/grants/requests/"+rid+"?wait=10", tok, nil)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	<-done
	if len(srv.waiters) != 0 {
		t.Fatalf("waiters leaked: %v", srv.waiters)
	}
}

func TestExpireIfStaleReflectsConcurrentDecision(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)
	doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	// A stale in-memory copy: still says pending and long past expiry.
	ap, err := st.GetApproval(rid)
	if err != nil {
		t.Fatal(err)
	}
	stale := *ap
	stale.Status = "pending"
	past := time.Now().Add(-time.Hour)
	stale.ExpiresAt = past
	srv.expireIfStale(&stale)
	if stale.Status != "approved" || stale.GrantID == "" {
		t.Fatalf("stale copy should reflect approved, got %+v", stale)
	}
}

func TestOwnerGrantsEffectiveMaxUses(t *testing.T) {
	srv, st, dek, _, own := approvalServer(t, "none")
	pt, _ := json.Marshal(map[string]string{"username": "u"})
	ct, _ := crypto.Encrypt(dek, pt)
	if err := st.AddCredential(&store.Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: "{}", Ciphertext: ct}); err != nil {
		t.Fatal(err)
	}
	// Grant with max_uses in the policy (not the column).
	_, g, err := srv.issuer.Issue(1, "cred://github.com/joan", `{"max_uses":1}`, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.IncrementGrantUses(g.ID); err != nil {
		t.Fatal(err)
	}
	code, out := doJSON(t, srv, "GET", "/v1/owner/grants", own, nil)
	if code != 200 {
		t.Fatalf("owner grants: %d", code)
	}
	list := out["grants"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["active"] != false {
		t.Fatalf("policy-exhausted grant should be inactive: %v", list)
	}
}

func TestCanceledPollDoesNotStrandOthers(t *testing.T) {
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	_, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	rid := out["request_id"].(string)

	// Poll A: canceled request context mid-wait.
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		req := httptest.NewRequest("GET", "/v1/grants/requests/"+rid+"?wait=60", nil).WithContext(ctxA)
		req.Header.Set("Authorization", "Bearer "+tok)
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}()
	// Poll B: survives, should wake on approve.
	doneB := make(chan map[string]any, 1)
	go func() {
		defer close(doneB)
		req := httptest.NewRequest("GET", "/v1/grants/requests/"+rid+"?wait=60", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		m := map[string]any{}
		json.NewDecoder(rec.Body).Decode(&m)
		doneB <- m
	}()
	time.Sleep(100 * time.Millisecond)
	cancelA()
	<-doneA
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	select {
	case m := <-doneB:
		if m["status"] != "approved" || m["token"] == nil {
			t.Fatalf("poller B bad response: %v", m)
		}
	case <-time.After(time.Second):
		t.Fatal("poller B stranded by canceled poller A")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("poller B took %v", time.Since(start))
	}
	if len(srv.waiters) != 0 {
		t.Fatalf("waiters leaked: %v", srv.waiters)
	}
}

func TestOwnerGrantsEffectiveMaxUsesMin(t *testing.T) {
	srv, st, dek, _, own := approvalServer(t, "none")
	pt, _ := json.Marshal(map[string]string{"username": "u"})
	ct, _ := crypto.Encrypt(dek, pt)
	if err := st.AddCredential(&store.Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: "{}", Ciphertext: ct}); err != nil {
		t.Fatal(err)
	}
	// Column says 5, policy says 1, uses 1 → policy wins → inactive.
	_, g, err := srv.issuer.Issue(1, "cred://github.com/joan", `{"max_uses":1}`, time.Hour, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.IncrementGrantUses(g.ID); err != nil {
		t.Fatal(err)
	}
	code, out := doJSON(t, srv, "GET", "/v1/owner/grants", own, nil)
	if code != 200 {
		t.Fatalf("owner grants: %d", code)
	}
	list := out["grants"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["active"] != false {
		t.Fatalf("min(column=5,policy=1)=1 with uses=1 should be inactive: %v", list)
	}
}

func TestOwnerCaptures(t *testing.T) {
	t.Setenv("VALET_CAPTURE_RETURN_ORIGINS", "https://demo.example")
	srv, st, _, _, own := approvalServer(t, "card")
	// No auth → 401.
	code, _ := doJSON(t, srv, "POST", "/v1/owner/captures", "", map[string]any{"label": "personal"})
	if code != 401 {
		t.Fatalf("unauth: want 401, got %d", code)
	}
	code, out := doJSON(t, srv, "POST", "/v1/owner/captures", own,
		map[string]any{"label": "personal", "ttl_seconds": 600, "return_url": "https://demo.example/?saved=1"})
	if code != 201 {
		t.Fatalf("want 201, got %d %v", code, out)
	}
	tok, _ := out["token"].(string)
	url, _ := out["url"].(string)
	if tok == "" || !strings.Contains(url, tok) || !strings.HasSuffix(url, "/capture/"+tok) {
		t.Fatalf("bad response: %v", out)
	}
	c, err := st.GetCapture(tok)
	if err != nil || c.Label != "personal" {
		t.Fatalf("capture not stored: %v %v", c, err)
	}
	if !strings.Contains(c.Metadata, "return_url") {
		t.Fatalf("return_url not in metadata: %s", c.Metadata)
	}
	// Bad ttl → 400.
	code, _ = doJSON(t, srv, "POST", "/v1/owner/captures", own, map[string]any{"label": "x", "ttl_seconds": -5})
	if code != 400 {
		t.Fatalf("negative ttl: want 400, got %d", code)
	}
	// Non-http(s) return_url → 400.
	code, _ = doJSON(t, srv, "POST", "/v1/owner/captures", own, map[string]any{"label": "x", "return_url": "javascript:alert(1)"})
	if code != 400 {
		t.Fatalf("js return_url: want 400, got %d", code)
	}
	// Missing label → 400.
	code, _ = doJSON(t, srv, "POST", "/v1/owner/captures", own, map[string]any{})
	if code != 400 {
		t.Fatalf("no label: want 400, got %d", code)
	}
}

func addWalletCred(t *testing.T, srv *Server, st *store.SQLite) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pt, _ := json.Marshal(map[string]string{
		"secret_key": "sk_test_x", "wallet_secret": base64.StdEncoding.EncodeToString(der), "account_id": "acc_x",
	})
	ct, err := crypto.Encrypt(srv.dek, pt)
	if err != nil {
		t.Fatal(err)
	}
	err = st.AddCredential(&store.Credential{
		Handle: "wallet://agent", Type: "wallet", Label: "agent",
		Metadata:   `{"provider":"openfort","address":"0xabc","network":"eip155:84532","asset":"USDC"}`,
		Ciphertext: ct,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func x402Req(t *testing.T, srv *Server, agentTok string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/edge/wallet/x402", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestWalletX402(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCred(t, srv, st)
	orig := walletFetch
	defer func() { walletFetch = orig }()
	var gotPol wallet.Policy
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		gotPol = pol
		return &wallet.Response{
			Status: 200, Headers: map[string]string{"content-type": "application/json"},
			Body: `{"ok":true}`,
			Payment: &wallet.PaymentInfo{
				Network: "eip155:84532", Asset: "0xusdc", PayTo: "0xpayee",
				Amount: "700", Transaction: "0xtx1", Payer: "0xabc",
			},
		}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["api.example.com"],"spend":{"per_tx":1000,"total":2000}}`, time.Hour)
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/report", "method": "GET",
	})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Status  string `json:"status"`
		Payment struct {
			Amount      string `json:"amount"`
			Transaction string `json:"transaction"`
		} `json:"payment"`
	}
	json.NewDecoder(rec.Body).Decode(&out)
	if out.Status != "paid" || out.Payment.Amount != "700" || out.Payment.Transaction != "0xtx1" {
		t.Fatalf("bad response %s", rec.Body)
	}
	if len(gotPol.Networks) != 1 || gotPol.Networks[0] != "eip155:84532" {
		t.Fatalf("bad networks %v", gotPol.Networks)
	}
	// "USDC" metadata resolves to the network's default asset address.
	if len(gotPol.Assets) != 1 || !strings.EqualFold(gotPol.Assets[0], "0x036CbD53842c5426634e7929541eC2318f3dCF7e") {
		t.Fatalf("bad assets %v", gotPol.Assets)
	}
	if gotPol.MaxAmount == nil || gotPol.MaxAmount.Int64() != 1000 {
		t.Fatalf("bad cap %v", gotPol.MaxAmount)
	}
	// Spend recorded on the grant.
	tokID, _, _ := strings.Cut(tok, ".")
	g, _ := st.GetGrant(tokID)
	if g.Spent != 700 || g.Uses != 1 {
		t.Fatalf("spent=%d uses=%d", g.Spent, g.Uses)
	}
	// Second call: remaining total (1300) still > per_tx (1000) → cap stays 1000.
	rec = x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/report", "method": "GET",
	})
	if rec.Code != 200 {
		t.Fatalf("second call: %d %s", rec.Code, rec.Body)
	}
	// Spend now 1400; cap next call to total-spent=600.
	rec = x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/report", "method": "GET",
	})
	if rec.Code != 200 {
		t.Fatalf("third call: %d", rec.Code)
	}
	if gotPol.MaxAmount.Int64() != 600 {
		t.Fatalf("third cap %v want 600", gotPol.MaxAmount)
	}
}

func TestWalletX402Denies(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCred(t, srv, st)
	// Unscoped grant.
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent", `{}`, time.Hour)
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x",
	})
	if rec.Code != 403 {
		t.Fatalf("unscoped: want 403 got %d %s", rec.Code, rec.Body)
	}
	// Wrong handle kind.
	tok = issueGrantHandle(t, srv, st, agentTok, "cred://github.com/joan", `{"hosts":["api.example.com"]}`, time.Hour)
	rec = x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x",
	})
	if rec.Code != 403 {
		t.Fatalf("non-wallet: want 403 got %d", rec.Code)
	}
	// Non-https URL.
	tok = issueGrantHandle(t, srv, st, agentTok, "wallet://agent", `{"hosts":["api.example.com"]}`, time.Hour)
	rec = x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "http://api.example.com/x",
	})
	if rec.Code != 400 {
		t.Fatalf("http url: want 400 got %d", rec.Code)
	}
	// Host outside policy.
	rec = x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://evil.example.com/x",
	})
	if rec.Code != 403 {
		t.Fatalf("bad host: want 403 got %d", rec.Code)
	}
	// Fetch policy refusal maps to 403.
	orig := walletFetch
	defer func() { walletFetch = orig }()
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		return nil, fmt.Errorf("%w: over cap", wallet.ErrPolicy)
	}
	rec = x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x",
	})
	if rec.Code != 403 {
		t.Fatalf("policy: want 403 got %d %s", rec.Code, rec.Body)
	}
}

func TestWalletX402PaymentRejected(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCred(t, srv, st)
	orig := walletFetch
	defer func() { walletFetch = orig }()
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		return &wallet.Response{Status: 402, PaymentAttempted: true}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["api.example.com"],"spend":{"per_tx":1000,"total":2000}}`, time.Hour)
	tokID, _, _ := strings.Cut(tok, ".")
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x", "method": "GET",
	})
	if rec.Code != 200 {
		t.Fatalf("want 200 got %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Status  string `json:"status"`
		Payment any    `json:"payment"`
	}
	json.NewDecoder(rec.Body).Decode(&out)
	if out.Status != "ok" || out.Payment != nil {
		t.Fatalf("bad response %s", rec.Body)
	}
	g, _ := st.GetGrant(tokID)
	if g.Spent != 0 || g.Uses != 0 {
		t.Fatalf("rejected payment recorded: spent=%d uses=%d", g.Spent, g.Uses)
	}
	// Audit shows payment_rejected.
	audits, _ := st.ListAudit(10)
	found := false
	for _, a := range audits {
		if a.Edge == "wallet" && strings.Contains(a.Detail, "payment_rejected") {
			found = true
		}
	}
	if !found {
		t.Fatal("no payment_rejected audit")
	}
}

func TestOwnerCapturesReturnOrigins(t *testing.T) {
	newSrv := func(t *testing.T, origins, public string) *Server {
		t.Helper()
		t.Setenv("VALET_REQUIRE_APPROVAL", "card")
		t.Setenv("VALET_OWNER_TOKEN", "owner-tok")
		t.Setenv("VALET_CAPTURE_RETURN_ORIGINS", origins)
		t.Setenv("VALET_PUBLIC_URL", public)
		st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		dek, _ := crypto.GenerateDEK()
		return New(st, grant.NewIssuer(st, dek), audit.New(st), &fakeFiller{}, dek, nil)
	}
	post := func(srv *Server, ret string) int {
		code, _ := doJSON(t, srv, "POST", "/v1/owner/captures", "owner-tok",
			map[string]any{"label": "x", "return_url": ret})
		return code
	}

	// Explicit allowlist: matching origin (case-insensitive) accepted, other rejected.
	srv := newSrv(t, " https://demo.example , https://ALT.example:8443 ", "")
	if c := post(srv, "https://demo.example/path?q=1"); c != 201 {
		t.Fatalf("allowed origin: want 201, got %d", c)
	}
	if c := post(srv, "https://alt.example:8443/x"); c != 201 {
		t.Fatalf("allowed origin w/ port: want 201, got %d", c)
	}
	if c := post(srv, "https://evil.example/"); c != 400 {
		t.Fatalf("disallowed origin: want 400, got %d", c)
	}

	// Env unset + VALET_PUBLIC_URL set → only that origin accepted.
	srv = newSrv(t, "", "https://valet.example/valet")
	if c := post(srv, "https://valet.example/done"); c != 201 {
		t.Fatalf("public-url origin: want 201, got %d", c)
	}
	if c := post(srv, "https://other.example/"); c != 400 {
		t.Fatalf("non-public origin: want 400, got %d", c)
	}

	// Neither set → any return_url rejected, empty still ok.
	srv = newSrv(t, "", "")
	if c := post(srv, "https://valet.example/"); c != 400 {
		t.Fatalf("no allowlist: want 400, got %d", c)
	}
	code, _ := doJSON(t, srv, "POST", "/v1/owner/captures", "owner-tok", map[string]any{"label": "x"})
	if code != 201 {
		t.Fatalf("empty return_url: want 201, got %d", code)
	}
}

func TestCaptureCompleteInspectorOverridesClient(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&inspectorProvider{fakeProvider{}, "4242", "424242", nil})
	tok := newCapture(t, st, "visa-insp", time.Hour)
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_sandbox_pan9", "exp_month": "12", "exp_year": "2030", "last4": "1111", "bin": "411111",
	})
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	cred, err := st.GetCredential("card://visa-insp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cred.Metadata, `"last4":"4242"`) ||
		!strings.Contains(cred.Metadata, `"bin":"424242"`) ||
		!strings.Contains(cred.Metadata, `"last4_source":"vgs"`) {
		t.Fatalf("VGS values must win: %s", cred.Metadata)
	}
}

func TestCaptureCompleteInspectorFallback(t *testing.T) {
	srv, st, _ := testServer(t)
	// Provider without AliasInspector → client values, source client.
	srv.SetCardProvider(&fakeProvider{})
	tok := newCapture(t, st, "visa-cli", time.Hour)
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_sandbox_pan8", "exp_month": "12", "exp_year": "2030", "last4": "1111",
	})
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	cred, err := st.GetCredential("card://visa-cli")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cred.Metadata, `"last4":"1111"`) ||
		!strings.Contains(cred.Metadata, `"last4_source":"client"`) {
		t.Fatalf("client values expected: %s", cred.Metadata)
	}
	// Inspector error also falls back to client values.
	srv2, st2, _ := testServer(t)
	srv2.SetCardProvider(&inspectorProvider{fakeProvider{}, "", "", fmt.Errorf("no creds")})
	tok2 := newCapture(t, st2, "visa-err", time.Hour)
	rec = capReq(t, srv2, "POST", "/capture/"+tok2+"/complete", map[string]any{
		"number": "tok_sandbox_pan7", "exp_month": "12", "exp_year": "2030", "last4": "5555",
	})
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	cred, err = st2.GetCredential("card://visa-err")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cred.Metadata, `"last4":"5555"`) ||
		!strings.Contains(cred.Metadata, `"last4_source":"client"`) {
		t.Fatalf("fallback expected: %s", cred.Metadata)
	}
}

func TestCaptureCompleteUpsertsLabel(t *testing.T) {
	srv, st, _ := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	for i, tok4 := range []string{"0000", "9999"} {
		tok := fmt.Sprintf("cap-re-%d", i)
		if err := st.CreateCapture(&store.Capture{
			Token: tok, Label: "visa-re", Metadata: `{"provider":"vgs"}`, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
			"number": "tok_pan_" + tok4, "exp_month": "12", "exp_year": "2030", "last4": tok4,
		})
		if rec.Code != 200 {
			t.Fatalf("capture %d: got %d %s", i, rec.Code, rec.Body)
		}
	}
	creds, _ := st.ListCredentials()
	n := 0
	for _, c := range creds {
		if c.Handle == "card://visa-re" {
			n++
			if !strings.Contains(c.Metadata, `"last4":"9999"`) {
				t.Fatalf("second capture should replace: %s", c.Metadata)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want 1 credential for card://visa-re, got %d", n)
	}
}

func TestOwnerDeleteHandle(t *testing.T) {
	srv, st, _, _, own := approvalServer(t, "card")
	cardCred(t, srv, st)
	// Handles contain :// — they travel %-escaped in the wildcard path.
	enc := "/v1/owner/handles/card:%2F%2Fvisa-4242"
	// Wrong/no auth → 401.
	code, _ := doJSON(t, srv, "DELETE", enc, "", nil)
	if code != 401 {
		t.Fatalf("unauth: want 401, got %d", code)
	}
	// Unknown handle → 404 (no egress-discovered api:// handles either).
	code, _ = doJSON(t, srv, "DELETE", "/v1/owner/handles/card:%2F%2Fnope", own, nil)
	if code != 404 {
		t.Fatalf("missing: want 404, got %d", code)
	}
	code, out := doJSON(t, srv, "DELETE", enc, own, nil)
	if code != 200 || out["status"] != "deleted" {
		t.Fatalf("delete: got %d %v", code, out)
	}
	if _, err := st.GetCredential("card://visa-4242"); err != store.ErrNotFound {
		t.Fatalf("credential still present: %v", err)
	}
	audits, _ := st.ListAudit(10)
	found := false
	for _, a := range audits {
		if a.Edge == "owner" && a.Target == "delete" && a.Handle == "card://visa-4242" {
			found = true
		}
	}
	if !found {
		t.Fatal("no owner-delete audit entry")
	}
}

func TestCaptureReplaceRevokesGrants(t *testing.T) {
	srv, st, agentTok := testServer(t)
	srv.SetCardProvider(&fakeProvider{})
	// First capture creates card://visa-re.
	tok := "cap-r1"
	if err := st.CreateCapture(&store.Capture{Token: tok, Label: "visa-re", Metadata: `{"provider":"vgs"}`, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rec := capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_pan_1", "exp_month": "12", "exp_year": "2030", "last4": "0000",
	})
	if rec.Code != 200 {
		t.Fatalf("first capture: %d %s", rec.Code, rec.Body)
	}
	// A live grant against that handle.
	grantTok := issueGrantHandle(t, srv, st, agentTok, "card://visa-re", `{"spend":{"per_tx":100}}`, time.Hour)
	// Re-capture the same label — replaces the credential.
	tok = "cap-r2"
	if err := st.CreateCapture(&store.Capture{Token: tok, Label: "visa-re", Metadata: `{"provider":"vgs"}`, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rec = capReq(t, srv, "POST", "/capture/"+tok+"/complete", map[string]any{
		"number": "tok_pan_2", "exp_month": "12", "exp_year": "2031", "last4": "9999",
	})
	if rec.Code != 200 {
		t.Fatalf("second capture: %d %s", rec.Code, rec.Body)
	}
	// The old grant is revoked.
	grantID, _, _ := strings.Cut(grantTok, ".")
	g, err := st.GetGrant(grantID)
	if err != nil {
		t.Fatal(err)
	}
	if g.RevokedAt == nil {
		t.Fatal("grant on replaced handle still live")
	}
	// Replace audit entry exists.
	audits, _ := st.ListAudit(20)
	found := false
	for _, a := range audits {
		if a.Edge == "capture" && a.Target == "replace" {
			found = true
		}
	}
	if !found {
		t.Fatal("no capture/replace audit entry")
	}
}

func TestWalletX402ConcurrentSpend(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCred(t, srv, st)
	orig := walletFetch
	defer func() { walletFetch = orig }()
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		time.Sleep(20 * time.Millisecond) // widen the race
		amt := "10"
		if pol.MaxAmount != nil && pol.MaxAmount.Int64() < 10 {
			return nil, fmt.Errorf("%w: grant total limit exceeded", wallet.ErrPolicy)
		}
		return &wallet.Response{Status: 200, Payment: &wallet.PaymentInfo{
			Network: "eip155:84532", Asset: "0xusdc", PayTo: "0xp", Amount: amt, Transaction: "0xt",
		}}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["api.example.com"],"spend":{"total":15}}`, time.Hour)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	bodies := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := x402Req(t, srv, agentTok, map[string]any{
				"grant_token": tok, "url": "https://api.example.com/x",
			})
			codes <- rec.Code
			bodies <- rec.Body.String()
		}()
	}
	wg.Wait()
	close(codes)
	close(bodies)
	paid, denied := 0, 0
	for c := range codes {
		if c == 200 {
			paid++
		} else if c == 403 {
			denied++
		}
	}
	if paid != 1 || denied != 1 {
		t.Fatalf("paid=%d denied=%d", paid, denied)
	}
	for b := range bodies {
		t.Log(b)
	}
	tokID, _, _ := strings.Cut(tok, ".")
	g, _ := st.GetGrant(tokID)
	if g.Spent != 10 {
		t.Fatalf("spent=%d want 10", g.Spent)
	}
}

func TestCardPaySpendTotal(t *testing.T) {
	srv, st, tok := testServer(t)
	cardCred(t, srv, st)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"charged":true}`)
	}))
	defer upstream.Close()
	srv.SetCardProvider(&fakeProvider{upstream: upstream})
	gtok := issueGrantHandle(t, srv, st, tok, "card://visa-4242",
		`{"spend":{"merchants":["*"],"total":15}}`, time.Hour)
	pay := func() *httptest.ResponseRecorder {
		rec, req := payReq(t, tok, map[string]any{
			"grant_token": gtok, "url": upstream.URL + "/charge", "method": "POST",
			"body": `{"pan":"{{card.number}}"}`, "amount": 10, "currency": "USD",
		})
		srv.ServeHTTP(rec, req)
		return rec
	}
	if rec := pay(); rec.Code != 200 {
		t.Fatalf("first pay: %d %s", rec.Code, rec.Body)
	}
	rec := pay()
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "grant total limit exceeded") {
		t.Fatalf("second pay: %d %s", rec.Code, rec.Body)
	}
	tokID, _, _ := strings.Cut(gtok, ".")
	g, _ := st.GetGrant(tokID)
	if g.Spent != 10 {
		t.Fatalf("spent=%d", g.Spent)
	}
}

func TestOwnerGrantsSpentAndActive(t *testing.T) {
	t.Setenv("VALET_OWNER_TOKEN", "owner-tok")
	srv, st, agentTok := testServer(t)
	addWalletCred(t, srv, st)
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["x"],"spend":{"total":15}}`, time.Hour)
	tokID, _, _ := strings.Cut(tok, ".")
	if err := st.AddGrantSpend(tokID, 15); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/v1/owner/grants", nil)
	req.Header.Set("Authorization", "Bearer owner-tok")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Grants []struct {
			Spent  int64 `json:"spent"`
			Active bool  `json:"active"`
		} `json:"grants"`
	}
	json.NewDecoder(rec.Body).Decode(&out)
	if len(out.Grants) == 0 {
		t.Fatal("no grants")
	}
	for _, gr := range out.Grants {
		if gr.Spent == 15 && gr.Active {
			t.Fatal("grant at total still active")
		}
	}
	var wg *struct {
		Spent  int64 `json:"spent"`
		Active bool  `json:"active"`
	}
	for i := range out.Grants {
		if out.Grants[i].Spent == 15 {
			wg = &out.Grants[i]
		}
	}
	if wg == nil || wg.Spent != 15 {
		t.Fatal("spent not surfaced")
	}
}

func addWalletCredNet(t *testing.T, srv *Server, st *store.SQLite, handle_, network string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pt, _ := json.Marshal(map[string]string{
		"secret_key": "sk_test_x", "wallet_secret": base64.StdEncoding.EncodeToString(der), "account_id": "acc_x",
	})
	ct, err := crypto.Encrypt(srv.dek, pt)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]string{
		"provider": "openfort", "address": "0xabc", "network": network, "asset": "USDC",
	})
	err = st.AddCredential(&store.Credential{
		Handle: handle_, Type: "wallet", Label: handle_, Metadata: string(meta), Ciphertext: ct,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mppReq(t *testing.T, srv *Server, agentTok string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/edge/wallet/mpp", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestWalletMPP(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCredNet(t, srv, st, "wallet://agent", "eip155:42431")
	orig := mppFetch
	defer func() { mppFetch = orig }()
	var gotPol mppedg.Policy
	mppFetch = func(ctx context.Context, s mppedg.HashSigner, req wallet.Request, pol mppedg.Policy, rpc tempo.RPCClient) (*wallet.Response, error) {
		gotPol = pol
		return &wallet.Response{Status: 200, PaymentAttempted: true, Payment: &wallet.PaymentInfo{
			Protocol: "mpp", Method: "tempo", Network: "eip155:42431",
			Asset: "0x20c0000000000000000000000000000000000000", PayTo: "0xp",
			Amount: "10000", Transaction: "0xmpp",
		}}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["api.example.com"],"spend":{"total":100000}}`, time.Hour)
	rec := mppReq(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x",
	})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Status  string `json:"status"`
		Payment *struct {
			Protocol    string `json:"protocol"`
			Transaction string `json:"transaction"`
		} `json:"payment"`
	}
	json.NewDecoder(rec.Body).Decode(&out)
	if out.Status != "paid" || out.Payment == nil || out.Payment.Protocol != "mpp" || out.Payment.Transaction != "0xmpp" {
		t.Fatalf("bad response %s", rec.Body)
	}
	if len(gotPol.ChainIDs) != 1 || gotPol.ChainIDs[0] != 42431 {
		t.Fatalf("chain ids %v", gotPol.ChainIDs)
	}
	// Tempo chain assets resolve via DefaultCurrenciesForChain (pathUSD + OUSD).
	if len(gotPol.Assets) != 2 {
		t.Fatalf("assets %v", gotPol.Assets)
	}
	tokID, _, _ := strings.Cut(tok, ".")
	g, _ := st.GetGrant(tokID)
	if g.Spent != 10000 || g.Uses != 1 {
		t.Fatalf("spent=%d uses=%d", g.Spent, g.Uses)
	}
}

func TestWalletMPPDenies(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCredNet(t, srv, st, "wallet://agent", "eip155:42431")
	orig := mppFetch
	defer func() { mppFetch = orig }()
	signed := false
	mppFetch = func(ctx context.Context, s mppedg.HashSigner, req wallet.Request, pol mppedg.Policy, rpc tempo.RPCClient) (*wallet.Response, error) {
		if pol.MaxAmount != nil && pol.MaxAmount.Int64() < 10000 {
			return nil, fmt.Errorf("%w: amount exceeds cap", wallet.ErrPolicy)
		}
		signed = true
		return &wallet.Response{Status: 200}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["api.example.com"],"spend":{"total":100000}}`, time.Hour)
	rec := mppReq(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x", "max_amount": 5000,
	})
	if rec.Code != 403 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if signed {
		t.Fatal("signed despite cap")
	}
	tokID, _, _ := strings.Cut(tok, ".")
	g, _ := st.GetGrant(tokID)
	if g.Spent != 0 || g.Uses != 0 {
		t.Fatalf("spent=%d uses=%d", g.Spent, g.Uses)
	}
}

func TestWalletNetworkListParses(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCredNet(t, srv, st, "wallet://multi", "eip155:84532,eip155:42431")
	orig := walletFetch
	defer func() { walletFetch = orig }()
	var gotPol wallet.Policy
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		gotPol = pol
		return &wallet.Response{Status: 200}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://multi",
		`{"hosts":["api.example.com"]}`, time.Hour)
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x",
	})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(gotPol.Networks) != 2 {
		t.Fatalf("networks %v", gotPol.Networks)
	}
	// USDC on 84532 + pathUSD/OUSD on 42431.
	if len(gotPol.Assets) != 3 {
		t.Fatalf("assets %v", gotPol.Assets)
	}
}

func addWalletCredSvm(t *testing.T, srv *Server, st *store.SQLite, handle_, network string, svm bool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	fields := map[string]string{
		"secret_key": "sk_test_x", "wallet_secret": base64.StdEncoding.EncodeToString(der), "account_id": "acc_x",
	}
	if svm {
		fields["svm_account_id"] = "acc_svm_x"
		fields["svm_address"] = "FDx9mfVqTvXUaSPQDELwDtGgMqxirmAFsEK2s4YsKfsc"
	}
	pt, _ := json.Marshal(fields)
	ct, err := crypto.Encrypt(srv.dek, pt)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]string{
		"provider": "openfort", "address": "0xabc", "network": network, "asset": "USDC",
	})
	if err := st.AddCredential(&store.Credential{
		Handle: handle_, Type: "wallet", Label: handle_, Metadata: string(meta), Ciphertext: ct,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWalletX402Solana(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCredSvm(t, srv, st, "wallet://sol", "eip155:84532,solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", true)
	orig := walletFetch
	defer func() { walletFetch = orig }()
	var gotSigners wallet.Signers
	var gotPol wallet.Policy
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		gotSigners = signers
		gotPol = pol
		return &wallet.Response{Status: 200, PaymentAttempted: true, Payment: &wallet.PaymentInfo{
			Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
			PayTo: "FDx9mfVqTvXUaSPQDELwDtGgMqxirmAFsEK2s4YsKfsc", Amount: "10000", Transaction: "5tx",
		}}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://sol",
		`{"hosts":["api.example.com"],"spend":{"total":50000}}`, time.Hour)
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x", "method": "GET",
	})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if gotSigners.SVM == nil || gotSigners.EVM == nil {
		t.Fatal("both signers expected")
	}
	var netsOK, assetOK bool
	for _, n := range gotPol.Networks {
		if n == "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" {
			netsOK = true
		}
	}
	for _, a := range gotPol.Assets {
		if strings.EqualFold(a, "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU") {
			assetOK = true
		}
	}
	if !netsOK || !assetOK {
		t.Fatalf("bad policy networks=%v assets=%v", gotPol.Networks, gotPol.Assets)
	}
	g, err := st.GetGrant(strings.SplitN(tok, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	if g.Uses != 1 || g.Spent != 10000 {
		t.Fatalf("grant uses=%d spent=%d", g.Uses, g.Spent)
	}
}

func TestWalletX402SolanaMissingSVM(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCredSvm(t, srv, st, "wallet://solonly", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", false)
	called := false
	orig := walletFetch
	defer func() { walletFetch = orig }()
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		called = true
		return &wallet.Response{Status: 200}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://solonly",
		`{"hosts":["api.example.com"]}`, time.Hour)
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x", "method": "GET",
	})
	if rec.Code != 403 {
		t.Fatalf("want 403 got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "no solana account") {
		t.Fatalf("wrong error %s", rec.Body)
	}
	if called {
		t.Fatal("fetch called despite missing svm account")
	}
}

func TestWalletChainIDsStrict(t *testing.T) {
	got := walletChainIDs([]string{"eip155:84532", "4217", "solana:dev", "eip155:-1", "eip155:0", "eip155:abc", "", "eip155:42431"})
	want := []int64{84532, 42431}
	if len(got) != len(want) {
		t.Fatalf("chain ids %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chain ids %v", got)
		}
	}
}

func TestWalletChainAssetsPerChain(t *testing.T) {
	// Empty/USDC resolves to each chain's own Tempo defaults.
	ca := walletChainAssets([]string{"eip155:42431", "eip155:4217"}, "USDC")
	pA := tempo.DefaultCurrenciesForChain(42431)
	if len(ca[42431]) != len(pA) || len(ca[4217]) == 0 {
		t.Fatalf("chain assets %v", ca)
	}
	if ca[42431][0] == ca[4217][0] && len(pA) == 1 {
		t.Fatalf("chains share default unexpectedly %v", ca)
	}
	// Explicit asset applies to every chain.
	ca2 := walletChainAssets([]string{"eip155:42431", "eip155:1"}, "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF")
	if len(ca2[42431]) != 1 || len(ca2[1]) != 1 || ca2[1][0] != "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Fatalf("explicit chain assets %v", ca2)
	}
}

// A Response with Status 0 but a Payment (conn lost after paying) must
// still record the grant use + spend.
func TestWalletX402LostResponseStillCounts(t *testing.T) {
	srv, st, agentTok := testServer(t)
	addWalletCred(t, srv, st)
	orig := walletFetch
	defer func() { walletFetch = orig }()
	walletFetch = func(ctx context.Context, signers wallet.Signers, req wallet.Request, pol wallet.Policy) (*wallet.Response, error) {
		return &wallet.Response{Status: 0, PaymentAttempted: true, Payment: &wallet.PaymentInfo{
			Network: "eip155:84532", Asset: "0xusdc", PayTo: "0xp", Amount: "700", Transaction: "0xt",
		}}, nil
	}
	tok := issueGrantHandle(t, srv, st, agentTok, "wallet://agent",
		`{"hosts":["api.example.com"],"spend":{"total":2000}}`, time.Hour)
	rec := x402Req(t, srv, agentTok, map[string]any{
		"grant_token": tok, "url": "https://api.example.com/x", "method": "GET",
	})
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Status string `json:"status"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Status != "paid" {
		t.Fatalf("want paid got %s", rec.Body)
	}
	g, err := st.GetGrant(strings.SplitN(tok, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	if g.Uses != 1 || g.Spent != 700 {
		t.Fatalf("uses=%d spent=%d", g.Uses, g.Spent)
	}
}
