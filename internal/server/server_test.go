package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/edge/card"
	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/store"
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
