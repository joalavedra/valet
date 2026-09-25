package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/store"
)

type fakeFiller struct {
	pageURL    string
	gotValues  map[string]string
	fillErr    error
	fillStatus browser.Result
}

func (f *fakeFiller) PageURL(ctx context.Context, ws string) (string, error) {
	return f.pageURL, nil
}

func (f *fakeFiller) Fill(ctx context.Context, ws string, mapping map[string]string, submit string, values map[string]string) (browser.Result, error) {
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
	srv := New(st, grant.NewIssuer(st, dek), audit.New(st), &fakeFiller{pageURL: "https://github.com/login"}, dek)
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
	a, err := st.GetAgentByTokenHash(hashToken(agentTok))
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.issuer.Issue(a.ID, "cred://github.com/joan", policyJSON, ttl, 0)
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
		"cdp_ws_url":  "ws://x",
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
		"grant_token": gtok, "cdp_ws_url": "ws://x",
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

func TestBrowserFillExpiredGrant(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"hosts":["github.com"]}`, -time.Hour)
	rec, req := fillReq(t, tok, map[string]any{
		"grant_token": gtok, "cdp_ws_url": "ws://x",
		"mapping": map[string]string{"password": "#p"},
	})
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCardPayNotImplemented(t *testing.T) {
	srv, st, tok := testServer(t)
	gtok := issueGrant(t, srv, st, tok, `{"spend":{"per_tx":100,"merchants":["shop.com"]}}`, time.Hour)
	payload, _ := json.Marshal(map[string]any{"grant": gtok, "merchant": "shop.com", "amount": 50, "currency": "USD"})
	req := httptest.NewRequest("POST", "/v1/edge/card/pay", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}
