package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/store"
)

func testServer(t *testing.T) (*Server, *store.SQLite, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dek, _ := crypto.GenerateDEK()
	srv := New(st, grant.NewIssuer(st, dek), audit.New(st), nil, dek)
	token := "tok-abc"
	if _, err := st.CreateAgent("bot", hashToken(token)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCredential(&store.Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: "{}", Ciphertext: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	return srv, st, token
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

func TestCardPayNotImplemented(t *testing.T) {
	srv, st, tok := testServer(t)
	a, _ := st.GetAgentByTokenHash(hashToken(tok))
	gtok, _, err := srv.issuer.Issue(a.ID, "cred://github.com/joan", `{"spend":{"per_tx":100,"merchants":["shop.com"]}}`, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"grant": gtok, "merchant": "shop.com", "amount": 50, "currency": "USD"})
	req := httptest.NewRequest("POST", "/v1/edge/card/pay", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}
