// Package server exposes Valet's control-plane HTTP API: handle listing,
// grant issuance, browser-fill edge invocation, card pay stub, and audit.
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/policy"
	"github.com/joalavedra/valet/internal/store"
)

// Server holds dependencies for the HTTP API.
type Server struct {
	st     store.Store
	issuer *grant.Issuer
	chain  *audit.Chain
	filler browser.Filler
	dek    []byte
	mux    *http.ServeMux
}

// New builds the API mux.
func New(st store.Store, issuer *grant.Issuer, chain *audit.Chain, filler browser.Filler, dek []byte) *Server {
	s := &Server{st: st, issuer: issuer, chain: chain, filler: filler, dek: dek, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /v1/handles", s.agentAuth(s.handles))
	s.mux.HandleFunc("POST /v1/grants", s.agentAuth(s.createGrant))
	s.mux.HandleFunc("POST /v1/edge/browser/fill", s.agentAuth(s.browserFill))
	s.mux.HandleFunc("POST /v1/edge/card/pay", s.agentAuth(s.cardPay))
	s.mux.HandleFunc("GET /v1/audit", s.ownerAuth(s.listAudit))
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	t, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(t)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// agentAuth gates a handler behind an agent bearer token.
func (s *Server) agentAuth(next func(http.ResponseWriter, *http.Request, *store.Agent)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		a, err := s.st.GetAgentByTokenHash(hashToken(tok))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		next(w, r, a)
	}
}

// ownerAuth gates a handler behind VALET_MASTER_PASSWORD as a bearer token.
func (s *Server) ownerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bearer(r) != os.Getenv("VALET_MASTER_PASSWORD") || os.Getenv("VALET_MASTER_PASSWORD") == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "owner auth required"})
			return
		}
		next(w, r)
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type handleInfo struct {
	Handle   string `json:"handle"`
	Type     string `json:"type"`
	Site     string `json:"site,omitempty"`
	Label    string `json:"label,omitempty"`
	Metadata string `json:"metadata"`
}

func (s *Server) handles(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	creds, err := s.st.ListCredentials()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := []handleInfo{}
	for _, c := range creds {
		out = append(out, handleInfo{Handle: c.Handle, Type: c.Type, Site: c.Site, Label: c.Label, Metadata: c.Metadata})
	}
	writeJSON(w, http.StatusOK, map[string]any{"handles": out})
}

type grantRequest struct {
	Handle  string         `json:"handle"`
	Policy  *policy.Policy `json:"policy"`
	TTL     int64          `json:"ttl"` // seconds
	MaxUses int            `json:"max_uses"`
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	cred, err := s.st.GetCredential(req.Handle)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
		return
	}
	p := req.Policy
	if p == nil {
		p = &policy.Policy{}
	}
	if p.RequireHuman {
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: cred.Handle, Edge: "control", Target: "grant", Decision: "pending_approval", Detail: "{}"})
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending_approval"})
		return
	}
	ttl := time.Duration(req.TTL) * time.Second
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	pj, _ := json.Marshal(p)
	token, g, err := s.issuer.Issue(a.ID, cred.Handle, string(pj), ttl, req.MaxUses)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: cred.Handle, Edge: "control", Target: "grant", Decision: "granted", Detail: "{}"})
	writeJSON(w, http.StatusOK, map[string]any{"grant_id": g.ID, "token": token, "expires_at": g.ExpiresAt})
}

type fillRequest struct {
	Grant    string                      `json:"grant"`
	CDPWSURL string                      `json:"cdp_ws_url"`
	Mapping  map[string]browser.FieldRef `json:"mapping"`
}

func (s *Server) browserFill(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req fillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	g, err := s.issuer.Consume(req.Grant, a.ID)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	cred, err := s.st.GetCredential(g.Handle)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
		return
	}
	values, err := s.credValues(cred)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	res, err := s.filler.Fill(r.Context(), req.CDPWSURL, req.Mapping, values)
	if err != nil {
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "browser", Target: cred.Site, Decision: "deny", Detail: "{}"})
		writeJSON(w, http.StatusBadGateway, res)
		return
	}
	_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "browser", Target: cred.Site, Decision: "allow", Detail: "{}"})
	writeJSON(w, http.StatusOK, res)
}

// credValues decrypts the credential payload into field->value pairs.
// Plaintext exists only within the edge call scope.
func (s *Server) credValues(c *store.Credential) (map[string]string, error) {
	pt, err := crypto.Decrypt(s.dek, c.Ciphertext)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	if err := json.Unmarshal(pt, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

type payRequest struct {
	Grant    string `json:"grant"`
	Merchant string `json:"merchant"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Rail     string `json:"rail,omitempty"`
}

func (s *Server) cardPay(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req payRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	g, err := s.issuer.Consume(req.Grant, a.ID)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	var p policy.Policy
	json.Unmarshal([]byte(g.Policy), &p)
	d := policy.Evaluate(&p, &policy.GrantView{ExpiresAt: g.ExpiresAt, Uses: g.Uses, MaxUses: g.MaxUses}, policy.Request{
		Merchant: req.Merchant, Amount: req.Amount, Currency: req.Currency, Now: time.Now(),
	})
	if !d.Allow {
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "card", Target: req.Merchant, Decision: "deny", Detail: "{}"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": d.Reason})
		return
	}
	_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "card", Target: req.Merchant, Decision: "allow", Detail: "{}"})
	writeJSON(w, http.StatusNotImplemented, map[string]string{"status": "not_implemented"})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.st.ListAudit(500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}
