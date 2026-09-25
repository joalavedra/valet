// Package server exposes Valet's control-plane HTTP API: handle listing,
// grant issuance, browser-fill edge invocation, card pay stub, and audit.
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/handle"
	"github.com/joalavedra/valet/internal/policy"
	"github.com/joalavedra/valet/internal/store"
)

// Server holds dependencies for the HTTP API.
type Server struct {
	st         store.Store
	issuer     *grant.Issuer
	chain      *audit.Chain
	filler     browser.Filler
	egress     *egress.Client
	dek        []byte
	cdpAllow   []string
	cdpDefault string
	mux        *http.ServeMux
}

// New builds the API mux.
func New(st store.Store, issuer *grant.Issuer, chain *audit.Chain, filler browser.Filler, dek []byte, eg *egress.Client) *Server {
	allow := strings.Split(os.Getenv("VALET_CDP_ALLOW"), ",")
	if len(allow) == 1 && strings.TrimSpace(allow[0]) == "" {
		allow = []string{"127.0.0.1", "localhost", "::1"}
	}
	for i := range allow {
		allow[i] = strings.TrimSpace(allow[i])
	}
	s := &Server{st: st, issuer: issuer, chain: chain, filler: filler, dek: dek, egress: eg, cdpAllow: allow, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /v1/handles", s.agentAuth(s.handles))
	s.mux.HandleFunc("POST /v1/grants", s.agentAuth(s.createGrant))
	s.mux.HandleFunc("POST /v1/edge/browser/fill", s.agentAuth(s.browserFill))
	s.mux.HandleFunc("POST /v1/edge/card/pay", s.agentAuth(s.cardPay))
	s.mux.HandleFunc("POST /v1/edge/http/call", s.agentAuth(s.httpCall))
	s.mux.HandleFunc("GET /v1/audit", s.ownerAuth(s.listAudit))
	return s
}

// SetCDPDefault sets the fallback CDP endpoint (e.g. VALET_CDP_URL) used
// when a fill request omits cdp_ws_url.
func (s *Server) SetCDPDefault(url string) { s.cdpDefault = url }

// auditDeny records a denied edge attempt with a machine-readable reason.
func (s *Server) auditDeny(agentID int64, handle, edge, target, reason string) {
	detail, _ := json.Marshal(map[string]string{"reason": reason})
	_ = s.chain.Append(&store.AuditEntry{AgentID: agentID, Handle: handle, Edge: edge, Target: target, Decision: "deny", Detail: string(detail)})
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
	if s.egress != nil {
		if svcs, err := s.egress.Discover(r.Context()); err == nil {
			for _, svc := range svcs {
				out = append(out, handleInfo{Handle: "api://" + svc.Name, Type: "api", Site: svcHost(svc.Host), Label: svc.Name})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"handles": out})
}

// svcHost splits an Agent Vault service host pattern (host/path/*) into
// its host and optional path-glob parts.
func svcHost(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[:i]
	}
	return pattern
}

func svcPath(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}
	return ""
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
	var cred *store.Credential
	if kind, _, _, perr := handle.Parse(req.Handle); perr == nil && kind == "api" {
		// Virtual handle backed by an Agent Vault service, not the store.
		if s.egress == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
			return
		}
		svc, err := s.egress.ServiceByName(r.Context(), strings.TrimPrefix(req.Handle, "api://"))
		if err != nil || svc == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
			return
		}
		cred = &store.Credential{Handle: req.Handle, Type: "api", Site: svcHost(svc.Host), Label: svc.Name}
	} else {
		c, err := s.st.GetCredential(req.Handle)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
			return
		}
		cred = c
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
	GrantToken string            `json:"grant_token"`
	CDPWSURL   string            `json:"cdp_ws_url"`
	PageURL    string            `json:"page_url"` // optional: pick the tab by its URL
	Mapping    map[string]string `json:"mapping"`  // field -> CSS selector
	Submit     string            `json:"submit"`   // optional submit selector
}

func (s *Server) cdpAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	for _, allowed := range s.cdpAllow {
		if allowed == host || allowed == net.JoinHostPort(host, port) || (port == "" && allowed == host) {
			return true
		}
	}
	return false
}

func (s *Server) browserFill(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req fillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	cdpBase := req.CDPWSURL
	if cdpBase == "" {
		cdpBase = s.cdpDefault
	}
	if cdpBase == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cdp_ws_url required"})
		return
	}
	if !s.cdpAllowed(cdpBase) {
		s.auditDeny(a.ID, "", "browser", "", "cdp_host_denied")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cdp host not allowed"})
		return
	}
	if req.PageURL != "" {
		resolved, err := s.filler.ResolvePage(r.Context(), cdpBase, req.PageURL)
		if err != nil {
			slog.Debug("page resolve failed", "error", err)
			s.auditDeny(a.ID, "", "browser", "", "page_not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "page not found"})
			return
		}
		cdpBase = resolved
	}
	g, err := s.issuer.Verify(req.GrantToken, a.ID)
	if err != nil {
		reason, code := "grant_invalid", http.StatusForbidden
		if errors.Is(err, grant.ErrExpired) {
			reason, code = "grant_expired", http.StatusUnauthorized
		} else if errors.Is(err, grant.ErrExhausted) {
			reason = "grant_exhausted"
		}
		s.auditDeny(a.ID, "", "browser", "", reason)
		writeJSON(w, code, map[string]string{"error": reason})
		return
	}
	cred, err := s.st.GetCredential(g.Handle)
	if err != nil {
		s.auditDeny(a.ID, g.Handle, "browser", "", "grant_invalid")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
		return
	}
	pageURL, err := s.filler.PageURL(r.Context(), cdpBase)
	if err != nil {
		slog.Debug("cdp connect failed", "error", err)
		s.auditDeny(a.ID, g.Handle, "browser", "", "cdp_unreachable")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "cdp connect failed"})
		return
	}
	u, parseErr := url.Parse(pageURL)
	host := ""
	if parseErr == nil && u != nil {
		host = u.Hostname()
	}
	if host == "" {
		s.auditDeny(a.ID, g.Handle, "browser", "", "no_page_url")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no page url"})
		return
	}
	var p policy.Policy
	if err := json.Unmarshal([]byte(g.Policy), &p); err != nil {
		s.auditDeny(a.ID, g.Handle, "browser", host, "grant_invalid")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant_invalid"})
		return
	}
	d := policy.Evaluate(&p, &policy.GrantView{ExpiresAt: g.ExpiresAt, Uses: g.Uses, MaxUses: g.MaxUses}, policy.Request{Host: host, Now: time.Now()})
	if !d.Allow {
		s.auditDeny(a.ID, g.Handle, "browser", host, "host_denied")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host_denied"})
		return
	}
	if _, err := s.issuer.Consume(req.GrantToken, a.ID); err != nil {
		s.auditDeny(a.ID, g.Handle, "browser", host, "grant_exhausted")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant_exhausted"})
		return
	}
	values, err := s.credValues(cred)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "credential decrypt failed"})
		return
	}
	defer func() {
		for k := range values {
			values[k] = ""
		}
	}()
	if _, wantsOTP := req.Mapping["otp"]; wantsOTP && values["totp_seed"] != "" {
		code, err := browser.TOTPCode(values["totp_seed"])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "totp failed"})
			return
		}
		values["otp"] = code
		delete(values, "totp_seed")
	}
	res, err := s.filler.Fill(r.Context(), cdpBase, host, req.Mapping, req.Submit, values)
	if err != nil {
		slog.Debug("browser fill failed", "error", err)
		s.auditDeny(a.ID, g.Handle, "browser", host, "fill_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fill failed", "status": res.Status})
		return
	}
	if res.Status == browser.StatusHostMismatch {
		s.auditDeny(a.ID, g.Handle, "browser", host, "host_denied")
		writeJSON(w, http.StatusForbidden, map[string]string{"status": res.Status})
		return
	}
	_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "browser", Target: host, Decision: "allow", Detail: "{}"})
	writeJSON(w, http.StatusOK, map[string]string{"status": res.Status})
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

type callRequest struct {
	Grant   string            `json:"grant_token"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

func (s *Server) httpCall(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	if s.egress == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "egress not configured"})
		return
	}
	var req callRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	g, err := s.issuer.Verify(req.Grant, a.ID)
	if err != nil {
		s.auditDeny(a.ID, "", "http", "", grantReason(err))
		writeJSON(w, grantStatus(err), map[string]string{"error": "invalid grant"})
		return
	}
	kind, _, label, err := handle.Parse(g.Handle)
	if err != nil || kind != "api" {
		s.auditDeny(a.ID, g.Handle, "http", "", "not_api_handle")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant is not for an api handle"})
		return
	}
	svc, err := s.egress.ServiceByName(r.Context(), label)
	if err != nil {
		slog.Debug("http call discover failed", "err", err)
		s.auditDeny(a.ID, g.Handle, "http", "", "egress_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "egress failed"})
		return
	}
	if svc == nil {
		s.auditDeny(a.ID, g.Handle, "http", "", "service_mismatch")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "service not discovered"})
		return
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		s.auditDeny(a.ID, g.Handle, "http", "", "bad_url")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid url"})
		return
	}
	target := u.Host
	if !policy.GlobMatch(svcHost(svc.Host), u.Host) && !policy.GlobMatch(svcHost(svc.Host), u.Hostname()) {
		s.auditDeny(a.ID, g.Handle, "http", target, "service_mismatch")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "request host does not match service"})
		return
	}
	if pat := svcPath(svc.Host); pat != "" && !policy.GlobMatch(pat, u.Path) {
		s.auditDeny(a.ID, g.Handle, "http", target, "service_mismatch")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "request path does not match service"})
		return
	}
	var p policy.Policy
	json.Unmarshal([]byte(g.Policy), &p)
	d := policy.Evaluate(&p, &policy.GrantView{ExpiresAt: g.ExpiresAt, Uses: g.Uses, MaxUses: g.MaxUses}, policy.Request{
		Host: u.Hostname(), Method: req.Method, Path: u.Path, Now: time.Now(),
	})
	if !d.Allow {
		s.auditDeny(a.ID, g.Handle, "http", target, evalReason(d.Reason))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": d.Reason})
		return
	}
	if _, err := s.issuer.Consume(req.Grant, a.ID); err != nil {
		s.auditDeny(a.ID, g.Handle, "http", target, grantReason(err))
		writeJSON(w, grantStatus(err), map[string]string{"error": "invalid grant"})
		return
	}
	res, err := s.egress.Do(r.Context(), egress.Request{Method: req.Method, URL: req.URL, Headers: req.Headers, Body: []byte(req.Body)})
	if err != nil {
		slog.Debug("http call egress failed", "err", err)
		s.auditDeny(a.ID, g.Handle, "http", target, "egress_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "egress failed"})
		return
	}
	_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "http", Target: target, Decision: "allow", Detail: "{}"})
	writeJSON(w, http.StatusOK, res)
}

// grantReason maps grant verification errors to audit reason codes.
func grantReason(err error) string {
	switch {
	case errors.Is(err, grant.ErrExpired):
		return "grant_expired"
	case errors.Is(err, grant.ErrExhausted):
		return "grant_exhausted"
	default:
		return "grant_invalid"
	}
}

func grantStatus(err error) int {
	if grantReason(err) == "grant_expired" {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// evalReason maps policy deny text to an audit reason code.
func evalReason(reason string) string {
	switch {
	case strings.HasPrefix(reason, "host"):
		return "host_denied"
	case strings.HasPrefix(reason, "method"):
		return "method_denied"
	case strings.HasPrefix(reason, "path"):
		return "path_denied"
	case strings.HasPrefix(reason, "grant expired"):
		return "grant_expired"
	case strings.Contains(reason, "use limit"):
		return "grant_exhausted"
	default:
		return "policy_denied"
	}
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.st.ListAudit(500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}
