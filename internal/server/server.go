// Package server exposes Valet's control-plane HTTP API: handle listing,
// grant issuance, browser-fill edge invocation, card pay stub, and audit.
package server

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/edge/card"
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
	cardProv   card.Provider
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
	s.mux.HandleFunc("GET /capture/{token}", s.capturePage)
	s.mux.HandleFunc("POST /capture/{token}/complete", s.captureComplete)
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

//go:embed capture.html
var capturePageHTML string
var captureTmpl = template.Must(template.New("capture").Parse(capturePageHTML))

// validCapture returns the capture if it exists, is unused and unexpired.
func (s *Server) validCapture(token string) *store.Capture {
	c, err := s.st.GetCapture(token)
	if err != nil || c.UsedAt != nil || time.Now().After(c.ExpiresAt) {
		return nil
	}
	return c
}

const captureCSP = "default-src 'none'; script-src 'self' 'unsafe-inline' https://js.verygoodvault.com; " +
	"frame-src https://*.verygoodvault.com https://*.verygood.systems https:; " +
	"connect-src https://*.verygoodvault.com https://*.verygoodproxy.com https://*.verygood.systems 'self'; " +
	"img-src https://*.verygoodvault.com https://*.verygood.systems data:; style-src 'self' 'unsafe-inline'"

// capturePage serves the one-time Collect.js form; the token is the auth.
func (s *Server) capturePage(w http.ResponseWriter, r *http.Request) {
	c := s.validCapture(r.PathValue("token"))
	if c == nil {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture not found"})
		return
	}
	prov, err := s.cardProvider("vgs")
	if err != nil {
		slog.Debug("capture provider unavailable", "error", err)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "card provider not configured"})
		return
	}
	cfg, err := prov.CaptureConfig()
	if err != nil {
		slog.Debug("capture config failed", "error", err)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "card provider not configured"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", captureCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]string{
		"Token":          c.Token,
		"VaultID":        cfg.Fields["vault_id"],
		"Env":            cfg.Fields["environment"],
		"CollectVersion": cfg.Fields["collect_version"],
	}
	if data["CollectVersion"] == "" {
		data["CollectVersion"] = "3.4.0"
	}
	if err := captureTmpl.Execute(w, data); err != nil {
		slog.Debug("capture template failed", "error", err)
	}
}

type captureCompleteRequest struct {
	Number   string `json:"number"`
	CVC      string `json:"cvc"`
	ExpMonth string `json:"exp_month"`
	ExpYear  string `json:"exp_year"`
	Holder   string `json:"holder"`
	Last4    string `json:"last4"`
	Bin      string `json:"bin"`
}

var tokAliasRE = regexp.MustCompile(`^tok_[A-Za-z0-9_]+$`)
var cvcAliasRE = regexp.MustCompile(`^(tok_[A-Za-z0-9_]+|\d{3,4})$`)
var binRE = regexp.MustCompile(`^\d{6,8}$`)
var last4RE = regexp.MustCompile(`^\d{4}$`)
var yearRE = regexp.MustCompile(`^\d{4}$`)

func luhnPan(s string) bool {
	var digits []byte
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		digits = append(digits, s[i]-'0')
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i])
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// captureComplete stores a card credential from Collect.js aliases. The
// capture is claimed atomically before the credential is written so a token
// can never mint two cards.
func (s *Server) captureComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	c := s.validCapture(r.PathValue("token"))
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "capture not found"})
		return
	}
	var req captureCompleteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	// Number must be a UUID-format alias (tok_…); format-preserving aliases
	// are Luhn-valid and indistinguishable from a PAN. CVC aliases are tok_ or
	// a 3–4 digit length-preserving alias, too short to be a PAN.
	if !tokAliasRE.MatchString(req.Number) || luhnPan(req.Number) ||
		(req.CVC != "" && !cvcAliasRE.MatchString(req.CVC)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "raw card data rejected"})
		return
	}
	m, err := strconv.Atoi(req.ExpMonth)
	if err != nil || m < 1 || m > 12 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad exp_month"})
		return
	}
	if !yearRE.MatchString(req.ExpYear) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad exp_year"})
		return
	}
	if err := s.st.MarkCaptureUsed(c.Token); err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "capture already used"})
		return
	}
	fields := map[string]string{
		"number": req.Number, "exp_month": req.ExpMonth,
		"exp_year": req.ExpYear, "holder": req.Holder,
	}
	if req.CVC != "" {
		fields["cvc"] = req.CVC
	}
	metaMap := map[string]string{"provider": "vgs", "source": "collect"}
	if last4RE.MatchString(req.Last4) {
		metaMap["last4"] = req.Last4
	}
	if binRE.MatchString(req.Bin) {
		metaMap["bin"] = req.Bin
	}
	meta, _ := json.Marshal(metaMap)
	pt, _ := json.Marshal(fields)
	ct, err := crypto.Encrypt(s.dek, pt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encrypt failed"})
		return
	}
	h, err := handle.New("card", "", c.Label)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad label"})
		return
	}
	if err := s.st.AddCredential(&store.Credential{
		Handle: h.String(), Type: "card", Label: c.Label,
		Metadata: string(meta), Ciphertext: ct,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
		return
	}
	detail, _ := json.Marshal(map[string]string{"handle": h.String(), "source": "collect"})
	_ = s.chain.Append(&store.AuditEntry{Handle: h.String(), Edge: "card", Target: "capture", Decision: "allow", Detail: string(detail)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "handle": h.String()})
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
	if len(req.Mapping) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mapping required"})
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
	// Fill returns StatusHostMismatch together with an error; check it first.
	if res.Status == browser.StatusHostMismatch {
		s.auditDeny(a.ID, g.Handle, "browser", host, "host_denied")
		writeJSON(w, http.StatusForbidden, map[string]string{"status": res.Status})
		return
	}
	if err != nil {
		slog.Debug("browser fill failed", "error", err)
		s.auditDeny(a.ID, g.Handle, "browser", host, "fill_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fill failed", "status": res.Status})
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
	GrantToken string            `json:"grant_token"`
	URL        string            `json:"url"`
	Method     string            `json:"method"` // default POST
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
	Amount     int64             `json:"amount"`
	Currency   string            `json:"currency"`
}

// cardProvider returns the configured provider or lazily resolves "vgs".
func (s *Server) cardProvider(name string) (card.Provider, error) {
	if s.cardProv != nil {
		return s.cardProv, nil
	}
	return card.Get(name)
}

// SetCardProvider overrides the card-vault provider (used by tests).
func (s *Server) SetCardProvider(p card.Provider) { s.cardProv = p }

func (s *Server) cardPay(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req payRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	g, err := s.issuer.Verify(req.GrantToken, a.ID)
	if err != nil {
		s.auditDeny(a.ID, "", "card", "", grantReason(err))
		writeJSON(w, grantStatus(err), map[string]string{"error": "invalid grant"})
		return
	}
	kind, _, _, err := handle.Parse(g.Handle)
	if err != nil || kind != "card" {
		s.auditDeny(a.ID, g.Handle, "card", "", "not_card_handle")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant is not for a card handle"})
		return
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		s.auditDeny(a.ID, g.Handle, "card", "", "bad_url")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid url"})
		return
	}
	merchant := u.Hostname()
	var p policy.Policy
	if err := json.Unmarshal([]byte(g.Policy), &p); err != nil {
		s.auditDeny(a.ID, g.Handle, "card", merchant, "grant_invalid")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant_invalid"})
		return
	}
	// Card grants must be scoped to merchants; a spend policy without an
	// amount can't be evaluated.
	if len(p.Hosts) == 0 && (p.Spend == nil || len(p.Spend.Merchants) == 0) {
		s.auditDeny(a.ID, g.Handle, "card", merchant, "unscoped_card_grant")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "card grant must restrict merchants"})
		return
	}
	if p.Spend != nil && req.Amount <= 0 {
		s.auditDeny(a.ID, g.Handle, "card", merchant, "amount_required")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "amount required"})
		return
	}
	d := policy.Evaluate(&p, &policy.GrantView{ExpiresAt: g.ExpiresAt, Uses: g.Uses, MaxUses: g.MaxUses}, policy.Request{
		Host: merchant, Merchant: merchant, Path: u.Path, Method: req.Method,
		Amount: req.Amount, Currency: req.Currency, Now: time.Now(),
	})
	if !d.Allow {
		s.auditDeny(a.ID, g.Handle, "card", merchant, d.Reason)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": d.Reason})
		return
	}
	cred, err := s.st.GetCredential(g.Handle)
	if err != nil {
		s.auditDeny(a.ID, g.Handle, "card", merchant, "credential_error")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
		return
	}
	fields, err := s.credValues(cred)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "credential decrypt failed"})
		return
	}
	defer func() {
		for k := range fields {
			fields[k] = ""
		}
	}()
	provName := "vgs"
	var meta struct {
		Provider string `json:"provider"`
	}
	if json.Unmarshal([]byte(cred.Metadata), &meta) == nil && meta.Provider != "" {
		provName = meta.Provider
	}
	prov, err := s.cardProvider(provName)
	if err != nil {
		slog.Debug("card provider unavailable", "error", err)
		s.auditDeny(a.ID, g.Handle, "card", merchant, "provider_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "pay failed"})
		return
	}
	// Fill before Consume: a fill failure must not burn a grant use.
	freq, err := card.Fill(card.PayRequest{Method: req.Method, URL: req.URL, Headers: req.Headers, Body: req.Body}, fields)
	if err != nil {
		if errors.Is(err, card.ErrCVCRequired) {
			s.auditDeny(a.ID, g.Handle, "card", merchant, "cvc_required")
			writeJSON(w, http.StatusConflict, map[string]string{"error": "cvc_required", "status": "need_cvc"})
			return
		}
		s.auditDeny(a.ID, g.Handle, "card", merchant, "fill_error")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "fill failed"})
		return
	}
	if _, err := s.issuer.Consume(req.GrantToken, a.ID); err != nil {
		s.auditDeny(a.ID, g.Handle, "card", merchant, grantReason(err))
		writeJSON(w, grantStatus(err), map[string]string{"error": "invalid grant"})
		return
	}
	res, err := card.Do(r.Context(), prov, freq, fields)
	if err != nil {
		slog.Debug("card pay failed", "error", err)
		s.auditDeny(a.ID, g.Handle, "card", merchant, "pay_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "pay failed"})
		return
	}
	status := "upstream_error"
	switch {
	case res.Status >= 200 && res.Status < 300:
		status = "ok"
	case res.Status >= 400 && res.Status < 500:
		status = "declined"
	}
	detail, _ := json.Marshal(map[string]any{"amount": req.Amount, "currency": req.Currency})
	_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: g.Handle, Edge: "card", Target: merchant, Decision: "allow", Detail: string(detail)})
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status, "http_status": res.Status, "headers": res.Headers,
		"body": res.Body, "truncated": res.Truncated,
	})
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
