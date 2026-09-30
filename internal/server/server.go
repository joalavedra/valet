// Package server exposes Valet's control-plane HTTP API: handle listing,
// grant issuance, browser-fill edge invocation, card pay stub, and audit.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/edge/card"
	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/edge/wallet"
	mppedg "github.com/joalavedra/valet/internal/edge/wallet/mpp"
	"github.com/joalavedra/valet/internal/edge/wallet/openfort"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/handle"
	"github.com/joalavedra/valet/internal/policy"
	"github.com/joalavedra/valet/internal/store"
	"github.com/tempoxyz/mpp-go/pkg/tempo"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
	"github.com/x402-foundation/x402/go/mechanisms/svm"
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

	// allowPrivate lets wallet edges dial non-publicly-routable upstreams
	// (VALET_ALLOW_PRIVATE_UPSTREAMS=1); default is the SSRF hard fence.
	allowPrivate bool
	// approvalMode is "card" (default), "all", or "none".
	approvalMode   string
	approvalTTL    time.Duration
	approvalNotify string
	ownerToken     string
	// captureReturnOrigins restricts capture return_url targets
	// (VALET_CAPTURE_RETURN_ORIGINS, else the VALET_PUBLIC_URL origin).
	captureReturnOrigins []string
	waitersMu            sync.Mutex
	waiters              map[string]*waiter
	// grantLocks serializes edge calls that read+update a grant's spend
	// so concurrent payments can't overshoot the cumulative total.
	grantLocks sync.Map // grant id -> *sync.Mutex
}

// lockGrant returns an unlock func holding a per-grant mutex.
func (s *Server) lockGrant(id string) func() {
	v, _ := s.grantLocks.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// waiter is a shared notification channel for polls on the same request id;
// refs counts registered pollers so a canceled one can't strand the rest.
type waiter struct {
	ch   chan struct{}
	refs int
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
	mode := os.Getenv("VALET_REQUIRE_APPROVAL")
	if mode == "" {
		mode = "card"
	}
	approvalTTL := 10 * time.Minute
	if v := os.Getenv("VALET_APPROVAL_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			approvalTTL = d
		}
	}
	s := &Server{
		st: st, issuer: issuer, chain: chain, filler: filler, dek: dek, egress: eg,
		cdpAllow: allow, mux: http.NewServeMux(),
		approvalMode: mode, approvalTTL: approvalTTL,
		approvalNotify: os.Getenv("VALET_APPROVAL_WEBHOOK"),
		ownerToken:     os.Getenv("VALET_OWNER_TOKEN"),
		allowPrivate:   os.Getenv("VALET_ALLOW_PRIVATE_UPSTREAMS") == "1",
		waiters:        map[string]*waiter{},
	}
	s.captureReturnOrigins = parseOrigins(os.Getenv("VALET_CAPTURE_RETURN_ORIGINS"))
	if len(s.captureReturnOrigins) == 0 {
		// Default: only Valet's own public origin may be a return target.
		if pub := os.Getenv("VALET_PUBLIC_URL"); pub != "" {
			if u, err := url.Parse(pub); err == nil && u.Host != "" &&
				(u.Scheme == "http" || u.Scheme == "https") {
				s.captureReturnOrigins = []string{strings.ToLower(u.Scheme + "://" + u.Host)}
			}
		}
	}
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /v1/handles", s.agentAuth(s.handles))
	s.mux.HandleFunc("POST /v1/grants", s.agentAuth(s.createGrant))
	s.mux.HandleFunc("GET /v1/grants/requests/{id}", s.agentAuth(s.grantRequestStatus))
	s.mux.HandleFunc("POST /v1/edge/browser/fill", s.agentAuth(s.browserFill))
	s.mux.HandleFunc("POST /v1/edge/card/pay", s.agentAuth(s.cardPay))
	s.mux.HandleFunc("POST /v1/edge/wallet/x402", s.agentAuth(s.walletX402))
	s.mux.HandleFunc("POST /v1/edge/wallet/mpp", s.agentAuth(s.walletMPP))
	s.mux.HandleFunc("POST /v1/edge/http/call", s.agentAuth(s.httpCall))
	s.mux.HandleFunc("GET /v1/audit", s.ownerAuth(s.listAudit))
	s.mux.HandleFunc("GET /v1/owner/handles", s.ownerAuth(s.ownerHandles))
	s.mux.HandleFunc("DELETE /v1/owner/handles/{handle...}", s.ownerAuth(s.ownerDeleteHandle))
	s.mux.HandleFunc("GET /v1/owner/approvals", s.ownerAuth(s.ownerApprovals))
	s.mux.HandleFunc("POST /v1/owner/approvals/{id}/approve", s.ownerAuth(s.ownerApprove))
	s.mux.HandleFunc("POST /v1/owner/approvals/{id}/deny", s.ownerAuth(s.ownerDeny))
	s.mux.HandleFunc("GET /v1/owner/grants", s.ownerAuth(s.ownerGrants))
	s.mux.HandleFunc("POST /v1/owner/grants/{id}/revoke", s.ownerAuth(s.ownerRevoke))
	s.mux.HandleFunc("GET /v1/owner/audit", s.ownerAuth(s.listAudit))
	s.mux.HandleFunc("POST /v1/owner/captures", s.ownerAuth(s.ownerCaptures))
	s.mux.HandleFunc("GET /capture/{token}", s.capturePage)
	s.mux.HandleFunc("POST /capture/{token}/complete", s.captureComplete)
	s.mux.HandleFunc("GET /wallet", s.walletPage)
	s.mux.HandleFunc("GET /approve/{id}", s.walletPage)
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

// ownerAuth gates a handler behind VALET_MASTER_PASSWORD or
// VALET_OWNER_TOKEN as a bearer token (either may be empty/disabled).
func (s *Server) ownerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		ok := false
		if mp := os.Getenv("VALET_MASTER_PASSWORD"); mp != "" {
			ok = subtle.ConstantTimeCompare([]byte(tok), []byte(mp)) == 1
		}
		if !ok && s.ownerToken != "" {
			ok = subtle.ConstantTimeCompare([]byte(tok), []byte(s.ownerToken)) == 1
		}
		if !ok {
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
		"ReturnURL":      s.captureReturnURL(c.Metadata),
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
	y, _ := strconv.Atoi(req.ExpYear)
	now := time.Now().UTC()
	if y > now.Year()+30 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad exp_year"})
		return
	}
	if y < now.Year() || (y == now.Year() && m < int(now.Month())) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "card expired"})
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
	// Client-supplied last4/bin are display-only and spoofable; prefer the
	// card provider's authoritative reveal when it supports AliasInspector.
	metaMap := map[string]string{"provider": "vgs", "source": "collect", "last4_source": "client"}
	if last4RE.MatchString(req.Last4) {
		metaMap["last4"] = req.Last4
	}
	if binRE.MatchString(req.Bin) {
		metaMap["bin"] = req.Bin
	}
	if prov, err := s.cardProvider("vgs"); err == nil {
		if insp, ok := prov.(card.AliasInspector); ok {
			ictx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			l4, bin, ierr := insp.InspectAlias(ictx, req.Number)
			cancel()
			if ierr != nil {
				slog.Debug("alias inspect failed; keeping client last4", "error", ierr)
			} else if l4 != "" {
				metaMap["last4"] = l4
				metaMap["last4_source"] = "vgs"
				if bin != "" {
					metaMap["bin"] = bin
				} else {
					delete(metaMap, "bin")
				}
			}
		}
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
	// Replacing an existing card must not leave old grants pointing at the
	// new credential: revoke live grants + deny pending approvals first.
	_, replacing := s.st.GetCredential(h.String())
	if replacing == nil {
		var pendingIDs []string
		if aps, err := s.st.ListApprovals("pending"); err == nil {
			for _, ap := range aps {
				if ap.Handle == h.String() {
					pendingIDs = append(pendingIDs, ap.ID)
				}
			}
		}
		if n, err := s.st.RevokeGrantsForHandle(h.String()); err != nil {
			slog.Debug("grant revoke on replace failed", "error", err)
		} else if n > 0 {
			for _, id := range pendingIDs {
				s.signalWaiters(id)
			}
			detail := fmt.Sprintf("%d grants revoked", n)
			_ = s.chain.Append(&store.AuditEntry{Handle: h.String(), Edge: "capture", Target: "replace", Decision: "allow", Detail: detail})
		}
	}
	if err := s.st.UpsertCredential(&store.Credential{
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

func (s *Server) listHandles(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handles(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	s.listHandles(w, r)
}

// ownerHandles exposes the same handle list to the owner.
func (s *Server) ownerHandles(w http.ResponseWriter, r *http.Request) {
	s.listHandles(w, r)
}

// ownerDeleteHandle removes a stored credential (e.g. a card) the owner no
// longer wants. Handles contain :// so they arrive in the wildcard path.
func (s *Server) ownerDeleteHandle(w http.ResponseWriter, r *http.Request) {
	h, err := url.PathUnescape(r.PathValue("handle"))
	if err != nil || h == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad handle"})
		return
	}
	if _, err := s.st.GetCredential(h); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "handle not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
		return
	}
	if err := s.st.DeleteCredential(h); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
		return
	}
	_ = s.chain.Append(&store.AuditEntry{Handle: h, Edge: "owner", Target: "delete", Decision: "allow", Detail: h})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
	Purpose string         `json:"purpose"`
}

// approvalID returns a fresh random request id (16 bytes hex).
func approvalID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// approveURL builds the human-facing link for a pending request. Relative
// when VALET_PUBLIC_URL is unset.
func approveURL(id string) string {
	base := strings.TrimRight(os.Getenv("VALET_PUBLIC_URL"), "/")
	return base + "/approve/" + id
}

// PublicBase returns the externally reachable base URL of this server:
// VALET_PUBLIC_URL, else http:// + VALET_LISTEN (default :14400, a bare
// port becoming localhost:port).
func PublicBase() string {
	if base := os.Getenv("VALET_PUBLIC_URL"); base != "" {
		return strings.TrimRight(base, "/")
	}
	listen := os.Getenv("VALET_LISTEN")
	if listen == "" {
		listen = ":14400"
	}
	if len(listen) > 0 && listen[0] == ':' {
		listen = "localhost" + listen
	}
	return "http://" + listen
}

// approvalRequired reports whether a grant request must wait for a human.
func (s *Server) approvalRequired(credType string, p *policy.Policy) bool {
	if p.RequireHuman {
		return true
	}
	switch s.approvalMode {
	case "all":
		return true
	case "none":
		return false
	default:
		// Comma-separated credential kinds, e.g. "card,wallet".
		for _, t := range strings.Split(s.approvalMode, ",") {
			if strings.TrimSpace(t) == credType {
				return true
			}
		}
		return false
	}
}

// signalWaiters wakes any long-polling grantRequestStatus handlers for id.
func (s *Server) signalWaiters(id string) {
	s.waitersMu.Lock()
	defer s.waitersMu.Unlock()
	if w, ok := s.waiters[id]; ok {
		delete(s.waiters, id)
		close(w.ch)
	}
}

// waiterChan registers a poller on id's shared channel (refcounted),
// creating it when absent.
func (s *Server) waiterChan(id string) chan struct{} {
	s.waitersMu.Lock()
	defer s.waitersMu.Unlock()
	w, ok := s.waiters[id]
	if !ok {
		w = &waiter{ch: make(chan struct{})}
		s.waiters[id] = w
	}
	w.refs++
	return w.ch
}

// dropWaiter releases one poll's reference; the entry is removed only when
// no pollers remain on this channel, so finished polls can't strand
// concurrent ones sharing it.
func (s *Server) dropWaiter(id string, ch chan struct{}) {
	s.waitersMu.Lock()
	defer s.waitersMu.Unlock()
	w, ok := s.waiters[id]
	if !ok || w.ch != ch {
		return
	}
	w.refs--
	if w.refs <= 0 {
		delete(s.waiters, id)
	}
}

// notifyWebhook best-effort POSTs the pending request to VALET_APPROVAL_WEBHOOK.
func (s *Server) notifyWebhook(a *store.Approval, agentName, label, policyJSON string) {
	if s.approvalNotify == "" {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]any{
			"request_id":  a.ID,
			"agent":       agentName,
			"handle":      a.Handle,
			"label":       label,
			"purpose":     a.Purpose,
			"policy":      json.RawMessage(policyJSON),
			"approve_url": approveURL(a.ID),
		})
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(s.approvalNotify, "application/json", bytes.NewReader(body))
		if err != nil {
			slog.Debug("approval webhook failed", "error", err)
			return
		}
		resp.Body.Close()
	}()
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
	pj, _ := json.Marshal(p)
	if s.approvalRequired(cred.Type, p) {
		id, err := approvalID()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ap := &store.Approval{
			ID: id, AgentID: a.ID, Handle: cred.Handle, Purpose: req.Purpose,
			Policy: string(pj), TTL: time.Duration(req.TTL) * time.Second,
			MaxUses: req.MaxUses, Status: "pending",
			ExpiresAt: time.Now().UTC().Add(s.approvalTTL),
		}
		if err := s.st.CreateApproval(ap); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		detail, _ := json.Marshal(map[string]string{"request_id": id, "purpose": req.Purpose})
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: cred.Handle, Edge: "control", Target: "grant", Decision: "pending_approval", Detail: string(detail)})
		s.notifyWebhook(ap, a.Name, cred.Label, string(pj))
		slog.Info("approval requested", "request_id", id, "agent", a.Name, "handle", cred.Handle, "purpose", req.Purpose, "approve_url", approveURL(id))
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status": "pending_approval", "request_id": id,
			"expires_at": ap.ExpiresAt, "approve_url": approveURL(id),
		})
		return
	}
	ttl := time.Duration(req.TTL) * time.Second
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
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
		} else if errors.Is(err, grant.ErrRevoked) {
			reason = "grant_revoked"
		}
		s.auditDeny(a.ID, "", "browser", "", reason)
		writeJSON(w, code, map[string]string{"error": grantErrorMessage(err, reason)})
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

// walletFetch does the x402 fetch; replaceable in tests.
var walletFetch = wallet.Fetch

// SetWalletFetcher overrides the x402 fetch implementation (used by tests).
func (s *Server) SetWalletFetcher(f func(context.Context, wallet.Signers, wallet.Request, wallet.Policy) (*wallet.Response, error)) {
	walletFetch = f
}

// mppFetch does the MPP (Tempo charge) fetch; replaceable in tests.
var mppFetch = mppedg.Fetch

// SetMPPFetcher overrides the MPP fetch implementation (used by tests).
func (s *Server) SetMPPFetcher(f func(context.Context, mppedg.HashSigner, wallet.Request, mppedg.Policy, tempo.RPCClient) (*wallet.Response, error)) {
	mppFetch = f
}

// walletRequest is the shared request shape for wallet payment edges.
type walletRequest struct {
	GrantToken string            `json:"grant_token"`
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
	MaxAmount  int64             `json:"max_amount"` // caller cap, minor units; 0 = none
}

type walletMeta struct {
	Provider string `json:"provider"`
	Address  string `json:"address"`
	Network  string `json:"network"` // eip155 refs, comma-separated list allowed
	Asset    string `json:"asset"`
}

// walletCallCtx carries the verified grant, decrypted credential and
// Openfort client shared by the x402 and MPP payment edges. Callers
// must defer unlock() and wipe(fields).
type walletCallCtx struct {
	g       *store.Grant
	cred    *store.Credential
	meta    walletMeta
	fields  map[string]string
	of      *openfort.Client
	signers wallet.Signers
	pol     *policy.Policy
	capAmt  *big.Int
	target  string
	unlock  func()
}

// walletPrelude runs the common verification path for wallet payment
// edges: grant verify + wallet kind, per-grant lock with a fresh Spent
// read, https+host check, hosts-scope requirement, policy evaluation,
// credential decrypt, Openfort client and the per-call amount cap.
// On failure it writes the error response and returns ok=false.
func (s *Server) walletPrelude(w http.ResponseWriter, r *http.Request, a *store.Agent, req *walletRequest) (*walletCallCtx, bool) {
	g, err := s.issuer.Verify(req.GrantToken, a.ID)
	if err != nil {
		s.auditDeny(a.ID, "", "wallet", "", grantReason(err))
		writeJSON(w, grantStatus(err), map[string]string{"error": grantErrorMessage(err, grantReason(err))})
		return nil, false
	}
	kind, _, _, err := handle.Parse(g.Handle)
	if err != nil || kind != "wallet" {
		s.auditDeny(a.ID, g.Handle, "wallet", "", "not_wallet_handle")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant is not for a wallet handle"})
		return nil, false
	}
	// Serialize the spend check+record per grant; re-read so Spent is
	// fresh after another call may have paid.
	unlock := s.lockGrant(g.ID)
	ok := false
	defer func() {
		if !ok {
			unlock()
		}
	}()
	if fresh, err := s.st.GetGrant(g.ID); err == nil {
		g = fresh
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		s.auditDeny(a.ID, g.Handle, "wallet", "", "bad_url")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid url"})
		return nil, false
	}
	target := u.Hostname()
	var p policy.Policy
	if err := json.Unmarshal([]byte(g.Policy), &p); err != nil {
		s.auditDeny(a.ID, g.Handle, "wallet", target, "grant_invalid")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant_invalid"})
		return nil, false
	}
	// Wallet grants must be scoped to hosts — payment network/amounts are
	// unknown until the 402 arrives, so host scope is the hard outer fence.
	if len(p.Hosts) == 0 {
		s.auditDeny(a.ID, g.Handle, "wallet", target, "unscoped_wallet_grant")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet grant must restrict hosts"})
		return nil, false
	}
	d := policy.Evaluate(&p, &policy.GrantView{ExpiresAt: g.ExpiresAt, Uses: g.Uses, MaxUses: g.MaxUses, Spent: g.Spent}, policy.Request{
		Host: target, Method: req.Method, Path: u.Path, Now: time.Now(),
	})
	if !d.Allow {
		s.auditDeny(a.ID, g.Handle, "wallet", target, d.Reason)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": d.Reason})
		return nil, false
	}
	cred, err := s.st.GetCredential(g.Handle)
	if err != nil {
		s.auditDeny(a.ID, g.Handle, "wallet", target, "credential_error")
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown handle"})
		return nil, false
	}
	var meta walletMeta
	json.Unmarshal([]byte(cred.Metadata), &meta)
	if meta.Provider != "openfort" || meta.Address == "" || meta.Network == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet metadata incomplete"})
		return nil, false
	}
	fields, err := s.credValues(cred)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "credential decrypt failed"})
		return nil, false
	}
	of, err := openfort.New(fields["secret_key"], fields["wallet_secret"])
	if err != nil {
		for k := range fields {
			fields[k] = ""
		}
		slog.Debug("openfort client init failed", "error", err)
		s.auditDeny(a.ID, g.Handle, "wallet", target, "wallet_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "wallet unavailable"})
		return nil, false
	}
	if fields["account_id"] == "" {
		for k := range fields {
			fields[k] = ""
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet has no account_id"})
		return nil, false
	}
	// Per-call cap = smallest of the configured ceilings.
	var capAmt *big.Int
	capAt := func(v int64) {
		if v <= 0 {
			return
		}
		n := big.NewInt(v)
		if capAmt == nil || n.Cmp(capAmt) < 0 {
			capAmt = n
		}
	}
	if p.Spend != nil {
		capAt(p.Spend.PerTx)
		if p.Spend.Total > 0 {
			capAt(p.Spend.Total - g.Spent)
		}
	}
	capAt(req.MaxAmount)
	if p.Spend != nil && p.Spend.Total > 0 && p.Spend.Total-g.Spent <= 0 {
		for k := range fields {
			fields[k] = ""
		}
		s.auditDeny(a.ID, g.Handle, "wallet", target, "grant total limit exceeded")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "grant total limit exceeded"})
		return nil, false
	}
	// Build the chain signers. EVM always present (account_id checked
	// above); SVM only when the credential carries an svm account pair.
	signers := wallet.Signers{EVM: wallet.NewSigner(of, fields["account_id"], meta.Address)}
	if fields["svm_account_id"] != "" {
		sv, err := wallet.NewSvmSigner(of, fields["svm_account_id"], fields["svm_address"])
		if err != nil {
			wipeFields(fields)
			slog.Debug("svm signer init failed", "error", err)
			s.auditDeny(a.ID, g.Handle, "wallet", target, "wallet_error")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet svm metadata incomplete"})
			return nil, false
		}
		signers.SVM = sv
	}
	hasSolana := false
	for _, n := range walletNetworks(meta.Network) {
		if strings.HasPrefix(n, "solana:") {
			hasSolana = true
		}
	}
	if hasSolana && signers.SVM == nil {
		wipeFields(fields)
		s.auditDeny(a.ID, g.Handle, "wallet", target, "policy_denied")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet has no solana account"})
		return nil, false
	}
	ok = true
	return &walletCallCtx{
		g: g, cred: cred, meta: meta, fields: fields, of: of, signers: signers,
		pol: &p, capAmt: capAmt, target: target, unlock: unlock,
	}, true
}

func wipeFields(fields map[string]string) {
	for k := range fields {
		fields[k] = ""
	}
}

// walletNetworks splits the credential's network metadata, which may be
// a comma-separated list of eip155 refs.
func walletNetworks(raw string) []string {
	var out []string
	for _, n := range strings.Split(raw, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// walletChainIDs parses the eip155 chain ids out of the network list;
// only `eip155:<positive int>` entries count — bare numbers or garbage
// are ignored.
func walletChainIDs(nets []string) []int64 {
	var out []int64
	for _, n := range nets {
		if !strings.HasPrefix(n, "eip155:") {
			continue
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(n, "eip155:"), 10, 64)
		if err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

// walletChainAssets resolves the credential's asset metadata into a
// per-chain currency allowlist for the MPP edge. An explicit 0x asset
// applies to every chain; empty/USDC resolves to that chain's Tempo
// defaults.
func walletChainAssets(nets []string, asset string) map[int64][]string {
	out := map[int64][]string{}
	for _, id := range walletChainIDs(nets) {
		switch {
		case strings.HasPrefix(asset, "0x"):
			out[id] = []string{strings.ToLower(asset)}
		default:
			var list []string
			for _, a := range tempo.DefaultCurrenciesForChain(id) {
				list = append(list, strings.ToLower(a))
			}
			out[id] = list
		}
	}
	return out
}

// walletAllowedAssets resolves the credential's asset metadata into the
// allowed token contract addresses for every configured network.
// "USDC" (or empty) means the network's default payment asset: Tempo
// chains use tempo.DefaultCurrenciesForChain, others use the x402
// NetworkConfigs default. A 0x address is used verbatim.
func walletAllowedAssets(nets []string, asset string) ([]string, bool) {
	if strings.HasPrefix(asset, "0x") {
		return []string{strings.ToLower(asset)}, true
	}
	if asset != "" && !strings.EqualFold(asset, "usdc") {
		return nil, false
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range nets {
		var list []string
		if id, err := strconv.ParseInt(strings.TrimPrefix(n, "eip155:"), 10, 64); err == nil && tempo.IsKnownChainID(id) {
			list = tempo.DefaultCurrenciesForChain(id)
		} else if cfg, ok := evm.NetworkConfigs[n]; ok {
			list = []string{cfg.DefaultAsset.Address}
		} else if cfg, ok := svm.NetworkConfigs[n]; ok {
			list = []string{cfg.DefaultAsset.Address}
		} else {
			return nil, false
		}
		for _, a := range list {
			if la := strings.ToLower(a); !seen[la] {
				seen[la] = true
				out = append(out, la)
			}
		}
	}
	return out, true
}

func (s *Server) walletX402(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req walletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	c, ok := s.walletPrelude(w, r, a, &req)
	if !ok {
		return
	}
	defer c.unlock()
	defer wipeFields(c.fields)
	nets := walletNetworks(c.meta.Network)
	assets, ok := walletAllowedAssets(nets, c.meta.Asset)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet metadata incomplete"})
		return
	}
	res, err := walletFetch(r.Context(), c.signers, wallet.Request{
		Method: req.Method, URL: req.URL, Headers: req.Headers, Body: req.Body,
	}, wallet.Policy{
		MaxAmount:    c.capAmt,
		Networks:     nets,
		Assets:       assets,
		AllowPrivate: s.allowPrivate,
	})
	if err != nil {
		if errors.Is(err, wallet.ErrPolicy) {
			s.auditDeny(a.ID, c.g.Handle, "wallet", c.target, "policy_denied")
			msg := strings.TrimPrefix(err.Error(), wallet.ErrPolicy.Error()+": ")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
			return
		}
		slog.Debug("x402 fetch failed", "error", err)
		s.auditDeny(a.ID, c.g.Handle, "wallet", c.target, "fetch_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed"})
		return
	}
	s.writeWalletResult(w, r, a, c, &req, res, "x402")
}

func (s *Server) walletMPP(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req walletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	c, ok := s.walletPrelude(w, r, a, &req)
	if !ok {
		return
	}
	defer c.unlock()
	defer wipeFields(c.fields)
	nets := walletNetworks(c.meta.Network)
	assets, ok := walletAllowedAssets(nets, c.meta.Asset)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wallet metadata incomplete"})
		return
	}
	signer := mppedg.WalletSigner(wallet.NewSigner(c.of, c.fields["account_id"], c.meta.Address))
	res, err := mppFetch(r.Context(), signer, wallet.Request{
		Method: req.Method, URL: req.URL, Headers: req.Headers, Body: req.Body,
	}, mppedg.Policy{
		ChainIDs:     walletChainIDs(nets),
		Assets:       assets,
		ChainAssets:  walletChainAssets(nets, c.meta.Asset),
		MaxAmount:    c.capAmt,
		AllowPrivate: s.allowPrivate,
	}, nil)
	if err != nil {
		if errors.Is(err, wallet.ErrPolicy) {
			s.auditDeny(a.ID, c.g.Handle, "wallet", c.target, "policy_denied")
			msg := strings.TrimPrefix(err.Error(), wallet.ErrPolicy.Error()+": ")
			writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
			return
		}
		slog.Debug("mpp fetch failed", "error", err)
		s.auditDeny(a.ID, c.g.Handle, "wallet", c.target, "fetch_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed"})
		return
	}
	s.writeWalletResult(w, r, a, c, &req, res, "mpp")
}

// writeWalletResult consumes a grant use + records spend only when a
// payment settled, appends the audit entry, and writes the JSON reply.
func (s *Server) writeWalletResult(w http.ResponseWriter, r *http.Request, a *store.Agent, c *walletCallCtx, req *walletRequest, res *wallet.Response, protocol string) {
	status := "ok"
	switch {
	case res.Payment != nil:
		status = "paid"
		if _, err := s.issuer.Consume(req.GrantToken, a.ID); err != nil {
			slog.Debug("grant consume after payment failed", "error", err)
		}
		if amt, ok := wallet.Amount(res.Payment); ok && amt.IsInt64() {
			if err := s.st.AddGrantSpend(c.g.ID, amt.Int64()); err != nil {
				slog.Debug("spend record failed", "error", err)
			}
		}
		detail, _ := json.Marshal(map[string]string{
			"status": "paid", "protocol": protocol, "amount": res.Payment.Amount, "asset": res.Payment.Asset,
			"network": res.Payment.Network, "pay_to": res.Payment.PayTo, "tx": res.Payment.Transaction,
		})
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: c.g.Handle, Edge: "wallet", Target: c.target, Decision: "allow", Detail: string(detail)})
	case res.PaymentAttempted:
		// Signed but the payee rejected it — no money moved, so no
		// grant use or spend is recorded.
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: c.g.Handle, Edge: "wallet", Target: c.target, Decision: "allow", Detail: `{"status":"payment_rejected","protocol":"` + protocol + `"}`})
	default:
		_ = s.chain.Append(&store.AuditEntry{AgentID: a.ID, Handle: c.g.Handle, Edge: "wallet", Target: c.target, Decision: "allow", Detail: `{"status":"no_payment","protocol":"` + protocol + `"}`})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status, "http_status": res.Status, "headers": res.Headers,
		"body": res.Body, "truncated": res.Truncated, "payment": res.Payment,
	})
}

func (s *Server) cardPay(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	var req payRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	g, err := s.issuer.Verify(req.GrantToken, a.ID)
	if err != nil {
		s.auditDeny(a.ID, "", "card", "", grantReason(err))
		writeJSON(w, grantStatus(err), map[string]string{"error": grantErrorMessage(err, grantReason(err))})
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
	d := policy.Evaluate(&p, &policy.GrantView{ExpiresAt: g.ExpiresAt, Uses: g.Uses, MaxUses: g.MaxUses, Spent: g.Spent}, policy.Request{
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
		writeJSON(w, grantStatus(err), map[string]string{"error": grantErrorMessage(err, grantReason(err))})
		return
	}
	if err := s.st.AddGrantSpend(g.ID, req.Amount); err != nil {
		slog.Debug("spend record failed", "error", err)
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
		writeJSON(w, grantStatus(err), map[string]string{"error": grantErrorMessage(err, grantReason(err))})
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
		writeJSON(w, grantStatus(err), map[string]string{"error": grantErrorMessage(err, grantReason(err))})
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
	case errors.Is(err, grant.ErrRevoked):
		return "grant_revoked"
	default:
		return "grant_invalid"
	}
}

// grantErrorMessage is the agent-facing error text for a verify failure.
func grantErrorMessage(err error, reason string) string {
	if errors.Is(err, grant.ErrRevoked) {
		return "grant revoked"
	}
	if reason == "grant_invalid" {
		return "invalid grant"
	}
	return reason
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
	entries, err := s.st.ListAuditRecent(500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

// expireIfStale lazily marks a pending approval past its TTL as expired.
func (s *Server) expireIfStale(ap *store.Approval) {
	if ap.Status != "pending" || !time.Now().After(ap.ExpiresAt) {
		return
	}
	err := s.st.DecideApproval(ap.ID, "expired", "", nil)
	if err == nil {
		ap.Status = "expired"
		s.signalWaiters(ap.ID)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		// Someone decided it concurrently — reflect the real outcome.
		if fresh, ferr := s.st.GetApproval(ap.ID); ferr == nil {
			ap.Status = fresh.Status
			ap.GrantID = fresh.GrantID
			ap.TokenCT = fresh.TokenCT
		}
	}
}

// grantRequestStatus lets an agent poll (or long-poll) its own approval.
func (s *Server) grantRequestStatus(w http.ResponseWriter, r *http.Request, a *store.Agent) {
	id := r.PathValue("id")
	ap, err := s.st.GetApproval(id)
	if err != nil || ap.AgentID != a.ID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
		return
	}
	waitSec, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if waitSec < 0 {
		waitSec = 0
	}
	if waitSec > 120 {
		waitSec = 120
	}
	deadline := time.Now().Add(time.Duration(waitSec) * time.Second)
	for {
		// Register the waiter before re-reading status so a decision that
		// lands between the read and the select still wakes this poll.
		// wait=0 polls never block, so they skip registration entirely.
		var ch chan struct{}
		if waitSec > 0 {
			ch = s.waiterChan(ap.ID)
		}
		release := func() {
			if ch != nil {
				s.dropWaiter(id, ch)
			}
		}
		ap, err = s.st.GetApproval(id)
		if err != nil {
			release()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "request not found"})
			return
		}
		s.expireIfStale(ap)
		if ap.Status != "pending" {
			resp := map[string]any{"status": ap.Status, "request_id": ap.ID}
			if ap.Status == "approved" {
				tok, derr := crypto.Decrypt(s.dek, ap.TokenCT)
				if derr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token decrypt failed"})
					return
				}
				resp["grant_id"] = ap.GrantID
				resp["token"] = string(tok)
				if g, gerr := s.st.GetGrant(ap.GrantID); gerr == nil {
					resp["expires_at"] = g.ExpiresAt
				}
			}
			release()
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if waitSec == 0 || !time.Now().Before(deadline) {
			release()
			writeJSON(w, http.StatusOK, map[string]any{"status": "pending", "request_id": ap.ID})
			return
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ch:
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			release()
			return
		}
		timer.Stop()
		release()
	}
}

type ownerApprovalView struct {
	ID        string          `json:"id"`
	Agent     string          `json:"agent"`
	Handle    string          `json:"handle"`
	Type      string          `json:"type"`
	Label     string          `json:"label"`
	Site      string          `json:"site"`
	Metadata  string          `json:"metadata"`
	Purpose   string          `json:"purpose"`
	Policy    json.RawMessage `json:"policy"`
	TTL       int64           `json:"ttl"`
	MaxUses   int             `json:"max_uses"`
	Status    string          `json:"status"`
	GrantID   string          `json:"grant_id"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	DecidedAt *time.Time      `json:"decided_at"`
}

// approvalView renders an approval for owner consumption.
func (s *Server) approvalView(ap *store.Approval) ownerApprovalView {
	kind, site, label, _ := handle.Parse(ap.Handle)
	v := ownerApprovalView{
		ID: ap.ID, Handle: ap.Handle, Type: kind, Site: site, Label: label,
		Purpose: ap.Purpose, Policy: json.RawMessage(ap.Policy),
		TTL: int64(ap.TTL / time.Second), MaxUses: ap.MaxUses, Status: ap.Status,
		GrantID: ap.GrantID, CreatedAt: ap.CreatedAt, ExpiresAt: ap.ExpiresAt,
		DecidedAt: ap.DecidedAt,
	}
	if ag, err := s.st.GetAgent(ap.AgentID); err == nil {
		v.Agent = ag.Name
	}
	if kind != "api" {
		if c, err := s.st.GetCredential(ap.Handle); err == nil {
			v.Metadata = c.Metadata
			if c.Label != "" {
				v.Label = c.Label
			}
			if c.Site != "" {
				v.Site = c.Site
			}
		}
	}
	return v
}

func (s *Server) ownerApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	list, err := s.st.ListApprovals(status)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := []ownerApprovalView{}
	for i := range list {
		s.expireIfStale(&list[i])
		if status == "pending" && list[i].Status != "pending" {
			continue
		}
		out = append(out, s.approvalView(&list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": out})
}

func (s *Server) ownerApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ap, err := s.st.GetApproval(id)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not pending"})
		return
	}
	s.expireIfStale(ap)
	if ap.Status != "pending" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not pending"})
		return
	}
	ttl := ap.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	token, g, err := s.issuer.Issue(ap.AgentID, ap.Handle, ap.Policy, ttl, ap.MaxUses)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ct, err := crypto.Encrypt(s.dek, []byte(token))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encrypt failed"})
		return
	}
	if err := s.st.DecideApproval(id, "approved", g.ID, ct); err != nil {
		// Lost a race against another decider — undo the issued grant.
		_ = s.st.RevokeGrant(g.ID)
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not pending"})
		return
	}
	detail, _ := json.Marshal(map[string]string{"request_id": id, "grant_id": g.ID, "via": "owner"})
	_ = s.chain.Append(&store.AuditEntry{AgentID: ap.AgentID, Handle: ap.Handle, Edge: "control", Target: "grant", Decision: "granted", Detail: string(detail)})
	s.signalWaiters(id)
	writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "grant_id": g.ID, "expires_at": g.ExpiresAt})
}

func (s *Server) ownerDeny(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ap, err := s.st.GetApproval(id)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not pending"})
		return
	}
	s.expireIfStale(ap)
	if ap.Status != "pending" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not pending"})
		return
	}
	if err := s.st.DecideApproval(id, "denied", "", nil); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "not pending"})
		return
	}
	detail, _ := json.Marshal(map[string]string{"request_id": id, "via": "owner"})
	_ = s.chain.Append(&store.AuditEntry{AgentID: ap.AgentID, Handle: ap.Handle, Edge: "control", Target: "grant", Decision: "denied", Detail: string(detail)})
	s.signalWaiters(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}

type ownerGrantView struct {
	ID        string          `json:"id"`
	Agent     string          `json:"agent"`
	Handle    string          `json:"handle"`
	Label     string          `json:"label"`
	Type      string          `json:"type"`
	Policy    json.RawMessage `json:"policy"`
	ExpiresAt time.Time       `json:"expires_at"`
	MaxUses   int             `json:"max_uses"`
	Uses      int             `json:"uses"`
	Spent     int64           `json:"spent"`
	CreatedAt time.Time       `json:"created_at"`
	RevokedAt *time.Time      `json:"revoked_at"`
	Active    bool            `json:"active"`
}

func (s *Server) ownerGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.st.ListGrants()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := []ownerGrantView{}
	for _, g := range grants {
		kind, _, label, _ := handle.Parse(g.Handle)
		v := ownerGrantView{
			ID: g.ID, Handle: g.Handle, Type: kind, Label: label,
			Policy: json.RawMessage(g.Policy), ExpiresAt: g.ExpiresAt,
			MaxUses: g.MaxUses, Uses: g.Uses, CreatedAt: g.CreatedAt,
			RevokedAt: g.RevokedAt,
		}
		if ag, err := s.st.GetAgent(g.AgentID); err == nil {
			v.Agent = ag.Name
		}
		if c, err := s.st.GetCredential(g.Handle); err == nil && c.Label != "" {
			v.Label = c.Label
		}
		var p policy.Policy
		json.Unmarshal([]byte(g.Policy), &p)
		effectiveMax := g.MaxUses
		if effectiveMax == 0 || (p.MaxUses > 0 && p.MaxUses < effectiveMax) {
			effectiveMax = p.MaxUses
		}
		v.Spent = g.Spent
		spendOK := p.Spend == nil || p.Spend.Total == 0 || g.Spent < p.Spend.Total
		v.Active = v.RevokedAt == nil && time.Now().Before(g.ExpiresAt) && (effectiveMax == 0 || g.Uses < effectiveMax) && spendOK
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func (s *Server) ownerRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.st.RevokeGrant(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "grant not found"})
		return
	}
	g, _ := s.st.GetGrant(id)
	detail, _ := json.Marshal(map[string]string{"grant_id": id, "via": "owner"})
	e := &store.AuditEntry{Edge: "control", Target: "grant", Decision: "revoked", Detail: string(detail)}
	if g != nil {
		e.AgentID = g.AgentID
		e.Handle = g.Handle
	}
	_ = s.chain.Append(e)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// parseOrigins normalizes a comma-separated origin list: trimmed,
// lowercased, empty entries dropped.
func parseOrigins(list string) []string {
	var out []string
	for _, o := range strings.Split(list, ",") {
		if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// returnOriginAllowed reports whether u's origin is in the allowlist.
func returnOriginAllowed(allow []string, u *url.URL) bool {
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, a := range allow {
		if a == origin {
			return true
		}
	}
	return false
}

// captureReturnURL extracts an http(s) return_url from capture metadata;
// anything else — including non-allowlisted origins — is ignored (never
// redirected to).
func (s *Server) captureReturnURL(metadata string) string {
	var meta struct {
		ReturnURL string `json:"return_url"`
	}
	if json.Unmarshal([]byte(metadata), &meta) != nil || meta.ReturnURL == "" {
		return ""
	}
	u, err := url.Parse(meta.ReturnURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	if !returnOriginAllowed(s.captureReturnOrigins, u) {
		return ""
	}
	return meta.ReturnURL
}

type ownerCaptureRequest struct {
	Label      string `json:"label"`
	TTLSeconds int64  `json:"ttl_seconds"`
	ReturnURL  string `json:"return_url"`
}

// ownerCaptures mints a one-time card-capture link (same shape as
// `valet card capture`) for embedding into approval/phone flows.
func (s *Server) ownerCaptures(w http.ResponseWriter, r *http.Request) {
	var req ownerCaptureRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if req.Label == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label required"})
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if req.TTLSeconds == 0 {
		ttl = 15 * time.Minute
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad ttl_seconds"})
		return
	}
	if req.ReturnURL != "" {
		u, err := url.Parse(req.ReturnURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "return_url must be http(s)"})
			return
		}
		if !returnOriginAllowed(s.captureReturnOrigins, u) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "return_url origin not allowed"})
			return
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token failed"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	expires := time.Now().UTC().Add(ttl)
	metaMap := map[string]string{"provider": "vgs"}
	if req.ReturnURL != "" {
		metaMap["return_url"] = req.ReturnURL
	}
	meta, _ := json.Marshal(metaMap)
	if err := s.st.CreateCapture(&store.Capture{
		Token: token, Label: req.Label,
		Metadata: string(meta), ExpiresAt: expires,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "url": PublicBase() + "/capture/" + token, "expires_at": expires,
	})
}

//go:embed wallet.html
var walletHTML []byte

const walletCSP = "default-src 'none'; script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"

// walletPage serves the owner wallet/approval SPA; the page reads the
// request id from its own URL, so no templating is applied.
func (s *Server) walletPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", walletCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(walletHTML)
}
