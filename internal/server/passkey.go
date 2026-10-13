package server

// Passkey step-up for approvals.
//
// With no passkey enrolled, approvals work as before: the owner token is
// enough. Once one is enrolled, approving a grant request also needs a
// fresh WebAuthn assertion, bound to that request and to the card it is
// approved with, so an assertion can't be replayed onto another request or
// another card. Denying never needs one.
//
// The first passkey enrolls with the owner token alone. Enrolling another
// or removing one needs an assertion from an enrolled passkey, so a leaked
// owner token can't enroll its own authenticator and walk around the
// step-up.
//
// Config: VALET_PASSKEY_ORIGINS (comma-separated origins the browser runs
// on; default the VALET_PUBLIC_URL origin) and VALET_PASSKEY_RP_ID
// (default the first origin's host).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/joalavedra/valet/internal/store"
)

const (
	passkeySessionTTL = 5 * time.Minute
	maxPasskeySession = 256
	metaPasskeyUserID = "passkey_user_id"
)

var (
	errPasskeyRequired     = errors.New("passkey_required")
	errPasskeyFailed       = errors.New("passkey verification failed")
	errPasskeyUnconfigured = errors.New("passkeys not configured (set VALET_PASSKEY_ORIGINS)")
)

type passkeys struct {
	wa       *webauthn.WebAuthn // nil when not configured
	mu       sync.Mutex
	sessions map[string]passkeySession
}

type passkeySession struct {
	data webauthn.SessionData
	// bind is what the session may be spent on: "register" for an
	// enrollment, else a step-up binding (see stepUpBinding).
	bind string
	exp  time.Time
}

// stepUp is the proof a gated owner action carries: the challenge session
// it answers and the browser's assertion (PublicKeyCredential JSON).
type stepUp struct {
	SessionID string          `json:"session_id"`
	Assertion json.RawMessage `json:"assertion"`
}

// stepUpBinding names exactly what an assertion authorizes.
func stepUpBinding(action string, subject ...string) string {
	return action + "\x00" + strings.Join(subject, "\x00")
}

func newPasskeys() *passkeys {
	p := &passkeys{sessions: map[string]passkeySession{}}
	origins := parseOrigins(os.Getenv("VALET_PASSKEY_ORIGINS"))
	if len(origins) == 0 {
		if pub := os.Getenv("VALET_PUBLIC_URL"); pub != "" {
			if u, err := url.Parse(pub); err == nil && u.Host != "" {
				origins = []string{strings.ToLower(u.Scheme + "://" + u.Host)}
			}
		}
	}
	if len(origins) == 0 {
		return p
	}
	rpID := os.Getenv("VALET_PASSKEY_RP_ID")
	if rpID == "" {
		if u, err := url.Parse(origins[0]); err == nil {
			rpID = u.Hostname()
		}
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Valet",
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err == nil {
		p.wa = wa
	}
	return p
}

func (p *passkeys) put(bind string, data *webauthn.SessionData) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.sessions {
		if now.After(v.exp) {
			delete(p.sessions, k)
		}
	}
	if len(p.sessions) >= maxPasskeySession {
		return "", errors.New("too many pending passkey challenges")
	}
	p.sessions[id] = passkeySession{data: *data, bind: bind, exp: now.Add(passkeySessionTTL)}
	return id, nil
}

// take spends a session: it is gone whether or not it matches.
func (p *passkeys) take(id, bind string) (*webauthn.SessionData, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	delete(p.sessions, id)
	if !ok || s.bind != bind || time.Now().After(s.exp) {
		return nil, false
	}
	return &s.data, true
}

// passkeyOwner is the single WebAuthn user: the Valet owner.
type passkeyOwner struct {
	id    []byte
	creds []webauthn.Credential
}

func (o *passkeyOwner) WebAuthnID() []byte                         { return o.id }
func (o *passkeyOwner) WebAuthnName() string                       { return "owner" }
func (o *passkeyOwner) WebAuthnDisplayName() string                { return "Valet owner" }
func (o *passkeyOwner) WebAuthnCredentials() []webauthn.Credential { return o.creds }

func (s *Server) passkeyOwner() (*passkeyOwner, []store.Passkey, error) {
	uid, err := s.st.Meta(metaPasskeyUserID)
	if errors.Is(err, store.ErrNotFound) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		uid = base64.RawURLEncoding.EncodeToString(b)
		if err := s.st.SetMeta(metaPasskeyUserID, uid); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	id, err := base64.RawURLEncoding.DecodeString(uid)
	if err != nil {
		return nil, nil, err
	}
	list, err := s.st.ListPasskeys()
	if err != nil {
		return nil, nil, err
	}
	o := &passkeyOwner{id: id}
	for _, pk := range list {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(pk.Credential), &c); err != nil {
			return nil, nil, err
		}
		o.creds = append(o.creds, c)
	}
	return o, list, nil
}

// passkeyGate enforces the step-up for an owner action. No passkey
// enrolled means no gate; enrolled but unconfigured fails closed.
func (s *Server) passkeyGate(proof *stepUp, bind string) (credID string, err error) {
	owner, list, err := s.passkeyOwner()
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "", nil
	}
	if s.pk.wa == nil {
		return "", errPasskeyUnconfigured
	}
	if proof == nil || proof.SessionID == "" || len(proof.Assertion) == 0 {
		return "", errPasskeyRequired
	}
	sess, ok := s.pk.take(proof.SessionID, bind)
	if !ok {
		return "", errPasskeyFailed
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(proof.Assertion)
	if err != nil {
		return "", errPasskeyFailed
	}
	cred, err := s.pk.wa.ValidateLogin(owner, *sess, parsed)
	if err != nil || cred.Authenticator.CloneWarning {
		return "", errPasskeyFailed
	}
	credID = base64.RawURLEncoding.EncodeToString(cred.ID)
	cj, _ := json.Marshal(cred)
	if err := s.st.TouchPasskey(credID, string(cj)); err != nil {
		return "", errPasskeyFailed
	}
	return credID, nil
}

// writePasskeyErr maps gate errors to responses. "passkey_required" lets
// a client know to run the ceremony and retry.
func writePasskeyErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errPasskeyRequired):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "passkey_required"})
	case errors.Is(err, errPasskeyFailed):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, errPasskeyUnconfigured):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkey check failed"})
	}
}

type passkeyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// GET /v1/owner/passkeys
func (s *Server) ownerPasskeys(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListPasskeys()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := []passkeyView{}
	for _, p := range list {
		out = append(out, passkeyView{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": s.pk.wa != nil, "required": len(out) > 0, "passkeys": out,
	})
}

// POST /v1/owner/passkeys/challenge {action, approval_id?, handle?, passkey_id?}
// Starts a step-up: the returned options go to navigator.credentials.get,
// and the session can only be spent on the action it names.
func (s *Server) ownerPasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action     string `json:"action"`
		ApprovalID string `json:"approval_id"`
		Handle     string `json:"handle"`
		PasskeyID  string `json:"passkey_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	var bind string
	switch req.Action {
	case "approve":
		if req.ApprovalID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "approval_id required"})
			return
		}
		bind = stepUpBinding("approve", req.ApprovalID, req.Handle)
	case "register":
		bind = stepUpBinding("register")
	case "delete":
		bind = stepUpBinding("delete", req.PasskeyID)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be approve, register or delete"})
		return
	}
	if s.pk.wa == nil {
		writePasskeyErr(w, errPasskeyUnconfigured)
		return
	}
	owner, list, err := s.passkeyOwner()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(list) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no passkey enrolled"})
		return
	}
	opts, data, err := s.pk.wa.BeginLogin(owner, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sid, err := s.pk.put(bind, data)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sid, "options": opts})
}

// POST /v1/owner/passkeys/register/begin {passkey?: stepUp}
func (s *Server) ownerPasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passkey *stepUp `json:"passkey"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
	}
	if s.pk.wa == nil {
		writePasskeyErr(w, errPasskeyUnconfigured)
		return
	}
	if _, err := s.passkeyGate(req.Passkey, stepUpBinding("register")); err != nil {
		writePasskeyErr(w, err)
		return
	}
	owner, _, err := s.passkeyOwner()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var exclude []protocol.CredentialDescriptor
	for i := range owner.creds {
		exclude = append(exclude, owner.creds[i].Descriptor())
	}
	opts, data, err := s.pk.wa.BeginRegistration(owner, webauthn.WithExclusions(exclude))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sid, err := s.pk.put(stepUpBinding("enroll"), data)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sid, "options": opts})
}

// POST /v1/owner/passkeys/register/finish {session_id, name, credential}
func (s *Server) ownerPasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID  string          `json:"session_id"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if s.pk.wa == nil {
		writePasskeyErr(w, errPasskeyUnconfigured)
		return
	}
	sess, ok := s.pk.take(req.SessionID, stepUpBinding("enroll"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown or expired session"})
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad credential"})
		return
	}
	owner, _, err := s.passkeyOwner()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cred, err := s.pk.wa.CreateCredential(owner, *sess, parsed)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey registration failed"})
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > 64 {
		name = name[:64]
	}
	if name == "" {
		name = "Passkey"
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	cj, _ := json.Marshal(cred)
	if err := s.st.AddPasskey(&store.Passkey{ID: id, Name: name, Credential: string(cj)}); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "passkey already enrolled"})
		return
	}
	detail, _ := json.Marshal(map[string]string{"passkey_id": id, "name": name})
	_ = s.chain.Append(&store.AuditEntry{Edge: "owner", Target: "passkey", Decision: "enrolled", Detail: string(detail)})
	writeJSON(w, http.StatusOK, passkeyView{ID: id, Name: name, CreatedAt: time.Now().UTC()})
}

// DELETE /v1/owner/passkeys/{id} {passkey: stepUp}
func (s *Server) ownerPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Passkey *stepUp `json:"passkey"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
	}
	if _, err := s.passkeyGate(req.Passkey, stepUpBinding("delete", id)); err != nil {
		writePasskeyErr(w, err)
		return
	}
	if err := s.st.DeletePasskey(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown passkey"})
		return
	}
	detail, _ := json.Marshal(map[string]string{"passkey_id": id})
	_ = s.chain.Append(&store.AuditEntry{Edge: "owner", Target: "passkey", Decision: "removed", Detail: string(detail)})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}
