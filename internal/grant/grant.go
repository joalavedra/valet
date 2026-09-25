// Package grant issues and verifies signed grant tokens. A token is
// "<id>.<hmac>" where the HMAC binds the grant id to the agent, handle,
// and expiry already recorded in the store.
package grant

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/joalavedra/valet/internal/store"
)

var (
	ErrInvalid   = errors.New("grant: invalid token")
	ErrExpired   = errors.New("grant: expired")
	ErrExhausted = errors.New("grant: use limit reached")
)

// Issuer signs and verifies grant tokens.
type Issuer struct {
	st     store.Store
	secret []byte
}

// NewIssuer returns an Issuer using st and an HMAC secret (e.g. the DEK).
func NewIssuer(st store.Store, secret []byte) *Issuer {
	return &Issuer{st: st, secret: secret}
}

func (i *Issuer) mac(agentID int64, id, handle string, exp time.Time) string {
	h := hmac.New(sha256.New, i.secret)
	fmt.Fprintf(h, "%d|%s|%s|%d", agentID, id, handle, exp.Unix())
	return hex.EncodeToString(h.Sum(nil))
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Issue stores a grant for (agent, handle, policy) and returns the token.
func (i *Issuer) Issue(agentID int64, h string, policyJSON string, ttl time.Duration, maxUses int) (string, *store.Grant, error) {
	id, err := newID()
	if err != nil {
		return "", nil, err
	}
	exp := time.Now().UTC().Add(ttl)
	g := &store.Grant{ID: id, AgentID: agentID, Handle: h, Policy: policyJSON, ExpiresAt: exp, MaxUses: maxUses}
	if err := i.st.AddGrant(g); err != nil {
		return "", nil, err
	}
	token := id + "." + i.mac(agentID, id, h, exp)
	return token, g, nil
}

// Verify checks the token signature and returns the stored grant.
func (i *Issuer) Verify(token string, agentID int64) (*store.Grant, error) {
	id, sig, ok := strings.Cut(token, ".")
	if !ok || id == "" || sig == "" {
		return nil, ErrInvalid
	}
	g, err := i.st.GetGrant(id)
	if err != nil {
		return nil, ErrInvalid
	}
	want := i.mac(agentID, id, g.Handle, g.ExpiresAt)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return nil, ErrInvalid
	}
	if time.Now().After(g.ExpiresAt) {
		return nil, ErrExpired
	}
	if g.MaxUses > 0 && g.Uses >= g.MaxUses {
		return nil, ErrExhausted
	}
	return g, nil
}

// Consume verifies the token and records one use.
func (i *Issuer) Consume(token string, agentID int64) (*store.Grant, error) {
	g, err := i.Verify(token, agentID)
	if err != nil {
		return nil, err
	}
	if err := i.st.IncrementGrantUses(g.ID); err != nil {
		return nil, err
	}
	return g, nil
}
