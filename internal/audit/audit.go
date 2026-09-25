// Package audit implements an append-only, hash-chained audit log.
// Each entry's hash is sha256(prev_hash || canonical JSON of the entry body).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/joalavedra/valet/internal/store"
)

var ErrChainBroken = errors.New("audit: hash chain verification failed")

// canonical marshals the chain-relevant fields deterministically.
func canonical(e *store.AuditEntry) []byte {
	b, _ := json.Marshal(struct {
		TS       time.Time `json:"ts"`
		AgentID  int64     `json:"agent_id"`
		Handle   string    `json:"handle"`
		Edge     string    `json:"edge"`
		Target   string    `json:"target"`
		Decision string    `json:"decision"`
		Detail   string    `json:"detail"`
	}{e.TS, e.AgentID, e.Handle, e.Edge, e.Target, e.Decision, e.Detail})
	return b
}

// Hash computes the chain hash for e given prevHash.
func Hash(e *store.AuditEntry, prevHash string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonical(e))
	return hex.EncodeToString(h.Sum(nil))
}

// Chain wraps a Store to append hash-linked entries.
type Chain struct {
	st store.Store
}

// New returns a Chain over st.
func New(st store.Store) *Chain { return &Chain{st: st} }

// Append fills PrevHash/Hash on e and appends it.
func (c *Chain) Append(e *store.AuditEntry) error {
	e.TS = time.Now().UTC()
	prev, err := c.st.LastAudit()
	if err == store.ErrNotFound {
		e.PrevHash = ""
	} else if err != nil {
		return err
	} else {
		e.PrevHash = prev.Hash
	}
	e.Hash = Hash(e, e.PrevHash)
	return c.st.AppendAudit(e)
}

// Verify recomputes the chain over the first `limit` entries (0 = all).
func Verify(entries []store.AuditEntry) error {
	prev := ""
	for i := range entries {
		e := &entries[i]
		if e.PrevHash != prev {
			return ErrChainBroken
		}
		if e.Hash != Hash(e, prev) {
			return ErrChainBroken
		}
		prev = e.Hash
	}
	return nil
}

// VerifyStore loads the audit table from st and verifies the chain.
func (c *Chain) VerifyStore() error {
	entries, err := c.st.ListAudit(0)
	if err != nil {
		return err
	}
	return Verify(entries)
}
