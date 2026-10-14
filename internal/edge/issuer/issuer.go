// Package issuer defines the pluggable card-issuer driver interface for the
// issuer:// rail: a grant on an issuer credential mints exactly one scoped
// card (merchant-locked, capped, expiring). Drivers hold the BIN and the
// PCI scope; Valet never stores a PAN.
package issuer

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CardSpec describes the card to mint for one grant.
type CardSpec struct {
	GrantID   string
	Merchants []string // host globs from policy.Spend.Merchants (or Hosts)
	PerTx     int64    // minor units
	Total     int64    // lifetime cap (0 = per-tx only)
	Currency  string
	ExpiresAt time.Time // ≤ grant expiry
	SingleUse bool      // MaxUses == 1
	Purpose   string    // shown in issuer-side approval UIs
}

// Card is a minted, scoped card as reported by the issuer.
type Card struct {
	ID, Brand, Last4, ExpMonth, ExpYear string
	Holder                              string
	Status                              string // active | closed | pending_approval
	NeedsOwnerApproval                  bool   // issuer runs its own HITL
}

// Fields are the fill-time values; callers zero them after use. CVC may be
// empty for issuers that don't expose it (merchant step-up, same as cards).
type Fields struct{ Number, ExpMonth, ExpYear, CVC, Holder string }

// Zero wipes the field values in place.
func (f *Fields) Zero() { *f = Fields{} }

// Caps reports what a driver can enforce at the network level.
type Caps struct {
	MerchantLock  bool
	Cap           bool
	SingleUse     bool
	Reveal        bool
	OwnerApproval bool
}

// Issuer is the card-issuer driver contract.
type Issuer interface {
	Name() string
	Capabilities() Caps
	Issue(ctx context.Context, spec CardSpec) (Card, error)
	// Reveal returns fill-time values — only at the fill edge, never
	// persisted or logged.
	Reveal(ctx context.Context, cardID string) (Fields, error)
	Close(ctx context.Context, cardID string) error
}

var (
	regMu sync.RWMutex
	reg   = map[string]Issuer{}
)

// Register adds i under name; duplicate names panic.
func Register(name string, i Issuer) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := reg[name]; dup {
		panic("issuer: driver registered twice: " + name)
	}
	reg[name] = i
}

// Get returns the registered driver or an error.
func Get(name string) (Issuer, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	i, ok := reg[name]
	if !ok {
		return nil, fmt.Errorf("issuer: driver %q not configured", name)
	}
	return i, nil
}
