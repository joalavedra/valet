// Package card defines the pluggable card-vault provider interface used by
// the card edge. Providers hold PANs in their own vault; Valet only ever
// stores aliases (handles like card://visa-4242).
package card

import (
	"fmt"
	"net/http"
	"sync"
)

// CaptureConfig describes how the user's browser captures a card into the
// provider vault (e.g. hosted iframe fields).
type CaptureConfig struct {
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"` // field name -> iframe/collect config
}

// Provider is the card-vault driver contract.
type Provider interface {
	Name() string
	// Transport returns a RoundTripper that sends requests through the
	// provider's detokenizing outbound proxy.
	Transport() (http.RoundTripper, error)
	CaptureConfig() (CaptureConfig, error)
}

var (
	regMu sync.RWMutex
	reg   = map[string]Provider{}
)

// Register adds p under name; duplicate names panic.
func Register(name string, p Provider) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := reg[name]; dup {
		panic("card: provider registered twice: " + name)
	}
	reg[name] = p
}

// Get returns the registered provider or an error.
func Get(name string) (Provider, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	p, ok := reg[name]
	if !ok {
		return nil, fmt.Errorf("card: provider %q not configured", name)
	}
	return p, nil
}
