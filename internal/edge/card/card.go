// Package card defines the pluggable card-vault provider interface used by
// the card edge. Providers hold PANs in their own vault; Valet only ever
// stores aliases (handles like card://visa-4242).
package card

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CardInput is raw card data. Fields are marked json:"-" so a CardInput can
// never be serialized into logs, audit rows, or API responses.
type CardInput struct {
	PAN    string `json:"-"`
	CVC    string `json:"-"`
	ExpMM  int    `json:"exp_month,omitempty"`
	ExpYY  int    `json:"exp_year,omitempty"`
	Holder string `json:"holder,omitempty"`
}

// Alias is a provider-side token standing in for a PAN.
type Alias string

// CaptureConfig describes how the user's browser captures a card into the
// provider vault (e.g. hosted iframe fields).
type CaptureConfig struct {
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"` // field name -> iframe/collect config
}

// StepUpConfig describes a human step-up flow (e.g. CVC re-entry).
type StepUpConfig struct {
	URL     string        `json:"url"`
	Expires time.Duration `json:"expires"`
}

// Provider is the card-vault driver contract.
type Provider interface {
	Name() string
	CaptureConfig(ctx context.Context) (CaptureConfig, error)
	// Tokenize is sandbox/test only: production capture happens in provider
	// iframes and never passes PANs through this process.
	Tokenize(ctx context.Context, raw CardInput) (Alias, error)
	OutboundRoute(ctx context.Context, alias Alias, req *http.Request) (*http.Request, error)
	UpdateCVC(ctx context.Context, alias Alias, ttl time.Duration) (StepUpConfig, error)
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
		return nil, fmt.Errorf("card: unknown provider %q", name)
	}
	return p, nil
}
