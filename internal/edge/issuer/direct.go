package issuer

import (
	"errors"
	"net/http"

	"github.com/joalavedra/valet/internal/edge/card"
	"github.com/joalavedra/valet/internal/edge/netguard"
)

// directProvider is the card.Provider used for issuer grants: the filled
// request goes straight to the merchant (no detokenizing proxy), still
// behind the netguard SSRF dial fence.
type directProvider struct{ allowPrivate bool }

// DirectProvider returns the provider cardPay uses for issuer:// grants.
func DirectProvider(allowPrivate bool) card.Provider {
	return directProvider{allowPrivate: allowPrivate}
}

func (d directProvider) Name() string { return "direct" }

func (d directProvider) Transport() (http.RoundTripper, error) {
	return netguard.Transport(d.allowPrivate), nil
}

func (d directProvider) CaptureConfig() (card.CaptureConfig, error) {
	return card.CaptureConfig{}, errors.New("issuer cards are not captured")
}
