package card

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

// VGS is the Very Good Security driver. VGS's outbound route is an HTTPS
// forward proxy at https://USER:PASS@<vault>.<env>.verygoodproxy.com:8443;
// detokenization happens proxy-side for upstream hosts that have an
// Outbound Route configured in the VGS dashboard. TLS to the proxy requires
// trusting VGS's environment CA (PEM file, VGS_CA_FILE).
// sandboxPEM is VGS's public self-signed sandbox CA for *.sandbox.
// verygoodproxy.com, embedded from the VGS docs (outbound-connection page).
// A copy also lives at deploy/vgs/sandbox.pem for curl users. Live
// environments must pass VGS_CA_FILE.
//
//go:embed vgs_sandbox.pem
var sandboxPEM []byte

type VGS struct {
	VaultID  string
	Env      string // e.g. "sandbox" or "live"
	Username string
	Password string
	CAFile   string
}

func init() {
	if os.Getenv("VGS_VAULT_ID") == "" {
		return // register nothing so Get("vgs") reports a clear error
	}
	env := os.Getenv("VGS_ENV")
	if env == "" {
		env = "sandbox"
	}
	Register("vgs", &VGS{
		VaultID:  os.Getenv("VGS_VAULT_ID"),
		Env:      env,
		Username: os.Getenv("VGS_USERNAME"),
		Password: os.Getenv("VGS_PASSWORD"),
		CAFile:   os.Getenv("VGS_CA_FILE"),
	})
}

func (v *VGS) Name() string { return "vgs" }

// Transport returns a RoundTripper routed through the VGS outbound proxy.
func (v *VGS) Transport() (http.RoundTripper, error) {
	if v.VaultID == "" || v.Username == "" || v.Password == "" {
		return nil, errors.New("vgs: not configured (VGS_VAULT_ID/VGS_USERNAME/VGS_PASSWORD)")
	}
	env := v.Env
	if env == "" {
		env = "sandbox"
	}
	proxy, err := url.Parse(fmt.Sprintf("https://%s:%s@%s.%s.verygoodproxy.com:8443",
		url.QueryEscape(v.Username), url.QueryEscape(v.Password), v.VaultID, env))
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if v.CAFile != "" {
		pem, err := os.ReadFile(v.CAFile)
		if err != nil {
			return nil, fmt.Errorf("vgs: ca file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("vgs: ca file is not PEM")
		}
	} else if env == "sandbox" {
		pool.AppendCertsFromPEM(sandboxPEM)
	}
	return &http.Transport{
		Proxy:           http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}, nil
}

// CaptureConfig describes the VGS Collect.js hosted-fields capture.
func (v *VGS) CaptureConfig() (CaptureConfig, error) {
	if v.VaultID == "" {
		return CaptureConfig{}, errors.New("vgs: VGS_VAULT_ID not set")
	}
	env := v.Env
	if env == "" {
		env = "sandbox"
	}
	return CaptureConfig{
		Provider: "vgs",
		Fields: map[string]string{
			"vault_id":    v.VaultID,
			"environment": env,
			"collect_js":  "https://js.verygoodvault.com/vgs-collect/3.2.2/vgs-collect.js",
		},
	}, nil
}
