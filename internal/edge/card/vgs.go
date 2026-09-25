package card

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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

// vgsCollectVersion is the latest stable Collect.js release per the VGS
// changelog (3.4.0, Dec 2025).
const vgsCollectVersion = "3.4.0"

type VGS struct {
	VaultID      string
	Env          string // e.g. "sandbox" or "live"
	Username     string
	Password     string
	CAFile       string
	ClientID     string // VGS service account (OAuth2) for Vault API tokenization
	ClientSecret string
	authURL      string // unexported overrides for tests
	vaultAPIURL  string
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
		VaultID:      os.Getenv("VGS_VAULT_ID"),
		Env:          env,
		Username:     os.Getenv("VGS_USERNAME"),
		Password:     os.Getenv("VGS_PASSWORD"),
		CAFile:       os.Getenv("VGS_CA_FILE"),
		ClientID:     os.Getenv("VGS_CLIENT_ID"),
		ClientSecret: os.Getenv("VGS_CLIENT_SECRET"),
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

// Tokenize creates aliases via the VGS Vault API (OAuth2 client-credentials
// against the service account). Returned aliases are in the same order as
// inputs; raw values are never persisted here.
func (v *VGS) Tokenize(ctx context.Context, values []TokenizeInput) ([]string, error) {
	if v.ClientID == "" || v.ClientSecret == "" {
		return nil, errors.New("vgs: VGS_CLIENT_ID/VGS_CLIENT_SECRET not set")
	}
	authURL := v.authURL
	if authURL == "" {
		authURL = "https://auth.verygoodsecurity.com/auth/realms/vgs/protocol/openid-connect/token"
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {v.ClientID},
		"client_secret": {v.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", authURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vgs: tokenize auth failed (status %d)", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil || tok.AccessToken == "" {
		return nil, errors.New("vgs: tokenize auth returned no access_token")
	}
	env := v.Env
	if env == "" {
		env = "sandbox"
	}
	apiBase := v.vaultAPIURL
	if apiBase == "" {
		apiBase = fmt.Sprintf("https://%s.%s.vault-api.verygoodvault.com", v.VaultID, env)
	}
	type item struct {
		Value       string   `json:"value"`
		Classifiers []string `json:"classifiers,omitempty"`
		Format      string   `json:"format"`
		Storage     string   `json:"storage"`
	}
	items := make([]item, len(values))
	for i, in := range values {
		storage := "PERSISTENT"
		if in.Volatile {
			storage = "VOLATILE"
		}
		items[i] = item{Value: in.Value, Classifiers: in.Classifiers, Format: in.Format, Storage: storage}
	}
	body, err := json.Marshal(map[string]any{"data": items})
	if err != nil {
		return nil, err
	}
	areq, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/aliases", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	areq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	areq.Header.Set("Content-Type", "application/json")
	aresp, err := http.DefaultClient.Do(areq)
	if err != nil {
		return nil, err
	}
	defer aresp.Body.Close()
	if aresp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vgs: tokenize failed (status %d)", aresp.StatusCode)
	}
	var out struct {
		Data []struct {
			Aliases []struct {
				Alias string `json:"alias"`
			} `json:"aliases"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(aresp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, errors.New("vgs: tokenize bad response")
	}
	if len(out.Data) != len(values) {
		return nil, fmt.Errorf("vgs: tokenize returned %d items for %d inputs", len(out.Data), len(values))
	}
	aliases := make([]string, len(values))
	for i := range out.Data {
		if len(out.Data[i].Aliases) == 0 {
			return nil, fmt.Errorf("vgs: tokenize item %d has no alias", i)
		}
		aliases[i] = out.Data[i].Aliases[0].Alias
	}
	return aliases, nil
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
			"vault_id":        v.VaultID,
			"environment":     env,
			"collect_js":      "https://js.verygoodvault.com/vgs-collect/" + vgsCollectVersion + "/vgs-collect.js",
			"collect_version": vgsCollectVersion,
		},
	}, nil
}
