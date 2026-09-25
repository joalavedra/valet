package card

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// VGS is a stub driver for Very Good Security.
// VGS outbound routing is a forward proxy: clients send requests through
// https://{username}:{password}@{vaultId}.{env}.verygoodproxy.com and the
// vault swaps aliases for real PANs in transit. Phase 1 models this by
// rewriting the request URL to the proxy host and setting basic auth;
// TODO(vgs): confirm exact shape (CONNECT vs absolute-form) against
// https://www.verygoodsecurity.com/docs — outbound connection docs.
type VGS struct {
	VaultID  string
	Env      string // e.g. "sandbox" or "live"
	RouteID  string
	Username string
	Password string
}

func init() {
	p := &VGS{
		VaultID:  os.Getenv("VGS_VAULT_ID"),
		Env:      envOr("VGS_ENV", "sandbox"),
		RouteID:  os.Getenv("VGS_ROUTE_ID"),
		Username: os.Getenv("VGS_USERNAME"),
		Password: os.Getenv("VGS_PASSWORD"),
	}
	Register("vgs", p)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (v *VGS) Name() string { return "vgs" }

func (v *VGS) proxyHost() string {
	return fmt.Sprintf("%s.%s.verygoodproxy.com", v.VaultID, v.Env)
}

func (v *VGS) CaptureConfig(ctx context.Context) (CaptureConfig, error) {
	if v.VaultID == "" {
		return CaptureConfig{}, errors.New("vgs: VGS_VAULT_ID not set")
	}
	return CaptureConfig{
		Provider: "vgs",
		Fields: map[string]string{
			"collect.js": fmt.Sprintf("https://js.verygoodvault.com/collect/%s", v.VaultID),
			"route_id":   v.RouteID,
		},
	}, nil
}

func (v *VGS) Tokenize(ctx context.Context, raw CardInput) (Alias, error) {
	if v.VaultID == "" {
		return "", errors.New("vgs: VGS_VAULT_ID not set")
	}
	return Alias(fmt.Sprintf("vgs-sandbox-alias-%s", v.VaultID)), nil
}

func (v *VGS) OutboundRoute(ctx context.Context, alias Alias, req *http.Request) (*http.Request, error) {
	if v.Username == "" || v.Password == "" {
		return nil, errors.New("vgs: credentials not configured")
	}
	r := req.Clone(ctx)
	u, err := url.Parse(r.URL.String())
	if err != nil {
		return nil, err
	}
	u.Scheme = "https"
	u.Host = v.proxyHost()
	r.URL = u
	r.Header.Set("Proxy-Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(v.Username+":"+v.Password)))
	r.Header.Set("X-VGS-Alias", string(alias))
	return r, nil
}

func (v *VGS) UpdateCVC(ctx context.Context, alias Alias, ttl time.Duration) (StepUpConfig, error) {
	if v.VaultID == "" {
		return StepUpConfig{}, errors.New("vgs: VGS_VAULT_ID not set")
	}
	return StepUpConfig{
		URL:     fmt.Sprintf("https://%s.verygoodsecurity.com/collect/cvc?alias=%s", v.proxyHost(), url.QueryEscape(string(alias))),
		Expires: ttl,
	}, nil
}
