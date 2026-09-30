package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// valetClient is the thin control-plane client: agent calls bear the agent
// token, owner calls the owner token.
type valetClient struct {
	base       string
	agentToken string
	ownerToken string
	http       *http.Client
}

func newValetClient(base, agentToken, ownerToken string) *valetClient {
	return &valetClient{base: base, agentToken: agentToken, ownerToken: ownerToken, http: &http.Client{Timeout: 30 * time.Second}}
}

func (v *valetClient) call(ctx context.Context, token, method, path string, body, out any) error {
	return v.callWith(ctx, v.http, token, method, path, body, out)
}

func (v *valetClient) callWith(ctx context.Context, cl *http.Client, token, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == 202 {
		// pending_approval is a success shape for /v1/grants.
	} else if resp.StatusCode >= 400 {
		return fmt.Errorf("valet %s %s -> %d: %s", method, path, resp.StatusCode, string(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("valet: bad response: %w", err)
		}
	}
	return nil
}

// ---- agent calls ----

func (v *valetClient) requestGrant(ctx context.Context, handle, purpose string, ttl, maxUses int64, policy any) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.agentToken, "POST", "/v1/grants",
		map[string]any{"handle": handle, "purpose": purpose, "ttl": ttl, "max_uses": maxUses, "policy": policy}, &out)
	return out, err
}

func (v *valetClient) grantRequestStatus(ctx context.Context, id string, wait int) (map[string]any, error) {
	var out map[string]any
	path := fmt.Sprintf("/v1/grants/requests/%s?wait=%d", id, wait)
	// Per-call client with a long-poll timeout; never mutate the shared client.
	cl := &http.Client{Timeout: time.Duration(wait+15) * time.Second, Transport: v.http.Transport}
	err := v.callWith(ctx, cl, v.agentToken, "GET", path, nil, &out)
	return out, err
}

func (v *valetClient) pay(ctx context.Context, grantToken, url, body string, amount int64, currency string) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.agentToken, "POST", "/v1/edge/card/pay",
		map[string]any{
			"grant_token": grantToken, "method": "POST", "url": url,
			"headers": map[string]string{"Content-Type": "application/json"},
			"body":    body, "amount": amount, "currency": currency,
		}, &out)
	return out, err
}

// walletFetch runs a crypto-rail fetch through Valet's wallet edge:
// rail "x402" → /v1/edge/wallet/x402, "mpp" → /v1/edge/wallet/mpp.
func (v *valetClient) walletFetch(ctx context.Context, grantToken, rail, method, url string) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.agentToken, "POST", "/v1/edge/wallet/"+rail,
		map[string]any{"grant_token": grantToken, "method": method, "url": url}, &out)
	return out, err
}

// ---- owner calls ----

func (v *valetClient) ownerCreateCapture(ctx context.Context, label string, ttl int64, returnURL string) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.ownerToken, "POST", "/v1/owner/captures",
		map[string]any{"label": label, "ttl_seconds": ttl, "return_url": returnURL}, &out)
	return out, err
}

func (v *valetClient) ownerList(ctx context.Context, path string) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.ownerToken, "GET", path, nil, &out)
	return out, err
}

func (v *valetClient) ownerDelete(ctx context.Context, path string) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.ownerToken, "DELETE", path, nil, &out)
	return out, err
}

func (v *valetClient) ownerAction(ctx context.Context, path string) (map[string]any, error) {
	var out map[string]any
	err := v.call(ctx, v.ownerToken, "POST", path, nil, &out)
	return out, err
}

// valetProxy reverse-proxies an allowlist of /valet/* paths to the valet
// server — only /capture/<token> (page + Collect.js posts, same-origin)
// and /healthz are exposed without auth; anything else is a 404.
type valetProxy struct {
	target string
	client *http.Client
}

func (p *valetProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// r.URL.Path here is already stripped of the /valet prefix.
	if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/capture/") {
		http.NotFound(w, r)
		return
	}
	u, _ := url.Parse(p.target)
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			req.Host = u.Host
		},
		Transport: p.client.Transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, 502, map[string]string{"error": "valet unreachable"})
		},
	}
	rp.ServeHTTP(w, r)
}
