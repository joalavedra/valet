// Package egress implements the HTTP egress edge: agent requests are
// forwarded through an Infisical Agent Vault forward proxy, which injects
// the real credential upstream. Secret material never enters this process.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config wires the Agent Vault forward proxy and its control-plane API.
type Config struct {
	ProxyURL string // e.g. http://TOKEN:VAULT@127.0.0.1:14322
	CAFile   string // PEM file for HTTPS upstreams through the proxy (optional)
	Addr     string // Agent Vault API base, e.g. http://127.0.0.1:14321
	Token    string // agent token for /discover
	Vault    string // vault name for X-Vault header (optional)
}

// FromEnv reads VALET_AGENTVAULT_* env vars; false when unset.
func FromEnv() (*Config, bool) {
	c := &Config{
		ProxyURL: os.Getenv("VALET_AGENTVAULT_PROXY"),
		CAFile:   os.Getenv("VALET_AGENTVAULT_CA"),
		Addr:     os.Getenv("VALET_AGENTVAULT_ADDR"),
		Token:    os.Getenv("VALET_AGENTVAULT_TOKEN"),
		Vault:    os.Getenv("VALET_AGENTVAULT_VAULT"),
	}
	if c.ProxyURL == "" {
		return nil, false
	}
	return c, true
}

// Service is a brokerable upstream advertised by /discover.
type Service struct {
	Name string `json:"name"`
	Host string `json:"host"` // may carry an inline path pattern: host/path/*
}

// Client forwards requests through the Agent Vault proxy.
type Client struct {
	cfg    *Config
	hc     *http.Client
	mu     sync.Mutex
	svcs   []Service
	cached time.Time
}

// New builds a proxied http.Client; CAFile PEM is added to the root pool.
func New(cfg *Config) (*Client, error) {
	proxy, err := url.Parse(cfg.ProxyURL)
	if err != nil || proxy.Host == "" {
		return nil, fmt.Errorf("invalid egress proxy url")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read egress ca: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("egress ca file is not PEM")
		}
	}
	return &Client{
		cfg: cfg,
		hc: &http.Client{
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxy),
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
			// Redirects go back to the agent; following them would send the
			// request to a host the grant policy never evaluated.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Timeout:       30 * time.Second,
		},
	}, nil
}

// Discover lists services from {Addr}/discover, cached for 60s.
func (c *Client) Discover(ctx context.Context) ([]Service, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.cached) < 60*time.Second && c.svcs != nil {
		return c.svcs, nil
	}
	if c.cfg.Addr == "" || c.cfg.Token == "" {
		return nil, fmt.Errorf("egress discover not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.Addr, "/")+"/discover", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	if c.cfg.Vault != "" {
		req.Header.Set("X-Vault", c.cfg.Vault)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover status %d", resp.StatusCode)
	}
	var body struct {
		Services []Service `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	c.svcs = body.Services
	c.cached = time.Now()
	return c.svcs, nil
}

// ServiceByName returns the discovered service for a handle label.
func (c *Client) ServiceByName(ctx context.Context, name string) (*Service, error) {
	svcs, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range svcs {
		if s.Name == name {
			s := s
			return &s, nil
		}
	}
	return nil, nil
}

// Request is an agent-supplied outbound request.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// Response mirrors the upstream reply; body is capped at 1 MiB.
type Response struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated,omitempty"`
}

const maxBody = 1 << 20

var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true, "host": true,
}

var respHeaders = map[string]bool{
	"content-type": true, "content-length": true, "date": true,
	"x-request-id": true, "retry-after": true, "location": true,
}

// Do forwards req through the proxy and returns the filtered response.
// Errors never include the proxy URL or credentials.
func (c *Client) Do(ctx context.Context, in Request) (*Response, error) {
	u, err := url.Parse(in.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid request url")
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if len(in.Body) > 0 {
		body = strings.NewReader(string(in.Body))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// Headers named by the agent's Connection header are also hop-by-hop.
	connNames := map[string]bool{}
	for _, tok := range strings.Split(in.Headers["Connection"]+","+in.Headers["connection"], ",") {
		if t := strings.ToLower(strings.TrimSpace(tok)); t != "" {
			connNames[t] = true
		}
	}
	for k, v := range in.Headers {
		lk := strings.ToLower(k)
		if hopHeaders[lk] || connNames[lk] || strings.HasPrefix(lk, "proxy-") {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("egress request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("egress read failed: %w", err)
	}
	out := &Response{Status: resp.StatusCode, Headers: map[string]string{}, Body: string(raw)}
	if len(raw) > maxBody {
		out.Body = string(raw[:maxBody])
		out.Truncated = true
	}
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if respHeaders[lk] || strings.HasPrefix(lk, "x-ratelimit-") {
			if out.Truncated && lk == "content-length" {
				continue
			}
			out.Headers[k] = strings.Join(vv, ", ")
		}
	}
	return out, nil
}
