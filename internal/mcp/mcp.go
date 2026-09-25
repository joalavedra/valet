// Package mcp exposes Valet's agent-facing tools over the Model Context
// Protocol. Tools return handles and statuses only — never secret values.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend is the control-plane surface the tools call through.
type Backend interface {
	ListHandles(ctx context.Context) (any, error)
	RequestGrant(ctx context.Context, handle string, policyJSON string, ttl string) (any, error)
	BrowserFill(ctx context.Context, grant, cdpWSURL string, mapping map[string]string, submit string) (any, error)
	HTTPCall(ctx context.Context, grant, method, url, headersJSON, body string) (any, error)
	Pay(ctx context.Context, grant, merchant string, amount int64, currency, rail string) (any, error)
}

// HTTPBackend forwards tool calls to a running valet server.
type HTTPBackend struct {
	Base  string
	Token string
	Do    *http.Client
}

func (b *HTTPBackend) client() *http.Client {
	if b.Do != nil {
		return b.Do
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// redact scrubs the agent token out of any echoed text before it reaches
// the model.
func (b *HTTPBackend) redact(s string) string {
	if b.Token != "" {
		s = strings.ReplaceAll(s, b.Token, "[redacted]")
	}
	return s
}

func (b *HTTPBackend) call(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.Base, "/")+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.Token != "" {
		req.Header.Set("Authorization", "Bearer "+b.Token)
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("valet: %s %s -> %d: %s", method, path, resp.StatusCode, b.redact(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("valet: bad response: %w", err)
		}
	}
	return nil
}

// ListHandles returns the credential handles visible to the agent.
func (b *HTTPBackend) ListHandles(ctx context.Context) (any, error) {
	var out any
	err := b.call(ctx, "GET", "/v1/handles", nil, &out)
	return out, err
}

// RequestGrant requests a grant for handle under the given JSON policy.
func (b *HTTPBackend) RequestGrant(ctx context.Context, handle, policyJSON, ttl string) (any, error) {
	var pol any
	if policyJSON != "" {
		if err := json.Unmarshal([]byte(policyJSON), &pol); err != nil {
			return nil, fmt.Errorf("invalid policy json: %w", err)
		}
	}
	var out any
	body := map[string]any{"handle": handle, "policy": pol}
	if ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		body["ttl"] = int64(d / time.Second)
	}
	err := b.call(ctx, "POST", "/v1/grants", body, &out)
	return out, err
}

// BrowserFill asks the browser edge to fill fields via CDP.
func (b *HTTPBackend) BrowserFill(ctx context.Context, grant, cdpWSURL string, mapping map[string]string, submit string) (any, error) {
	var out any
	err := b.call(ctx, "POST", "/v1/edge/browser/fill", map[string]any{
		"grant_token": grant, "cdp_ws_url": cdpWSURL, "mapping": mapping, "submit": submit,
	}, &out)
	return out, err
}

// HTTPCall asks the egress edge to perform an authenticated HTTP request.
func (b *HTTPBackend) HTTPCall(ctx context.Context, grant, method, url, headersJSON, body string) (any, error) {
	payload := map[string]any{"grant_token": grant, "method": method, "url": url, "body": body}
	if headersJSON != "" {
		var h map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &h); err != nil {
			return nil, fmt.Errorf("invalid headers json: %w", err)
		}
		payload["headers"] = h
	}
	var out any
	err := b.call(ctx, "POST", "/v1/edge/http/call", payload, &out)
	return out, err
}

func (b *HTTPBackend) Pay(ctx context.Context, grant, merchant string, amount int64, currency, rail string) (any, error) {
	var out any
	err := b.call(ctx, "POST", "/v1/edge/card/pay", map[string]any{
		"grant": grant, "merchant": merchant, "amount": amount, "currency": currency, "rail": rail,
	}, &out)
	return out, err
}

type listHandlesArgs struct{}

type requestGrantArgs struct {
	Handle string `json:"handle" jsonschema:"handle URI, e.g. cred://github.com/joan"`
	Policy string `json:"policy" jsonschema:"JSON policy object"`
	TTL    string `json:"ttl,omitempty" jsonschema:"duration such as 30m or 2h"`
}

type httpCallArgs struct {
	Grant   string `json:"grant" jsonschema:"grant token"`
	Method  string `json:"method" jsonschema:"HTTP method"`
	URL     string `json:"url" jsonschema:"absolute request URL"`
	Headers string `json:"headers,omitempty" jsonschema:"JSON object of extra headers"`
	Body    string `json:"body,omitempty" jsonschema:"request body"`
}

type browserFillArgs struct {
	Grant    string            `json:"grant" jsonschema:"grant token"`
	CDPWSURL string            `json:"cdp_ws_url" jsonschema:"CDP websocket URL of the agent browser"`
	Mapping  map[string]string `json:"mapping" jsonschema:"field name -> CSS selector"`
	Submit   string            `json:"submit,omitempty" jsonschema:"optional submit-button CSS selector"`
}

type payArgs struct {
	Grant    string `json:"grant" jsonschema:"grant token"`
	Merchant string `json:"merchant" jsonschema:"merchant domain"`
	Amount   int64  `json:"amount" jsonschema:"amount in minor currency units"`
	Currency string `json:"currency" jsonschema:"ISO currency code"`
	Rail     string `json:"rail,omitempty" jsonschema:"payment rail override"`
}

func result(v any, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}, IsError: true}, nil, nil
	}
	return nil, v, nil
}

// New builds the MCP server with all valet tools.
func New(b Backend) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "valet", Version: "0.0.1"}, nil)

	mcp.AddTool(s, &mcp.Tool{Name: "list_handles", Description: "List credential handles and metadata available to this agent. Never returns secrets."},
		func(ctx context.Context, req *mcp.CallToolRequest, args listHandlesArgs) (*mcp.CallToolResult, any, error) {
			return result(b.ListHandles(ctx))
		})
	mcp.AddTool(s, &mcp.Tool{Name: "request_grant", Description: "Request a grant to use a handle under a policy."},
		func(ctx context.Context, req *mcp.CallToolRequest, args requestGrantArgs) (*mcp.CallToolResult, any, error) {
			return result(b.RequestGrant(ctx, args.Handle, args.Policy, args.TTL))
		})
	mcp.AddTool(s, &mcp.Tool{Name: "http_call", Description: "Authenticated HTTP call via the egress edge (Infisical Agent Vault injects the credential; the agent never sees it)"},
		func(ctx context.Context, req *mcp.CallToolRequest, args httpCallArgs) (*mcp.CallToolResult, any, error) {
			return result(b.HTTPCall(ctx, args.Grant, args.Method, args.URL, args.Headers, args.Body))
		})
	mcp.AddTool(s, &mcp.Tool{Name: "browser_fill", Description: "Fill login form fields in the agent's browser via CDP. Returns status only, never typed values."},
		func(ctx context.Context, req *mcp.CallToolRequest, args browserFillArgs) (*mcp.CallToolResult, any, error) {
			return result(b.BrowserFill(ctx, args.Grant, args.CDPWSURL, args.Mapping, args.Submit))
		})
	mcp.AddTool(s, &mcp.Tool{Name: "pay", Description: "Pay a merchant with a stored card handle. Returns a receipt/status, never a PAN."},
		func(ctx context.Context, req *mcp.CallToolRequest, args payArgs) (*mcp.CallToolResult, any, error) {
			return result(b.Pay(ctx, args.Grant, args.Merchant, args.Amount, args.Currency, args.Rail))
		})
	return s
}

// Run serves the MCP server over stdio.
func Run(ctx context.Context, b Backend) error {
	return New(b).Run(ctx, &mcp.StdioTransport{})
}
