// Package mcp exposes Valet's agent-facing tools over the Model Context
// Protocol. Tools return handles and statuses only — never secret values.
package mcp

import (
	"context"
	"errors"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend is the control-plane surface the tools call through.
type Backend interface {
	ListHandles(ctx context.Context) (any, error)
	RequestGrant(ctx context.Context, handle string, policyJSON string) (any, error)
	BrowserFill(ctx context.Context, grant, cdpWSURL string, mapping map[string]string) (any, error)
	Pay(ctx context.Context, grant, merchant string, amount int64, currency, rail string) (any, error)
}

// HTTPBackend forwards tool calls to a running valet server.
type HTTPBackend struct {
	Base  string
	Token string
	Do    *http.Client
}

// ErrNotImplemented marks Phase-1 stubs.
var ErrNotImplemented = errors.New("not_implemented")

func (b *HTTPBackend) ListHandles(ctx context.Context) (any, error) { return nil, ErrNotImplemented }

func (b *HTTPBackend) RequestGrant(ctx context.Context, handle, policyJSON string) (any, error) {
	return nil, ErrNotImplemented
}

func (b *HTTPBackend) BrowserFill(ctx context.Context, grant, cdpWSURL string, mapping map[string]string) (any, error) {
	return nil, ErrNotImplemented
}

func (b *HTTPBackend) Pay(ctx context.Context, grant, merchant string, amount int64, currency, rail string) (any, error) {
	return nil, ErrNotImplemented
}

type listHandlesArgs struct{}

type requestGrantArgs struct {
	Handle string `json:"handle" jsonschema:"handle URI, e.g. cred://github.com/joan"`
	Policy string `json:"policy" jsonschema:"JSON policy object"`
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
	Mapping  map[string]string `json:"mapping" jsonschema:"selector -> field name"`
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
			return result(b.RequestGrant(ctx, args.Handle, args.Policy))
		})
	mcp.AddTool(s, &mcp.Tool{Name: "http_call", Description: "Make an authenticated HTTP call through the egress edge (delegated to Infisical Agent Vault in Phase 1)."},
		func(ctx context.Context, req *mcp.CallToolRequest, args httpCallArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "not_implemented"}}, IsError: true}, nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "browser_fill", Description: "Fill login form fields in the agent's browser via CDP. Returns status only, never typed values."},
		func(ctx context.Context, req *mcp.CallToolRequest, args browserFillArgs) (*mcp.CallToolResult, any, error) {
			return result(b.BrowserFill(ctx, args.Grant, args.CDPWSURL, args.Mapping))
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
