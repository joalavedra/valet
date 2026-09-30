// Package wallet is the x402 edge: it answers `402 Payment Required`
// challenges by signing EIP-3009 authorizations through an Openfort
// backend wallet. Only the `exact` scheme on allowlisted networks is
// paid; arbitrary transaction signing is not exposed.
package wallet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	x402 "github.com/x402-foundation/x402/go"
	x402http "github.com/x402-foundation/x402/go/http"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
	exactclient "github.com/x402-foundation/x402/go/mechanisms/evm/exact/client"
	exactv1 "github.com/x402-foundation/x402/go/mechanisms/evm/exact/v1/client"
	evmv1 "github.com/x402-foundation/x402/go/mechanisms/evm/v1"

	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/edge/wallet/openfort"
)

// ErrPolicy wraps any payment-policy refusal; callers map it to 403.
var ErrPolicy = errors.New("payment not allowed by policy")

// Signer adapts an Openfort backend-wallet client to the x402 SDK's
// evm.ClientEvmSigner: typed data is hashed locally and only the
// resulting digest is sent to Openfort for signing.
type Signer struct {
	of        *openfort.Client
	accountID string
	address   string
}

// NewSigner builds a Signer for an Openfort account.
func NewSigner(of *openfort.Client, accountID, address string) *Signer {
	return &Signer{of: of, accountID: accountID, address: address}
}

// Address returns the wallet's EVM address.
func (s *Signer) Address() string { return s.address }

// SignTypedData hashes the EIP-712 payload and signs it via Openfort.
func (s *Signer) SignTypedData(ctx context.Context, domain evm.TypedDataDomain, types map[string][]evm.TypedDataField, primaryType string, message map[string]interface{}) ([]byte, error) {
	hash, err := evm.HashTypedData(domain, types, primaryType, message)
	if err != nil {
		return nil, fmt.Errorf("typed data hash: %w", err)
	}
	var h [32]byte
	copy(h[:], hash)
	return s.of.SignHash(ctx, s.accountID, h)
}

// Policy constrains which payment requirements Fetch may fulfill.
type Policy struct {
	MaxAmount *big.Int // per call, asset minor units (USDC 6dp); nil = no cap
	Networks  []string // allowed CAIP-2 networks, e.g. "eip155:84532"; empty = deny all
	Assets    []string // allowed asset contract addresses (lowercase); empty = any
	PayTo     []string // allowed recipients (lowercase); empty = any
}

// Request is one HTTP request the edge makes on the agent's behalf.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// PaymentInfo is the receipt of a settled x402 payment.
type PaymentInfo struct {
	Network     string `json:"network"`
	Asset       string `json:"asset"`
	PayTo       string `json:"pay_to"`
	Amount      string `json:"amount"`
	Transaction string `json:"transaction"`
	Payer       string `json:"payer"`
}

// Response is what the agent sees: status, filtered headers, redacted
// body and, when a payment settled, its receipt.
type Response struct {
	Status    int               `json:"http_status"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body"`
	Redacted  bool              `json:"redacted,omitempty"`
	Truncated bool              `json:"truncated,omitempty"`
	Payment   *PaymentInfo      `json:"payment,omitempty"`
	// PaymentAttempted is true when a requirement was selected and a
	// payment signature was sent, regardless of the outcome.
	PaymentAttempted bool `json:"payment_attempted,omitempty"`
}

const maxBody = 1 << 20

// Amount parses PaymentInfo.Amount (minor units) into a big.Int.
func Amount(p *PaymentInfo) (*big.Int, bool) {
	if p == nil || p.Amount == "" {
		return nil, false
	}
	n, ok := new(big.Int).SetString(p.Amount, 10)
	return n, ok
}

// Fetch performs req, paying an x402 challenge when the server's offer
// satisfies pol. A non-402 response passes through unpaid. Refusals are
// ErrPolicy-wrapped; signing never happens for disallowed requirements.
func Fetch(ctx context.Context, signer evm.ClientEvmSigner, req Request, pol Policy) (*Response, error) {
	if len(pol.Networks) == 0 {
		return nil, fmt.Errorf("%w: no networks allowed", ErrPolicy)
	}
	u := req.URL
	if u == "" {
		return nil, fmt.Errorf("bad url")
	}
	paidView := struct {
		network, asset, payTo, amount string
	}{}
	allowed := func(views []x402.PaymentRequirementsView) []x402.PaymentRequirementsView {
		out := make([]x402.PaymentRequirementsView, 0, len(views))
		for _, v := range views {
			if v.GetScheme() != "exact" {
				continue
			}
			if !matchCI(pol.Networks, caip2(v.GetNetwork())) {
				continue
			}
			if len(pol.Assets) > 0 && !matchCI(pol.Assets, v.GetAsset()) {
				continue
			}
			if len(pol.PayTo) > 0 && !matchCI(pol.PayTo, v.GetPayTo()) {
				continue
			}
			if pol.MaxAmount != nil {
				amt, ok := new(big.Int).SetString(v.GetAmount(), 10)
				if !ok || amt.Cmp(pol.MaxAmount) > 0 {
					continue
				}
			}
			out = append(out, v)
		}
		return out
	}
	client := x402.Newx402Client(
		x402.WithPaymentSelector(func(views []x402.PaymentRequirementsView) x402.PaymentRequirementsView {
			sel := views[0]
			paidView.network = caip2(sel.GetNetwork())
			paidView.asset, paidView.payTo, paidView.amount = sel.GetAsset(), sel.GetPayTo(), sel.GetAmount()
			return sel
		}),
	).
		Register("eip155:*", exactclient.NewExactEvmScheme(signer, nil)).
		RegisterPolicy(allowed)
	for _, n := range evmv1.Networks {
		client.RegisterV1(x402.Network(n), exactv1.NewExactEvmSchemeV1(signer))
	}
	hc := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	x402http.WrapHTTPClientWithPayment(hc, x402http.Newx402HTTPClient(client))

	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("bad request: %w", err)
	}
	for k, v := range req.Headers {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "connection" || strings.HasPrefix(lk, "proxy-") {
			continue
		}
		hreq.Header.Set(k, v)
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		var pe *x402.PaymentError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("%w: %s", ErrPolicy, scrubErr(err))
		}
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	out := &Response{Status: resp.StatusCode, Headers: map[string]string{}, Body: string(raw)}
	if len(raw) > maxBody {
		out.Body = string(raw[:maxBody])
		out.Truncated = true
	}
	out.Body, out.Redacted = egress.RedactSecrets(out.Body)
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "date" || lk == "x-request-id" ||
			lk == "retry-after" || lk == "location" || strings.HasPrefix(lk, "x-ratelimit-") {
			v, changed := egress.RedactSecrets(strings.Join(vv, ", "))
			out.Redacted = out.Redacted || changed
			out.Headers[k] = v
		}
	}
	// A payment counts only when the retry succeeded — a requirement was
	// selected AND the final response isn't another 402. A terminal 402
	// after signing means the facilitator rejected the payment.
	out.PaymentAttempted = paidView.network != ""
	if paidView.network != "" && resp.StatusCode != http.StatusPaymentRequired {
		out.Payment = &PaymentInfo{
			Network: paidView.network, Asset: paidView.asset,
			PayTo: paidView.payTo, Amount: paidView.amount,
		}
	}
	// Settlement receipt (tx hash, payer) rides in PAYMENT-RESPONSE.
	hdrs := map[string]string{}
	for k, vv := range resp.Header {
		if len(vv) > 0 {
			hdrs[k] = vv[0]
		}
	}
	if settle, err := x402http.Newx402HTTPClient(client).GetPaymentSettleResponse(hdrs); err == nil && settle != nil {
		if out.Payment == nil {
			out.Payment = &PaymentInfo{Network: string(settle.Network)}
		}
		out.Payment.Transaction = settle.Transaction
		out.Payment.Payer = settle.Payer
		if settle.Amount != "" {
			out.Payment.Amount = settle.Amount
		}
		if out.Payment.Network == "" {
			out.Payment.Network = string(settle.Network)
		}
	}
	return out, nil
}

// caip2 normalizes a requirement network to CAIP-2 form; v1 servers
// still use legacy names ("base-sepolia") which map to "eip155:<id>".
func caip2(network string) string {
	if strings.HasPrefix(network, "eip155:") {
		return network
	}
	if id, err := evmv1.GetEvmChainId(network); err == nil {
		return "eip155:" + id.String()
	}
	return network
}

func matchCI(list []string, v string) bool {
	for _, it := range list {
		if strings.EqualFold(strings.TrimSpace(it), v) {
			return true
		}
	}
	return false
}

// scrubErr shortens SDK errors to a single line, dropping any base64
// blobs that would leak the payment payload into agent-visible errors.
func scrubErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
