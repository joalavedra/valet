// Package mpp is the MPP (Machine Payments Protocol) edge: it answers
// `402 Payment Required` challenges carrying `WWW-Authenticate: Payment`
// by signing Tempo charge transactions through the same backend wallet
// used by the x402 edge. Only the tempo/charge pull flow is supported;
// push ("hash") credentials are never produced.
package mpp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/tempoxyz/mpp-go/pkg/client"
	"github.com/tempoxyz/mpp-go/pkg/mpp"
	"github.com/tempoxyz/mpp-go/pkg/tempo"
	temposigner "github.com/tempoxyz/tempo-go/pkg/signer"
	tempotx "github.com/tempoxyz/tempo-go/pkg/transaction"

	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/edge/netguard"
	"github.com/joalavedra/valet/internal/edge/wallet"
)

// feePayerMarker mirrors mpp-go pkg/tempo/client/method.go: the legacy
// sponsored-transaction suffix recognized by tempo-go during deserialize.
const feePayerMarker = "feefeefeefee"

const maxBody = 1 << 20

// HashSigner signs 32-byte digests and reports its EVM address. The
// returned signature is 65 bytes r||s||v with v ∈ {0,1} (yParity).
// wallet.Signer satisfies it via Openfort.
type HashSigner interface {
	Address() common.Address
	SignHash(ctx context.Context, hash [32]byte) ([]byte, error)
}

// WalletSigner adapts *wallet.Signer (Openfort-backed) to HashSigner.
func WalletSigner(s *wallet.Signer) HashSigner { return walletSigner{s} }

type walletSigner struct{ s *wallet.Signer }

func (w walletSigner) Address() common.Address { return w.s.AddressCommon() }
func (w walletSigner) SignHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	return w.s.SignHash(ctx, hash)
}

// Policy constrains which MPP challenges Fetch may fulfill.
type Policy struct {
	ChainIDs       []int64  // allowed Tempo chain ids; empty = deny all
	Assets         []string // allowed currency token addresses (lowercase); empty = any
	PayTo          []string // allowed recipient addresses (lowercase); empty = any
	MaxAmount      *big.Int // per call, base units; nil = no cap
	AllowSponsored bool     // permit fee-payer (sponsored) challenges
	// ChainAssets, when non-nil, constrains allowed currencies per chain
	// (denies a chain absent from the map outright). Falls back to Assets.
	ChainAssets map[int64][]string
	// AllowPrivate permits dialing non-publicly-routable upstreams
	// (loopback, RFC1918, link-local). Default false = SSRF hard fence.
	AllowPrivate bool
}

// paidInfo records what a credential paid for, for the receipt.
type paidInfo struct {
	chainID     int64
	currency    string
	recipient   string
	amount      string
	challengeID string
	proof       bool
}

// Method implements client.Method and client.ChallengeMatcher for
// tempo/charge, backed by a HashSigner instead of a local key.
type Method struct {
	signer   HashSigner
	rpc      tempo.RPCClient // optional override (tests)
	pol      Policy
	clientID string

	mu   sync.Mutex
	last *paidInfo
}

// NewMethod builds a tempo charge Method.
func NewMethod(signer HashSigner, pol Policy, rpc tempo.RPCClient) *Method {
	return &Method{signer: signer, pol: pol, rpc: rpc, clientID: "valet"}
}

// Name returns the method token used in Challenges and Credentials.
func (m *Method) Name() string { return tempo.MethodName }

// Intent returns the charge intent handled by this method.
func (m *Method) Intent() string { return tempo.IntentCharge }

// CanHandleChallenge reports whether the challenge satisfies the policy
// — the transport consults it before any credential is created.
func (m *Method) CanHandleChallenge(challenge *mpp.Challenge) bool {
	return m.checkPolicy(challenge) == nil
}

// checkPolicy applies the payment policy without touching the signer.
func (m *Method) checkPolicy(challenge *mpp.Challenge) error {
	if challenge.Method != tempo.MethodName {
		return fmt.Errorf("unsupported method %q", challenge.Method)
	}
	if challenge.Intent != tempo.IntentCharge {
		return fmt.Errorf("unsupported intent %q", challenge.Intent)
	}
	if challenge.Expires != "" {
		expiry, err := parseExpiry(challenge.Expires)
		if err != nil || expiry.Before(time.Now().UTC()) {
			return fmt.Errorf("challenge expired")
		}
	}
	request, err := tempo.ParseChargeRequest(challenge.Request)
	if err != nil {
		return fmt.Errorf("bad charge request: %w", err)
	}
	// ParseChargeRequest misses chainId when the request was decoded with
	// json.Number (as mpp.ParseChallenge does) — read it ourselves.
	chainID, ok := requestChainID(challenge.Request)
	if !ok {
		return fmt.Errorf("challenge has no chain id")
	}
	if !chainAllowed(m.pol.ChainIDs, chainID) {
		return fmt.Errorf("chain %d not allowed", chainID)
	}
	if m.pol.ChainAssets != nil {
		assets, ok := m.pol.ChainAssets[chainID]
		if !ok {
			return fmt.Errorf("chain %d has no allowed assets", chainID)
		}
		if !matchFold(assets, request.Currency) {
			return fmt.Errorf("currency %s not allowed on chain %d", request.Currency, chainID)
		}
	} else if len(m.pol.Assets) > 0 && !matchFold(m.pol.Assets, request.Currency) {
		return fmt.Errorf("currency %s not allowed", request.Currency)
	}
	if len(m.pol.PayTo) > 0 && !matchFold(m.pol.PayTo, request.Recipient) {
		return fmt.Errorf("recipient %s not allowed", request.Recipient)
	}
	if len(request.MethodDetails.Splits) > 0 {
		return fmt.Errorf("split payments not allowed")
	}
	if request.MethodDetails.FeePayer && !m.pol.AllowSponsored {
		return fmt.Errorf("sponsored (fee-payer) charges not allowed")
	}
	amount, ok := new(big.Int).SetString(request.Amount, 10)
	if !ok {
		return fmt.Errorf("bad amount %q", request.Amount)
	}
	if amount.Sign() < 0 {
		return fmt.Errorf("negative amount %q", request.Amount)
	}
	if amount.Sign() > 0 && m.pol.MaxAmount != nil && amount.Cmp(m.pol.MaxAmount) > 0 {
		return fmt.Errorf("amount %s exceeds cap %s", amount, m.pol.MaxAmount)
	}
	return nil
}

// CreateCredential mirrors mpp-go pkg/tempo/client/method.go exactly —
// same transfer building, memo attribution, gas handling and sponsored
// branch — except signing goes through the HashSigner (a remote digest
// signer) instead of a local key. Pull ("transaction") credentials only;
// zero-amount challenges get a proof credential.
func (m *Method) CreateCredential(ctx context.Context, challenge *mpp.Challenge) (*mpp.Credential, error) {
	if err := m.checkPolicy(challenge); err != nil {
		return nil, fmt.Errorf("%w: %s", wallet.ErrPolicy, err)
	}
	request, _ := tempo.ParseChargeRequest(challenge.Request) // checked above
	chainID, _ := requestChainID(challenge.Request)

	rpc := m.rpc
	if rpc == nil {
		rpcURL, err := tempo.RPCURLForChain(chainID)
		if err != nil {
			return nil, fmt.Errorf("tempo client: %w; configure RPC explicitly", err)
		}
		rpc = tempo.NewRPCClient(rpcURL)
	}
	gotChainID, err := rpc.GetChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("tempo client: get chain id: %w", err)
	}
	if int64(gotChainID) != chainID {
		return nil, fmt.Errorf("tempo client: chain id mismatch (rpc=%d, expected=%d)", gotChainID, chainID)
	}

	addr := m.signer.Address()
	amount, _ := new(big.Int).SetString(request.Amount, 10) // checked in checkPolicy
	if amount != nil && amount.Sign() == 0 {
		if !request.Allows(tempo.CredentialTypeProof) {
			return nil, fmt.Errorf("%w: challenge does not accept proof credentials", wallet.ErrPolicy)
		}
		signature, err := m.signProof(ctx, chainID, challenge.ID, challenge.Realm)
		if err != nil {
			return nil, err
		}
		m.record(&paidInfo{chainID: chainID, currency: request.Currency,
			recipient: request.Recipient, amount: "0", challengeID: challenge.ID, proof: true})
		return &mpp.Credential{
			Challenge: challenge.ToEcho(),
			Payload: tempo.ChargeCredentialPayload{
				Type:      tempo.CredentialTypeProof,
				Signature: signature,
			}.Map(),
			Source: tempo.ProofSource(chainID, addr),
		}, nil
	}
	if !request.Allows(tempo.CredentialTypeTransaction) {
		return nil, fmt.Errorf("%w: transaction credentials not allowed by this challenge", wallet.ErrPolicy)
	}

	memo := tempo.EncodeAttribution(challenge.Realm, m.clientID, challenge.ID)
	rawTx, err := m.buildTransfer(ctx, rpc, request, memo, chainID)
	if err != nil {
		return nil, err
	}
	m.record(&paidInfo{chainID: chainID, currency: request.Currency,
		recipient: request.Recipient, amount: request.Amount, challengeID: challenge.ID})
	return &mpp.Credential{
		Challenge: challenge.ToEcho(),
		Payload: tempo.ChargeCredentialPayload{
			Type:      tempo.CredentialTypeTransaction,
			Signature: rawTx,
		}.Map(),
		Source: tempo.ProofSource(chainID, addr),
	}, nil
}

func (m *Method) record(p *paidInfo) {
	m.mu.Lock()
	m.last = p
	m.mu.Unlock()
}

// paid returns the payment details recorded by the last credential, or nil.
func (m *Method) paid() *paidInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

func (m *Method) signProof(ctx context.Context, chainID int64, challengeID, realm string) (string, error) {
	hash, err := tempo.ProofTypedDataHash(chainID, m.signer.Address(), challengeID, realm)
	if err != nil {
		return "", fmt.Errorf("tempo client: build proof payload: %w", err)
	}
	var h [32]byte
	copy(h[:], hash.Bytes())
	sig, err := m.signer.SignHash(ctx, h)
	if err != nil {
		return "", fmt.Errorf("tempo client: sign proof payload: %w", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("tempo client: bad signature length %d", len(sig))
	}
	return hexutil.Encode(sig), nil
}

// buildTransfer mirrors mpp-go's buildTransfer, substituting remote
// digest signing for the local signer.
func (m *Method) buildTransfer(
	ctx context.Context,
	rpc tempo.RPCClient,
	request tempo.ChargeRequest,
	memo string,
	chainID int64,
) (string, error) {
	transfers, err := buildTransfers(request, memo)
	if err != nil {
		return "", err
	}

	gasPrice, err := m.gasPrice(ctx, rpc)
	if err != nil {
		return "", err
	}
	token := common.HexToAddress(request.Currency)
	gasLimit := tempo.DefaultGasLimit
	if len(transfers) == 1 {
		dataHex := transferDataHex(transfers[0])
		if estimated, err := m.estimateGas(ctx, rpc, token.Hex(), dataHex); err == nil && estimated+5_000 > gasLimit {
			gasLimit = estimated + 5_000
		}
	}

	builder := tempotx.NewBuilder(big.NewInt(chainID)).
		SetMaxFeePerGas(gasPrice).
		SetMaxPriorityFeePerGas(new(big.Int).Set(gasPrice)).
		SetGas(gasLimit).
		SetNonceKey(big.NewInt(0))
	for _, transfer := range transfers {
		builder.AddCall(token, big.NewInt(0), common.FromHex(transferDataHex(transfer)))
	}

	addr := m.signer.Address()
	if request.MethodDetails.FeePayer {
		builder.
			SetSponsored(true).
			SetNonceKey(new(big.Int).Set(tempo.ExpiringNonceKey)).
			SetNonce(0).
			SetValidBefore(uint64(time.Now().Add(tempo.FeePayerWindow).Unix()))
	} else {
		nonce, err := rpc.GetTransactionCount(ctx, addr.Hex())
		if err != nil {
			return "", fmt.Errorf("tempo client: get nonce: %w", err)
		}
		builder.SetNonce(nonce).SetFeeToken(token)
	}
	tx, err := builder.BuildAndValidate()
	if err != nil {
		return "", fmt.Errorf("tempo client: build transaction: %w", err)
	}

	hash, err := tempotx.GetSignPayload(tx)
	if err != nil {
		return "", fmt.Errorf("tempo client: sign payload: %w", err)
	}
	var h [32]byte
	copy(h[:], hash.Bytes())
	sig, err := m.signer.SignHash(ctx, h)
	if err != nil {
		return "", fmt.Errorf("tempo client: sign transaction: %w", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("tempo client: bad signature length %d", len(sig))
	}
	tx.Signature = temposigner.NewSignatureEnvelope(
		new(big.Int).SetBytes(sig[:32]),
		new(big.Int).SetBytes(sig[32:64]),
		sig[64],
	)
	tx.From = addr

	serialized, err := tempotx.Serialize(tx, nil)
	if err != nil {
		return "", fmt.Errorf("tempo client: serialize transaction: %w", err)
	}
	if request.MethodDetails.FeePayer {
		return serialized + strings.TrimPrefix(strings.ToLower(addr.Hex()), "0x") + feePayerMarker, nil
	}
	return serialized, nil
}

// --- the helpers below mirror mpp-go pkg/tempo/client/method.go ---

type transfer struct {
	amount    *big.Int
	memo      string
	recipient string
}

func buildTransfers(request tempo.ChargeRequest, memo string) ([]transfer, error) {
	totalAmount, ok := new(big.Int).SetString(request.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("tempo client: invalid amount %q", request.Amount)
	}
	primaryAmount := new(big.Int).Set(totalAmount)
	transfers := make([]transfer, 0, len(request.MethodDetails.Splits)+1)
	for _, split := range request.MethodDetails.Splits {
		splitAmount, ok := new(big.Int).SetString(split.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("tempo client: invalid split amount %q", split.Amount)
		}
		primaryAmount.Sub(primaryAmount, splitAmount)
		transfers = append(transfers, transfer{
			amount:    splitAmount,
			memo:      split.Memo,
			recipient: split.Recipient,
		})
	}
	transfers = append([]transfer{{
		amount:    primaryAmount,
		memo:      memo,
		recipient: request.Recipient,
	}}, transfers...)
	return transfers, nil
}

func transferDataHex(transfer transfer) string {
	if transfer.memo != "" {
		dataHex, _ := tempo.EncodeTransferWithMemo(transfer.recipient, transfer.amount, transfer.memo)
		return dataHex
	}
	return tempo.EncodeTransfer(transfer.recipient, transfer.amount)
}

func (m *Method) gasPrice(ctx context.Context, rpc tempo.RPCClient) (*big.Int, error) {
	response, err := rpc.SendRequest(ctx, "eth_gasPrice")
	if err != nil {
		return nil, fmt.Errorf("tempo client: eth_gasPrice: %w", err)
	}
	if err := response.CheckError(); err != nil {
		return nil, err
	}
	value, ok := response.Result.(string)
	if !ok {
		return nil, fmt.Errorf("tempo client: unexpected eth_gasPrice result %T", response.Result)
	}
	parsed, err := tempo.ParseHexBigInt(value)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func (m *Method) estimateGas(
	ctx context.Context,
	rpc tempo.RPCClient,
	to string,
	data string,
) (uint64, error) {
	response, err := rpc.SendRequest(ctx, "eth_estimateGas", map[string]any{
		"from": m.signer.Address().Hex(),
		"to":   to,
		"data": data,
	})
	if err != nil {
		return 0, err
	}
	if err := response.CheckError(); err != nil {
		return 0, err
	}
	value, ok := response.Result.(string)
	if !ok {
		return 0, fmt.Errorf("tempo client: unexpected eth_estimateGas result %T", response.Result)
	}
	return tempo.ParseHexUint64(value)
}

// requestChainID extracts methodDetails.chainId regardless of the
// decoder's number type (float64, json.Number or string).
func requestChainID(request map[string]any) (int64, bool) {
	raw, ok := request["methodDetails"].(map[string]any)
	if !ok {
		return 0, false
	}
	switch v := raw["chainId"].(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case float64:
		if v == float64(int64(v)) {
			return int64(v), true
		}
	case json.Number:
		if id, err := v.Int64(); err == nil {
			return id, true
		}
	case string:
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			return id, true
		}
	}
	return 0, false
}

func parseExpiry(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05.000Z", value)
}

func chainAllowed(ids []int64, id int64) bool {
	for _, it := range ids {
		if it == id {
			return true
		}
	}
	return false
}

// matchFold compares case-insensitively only for 0x-prefixed hex
// (EVM addresses); everything else is exact — base58 Solana addresses
// are case-sensitive.
func matchFold(list []string, v string) bool {
	for _, it := range list {
		it = strings.TrimSpace(it)
		if strings.HasPrefix(it, "0x") || strings.HasPrefix(v, "0x") {
			if strings.EqualFold(it, v) {
				return true
			}
		} else if it == v {
			return true
		}
	}
	return false
}

// Fetch performs req, answering an MPP tempo/charge challenge when the
// offer satisfies pol. A non-402 response passes through unpaid.
// Refusals are wallet.ErrPolicy-wrapped; the signer is never invoked
// for a disallowed challenge.
func Fetch(ctx context.Context, signer HashSigner, req wallet.Request, pol Policy, rpc tempo.RPCClient) (*wallet.Response, error) {
	if len(pol.ChainIDs) == 0 {
		return nil, fmt.Errorf("%w: no chains allowed", wallet.ErrPolicy)
	}
	u := req.URL
	if u == "" {
		return nil, fmt.Errorf("bad url")
	}
	method := NewMethod(signer, pol, rpc)

	tr := client.NewTransport([]client.Method{method}, netguard.Transport(pol.AllowPrivate))
	hc := &http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	m := strings.ToUpper(req.Method)
	if m == "" {
		m = http.MethodGet
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, m, u, body)
	if err != nil {
		return nil, fmt.Errorf("bad request: %w", err)
	}
	for k, v := range req.Headers {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "connection" || strings.HasPrefix(lk, "proxy-") {
			continue
		}
		// Agent-supplied MPP payment material must never reach the
		// upstream — only the edge may attach a credential. A
		// "Payment ..." Authorization is MPP payment material; Bearer /
		// Basic and other schemes are the agent's own API auth.
		if lk == "authorization" && len(v) >= 8 && strings.EqualFold(v[:8], "payment ") {
			continue
		}
		if lk == "payment-receipt" || lk == "www-authenticate" ||
			lk == "payment-authorization" || lk == "payment-session" ||
			lk == "payment-session-snapshot" || lk == "accept-payment" {
			continue
		}
		hreq.Header.Set(k, v)
	}

	resp, err := hc.Do(hreq)
	if err != nil {
		if errors.Is(err, wallet.ErrPolicy) {
			return nil, fmt.Errorf("%w: %s", wallet.ErrPolicy, wallet.ScrubErr(err))
		}
		// Blocked upstreams fail before any challenge → no credential.
		if errors.Is(err, netguard.ErrBlocked) {
			return nil, fmt.Errorf("%w: %s", wallet.ErrPolicy, wallet.ScrubErr(err))
		}
		// The credential was already sent and the conn died — the upstream
		// may still settle; conservatively count it as paid.
		if paid := method.paid(); paid != nil {
			return &wallet.Response{Status: 0, PaymentAttempted: true,
				Payment: paymentFrom(paid, "")}, nil
		}
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	paid := method.paid()
	out := &wallet.Response{Status: resp.StatusCode, Headers: map[string]string{}}
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if rerr != nil && paid == nil {
		return nil, fmt.Errorf("read failed: %w", rerr)
	}
	// Same rule as the x402 edge: if we signed and the body died
	// mid-read, the upstream may still settle — count it as paid.
	if rerr != nil {
		out.PaymentAttempted = true
		out.Payment = paymentFrom(paid, "")
		return out, nil
	}
	out.Body = string(raw)
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
	out.PaymentAttempted = paid != nil
	// A terminal 402 we refused to pay: surface the policy denial (like
	// the x402 edge) instead of echoing the upstream challenge.
	if paid == nil && resp.StatusCode == http.StatusPaymentRequired {
		for _, hdr := range resp.Header.Values(mpp.HeaderWWWAuthenticate) {
			ch, err := mpp.ParseChallenge(hdr)
			if err != nil || ch == nil || ch.Method != tempo.MethodName || ch.Intent != tempo.IntentCharge {
				continue
			}
			if err := method.checkPolicy(ch); err != nil {
				return nil, fmt.Errorf("%w: %s", wallet.ErrPolicy, err)
			}
			return nil, fmt.Errorf("%w: tempo charge could not be fulfilled", wallet.ErrPolicy)
		}
	}
	if paid != nil && resp.StatusCode != http.StatusPaymentRequired {
		out.Payment = paymentFrom(paid, "")
		// The receipt (tx reference) rides in Payment-Receipt —
		// meaningful only when we actually sent a credential.
		if rh := resp.Header.Get(mpp.HeaderPaymentReceipt); rh != "" {
			if rec, err := mpp.ParsePaymentReceipt(rh); err == nil && rec != nil {
				out.Payment.Transaction = rec.Reference
				out.Payment.Receipt = rh
			}
		}
	}
	return out, nil
}

func paymentFrom(p *paidInfo, receipt string) *wallet.PaymentInfo {
	return &wallet.PaymentInfo{
		Protocol: "mpp",
		Method:   tempo.MethodName,
		Receipt:  receipt,
		Network:  fmt.Sprintf("eip155:%d", p.chainID),
		Asset:    p.currency,
		PayTo:    p.recipient,
		Amount:   p.amount,
	}
}
