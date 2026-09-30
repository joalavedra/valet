package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	x402 "github.com/x402-foundation/x402/go"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
	evmsigner "github.com/x402-foundation/x402/go/signers/evm"

	"github.com/joalavedra/valet/internal/edge/wallet/openfort"
)

const (
	testNet   = "eip155:84532"
	testAsset = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" // USDC base sepolia
	testPayTo = "0x1111111111111111111111111111111111111111"
)

// evmKey must be a real secp256k1 key.
func evmKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// openfortStub signs posted digests with key over secp256k1, mimicking
// POST /v2/accounts/backend/{id}/sign.
func openfortStub(t *testing.T, key *ecdsa.PrivateKey) (*openfort.Client, *int) {
	t.Helper()
	calls := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Data string `json:"data"`
		}
		json.Unmarshal(body, &req)
		digest, _ := hex.DecodeString(strings.TrimPrefix(req.Data, "0x"))
		sig, err := ethcrypto.Sign(digest, key)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		// crypto.Sign already emits v as 0/1, like Openfort.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"signature": "0x" + hex.EncodeToString(sig)})
	}))
	t.Cleanup(srv.Close)
	// wallet secret is a P-256 key; signing auth is stub-ignored.
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p256)
	c, err := openfort.New("sk_test_stub", base64.StdEncoding.EncodeToString(der), openfort.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c, calls
}

func TestSignerRecoversToAddress(t *testing.T) {
	key := evmKey(t)
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	of, _ := openfortStub(t, key)
	s := NewSigner(of, "acc_test", addr)
	if s.Address() != addr {
		t.Fatalf("address mismatch")
	}
	// EIP-3009 TransferWithAuthorization shape.
	sig, err := s.SignTypedData(context.Background(),
		evm.TypedDataDomain{Name: "USD Coin", Version: "2", ChainID: big.NewInt(84532), VerifyingContract: testAsset},
		map[string][]evm.TypedDataField{
			"TransferWithAuthorization": {
				{Name: "from", Type: "address"}, {Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"}, {Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"}, {Name: "nonce", Type: "bytes32"},
			},
		},
		"TransferWithAuthorization",
		map[string]any{
			"from": addr, "to": testPayTo, "value": "1000",
			"validAfter": "0", "validBefore": "9999999999",
			"nonce": "0x" + strings.Repeat("01", 32),
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len %d", len(sig))
	}
	// Recover and compare.
	hash, err := evm.HashTypedData(
		evm.TypedDataDomain{Name: "USD Coin", Version: "2", ChainID: big.NewInt(84532), VerifyingContract: testAsset},
		map[string][]evm.TypedDataField{
			"TransferWithAuthorization": {
				{Name: "from", Type: "address"}, {Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"}, {Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"}, {Name: "nonce", Type: "bytes32"},
			},
		},
		"TransferWithAuthorization",
		map[string]any{
			"from": addr, "to": testPayTo, "value": "1000",
			"validAfter": "0", "validBefore": "9999999999",
			"nonce": "0x" + strings.Repeat("01", 32),
		})
	if err != nil {
		t.Fatal(err)
	}
	sig[64] -= 27 // SigToPub wants 0/1
	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ethcrypto.PubkeyToAddress(*pub).Hex() != addr {
		t.Fatal("signature does not recover to signer address")
	}
}

// v2Server returns 402 with a base64 PAYMENT-REQUIRED header, then 200
// with PAYMENT-RESPONSE once PAYMENT-SIGNATURE arrives.
func v2Server(t *testing.T, amount string, opts ...func(*x402.PaymentRequirements)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			settle, _ := json.Marshal(x402.SettleResponse{
				Success: true, Transaction: "0xabc123", Network: x402.Network(testNet),
				Payer: "0xpayer", Amount: amount,
			})
			w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(settle))
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
			return
		}
		req := x402.PaymentRequirements{
			Scheme: "exact", Network: testNet, Asset: testAsset,
			Amount: amount, PayTo: testPayTo, MaxTimeoutSeconds: 300,
			Extra: map[string]interface{}{"name": "USD Coin", "version": "2"},
		}
		for _, f := range opts {
			if f != nil {
				f(&req)
			}
		}
		pr, _ := json.Marshal(x402.PaymentRequired{
			X402Version: 2, Accepts: []x402.PaymentRequirements{req},
			Resource: &x402.ResourceInfo{URL: "http://" + r.Host + r.URL.Path},
		})
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(pr))
		w.WriteHeader(402)
	}))
}

func testSigner(t *testing.T) *evmsigner.ClientSigner {
	t.Helper()
	key := evmKey(t)
	s, err := evmsigner.NewClientSignerFromPrivateKey(hex.EncodeToString(ethcrypto.FromECDSA(key)))
	if err != nil {
		t.Fatal(err)
	}
	cs, ok := s.(*evmsigner.ClientSigner)
	if !ok {
		t.Fatalf("unexpected signer type")
	}
	return cs
}

func TestFetchPaysV2(t *testing.T) {
	srv := v2Server(t, "1000")
	defer srv.Close()
	s := testSigner(t)
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL + "/data"},
		Policy{Networks: []string{testNet}, MaxAmount: big.NewInt(2000)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || !strings.Contains(res.Body, `"ok":true`) {
		t.Fatalf("bad response %+v", res)
	}
	if res.Payment == nil || res.Payment.Transaction != "0xabc123" || res.Payment.Amount != "1000" {
		t.Fatalf("bad payment info %+v", res.Payment)
	}
	if res.Payment.Network != testNet || res.Payment.PayTo != testPayTo {
		t.Fatalf("bad payment fields %+v", res.Payment)
	}
}

func TestFetchPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("free"))
	}))
	defer srv.Close()
	s := testSigner(t)
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL},
		Policy{Networks: []string{testNet}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.Payment != nil || res.Body != "free" {
		t.Fatalf("bad passthrough %+v", res)
	}
}

func TestFetchDenies(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*x402.PaymentRequirements)
		pol  Policy
	}{
		{"network", func(r *x402.PaymentRequirements) { r.Network = "eip155:1" }, Policy{Networks: []string{testNet}}},
		{"payTo", func(r *x402.PaymentRequirements) { r.PayTo = "0x9999999999999999999999999999999999999999" }, Policy{Networks: []string{testNet}, PayTo: []string{testPayTo}}},
		{"asset", func(r *x402.PaymentRequirements) { r.Asset = "0xdead" }, Policy{Networks: []string{testNet}, Assets: []string{testAsset}}},
		{"amount", nil, Policy{Networks: []string{testNet}, MaxAmount: big.NewInt(500)}},
		{"scheme", func(r *x402.PaymentRequirements) { r.Scheme = "upto" }, Policy{Networks: []string{testNet}}},
	}
	for _, tc := range cases {
		srv := v2Server(t, "1000", tc.mut)
		s := &countingSigner{inner: testSigner(t)}
		_, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL}, tc.pol)
		if !errors.Is(err, ErrPolicy) {
			t.Fatalf("%s: want ErrPolicy, got %v", tc.name, err)
		}
		if s.calls != 0 {
			t.Fatalf("%s: signer called %d times", tc.name, s.calls)
		}
		srv.Close()
	}
	// Empty networks denies even a well-formed offer.
	srv := v2Server(t, "100")
	s := testSigner(t)
	if _, err := Fetch(context.Background(), Signers{EVM: s}, Request{URL: srv.URL}, Policy{}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("empty networks: want ErrPolicy, got %v", err)
	}
	srv.Close()
}

func TestFetchV1(t *testing.T) {
	// V1 servers return a JSON body with x402Version:1 and X-PAYMENT.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PAYMENT") != "" {
			w.Header().Set("X-PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(
				[]byte(`{"success":true,"transaction":"0xv1tx","network":"base-sepolia","payer":"0xpayer"}`)))
			w.Write([]byte("v1 ok"))
			return
		}
		w.WriteHeader(402)
		json.NewEncoder(w).Encode(map[string]any{
			"x402Version": 1,
			"accepts": []map[string]any{{
				"scheme": "exact", "network": "base-sepolia",
				"asset": testAsset, "maxAmountRequired": "700",
				"payTo": testPayTo, "maxTimeoutSeconds": 300,
				"extra": map[string]any{"name": "USD Coin", "version": "2"},
			}},
		})
	}))
	defer srv.Close()
	s := testSigner(t)
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL},
		Policy{Networks: []string{testNet}, MaxAmount: big.NewInt(1000)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.Payment == nil || res.Payment.Transaction != "0xv1tx" {
		t.Fatalf("v1: %+v", res)
	}
}

func TestAmountHelper(t *testing.T) {
	n, ok := Amount(&PaymentInfo{Amount: "1500000"})
	if !ok || n.Cmp(big.NewInt(1500000)) != 0 {
		t.Fatal("bad amount")
	}
	if _, ok := Amount(&PaymentInfo{}); ok {
		t.Fatal("want false")
	}
}

type countingSigner struct {
	inner evm.ClientEvmSigner
	calls int
}

func (c *countingSigner) Address() string { return c.inner.Address() }
func (c *countingSigner) SignTypedData(ctx context.Context, d evm.TypedDataDomain, t map[string][]evm.TypedDataField, p string, m map[string]interface{}) ([]byte, error) {
	c.calls++
	return c.inner.SignTypedData(ctx, d, t, p, m)
}

func TestFetchPaymentRejected(t *testing.T) {
	// Facilitator rejects: second request also answers 402.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := x402.PaymentRequirements{
			Scheme: "exact", Network: testNet, Asset: testAsset,
			Amount: "1000", PayTo: testPayTo, MaxTimeoutSeconds: 300,
			Extra: map[string]interface{}{"name": "USD Coin", "version": "2"},
		}
		pr, _ := json.Marshal(x402.PaymentRequired{X402Version: 2, Accepts: []x402.PaymentRequirements{req}})
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(pr))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	s := &countingSigner{inner: testSigner(t)}
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL},
		Policy{Networks: []string{testNet}, MaxAmount: big.NewInt(2000)})
	if err != nil {
		t.Fatal(err)
	}
	if s.calls == 0 {
		t.Fatal("signer never called")
	}
	if res.Status != 402 {
		t.Fatalf("status %d", res.Status)
	}
	if res.Payment != nil {
		t.Fatalf("payment recorded for rejected settle: %+v", res.Payment)
	}
	if !res.PaymentAttempted {
		t.Fatal("PaymentAttempted false")
	}
}

func TestFetchLostReceiptCountsPaid(t *testing.T) {
	// Upstream returns 402, then on the signed retry sends 200 headers
	// with an oversized Content-Length and aborts mid-body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") == "" {
			req := x402.PaymentRequirements{
				Scheme: "exact", Network: testNet, Asset: testAsset,
				Amount: "1000", PayTo: testPayTo, MaxTimeoutSeconds: 300,
				Extra: map[string]interface{}{"name": "USD Coin", "version": "2"},
			}
			pr, _ := json.Marshal(x402.PaymentRequired{X402Version: 2, Accepts: []x402.PaymentRequirements{req}})
			w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(pr))
			w.WriteHeader(402)
			return
		}
		w.Header().Set("Content-Length", "10000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()
	s := testSigner(t)
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL},
		Policy{Networks: []string{testNet}, MaxAmount: big.NewInt(2000)})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.PaymentAttempted || res.Payment == nil {
		t.Fatalf("lost receipt: %+v", res)
	}
	if res.Payment.Amount != "1000" || res.Payment.Network != testNet {
		t.Fatalf("bad conservative payment %+v", res.Payment)
	}
}

func TestFetchIgnoresSpoofedSettleHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settle, _ := json.Marshal(x402.SettleResponse{Success: true, Transaction: "0xfake", Network: x402.Network(testNet)})
		w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(settle))
		w.Write([]byte("free"))
	}))
	defer srv.Close()
	s := testSigner(t)
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL},
		Policy{Networks: []string{testNet}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Payment != nil || res.PaymentAttempted {
		t.Fatalf("spoofed settle accepted: %+v", res.Payment)
	}
}

func TestFetchStripsPaymentHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"Payment-Signature", "X-Payment", "Payment-Required", "Payment-Response", "X-Payment-Response"} {
			if r.Header.Get(h) != "" {
				t.Errorf("agent header %s leaked upstream", h)
			}
		}
		if r.Header.Get("Authorization") != "Bearer ok" {
			t.Errorf("authorization stripped")
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	s := testSigner(t)
	_, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL,
		Headers: map[string]string{
			"Payment-Signature": "AAAA", "X-Payment": "AAAA", "Payment-Required": "x",
			"Payment-Response": "x", "X-Payment-Response": "x",
			"Authorization": "Bearer ok",
		}}, Policy{Networks: []string{testNet}})
	if err != nil {
		t.Fatal(err)
	}
}

// A server that hijacks and closes the connection once the payment
// signature arrives simulates a lost response after paying.
func TestFetchConnClosedAfterSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			t.Error("no hijacker")
		}
		req := x402.PaymentRequirements{
			Scheme: "exact", Network: testNet, Asset: testAsset,
			Amount: "1000", PayTo: testPayTo, MaxTimeoutSeconds: 300,
			Extra: map[string]interface{}{"name": "USD Coin", "version": "2"},
		}
		pr, _ := json.Marshal(x402.PaymentRequired{
			X402Version: 2, Accepts: []x402.PaymentRequirements{req},
			Resource: &x402.ResourceInfo{URL: "http://" + r.Host + r.URL.Path},
		})
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(pr))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	s := testSigner(t)
	res, err := Fetch(context.Background(), Signers{EVM: s}, Request{Method: "GET", URL: srv.URL},
		Policy{Networks: []string{testNet}, MaxAmount: big.NewInt(2000)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.PaymentAttempted || res.Payment == nil {
		t.Fatalf("expected conservative paid result: %+v", res)
	}
	if res.Payment.Network != testNet || res.Payment.Amount != "1000" {
		t.Fatalf("payment %+v", res.Payment)
	}
	if res.Status != 0 {
		t.Fatalf("status %d", res.Status)
	}
}
