package mpp

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tempoxyz/mpp-go/pkg/mpp"
	"github.com/tempoxyz/mpp-go/pkg/tempo"
	temporpc "github.com/tempoxyz/tempo-go/pkg/client"
	tempotx "github.com/tempoxyz/tempo-go/pkg/transaction"

	"github.com/joalavedra/valet/internal/edge/wallet"
)

const (
	testChain  = int64(42431)
	testRealm  = "test.example"
	testSecret = "unit-test-secret"
)

var (
	payee    = common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	currency = tempo.PathUSDAddress
)

// testSigner signs secp256k1 digests locally (v ∈ {0,1}).
type testSigner struct {
	key   *ecdsa.PrivateKey
	addr  common.Address
	calls int32
}

func newTestSigner(t *testing.T) *testSigner {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: k, addr: crypto.PubkeyToAddress(k.PublicKey)}
}

func (s *testSigner) Address() common.Address { return s.addr }

func (s *testSigner) SignHash(_ context.Context, hash [32]byte) ([]byte, error) {
	atomic.AddInt32(&s.calls, 1)
	return crypto.Sign(hash[:], s.key)
}

func (s *testSigner) callCount() int { return int(atomic.LoadInt32(&s.calls)) }

// fakeRPC answers the RPC calls Method needs, no network.
type fakeRPC struct {
	chainID uint64
	nonce   uint64
	sends   int32
}

func (f *fakeRPC) GetChainID(context.Context) (uint64, error) { return f.chainID, nil }
func (f *fakeRPC) GetTransactionCount(context.Context, string) (uint64, error) {
	return f.nonce, nil
}
func (f *fakeRPC) SendRawTransaction(context.Context, string) (string, error) {
	atomic.AddInt32(&f.sends, 1)
	return "0x" + strings.Repeat("ab", 32), nil
}
func (f *fakeRPC) SendRequest(_ context.Context, method string, _ ...interface{}) (*temporpc.JSONRPCResponse, error) {
	switch method {
	case "eth_gasPrice":
		return temporpc.NewJSONRPCResponse(nil, "0x3b9aca00"), nil
	case "eth_estimateGas":
		return temporpc.NewJSONRPCResponse(nil, "0x7a120"), nil
	}
	return temporpc.NewJSONRPCResponse(nil, nil), nil
}

func chargeMap(amount, cur, to string, chainID int64) map[string]any {
	req, err := tempo.NormalizeChargeRequest(tempo.ChargeRequestParams{
		Amount: amount, Currency: cur, Recipient: to, ChainID: chainID,
	})
	if err != nil {
		panic(err)
	}
	return req.Map()
}

func testChallenge(t *testing.T, reqMap map[string]any) *mpp.Challenge {
	return mpp.NewChallenge(testSecret, testRealm, tempo.MethodName, tempo.IntentCharge,
		reqMap, mpp.WithExpires(time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339)))
}

func defaultPolicy() Policy {
	return Policy{ChainIDs: []int64{testChain}, Assets: []string{strings.ToLower(currency)},
		PayTo: []string{strings.ToLower(payee.Hex())}, MaxAmount: big.NewInt(100000)}
}

// decodeCredTx parses the credential's serialized transaction, verifies
// it decodes, recovers the sender from the signature, and returns the tx.
func decodeCredTx(t *testing.T, cred *mpp.Credential, want common.Address) *tempotx.Tx {
	t.Helper()
	sigField, ok := cred.Payload["signature"].(string)
	if !ok || sigField == "" {
		t.Fatalf("no signature payload: %+v", cred.Payload)
	}
	tx, err := tempotx.Deserialize(sigField)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if tx.Signature == nil || tx.Signature.Signature == nil {
		t.Fatal("tx missing signature")
	}
	hash, err := tempotx.GetSignPayload(tx)
	if err != nil {
		t.Fatal(err)
	}
	sig := tx.Signature.Signature
	raw := make([]byte, 65)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:64])
	raw[64] = sig.YParity
	pub, err := crypto.Ecrecover(hash.Bytes(), raw)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	pk, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := crypto.PubkeyToAddress(*pk); got != want {
		t.Fatalf("recovered %s want %s", got, want)
	}
	return tx
}

func TestCreateCredentialPullTx(t *testing.T) {
	s := newTestSigner(t)
	rpc := &fakeRPC{chainID: uint64(testChain), nonce: 42}
	m := NewMethod(s, defaultPolicy(), rpc)
	ch := testChallenge(t, chargeMap("0.01", currency, payee.Hex(), testChain))
	cred, err := m.CreateCredential(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Payload["type"] != string(tempo.CredentialTypeTransaction) {
		t.Fatalf("type %v", cred.Payload["type"])
	}
	tx := decodeCredTx(t, cred, s.Address())
	if tx.ChainID.Cmp(big.NewInt(testChain)) != 0 {
		t.Fatalf("chain %v", tx.ChainID)
	}
	if tx.Nonce != 42 {
		t.Fatalf("nonce %d", tx.Nonce)
	}
	if tx.FeeToken != common.HexToAddress(currency) {
		t.Fatalf("fee token %v", tx.FeeToken)
	}
	if len(tx.Calls) != 1 {
		t.Fatalf("calls %d", len(tx.Calls))
	}
	req, _ := tempo.ParseChargeRequest(ch.Request)
	if !tempo.MatchTransferCalldata(common.Bytes2Hex(tx.Calls[0].Data), req, testRealm, ch.ID) {
		t.Fatal("calldata does not match charge")
	}
	if rpc.sends != 0 {
		t.Fatal("push mode used — expected pull")
	}
	if got := m.paid(); got == nil || got.amount != "10000" || got.chainID != testChain {
		t.Fatalf("paid record %+v", got)
	}
}

func TestPolicyDeniesNeverSign(t *testing.T) {
	goodReq := func() map[string]any { return chargeMap("0.01", currency, payee.Hex(), testChain) }
	cases := []struct {
		name   string
		req    map[string]any
		pol    Policy
		exp    bool
		mutate func(*mpp.Challenge)
	}{
		{"wrong chain", chargeMap("0.01", currency, payee.Hex(), 4217), defaultPolicy(), false, nil},
		{"wrong currency", chargeMap("0.01", tempo.OUSDAddress, payee.Hex(), testChain), defaultPolicy(), false, nil},
		{"wrong recipient", chargeMap("0.01", currency, common.Address{0x99}.Hex(), testChain), defaultPolicy(), false, nil},
		{"over cap", chargeMap("1.0", currency, payee.Hex(), testChain), defaultPolicy(), false, nil},
		{"splits", func() map[string]any {
			r, _ := tempo.NormalizeChargeRequest(tempo.ChargeRequestParams{
				Amount: "0.02", Currency: currency, Recipient: payee.Hex(), ChainID: testChain,
				Splits: []tempo.SplitParams{{Amount: "0.01", Recipient: common.Address{0x11}.Hex()}},
			})
			return r.Map()
		}(), defaultPolicy(), false, nil},
		{"sponsored disallowed", chargeMap("0.01", currency, payee.Hex(), testChain), defaultPolicy(), false,
			func(c *mpp.Challenge) {
				c.Request["methodDetails"].(map[string]any)["feePayer"] = true
			}},
		{"expired", goodReq(), defaultPolicy(), true, nil},
		{"no chain id", func() map[string]any {
			r, _ := tempo.NormalizeChargeRequest(tempo.ChargeRequestParams{
				Amount: "0.01", Currency: currency, Recipient: payee.Hex()})
			return r.Map()
		}(), defaultPolicy(), false, nil},
		{"empty chains", goodReq(), Policy{Assets: []string{strings.ToLower(currency)}}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSigner(t)
			m := NewMethod(s, tc.pol, &fakeRPC{chainID: uint64(testChain)})
			ch := testChallenge(t, tc.req)
			if tc.exp {
				ch.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
			}
			if tc.mutate != nil {
				tc.mutate(ch)
			}
			if m.CanHandleChallenge(ch) {
				t.Fatal("CanHandleChallenge=true")
			}
			_, err := m.CreateCredential(context.Background(), ch)
			if err == nil || !strings.Contains(err.Error(), "payment not allowed") {
				t.Fatalf("err %v", err)
			}
			if s.callCount() != 0 {
				t.Fatal("signer called on policy violation")
			}
		})
	}
}

func TestZeroAmountProof(t *testing.T) {
	s := newTestSigner(t)
	m := NewMethod(s, defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	ch := testChallenge(t, chargeMap("0", currency, payee.Hex(), testChain))
	cred, err := m.CreateCredential(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Payload["type"] != string(tempo.CredentialTypeProof) {
		t.Fatalf("type %v", cred.Payload["type"])
	}
	hexSig, _ := cred.Payload["signature"].(string)
	raw := common.FromHex(hexSig)
	if len(raw) != 65 {
		t.Fatalf("sig len %d", len(raw))
	}
	hash, err := tempo.ProofTypedDataHash(testChain, s.Address(), ch.ID, testRealm)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.Ecrecover(hash.Bytes(), raw)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := crypto.PubkeyToAddress(*pk); got != s.Address() {
		t.Fatalf("recovered %s", got)
	}
}

// mppServer emits a real WWW-Authenticate: Payment challenge and verifies
// the credential's tx, then settles with a Payment-Receipt.
func mppServer(t *testing.T, s *testSigner, reqMap map[string]any) *httptest.Server {
	t.Helper()
	ch := testChallenge(t, reqMap)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Payment ") {
			w.Header().Set("WWW-Authenticate", ch.ToAuthenticate(testRealm))
			w.WriteHeader(402)
			return
		}
		cred, err := mpp.ParseCredential(auth)
		if err != nil {
			t.Errorf("bad credential: %v", err)
			w.WriteHeader(400)
			return
		}
		tx := decodeCredTx(t, cred, s.Address())
		req, _ := tempo.ParseChargeRequest(ch.Request)
		if !tempo.MatchTransferCalldata(common.Bytes2Hex(tx.Calls[0].Data), req, testRealm, ch.ID) {
			t.Error("calldata mismatch")
			w.WriteHeader(402)
			return
		}
		rec := mpp.Success(tempo.MethodName, "0x"+strings.Repeat("cd", 32))
		w.Header().Set(mpp.HeaderPaymentReceipt, mpp.FormatPaymentReceipt(rec))
		w.Write([]byte(`{"ok":true}`))
	}))
}

func TestFetchPaysTempo(t *testing.T) {
	s := newTestSigner(t)
	srv := mppServer(t, s, chargeMap("0.01", currency, payee.Hex(), testChain))
	defer srv.Close()
	res, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL},
		defaultPolicy(), &fakeRPC{chainID: uint64(testChain), nonce: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.Payment == nil {
		t.Fatalf("%+v", res)
	}
	if res.Payment.Protocol != "mpp" || res.Payment.Method != "tempo" {
		t.Fatalf("payment %+v", res.Payment)
	}
	if res.Payment.Amount != "10000" || res.Payment.Network != "eip155:42431" {
		t.Fatalf("payment %+v", res.Payment)
	}
	if res.Payment.Transaction == "" || res.Payment.Receipt == "" {
		t.Fatalf("missing receipt: %+v", res.Payment)
	}
}

func TestFetchPassthrough(t *testing.T) {
	s := newTestSigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("free"))
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL},
		defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Payment != nil || res.PaymentAttempted || res.Body != "free" {
		t.Fatalf("%+v", res)
	}
}

func TestFetchDeniesBeforeSigning(t *testing.T) {
	s := newTestSigner(t)
	srv := mppServer(t, s, chargeMap("0.01", currency, payee.Hex(), testChain))
	defer srv.Close()
	pol := defaultPolicy()
	pol.MaxAmount = big.NewInt(1) // under the 0.01 amount
	res, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL},
		pol, &fakeRPC{chainID: uint64(testChain)})
	if err == nil || !errors.Is(err, wallet.ErrPolicy) {
		t.Fatalf("expected ErrPolicy, got res=%+v err=%v", res, err)
	}
	if s.callCount() != 0 {
		t.Fatal("signer called")
	}
}

func TestFetchRejectsAfterCredential(t *testing.T) {
	s := newTestSigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ch := testChallenge(t, chargeMap("0.01", currency, payee.Hex(), testChain))
		w.Header().Set("WWW-Authenticate", ch.ToAuthenticate(testRealm))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL},
		defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 402 || !res.PaymentAttempted || res.Payment != nil {
		t.Fatalf("%+v", res)
	}
	if s.callCount() == 0 {
		t.Fatal("expected a signature attempt")
	}
}

func TestFetchIgnoresSpoofedReceipt(t *testing.T) {
	s := newTestSigner(t)
	rec := mpp.Success(tempo.MethodName, "0x"+strings.Repeat("ee", 32))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(mpp.HeaderPaymentReceipt, mpp.FormatPaymentReceipt(rec))
		w.Write([]byte("free"))
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL},
		defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Payment != nil || res.PaymentAttempted {
		t.Fatalf("spoofed receipt accepted: %+v", res.Payment)
	}
}

func TestFetchStripsPaymentHeaders(t *testing.T) {
	s := newTestSigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("authorization = %q", got)
		}
		if r.Header.Get("Payment-Receipt") != "" || r.Header.Get("WWW-Authenticate") != "" {
			t.Error("payment header leaked")
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL,
		Headers: map[string]string{
			"Authorization":    "Bearer tok",
			"Payment-Receipt":  "AAAA",
			"WWW-Authenticate": "Payment x",
		}}, defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFetchStripsPaymentAuthorization(t *testing.T) {
	s := newTestSigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("payment authorization leaked: %q", got)
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL,
		Headers: map[string]string{"Authorization": "Payment e30="}},
		defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFetchLostBodyCountsPaid(t *testing.T) {
	s := newTestSigner(t)
	ch := testChallenge(t, chargeMap("0.01", currency, payee.Hex(), testChain))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Payment ") {
			w.Header().Set("WWW-Authenticate", ch.ToAuthenticate(testRealm))
			w.WriteHeader(402)
			return
		}
		w.Header().Set("Content-Length", "10000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), s, wallet.Request{Method: "GET", URL: srv.URL},
		defaultPolicy(), &fakeRPC{chainID: uint64(testChain)})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.PaymentAttempted || res.Payment == nil {
		t.Fatalf("lost receipt: %+v", res)
	}
	if res.Payment.Amount != "10000" || res.Payment.Protocol != "mpp" {
		t.Fatalf("%+v", res.Payment)
	}
}
