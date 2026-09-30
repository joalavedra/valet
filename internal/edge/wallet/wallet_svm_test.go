package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	x402 "github.com/x402-foundation/x402/go"
	"github.com/x402-foundation/x402/go/mechanisms/svm"

	"github.com/joalavedra/valet/internal/edge/wallet/openfort"
)

const (
	solDevnet = svm.SolanaDevnetCAIP2
	solUSDC   = svm.USDCDevnetAddress
	solPayTo  = "FDx9mfVqTvXUaSPQDELwDtGgMqxirmAFsEK2s4YsKfsc"
	solFeePay = "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"
)

// svmKey must be a real ed25519 key; its public half is the Solana address.
func svmKey(t *testing.T) (ed25519.PrivateKey, solana.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, solana.PublicKeyFromBytes(pub)
}

// openfortSvmStub signs posted bytes with key over ed25519, mimicking
// POST /v2/accounts/backend/{id}/sign for an SVM account.
func openfortSvmStub(t *testing.T, key ed25519.PrivateKey) (*openfort.Client, *int) {
	t.Helper()
	calls := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Data string `json:"data"`
		}
		json.Unmarshal(body, &req)
		msg, err := hex.DecodeString(strings.TrimPrefix(req.Data, "0x"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sig := ed25519.Sign(key, msg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"signature": "0x" + hex.EncodeToString(sig)})
	}))
	t.Cleanup(srv.Close)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p256)
	c, err := openfort.New("sk_test_stub", base64.StdEncoding.EncodeToString(der), openfort.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c, calls
}

// svmTx builds a minimal versioned tx with a different fee payer so the
// wallet key lands at index 1 among required signers.
func svmTx(t *testing.T, wallet solana.PublicKey, feePayer solana.PublicKey) *solana.Transaction {
	t.Helper()
	tx, err := solana.NewTransactionBuilder().
		AddInstruction(solana.NewInstruction(
			solana.MustPublicKeyFromBase58(svm.MemoProgramAddress),
			solana.AccountMetaSlice{{PublicKey: wallet, IsSigner: true}},
			[]byte("test"),
		)).
		SetRecentBlockHash(solana.MustHashFromBase58("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM")).
		SetFeePayer(feePayer).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	tx.Message.SetVersion(solana.MessageVersionV0)
	return tx
}

func TestSvmSignerPartialSign(t *testing.T) {
	priv, pub := svmKey(t)
	of, calls := openfortSvmStub(t, priv)
	s, err := NewSvmSigner(of, "acc_sol", pub.String())
	if err != nil {
		t.Fatal(err)
	}
	feePayer := solana.MustPublicKeyFromBase58(solFeePay)
	tx := svmTx(t, pub, feePayer)
	if err := s.SignTransaction(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Fatalf("openfort calls %d", *calls)
	}
	// Fee payer first, wallet second among required signers.
	if tx.Message.AccountKeys[0] != feePayer {
		t.Fatalf("fee payer not first: %s", tx.Message.AccountKeys[0])
	}
	idx, err := tx.GetAccountIndex(pub)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := tx.Message.MarshalBinary()
	if !ed25519.Verify(pub[:], msg, tx.Signatures[idx][:]) {
		t.Fatal("inserted signature does not verify")
	}
	// A tampered signer response must be rejected.
	badOf := func() *openfort.Client {
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(p256)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"signature": "0x" + hex.EncodeToString(other[:])})
		}))
		t.Cleanup(srv.Close)
		c, err := openfort.New("sk_test_stub", base64.StdEncoding.EncodeToString(der), openfort.WithBaseURL(srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}()
	bs, err := NewSvmSigner(badOf, "acc_sol", pub.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.SignTransaction(context.Background(), svmTx(t, pub, feePayer)); err == nil ||
		!strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("expected verify failure, got %v", err)
	}
	// Wallet absent from required signers → error, sign still called.
	stranger := solana.MustPublicKeyFromBase58(solPayTo)
	tx2 := svmTx(t, stranger, feePayer)
	if err := s.SignTransaction(context.Background(), tx2); err == nil ||
		!strings.Contains(err.Error(), "not a required signer") {
		t.Fatalf("expected not-a-signer error, got %v", err)
	}
}

// svmRPC stubs the two JSON-RPC calls the exact scheme makes:
// getAccountInfo (mint, SPL Token program) and getLatestBlockhash.
func svmRPC(t *testing.T) *httptest.Server {
	t.Helper()
	// SPL Token Mint layout, 82 bytes: mintAuthority COption(4+32),
	// supply u64, decimals u8, isInitialized u8, freezeAuthority COption.
	mint := make([]byte, 82)
	binary.LittleEndian.PutUint64(mint[36:44], 1_000_000_000)
	mint[44] = 6 // decimals
	mint[45] = 1 // initialized
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.Unmarshal(body, &req)
		var result any
		switch req.Method {
		case "getAccountInfo":
			result = map[string]any{"context": map[string]any{"slot": 1}, "value": map[string]any{
				"lamports": 1, "owner": solana.TokenProgramID.String(), "executable": false,
				"rentEpoch": 0, "data": []string{base64.StdEncoding.EncodeToString(mint), "base64"},
			}}
		case "getLatestBlockhash":
			result = map[string]any{"context": map[string]any{"slot": 1}, "value": map[string]any{
				"blockhash": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM", "lastValidBlockHeight": 100,
			}}
		default:
			t.Errorf("unexpected RPC method %s", req.Method)
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "result": result,
		})
	}))
}

// solV2Server serves a solana-devnet 402 then 200 once a
// PAYMENT-SIGNATURE arrives, capturing the decoded transaction.
func solV2Server(t *testing.T, amount string, network string) (*httptest.Server, *solana.Transaction) {
	t.Helper()
	got := &solana.Transaction{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hdr := r.Header.Get("PAYMENT-SIGNATURE"); hdr != "" {
			raw, _ := base64.StdEncoding.DecodeString(hdr)
			var payload struct {
				Payload struct {
					Transaction string `json:"transaction"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Errorf("bad PAYMENT-SIGNATURE json: %v", err)
			}
			tx, err := svm.DecodeTransaction(payload.Payload.Transaction)
			if err != nil {
				t.Errorf("bad transaction: %v", err)
			} else {
				*got = *tx
			}
			settle, _ := json.Marshal(x402.SettleResponse{
				Success: true, Transaction: "5soltx", Network: x402.Network(solDevnet),
				Payer: "payer_b58", Amount: amount,
			})
			w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(settle))
			w.Write([]byte(`{"ok":true}`))
			return
		}
		req := x402.PaymentRequirements{
			Scheme: "exact", Network: network, Asset: solUSDC,
			Amount: amount, PayTo: solPayTo, MaxTimeoutSeconds: 300,
			Extra: map[string]interface{}{"feePayer": solFeePay},
		}
		pr, _ := json.Marshal(x402.PaymentRequired{
			X402Version: 2, Accepts: []x402.PaymentRequirements{req},
			Resource: &x402.ResourceInfo{URL: "http://" + r.Host + r.URL.Path},
		})
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(pr))
		w.WriteHeader(402)
	}))
	return srv, got
}

func TestFetchPaysSolanaDevnet(t *testing.T) {
	priv, pub := svmKey(t)
	of, calls := openfortSvmStub(t, priv)
	s, err := NewSvmSigner(of, "acc_sol", pub.String())
	if err != nil {
		t.Fatal(err)
	}
	rpc := svmRPC(t)
	defer rpc.Close()
	srv, got := solV2Server(t, "10000", solDevnet)
	defer srv.Close()
	res, err := Fetch(context.Background(), Signers{SVM: s, SvmRPC: rpc.URL},
		Request{Method: "GET", URL: srv.URL + "/data"},
		Policy{Networks: []string{solDevnet}, Assets: []string{solUSDC}, MaxAmount: big.NewInt(50000)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || !strings.Contains(res.Body, `"ok":true`) {
		t.Fatalf("bad response %+v", res)
	}
	if res.Payment == nil || res.Payment.Transaction != "5soltx" || res.Payment.Network != solDevnet {
		t.Fatalf("bad payment %+v", res.Payment)
	}
	if *calls != 1 {
		t.Fatalf("openfort calls %d", *calls)
	}
	// The settled tx carries our signature and the facilitator fee payer.
	feePayer := solana.MustPublicKeyFromBase58(solFeePay)
	if len(got.Message.AccountKeys) == 0 || got.Message.AccountKeys[0] != feePayer {
		t.Fatalf("fee payer wrong: %+v", got.Message.AccountKeys)
	}
	idx, err := got.GetAccountIndex(pub)
	if err != nil {
		t.Fatalf("wallet not a signer: %v", err)
	}
	msg, _ := got.Message.MarshalBinary()
	if !ed25519.Verify(pub[:], msg, got.Signatures[idx][:]) {
		t.Fatal("payment tx signature does not verify")
	}
}

func TestFetchSolanaPolicyDenies(t *testing.T) {
	priv, pub := svmKey(t)
	of, calls := openfortSvmStub(t, priv)
	s, err := NewSvmSigner(of, "acc_sol", pub.String())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pol  Policy
	}{
		{"wrong_network", Policy{Networks: []string{"eip155:84532"}, MaxAmount: big.NewInt(50000)}},
		{"over_cap", Policy{Networks: []string{solDevnet}, MaxAmount: big.NewInt(5000)}},
		{"wrong_asset", Policy{Networks: []string{solDevnet}, Assets: []string{"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}, MaxAmount: big.NewInt(50000)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := solV2Server(t, "10000", solDevnet)
			defer srv.Close()
			*calls = 0
			_, err := Fetch(context.Background(), Signers{SVM: s}, Request{Method: "GET", URL: srv.URL + "/x"}, tc.pol)
			var pe *x402.PaymentError
			if !errors.Is(err, ErrPolicy) && !errors.As(err, &pe) {
				t.Fatalf("expected policy refusal, got %v", err)
			}
			if *calls != 0 {
				t.Fatalf("openfort called on denied requirement")
			}
		})
	}
	// v1 names normalize to CAIP-2 for policy matching.
	if got := caip2("solana-devnet"); got != solDevnet {
		t.Fatalf("caip2(solana-devnet) = %s", got)
	}
	if got := caip2("solana"); got != svm.SolanaMainnetCAIP2 {
		t.Fatalf("caip2(solana) = %s", got)
	}
}
