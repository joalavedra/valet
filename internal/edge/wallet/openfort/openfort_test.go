package openfort

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, base64.StdEncoding.EncodeToString(der)
}

func TestCanonicalJSON(t *testing.T) {
	in := map[string]any{
		"b": "2",
		"a": map[string]any{"z": 1, "y": []any{map[string]any{"k2": 2, "k1": 1}}},
	}
	got, err := canonicalJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"y":[{"k1":1,"k2":2}],"z":1},"b":"2"}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	// No HTML escaping.
	got, _ = canonicalJSON(map[string]any{"x": "a<b&c"})
	if strings.Contains(string(got), "\\u") {
		t.Fatalf("html escaping present: %s", got)
	}
}

func TestWalletAuthJWT(t *testing.T) {
	key, b64 := testKey(t)
	c, err := New("sk_test_secret", b64, WithBaseURL("https://api.openfort.io"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.walletAuthJWT("POST", "api.openfort.io", "/v2/accounts/backend/acc_x/sign", []byte(`{"data":"0x00"}`))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("bad jwt shape: %d parts", len(parts))
	}
	var hdr, claims map[string]any
	json.Unmarshal(b64urlDecode(t, parts[0]), &hdr)
	json.Unmarshal(b64urlDecode(t, parts[1]), &claims)
	if hdr["alg"] != "ES256" || hdr["typ"] != "JWT" {
		t.Fatalf("bad header: %v", hdr)
	}
	uris, _ := claims["uris"].([]any)
	if len(uris) != 1 || uris[0] != "POST api.openfort.io/v2/accounts/backend/acc_x/sign" {
		t.Fatalf("bad uris: %v", claims["uris"])
	}
	wantHash := sha256.Sum256([]byte(`{"data":"0x00"}`))
	if claims["reqHash"] != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("bad reqHash: %v", claims["reqHash"])
	}
	if claims["iat"] != claims["nbf"] || claims["jti"] == "" {
		t.Fatalf("bad claims: %v", claims)
	}
	// Verify ES256 r||s signature.
	sig, err := b64url.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("bad signature bytes: %d", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify")
	}
}

func b64urlDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64url.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNormalizeV(t *testing.T) {
	mk := func(v byte) []byte { s := make([]byte, 65); s[64] = v; return s }
	for _, tc := range []struct{ in, want byte }{{0, 27}, {1, 28}, {27, 27}, {28, 28}} {
		got, err := NormalizeV(mk(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		if got[64] != tc.want {
			t.Fatalf("v=%d: got %d want %d", tc.in, got[64], tc.want)
		}
	}
	if _, err := NormalizeV(make([]byte, 64)); err == nil {
		t.Fatal("want length error")
	}
}

func TestSignHash(t *testing.T) {
	_, b64 := testKey(t)
	var gotAuth, gotWalletAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotWalletAuth = r.Header.Get("X-Wallet-Auth")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Path != "/v2/accounts/backend/acc_1/sign" {
			t.Errorf("bad path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// v=0 -> must normalize to 27.
		sig := make([]byte, 65)
		for i := range sig {
			sig[i] = byte(i)
		}
		sig[64] = 0
		json.NewEncoder(w).Encode(map[string]string{"signature": "0x" + hex.EncodeToString(sig)})
	}))
	defer srv.Close()
	c, err := New("sk_test_abc123", b64, WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	var h [32]byte
	out, err := c.SignHash(context.Background(), "acc_1", h)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 65 || out[64] != 27 {
		t.Fatalf("bad normalized sig len=%d v=%d", len(out), out[64])
	}
	if gotAuth != "Bearer sk_test_abc123" {
		t.Fatalf("bad auth header")
	}
	if !strings.HasPrefix(gotWalletAuth, "eyJ") {
		t.Fatalf("no wallet auth jwt")
	}
	if !strings.Contains(gotBody, `"data"`) {
		t.Fatalf("bad body %s", gotBody)
	}
}

func TestSignHashErrorLeaksNothing(t *testing.T) {
	_, b64 := testKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"unauthorized sk_test_abc123"}`))
	}))
	defer srv.Close()
	c, _ := New("sk_test_abc123", b64, WithBaseURL(srv.URL))
	_, err := c.SignHash(context.Background(), "acc_1", [32]byte{})
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "sk_test_abc123") || strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("error leaks secret/body: %v", err)
	}
}

func TestNewBadSecret(t *testing.T) {
	if _, err := New("k", "not-base64!!"); err == nil {
		t.Fatal("want error")
	}
	// RSA key, not P-256.
	if _, err := New("k", base64.StdEncoding.EncodeToString(pemEncodeJunk())); err == nil {
		t.Fatal("want error")
	}
	if _, err := New("", "AA=="); err == nil {
		t.Fatal("want error")
	}
}

func pemEncodeJunk() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})
}

func TestNoRedirectFollow(t *testing.T) {
	_, b64 := testKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/x", 302)
	}))
	defer srv.Close()
	c, _ := New("sk", b64, WithBaseURL(srv.URL))
	if _, err := c.SignHash(context.Background(), "acc_1", [32]byte{}); err == nil {
		t.Fatal("redirect followed or error missing")
	}
}
