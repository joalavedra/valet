// Package openfort is a minimal client for Openfort developer-custody
// backend wallets. It creates accounts and signs EIP-712 hashes; the
// account's private key never leaves Openfort custody.
//
// Every request carries `Authorization: Bearer <secret key>` plus an
// `X-Wallet-Auth` ES256 JWT signed with the wallet secret (a P-256 key,
// base64 PKCS8 DER). The JWT binds the request: claim `uris` is
// "<METHOD> <host><path>" and `reqHash` is the lowercase hex SHA-256 of
// the canonically (recursively key-sorted) JSON body.
package openfort

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const defaultBase = "https://api.openfort.io"

// Client talks to the Openfort backend-wallets API.
type Client struct {
	baseURL   string
	http      *http.Client
	secretKey string
	walletKey *ecdsa.PrivateKey
}

// Option configures a Client (tests).
type Option func(*Client)

// WithBaseURL overrides the API base (default https://api.openfort.io).
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = u } }

// WithHTTPClient overrides the http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New parses the base64 PKCS8 DER P-256 wallet secret and builds a client.
func New(secretKey, walletSecretB64DER string, opts ...Option) (*Client, error) {
	if secretKey == "" {
		return nil, errors.New("openfort: secret key required")
	}
	der, err := base64.StdEncoding.DecodeString(walletSecretB64DER)
	if err != nil {
		return nil, fmt.Errorf("openfort: bad wallet secret encoding")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	for i := range der {
		der[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("openfort: bad wallet secret key")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("openfort: wallet secret is not a P-256 key")
	}
	c := &Client{baseURL: defaultBase, secretKey: secretKey, walletKey: ec,
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// canonicalJSON returns v serialized with object keys recursively sorted,
// compact, no HTML escaping — matching the Node SDK's sortKeys+JSON.stringify
// used for the reqHash claim and the wire body.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sortKeys(v)); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func sortKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = sortKeys(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = sortKeys(x)
		}
		return a
	default:
		return v
	}
}

var b64url = base64.RawURLEncoding

// walletAuthJWT builds the X-Wallet-Auth ES256 JWT:
// header {"alg":"ES256","typ":"JWT"}, claims iat, nbf (=iat), jti (random
// hex nonce), uris ["<METHOD> <host><path>"], reqHash = sha256 hex of the
// canonical JSON body. Signature is raw r||s (64 bytes) per JWS ES256.
func (c *Client) walletAuthJWT(method, host, path string, body []byte) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT"})
	now := time.Now().Unix()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	claims, err := canonicalJSON(map[string]any{
		"iat":     now,
		"nbf":     now,
		"jti":     hex.EncodeToString(jti),
		"uris":    []any{method + " " + host + path},
		"reqHash": hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return "", err
	}
	signing := b64url.EncodeToString(hdr) + "." + b64url.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.walletKey, digest[:])
	if err != nil {
		return "", err
	}
	size := (c.walletKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return signing + "." + b64url.EncodeToString(sig), nil
}

// do sends an authenticated JSON request. Errors never include request
// headers or response bodies; the body is logged at debug level only.
func (c *Client) do(ctx context.Context, method, path string, reqBody map[string]any, out any) error {
	sorted, err := canonicalJSON(reqBody)
	if err != nil {
		return err
	}
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return fmt.Errorf("openfort: bad base url")
	}
	jwt, err := c.walletAuthJWT(method, u.Host, u.Path, sorted)
	if err != nil {
		return fmt.Errorf("openfort: wallet auth failed")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(sorted))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("X-Wallet-Auth", jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("openfort: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("openfort: read failed")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("openfort: request failed (status %d)", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("openfort: bad response")
		}
	}
	return nil
}

// CreateBackendAccount creates a developer-custody EVM account and
// returns its account id ("acc_…") and wallet address.
func (c *Client) CreateBackendAccount(ctx context.Context) (id, address string, err error) {
	var out struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/accounts/backend", map[string]any{"chainType": "EVM"}, &out); err != nil {
		return "", "", err
	}
	if out.ID == "" || out.Address == "" {
		return "", "", fmt.Errorf("openfort: incomplete account response")
	}
	return out.ID, out.Address, nil
}

// SignHash signs a 32-byte digest with the account's backend wallet and
// returns the normalized 65-byte signature (v adjusted to 27/28).
func (c *Client) SignHash(ctx context.Context, accountID string, hash [32]byte) ([]byte, error) {
	var out struct {
		Signature string `json:"signature"`
	}
	err := c.do(ctx, http.MethodPost, "/v2/accounts/backend/"+accountID+"/sign",
		map[string]any{"data": "0x" + hex.EncodeToString(hash[:])}, &out)
	if err != nil {
		return nil, fmt.Errorf("openfort: sign failed")
	}
	sig, err := hex.DecodeString(trim0x(out.Signature))
	if err != nil {
		return nil, fmt.Errorf("openfort: bad signature encoding")
	}
	return NormalizeV(sig)
}

func trim0x(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}

// NormalizeV adjusts an ECDSA recovery id of 0/1 to 27/28, matching
// openfort-node's normalizeSignature. Openfort may return either.
func NormalizeV(sig []byte) ([]byte, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("openfort: signature length %d != 65", len(sig))
	}
	out := make([]byte, 65)
	copy(out, sig)
	if out[64] < 27 {
		out[64] += 27
	}
	return out, nil
}
