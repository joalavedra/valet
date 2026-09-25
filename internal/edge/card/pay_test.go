package card

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var testFields = map[string]string{
	"number": "tok_pan", "exp_month": "12", "exp_year": "2030", "holder": "Joan", "cvc": "tok_cvc",
}

func TestFillPlaceholders(t *testing.T) {
	req := PayRequest{
		Method: "post", URL: "https://api.shop.com/charge",
		Headers: map[string]string{"X-Card": "{{card.holder}}"},
		Body:    `{"pan":"{{card.number}}","exp":"{{card.exp_month}}/{{card.exp_year}}","cvc":"{{card.cvc}}"}`,
	}
	out, err := Fill(req, testFields)
	if err != nil {
		t.Fatal(err)
	}
	if out.Method != "post" || !strings.Contains(out.Body, "tok_pan") || !strings.Contains(out.Body, "12/2030") || !strings.Contains(out.Body, "tok_cvc") {
		t.Fatalf("bad fill: %v", out)
	}
	if out.Headers["X-Card"] != "Joan" {
		t.Fatalf("header not filled: %v", out.Headers)
	}
}

func TestFillUnknownPlaceholder(t *testing.T) {
	_, err := Fill(PayRequest{Body: `{"x":"{{card.bank}}"}`}, testFields)
	if err == nil || !strings.Contains(err.Error(), "unknown card placeholder") {
		t.Fatalf("want unknown placeholder error, got %v", err)
	}
}

func TestFillMissingCVC(t *testing.T) {
	fields := map[string]string{"number": "tok_pan", "exp_month": "12", "exp_year": "2030", "holder": "Joan"}
	_, err := Fill(PayRequest{Body: `{"cvc":"{{card.cvc}}"}`}, fields)
	if err == nil || !strings.Contains(err.Error(), "cvc required (step-up)") {
		t.Fatalf("want step-up error, got %v", err)
	}
}

type staticProvider struct {
	rt  http.RoundTripper
	err error
}

func (p staticProvider) Name() string { return "static" }
func (p staticProvider) Transport() (http.RoundTripper, error) {
	return p.rt, p.err
}
func (p staticProvider) CaptureConfig() (CaptureConfig, error) {
	return CaptureConfig{Provider: "static"}, nil
}

func TestDoNoRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer upstream.Close()
	res, err := Do(context.Background(), staticProvider{rt: http.DefaultTransport},
		PayRequest{Method: "GET", URL: upstream.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusFound || res.Headers["Location"] == "" {
		t.Fatalf("redirect should pass through, got %v %+v", res.Status, res.Headers)
	}
}

func TestDoTruncatedDropsContentLength(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("a", maxPayBody+10))
	}))
	defer upstream.Close()
	res, err := Do(context.Background(), staticProvider{rt: http.DefaultTransport},
		PayRequest{Method: "GET", URL: upstream.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Body) != maxPayBody {
		t.Fatalf("expected truncation: %v", res.Truncated)
	}
	for k := range res.Headers {
		if strings.EqualFold(k, "Content-Length") {
			t.Fatal("Content-Length emitted on truncated response")
		}
	}
}

// TestVGSLive exercises the real proxy auth + CA chain; skipped without env.
func TestVGSLive(t *testing.T) {
	if os.Getenv("VGS_VAULT_ID") == "" || os.Getenv("VGS_USERNAME") == "" || os.Getenv("VGS_PASSWORD") == "" {
		t.Skip("VGS_VAULT_ID/VGS_USERNAME/VGS_PASSWORD not all set")
	}
	v := &VGS{
		VaultID:  os.Getenv("VGS_VAULT_ID"),
		Env:      os.Getenv("VGS_ENV"),
		Username: os.Getenv("VGS_USERNAME"),
		Password: os.Getenv("VGS_PASSWORD"),
		CAFile:   os.Getenv("VGS_CA_FILE"),
	}
	tr, err := v.Transport()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Do(context.Background(), staticProvider{rt: tr},
		PayRequest{Method: "GET", URL: "https://httpbin.org/get"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 {
		t.Fatalf("live status %d", res.Status)
	}
	fmt.Println("VGS live smoke status:", res.Status)
}

func TestRedact(t *testing.T) {
	fields := map[string]string{"number": "tok_alias_pan", "cvc": "tok_cvc9", "exp_month": "12"}
	body := `{"pan":"tok_alias_pan","raw":"4111 1111 1111 1111","cvv":"123","other":42,"exp":"12"}`
	got := redact(body, fields)
	if strings.Contains(got, "tok_alias_pan") || strings.Contains(got, "4111 1111 1111 1111") || strings.Contains(got, `"cvv":"123"`) {
		t.Fatalf("redaction failed: %s", got)
	}
	if !strings.Contains(got, "[redacted]") || !strings.Contains(got, "****1111") || !strings.Contains(got, `"***"`) {
		t.Fatalf("bad redacted form: %s", got)
	}
	// Non-Luhn digit runs and short values survive.
	if got := redact(`{"n":"1234567890123456789","exp":"12"}`, fields); !strings.Contains(got, "1234567890123456789") {
		t.Fatalf("non-PAN mangled: %s", got)
	}
}

func TestDoStripsHopHeaders(t *testing.T) {
	saw := map[string]string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			saw[strings.ToLower(k)] = k
		}
	}))
	defer upstream.Close()
	_, err := Do(context.Background(), staticProvider{rt: http.DefaultTransport},
		PayRequest{Method: "GET", URL: upstream.URL, Headers: map[string]string{
			"Proxy-Authorization": "Basic x", "Connection": "X-Smuggle", "X-Smuggle": "1",
			"Upgrade": "h2c", "X-Keep": "1",
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"proxy-authorization", "x-smuggle", "upgrade", "connection"} {
		if _, ok := saw[bad]; ok {
			t.Fatalf("hop header forwarded: %s", bad)
		}
	}
	if _, ok := saw["x-keep"]; !ok {
		t.Fatal("ordinary header missing")
	}
}

func TestDoRedactsResponse(t *testing.T) {
	fields := map[string]string{"number": "tok_live_pan"}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"echo":"tok_live_pan","card":"4111111111111111"}`)
	}))
	defer upstream.Close()
	res, err := Do(context.Background(), staticProvider{rt: http.DefaultTransport},
		PayRequest{Method: "GET", URL: upstream.URL}, fields)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Body, "tok_live_pan") || strings.Contains(res.Body, "4111111111111111") {
		t.Fatalf("response not redacted: %s", res.Body)
	}
}

func newVGSStub(t *testing.T) *VGS {
	t.Helper()
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type=%q", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok_test"}`)
	}))
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/aliases" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Error("missing bearer")
		}
		var req struct {
			Data []struct {
				Value   string   `json:"value"`
				Format  string   `json:"format"`
				Storage string   `json:"storage"`
				Classes []string `json:"classifiers"`
			} `json:"data"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var resp struct {
			Data []map[string]any `json:"data"`
		}
		for i, d := range req.Data {
			resp.Data = append(resp.Data, map[string]any{
				"value":   nil,
				"aliases": []map[string]string{{"alias": fmt.Sprintf("alias_%d", i), "format": d.Format}},
			})
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(func() { auth.Close(); vault.Close() })
	return &VGS{ClientID: "id", ClientSecret: "sec", authURL: auth.URL, vaultAPIURL: vault.URL}
}

func TestVGSTokenizeHappy(t *testing.T) {
	v := newVGSStub(t)
	aliases, err := v.Tokenize(context.Background(), []TokenizeInput{
		{Value: "4111111111111111", Format: "FPE_SIX_T_FOUR"},
		{Value: "123", Format: "NUM_LENGTH_PRESERVING", Volatile: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) != 2 || aliases[0] != "alias_0" || aliases[1] != "alias_1" {
		t.Fatalf("aliases=%v", aliases)
	}
}

func TestVGSTokenizeAuthFail(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer auth.Close()
	v := &VGS{ClientID: "id", ClientSecret: "sec", authURL: auth.URL, vaultAPIURL: "unused"}
	_, err := v.Tokenize(context.Background(), []TokenizeInput{{Value: "4111111111111111"}})
	if err == nil || strings.Contains(err.Error(), "4111") {
		t.Fatalf("err=%v", err)
	}
}

func TestVGSTokenizeNon2xx(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"t"}`)
	}))
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer auth.Close()
	defer vault.Close()
	v := &VGS{ClientID: "id", ClientSecret: "sec", authURL: auth.URL, vaultAPIURL: vault.URL}
	_, err := v.Tokenize(context.Background(), []TokenizeInput{{Value: "4111111111111111"}})
	if err == nil || !strings.Contains(err.Error(), "status 500") || strings.Contains(err.Error(), "4111") {
		t.Fatalf("err=%v", err)
	}
}

func TestVGSTokenizeMissingCreds(t *testing.T) {
	_, err := (&VGS{}).Tokenize(context.Background(), []TokenizeInput{{Value: "x"}})
	if err == nil || !strings.Contains(err.Error(), "VGS_CLIENT_ID") {
		t.Fatalf("err=%v", err)
	}
}

func TestDoKeepsNonSecretFields(t *testing.T) {
	fields := map[string]string{
		"number": "4111111111111111", "cvc": "tok_cvc", "exp_year": "2030",
		"exp_month": "12", "holder": "Jane Tester",
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"exp":"2030","holder":"Jane Tester","pan":"4111111111111111","cvv":"tok_cvc"}`)
	}))
	defer upstream.Close()
	res, err := Do(context.Background(), staticProvider{rt: http.DefaultTransport},
		PayRequest{Method: "GET", URL: upstream.URL}, fields)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Body, `"exp":"2030"`) || !strings.Contains(res.Body, "Jane Tester") {
		t.Fatalf("non-secret fields redacted: %s", res.Body)
	}
	if strings.Contains(res.Body, "4111111111111111") || strings.Contains(res.Body, "tok_cvc") {
		t.Fatalf("secrets leaked: %s", res.Body)
	}
}
