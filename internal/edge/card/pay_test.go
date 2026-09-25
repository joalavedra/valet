package card

import (
	"context"
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
		PayRequest{Method: "GET", URL: "https://echo.apps.verygood.systems/get"}, nil)
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
