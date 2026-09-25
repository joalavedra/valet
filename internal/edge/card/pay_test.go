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
		PayRequest{Method: "GET", URL: upstream.URL})
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
		PayRequest{Method: "GET", URL: upstream.URL})
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
	if os.Getenv("VGS_VAULT_ID") == "" {
		t.Skip("VGS_VAULT_ID not set")
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
		PayRequest{Method: "GET", URL: "https://echo.apps.verygood.systems/get"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 {
		t.Fatalf("live status %d", res.Status)
	}
	fmt.Println("VGS live smoke status:", res.Status)
}
