package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
)

func TestMask(t *testing.T) {
	values := map[string]string{
		"cred://github.com/joan":    "s3cret-pass",
		"cred://github.com/joan#pw": "",
	}
	in := "typed s3cret-pass into #password, retried s3cret-pass"
	want := "typed {{cred://github.com/joan}} into #password, retried {{cred://github.com/joan}}"
	if got := Mask(in, values); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := Mask("", values); got != "" {
		t.Fatal("empty input")
	}
}

func TestTOTPCode(t *testing.T) {
	code, err := TOTPCode("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("want 6 digits, got %q", code)
	}
}

func TestFillIntegration(t *testing.T) {
	ws := os.Getenv("VALET_CDP_URL")
	if ws == "" {
		t.Skip("VALET_CDP_URL not set")
	}
	f := &CDPFiller{}
	loc, err := f.PageURL(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("page: %s", loc)
	res, err := f.Fill(context.Background(), ws, "the-internet.herokuapp.com",
		map[string]string{"username": "#username", "password": "#password"},
		"",
		map[string]string{"username": "u", "password": "p"})
	if err != nil {
		t.Fatal(err, res)
	}
	if res.Status != StatusOK {
		t.Fatalf("status %q: %s", res.Status, res.Detail)
	}
	if shot := os.Getenv("VALET_SCREENSHOT"); shot != "" {
		saveScreenshot(t, f, ws, shot)
	}
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var targets []struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		t.Fatal(err)
	}
	pageCount := 0
	for _, target := range targets {
		if target.Type == "page" {
			pageCount++
		}
	}
	if pageCount == 0 {
		t.Fatal("page target disappeared after fill")
	}
	res, err = f.Fill(context.Background(), ws, "the-internet.herokuapp.com", map[string]string{"username": "#username", "password": "#password"}, "", map[string]string{"username": "u2", "password": "p2"})
	if err != nil || res.Status != StatusOK {
		t.Fatalf("second fill: %v %+v", err, res)
	}
}

func saveScreenshot(t *testing.T, f *CDPFiller, ws, path string) {
	t.Helper()
	bctx, err := f.session(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	var png []byte
	if err := chromedp.Run(bctx, chromedp.CaptureScreenshot(&png)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, png, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyOutcome(t *testing.T) {
	tests := []struct {
		name                   string
		before, after          string
		password, otp, captcha bool
		text, want             string
		filledOTP              bool
	}{
		{"redirect", "/login", "/home", true, false, false, "", StatusOK, false},
		{"password gone", "/login", "/login", false, false, false, "", StatusOK, false},
		{"otp", "/login", "/login", true, true, false, "", StatusNeedOTP, false},
		{"otp filled, same page", "/login", "/login", true, true, false, "", StatusUnknown, true},
		{"otp filled, navigated", "/login", "/totp", true, true, false, "", StatusNeedOTP, true},
		{"captcha", "/login", "/login", true, false, true, "", StatusCaptcha, false},
		{"wrong", "/login", "/login", true, false, false, "Invalid username or password", StatusWrongPassword, false},
		{"unknown", "/login", "/login", true, false, false, "Welcome", StatusUnknown, false},
	}
	for _, tc := range tests {
		if got := classifyOutcome(tc.before, tc.after, tc.password, tc.otp, tc.captcha, tc.text, tc.filledOTP); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestScreenshotIntegration(t *testing.T) {
	ws := os.Getenv("VALET_CDP_URL")
	shot := os.Getenv("VALET_SCREENSHOT")
	if ws == "" || shot == "" {
		t.Skip("VALET_CDP_URL/VALET_SCREENSHOT not set")
	}
	saveScreenshot(t, &CDPFiller{}, ws, shot)
}

func fakeCDP(t *testing.T, pages []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json/version":
			json.NewEncoder(w).Encode(map[string]any{"webSocketDebuggerUrl": "ws://x/devtools/browser/1"})
		case "/json":
			json.NewEncoder(w).Encode(pages)
		default:
			http.NotFound(w, r)
		}
	}))
}

func page(url, id string) map[string]any {
	return map[string]any{"id": id, "type": "page", "url": url}
}

func TestResolvePage(t *testing.T) {
	ts := fakeCDP(t, []map[string]any{
		page("https://a.example.com/login", "P1"),
		page("https://a.example.com/login?tab=2", "P2"),
		page("https://b.example.com/", "P3"),
	})
	defer ts.Close()
	f := &CDPFiller{}
	base := ts.URL // http:// base → ws:// result

	got, err := f.ResolvePage(context.Background(), base, "https://a.example.com/login")
	if err != nil || !strings.HasSuffix(got, "/devtools/page/P1") {
		t.Fatalf("exact match: %q %v", got, err)
	}
	if !strings.HasPrefix(got, "ws://") {
		t.Fatalf("expected ws scheme, got %q", got)
	}
	// Fragment/trailing-slash normalization still exact.
	got, err = f.ResolvePage(context.Background(), base, "https://b.example.com/#top")
	if err != nil || !strings.HasSuffix(got, "/devtools/page/P3") {
		t.Fatalf("normalized match: %q %v", got, err)
	}
	// Query-only difference falls back to scheme+host+path match, but both
	// P1 and P2 share that path → ambiguous.
	if _, err = f.ResolvePage(context.Background(), base, "https://a.example.com/login?x=9"); err == nil {
		t.Fatal("expected ambiguous error")
	}
	// Unknown page.
	if _, err = f.ResolvePage(context.Background(), base, "https://zzz.example.com/x"); err == nil {
		t.Fatal("expected page not found")
	}
}

func TestResolvePageHostFallback(t *testing.T) {
	ts := fakeCDP(t, []map[string]any{
		page("https://c.example.com/other", "Q1"),
		page("https://d.example.com/", "Q2"),
	})
	defer ts.Close()
	f := &CDPFiller{}
	// Only one page on the hostname → unique-host fallback.
	got, err := f.ResolvePage(context.Background(), ts.URL, "https://c.example.com/nowhere")
	if err != nil || !strings.HasSuffix(got, "/devtools/page/Q1") {
		t.Fatalf("host fallback: %q %v", got, err)
	}
}
