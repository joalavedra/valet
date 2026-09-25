package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
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
