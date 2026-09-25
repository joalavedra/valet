package browser

import (
	"context"
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
	res, err := f.Fill(context.Background(), ws,
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

func TestScreenshotIntegration(t *testing.T) {
	ws := os.Getenv("VALET_CDP_URL")
	shot := os.Getenv("VALET_SCREENSHOT")
	if ws == "" || shot == "" {
		t.Skip("VALET_CDP_URL/VALET_SCREENSHOT not set")
	}
	saveScreenshot(t, &CDPFiller{}, ws, shot)
}
