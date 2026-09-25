package browser

import (
	"context"
	"os"
	"testing"
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
	res, err := f.Fill(context.Background(), ws,
		map[string]FieldRef{"#username": {Field: "username"}, "#password": {Field: "password"}},
		map[string]string{"username": "u", "password": "p"})
	if err != nil {
		t.Fatal(err, res)
	}
	if res.Status != StatusOK {
		t.Fatalf("status %q: %s", res.Status, res.Detail)
	}
}
