package mock

import (
	"context"
	"testing"
	"time"

	"github.com/joalavedra/valet/internal/edge/issuer"
)

func luhnOK(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func TestIssueLuhnAndLifecycle(t *testing.T) {
	m := New()
	c, err := m.Issue(context.Background(), issuer.CardSpec{
		GrantID: "g1", PerTx: 1000, SingleUse: true,
		ExpiresAt: time.Now().AddDate(0, 6, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "active" || c.Brand != "visa" {
		t.Fatalf("unexpected card %+v", c)
	}
	f, err := m.Reveal(context.Background(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Number) != 16 || f.Number[:6] != "411111" || !luhnOK(f.Number) {
		t.Fatalf("bad test PAN %q", f.Number)
	}
	if len(f.CVC) != 3 || f.ExpMonth == "" || f.Holder != "VALET AGENT" {
		t.Fatalf("bad fields %+v", f)
	}
	f.Zero()
	if f.Number != "" {
		t.Fatal("Zero() did not clear fields")
	}
	// Close is idempotent; Reveal afterwards fails.
	if err := m.Close(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reveal(context.Background(), c.ID); err == nil {
		t.Fatal("Reveal after Close must fail")
	}
	if _, err := m.Reveal(context.Background(), "mock_nope"); err == nil {
		t.Fatal("Reveal of unknown card must fail")
	}
}
