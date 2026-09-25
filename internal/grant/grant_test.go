package grant

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joalavedra/valet/internal/store"
)

func tempIssuer(t *testing.T) (*Issuer, *store.Agent) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a, err := st.CreateAgent("bot", "hash")
	if err != nil {
		t.Fatal(err)
	}
	return NewIssuer(st, []byte("secret")), a
}

func TestIssueVerifyConsume(t *testing.T) {
	i, a := tempIssuer(t)
	tok, g, err := i.Issue(a.ID, "cred://x/y", "{}", time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := i.Verify(tok, a.ID)
	if err != nil || got.ID != g.ID {
		t.Fatal(err, got)
	}
	if _, err := i.Consume(tok, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Consume(tok, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Consume(tok, a.ID); err != ErrExhausted {
		t.Fatalf("want ErrExhausted, got %v", err)
	}
}

func TestBadToken(t *testing.T) {
	i, a := tempIssuer(t)
	if _, err := i.Verify("garbage", a.ID); err != ErrInvalid {
		t.Fatal(err)
	}
	tok, _, _ := i.Issue(a.ID, "cred://x/y", "{}", time.Hour, 0)
	if _, err := i.Verify(tok, a.ID+999); err != ErrInvalid {
		t.Fatalf("want ErrInvalid for wrong agent, got %v", err)
	}
	parts := strings.Split(tok, ".")
	if _, err := i.Verify(parts[0]+".deadbeef", a.ID); err != ErrInvalid {
		t.Fatal(err)
	}
}

func TestExpiry(t *testing.T) {
	i, a := tempIssuer(t)
	tok, _, _ := i.Issue(a.ID, "cred://x/y", "{}", -time.Hour, 0)
	if _, err := i.Verify(tok, a.ID); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}
