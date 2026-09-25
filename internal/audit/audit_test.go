package audit

import (
	"path/filepath"
	"testing"

	"github.com/joalavedra/valet/internal/store"
)

func tempChain(t *testing.T) *Chain {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st)
}

func TestAppendAndVerify(t *testing.T) {
	c := tempChain(t)
	for i := 0; i < 3; i++ {
		if err := c.Append(&store.AuditEntry{AgentID: 1, Handle: "cred://x/y", Edge: "browser", Target: "t", Decision: "allow", Detail: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.VerifyStore(); err != nil {
		t.Fatal(err)
	}
}

func TestTamperBreaksVerify(t *testing.T) {
	c := tempChain(t)
	c.Append(&store.AuditEntry{Handle: "a", Decision: "allow"})
	c.Append(&store.AuditEntry{Handle: "b", Decision: "allow"})
	c.Append(&store.AuditEntry{Handle: "c", Decision: "deny"})

	entries := []store.AuditEntry{
		{Handle: "a", Decision: "allow"},
		{Handle: "b", Decision: "allow"},
		{Handle: "c", Decision: "deny"},
	}
	for i := range entries {
		entries[i].PrevHash = ""
	}
	// Rebuild a valid chain then tamper.
	prev := ""
	for i := range entries {
		entries[i].PrevHash = prev
		entries[i].Hash = Hash(&entries[i], prev)
		prev = entries[i].Hash
	}
	if err := Verify(entries); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
	entries[1].Decision = "tampered"
	if err := Verify(entries); err != ErrChainBroken {
		t.Fatalf("want ErrChainBroken, got %v", err)
	}
}
