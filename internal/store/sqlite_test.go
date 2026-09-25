package store

import (
	"path/filepath"
	"testing"
	"time"
)

func tempStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCredentialRoundTrip(t *testing.T) {
	s := tempStore(t)
	c := &Credential{Handle: "cred://github.com/joan", Type: "login", Site: "github.com", Label: "joan", Metadata: `{"user":"joan"}`, Ciphertext: []byte("ct")}
	if err := s.AddCredential(c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCredential(c.Handle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Site != "github.com" || string(got.Ciphertext) != "ct" {
		t.Fatalf("bad round trip: %+v", got)
	}
	all, err := s.ListCredentials()
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %v %d", err, len(all))
	}
	if string(all[0].Ciphertext) != "" {
		t.Fatal("list must not return ciphertext")
	}
	if _, err := s.GetCredential("cred://no/x"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.AddCredential(c); err == nil {
		t.Fatal("want unique constraint error")
	}
}

func TestAgentAndGrant(t *testing.T) {
	s := tempStore(t)
	a, err := s.CreateAgent("bot", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAgentByTokenHash("deadbeef")
	if err != nil || got.Name != "bot" {
		t.Fatal(err, got)
	}
	g := &Grant{ID: "g1", AgentID: a.ID, Handle: "cred://x/y", Policy: "{}", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 3}
	if err := s.AddGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := s.IncrementGrantUses("g1"); err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetGrant("g1")
	if err != nil || got2.Uses != 1 {
		t.Fatal(err, got2)
	}
}

func TestAuditAndMeta(t *testing.T) {
	s := tempStore(t)
	if err := s.AppendAudit(&AuditEntry{AgentID: 1, Handle: "h", Edge: "browser", Target: "t", Decision: "allow", Detail: "{}", PrevHash: "", Hash: "abc"}); err != nil {
		t.Fatal(err)
	}
	last, err := s.LastAudit()
	if err != nil || last.Hash != "abc" {
		t.Fatal(err, last)
	}
	if err := s.SetMeta("k", "v"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Meta("k")
	if err != nil || v != "v" {
		t.Fatal(err, v)
	}
	if _, err := s.Meta("missing"); err != ErrNotFound {
		t.Fatal(err)
	}
}
