package store

import (
	"database/sql"
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

func TestApprovalLifecycle(t *testing.T) {
	s := tempStore(t)
	a, err := s.CreateAgent("bot", "hash")
	if err != nil {
		t.Fatal(err)
	}
	ap := &Approval{ID: "req1", AgentID: a.ID, Handle: "cred://x/y", Purpose: "coffee",
		Policy: `{"hosts":["x.com"]}`, TTL: 5 * time.Minute, MaxUses: 1,
		Status: "pending", ExpiresAt: time.Now().Add(10 * time.Minute)}
	if err := s.CreateApproval(ap); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetApproval("req1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.Purpose != "coffee" || got.TTL != 5*time.Minute || got.AgentID != a.ID {
		t.Fatalf("bad round trip: %+v", got)
	}
	if _, err := s.GetApproval("nope"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	list, err := s.ListApprovals("pending")
	if err != nil || len(list) != 1 {
		t.Fatalf("want 1 pending, got %v %v", list, err)
	}
	if err := s.DecideApproval("req1", "approved", "g1", []byte("ct")); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetApproval("req1")
	if got.Status != "approved" || got.GrantID != "g1" || string(got.TokenCT) != "ct" || got.DecidedAt == nil {
		t.Fatalf("bad decided: %+v", got)
	}
	if err := s.DecideApproval("req1", "denied", "", nil); err != ErrNotFound {
		t.Fatalf("double-decide: want ErrNotFound, got %v", err)
	}
	list, _ = s.ListApprovals("pending")
	if len(list) != 0 {
		t.Fatalf("want 0 pending, got %v", list)
	}
	list, _ = s.ListApprovals("")
	if len(list) != 1 {
		t.Fatalf("want 1 total, got %v", list)
	}
}

func TestGrantRevocation(t *testing.T) {
	s := tempStore(t)
	a, err := s.CreateAgent("bot", "hash")
	if err != nil {
		t.Fatal(err)
	}
	g := &Grant{ID: "g1", AgentID: a.ID, Handle: "cred://x/y", Policy: "{}", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.AddGrant(g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGrant("g1")
	if err != nil || got.RevokedAt != nil {
		t.Fatal(err, got)
	}
	if err := s.RevokeGrant("g1"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetGrant("g1")
	if got.RevokedAt == nil {
		t.Fatal("want revoked_at set")
	}
	if err := s.RevokeGrant("g1"); err != ErrNotFound {
		t.Fatalf("second revoke: want ErrNotFound, got %v", err)
	}
	if err := s.RevokeGrant("nope"); err != ErrNotFound {
		t.Fatalf("unknown revoke: want ErrNotFound, got %v", err)
	}
	grants, err := s.ListGrants()
	if err != nil || len(grants) != 1 || grants[0].RevokedAt == nil {
		t.Fatalf("bad list: %+v %v", grants, err)
	}
	ag, err := s.GetAgent(a.ID)
	if err != nil || ag.Name != "bot" {
		t.Fatal(err, ag)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer s2.Close()
	var version int
	if err := s2.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}
}

func TestMigrationUpgradesPreV3DB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(initSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(capturesSQL); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// user_version is still 0, as a DB created before migration tracking.
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	defer s.Close()
	a, err := s.CreateAgent("bot", "hash")
	if err != nil {
		t.Fatal(err)
	}
	g := &Grant{ID: "g1", AgentID: a.ID, Handle: "cred://x/y", Policy: "{}", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.AddGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeGrant("g1"); err != nil {
		t.Fatalf("revoked_at column missing: %v", err)
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}
}

func TestMigrationToleratesPreAppliedV3(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buggy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a DB written by the buggy build: every migration ran,
	// user_version stayed 0.
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open buggy-written db: %v", err)
	}
	defer s.Close()
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}
}
