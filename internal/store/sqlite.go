package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLite implements Store on top of modernc.org/sqlite (pure Go, no cgo).
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (creating if needed) the database at path and runs migrations.
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("user_version: %w", err)
	}
	for i, m := range migrations {
		if i+1 <= version {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("migration %d: %w", i+1, err)
		}
		// A failed migration rolls back together with its version stamp so
		// a partial application is never recorded as complete.
		if _, err := tx.Exec(m); err != nil {
			// A DB written by a build that ran migrations without
			// version tracking may already carry an ALTERed column.
			if !strings.Contains(err.Error(), "duplicate column name") {
				tx.Rollback()
				db.Close()
				return nil, fmt.Errorf("migration %d: %w", i+1, err)
			}
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("user_version: %w", err)
		}
		if err := tx.Commit(); err != nil {
			db.Close()
			return nil, fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return &SQLite{db: db}, nil
}

var ErrNotFound = errors.New("store: not found")

func (s *SQLite) AddCredential(c *Credential) error {
	res, err := s.db.Exec(
		`INSERT INTO credentials (handle, type, site, label, metadata_json, ciphertext) VALUES (?,?,?,?,?,?)`,
		c.Handle, c.Type, c.Site, c.Label, c.Metadata, c.Ciphertext)
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLite) UpsertCredential(c *Credential) error {
	_, err := s.db.Exec(
		`INSERT INTO credentials (handle, type, site, label, metadata_json, ciphertext) VALUES (?,?,?,?,?,?)
		 ON CONFLICT(handle) DO UPDATE SET type=excluded.type, site=excluded.site,
		 label=excluded.label, metadata_json=excluded.metadata_json, ciphertext=excluded.ciphertext`,
		c.Handle, c.Type, c.Site, c.Label, c.Metadata, c.Ciphertext)
	if err != nil {
		return err
	}
	return s.db.QueryRow(`SELECT id FROM credentials WHERE handle = ?`, c.Handle).Scan(&c.ID)
}

func (s *SQLite) DeleteCredential(h string) error {
	res, err := s.db.Exec(`DELETE FROM credentials WHERE handle = ?`, h)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) GetCredential(h string) (*Credential, error) {
	c := &Credential{}
	err := s.db.QueryRow(
		`SELECT id, handle, type, site, label, metadata_json, ciphertext, created_at FROM credentials WHERE handle = ?`, h).
		Scan(&c.ID, &c.Handle, &c.Type, &c.Site, &c.Label, &c.Metadata, &c.Ciphertext, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *SQLite) ListCredentials() ([]Credential, error) {
	rows, err := s.db.Query(`SELECT id, handle, type, site, label, metadata_json, created_at FROM credentials ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Handle, &c.Type, &c.Site, &c.Label, &c.Metadata, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) CreateAgent(name, tokenHash string) (*Agent, error) {
	res, err := s.db.Exec(`INSERT INTO agents (name, token_hash) VALUES (?,?)`, name, tokenHash)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Agent{ID: id, Name: name, TokenHash: tokenHash, CreatedAt: time.Now()}, nil
}

func (s *SQLite) GetAgentByTokenHash(h string) (*Agent, error) {
	a := &Agent{}
	err := s.db.QueryRow(`SELECT id, name, token_hash, created_at FROM agents WHERE token_hash = ?`, h).
		Scan(&a.ID, &a.Name, &a.TokenHash, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *SQLite) GetAgent(id int64) (*Agent, error) {
	a := &Agent{}
	err := s.db.QueryRow(`SELECT id, name, token_hash, created_at FROM agents WHERE id = ?`, id).
		Scan(&a.ID, &a.Name, &a.TokenHash, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *SQLite) AddGrant(g *Grant) error {
	_, err := s.db.Exec(
		`INSERT INTO grants (id, agent_id, handle, policy_json, expires_at, max_uses) VALUES (?,?,?,?,?,?)`,
		g.ID, g.AgentID, g.Handle, g.Policy, g.ExpiresAt.UTC(), g.MaxUses)
	return err
}

func (s *SQLite) scanGrant(row interface{ Scan(...any) error }) (*Grant, error) {
	g := &Grant{}
	var revokedAt sql.NullTime
	err := row.Scan(&g.ID, &g.AgentID, &g.Handle, &g.Policy, &g.ExpiresAt, &g.MaxUses, &g.Uses, &revokedAt, &g.Spent, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		g.RevokedAt = &revokedAt.Time
	}
	return g, nil
}

func (s *SQLite) GetGrant(id string) (*Grant, error) {
	return s.scanGrant(s.db.QueryRow(
		`SELECT id, agent_id, handle, policy_json, expires_at, max_uses, uses, revoked_at, spent, created_at FROM grants WHERE id = ?`, id))
}

func (s *SQLite) ListGrants() ([]Grant, error) {
	rows, err := s.db.Query(
		`SELECT id, agent_id, handle, policy_json, expires_at, max_uses, uses, revoked_at, spent, created_at FROM grants ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		g, err := s.scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (s *SQLite) IncrementGrantUses(id string) error {
	_, err := s.db.Exec(`UPDATE grants SET uses = uses + 1 WHERE id = ?`, id)
	return err
}

// AddGrantSpend atomically accumulates amount into a grant's spent total.
func (s *SQLite) AddGrantSpend(id string, amount int64) error {
	res, err := s.db.Exec(`UPDATE grants SET spent = spent + ? WHERE id = ?`, amount, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeGrant marks a grant revoked once; a second revoke (or unknown id)
// reports ErrNotFound.
func (s *SQLite) RevokeGrant(id string) error {
	res, err := s.db.Exec(`UPDATE grants SET revoked_at=CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeGrantsForHandle marks all unrevoked grants for a handle revoked and
// denies its pending approvals (card replacement must not let old grants
// charge the new credential).
func (s *SQLite) RevokeGrantsForHandle(handle string) (int, error) {
	total := 0
	for _, q := range []string{
		`UPDATE grants SET revoked_at=CURRENT_TIMESTAMP WHERE handle = ? AND revoked_at IS NULL`,
		`UPDATE approvals SET status='denied', decided_at=CURRENT_TIMESTAMP WHERE handle = ? AND status='pending'`,
	} {
		res, err := s.db.Exec(q, handle)
		if err != nil {
			return total, err
		}
		if n, err := res.RowsAffected(); err == nil {
			total += int(n)
		}
	}
	return total, nil
}

func (s *SQLite) CreateApproval(a *Approval) error {
	_, err := s.db.Exec(
		`INSERT INTO approvals (id, agent_id, handle, purpose, policy_json, ttl_seconds, max_uses, status, expires_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		a.ID, a.AgentID, a.Handle, a.Purpose, a.Policy, int64(a.TTL/time.Second), a.MaxUses, a.Status, a.ExpiresAt.UTC())
	return err
}

func (s *SQLite) scanApproval(row interface{ Scan(...any) error }) (*Approval, error) {
	a := &Approval{}
	var grantID sql.NullString
	var tokenCT []byte
	var decidedAt, createdAt sql.NullTime
	var ttl int64
	err := row.Scan(&a.ID, &a.AgentID, &a.Handle, &a.Purpose, &a.Policy, &ttl, &a.MaxUses,
		&a.Status, &grantID, &tokenCT, &a.ExpiresAt, &decidedAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.TTL = time.Duration(ttl) * time.Second
	a.GrantID = grantID.String
	a.TokenCT = tokenCT
	if decidedAt.Valid {
		a.DecidedAt = &decidedAt.Time
	}
	if createdAt.Valid {
		a.CreatedAt = createdAt.Time
	}
	return a, nil
}

const approvalCols = `id, agent_id, handle, purpose, policy_json, ttl_seconds, max_uses, status, grant_id, token_ct, expires_at, decided_at, created_at`

func (s *SQLite) GetApproval(id string) (*Approval, error) {
	return s.scanApproval(s.db.QueryRow(
		`SELECT `+approvalCols+` FROM approvals WHERE id = ?`, id))
}

// ListApprovals returns approvals newest first; empty status lists all.
func (s *SQLite) ListApprovals(status string) ([]Approval, error) {
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = s.db.Query(`SELECT ` + approvalCols + ` FROM approvals ORDER BY created_at DESC`)
	} else {
		rows, err = s.db.Query(`SELECT `+approvalCols+` FROM approvals WHERE status = ? ORDER BY created_at DESC`, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := s.scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// DecideApproval atomically moves a pending approval to status; a second
// decision (or unknown id) reports ErrNotFound.
func (s *SQLite) DecideApproval(id, status, grantID string, tokenCT []byte) error {
	res, err := s.db.Exec(
		`UPDATE approvals SET status=?, grant_id=?, token_ct=?, decided_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'`,
		status, grantID, tokenCT, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) CreateCapture(c *Capture) error {
	_, err := s.db.Exec(
		`INSERT INTO captures (token, label, metadata_json, expires_at) VALUES (?,?,?,?)`,
		c.Token, c.Label, c.Metadata, c.ExpiresAt)
	return err
}

func (s *SQLite) GetCapture(token string) (*Capture, error) {
	c := &Capture{}
	var usedAt sql.NullTime
	err := s.db.QueryRow(
		`SELECT token, label, metadata_json, expires_at, used_at, created_at FROM captures WHERE token=?`,
		token).Scan(&c.Token, &c.Label, &c.Metadata, &c.ExpiresAt, &usedAt, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		c.UsedAt = &usedAt.Time
	}
	return c, nil
}

// MarkCaptureUsed atomically claims the capture; it errors if the token is
// already used so only one submission can ever complete.
func (s *SQLite) MarkCaptureUsed(token string) error {
	res, err := s.db.Exec(
		`UPDATE captures SET used_at=CURRENT_TIMESTAMP WHERE token=? AND used_at IS NULL`,
		token)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("store: capture already used")
	}
	return nil
}

func (s *SQLite) AppendAudit(e *AuditEntry) error {
	_, err := s.db.Exec(
		`INSERT INTO audit (agent_id, handle, edge, target, decision, detail_json, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)`,
		e.AgentID, e.Handle, e.Edge, e.Target, e.Decision, e.Detail, e.PrevHash, e.Hash)
	return err
}

func (s *SQLite) LastAudit() (*AuditEntry, error) {
	e := &AuditEntry{}
	err := s.db.QueryRow(
		`SELECT id, ts, agent_id, handle, edge, target, decision, detail_json, prev_hash, hash FROM audit ORDER BY id DESC LIMIT 1`).
		Scan(&e.ID, &e.TS, &e.AgentID, &e.Handle, &e.Edge, &e.Target, &e.Decision, &e.Detail, &e.PrevHash, &e.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *SQLite) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, agent_id, handle, edge, target, decision, detail_json, prev_hash, hash FROM audit ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.AgentID, &e.Handle, &e.Edge, &e.Target, &e.Decision, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAuditRecent returns the newest entries first; ListAudit stays
// ascending for chain verification.
func (s *SQLite) ListAuditRecent(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, agent_id, handle, edge, target, decision, detail_json, prev_hash, hash FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.AgentID, &e.Handle, &e.Edge, &e.Target, &e.Decision, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLite) Meta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *SQLite) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *SQLite) Close() error { return s.db.Close() }
