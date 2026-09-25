package store

import (
	"database/sql"
	"errors"
	"fmt"
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
	for i, m := range migrations {
		if _, err := db.Exec(m); err != nil {
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

func (s *SQLite) AddGrant(g *Grant) error {
	_, err := s.db.Exec(
		`INSERT INTO grants (id, agent_id, handle, policy_json, expires_at, max_uses) VALUES (?,?,?,?,?,?)`,
		g.ID, g.AgentID, g.Handle, g.Policy, g.ExpiresAt.UTC(), g.MaxUses)
	return err
}

func (s *SQLite) GetGrant(id string) (*Grant, error) {
	g := &Grant{}
	err := s.db.QueryRow(
		`SELECT id, agent_id, handle, policy_json, expires_at, max_uses, uses, created_at FROM grants WHERE id = ?`, id).
		Scan(&g.ID, &g.AgentID, &g.Handle, &g.Policy, &g.ExpiresAt, &g.MaxUses, &g.Uses, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return g, err
}

func (s *SQLite) IncrementGrantUses(id string) error {
	_, err := s.db.Exec(`UPDATE grants SET uses = uses + 1 WHERE id = ?`, id)
	return err
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
