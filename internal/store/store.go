// Package store defines the persistence interface and a pure-Go SQLite
// implementation for credentials, agents, grants, and the audit log.
package store

import "time"

// Credential is a stored secret. Ciphertext is the envelope-encrypted secret
// payload; plaintext never leaves this process.
type Credential struct {
	ID         int64
	Handle     string
	Type       string // login | api_key | card
	Site       string
	Label      string
	Metadata   string // JSON
	Ciphertext []byte
	CreatedAt  time.Time
}

// Agent is a named agent identity. Only the token hash is persisted.
type Agent struct {
	ID        int64
	Name      string
	TokenHash string
	CreatedAt time.Time
}

// Grant is a stored permission record binding an agent to a handle.
type Grant struct {
	ID        string
	AgentID   int64
	Handle    string
	Policy    string // JSON
	ExpiresAt time.Time
	MaxUses   int
	Uses      int
	CreatedAt time.Time
}

// AuditEntry is one link in the hash-chained audit log.
type AuditEntry struct {
	ID       int64
	TS       time.Time
	AgentID  int64
	Handle   string
	Edge     string
	Target   string
	Decision string
	Detail   string // canonical JSON
	PrevHash string
	Hash     string
}

// Store is the persistence contract.
type Store interface {
	AddCredential(c *Credential) error
	GetCredential(h string) (*Credential, error)
	ListCredentials() ([]Credential, error)

	CreateAgent(name, tokenHash string) (*Agent, error)
	GetAgentByTokenHash(h string) (*Agent, error)

	AddGrant(g *Grant) error
	GetGrant(id string) (*Grant, error)
	IncrementGrantUses(id string) error

	AppendAudit(e *AuditEntry) error
	LastAudit() (*AuditEntry, error)
	ListAudit(limit int) ([]AuditEntry, error)

	Meta(key string) (string, error)
	SetMeta(key, value string) error

	Close() error
}
