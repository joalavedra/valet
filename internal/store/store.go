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
	RevokedAt *time.Time
	CreatedAt time.Time
}

// Approval is a pending human decision over a grant request. TokenCT holds
// the issued grant token ciphertext once approved so the agent can claim it.
type Approval struct {
	ID        string
	AgentID   int64
	Handle    string
	Purpose   string
	Policy    string // JSON
	TTL       time.Duration
	MaxUses   int
	Status    string // pending | approved | denied | expired
	GrantID   string
	TokenCT   []byte
	ExpiresAt time.Time
	DecidedAt *time.Time
	CreatedAt time.Time
}

// Capture is a pending browser card-capture session. The token is the only
// auth to the capture page; once completed it's marked used and the card
// fields land in credentials.
type Capture struct {
	Token     string
	Label     string
	Metadata  string // JSON
	ExpiresAt time.Time
	UsedAt    *time.Time
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
	// UpsertCredential inserts or replaces the credential at c.Handle
	// (used by card capture so re-capturing a label refreshes it).
	UpsertCredential(c *Credential) error
	GetCredential(h string) (*Credential, error)
	ListCredentials() ([]Credential, error)
	DeleteCredential(h string) error

	CreateAgent(name, tokenHash string) (*Agent, error)
	GetAgentByTokenHash(h string) (*Agent, error)
	GetAgent(id int64) (*Agent, error)

	AddGrant(g *Grant) error
	GetGrant(id string) (*Grant, error)
	ListGrants() ([]Grant, error)
	IncrementGrantUses(id string) error
	RevokeGrant(id string) error
	// RevokeGrantsForHandle revokes every live grant and denies every
	// pending approval request for the handle; returns rows affected.
	RevokeGrantsForHandle(handle string) (int, error)

	CreateApproval(a *Approval) error
	GetApproval(id string) (*Approval, error)
	ListApprovals(status string) ([]Approval, error)
	DecideApproval(id, status, grantID string, tokenCT []byte) error

	CreateCapture(c *Capture) error
	GetCapture(token string) (*Capture, error)
	MarkCaptureUsed(token string) error

	AppendAudit(e *AuditEntry) error
	LastAudit() (*AuditEntry, error)
	ListAudit(limit int) ([]AuditEntry, error)
	ListAuditRecent(limit int) ([]AuditEntry, error)

	Meta(key string) (string, error)
	SetMeta(key, value string) error

	Close() error
}
