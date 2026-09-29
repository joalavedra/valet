ALTER TABLE grants ADD COLUMN revoked_at TIMESTAMP NULL;

CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    agent_id    INTEGER NOT NULL REFERENCES agents(id),
    handle      TEXT NOT NULL,
    purpose     TEXT NOT NULL DEFAULT '',
    policy_json TEXT NOT NULL DEFAULT '{}',
    ttl_seconds INTEGER NOT NULL,
    max_uses    INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'pending',
    grant_id    TEXT NULL,
    token_ct    BLOB NULL,
    expires_at  TIMESTAMP NOT NULL,
    decided_at  TIMESTAMP NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
