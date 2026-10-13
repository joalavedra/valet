CREATE TABLE IF NOT EXISTS passkeys (
    id              TEXT PRIMARY KEY, -- base64url credential id
    name            TEXT NOT NULL DEFAULT '',
    credential_json TEXT NOT NULL,    -- webauthn.Credential (public key, sign count)
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    TIMESTAMP NULL
);
