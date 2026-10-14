CREATE TABLE IF NOT EXISTS issued_cards (
    id         TEXT PRIMARY KEY,
    grant_id   TEXT UNIQUE NOT NULL,
    handle     TEXT NOT NULL,
    driver     TEXT NOT NULL,
    card_id    TEXT NOT NULL,
    brand      TEXT,
    last4      TEXT,
    exp_month  TEXT,
    exp_year   TEXT,
    status     TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at  TIMESTAMP NULL
);
