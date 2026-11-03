-- API tokens for pipelines and the CLI. A token acts as its owner, only on
-- the test endpoints, until it expires. Only the SHA-256 of the token is
-- stored; the prefix (first characters) identifies it in the UI.
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_used_at TEXT
);

CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);
