CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name         TEXT NOT NULL DEFAULT '',
    role                 TEXT NOT NULL CHECK (role IN ('admin','user')),
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    disabled             INTEGER NOT NULL DEFAULT 0,
    all_namespaces       INTEGER NOT NULL DEFAULT 0,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    last_login_at        TEXT,
    password_changed_at  TEXT NOT NULL
);

CREATE TABLE user_namespaces (
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    namespace TEXT NOT NULL,
    PRIMARY KEY (user_id, namespace)
);

-- Only the SHA-256 of the session token is stored.
CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);
