-- UI language per user (default English) and explicit permission to run
-- probes from the namespace where NetCheck itself is installed.
ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'en';
ALTER TABLE users ADD COLUMN allow_netcheck_namespace INTEGER NOT NULL DEFAULT 0;

-- Public session id (for the admin "active sessions" view) and minimal
-- context. The token itself is never stored.
ALTER TABLE sessions ADD COLUMN id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_sessions_id ON sessions (id);

-- Versions of NetCheck that have run against this database.
CREATE TABLE app_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         TEXT NOT NULL,
    commit_sha      TEXT NOT NULL DEFAULT '',
    build_date      TEXT NOT NULL DEFAULT '',
    image           TEXT NOT NULL DEFAULT '',
    probe_image     TEXT NOT NULL DEFAULT '',
    chart_version   TEXT NOT NULL DEFAULT '',
    first_seen_at   TEXT NOT NULL,
    last_started_at TEXT NOT NULL,
    starts          INTEGER NOT NULL DEFAULT 1
);
