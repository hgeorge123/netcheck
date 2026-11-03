-- Proxies become one row each: administrators' proxies (owner_id NULL),
-- shared with everyone or kept for administrators, and personal proxies that
-- only their owner sees and uses (deleted with the account). Each proxy may
-- carry the certificate authorities trusted for checks through it (JSON
-- list of PEM). The proxies of the single-row list become shared
-- administrators' proxies, so users keep seeing them.
CREATE TABLE http_proxies (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT REFERENCES users (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    shared     INTEGER NOT NULL DEFAULT 0,
    cas_json   TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_http_proxies_name ON http_proxies (COALESCE(owner_id, ''), name);
CREATE INDEX idx_http_proxies_owner ON http_proxies (owner_id);

-- The Helm values seed the administrators' proxies once; this row records it.
CREATE TABLE proxy_seed (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    seeded_at TEXT NOT NULL
);

INSERT INTO http_proxies (id, owner_id, name, host, port, shared, cas_json, created_at, updated_at, updated_by)
SELECT 'p' || lower(hex(randomblob(12))), NULL, json_extract(j.value, '$.name'), json_extract(j.value, '$.host'),
       json_extract(j.value, '$.port'), 1, '[]', p.updated_at, p.updated_at, p.updated_by
FROM proxies p, json_each(p.proxies_json) j;
INSERT INTO proxy_seed (id, seeded_at) SELECT 1, updated_at FROM proxies;
DROP TABLE proxies;
