-- HTTP proxies TCP and HTTPS checks may go through (CONNECT), edited by
-- administrators in the web UI. A single row with a JSON list; seeded from
-- the Helm values on the first start.
CREATE TABLE proxies (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    proxies_json TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    updated_by   TEXT NOT NULL
);
