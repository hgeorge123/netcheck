-- Destination policy edited by administrators in the web UI. A single row;
-- seeded from the Helm values on the first start. Platform protections
-- (metadata, API server...) are never stored here: they come from the
-- configuration and are always added on top.
CREATE TABLE destination_policy (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    policy_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    updated_by  TEXT NOT NULL
);
