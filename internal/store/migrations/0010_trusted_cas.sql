-- Certificate authorities trusted for HTTPS checks on top of the public ones
-- (corporate PKI, TLS inspection proxies), edited by administrators in the
-- web UI. A single row with a JSON list of PEM certificates; seeded from the
-- Helm values on the first start.
CREATE TABLE trusted_cas (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    certificates_json TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    updated_by        TEXT NOT NULL
);
