-- Data retention edited by administrators in the web UI. A single row;
-- seeded from the Helm values (retention.*) on the first start.
CREATE TABLE retention_settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    output_days   INTEGER NOT NULL,
    metadata_days INTEGER NOT NULL,
    updated_at    TEXT NOT NULL,
    updated_by    TEXT NOT NULL
);
