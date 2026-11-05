-- Check types administrators switched off for everybody (Administration >
-- Check types): a single row with a JSON list of names (dns, tcp, udp, http,
-- https, ping, traceroute, and firewall for the firewall ticket mode).
-- Seeded from the Helm values on the first start.
CREATE TABLE check_types (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    disabled_json TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    updated_by    TEXT NOT NULL
);
