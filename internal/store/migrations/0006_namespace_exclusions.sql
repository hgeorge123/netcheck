-- Namespaces excluded by administrators in the web, ON TOP of the Helm
-- exclusions (namespaceScope.exclude) and the system namespaces. The web can
-- only add exclusions; the Helm ones are enforced by admission as well.
CREATE TABLE namespace_exclusions (
    name        TEXT PRIMARY KEY,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL
);
