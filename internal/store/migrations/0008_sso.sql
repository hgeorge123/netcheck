-- Single sign-on (OIDC). SSO accounts are created at their first sign-in and
-- take their permissions from access rules, which administrators define in
-- advance for a group, a user or any authenticated user.
ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'oidc'));
-- Issuer and subject of the identity provider ("<issuer>#<sub>"), stable even
-- if the e-mail or username changes.
ALTER TABLE users ADD COLUMN external_subject TEXT;
-- Groups of the last SSO sign-in (JSON), so rule changes apply at once.
ALTER TABLE users ADD COLUMN external_groups TEXT NOT NULL DEFAULT '[]';
CREATE UNIQUE INDEX idx_users_external_subject ON users (external_subject) WHERE external_subject IS NOT NULL;

CREATE TABLE access_rules (
    id                       TEXT PRIMARY KEY,
    subject_type             TEXT NOT NULL CHECK (subject_type IN ('group', 'user', 'authenticated')),
    -- Group name or username (lowercase); empty for 'authenticated'.
    subject                  TEXT NOT NULL DEFAULT '',
    role                     TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    all_namespaces           INTEGER NOT NULL DEFAULT 0,
    allow_netcheck_namespace INTEGER NOT NULL DEFAULT 0,
    namespaces               TEXT NOT NULL DEFAULT '[]',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    updated_by               TEXT NOT NULL,
    UNIQUE (subject_type, subject)
);
