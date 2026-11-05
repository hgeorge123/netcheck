-- Roles (ADR 0005): named sets of permissions. "user" and "admin" are the
-- built-in roles under the ids every existing user and access rule already
-- uses, so no row changes. Custom roles are added by administrators in the
-- web; users.role and access_rules.role hold a role id.
CREATE TABLE roles (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description      TEXT NOT NULL DEFAULT '',
    permissions_json TEXT NOT NULL,
    builtin          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    updated_by       TEXT NOT NULL
);

-- The permissions of the built-in roles live in the code; the rows only make
-- them listable and referenceable.
INSERT INTO roles (id, name, description, permissions_json, builtin, created_at, updated_at, updated_by) VALUES
    ('user', 'User', '', '[]', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system'),
    ('admin', 'Administrator', '', '[]', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');

-- A custom role is stored next to the base role ("user"): the CHECK on
-- users.role and access_rules.role stays as it is (rebuilding those tables
-- would cascade to sessions, tokens and proxies). Empty = the base role.
ALTER TABLE users ADD COLUMN role_id TEXT NOT NULL DEFAULT '';
ALTER TABLE access_rules ADD COLUMN role_id TEXT NOT NULL DEFAULT '';
