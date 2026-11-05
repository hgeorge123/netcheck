-- Local groups (ADR 0005, phase 3): a role with its namespaces given to
-- every member. Members are accounts (local or SSO); deleting either side
-- removes the membership.
CREATE TABLE local_groups (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description              TEXT NOT NULL DEFAULT '',
    role                     TEXT NOT NULL,
    all_namespaces           INTEGER NOT NULL DEFAULT 0,
    allow_netcheck_namespace INTEGER NOT NULL DEFAULT 0,
    namespaces               TEXT NOT NULL DEFAULT '[]',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    updated_by               TEXT NOT NULL
);

CREATE TABLE local_group_members (
    group_id TEXT NOT NULL REFERENCES local_groups(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX local_group_members_user ON local_group_members(user_id);
