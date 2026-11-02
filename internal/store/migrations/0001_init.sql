CREATE TABLE runs (
    id                   TEXT PRIMARY KEY,
    created_at           TEXT NOT NULL,
    started_at           TEXT,
    finished_at          TEXT,
    actor_id             TEXT NOT NULL,
    actor_display        TEXT NOT NULL DEFAULT '',
    namespace            TEXT NOT NULL,
    cluster_id           TEXT NOT NULL,
    target               TEXT NOT NULL,
    status               TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed','cancelled','infra_error')),
    request_json         TEXT NOT NULL,
    spec_json            TEXT NOT NULL,
    source_workload_hint TEXT NOT NULL DEFAULT '',
    policy_fidelity      TEXT NOT NULL DEFAULT '',
    failure_category     TEXT NOT NULL DEFAULT '',
    error_message        TEXT NOT NULL DEFAULT '',
    job_name             TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_runs_created ON runs (created_at DESC, id DESC);
CREATE INDEX idx_runs_namespace_created ON runs (namespace, created_at DESC, id DESC);
CREATE INDEX idx_runs_status ON runs (status);

CREATE TABLE probe_executions (
    id                TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    seq               INTEGER NOT NULL,
    check_id          TEXT NOT NULL,
    method            TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed','timed_out','cancelled','infra_error')),
    category          TEXT NOT NULL DEFAULT '',
    argv_json         TEXT NOT NULL DEFAULT '[]',
    started_at        TEXT,
    finished_at       TEXT,
    duration_ms       INTEGER,
    exit_code         INTEGER,
    stdout            TEXT NOT NULL DEFAULT '',
    stderr            TEXT NOT NULL DEFAULT '',
    resolved_ips_json TEXT NOT NULL DEFAULT '[]',
    used_ip           TEXT NOT NULL DEFAULT '',
    pod_ip            TEXT NOT NULL DEFAULT '',
    node_name         TEXT NOT NULL DEFAULT '',
    job_name          TEXT NOT NULL DEFAULT '',
    diagnosis_json    TEXT NOT NULL DEFAULT '',
    result_json       TEXT NOT NULL DEFAULT '',
    UNIQUE (run_id, check_id)
);

CREATE INDEX idx_exec_run ON probe_executions (run_id, seq);

CREATE TABLE audit_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    actor_id     TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    namespace    TEXT NOT NULL DEFAULT '',
    run_id       TEXT NOT NULL DEFAULT '',
    outcome      TEXT NOT NULL,
    request_id   TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_timestamp ON audit_events (timestamp);
