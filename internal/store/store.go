// Package store persists runs, probe executions and audit events in SQLite
// (modernc.org/sqlite, no CGO) with versioned, transactional migrations.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// TimeLayout is fixed width so lexicographic order equals time order.
const TimeLayout = "2006-01-02T15:04:05.000000Z"

// Run statuses.
const (
	RunQueued     = "queued"
	RunRunning    = "running"
	RunSucceeded  = "succeeded"
	RunFailed     = "failed"
	RunCancelled  = "cancelled"
	RunInfraError = "infra_error"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Run is a persisted batch.
type Run struct {
	ID                 string
	CreatedAt          time.Time
	StartedAt          *time.Time
	FinishedAt         *time.Time
	ActorID            string
	ActorDisplay       string
	Namespace          string
	ClusterID          string
	Target             string
	Status             string
	RequestJSON        string
	SpecJSON           string
	SourceWorkloadHint string
	PolicyFidelity     string
	FailureCategory    string
	ErrorMessage       string
	JobName            string
}

// Execution is one probe method execution within a run.
type Execution struct {
	ID              string
	RunID           string
	Seq             int
	CheckID         string
	Method          string
	Status          string
	Category        string
	ArgvJSON        string
	StartedAt       *time.Time
	FinishedAt      *time.Time
	DurationMS      *int64
	ExitCode        *int
	Stdout          string
	Stderr          string
	ResolvedIPsJSON string
	UsedIP          string
	PodIP           string
	NodeName        string
	NodeIP          string
	PodName         string
	JobName         string
	DiagnosisJSON   string
	ResultJSON      string
}

// AuditEvent is an append-only audit record. DetailsJSON must never contain
// secrets, tokens or cookies.
type AuditEvent struct {
	Timestamp   time.Time
	ActorID     string
	Action      string
	Namespace   string
	RunID       string
	Outcome     string
	RequestID   string
	DetailsJSON string
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(ctx context.Context, path string, wal bool) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if wal {
		q.Add("_pragma", "journal_mode(WAL)")
	} else {
		q.Add("_pragma", "journal_mode(DELETE)")
	}
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// A single connection serialises writers; adequate for a single replica
	// MVP and avoids SQLITE_BUSY upgrade deadlocks.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks database availability for readiness probes.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		version, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", e.Name())
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, ts(time.Now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("apply migration %s: %w", e.Name(), err)
		}
	}
	return nil
}

// SchemaVersion returns the highest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func ts(t time.Time) string { return t.UTC().Format(TimeLayout) }

func tsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func parseTS(s sql.NullString) *time.Time {
	if !s.Valid {
		return nil
	}
	t, err := time.Parse(TimeLayout, s.String)
	if err != nil {
		return nil
	}
	return &t
}

const insertAuditSQL = `INSERT INTO audit_events (timestamp, actor_id, action, namespace, run_id, outcome, request_id, details_json) VALUES (?,?,?,?,?,?,?,?)`

func auditArgs(ev AuditEvent) []any {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	if ev.DetailsJSON == "" {
		ev.DetailsJSON = "{}"
	}
	return []any{ts(ev.Timestamp), ev.ActorID, ev.Action, ev.Namespace, ev.RunID, ev.Outcome, ev.RequestID, ev.DetailsJSON}
}

// InsertAudit appends an audit event.
func (s *Store) InsertAudit(ctx context.Context, ev AuditEvent) error {
	_, err := s.db.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
	return err
}

// CreateRun persists a queued run, its queued executions and the audit event
// atomically, before any Kubernetes resource is created.
func (s *Store) CreateRun(ctx context.Context, r Run, execs []Execution, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO runs (id, created_at, actor_id, actor_display, namespace, cluster_id, target, status,
			request_json, spec_json, source_workload_hint, policy_fidelity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, ts(r.CreatedAt), r.ActorID, r.ActorDisplay, r.Namespace, r.ClusterID, r.Target, r.Status,
			r.RequestJSON, r.SpecJSON, r.SourceWorkloadHint, r.PolicyFidelity)
		if err != nil {
			return err
		}
		for _, e := range execs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO probe_executions (id, run_id, seq, check_id, method, status) VALUES (?,?,?,?,?,?)`,
				e.ID, r.ID, e.Seq, e.CheckID, e.Method, e.Status); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// MarkRunning moves a run to running once its Job exists.
func (s *Store) MarkRunning(ctx context.Context, id, jobName, fidelity string, startedAt time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE runs SET status = 'running', job_name = ?, policy_fidelity = ?, started_at = ? WHERE id = ? AND status IN ('queued','running')`,
			jobName, fidelity, ts(startedAt), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, `UPDATE probe_executions SET status = 'running', job_name = ? WHERE run_id = ? AND status = 'queued'`, jobName, id)
		return err
	})
}

// Completion is the final state of a run.
type Completion struct {
	Status          string
	FailureCategory string
	ErrorMessage    string
	FinishedAt      time.Time
	// Executions are matched by CheckID. Executions not listed inherit
	// ExecutionFallbackStatus (e.g. infra_error when the probe never ran).
	Executions              []Execution
	ExecutionFallbackStatus string
	Audit                   []AuditEvent
}

// CompleteRun stores the terminal state of a run in one transaction.
func (s *Store) CompleteRun(ctx context.Context, id string, c Completion) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, failure_category = ?, error_message = ?, finished_at = ? WHERE id = ? AND status IN ('queued','running')`,
			c.Status, c.FailureCategory, c.ErrorMessage, ts(c.FinishedAt), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		for _, e := range c.Executions {
			if e.ArgvJSON == "" {
				e.ArgvJSON = "[]"
			}
			if e.ResolvedIPsJSON == "" {
				e.ResolvedIPsJSON = "[]"
			}
			_, err := tx.ExecContext(ctx, `UPDATE probe_executions SET status = ?, category = ?, argv_json = ?, started_at = ?, finished_at = ?,
				duration_ms = ?, exit_code = ?, stdout = ?, stderr = ?, resolved_ips_json = ?, used_ip = ?, pod_ip = ?, node_name = ?, node_ip = ?, pod_name = ?,
				job_name = ?, diagnosis_json = ?, result_json = ? WHERE run_id = ? AND check_id = ?`,
				e.Status, e.Category, e.ArgvJSON, tsPtr(e.StartedAt), tsPtr(e.FinishedAt), e.DurationMS, e.ExitCode, e.Stdout, e.Stderr,
				e.ResolvedIPsJSON, e.UsedIP, e.PodIP, e.NodeName, e.NodeIP, e.PodName, e.JobName, e.DiagnosisJSON, e.ResultJSON, id, e.CheckID)
			if err != nil {
				return err
			}
		}
		if c.ExecutionFallbackStatus != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE probe_executions SET status = ?, category = ?, finished_at = ? WHERE run_id = ? AND status IN ('queued','running')`,
				c.ExecutionFallbackStatus, c.FailureCategory, ts(c.FinishedAt), id); err != nil {
				return err
			}
		}
		for _, ev := range c.Audit {
			if _, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...); err != nil {
				return err
			}
		}
		return nil
	})
}

const runColumns = `id, created_at, started_at, finished_at, actor_id, actor_display, namespace, cluster_id, target, status,
	request_json, spec_json, source_workload_hint, policy_fidelity, failure_category, error_message, job_name`

func scanRun(sc interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var created string
	var started, finished sql.NullString
	err := sc.Scan(&r.ID, &created, &started, &finished, &r.ActorID, &r.ActorDisplay, &r.Namespace, &r.ClusterID, &r.Target,
		&r.Status, &r.RequestJSON, &r.SpecJSON, &r.SourceWorkloadHint, &r.PolicyFidelity, &r.FailureCategory, &r.ErrorMessage, &r.JobName)
	if err != nil {
		return Run{}, err
	}
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		r.CreatedAt = *t
	}
	r.StartedAt, r.FinishedAt = parseTS(started), parseTS(finished)
	return r, nil
}

// GetRun returns a run and its executions ordered by seq.
func (s *Store) GetRun(ctx context.Context, id string) (Run, []Execution, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, nil, ErrNotFound
	}
	if err != nil {
		return Run{}, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, seq, check_id, method, status, category, argv_json, started_at, finished_at,
		duration_ms, exit_code, stdout, stderr, resolved_ips_json, used_ip, pod_ip, node_name, node_ip, pod_name, job_name, diagnosis_json, result_json
		FROM probe_executions WHERE run_id = ? ORDER BY seq`, id)
	if err != nil {
		return Run{}, nil, err
	}
	defer rows.Close()
	var execs []Execution
	for rows.Next() {
		var e Execution
		var started, finished sql.NullString
		var dur, exit sql.NullInt64
		if err := rows.Scan(&e.ID, &e.RunID, &e.Seq, &e.CheckID, &e.Method, &e.Status, &e.Category, &e.ArgvJSON, &started, &finished,
			&dur, &exit, &e.Stdout, &e.Stderr, &e.ResolvedIPsJSON, &e.UsedIP, &e.PodIP, &e.NodeName, &e.NodeIP, &e.PodName, &e.JobName, &e.DiagnosisJSON, &e.ResultJSON); err != nil {
			return Run{}, nil, err
		}
		e.StartedAt, e.FinishedAt = parseTS(started), parseTS(finished)
		if dur.Valid {
			e.DurationMS = &dur.Int64
		}
		if exit.Valid {
			v := int(exit.Int64)
			e.ExitCode = &v
		}
		execs = append(execs, e)
	}
	return r, execs, rows.Err()
}

// ListFilter selects runs. The authorization filter is applied in SQL, never
// only in the UI: either AllNamespaces or a non-empty AllowedNamespaces list,
// and ActorID (when set) keeps only the runs that user started.
type ListFilter struct {
	AllNamespaces     bool
	AllowedNamespaces []string
	ActorID           string
	Namespace         string
	Status            string
	From, To          *time.Time
	PageSize          int
	Cursor            string
}

// ErrInvalidCursor is returned for malformed cursors.
var ErrInvalidCursor = errors.New("invalid cursor")

func encodeCursor(r Run) string {
	return base64.RawURLEncoding.EncodeToString([]byte(ts(r.CreatedAt) + "|" + r.ID))
}

func decodeCursor(c string) (string, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", "", ErrInvalidCursor
	}
	created, id, ok := strings.Cut(string(b), "|")
	if !ok || len(created) != len(TimeLayout) || id == "" {
		return "", "", ErrInvalidCursor
	}
	if _, err := time.Parse(TimeLayout, created); err != nil {
		return "", "", ErrInvalidCursor
	}
	return created, id, nil
}

// ListRuns returns a page of runs, newest first, and the next cursor.
func (s *Store) ListRuns(ctx context.Context, f ListFilter) ([]Run, string, error) {
	if len(f.AllowedNamespaces) == 0 && !f.AllNamespaces {
		return nil, "", nil
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := []string{"1 = 1"}
	var args []any
	if !f.AllNamespaces {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(f.AllowedNamespaces)), ",")
		where = append(where, "namespace IN ("+placeholders+")")
		for _, n := range f.AllowedNamespaces {
			args = append(args, n)
		}
	}
	if f.ActorID != "" {
		where, args = append(where, "actor_id = ?"), append(args, f.ActorID)
	}
	if f.Namespace != "" {
		where, args = append(where, "namespace = ?"), append(args, f.Namespace)
	}
	if f.Status != "" {
		where, args = append(where, "status = ?"), append(args, f.Status)
	}
	if f.From != nil {
		where, args = append(where, "created_at >= ?"), append(args, ts(*f.From))
	}
	if f.To != nil {
		where, args = append(where, "created_at < ?"), append(args, ts(*f.To))
	}
	if f.Cursor != "" {
		created, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		where = append(where, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, created, created, id)
	}
	args = append(args, f.PageSize+1)
	rows, err := s.db.QueryContext(ctx, `SELECT `+runColumns+` FROM runs WHERE `+strings.Join(where, " AND ")+
		` ORDER BY created_at DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > f.PageSize {
		out = out[:f.PageSize]
		next = encodeCursor(out[len(out)-1])
	}
	return out, next, nil
}

// ListActiveRuns returns runs that were queued or running, for recovery.
func (s *Store) ListActiveRuns(ctx context.Context) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+runColumns+` FROM runs WHERE status IN ('queued','running') ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAudit returns the audit events of a run in insertion order.
func (s *Store) ListAudit(ctx context.Context, runID string) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT timestamp, actor_id, action, namespace, run_id, outcome, request_id, details_json
		FROM audit_events WHERE run_id = ? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var t string
		if err := rows.Scan(&t, &ev.ActorID, &ev.Action, &ev.Namespace, &ev.RunID, &ev.Outcome, &ev.RequestID, &ev.DetailsJSON); err != nil {
			return nil, err
		}
		if p := parseTS(sql.NullString{String: t, Valid: true}); p != nil {
			ev.Timestamp = *p
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// RunStatus returns only the status of a run.
func (s *Store) RunStatus(ctx context.Context, id string) (string, error) {
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM runs WHERE id = ?`, id).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return st, err
}

// Purge applies retention: outputs of executions older than outputsBefore are
// blanked, and runs (cascading executions) and audit events older than
// metadataBefore are deleted. Active runs are never purged.
func (s *Store) Purge(ctx context.Context, outputsBefore, metadataBefore time.Time) (blanked, deleted int64, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE probe_executions SET stdout = '', stderr = ''
			WHERE (stdout != '' OR stderr != '') AND run_id IN
			(SELECT id FROM runs WHERE created_at < ? AND status NOT IN ('queued','running'))`, ts(outputsBefore))
		if err != nil {
			return err
		}
		blanked, _ = res.RowsAffected()
		res, err = tx.ExecContext(ctx, `DELETE FROM runs WHERE created_at < ? AND status NOT IN ('queued','running')`, ts(metadataBefore))
		if err != nil {
			return err
		}
		deleted, _ = res.RowsAffected()
		_, err = tx.ExecContext(ctx, `DELETE FROM audit_events WHERE timestamp < ?`, ts(metadataBefore))
		return err
	})
	return blanked, deleted, err
}
