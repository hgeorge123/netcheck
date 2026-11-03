package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AppVersion is one NetCheck build that has run against this database.
type AppVersion struct {
	ID            int64
	Version       string
	Commit        string
	BuildDate     string
	Image         string
	ProbeImage    string
	ChartVersion  string
	FirstSeenAt   time.Time
	LastStartedAt time.Time
	Starts        int
}

// RecordVersion registers a start of v: the latest row is updated when it
// is the same build, otherwise a new history row is added.
func (s *Store) RecordVersion(ctx context.Context, v AppVersion, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var id int64
		var version, commit, image, probe, chart string
		err := tx.QueryRowContext(ctx, `SELECT id, version, commit_sha, image, probe_image, chart_version FROM app_versions ORDER BY id DESC LIMIT 1`).
			Scan(&id, &version, &commit, &image, &probe, &chart)
		if err == nil && version == v.Version && commit == v.Commit && image == v.Image && probe == v.ProbeImage && chart == v.ChartVersion {
			_, err = tx.ExecContext(ctx, `UPDATE app_versions SET last_started_at = ?, starts = starts + 1 WHERE id = ?`, ts(now), id)
			return err
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO app_versions (version, commit_sha, build_date, image, probe_image, chart_version, first_seen_at, last_started_at)
			VALUES (?,?,?,?,?,?,?,?)`, v.Version, v.Commit, v.BuildDate, v.Image, v.ProbeImage, v.ChartVersion, ts(now), ts(now))
		return err
	})
}

// ListVersions returns the version history, newest first.
func (s *Store) ListVersions(ctx context.Context) ([]AppVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, version, commit_sha, build_date, image, probe_image, chart_version, first_seen_at, last_started_at, starts
		FROM app_versions ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppVersion{}
	for rows.Next() {
		var v AppVersion
		var first, last string
		if err := rows.Scan(&v.ID, &v.Version, &v.Commit, &v.BuildDate, &v.Image, &v.ProbeImage, &v.ChartVersion, &first, &last, &v.Starts); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: first, Valid: true}); t != nil {
			v.FirstSeenAt = *t
		}
		if t := parseTS(sql.NullString{String: last, Valid: true}); t != nil {
			v.LastStartedAt = *t
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RunStats aggregates runs and checks for the dashboard.
type RunStats struct {
	ByStatus       map[string]int            `json:"byStatus"`
	ByMethodStatus map[string]map[string]int `json:"byMethodStatus"`
	Total          int                       `json:"total"`
}

// Stats aggregates runs created since `since`, restricted like ListRuns.
func (s *Store) Stats(ctx context.Context, f ListFilter, since time.Time) (RunStats, error) {
	st := RunStats{ByStatus: map[string]int{}, ByMethodStatus: map[string]map[string]int{}}
	if len(f.AllowedNamespaces) == 0 && !f.AllNamespaces {
		return st, nil
	}
	where, args := "r.created_at >= ?", []any{ts(since)}
	if !f.AllNamespaces {
		where += " AND r.namespace IN (" + placeholders(len(f.AllowedNamespaces)) + ")"
		for _, n := range f.AllowedNamespaces {
			args = append(args, n)
		}
	}
	if f.ActorID != "" {
		where += " AND r.actor_id = ?"
		args = append(args, f.ActorID)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.status, COUNT(*) FROM runs r WHERE `+where+` GROUP BY r.status`, args...)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return st, err
		}
		st.ByStatus[status] = n
		st.Total += n
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT e.method, e.status, COUNT(*) FROM probe_executions e JOIN runs r ON r.id = e.run_id
		WHERE `+where+` GROUP BY e.method, e.status`, args...)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var method, status string
		var n int
		if err := rows.Scan(&method, &status, &n); err != nil {
			return st, err
		}
		if st.ByMethodStatus[method] == nil {
			st.ByMethodStatus[method] = map[string]int{}
		}
		st.ByMethodStatus[method][status] = n
	}
	return st, rows.Err()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}
