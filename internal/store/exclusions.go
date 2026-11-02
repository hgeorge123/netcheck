package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// NamespaceExclusion is a namespace excluded by an administrator in the web.
type NamespaceExclusion struct {
	Name      string
	Reason    string
	CreatedAt time.Time
	CreatedBy string
}

// ErrAlreadyExists is returned when inserting a duplicate key.
var ErrAlreadyExists = errors.New("already exists")

// ListNamespaceExclusions returns the web exclusions sorted by name.
func (s *Store) ListNamespaceExclusions(ctx context.Context) ([]NamespaceExclusion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, reason, created_at, created_by FROM namespace_exclusions ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NamespaceExclusion{}
	for rows.Next() {
		var e NamespaceExclusion
		var created string
		if err := rows.Scan(&e.Name, &e.Reason, &created, &e.CreatedBy); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
			e.CreatedAt = *t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddNamespaceExclusion stores an exclusion and its audit event atomically.
func (s *Store) AddNamespaceExclusion(ctx context.Context, e NamespaceExclusion, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO namespace_exclusions (name, reason, created_at, created_by) VALUES (?,?,?,?)
			ON CONFLICT (name) DO NOTHING`, e.Name, e.Reason, ts(e.CreatedAt), e.CreatedBy)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrAlreadyExists
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// DeleteNamespaceExclusion removes a web exclusion and records the audit event.
func (s *Store) DeleteNamespaceExclusion(ctx context.Context, name string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM namespace_exclusions WHERE name = ?`, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
