package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// StoredRetention is the data retention saved by administrators.
type StoredRetention struct {
	OutputDays   int
	MetadataDays int
	UpdatedAt    time.Time
	UpdatedBy    string
}

// GetRetention returns the stored retention or ErrNotFound.
func (s *Store) GetRetention(ctx context.Context) (StoredRetention, error) {
	var r StoredRetention
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT output_days, metadata_days, updated_at, updated_by FROM retention_settings WHERE id = 1`).
		Scan(&r.OutputDays, &r.MetadataDays, &updated, &r.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredRetention{}, ErrNotFound
	}
	if err != nil {
		return StoredRetention{}, err
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		r.UpdatedAt = *t
	}
	return r, nil
}

// SaveRetention replaces the stored retention and records the audit event
// atomically.
func (s *Store) SaveRetention(ctx context.Context, r StoredRetention, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO retention_settings (id, output_days, metadata_days, updated_at, updated_by) VALUES (1, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET output_days = excluded.output_days, metadata_days = excluded.metadata_days,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			r.OutputDays, r.MetadataDays, ts(r.UpdatedAt), r.UpdatedBy); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
