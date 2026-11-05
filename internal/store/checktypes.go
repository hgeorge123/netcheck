package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// StoredCheckTypes are the check types disabled by administrators (JSON list
// of names).
type StoredCheckTypes struct {
	DisabledJSON string
	UpdatedAt    time.Time
	UpdatedBy    string
}

// GetCheckTypes returns the stored setting or ErrNotFound.
func (s *Store) GetCheckTypes(ctx context.Context) (StoredCheckTypes, error) {
	var c StoredCheckTypes
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT disabled_json, updated_at, updated_by FROM check_types WHERE id = 1`).
		Scan(&c.DisabledJSON, &updated, &c.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredCheckTypes{}, ErrNotFound
	}
	if err != nil {
		return StoredCheckTypes{}, err
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		c.UpdatedAt = *t
	}
	return c, nil
}

// SaveCheckTypes replaces the setting and records the audit event atomically.
func (s *Store) SaveCheckTypes(ctx context.Context, c StoredCheckTypes, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO check_types (id, disabled_json, updated_at, updated_by) VALUES (1, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET disabled_json = excluded.disabled_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			c.DisabledJSON, ts(c.UpdatedAt), c.UpdatedBy); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
