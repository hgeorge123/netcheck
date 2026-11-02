package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// StoredPolicy is the destination policy saved by administrators (JSON of
// probes.DestinationPolicy without platform denies).
type StoredPolicy struct {
	PolicyJSON string
	UpdatedAt  time.Time
	UpdatedBy  string
}

// GetDestinationPolicy returns the stored policy or ErrNotFound.
func (s *Store) GetDestinationPolicy(ctx context.Context) (StoredPolicy, error) {
	var p StoredPolicy
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT policy_json, updated_at, updated_by FROM destination_policy WHERE id = 1`).
		Scan(&p.PolicyJSON, &updated, &p.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredPolicy{}, ErrNotFound
	}
	if err != nil {
		return StoredPolicy{}, err
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		p.UpdatedAt = *t
	}
	return p, nil
}

// SaveDestinationPolicy replaces the stored policy and records the audit
// event atomically.
func (s *Store) SaveDestinationPolicy(ctx context.Context, p StoredPolicy, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO destination_policy (id, policy_json, updated_at, updated_by) VALUES (1, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET policy_json = excluded.policy_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			p.PolicyJSON, ts(p.UpdatedAt), p.UpdatedBy); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
