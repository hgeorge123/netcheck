package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// StoredProxies are the proxies saved by administrators (JSON list).
type StoredProxies struct {
	ProxiesJSON string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// GetProxies returns the stored proxies or ErrNotFound.
func (s *Store) GetProxies(ctx context.Context) (StoredProxies, error) {
	var p StoredProxies
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT proxies_json, updated_at, updated_by FROM proxies WHERE id = 1`).
		Scan(&p.ProxiesJSON, &updated, &p.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredProxies{}, ErrNotFound
	}
	if err != nil {
		return StoredProxies{}, err
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		p.UpdatedAt = *t
	}
	return p, nil
}

// SaveProxies replaces the stored proxies and records the audit event
// atomically.
func (s *Store) SaveProxies(ctx context.Context, p StoredProxies, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO proxies (id, proxies_json, updated_at, updated_by) VALUES (1, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET proxies_json = excluded.proxies_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			p.ProxiesJSON, ts(p.UpdatedAt), p.UpdatedBy); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
