package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// StoredTrustedCAs are the certificate authorities saved by administrators
// (JSON list of PEM certificates).
type StoredTrustedCAs struct {
	CertificatesJSON string
	UpdatedAt        time.Time
	UpdatedBy        string
}

// GetTrustedCAs returns the stored authorities or ErrNotFound.
func (s *Store) GetTrustedCAs(ctx context.Context) (StoredTrustedCAs, error) {
	var c StoredTrustedCAs
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT certificates_json, updated_at, updated_by FROM trusted_cas WHERE id = 1`).
		Scan(&c.CertificatesJSON, &updated, &c.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredTrustedCAs{}, ErrNotFound
	}
	if err != nil {
		return StoredTrustedCAs{}, err
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		c.UpdatedAt = *t
	}
	return c, nil
}

// SaveTrustedCAs replaces the stored authorities and records the audit event
// atomically.
func (s *Store) SaveTrustedCAs(ctx context.Context, c StoredTrustedCAs, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO trusted_cas (id, certificates_json, updated_at, updated_by) VALUES (1, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET certificates_json = excluded.certificates_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			c.CertificatesJSON, ts(c.UpdatedAt), c.UpdatedBy); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
