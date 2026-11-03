package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ErrProxyExists is returned when the owner already has a proxy with that name.
var ErrProxyExists = errors.New("a proxy with that name already exists")

// ProxyRecord is a stored proxy. OwnerID is empty for administrators'
// proxies (Shared: every user may use it; otherwise only administrators) and
// set for personal proxies, which only their owner sees and uses.
type ProxyRecord struct {
	ID        string
	OwnerID   string
	Name      string
	Host      string
	Port      int
	Shared    bool
	CAsJSON   string // JSON list of PEM certificates
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}

// NewProxyID returns a random proxy identifier.
func NewProxyID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "p" + hex.EncodeToString(b)
}

const proxyColumns = `id, COALESCE(owner_id, ''), name, host, port, shared, cas_json, created_at, updated_at, updated_by`

func scanProxy(sc interface{ Scan(...any) error }) (ProxyRecord, error) {
	var p ProxyRecord
	var shared int
	var created, updated string
	if err := sc.Scan(&p.ID, &p.OwnerID, &p.Name, &p.Host, &p.Port, &shared, &p.CAsJSON, &created, &updated, &p.UpdatedBy); err != nil {
		return ProxyRecord{}, err
	}
	p.Shared = shared == 1
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		p.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		p.UpdatedAt = *t
	}
	return p, nil
}

// ListProxies returns every stored proxy, administrators' first, by name.
func (s *Store) ListProxies(ctx context.Context) ([]ProxyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+proxyColumns+` FROM http_proxies ORDER BY owner_id IS NOT NULL, owner_id, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyRecord{}
	for rows.Next() {
		p, err := scanProxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountProxies returns how many proxies the owner has ("" for administrators').
func (s *Store) CountProxies(ctx context.Context, ownerID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM http_proxies WHERE COALESCE(owner_id, '') = ?`, ownerID).Scan(&n)
	return n, err
}

func ownerArg(ownerID string) any {
	if ownerID == "" {
		return nil
	}
	return ownerID
}

func proxyWriteErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrProxyExists
	}
	return err
}

// CreateProxy stores a new proxy and records the audit event atomically.
func (s *Store) CreateProxy(ctx context.Context, p ProxyRecord, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO http_proxies (id, owner_id, name, host, port, shared, cas_json, created_at, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, p.ID, ownerArg(p.OwnerID), p.Name, p.Host, p.Port, b2i(p.Shared), p.CAsJSON,
			ts(p.CreatedAt), ts(p.UpdatedAt), p.UpdatedBy); err != nil {
			return proxyWriteErr(err)
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// UpdateProxy replaces a proxy of the same owner (ErrNotFound otherwise:
// nobody can change another owner's proxy).
func (s *Store) UpdateProxy(ctx context.Context, p ProxyRecord, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE http_proxies SET name = ?, host = ?, port = ?, shared = ?, cas_json = ?, updated_at = ?, updated_by = ?
			WHERE id = ? AND COALESCE(owner_id, '') = ?`, p.Name, p.Host, p.Port, b2i(p.Shared), p.CAsJSON, ts(p.UpdatedAt), p.UpdatedBy,
			p.ID, p.OwnerID)
		if err != nil {
			return proxyWriteErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// DeleteProxy deletes a proxy of the owner (ErrNotFound otherwise).
func (s *Store) DeleteProxy(ctx context.Context, id, ownerID string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM http_proxies WHERE id = ? AND COALESCE(owner_id, '') = ?`, id, ownerID)
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

// SeedProxies stores the administrators' proxies of the Helm values, only
// the first time: it reports false when they were seeded before.
func (s *Store) SeedProxies(ctx context.Context, list []ProxyRecord, at time.Time, ev AuditEvent) (bool, error) {
	seeded := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxy_seed`).Scan(&n); err != nil || n > 0 {
			return err
		}
		for _, p := range list {
			if _, err := tx.ExecContext(ctx, `INSERT INTO http_proxies (id, owner_id, name, host, port, shared, cas_json, created_at, updated_at, updated_by)
				VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)`, p.ID, p.Name, p.Host, p.Port, b2i(p.Shared), p.CAsJSON,
				ts(p.CreatedAt), ts(p.UpdatedAt), p.UpdatedBy); err != nil {
				return proxyWriteErr(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO proxy_seed (id, seeded_at) VALUES (1, ?)`, ts(at)); err != nil {
			return err
		}
		seeded = true
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
	return seeded, err
}
