package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Subjects of an access rule.
const (
	SubjectGroup         = "group"
	SubjectUser          = "user"
	SubjectAuthenticated = "authenticated"
)

// AccessRule grants permissions to SSO accounts before they sign in: to the
// members of a group, to one username or to any authenticated user.
type AccessRule struct {
	ID                     string
	SubjectType            string
	Subject                string
	Role                   string
	AllNamespaces          bool
	AllowNetcheckNamespace bool
	Namespaces             []string
	CreatedAt              time.Time
	UpdatedAt              time.Time
	UpdatedBy              string
}

func jsonList(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

const ruleColumns = `id, subject_type, subject, role, all_namespaces, allow_netcheck_namespace, namespaces, created_at, updated_at, updated_by`

func scanRule(sc interface{ Scan(...any) error }) (AccessRule, error) {
	var r AccessRule
	var all, own int
	var ns, created, updated string
	if err := sc.Scan(&r.ID, &r.SubjectType, &r.Subject, &r.Role, &all, &own, &ns, &created, &updated, &r.UpdatedBy); err != nil {
		return AccessRule{}, err
	}
	r.AllNamespaces, r.AllowNetcheckNamespace = all == 1, own == 1
	r.Namespaces = []string{}
	_ = json.Unmarshal([]byte(ns), &r.Namespaces)
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		r.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		r.UpdatedAt = *t
	}
	return r, nil
}

// ListAccessRules returns every rule, groups first, then users, then the
// "any authenticated user" rule.
func (s *Store) ListAccessRules(ctx context.Context) ([]AccessRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ruleColumns+` FROM access_rules
		ORDER BY CASE subject_type WHEN 'group' THEN 0 WHEN 'user' THEN 1 ELSE 2 END, subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAccessRule returns one rule.
func (s *Store) GetAccessRule(ctx context.Context, id string) (AccessRule, error) {
	r, err := scanRule(s.db.QueryRowContext(ctx, `SELECT `+ruleColumns+` FROM access_rules WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return AccessRule{}, ErrNotFound
	}
	return r, err
}

// SaveAccessRule inserts or replaces a rule with an audit event.
func (s *Store) SaveAccessRule(ctx context.Context, r AccessRule, ev AuditEvent) error {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO access_rules (`+ruleColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT (id) DO UPDATE SET subject_type = excluded.subject_type, subject = excluded.subject, role = excluded.role,
			all_namespaces = excluded.all_namespaces, allow_netcheck_namespace = excluded.allow_netcheck_namespace,
			namespaces = excluded.namespaces, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			r.ID, r.SubjectType, r.Subject, r.Role, b2i(r.AllNamespaces), b2i(r.AllowNetcheckNamespace), jsonList(r.Namespaces),
			ts(r.CreatedAt), ts(r.UpdatedAt), r.UpdatedBy)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteAccessRule removes a rule with an audit event.
func (s *Store) DeleteAccessRule(ctx context.Context, id string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM access_rules WHERE id = ?`, id)
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

// SyncSSOUser stores the permissions computed from the access rules, the
// profile and groups of an SSO account. Without access (no matching rule)
// its sessions and API tokens are deleted.
func (s *Store) SyncSSOUser(ctx context.Context, u User, access bool, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ?, role = ?, all_namespaces = ?, allow_netcheck_namespace = ?,
			external_groups = ?, updated_at = ? WHERE id = ? AND source = 'oidc'`,
			u.DisplayName, u.Role, b2i(u.AllNamespaces), b2i(u.AllowNetcheckNamespace), jsonList(u.ExternalGroups), ts(now), u.ID); err != nil {
			return err
		}
		if err := writeNamespaces(ctx, tx, u.ID, u.Namespaces); err != nil {
			return err
		}
		if !access {
			for _, q := range []string{`DELETE FROM sessions WHERE user_id = ?`, `DELETE FROM api_tokens WHERE user_id = ?`} {
				if _, err := tx.ExecContext(ctx, q, u.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
