package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Role is a named set of permissions. The built-in roles (RoleUser and
// RoleAdmin) have their permissions in the code; custom roles store theirs.
type Role struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	Builtin     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	UpdatedBy   string
}

var (
	// ErrRoleInUse is returned when deleting a role still given to a user or
	// an access rule.
	ErrRoleInUse = errors.New("the role is still assigned")
	// ErrRoleExists is returned when another role has the same name.
	ErrRoleExists = errors.New("a role with that name already exists")
	// ErrBuiltinRole is returned when changing or deleting a built-in role.
	ErrBuiltinRole = errors.New("built-in roles cannot be changed")
)

// splitRole stores a role id as the users/access_rules columns expect:
// "admin" and "user" go in role; a custom role id goes in role_id with
// "user" as its base role (never admin).
func splitRole(role string) (base, custom string) {
	if role == RoleAdmin || role == RoleUser || role == "" {
		return role, ""
	}
	return RoleUser, role
}

// joinRole is the inverse of splitRole.
func joinRole(base, custom string) string {
	if base == RoleAdmin || custom == "" {
		return base
	}
	return custom
}

const roleColumns = `id, name, description, permissions_json, builtin, created_at, updated_at, updated_by`

func scanRole(sc interface{ Scan(...any) error }) (Role, error) {
	var r Role
	var perms, created, updated string
	var builtin int
	if err := sc.Scan(&r.ID, &r.Name, &r.Description, &perms, &builtin, &created, &updated, &r.UpdatedBy); err != nil {
		return Role{}, err
	}
	r.Builtin = builtin == 1
	r.Permissions = []string{}
	_ = json.Unmarshal([]byte(perms), &r.Permissions)
	for dst, s := range map[*time.Time]string{&r.CreatedAt: created, &r.UpdatedAt: updated} {
		if t := parseTS(sql.NullString{String: s, Valid: true}); t != nil {
			*dst = *t
		}
	}
	return r, nil
}

// ListRoles returns the built-in roles first, then the custom ones by name.
func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+roleColumns+` FROM roles ORDER BY builtin DESC, name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRole returns one role or ErrNotFound.
func (s *Store) GetRole(ctx context.Context, id string) (Role, error) {
	r, err := scanRole(s.db.QueryRowContext(ctx, `SELECT `+roleColumns+` FROM roles WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	return r, err
}

// SaveRole creates or replaces a custom role with an audit event.
func (s *Store) SaveRole(ctx context.Context, r Role, ev AuditEvent) error {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var builtin int
		err := tx.QueryRowContext(ctx, `SELECT builtin FROM roles WHERE id = ?`, r.ID).Scan(&builtin)
		if err == nil && builtin == 1 {
			return ErrBuiltinRole
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		perms, _ := json.Marshal(r.Permissions)
		if _, err := tx.ExecContext(ctx, `INSERT INTO roles (`+roleColumns+`) VALUES (?,?,?,?,0,?,?,?)
			ON CONFLICT (id) DO UPDATE SET name = excluded.name, description = excluded.description,
			permissions_json = excluded.permissions_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			r.ID, r.Name, r.Description, string(perms), ts(r.CreatedAt), ts(r.UpdatedAt), r.UpdatedBy); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrRoleExists
	}
	return err
}

// RoleUsage counts the users, access rules and local groups that give a role.
func (s *Store) RoleUsage(ctx context.Context, id string) (users, rules, groups int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM users WHERE role_id = ?), (SELECT COUNT(*) FROM access_rules WHERE role_id = ?),
		(SELECT COUNT(*) FROM local_groups WHERE role = ?)`, id, id, id).Scan(&users, &rules, &groups)
	return users, rules, groups, err
}

// DeleteRole deletes a custom role nobody holds.
func (s *Store) DeleteRole(ctx context.Context, id string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var builtin int
		err := tx.QueryRowContext(ctx, `SELECT builtin FROM roles WHERE id = ?`, id).Scan(&builtin)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if builtin == 1 {
			return ErrBuiltinRole
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM users WHERE role_id = ?) + (SELECT COUNT(*) FROM access_rules WHERE role_id = ?) +
			(SELECT COUNT(*) FROM local_groups WHERE role = ?)`, id, id, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrRoleInUse
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE id = ?`, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
