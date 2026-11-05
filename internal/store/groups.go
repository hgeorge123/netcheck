package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// LocalGroup is a role with its namespaces given to every member.
type LocalGroup struct {
	ID                     string
	Name                   string
	Description            string
	Role                   string
	AllNamespaces          bool
	AllowNetcheckNamespace bool
	Namespaces             []string
	// Members are user ids, sorted.
	Members   []string
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}

// ErrGroupExists is returned when another group has the same name.
var ErrGroupExists = errors.New("a group with that name already exists")

// ErrSelfAdmin is returned when a change would take the administrator role
// away from the person making it.
var ErrSelfAdmin = errors.New("you cannot take away your own administrator role")

// adminCountSQL counts enabled administrators: by their own role or as members
// of a group with the admin role.
const adminCountSQL = `SELECT COUNT(*) FROM users u WHERE u.disabled = 0 AND (u.role = 'admin' OR EXISTS (
	SELECT 1 FROM local_group_members m JOIN local_groups g ON g.id = m.group_id WHERE m.user_id = u.id AND g.role = 'admin'))`

// noAdminLeft reports, inside a transaction after a change, whether no
// enabled administrator is left.
func noAdminLeft(ctx context.Context, tx *sql.Tx) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, adminCountSQL).Scan(&n)
	return n == 0, err
}

// isAdmin reports, inside a transaction, whether a user is an enabled
// administrator (own role or group).
func isAdmin(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, adminCountSQL+` AND u.id = ?`, userID).Scan(&n)
	return n > 0, err
}

// checkAdmins fails a change that leaves no administrator or takes the role
// away from the actor (empty actor: not checked).
func checkAdmins(ctx context.Context, tx *sql.Tx, actorID string) error {
	if none, err := noAdminLeft(ctx, tx); err != nil {
		return err
	} else if none {
		return ErrLastAdmin
	}
	if actorID != "" {
		if ok, err := isAdmin(ctx, tx, actorID); err != nil {
			return err
		} else if !ok {
			return ErrSelfAdmin
		}
	}
	return nil
}

const groupColumns = `id, name, description, role, all_namespaces, allow_netcheck_namespace, namespaces, created_at, updated_at, updated_by`

func scanGroup(sc interface{ Scan(...any) error }) (LocalGroup, error) {
	var g LocalGroup
	var all, own int
	var ns, created, updated string
	if err := sc.Scan(&g.ID, &g.Name, &g.Description, &g.Role, &all, &own, &ns, &created, &updated, &g.UpdatedBy); err != nil {
		return LocalGroup{}, err
	}
	g.AllNamespaces, g.AllowNetcheckNamespace = all == 1, own == 1
	g.Namespaces, g.Members = []string{}, []string{}
	_ = json.Unmarshal([]byte(ns), &g.Namespaces)
	for dst, s := range map[*time.Time]string{&g.CreatedAt: created, &g.UpdatedAt: updated} {
		if t := parseTS(sql.NullString{String: s, Valid: true}); t != nil {
			*dst = *t
		}
	}
	return g, nil
}

// ListGroups returns every group with its members, by name.
func (s *Store) ListGroups(ctx context.Context) ([]LocalGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+groupColumns+` FROM local_groups ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	out := []LocalGroup{}
	idx := map[string]int{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		idx[g.ID] = len(out)
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mrows, err := s.db.QueryContext(ctx, `SELECT group_id, user_id FROM local_group_members ORDER BY user_id`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var gid, uid string
		if err := mrows.Scan(&gid, &uid); err != nil {
			return nil, err
		}
		if i, ok := idx[gid]; ok {
			out[i].Members = append(out[i].Members, uid)
		}
	}
	return out, mrows.Err()
}

// GetGroup returns one group with its members, or ErrNotFound.
func (s *Store) GetGroup(ctx context.Context, id string) (LocalGroup, error) {
	all, err := s.ListGroups(ctx)
	if err != nil {
		return LocalGroup{}, err
	}
	for _, g := range all {
		if g.ID == id {
			return g, nil
		}
	}
	return LocalGroup{}, ErrNotFound
}

// SaveGroup creates or replaces a group and its members. It fails with
// ErrLastAdmin or ErrSelfAdmin when the change would leave no administrator
// or take the role away from actorID.
func (s *Store) SaveGroup(ctx context.Context, g LocalGroup, actorID string, ev AuditEvent) error {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO local_groups (`+groupColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT (id) DO UPDATE SET name = excluded.name, description = excluded.description, role = excluded.role,
			all_namespaces = excluded.all_namespaces, allow_netcheck_namespace = excluded.allow_netcheck_namespace,
			namespaces = excluded.namespaces, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			g.ID, g.Name, g.Description, g.Role, b2i(g.AllNamespaces), b2i(g.AllowNetcheckNamespace), jsonList(g.Namespaces),
			ts(g.CreatedAt), ts(g.UpdatedAt), g.UpdatedBy); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM local_group_members WHERE group_id = ?`, g.ID); err != nil {
			return err
		}
		for _, uid := range g.Members {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO local_group_members (group_id, user_id) VALUES (?, ?)`, g.ID, uid); err != nil {
				return err
			}
		}
		if err := checkAdmins(ctx, tx, actorID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrGroupExists
	}
	return err
}

// DeleteGroup deletes a group (its memberships cascade), with the same
// administrator checks as SaveGroup.
func (s *Store) DeleteGroup(ctx context.Context, id, actorID string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM local_groups WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if err := checkAdmins(ctx, tx, actorID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}
