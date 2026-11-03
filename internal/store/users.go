package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// User roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	// ErrConflict is returned when a unique constraint (username) is violated.
	ErrConflict = errors.New("conflict")
	// ErrLastAdmin is returned when a change would leave no active admin.
	ErrLastAdmin = errors.New("operation would leave no active admin")
)

// User is a local NetCheck account. PasswordHash is an argon2id PHC string.
type User struct {
	ID                 string
	Username           string
	DisplayName        string
	Role               string
	PasswordHash       string
	MustChangePassword bool
	Disabled           bool
	AllNamespaces      bool
	Namespaces         []string
	FailedAttempts     int
	LockedUntil        *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastLoginAt        *time.Time
	PasswordChangedAt  time.Time
	// Language is the UI language: "en" (default) or "es".
	Language string
	// AllowNetcheckNamespace lets the user run probes from the namespace
	// where NetCheck is installed (hidden for everybody else).
	AllowNetcheckNamespace bool
	// Source is SourceLocal (password) or SourceOIDC (single sign-on).
	Source string
	// ExternalSubject identifies an SSO account at its identity provider.
	ExternalSubject string
	// ExternalGroups are the groups of the last SSO sign-in.
	ExternalGroups []string
}

// Account sources.
const (
	SourceLocal = "local"
	SourceOIDC  = "oidc"
)

// Session is a server-side login session. ID is a public random identifier
// for administration; the token itself is never stored.
type Session struct {
	ID         string
	TokenHash  string
	UserID     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	ClientIP   string
	UserAgent  string
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const userColumns = `id, username, display_name, role, password_hash, must_change_password, disabled, all_namespaces,
	failed_attempts, locked_until, created_at, updated_at, last_login_at, password_changed_at, language, allow_netcheck_namespace,
	source, external_subject, external_groups`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var must, disabled, all, own int
	var locked, lastLogin sql.NullString
	var created, updated, pwChanged, groups string
	var subject sql.NullString
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &must, &disabled, &all,
		&u.FailedAttempts, &locked, &created, &updated, &lastLogin, &pwChanged, &u.Language, &own,
		&u.Source, &subject, &groups); err != nil {
		return User{}, err
	}
	u.ExternalSubject = subject.String
	u.ExternalGroups = []string{}
	_ = json.Unmarshal([]byte(groups), &u.ExternalGroups)
	u.MustChangePassword, u.Disabled, u.AllNamespaces, u.AllowNetcheckNamespace = must == 1, disabled == 1, all == 1, own == 1
	u.LockedUntil, u.LastLoginAt = parseTS(locked), parseTS(lastLogin)
	for dst, s := range map[*time.Time]string{&u.CreatedAt: created, &u.UpdatedAt: updated, &u.PasswordChangedAt: pwChanged} {
		if t := parseTS(sql.NullString{String: s, Valid: true}); t != nil {
			*dst = *t
		}
	}
	return u, nil
}

func loadNamespaces(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, u *User) error {
	rows, err := q.QueryContext(ctx, `SELECT namespace FROM user_namespaces WHERE user_id = ? ORDER BY namespace`, u.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	u.Namespaces = []string{}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return err
		}
		u.Namespaces = append(u.Namespaces, ns)
	}
	return rows.Err()
}

func writeNamespaces(ctx context.Context, tx *sql.Tx, userID string, namespaces []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_namespaces WHERE user_id = ?`, userID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ns := range namespaces {
		if seen[ns] {
			continue
		}
		seen[ns] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_namespaces (user_id, namespace) VALUES (?, ?)`, userID, ns); err != nil {
			return err
		}
	}
	return nil
}

// CreateUser inserts a user, its namespaces and an audit event atomically.
func (s *Store) CreateUser(ctx context.Context, u User, ev AuditEvent) error {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if u.Language == "" {
			u.Language = "en"
		}
		if u.Source == "" {
			u.Source = SourceLocal
		}
		var subject any
		if u.ExternalSubject != "" {
			subject = u.ExternalSubject
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO users (`+userColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			u.ID, u.Username, u.DisplayName, u.Role, u.PasswordHash, b2i(u.MustChangePassword), b2i(u.Disabled), b2i(u.AllNamespaces),
			0, nil, ts(u.CreatedAt), ts(u.UpdatedAt), nil, ts(u.PasswordChangedAt), u.Language, b2i(u.AllowNetcheckNamespace),
			u.Source, subject, jsonList(u.ExternalGroups))
		if err != nil {
			return err
		}
		if err := writeNamespaces(ctx, tx, u.ID, u.Namespaces); err != nil {
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

func (s *Store) getUser(ctx context.Context, where string, arg any) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return u, loadNamespaces(ctx, s.db, &u)
}

// GetUser returns a user by id.
func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return s.getUser(ctx, "id = ?", id)
}

// GetUserByExternalSubject returns the SSO account of an identity provider subject.
func (s *Store) GetUserByExternalSubject(ctx context.Context, subject string) (User, error) {
	return s.getUser(ctx, "external_subject = ?", subject)
}

// GetUserByUsername returns a user by case-insensitive username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.getUser(ctx, "username = ?", username)
}

// ListUsers returns all users sorted by username.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := loadNamespaces(ctx, s.db, &out[i]); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// CountActiveAdmins returns enabled admins.
func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// leavesNoAdmin reports whether removing admin capability from target would
// leave the system without an enabled admin. Runs inside the caller's tx so
// the check and the write are atomic.
func leavesNoAdmin(ctx context.Context, tx *sql.Tx, targetID string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, targetID).Scan(&n)
	return n == 0, err
}

// UpdateUser replaces the mutable profile fields (display name, role,
// disabled, namespaces). Disabling a user deletes its sessions.
func (s *Store) UpdateUser(ctx context.Context, u User, now time.Time, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var curRole string
		var curDisabled int
		err := tx.QueryRowContext(ctx, `SELECT role, disabled FROM users WHERE id = ?`, u.ID).Scan(&curRole, &curDisabled)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		losesAdmin := curRole == RoleAdmin && curDisabled == 0 && (u.Role != RoleAdmin || u.Disabled)
		if losesAdmin {
			if none, err := leavesNoAdmin(ctx, tx, u.ID); err != nil {
				return err
			} else if none {
				return ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ?, role = ?, disabled = ?, all_namespaces = ?, allow_netcheck_namespace = ?, updated_at = ? WHERE id = ?`,
			u.DisplayName, u.Role, b2i(u.Disabled), b2i(u.AllNamespaces), b2i(u.AllowNetcheckNamespace), ts(now), u.ID); err != nil {
			return err
		}
		if err := writeNamespaces(ctx, tx, u.ID, u.Namespaces); err != nil {
			return err
		}
		if u.Disabled {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, u.ID); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// SetPassword stores a new hash, clears lockout and deletes every session of
// the user except keepSessionHash (the caller's own session on self-change).
func (s *Store) SetPassword(ctx context.Context, userID, hash string, mustChange bool, now time.Time, keepSessionHash string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, must_change_password = ?, password_changed_at = ?, updated_at = ?,
			failed_attempts = 0, locked_until = NULL WHERE id = ?`, hash, b2i(mustChange), ts(now), ts(now), userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, userID, keepSessionHash); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// DeleteUser removes a user (sessions and namespace grants cascade). Run
// history keeps the actor display name.
func (s *Store) DeleteUser(ctx context.Context, userID string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var role string
		var disabled int
		err := tx.QueryRowContext(ctx, `SELECT role, disabled FROM users WHERE id = ?`, userID).Scan(&role, &disabled)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if role == RoleAdmin && disabled == 0 {
			if none, err := leavesNoAdmin(ctx, tx, userID); err != nil {
				return err
			} else if none {
				return ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// RecordLoginFailure increments the failure counter and locks the account
// when it reaches maxFailures. It returns the updated counter.
func (s *Store) RecordLoginFailure(ctx context.Context, userID string, maxFailures int, lockUntil time.Time, ev AuditEvent) (int, error) {
	var n int
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ? RETURNING failed_attempts`, userID).Scan(&n); err != nil {
			return err
		}
		if n >= maxFailures {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET locked_until = ?, failed_attempts = 0 WHERE id = ?`, ts(lockUntil), userID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
	return n, err
}

// Unlock clears the lockout of a user.
func (s *Store) Unlock(ctx context.Context, userID string, now time.Time, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET locked_until = NULL, failed_attempts = 0, updated_at = ? WHERE id = ?`, ts(now), userID)
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

// CreateSession records a successful login and its session atomically.
func (s *Store) CreateSession(ctx context.Context, sess Session, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`,
			ts(sess.CreatedAt), sess.UserID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, id, client_ip, user_agent) VALUES (?,?,?,?,?,?,?,?)`,
			sess.TokenHash, sess.UserID, ts(sess.CreatedAt), ts(sess.LastSeenAt), ts(sess.ExpiresAt), sess.ID, sess.ClientIP, sess.UserAgent); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// GetSession returns a session by token hash.
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var created, seen, expires string
	err := s.db.QueryRowContext(ctx, `SELECT token_hash, user_id, created_at, last_seen_at, expires_at, id, client_ip, user_agent FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &created, &seen, &expires, &sess.ID, &sess.ClientIP, &sess.UserAgent)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	for dst, s := range map[*time.Time]string{&sess.CreatedAt: created, &sess.LastSeenAt: seen, &sess.ExpiresAt: expires} {
		if t := parseTS(sql.NullString{String: s, Valid: true}); t != nil {
			*dst = *t
		}
	}
	return sess, nil
}

// TouchSession updates last activity.
func (s *Store) TouchSession(ctx context.Context, tokenHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, ts(now), tokenHash)
	return err
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// SetLanguage stores the UI language preference of a user.
func (s *Store) SetLanguage(ctx context.Context, userID, language string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET language = ?, updated_at = ? WHERE id = ?`, language, ts(now), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ActiveSession is a live session with its owner, for administration.
type ActiveSession struct {
	Session
	Username    string
	DisplayName string
	Role        string
}

// ListActiveSessions returns sessions that are neither expired nor idle,
// most recent activity first.
func (s *Store) ListActiveSessions(ctx context.Context, now time.Time, idle time.Duration) ([]ActiveSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.client_ip, s.user_agent,
		u.username, u.display_name, u.role
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.expires_at >= ? AND s.last_seen_at >= ? AND u.disabled = 0
		ORDER BY s.last_seen_at DESC`, ts(now), ts(now.Add(-idle)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActiveSession{}
	for rows.Next() {
		var a ActiveSession
		var created, seen, expires string
		if err := rows.Scan(&a.ID, &a.UserID, &created, &seen, &expires, &a.ClientIP, &a.UserAgent, &a.Username, &a.DisplayName, &a.Role); err != nil {
			return nil, err
		}
		for dst, v := range map[*time.Time]string{&a.CreatedAt: created, &a.LastSeenAt: seen, &a.ExpiresAt: expires} {
			if t := parseTS(sql.NullString{String: v, Valid: true}); t != nil {
				*dst = *t
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteSessionByID revokes a session by its public id.
func (s *Store) DeleteSessionByID(ctx context.Context, id string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ? AND id != ''`, id)
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

// PurgeSessions deletes sessions expired by absolute or idle timeout.
func (s *Store) PurgeSessions(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?`, ts(now), ts(now.Add(-idle)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
