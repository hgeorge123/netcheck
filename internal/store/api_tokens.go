package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// APIToken is a token for pipelines and the CLI. The secret itself is never
// stored, only its SHA-256.
type APIToken struct {
	ID         string
	UserID     string
	Username   string // owner, filled by the list queries
	Name       string
	TokenHash  string
	Prefix     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt *time.Time
}

const tokenColumns = `t.id, t.user_id, u.username, t.name, t.token_hash, t.prefix, t.created_at, t.expires_at, t.last_used_at`

func scanToken(sc interface{ Scan(...any) error }) (APIToken, error) {
	var tk APIToken
	var created, expires string
	var used sql.NullString
	if err := sc.Scan(&tk.ID, &tk.UserID, &tk.Username, &tk.Name, &tk.TokenHash, &tk.Prefix, &created, &expires, &used); err != nil {
		return APIToken{}, err
	}
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		tk.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: expires, Valid: true}); t != nil {
		tk.ExpiresAt = *t
	}
	tk.LastUsedAt = parseTS(used)
	return tk, nil
}

// CreateAPIToken stores a token with an audit event.
func (s *Store) CreateAPIToken(ctx context.Context, tk APIToken, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, created_at, expires_at)
			VALUES (?,?,?,?,?,?,?)`, tk.ID, tk.UserID, tk.Name, tk.TokenHash, tk.Prefix, ts(tk.CreatedAt), ts(tk.ExpiresAt)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertAuditSQL, auditArgs(ev)...)
		return err
	})
}

// GetAPITokenByHash returns the token with that hash.
func (s *Store) GetAPITokenByHash(ctx context.Context, hash string) (APIToken, error) {
	tk, err := scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, ErrNotFound
	}
	return tk, err
}

// ListAPITokens returns the tokens of a user, or of everybody when userID is
// empty, newest first.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	q := `SELECT ` + tokenColumns + ` FROM api_tokens t JOIN users u ON u.id = t.user_id`
	args := []any{}
	if userID != "" {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY t.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		tk, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tk)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token. With userID set, only a token of that user.
func (s *Store) DeleteAPIToken(ctx context.Context, id, userID string, ev AuditEvent) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		q, args := `DELETE FROM api_tokens WHERE id = ?`, []any{id}
		if userID != "" {
			q += ` AND user_id = ?`
			args = append(args, userID)
		}
		res, err := tx.ExecContext(ctx, q, args...)
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

// TouchAPIToken records the last use of a token.
func (s *Store) TouchAPIToken(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, ts(now), id)
	return err
}

// PurgeAPITokens deletes expired tokens.
func (s *Store) PurgeAPITokens(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE expires_at < ?`, ts(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
