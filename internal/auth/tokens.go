package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/store"
)

// API tokens let pipelines and the CLI run tests as their owner. They only
// reach the test endpoints (see the API scope), expire, are stored hashed and
// are shown once.

// TokenPrefix marks NetCheck API tokens (and makes leaked ones easy to find).
const TokenPrefix = "nck_"

const (
	maxTokenDays     = 365
	maxTokensPerUser = 20
)

// TokenInput is the payload to create a token.
type TokenInput struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expiresInDays"`
}

func newTokenID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "t" + hex.EncodeToString(b)
}

// CreateToken creates a token for the caller and returns its secret once.
func (l *LocalAuth) CreateToken(ctx context.Context, owner Identity, in TokenInput, requestID string) (string, store.APIToken, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 || strings.ContainsFunc(in.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", store.APIToken{}, InputError{"name", "token_name_invalid", "give the token a name of 1-64 printable characters"}
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > maxTokenDays {
		return "", store.APIToken{}, InputError{"expiresInDays", "token_expiry_invalid", "a token expires after 1 to 365 days"}
	}
	existing, err := l.Store.ListAPITokens(ctx, owner.ID)
	if err != nil {
		return "", store.APIToken{}, err
	}
	if len(existing) >= maxTokensPerUser {
		return "", store.APIToken{}, InputError{"name", "token_limit", "you already have 20 tokens: revoke one first"}
	}
	raw := TokenPrefix + newToken()
	now := l.now()
	tk := store.APIToken{ID: newTokenID(), UserID: owner.ID, Username: owner.Username, Name: in.Name, TokenHash: hashToken(raw),
		Prefix: raw[:len(TokenPrefix)+4], CreatedAt: now, ExpiresAt: now.Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)}
	err = l.Store.CreateAPIToken(ctx, tk, store.AuditEvent{ActorID: owner.ID, Action: "token.create", Outcome: "success", RequestID: requestID,
		DetailsJSON: details(map[string]any{"tokenId": tk.ID, "name": tk.Name, "expiresAt": tk.ExpiresAt})})
	if err != nil {
		return "", store.APIToken{}, err
	}
	return raw, tk, nil
}

// AuthenticateToken returns the owner of a valid token, marked with the
// token id so the API can restrict it to the test endpoints.
func (l *LocalAuth) AuthenticateToken(ctx context.Context, raw string) (Identity, error) {
	if !strings.HasPrefix(raw, TokenPrefix) || len(raw) > 128 {
		return Identity{}, ErrUnauthenticated
	}
	tk, err := l.Store.GetAPITokenByHash(ctx, hashToken(raw))
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	now := l.now()
	if now.After(tk.ExpiresAt) {
		return Identity{}, ErrUnauthenticated
	}
	u, err := l.Store.GetUser(ctx, tk.UserID)
	if err != nil || u.Disabled || u.MustChangePassword {
		return Identity{}, ErrUnauthenticated
	}
	if tk.LastUsedAt == nil || now.Sub(*tk.LastUsedAt) > time.Minute {
		_ = l.Store.TouchAPIToken(ctx, tk.ID, now)
	}
	id := l.withGrants(ctx, identityOf(u, ""), u)
	id.TokenID = tk.ID
	return id, nil
}

// RevokeToken deletes a token: any token for admins (all=true), otherwise
// only one of the caller.
func (l *LocalAuth) RevokeToken(ctx context.Context, actor Identity, id string, all bool, requestID string) error {
	owner := actor.ID
	if all {
		owner = ""
	}
	return l.Store.DeleteAPIToken(ctx, id, owner, store.AuditEvent{ActorID: actor.ID, Action: "token.revoke", Outcome: "success",
		RequestID: requestID, DetailsJSON: details(map[string]any{"tokenId": id})})
}

// ErrTokenScope is returned when a token is used outside the test endpoints.
var ErrTokenScope = errors.New("API tokens can only run and read tests")
