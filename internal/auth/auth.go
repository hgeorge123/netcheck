// Package auth implements local accounts: password hashing,
// sessions, login throttling, user administration and namespace
// authorization, enforced on every API operation.
package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
)

// Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Identity is the authenticated caller. ID is the stable internal id.
type Identity struct {
	ID                 string   `json:"id"`
	Username           string   `json:"username"`
	Display            string   `json:"display"`
	Role               string   `json:"role"`
	AllNamespaces      bool     `json:"allNamespaces"`
	Namespaces         []string `json:"namespaces"`
	MustChangePassword bool     `json:"mustChangePassword"`
	Language           string   `json:"language"`
	// AllowNetcheckNamespace exposes the NetCheck namespace as a source.
	AllowNetcheckNamespace bool `json:"allowNetcheckNamespace"`
	// Source is "local" (password) or "oidc" (single sign-on).
	Source string `json:"source"`
	// SessionHash identifies the current session (never serialised).
	SessionHash string `json:"-"`
	// TokenID is set when the caller authenticated with an API token.
	TokenID string `json:"-"`
}

// IsAdmin reports whether the identity has the admin role.
func (i Identity) IsAdmin() bool { return i.Role == RoleAdmin }

// ErrUnauthenticated is returned when no valid session is present.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator extracts a trusted identity from a request.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// NamespaceSource lists the namespaces where probes can currently run.
type NamespaceSource interface {
	Available(ctx context.Context) ([]string, error)
}

// NamespaceGrant is a namespace the caller may use.
type NamespaceGrant struct {
	Name   string `json:"name"`
	CanRun bool   `json:"canRun"`
}

// Authorizer derives namespace grants from the identity and the live list
// of available namespaces. "All namespaces" is evaluated on every call, so
// namespaces created later are included automatically.
type Authorizer struct {
	Source NamespaceSource
	// OwnNamespace is where NetCheck runs. It is never part of Source and is
	// only granted to identities with AllowNetcheckNamespace (admins too).
	OwnNamespace string
}

// Grants returns the namespaces the identity may run probes in, sorted.
func (a *Authorizer) Grants(ctx context.Context, id Identity) ([]NamespaceGrant, error) {
	avail, err := a.Source.Available(ctx)
	if err != nil {
		return nil, err
	}
	out := []NamespaceGrant{}
	for _, ns := range avail {
		if ns == a.OwnNamespace {
			continue
		}
		if id.IsAdmin() || id.AllNamespaces || slices.Contains(id.Namespaces, ns) {
			out = append(out, NamespaceGrant{Name: ns, CanRun: true})
		}
	}
	if a.OwnNamespace != "" && id.AllowNetcheckNamespace {
		out = append(out, NamespaceGrant{Name: a.OwnNamespace, CanRun: true})
	}
	slices.SortFunc(out, func(x, y NamespaceGrant) int {
		if x.Name < y.Name {
			return -1
		}
		if x.Name > y.Name {
			return 1
		}
		return 0
	})
	return out, nil
}

// CanRun reports whether the identity may launch probes in ns right now.
func (a *Authorizer) CanRun(ctx context.Context, id Identity, ns string) (bool, error) {
	grants, err := a.Grants(ctx, id)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(grants, func(g NamespaceGrant) bool { return g.Name == ns }), nil
}

// RunScope says whose tests the identity may read: every test for
// administrators; otherwise only the tests the identity started, with the web
// or its API tokens, whatever its namespaces. Namespaces decide where a user
// may run tests, not whose results they see.
func RunScope(id Identity) (all bool, actorID string) {
	if id.IsAdmin() {
		return true, ""
	}
	return false, id.ID
}

// CanViewRun reports whether the identity may read a test started by actorID.
func CanViewRun(id Identity, actorID string) bool {
	all, own := RunScope(id)
	return all || (own != "" && own == actorID)
}

type ctxKey struct{}

// WithIdentity stores the identity in ctx.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored by WithIdentity.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
