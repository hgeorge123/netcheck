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
	// Grants are the roles of the identity, each with its namespaces: one for
	// a local account (its own role and namespaces), one per matching access
	// rule for single sign-on. Empty means the fields above.
	Grants []Grant `json:"-"`
	// SessionHash identifies the current session (never serialised).
	SessionHash string `json:"-"`
	// TokenID is set when the caller authenticated with an API token.
	TokenID string `json:"-"`
}

// EffectiveGrants returns the grants of the identity.
func (i Identity) EffectiveGrants() []Grant {
	if len(i.Grants) > 0 {
		return i.Grants
	}
	return []Grant{{Role: i.Role, AllNamespaces: i.AllNamespaces, AllowNetcheckNamespace: i.AllowNetcheckNamespace, Namespaces: i.Namespaces, Source: "account"}}
}

// IsAdmin reports whether the identity has the admin role.
func (i Identity) IsAdmin() bool {
	return i.Role == RoleAdmin || slices.ContainsFunc(i.Grants, func(g Grant) bool { return g.Role == RoleAdmin })
}

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

// NamespaceGrant is a namespace the caller may use, with what its roles allow
// there.
type NamespaceGrant struct {
	Name   string `json:"name"`
	CanRun bool   `json:"canRun"`
	// Checks are the methods the roles of the caller allow here.
	Checks []string `json:"checks"`
	// FirewallMode tells whether the firewall ticket mode is allowed here.
	FirewallMode bool `json:"firewallMode"`
}

// Authorizer derives namespace grants from the identity and the live list
// of available namespaces. "All namespaces" is evaluated on every call, so
// namespaces created later are included automatically.
type Authorizer struct {
	Source NamespaceSource
	// OwnNamespace is where NetCheck runs. It is never part of Source and is
	// only granted to identities with AllowNetcheckNamespace (admins too).
	OwnNamespace string
	// Roles gives the permissions of each role (nil: built-in roles only).
	Roles *Roles
}

// covers reports whether a grant reaches namespace ns.
func (a *Authorizer) covers(g Grant, ns string) bool {
	if a.OwnNamespace != "" && ns == a.OwnNamespace {
		return g.AllowNetcheckNamespace
	}
	return g.Role == RoleAdmin || g.AllNamespaces || slices.Contains(g.Namespaces, ns)
}

// grant evaluates one namespace: the union of the roles of the grants that
// reach it, never of grants given for other namespaces (ADR 0005 §5).
func (a *Authorizer) grant(id Identity, ns string) (NamespaceGrant, bool) {
	out := NamespaceGrant{Name: ns, CanRun: true, Checks: []string{}}
	found := false
	for _, g := range id.EffectiveGrants() {
		if !a.covers(g, ns) {
			continue
		}
		found = true
		perms := a.Roles.Permissions(g.Role)
		for _, m := range CheckMethods {
			if slices.Contains(perms, CheckPermission(m)) && !slices.Contains(out.Checks, m) {
				out.Checks = append(out.Checks, m)
			}
		}
		out.FirewallMode = out.FirewallMode || slices.Contains(perms, PermFirewall)
	}
	slices.SortFunc(out.Checks, func(x, y string) int { return slices.Index(CheckMethods, x) - slices.Index(CheckMethods, y) })
	return out, found
}

// Grants returns the namespaces the identity may run probes in, sorted, with
// what its roles allow in each.
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
		if g, ok := a.grant(id, ns); ok {
			out = append(out, g)
		}
	}
	if a.OwnNamespace != "" {
		if g, ok := a.grant(id, a.OwnNamespace); ok {
			out = append(out, g)
		}
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

// Grant returns what the identity may do in ns right now (ok=false when it
// cannot run probes there).
func (a *Authorizer) Grant(ctx context.Context, id Identity, ns string) (NamespaceGrant, bool, error) {
	grants, err := a.Grants(ctx, id)
	if err != nil {
		return NamespaceGrant{}, false, err
	}
	for _, g := range grants {
		if g.Name == ns {
			return g, true, nil
		}
	}
	return NamespaceGrant{}, false, nil
}

// CanRun reports whether the identity may launch probes in ns right now.
func (a *Authorizer) CanRun(ctx context.Context, id Identity, ns string) (bool, error) {
	_, ok, err := a.Grant(ctx, id, ns)
	return ok, err
}

// Has reports whether any role of the identity grants a permission that does
// not depend on the namespace (proxies, tokens, run visibility).
func (a *Authorizer) Has(id Identity, perm string) bool {
	if id.IsAdmin() {
		return true
	}
	for _, g := range id.EffectiveGrants() {
		if a.Roles.Has(g.Role, perm) {
			return true
		}
	}
	return false
}

// Permissions lists the permissions that do not depend on the namespace.
func (a *Authorizer) Permissions(id Identity) []string {
	out := []string{}
	for _, p := range AllPermissions() {
		if a.Has(id, p) {
			out = append(out, p)
		}
	}
	return out
}

// RunScope says whose tests the identity may read: every test for
// administrators; with runs.all, every test of the namespaces it can use;
// otherwise only the tests it started, with the web or its API tokens.
func (a *Authorizer) RunScope(ctx context.Context, id Identity) (all bool, namespaces []string, actorID string, err error) {
	if id.IsAdmin() {
		return true, nil, "", nil
	}
	if !a.Has(id, PermRunsAll) {
		return false, nil, id.ID, nil
	}
	grants, err := a.Grants(ctx, id)
	if err != nil {
		return false, nil, "", err
	}
	namespaces = []string{}
	for _, g := range grants {
		namespaces = append(namespaces, g.Name)
	}
	return false, namespaces, "", nil
}

// CanViewRun reports whether the identity may read a test started by actorID
// in namespace ns.
func (a *Authorizer) CanViewRun(ctx context.Context, id Identity, actorID, ns string) (bool, error) {
	if actorID != "" && actorID == id.ID {
		return true, nil
	}
	all, namespaces, own, err := a.RunScope(ctx, id)
	if err != nil {
		return false, err
	}
	return all || slices.Contains(namespaces, ns) || (own != "" && own == actorID), nil
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
