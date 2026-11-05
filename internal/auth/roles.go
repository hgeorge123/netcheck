package auth

import (
	"context"
	"slices"
	"sync"

	"github.com/hgeorge123/netcheck/internal/store"
)

// Permissions of the roles (ADR 0005). Check types are "check.<method>".
const (
	PermFirewall        = "mode.firewall"
	PermRunsAll         = "runs.all"
	PermRunsGroup       = "runs.group"
	PermProxiesShared   = "proxies.useShared"
	PermProxiesPersonal = "proxies.personal"
	PermTokensCreate    = "tokens.create"
)

// CheckMethods are the methods a role can allow, in display order.
var CheckMethods = []string{"dns", "tcp", "udp", "http", "https", "ping", "traceroute"}

// CheckPermission is the permission to run a method.
func CheckPermission(method string) string { return "check." + method }

// AllPermissions lists every permission a custom role can have, in display
// order. Administration stays with the built-in Administrator role.
func AllPermissions() []string {
	out := make([]string, 0, len(CheckMethods)+5)
	for _, m := range CheckMethods {
		out = append(out, CheckPermission(m))
	}
	return append(out, PermFirewall, PermRunsAll, PermRunsGroup, PermProxiesShared, PermProxiesPersonal, PermTokensCreate)
}

// userPermissions are the built-in User role's: every check, the firewall
// ticket, proxies and tokens; only their own tests.
func userPermissions() []string {
	return slices.DeleteFunc(AllPermissions(), func(p string) bool { return p == PermRunsAll || p == PermRunsGroup })
}

// Roles holds the roles in memory for the authorization of every request.
// The built-in roles have their permissions in the code; a role missing from
// the database (for example deleted while a session was open) grants nothing.
type Roles struct {
	mu   sync.RWMutex
	byID map[string]store.Role
}

// LoadRoles reads every role.
func LoadRoles(ctx context.Context, st *store.Store) (*Roles, error) {
	h := &Roles{}
	return h, h.Reload(ctx, st)
}

// Reload reads the roles again after a change.
func (h *Roles) Reload(ctx context.Context, st *store.Store) error {
	list, err := st.ListRoles(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]store.Role, len(list))
	for _, r := range list {
		m[r.ID] = r
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byID = m
	return nil
}

// Exists reports whether a role id can be given to a user or a rule.
func (h *Roles) Exists(id string) bool {
	if id == store.RoleAdmin || id == store.RoleUser {
		return true
	}
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.byID[id]
	return ok
}

// Name returns the display name of a role (its id when unknown).
func (h *Roles) Name(id string) string {
	if h != nil {
		h.mu.RLock()
		defer h.mu.RUnlock()
		if r, ok := h.byID[id]; ok {
			return r.Name
		}
	}
	return id
}

// Permissions returns the permissions of a role. Administrator has all of
// them; a nil holder knows only the built-in roles.
func (h *Roles) Permissions(id string) []string {
	switch id {
	case store.RoleAdmin:
		return AllPermissions()
	case store.RoleUser:
		return userPermissions()
	}
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return slices.Clone(h.byID[id].Permissions)
}

// Has reports whether a role grants a permission.
func (h *Roles) Has(id, perm string) bool { return slices.Contains(h.Permissions(id), perm) }
