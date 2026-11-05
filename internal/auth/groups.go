package auth

import (
	"context"
	"slices"
	"sync"

	"github.com/hgeorge123/netcheck/internal/store"
)

// Groups holds the local groups in memory for the authorization of every
// request; it is reloaded after every change.
type Groups struct {
	mu   sync.RWMutex
	list []store.LocalGroup
}

// LoadGroups reads every local group.
func LoadGroups(ctx context.Context, st *store.Store) (*Groups, error) {
	h := &Groups{}
	return h, h.Reload(ctx, st)
}

// Reload reads the groups again after a change.
func (h *Groups) Reload(ctx context.Context, st *store.Store) error {
	list, err := st.ListGroups(ctx)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.list = list
	return nil
}

// Of returns the groups a user is a member of.
func (h *Groups) Of(userID string) []store.LocalGroup {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []store.LocalGroup
	for _, g := range h.list {
		if slices.Contains(g.Members, userID) {
			out = append(out, g)
		}
	}
	return out
}

// Peers returns the other members of the groups of a user.
func (h *Groups) Peers(userID string) []string {
	var out []string
	for _, g := range h.Of(userID) {
		for _, m := range g.Members {
			if m != userID && !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

// groupGrant is what membership of a group gives.
func groupGrant(g store.LocalGroup) Grant {
	ns := slices.Clone(g.Namespaces)
	if ns == nil {
		ns = []string{}
	}
	return Grant{Role: g.Role, AllNamespaces: g.AllNamespaces, AllowNetcheckNamespace: g.AllowNetcheckNamespace, Namespaces: ns,
		Source: "localgroup:" + g.Name}
}
